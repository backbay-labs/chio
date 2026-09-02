use std::fs::{File, Metadata, OpenOptions};
use std::future::Future;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use chio_control_plane::trust_control::finding_hosted_profile::{
    FindingHostedProfile, FindingHostedSigningRole,
};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{canonical_json_bytes_from_str, PublicKey};
use chio_finding_hosted_edge::{
    serve_hosted_market_loopback_with_shutdown, HostedAuthenticator, HostedHttpServerConfig,
    HostedHttpServerState, HostedReleaseIdentity, HOSTED_RELEASE_IDENTITY_SCHEMA,
};
use chio_finding_market_store_postgres::{
    HostedAuthorityMode, HostedMarketAuthority, HostedMarketStoreError, HostedPostgresConfig,
    HostedReplicationCheckBody, HostedTenantId, PostgresFindingMarketReplicator,
    PostgresFindingMarketStore, HOSTED_REPLICATION_CHECK_SCHEMA,
};
use clap::Parser;
use nix::libc;
use zeroize::Zeroizing;

const MAX_PROFILE_BYTES: u64 = 4 * 1024 * 1024;
/// In-flight ceiling per edge replica; excess sheds to the proxy's retry.
const MAX_CONCURRENT_REQUESTS: usize = 1_024;
const MAX_HTTP_BODY_BYTES: usize = 4 * 1024 * 1024;
const DEPLOYED_CANDIDATE_SHA_ENV: &str = "CHIO_FINDING_DEPLOYED_CANDIDATE_SHA";
const DEPLOYED_ARTIFACT_SHA256_ENV: &str = "CHIO_FINDING_DEPLOYED_ARTIFACT_SHA256";

#[derive(Debug, Parser)]
#[command(name = "chio-finding-market-server")]
#[command(about = "Serve the authenticated PostgreSQL cognition market")]
struct Args {
    #[arg(long)]
    profile: PathBuf,
    #[arg(long, conflicts_with = "replication_check_interval_secs")]
    replication_check_once: bool,
    #[arg(long, value_parser = clap::value_parser!(u64).range(5..=20))]
    replication_check_interval_secs: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
enum ServerError {
    #[error("hosted server profile is invalid: {0}")]
    Profile(String),
    /// Carries the environment variable name, never its value.
    #[error("hosted server secret is unavailable: {0}")]
    Secret(String),
    #[error("hosted server database is unavailable: {0}")]
    Database(String),
    #[error("hosted server authentication boundary is invalid: {0}")]
    Authentication(String),
    #[error("hosted server listener is unavailable: {0}")]
    Listener(std::io::Error),
    #[error("hosted server replication freshness is unavailable: {0}")]
    Replication(String),
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), ServerError> {
    let profile: FindingHostedProfile = read_profile(&args.profile)?;
    profile
        .validate()
        .map_err(|error| ServerError::Profile(error.to_string()))?;
    if args.replication_check_once || args.replication_check_interval_secs.is_some() {
        return run_replication_checks(&profile, args.replication_check_interval_secs).await;
    }
    if !profile.listen.ip().is_loopback() {
        return Err(ServerError::Profile(
            "listen address must be loopback".to_owned(),
        ));
    }
    let trusted_proxy = profile
        .load_trusted_proxy()
        .map_err(|error| ServerError::Authentication(error.to_string()))?
        .ok_or_else(|| ServerError::Authentication("profile names no trusted proxy".to_owned()))?;
    let database_url = Zeroizing::new(
        std::env::var(&profile.database.runtime_url_env)
            .map_err(|_| ServerError::Secret(profile.database.runtime_url_env.clone()))?,
    );
    let max_jobs = i64::try_from(profile.database.max_jobs_per_tenant)
        .map_err(|_| ServerError::Profile("max_jobs_per_tenant exceeds i64".to_owned()))?;
    let database_config = HostedPostgresConfig::new(database_url.to_string())
        .and_then(|config| config.with_ca_certificate(&profile.database.ca_certificate_path))
        .and_then(|config| config.with_max_connections(profile.database.max_connections))
        .and_then(|config| {
            config.with_acquire_timeout(Duration::from_millis(
                profile.database.acquire_timeout_millis,
            ))
        })
        .and_then(|config| config.with_max_jobs_per_tenant(max_jobs))
        .map_err(|error| ServerError::Profile(error.to_string()))?;
    let store = Arc::new(
        PostgresFindingMarketStore::connect(&database_config)
            .await
            .map_err(|error| ServerError::Database(error.to_string()))?,
    );
    let authenticator = Arc::new(
        HostedAuthenticator::new(
            profile
                .authenticator_config()
                .map_err(|error| ServerError::Authentication(error.to_string()))?,
            store.clone(),
            Arc::new(
                profile
                    .load_api_key_pepper()
                    .map_err(|error| ServerError::Authentication(error.to_string()))?,
            ),
        )
        .map_err(|error| ServerError::Authentication(error.to_string()))?,
    );
    let release_identity = deployed_release_identity(&profile)?;
    let kernel_receipt_key = PublicKey::from_hex(&profile.kernel_public_key_hex)
        .map_err(|_| ServerError::Profile("kernel_public_key_hex is invalid".to_owned()))?;
    let penalty_authority_key = PublicKey::from_hex(&profile.market.market_penalty.key_hex)
        .map_err(|_| ServerError::Profile("market penalty key_hex is invalid".to_owned()))?;
    let state = HostedHttpServerState::new(
        HostedHttpServerConfig {
            public_endpoint: profile.public_endpoint.clone(),
            maximum_body_bytes: MAX_HTTP_BODY_BYTES,
            maximum_concurrent_requests: MAX_CONCURRENT_REQUESTS,
            penalty_authority_id: profile.market.market_penalty.authority_id.clone(),
            penalty_authority_key,
            kernel_receipt_key,
            release_identity,
        },
        authenticator,
        store,
        Arc::new(trusted_proxy),
    )
    .map_err(|error| ServerError::Authentication(error.to_string()))?;
    let listener = tokio::net::TcpListener::bind(profile.listen)
        .await
        .map_err(ServerError::Listener)?;
    serve_hosted_market_loopback_with_shutdown(listener, state, shutdown_signal())
        .await
        .map_err(ServerError::Listener)
}

fn deployed_release_identity(
    profile: &FindingHostedProfile,
) -> Result<HostedReleaseIdentity, ServerError> {
    let candidate_sha = std::env::var(DEPLOYED_CANDIDATE_SHA_ENV)
        .map_err(|_| ServerError::Secret(DEPLOYED_CANDIDATE_SHA_ENV.to_owned()))?;
    let artifact_sha256 = std::env::var(DEPLOYED_ARTIFACT_SHA256_ENV)
        .map_err(|_| ServerError::Secret(DEPLOYED_ARTIFACT_SHA256_ENV.to_owned()))?;
    validate_deployed_binding(
        &profile.release.candidate_sha,
        &profile.release.artifact_sha256,
        &candidate_sha,
        &artifact_sha256,
    )?;
    Ok(HostedReleaseIdentity {
        schema: HOSTED_RELEASE_IDENTITY_SCHEMA.to_owned(),
        deployment_id: profile.deployment_id.clone(),
        candidate_sha,
        artifact_sha256,
        configuration_revision: profile.release.configuration_revision.clone(),
    })
}

fn validate_deployed_binding(
    expected_candidate_sha: &str,
    expected_artifact_sha256: &str,
    deployed_candidate_sha: &str,
    deployed_artifact_sha256: &str,
) -> Result<(), ServerError> {
    if deployed_candidate_sha != expected_candidate_sha
        || deployed_artifact_sha256 != expected_artifact_sha256
    {
        return Err(ServerError::Profile(
            "deployed candidate or artifact digest differs from the profile release".to_owned(),
        ));
    }
    Ok(())
}

async fn run_replication_checks(
    profile: &FindingHostedProfile,
    interval_secs: Option<u64>,
) -> Result<(), ServerError> {
    let database_url = Zeroizing::new(
        std::env::var(&profile.database.replicator_url_env)
            .map_err(|_| ServerError::Secret(profile.database.replicator_url_env.clone()))?,
    );
    let database_config = HostedPostgresConfig::new(database_url.to_string())
        .and_then(|config| config.with_ca_certificate(&profile.database.ca_certificate_path))
        .and_then(|config| config.with_max_connections(profile.database.max_connections.min(8)))
        .and_then(|config| {
            config.with_acquire_timeout(Duration::from_millis(
                profile.database.acquire_timeout_millis,
            ))
        })
        .map_err(|error| ServerError::Profile(error.to_string()))?;
    let replicator = PostgresFindingMarketReplicator::connect(&database_config)
        .await
        .map_err(|error| ServerError::Replication(error.to_string()))?;
    let signer = profile
        .load_signer(FindingHostedSigningRole::AuthorityStatus)
        .map_err(ServerError::Replication)?;
    let initial = write_replication_checks(profile, &replicator, signer.clone()).await?;
    let Some(interval_secs) = interval_secs else {
        return initial.require_complete();
    };
    if initial.all_failed() {
        return Err(ServerError::Replication(
            "every tenant check failed in the initial round".to_owned(),
        ));
    }
    if initial.has_failures() {
        eprintln!(
            "{}",
            ServerError::Replication("a tenant check failed in the initial round".to_owned())
        );
    }
    let mut consecutive_all_failed_rounds = 0_u8;
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval.tick().await;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let round = write_replication_checks(profile, &replicator, signer.clone()).await?;
                if round.all_failed() {
                    consecutive_all_failed_rounds = consecutive_all_failed_rounds.saturating_add(1);
                    if consecutive_all_failed_rounds >= 3 {
                        return Err(ServerError::Replication(
                            "every tenant check failed for three consecutive rounds".to_owned(),
                        ));
                    }
                } else {
                    consecutive_all_failed_rounds = 0;
                }
                if round.has_failures() {
                    eprintln!(
                        "{}",
                        ServerError::Replication("a tenant check failed this round".to_owned())
                    );
                }
            }
            _ = shutdown_signal() => return Ok(()),
        }
    }
}

async fn write_replication_checks(
    profile: &FindingHostedProfile,
    replicator: &PostgresFindingMarketReplicator,
    signer: Arc<dyn chio_core_types::SigningBackend>,
) -> Result<ReplicationRoundOutcome, ServerError> {
    let tenant_ids = profile
        .tenants
        .iter()
        .filter(|tenant| tenant.enabled)
        .map(|tenant| HostedTenantId::new(tenant.tenant_id.clone()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ServerError::Profile(error.to_string()))?;
    let configuration_revision = profile.release.configuration_revision.clone();
    let replicator = replicator.clone();
    Ok(run_replication_round(tenant_ids, move |tenant_id| {
        let configuration_revision = configuration_revision.clone();
        let replicator = replicator.clone();
        let signer = signer.clone();
        async move {
            write_replication_check(
                &configuration_revision,
                &tenant_id,
                &replicator,
                signer.as_ref(),
            )
            .await
        }
    })
    .await)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReplicationRoundOutcome {
    attempted: usize,
    succeeded: usize,
}

impl ReplicationRoundOutcome {
    fn has_failures(self) -> bool {
        self.succeeded != self.attempted
    }

    fn all_failed(self) -> bool {
        self.attempted == 0 || self.succeeded == 0
    }

    fn require_complete(self) -> Result<(), ServerError> {
        if self.has_failures() {
            Err(ServerError::Replication(format!(
                "{} of {} tenant checks succeeded",
                self.succeeded, self.attempted
            )))
        } else {
            Ok(())
        }
    }
}

async fn run_replication_round<F, Fut>(
    tenant_ids: Vec<HostedTenantId>,
    mut refresh: F,
) -> ReplicationRoundOutcome
where
    F: FnMut(HostedTenantId) -> Fut,
    Fut: Future<Output = Result<(), ServerError>> + Send + 'static,
{
    let mut jobs = tokio::task::JoinSet::new();
    for tenant_id in tenant_ids {
        jobs.spawn(refresh(tenant_id));
    }
    let attempted = jobs.len();
    let mut succeeded = 0;
    while let Some(result) = jobs.join_next().await {
        if matches!(result, Ok(Ok(()))) {
            succeeded += 1;
        }
    }
    ReplicationRoundOutcome {
        attempted,
        succeeded,
    }
}

async fn write_replication_check(
    configuration_revision: &str,
    tenant_id: &HostedTenantId,
    replicator: &PostgresFindingMarketReplicator,
    signer: &dyn chio_core_types::SigningBackend,
) -> Result<(), ServerError> {
    let retry_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let state = replicator
            .authority_state(tenant_id)
            .await
            .map_err(|error| ServerError::Replication(error.to_string()))?;
        if state.authority != HostedMarketAuthority::Postgres
            || !accepts_postgres_mutations(state.mode)
            || !state.mutations_enabled
            || state.configuration_revision != configuration_revision
        {
            return Err(ServerError::Replication(
                "tenant authority state does not accept postgres mutations".to_owned(),
            ));
        }
        let projection_sha256 = replicator
            .target_projection_sha256(tenant_id)
            .await
            .map_err(|error| ServerError::Replication(error.to_string()))?;
        let checked_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| ServerError::Replication(error.to_string()))?
            .as_secs();
        let check = SignedExportEnvelope::sign_with_backend(
            HostedReplicationCheckBody {
                schema: HOSTED_REPLICATION_CHECK_SCHEMA.to_owned(),
                tenant_id: tenant_id.as_str().to_owned(),
                source_authority: HostedMarketAuthority::Postgres,
                authority_epoch: state.authority_epoch,
                through_sequence: state.last_outbox_sequence,
                source_projection_sha256: projection_sha256.clone(),
                target_projection_sha256: projection_sha256,
                lag_seconds: 0,
                projection_difference_count: 0,
                security_counter_count: 0,
                checked_at,
            },
            signer,
        )
        .map_err(|error| ServerError::Replication(error.to_string()))?;
        match replicator
            .append_replication_check(tenant_id, &signer.public_key(), &check)
            .await
        {
            Ok(_) => return Ok(()),
            Err(HostedMarketStoreError::Conflict | HostedMarketStoreError::DigestMismatch)
                if tokio::time::Instant::now() < retry_deadline =>
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => return Err(ServerError::Replication(error.to_string())),
        }
    }
}

fn accepts_postgres_mutations(mode: HostedAuthorityMode) -> bool {
    matches!(
        mode,
        HostedAuthorityMode::RollbackWindow
            | HostedAuthorityMode::Authoritative
            | HostedAuthorityMode::Retired
    )
}

#[cfg(unix)]
async fn shutdown_signal() {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut terminate) => {
            tokio::select! {
                result = tokio::signal::ctrl_c() => {
                    if result.is_err() {
                        let _ = terminate.recv().await;
                    }
                }
                _ = terminate.recv() => {}
            }
        }
        Err(_) => {
            if tokio::signal::ctrl_c().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn read_profile<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, ServerError> {
    if !path.is_absolute() {
        return Err(ServerError::Profile(
            "profile path must be absolute".to_owned(),
        ));
    }
    let (mut file, metadata) = open_private_regular(path)?;
    if metadata.len() == 0 || metadata.len() > MAX_PROFILE_BYTES {
        return Err(ServerError::Profile(
            "profile file is empty or exceeds the size bound".to_owned(),
        ));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| ServerError::Profile("profile bytes failed a read gate".to_owned()))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(MAX_PROFILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ServerError::Profile("profile bytes failed a read gate".to_owned()))?;
    let bytes_len = u64::try_from(bytes.len())
        .map_err(|_| ServerError::Profile("profile bytes failed a read gate".to_owned()))?;
    if bytes_len != metadata.len() || bytes_len > MAX_PROFILE_BYTES {
        return Err(ServerError::Profile(
            "profile file failed a private-regular-file gate".to_owned(),
        ));
    }
    let raw = std::str::from_utf8(&bytes)
        .map_err(|_| ServerError::Profile("profile bytes failed a read gate".to_owned()))?;
    if canonical_json_bytes_from_str(raw)
        .map_err(|_| ServerError::Profile("profile bytes failed a read gate".to_owned()))?
        != bytes
    {
        return Err(ServerError::Profile(
            "profile file failed a private-regular-file gate".to_owned(),
        ));
    }
    serde_json::from_slice(&bytes).map_err(|error| ServerError::Profile(error.to_string()))
}

fn open_private_regular(path: &Path) -> Result<(File, Metadata), ServerError> {
    let before = std::fs::symlink_metadata(path)
        .map_err(|_| ServerError::Profile("profile bytes failed a read gate".to_owned()))?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.mode() & 0o077 != 0
        || before.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(ServerError::Profile(
            "profile file failed a private-regular-file gate".to_owned(),
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ServerError::Profile("profile bytes failed a read gate".to_owned()))?;
    let after = file
        .metadata()
        .map_err(|_| ServerError::Profile("profile bytes failed a read gate".to_owned()))?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || !after.is_file()
        || after.mode() & 0o077 != 0
        || after.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(ServerError::Profile(
            "profile file failed a private-regular-file gate".to_owned(),
        ));
    }
    Ok((file, after))
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn private_file(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap_or_else(|error| panic!("test file create failed: {error}"));
        file.write_all(bytes)
            .unwrap_or_else(|error| panic!("test file write failed: {error}"));
    }

    #[test]
    fn profile_reader_rejects_relative_paths_before_io() {
        assert!(matches!(
            read_profile::<serde_json::Value>(Path::new("profile.json")),
            Err(ServerError::Profile(_))
        ));
    }

    #[test]
    fn public_errors_carry_causes_but_never_secret_values() {
        assert_eq!(
            ServerError::Database("pool timed out".to_owned()).to_string(),
            "hosted server database is unavailable: pool timed out"
        );
        let secret = ServerError::Secret("CHIO_TEST_URL_ENV".to_owned()).to_string();
        assert!(secret.contains("CHIO_TEST_URL_ENV"));
    }

    #[test]
    fn deployed_release_binding_rejects_candidate_or_artifact_drift() {
        let candidate = "a".repeat(40);
        let artifact = "b".repeat(64);
        assert!(validate_deployed_binding(&candidate, &artifact, &candidate, &artifact).is_ok());
        assert!(
            validate_deployed_binding(&candidate, &artifact, &"c".repeat(40), &artifact).is_err()
        );
        assert!(
            validate_deployed_binding(&candidate, &artifact, &candidate, &"d".repeat(64)).is_err()
        );
    }

    #[test]
    fn replication_freshness_covers_every_writable_postgres_mode() {
        for mode in [
            HostedAuthorityMode::RollbackWindow,
            HostedAuthorityMode::Authoritative,
            HostedAuthorityMode::Retired,
        ] {
            assert!(accepts_postgres_mutations(mode));
        }
        for mode in [HostedAuthorityMode::Shadow, HostedAuthorityMode::Frozen] {
            assert!(!accepts_postgres_mutations(mode));
        }
    }

    #[tokio::test]
    async fn replication_round_attempts_every_tenant_after_one_fails() {
        let tenants = ["tenant:first", "tenant:frozen", "tenant:last"]
            .into_iter()
            .map(|tenant| {
                HostedTenantId::new(tenant)
                    .unwrap_or_else(|error| panic!("test tenant failed: {error}"))
            })
            .collect();
        let attempts = Arc::new(AtomicUsize::new(0));
        let result = run_replication_round(tenants, {
            let attempts = attempts.clone();
            move |tenant| {
                let attempts = attempts.clone();
                async move {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    if tenant.as_str() == "tenant:frozen" {
                        Err(ServerError::Replication("forced".to_owned()))
                    } else {
                        Ok(())
                    }
                }
            }
        })
        .await;
        assert_eq!(
            result,
            ReplicationRoundOutcome {
                attempted: 3,
                succeeded: 2
            }
        );
        assert!(result.has_failures());
        assert!(!result.all_failed());
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn replication_round_reports_global_freshness_loss() {
        let tenants = ["tenant:first", "tenant:second"]
            .into_iter()
            .map(|tenant| {
                HostedTenantId::new(tenant)
                    .unwrap_or_else(|error| panic!("test tenant failed: {error}"))
            })
            .collect();
        let result = run_replication_round(tenants, |_| async {
            Err(ServerError::Replication("forced".to_owned()))
        })
        .await;
        assert_eq!(
            result,
            ReplicationRoundOutcome {
                attempted: 2,
                succeeded: 0
            }
        );
        assert!(result.all_failed());
        assert!(matches!(
            result.require_complete(),
            Err(ServerError::Replication(_))
        ));
    }

    #[test]
    fn profile_reader_requires_private_canonical_regular_file() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("test directory create failed: {error}"));
        let profile = directory.path().join("profile.json");
        private_file(&profile, b"{}");
        assert_eq!(
            read_profile::<serde_json::Value>(&profile)
                .unwrap_or_else(|error| panic!("private profile read failed: {error}")),
            serde_json::json!({})
        );
        std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o640))
            .unwrap_or_else(|error| panic!("test permissions failed: {error}"));
        assert!(matches!(
            read_profile::<serde_json::Value>(&profile),
            Err(ServerError::Profile(_))
        ));
    }

    #[test]
    fn profile_reader_rejects_symlink_and_oversized_input() {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|error| panic!("test directory create failed: {error}"));
        let target = directory.path().join("target.json");
        private_file(&target, b"{}");
        let link = directory.path().join("profile.json");
        std::os::unix::fs::symlink(&target, &link)
            .unwrap_or_else(|error| panic!("test symlink failed: {error}"));
        assert!(matches!(
            read_profile::<serde_json::Value>(&link),
            Err(ServerError::Profile(_))
        ));

        let oversized = directory.path().join("oversized.json");
        private_file(&oversized, b"{");
        OpenOptions::new()
            .write(true)
            .open(&oversized)
            .and_then(|file| file.set_len(MAX_PROFILE_BYTES + 1))
            .unwrap_or_else(|error| panic!("test sparse file failed: {error}"));
        assert!(matches!(
            read_profile::<serde_json::Value>(&oversized),
            Err(ServerError::Profile(_))
        ));
    }
}
