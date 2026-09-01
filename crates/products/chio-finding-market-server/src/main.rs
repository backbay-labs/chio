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
use chio_core_types::canonical_json_bytes_from_str;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
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

#[derive(Clone, Copy, Debug, thiserror::Error)]
enum ServerError {
    #[error("hosted server profile is invalid")]
    Profile,
    #[error("hosted server secret is unavailable")]
    Secret,
    #[error("hosted server database is unavailable")]
    Database,
    #[error("hosted server authentication boundary is invalid")]
    Authentication,
    #[error("hosted server listener is unavailable")]
    Listener,
    #[error("hosted server replication freshness is unavailable")]
    Replication,
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
    profile.validate().map_err(|_| ServerError::Profile)?;
    if args.replication_check_once || args.replication_check_interval_secs.is_some() {
        return run_replication_checks(&profile, args.replication_check_interval_secs).await;
    }
    if !profile.listen.ip().is_loopback() {
        return Err(ServerError::Profile);
    }
    let trusted_proxy = profile
        .load_trusted_proxy()
        .map_err(|_| ServerError::Authentication)?
        .ok_or(ServerError::Authentication)?;
    let database_url = Zeroizing::new(
        std::env::var(&profile.database.runtime_url_env).map_err(|_| ServerError::Secret)?,
    );
    let max_jobs =
        i64::try_from(profile.database.max_jobs_per_tenant).map_err(|_| ServerError::Profile)?;
    let database_config = HostedPostgresConfig::new(database_url.to_string())
        .and_then(|config| config.with_ca_certificate(&profile.database.ca_certificate_path))
        .and_then(|config| config.with_max_connections(profile.database.max_connections))
        .and_then(|config| {
            config.with_acquire_timeout(Duration::from_millis(
                profile.database.acquire_timeout_millis,
            ))
        })
        .and_then(|config| config.with_max_jobs_per_tenant(max_jobs))
        .map_err(|_| ServerError::Profile)?;
    let store = Arc::new(
        PostgresFindingMarketStore::connect(&database_config)
            .await
            .map_err(|_| ServerError::Database)?,
    );
    let authenticator = Arc::new(
        HostedAuthenticator::new(
            profile
                .authenticator_config()
                .map_err(|_| ServerError::Authentication)?,
            store.clone(),
            Arc::new(
                profile
                    .load_api_key_pepper()
                    .map_err(|_| ServerError::Authentication)?,
            ),
        )
        .map_err(|_| ServerError::Authentication)?,
    );
    let release_identity = deployed_release_identity(&profile)?;
    let state = HostedHttpServerState::new(
        HostedHttpServerConfig {
            public_endpoint: profile.public_endpoint.clone(),
            maximum_body_bytes: MAX_HTTP_BODY_BYTES,
            release_identity,
        },
        authenticator,
        store,
        Arc::new(trusted_proxy),
    )
    .map_err(|_| ServerError::Authentication)?;
    let listener = tokio::net::TcpListener::bind(profile.listen)
        .await
        .map_err(|_| ServerError::Listener)?;
    serve_hosted_market_loopback_with_shutdown(listener, state, shutdown_signal())
        .await
        .map_err(|_| ServerError::Listener)
}

fn deployed_release_identity(
    profile: &FindingHostedProfile,
) -> Result<HostedReleaseIdentity, ServerError> {
    let candidate_sha =
        std::env::var(DEPLOYED_CANDIDATE_SHA_ENV).map_err(|_| ServerError::Secret)?;
    let artifact_sha256 =
        std::env::var(DEPLOYED_ARTIFACT_SHA256_ENV).map_err(|_| ServerError::Secret)?;
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
        return Err(ServerError::Profile);
    }
    Ok(())
}

async fn run_replication_checks(
    profile: &FindingHostedProfile,
    interval_secs: Option<u64>,
) -> Result<(), ServerError> {
    let database_url = Zeroizing::new(
        std::env::var(&profile.database.replicator_url_env).map_err(|_| ServerError::Secret)?,
    );
    let database_config = HostedPostgresConfig::new(database_url.to_string())
        .and_then(|config| config.with_ca_certificate(&profile.database.ca_certificate_path))
        .and_then(|config| config.with_max_connections(profile.database.max_connections.min(8)))
        .and_then(|config| {
            config.with_acquire_timeout(Duration::from_millis(
                profile.database.acquire_timeout_millis,
            ))
        })
        .map_err(|_| ServerError::Profile)?;
    let replicator = PostgresFindingMarketReplicator::connect(&database_config)
        .await
        .map_err(|_| ServerError::Replication)?;
    let signer = profile
        .load_signer(FindingHostedSigningRole::AuthorityStatus)
        .map_err(|_| ServerError::Replication)?;
    let initial_result = write_replication_checks(profile, &replicator, signer.clone()).await;
    let Some(interval_secs) = interval_secs else {
        return initial_result;
    };
    if initial_result.is_err() {
        eprintln!("{}", ServerError::Replication);
    }
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval.tick().await;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if write_replication_checks(profile, &replicator, signer.clone()).await.is_err() {
                    eprintln!("{}", ServerError::Replication);
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
) -> Result<(), ServerError> {
    let tenant_ids = profile
        .tenants
        .iter()
        .filter(|tenant| tenant.enabled)
        .map(|tenant| HostedTenantId::new(tenant.tenant_id.clone()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ServerError::Profile)?;
    let configuration_revision = profile.release.configuration_revision.clone();
    let replicator = replicator.clone();
    run_replication_round(tenant_ids, move |tenant_id| {
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
    .await
}

async fn run_replication_round<F, Fut>(
    tenant_ids: Vec<HostedTenantId>,
    mut refresh: F,
) -> Result<(), ServerError>
where
    F: FnMut(HostedTenantId) -> Fut,
    Fut: Future<Output = Result<(), ServerError>> + Send + 'static,
{
    let mut jobs = tokio::task::JoinSet::new();
    for tenant_id in tenant_ids {
        jobs.spawn(refresh(tenant_id));
    }
    let mut failed = false;
    while let Some(result) = jobs.join_next().await {
        if !matches!(result, Ok(Ok(()))) {
            failed = true;
        }
    }
    if failed {
        Err(ServerError::Replication)
    } else {
        Ok(())
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
            .map_err(|_| ServerError::Replication)?;
        if state.authority != HostedMarketAuthority::Postgres
            || state.mode != HostedAuthorityMode::Authoritative
            || !state.mutations_enabled
            || state.configuration_revision != configuration_revision
        {
            return Err(ServerError::Replication);
        }
        let projection_sha256 = replicator
            .target_projection_sha256(tenant_id)
            .await
            .map_err(|_| ServerError::Replication)?;
        let checked_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ServerError::Replication)?
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
        .map_err(|_| ServerError::Replication)?;
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
            Err(_) => return Err(ServerError::Replication),
        }
    }
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
        return Err(ServerError::Profile);
    }
    let (mut file, metadata) = open_private_regular(path)?;
    if metadata.len() == 0 || metadata.len() > MAX_PROFILE_BYTES {
        return Err(ServerError::Profile);
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| ServerError::Profile)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(MAX_PROFILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ServerError::Profile)?;
    let bytes_len = u64::try_from(bytes.len()).map_err(|_| ServerError::Profile)?;
    if bytes_len != metadata.len() || bytes_len > MAX_PROFILE_BYTES {
        return Err(ServerError::Profile);
    }
    let raw = std::str::from_utf8(&bytes).map_err(|_| ServerError::Profile)?;
    if canonical_json_bytes_from_str(raw).map_err(|_| ServerError::Profile)? != bytes {
        return Err(ServerError::Profile);
    }
    serde_json::from_slice(&bytes).map_err(|_| ServerError::Profile)
}

fn open_private_regular(path: &Path) -> Result<(File, Metadata), ServerError> {
    let before = std::fs::symlink_metadata(path).map_err(|_| ServerError::Profile)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.mode() & 0o077 != 0
        || before.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(ServerError::Profile);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ServerError::Profile)?;
    let after = file.metadata().map_err(|_| ServerError::Profile)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || !after.is_file()
        || after.mode() & 0o077 != 0
        || after.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(ServerError::Profile);
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
            Err(ServerError::Profile)
        ));
    }

    #[test]
    fn public_errors_do_not_expose_dependency_details() {
        assert_eq!(
            ServerError::Database.to_string(),
            "hosted server database is unavailable"
        );
        assert!(!ServerError::Secret.to_string().contains("environment"));
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
                        Err(ServerError::Replication)
                    } else {
                        Ok(())
                    }
                }
            }
        })
        .await;
        assert!(matches!(result, Err(ServerError::Replication)));
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
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
            Err(ServerError::Profile)
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
            Err(ServerError::Profile)
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
            Err(ServerError::Profile)
        ));
    }
}
