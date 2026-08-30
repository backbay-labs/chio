use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chio_control_plane::trust_control::finding_hosted_profile::{
    FindingHostedProfile, FindingHostedSigningRole,
};
use chio_core_types::{canonical_json_bytes, canonical_json_bytes_from_str, sha256_hex, PublicKey};
use chio_finding_market_store_postgres::{
    HostedJobState, HostedPostgresConfig, HostedTenantId, PostgresFindingMarketStore,
};
use chio_finding_worker::{
    FindingWorkerExitClassification, FindingWorkerGuestOpenFilesBoundary,
    FindingWorkerGuestProcessBoundary, FindingWorkerJobPayload, SignedFindingWorkerResult,
    FINDING_WORKER_GUEST_ENFORCEMENT_SCHEMA,
};
use clap::{Parser, Subcommand};
use nix::libc;
use serde::{Deserialize, Serialize};

const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const CANARY_SCHEMA: &str = "chio.finding.kvm-canary-job.v1";

#[derive(Debug, Parser)]
#[command(name = "chio-finding-market-canary")]
#[command(about = "Provision or verify one exact hosted worker canary")]
struct Args {
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    job: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Provision,
    Verify,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanaryJob {
    schema: String,
    candidate_sha: String,
    configuration_revision: String,
    nonce: String,
    tenant_id: String,
    job_id: String,
    job_kind: String,
    request_sha256: String,
    payload: FindingWorkerJobPayload,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanaryRequestDigest<'a> {
    schema: &'static str,
    candidate_sha: &'a str,
    configuration_revision: &'a str,
    nonce: &'a str,
    tenant_id: &'a str,
    job_id: &'a str,
    job_kind: &'a str,
    job_spec_sha256: &'a str,
    worker_binary_sha256: &'a str,
    firecracker_sha256: &'a str,
    jailer_sha256: &'a str,
    kernel_sha256: &'a str,
    rootfs_sha256: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanaryReport {
    schema: &'static str,
    operation: &'static str,
    candidate_sha: String,
    configuration_revision: String,
    tenant_id: String,
    job_id: String,
    request_sha256: String,
    payload_sha256: String,
    lease_fence: u64,
    terminal_state: &'static str,
    result_sha256: Option<String>,
    result_envelope_sha256: Option<String>,
    completed_at: Option<u64>,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(report) => match canonical_json_bytes(&report) {
            Ok(bytes) if write_stdout(&bytes).is_ok() => ExitCode::SUCCESS,
            _ => ExitCode::FAILURE,
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<CanaryReport, &'static str> {
    let profile: FindingHostedProfile = read_canonical_private(&args.profile)?;
    profile.validate().map_err(|_| "canary_profile_invalid")?;
    let job: CanaryJob = read_canonical_private(&args.job)?;
    validate_job(&profile, &job)?;
    let tenant = HostedTenantId::new(job.tenant_id.clone()).map_err(|_| "canary_job_invalid")?;
    let store = connect_store(&profile).await?;
    match args.command {
        Command::Provision => provision(&store, &tenant, &job).await,
        Command::Verify => verify(&store, &tenant, &profile, &job).await,
    }
}

fn validate_job(profile: &FindingHostedProfile, job: &CanaryJob) -> Result<(), &'static str> {
    let current =
        std::env::var("CHIO_FINDING_CANDIDATE_SHA").map_err(|_| "canary_candidate_missing")?;
    if job.schema != CANARY_SCHEMA
        || current != job.candidate_sha
        || job.candidate_sha.len() != 40
        || !job
            .candidate_sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || job.configuration_revision != profile.release.configuration_revision
        || job.nonce.len() < 32
        || job.nonce.len() > 256
        || job.nonce.chars().any(char::is_control)
        || profile
            .tenants
            .iter()
            .filter(|tenant| tenant.enabled)
            .count()
            != 1
        || !profile
            .tenants
            .iter()
            .any(|tenant| tenant.enabled && tenant.tenant_id == job.tenant_id)
    {
        return Err("canary_job_invalid");
    }
    job.payload
        .job
        .validate()
        .map_err(|_| "canary_job_invalid")?;
    let job_spec_sha256 = job.payload.job.sha256().map_err(|_| "canary_job_invalid")?;
    let request = CanaryRequestDigest {
        schema: CANARY_SCHEMA,
        candidate_sha: &job.candidate_sha,
        configuration_revision: &job.configuration_revision,
        nonce: &job.nonce,
        tenant_id: &job.tenant_id,
        job_id: &job.job_id,
        job_kind: &job.job_kind,
        job_spec_sha256: &job_spec_sha256,
        worker_binary_sha256: &profile.worker.worker_binary_sha256,
        firecracker_sha256: &profile.worker.firecracker_sha256,
        jailer_sha256: &profile.worker.jailer_sha256,
        kernel_sha256: &profile.worker.kernel_sha256,
        rootfs_sha256: &profile.worker.rootfs_sha256,
    };
    let expected_request =
        sha256_hex(&canonical_json_bytes(&request).map_err(|_| "canary_job_invalid")?);
    let capability = &job.payload.capability.body;
    if job.request_sha256 != expected_request
        || capability.tenant_id != job.tenant_id
        || capability.job_id != job.job_id
        || capability.job_kind != job.job_kind
        || capability.request_sha256 != job.request_sha256
        || capability.job_spec_sha256 != job_spec_sha256
        || capability.max_attempts != 1
    {
        return Err("canary_job_binding_invalid");
    }
    let authority = PublicKey::from_hex(&profile.kernel_public_key_hex)
        .map_err(|_| "canary_profile_invalid")?;
    if job.payload.capability.signer_key != authority
        || !job
            .payload
            .capability
            .verify_signature()
            .map_err(|_| "canary_capability_invalid")?
    {
        return Err("canary_capability_invalid");
    }
    Ok(())
}

async fn provision(
    store: &PostgresFindingMarketStore,
    tenant: &HostedTenantId,
    job: &CanaryJob,
) -> Result<CanaryReport, &'static str> {
    if store
        .job_count(tenant)
        .await
        .map_err(|_| "canary_database_unavailable")?
        != 0
        || store
            .nonterminal_job_count(tenant)
            .await
            .map_err(|_| "canary_database_unavailable")?
            != 0
    {
        return Err("canary_queue_not_empty");
    }
    let payload = canonical_json_bytes(&job.payload).map_err(|_| "canary_job_invalid")?;
    let now = current_unix_secs()?;
    store
        .put_job(
            tenant,
            &job.job_id,
            &job.job_kind,
            &job.request_sha256,
            &payload,
            now,
            now,
        )
        .await
        .map_err(|_| "canary_provision_failed")?;
    let retained = store
        .get_job(tenant, &job.job_id)
        .await
        .map_err(|_| "canary_database_unavailable")?
        .ok_or("canary_provision_failed")?;
    if store
        .job_count(tenant)
        .await
        .map_err(|_| "canary_database_unavailable")?
        != 1
        || store
            .nonterminal_job_count(tenant)
            .await
            .map_err(|_| "canary_database_unavailable")?
            != 1
        || retained.state != HostedJobState::Pending
        || retained.request_sha256 != job.request_sha256
        || retained.payload_json != payload
    {
        return Err("canary_provision_failed");
    }
    report("provision", job, &retained, None)
}

async fn verify(
    store: &PostgresFindingMarketStore,
    tenant: &HostedTenantId,
    profile: &FindingHostedProfile,
    job: &CanaryJob,
) -> Result<CanaryReport, &'static str> {
    let retained = store
        .get_job(tenant, &job.job_id)
        .await
        .map_err(|_| "canary_database_unavailable")?
        .ok_or("canary_job_missing")?;
    if store
        .job_count(tenant)
        .await
        .map_err(|_| "canary_database_unavailable")?
        != 1
        || store
            .nonterminal_job_count(tenant)
            .await
            .map_err(|_| "canary_database_unavailable")?
            != 0
    {
        return Err("canary_queue_not_exact");
    }
    let result_sha256 = retained.result_json.as_deref().map(sha256_hex);
    if retained.state != HostedJobState::Completed
        || retained.attempt_count != 1
        || retained.request_sha256 != job.request_sha256
        || retained.result_json.is_none()
        || retained.result_sha256.as_deref() != result_sha256.as_deref()
    {
        return Err("canary_terminal_mismatch");
    }
    let result_json = retained
        .result_json
        .as_deref()
        .ok_or("canary_terminal_mismatch")?;
    let envelope: SignedFindingWorkerResult =
        serde_json::from_slice(result_json).map_err(|_| "canary_result_invalid")?;
    let signer = worker_signer(profile)?;
    let body = &envelope.body;
    let limits = &job.payload.job.resource_limits;
    let enforcement = &body.result.guest_enforcement;
    if envelope.signer_key != signer
        || !envelope
            .verify_signature()
            .map_err(|_| "canary_result_invalid")?
        || body.tenant_id != job.tenant_id
        || body.job_id != job.job_id
        || body.request_sha256 != job.request_sha256
        || body.worker_binary_sha256 != profile.worker.worker_binary_sha256
        || body.firecracker_sha256 != profile.worker.firecracker_sha256
        || body.jailer_sha256 != profile.worker.jailer_sha256
        || body.kernel_sha256 != profile.worker.kernel_sha256
        || body.rootfs_sha256 != profile.worker.rootfs_sha256
        || body.result.classification != FindingWorkerExitClassification::Succeeded
        || body.result.finding_artifact_sha256.is_none()
        || body.result.tenant_id != job.tenant_id
        || body.result.job_id != job.job_id
        || body.result.request_sha256 != job.request_sha256
        || enforcement.schema != FINDING_WORKER_GUEST_ENFORCEMENT_SCHEMA
        || enforcement.process_boundary != FindingWorkerGuestProcessBoundary::CgroupV2
        || enforcement.process_limit != limits.process_count
        || !enforcement.process_limit_probe_passed
        || enforcement.process_limit_hits != 0
        || enforcement.open_files_boundary != FindingWorkerGuestOpenFilesBoundary::RlimitNofile
        || enforcement.open_files_soft_limit != limits.open_files
        || enforcement.open_files_hard_limit != limits.open_files
        || !enforcement.open_files_limit_probe_passed
        || enforcement.open_files_limit_hits != 0
    {
        return Err("canary_result_invalid");
    }
    report("verify", job, &retained, Some(sha256_hex(result_json)))
}

fn report(
    operation: &'static str,
    job: &CanaryJob,
    retained: &chio_finding_market_store_postgres::HostedMarketJob,
    envelope_sha256: Option<String>,
) -> Result<CanaryReport, &'static str> {
    Ok(CanaryReport {
        schema: "chio.finding.kvm-canary-report.v1",
        operation,
        candidate_sha: job.candidate_sha.clone(),
        configuration_revision: job.configuration_revision.clone(),
        tenant_id: job.tenant_id.clone(),
        job_id: job.job_id.clone(),
        request_sha256: job.request_sha256.clone(),
        payload_sha256: retained.payload_sha256.clone(),
        lease_fence: retained.lease_fence,
        terminal_state: match retained.state {
            HostedJobState::Pending => "pending",
            HostedJobState::Completed => "completed",
            _ => return Err("canary_terminal_mismatch"),
        },
        result_sha256: retained.result_sha256.clone(),
        result_envelope_sha256: envelope_sha256,
        completed_at: (retained.state == HostedJobState::Completed).then_some(retained.updated_at),
    })
}

fn worker_signer(profile: &FindingHostedProfile) -> Result<PublicKey, &'static str> {
    let signer = profile
        .signers
        .iter()
        .find(|signer| signer.role == FindingHostedSigningRole::Worker)
        .ok_or("canary_profile_invalid")?;
    PublicKey::from_hex(&signer.public_key_hex).map_err(|_| "canary_profile_invalid")
}

async fn connect_store(
    profile: &FindingHostedProfile,
) -> Result<PostgresFindingMarketStore, &'static str> {
    let url = std::env::var(&profile.database.runtime_url_env)
        .map_err(|_| "canary_database_secret_missing")?;
    let jobs = i64::try_from(profile.database.max_jobs_per_tenant)
        .map_err(|_| "canary_profile_invalid")?;
    let config = HostedPostgresConfig::new(url)
        .and_then(|config| config.with_ca_certificate(&profile.database.ca_certificate_path))
        .and_then(|config| config.with_max_connections(profile.database.max_connections))
        .and_then(|config| config.with_max_jobs_per_tenant(jobs))
        .and_then(|config| {
            config.with_acquire_timeout(Duration::from_millis(
                profile.database.acquire_timeout_millis,
            ))
        })
        .map_err(|_| "canary_profile_invalid")?;
    PostgresFindingMarketStore::connect(&config)
        .await
        .map_err(|_| "canary_database_unavailable")
}

fn read_canonical_private<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, &'static str> {
    if !path.is_absolute() {
        return Err("canary_file_invalid");
    }
    let (mut file, metadata) = open_private_regular(path)?;
    if metadata.len() == 0 || metadata.len() > MAX_FILE_BYTES {
        return Err("canary_file_invalid");
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| "canary_file_invalid")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|_| "canary_file_invalid")?;
    let raw = std::str::from_utf8(&bytes).map_err(|_| "canary_file_invalid")?;
    if canonical_json_bytes_from_str(raw).map_err(|_| "canary_file_invalid")? != bytes {
        return Err("canary_file_invalid");
    }
    serde_json::from_slice(&bytes).map_err(|_| "canary_file_invalid")
}

fn open_private_regular(path: &Path) -> Result<(File, Metadata), &'static str> {
    let before = std::fs::symlink_metadata(path).map_err(|_| "canary_file_invalid")?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.mode() & 0o077 != 0
        || before.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err("canary_file_invalid");
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "canary_file_invalid")?;
    let after = file.metadata().map_err(|_| "canary_file_invalid")?;
    if before.dev() != after.dev() || before.ino() != after.ino() || !after.is_file() {
        return Err("canary_file_invalid");
    }
    Ok((file, after))
}

fn current_unix_secs() -> Result<u64, &'static str> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "canary_clock_invalid")
}

fn write_stdout(bytes: &[u8]) -> Result<(), ()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    lock.write_all(bytes).map_err(|_| ())?;
    lock.write_all(b"\n").map_err(|_| ())?;
    lock.flush().map_err(|_| ())
}
