use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chio_control_plane::trust_control::finding_hosted_profile::{
    FindingHostedAuthMethod, FindingHostedProfile, FindingHostedSigningRole,
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
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const CANARY_SCHEMA: &str = "chio.finding.kvm-canary-job.v1";
const MAX_NETWORK_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "chio-finding-market-canary")]
#[command(about = "Provision or verify one exact hosted worker canary")]
struct Args {
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    job: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Provision,
    Verify,
    /// Exercise seller publication, exact replay, buyer resolution, and a
    /// negative tenant-isolation probe through the deployed HTTPS listener.
    Network {
        #[arg(long)]
        finding: PathBuf,
        #[arg(long)]
        tenant_id: String,
        #[arg(long)]
        seller_key_id_env: String,
        #[arg(long)]
        seller_key_secret_env: String,
        #[arg(long)]
        buyer_key_id_env: String,
        #[arg(long)]
        buyer_key_secret_env: String,
    },
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

#[derive(Serialize)]
#[serde(untagged)]
enum CanaryOutput {
    Kvm(CanaryReport),
    Network(NetworkCanaryReport),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkCanaryReport {
    schema: &'static str,
    candidate_sha: String,
    configuration_revision: String,
    tenant_id: String,
    finding_id: String,
    finding_sha256: String,
    event_id: String,
    first_outcome: String,
    retry_outcome: String,
    buyer_payload_matched: bool,
    buyer_catalog_matched: bool,
    tenant_isolation_denied: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NetworkMutationResponse {
    schema: String,
    request_id: String,
    tenant_id: String,
    operation_id: String,
    outcome: String,
    resource_id: String,
    resource_sha256: String,
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

async fn network_canary(
    profile: &FindingHostedProfile,
    finding_path: &Path,
    tenant_id: &str,
    seller_key_id_env: &str,
    seller_key_secret_env: &str,
    buyer_key_id_env: &str,
    buyer_key_secret_env: &str,
) -> Result<NetworkCanaryReport, &'static str> {
    let tenant = profile
        .tenants
        .iter()
        .find(|tenant| tenant.enabled && tenant.tenant_id == tenant_id)
        .ok_or("network_canary_tenant_invalid")?;
    if !tenant
        .auth_methods
        .contains(&FindingHostedAuthMethod::ApiKey)
    {
        return Err("network_canary_api_key_not_admitted");
    }
    let (finding_bytes, finding): (Vec<u8>, chio_finding::Finding) =
        read_canonical_private_bytes(finding_path)?;
    chio_finding::verify_finding(&finding).map_err(|_| "network_canary_finding_invalid")?;
    let now = current_unix_secs()?;
    if finding.issued_at > now || finding.expires_at <= now {
        return Err("network_canary_finding_inactive");
    }
    let candidate_sha = candidate_sha()?;
    let event_id = sha256_hex(
        format!(
            "chio.finding.network-canary-event.v1\0{}\0{}\0{}\0{}",
            candidate_sha, profile.release.configuration_revision, tenant_id, finding.finding_id
        )
        .as_bytes(),
    );
    let seller_key_id = read_canary_environment(seller_key_id_env)?;
    let seller_key_secret = Zeroizing::new(read_canary_environment(seller_key_secret_env)?);
    let buyer_key_id = read_canary_environment(buyer_key_id_env)?;
    let buyer_key_secret = Zeroizing::new(read_canary_environment(buyer_key_secret_env)?);
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .user_agent("chio-finding-market-network-canary/1")
        .build()
        .map_err(|_| "network_canary_client_invalid")?;
    let first_request_id = sha256_hex(format!("{event_id}:first").as_bytes());
    let first = publish_network_finding(
        &client,
        profile,
        tenant_id,
        &seller_key_id,
        &seller_key_secret,
        &first_request_id,
        &event_id,
        &finding_bytes,
    )
    .await?;
    if first.outcome != "applied" && first.outcome != "exact_replay" {
        return Err("network_canary_publish_outcome_invalid");
    }
    validate_network_mutation(&first, tenant_id, &finding.finding_id, &event_id)?;
    let retry_request_id = sha256_hex(format!("{event_id}:retry").as_bytes());
    let retry = publish_network_finding(
        &client,
        profile,
        tenant_id,
        &seller_key_id,
        &seller_key_secret,
        &retry_request_id,
        &event_id,
        &finding_bytes,
    )
    .await?;
    validate_network_mutation(&retry, tenant_id, &finding.finding_id, &event_id)?;
    if retry.outcome != "exact_replay" {
        return Err("network_canary_retry_not_exact");
    }
    let resolved = network_get(
        &client,
        profile,
        tenant_id,
        &buyer_key_id,
        &buyer_key_secret,
        &sha256_hex(format!("{event_id}:get").as_bytes()),
        &format!("/v1/findings/{}", finding.finding_id),
    )
    .await?;
    if resolved != finding_bytes {
        return Err("network_canary_payload_mismatch");
    }
    let catalog_bytes = network_get(
        &client,
        profile,
        tenant_id,
        &buyer_key_id,
        &buyer_key_secret,
        &sha256_hex(format!("{event_id}:list").as_bytes()),
        "/v1/findings?limit=100",
    )
    .await?;
    let catalog: serde_json::Value =
        serde_json::from_slice(&catalog_bytes).map_err(|_| "network_canary_catalog_invalid")?;
    let finding_value: serde_json::Value =
        serde_json::from_slice(&finding_bytes).map_err(|_| "network_canary_finding_invalid")?;
    let catalog_matched = catalog
        .get("items")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|items| {
            items.iter().any(|item| {
                item.get("aggregateId").and_then(serde_json::Value::as_str)
                    == Some(finding.finding_id.as_str())
                    && item.get("payload") == Some(&finding_value)
            })
        });
    if !catalog_matched {
        return Err("network_canary_catalog_mismatch");
    }
    let isolation_tenant = format!("network-canary-isolation-{}", &event_id[..32]);
    if profile
        .tenants
        .iter()
        .any(|candidate| candidate.tenant_id == isolation_tenant)
    {
        return Err("network_canary_isolation_probe_ambiguous");
    }
    let isolation_denied = network_get_status(
        &client,
        profile,
        &isolation_tenant,
        &buyer_key_id,
        &buyer_key_secret,
        &sha256_hex(format!("{event_id}:isolation").as_bytes()),
        &format!("/v1/findings/{}", finding.finding_id),
    )
    .await?
        == StatusCode::UNAUTHORIZED;
    if !isolation_denied {
        return Err("network_canary_tenant_isolation_failed");
    }
    Ok(NetworkCanaryReport {
        schema: "chio.finding.hosted-network-canary-report.v1",
        candidate_sha,
        configuration_revision: profile.release.configuration_revision.clone(),
        tenant_id: tenant_id.to_owned(),
        finding_id: finding.finding_id,
        finding_sha256: sha256_hex(&finding_bytes),
        event_id,
        first_outcome: first.outcome,
        retry_outcome: retry.outcome,
        buyer_payload_matched: true,
        buyer_catalog_matched: true,
        tenant_isolation_denied: true,
    })
}

#[allow(clippy::too_many_arguments)]
async fn publish_network_finding(
    client: &reqwest::Client,
    profile: &FindingHostedProfile,
    tenant_id: &str,
    key_id: &str,
    key_secret: &str,
    request_id: &str,
    event_id: &str,
    finding: &[u8],
) -> Result<NetworkMutationResponse, &'static str> {
    let response = client
        .post(format!(
            "{}/v1/findings/publish",
            profile.public_endpoint.trim_end_matches('/')
        ))
        .header("Chio-Tenant-ID", tenant_id)
        .header("Chio-Request-ID", request_id)
        .header("Chio-API-Key-ID", key_id)
        .header("Chio-API-Key-Secret", key_secret)
        .header("Idempotency-Key", event_id)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(finding.to_vec())
        .send()
        .await
        .map_err(|_| "network_canary_request_failed")?;
    if response.status() != StatusCode::OK {
        return Err("network_canary_publish_failed");
    }
    let bytes = bounded_response(response).await?;
    serde_json::from_slice(&bytes).map_err(|_| "network_canary_publish_response_invalid")
}

fn validate_network_mutation(
    response: &NetworkMutationResponse,
    tenant_id: &str,
    finding_id: &str,
    event_id: &str,
) -> Result<(), &'static str> {
    if response.schema != "chio.finding.hosted-mutation-response.v1"
        || response.request_id.len() != 64
        || response.tenant_id != tenant_id
        || response.operation_id != event_id
        || response.resource_id != finding_id
        || response.resource_sha256.len() != 64
        || !response
            .resource_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("network_canary_publish_binding_invalid");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn network_get(
    client: &reqwest::Client,
    profile: &FindingHostedProfile,
    tenant_id: &str,
    key_id: &str,
    key_secret: &str,
    request_id: &str,
    path: &str,
) -> Result<Vec<u8>, &'static str> {
    let response = network_request(
        client, profile, tenant_id, key_id, key_secret, request_id, path,
    )
    .await?;
    if response.status() != StatusCode::OK {
        return Err("network_canary_read_failed");
    }
    bounded_response(response).await
}

#[allow(clippy::too_many_arguments)]
async fn network_get_status(
    client: &reqwest::Client,
    profile: &FindingHostedProfile,
    tenant_id: &str,
    key_id: &str,
    key_secret: &str,
    request_id: &str,
    path: &str,
) -> Result<StatusCode, &'static str> {
    network_request(
        client, profile, tenant_id, key_id, key_secret, request_id, path,
    )
    .await
    .map(|response| response.status())
}

#[allow(clippy::too_many_arguments)]
async fn network_request(
    client: &reqwest::Client,
    profile: &FindingHostedProfile,
    tenant_id: &str,
    key_id: &str,
    key_secret: &str,
    request_id: &str,
    path: &str,
) -> Result<reqwest::Response, &'static str> {
    client
        .get(format!(
            "{}{}",
            profile.public_endpoint.trim_end_matches('/'),
            path
        ))
        .header("Chio-Tenant-ID", tenant_id)
        .header("Chio-Request-ID", request_id)
        .header("Chio-API-Key-ID", key_id)
        .header("Chio-API-Key-Secret", key_secret)
        .send()
        .await
        .map_err(|_| "network_canary_request_failed")
}

async fn bounded_response(mut response: reqwest::Response) -> Result<Vec<u8>, &'static str> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_NETWORK_RESPONSE_BYTES as u64)
    {
        return Err("network_canary_response_oversized");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "network_canary_response_failed")?
    {
        if body.len().saturating_add(chunk.len()) > MAX_NETWORK_RESPONSE_BYTES {
            return Err("network_canary_response_oversized");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn candidate_sha() -> Result<String, &'static str> {
    let value =
        std::env::var("CHIO_FINDING_CANDIDATE_SHA").map_err(|_| "canary_candidate_missing")?;
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("canary_candidate_invalid");
    }
    Ok(value)
}

fn read_canary_environment(name: &str) -> Result<String, &'static str> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err("network_canary_environment_invalid");
    }
    let value = std::env::var(name).map_err(|_| "network_canary_secret_missing")?;
    if value.is_empty()
        || value.len() > 4_096
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err("network_canary_secret_invalid");
    }
    Ok(value)
}

async fn run(args: Args) -> Result<CanaryOutput, &'static str> {
    let profile: FindingHostedProfile = read_canonical_private(&args.profile)?;
    profile.validate().map_err(|_| "canary_profile_invalid")?;
    match args.command {
        command @ (Command::Provision | Command::Verify) => {
            let job_path = args.job.as_deref().ok_or("canary_job_missing")?;
            let job: CanaryJob = read_canonical_private(job_path)?;
            validate_job(&profile, &job)?;
            let tenant =
                HostedTenantId::new(job.tenant_id.clone()).map_err(|_| "canary_job_invalid")?;
            let store = connect_store(&profile).await?;
            let report = match command {
                Command::Provision => provision(&store, &tenant, &job).await?,
                Command::Verify => verify(&store, &tenant, &profile, &job).await?,
                Command::Network { .. } => return Err("canary_command_invalid"),
            };
            Ok(CanaryOutput::Kvm(report))
        }
        Command::Network {
            finding,
            tenant_id,
            seller_key_id_env,
            seller_key_secret_env,
            buyer_key_id_env,
            buyer_key_secret_env,
        } => {
            if args.job.is_some() {
                return Err("canary_job_unexpected");
            }
            network_canary(
                &profile,
                &finding,
                &tenant_id,
                &seller_key_id_env,
                &seller_key_secret_env,
                &buyer_key_id_env,
                &buyer_key_secret_env,
            )
            .await
            .map(CanaryOutput::Network)
        }
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
    read_canonical_private_bytes(path).map(|(_, value)| value)
}

fn read_canonical_private_bytes<T: serde::de::DeserializeOwned>(
    path: &Path,
) -> Result<(Vec<u8>, T), &'static str> {
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
    let value = serde_json::from_slice(&bytes).map_err(|_| "canary_file_invalid")?;
    Ok((bytes, value))
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
