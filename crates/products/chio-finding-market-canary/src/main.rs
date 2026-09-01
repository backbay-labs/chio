use std::collections::BTreeSet;
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
use chio_egress_contract::{ContractResponse, HttpEgressContract};
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
const NETWORK_FINDING_POOL_SCHEMA: &str = "chio.finding.network-canary-pool.v1";
const MAX_NETWORK_FINDING_POOL_SIZE: usize = 128;
const GITHUB_RUN_ID_ENV: &str = "GITHUB_RUN_ID";
const GITHUB_RUN_ATTEMPT_ENV: &str = "GITHUB_RUN_ATTEMPT";

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
    Network(Box<NetworkArgs>),
}

#[derive(Debug, clap::Args)]
struct NetworkArgs {
    #[arg(long)]
    finding_pool: PathBuf,
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
    #[arg(long)]
    isolation_tenant_id: String,
    #[arg(long)]
    isolation_buyer_key_id_env: String,
    #[arg(long)]
    isolation_buyer_key_secret_env: String,
}

struct NetworkCanaryInputs<'a> {
    finding_pool_path: &'a Path,
    tenant_id: &'a str,
    seller_key_id_env: &'a str,
    seller_key_secret_env: &'a str,
    buyer_key_id_env: &'a str,
    buyer_key_secret_env: &'a str,
    isolation_tenant_id: &'a str,
    isolation_buyer_key_id_env: &'a str,
    isolation_buyer_key_secret_env: &'a str,
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
    deployed_candidate_sha: String,
    deployed_artifact_sha256: String,
    tenant_id: String,
    finding_id: String,
    finding_sha256: String,
    finding_pool_sha256: String,
    run_nonce_sha256: String,
    event_id: String,
    first_outcome: String,
    retry_outcome: String,
    buyer_payload_matched: bool,
    buyer_catalog_matched: bool,
    tenant_isolation_denied: bool,
}

struct NetworkHttpClient {
    client: reqwest::Client,
    egress_contract: HttpEgressContract,
}

impl NetworkHttpClient {
    fn new(public_endpoint: &str, tenant_id: &str) -> Result<Self, &'static str> {
        let egress_contract = network_egress_contract(public_endpoint, tenant_id)?;
        let client = chio_egress_contract::client_builder_with_contract(&egress_contract)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| "network_canary_client_invalid")?;
        Ok(Self {
            client,
            egress_contract,
        })
    }

    async fn send(&self, request: reqwest::Request) -> Result<ContractResponse, &'static str> {
        chio_egress_contract::send_with_contract(&self.egress_contract, &self.client, request)
            .await
            .map_err(|_| "network_canary_request_failed")
    }
}

fn network_egress_contract(
    public_endpoint: &str,
    tenant_id: &str,
) -> Result<HttpEgressContract, &'static str> {
    let endpoint = reqwest::Url::parse(public_endpoint)
        .map_err(|_| "network_canary_egress_contract_invalid")?;
    if endpoint.scheme() != "https"
        || endpoint.path() != "/"
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
    {
        return Err("network_canary_egress_contract_invalid");
    }
    let host = endpoint
        .host_str()
        .ok_or("network_canary_egress_contract_invalid")?;
    let normalized_host = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]", host.to_ascii_lowercase())
    } else {
        host.trim_end_matches('.').to_ascii_lowercase()
    };
    let authority = match endpoint.port() {
        Some(port) => format!("{normalized_host}:{port}"),
        None => normalized_host,
    };
    let contract = HttpEgressContract {
        tenant_egress_namespace: format!("cognition-market.network-canary:{tenant_id}"),
        allowed_schemes: BTreeSet::from(["https".to_owned()]),
        allowed_authority_set: BTreeSet::from([authority]),
        deny_loopback: true,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 0,
        max_response_bytes: MAX_NETWORK_RESPONSE_BYTES as u64,
    };
    contract
        .validate_dispatchable_with_pinned_dns()
        .and_then(|()| contract.enforce_url(endpoint.as_str(), 0).map(|_| ()))
        .map_err(|_| "network_canary_egress_contract_invalid")?;
    Ok(contract)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NetworkFindingPool {
    schema: String,
    finding_paths: Vec<String>,
}

struct NetworkFindingCandidate {
    bytes: Vec<u8>,
    finding: chio_finding::Finding,
}

struct FreshNetworkPublication {
    candidate: NetworkFindingCandidate,
    event_id: String,
    response: NetworkMutationResponse,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NetworkReleaseIdentity {
    schema: String,
    deployment_id: String,
    candidate_sha: String,
    artifact_sha256: String,
    configuration_revision: String,
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
    inputs: NetworkCanaryInputs<'_>,
) -> Result<NetworkCanaryReport, &'static str> {
    let NetworkCanaryInputs {
        finding_pool_path,
        tenant_id,
        seller_key_id_env,
        seller_key_secret_env,
        buyer_key_id_env,
        buyer_key_secret_env,
        isolation_tenant_id,
        isolation_buyer_key_id_env,
        isolation_buyer_key_secret_env,
    } = inputs;
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
    let isolation_tenant = profile
        .tenants
        .iter()
        .find(|candidate| candidate.enabled && candidate.tenant_id == isolation_tenant_id)
        .ok_or("network_canary_isolation_tenant_invalid")?;
    if isolation_tenant.tenant_id == tenant.tenant_id
        || !isolation_tenant
            .auth_methods
            .contains(&FindingHostedAuthMethod::ApiKey)
    {
        return Err("network_canary_isolation_tenant_invalid");
    }
    let now = current_unix_secs()?;
    let candidate_sha = candidate_sha()?;
    if candidate_sha != profile.release.candidate_sha {
        return Err("network_canary_profile_candidate_mismatch");
    }
    let run_nonce = network_run_nonce()?;
    let run_nonce_sha256 = sha256_hex(run_nonce.as_bytes());
    let (finding_pool_sha256, finding_candidates) =
        load_network_finding_pool(finding_pool_path, now, &run_nonce)?;
    let seller_key_id = read_canary_environment(seller_key_id_env)?;
    let seller_key_secret = Zeroizing::new(read_canary_environment(seller_key_secret_env)?);
    let buyer_key_id = read_canary_environment(buyer_key_id_env)?;
    let buyer_key_secret = Zeroizing::new(read_canary_environment(buyer_key_secret_env)?);
    let isolation_buyer_key_id = read_canary_environment(isolation_buyer_key_id_env)?;
    let isolation_buyer_key_secret =
        Zeroizing::new(read_canary_environment(isolation_buyer_key_secret_env)?);
    if isolation_buyer_key_id == buyer_key_id
        || isolation_buyer_key_secret.as_str() == buyer_key_secret.as_str()
    {
        return Err("network_canary_isolation_credential_reused");
    }
    let http = NetworkHttpClient::new(&profile.public_endpoint, tenant_id)?;
    let isolation_http = NetworkHttpClient::new(&profile.public_endpoint, isolation_tenant_id)?;
    let release_bytes = network_get(
        &http,
        profile,
        tenant_id,
        &buyer_key_id,
        &buyer_key_secret,
        &sha256_hex(format!("{candidate_sha}:{run_nonce}:release").as_bytes()),
        "/v1/release",
    )
    .await?;
    let deployed: NetworkReleaseIdentity = serde_json::from_slice(&release_bytes)
        .map_err(|_| "network_canary_release_identity_invalid")?;
    if deployed.schema != "chio.finding.hosted-release-identity.v1"
        || deployed.deployment_id != profile.deployment_id
        || deployed.candidate_sha != candidate_sha
        || deployed.artifact_sha256 != profile.release.artifact_sha256
        || deployed.configuration_revision != profile.release.configuration_revision
    {
        return Err("network_canary_release_identity_mismatch");
    }
    let FreshNetworkPublication {
        candidate,
        event_id,
        response: first,
    } = publish_fresh_network_finding(
        &http,
        profile,
        tenant_id,
        &seller_key_id,
        &seller_key_secret,
        &buyer_key_id,
        &buyer_key_secret,
        &candidate_sha,
        &run_nonce,
        finding_candidates,
    )
    .await?;
    let finding = candidate.finding;
    let finding_bytes = candidate.bytes;
    let finding_sha256 = sha256_hex(&finding_bytes);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let retry_request_id = sha256_hex(format!("{event_id}:retry").as_bytes());
    let retry = publish_network_finding(
        &http,
        profile,
        tenant_id,
        &seller_key_id,
        &seller_key_secret,
        &retry_request_id,
        &event_id,
        &finding_bytes,
    )
    .await?;
    validate_network_mutation(
        &retry,
        tenant_id,
        &finding.finding_id,
        &event_id,
        &retry_request_id,
        &finding_sha256,
    )?;
    if retry.outcome != "exact_replay" {
        return Err("network_canary_retry_not_exact");
    }
    let resolved = network_get(
        &http,
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
    let catalog_path = finding_catalog_path(&finding.finding_id)?;
    let catalog_bytes = network_get(
        &http,
        profile,
        tenant_id,
        &buyer_key_id,
        &buyer_key_secret,
        &sha256_hex(format!("{event_id}:list").as_bytes()),
        &catalog_path,
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
    let isolation_denied = network_get_status(
        &isolation_http,
        profile,
        isolation_tenant_id,
        &isolation_buyer_key_id,
        &isolation_buyer_key_secret,
        &sha256_hex(format!("{event_id}:isolation").as_bytes()),
        &format!("/v1/findings/{}", finding.finding_id),
    )
    .await?
        == StatusCode::NOT_FOUND;
    if !isolation_denied {
        return Err("network_canary_tenant_isolation_failed");
    }
    Ok(NetworkCanaryReport {
        schema: "chio.finding.hosted-network-canary-report.v1",
        candidate_sha,
        configuration_revision: profile.release.configuration_revision.clone(),
        deployed_candidate_sha: deployed.candidate_sha,
        deployed_artifact_sha256: deployed.artifact_sha256,
        tenant_id: tenant_id.to_owned(),
        finding_id: finding.finding_id,
        finding_sha256,
        finding_pool_sha256,
        run_nonce_sha256,
        event_id,
        first_outcome: first.outcome,
        retry_outcome: retry.outcome,
        buyer_payload_matched: true,
        buyer_catalog_matched: true,
        tenant_isolation_denied: true,
    })
}

fn network_run_nonce() -> Result<String, &'static str> {
    let run_id =
        std::env::var(GITHUB_RUN_ID_ENV).map_err(|_| "network_canary_run_identity_missing")?;
    let run_attempt =
        std::env::var(GITHUB_RUN_ATTEMPT_ENV).map_err(|_| "network_canary_run_identity_missing")?;
    network_run_nonce_from(&run_id, &run_attempt)
}

fn network_run_nonce_from(run_id: &str, run_attempt: &str) -> Result<String, &'static str> {
    let valid_number = |value: &str, maximum_length: usize| {
        !value.is_empty()
            && value.len() <= maximum_length
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && value.parse::<u64>().is_ok_and(|number| number > 0)
    };
    if !valid_number(run_id, 32) || !valid_number(run_attempt, 10) {
        return Err("network_canary_run_identity_invalid");
    }
    Ok(format!("{run_id}:{run_attempt}"))
}

fn network_event_id(
    candidate_sha: &str,
    configuration_revision: &str,
    tenant_id: &str,
    finding_id: &str,
    run_nonce: &str,
) -> String {
    sha256_hex(
        format!(
            "chio.finding.network-canary-event.v1\0{candidate_sha}\0{configuration_revision}\0{tenant_id}\0{finding_id}\0{run_nonce}"
        )
        .as_bytes(),
    )
}

fn require_fresh_network_publish(outcome: &str) -> Result<(), &'static str> {
    if outcome == "applied" {
        Ok(())
    } else {
        Err("network_canary_publish_outcome_invalid")
    }
}

fn load_network_finding_pool(
    path: &Path,
    now: u64,
    run_nonce: &str,
) -> Result<(String, Vec<NetworkFindingCandidate>), &'static str> {
    let (pool_bytes, pool): (Vec<u8>, NetworkFindingPool) = read_canonical_private_bytes(path)?;
    if pool.schema != NETWORK_FINDING_POOL_SCHEMA
        || !(2..=MAX_NETWORK_FINDING_POOL_SIZE).contains(&pool.finding_paths.len())
    {
        return Err("network_canary_finding_pool_invalid");
    }
    let mut paths = BTreeSet::new();
    let mut finding_ids = BTreeSet::new();
    let mut issuer = None;
    let mut candidates = Vec::with_capacity(pool.finding_paths.len());
    for finding_path in pool.finding_paths {
        if finding_path.is_empty()
            || finding_path.len() > 4_096
            || finding_path.trim() != finding_path
            || !Path::new(&finding_path).is_absolute()
            || !paths.insert(finding_path.clone())
        {
            return Err("network_canary_finding_pool_invalid");
        }
        let (bytes, finding): (Vec<u8>, chio_finding::Finding) =
            read_canonical_private_bytes(Path::new(&finding_path))?;
        chio_finding::verify_finding(&finding).map_err(|_| "network_canary_finding_invalid")?;
        if finding.issued_at > now
            || finding.expires_at <= now
            || !finding_ids.insert(finding.finding_id.clone())
            || issuer
                .as_ref()
                .is_some_and(|expected| expected != &finding.issuer)
        {
            return Err("network_canary_finding_pool_invalid");
        }
        issuer.get_or_insert_with(|| finding.issuer.clone());
        candidates.push(NetworkFindingCandidate { bytes, finding });
    }
    candidates.sort_by_cached_key(|candidate| {
        sha256_hex(
            format!(
                "chio.finding.network-canary-selection.v1\0{run_nonce}\0{}",
                candidate.finding.finding_id
            )
            .as_bytes(),
        )
    });
    Ok((sha256_hex(&pool_bytes), candidates))
}

#[allow(clippy::too_many_arguments)]
async fn publish_fresh_network_finding(
    http: &NetworkHttpClient,
    profile: &FindingHostedProfile,
    tenant_id: &str,
    seller_key_id: &str,
    seller_key_secret: &str,
    buyer_key_id: &str,
    buyer_key_secret: &str,
    candidate_sha: &str,
    run_nonce: &str,
    candidates: Vec<NetworkFindingCandidate>,
) -> Result<FreshNetworkPublication, &'static str> {
    for candidate in candidates {
        let finding_id = candidate.finding.finding_id.as_str();
        let event_id = network_event_id(
            candidate_sha,
            &profile.release.configuration_revision,
            tenant_id,
            finding_id,
            run_nonce,
        );
        let availability_request_id = sha256_hex(format!("{event_id}:availability").as_bytes());
        let availability = network_request(
            http,
            profile,
            tenant_id,
            buyer_key_id,
            buyer_key_secret,
            &availability_request_id,
            &format!("/v1/findings/{finding_id}"),
        )
        .await?;
        let availability_status = availability.status();
        let existing = bounded_response(&availability)?;
        if availability_status == StatusCode::OK {
            if existing != candidate.bytes {
                return Err("network_canary_finding_identity_conflict");
            }
            continue;
        }
        if availability_status != StatusCode::NOT_FOUND {
            return Err("network_canary_finding_availability_failed");
        }
        let request_id = sha256_hex(format!("{event_id}:first").as_bytes());
        let Some(response) = try_publish_network_finding(
            http,
            profile,
            tenant_id,
            seller_key_id,
            seller_key_secret,
            &request_id,
            &event_id,
            &candidate.bytes,
        )
        .await?
        else {
            continue;
        };
        require_fresh_network_publish(&response.outcome)?;
        validate_network_mutation(
            &response,
            tenant_id,
            finding_id,
            &event_id,
            &request_id,
            &sha256_hex(&candidate.bytes),
        )?;
        return Ok(FreshNetworkPublication {
            candidate,
            event_id,
            response,
        });
    }
    Err("network_canary_finding_pool_exhausted")
}

fn finding_catalog_path(finding_id: &str) -> Result<String, &'static str> {
    if finding_id.len() != 64
        || !finding_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("network_canary_finding_invalid");
    }
    let mut predecessor = finding_id.as_bytes().to_vec();
    for index in (0..predecessor.len()).rev() {
        predecessor[index] = match predecessor[index] {
            b'1'..=b'9' => predecessor[index] - 1,
            b'a' => b'9',
            b'b'..=b'f' => predecessor[index] - 1,
            b'0' => {
                predecessor[index] = b'f';
                continue;
            }
            _ => return Err("network_canary_finding_invalid"),
        };
        let after = String::from_utf8(predecessor).map_err(|_| "network_canary_finding_invalid")?;
        return Ok(format!("/v1/findings?after={after}&limit=1"));
    }
    Ok("/v1/findings?limit=1".to_owned())
}

#[allow(clippy::too_many_arguments)]
async fn try_publish_network_finding(
    http: &NetworkHttpClient,
    profile: &FindingHostedProfile,
    tenant_id: &str,
    key_id: &str,
    key_secret: &str,
    request_id: &str,
    event_id: &str,
    finding: &[u8],
) -> Result<Option<NetworkMutationResponse>, &'static str> {
    let response = send_network_finding(
        http, profile, tenant_id, key_id, key_secret, request_id, event_id, finding,
    )
    .await?;
    if response.status() == StatusCode::CONFLICT {
        bounded_response(&response)?;
        return Ok(None);
    }
    parse_network_publish_response(response).map(Some)
}

#[allow(clippy::too_many_arguments)]
async fn publish_network_finding(
    http: &NetworkHttpClient,
    profile: &FindingHostedProfile,
    tenant_id: &str,
    key_id: &str,
    key_secret: &str,
    request_id: &str,
    event_id: &str,
    finding: &[u8],
) -> Result<NetworkMutationResponse, &'static str> {
    let response = send_network_finding(
        http, profile, tenant_id, key_id, key_secret, request_id, event_id, finding,
    )
    .await?;
    parse_network_publish_response(response)
}

#[allow(clippy::too_many_arguments)]
async fn send_network_finding(
    http: &NetworkHttpClient,
    profile: &FindingHostedProfile,
    tenant_id: &str,
    key_id: &str,
    key_secret: &str,
    request_id: &str,
    event_id: &str,
    finding: &[u8],
) -> Result<ContractResponse, &'static str> {
    let request = http
        .client
        .post(format!(
            "{}/v1/findings/publish",
            profile.public_endpoint.trim_end_matches('/')
        ))
        .header("Chio-Tenant-ID", tenant_id)
        .header("Chio-Request-ID", request_id)
        .header("Chio-API-Key-ID", key_id)
        .header("Chio-API-Key-Secret", key_secret)
        .header("Idempotency-Key", event_id)
        .header(
            reqwest::header::USER_AGENT,
            "chio-finding-market-network-canary/1",
        )
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(finding.to_vec())
        .build()
        .map_err(|_| "network_canary_request_invalid")?;
    http.send(request).await
}

fn parse_network_publish_response(
    response: ContractResponse,
) -> Result<NetworkMutationResponse, &'static str> {
    if response.status() != StatusCode::OK {
        return Err("network_canary_publish_failed");
    }
    let bytes = bounded_response(&response)?;
    serde_json::from_slice(&bytes).map_err(|_| "network_canary_publish_response_invalid")
}

fn validate_network_mutation(
    response: &NetworkMutationResponse,
    tenant_id: &str,
    finding_id: &str,
    event_id: &str,
    request_id: &str,
    finding_sha256: &str,
) -> Result<(), &'static str> {
    if response.schema != "chio.finding.hosted-mutation-response.v1"
        || response.request_id != request_id
        || response.tenant_id != tenant_id
        || response.operation_id != event_id
        || response.resource_id != finding_id
        || response.resource_sha256 != finding_sha256
    {
        return Err("network_canary_publish_binding_invalid");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn network_get(
    http: &NetworkHttpClient,
    profile: &FindingHostedProfile,
    tenant_id: &str,
    key_id: &str,
    key_secret: &str,
    request_id: &str,
    path: &str,
) -> Result<Vec<u8>, &'static str> {
    let response = network_request(
        http, profile, tenant_id, key_id, key_secret, request_id, path,
    )
    .await?;
    if response.status() != StatusCode::OK {
        return Err("network_canary_read_failed");
    }
    bounded_response(&response)
}

#[allow(clippy::too_many_arguments)]
async fn network_get_status(
    http: &NetworkHttpClient,
    profile: &FindingHostedProfile,
    tenant_id: &str,
    key_id: &str,
    key_secret: &str,
    request_id: &str,
    path: &str,
) -> Result<StatusCode, &'static str> {
    let response = network_request(
        http, profile, tenant_id, key_id, key_secret, request_id, path,
    )
    .await?;
    let status = response.status();
    bounded_response(&response)?;
    Ok(status)
}

#[allow(clippy::too_many_arguments)]
async fn network_request(
    http: &NetworkHttpClient,
    profile: &FindingHostedProfile,
    tenant_id: &str,
    key_id: &str,
    key_secret: &str,
    request_id: &str,
    path: &str,
) -> Result<ContractResponse, &'static str> {
    let request = http
        .client
        .get(format!(
            "{}{}",
            profile.public_endpoint.trim_end_matches('/'),
            path
        ))
        .header("Chio-Tenant-ID", tenant_id)
        .header("Chio-Request-ID", request_id)
        .header("Chio-API-Key-ID", key_id)
        .header("Chio-API-Key-Secret", key_secret)
        .header(
            reqwest::header::USER_AGENT,
            "chio-finding-market-network-canary/1",
        )
        .build()
        .map_err(|_| "network_canary_request_invalid")?;
    http.send(request).await
}

fn bounded_response(response: &ContractResponse) -> Result<Vec<u8>, &'static str> {
    if response.body().len() > MAX_NETWORK_RESPONSE_BYTES {
        return Err("network_canary_response_oversized");
    }
    Ok(response.body().to_vec())
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
                Command::Network(_) => return Err("canary_command_invalid"),
            };
            Ok(CanaryOutput::Kvm(report))
        }
        Command::Network(network) => {
            if args.job.is_some() {
                return Err("canary_job_unexpected");
            }
            network_canary(
                &profile,
                NetworkCanaryInputs {
                    finding_pool_path: &network.finding_pool,
                    tenant_id: &network.tenant_id,
                    seller_key_id_env: &network.seller_key_id_env,
                    seller_key_secret_env: &network.seller_key_secret_env,
                    buyer_key_id_env: &network.buyer_key_id_env,
                    buyer_key_secret_env: &network.buyer_key_secret_env,
                    isolation_tenant_id: &network.isolation_tenant_id,
                    isolation_buyer_key_id_env: &network.isolation_buyer_key_id_env,
                    isolation_buyer_key_secret_env: &network.isolation_buyer_key_secret_env,
                },
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
        || !candidate_binding_is_exact(&current, &job.candidate_sha, &profile.release.candidate_sha)
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

fn candidate_binding_is_exact(current: &str, job: &str, profile: &str) -> bool {
    current == job
        && job == profile
        && job.len() == 40
        && job
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
    std::io::Read::by_ref(&mut file)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "canary_file_invalid")?;
    let bytes_len = u64::try_from(bytes.len()).map_err(|_| "canary_file_invalid")?;
    if bytes_len != metadata.len() || bytes_len > MAX_FILE_BYTES {
        return Err("canary_file_invalid");
    }
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
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || !after.is_file()
        || after.mode() & 0o077 != 0
        || after.uid() != nix::unistd::geteuid().as_raw()
    {
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

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    use chio_core_types::capability::scope::MonetaryAmount;
    use chio_core_types::crypto::Keypair;
    use chio_finding::{
        compute_finding_id, sign_finding, Finding, FindingDescriptor, FindingEvidenceClass,
        FindingGuaranteeClass, FindingOutcomeClass, FINDING_SCHEMA_V1,
    };

    use super::*;

    fn signed_test_finding(seed: u8, marker: &str, now: u64) -> Finding {
        let issuer = Keypair::from_seed(&[seed; 32]);
        let mut finding = Finding {
            schema: FINDING_SCHEMA_V1.to_owned(),
            finding_id: String::new(),
            descriptor: FindingDescriptor {
                topic: format!("canary:{marker}"),
                context_sha256: sha256_hex(marker.as_bytes()),
                outcome_class: FindingOutcomeClass::PositiveResult,
            },
            guarantee_class: FindingGuaranteeClass::Asserted,
            payload_sha256: sha256_hex(format!("payload:{marker}").as_bytes()),
            payload_media_type: "application/json".to_owned(),
            evidence_receipt_ids: Vec::new(),
            evidence_checkpoint_ref: format!("checkpoint:{marker}"),
            evidence_cost: MonetaryAmount {
                units: 0,
                currency: "USD".to_owned(),
            },
            runtime_assurance_tier: None,
            evidence_class: FindingEvidenceClass::Asserted,
            replay_recipe_sha256: None,
            intent_commitment_receipt_id: None,
            bond_ref: format!("bond:{marker}"),
            status_feed_ref: format!("status:{marker}"),
            license_ref: None,
            price_hint_ref: None,
            issuer: issuer.public_key(),
            issued_at: now.saturating_sub(1),
            expires_at: now.saturating_add(3_600),
            signature: String::new(),
        };
        finding.finding_id = compute_finding_id(&finding)
            .unwrap_or_else(|error| panic!("test finding id failed: {error}"));
        sign_finding(finding, &issuer)
            .unwrap_or_else(|error| panic!("test finding signing failed: {error}"))
    }

    fn write_private_json(path: &Path, value: &impl Serialize) {
        let bytes = canonical_json_bytes(value)
            .unwrap_or_else(|error| panic!("test canonical JSON failed: {error}"));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap_or_else(|error| panic!("test private file failed: {error}"));
        file.write_all(&bytes)
            .unwrap_or_else(|error| panic!("test private write failed: {error}"));
    }

    #[test]
    fn network_event_identity_is_bound_to_the_workflow_attempt() {
        let first = network_event_id("a", "revision", "tenant", "finding", "100:1");
        let rerun = network_event_id("a", "revision", "tenant", "finding", "100:2");
        let new_run = network_event_id("a", "revision", "tenant", "finding", "101:1");
        assert_ne!(first, rerun);
        assert_ne!(first, new_run);
        assert_eq!(network_run_nonce_from("100", "2"), Ok("100:2".to_owned()));
        assert!(network_run_nonce_from("0", "1").is_err());
        assert!(network_run_nonce_from("100", "attempt-1").is_err());
    }

    #[test]
    fn network_command_requires_the_distinct_isolation_tenant_contract() {
        let args = Args::try_parse_from([
            "canary",
            "--profile",
            "/tmp/profile.json",
            "network",
            "--finding-pool",
            "/tmp/findings.json",
            "--tenant-id",
            "tenant:primary",
            "--seller-key-id-env",
            "SELLER_ID",
            "--seller-key-secret-env",
            "SELLER_SECRET",
            "--buyer-key-id-env",
            "BUYER_ID",
            "--buyer-key-secret-env",
            "BUYER_SECRET",
            "--isolation-tenant-id",
            "tenant:isolation",
            "--isolation-buyer-key-id-env",
            "ISOLATION_BUYER_ID",
            "--isolation-buyer-key-secret-env",
            "ISOLATION_BUYER_SECRET",
        ])
        .unwrap_or_else(|error| panic!("network arguments failed: {error}"));
        let Command::Network(network) = args.command else {
            panic!("network command was not parsed");
        };
        assert_eq!(network.isolation_tenant_id, "tenant:isolation");
        assert!(Args::try_parse_from([
            "canary",
            "--profile",
            "/tmp/profile.json",
            "network",
            "--finding-pool",
            "/tmp/findings.json",
            "--tenant-id",
            "tenant:primary",
            "--seller-key-id-env",
            "SELLER_ID",
            "--seller-key-secret-env",
            "SELLER_SECRET",
            "--buyer-key-id-env",
            "BUYER_ID",
            "--buyer-key-secret-env",
            "BUYER_SECRET",
        ])
        .is_err());
    }

    #[test]
    fn kvm_job_is_bound_to_the_profile_candidate() {
        let candidate = "a".repeat(40);
        let other = "b".repeat(40);
        assert!(candidate_binding_is_exact(
            &candidate, &candidate, &candidate
        ));
        assert!(!candidate_binding_is_exact(&candidate, &candidate, &other));
        assert!(!candidate_binding_is_exact(&candidate, &other, &candidate));
        assert!(!candidate_binding_is_exact(
            &"A".repeat(40),
            &"A".repeat(40),
            &"A".repeat(40)
        ));
    }

    #[test]
    fn network_canary_requires_a_fresh_first_publication() {
        assert_eq!(require_fresh_network_publish("applied"), Ok(()));
        assert_eq!(
            require_fresh_network_publish("exact_replay"),
            Err("network_canary_publish_outcome_invalid")
        );
    }

    #[test]
    fn network_http_egress_is_exact_tenant_scoped_and_fail_closed() {
        let contract = network_egress_contract("https://market.example", "tenant:primary")
            .unwrap_or_else(|error| panic!("egress contract failed: {error}"));
        assert_eq!(
            contract.tenant_egress_namespace,
            "cognition-market.network-canary:tenant:primary"
        );
        assert!(contract
            .enforce_url("https://market.example/v1/release", 0)
            .is_ok());
        assert!(contract
            .enforce_url("https://other.example/v1/release", 0)
            .is_err());
        assert!(contract
            .enforce_url("http://market.example/v1/release", 0)
            .is_err());
        assert!(network_egress_contract("https://127.0.0.1", "tenant:primary").is_err());
        assert!(network_egress_contract("https://market.example/api", "tenant:primary").is_err());
    }

    #[test]
    fn finding_pool_is_private_bounded_unique_and_single_issuer() {
        let now = 2_000_000_000;
        let directory =
            tempfile::tempdir().unwrap_or_else(|error| panic!("test directory failed: {error}"));
        let first_path = directory.path().join("first.json");
        let second_path = directory.path().join("second.json");
        let duplicate_path = directory.path().join("duplicate.json");
        let pool_path = directory.path().join("pool.json");
        let duplicate_pool_path = directory.path().join("duplicate-pool.json");
        let first = signed_test_finding(61, "first", now);
        let second = signed_test_finding(61, "second", now);
        write_private_json(&first_path, &first);
        write_private_json(&second_path, &second);
        write_private_json(&duplicate_path, &first);
        write_private_json(
            &pool_path,
            &serde_json::json!({
                "schema": NETWORK_FINDING_POOL_SCHEMA,
                "findingPaths": [
                    first_path.to_string_lossy(),
                    second_path.to_string_lossy()
                ]
            }),
        );
        let (digest, candidates) = load_network_finding_pool(&pool_path, now, "100:1")
            .unwrap_or_else(|error| panic!("test pool failed: {error}"));
        assert_eq!(digest.len(), 64);
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.finding.finding_id.clone())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([first.finding_id.clone(), second.finding_id])
        );

        write_private_json(
            &duplicate_pool_path,
            &serde_json::json!({
                "schema": NETWORK_FINDING_POOL_SCHEMA,
                "findingPaths": [
                    first_path.to_string_lossy(),
                    duplicate_path.to_string_lossy()
                ]
            }),
        );
        assert!(
            load_network_finding_pool(&duplicate_pool_path, now, "100:2").is_err(),
            "duplicate Finding identities must reject"
        );
    }

    #[test]
    fn catalog_probe_targets_the_finding_lexicographically() {
        let id = format!("{}10", "0".repeat(62));
        let expected_after = format!("{}0f", "0".repeat(62));
        assert_eq!(
            finding_catalog_path(&id),
            Ok(format!("/v1/findings?after={expected_after}&limit=1"))
        );

        let carry_id = format!("1{}", "0".repeat(63));
        let carry_after = format!("0{}", "f".repeat(63));
        assert_eq!(
            finding_catalog_path(&carry_id),
            Ok(format!("/v1/findings?after={carry_after}&limit=1"))
        );
        let alpha_id = format!("{}a", "0".repeat(63));
        let alpha_after = format!("{}9", "0".repeat(63));
        assert_eq!(
            finding_catalog_path(&alpha_id),
            Ok(format!("/v1/findings?after={alpha_after}&limit=1"))
        );
        assert_eq!(
            finding_catalog_path(&"0".repeat(64)),
            Ok("/v1/findings?limit=1".to_owned())
        );
        assert!(finding_catalog_path(&"g".repeat(64)).is_err());
    }
}
