#![allow(clippy::expect_used, clippy::too_many_arguments, clippy::unwrap_used)]

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chio_core::capability::{
    scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    lineage::ChildRequestReceipt, lineage::ChildRequestReceiptBody,
};
use chio_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
use chio_core::{canonical_json_bytes, sha256_hex};
use chio_kernel::BudgetStore;
use chio_store_sqlite::SqliteBudgetStore;
use chio_test_support::loopback::{reserve_listen_addr, skip_when_loopback_bind_denied};
use reqwest::blocking::Client;
use reqwest::header::AUTHORIZATION;
use serde_json::{json, Value};

const TRUST_CLUSTER_QUALIFICATION_RUNS: usize = 5;
const MULTI_REGION_PARTITION_SAMPLES: usize = 20;
const CLUSTER_NODE_ID_HEADER: &str = "x-chio-cluster-node-id";
const CLUSTER_AUTH_ISSUED_AT_HEADER: &str = "x-chio-cluster-auth-issued-at";
const CLUSTER_AUTH_SIGNATURE_HEADER: &str = "x-chio-cluster-auth-signature";
const CLUSTER_AUTH_TERM_HEADER: &str = "x-chio-cluster-auth-term";
const CLUSTER_AUTH_SCHEME: &str = "chio.cluster.peer.v1";

fn internal_peer_registry() -> &'static Mutex<HashMap<String, String>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn trust_cluster_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn register_internal_peer(base_url: &str, peer_urls: &[String]) {
    let mut registry = internal_peer_registry()
        .lock()
        .expect("lock internal peer registry");
    if let Some(peer_url) = peer_urls.first() {
        registry.insert(base_url.to_string(), peer_url.clone());
    } else {
        registry.remove(base_url);
    }
}

fn internal_peer_node_id(base_url: &str) -> Option<String> {
    internal_peer_registry()
        .lock()
        .expect("lock internal peer registry")
        .get(base_url)
        .cloned()
}

fn cluster_peer_auth_signature(
    service_token: &str,
    node_id: &str,
    endpoint: &str,
    issued_at: i64,
    term: Option<u64>,
) -> String {
    let payload = canonical_json_bytes(&json!({
        "scheme": CLUSTER_AUTH_SCHEME,
        "serviceToken": service_token,
        "nodeId": node_id,
        "endpoint": endpoint,
        "issuedAt": issued_at,
        "term": term,
    }))
    .expect("encode cluster peer auth payload");
    sha256_hex(&payload)
}

fn unique_test_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("chio-cli-trust-cluster-{nonce}"))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root")
        .to_path_buf()
}

fn reserve_cluster_nodes(count: usize) -> Vec<(SocketAddr, String)> {
    let mut nodes = (0..count)
        .map(|_| {
            let addr = reserve_listen_addr();
            (addr, format!("http://{addr}"))
        })
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| left.1.cmp(&right.1));
    nodes
}

struct ServerGuard {
    child: Child,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_trust_service(
    listen: SocketAddr,
    service_token: &str,
    receipt_db_path: &Path,
    revocation_db_path: &Path,
    authority_db_path: &Path,
    budget_db_path: &Path,
    policy_path: Option<&Path>,
    advertise_url: &str,
    peer_urls: &[String],
) -> ServerGuard {
    let mut args = vec![
        "--receipt-db".to_string(),
        receipt_db_path
            .to_str()
            .expect("receipt db path")
            .to_string(),
        "--revocation-db".to_string(),
        revocation_db_path
            .to_str()
            .expect("revocation db path")
            .to_string(),
        "--authority-db".to_string(),
        authority_db_path
            .to_str()
            .expect("authority db path")
            .to_string(),
        "--budget-db".to_string(),
        budget_db_path.to_str().expect("budget db path").to_string(),
        "trust".to_string(),
        "serve".to_string(),
        "--listen".to_string(),
        listen.to_string(),
        "--service-token".to_string(),
        service_token.to_string(),
        "--advertise-url".to_string(),
        advertise_url.to_string(),
        "--allow-local-peer-urls".to_string(),
        "--cluster-sync-interval-ms".to_string(),
        "2000".to_string(),
    ];
    for peer_url in peer_urls {
        args.push("--peer-url".to_string());
        args.push(peer_url.clone());
    }
    if let Some(policy_path) = policy_path {
        args.push("--policy".to_string());
        args.push(policy_path.to_str().expect("policy path").to_string());
    }
    register_internal_peer(advertise_url, peer_urls);

    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn chio trust serve");

    ServerGuard { child }
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn wait_until<F>(label: &str, timeout: Duration, mut condition: F)
where
    F: FnMut() -> bool,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("condition `{label}` not satisfied before timeout");
}

fn wait_until_with_diagnostics<F, D>(
    label: &str,
    timeout: Duration,
    mut condition: F,
    diagnostics: D,
) where
    F: FnMut() -> bool,
    D: Fn() -> Value,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let diagnostics = diagnostics();
    panic!(
        "condition `{label}` not satisfied before timeout\n{}",
        serde_json::to_string_pretty(&diagnostics).expect("serialize timeout diagnostics")
    );
}

fn measure_until_with_diagnostics<F, D>(
    label: &str,
    timeout: Duration,
    mut condition: F,
    diagnostics: D,
) -> u64
where
    F: FnMut() -> bool,
    D: Fn() -> Value,
{
    let started_at = Instant::now();
    let deadline = started_at + timeout;
    while Instant::now() < deadline {
        if condition() {
            return started_at.elapsed().as_millis() as u64;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let diagnostics = diagnostics();
    panic!(
        "condition `{label}` not satisfied before timeout\n{}",
        serde_json::to_string_pretty(&diagnostics).expect("serialize timeout diagnostics")
    );
}

fn get_json(client: &Client, url: &str, token: &str) -> Value {
    client
        .get(url)
        .header(AUTHORIZATION, bearer(token))
        .send()
        .expect("send GET")
        .error_for_status()
        .expect("successful GET")
        .json()
        .expect("decode json")
}

fn try_get_json(client: &Client, url: &str, token: &str) -> Option<Value> {
    client
        .get(url)
        .header(AUTHORIZATION, bearer(token))
        .send()
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .ok()
}

fn try_internal_cluster_status(client: &Client, base_url: &str, token: &str) -> Option<Value> {
    let endpoint = "/v1/internal/cluster/status";
    let node_id = internal_peer_node_id(base_url)?;
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs() as i64;
    let signature = cluster_peer_auth_signature(token, &node_id, endpoint, issued_at, None);
    client
        .get(format!("{base_url}{endpoint}"))
        .header(CLUSTER_NODE_ID_HEADER, node_id)
        .header(CLUSTER_AUTH_ISSUED_AT_HEADER, issued_at.to_string())
        .header(CLUSTER_AUTH_SIGNATURE_HEADER, signature)
        .send()
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .ok()
}

fn set_cluster_partition(
    client: &Client,
    base_url: &str,
    token: &str,
    blocked_peer_urls: &[String],
) -> Value {
    let endpoint = "/v1/internal/cluster/partition";
    let node_id =
        internal_peer_node_id(base_url).expect("registered internal peer node id for partition");
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs() as i64;
    let signature = cluster_peer_auth_signature(token, &node_id, endpoint, issued_at, Some(0));
    client
        .post(format!("{base_url}{endpoint}"))
        .header(CLUSTER_NODE_ID_HEADER, node_id)
        .header(CLUSTER_AUTH_ISSUED_AT_HEADER, issued_at.to_string())
        .header(CLUSTER_AUTH_SIGNATURE_HEADER, signature)
        .header(CLUSTER_AUTH_TERM_HEADER, "0")
        .json(&json!({ "blockedPeerUrls": blocked_peer_urls }))
        .send()
        .expect("send cluster partition POST")
        .error_for_status()
        .expect("successful cluster partition POST")
        .json()
        .expect("decode cluster partition response")
}

fn post_internal_json_status(
    client: &Client,
    base_url: &str,
    token: &str,
    endpoint: &str,
    node_id: &str,
    term: Option<u64>,
    body: &Value,
) -> (u16, String) {
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs() as i64;
    let signature = cluster_peer_auth_signature(token, node_id, endpoint, issued_at, term);
    let mut request = client
        .post(format!("{base_url}{endpoint}"))
        .header(CLUSTER_NODE_ID_HEADER, node_id)
        .header(CLUSTER_AUTH_ISSUED_AT_HEADER, issued_at.to_string())
        .header(CLUSTER_AUTH_SIGNATURE_HEADER, signature);
    if let Some(term) = term {
        request = request.header(CLUSTER_AUTH_TERM_HEADER, term.to_string());
    }
    let response = request.json(body).send().expect("send internal POST");
    let status = response.status().as_u16();
    let body = response.text().unwrap_or_default();
    (status, body)
}

fn post_json_status(client: &Client, url: &str, token: &str, body: &Value) -> (u16, String) {
    let response = client
        .post(url)
        .header(AUTHORIZATION, bearer(token))
        .json(body)
        .send()
        .expect("send POST");
    let status = response.status().as_u16();
    let body = response.text().unwrap_or_default();
    (status, body)
}

fn cluster_status_diagnostics(client: &Client, urls: &[String], token: &str) -> Value {
    Value::Array(
        urls.iter()
            .map(|base_url| {
                json!({
                    "baseUrl": base_url,
                    "health": try_get_json(client, &format!("{base_url}/health"), token),
                    "clusterStatus": try_internal_cluster_status(client, base_url, token),
                })
            })
            .collect(),
    )
}

fn tool_receipt_visible(
    client: &Client,
    base_url: &str,
    token: &str,
    capability_id: &str,
    receipt_id: &str,
) -> bool {
    try_get_json(
        client,
        &format!(
            "{base_url}/v1/receipts/tools?capabilityId={capability_id}&toolServer=wrapped-http-mock&toolName=echo_json&decision=allow&limit=10"
        ),
        token,
    )
    .and_then(|value| value["receipts"].as_array().cloned())
    .map(|receipts| {
        receipts
            .iter()
            .any(|receipt| receipt["id"].as_str() == Some(receipt_id))
    })
    .unwrap_or(false)
}

fn percentile_nearest_rank(samples: &[u64], percentile: usize) -> u64 {
    assert!(
        !samples.is_empty(),
        "percentiles require at least one sample"
    );
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = ((percentile * sorted.len()).saturating_add(99)) / 100;
    let index = rank.saturating_sub(1).min(sorted.len().saturating_sub(1));
    sorted[index]
}

fn latency_summary(samples: &[u64]) -> Value {
    let min = *samples.iter().min().expect("latency samples");
    let max = *samples.iter().max().expect("latency samples");
    json!({
        "count": samples.len(),
        "minMs": min,
        "maxMs": max,
        "p50Ms": percentile_nearest_rank(samples, 50),
        "p95Ms": percentile_nearest_rank(samples, 95),
        "p99Ms": percentile_nearest_rank(samples, 99),
    })
}

fn multi_region_qualification_report_path() -> PathBuf {
    workspace_root()
        .join("target")
        .join("trust-cluster-qualification")
        .join("298-multi-region-qualification.json")
}

fn write_multi_region_qualification_report(report: &Value) -> PathBuf {
    let path = multi_region_qualification_report_path();
    fs::create_dir_all(path.parent().expect("report parent directory"))
        .expect("create qualification report directory");
    fs::write(
        &path,
        serde_json::to_vec_pretty(report).expect("serialize qualification report"),
    )
    .expect("write qualification report");
    path
}

fn try_tool_receipt_count(client: &Client, base_url: &str, token: &str) -> Option<u64> {
    try_get_json(
        client,
        &format!("{base_url}/v1/receipts/tools?limit=100"),
        token,
    )?["count"]
        .as_u64()
}

fn node_diagnostics(client: &Client, base_url: &str, token: &str, capability_id: &str) -> Value {
    json!({
        "health": try_get_json(client, &format!("{base_url}/health"), token),
        "clusterStatus": try_internal_cluster_status(client, base_url, token),
        "lineage": try_get_json(
            client,
            &format!("{base_url}/v1/lineage/{capability_id}/chain"),
            token,
        ),
        "budgets": try_get_json(
            client,
            &format!("{base_url}/v1/budgets?capabilityId={capability_id}&limit=10"),
            token,
        ),
    })
}

fn cluster_timeout_diagnostics(
    client: &Client,
    leader_url: &str,
    follower_url: &str,
    token: &str,
    capability_id: &str,
) -> Value {
    json!({
        "leaderUrl": leader_url,
        "followerUrl": follower_url,
        "leader": node_diagnostics(client, leader_url, token, capability_id),
        "follower": node_diagnostics(client, follower_url, token, capability_id),
    })
}

fn wait_for_node_health(client: &Client, base_url: &str, token: &str, label: &str) {
    wait_until_with_diagnostics(
        label,
        Duration::from_secs(30),
        || try_get_json(client, &format!("{base_url}/health"), token).is_some(),
        || {
            json!({
                "baseUrl": base_url,
                "health": try_get_json(client, &format!("{base_url}/health"), token),
                "clusterStatus": try_internal_cluster_status(client, base_url, token),
            })
        },
    );
}

fn post_json(client: &Client, url: &str, token: &str, body: &Value) -> Value {
    let mut last_error = None;
    for _ in 0..120 {
        match client
            .post(url)
            .header(AUTHORIZATION, bearer(token))
            .json(body)
            .send()
        {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    return response.json().expect("decode json");
                }
                let response_body = response.text().unwrap_or_default();
                last_error = Some(format!("{status} body={response_body}"));
            }
            Err(error) => last_error = Some(error.to_string()),
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!(
        "POST {url} did not succeed after retries: {}",
        last_error.unwrap_or_else(|| "unknown error".to_string())
    );
}

fn post_json_eventually_ok_with_diagnostics<D>(
    client: &Client,
    url: &str,
    token: &str,
    body: &Value,
    label: &str,
    timeout: Duration,
    diagnostics: D,
) -> Value
where
    D: Fn() -> Value,
{
    let deadline = Instant::now() + timeout;
    let mut last_error = None;
    while Instant::now() < deadline {
        match client
            .post(url)
            .header(AUTHORIZATION, bearer(token))
            .json(body)
            .send()
        {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    return response.json().expect("decode json");
                }
                let response_body = response.text().unwrap_or_default();
                last_error = Some(format!("{status} body={response_body}"));
            }
            Err(error) => last_error = Some(error.to_string()),
        }
        thread::sleep(Duration::from_millis(250));
    }
    let diagnostics = diagnostics();
    panic!(
        "POST {url} did not eventually succeed for `{label}`: {}\n{}",
        last_error.unwrap_or_else(|| "unknown error".to_string()),
        serde_json::to_string_pretty(&diagnostics).expect("serialize timeout diagnostics")
    );
}

fn wait_for_leader_convergence(
    client: &Client,
    service_token: &str,
    url_a: &str,
    url_b: &str,
    expected_leader_url: &str,
) {
    let urls = vec![url_a.to_string(), url_b.to_string()];
    wait_until_with_diagnostics(
        "cluster leader convergence",
        Duration::from_secs(90),
        || {
            let Some(health_a) = try_get_json(client, &format!("{url_a}/health"), service_token)
            else {
                return false;
            };
            let Some(health_b) = try_get_json(client, &format!("{url_b}/health"), service_token)
            else {
                return false;
            };
            let Some(status_a) = try_internal_cluster_status(client, url_a, service_token) else {
                return false;
            };
            let Some(status_b) = try_internal_cluster_status(client, url_b, service_token) else {
                return false;
            };
            health_a.get("leaderUrl").and_then(Value::as_str) == Some(expected_leader_url)
                && health_b.get("leaderUrl").and_then(Value::as_str) == Some(expected_leader_url)
                && status_a.get("leaderUrl").and_then(Value::as_str) == Some(expected_leader_url)
                && status_b.get("leaderUrl").and_then(Value::as_str) == Some(expected_leader_url)
                && status_a.get("electionTerm").and_then(Value::as_u64)
                    == status_b.get("electionTerm").and_then(Value::as_u64)
                && status_a.get("hasQuorum").and_then(Value::as_bool) == Some(true)
                && status_b.get("hasQuorum").and_then(Value::as_bool) == Some(true)
        },
        || cluster_status_diagnostics(client, &urls, service_token),
    );
}

fn wait_for_cluster_leader_convergence(
    client: &Client,
    service_token: &str,
    urls: &[String],
    label: &str,
) -> String {
    let mut converged_leader = None;
    wait_until_with_diagnostics(
        label,
        Duration::from_secs(90),
        || {
            let mut observed = None::<String>;
            for base_url in urls {
                let Some(health) =
                    try_get_json(client, &format!("{base_url}/health"), service_token)
                else {
                    return false;
                };
                let Some(current_leader) = health.get("leaderUrl").and_then(Value::as_str) else {
                    return false;
                };
                // Also require the internal cluster status endpoint to be queryable on every
                // node and to agree on the same leader. Without this, callers can race between
                // /health (which is up early) and /v1/internal/cluster/status (which depends on
                // the cluster state machine being initialized) and observe a transient None.
                let Some(status) = try_internal_cluster_status(client, base_url, service_token)
                else {
                    return false;
                };
                if status.get("leaderUrl").and_then(Value::as_str) != Some(current_leader) {
                    return false;
                }
                if status.get("hasQuorum").and_then(Value::as_bool) != Some(true) {
                    return false;
                }
                if let Some(expected_leader) = observed.as_deref() {
                    if expected_leader != current_leader {
                        return false;
                    }
                } else {
                    observed = Some(current_leader.to_string());
                }
            }
            converged_leader = observed;
            converged_leader.is_some()
        },
        || cluster_status_diagnostics(client, urls, service_token),
    );
    converged_leader.expect("converged leader url")
}

/// Polls `try_internal_cluster_status` against `base_url` until it returns `Some`.
///
/// The internal cluster status endpoint can transiently fail with HTTP errors during cluster
/// state transitions (initial bring-up, leader failover, follower restart) even when the node's
/// `/health` endpoint is already up. Single-shot callers that immediately panic on `None` are
/// the source of intermittent flakes.
/// This helper bounds the wait with a deadline and returns the first non-`None` snapshot.
fn wait_for_internal_cluster_status(
    client: &Client,
    base_url: &str,
    token: &str,
    label: &str,
) -> Value {
    let timeout = Duration::from_secs(30);
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = try_internal_cluster_status(client, base_url, token) {
            return status;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let diagnostics = json!({
        "baseUrl": base_url,
        "health": try_get_json(client, &format!("{base_url}/health"), token),
        "clusterStatus": try_internal_cluster_status(client, base_url, token),
    });
    panic!(
        "internal cluster status `{label}` did not become available before timeout\n{}",
        serde_json::to_string_pretty(&diagnostics).expect("serialize timeout diagnostics")
    );
}

fn sample_receipt(id: &str, capability_id: &str) -> ChioReceipt {
    let keypair = Keypair::generate();
    let action = ToolCallAction::from_parameters(json!({"message": "cluster"}))
        .expect("hash receipt parameters");
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1,
            capability_id: capability_id.to_string(),
            tool_server: "wrapped-http-mock".to_string(),
            tool_name: "echo_json".to_string(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-hash".to_string(),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .expect("sign receipt")
}

fn sample_child_receipt(id: &str, request_suffix: &str) -> ChildRequestReceipt {
    let keypair = Keypair::generate();
    ChildRequestReceipt::sign(
        ChildRequestReceiptBody {
            id: id.to_string(),
            timestamp: 2,
            session_id: SessionId::new(format!("sess-{request_suffix}")),
            parent_request_id: RequestId::new(format!("parent-{request_suffix}")),
            request_id: RequestId::new(format!("child-{request_suffix}")),
            operation_kind: OperationKind::CreateMessage,
            terminal_state: OperationTerminalState::Completed,
            outcome_hash: "outcome-hash".to_string(),
            policy_hash: "policy-hash".to_string(),
            metadata: Some(json!({ "source": "trust-cluster" })),
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .expect("sign child receipt")
}

fn sample_capability(id: &str, subject_kp: &Keypair, issuer_kp: &Keypair) -> CapabilityToken {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer_kp.public_key(),
            subject: subject_kp.public_key(),
            scope: ChioScope::default(),
            issued_at: 1_000,
            expires_at: 9_000,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        issuer_kp,
    )
    .expect("sign capability")
}

fn assert_write_visibility_metadata(response: &Value) -> &str {
    assert_eq!(response["visibleAtLeader"].as_bool(), Some(true));
    let leader_url = response["leaderUrl"].as_str().expect("leaderUrl metadata");
    assert_eq!(response["handledBy"].as_str(), Some(leader_url));
    leader_url
}

fn assert_expected_write_visibility_metadata(response: &Value, leader_url: &str) {
    assert_eq!(assert_write_visibility_metadata(response), leader_url);
}

fn assert_leader_visible_metadata(response: &Value) {
    assert_eq!(response["visibleAtLeader"].as_bool(), Some(true));
    assert!(response["leaderUrl"].as_str().is_some());
    assert!(response["handledBy"].as_str().is_some());
}

fn assert_budget_commit_metadata(
    response: &Value,
    expected_authority_id: &str,
    quorum_size: u64,
    committed_nodes: u64,
    expected_witnesses: &[&str],
) {
    let commit = &response["budgetCommit"];
    assert_eq!(commit["authorityId"].as_str(), Some(expected_authority_id));
    assert_eq!(commit["budgetTerm"], commit["leaseEpoch"]);
    assert_eq!(commit["quorumCommitted"].as_bool(), Some(true));
    assert_eq!(commit["quorumSize"].as_u64(), Some(quorum_size));
    assert_eq!(commit["committedNodes"].as_u64(), Some(committed_nodes));
    assert!(
        commit["budgetSeq"].as_u64().unwrap_or(0) > 0,
        "expected positive budget seq in commit metadata: {commit}"
    );
    assert_eq!(commit["commitIndex"], commit["budgetSeq"]);
    let witnesses = commit["witnessUrls"]
        .as_array()
        .expect("budget commit witnesses array")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert_eq!(witnesses.len(), expected_witnesses.len());
    for witness in expected_witnesses {
        assert!(
            witnesses.contains(witness),
            "missing witness `{witness}` in budget commit metadata: {commit}"
        );
    }
}

fn assert_budget_authority_metadata(
    response: &Value,
    expected_authority_id: &str,
    expected_guarantee_level: &str,
) {
    let authority = &response["budgetAuthority"];
    assert_eq!(
        authority["authorityId"].as_str(),
        Some(expected_authority_id)
    );
    assert_eq!(authority["leaderUrl"].as_str(), Some(expected_authority_id));
    assert_eq!(
        authority["guaranteeLevel"].as_str(),
        Some(expected_guarantee_level)
    );
    assert!(
        authority["budgetTerm"].as_u64().unwrap_or(0) > 0,
        "expected positive budget term in authority metadata: {authority}"
    );
    assert_eq!(authority["leaseEpoch"], authority["budgetTerm"]);
    assert!(
        authority["leaseId"]
            .as_str()
            .unwrap_or_default()
            .contains(expected_authority_id),
        "expected lease id to include authority id: {authority}"
    );
}

fn assert_authority_generation(client: &Client, base_url: &str, token: &str, expected: u64) {
    let authority = get_json(client, &format!("{base_url}/v1/authority"), token);
    assert_eq!(authority["generation"].as_u64(), Some(expected));
}

fn assert_tool_receipt_visible(
    client: &Client,
    base_url: &str,
    token: &str,
    capability_id: &str,
    receipt_id: &str,
) {
    let receipts = get_json(
        client,
        &format!(
            "{base_url}/v1/receipts/tools?capabilityId={capability_id}&toolServer=wrapped-http-mock&toolName=echo_json&decision=allow&limit=10"
        ),
        token,
    );
    let receipts = receipts["receipts"]
        .as_array()
        .expect("tool receipts array");
    assert!(receipts
        .iter()
        .any(|receipt| receipt["id"].as_str() == Some(receipt_id)));
}

fn assert_child_receipt_visible(
    client: &Client,
    base_url: &str,
    token: &str,
    request_id: &str,
    receipt_id: &str,
) {
    let url = format!("{base_url}/v1/receipts/children?requestId={request_id}&limit=10");
    wait_until_with_diagnostics(
        &format!("child receipt {receipt_id} visible for {request_id}"),
        Duration::from_secs(30),
        || {
            let Some(receipts) = try_get_json(client, &url, token) else {
                return false;
            };
            receipts["receipts"]
                .as_array()
                .map(|receipts| {
                    receipts
                        .iter()
                        .any(|receipt| receipt["id"].as_str() == Some(receipt_id))
                })
                .unwrap_or(false)
        },
        || {
            json!({
                "url": url,
                "health": try_get_json(client, &format!("{base_url}/health"), token),
                "children": try_get_json(client, &url, token),
            })
        },
    );
}

fn assert_revocation_visible(client: &Client, base_url: &str, token: &str, capability_id: &str) {
    let revocations = get_json(
        client,
        &format!("{base_url}/v1/revocations?capabilityId={capability_id}&limit=10"),
        token,
    );
    assert_eq!(revocations["revoked"].as_bool(), Some(true));
    assert!(revocations["revocations"]
        .as_array()
        .expect("revocations array")
        .iter()
        .any(|entry| entry["capabilityId"].as_str() == Some(capability_id)));
}

fn assert_budget_invocation_count(
    client: &Client,
    base_url: &str,
    token: &str,
    capability_id: &str,
    grant_index: u64,
    expected: u64,
) {
    let budgets = get_json(
        client,
        &format!("{base_url}/v1/budgets?capabilityId={capability_id}&limit=10"),
        token,
    );
    let usage = budgets["usages"]
        .as_array()
        .expect("budgets array")
        .iter()
        .find(|usage| usage["grantIndex"].as_u64() == Some(grant_index))
        .expect("matching budget usage");
    assert_eq!(usage["invocationCount"].as_u64(), Some(expected));
}

fn assert_budget_totals(
    client: &Client,
    base_url: &str,
    token: &str,
    capability_id: &str,
    grant_index: u64,
    expected_exposure: u64,
    expected_realized_spend: u64,
) {
    let budgets = get_json(
        client,
        &format!("{base_url}/v1/budgets?capabilityId={capability_id}&limit=10"),
        token,
    );
    let usage = budgets["usages"]
        .as_array()
        .expect("budgets array")
        .iter()
        .find(|usage| usage["grantIndex"].as_u64() == Some(grant_index))
        .expect("matching budget usage");
    assert_eq!(
        usage["totalExposureCharged"].as_u64(),
        Some(expected_exposure)
    );
    assert_eq!(
        usage["totalRealizedSpend"].as_u64(),
        Some(expected_realized_spend)
    );
}

#[cfg(unix)]
fn send_signal(child: &Child, signal: &str) {
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(child.id().to_string())
        .status()
        .expect("send signal to child");
    assert!(
        status.success(),
        "signal {signal} should succeed for child {}",
        child.id()
    );
}

fn assert_lineage_visible(client: &Client, base_url: &str, token: &str, capability_id: &str) {
    wait_until_with_diagnostics(
        &format!("lineage visible for {capability_id}"),
        Duration::from_secs(20),
        || {
            let Some(lineage) = try_get_json(
                client,
                &format!("{base_url}/v1/lineage/{capability_id}"),
                token,
            ) else {
                return false;
            };
            lineage["capabilityId"]
                .as_str()
                .or_else(|| lineage["capability_id"].as_str())
                == Some(capability_id)
        },
        || node_diagnostics(client, base_url, token, capability_id),
    );
}

fn run_trust_control_cluster_proving_scenario(run_index: usize, run_total: usize) {
    println!("trust-cluster proving run {run_index}/{run_total}");

    let dir = unique_test_dir().join(format!("run-{run_index}-of-{run_total}"));
    fs::create_dir_all(&dir).expect("create test dir");
    let addr_a = reserve_listen_addr();
    let addr_b = reserve_listen_addr();
    let url_a = format!("http://{addr_a}");
    let url_b = format!("http://{addr_b}");
    let expected_leader_url = std::cmp::min(url_a.clone(), url_b.clone());
    let service_token = "cluster-token";

    let receipt_db_a = dir.join("receipts-a.sqlite3");
    let revocation_db_a = dir.join("revocations-a.sqlite3");
    let authority_db_a = dir.join("authority-a.sqlite3");
    let budget_db_a = dir.join("budgets-a.sqlite3");
    let receipt_db_b = dir.join("receipts-b.sqlite3");
    let revocation_db_b = dir.join("revocations-b.sqlite3");
    let authority_db_b = dir.join("authority-b.sqlite3");
    let budget_db_b = dir.join("budgets-b.sqlite3");

    let mut server_a = Some(spawn_trust_service(
        addr_a,
        service_token,
        &receipt_db_a,
        &revocation_db_a,
        &authority_db_a,
        &budget_db_a,
        None,
        &url_a,
        std::slice::from_ref(&url_b.to_string()),
    ));
    let mut server_b = Some(spawn_trust_service(
        addr_b,
        service_token,
        &receipt_db_b,
        &revocation_db_b,
        &authority_db_b,
        &budget_db_b,
        None,
        &url_b,
        std::slice::from_ref(&url_a.to_string()),
    ));

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("build client");

    wait_until("node A health reachable", Duration::from_secs(20), || {
        try_get_json(&client, &format!("{url_a}/health"), service_token).is_some()
    });
    wait_until("node B health reachable", Duration::from_secs(20), || {
        try_get_json(&client, &format!("{url_b}/health"), service_token).is_some()
    });
    wait_for_leader_convergence(&client, service_token, &url_a, &url_b, &expected_leader_url);

    let leader_url = expected_leader_url;
    let follower_url = if leader_url == url_a {
        url_b.clone()
    } else {
        url_a.clone()
    };

    assert_authority_generation(&client, &leader_url, service_token, 1);

    let rotated_leader = post_json_eventually_ok_with_diagnostics(
        &client,
        &format!("{leader_url}/v1/authority"),
        service_token,
        &json!({}),
        "leader authority rotation after cluster convergence",
        Duration::from_secs(30),
        || cluster_status_diagnostics(&client, &[url_a.clone(), url_b.clone()], service_token),
    );
    assert_eq!(rotated_leader["generation"].as_u64(), Some(2));
    assert_expected_write_visibility_metadata(&rotated_leader, &leader_url);
    assert_authority_generation(&client, &leader_url, service_token, 2);

    let rotated_follower = post_json_eventually_ok_with_diagnostics(
        &client,
        &format!("{follower_url}/v1/authority"),
        service_token,
        &json!({}),
        "follower authority rotation after leader rotation",
        Duration::from_secs(30),
        || cluster_status_diagnostics(&client, &[url_a.clone(), url_b.clone()], service_token),
    );
    assert_eq!(rotated_follower["generation"].as_u64(), Some(3));
    assert_expected_write_visibility_metadata(&rotated_follower, &leader_url);
    assert_authority_generation(&client, &leader_url, service_token, 3);

    wait_until(
        "authority generation replication",
        Duration::from_secs(90),
        || {
            try_get_json(
                &client,
                &format!("{follower_url}/v1/authority"),
                service_token,
            )
            .and_then(|value| value["generation"].as_u64())
                == Some(3)
        },
    );

    // `ChioReceipt::sign` overwrites the supplied id with the canonical content hash
    // (`chio_receipt_id`) and folds the input string in as a signing nonce. Match
    // visibility against the stored id, not the nonce.
    let leader_tool = sample_receipt("cluster-tool-leader", "cap-tool-leader");
    let leader_tool_id = leader_tool.id.clone();
    let leader_tool_receipt = serde_json::to_value(&leader_tool).expect("tool receipt json");
    let stored_leader_tool = post_json(
        &client,
        &format!("{leader_url}/v1/receipts/tools"),
        service_token,
        &leader_tool_receipt,
    );
    assert_eq!(stored_leader_tool["stored"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&stored_leader_tool, &leader_url);
    assert_tool_receipt_visible(
        &client,
        &leader_url,
        service_token,
        "cap-tool-leader",
        &leader_tool_id,
    );

    let follower_tool = sample_receipt("cluster-tool-follower", "cap-tool-follower");
    let follower_tool_id = follower_tool.id.clone();
    let follower_tool_receipt = serde_json::to_value(&follower_tool).expect("tool receipt json");
    let stored_follower_tool = post_json(
        &client,
        &format!("{follower_url}/v1/receipts/tools"),
        service_token,
        &follower_tool_receipt,
    );
    assert_eq!(stored_follower_tool["stored"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&stored_follower_tool, &leader_url);
    assert_tool_receipt_visible(
        &client,
        &leader_url,
        service_token,
        "cap-tool-follower",
        &follower_tool_id,
    );

    wait_until("tool receipt replication", Duration::from_secs(90), || {
        try_get_json(
            &client,
            &format!("{follower_url}/v1/receipts/tools?limit=10"),
            service_token,
        )
        .and_then(|value| value["count"].as_u64())
            == Some(2)
    });

    let leader_child_receipt =
        serde_json::to_value(sample_child_receipt("cluster-child-leader", "leader"))
            .expect("child receipt json");
    let stored_leader_child = post_json(
        &client,
        &format!("{leader_url}/v1/receipts/children"),
        service_token,
        &leader_child_receipt,
    );
    assert_eq!(stored_leader_child["stored"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&stored_leader_child, &leader_url);
    assert_child_receipt_visible(
        &client,
        &leader_url,
        service_token,
        "child-leader",
        "cluster-child-leader",
    );

    let follower_child_receipt =
        serde_json::to_value(sample_child_receipt("cluster-child-follower", "follower"))
            .expect("child receipt json");
    let stored_follower_child = post_json(
        &client,
        &format!("{follower_url}/v1/receipts/children"),
        service_token,
        &follower_child_receipt,
    );
    assert_eq!(stored_follower_child["stored"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&stored_follower_child, &leader_url);
    assert_child_receipt_visible(
        &client,
        &leader_url,
        service_token,
        "child-follower",
        "cluster-child-follower",
    );

    wait_until("child receipt replication", Duration::from_secs(90), || {
        try_get_json(
            &client,
            &format!("{follower_url}/v1/receipts/children?limit=10"),
            service_token,
        )
        .and_then(|value| value["count"].as_u64())
            == Some(2)
    });

    let issuer_kp = Keypair::generate();
    let root_kp = Keypair::generate();
    let child_kp = Keypair::generate();
    let root_capability = sample_capability("cluster-lineage-root", &root_kp, &issuer_kp);
    let child_capability = sample_capability("cluster-lineage-child", &child_kp, &issuer_kp);

    let stored_root_lineage = post_json(
        &client,
        &format!("{leader_url}/v1/lineage"),
        service_token,
        &json!({
            "capability": root_capability,
        }),
    );
    assert_eq!(stored_root_lineage["stored"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&stored_root_lineage, &leader_url);
    assert_lineage_visible(&client, &leader_url, service_token, "cluster-lineage-root");

    let stored_child_lineage = post_json(
        &client,
        &format!("{follower_url}/v1/lineage"),
        service_token,
        &json!({
            "capability": child_capability,
            "parentCapabilityId": "cluster-lineage-root",
        }),
    );
    assert_eq!(stored_child_lineage["stored"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&stored_child_lineage, &leader_url);
    assert_lineage_visible(&client, &leader_url, service_token, "cluster-lineage-child");

    wait_until_with_diagnostics(
        "lineage replication",
        Duration::from_secs(90),
        || {
            let Some(lineage) = try_get_json(
                &client,
                &format!("{follower_url}/v1/lineage/cluster-lineage-child/chain"),
                service_token,
            ) else {
                return false;
            };
            let Some(chain) = lineage.as_array() else {
                return false;
            };
            chain.len() == 2
                && chain[0]["capability_id"].as_str() == Some("cluster-lineage-root")
                && chain[1]["capability_id"].as_str() == Some("cluster-lineage-child")
        },
        || {
            cluster_timeout_diagnostics(
                &client,
                &leader_url,
                &follower_url,
                service_token,
                "cluster-lineage-child",
            )
        },
    );

    let revoked_leader = post_json(
        &client,
        &format!("{leader_url}/v1/revocations"),
        service_token,
        &json!({"capabilityId": "cap-revoke-leader"}),
    );
    assert_eq!(revoked_leader["revoked"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&revoked_leader, &leader_url);
    assert_revocation_visible(&client, &leader_url, service_token, "cap-revoke-leader");

    let revoked_follower = post_json(
        &client,
        &format!("{follower_url}/v1/revocations"),
        service_token,
        &json!({"capabilityId": "cap-revoke-follower"}),
    );
    assert_eq!(revoked_follower["revoked"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&revoked_follower, &leader_url);
    assert_revocation_visible(&client, &leader_url, service_token, "cap-revoke-follower");

    wait_until_with_diagnostics(
        "revocation replication",
        Duration::from_secs(120),
        || {
            let revocation_visible = |value: &Value, capability_id: &str| {
                value["revoked"].as_bool() == Some(true)
                    && value["revocations"]
                        .as_array()
                        .map(|revocations| {
                            revocations
                                .iter()
                                .any(|entry| entry["capabilityId"].as_str() == Some(capability_id))
                        })
                        .unwrap_or(false)
            };
            let Some(leader_revocation) = try_get_json(
                &client,
                &format!("{follower_url}/v1/revocations?capabilityId=cap-revoke-leader&limit=10"),
                service_token,
            ) else {
                return false;
            };
            let Some(follower_revocation) = try_get_json(
                &client,
                &format!("{follower_url}/v1/revocations?capabilityId=cap-revoke-follower&limit=10"),
                service_token,
            ) else {
                return false;
            };
            revocation_visible(&leader_revocation, "cap-revoke-leader")
                && revocation_visible(&follower_revocation, "cap-revoke-follower")
        },
        || {
            json!({
                "leaderUrl": leader_url,
                "followerUrl": follower_url,
                "leader": {
                    "health": try_get_json(&client, &format!("{leader_url}/health"), service_token),
                    "clusterStatus": try_internal_cluster_status(&client, &leader_url, service_token),
                    "capRevokeLeader": try_get_json(
                        &client,
                        &format!(
                            "{leader_url}/v1/revocations?capabilityId=cap-revoke-leader&limit=10"
                        ),
                        service_token,
                    ),
                    "capRevokeFollower": try_get_json(
                        &client,
                        &format!(
                            "{leader_url}/v1/revocations?capabilityId=cap-revoke-follower&limit=10"
                        ),
                        service_token,
                    ),
                },
                "follower": {
                    "health": try_get_json(&client, &format!("{follower_url}/health"), service_token),
                    "clusterStatus": try_internal_cluster_status(&client, &follower_url, service_token),
                    "capRevokeLeader": try_get_json(
                        &client,
                        &format!(
                            "{follower_url}/v1/revocations?capabilityId=cap-revoke-leader&limit=10"
                        ),
                        service_token,
                    ),
                    "capRevokeFollower": try_get_json(
                        &client,
                        &format!(
                            "{follower_url}/v1/revocations?capabilityId=cap-revoke-follower&limit=10"
                        ),
                        service_token,
                    ),
                },
            })
        },
    );

    let leader_budget = post_json(
        &client,
        &format!("{leader_url}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-shared",
            "grantIndex": 0,
            "maxInvocations": 4
        }),
    );
    assert_eq!(leader_budget["allowed"].as_bool(), Some(true));
    assert_eq!(leader_budget["invocationCount"].as_u64(), Some(1));
    assert_expected_write_visibility_metadata(&leader_budget, &leader_url);
    assert_budget_invocation_count(&client, &leader_url, service_token, "cap-shared", 0, 1);

    let second_budget = post_json(
        &client,
        &format!("{follower_url}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-shared",
            "grantIndex": 0,
            "maxInvocations": 4
        }),
    );
    assert_eq!(second_budget["allowed"].as_bool(), Some(true));
    assert_eq!(second_budget["invocationCount"].as_u64(), Some(2));
    assert_expected_write_visibility_metadata(&second_budget, &leader_url);
    assert_budget_invocation_count(&client, &leader_url, service_token, "cap-shared", 0, 2);

    let rapid_budget = post_json(
        &client,
        &format!("{leader_url}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-shared",
            "grantIndex": 0,
            "maxInvocations": 4
        }),
    );
    assert_eq!(rapid_budget["allowed"].as_bool(), Some(true));
    assert_eq!(rapid_budget["invocationCount"].as_u64(), Some(3));
    assert_expected_write_visibility_metadata(&rapid_budget, &leader_url);
    assert_budget_invocation_count(&client, &leader_url, service_token, "cap-shared", 0, 3);

    wait_until_with_diagnostics(
        "follower budget visibility",
        Duration::from_secs(90),
        || {
            let Some(budgets) = try_get_json(
                &client,
                &format!("{follower_url}/v1/budgets?capabilityId=cap-shared&limit=10"),
                service_token,
            ) else {
                return false;
            };
            budgets["count"].as_u64() == Some(1)
                && budgets["usages"][0]["invocationCount"].as_u64() == Some(3)
        },
        || {
            cluster_timeout_diagnostics(
                &client,
                &leader_url,
                &follower_url,
                service_token,
                "cap-shared",
            )
        },
    );
    assert_budget_invocation_count(&client, &leader_url, service_token, "cap-shared", 0, 3);
    assert_budget_invocation_count(&client, &follower_url, service_token, "cap-shared", 0, 3);
    assert_budget_totals(&client, &leader_url, service_token, "cap-shared", 0, 0, 0);
    wait_for_leader_convergence(&client, service_token, &url_a, &url_b, &leader_url);

    let authorized_budget = post_json_eventually_ok_with_diagnostics(
        &client,
        &format!("{leader_url}/v1/budgets/authorize-exposure"),
        service_token,
        &json!({
            "capabilityId": "cap-shared",
            "grantIndex": 0,
            "maxInvocations": 4,
            "exposureUnits": 75,
            "maxExposurePerInvocation": 100,
            "maxTotalExposureUnits": 400,
            "holdId": "cap-shared-hold-1",
            "eventId": "cap-shared-hold-1:authorize"
        }),
        "shared budget authorize exposure reaches quorum",
        Duration::from_secs(30),
        || {
            cluster_timeout_diagnostics(
                &client,
                &leader_url,
                &follower_url,
                service_token,
                "cap-shared",
            )
        },
    );
    assert_eq!(authorized_budget["allowed"].as_bool(), Some(true));
    assert_eq!(authorized_budget["invocationCount"].as_u64(), Some(4));
    assert_eq!(authorized_budget["totalExposureCharged"].as_u64(), Some(75));
    assert_eq!(authorized_budget["totalRealizedSpend"].as_u64(), Some(0));
    assert_expected_write_visibility_metadata(&authorized_budget, &leader_url);
    assert_budget_authority_metadata(&authorized_budget, &leader_url, "ha_quorum_commit");
    assert_budget_commit_metadata(
        &authorized_budget,
        &leader_url,
        2,
        2,
        &[leader_url.as_str(), follower_url.as_str()],
    );
    assert_budget_invocation_count(&client, &leader_url, service_token, "cap-shared", 0, 4);
    assert_budget_totals(&client, &leader_url, service_token, "cap-shared", 0, 75, 0);

    let survivor_url = if leader_url == url_a {
        drop(server_a.take());
        url_b.clone()
    } else {
        drop(server_b.take());
        url_a.clone()
    };
    wait_until(
        "quorum loss after leader failure",
        Duration::from_secs(90),
        || {
            let Some(status) = try_internal_cluster_status(&client, &survivor_url, service_token)
            else {
                return false;
            };
            status["leaderUrl"].is_null()
                && status["hasQuorum"].as_bool() == Some(false)
                && status["reachableNodes"].as_u64() == Some(1)
        },
    );

    let (status, body) = post_json_status(
        &client,
        &format!("{survivor_url}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-shared",
            "grantIndex": 0,
            "maxInvocations": 4
        }),
    );
    assert_eq!(status, 503);
    assert!(
        body.contains("quorum") || body.contains("leader"),
        "expected quorum failure body, got: {body}"
    );

    let budgets = get_json(
        &client,
        &format!("{survivor_url}/v1/budgets?capabilityId=cap-shared&limit=10"),
        service_token,
    );
    assert_eq!(budgets["count"].as_u64(), Some(1));
    assert_eq!(budgets["usages"][0]["invocationCount"].as_u64(), Some(4));
    assert_eq!(
        budgets["usages"][0]["totalExposureCharged"].as_u64(),
        Some(75)
    );
}

#[test]
#[ignore = "flaky on CI: trust-cluster quorum race; passes locally"]
fn trust_control_cluster_replicates_state_and_fails_closed_without_quorum() {
    if skip_when_loopback_bind_denied(
        "trust_control_cluster_replicates_state_and_fails_closed_without_quorum",
    ) {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    run_trust_control_cluster_proving_scenario(1, 1);
}

#[test]
#[ignore = "slow scenario: exercises trust-control runtime assurance issuance"]
fn trust_cluster_runtime_assurance_policy_gates_capability_issuance() {
    if skip_when_loopback_bind_denied(
        "trust_cluster_runtime_assurance_policy_gates_capability_issuance",
    ) {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");

    let addr = reserve_listen_addr();
    let base_url = format!("http://{addr}");
    let service_token = "runtime-assurance-token";
    let receipt_db = dir.join("receipts.sqlite3");
    let revocation_db = dir.join("revocations.sqlite3");
    let authority_db = dir.join("authority.sqlite3");
    let budget_db = dir.join("budgets.sqlite3");
    let policy_path = dir.join("runtime-assurance-policy.yaml");
    fs::write(
        &policy_path,
        r#"
hushspec: "0.1.0"
name: runtime-assurance
rules:
  tool_access:
    enabled: true
    allow: ["payments.charge"]
extensions:
  runtime_assurance:
    tiers:
      baseline:
        minimum_attestation_tier: none
        max_scope:
          operations: ["invoke"]
          max_invocations: 5
          max_cost_per_invocation:
            units: 50
            currency: USD
          max_total_cost:
            units: 100
            currency: USD
          max_delegation_depth: 0
          ttl_seconds: 30
      attested:
        minimum_attestation_tier: attested
        max_scope:
          operations: ["invoke"]
          max_invocations: 20
          max_cost_per_invocation:
            units: 250
            currency: USD
          max_total_cost:
            units: 1000
            currency: USD
          max_delegation_depth: 0
          ttl_seconds: 300
"#,
    )
    .expect("write policy");

    let _server = spawn_trust_service(
        addr,
        service_token,
        &receipt_db,
        &revocation_db,
        &authority_db,
        &budget_db,
        Some(&policy_path),
        &base_url,
        &[],
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("build client");
    wait_until(
        "runtime assurance health reachable",
        Duration::from_secs(20),
        || try_get_json(&client, &format!("{base_url}/health"), service_token).is_some(),
    );

    let health = get_json(&client, &format!("{base_url}/health"), service_token);
    assert_eq!(
        health["federation"]["runtimeAssurancePolicyConfigured"].as_bool(),
        Some(true)
    );

    let subject = Keypair::generate();
    let runtime_attestation = serde_json::to_value(
        chio_core::capability::runtime_attestation::RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.v1".to_string(),
            verifier: "verifier.chio".to_string(),
            tier: chio_core::capability::runtime_attestation::RuntimeAssuranceTier::Attested,
            issued_at: 1,
            expires_at: 4_102_444_800u64,
            evidence_sha256: "attestation-digest".to_string(),
            runtime_identity: Some("spiffe://chio/runtime/test".to_string()),
            workload_identity: None,
            claims: None,
        },
    )
    .expect("serialize runtime attestation");
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "payments".to_string(),
            tool_name: "charge".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::GovernedIntentRequired],
            max_invocations: Some(10),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 250,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1_000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };

    let denied = client
        .post(format!("{base_url}/v1/capabilities/issue"))
        .header(AUTHORIZATION, bearer(service_token))
        .json(&json!({
            "subjectPublicKey": subject.public_key().to_hex(),
            "scope": scope,
            "ttlSeconds": 120
        }))
        .send()
        .expect("send denied issue request");
    assert_eq!(denied.status().as_u16(), 403);

    let allowed = client
        .post(format!("{base_url}/v1/capabilities/issue"))
        .header(AUTHORIZATION, bearer(service_token))
        .json(&json!({
            "subjectPublicKey": subject.public_key().to_hex(),
            "scope": scope,
            "ttlSeconds": 120,
            "runtimeAttestation": runtime_attestation
        }))
        .send()
        .expect("send allowed issue request");
    assert_eq!(allowed.status().as_u16(), 200);
    let allowed_json: serde_json::Value = allowed.json().expect("parse allowed issue response");
    let capability: CapabilityToken =
        serde_json::from_value(allowed_json["capability"].clone()).expect("decode capability");
    assert!(
        capability.scope.grants[0]
            .constraints
            .contains(&Constraint::MinimumRuntimeAssurance(
                chio_core::capability::runtime_attestation::RuntimeAssuranceTier::Attested
            )),
        "issued capability should retain the required runtime assurance tier"
    );
}

#[test]
fn trust_control_cluster_internal_status_requires_signed_node_identity() {
    if skip_when_loopback_bind_denied(
        "trust_control_cluster_internal_status_requires_signed_node_identity",
    ) {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir().join("cluster-node-identity");
    fs::create_dir_all(&dir).expect("create test dir");

    let addr_a = reserve_listen_addr();
    let addr_b = reserve_listen_addr();
    let url_a = format!("http://{addr_a}");
    let url_b = format!("http://{addr_b}");
    let expected_leader_url = std::cmp::min(url_a.clone(), url_b.clone());
    let service_token = "cluster-node-identity-token";

    let _server_a = spawn_trust_service(
        addr_a,
        service_token,
        &dir.join("receipts-a.sqlite3"),
        &dir.join("revocations-a.sqlite3"),
        &dir.join("authority-a.sqlite3"),
        &dir.join("budgets-a.sqlite3"),
        None,
        &url_a,
        std::slice::from_ref(&url_b),
    );
    let _server_b = spawn_trust_service(
        addr_b,
        service_token,
        &dir.join("receipts-b.sqlite3"),
        &dir.join("revocations-b.sqlite3"),
        &dir.join("authority-b.sqlite3"),
        &dir.join("budgets-b.sqlite3"),
        None,
        &url_b,
        std::slice::from_ref(&url_a),
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("build client");

    wait_until(
        "node identity cluster health reachable",
        Duration::from_secs(20),
        || try_get_json(&client, &format!("{url_a}/health"), service_token).is_some(),
    );
    wait_until(
        "node identity peer health reachable",
        Duration::from_secs(20),
        || try_get_json(&client, &format!("{url_b}/health"), service_token).is_some(),
    );
    wait_for_leader_convergence(&client, service_token, &url_a, &url_b, &expected_leader_url);

    let unsigned = client
        .get(format!("{url_a}/v1/internal/cluster/status"))
        .send()
        .expect("send unsigned internal cluster status request");
    assert_eq!(unsigned.status().as_u16(), 401);

    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs() as i64;
    let invalid_signature = client
        .get(format!("{url_a}/v1/internal/cluster/status"))
        .header(CLUSTER_NODE_ID_HEADER, url_b.clone())
        .header(CLUSTER_AUTH_ISSUED_AT_HEADER, issued_at.to_string())
        .header(CLUSTER_AUTH_SIGNATURE_HEADER, "deadbeef")
        .send()
        .expect("send invalid internal cluster status request");
    assert_eq!(invalid_signature.status().as_u16(), 401);

    let status = try_internal_cluster_status(&client, &url_a, service_token)
        .expect("allowlisted signed peer request should succeed");
    assert_eq!(
        status["leaderUrl"].as_str(),
        Some(expected_leader_url.as_str())
    );
}

#[test]
fn trust_control_cluster_requires_quorum_and_heals_after_partition() {
    if skip_when_loopback_bind_denied(
        "trust_control_cluster_requires_quorum_and_heals_after_partition",
    ) {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir().join("quorum-heal");
    fs::create_dir_all(&dir).expect("create test dir");

    let nodes = reserve_cluster_nodes(3);
    let (addr_a, url_a) = nodes[0].clone();
    let (addr_b, url_b) = nodes[1].clone();
    let (addr_c, url_c) = nodes[2].clone();
    let urls = vec![url_a.clone(), url_b.clone(), url_c.clone()];
    let service_token = "cluster-quorum-token";
    let expected_leader_url = url_a.clone();
    let majority_urls = vec![url_a.clone(), url_b.clone()];
    let isolated_url = url_c.clone();

    let _server_a = spawn_trust_service(
        addr_a,
        service_token,
        &dir.join("receipts-a.sqlite3"),
        &dir.join("revocations-a.sqlite3"),
        &dir.join("authority-a.sqlite3"),
        &dir.join("budgets-a.sqlite3"),
        None,
        &url_a,
        &[url_b.clone(), url_c.clone()],
    );
    let _server_b = spawn_trust_service(
        addr_b,
        service_token,
        &dir.join("receipts-b.sqlite3"),
        &dir.join("revocations-b.sqlite3"),
        &dir.join("authority-b.sqlite3"),
        &dir.join("budgets-b.sqlite3"),
        None,
        &url_b,
        &[url_a.clone(), url_c.clone()],
    );
    let _server_c = spawn_trust_service(
        addr_c,
        service_token,
        &dir.join("receipts-c.sqlite3"),
        &dir.join("revocations-c.sqlite3"),
        &dir.join("authority-c.sqlite3"),
        &dir.join("budgets-c.sqlite3"),
        None,
        &url_c,
        &[url_a.clone(), url_b.clone()],
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("build client");

    for base_url in &urls {
        wait_until(
            "cluster node health reachable",
            Duration::from_secs(20),
            || try_get_json(&client, &format!("{base_url}/health"), service_token).is_some(),
        );
    }

    wait_until_with_diagnostics(
        "three-node quorum convergence",
        Duration::from_secs(90),
        || {
            urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["quorumSize"].as_u64() == Some(2)
                    && status["reachableNodes"].as_u64() == Some(3)
            })
        },
        || cluster_status_diagnostics(&client, &urls, service_token),
    );

    for base_url in &majority_urls {
        set_cluster_partition(
            &client,
            base_url,
            service_token,
            std::slice::from_ref(&isolated_url),
        );
    }
    set_cluster_partition(
        &client,
        &isolated_url,
        service_token,
        &[url_a.clone(), url_b.clone()],
    );

    wait_until_with_diagnostics(
        "minority partition loses quorum",
        Duration::from_secs(90),
        || {
            let majority_ok = majority_urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["reachableNodes"].as_u64() == Some(2)
            });
            let Some(isolated_status) =
                try_internal_cluster_status(&client, &isolated_url, service_token)
            else {
                return false;
            };
            majority_ok
                && isolated_status["leaderUrl"].is_null()
                && isolated_status["hasQuorum"].as_bool() == Some(false)
                && isolated_status["reachableNodes"].as_u64() == Some(1)
                && isolated_status["role"].as_str() == Some("candidate")
        },
        || cluster_status_diagnostics(&client, &urls, service_token),
    );

    let (status, body) = post_json_status(
        &client,
        &format!("{isolated_url}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-quorum-heal",
            "grantIndex": 0,
            "maxInvocations": 5
        }),
    );
    assert_eq!(status, 503);
    assert!(
        body.contains("quorum") || body.contains("leader"),
        "expected quorum failure body, got: {body}"
    );

    let majority_write = post_json(
        &client,
        &format!("{url_b}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-quorum-heal",
            "grantIndex": 0,
            "maxInvocations": 5
        }),
    );
    assert_eq!(majority_write["allowed"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&majority_write, &expected_leader_url);

    for base_url in &urls {
        let response = set_cluster_partition(&client, base_url, service_token, &[]);
        assert_eq!(
            response["blockedPeerUrls"].as_array().map(Vec::len),
            Some(0)
        );
    }

    wait_until_with_diagnostics(
        "three-node quorum heal convergence",
        Duration::from_secs(90),
        || {
            urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["reachableNodes"].as_u64() == Some(3)
            })
        },
        || cluster_status_diagnostics(&client, &urls, service_token),
    );

    wait_until_with_diagnostics(
        "healed minority catches up from snapshot",
        Duration::from_secs(90),
        || {
            let Some(budgets) = try_get_json(
                &client,
                &format!("{isolated_url}/v1/budgets?capabilityId=cap-quorum-heal&limit=10"),
                service_token,
            ) else {
                return false;
            };
            let Some(status) = try_internal_cluster_status(&client, &isolated_url, service_token)
            else {
                return false;
            };
            budgets["count"].as_u64() == Some(1)
                && budgets["usages"][0]["invocationCount"].as_u64() == Some(1)
                && status["peers"]
                    .as_array()
                    .expect("peer status array")
                    .iter()
                    .any(|peer| peer["snapshotAppliedCount"].as_u64().unwrap_or(0) >= 1)
        },
        || cluster_status_diagnostics(&client, &urls, service_token),
    );
}

#[test]
fn trust_control_cluster_rejects_stale_authority_term_after_failover_and_restart() {
    if skip_when_loopback_bind_denied(
        "trust_control_cluster_rejects_stale_authority_term_after_failover_and_restart",
    ) {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir().join("authority-fence-failover");
    fs::create_dir_all(&dir).expect("create test dir");

    let nodes = reserve_cluster_nodes(3);
    let (addr_a, url_a) = nodes[0].clone();
    let (addr_b, url_b) = nodes[1].clone();
    let (addr_c, url_c) = nodes[2].clone();
    let urls = vec![url_a.clone(), url_b.clone(), url_c.clone()];
    let service_token = "cluster-authority-fence-token";

    let receipts_a = dir.join("receipts-a.sqlite3");
    let revocations_a = dir.join("revocations-a.sqlite3");
    let authority_a = dir.join("authority-a.sqlite3");
    let budgets_a = dir.join("budgets-a.sqlite3");
    let receipts_b = dir.join("receipts-b.sqlite3");
    let revocations_b = dir.join("revocations-b.sqlite3");
    let authority_b = dir.join("authority-b.sqlite3");
    let budgets_b = dir.join("budgets-b.sqlite3");
    let receipts_c = dir.join("receipts-c.sqlite3");
    let revocations_c = dir.join("revocations-c.sqlite3");
    let authority_c = dir.join("authority-c.sqlite3");
    let budgets_c = dir.join("budgets-c.sqlite3");

    let mut server_a = Some(spawn_trust_service(
        addr_a,
        service_token,
        &receipts_a,
        &revocations_a,
        &authority_a,
        &budgets_a,
        None,
        &url_a,
        &[url_b.clone(), url_c.clone()],
    ));
    let _server_b = spawn_trust_service(
        addr_b,
        service_token,
        &receipts_b,
        &revocations_b,
        &authority_b,
        &budgets_b,
        None,
        &url_b,
        &[url_a.clone(), url_c.clone()],
    );
    let _server_c = spawn_trust_service(
        addr_c,
        service_token,
        &receipts_c,
        &revocations_c,
        &authority_c,
        &budgets_c,
        None,
        &url_c,
        &[url_a.clone(), url_b.clone()],
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("build client");

    for base_url in &urls {
        wait_for_node_health(
            &client,
            base_url,
            service_token,
            "authority fence node health reachable",
        );
    }

    let initial_leader = wait_for_cluster_leader_convergence(
        &client,
        service_token,
        &urls,
        "initial authority leader convergence",
    );
    assert_eq!(initial_leader, url_a);
    let initial_status =
        wait_for_internal_cluster_status(&client, &url_b, service_token, "initial cluster status");
    let initial_term = initial_status["authorityLease"]["term"]
        .as_u64()
        .expect("initial authority lease term");

    drop(server_a.take());

    let majority_urls = vec![url_b.clone(), url_c.clone()];
    wait_until_with_diagnostics(
        "majority authority failover convergence",
        Duration::from_secs(90),
        || {
            let leader_status = try_internal_cluster_status(&client, &url_b, service_token);
            let leader_term_advanced = leader_status
                .as_ref()
                .and_then(|status| status["authorityLease"]["term"].as_u64())
                .is_some_and(|term| term > initial_term);
            majority_urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(url_b.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["reachableNodes"].as_u64() == Some(2)
            }) && leader_term_advanced
        },
        || cluster_status_diagnostics(&client, &majority_urls, service_token),
    );

    let failover_status = wait_for_internal_cluster_status(
        &client,
        &url_b,
        service_token,
        "failover status after leader loss",
    );
    let failover_term = failover_status["authorityLease"]["term"]
        .as_u64()
        .expect("failover authority term");
    assert!(failover_term > initial_term);

    let _restarted_a = spawn_trust_service(
        addr_a,
        service_token,
        &receipts_a,
        &revocations_a,
        &authority_a,
        &budgets_a,
        None,
        &url_a,
        &[url_b.clone(), url_c.clone()],
    );
    wait_for_node_health(
        &client,
        &url_a,
        service_token,
        "restarted stale node health reachable",
    );
    let restarted_leader = wait_for_cluster_leader_convergence(
        &client,
        service_token,
        &urls,
        "restarted cluster reconverges after old leader returns",
    );
    let restarted_status = wait_for_internal_cluster_status(
        &client,
        &restarted_leader,
        service_token,
        "restarted cluster status",
    );
    let restarted_term = restarted_status["authorityLease"]["term"]
        .as_u64()
        .expect("restarted authority term");
    assert!(restarted_term >= failover_term);

    let generation_before = get_json(
        &client,
        &format!("{restarted_leader}/v1/authority"),
        service_token,
    )["generation"]
        .as_u64()
        .expect("generation before stale mutation");
    let stale_peer_url = urls
        .iter()
        .find(|candidate| *candidate != &restarted_leader)
        .cloned()
        .expect("stale peer url");

    let (stale_status, stale_body) = post_internal_json_status(
        &client,
        &restarted_leader,
        service_token,
        "/v1/authority",
        &stale_peer_url,
        Some(initial_term),
        &json!({}),
    );
    assert_eq!(stale_status, 409);
    assert!(
        stale_body.contains("term does not match the current lease")
            || stale_body.contains("stale"),
        "expected stale leader rejection body, got: {stale_body}"
    );

    let generation_after_reject = get_json(
        &client,
        &format!("{restarted_leader}/v1/authority"),
        service_token,
    )["generation"]
        .as_u64()
        .expect("generation after stale mutation rejection");
    assert_eq!(generation_after_reject, generation_before);

    let forwarding_leader = wait_for_cluster_leader_convergence(
        &client,
        service_token,
        &urls,
        "cluster leader remains stable before follower forwarding",
    );
    let forwarding_generation_before = get_json(
        &client,
        &format!("{forwarding_leader}/v1/authority"),
        service_token,
    )["generation"]
        .as_u64()
        .expect("generation before follower forwarding");
    let forwarding_peer_url = urls
        .iter()
        .find(|candidate| *candidate != &forwarding_leader)
        .cloned()
        .expect("forwarding peer url");

    let forwarded = post_json(
        &client,
        &format!("{forwarding_peer_url}/v1/authority"),
        service_token,
        &json!({}),
    );
    assert_eq!(
        forwarded["handledBy"].as_str(),
        Some(forwarding_leader.as_str())
    );
    assert_eq!(
        forwarded["leaderUrl"].as_str(),
        Some(forwarding_leader.as_str())
    );
    assert_eq!(
        forwarded["generation"].as_u64(),
        Some(forwarding_generation_before.saturating_add(1))
    );
}

#[cfg(unix)]
#[test]
fn trust_control_cluster_failed_quorum_does_not_leave_orphaned_exposure() {
    if skip_when_loopback_bind_denied(
        "trust_control_cluster_failed_quorum_does_not_leave_orphaned_exposure",
    ) {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir().join("budget-quorum-commit-timeout");
    fs::create_dir_all(&dir).expect("create test dir");

    let addr_a = reserve_listen_addr();
    let addr_b = reserve_listen_addr();
    let url_a = format!("http://{addr_a}");
    let url_b = format!("http://{addr_b}");
    let expected_leader_url = std::cmp::min(url_a.clone(), url_b.clone());
    let service_token = "budget-quorum-commit-timeout-token";

    let server_a = spawn_trust_service(
        addr_a,
        service_token,
        &dir.join("receipts-a.sqlite3"),
        &dir.join("revocations-a.sqlite3"),
        &dir.join("authority-a.sqlite3"),
        &dir.join("budgets-a.sqlite3"),
        None,
        &url_a,
        std::slice::from_ref(&url_b),
    );
    let server_b = spawn_trust_service(
        addr_b,
        service_token,
        &dir.join("receipts-b.sqlite3"),
        &dir.join("revocations-b.sqlite3"),
        &dir.join("authority-b.sqlite3"),
        &dir.join("budgets-b.sqlite3"),
        None,
        &url_b,
        std::slice::from_ref(&url_a),
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("build client");

    wait_until(
        "budget quorum timeout cluster health reachable",
        Duration::from_secs(20),
        || try_get_json(&client, &format!("{url_a}/health"), service_token).is_some(),
    );
    wait_until(
        "budget quorum timeout peer health reachable",
        Duration::from_secs(20),
        || try_get_json(&client, &format!("{url_b}/health"), service_token).is_some(),
    );
    wait_for_leader_convergence(&client, service_token, &url_a, &url_b, &expected_leader_url);

    let stopped_peer = if expected_leader_url == url_a {
        &server_b.child
    } else {
        &server_a.child
    };
    send_signal(stopped_peer, "STOP");

    let (status, body) = post_json_status(
        &client,
        &format!("{expected_leader_url}/v1/budgets/authorize-exposure"),
        service_token,
        &json!({
            "capabilityId": "cap-stalled-commit",
            "grantIndex": 0,
            "maxInvocations": 5,
            "exposureUnits": 60,
            "maxExposurePerInvocation": 100,
            "maxTotalExposureUnits": 400,
            "holdId": "cap-stalled-commit-hold-1",
            "eventId": "cap-stalled-commit-hold-1:authorize"
        }),
    );
    assert_eq!(status, 503);
    assert!(
        body.contains("leader-visible") || body.contains("quorum commit"),
        "expected explicit quorum-commit failure body, got: {body}"
    );
    wait_until(
        "failed quorum authorize rollback removes orphaned exposure",
        Duration::from_secs(10),
        || {
            let Some(budgets) = try_get_json(
                &client,
                &format!(
                    "{expected_leader_url}/v1/budgets?capabilityId=cap-stalled-commit&limit=10"
                ),
                service_token,
            ) else {
                return false;
            };
            let Some(usage) = budgets["usages"].as_array().and_then(|usages| {
                usages
                    .iter()
                    .find(|usage| usage["grantIndex"].as_u64() == Some(0))
            }) else {
                return false;
            };
            usage["invocationCount"].as_u64() == Some(0)
                && usage["totalExposureCharged"].as_u64() == Some(0)
                && usage["totalRealizedSpend"].as_u64() == Some(0)
        },
    );
}

#[test]
fn trust_control_cluster_replicates_denied_budget_events_without_usage_rows() {
    if skip_when_loopback_bind_denied(
        "trust_control_cluster_replicates_denied_budget_events_without_usage_rows",
    ) {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir().join("denied-budget-events");
    fs::create_dir_all(&dir).expect("create test dir");

    let addr_a = reserve_listen_addr();
    let addr_b = reserve_listen_addr();
    let url_a = format!("http://{addr_a}");
    let url_b = format!("http://{addr_b}");
    let expected_leader_url = std::cmp::min(url_a.clone(), url_b.clone());
    let follower_url = if expected_leader_url == url_a {
        url_b.clone()
    } else {
        url_a.clone()
    };
    let budget_db_a = dir.join("budgets-a.sqlite3");
    let budget_db_b = dir.join("budgets-b.sqlite3");
    let service_token = "denied-budget-events-token";

    let _server_a = spawn_trust_service(
        addr_a,
        service_token,
        &dir.join("receipts-a.sqlite3"),
        &dir.join("revocations-a.sqlite3"),
        &dir.join("authority-a.sqlite3"),
        &budget_db_a,
        None,
        &url_a,
        std::slice::from_ref(&url_b),
    );
    let _server_b = spawn_trust_service(
        addr_b,
        service_token,
        &dir.join("receipts-b.sqlite3"),
        &dir.join("revocations-b.sqlite3"),
        &dir.join("authority-b.sqlite3"),
        &budget_db_b,
        None,
        &url_b,
        std::slice::from_ref(&url_a),
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("build client");

    wait_until(
        "denied budget cluster health reachable",
        Duration::from_secs(20),
        || try_get_json(&client, &format!("{url_a}/health"), service_token).is_some(),
    );
    wait_until(
        "denied budget peer health reachable",
        Duration::from_secs(20),
        || try_get_json(&client, &format!("{url_b}/health"), service_token).is_some(),
    );
    wait_for_leader_convergence(&client, service_token, &url_a, &url_b, &expected_leader_url);

    let denied_budget = post_json_eventually_ok_with_diagnostics(
        &client,
        &format!("{follower_url}/v1/budgets/authorize-exposure"),
        service_token,
        &json!({
            "capabilityId": "cap-denied-cluster",
            "grantIndex": 0,
            "maxInvocations": 1,
            "exposureUnits": 25,
            "maxExposurePerInvocation": 50,
            "maxTotalExposureUnits": 10,
            "holdId": "cap-denied-cluster-hold-1",
            "eventId": "cap-denied-cluster-hold-1:authorize"
        }),
        "denied budget authorize reaches leader visibility",
        Duration::from_secs(30),
        || {
            cluster_timeout_diagnostics(
                &client,
                &expected_leader_url,
                &follower_url,
                service_token,
                "cap-denied-cluster",
            )
        },
    );
    assert_eq!(denied_budget["allowed"].as_bool(), Some(false));
    assert_expected_write_visibility_metadata(&denied_budget, &expected_leader_url);
    assert!(denied_budget["invocationCount"].is_null());
    assert!(denied_budget["totalExposureCharged"].is_null());
    assert!(denied_budget["totalRealizedSpend"].is_null());

    let follower_budget_db = if follower_url == url_a {
        budget_db_a.clone()
    } else {
        budget_db_b.clone()
    };
    let leader_budget_db = if expected_leader_url == url_a {
        budget_db_a.clone()
    } else {
        budget_db_b.clone()
    };

    wait_until_with_diagnostics(
        "denied budget event replicates to follower",
        Duration::from_secs(30),
        || {
            let Ok(store) = SqliteBudgetStore::open(&follower_budget_db) else {
                return false;
            };
            let Ok(events) = store.list_mutation_events(10, Some("cap-denied-cluster"), Some(0))
            else {
                return false;
            };
            let Some(event) = events.first() else {
                return false;
            };
            event.event_id == "cap-denied-cluster-hold-1:authorize"
                && event.allowed == Some(false)
                && event.usage_seq.is_none()
        },
        || {
            cluster_timeout_diagnostics(
                &client,
                &expected_leader_url,
                &follower_url,
                service_token,
                "cap-denied-cluster",
            )
        },
    );

    for budget_db in [&leader_budget_db, &follower_budget_db] {
        let store = SqliteBudgetStore::open(budget_db).expect("open budget db");
        let events = store
            .list_mutation_events(10, Some("cap-denied-cluster"), Some(0))
            .expect("list denied mutation events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "cap-denied-cluster-hold-1:authorize");
        assert_eq!(events[0].allowed, Some(false));
        assert_eq!(events[0].usage_seq, None);
        assert!(events[0].event_seq >= 1);
        assert!(store
            .list_usages_after(10, Some(0))
            .expect("list denied budget usages")
            .is_empty());
    }
}

#[test]
fn trust_control_cluster_late_joiner_catches_up_from_snapshot_and_compacts() {
    if skip_when_loopback_bind_denied(
        "trust_control_cluster_late_joiner_catches_up_from_snapshot_and_compacts",
    ) {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir().join("late-joiner");
    fs::create_dir_all(&dir).expect("create test dir");

    let nodes = reserve_cluster_nodes(3);
    let (addr_a, url_a) = nodes[0].clone();
    let (addr_b, url_b) = nodes[1].clone();
    let (addr_c, url_c) = nodes[2].clone();
    let warm_urls = vec![url_a.clone(), url_b.clone()];
    let all_urls = vec![url_a.clone(), url_b.clone(), url_c.clone()];
    let service_token = "cluster-snapshot-token";
    let _server_a = spawn_trust_service(
        addr_a,
        service_token,
        &dir.join("receipts-a.sqlite3"),
        &dir.join("revocations-a.sqlite3"),
        &dir.join("authority-a.sqlite3"),
        &dir.join("budgets-a.sqlite3"),
        None,
        &url_a,
        &[url_b.clone(), url_c.clone()],
    );
    let _server_b = spawn_trust_service(
        addr_b,
        service_token,
        &dir.join("receipts-b.sqlite3"),
        &dir.join("revocations-b.sqlite3"),
        &dir.join("authority-b.sqlite3"),
        &dir.join("budgets-b.sqlite3"),
        None,
        &url_b,
        &[url_a.clone(), url_c.clone()],
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("build client");

    for base_url in &warm_urls {
        wait_for_node_health(
            &client,
            base_url,
            service_token,
            "warm node health reachable",
        );
    }

    let expected_leader_url = wait_for_cluster_leader_convergence(
        &client,
        service_token,
        &warm_urls,
        "two-node leader convergence with third node absent",
    );
    wait_until_with_diagnostics(
        "two-node quorum convergence with third node absent",
        Duration::from_secs(90),
        || {
            warm_urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["reachableNodes"].as_u64() == Some(2)
            })
        },
        || cluster_status_diagnostics(&client, &warm_urls, service_token),
    );

    for index in 0..10 {
        let receipt = serde_json::to_value(sample_receipt(
            &format!("snapshot-prejoin-{index}"),
            &format!("cap-prejoin-{index}"),
        ))
        .expect("serialize prejoin receipt");
        let stored = post_json(
            &client,
            &format!("{url_b}/v1/receipts/tools"),
            service_token,
            &receipt,
        );
        assert_eq!(stored["stored"].as_bool(), Some(true));
        assert_leader_visible_metadata(&stored);
    }

    wait_until_with_diagnostics(
        "warm nodes replicate prejoin receipts",
        Duration::from_secs(90),
        || {
            try_tool_receipt_count(&client, &url_a, service_token) == Some(10)
                && try_tool_receipt_count(&client, &url_b, service_token) == Some(10)
        },
        || cluster_status_diagnostics(&client, &warm_urls, service_token),
    );

    let _server_c = spawn_trust_service(
        addr_c,
        service_token,
        &dir.join("receipts-c.sqlite3"),
        &dir.join("revocations-c.sqlite3"),
        &dir.join("authority-c.sqlite3"),
        &dir.join("budgets-c.sqlite3"),
        None,
        &url_c,
        &[url_a.clone(), url_b.clone()],
    );

    wait_for_node_health(
        &client,
        &url_c,
        service_token,
        "late joiner health reachable",
    );

    wait_until_with_diagnostics(
        "late joiner snapshot catch-up",
        Duration::from_secs(90),
        || {
            let Some(status) = try_internal_cluster_status(&client, &url_c, service_token) else {
                return false;
            };
            try_tool_receipt_count(&client, &url_c, service_token) == Some(10)
                && status["hasQuorum"].as_bool() == Some(true)
                && status["peers"]
                    .as_array()
                    .expect("peer status array")
                    .iter()
                    .any(|peer| {
                        peer["snapshotAppliedCount"].as_u64().unwrap_or(0) >= 1
                            && peer["lastSnapshotAt"].as_u64().is_some()
                    })
        },
        || cluster_status_diagnostics(&client, &all_urls, service_token),
    );
    wait_for_cluster_leader_convergence(
        &client,
        service_token,
        &all_urls,
        "three-node leader convergence after late joiner catch-up",
    );

    for index in 10..20 {
        let receipt = serde_json::to_value(sample_receipt(
            &format!("snapshot-postjoin-{index}"),
            &format!("cap-postjoin-{index}"),
        ))
        .expect("serialize postjoin receipt");
        let stored = post_json(
            &client,
            &format!("{url_b}/v1/receipts/tools"),
            service_token,
            &receipt,
        );
        assert_eq!(stored["stored"].as_bool(), Some(true));
        assert_leader_visible_metadata(&stored);
    }

    wait_until_with_diagnostics(
        "late joiner snapshot compaction after sustained deltas",
        Duration::from_secs(90),
        || {
            let Some(status) = try_internal_cluster_status(&client, &url_c, service_token) else {
                return false;
            };
            try_tool_receipt_count(&client, &url_c, service_token) == Some(20)
                && status["peers"]
                    .as_array()
                    .expect("peer status array")
                    .iter()
                    .any(|peer| {
                        peer["snapshotAppliedCount"].as_u64().unwrap_or(0) >= 2
                            && peer["forceSnapshot"].as_bool() == Some(false)
                    })
        },
        || cluster_status_diagnostics(&client, &all_urls, service_token),
    );
}

#[test]
fn trust_control_cluster_snapshot_replays_holds_and_mutation_events() {
    if skip_when_loopback_bind_denied(
        "trust_control_cluster_snapshot_replays_holds_and_mutation_events",
    ) {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir().join("snapshot-budget-holds");
    fs::create_dir_all(&dir).expect("create test dir");

    let nodes = reserve_cluster_nodes(3);
    let (addr_late, late_url) = nodes[0].clone();
    let (addr_a, url_a) = nodes[1].clone();
    let (addr_b, url_b) = nodes[2].clone();
    let warm_urls = vec![url_a.clone(), url_b.clone()];
    let all_urls = vec![late_url.clone(), url_a.clone(), url_b.clone()];
    let service_token = "cluster-snapshot-budget-token";
    let warm_leader_url = url_a.clone();
    let late_budget_db = dir.join("budgets-late.sqlite3");

    let _server_a = spawn_trust_service(
        addr_a,
        service_token,
        &dir.join("receipts-a.sqlite3"),
        &dir.join("revocations-a.sqlite3"),
        &dir.join("authority-a.sqlite3"),
        &dir.join("budgets-a.sqlite3"),
        None,
        &url_a,
        &[late_url.clone(), url_b.clone()],
    );
    let _server_b = spawn_trust_service(
        addr_b,
        service_token,
        &dir.join("receipts-b.sqlite3"),
        &dir.join("revocations-b.sqlite3"),
        &dir.join("authority-b.sqlite3"),
        &dir.join("budgets-b.sqlite3"),
        None,
        &url_b,
        &[late_url.clone(), url_a.clone()],
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("build client");

    for base_url in &warm_urls {
        wait_for_node_health(
            &client,
            base_url,
            service_token,
            "warm budget node health reachable",
        );
    }

    wait_until_with_diagnostics(
        "warm budget cluster converges without late joiner",
        Duration::from_secs(90),
        || {
            warm_urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(warm_leader_url.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["reachableNodes"].as_u64() == Some(2)
            })
        },
        || cluster_status_diagnostics(&client, &warm_urls, service_token),
    );

    let authorize = post_json_eventually_ok_with_diagnostics(
        &client,
        &format!("{url_b}/v1/budgets/authorize-exposure"),
        service_token,
        &json!({
            "capabilityId": "cap-snapshot-hold",
            "grantIndex": 0,
            "maxInvocations": 5,
            "exposureUnits": 90,
            "maxExposurePerInvocation": 100,
            "maxTotalExposureUnits": 400,
            "holdId": "cap-snapshot-hold-1",
            "eventId": "cap-snapshot-hold-1:authorize"
        }),
        "snapshot hold authorization reaches quorum",
        Duration::from_secs(90),
        || cluster_status_diagnostics(&client, &warm_urls, service_token),
    );
    assert_eq!(authorize["allowed"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&authorize, &warm_leader_url);

    let release = post_json(
        &client,
        &format!("{url_a}/v1/budgets/reconcile-spend"),
        service_token,
        &json!({
            "capabilityId": "cap-snapshot-hold",
            "grantIndex": 0,
            "reductionUnits": 30,
            "holdId": "cap-snapshot-hold-1",
            "eventId": "cap-snapshot-hold-1:release"
        }),
    );
    assert_eq!(release["releasedExposureUnits"].as_u64(), Some(30));
    assert_expected_write_visibility_metadata(&release, &warm_leader_url);

    let capture = post_json(
        &client,
        &format!("{url_b}/v1/budgets/capture-invocation"),
        service_token,
        &json!({
            "capabilityId": "cap-snapshot-hold",
            "grantIndex": 0,
            "holdId": "cap-snapshot-hold-1",
            "eventId": "cap-snapshot-hold-1:capture-invocation"
        }),
    );
    assert!(matches!(
        capture["decision"].as_str(),
        Some("captured" | "already_captured")
    ));
    assert_expected_write_visibility_metadata(&capture, &warm_leader_url);
    assert_budget_invocation_count(
        &client,
        &warm_leader_url,
        service_token,
        "cap-snapshot-hold",
        0,
        1,
    );
    assert_budget_totals(
        &client,
        &warm_leader_url,
        service_token,
        "cap-snapshot-hold",
        0,
        60,
        0,
    );

    let _late_server = spawn_trust_service(
        addr_late,
        service_token,
        &dir.join("receipts-late.sqlite3"),
        &dir.join("revocations-late.sqlite3"),
        &dir.join("authority-late.sqlite3"),
        &late_budget_db,
        None,
        &late_url,
        &[url_a.clone(), url_b.clone()],
    );

    wait_for_node_health(
        &client,
        &late_url,
        service_token,
        "late budget node health reachable",
    );

    wait_until_with_diagnostics(
        "late joiner snapshots budget hold history",
        Duration::from_secs(90),
        || {
            let Some(status) = try_internal_cluster_status(&client, &late_url, service_token)
            else {
                return false;
            };
            let Some(budgets) = try_get_json(
                &client,
                &format!("{late_url}/v1/budgets?capabilityId=cap-snapshot-hold&limit=10"),
                service_token,
            ) else {
                return false;
            };
            status["leaderUrl"].as_str().is_some()
                && status["hasQuorum"].as_bool() == Some(true)
                && status["reachableNodes"].as_u64().unwrap_or(0) >= 2
                && budgets["count"].as_u64() == Some(1)
                && budgets["usages"][0]["invocationCount"].as_u64() == Some(1)
                && budgets["usages"][0]["totalExposureCharged"].as_u64() == Some(60)
                && budgets["usages"][0]["totalRealizedSpend"].as_u64() == Some(0)
        },
        || cluster_status_diagnostics(&client, &all_urls, service_token),
    );

    let late_store = SqliteBudgetStore::open(&late_budget_db).expect("open late budget db");
    let pre_reconcile_events = late_store
        .list_mutation_events(10, Some("cap-snapshot-hold"), Some(0))
        .expect("list replayed mutation events");
    let pre_reconcile_event_ids = pre_reconcile_events
        .iter()
        .map(|event| event.event_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        pre_reconcile_event_ids,
        vec![
            "cap-snapshot-hold-1:authorize",
            "cap-snapshot-hold-1:release",
            "cap-snapshot-hold-1:capture-invocation",
        ]
    );
    drop(late_store);

    let reconcile = post_json(
        &client,
        &format!("{late_url}/v1/budgets/reconcile-spend"),
        service_token,
        &json!({
            "capabilityId": "cap-snapshot-hold",
            "grantIndex": 0,
            "authorizedExposureUnits": 60,
            "realizedSpendUnits": 45,
            "holdId": "cap-snapshot-hold-1",
            "eventId": "cap-snapshot-hold-1:reconcile"
        }),
    );
    assert_eq!(reconcile["releasedExposureUnits"].as_u64(), Some(15));
    assert_leader_visible_metadata(&reconcile);
    assert_budget_totals(
        &client,
        &late_url,
        service_token,
        "cap-snapshot-hold",
        0,
        0,
        45,
    );

    let late_store = SqliteBudgetStore::open(&late_budget_db).expect("reopen late budget db");
    let usage = late_store
        .get_usage("cap-snapshot-hold", 0)
        .expect("get replayed budget usage")
        .expect("late usage row");
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 0);
    assert_eq!(usage.total_cost_realized_spend, 45);

    let post_reconcile_event_ids = late_store
        .list_mutation_events(10, Some("cap-snapshot-hold"), Some(0))
        .expect("list late mutation events after reconcile")
        .into_iter()
        .map(|event| event.event_id)
        .collect::<Vec<_>>();
    assert_eq!(
        post_reconcile_event_ids,
        vec![
            "cap-snapshot-hold-1:authorize".to_string(),
            "cap-snapshot-hold-1:release".to_string(),
            "cap-snapshot-hold-1:capture-invocation".to_string(),
            "cap-snapshot-hold-1:reconcile".to_string(),
        ]
    );
}

#[test]
fn trust_control_cluster_multi_region_partition_qualification() {
    if skip_when_loopback_bind_denied("trust_control_cluster_multi_region_partition_qualification")
    {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    let dir = unique_test_dir().join("multi-region-qualification");
    fs::create_dir_all(&dir).expect("create test dir");

    let nodes = reserve_cluster_nodes(3);
    let (addr_a, url_a) = nodes[0].clone();
    let (addr_b, url_b) = nodes[1].clone();
    let (addr_c, url_c) = nodes[2].clone();
    let all_urls = vec![url_a.clone(), url_b.clone(), url_c.clone()];
    let majority_urls = vec![url_a.clone(), url_b.clone()];
    let isolated_url = url_c.clone();
    let service_token = "cluster-multi-region-token";

    let _server_a = spawn_trust_service(
        addr_a,
        service_token,
        &dir.join("receipts-a.sqlite3"),
        &dir.join("revocations-a.sqlite3"),
        &dir.join("authority-a.sqlite3"),
        &dir.join("budgets-a.sqlite3"),
        None,
        &url_a,
        &[url_b.clone(), url_c.clone()],
    );
    let _server_b = spawn_trust_service(
        addr_b,
        service_token,
        &dir.join("receipts-b.sqlite3"),
        &dir.join("revocations-b.sqlite3"),
        &dir.join("authority-b.sqlite3"),
        &dir.join("budgets-b.sqlite3"),
        None,
        &url_b,
        &[url_a.clone(), url_c.clone()],
    );
    let _server_c = spawn_trust_service(
        addr_c,
        service_token,
        &dir.join("receipts-c.sqlite3"),
        &dir.join("revocations-c.sqlite3"),
        &dir.join("authority-c.sqlite3"),
        &dir.join("budgets-c.sqlite3"),
        None,
        &url_c,
        &[url_a.clone(), url_b.clone()],
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("build client");

    for base_url in &all_urls {
        wait_until(
            "cluster node health reachable",
            Duration::from_secs(20),
            || try_get_json(&client, &format!("{base_url}/health"), service_token).is_some(),
        );
    }

    let expected_leader_url = wait_for_cluster_leader_convergence(
        &client,
        service_token,
        &all_urls,
        "simulated three-region leader convergence",
    );
    wait_until_with_diagnostics(
        "simulated three-region quorum convergence",
        Duration::from_secs(90),
        || {
            all_urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["reachableNodes"].as_u64() == Some(3)
                    && status["quorumSize"].as_u64() == Some(2)
            })
        },
        || cluster_status_diagnostics(&client, &all_urls, service_token),
    );

    let mut healed_partition_samples_ms = Vec::new();
    for index in 0..MULTI_REGION_PARTITION_SAMPLES {
        for base_url in &majority_urls {
            let response = set_cluster_partition(
                &client,
                base_url,
                service_token,
                std::slice::from_ref(&isolated_url),
            );
            assert_eq!(response["selfUrl"].as_str(), Some(base_url.as_str()));
            assert_eq!(
                response["blockedPeerUrls"].as_array().map(Vec::len),
                Some(1)
            );
        }
        let isolated_partition = set_cluster_partition(
            &client,
            &isolated_url,
            service_token,
            &[url_a.clone(), url_b.clone()],
        );
        assert_eq!(isolated_partition["hasQuorum"].as_bool(), Some(false));

        wait_until_with_diagnostics(
            &format!("partition convergence sample {index}"),
            Duration::from_secs(90),
            || {
                let majority_ok = majority_urls.iter().all(|base_url| {
                    let Some(status) =
                        try_internal_cluster_status(&client, base_url, service_token)
                    else {
                        return false;
                    };
                    status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                        && status["hasQuorum"].as_bool() == Some(true)
                        && status["reachableNodes"].as_u64() == Some(2)
                });
                let Some(isolated_status) =
                    try_internal_cluster_status(&client, &isolated_url, service_token)
                else {
                    return false;
                };
                majority_ok
                    && isolated_status["leaderUrl"].is_null()
                    && isolated_status["hasQuorum"].as_bool() == Some(false)
                    && isolated_status["reachableNodes"].as_u64() == Some(1)
                    && isolated_status["role"].as_str() == Some("candidate")
            },
            || cluster_status_diagnostics(&client, &all_urls, service_token),
        );

        if index == 0 {
            let denied_receipt = serde_json::to_value(sample_receipt(
                "multi-region-denied",
                "cap-multi-region-denied",
            ))
            .expect("denied receipt json");
            let (status, body) = post_json_status(
                &client,
                &format!("{isolated_url}/v1/receipts/tools"),
                service_token,
                &denied_receipt,
            );
            assert_eq!(status, 503);
            assert!(
                body.contains("quorum") || body.contains("leader"),
                "expected quorum failure body, got: {body}"
            );
        }

        let receipt_nonce = format!("multi-region-heal-{index}");
        let capability_id = format!("cap-multi-region-heal-{index}");
        let signed_receipt = sample_receipt(&receipt_nonce, &capability_id);
        // `ChioReceipt::sign` overwrites the supplied id with the canonical content
        // hash (`chio_receipt_id`) and re-purposes the input string as a signing
        // nonce. Match visibility against the stored id, not the nonce.
        let receipt_id = signed_receipt.id.clone();
        let receipt = serde_json::to_value(&signed_receipt).expect("receipt json");
        let stored = post_json(
            &client,
            &format!("{url_b}/v1/receipts/tools"),
            service_token,
            &receipt,
        );
        assert_eq!(stored["stored"].as_bool(), Some(true));
        assert_expected_write_visibility_metadata(&stored, &expected_leader_url);

        for base_url in &all_urls {
            let response = set_cluster_partition(&client, base_url, service_token, &[]);
            assert_eq!(
                response["blockedPeerUrls"].as_array().map(Vec::len),
                Some(0)
            );
        }

        let lag_ms = measure_until_with_diagnostics(
            &format!("post-heal replication sample {index}"),
            Duration::from_secs(90),
            || {
                let converged = all_urls.iter().all(|base_url| {
                    let Some(status) =
                        try_internal_cluster_status(&client, base_url, service_token)
                    else {
                        return false;
                    };
                    status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                        && status["hasQuorum"].as_bool() == Some(true)
                        && status["reachableNodes"].as_u64() == Some(3)
                        && tool_receipt_visible(
                            &client,
                            base_url,
                            service_token,
                            &capability_id,
                            &receipt_id,
                        )
                });
                converged
            },
            || cluster_status_diagnostics(&client, &all_urls, service_token),
        );
        healed_partition_samples_ms.push(lag_ms);
    }

    let report = json!({
        "phase": 298,
        "scenario": "local-simulated-three-region-partition-qualification",
        "generatedAt": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_secs(),
        "clusterSyncIntervalMs": 2000,
        "regions": [
            {"name": "region-a", "baseUrl": url_a},
            {"name": "region-b", "baseUrl": url_b},
            {"name": "region-c", "baseUrl": url_c},
        ],
        "consistencyChecks": {
            "leaderUrl": expected_leader_url,
            "minorityWritesFailClosed": true,
            "healedClusterRestoresQuorum": true,
            "splitBrainObserved": false,
        },
        "postHealReplicationMs": {
            "samples": healed_partition_samples_ms,
            "summary": latency_summary(&healed_partition_samples_ms),
        },
        "notes": [
            "This artifact records local simulated-region qualification numbers, not hosted WAN latencies.",
            "Replication lag is measured from partition heal until all nodes converge on the expected replicated receipt visibility."
        ]
    });
    let report_path = write_multi_region_qualification_report(&report);
    assert!(report_path.exists(), "qualification report should exist");
    println!(
        "multi-region qualification report: {}",
        report_path.display()
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize qualification report")
    );
}

#[test]
#[ignore = "slow scenario: repeats the full failover scenario"]
fn trust_control_cluster_repeat_run_qualification() {
    if skip_when_loopback_bind_denied("trust_control_cluster_repeat_run_qualification") {
        return;
    }

    let _test_lock = trust_cluster_test_lock();
    for run_index in 1..=TRUST_CLUSTER_QUALIFICATION_RUNS {
        run_trust_control_cluster_proving_scenario(run_index, TRUST_CLUSTER_QUALIFICATION_RUNS);
    }
}
