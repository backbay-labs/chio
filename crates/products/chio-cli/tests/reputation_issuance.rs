#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_test_support::loopback::{reserve_listen_addr, skip_when_loopback_bind_denied};
use reqwest::blocking::Client;

fn unique_dir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}"))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn fixture_path(name: &str) -> PathBuf {
    workspace_root().join("examples/policies").join(name)
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
    listen: std::net::SocketAddr,
    service_token: &str,
    policy_path: &Path,
    receipt_db_path: &Path,
    revocation_db_path: &Path,
    authority_db_path: &Path,
    budget_db_path: &Path,
) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--revocation-db",
            revocation_db_path.to_str().expect("revocation db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "trust",
            "serve",
            "--listen",
            &listen.to_string(),
            "--service-token",
            service_token,
            "--policy",
            policy_path.to_str().expect("policy path"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trust service");
    ServerGuard { child }
}

fn wait_for_trust_service(client: &Client, base_url: &str) {
    for _ in 0..100 {
        match client.get(format!("{base_url}/health")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return,
            Ok(_) | Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
    panic!("trust service did not become ready");
}

#[test]
fn trust_service_enforces_reputation_gated_issuance_policy() {
    if skip_when_loopback_bind_denied("trust_service_enforces_reputation_gated_issuance_policy") {
        return;
    }

    let dir = unique_dir("chio-cli-reputation-issuance");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let policy_path = fixture_path("hushspec-reputation.yaml");

    let listen = reserve_listen_addr();
    let service_token = "reputation-issuance-test-token";
    let base_url = format!("http://{listen}");

    let _service = spawn_trust_service(
        listen,
        service_token,
        &policy_path,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );

    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url);

    let subject_kp = chio_core::crypto::Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();

    let denied_issue_body = serde_json::json!({
        "subjectPublicKey": subject_hex,
        "scope": {
            "grants": [{
                "server_id": "filesystem",
                "tool_name": "safe_invoke",
                "operations": ["invoke"],
                "constraints": []
            }],
            "resource_grants": [],
            "prompt_grants": []
        },
        "ttlSeconds": 300
    });

    let denied_response = client
        .post(format!("{base_url}/v1/capabilities/issue"))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(&denied_issue_body)
        .send()
        .expect("send denied issue request");
    assert_eq!(
        denied_response.status(),
        reqwest::StatusCode::FORBIDDEN,
        "probationary broad issuance should be denied; body: {}",
        denied_response.text().unwrap_or_default()
    );

    let allowed_issue_body = serde_json::json!({
        "subjectPublicKey": subject_hex,
        "scope": {
            "grants": [{
                "server_id": "filesystem",
                "tool_name": "read_file",
                "operations": ["read"],
                "constraints": [{
                    "type": "path_prefix",
                    "value": "/workspace/safe"
                }],
                "max_invocations": 10,
                "max_cost_per_invocation": {
                    "units": 50,
                    "currency": "USD"
                },
                "max_total_cost": {
                    "units": 500,
                    "currency": "USD"
                }
            }],
            "resource_grants": [],
            "prompt_grants": []
        },
        "ttlSeconds": 30
    });

    let allowed_response = client
        .post(format!("{base_url}/v1/capabilities/issue"))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(&allowed_issue_body)
        .send()
        .expect("send allowed issue request");
    assert_eq!(
        allowed_response.status(),
        reqwest::StatusCode::OK,
        "constrained probationary issuance should succeed; body: {}",
        allowed_response.text().unwrap_or_default()
    );

    let allowed_json: serde_json::Value = allowed_response
        .json()
        .expect("parse allowed capability response");
    let capability_id = allowed_json["capability"]["id"]
        .as_str()
        .expect("capability id")
        .to_string();

    let lineage_response = client
        .get(format!("{base_url}/v1/lineage/{capability_id}"))
        .header("Authorization", format!("Bearer {service_token}"))
        .send()
        .expect("query lineage");
    assert_eq!(lineage_response.status(), reqwest::StatusCode::OK);

    let _ = std::fs::remove_dir_all(dir);
}
