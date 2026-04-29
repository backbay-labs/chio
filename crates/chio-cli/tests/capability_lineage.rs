//! Integration test: capability lineage is recorded at issuance.
//!
//! Verifies that GET /v1/lineage/{capability_id} returns a snapshot
//! immediately after POST /v1/capabilities/issue creates the token.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::{
    ChioScope, Constraint, Operation, RuntimeAssuranceTier, RuntimeAttestationEvidence, ToolGrant,
    WorkloadCredentialKind, WorkloadIdentity, WorkloadIdentityScheme,
};
use chio_core::crypto::Keypair;
use reqwest::blocking::Client;
use reqwest::header::AUTHORIZATION;

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn issue_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "test-server".to_string(),
            tool_name: "test_tool".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::GovernedIntentRequired],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    }
}

fn conflicting_runtime_attestation() -> RuntimeAttestationEvidence {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs();
    RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.v1".to_string(),
        verifier: "verifier.chio".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(5),
        expires_at: now + 300,
        evidence_sha256: "attestation-digest".to_string(),
        runtime_identity: Some("spiffe://prod.chio/payments/worker".to_string()),
        workload_identity: Some(WorkloadIdentity {
            scheme: WorkloadIdentityScheme::Spiffe,
            credential_kind: WorkloadCredentialKind::X509Svid,
            uri: "spiffe://dev.chio/payments/worker".to_string(),
            trust_domain: "dev.chio".to_string(),
            path: "/payments/worker".to_string(),
        }),
        claims: None,
    }
}

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

fn reserve_listen_addr() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind temp listener");
    let addr = listener.local_addr().expect("listener addr");
    drop(listener);
    addr
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
    receipt_db_path: &PathBuf,
    revocation_db_path: &PathBuf,
    authority_db_path: &PathBuf,
    budget_db_path: &PathBuf,
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
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trust service");
    ServerGuard { child }
}

fn wait_for_trust_service(client: &Client, base_url: &str, service: &mut ServerGuard) {
    for _ in 0..150 {
        match client.get(format!("{base_url}/health")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return,
            Ok(_) | Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
        if let Some(status) = service.child.try_wait().expect("poll trust service") {
            let mut stderr = String::new();
            if let Some(child_stderr) = service.child.stderr.as_mut() {
                let _ = child_stderr.read_to_string(&mut stderr);
            }
            panic!("trust service exited before becoming ready (status {status}): {stderr}");
        }
    }
    panic!("trust service did not become ready");
}

#[test]
fn issue_capability_records_lineage_snapshot() {
    let dir = unique_dir("chio-cli-lineage-test");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "lineage-test-token";
    let base_url = format!("http://{listen}");

    let mut service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );

    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url, &mut service);

    // Generate a fresh Ed25519 keypair for the subject (agent).
    // We encode the public key as hex for the request body.
    let subject_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();

    // Issue a capability via the trust-control HTTP endpoint.
    let issue_body = serde_json::json!({
        "subjectPublicKey": subject_hex,
        "scope": issue_scope(),
        "ttlSeconds": 3600
    });

    let issue_resp = client
        .post(format!("{base_url}/v1/capabilities/issue"))
        .header(AUTHORIZATION, bearer(service_token))
        .json(&issue_body)
        .send()
        .expect("send issue capability request");

    assert_eq!(
        issue_resp.status(),
        reqwest::StatusCode::OK,
        "issue capability should succeed; body: {}",
        issue_resp.text().unwrap_or_default()
    );

    let issue_json: serde_json::Value = issue_resp.json().expect("parse issue capability response");
    let capability_id = issue_json["capability"]["id"]
        .as_str()
        .expect("capability.id should be a string")
        .to_string();
    assert!(
        !capability_id.is_empty(),
        "capability id should not be empty"
    );

    // Query the lineage endpoint to verify the snapshot was recorded.
    let lineage_resp = client
        .get(format!("{base_url}/v1/lineage/{capability_id}"))
        .header(AUTHORIZATION, bearer(service_token))
        .send()
        .expect("send lineage query request");

    assert_eq!(
        lineage_resp.status(),
        reqwest::StatusCode::OK,
        "lineage query should return 200; body: {}",
        lineage_resp.text().unwrap_or_default()
    );

    let lineage_json: serde_json::Value = lineage_resp.json().expect("parse lineage response");

    // Verify the snapshot fields match the issued capability.
    assert_eq!(
        lineage_json["capability_id"].as_str().unwrap_or(""),
        capability_id,
        "lineage capability_id should match issued id"
    );
    assert_eq!(
        lineage_json["subject_key"].as_str().unwrap_or(""),
        subject_hex,
        "lineage subject_key should match the agent's public key"
    );
    assert_eq!(
        lineage_json["delegation_depth"].as_u64().unwrap_or(999),
        0,
        "root capability should have delegation_depth = 0"
    );
    assert!(
        lineage_json["parent_capability_id"].is_null(),
        "root capability should have no parent"
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn authority_endpoints_require_auth_and_rotate_generation() {
    let dir = unique_dir("chio-cli-authority-http");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "authority-http-token";
    let base_url = format!("http://{listen}");

    let mut service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );

    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url, &mut service);

    let unauthorized = client
        .get(format!("{base_url}/v1/authority"))
        .send()
        .expect("send unauthorized authority request");
    assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);

    let before = client
        .get(format!("{base_url}/v1/authority"))
        .header(AUTHORIZATION, bearer(service_token))
        .send()
        .expect("send authority status request");
    assert_eq!(before.status(), reqwest::StatusCode::OK);
    let before: serde_json::Value = before.json().expect("parse authority status");
    let before_generation = before["generation"].as_u64().expect("authority generation");

    let unauthorized_rotate = client
        .post(format!("{base_url}/v1/authority"))
        .send()
        .expect("send unauthorized rotate request");
    assert_eq!(
        unauthorized_rotate.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );

    let rotated = client
        .post(format!("{base_url}/v1/authority"))
        .header(AUTHORIZATION, bearer(service_token))
        .send()
        .expect("send rotate request");
    assert_eq!(rotated.status(), reqwest::StatusCode::OK);
    let rotated: serde_json::Value = rotated.json().expect("parse rotated authority");
    let rotated_generation = rotated["generation"]
        .as_u64()
        .expect("rotated authority generation");
    assert!(
        rotated_generation > before_generation,
        "rotation should advance authority generation"
    );

    let after = client
        .get(format!("{base_url}/v1/authority"))
        .header(AUTHORIZATION, bearer(service_token))
        .send()
        .expect("send authority status request after rotation");
    assert_eq!(after.status(), reqwest::StatusCode::OK);
    let after: serde_json::Value = after.json().expect("parse post-rotation authority status");
    assert_eq!(after["generation"].as_u64(), Some(rotated_generation));

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn issue_capability_rejects_invalid_public_key() {
    let dir = unique_dir("chio-cli-invalid-capability-key");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "invalid-capability-key-token";
    let base_url = format!("http://{listen}");

    let mut service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );

    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url, &mut service);

    let response = client
        .post(format!("{base_url}/v1/capabilities/issue"))
        .header(AUTHORIZATION, bearer(service_token))
        .json(&serde_json::json!({
            "subjectPublicKey": "not-a-public-key",
            "scope": issue_scope(),
            "ttlSeconds": 120
        }))
        .send()
        .expect("send invalid issue capability request");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json().expect("parse invalid key response");
    assert!(body["error"]
        .as_str()
        .expect("invalid key error string")
        .contains("hex"));

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn issue_capability_rejects_conflicting_runtime_attestation_binding() {
    let dir = unique_dir("chio-cli-invalid-runtime-attestation");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let listen = reserve_listen_addr();
    let service_token = "invalid-runtime-attestation-token";
    let base_url = format!("http://{listen}");

    let mut service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );

    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url, &mut service);

    let subject_kp = Keypair::generate();
    let response = client
        .post(format!("{base_url}/v1/capabilities/issue"))
        .header(AUTHORIZATION, bearer(service_token))
        .json(&serde_json::json!({
            "subjectPublicKey": subject_kp.public_key().to_hex(),
            "scope": issue_scope(),
            "ttlSeconds": 120,
            "runtimeAttestation": conflicting_runtime_attestation(),
        }))
        .send()
        .expect("send conflicting runtime attestation request");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response
        .json()
        .expect("parse conflicting runtime attestation response");
    assert!(body["error"]
        .as_str()
        .expect("runtime attestation error string")
        .contains("workload identity is invalid"));

    let _ = std::fs::remove_dir_all(dir);
}
