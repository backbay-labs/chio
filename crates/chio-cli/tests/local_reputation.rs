#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::{ChioScope, MonetaryAmount, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    ChioReceipt, ChioReceiptBody, Decision, ReceiptAttributionMetadata, ToolCallAction,
};
use chio_credentials::{
    PortableNegativeEventEvidenceKind, PortableNegativeEventEvidenceReference,
    PortableNegativeEventIssueRequest, PortableNegativeEventKind, PortableReputationEvaluation,
    PortableReputationEvaluationRequest, PortableReputationFindingCode,
    PortableReputationSummaryIssueRequest, PortableReputationWeightingProfile,
    SignedPortableNegativeEvent, SignedPortableReputationSummary,
};
use chio_kernel::{
    BudgetStore, CapabilityAuthority, CapabilitySnapshot, FederatedEvidenceShareImport,
    LocalCapabilityAuthority, ReceiptStore, StoredToolReceipt,
};
use chio_store_sqlite::{SqliteBudgetStore, SqliteReceiptStore};
use reqwest::blocking::Client;

fn unique_dir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}"))
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
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
    policy_path: &PathBuf,
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
            "--advertise-url",
            &format!("http://{listen}"),
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
    for _ in 0..300 {
        match client.get(format!("{base_url}/health")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return,
            Ok(_) | Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
    panic!("trust service did not become ready");
}

fn create_passport(
    receipt_db_path: &PathBuf,
    budget_db_path: &PathBuf,
    subject_hex: &str,
    passport_path: &PathBuf,
    signing_seed_path: &PathBuf,
) {
    let create_passport = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "passport",
            "create",
            "--subject-public-key",
            subject_hex,
            "--output",
            passport_path.to_str().expect("passport path"),
            "--signing-seed-file",
            signing_seed_path.to_str().expect("signing seed path"),
        ])
        .output()
        .expect("run passport create");
    assert!(
        create_passport.status.success(),
        "chio passport create failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&create_passport.stdout),
        String::from_utf8_lossy(&create_passport.stderr)
    );
}

fn make_receipt(
    id: &str,
    capability_id: &str,
    subject_key: &str,
    issuer_key: &str,
    timestamp: u64,
) -> ChioReceipt {
    let kernel_kp = Keypair::generate();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "path": "/workspace/safe/data.txt"
            }))
            .expect("action"),
            decision: Decision::Allow,
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "attribution": ReceiptAttributionMetadata {
                    subject_key: subject_key.to_string(),
                    issuer_key: issuer_key.to_string(),
                    delegation_depth: 0,
                    grant_index: Some(0),
                }
            })),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kernel_kp.public_key(),
        },
        &kernel_kp,
    )
    .expect("sign receipt")
}

fn imported_scope_json() -> String {
    serde_json::to_string(&ChioScope {
        grants: vec![ToolGrant {
            server_id: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Read],
            constraints: Vec::new(),
            max_invocations: Some(5),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 25,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 125,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    })
    .expect("serialize imported scope")
}

#[allow(clippy::too_many_arguments)]
fn import_federated_reputation_share(
    receipt_db_path: &PathBuf,
    share_id: &str,
    subject_key: &str,
    issuer: &str,
    partner: &str,
    require_proofs: bool,
    exported_at: u64,
) {
    let remote_signer = Keypair::generate().public_key().to_hex();
    let root_capability_id = format!("{share_id}-root");
    let delegate_capability_id = format!("{share_id}-delegate");
    let scope_json = imported_scope_json();

    let mut store = SqliteReceiptStore::open(receipt_db_path).expect("open receipt store");
    store
        .import_federated_evidence_share(&FederatedEvidenceShareImport {
            share_id: share_id.to_string(),
            manifest_hash: format!("manifest-{share_id}"),
            exported_at,
            issuer: issuer.to_string(),
            partner: partner.to_string(),
            signer_public_key: remote_signer.clone(),
            require_proofs,
            query_json: serde_json::json!({
                "subjectKey": subject_key,
                "shareId": share_id,
            })
            .to_string(),
            tool_receipts: vec![
                StoredToolReceipt {
                    seq: 1,
                    receipt: make_receipt(
                        &format!("{share_id}-receipt-1"),
                        &delegate_capability_id,
                        subject_key,
                        &remote_signer,
                        exported_at.saturating_sub(300),
                    ),
                },
                StoredToolReceipt {
                    seq: 2,
                    receipt: make_receipt(
                        &format!("{share_id}-receipt-2"),
                        &delegate_capability_id,
                        subject_key,
                        &remote_signer,
                        exported_at.saturating_sub(60),
                    ),
                },
            ],
            capability_lineage: vec![
                CapabilitySnapshot {
                    capability_id: root_capability_id.clone(),
                    subject_key: subject_key.to_string(),
                    issuer_key: remote_signer.clone(),
                    issued_at: exported_at.saturating_sub(1_800),
                    expires_at: exported_at.saturating_add(86_400),
                    grants_json: scope_json.clone(),
                    delegation_depth: 0,
                    parent_capability_id: None,
                },
                CapabilitySnapshot {
                    capability_id: delegate_capability_id,
                    subject_key: subject_key.to_string(),
                    issuer_key: remote_signer,
                    issued_at: exported_at.saturating_sub(900),
                    expires_at: exported_at.saturating_add(43_200),
                    grants_json: scope_json,
                    delegation_depth: 1,
                    parent_capability_id: Some(root_capability_id),
                },
            ],
        })
        .expect("import federated reputation share");
}

fn seed_subject_history(
    receipt_db_path: &PathBuf,
    budget_db_path: &PathBuf,
    subject_kp: &Keypair,
) -> String {
    let authority = LocalCapabilityAuthority::new(Keypair::generate());
    let capability = authority
        .issue_capability(
            &subject_kp.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "filesystem".to_string(),
                    tool_name: "read_file".to_string(),
                    operations: vec![Operation::Read],
                    constraints: Vec::new(),
                    max_invocations: Some(10),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 50,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 500,
                        currency: "USD".to_string(),
                    }),
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            300,
        )
        .expect("issue capability");

    let receipt_store = SqliteReceiptStore::open(receipt_db_path).expect("open receipt store");
    receipt_store
        .record_capability_snapshot(&capability, None)
        .expect("record capability snapshot");

    let subject_key = subject_kp.public_key().to_hex();
    let issuer_key = authority.authority_public_key().to_hex();
    receipt_store
        .append_chio_receipt(&make_receipt(
            "rep-1",
            &capability.id,
            &subject_key,
            &issuer_key,
            1_700_000_000,
        ))
        .expect("append first receipt");
    receipt_store
        .append_chio_receipt(&make_receipt(
            "rep-2",
            &capability.id,
            &subject_key,
            &issuer_key,
            1_700_086_500,
        ))
        .expect("append second receipt");

    let budget_store = SqliteBudgetStore::open(budget_db_path).expect("open budget store");
    assert!(
        budget_store
            .try_charge_cost(&capability.id, 0, Some(10), 25, Some(50), Some(500))
            .expect("charge cost"),
        "seed budget charge should succeed"
    );

    subject_key
}

#[test]
fn trust_service_exposes_local_reputation_scorecard() {
    let dir = unique_dir("chio-cli-local-reputation-http");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let policy_path = fixture_path("hushspec-reputation.yaml");

    let subject_kp = Keypair::generate();
    let subject_hex = seed_subject_history(&receipt_db_path, &budget_db_path, &subject_kp);

    let listen = reserve_listen_addr();
    let service_token = "local-reputation-service-token";
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

    let response = client
        .get(format!(
            "{base_url}/v1/reputation/local/{subject_hex}?since=1700080000"
        ))
        .header("Authorization", format!("Bearer {service_token}"))
        .send()
        .expect("send local reputation request");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "local reputation request failed: {}",
        response.text().unwrap_or_default()
    );

    let body: serde_json::Value = client
        .get(format!(
            "{base_url}/v1/reputation/local/{subject_hex}?since=1700080000"
        ))
        .header("Authorization", format!("Bearer {service_token}"))
        .send()
        .expect("send local reputation request")
        .json()
        .expect("parse local reputation response");

    assert_eq!(body["subjectKey"], subject_hex);
    assert_eq!(body["scoringSource"], "issuance_policy");
    assert_eq!(body["probationary"], true);
    assert_eq!(body["probationaryScoreCeiling"], 0.6);
    assert_eq!(body["scorecard"]["history_depth"]["receipt_count"], 1);
    assert_eq!(
        body["scorecard"]["resource_stewardship"]["average_utilization"]["state"],
        "known"
    );
}

#[test]
fn trust_service_exposes_reputation_compare_over_http() {
    let dir = unique_dir("chio-cli-reputation-compare-direct-http");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let passport_path = dir.join("passport.json");
    let signing_seed_path = dir.join("authority-seed.txt");
    let policy_path = fixture_path("hushspec-reputation.yaml");

    let subject_kp = Keypair::generate();
    let subject_hex = seed_subject_history(&receipt_db_path, &budget_db_path, &subject_kp);
    create_passport(
        &receipt_db_path,
        &budget_db_path,
        &subject_hex,
        &passport_path,
        &signing_seed_path,
    );

    let passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).expect("read passport"))
            .expect("parse passport");

    let listen = reserve_listen_addr();
    let service_token = "local-reputation-compare-http-token";
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

    let response = client
        .post(format!("{base_url}/v1/reputation/compare/{subject_hex}"))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(&serde_json::json!({
            "passport": passport,
        }))
        .send()
        .expect("send reputation compare request");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "reputation compare request failed: {}",
        response.text().unwrap_or_default()
    );

    let body: serde_json::Value = client
        .post(format!("{base_url}/v1/reputation/compare/{subject_hex}"))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(&serde_json::json!({
            "passport": serde_json::from_slice::<serde_json::Value>(&std::fs::read(&passport_path).expect("read passport again"))
                .expect("parse passport again"),
        }))
        .send()
        .expect("send reputation compare request")
        .json()
        .expect("parse reputation compare response");

    assert_eq!(body["subjectKey"], subject_hex);
    assert_eq!(body["subjectMatches"], true);
    assert_eq!(body["local"]["scoringSource"], "issuance_policy");
    assert_eq!(body["passportVerification"]["credentialCount"], 1);
    assert_eq!(body["sharedEvidence"]["summary"]["matchingShares"], 0);
}

#[test]
fn cli_reputation_local_reports_policy_backed_scorecard() {
    let dir = unique_dir("chio-cli-local-reputation-cli");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let policy_path = fixture_path("hushspec-reputation.yaml");

    let subject_kp = Keypair::generate();
    let subject_hex = seed_subject_history(&receipt_db_path, &budget_db_path, &subject_kp);

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "reputation",
            "local",
            "--subject-public-key",
            &subject_hex,
            "--policy",
            policy_path.to_str().expect("policy path"),
        ])
        .output()
        .expect("run chio reputation local");
    assert!(
        output.status.success(),
        "chio reputation local failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let body: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse reputation CLI output");
    assert_eq!(body["subjectKey"], subject_hex);
    assert_eq!(body["scoringSource"], "issuance_policy");
    assert_eq!(body["probationary"], true);
    assert!(
        body["resolvedTier"]["name"].as_str().is_some(),
        "resolved tier should be populated"
    );
    assert_eq!(
        body["scorecard"]["resource_stewardship"]["average_utilization"]["state"],
        "known"
    );
}

#[test]
fn cli_reputation_local_surfaces_imported_trust_guardrails() {
    let dir = unique_dir("chio-cli-local-reputation-imported-trust");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let subject_kp = Keypair::generate();
    let subject_hex = seed_subject_history(&receipt_db_path, &budget_db_path, &subject_kp);
    let now = current_unix_secs();

    import_federated_reputation_share(
        &receipt_db_path,
        "share-accepted",
        &subject_hex,
        "org-remote-accepted",
        "org-local",
        true,
        now.saturating_sub(3_600),
    );
    import_federated_reputation_share(
        &receipt_db_path,
        "share-rejected",
        &subject_hex,
        "org-remote-rejected",
        "org-local",
        false,
        now.saturating_sub(1_800),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "reputation",
            "local",
            "--subject-public-key",
            &subject_hex,
        ])
        .output()
        .expect("run chio reputation local");
    assert!(
        output.status.success(),
        "chio reputation local failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let body: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse reputation local output");
    assert_eq!(body["importedTrust"]["signalCount"], 2);
    assert_eq!(body["importedTrust"]["acceptedCount"], 1);

    let signals = body["importedTrust"]["signals"]
        .as_array()
        .expect("imported trust signals");
    let accepted = signals
        .iter()
        .find(|signal| signal["provenance"]["shareId"] == "share-accepted")
        .expect("accepted imported signal");
    assert_eq!(accepted["accepted"], true);
    assert_eq!(accepted["provenance"]["issuer"], "org-remote-accepted");
    assert_eq!(accepted["policy"]["attenuationFactor"], 0.5);
    assert!(
        accepted["attenuatedCompositeScore"]
            .as_f64()
            .expect("attenuated imported composite")
            > 0.0
    );

    let rejected = signals
        .iter()
        .find(|signal| signal["provenance"]["shareId"] == "share-rejected")
        .expect("rejected imported signal");
    assert_eq!(rejected["accepted"], false);
    assert!(
        rejected["attenuatedCompositeScore"].is_null(),
        "rejected imported signal should not expose an attenuated score"
    );
    assert!(
        rejected["reasons"]
            .as_array()
            .expect("rejected reasons")
            .iter()
            .any(|reason| reason
                .as_str()
                .expect("reason string")
                .contains("did not require proofs")),
        "rejected imported signal should explain the proof guardrail"
    );
}

#[test]
fn cli_reputation_compare_reports_drift_against_fresh_passport() {
    let dir = unique_dir("chio-cli-reputation-compare-cli");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let passport_path = dir.join("passport.json");
    let signing_seed_path = dir.join("authority-seed.txt");
    let verifier_policy_path = dir.join("passport-verifier.yaml");

    let subject_kp = Keypair::generate();
    let subject_hex = seed_subject_history(&receipt_db_path, &budget_db_path, &subject_kp);

    create_passport(
        &receipt_db_path,
        &budget_db_path,
        &subject_hex,
        &passport_path,
        &signing_seed_path,
    );

    let passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).expect("read passport"))
            .expect("parse passport");
    let issuer_did = passport["credentials"][0]["issuer"]
        .as_str()
        .expect("issuer did")
        .to_string();
    let composite_score = passport["credentials"][0]["credentialSubject"]["metrics"]
        ["composite_score"]["value"]
        .as_f64()
        .expect("composite score");
    std::fs::write(
        &verifier_policy_path,
        format!(
            "issuerAllowlist:\n  - \"{issuer_did}\"\nminCompositeScore: {}\nminReceiptCount: 2\nminLineageRecords: 1\n",
            (composite_score - 0.01).max(0.0)
        ),
    )
    .expect("write verifier policy");

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "reputation",
            "compare",
            "--subject-public-key",
            &subject_hex,
            "--passport",
            passport_path.to_str().expect("passport path"),
            "--verifier-policy",
            verifier_policy_path.to_str().expect("verifier policy path"),
        ])
        .output()
        .expect("run chio reputation compare");
    assert!(
        output.status.success(),
        "chio reputation compare failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let body: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse reputation compare output");
    assert_eq!(body["subjectKey"], subject_hex);
    assert_eq!(body["subjectMatches"], true);
    assert_eq!(body["passportEvaluation"]["accepted"], true);
    assert_eq!(body["credentialDrifts"][0]["policyAccepted"], true);
    assert_eq!(body["sharedEvidence"]["summary"]["matchingShares"], 0);
    assert!(
        body["credentialDrifts"][0]["metrics"]["compositeScore"]["localMinusPortable"]
            .as_f64()
            .expect("composite drift")
            .abs()
            < 1e-9
    );
}

#[test]
fn cli_reputation_compare_supports_control_service_local_view() {
    let dir = unique_dir("chio-cli-reputation-compare-http");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let passport_path = dir.join("passport.json");
    let signing_seed_path = dir.join("authority-seed.txt");
    let policy_path = fixture_path("hushspec-reputation.yaml");

    let subject_kp = Keypair::generate();
    let subject_hex = seed_subject_history(&receipt_db_path, &budget_db_path, &subject_kp);

    create_passport(
        &receipt_db_path,
        &budget_db_path,
        &subject_hex,
        &passport_path,
        &signing_seed_path,
    );

    let listen = reserve_listen_addr();
    let service_token = "local-reputation-compare-service-token";
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

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "reputation",
            "compare",
            "--subject-public-key",
            &subject_hex,
            "--passport",
            passport_path.to_str().expect("passport path"),
        ])
        .output()
        .expect("run chio reputation compare over control service");
    assert!(
        output.status.success(),
        "chio reputation compare over control service failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let body: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse remote reputation compare output");
    assert_eq!(body["subjectKey"], subject_hex);
    assert_eq!(body["subjectMatches"], true);
    assert_eq!(body["local"]["scoringSource"], "issuance_policy");
    assert_eq!(
        body["passportVerification"]["subject"],
        format!("did:chio:{subject_hex}")
    );
    assert_eq!(body["sharedEvidence"]["summary"]["matchingShares"], 0);
}

#[test]
fn trust_service_reputation_views_include_imported_trust_provenance() {
    let dir = unique_dir("chio-cli-reputation-imported-trust-http");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let passport_path = dir.join("passport.json");
    let signing_seed_path = dir.join("authority-seed.txt");
    let policy_path = fixture_path("hushspec-reputation.yaml");

    let subject_kp = Keypair::generate();
    let subject_hex = seed_subject_history(&receipt_db_path, &budget_db_path, &subject_kp);
    let now = current_unix_secs();
    import_federated_reputation_share(
        &receipt_db_path,
        "share-http-imported",
        &subject_hex,
        "org-http-remote",
        "org-http-local",
        true,
        now.saturating_sub(1_200),
    );

    create_passport(
        &receipt_db_path,
        &budget_db_path,
        &subject_hex,
        &passport_path,
        &signing_seed_path,
    );
    let passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).expect("read passport"))
            .expect("parse passport");

    let listen = reserve_listen_addr();
    let service_token = "imported-trust-http-token";
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

    let local_body: serde_json::Value = client
        .get(format!("{base_url}/v1/reputation/local/{subject_hex}"))
        .header("Authorization", format!("Bearer {service_token}"))
        .send()
        .expect("send local reputation request")
        .json()
        .expect("parse local reputation body");
    assert_eq!(local_body["importedTrust"]["signalCount"], 1);
    assert_eq!(local_body["importedTrust"]["acceptedCount"], 1);
    assert_eq!(
        local_body["importedTrust"]["signals"][0]["provenance"]["issuer"],
        "org-http-remote"
    );

    let compare_body: serde_json::Value = client
        .post(format!("{base_url}/v1/reputation/compare/{subject_hex}"))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(&serde_json::json!({
            "passport": passport,
        }))
        .send()
        .expect("send reputation compare request")
        .json()
        .expect("parse reputation compare body");
    assert_eq!(compare_body["importedTrust"]["signalCount"], 1);
    assert_eq!(compare_body["importedTrust"]["acceptedCount"], 1);
    assert_eq!(
        compare_body["importedTrust"]["signals"][0]["provenance"]["partner"],
        "org-http-local"
    );
    assert!(
        compare_body["importedTrust"]["signals"][0]["attenuatedCompositeScore"]
            .as_f64()
            .expect("attenuated imported score")
            > 0.0
    );
}

#[test]
fn trust_service_portable_reputation_issue_and_evaluate_respects_local_weighting() {
    let dir = unique_dir("chio-cli-portable-reputation-http");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let policy_path = fixture_path("hushspec-reputation.yaml");

    let subject_kp = Keypair::generate();
    let subject_hex = seed_subject_history(&receipt_db_path, &budget_db_path, &subject_kp);
    let now = current_unix_secs();

    let listen = reserve_listen_addr();
    let service_token = "portable-reputation-token";
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

    let summary: SignedPortableReputationSummary = client
        .post(format!("{base_url}/v1/reputation/portable/summaries/issue"))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(&PortableReputationSummaryIssueRequest {
            subject_key: subject_hex.clone(),
            since: Some(now.saturating_sub(3_600)),
            until: Some(now),
            issued_at: Some(now),
            expires_at: Some(now.saturating_add(3_600)),
            note: None,
        })
        .send()
        .expect("issue portable reputation summary")
        .json()
        .expect("parse portable reputation summary");
    let issuer_operator_id = summary.body.issuer_operator_id.as_str();
    let issuer_weight_key = issuer_operator_id.to_string();
    let imported_positive = summary.body.effective_score;

    let event: SignedPortableNegativeEvent = client
        .post(format!("{base_url}/v1/reputation/portable/events/issue"))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(&PortableNegativeEventIssueRequest {
            subject_key: subject_hex.clone(),
            kind: PortableNegativeEventKind::PolicyViolation,
            severity: 0.4,
            observed_at: now.saturating_sub(120),
            published_at: Some(now.saturating_sub(60)),
            expires_at: Some(now.saturating_add(3_600)),
            evidence_refs: vec![PortableNegativeEventEvidenceReference {
                kind: PortableNegativeEventEvidenceKind::External,
                reference_id: "case-1".to_string(),
                uri: Some("https://issuer.example/cases/1".to_string()),
                sha256: None,
            }],
            note: None,
        })
        .send()
        .expect("issue portable negative event")
        .json()
        .expect("parse portable negative event");
    let issuer_weights = serde_json::json!({
        issuer_weight_key: 0.75
    });

    let evaluation: PortableReputationEvaluation = client
        .post(format!("{base_url}/v1/reputation/portable/evaluate"))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(&PortableReputationEvaluationRequest {
            subject_key: subject_hex.clone(),
            summaries: vec![summary.clone()],
            negative_events: vec![event],
            weighting_profile: PortableReputationWeightingProfile {
                profile_id: "local-profile".to_string(),
                allowed_issuer_operator_ids: vec![issuer_operator_id.to_string()],
                issuer_weights: serde_json::from_value(issuer_weights).expect("issuer weights"),
                max_summary_age_secs: 3600,
                max_event_age_secs: 3600,
                reject_probationary: false,
                negative_event_weight: 0.5,
                blocking_event_kinds: vec![PortableNegativeEventKind::FraudSignal],
            },
            evaluated_at: Some(now),
        })
        .send()
        .expect("evaluate portable reputation")
        .json()
        .expect("parse portable reputation evaluation");
    assert_eq!(evaluation.accepted_summary_count, 1);
    assert_eq!(evaluation.accepted_negative_event_count, 1);
    assert_eq!(evaluation.rejected_summary_count, 0);
    assert_eq!(evaluation.rejected_negative_event_count, 0);
    assert_eq!(evaluation.imported_positive_score, Some(imported_positive));
    assert!(evaluation.negative_event_penalty > 0.0);
    assert!(
        evaluation
            .effective_score
            .expect("effective score should be present")
            < imported_positive
    );
    assert!(!evaluation.blocked);

    let rejected: PortableReputationEvaluation = client
        .post(format!("{base_url}/v1/reputation/portable/evaluate"))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(&PortableReputationEvaluationRequest {
            subject_key: subject_hex,
            summaries: vec![summary],
            negative_events: Vec::new(),
            weighting_profile: PortableReputationWeightingProfile {
                profile_id: "reject-issuer".to_string(),
                allowed_issuer_operator_ids: vec!["https://other.example".to_string()],
                issuer_weights: Default::default(),
                max_summary_age_secs: 3600,
                max_event_age_secs: 3600,
                reject_probationary: false,
                negative_event_weight: 0.5,
                blocking_event_kinds: Vec::new(),
            },
            evaluated_at: Some(now),
        })
        .send()
        .expect("evaluate rejected portable reputation")
        .json()
        .expect("parse rejected portable reputation evaluation");
    assert_eq!(rejected.accepted_summary_count, 0);
    assert_eq!(rejected.rejected_summary_count, 1);
    assert!(rejected.effective_score.is_none());
    assert_eq!(
        rejected.findings[0].code,
        PortableReputationFindingCode::IssuerNotAllowed
    );
}
