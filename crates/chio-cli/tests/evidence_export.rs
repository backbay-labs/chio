#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::{
    CapabilityToken, CapabilityTokenBody, ChioScope, Operation, ToolGrant,
};
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    ChildRequestReceipt, ChildRequestReceiptBody, ChioReceipt, ChioReceiptBody, Decision,
    ToolCallAction,
};
use chio_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
use chio_core::sha256_hex;
use chio_kernel::{build_checkpoint, ReceiptStore};
use chio_store_sqlite::SqliteReceiptStore;
use reqwest::blocking::Client;

fn unique_path(prefix: &str, suffix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}{suffix}"))
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

fn wait_for_trust_service(client: &Client, base_url: &str) {
    for _ in 0..100 {
        match client.get(format!("{base_url}/health")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return,
            Ok(_) | Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
    panic!("trust service did not become ready");
}

fn capability_with_id(id: &str, subject: &Keypair, issuer: &Keypair) -> CapabilityToken {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            issued_at: 100,
            expires_at: 10_000,
            delegation_chain: vec![],
        },
        issuer,
    )
    .expect("sign capability")
}

fn receipt_with_ts(id: &str, capability_id: &str, timestamp: u64) -> ChioReceipt {
    let keypair = Keypair::generate();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"cmd":"echo hi"}))
                .expect("action"),
            decision: Decision::Allow,
            content_hash: "content-1".to_string(),
            policy_hash: "policy-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .expect("sign receipt")
}

fn child_receipt_with_ts(id: &str, timestamp: u64) -> ChildRequestReceipt {
    let keypair = Keypair::generate();
    ChildRequestReceipt::sign(
        ChildRequestReceiptBody {
            id: id.to_string(),
            timestamp,
            session_id: SessionId::new("sess-evidence"),
            parent_request_id: RequestId::new("parent-evidence"),
            request_id: RequestId::new(format!("request-{id}")),
            operation_kind: OperationKind::CreateMessage,
            terminal_state: OperationTerminalState::Completed,
            outcome_hash: format!("outcome-{id}"),
            policy_hash: "policy-evidence".to_string(),
            metadata: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .expect("sign child receipt")
}

fn export_fixture_package(receipt_db_path: &PathBuf, output_dir: &PathBuf) {
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .arg("--receipt-db")
        .arg(receipt_db_path)
        .arg("evidence")
        .arg("export")
        .arg("--output")
        .arg(output_dir)
        .output()
        .expect("run chio evidence export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn create_federation_policy(
    output_path: &PathBuf,
    signing_seed_path: &PathBuf,
    issuer: &str,
    partner: &str,
    capability_id: &str,
    expires_at: u64,
) {
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "evidence",
            "federation-policy",
            "create",
            "--output",
            output_path.to_str().expect("policy path"),
            "--signing-seed-file",
            signing_seed_path.to_str().expect("seed path"),
            "--issuer",
            issuer,
            "--partner",
            partner,
            "--capability",
            capability_id,
            "--expires-at",
            &expires_at.to_string(),
            "--require-proofs",
        ])
        .output()
        .expect("run federation policy create");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn evidence_export_writes_manifest_and_expected_files() {
    let receipt_db_path = unique_path("evidence-export", ".sqlite3");
    let output_dir = unique_path("evidence-export-output", "");
    let policy_file = unique_path("evidence-export-policy", ".yaml");
    fs::write(
        &policy_file,
        r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5
guards:
  forbidden_path:
    enabled: true
capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#,
    )
    .expect("write policy");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let capability = capability_with_id("cap-evidence", &subject, &issuer);
        store
            .record_capability_snapshot(&capability, None)
            .expect("record capability snapshot");
        let seq1 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts("rcpt-1", "cap-evidence", 100))
            .expect("append receipt");
        let seq2 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts("rcpt-2", "cap-evidence", 101))
            .expect("append receipt");
        store
            .append_child_receipt(&child_receipt_with_ts("child-1", 100))
            .expect("append child receipt");
        let canonical = store
            .receipts_canonical_bytes_range(seq1, seq2)
            .expect("canonical bytes");
        let checkpoint = build_checkpoint(
            1,
            seq1,
            seq2,
            &canonical
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>(),
            &issuer,
        )
        .expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .arg("--receipt-db")
        .arg(&receipt_db_path)
        .arg("evidence")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .arg("--policy-file")
        .arg(&policy_file)
        .output()
        .expect("run chio evidence export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    for relative_path in [
        "manifest.json",
        "query.json",
        "receipts.ndjson",
        "child-receipts.ndjson",
        "checkpoints.ndjson",
        "capability-lineage.ndjson",
        "inclusion-proofs.ndjson",
        "retention.json",
        "README.txt",
        "policy/metadata.json",
        "policy/source.yaml",
    ] {
        assert!(
            output_dir.join(relative_path).exists(),
            "expected {}",
            relative_path
        );
    }

    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output_dir.join("manifest.json")).expect("read manifest"))
            .expect("parse manifest");
    assert_eq!(manifest["counts"]["toolReceipts"], 2);
    assert_eq!(manifest["counts"]["childReceipts"], 1);
    assert_eq!(manifest["counts"]["checkpoints"], 1);
    assert_eq!(manifest["counts"]["inclusionProofs"], 2);
    assert_eq!(manifest["counts"]["uncheckpointedReceipts"], 0);
    assert_eq!(manifest["policy"]["format"], "chio_yaml");

    let verify = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .arg("evidence")
        .arg("verify")
        .arg("--input")
        .arg(&output_dir)
        .output()
        .expect("run chio evidence verify");

    assert!(
        verify.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(String::from_utf8_lossy(&verify.stdout).contains("evidence package verified"));

    let _ = fs::remove_file(receipt_db_path);
    let _ = fs::remove_file(policy_file);
    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn evidence_export_require_proofs_fails_when_receipts_are_uncheckpointed() {
    let receipt_db_path = unique_path("evidence-export-require-proofs", ".sqlite3");
    let output_dir = unique_path("evidence-export-require-proofs-output", "");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let capability = capability_with_id("cap-require-proofs", &subject, &issuer);
        store
            .record_capability_snapshot(&capability, None)
            .expect("record capability snapshot");
        store
            .append_chio_receipt_returning_seq(&receipt_with_ts(
                "rcpt-uncheckpointed",
                "cap-require-proofs",
                100,
            ))
            .expect("append receipt");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .arg("--receipt-db")
        .arg(&receipt_db_path)
        .arg("evidence")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .arg("--require-proofs")
        .output()
        .expect("run chio evidence export");

    assert!(!output.status.success(), "export should fail");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("uncheckpointed"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = fs::remove_file(receipt_db_path);
    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn evidence_export_with_signed_federation_policy_roundtrips() {
    let receipt_db_path = unique_path("evidence-export-federated", ".sqlite3");
    let output_dir = unique_path("evidence-export-federated-output", "");
    let federation_policy_path = unique_path("federation-policy", ".json");
    let signing_seed_path = unique_path("federation-policy-seed", ".txt");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let capability = capability_with_id("cap-federated", &subject, &issuer);
        store
            .record_capability_snapshot(&capability, None)
            .expect("record capability snapshot");
        let seq1 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts("rcpt-1", "cap-federated", 100))
            .expect("append receipt");
        let seq2 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts("rcpt-2", "cap-federated", 101))
            .expect("append receipt");
        let canonical = store
            .receipts_canonical_bytes_range(seq1, seq2)
            .expect("canonical bytes");
        let checkpoint = build_checkpoint(
            1,
            seq1,
            seq2,
            &canonical
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>(),
            &issuer,
        )
        .expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    create_federation_policy(
        &federation_policy_path,
        &signing_seed_path,
        "org-alpha",
        "org-beta",
        "cap-federated",
        4_102_444_800,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .arg("--receipt-db")
        .arg(&receipt_db_path)
        .arg("evidence")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .arg("--federation-policy")
        .arg(&federation_policy_path)
        .output()
        .expect("run chio evidence export with federation policy");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(output_dir.join("federation-policy.json").exists());
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output_dir.join("manifest.json")).expect("read manifest"))
            .expect("parse manifest");
    assert_eq!(manifest["federationPolicy"]["issuer"], "org-alpha");
    assert_eq!(manifest["federationPolicy"]["partner"], "org-beta");
    assert_eq!(manifest["federationPolicy"]["requireProofs"], true);

    let verify = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .arg("evidence")
        .arg("verify")
        .arg("--input")
        .arg(&output_dir)
        .output()
        .expect("run chio evidence verify");

    assert!(
        verify.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn evidence_import_roundtrip_surfaces_imported_trust_without_rewriting_local_history() {
    let source_receipt_db_path = unique_path("evidence-export-imported-trust-source", ".sqlite3");
    let imported_receipt_db_path =
        unique_path("evidence-export-imported-trust-imported", ".sqlite3");
    let output_dir = unique_path("evidence-export-imported-trust-output", "");
    let federation_policy_path = unique_path("federation-policy-imported-trust", ".json");
    let signing_seed_path = unique_path("federation-policy-imported-trust-seed", ".txt");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let subject_hex = subject.public_key().to_hex();

    {
        let store =
            SqliteReceiptStore::open(&source_receipt_db_path).expect("open source receipt store");
        let capability = capability_with_id("cap-federated-reputation", &subject, &issuer);
        store
            .record_capability_snapshot(&capability, None)
            .expect("record capability snapshot");
        let seq1 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts(
                "rcpt-imported-1",
                "cap-federated-reputation",
                100,
            ))
            .expect("append first receipt");
        let seq2 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts(
                "rcpt-imported-2",
                "cap-federated-reputation",
                101,
            ))
            .expect("append second receipt");
        let canonical = store
            .receipts_canonical_bytes_range(seq1, seq2)
            .expect("canonical bytes");
        let checkpoint = build_checkpoint(
            1,
            seq1,
            seq2,
            &canonical
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>(),
            &issuer,
        )
        .expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    create_federation_policy(
        &federation_policy_path,
        &signing_seed_path,
        "org-alpha",
        "org-beta",
        "cap-federated-reputation",
        4_102_444_800,
    );

    let export = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .arg("--receipt-db")
        .arg(&source_receipt_db_path)
        .arg("evidence")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .arg("--federation-policy")
        .arg(&federation_policy_path)
        .output()
        .expect("run chio evidence export");
    assert!(
        export.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&export.stdout),
        String::from_utf8_lossy(&export.stderr)
    );

    let import = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            imported_receipt_db_path
                .to_str()
                .expect("imported receipt db path"),
            "evidence",
            "import",
            "--input",
            output_dir.to_str().expect("evidence output path"),
        ])
        .output()
        .expect("run chio evidence import");
    assert!(
        import.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&import.stdout),
        String::from_utf8_lossy(&import.stderr)
    );

    let imported_share: serde_json::Value =
        serde_json::from_slice(&import.stdout).expect("parse evidence import output");
    assert_eq!(imported_share["issuer"], "org-alpha");
    assert_eq!(imported_share["partner"], "org-beta");

    let reputation = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            imported_receipt_db_path
                .to_str()
                .expect("imported receipt db path"),
            "reputation",
            "local",
            "--subject-public-key",
            &subject_hex,
        ])
        .output()
        .expect("run imported reputation local");
    assert!(
        reputation.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&reputation.stdout),
        String::from_utf8_lossy(&reputation.stderr)
    );

    let body: serde_json::Value =
        serde_json::from_slice(&reputation.stdout).expect("parse reputation local output");
    assert_eq!(body["scorecard"]["history_depth"]["receipt_count"], 0);
    assert_eq!(body["importedTrust"]["signalCount"], 1);
    assert_eq!(body["importedTrust"]["acceptedCount"], 1);
    assert_eq!(
        body["importedTrust"]["signals"][0]["provenance"]["issuer"],
        "org-alpha"
    );
    assert_eq!(
        body["importedTrust"]["signals"][0]["provenance"]["partner"],
        "org-beta"
    );
    assert_eq!(
        body["importedTrust"]["signals"][0]["scorecard"]["history_depth"]["receipt_count"],
        2
    );
    assert!(
        body["importedTrust"]["signals"][0]["attenuatedCompositeScore"]
            .as_f64()
            .expect("attenuated imported score")
            > 0.0
    );
}

#[test]
fn evidence_export_rejects_scope_outside_federation_policy() {
    let receipt_db_path = unique_path("evidence-export-federated-scope", ".sqlite3");
    let output_dir = unique_path("evidence-export-federated-scope-output", "");
    let federation_policy_path = unique_path("federation-policy-scope", ".json");
    let signing_seed_path = unique_path("federation-policy-scope-seed", ".txt");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let capability = capability_with_id("cap-one", &subject, &issuer);
        store
            .record_capability_snapshot(&capability, None)
            .expect("record capability snapshot");
    }

    create_federation_policy(
        &federation_policy_path,
        &signing_seed_path,
        "org-alpha",
        "org-beta",
        "cap-one",
        4_102_444_800,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .arg("--receipt-db")
        .arg(&receipt_db_path)
        .arg("evidence")
        .arg("export")
        .arg("--output")
        .arg(&output_dir)
        .arg("--federation-policy")
        .arg(&federation_policy_path)
        .arg("--capability")
        .arg("cap-two")
        .output()
        .expect("run chio evidence export with mismatched federation policy");

    assert!(!output.status.success(), "export should fail");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("outside the signed federation policy"),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn evidence_export_supports_remote_trust_control_with_federation_policy() {
    let dir = unique_path("evidence-export-remote", "");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let output_dir = dir.join("evidence-package");
    let federation_policy_path = dir.join("federation-policy.json");
    let signing_seed_path = dir.join("federation-policy-seed.txt");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let capability = capability_with_id("cap-remote-federated", &subject, &issuer);
        store
            .record_capability_snapshot(&capability, None)
            .expect("record capability snapshot");
        let seq1 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts(
                "rcpt-1",
                "cap-remote-federated",
                100,
            ))
            .expect("append receipt");
        let seq2 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts(
                "rcpt-2",
                "cap-remote-federated",
                101,
            ))
            .expect("append receipt");
        let canonical = store
            .receipts_canonical_bytes_range(seq1, seq2)
            .expect("canonical bytes");
        let checkpoint = build_checkpoint(
            1,
            seq1,
            seq2,
            &canonical
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>(),
            &issuer,
        )
        .expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    create_federation_policy(
        &federation_policy_path,
        &signing_seed_path,
        "org-alpha",
        "org-beta",
        "cap-remote-federated",
        4_102_444_800,
    );

    let listen = reserve_listen_addr();
    let service_token = "remote-evidence-export-token";
    let base_url = format!("http://{listen}");
    let _service = spawn_trust_service(
        listen,
        service_token,
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
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "evidence",
            "export",
            "--output",
            output_dir.to_str().expect("output dir"),
            "--federation-policy",
            federation_policy_path
                .to_str()
                .expect("federation policy path"),
        ])
        .output()
        .expect("run remote chio evidence export");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(output_dir.join("manifest.json").exists());
    assert!(output_dir.join("federation-policy.json").exists());

    let verify = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .arg("evidence")
        .arg("verify")
        .arg("--input")
        .arg(&output_dir)
        .output()
        .expect("run chio evidence verify");

    assert!(
        verify.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn evidence_verify_detects_tampered_receipt_even_if_manifest_hash_is_updated() {
    let receipt_db_path = unique_path("evidence-verify-tamper", ".sqlite3");
    let output_dir = unique_path("evidence-verify-tamper-output", "");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let capability = capability_with_id("cap-evidence-verify", &subject, &issuer);
        store
            .record_capability_snapshot(&capability, None)
            .expect("record capability snapshot");
        let seq1 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts(
                "rcpt-1",
                "cap-evidence-verify",
                100,
            ))
            .expect("append receipt");
        let seq2 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts(
                "rcpt-2",
                "cap-evidence-verify",
                101,
            ))
            .expect("append receipt");
        let canonical = store
            .receipts_canonical_bytes_range(seq1, seq2)
            .expect("canonical bytes");
        let checkpoint = build_checkpoint(
            1,
            seq1,
            seq2,
            &canonical
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>(),
            &issuer,
        )
        .expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    export_fixture_package(&receipt_db_path, &output_dir);

    let receipts_path = output_dir.join("receipts.ndjson");
    let tampered_receipts = fs::read_to_string(&receipts_path)
        .expect("read receipts")
        .replace("\"tool_name\":\"bash\"", "\"tool_name\":\"cat\"");
    fs::write(&receipts_path, tampered_receipts.as_bytes()).expect("write tampered receipts");

    let manifest_path = output_dir.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    let files = manifest["files"].as_array_mut().expect("manifest files");
    let tampered_hash = sha256_hex(tampered_receipts.as_bytes());
    for file in files {
        if file["path"] == "receipts.ndjson" {
            file["sha256"] = serde_json::Value::String(tampered_hash.clone());
            file["bytes"] = serde_json::Value::from(tampered_receipts.len() as u64);
        }
    }
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");

    let verify = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .arg("evidence")
        .arg("verify")
        .arg("--input")
        .arg(&output_dir)
        .output()
        .expect("run chio evidence verify");

    assert!(
        !verify.status.success(),
        "verify should fail on tampered receipt"
    );
    assert!(
        String::from_utf8_lossy(&verify.stderr).contains("signature verification failed"),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );

    let _ = fs::remove_file(receipt_db_path);
    let _ = fs::remove_dir_all(output_dir);
}
