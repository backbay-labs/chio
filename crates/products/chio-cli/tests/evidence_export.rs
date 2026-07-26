#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    lineage::ChildRequestReceipt, lineage::ChildRequestReceiptBody,
};
use chio_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
use chio_core::sha256_hex;
use chio_kernel::{build_checkpoint, ReceiptStore};
use chio_store_sqlite::SqliteReceiptStore;
use chio_test_support::loopback::{reserve_listen_addr, skip_when_loopback_bind_denied};
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
        .nth(3)
        .expect("workspace root")
        .to_path_buf()
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
            aggregate_invocation_budget: None,
        },
        issuer,
    )
    .expect("sign capability")
}

fn receipt_with_ts(id: &str, capability_id: &str, timestamp: u64) -> ChioReceipt {
    receipt_with_tenant(id, capability_id, timestamp, None)
}

fn receipt_with_tenant(
    id: &str,
    capability_id: &str,
    timestamp: u64,
    tenant_id: Option<&str>,
) -> ChioReceipt {
    let keypair = Keypair::generate();
    receipt_with_keypair(id, capability_id, timestamp, tenant_id, &keypair)
}

fn receipt_with_keypair(
    id: &str,
    capability_id: &str,
    timestamp: u64,
    tenant_id: Option<&str>,
    keypair: &Keypair,
) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"cmd":"echo hi"}))
                .expect("action"),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-1".to_string(),
            policy_hash: "policy-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: tenant_id.map(ToOwned::to_owned),
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        keypair,
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

fn export_fixture_package(receipt_db_path: &Path, output_dir: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .arg("--receipt-db")
        .arg(receipt_db_path)
        .arg("evidence")
        .arg("export")
        .arg("--admin-all")
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
    output_path: &Path,
    signing_seed_path: &Path,
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
            "--admin-all",
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
            .append_chio_receipt_returning_seq(&receipt_with_keypair(
                "rcpt-1",
                "cap-evidence",
                100,
                None,
                &issuer,
            ))
            .expect("append receipt");
        let seq2 = store
            .append_chio_receipt_returning_seq(&receipt_with_keypair(
                "rcpt-2",
                "cap-evidence",
                101,
                None,
                &issuer,
            ))
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
        .arg("--admin-all")
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
        .arg("--admin-all")
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
            .append_chio_receipt_returning_seq(&receipt_with_keypair(
                "rcpt-1",
                "cap-federated",
                100,
                None,
                &issuer,
            ))
            .expect("append receipt");
        let seq2 = store
            .append_chio_receipt_returning_seq(&receipt_with_keypair(
                "rcpt-2",
                "cap-federated",
                101,
                None,
                &issuer,
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
        "cap-federated",
        4_102_444_800,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .arg("--receipt-db")
        .arg(&receipt_db_path)
        .arg("evidence")
        .arg("export")
        .arg("--admin-all")
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
    let authority_seed_path = unique_path("evidence-import-authority-seed", ".txt");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let subject_hex = subject.public_key().to_hex();

    // The source receipts are signed with `issuer`; model the importer choosing
    // to trust that partner's kernel key by seeding the same key as the local
    // authority seed. This lets the imported share's scorecard surface its 2
    // receipts without rewriting the importer's (empty) local history. The
    // share's federation-policy signer is a different key and is deliberately
    // NOT auto-trusted (that would be fail-open).
    std::fs::write(&authority_seed_path, issuer.seed_hex()).expect("write authority seed");

    {
        let store =
            SqliteReceiptStore::open(&source_receipt_db_path).expect("open source receipt store");
        let capability = capability_with_id("cap-federated-reputation", &subject, &issuer);
        store
            .record_capability_snapshot(&capability, None)
            .expect("record capability snapshot");
        let seq1 = store
            .append_chio_receipt_returning_seq(&receipt_with_keypair(
                "rcpt-imported-1",
                "cap-federated-reputation",
                100,
                None,
                &issuer,
            ))
            .expect("append first receipt");
        let seq2 = store
            .append_chio_receipt_returning_seq(&receipt_with_keypair(
                "rcpt-imported-2",
                "cap-federated-reputation",
                101,
                None,
                &issuer,
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
        .arg("--admin-all")
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
            "--authority-seed-file",
            authority_seed_path.to_str().expect("authority seed path"),
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
        .arg("--admin-all")
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
    if skip_when_loopback_bind_denied(
        "evidence_export_supports_remote_trust_control_with_federation_policy",
    ) {
        return;
    }

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
            .append_chio_receipt_returning_seq(&receipt_with_keypair(
                "rcpt-1",
                "cap-remote-federated",
                100,
                None,
                &issuer,
            ))
            .expect("append receipt");
        let seq2 = store
            .append_chio_receipt_returning_seq(&receipt_with_keypair(
                "rcpt-2",
                "cap-remote-federated",
                101,
                None,
                &issuer,
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
            "--admin-all",
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
            .append_chio_receipt_returning_seq(&receipt_with_keypair(
                "rcpt-1",
                "cap-evidence-verify",
                100,
                None,
                &issuer,
            ))
            .expect("append receipt");
        let seq2 = store
            .append_chio_receipt_returning_seq(&receipt_with_keypair(
                "rcpt-2",
                "cap-evidence-verify",
                101,
                None,
                &issuer,
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
    // The signed manifest commits to a semantic summary derived from each
    // receipt's signature and action-hash validity, so tampering the receipt
    // body trips the semantic-summary check before the raw signature pass even
    // when the manifest file hash is refreshed to match the altered bytes.
    assert!(
        String::from_utf8_lossy(&verify.stderr)
            .contains("semantic summary does not match exported data"),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );

    let _ = fs::remove_file(receipt_db_path);
    let _ = fs::remove_dir_all(output_dir);
}

fn build_tenant_scoped_export_fixture(receipt_db_path: &Path, output_dir: &Path, tenant: &str) {
    let store = SqliteReceiptStore::open(receipt_db_path).expect("open receipt store");
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let capability = capability_with_id("cap-tenant-disclosure", &subject, &issuer);
    store
        .record_capability_snapshot(&capability, None)
        .expect("record capability snapshot");
    // Two receipts for the requesting tenant interleaved with two receipts for
    // tenant-b, so a single checkpoint covers both tenants. This is the leak
    // vector under audit: the requesting tenant's export must not silently
    // disclose tenant-b's receipts, but it must document that the signed
    // checkpoint body inherently covers the cross-tenant batch range. The
    // receipt store rejects checkpoints over mixed receipt signers, so all
    // receipts in the batch share the issuer keypair as their kernel key.
    let seq_a1 = store
        .append_chio_receipt_returning_seq(&receipt_with_keypair(
            "rcpt-a-1",
            "cap-tenant-disclosure",
            100,
            Some(tenant),
            &issuer,
        ))
        .expect("append receipt");
    let _seq_b1 = store
        .append_chio_receipt_returning_seq(&receipt_with_keypair(
            "rcpt-b-1",
            "cap-tenant-disclosure",
            101,
            Some("tenant-b"),
            &issuer,
        ))
        .expect("append receipt");
    let _seq_a2 = store
        .append_chio_receipt_returning_seq(&receipt_with_keypair(
            "rcpt-a-2",
            "cap-tenant-disclosure",
            102,
            Some(tenant),
            &issuer,
        ))
        .expect("append receipt");
    let seq_b2 = store
        .append_chio_receipt_returning_seq(&receipt_with_keypair(
            "rcpt-b-2",
            "cap-tenant-disclosure",
            103,
            Some("tenant-b"),
            &issuer,
        ))
        .expect("append receipt");
    let canonical = store
        .receipts_canonical_bytes_range(seq_a1, seq_b2)
        .expect("canonical bytes");
    let checkpoint = build_checkpoint(
        1,
        seq_a1,
        seq_b2,
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

    drop(store);

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .arg("--receipt-db")
        .arg(receipt_db_path)
        .arg("evidence")
        .arg("export")
        .arg("--tenant")
        .arg(tenant)
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

#[test]
fn tenant_evidence_export_omits_cross_tenant_metadata() {
    let receipt_db_path = unique_path("tenant-disclosure-omit", ".sqlite3");
    let output_dir = unique_path("tenant-disclosure-omit-output", "");
    build_tenant_scoped_export_fixture(&receipt_db_path, &output_dir, "tenant-a");

    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output_dir.join("manifest.json")).expect("read manifest"))
            .expect("parse manifest");

    // The tool receipts only include the requesting tenant's receipts.
    assert_eq!(
        manifest["counts"]["toolReceipts"], 2,
        "tenant-scoped export must only include the requesting tenant's receipts"
    );

    // Narrowed cross-tenant metadata: liveDbSizeBytes must NOT leak when the
    // export is scoped to a single tenant, because that field aggregates
    // across every tenant in the live database.
    let retention: serde_json::Value = serde_json::from_slice(
        &fs::read(output_dir.join("retention.json")).expect("read retention"),
    )
    .expect("parse retention");
    assert!(
        retention
            .get("liveDbSizeBytes")
            .map(|value| value.is_null())
            .unwrap_or(true),
        "tenant-scoped retention must not disclose the cross-tenant live database size: {retention}"
    );

    // The receipts ndjson must only contain receipts tagged with tenant-a;
    // receipts.ndjson must not surface any tenant-b records.
    let receipts =
        fs::read_to_string(output_dir.join("receipts.ndjson")).expect("read receipts.ndjson");
    let tenant_a_count = receipts.matches("\"tenant_id\":\"tenant-a\"").count();
    let tenant_b_count = receipts.matches("\"tenant_id\":\"tenant-b\"").count();
    assert_eq!(
        tenant_a_count, 2,
        "exactly the two tenant-a receipts must be exported: {receipts}"
    );
    assert_eq!(
        tenant_b_count, 0,
        "receipts.ndjson must not leak any tenant-b receipt records: {receipts}"
    );

    // The verify subcommand must accept the package as legitimate.
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

    let _ = fs::remove_file(receipt_db_path);
    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn tenant_evidence_export_documents_metadata_disclosure() {
    let receipt_db_path = unique_path("tenant-disclosure-notice", ".sqlite3");
    let output_dir = unique_path("tenant-disclosure-notice-output", "");
    build_tenant_scoped_export_fixture(&receipt_db_path, &output_dir, "tenant-a");

    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output_dir.join("manifest.json")).expect("read manifest"))
            .expect("parse manifest");

    let notice = manifest
        .get("disclosureNotice")
        .expect("tenant-scoped manifest must carry a disclosureNotice field");
    assert_eq!(
        notice["schema"], "chio.evidence_export_disclosure_notice.v1",
        "disclosure notice schema must be the canonical Chio identifier"
    );
    assert!(
        notice["summary"]
            .as_str()
            .map(|summary| summary.contains("cross-tenant")
                || summary.contains("per-batch Merkle tree"))
            .unwrap_or(false),
        "disclosure summary must explain the cross-tenant disclosure: {notice}"
    );

    let body_fields = notice["disclosedCheckpointBodyFields"]
        .as_array()
        .expect("disclosedCheckpointBodyFields must be a JSON array");
    let body_strings = body_fields
        .iter()
        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    for required in [
        "batch_start_seq",
        "batch_end_seq",
        "tree_size",
        "merkle_root",
    ] {
        assert!(
            body_strings.iter().any(|value| value == required),
            "disclosure notice must list {required} as a disclosed checkpoint body field: {body_strings:?}"
        );
    }

    let publication_fields = notice["disclosedPublicationFields"]
        .as_array()
        .expect("disclosedPublicationFields must be a JSON array");
    let publication_strings = publication_fields
        .iter()
        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    for required in ["entry_start_seq", "entry_end_seq", "log_tree_size"] {
        assert!(
            publication_strings.iter().any(|value| value == required),
            "disclosure notice must list {required} as a disclosed publication field: {publication_strings:?}"
        );
    }

    assert!(
        notice["protocolReference"]
            .as_str()
            .map(|reference| !reference.is_empty())
            .unwrap_or(false),
        "disclosure notice must carry a non-empty protocolReference for auditors: {notice}"
    );

    // The README.txt must call out the disclosure so an operator scanning the
    // package directory cannot miss it.
    let readme = fs::read_to_string(output_dir.join("README.txt")).expect("read README.txt");
    assert!(
        readme.contains("Cross-tenant disclosure notice"),
        "README.txt must surface the cross-tenant disclosure notice: {readme}"
    );

    let _ = fs::remove_file(receipt_db_path);
    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn admin_all_evidence_export_omits_tenant_disclosure_notice() {
    let receipt_db_path = unique_path("admin-disclosure-absent", ".sqlite3");
    let output_dir = unique_path("admin-disclosure-absent-output", "");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let capability = capability_with_id("cap-admin-disclosure", &subject, &issuer);
        store
            .record_capability_snapshot(&capability, None)
            .expect("record capability snapshot");
        let seq1 = store
            .append_chio_receipt_returning_seq(&receipt_with_keypair(
                "rcpt-a-1",
                "cap-admin-disclosure",
                100,
                Some("tenant-a"),
                &issuer,
            ))
            .expect("append receipt");
        let seq2 = store
            .append_chio_receipt_returning_seq(&receipt_with_keypair(
                "rcpt-b-1",
                "cap-admin-disclosure",
                101,
                Some("tenant-b"),
                &issuer,
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

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .arg("--receipt-db")
        .arg(&receipt_db_path)
        .arg("evidence")
        .arg("export")
        .arg("--admin-all")
        .arg("--output")
        .arg(&output_dir)
        .output()
        .expect("run chio evidence export");
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output_dir.join("manifest.json")).expect("read manifest"))
            .expect("parse manifest");
    assert!(
        manifest.get("disclosureNotice").is_none()
            || manifest
                .get("disclosureNotice")
                .map(|value| value.is_null())
                .unwrap_or(false),
        "admin-all manifest must not attach a tenant-scoped disclosure notice: {manifest}"
    );

    let _ = fs::remove_file(receipt_db_path);
    let _ = fs::remove_dir_all(output_dir);
}
