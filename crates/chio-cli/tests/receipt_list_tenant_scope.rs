//! Local `chio receipt list` / `chio receipt explain` tenant-scope tests.
//!
//! These exercise the P1 fix that prevents the local `--receipt-db`
//! reading path from silently defaulting to admin-all when the operator
//! omits both `--tenant <id>` and `--admin-all`. Cross-tenant data must
//! never leak from a multi-tenant SQLite receipt store unless the
//! operator explicitly opts in.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::crypto::Keypair;
use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction, TrustLevel};
use chio_store_sqlite::SqliteReceiptStore;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn unique_db_path(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("chio-{prefix}-{nonce}.sqlite3"))
}

fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));
}

fn signed_receipt(id: &str, capability_id: &str, tenant: Option<&str>) -> ChioReceipt {
    let kp = Keypair::generate();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_710_000_000,
            capability_id: capability_id.to_string(),
            tool_server: "srv".to_string(),
            tool_name: "ping".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({}))
                .expect("tool action hash"),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "c".to_string(),
            policy_hash: "p".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: tenant.map(str::to_string),
            kernel_key: kp.public_key(),
        },
        &kp,
    )
    .expect("signed receipt")
}

/// A test fixture pairing the SQLite DB path with the receipt IDs
/// produced when the rows were inserted. Receipt IDs are derived
/// canonically from the signed body, not from the caller-provided
/// label, so the actual IDs must be captured here to drive
/// `receipt explain` lookups.
struct MultiTenantFixture {
    path: PathBuf,
    tenant_a_ids: Vec<String>,
    tenant_b_ids: Vec<String>,
}

/// Build a multi-tenant SQLite receipt store with three rows for
/// tenant-A and two for tenant-B, returning the fixture (DB path plus
/// the canonical receipt IDs assigned to each row by the signer).
fn build_multi_tenant_receipt_db(prefix: &str) -> MultiTenantFixture {
    let path = unique_db_path(prefix);
    let store = SqliteReceiptStore::open(&path).expect("open store");
    let mut tenant_a_ids = Vec::new();
    let mut tenant_b_ids = Vec::new();
    for i in 0..3 {
        let r = signed_receipt(
            &format!("rcpt-a-{i}"),
            &format!("cap-a-{i}"),
            Some("tenant-A"),
        );
        tenant_a_ids.push(r.id.clone());
        store
            .append_chio_receipt_returning_seq(&r)
            .expect("append tenant-A receipt");
    }
    for i in 0..2 {
        let r = signed_receipt(
            &format!("rcpt-b-{i}"),
            &format!("cap-b-{i}"),
            Some("tenant-B"),
        );
        tenant_b_ids.push(r.id.clone());
        store
            .append_chio_receipt_returning_seq(&r)
            .expect("append tenant-B receipt");
    }
    drop(store);
    MultiTenantFixture {
        path,
        tenant_a_ids,
        tenant_b_ids,
    }
}

fn run_chio(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args(args)
        .output()
        .expect("run chio binary")
}

#[test]
fn receipt_list_without_tenant_or_admin_all_fails_closed() {
    let fixture = build_multi_tenant_receipt_db("receipt-list-no-flag");
    let path_str = fixture.path.to_str().expect("utf-8 path").to_string();

    let output = run_chio(&[
        "--receipt-db",
        &path_str,
        "receipt",
        "list",
        "--limit",
        "100",
    ]);

    assert!(
        !output.status.success(),
        "receipt list without --tenant/--admin-all must fail closed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--tenant") && stderr.contains("--admin-all"),
        "error must name both flags; got:\n{stderr}"
    );
    // Cross-tenant data must not have been emitted to stdout.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("cap-a-0") && !stdout.contains("cap-b-0"),
        "no receipts may be emitted when the call fails closed; stdout:\n{stdout}"
    );

    cleanup(&fixture.path);
}

#[test]
fn receipt_list_with_tenant_scopes_to_that_tenant() {
    let fixture = build_multi_tenant_receipt_db("receipt-list-tenant");
    let path_str = fixture.path.to_str().expect("utf-8 path").to_string();

    let output = run_chio(&[
        "--receipt-db",
        &path_str,
        "receipt",
        "list",
        "--limit",
        "100",
        "--tenant",
        "tenant-A",
    ]);

    assert!(
        output.status.success(),
        "receipt list --tenant tenant-A must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        3,
        "tenant-A scoped listing must return exactly 3 receipts; got:\n{stdout}"
    );
    for line in &lines {
        let row: serde_json::Value = serde_json::from_str(line).expect("receipt JSON line");
        let tid = row["tenant_id"].as_str();
        assert_eq!(
            tid,
            Some("tenant-A"),
            "tenant-A scoped listing must not leak other tenants; row={row}"
        );
    }
    assert!(
        !stdout.contains("cap-b-"),
        "tenant-A scoped listing must not leak tenant-B receipts; stdout:\n{stdout}"
    );

    cleanup(&fixture.path);
}

#[test]
fn receipt_list_with_admin_all_returns_all_tenants() {
    let fixture = build_multi_tenant_receipt_db("receipt-list-admin-all");
    let path_str = fixture.path.to_str().expect("utf-8 path").to_string();

    let output = run_chio(&[
        "--receipt-db",
        &path_str,
        "receipt",
        "list",
        "--limit",
        "100",
        "--admin-all",
    ]);

    assert!(
        output.status.success(),
        "receipt list --admin-all must succeed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        5,
        "admin-all listing must return all 5 receipts; got:\n{stdout}"
    );
    let mut tenants = std::collections::BTreeSet::new();
    for line in &lines {
        let row: serde_json::Value = serde_json::from_str(line).expect("receipt JSON line");
        if let Some(tid) = row["tenant_id"].as_str() {
            tenants.insert(tid.to_string());
        }
    }
    assert!(
        tenants.contains("tenant-A") && tenants.contains("tenant-B"),
        "admin-all listing must include both tenants; saw {tenants:?}"
    );

    cleanup(&fixture.path);
}

#[test]
fn receipt_list_with_both_tenant_and_admin_all_is_rejected() {
    let fixture = build_multi_tenant_receipt_db("receipt-list-both-flags");
    let path_str = fixture.path.to_str().expect("utf-8 path").to_string();

    let output = run_chio(&[
        "--receipt-db",
        &path_str,
        "receipt",
        "list",
        "--limit",
        "100",
        "--tenant",
        "tenant-A",
        "--admin-all",
    ]);

    assert!(
        !output.status.success(),
        "passing both --tenant and --admin-all must be rejected; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Confirm no cross-tenant data leaked while clap rejected the args.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("cap-a-0") && !stdout.contains("cap-b-0"),
        "no receipts may be emitted when both flags conflict; stdout:\n{stdout}"
    );

    cleanup(&fixture.path);
}

#[test]
fn receipt_explain_without_tenant_or_admin_all_fails_closed() {
    let fixture = build_multi_tenant_receipt_db("receipt-explain-no-flag");
    let path_str = fixture.path.to_str().expect("utf-8 path").to_string();
    let target = fixture
        .tenant_a_ids
        .first()
        .expect("at least one tenant-A receipt")
        .clone();

    let output = run_chio(&["--receipt-db", &path_str, "receipt", "explain", &target]);

    assert!(
        !output.status.success(),
        "receipt explain without --tenant/--admin-all must fail closed; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--tenant") && stderr.contains("--admin-all"),
        "error must name both flags; got:\n{stderr}"
    );
    // No receipt details should have been emitted on stdout.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains(&target),
        "no receipt details may be emitted when the call fails closed; stdout:\n{stdout}"
    );

    cleanup(&fixture.path);
}

#[test]
fn receipt_explain_with_tenant_succeeds() {
    let fixture = build_multi_tenant_receipt_db("receipt-explain-tenant");
    let path_str = fixture.path.to_str().expect("utf-8 path").to_string();
    let target = fixture
        .tenant_a_ids
        .first()
        .expect("at least one tenant-A receipt")
        .clone();

    let output = run_chio(&[
        "--receipt-db",
        &path_str,
        "receipt",
        "explain",
        &target,
        "--tenant",
        "tenant-A",
    ]);

    assert!(
        output.status.success(),
        "receipt explain --tenant tenant-A must succeed for an in-tenant receipt; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&target),
        "receipt explain must surface the requested receipt id; stdout:\n{stdout}"
    );

    cleanup(&fixture.path);
}

#[test]
fn receipt_explain_with_tenant_does_not_cross_tenants() {
    // A tenant-A scoped explain must not find a tenant-B receipt by id.
    let fixture = build_multi_tenant_receipt_db("receipt-explain-cross-tenant");
    let path_str = fixture.path.to_str().expect("utf-8 path").to_string();
    let cross_target = fixture
        .tenant_b_ids
        .first()
        .expect("at least one tenant-B receipt")
        .clone();

    let output = run_chio(&[
        "--receipt-db",
        &path_str,
        "receipt",
        "explain",
        &cross_target,
        "--tenant",
        "tenant-A",
    ]);

    assert!(
        !output.status.success(),
        "receipt explain scoped to tenant-A must not surface a tenant-B receipt; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    cleanup(&fixture.path);
}
