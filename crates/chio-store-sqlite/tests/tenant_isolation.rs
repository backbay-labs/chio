//! Multi-tenant receipt isolation tests for
//! `chio_store_sqlite::SqliteReceiptStore`.
//!
//! The scenario mirrors the roadmap acceptance criterion:
//!
//!   Tenant A writes 5 receipts, tenant B writes 3, and an operator's
//!   pre-migration session writes 2 legacy untagged rows. The store
//!   must:
//!     * return 5 rows for `tenant_filter = Some("tenant-A")` by
//!       default under strict isolation;
//!     * return 3 rows for `tenant_filter = Some("tenant-B")` by
//!       default under strict isolation;
//!     * return 5 + 2 (= 7) and 3 + 2 (= 5) rows respectively only when
//!       explicit compatibility mode is enabled;
//!     * return all 10 rows for `tenant_filter = None` (admin / compat).
//!
//! The tenant_id is derived from the receipt body -- the store does not
//! accept caller-injected tenant hints, per Phase 1.5 threat model.

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::crypto::Keypair;
use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction};
use chio_kernel::receipt_query::ReceiptQuery;
use chio_store_sqlite::SqliteReceiptStore;

trait TestResultOk<T, E> {
    fn test_expect(self, context: &'static str) -> T;
    fn test_unwrap(self) -> T;
}

impl<T, E> TestResultOk<T, E> for Result<T, E> {
    fn test_expect(self, context: &'static str) -> T {
        match self {
            Ok(value) => value,
            Err(_) => panic!("{context}"),
        }
    }

    fn test_unwrap(self) -> T {
        match self {
            Ok(value) => value,
            Err(_) => panic!("expected Ok result"),
        }
    }
}

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("chio-{prefix}-{nonce}.sqlite3"))
}

fn cleanup(path: &std::path::Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(format!("{}-wal", path.display()));
    let _ = fs::remove_file(format!("{}-shm", path.display()));
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
                .test_expect("tool action hash"),
            decision: Decision::Allow,
            content_hash: "c".to_string(),
            policy_hash: "p".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: tenant.map(str::to_string),
            kernel_key: kp.public_key(),
        },
        &kp,
    )
    .test_expect("signed receipt")
}

fn basic_query(tenant: Option<String>) -> ReceiptQuery {
    ReceiptQuery {
        limit: chio_kernel::MAX_QUERY_LIMIT,
        tenant_filter: tenant,
        ..ReceiptQuery::default()
    }
}

#[test]
fn tenant_scoped_queries_respect_and_leak_only_legacy_null_rows() {
    let path = unique_db_path("tenant-isolation");
    let store = SqliteReceiptStore::open(&path).test_expect("open store");
    assert!(
        store.strict_tenant_isolation_enabled(),
        "strict tenant isolation must be enabled by default"
    );

    // 5 receipts for tenant A.
    for i in 0..5 {
        let r = signed_receipt(
            &format!("rcpt-a-{i}"),
            &format!("cap-a-{i}"),
            Some("tenant-A"),
        );
        store
            .append_chio_receipt_returning_seq(&r)
            .test_expect("append tenant-A receipt");
    }
    // 3 receipts for tenant B.
    for i in 0..3 {
        let r = signed_receipt(
            &format!("rcpt-b-{i}"),
            &format!("cap-b-{i}"),
            Some("tenant-B"),
        );
        store
            .append_chio_receipt_returning_seq(&r)
            .test_expect("append tenant-B receipt");
    }
    // 2 pre-migration legacy receipts without a tenant_id. These land in
    // the store with `tenant_id IS NULL`.
    for i in 0..2 {
        let r = signed_receipt(
            &format!("rcpt-legacy-{i}"),
            &format!("cap-legacy-{i}"),
            None,
        );
        store
            .append_chio_receipt_returning_seq(&r)
            .test_expect("append legacy receipt");
    }

    // Default strict mode: tenant A only sees its own rows.
    let a_page = store
        .query_receipts(&basic_query(Some("tenant-A".to_string())))
        .test_expect("query tenant-A");
    assert_eq!(
        a_page.total_count, 5,
        "tenant A default visibility must exclude legacy NULL rows"
    );
    assert_eq!(a_page.receipts.len(), 5);
    for stored in &a_page.receipts {
        assert_eq!(stored.receipt.tenant_id.as_deref(), Some("tenant-A"));
    }

    // Tenant B sees only its own rows by default.
    let b_page = store
        .query_receipts(&basic_query(Some("tenant-B".to_string())))
        .test_expect("query tenant-B");
    assert_eq!(b_page.total_count, 3);
    assert_eq!(b_page.receipts.len(), 3);
    for stored in &b_page.receipts {
        assert_eq!(stored.receipt.tenant_id.as_deref(), Some("tenant-B"));
    }

    // Explicit compatibility mode re-enables the NULL fallback set.
    store.with_strict_tenant_isolation(false);
    assert!(
        !store.strict_tenant_isolation_enabled(),
        "compatibility mode must be opt-in"
    );

    let a_compat = store
        .query_receipts(&basic_query(Some("tenant-A".to_string())))
        .test_expect("query tenant-A compat");
    assert_eq!(
        a_compat.total_count, 7,
        "compat mode must include legacy NULL rows in tenant-A view"
    );
    assert_eq!(a_compat.receipts.len(), 7);
    for stored in &a_compat.receipts {
        let tid = stored.receipt.tenant_id.as_deref();
        assert!(
            tid == Some("tenant-A") || tid.is_none(),
            "tenant A compat query must not leak tenant B rows; saw {tid:?}"
        );
    }

    let b_compat = store
        .query_receipts(&basic_query(Some("tenant-B".to_string())))
        .test_expect("query tenant-B compat");
    assert_eq!(b_compat.total_count, 5);
    for stored in &b_compat.receipts {
        let tid = stored.receipt.tenant_id.as_deref();
        assert!(
            tid == Some("tenant-B") || tid.is_none(),
            "tenant B compat query must not leak tenant A rows; saw {tid:?}"
        );
    }

    // Admin / compat mode: tenant_filter = None returns everything,
    // regardless of strict toggle.
    let admin = store
        .query_receipts(&basic_query(None))
        .test_expect("admin query");
    assert_eq!(admin.total_count, 10);
    assert_eq!(admin.receipts.len(), 10);

    store.with_strict_tenant_isolation(true);

    // Flip strict back on: tenant-scoped queries drop the legacy
    // fallback set again.
    let a_strict_again = store
        .query_receipts(&basic_query(Some("tenant-A".to_string())))
        .test_expect("query tenant-A strict again");
    assert_eq!(a_strict_again.total_count, 5);

    cleanup(&path);
}

#[test]
fn tenant_filter_none_returns_all_rows_regardless_of_tags() {
    let path = unique_db_path("tenant-isolation-all");
    let store = SqliteReceiptStore::open(&path).test_expect("open store");

    // Three distinct tenants + legacy nulls.
    for (tenant, count) in [
        (Some("ten-1"), 4usize),
        (Some("ten-2"), 1),
        (Some("ten-3"), 2),
        (None, 3),
    ] {
        for i in 0..count {
            let id = format!("rcpt-{}-{i}", tenant.unwrap_or("legacy"));
            let capability_id = format!("cap-{id}");
            let r = signed_receipt(&id, &capability_id, tenant);
            store
                .append_chio_receipt_returning_seq(&r)
                .test_expect("append receipt");
        }
    }

    let page = store
        .query_receipts(&basic_query(None))
        .test_expect("query without tenant filter");
    assert_eq!(page.total_count, 10);
    assert_eq!(page.receipts.len(), 10);

    // Even with strict mode flipped on, the `None` filter path is
    // documented as "no filter" and returns everything -- strict mode
    // only affects `Some(id)` queries.
    store.with_strict_tenant_isolation(true);
    let page_admin_strict = store
        .query_receipts(&basic_query(None))
        .test_expect("admin query under strict mode");
    assert_eq!(page_admin_strict.total_count, 10);

    cleanup(&path);
}

#[test]
fn tenant_a_queries_never_return_tenant_b_rows() {
    // Roadmap acceptance: "Receipts from tenant A are invisible to
    // tenant B queries." Verified from both directions and under strict
    // isolation so the NULL-fallback cannot mask a regression.
    let path = unique_db_path("tenant-isolation-cross");
    let store = SqliteReceiptStore::open(&path).test_expect("open store");

    let a = signed_receipt("rcpt-secret-a", "cap-a", Some("tenant-A"));
    let b = signed_receipt("rcpt-secret-b", "cap-b", Some("tenant-B"));
    store.append_chio_receipt_returning_seq(&a).test_unwrap();
    store.append_chio_receipt_returning_seq(&b).test_unwrap();

    store.with_strict_tenant_isolation(true);

    let a_view = store
        .query_receipts(&basic_query(Some("tenant-A".to_string())))
        .test_expect("query tenant-A");
    assert_eq!(a_view.total_count, 1);
    assert_eq!(a_view.receipts.len(), 1);
    assert_eq!(a_view.receipts[0].receipt.id, "rcpt-secret-a");
    assert!(
        !a_view
            .receipts
            .iter()
            .any(|r| r.receipt.id == "rcpt-secret-b"),
        "tenant A MUST NOT see tenant B's receipt under any mode"
    );

    let b_view = store
        .query_receipts(&basic_query(Some("tenant-B".to_string())))
        .test_expect("query tenant-B");
    assert_eq!(b_view.total_count, 1);
    assert_eq!(b_view.receipts[0].receipt.id, "rcpt-secret-b");
    assert!(
        !b_view
            .receipts
            .iter()
            .any(|r| r.receipt.id == "rcpt-secret-a"),
        "tenant B MUST NOT see tenant A's receipt under any mode"
    );

    cleanup(&path);
}
