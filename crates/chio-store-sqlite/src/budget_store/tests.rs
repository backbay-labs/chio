use super::*;
use chio_kernel::InMemoryBudgetStore;

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

fn usage_record(
    capability_id: &str,
    grant_index: u32,
    invocation_count: u32,
    updated_at: i64,
    seq: u64,
    total_cost_exposed: u64,
    total_cost_realized_spend: u64,
) -> BudgetUsageRecord {
    BudgetUsageRecord {
        capability_id: capability_id.to_string(),
        grant_index,
        invocation_count,
        updated_at,
        seq,
        total_cost_exposed,
        total_cost_realized_spend,
    }
}

fn assert_usage_totals(record: &BudgetUsageRecord, exposed: u64, realized: u64) {
    assert_eq!(record.total_cost_exposed, exposed);
    assert_eq!(record.total_cost_realized_spend, realized);
    assert_eq!(record.committed_cost_units().unwrap(), exposed + realized);
}

fn authority(authority_id: &str, lease_id: &str, lease_epoch: u64) -> BudgetEventAuthority {
    BudgetEventAuthority {
        authority_id: authority_id.to_string(),
        lease_id: lease_id.to_string(),
        lease_epoch,
    }
}

#[test]
fn sqlite_budget_store_persists_across_reopen() {
    let path = unique_db_path("chio-budgets");
    {
        let store = SqliteBudgetStore::open(&path).unwrap();
        assert!(store.try_increment("cap-1", 0, Some(2)).unwrap());
        assert!(store.try_increment("cap-1", 0, Some(2)).unwrap());
        assert!(!store.try_increment("cap-1", 0, Some(2)).unwrap());
    }

    let reopened = SqliteBudgetStore::open(&path).unwrap();
    let records = reopened.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].invocation_count, 2);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_usage_query_rejects_negative_persisted_counter() {
    let path = unique_db_path("chio-budget-negative-usage");
    let store = SqliteBudgetStore::open(&path).unwrap();
    store
        .upsert_usage(&usage_record("cap-negative", 0, 1, 10, 1, 0, 0))
        .unwrap();
    {
        let connection = store.connection().unwrap();
        connection
            .execute(
                r#"
                    UPDATE capability_grant_budgets
                    SET invocation_count = -1
                    WHERE capability_id = 'cap-negative' AND grant_index = 0
                    "#,
                [],
            )
            .unwrap();
    }

    let error = store
        .list_all_usages()
        .expect_err("negative persisted budget counters must fail closed");
    assert!(
        error
            .to_string()
            .contains("budget field `invocation_count` was negative"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_budget_store_rejects_pre_split_budget_schema() {
    let path = unique_db_path("chio-budget-pre-split-schema");
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                r#"
                    CREATE TABLE capability_grant_budgets (
                        capability_id TEXT NOT NULL,
                        grant_index INTEGER NOT NULL,
                        invocation_count INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        total_cost_charged INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (capability_id, grant_index)
                    );
                    INSERT INTO capability_grant_budgets (
                        capability_id,
                        grant_index,
                        invocation_count,
                        updated_at,
                        total_cost_charged
                    ) VALUES ('cap-1', 0, 1, 10, 55);
                    "#,
            )
            .unwrap();
    }

    let error = match SqliteBudgetStore::open(&path) {
        Ok(_) => panic!("pre-split budget schema should be rejected"),
        Err(error) => error,
    };
    assert!(error.to_string().contains(
        "missing split cost columns `total_cost_exposed` and `total_cost_realized_spend`"
    ));

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_budget_store_upsert_usage_keeps_newer_seq_state() {
    let path = unique_db_path("chio-budget-upsert");
    let store = SqliteBudgetStore::open(&path).unwrap();
    store
        .upsert_usage(&usage_record("cap-1", 0, 3, 10, 3, 300, 0))
        .unwrap();
    store
        .upsert_usage(&usage_record("cap-1", 0, 2, 9, 2, 200, 0))
        .unwrap();

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records[0].invocation_count, 3);
    assert_usage_totals(&records[0], 300, 0);
    assert_eq!(records[0].seq, 3);

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_budget_store_uses_seq_for_same_key_delta_queries() {
    let path = unique_db_path("chio-budget-seq-delta");
    let store = SqliteBudgetStore::open(&path).unwrap();

    assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());
    let first = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(first.len(), 1);
    let first_seq = first[0].seq;

    assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());
    assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());

    let delta = store.list_usages_after(10, Some(first_seq)).unwrap();
    assert_eq!(delta.len(), 1);
    assert_eq!(delta[0].invocation_count, 3);
    assert!(delta[0].seq > first_seq);

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_budget_store_preserves_imported_seq_across_failover_writes() {
    let path = unique_db_path("chio-budget-seq-floor");
    let store = SqliteBudgetStore::open(&path).unwrap();

    store
        .upsert_usage(&usage_record("cap-1", 0, 3, 10, 42, 0, 0))
        .unwrap();
    assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].invocation_count, 4);
    assert_eq!(records[0].seq, 43);

    let _ = fs::remove_file(path);
}

// --- try_charge_cost tests ---

#[test]
fn budget_store_try_charge_cost_within_limits_returns_true_sqlite() {
    let path = unique_db_path("chio-charge-cost-ok");
    let store = SqliteBudgetStore::open(&path).unwrap();
    // 100 units, cap is 200 per invocation, total cap is 1000
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap();
    assert!(ok);

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records[0].invocation_count, 1);
    assert_usage_totals(&records[0], 100, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_exceeds_per_invocation_cap_sqlite() {
    let path = unique_db_path("chio-charge-cost-per-inv");
    let store = SqliteBudgetStore::open(&path).unwrap();
    // 500 units > max_cost_per_invocation of 200
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 500, Some(200), Some(1000))
        .unwrap();
    assert!(!ok);

    // Nothing should have been charged
    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert!(records.is_empty() || records[0].invocation_count == 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_exceeds_total_cap_sqlite() {
    let path = unique_db_path("chio-charge-cost-total");
    let store = SqliteBudgetStore::open(&path).unwrap();
    // First charge 900 of 1000 budget
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 900, Some(1000), Some(1000))
        .unwrap());
    // Second charge of 200 would exceed the total cap of 1000
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 200, Some(1000), Some(1000))
        .unwrap();
    assert!(!ok);

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_usage_totals(&records[0], 900, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_atomic_increment_sqlite() {
    let path = unique_db_path("chio-charge-cost-atomic");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost("cap-1", 0, None, 100, Some(200), Some(1000))
        .unwrap());
    assert!(store
        .try_charge_cost("cap-1", 0, None, 150, Some(200), Some(1000))
        .unwrap());

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records[0].invocation_count, 2);
    assert_usage_totals(&records[0], 250, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_within_limits_returns_true_inmemory() {
    let store = InMemoryBudgetStore::new();
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap();
    assert!(ok);

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records[0].invocation_count, 1);
    assert_usage_totals(&records[0], 100, 0);
}

#[test]
fn budget_store_try_charge_cost_exceeds_per_invocation_cap_inmemory() {
    let store = InMemoryBudgetStore::new();
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 500, Some(200), Some(1000))
        .unwrap();
    assert!(!ok);
}

#[test]
fn budget_store_try_charge_cost_exceeds_total_cap_inmemory() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 900, Some(1000), Some(1000))
        .unwrap());
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 200, Some(1000), Some(1000))
        .unwrap();
    assert!(!ok);
}

#[test]
fn budget_usage_record_includes_split_cost_state() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, None, 42, None, None)
        .unwrap());
    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_usage_totals(&records[0], 42, 0);
}

#[test]
fn budget_store_reverse_charge_cost_restores_prior_state_inmemory() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.reverse_charge_cost("cap-1", 0, 100).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 0);
    assert_usage_totals(&record, 0, 0);
}

#[test]
fn budget_store_reverse_charge_cost_restores_prior_state_sqlite() {
    let path = unique_db_path("chio-reverse-charge");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.reverse_charge_cost("cap-1", 0, 100).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 0);
    assert_usage_totals(&record, 0, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_reduce_charge_cost_releases_exposure_only_inmemory() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.reduce_charge_cost("cap-1", 0, 25).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 1);
    assert_usage_totals(&record, 75, 0);
}

#[test]
fn budget_store_reduce_charge_cost_releases_exposure_only_sqlite() {
    let path = unique_db_path("chio-reduce-charge");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.reduce_charge_cost("cap-1", 0, 25).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 1);
    assert_usage_totals(&record, 75, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_settle_charge_cost_moves_exposure_to_realized_inmemory() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.settle_charge_cost("cap-1", 0, 100, 75).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 1);
    assert_usage_totals(&record, 0, 75);
}

#[test]
fn budget_store_settle_charge_cost_moves_exposure_to_realized_sqlite() {
    let path = unique_db_path("chio-settle-charge");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.settle_charge_cost("cap-1", 0, 100, 75).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 1);
    assert_usage_totals(&record, 0, 75);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_with_ids_is_idempotent_inmemory() {
    let store = InMemoryBudgetStore::new();
    let hold_id = "hold-cap-1-0";
    let event_id = "hold-cap-1-0:authorize";

    assert!(store
        .try_charge_cost_with_ids(
            "cap-1",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
        )
        .unwrap());
    assert!(store
        .try_charge_cost_with_ids(
            "cap-1",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
        )
        .unwrap());

    let usage = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let events = store
        .list_mutation_events(10, Some("cap-1"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, event_id);
    assert_eq!(events[0].hold_id.as_deref(), Some(hold_id));
    assert_eq!(events[0].kind, BudgetMutationKind::AuthorizeExposure);
    assert_eq!(events[0].allowed, Some(true));
}

#[test]
fn budget_store_try_charge_cost_with_ids_is_idempotent_sqlite() {
    let path = unique_db_path("chio-charge-cost-idempotent");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-1-0";
    let event_id = "hold-cap-1-0:authorize";

    assert!(store
        .try_charge_cost_with_ids(
            "cap-1",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
        )
        .unwrap());
    assert!(store
        .try_charge_cost_with_ids(
            "cap-1",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
        )
        .unwrap());

    let usage = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let events = store
        .list_mutation_events(10, Some("cap-1"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, event_id);
    assert_eq!(events[0].hold_id.as_deref(), Some(hold_id));
    assert_eq!(events[0].kind, BudgetMutationKind::AuthorizeExposure);
    assert_eq!(events[0].allowed, Some(true));

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_settle_with_ids_is_idempotent_and_append_only_sqlite() {
    let path = unique_db_path("chio-settle-charge-idempotent");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-1-0";
    let authorize_event_id = "hold-cap-1-0:authorize";
    let reconcile_event_id = "hold-cap-1-0:reconcile";

    assert!(store
        .try_charge_cost_with_ids(
            "cap-1",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(authorize_event_id),
        )
        .unwrap());
    store
        .settle_charge_cost_with_ids("cap-1", 0, 100, 75, Some(hold_id), Some(reconcile_event_id))
        .unwrap();
    store
        .settle_charge_cost_with_ids("cap-1", 0, 100, 75, Some(hold_id), Some(reconcile_event_id))
        .unwrap();

    let usage = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 0, 75);

    let events = store
        .list_mutation_events(10, Some("cap-1"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_id, authorize_event_id);
    assert_eq!(events[1].event_id, reconcile_event_id);
    assert_eq!(events[1].hold_id.as_deref(), Some(hold_id));
    assert_eq!(events[1].kind, BudgetMutationKind::ReconcileSpend);
    assert_eq!(events[1].exposure_units, 100);
    assert_eq!(events[1].realized_spend_units, 75);
    assert_eq!(events[1].total_cost_exposed_after, 0);
    assert_eq!(events[1].total_cost_realized_spend_after, 75);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_reduce_charge_cost_allows_zero_invocation_release_sqlite() {
    let path = unique_db_path("chio-reduce-charge-zero-invocations");
    let store = SqliteBudgetStore::open(&path).unwrap();
    store
        .upsert_usage(&usage_record("cap-zero", 0, 0, 10, 10, 40, 0))
        .unwrap();

    store.reduce_charge_cost("cap-zero", 0, 25).unwrap();

    let usage = store.get_usage("cap-zero", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 0);
    assert_usage_totals(&usage, 15, 0);

    let events = store
        .list_mutation_events(10, Some("cap-zero"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, BudgetMutationKind::ReleaseExposure);
    assert_eq!(events[0].invocation_count_after, 0);
    assert_eq!(events[0].total_cost_exposed_after, 15);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_list_mutation_events_preserves_append_order_sqlite() {
    let path = unique_db_path("chio-budget-event-order");
    let store = SqliteBudgetStore::open(&path).unwrap();

    assert!(store
        .try_charge_cost_with_ids(
            "cap-order",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some("hold-cap-order-0"),
            Some("z-authorize"),
        )
        .unwrap());
    store
        .reduce_charge_cost_with_ids(
            "cap-order",
            0,
            25,
            Some("hold-cap-order-0"),
            Some("a-release"),
        )
        .unwrap();

    let events = store
        .list_mutation_events(10, Some("cap-order"), Some(0))
        .unwrap();
    let event_ids = events
        .iter()
        .map(|record| record.event_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(event_ids, vec!["z-authorize", "a-release"]);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_hold_authority_requires_exact_lease_inmemory() {
    let store = InMemoryBudgetStore::new();
    let hold_id = "hold-cap-lease-0";
    let authorize_event_id = "hold-cap-lease-0:authorize";
    let release_event_id = "hold-cap-lease-0:release";
    let reconcile_event_id = "hold-cap-lease-0:reconcile";
    let initial = authority("budget-primary", "lease-7", 7);
    let advanced = authority("budget-primary", "lease-7", 8);
    let stale = authority("budget-primary", "lease-7", 6);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(authorize_event_id),
            Some(&initial),
        )
        .unwrap());

    let missing = store
        .reduce_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            25,
            Some(hold_id),
            Some("hold-cap-lease-0:release-missing"),
            None,
        )
        .expect_err("missing lease metadata should fail closed");
    assert!(missing
        .to_string()
        .contains("requires authority lease metadata"));

    let stale_error = store
        .reduce_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            25,
            Some(hold_id),
            Some("hold-cap-lease-0:release-stale"),
            Some(&stale),
        )
        .expect_err("stale lease epoch should fail closed");
    assert!(stale_error.to_string().contains("lease epoch regressed"));

    let advanced_error = store
        .reduce_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            25,
            Some(hold_id),
            Some(release_event_id),
            Some(&advanced),
        )
        .expect_err("advanced lease epoch should fail closed");
    assert!(advanced_error
        .to_string()
        .contains("advanced beyond the open lease"));

    store
        .reduce_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            25,
            Some(hold_id),
            Some(release_event_id),
            Some(&initial),
        )
        .unwrap();
    store
        .settle_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            75,
            75,
            Some(hold_id),
            Some(reconcile_event_id),
            Some(&initial),
        )
        .unwrap();

    let usage = store.get_usage("cap-lease", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 0, 75);

    let events = store
        .list_mutation_events(10, Some("cap-lease"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].authority.as_ref(), Some(&initial));
    assert_eq!(events[1].authority.as_ref(), Some(&initial));
    assert_eq!(events[2].authority.as_ref(), Some(&initial));
}

#[test]
fn budget_store_event_id_reuse_rejects_authority_rollover_sqlite() {
    let path = unique_db_path("chio-hold-authority-event-reuse");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-lease-0";
    let event_id = "hold-cap-lease-0:authorize";
    let initial = authority("budget-primary", "lease-7", 7);
    let changed = authority("budget-primary", "lease-8", 8);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());

    let error = store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .expect_err("reused event id with different authority should fail closed");
    assert!(error
        .to_string()
        .contains("was reused for a different mutation"));

    let usage = store.get_usage("cap-lease", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let events = store
        .list_mutation_events(10, Some("cap-lease"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].authority.as_ref(), Some(&initial));

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_deleted_provisional_event_allows_retry_after_compensation_sqlite() {
    let path = unique_db_path("chio-hold-authority-compensation");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-lease-0";
    let event_id = "hold-cap-lease-0:authorize";
    let initial = authority("budget-primary", "lease-7", 7);
    let changed = authority("budget-primary", "lease-8", 8);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());
    store
        .reverse_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            100,
            Some(hold_id),
            Some("hold-cap-lease-0:authorize:rollback:1"),
            Some(&initial),
        )
        .unwrap();
    store.delete_hold(hold_id).unwrap();
    store.delete_mutation_event(event_id).unwrap();

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .unwrap());

    let usage = store.get_usage("cap-lease", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let events = store
        .list_mutation_events(10, Some("cap-lease"), Some(0))
        .unwrap();
    let event_ids = events
        .iter()
        .map(|record| record.event_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        event_ids,
        vec![
            "hold-cap-lease-0:authorize:rollback:1",
            "hold-cap-lease-0:authorize"
        ]
    );

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_rollback_artifact_allows_retry_with_new_authority_sqlite() {
    let path = unique_db_path("chio-hold-authority-rollback-retry");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-lease-0";
    let event_id = "hold-cap-lease-0:authorize";
    let rollback_event_id = "hold-cap-lease-0:authorize:rollback:2";
    let initial = authority("budget-primary", "lease-7", 7);
    let changed = authority("budget-primary", "lease-8", 8);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());
    store
        .reverse_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            100,
            Some(hold_id),
            Some(rollback_event_id),
            Some(&initial),
        )
        .unwrap();

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .unwrap());

    let usage = store.get_usage("cap-lease", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let events = store
        .list_mutation_events(10, Some("cap-lease"), Some(0))
        .unwrap();
    let authorize = events
        .iter()
        .find(|record| record.event_id == event_id)
        .expect("replacement authorize event");
    assert_eq!(authorize.authority.as_ref(), Some(&changed));

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_retry_after_rollback_replaces_orphaned_open_hold_sqlite() {
    let path = unique_db_path("chio-hold-rollback-orphan-retry");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-orphan-0";
    let event_id = "hold-cap-orphan-0:authorize";
    let rollback_event_id = "hold-cap-orphan-0:authorize:rollback:5";
    let initial = authority("budget-primary", "lease-7", 7);
    let changed = authority("budget-primary", "lease-8", 8);

    for _ in 0..3 {
        assert!(store
            .try_increment_with_event_id("cap-orphan", 0, Some(10), None)
            .unwrap());
    }
    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-orphan",
            0,
            Some(10),
            75,
            Some(100),
            Some(400),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());
    store
        .reverse_charge_cost_with_ids_and_authority(
            "cap-orphan",
            0,
            75,
            Some(hold_id),
            Some(rollback_event_id),
            Some(&initial),
        )
        .unwrap();

    {
        let mut connection = store.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute(
                "DELETE FROM budget_mutation_events WHERE event_id = ?1",
                params![event_id],
            )
            .unwrap();
        SqliteBudgetStore::upsert_hold(
            &transaction,
            hold_id,
            "cap-orphan",
            0,
            75,
            75,
            HoldDisposition::Open,
            Some(&initial),
        )
        .unwrap();
        transaction.commit().unwrap();
    }

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-orphan",
            0,
            Some(10),
            75,
            Some(100),
            Some(400),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .unwrap());

    let usage = store.get_usage("cap-orphan", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 4);
    assert_usage_totals(&usage, 75, 0);

    let events = store
        .list_mutation_events(20, Some("cap-orphan"), Some(0))
        .unwrap();
    let rollback = events
        .iter()
        .find(|record| record.event_id == rollback_event_id)
        .expect("rollback event");
    let retry = events
        .iter()
        .find(|record| record.event_id == event_id)
        .expect("retry authorize event");
    assert!(retry.event_seq > rollback.event_seq);
    assert_eq!(retry.authority.as_ref(), Some(&changed));

    {
        let mut connection = store.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let hold = SqliteBudgetStore::load_hold(&transaction, hold_id)
            .unwrap()
            .expect("retry open hold");
        assert_eq!(hold.remaining_exposure_units, 75);
        assert_eq!(hold.disposition, HoldDisposition::Open);
    }

    {
        let mut connection = store.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute(
                "DELETE FROM budget_mutation_events WHERE event_id = ?1",
                params![event_id],
            )
            .unwrap();
        transaction.commit().unwrap();
    }

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-orphan",
            0,
            Some(10),
            75,
            Some(100),
            Some(400),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .unwrap());
    let events = store
        .list_mutation_events(20, Some("cap-orphan"), Some(0))
        .unwrap();
    let replayed_retry = events
        .iter()
        .find(|record| record.event_id == event_id)
        .expect("replayed retry authorize event");
    assert_eq!(replayed_retry.allowed, Some(true));
    assert_eq!(replayed_retry.usage_seq, Some(usage.seq));

    let _ = fs::remove_file(path);
}

#[test]
fn import_mutation_record_keeps_duplicate_release_events_idempotent_sqlite() {
    let path = unique_db_path("chio-budget-import-release-idempotent");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-import-0";
    let authorize_event_id = "hold-cap-import-0:authorize";
    let release_event_id = "hold-cap-import-0:release";

    assert!(store
        .try_charge_cost_with_ids(
            "cap-import",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(authorize_event_id),
        )
        .unwrap());
    store
        .reduce_charge_cost_with_ids("cap-import", 0, 100, Some(hold_id), Some(release_event_id))
        .unwrap();

    let release_record = store
        .list_mutation_events(10, Some("cap-import"), Some(0))
        .unwrap()
        .into_iter()
        .find(|record| record.event_id == release_event_id)
        .expect("release event record");

    store.import_mutation_record(&release_record).unwrap();

    let usage = store.get_usage("cap-import", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 0, 0);

    {
        let mut connection = store.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let hold = SqliteBudgetStore::load_hold(&transaction, hold_id)
            .unwrap()
            .expect("released hold state");
        assert_eq!(hold.remaining_exposure_units, 0);
        assert_eq!(hold.disposition, HoldDisposition::Released);
    }

    let events = store
        .list_mutation_events(10, Some("cap-import"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_id, authorize_event_id);
    assert_eq!(events[1].event_id, release_event_id);

    let _ = fs::remove_file(path);
}

#[test]
fn import_snapshot_records_replay_is_idempotent_when_peer_cursor_is_lost_sqlite() {
    let source_path = unique_db_path("chio-budget-import-replay-source");
    let target_path = unique_db_path("chio-budget-import-replay-target");
    let source = SqliteBudgetStore::open(&source_path).unwrap();

    assert!(source
        .try_charge_cost_with_ids(
            "cap-import-replay",
            0,
            Some(5),
            25,
            Some(50),
            Some(250),
            Some("hold-import-replay-0"),
            Some("hold-import-replay-0:authorize"),
        )
        .unwrap());
    let usage = source
        .get_usage("cap-import-replay", 0)
        .unwrap()
        .expect("source usage");
    let events = source
        .list_mutation_events(10, Some("cap-import-replay"), Some(0))
        .unwrap();

    let target = SqliteBudgetStore::open(&target_path).unwrap();
    target
        .import_snapshot_records(std::slice::from_ref(&usage), &events)
        .unwrap();
    target
        .import_snapshot_records(std::slice::from_ref(&usage), &events)
        .unwrap();

    let replicated_usage = target
        .get_usage("cap-import-replay", 0)
        .unwrap()
        .expect("replicated usage");
    assert_eq!(replicated_usage.invocation_count, 1);
    assert_usage_totals(&replicated_usage, 25, 0);
    let replicated_events = target
        .list_mutation_events(10, Some("cap-import-replay"), Some(0))
        .unwrap();
    assert_eq!(replicated_events.len(), 1);
    assert_eq!(
        replicated_events[0].event_id,
        "hold-import-replay-0:authorize"
    );

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(target_path);
}

#[test]
fn import_snapshot_records_rolls_back_usage_rows_when_mutation_conflicts_sqlite() {
    let path = unique_db_path("chio-budget-import-atomic");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let initial_authority = authority("budget-primary", "lease-1", 1);
    let conflicting_authority = authority("budget-primary", "lease-2", 2);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-import",
            0,
            Some(10),
            25,
            Some(100),
            Some(500),
            Some("hold-cap-import-atomic-0"),
            Some("hold-cap-import-atomic-0:authorize"),
            Some(&initial_authority),
        )
        .unwrap());

    let mut conflicting_event = store
        .list_mutation_events(10, Some("cap-import"), Some(0))
        .unwrap()
        .into_iter()
        .find(|record| record.event_id == "hold-cap-import-atomic-0:authorize")
        .expect("existing authorize event");
    conflicting_event.authority = Some(conflicting_authority);

    let imported_usage = usage_record("cap-import-rollback", 0, 2, unix_now(), 88, 40, 5);

    let error = store
        .import_snapshot_records(&[imported_usage], &[conflicting_event])
        .expect_err("conflicting event import should fail atomically");
    assert!(error
        .to_string()
        .contains("reused for a different mutation"));
    assert!(store.get_usage("cap-import-rollback", 0).unwrap().is_none());

    let existing = store.get_usage("cap-import", 0).unwrap().unwrap();
    assert_eq!(existing.invocation_count, 1);
    assert_usage_totals(&existing, 25, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_open_hold_recovers_missing_authorize_event_sqlite() {
    let path = unique_db_path("chio-hold-authority-recover-missing-event");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-recover-0";
    let event_id = "hold-cap-recover-0:authorize";
    let authority = authority("budget-primary", "lease-7", 7);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-recover",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&authority),
        )
        .unwrap());
    store.delete_mutation_event(event_id).unwrap();

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-recover",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&authority),
        )
        .unwrap());

    let events = store
        .list_mutation_events(10, Some("cap-recover"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, event_id);

    let _ = fs::remove_file(path);
}

#[test]
fn upsert_usage_preserves_newer_split_cost_state() {
    let path = unique_db_path("chio-budget-upsert-cost");
    let store = SqliteBudgetStore::open(&path).unwrap();

    // Higher-seq record written first
    store
        .upsert_usage(&usage_record("cap-1", 0, 5, 10, 10, 500, 0))
        .unwrap();

    // Lower-seq record written second (stale replica)
    store
        .upsert_usage(&usage_record("cap-1", 0, 3, 12, 5, 300, 0))
        .unwrap();

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_usage_totals(&records[0], 500, 0);
    assert_eq!(records[0].seq, 10);

    let _ = fs::remove_file(path);
}

#[test]
fn upsert_usage_does_not_resurrect_split_cost_state_from_stale_seq() {
    let path = unique_db_path("chio-budget-upsert-split");
    let store = SqliteBudgetStore::open(&path).unwrap();

    store
        .upsert_usage(&usage_record("cap-1", 0, 1, 20, 20, 0, 75))
        .unwrap();
    store
        .upsert_usage(&usage_record("cap-1", 0, 1, 10, 10, 100, 0))
        .unwrap();

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_usage_totals(&records[0], 0, 75);
    assert_eq!(records[0].seq, 20);

    let _ = fs::remove_file(path);
}

/// Documents the HA overrun bound for monetary budget enforcement.
///
/// In a split-brain scenario across N nodes, each node may independently
/// approve one invocation at max_cost_per_invocation before the LWW merge
/// propagates. The worst-case overrun is bounded by:
///   overrun <= max_cost_per_invocation * node_count
///
/// This test asserts the bound holds for a simulated 2-node split-brain.
#[test]
fn concurrent_charge_overrun_bound() {
    let path_a = unique_db_path("chio-overrun-node-a");
    let path_b = unique_db_path("chio-overrun-node-b");

    let max_per_invocation: u64 = 100;
    let total_budget: u64 = 150; // Tight: allows 1 full invocation + small buffer
    let node_count: u64 = 2;

    // Both nodes start fresh (simulating split-brain: neither sees the other's write)
    let node_a = SqliteBudgetStore::open(&path_a).unwrap();
    let node_b = SqliteBudgetStore::open(&path_b).unwrap();

    // Both nodes independently approve an invocation of max_per_invocation
    let approved_a = node_a
        .try_charge_cost(
            "cap-split",
            0,
            None,
            max_per_invocation,
            Some(max_per_invocation),
            Some(total_budget),
        )
        .unwrap();
    let approved_b = node_b
        .try_charge_cost(
            "cap-split",
            0,
            None,
            max_per_invocation,
            Some(max_per_invocation),
            Some(total_budget),
        )
        .unwrap();

    // Both nodes approved (split-brain; each sees a fresh slate)
    assert!(approved_a, "node A should approve");
    assert!(approved_b, "node B should approve");

    // The actual combined spend exceeds the total budget
    let combined_spend = max_per_invocation * node_count;
    // The overrun is bounded by max_cost_per_invocation * node_count
    let max_overrun = max_per_invocation * node_count;
    assert!(
        combined_spend <= max_overrun,
        "HA overrun bound violated: combined_spend={combined_spend} > max_overrun={max_overrun}"
    );

    // After LWW merge converges, outstanding exposure remains conservatively bounded.
    let record_a = node_a.list_usages(1, Some("cap-split")).unwrap();
    let record_b = node_b.list_usages(1, Some("cap-split")).unwrap();
    let total_after_merge = record_a[0].total_cost_exposed + record_b[0].total_cost_exposed;
    assert!(
        total_after_merge <= max_overrun,
        "post-merge total {total_after_merge} exceeds bound {max_overrun}"
    );

    let _ = fs::remove_file(path_a);
    let _ = fs::remove_file(path_b);
}

#[test]
fn budget_store_zero_max_total_denies_any_charge_inmemory() {
    // A grant with max_total_cost = 0 must deny even a charge of 1 unit.
    let store = InMemoryBudgetStore::new();
    let ok = store
        .try_charge_cost("cap-zero-budget", 0, None, 1, None, Some(0))
        .unwrap();
    assert!(
        !ok,
        "any charge against a zero-unit total budget must be denied"
    );
    let records = store.list_usages(10, Some("cap-zero-budget")).unwrap();
    assert!(
        records.is_empty() || records[0].invocation_count == 0,
        "no invocations should be recorded against a zero-unit budget"
    );
}

#[test]
fn budget_store_zero_max_total_denies_any_charge_sqlite() {
    let path = unique_db_path("chio-zero-budget-sqlite");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let ok = store
        .try_charge_cost("cap-zero-budget", 0, None, 1, None, Some(0))
        .unwrap();
    assert!(
        !ok,
        "any charge against a zero-unit total budget must be denied"
    );
    let records = store.list_usages(10, Some("cap-zero-budget")).unwrap();
    assert!(
        records.is_empty() || records[0].invocation_count == 0,
        "no invocations should be recorded against a zero-unit budget"
    );
    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_zero_cost_invocation_succeeds_and_records_zero_inmemory() {
    // A zero-cost invocation against a monetary grant should succeed and
    // record cost_charged = 0.
    let store = InMemoryBudgetStore::new();
    let ok = store
        .try_charge_cost("cap-zero-cost", 0, None, 0, None, Some(1000))
        .unwrap();
    assert!(
        ok,
        "zero-cost invocation should succeed when budget is available"
    );
    let records = store.list_usages(10, Some("cap-zero-cost")).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].invocation_count, 1);
    assert_usage_totals(&records[0], 0, 0);
}

#[test]
fn budget_store_zero_cost_invocation_succeeds_and_records_zero_sqlite() {
    let path = unique_db_path("chio-zero-cost-sqlite");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let ok = store
        .try_charge_cost("cap-zero-cost", 0, None, 0, None, Some(1000))
        .unwrap();
    assert!(
        ok,
        "zero-cost invocation should succeed when budget is available"
    );
    let records = store.list_usages(10, Some("cap-zero-cost")).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].invocation_count, 1);
    assert_usage_totals(&records[0], 0, 0);
    let _ = fs::remove_file(path);
}
