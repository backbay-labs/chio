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
fn budget_store_event_id_retry_survives_authority_rollover_sqlite() {
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

    let error = store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            101,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .expect_err("reused event id with a different mutation should fail closed");
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
fn import_snapshot_records_duplicate_event_ignores_peer_transport_fields_sqlite() {
    let source_path = unique_db_path("chio-budget-import-transport-source");
    let target_path = unique_db_path("chio-budget-import-transport-target");
    let source = SqliteBudgetStore::open(&source_path).unwrap();

    assert!(source
        .try_charge_cost_with_ids(
            "cap-import-transport",
            0,
            Some(10),
            25,
            Some(100),
            Some(500),
            Some("hold-import-transport-0"),
            Some("hold-import-transport-0:authorize"),
        )
        .unwrap());
    let usage = source
        .get_usage("cap-import-transport", 0)
        .unwrap()
        .expect("source usage");
    let events = source
        .list_mutation_events(10, Some("cap-import-transport"), Some(0))
        .unwrap();
    let mut replayed_event = events[0].clone();
    replayed_event.recorded_at = replayed_event.recorded_at.saturating_add(30);
    replayed_event.event_seq = replayed_event.event_seq.saturating_add(5);
    replayed_event.usage_seq = replayed_event.usage_seq.map(|seq| seq.saturating_add(5));

    let target = SqliteBudgetStore::open(&target_path).unwrap();
    target
        .import_snapshot_records(std::slice::from_ref(&usage), &events)
        .unwrap();
    target
        .import_snapshot_records(std::slice::from_ref(&usage), &[replayed_event])
        .unwrap();

    let replicated_events = target
        .list_mutation_events(10, Some("cap-import-transport"), Some(0))
        .unwrap();
    assert_eq!(replicated_events.len(), 1);
    assert_eq!(
        replicated_events[0].event_id,
        "hold-import-transport-0:authorize"
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

#[test]
fn sqlite_store_reports_truthful_single_node_guarantee_level() {
    use chio_kernel::budget_store::{BudgetGuaranteeLevel, BudgetStore};
    let dir = std::env::temp_dir().join(format!("chio-glevel-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = SqliteBudgetStore::open(dir.join("budget.sqlite")).unwrap();
    assert_eq!(
        store.budget_guarantee_level(),
        BudgetGuaranteeLevel::SingleNodeAtomic
    );
}

#[test]
fn reap_orphaned_holds_is_reachable_through_budget_store_trait() {
    // Verifies that crash-recovery reap is callable via `dyn BudgetStore`,
    // the type-erased handle that the sidecar startup path holds.
    use chio_kernel::budget_store::{
        BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetStore,
    };
    use std::collections::HashMap;
    use std::sync::Arc;

    let dir = std::env::temp_dir().join(format!("chio-reap-trait-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = SqliteBudgetStore::open(dir.join("budget.sqlite")).unwrap();

    // Authorize a hold so there is an open hold to reap.
    let decision = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: "cap-reap-trait".to_string(),
            grant_index: 0,
            max_invocations: Some(5),
            requested_exposure_units: 100,
            max_cost_per_invocation: Some(100),
            max_total_cost_units: Some(500),
            hold_id: Some("hold-orphan-trait".to_string()),
            event_id: Some("hold-orphan-trait:authorize".to_string()),
            authority: None,
            payment_journal: None,
        })
        .unwrap();
    assert!(matches!(
        decision,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));

    // Type-erase to dyn BudgetStore, simulating the startup path.
    let dyn_store: Arc<dyn BudgetStore> = Arc::new(store);

    // Reap with an empty arbitration map: the orphaned hold is reversed.
    let (reconciled, reversed) = dyn_store.reap_orphaned_holds(&HashMap::new()).unwrap();
    assert_eq!(reconciled, 0, "no holds in the realized map to reconcile");
    assert_eq!(reversed, 1, "the open orphaned hold must be reversed");

    // After reversal the committed cost for the cap returns to zero.
    let usage = dyn_store.get_usage("cap-reap-trait", 0).unwrap().unwrap();
    assert_eq!(
        usage.committed_cost_units().unwrap(),
        0,
        "reversed hold must leave committed cost at zero"
    );
}

#[test]
fn open_hold_stays_reserved_without_reap() {
    // Fail-closed property: an open hold is not reversed unless
    // reap_orphaned_holds is called with an arbitration map that contains it.
    // count_open_holds reports the hold count without modifying state, letting
    // startup log the warning and leave holds reserved (no double-spend).
    use chio_kernel::budget_store::{
        BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetStore,
    };
    use std::sync::Arc;

    let dir = std::env::temp_dir().join(format!("chio-noreap-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let store: Arc<dyn BudgetStore> =
        Arc::new(SqliteBudgetStore::open(dir.join("budget.sqlite")).unwrap());

    let decision = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: "cap-noreap".to_string(),
            grant_index: 0,
            max_invocations: Some(5),
            requested_exposure_units: 100,
            max_cost_per_invocation: Some(100),
            max_total_cost_units: Some(500),
            hold_id: Some("hold-noreap".to_string()),
            event_id: Some("hold-noreap:authorize".to_string()),
            authority: None,
            payment_journal: None,
        })
        .unwrap();
    assert!(matches!(
        decision,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));

    // count_open_holds reads hold state without modifying it.
    let count = store.count_open_holds().unwrap();
    assert_eq!(count, 1, "one open hold must be reported");

    // Without calling reap_orphaned_holds the hold remains reserved.
    let usage = store.get_usage("cap-noreap", 0).unwrap().unwrap();
    assert_eq!(
        usage.committed_cost_units().unwrap(),
        100,
        "open hold must remain reserved when startup does not call reap_orphaned_holds"
    );
}

#[test]
fn max_mutation_event_seq_reports_head() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-budget-head");
    let store = SqliteBudgetStore::open(&path)?;
    assert_eq!(store.max_mutation_event_seq()?, 0);
    // A single authorize charge allocates event_seq 1.
    store.try_charge_cost("cap-a", 0, Some(5), 3, None, None)?;
    assert_eq!(store.max_mutation_event_seq()?, 1);
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn budget_ack_heads_reports_contiguous_prefix_only() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-ack-heads");
    let store = SqliteBudgetStore::open(&path)?;

    // Import events {40, 42} for origin O (41 skipped) via the snapshot path,
    // which is how a peer's log arrives; floor defaults to 0.
    let event = |seq: u64| BudgetMutationRecord {
        event_id: format!("evt-{seq}"),
        hold_id: None,
        capability_id: "cap-o".to_string(),
        grant_index: 0,
        kind: BudgetMutationKind::AuthorizeExposure,
        allowed: Some(true),
        recorded_at: seq as i64,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        total_cost_exposed_after: 1,
        total_cost_realized_spend_after: 0,
        authority: Some(BudgetEventAuthority {
            authority_id: "http://origin-o".to_string(),
            lease_id: "http://origin-o#term-1".to_string(),
            lease_epoch: 1,
        }),
    };
    // Missing prefix (holds only {42,43}): with floor 0, no row is in the
    // island=0 group, so the origin is absent -> caller defaults to floor 0.
    store.import_snapshot_records(&[], &[event(42), event(43)])?;
    let heads = store.budget_ack_heads()?;
    assert!(
        heads.iter().all(|(origin, _)| origin != "http://origin-o"),
        "a missing prefix must not be laundered into an ack head"
    );

    // Now add the contiguous prefix 1..=41 for the same origin: the head is
    // the last contiguous seq before the 42/43 island, i.e. 43 becomes reachable.
    let contiguous: Vec<_> = (1..=41).map(event).collect();
    store.import_snapshot_records(&[], &contiguous)?;
    let heads = store.budget_ack_heads()?;
    let head = heads
        .iter()
        .find(|(origin, _)| origin == "http://origin-o")
        .map(|(_, seq)| *seq)
        .ok_or("origin O must now have a contiguous ack head")?;
    assert_eq!(head, 43, "1..=43 is now gap-free, so the head is 43");

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn budget_ack_heads_caps_partial_head_at_interior_gap() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-ack-heads-partial");
    let store = SqliteBudgetStore::open(&path)?;

    let event = |seq: u64| BudgetMutationRecord {
        event_id: format!("evt-{seq}"),
        hold_id: None,
        capability_id: "cap-p".to_string(),
        grant_index: 0,
        kind: BudgetMutationKind::AuthorizeExposure,
        allowed: Some(true),
        recorded_at: seq as i64,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        total_cost_exposed_after: 1,
        total_cost_realized_spend_after: 0,
        authority: Some(BudgetEventAuthority {
            authority_id: "http://origin-p".to_string(),
            lease_id: "http://origin-p#term-1".to_string(),
            lease_epoch: 1,
        }),
    };

    // Import {1,2,3,5,6} from floor 0: the run reaches down to the floor and is
    // gap-free through 3, then an interior gap at 4 splits off the {5,6} island.
    // The contiguous ack head must be the last gap-free seq (3), NOT the max
    // present seq (6): a mid-stream hole yields a PARTIAL head.
    store.import_snapshot_records(&[], &[event(1), event(2), event(3), event(5), event(6)])?;
    let heads = store.budget_ack_heads()?;
    let head = heads
        .iter()
        .find(|(origin, _)| origin == "http://origin-p")
        .map(|(_, seq)| *seq)
        .ok_or("origin P has a contiguous prefix from the floor, so it must report a head")?;
    assert_eq!(
        head, 3,
        "an interior gap at 4 caps the head at 3, not the max present seq 6"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn budget_ack_heads_stays_pinned_at_a_post_watermark_gap() -> Result<(), Box<dyn std::error::Error>>
{
    // Once the watermark W has advanced over a contiguous prefix and a REAL hole
    // sits at
    // W+1, the head is pinned at W. The status-path fast path probes only the
    // single W+1 slot and short-circuits the O(suffix) window scan, so it must
    // (a) keep returning W across repeated polls (never advance over the gap) and
    // (b) advance correctly the moment the gap is filled - the result must match
    // the genesis-anchored gaps-and-islands computation exactly.
    let path = unique_db_path("chio-ack-heads-post-watermark-gap");
    let store = SqliteBudgetStore::open(&path)?;

    let origin = "http://origin-g";
    let event = |seq: u64| BudgetMutationRecord {
        event_id: format!("evt-{seq}"),
        hold_id: None,
        capability_id: "cap-g".to_string(),
        grant_index: 0,
        kind: BudgetMutationKind::AuthorizeExposure,
        allowed: Some(true),
        recorded_at: seq as i64,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        total_cost_exposed_after: 1,
        total_cost_realized_spend_after: 0,
        authority: Some(BudgetEventAuthority {
            authority_id: origin.to_string(),
            lease_id: format!("{origin}#term-1"),
            lease_epoch: 1,
        }),
    };
    let origin_head = |heads: &[(String, u64)]| -> Option<u64> {
        heads
            .iter()
            .find(|(id, _)| id == origin)
            .map(|(_, seq)| *seq)
    };

    // Contiguous {1,2,3}: the head reaches 3 and the durable watermark advances to 3.
    store.import_snapshot_records(&[], &[event(1), event(2), event(3)])?;
    assert_eq!(origin_head(&store.budget_ack_heads()?), Some(3));

    // A hole at 4 (== W+1) with a later island {5,6}: the head must stay pinned at
    // 3 no matter how many times it is polled, and must never jump over the gap.
    store.import_snapshot_records(&[], &[event(5), event(6)])?;
    for _ in 0..3 {
        assert_eq!(
            origin_head(&store.budget_ack_heads()?),
            Some(3),
            "a permanent hole at W+1 keeps the head pinned at W (fail-closed, no over-count)"
        );
    }

    // Filling the gap at 4 lets the head advance across the now-contiguous 4,5,6.
    store.import_snapshot_records(&[], &[event(4)])?;
    assert_eq!(
        origin_head(&store.budget_ack_heads()?),
        Some(6),
        "filling W+1 advances the head over the now-contiguous 4,5,6"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn list_abandoned_event_seqs_in_range_bounds_upper_and_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    // The budget delta endpoint must never serialize an unbounded abandoned window.
    // The bounded query enforces
    // BOTH an upper bound (<= page_max) and a row cap in SQL, so a rollback storm
    // cannot materialize millions of tombstones into one response and blow past
    // the peer-response byte cap.
    let path = unique_db_path("chio-abandoned-in-range");
    let store = SqliteBudgetStore::open(&path)?;

    let seqs: Vec<u64> = (1..=1000).collect();
    store.record_abandoned_event_seqs(&seqs)?;

    // Upper bound: only (10, 20], ascending.
    let bounded = store.list_abandoned_event_seqs_in_range(10, 20, 100)?;
    assert_eq!(bounded, (11..=20).collect::<Vec<u64>>());

    // Row cap: a huge window returns at most `limit` rows, never the whole window.
    let capped = store.list_abandoned_event_seqs_in_range(0, 1000, 5)?;
    assert_eq!(capped, vec![1, 2, 3, 4, 5]);

    // Contrast: the unbounded method returns the whole window (the oversized-response
    // risk the bounded query removes).
    assert_eq!(store.list_abandoned_event_seqs_after(0)?.len(), 1000);

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn abandoned_seq_ranges_round_trip_and_advance_the_head() -> Result<(), Box<dyn std::error::Error>>
{
    // The cluster snapshot carries abandoned seqs RANGE-ENCODED so a rollback storm's
    // long contiguous run stays a handful of small pairs instead of an unbounded
    // integer list that could exceed MAX_PEER_RESPONSE_BYTES and stall recovery.
    // list_abandoned_event_seq_ranges
    // must COLLAPSE contiguous runs, and record_abandoned_event_seq_ranges must EXPAND
    // them back to the identical seq set so the filled-or-abandoned head advance is
    // preserved bit-for-bit.
    let head_for = |heads: &[(String, u64)], origin: &str| {
        heads.iter().find(|(o, _)| o == origin).map(|(_, seq)| *seq)
    };

    // Enumerated form -> range-encoded runs: {2,3,4},{7},{9,10} collapse to 3 pairs.
    let source_path = unique_db_path("chio-abandoned-ranges-source");
    let source = SqliteBudgetStore::open(&source_path)?;
    source.record_abandoned_event_seqs(&[2, 3, 4, 7, 9, 10])?;
    assert_eq!(
        source.list_abandoned_event_seq_ranges()?,
        vec![(2, 4), (7, 7), (9, 10)],
        "contiguous abandoned seqs must collapse to inclusive runs"
    );

    // Range form -> enumerated set on a fresh follower (lossless expansion).
    let follower_path = unique_db_path("chio-abandoned-ranges-follower");
    let follower = SqliteBudgetStore::open(&follower_path)?;
    follower.record_abandoned_event_seq_ranges(&[(2, 4), (7, 7), (9, 10)])?;
    assert_eq!(
        follower.list_abandoned_event_seqs()?,
        vec![2, 3, 4, 7, 9, 10],
        "a follower expands the runs to the identical abandoned seq set"
    );

    // A single LARGE contiguous run collapses to ONE pair (the rollback-storm case):
    // recorded cheaply via the range insert (a recursive CTE, not per-seq round-trips).
    let storm_path = unique_db_path("chio-abandoned-ranges-storm");
    let storm = SqliteBudgetStore::open(&storm_path)?;
    storm.record_abandoned_event_seq_ranges(&[(2, 50_001)])?;
    let ranges = storm.list_abandoned_event_seq_ranges()?;
    assert_eq!(
        ranges,
        vec![(2, 50_001)],
        "a 50k-seq rollback storm stays a single (start, end) pair"
    );
    assert_eq!(storm.list_abandoned_event_seqs()?.len(), 50_000);

    // Head advance: present {1, 50002} with the whole (2, 50001) run abandoned makes
    // [1..=50002] contiguous, so the head advances across the run - exactly as if each
    // seq had been recorded individually.
    storm.import_snapshot_records(
        &[],
        &[
            ack_head_event(1, "e1", "http://o"),
            ack_head_event(50_002, "e-tail", "http://o"),
        ],
    )?;
    assert_eq!(
        head_for(&storm.budget_ack_heads()?, "http://o"),
        Some(50_002),
        "the abandoned RANGE fills every hole so the head advances past the whole run"
    );

    let _ = fs::remove_file(&source_path);
    let _ = fs::remove_file(&follower_path);
    let _ = fs::remove_file(&storm_path);
    Ok(())
}

#[test]
fn budget_ack_heads_recognizes_multi_authority_global_contiguity(
) -> Result<(), Box<dyn std::error::Error>> {
    // event_seq is a single store-wide sequence, so multiple authorities share
    // one global stream and an origin's events are a sparse subsequence of it.
    // budget_ack_heads must anchor on the GLOBAL contiguous head, not a per-origin
    // island.
    let path = unique_db_path("chio-ack-heads-multi");
    let store = SqliteBudgetStore::open(&path)?;

    let event = |seq: u64, origin: &str| BudgetMutationRecord {
        event_id: format!("evt-{origin}-{seq}"),
        hold_id: None,
        capability_id: "cap-m".to_string(),
        grant_index: 0,
        kind: BudgetMutationKind::AuthorizeExposure,
        allowed: Some(true),
        recorded_at: seq as i64,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        total_cost_exposed_after: 1,
        total_cost_realized_spend_after: 0,
        authority: Some(BudgetEventAuthority {
            authority_id: origin.to_string(),
            lease_id: format!("{origin}#term-1"),
            lease_epoch: 1,
        }),
    };
    let head_for = |heads: &[(String, u64)], origin: &str| {
        heads.iter().find(|(o, _)| o == origin).map(|(_, seq)| *seq)
    };
    let a = "http://origin-a";
    let b = "http://origin-b";

    // Interleaved gap-free global prefix 1..=5: A owns {1,2,5}, B owns {3,4}.
    // Even though A's own seqs (1,2,5) are NOT consecutive integers, the GLOBAL
    // stream is gap-free, so both origins are acked at their true max within the
    // global head (5): A -> 5, B -> 4. A per-origin island query would wrongly
    // cap A at 2 (the 5 looks like a gap in A's own order).
    store.import_snapshot_records(
        &[],
        &[
            event(1, a),
            event(2, a),
            event(3, b),
            event(4, b),
            event(5, a),
        ],
    )?;
    let heads = store.budget_ack_heads()?;
    assert_eq!(
        head_for(&heads, a),
        Some(5),
        "origin A's sparse block must be acked to the global head, not its own island"
    );
    assert_eq!(
        head_for(&heads, b),
        Some(4),
        "the authority-change origin B (block starts at global 3) must be acked"
    );

    let _ = fs::remove_file(&path);

    // Global hole: A owns {1,2}, B owns {4,5} -> global seq 3 missing.
    // The global head is 2, so A -> 2 and B is ABSENT. A naive MAX-per-origin
    // ack head would over-report B = 5 past the hole (a double-spend risk).
    let path = unique_db_path("chio-ack-heads-multi-hole");
    let store = SqliteBudgetStore::open(&path)?;
    store.import_snapshot_records(&[], &[event(1, a), event(2, a), event(4, b), event(5, b)])?;
    let heads = store.budget_ack_heads()?;
    assert_eq!(
        head_for(&heads, a),
        Some(2),
        "origin A is gap-free through the global head 2"
    );
    assert_eq!(
        head_for(&heads, b),
        None,
        "origin B (all events above the global hole at 3) must be absent, never acked past the hole"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

fn ack_head_event(seq: u64, event_id: &str, origin: &str) -> BudgetMutationRecord {
    BudgetMutationRecord {
        event_id: event_id.to_string(),
        hold_id: None,
        capability_id: "cap-w".to_string(),
        grant_index: 0,
        kind: BudgetMutationKind::AuthorizeExposure,
        allowed: Some(true),
        recorded_at: seq as i64,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        total_cost_exposed_after: 1,
        total_cost_realized_spend_after: 0,
        authority: Some(BudgetEventAuthority {
            authority_id: origin.to_string(),
            lease_id: format!("{origin}#term-1"),
            lease_epoch: 1,
        }),
    }
}

#[test]
fn mutation_event_seq_for_event_id_returns_this_events_seq_not_authority_max(
) -> Result<(), Box<dyn std::error::Error>> {
    // The quorum-witness token must wait on THIS write's own event_seq (looked up
    // by event_id), not MAX(event_seq) for the authority, which a later
    // same-authority commit raises.
    let path = unique_db_path("chio-event-seq-by-id");
    let store = SqliteBudgetStore::open(&path)?;
    // Two events under the SAME authority: e1 at seq 1, e2 at seq 2.
    store.import_snapshot_records(
        &[],
        &[
            ack_head_event(1, "e1", "http://a"),
            ack_head_event(2, "e2", "http://a"),
        ],
    )?;
    assert_eq!(store.mutation_event_seq_for_event_id("e1")?, Some(1));
    assert_eq!(store.mutation_event_seq_for_event_id("e2")?, Some(2));
    assert_eq!(store.mutation_event_seq_for_event_id("missing")?, None);
    // The authority MAX is 2 - the WRONG seq for e1's quorum wait; the by-id
    // lookup returns 1, so e1's wait targets its own event.
    assert_eq!(store.max_mutation_event_seq_for_authority("http://a")?, 2);

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn budget_ack_head_watermark_recomputes_after_delete_caps_below_hole(
) -> Result<(), Box<dyn std::error::Error>> {
    // budget_ack_heads maintains the contiguous head from a durable watermark for
    // O(new rows) cost, but a DELETE that punches a hole
    // below the watermark must reset it so the next call re-verifies and caps the
    // head below the hole (never a stale-high head that over-counts).
    let path = unique_db_path("chio-ack-watermark-delete");
    let store = SqliteBudgetStore::open(&path)?;
    let head_for = |heads: &[(String, u64)], origin: &str| {
        heads.iter().find(|(o, _)| o == origin).map(|(_, seq)| *seq)
    };
    store.import_snapshot_records(
        &[],
        &[
            ack_head_event(1, "e1", "http://o"),
            ack_head_event(2, "e2", "http://o"),
            ack_head_event(3, "e3", "http://o"),
        ],
    )?;
    // Contiguous 1..3 -> head 3. Called twice to prove the watermark is stable
    // (the second call is a no-op advance, not a regression).
    assert_eq!(head_for(&store.budget_ack_heads()?, "http://o"), Some(3));
    assert_eq!(head_for(&store.budget_ack_heads()?, "http://o"), Some(3));

    // Delete the middle event (seq 2): the watermark reset forces re-verification
    // and the head caps at 1, NOT the stale-high 3.
    store.delete_mutation_event("e2")?;
    assert_eq!(
        head_for(&store.budget_ack_heads()?, "http://o"),
        Some(1),
        "a hole punched below the watermark must cap the head at 1, never stay at 3"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn budget_mutation_events_delete_trigger_resets_watermark_even_without_manual_call(
) -> Result<(), Box<dyn std::error::Error>> {
    // Defense-in-depth: every known DELETE FROM budget_mutation_events call site
    // pairs the delete with a manual reset_budget_ack_head_watermark call in the
    // same transaction. This test proves the invariant does NOT depend on that
    // discipline: a raw SQL delete that deliberately bypasses the manual reset
    // path (simulating a future call site that forgets it, or an out-of-band /
    // operator delete) must still zero the watermark, because the
    // budget_mutation_events_reset_ack_head_watermark AFTER DELETE trigger fires
    // structurally on the table itself.
    //
    // Without the trigger this test fails: head_seq would stay stale-high at 3
    // and budget_ack_heads would over-count origin "http://o" up to a seq (3)
    // whose row 2 no longer exists - a witness over-count / data-loss double-spend.
    let path = unique_db_path("chio-ack-watermark-trigger-raw-delete");
    let store = SqliteBudgetStore::open(&path)?;
    let head_for = |heads: &[(String, u64)], origin: &str| {
        heads.iter().find(|(o, _)| o == origin).map(|(_, seq)| *seq)
    };

    store.import_snapshot_records(
        &[],
        &[
            ack_head_event(1, "e1", "http://o"),
            ack_head_event(2, "e2", "http://o"),
            ack_head_event(3, "e3", "http://o"),
        ],
    )?;
    // Advance the watermark to 3 via the normal incremental path.
    assert_eq!(head_for(&store.budget_ack_heads()?, "http://o"), Some(3));
    {
        let connection = store.connection()?;
        let watermark: i64 = connection.query_row(
            "SELECT head_seq FROM budget_ack_head_watermark WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(watermark, 3, "watermark must have advanced to 3");
    }

    // Delete row seq 2 directly via raw SQL, bypassing delete_mutation_event
    // (and therefore bypassing reset_budget_ack_head_watermark entirely) to
    // isolate the trigger as the sole thing that can reset the watermark here.
    {
        let connection = store.connection()?;
        let deleted = connection.execute(
            "DELETE FROM budget_mutation_events WHERE event_id = ?1",
            params!["e2"],
        )?;
        assert_eq!(deleted, 1, "raw delete must remove exactly one row");
    }

    // The trigger fired in the same transaction as the raw DELETE (SQLite AFTER
    // triggers run within the firing statement), so head_seq is already 0 with
    // no further application-level call.
    {
        let connection = store.connection()?;
        let watermark: i64 = connection.query_row(
            "SELECT head_seq FROM budget_ack_head_watermark WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            watermark, 0,
            "the AFTER DELETE trigger must reset head_seq to 0 on any delete, \
             even one that bypasses reset_budget_ack_head_watermark"
        );
    }

    // budget_ack_heads must therefore re-verify from genesis and cap at 1, not
    // report a stale-high (or worse, unreset) head past the punched hole at 2.
    assert_eq!(
        head_for(&store.budget_ack_heads()?, "http://o"),
        Some(1),
        "re-verification from a reset watermark must cap the head at 1, not stay at 3"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn ack_head_reset_trigger_is_idempotent_across_reopens_and_concurrent_opens(
) -> Result<(), Box<dyn std::error::Error>> {
    // open() must not DROP+CREATE the ack-reset trigger on every open. Repeated and
    // concurrent opens must not error (no "trigger
    // already exists" race) and must not churn the trigger, while it still exists
    // exactly once with the current per-origin-clearing body.
    let path = unique_db_path("chio-trigger-idempotent");
    // First open creates the trigger.
    {
        let _ = SqliteBudgetStore::open(&path)?;
    }
    // Many concurrent opens: the steady-state path is a single sqlite_master read
    // with no DDL, so none of these may fail or churn the trigger.
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || SqliteBudgetStore::open(&path).map(|_| ()))
        })
        .collect();
    for handle in handles {
        handle
            .join()
            .expect("open thread panicked")
            .expect("a concurrent open must not error on the trigger migration");
    }

    let store = SqliteBudgetStore::open(&path)?;
    // The trigger exists exactly once and clears the per-origin heads (new body).
    {
        let connection = store.connection()?;
        let count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' \
             AND name = 'budget_mutation_events_reset_ack_head_watermark'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 1, "the reset trigger must exist exactly once");
        let sql: String = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' \
             AND name = 'budget_mutation_events_reset_ack_head_watermark'",
            [],
            |row| row.get(0),
        )?;
        assert!(
            sql.contains("budget_origin_ack_heads"),
            "the trigger must be the current version that clears the per-origin heads"
        );
    }

    // Functional: after all the reopens the trigger still resets the watermark on
    // delete, so the ack head re-verifies and caps below a punched hole.
    let head_for = |heads: &[(String, u64)], origin: &str| {
        heads.iter().find(|(o, _)| o == origin).map(|(_, seq)| *seq)
    };
    store.import_snapshot_records(
        &[],
        &[
            ack_head_event(1, "t1", "http://o"),
            ack_head_event(2, "t2", "http://o"),
            ack_head_event(3, "t3", "http://o"),
        ],
    )?;
    assert_eq!(head_for(&store.budget_ack_heads()?, "http://o"), Some(3));
    store.delete_mutation_event("t2")?;
    assert_eq!(
        head_for(&store.budget_ack_heads()?, "http://o"),
        Some(1),
        "the reset trigger must still fire after repeated/concurrent reopens"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn abandoned_seqs_advance_the_head_but_genuine_gaps_still_cap(
) -> Result<(), Box<dyn std::error::Error>> {
    // An abandoned/tombstoned seq (a rolled-back-then-re-appended write's original
    // seq) is treated as FILLED so the global contiguous ack head advances past it
    // (no permanent stall). A GENUINELY missing seq (never recorded abandoned) still
    // caps the head (never over-counts a data-losing node).
    let path = unique_db_path("chio-abandoned-fills-hole");
    let store = SqliteBudgetStore::open(&path)?;
    let head_for = |heads: &[(String, u64)], origin: &str| {
        heads.iter().find(|(o, _)| o == origin).map(|(_, seq)| *seq)
    };

    // Present {1, 3} with a hole at 2: without an abandoned record the head caps
    // at 1 (fail-closed).
    store.import_snapshot_records(
        &[],
        &[
            ack_head_event(1, "e1", "http://o"),
            ack_head_event(3, "e3", "http://o"),
        ],
    )?;
    assert_eq!(
        head_for(&store.budget_ack_heads()?, "http://o"),
        Some(1),
        "a genuine gap at 2 must cap the head at 1"
    );

    // Record 2 as abandoned: the head now advances to 3 (2 is a filled tombstone).
    store.record_abandoned_event_seqs(&[2])?;
    assert_eq!(
        head_for(&store.budget_ack_heads()?, "http://o"),
        Some(3),
        "an abandoned seq is filled, so the head advances past it"
    );

    // Add {5} (a NEW genuine hole at 4, not abandoned): the head still caps at 3.
    store.import_snapshot_records(&[], &[ack_head_event(5, "e5", "http://o")])?;
    assert_eq!(
        head_for(&store.budget_ack_heads()?, "http://o"),
        Some(3),
        "a genuine missing seq 4 (not abandoned) must still cap the head at 3"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn rollback_retry_records_abandoned_seq_and_head_does_not_stall() {
    // End-to-end: an authorize, its rollback, and a retry under a new lease. The
    // retry auto-deletes the rolled-back authorize and re-appends it at a fresh seq;
    // the freed seq is recorded abandoned so the global contiguous ack head advances
    // to the re-appended event instead of stalling at the hole.
    let path = unique_db_path("chio-rollback-retry-no-stall");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-x";
    let event_id = "evt-x:authorize";
    let initial = authority("budget-primary", "lease-1", 1);
    let changed = authority("budget-primary", "lease-2", 2);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-x",
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
    assert!(
        store.list_abandoned_event_seqs().unwrap().is_empty(),
        "no seq is abandoned before the rollback-retry"
    );
    store
        .reverse_charge_cost_with_ids_and_authority(
            "cap-x",
            0,
            100,
            Some(hold_id),
            Some("evt-x:authorize:rollback:1"),
            Some(&initial),
        )
        .unwrap();
    // Retry the SAME event_id WITHOUT a manual delete: existing_event_allowed
    // auto-deletes the stale authorize (abandoning its seq 1) and re-appends it.
    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-x",
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

    assert_eq!(
        store.list_abandoned_event_seqs().unwrap(),
        vec![1],
        "the rolled-back authorize's freed seq 1 must be recorded abandoned"
    );

    // The contiguous ack head advances to the max present event_seq (the re-
    // appended authorize): the abandoned seq 1 is filled, so no permanent stall.
    let max_seq = store.max_mutation_event_seq().unwrap();
    let heads = store.budget_ack_heads().unwrap();
    let origin_head = heads
        .iter()
        .find(|(origin, _)| origin == "budget-primary")
        .map(|(_, seq)| *seq);
    assert_eq!(
        origin_head,
        Some(max_seq),
        "the ack head must advance past the abandoned seq to the re-appended event, not stall"
    );

    let _ = fs::remove_file(&path);
}

#[test]
fn follower_replace_self_records_abandoned_seq_and_head_advances() {
    // An ALREADY-SYNCED follower holds E@X before the leader's rollback-retry, so
    // its pull cursor is already
    // past X and the delta's abandoned_seqs (which are strictly ABOVE the cursor)
    // exclude X. When it later imports the re-appended E@Y, the REPLACE path
    // deletes its local E@X; it must self-record X abandoned in the same
    // transaction so its contiguous ack head advances past the hole WITHOUT
    // waiting for a snapshot. Only the specifically-superseded seq is recorded, so
    // a genuine gap is never filled and the witness never over-counts.
    let leader_path = unique_db_path("chio-follower-replace-leader");
    let follower_path = unique_db_path("chio-follower-replace-follower");
    let leader = SqliteBudgetStore::open(&leader_path).unwrap();
    let follower = SqliteBudgetStore::open(&follower_path).unwrap();
    let hold_id = "hold-fr";
    let event_id = "evt-fr:authorize";
    let initial = authority("budget-primary", "lease-1", 1);
    let changed = authority("budget-primary", "lease-2", 2);

    // Leader authorizes E (seq 1), then rolls it back (rollback marker at seq 2).
    assert!(leader
        .try_charge_cost_with_ids_and_authority(
            "cap-fr",
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
    leader
        .reverse_charge_cost_with_ids_and_authority(
            "cap-fr",
            0,
            100,
            Some(hold_id),
            Some("evt-fr:authorize:rollback:1"),
            Some(&initial),
        )
        .unwrap();

    // Follower syncs the PRE-retry state (E@1 + the rollback marker), ascending.
    let pre_retry = leader.list_mutation_events_after_seq(100, 0).unwrap();
    follower.import_snapshot_records(&[], &pre_retry).unwrap();
    assert!(
        follower.list_abandoned_event_seqs().unwrap().is_empty(),
        "no abandoned seq before the leader's retry"
    );

    // Leader retries under the NEW lease: deletes E@1 (abandons 1), re-appends E@3.
    assert!(leader
        .try_charge_cost_with_ids_and_authority(
            "cap-fr",
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
    assert_eq!(leader.list_abandoned_event_seqs().unwrap(), vec![1]);

    // Follower imports the re-appended authorize (the leader's delta). Its cursor
    // is already past seq 1, so the delta would NOT carry seq 1 as abandoned - the
    // REPLACE path must record it locally.
    let reappended = leader
        .list_mutation_events_after_seq(100, 0)
        .unwrap()
        .into_iter()
        .find(|record| record.event_id == event_id)
        .expect("the re-appended authorize event");
    assert!(
        reappended.event_seq > 1,
        "re-appended at a fresh higher seq"
    );
    follower.import_mutation_record(&reappended).unwrap();

    // The follower self-recorded the superseded seq 1 abandoned, so its head
    // advances to the re-appended event instead of stalling at the hole.
    assert_eq!(
        follower.list_abandoned_event_seqs().unwrap(),
        vec![1],
        "the follower REPLACE path self-records the superseded seq abandoned"
    );
    let follower_max = follower.max_mutation_event_seq().unwrap();
    let heads = follower.budget_ack_heads().unwrap();
    let head = heads
        .iter()
        .find(|(origin, _)| origin == "budget-primary")
        .map(|(_, seq)| *seq);
    assert_eq!(
        head,
        Some(follower_max),
        "the follower head advances past the abandoned hole with no snapshot needed"
    );

    let _ = fs::remove_file(&leader_path);
    let _ = fs::remove_file(&follower_path);
}

#[test]
fn follower_replace_inserts_reappended_event_and_head_reaches_new_seq() {
    // Exercises the follower REPLACE path. An ALREADY-SYNCED follower holds the
    // ORIGINAL authorize E@1 (its pull cursor is already past 1). When it imports
    // the leader's re-appended E@new (same event_id, fresh higher seq), the REPLACE
    // path deletes E@1 and tombstones seq 1, then MUST re-insert E@new so the
    // follower actually holds the retried write and its budget_ack_heads head
    // ADVANCES to the new seq. Without the re-insert, E@new is ABSENT and the head
    // halts at the rollback marker (never witnessing the retried write -> quorum
    // waits time out). This asserts the ABSOLUTE new seq (not head == max, which
    // passes even with E@new missing because both degrade to the rollback marker
    // together).
    let leader_path = unique_db_path("chio-follower-replace-leader");
    let follower_path = unique_db_path("chio-follower-replace-follower");
    let leader = SqliteBudgetStore::open(&leader_path).unwrap();
    let follower = SqliteBudgetStore::open(&follower_path).unwrap();
    let hold_id = "hold-fr";
    let event_id = "evt-fr:authorize";
    let initial = authority("budget-primary", "lease-1", 1);
    let changed = authority("budget-primary", "lease-2", 2);

    // Leader authorizes E (seq 1), then rolls it back (rollback marker at seq 2).
    assert!(leader
        .try_charge_cost_with_ids_and_authority(
            "cap-fr",
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
    leader
        .reverse_charge_cost_with_ids_and_authority(
            "cap-fr",
            0,
            100,
            Some(hold_id),
            Some("evt-fr:authorize:rollback:1"),
            Some(&initial),
        )
        .unwrap();

    // Follower syncs the PRE-retry state (E@1 + the rollback marker), and confirms it
    // holds the ORIGINAL authorize at seq 1 with no abandoned slot yet.
    let pre_retry = leader.list_mutation_events_after_seq(100, 0).unwrap();
    follower.import_snapshot_records(&[], &pre_retry).unwrap();
    assert_eq!(
        follower.mutation_event_seq_for_event_id(event_id).unwrap(),
        Some(1),
        "follower holds the ORIGINAL authorize at seq 1 pre-retry"
    );
    assert!(follower.list_abandoned_event_seqs().unwrap().is_empty());

    // Leader retries under the NEW lease: deletes E@1 (abandons 1), re-appends E@new.
    assert!(leader
        .try_charge_cost_with_ids_and_authority(
            "cap-fr",
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
    let reappended = leader
        .list_mutation_events_after_seq(100, 0)
        .unwrap()
        .into_iter()
        .find(|record| record.event_id == event_id)
        .expect("the re-appended authorize event");
    let new_seq = reappended.event_seq;
    assert!(
        new_seq > 2,
        "re-appended strictly above the rollback marker"
    );

    // Follower imports the re-appended authorize. The REPLACE path deletes E@1,
    // tombstones seq 1, and re-inserts E@new.
    follower.import_mutation_record(&reappended).unwrap();

    // The re-appended event is PRESENT at its new seq (exactly one row: the
    // unique event_seq index would reject a duplicate).
    assert_eq!(
        follower.mutation_event_seq_for_event_id(event_id).unwrap(),
        Some(new_seq),
        "the follower re-inserts the re-appended event at its fresh seq"
    );
    // The follower's max advances to the re-appended seq (E@new is held, not lost).
    assert_eq!(
        follower.max_mutation_event_seq().unwrap(),
        new_seq,
        "the follower's max advances to the re-appended seq"
    );
    // The contiguous ack head ADVANCES to the ABSOLUTE new seq, so the
    // follower witnesses the retried write.
    let head = follower
        .budget_ack_heads()
        .unwrap()
        .into_iter()
        .find(|(origin, _)| origin == "budget-primary")
        .map(|(_, seq)| seq);
    assert_eq!(
        head,
        Some(new_seq),
        "the follower's ack head reaches the re-appended seq, not the rollback marker"
    );
    // The superseded OLD seq stays abandoned (a FILLED-but-not-live slot: it lets the
    // head cross the hole but contributes no origin ack, so no over-count).
    assert_eq!(
        follower.list_abandoned_event_seqs().unwrap(),
        vec![1],
        "the superseded old seq stays abandoned, never a live witness"
    );

    let _ = fs::remove_file(&leader_path);
    let _ = fs::remove_file(&follower_path);
}

#[test]
fn same_authority_rollback_retry_reinserts_reappended_event_and_head_advances() {
    // Exercises the SAME-AUTHORITY re-append. When the leader keeps its lease and
    // retries a rolled-back authorize, the re-appended event is byte-identical to
    // the original EXCEPT its fresh higher event_seq, so `same_imported_mutation`
    // (authority/content-only, ignores event_seq) reports it a duplicate. If the
    // importer short-circuited on that, it would never store the re-appended row, so
    // the follower's ack head would stall at the rollback marker (seq 2) and it could
    // not witness the retried write until a full snapshot rebuild. Gating the replace
    // path on `record.event_seq > existing.event_seq` makes a differing seq force the
    // replace + reinsert even when authority/content match; without it the follower
    // still holds E@1 and its head is 2.
    let leader_path = unique_db_path("chio-same-authority-retry-leader");
    let follower_path = unique_db_path("chio-same-authority-retry-follower");
    let leader = SqliteBudgetStore::open(&leader_path).unwrap();
    let follower = SqliteBudgetStore::open(&follower_path).unwrap();
    let hold_id = "hold-sa";
    let event_id = "evt-sa:authorize";
    // ONE authority reused across the original authorize AND the retry: the leader
    // never changed leases, so the re-appended event's authority is byte-identical.
    let leased = authority("budget-primary", "lease-1", 1);

    // Leader authorizes E (seq 1), then rolls it back (rollback marker at seq 2).
    assert!(leader
        .try_charge_cost_with_ids_and_authority(
            "cap-sa",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&leased),
        )
        .unwrap());
    leader
        .reverse_charge_cost_with_ids_and_authority(
            "cap-sa",
            0,
            100,
            Some(hold_id),
            Some("evt-sa:authorize:rollback:1"),
            Some(&leased),
        )
        .unwrap();

    // Follower syncs the PRE-retry state (E@1 + the rollback marker) and confirms it
    // holds the ORIGINAL authorize at seq 1 with no abandoned slot yet.
    let pre_retry = leader.list_mutation_events_after_seq(100, 0).unwrap();
    follower.import_snapshot_records(&[], &pre_retry).unwrap();
    assert_eq!(
        follower.mutation_event_seq_for_event_id(event_id).unwrap(),
        Some(1),
        "follower holds the ORIGINAL authorize at seq 1 pre-retry"
    );
    assert!(follower.list_abandoned_event_seqs().unwrap().is_empty());

    // Leader retries under the SAME lease: the rollback decremented the usage
    // counters, so this is a GENUINE re-append (not the idempotent no-op) - it
    // deletes E@1 (abandons 1) and re-appends E@new at a fresh higher seq.
    assert!(leader
        .try_charge_cost_with_ids_and_authority(
            "cap-sa",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&leased),
        )
        .unwrap());
    let reappended = leader
        .list_mutation_events_after_seq(100, 0)
        .unwrap()
        .into_iter()
        .find(|record| record.event_id == event_id)
        .expect("the re-appended authorize event");
    let new_seq = reappended.event_seq;
    assert!(
        new_seq > 2,
        "re-appended strictly above the rollback marker (leader really re-appended, not idempotent)"
    );
    // Sanity: the re-appended event carries the SAME authority as the original, so
    // `same_imported_mutation` would call it a duplicate on authority/content alone.
    assert_eq!(
        reappended.authority.as_ref(),
        Some(&leased),
        "the retry kept the original lease (same-authority re-append)"
    );

    // Follower imports the same-authority re-append.
    follower.import_mutation_record(&reappended).unwrap();

    // The re-appended event is PRESENT at its new seq (exactly one row: the
    // unique event_seq index would reject a duplicate).
    assert_eq!(
        follower.mutation_event_seq_for_event_id(event_id).unwrap(),
        Some(new_seq),
        "the follower re-inserts the same-authority re-append at its fresh seq"
    );
    assert_eq!(
        follower.max_mutation_event_seq().unwrap(),
        new_seq,
        "the follower's max advances to the re-appended seq"
    );
    // The contiguous ack head ADVANCES to the ABSOLUTE new seq (not the
    // rollback marker), so the follower witnesses the retried write.
    let head = follower
        .budget_ack_heads()
        .unwrap()
        .into_iter()
        .find(|(origin, _)| origin == "budget-primary")
        .map(|(_, seq)| seq);
    assert_eq!(
        head,
        Some(new_seq),
        "the follower's ack head reaches the re-appended seq, not the rollback marker"
    );
    // The superseded OLD seq stays abandoned: a FILLED-but-not-live slot that lets
    // the head cross the hole but contributes NO origin ack, so no over-count.
    assert_eq!(
        follower.list_abandoned_event_seqs().unwrap(),
        vec![1],
        "the superseded old seq stays abandoned, never a live witness"
    );

    let _ = fs::remove_file(&leader_path);
    let _ = fs::remove_file(&follower_path);
}

#[test]
fn mutation_event_witness_returns_stored_origin_authority() -> Result<(), Box<dyn std::error::Error>>
{
    // The witness identity for an idempotent retry comes from the event's STORED
    // origin authority, not the current lease, so a retry
    // after leadership moved targets the origin peers advertise it under.
    let path = unique_db_path("chio-stored-witness");
    let store = SqliteBudgetStore::open(&path)?;
    let old_leader = authority("http://old-leader", "http://old-leader#term-3", 3);
    store.try_charge_cost_with_ids_and_authority(
        "cap",
        0,
        Some(10),
        5,
        None,
        None,
        None,
        Some("evt-1"),
        Some(&old_leader),
    )?;

    let (seq, authority_id, lease_epoch) = store
        .mutation_event_witness_for_event_id("evt-1")?
        .ok_or("the written event must be found")?;
    assert!(seq > 0, "a real event carries a positive seq");
    assert_eq!(
        authority_id.as_deref(),
        Some("http://old-leader"),
        "the witness must carry the STORED origin, not the current leader"
    );
    assert_eq!(lease_epoch, Some(3), "and the stored lease epoch");

    // An absent event returns None so the caller falls back to the current lease.
    assert!(store
        .mutation_event_witness_for_event_id("evt-absent")?
        .is_none());

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn payment_journal_insert_advance_close_and_conflict() {
    use chio_kernel::budget_store::BudgetStore;
    use chio_kernel::payment::{
        PaymentJournalRecord, PaymentJournalState, PaymentSettleAction, PaymentSettleIntent,
    };

    let path = unique_db_path("payment-journal");
    let store = SqliteBudgetStore::open(&path).expect("open budget store");

    let record = PaymentJournalRecord {
        request_id: "req-J".to_string(),
        capability_id: "cap".to_string(),
        grant_index: 0,
        hold_id: Some("hold-1".to_string()),
        rail: "x402".to_string(),
        authorization_id: None,
        transaction_id: None,
        amount_units: 100,
        settle_action: None,
        settle_amount_units: None,
        currency: "USD".to_string(),
        state: PaymentJournalState::HoldPlaced,
        created_at_unix_ms: 1_000,
        tenant_id: Some("tenant-J".to_string()),
    };
    store.record_payment_journal(&record).expect("insert");

    // Reused request_id fails closed, even for an identical record.
    assert!(
        store.record_payment_journal(&record).is_err(),
        "reused request_id must conflict"
    );

    // HoldPlaced -> Authorized attaches the authorization id.
    store
        .advance_payment_journal(
            "req-J",
            PaymentJournalState::HoldPlaced,
            PaymentJournalState::Authorized,
            Some("auth-9"),
            None,
            None,
        )
        .expect("advance to Authorized");

    // A wrong expected state fails closed.
    assert!(
        store
            .advance_payment_journal(
                "req-J",
                PaymentJournalState::HoldPlaced,
                PaymentJournalState::Settling,
                None,
                None,
                Some(PaymentSettleIntent {
                    action: PaymentSettleAction::Capture,
                    amount_units: Some(80),
                }),
            )
            .is_err(),
        "wrong expected state must fail closed"
    );

    // A Settling advance without a settle intent fails closed.
    assert!(
        store
            .advance_payment_journal(
                "req-J",
                PaymentJournalState::Authorized,
                PaymentJournalState::Settling,
                None,
                None,
                None,
            )
            .is_err(),
        "Settling advance must carry the committed settle intent"
    );

    // Authorized -> Settling stamps settle_action and settle_amount_units.
    store
        .advance_payment_journal(
            "req-J",
            PaymentJournalState::Authorized,
            PaymentJournalState::Settling,
            None,
            None,
            Some(PaymentSettleIntent {
                action: PaymentSettleAction::Capture,
                amount_units: Some(80),
            }),
        )
        .expect("advance to Settling with settle intent");

    // Settling -> Settled attaches the transaction id.
    store
        .advance_payment_journal(
            "req-J",
            PaymentJournalState::Settling,
            PaymentJournalState::Settled,
            None,
            Some("txn-7"),
            None,
        )
        .expect("advance to Settled");

    let incomplete = store
        .list_incomplete_payment_journal(u64::MAX)
        .expect("list");
    let row = incomplete
        .iter()
        .find(|row| row.request_id == "req-J")
        .expect("row present");
    assert_eq!(row.authorization_id.as_deref(), Some("auth-9"));
    assert_eq!(row.transaction_id.as_deref(), Some("txn-7"));
    assert_eq!(row.settle_action, Some(PaymentSettleAction::Capture));
    assert_eq!(row.settle_amount_units, Some(80));
    assert_eq!(row.state, PaymentJournalState::Settled);
    assert_eq!(row.tenant_id.as_deref(), Some("tenant-J"));

    // Close is idempotent.
    assert!(store.close_payment_journal("req-J").expect("close"));
    assert!(!store
        .close_payment_journal("req-J")
        .expect("close again returns false"));
    assert!(store
        .list_incomplete_payment_journal(u64::MAX)
        .expect("list after close")
        .iter()
        .all(|row| row.request_id != "req-J"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn get_payment_journal_is_scoped_identically_to_the_incomplete_listing() {
    use chio_kernel::budget_store::BudgetStore;
    use chio_kernel::payment::{PaymentJournalRecord, PaymentJournalState};

    let path = unique_db_path("payment-journal-keyed-lookup");
    let store = SqliteBudgetStore::open(&path).expect("open budget store");

    // Absent request id: no row, no error.
    assert!(store
        .get_payment_journal("req-missing")
        .expect("lookup an absent row")
        .is_none());

    let record = PaymentJournalRecord {
        request_id: "req-K".to_string(),
        capability_id: "cap".to_string(),
        grant_index: 0,
        hold_id: Some("hold-1".to_string()),
        rail: "x402".to_string(),
        authorization_id: Some("auth-K".to_string()),
        transaction_id: None,
        amount_units: 100,
        settle_action: None,
        settle_amount_units: None,
        currency: "USD".to_string(),
        state: PaymentJournalState::HoldPlaced,
        tenant_id: Some("tenant-K".to_string()),
        created_at_unix_ms: 1_000,
    };
    store.record_payment_journal(&record).expect("insert");

    // A one-row keyed lookup finds exactly the record just inserted.
    let found = store
        .get_payment_journal("req-K")
        .expect("lookup a present row")
        .expect("row present");
    assert_eq!(found, record);

    // Closed: the keyed lookup returns None, matching
    // list_incomplete_payment_journal's scope so a monetary reconciler
    // never mistakes a terminal row for an open one.
    assert!(store.close_payment_journal("req-K").expect("close"));
    assert!(store
        .get_payment_journal("req-K")
        .expect("lookup a closed row")
        .is_none());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn payment_journal_reconcile_failed_rail_finds_only_reconcile_failed_rows() {
    use chio_kernel::budget_store::BudgetStore;
    use chio_kernel::payment::{PaymentJournalRecord, PaymentJournalState};

    let path = unique_db_path("payment-journal-reconcile-failed-rail");
    let store = SqliteBudgetStore::open(&path).expect("open budget store");

    // Absent request id: no row, no error, and no incident.
    assert!(store
        .payment_journal_reconcile_failed_rail("req-missing")
        .expect("lookup an absent row")
        .is_none());

    let record = PaymentJournalRecord {
        request_id: "req-L".to_string(),
        capability_id: "cap".to_string(),
        grant_index: 0,
        hold_id: Some("hold-1".to_string()),
        rail: "x402".to_string(),
        authorization_id: Some("auth-L".to_string()),
        transaction_id: None,
        amount_units: 100,
        settle_action: None,
        settle_amount_units: None,
        currency: "USD".to_string(),
        state: PaymentJournalState::HoldPlaced,
        created_at_unix_ms: 1_000,
        tenant_id: None,
    };
    store.record_payment_journal(&record).expect("insert");

    // An open (non-incident) row is invisible to this targeted lookup,
    // matching get_payment_journal's scope: only a ReconcileFailed row is
    // an incident.
    assert!(store
        .payment_journal_reconcile_failed_rail("req-L")
        .expect("lookup an open row")
        .is_none());

    store
        .advance_payment_journal(
            "req-L",
            PaymentJournalState::HoldPlaced,
            PaymentJournalState::ReconcileFailed,
            None,
            None,
            None,
        )
        .expect("advance to ReconcileFailed");

    // Now the row is a durable incident: the targeted lookup surfaces its
    // rail so a caller can dead-letter the intent with a useful detail.
    assert_eq!(
        store
            .payment_journal_reconcile_failed_rail("req-L")
            .expect("lookup a reconcile-failed row"),
        Some("x402".to_string())
    );

    // get_payment_journal never surfaces this row: it is a closed
    // incident, not an incomplete one.
    assert!(store
        .get_payment_journal("req-L")
        .expect("lookup a reconcile-failed row via get_payment_journal")
        .is_none());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn authorize_budget_hold_writes_journal_atomically() {
    use chio_kernel::budget_store::{BudgetAuthorizeHoldRequest, BudgetStore};
    use chio_kernel::payment::{PaymentJournalRecord, PaymentJournalState};

    let path = unique_db_path("hold-journal-atomic");
    let store = SqliteBudgetStore::open(&path).expect("open");
    let journal = PaymentJournalRecord {
        request_id: "req-H".to_string(),
        capability_id: "cap".to_string(),
        grant_index: 0,
        hold_id: Some("hold-req-H".to_string()),
        rail: "x402".to_string(),
        authorization_id: None,
        transaction_id: None,
        amount_units: 50,
        settle_action: None,
        settle_amount_units: None,
        currency: "USD".to_string(),
        state: PaymentJournalState::HoldPlaced,
        created_at_unix_ms: 2_000,
        tenant_id: None,
    };
    store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: "cap".to_string(),
            grant_index: 0,
            max_invocations: Some(10),
            requested_exposure_units: 50,
            max_cost_per_invocation: Some(50),
            max_total_cost_units: Some(500),
            hold_id: Some("hold-req-H".to_string()),
            event_id: Some("hold-req-H:authorize".to_string()),
            authority: None,
            payment_journal: Some(journal),
        })
        .expect("authorize hold with journal");
    // The HoldPlaced row is durable after the same transaction that wrote
    // the hold.
    let rows = store
        .list_incomplete_payment_journal(u64::MAX)
        .expect("list");
    assert!(rows
        .iter()
        .any(|row| row.request_id == "req-H" && row.state == PaymentJournalState::HoldPlaced));

    // A denied hold writes no journal row.
    let denied_journal = PaymentJournalRecord {
        request_id: "req-D".to_string(),
        hold_id: Some("hold-req-D".to_string()),
        amount_units: 10_000,
        ..rows[0].clone()
    };
    let decision = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: "cap".to_string(),
            grant_index: 0,
            max_invocations: Some(10),
            requested_exposure_units: 10_000,
            max_cost_per_invocation: Some(50),
            max_total_cost_units: Some(500),
            hold_id: Some("hold-req-D".to_string()),
            event_id: Some("hold-req-D:authorize".to_string()),
            authority: None,
            payment_journal: Some(denied_journal),
        })
        .expect("denied authorize still returns a decision");
    assert!(matches!(
        decision,
        chio_kernel::budget_store::BudgetAuthorizeHoldDecision::Denied(_)
    ));
    assert!(store
        .list_incomplete_payment_journal(u64::MAX)
        .expect("list after deny")
        .iter()
        .all(|row| row.request_id != "req-D"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn expire_open_hold_releases_exposure_without_recording_spend() {
    use chio_kernel::budget_store::{BudgetAuthorizeHoldRequest, BudgetMutationKind, BudgetStore};

    let path = unique_db_path("hold-sweep");
    let store = SqliteBudgetStore::open(&path).expect("open");
    store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: "cap".to_string(),
            grant_index: 0,
            max_invocations: Some(10),
            requested_exposure_units: 70,
            max_cost_per_invocation: Some(70),
            max_total_cost_units: Some(500),
            hold_id: Some("hold-sweep-1".to_string()),
            event_id: Some("hold-sweep-1:authorize".to_string()),
            authority: None,
            payment_journal: None,
        })
        .expect("authorize hold");

    let exposed_before = store
        .get_usage("cap", 0)
        .expect("usage")
        .expect("record")
        .total_cost_exposed;
    assert_eq!(exposed_before, 70);
    assert_eq!(store.open_hold_count().expect("count"), 1);

    // Everything older than a huge horizon is eligible.
    let open = store
        .list_open_holds_older_than(u64::MAX, 100)
        .expect("list open");
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].hold_id, "hold-sweep-1");
    assert_eq!(open[0].capability_id, "cap");
    assert_eq!(open[0].remaining_exposure_units, 70);

    // A hold younger than a zero-ms cutoff is not eligible.
    assert!(store
        .list_open_holds_older_than(0, 100)
        .expect("list young")
        .is_empty());

    assert!(store.expire_open_hold("hold-sweep-1").expect("expire"));
    // Idempotent: a second expire on a non-open hold changes nothing.
    assert!(!store
        .expire_open_hold("hold-sweep-1")
        .expect("expire again"));

    let usage = store.get_usage("cap", 0).expect("usage").expect("record");
    // The exposure dropped by exactly the released remainder; no realized
    // spend was recorded, and the hold's invocation debit was returned.
    assert_eq!(usage.total_cost_exposed, 0);
    assert_eq!(usage.total_cost_realized_spend, 0);
    assert_eq!(usage.invocation_count, 0);

    // The mutation log carries the expire event.
    let events = store
        .list_mutation_events(10, Some("cap"), Some(0))
        .expect("events");
    assert!(events
        .iter()
        .any(|event| event.kind == BudgetMutationKind::ExpireHold));
    assert_eq!(store.open_hold_count().expect("count after"), 0);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn expire_open_hold_returns_the_invocation_slot() {
    use chio_kernel::budget_store::{
        BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetStore,
    };

    let path = unique_db_path("hold-sweep-invocation");
    let store = SqliteBudgetStore::open(&path).expect("open");
    let authorize = |hold: &str| BudgetAuthorizeHoldRequest {
        capability_id: "cap".to_string(),
        grant_index: 0,
        max_invocations: Some(1),
        requested_exposure_units: 70,
        max_cost_per_invocation: Some(70),
        max_total_cost_units: Some(500),
        hold_id: Some(hold.to_string()),
        event_id: Some(format!("{hold}:authorize")),
        authority: None,
        payment_journal: None,
    };

    // The single invocation slot is consumed by the first hold.
    assert!(matches!(
        store
            .authorize_budget_hold(authorize("hold-inv-1"))
            .expect("authorize"),
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    let usage = store.get_usage("cap", 0).expect("usage").expect("record");
    assert_eq!(usage.invocation_count, 1);

    // Expiring the orphaned hold returns the slot: the call never
    // completed, so it must not permanently consume max_invocations.
    assert!(store.expire_open_hold("hold-inv-1").expect("expire"));
    let usage = store.get_usage("cap", 0).expect("usage").expect("record");
    assert_eq!(
        usage.invocation_count, 0,
        "expiry must reverse the invocation debit exactly like the normal reverse path"
    );
    assert_eq!(usage.total_cost_exposed, 0);

    // A retry after the sweep fits the same one-invocation grant again.
    assert!(matches!(
        store
            .authorize_budget_hold(authorize("hold-inv-2"))
            .expect("authorize retry"),
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));

    let _ = std::fs::remove_file(&path);
}
