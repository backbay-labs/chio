use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use chio_kernel::budget_store::BudgetMutationRecord;
use chio_kernel::{BudgetStore, BudgetUsageRecord, InMemoryBudgetStore};
use chio_kernel_core::{
    budget_charge_admits, budget_increment_admits, BudgetAdmissionProjectionError,
};
use chio_store_sqlite::SqliteBudgetStore;
use proptest::prelude::*;
use rusqlite::params;

use chio_test_support::prelude::*;

static NEXT_DATABASE_ID: AtomicU64 = AtomicU64::new(0);

struct SqliteFixture {
    store: Option<SqliteBudgetStore>,
    path: PathBuf,
}

impl SqliteFixture {
    fn new() -> Self {
        let id = NEXT_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "chio-budget-equivalence-{}-{id}.sqlite3",
            std::process::id()
        ));
        let store = SqliteBudgetStore::open(&path).test_unwrap();
        Self {
            store: Some(store),
            path,
        }
    }

    fn store(&self) -> &SqliteBudgetStore {
        self.store
            .as_ref()
            .unwrap_or_else(|| unreachable!("fixture store exists until drop"))
    }

    fn install_usage_anchor(&self, record: &BudgetUsageRecord) {
        let mut connection = rusqlite::Connection::open(&self.path).test_unwrap();
        let transaction = connection.transaction().test_unwrap();
        transaction
            .execute(
                "INSERT OR IGNORE INTO budget_usage_anchor_migration_gate(singleton) VALUES (1)",
                [],
            )
            .test_unwrap();
        transaction
            .execute(
                r#"
                INSERT INTO budget_usage_history_anchors (
                    capability_id, grant_index, invocation_count, updated_at, seq,
                    total_cost_exposed, total_cost_realized_spend, anchored_schema_version
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 6)
                "#,
                params![
                    &record.capability_id,
                    i64::from(record.grant_index),
                    i64::from(record.invocation_count),
                    record.updated_at,
                    i64::try_from(record.seq).test_unwrap(),
                    i64::try_from(record.total_cost_exposed).test_unwrap(),
                    i64::try_from(record.total_cost_realized_spend).test_unwrap(),
                ],
            )
            .test_unwrap();
        transaction
            .execute("DELETE FROM budget_usage_anchor_migration_gate", [])
            .test_unwrap();
        transaction.commit().test_unwrap();
        self.store().upsert_usage(record).test_unwrap();
    }
}

impl Drop for SqliteFixture {
    fn drop(&mut self) {
        drop(self.store.take());
        for path in [
            self.path.clone(),
            self.path.with_extension("sqlite3-wal"),
            self.path.with_extension("sqlite3-shm"),
        ] {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn seed_usage(
    store: &dyn BudgetStore,
    invocation_count: u8,
    committed_cost_units: u64,
    max_invocations: Option<u32>,
) {
    if invocation_count == 0 {
        return;
    }

    assert!(store
        .try_charge_cost("cap", 0, max_invocations, committed_cost_units, None, None,)
        .test_unwrap());
    for _ in 1..invocation_count {
        assert!(store
            .try_charge_cost("cap", 0, max_invocations, 0, None, None)
            .test_unwrap());
    }
}

fn assert_mutation_shape_eq(left: &[BudgetMutationRecord], right: &[BudgetMutationRecord]) {
    assert_eq!(left.len(), right.len());
    for (left, right) in left.iter().zip(right) {
        assert_eq!(left.hold_id, right.hold_id);
        assert_eq!(left.capability_id, right.capability_id);
        assert_eq!(left.grant_index, right.grant_index);
        assert_eq!(left.kind, right.kind);
        assert_eq!(left.allowed, right.allowed);
        assert_eq!(left.event_seq, right.event_seq);
        assert_eq!(left.usage_seq, right.usage_seq);
        assert_eq!(left.exposure_units, right.exposure_units);
        assert_eq!(left.realized_spend_units, right.realized_spend_units);
        assert_eq!(left.max_invocations, right.max_invocations);
        assert_eq!(left.max_cost_per_invocation, right.max_cost_per_invocation);
        assert_eq!(left.max_total_cost_units, right.max_total_cost_units);
        assert_eq!(left.invocation_count_after, right.invocation_count_after);
        assert_eq!(
            left.total_cost_exposed_after,
            right.total_cost_exposed_after
        );
        assert_eq!(
            left.total_cost_realized_spend_after,
            right.total_cost_realized_spend_after
        );
        assert_eq!(left.authority, right.authority);
    }
}

proptest! {
    #[test]
    fn in_memory_increment_calls_exact_projection(
        invocation_count in 0_u8..8,
        max_invocations in proptest::option::of(0_u32..10),
    ) {
        prop_assume!(max_invocations.is_none_or(
            |maximum| u32::from(invocation_count) <= maximum
        ));
        let store = InMemoryBudgetStore::new();
        seed_usage(&store, invocation_count, 0, max_invocations);

        let actual = store
            .try_increment("cap", 0, max_invocations)
            .test_unwrap();
        let expected = budget_increment_admits(u32::from(invocation_count), max_invocations);

        prop_assert_eq!(actual, expected);
    }

    #[test]
    fn in_memory_charge_calls_exact_projection(
        invocation_count in 0_u8..8,
        initial_cost_units in 0_u64..512,
        cost_units in 0_u64..512,
        max_invocations in proptest::option::of(0_u32..10),
        max_cost_per_invocation in proptest::option::of(0_u64..512),
        max_total_cost_units in proptest::option::of(0_u64..1_024),
    ) {
        prop_assume!(max_invocations.is_none_or(
            |maximum| u32::from(invocation_count) <= maximum
        ));
        let committed_cost_units = if invocation_count == 0 {
            0
        } else {
            initial_cost_units
        };
        let store = InMemoryBudgetStore::new();
        seed_usage(
            &store,
            invocation_count,
            committed_cost_units,
            max_invocations,
        );

        let actual = store
            .try_charge_cost(
                "cap",
                0,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
            )
            .test_unwrap();
        let expected = budget_charge_admits(
            u32::from(invocation_count),
            committed_cost_units,
            cost_units,
            max_invocations,
            max_cost_per_invocation,
            max_total_cost_units,
        )
        .test_unwrap();

        prop_assert_eq!(actual, expected);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn sqlite_increment_calls_exact_projection(
        invocation_count in 0_u8..8,
        max_invocations in proptest::option::of(0_u32..10),
    ) {
        prop_assume!(max_invocations.is_none_or(
            |maximum| u32::from(invocation_count) <= maximum
        ));
        let sqlite = SqliteFixture::new();
        let store = sqlite.store();
        seed_usage(store, invocation_count, 0, max_invocations);

        let actual = store
            .try_increment("cap", 0, max_invocations)
            .test_unwrap();
        let expected = budget_increment_admits(u32::from(invocation_count), max_invocations);

        prop_assert_eq!(actual, expected);
    }

    #[test]
    fn sqlite_charge_calls_exact_projection(
        invocation_count in 0_u8..8,
        initial_cost_units in 0_u64..512,
        cost_units in 0_u64..512,
        max_invocations in proptest::option::of(0_u32..10),
        max_cost_per_invocation in proptest::option::of(0_u64..512),
        max_total_cost_units in proptest::option::of(0_u64..1_024),
    ) {
        prop_assume!(max_invocations.is_none_or(
            |maximum| u32::from(invocation_count) <= maximum
        ));
        let committed_cost_units = if invocation_count == 0 {
            0
        } else {
            initial_cost_units
        };
        let sqlite = SqliteFixture::new();
        let store = sqlite.store();
        seed_usage(
            store,
            invocation_count,
            committed_cost_units,
            max_invocations,
        );

        let actual = store
            .try_charge_cost(
                "cap",
                0,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
            )
            .test_unwrap();
        let expected = budget_charge_admits(
            u32::from(invocation_count),
            committed_cost_units,
            cost_units,
            max_invocations,
            max_cost_per_invocation,
            max_total_cost_units,
        )
        .test_unwrap();

        prop_assert_eq!(actual, expected);
    }
}

#[test]
fn sqlite_and_in_memory_share_decisions_and_mutation_shape() {
    let memory = InMemoryBudgetStore::new();
    let sqlite = SqliteFixture::new();
    let sqlite = sqlite.store();

    for store in [&memory as &dyn BudgetStore, sqlite as &dyn BudgetStore] {
        assert_eq!(
            store
                .try_charge_cost("cap", 0, Some(3), 100, Some(200), Some(250))
                .test_unwrap(),
            budget_charge_admits(0, 0, 100, Some(3), Some(200), Some(250)).test_unwrap()
        );
        assert_eq!(
            store
                .try_charge_cost("cap", 0, Some(3), 175, Some(200), Some(250))
                .test_unwrap(),
            budget_charge_admits(1, 100, 175, Some(3), Some(200), Some(250)).test_unwrap()
        );
        assert_eq!(
            store.try_increment("cap", 0, Some(3)).test_unwrap(),
            budget_increment_admits(1, Some(3))
        );
    }

    let memory_usage = memory.get_usage("cap", 0).test_unwrap().test_unwrap();
    let sqlite_usage = sqlite.get_usage("cap", 0).test_unwrap().test_unwrap();
    assert_eq!(memory_usage.invocation_count, sqlite_usage.invocation_count);
    assert_eq!(
        memory_usage.total_cost_exposed,
        sqlite_usage.total_cost_exposed
    );
    assert_eq!(
        memory_usage.total_cost_realized_spend,
        sqlite_usage.total_cost_realized_spend
    );

    let memory_events = memory
        .list_mutation_events(10, Some("cap"), Some(0))
        .test_unwrap();
    let sqlite_events = sqlite
        .list_mutation_events(10, Some("cap"), Some(0))
        .test_unwrap();
    assert_mutation_shape_eq(&memory_events, &sqlite_events);
}

#[test]
fn sqlite_saturated_counter_calls_exact_projection_without_mutation() {
    let sqlite = SqliteFixture::new();
    sqlite.install_usage_anchor(&BudgetUsageRecord {
        capability_id: "saturated".to_string(),
        grant_index: 0,
        invocation_count: u32::MAX,
        updated_at: 1,
        seq: 1,
        total_cost_exposed: 0,
        total_cost_realized_spend: 0,
    });
    let sqlite = sqlite.store();

    let actual = sqlite
        .try_increment("saturated", 0, Some(u32::MAX))
        .test_unwrap();
    assert_eq!(actual, budget_increment_admits(u32::MAX, Some(u32::MAX)));

    let usage = sqlite.get_usage("saturated", 0).test_unwrap().test_unwrap();
    assert_eq!(usage.invocation_count, u32::MAX);
    let events = sqlite
        .list_mutation_events(10, Some("saturated"), Some(0))
        .test_unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].allowed, Some(false));
    assert_eq!(events[0].usage_seq, None);
    assert_eq!(events[0].invocation_count_after, u32::MAX);
}

#[test]
fn sqlite_uncapped_saturated_counter_fails_closed_without_mutation() {
    let sqlite = SqliteFixture::new();
    sqlite.install_usage_anchor(&BudgetUsageRecord {
        capability_id: "uncapped-saturated".to_string(),
        grant_index: 0,
        invocation_count: u32::MAX,
        updated_at: 1,
        seq: 1,
        total_cost_exposed: 0,
        total_cost_realized_spend: 0,
    });
    let sqlite = sqlite.store();

    let before = sqlite
        .get_usage("uncapped-saturated", 0)
        .test_unwrap()
        .test_unwrap();
    let events_before = sqlite
        .list_mutation_events(10, Some("uncapped-saturated"), Some(0))
        .test_unwrap();
    let error = sqlite
        .try_increment("uncapped-saturated", 0, None)
        .test_unwrap_err();
    assert_eq!(
        error.to_string(),
        "budget arithmetic overflow: invocation count overflowed u32"
    );

    let usage = sqlite
        .get_usage("uncapped-saturated", 0)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(usage, before);
    let events = sqlite
        .list_mutation_events(10, Some("uncapped-saturated"), Some(0))
        .test_unwrap();
    assert_eq!(events, events_before);
}

#[test]
fn in_memory_total_cost_overflow_keeps_state_and_event_history_unchanged() {
    assert_eq!(
        budget_charge_admits(1, u64::MAX, 1, None, None, Some(u64::MAX)),
        Err(BudgetAdmissionProjectionError::TotalCostOverflow),
    );

    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("overflow", 0, None, u64::MAX, None, None)
        .test_unwrap());
    let before = store.get_usage("overflow", 0).test_unwrap().test_unwrap();
    let events_before = store
        .list_mutation_events(10, Some("overflow"), Some(0))
        .test_unwrap();

    let error = store
        .try_charge_cost("overflow", 0, None, 1, None, Some(u64::MAX))
        .test_unwrap_err();
    assert_eq!(
        error.to_string(),
        "budget arithmetic overflow: authorized exposure + cost_units overflowed u64"
    );

    assert_eq!(
        store.get_usage("overflow", 0).test_unwrap().test_unwrap(),
        before
    );
    assert_eq!(
        store
            .list_mutation_events(10, Some("overflow"), Some(0))
            .test_unwrap(),
        events_before
    );
}

#[test]
fn sqlite_signed_storage_boundary_keeps_state_and_event_history_unchanged() {
    let sqlite = SqliteFixture::new();
    let store = sqlite.store();
    let signed_max = i64::MAX as u64;

    assert!(store
        .try_charge_cost("storage-boundary", 0, None, signed_max, None, None)
        .test_unwrap());
    let before = store
        .get_usage("storage-boundary", 0)
        .test_unwrap()
        .test_unwrap();
    let events_before = store
        .list_mutation_events(10, Some("storage-boundary"), Some(0))
        .test_unwrap();

    let error = store
        .try_charge_cost("storage-boundary", 0, None, 1, None, None)
        .test_unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "budget arithmetic overflow: budget field `total_cost_exposed` exceeds SQLite INTEGER range: {}",
            signed_max + 1
        )
    );

    assert_eq!(
        store
            .get_usage("storage-boundary", 0)
            .test_unwrap()
            .test_unwrap(),
        before
    );
    assert_eq!(
        store
            .list_mutation_events(10, Some("storage-boundary"), Some(0))
            .test_unwrap(),
        events_before
    );
}
