use super::*;
use chio_kernel::InMemoryBudgetStore;

#[path = "tests/composite.rs"]
mod composite_lifecycle;

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

fn install_usage_anchor(store: &SqliteBudgetStore, record: &BudgetUsageRecord) {
    install_usage_anchors(store, std::slice::from_ref(record));
}

fn install_usage_anchors(store: &SqliteBudgetStore, records: &[BudgetUsageRecord]) {
    let mut connection = store.connection().unwrap();
    let transaction = store.begin_write(&mut connection).unwrap();
    transaction
        .execute(
            "INSERT OR IGNORE INTO budget_usage_anchor_migration_gate(singleton) VALUES (1)",
            [],
        )
        .unwrap();
    for record in records {
        SqliteBudgetStore::upsert_usage_in_transaction(&transaction, record).unwrap();
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
                    budget_u64_to_sqlite(record.seq, "seq").unwrap(),
                    budget_u64_to_sqlite(record.total_cost_exposed, "total_cost_exposed").unwrap(),
                    budget_u64_to_sqlite(
                        record.total_cost_realized_spend,
                        "total_cost_realized_spend",
                    )
                    .unwrap(),
                ],
            )
            .unwrap();
    }
    transaction
        .execute("DELETE FROM budget_usage_anchor_migration_gate", [])
        .unwrap();
    transaction.commit().unwrap();
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
    install_usage_anchor(&store, &usage_record("cap-negative", 0, 1, 10, 1, 0, 0));
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

#[path = "tests/durability.rs"]
mod durability;

#[path = "tests/authority_replay.rs"]
mod authority_replay;

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
        .capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "cap-1".to_string(),
            grant_index: 0,
            hold_id: hold_id.to_string(),
            event_id: "hold-cap-1-0:capture-invocation".to_string(),
            trusted_time: None,
            authority: None,
        })
        .unwrap();
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
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].event_id, authorize_event_id);
    assert_eq!(events[1].kind, BudgetMutationKind::CaptureInvocation);
    assert_eq!(events[2].event_id, reconcile_event_id);
    assert_eq!(events[2].hold_id.as_deref(), Some(hold_id));
    assert_eq!(events[2].kind, BudgetMutationKind::ReconcileSpend);
    assert_eq!(events[2].exposure_units, 100);
    assert_eq!(events[2].realized_spend_units, 75);
    assert_eq!(events[2].total_cost_exposed_after, 0);
    assert_eq!(events[2].total_cost_realized_spend_after, 75);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_reduce_charge_cost_allows_zero_invocation_release_sqlite() {
    let path = unique_db_path("chio-reduce-charge-zero-invocations");
    let store = SqliteBudgetStore::open(&path).unwrap();
    install_usage_anchor(&store, &usage_record("cap-zero", 0, 0, 10, 10, 40, 0));

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
        .capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "cap-lease".to_string(),
            grant_index: 0,
            hold_id: hold_id.to_string(),
            event_id: "hold-cap-lease-0:capture-invocation".to_string(),
            trusted_time: None,
            authority: Some(initial.clone()),
        })
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
    assert_eq!(events.len(), 4);
    assert!(events
        .iter()
        .all(|event| event.authority.as_ref() == Some(&initial)));
}

#[test]
fn budget_store_event_id_retry_rejects_authority_rollover_sqlite() {
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
        .expect_err("exact replay must preserve the original authority");
    assert!(error
        .to_string()
        .contains("authority metadata does not match the original mutation"));
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
            101,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
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
fn budget_store_compensated_identity_is_terminal_and_fresh_identity_succeeds_sqlite() {
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
            Some(&initial),
        )
        .expect_err("compensated authorization identity must remain terminal");
    assert!(error.to_string().contains("cannot be reopened"));

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some("hold-cap-lease-1"),
            Some("hold-cap-lease-1:authorize"),
            Some(&changed),
        )
        .unwrap());

    let usage = store.get_usage("cap-lease", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let events = store
        .list_mutation_events(10, Some("cap-lease"), Some(0))
        .unwrap();
    let original = events
        .iter()
        .find(|record| record.event_id == event_id)
        .expect("original authorize event");
    assert_eq!(original.authority.as_ref(), Some(&initial));
    let fresh = events
        .iter()
        .find(|record| record.event_id == "hold-cap-lease-1:authorize")
        .expect("fresh authorize event");
    assert_eq!(fresh.authority.as_ref(), Some(&changed));

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
    drop(target);
    let reopened = SqliteBudgetStore::open(&target_path).expect("reopen imported snapshot");
    assert_eq!(
        reopened
            .get_usage("cap-import-replay", 0)
            .expect("reopened usage")
            .expect("reopened usage row")
            .invocation_count,
        1
    );

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(target_path);
}

#[test]
fn caller_provided_snapshot_anchor_cannot_create_usage_or_coverage() {
    let path = unique_db_path("chio-budget-explicit-anchor-only");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let usage = usage_record("cap-anchor-only", 0, 7, 1_717_171_717, 42, 550, 375);

    let error = store
        .upsert_usage(&usage)
        .expect_err("public usage upsert must not invent durable history");
    assert!(error.to_string().contains("explicit history anchor"));
    let error = store
        .import_snapshot_records(std::slice::from_ref(&usage), &[])
        .expect_err("the compatibility snapshot path must not invent durable history");
    assert!(error.to_string().contains("explicit history anchor"));
    assert!(store.get_usage("cap-anchor-only", 0).unwrap().is_none());
    assert!(store.list_usage_history_anchors().unwrap().is_empty());
    assert_eq!(store.budget_snapshot_covered_head().unwrap(), 0);

    let error = store
        .import_snapshot_records_with_anchors(
            std::slice::from_ref(&usage),
            &[],
            std::slice::from_ref(&usage),
            &[],
            42,
        )
        .expect_err("a caller-provided anchor must not create migration provenance");
    assert!(error
        .to_string()
        .contains("no identical locally migration-anchored state"));
    assert!(error
        .to_string()
        .contains("elected-leader snapshot path with verified anchor provenance"));
    assert!(store.get_usage("cap-anchor-only", 0).unwrap().is_none());
    assert!(store.list_usage_history_anchors().unwrap().is_empty());
    assert_eq!(store.budget_snapshot_covered_head().unwrap(), 0);

    let _ = fs::remove_file(path);
}

#[test]
fn elected_leader_provenance_bootstraps_a_fresh_pre_upgrade_follower() {
    let path = unique_db_path("chio-budget-verified-anchor-bootstrap");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let usage = usage_record("cap-legacy-anchor", 0, 7, 1_717_171_717, 42, 550, 375);
    let snapshot = BudgetStoreSnapshot {
        usages: vec![usage.clone()],
        usage_history_anchors: vec![usage.clone()],
        mutation_events: Vec::new(),
        abandoned_seq_ranges: Vec::new(),
        covered_head: 0,
        origin_ack_heads: Vec::new(),
    };
    let keypair = chio_core::crypto::Keypair::generate();
    let mut body = BudgetSnapshotAnchorCommitment {
        schema: "chio.budget-snapshot-anchor-commitment.v1".to_string(),
        commit_sequence: 1,
        previous_chain_digest: "0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        chain_digest: String::new(),
        anchor_set_digest: budget_snapshot_anchor_set_digest(std::slice::from_ref(&usage)).unwrap(),
        leader_url: "https://leader.example".to_string(),
        election_term: 9,
        committed_at: 1_717_171_718,
        signer_public_key: keypair.public_key().to_hex(),
    };
    body.chain_digest = budget_snapshot_anchor_chain_digest(&body).unwrap();
    let signature = keypair.sign_canonical(&body).unwrap().0;
    let chain = vec![SignedBudgetSnapshotAnchorCommitment { body, signature }];
    let provenance = BudgetSnapshotAnchorProvenance {
        schema: "chio.budget-snapshot-anchor-provenance.v1".to_string(),
        cluster_authenticator: budget_snapshot_anchor_authenticator("cluster-secret", &chain)
            .unwrap(),
        chain,
    };

    store
        .import_budget_snapshot_with_anchor_provenance(
            &snapshot,
            &provenance,
            "https://leader.example",
            9,
            "cluster-secret",
        )
        .unwrap();

    assert_eq!(
        store.get_usage("cap-legacy-anchor", 0).unwrap(),
        Some(usage.clone())
    );
    assert_eq!(store.list_usage_history_anchors().unwrap(), vec![usage]);
    assert_eq!(store.budget_snapshot_covered_head().unwrap(), 0);

    let _ = fs::remove_file(path);
}

#[test]
fn anchor_provenance_rejects_wrong_cluster_root_before_install() {
    let path = unique_db_path("chio-budget-anchor-wrong-root");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let usage = usage_record("cap-forged-anchor", 0, 1, 10, 1, 0, 0);
    let snapshot = BudgetStoreSnapshot {
        usages: vec![usage.clone()],
        usage_history_anchors: vec![usage],
        mutation_events: Vec::new(),
        abandoned_seq_ranges: Vec::new(),
        covered_head: 0,
        origin_ack_heads: Vec::new(),
    };
    let keypair = chio_core::crypto::Keypair::generate();
    let mut body = BudgetSnapshotAnchorCommitment {
        schema: "chio.budget-snapshot-anchor-commitment.v1".to_string(),
        commit_sequence: 1,
        previous_chain_digest: "0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        chain_digest: String::new(),
        anchor_set_digest: budget_snapshot_anchor_set_digest(&snapshot.usage_history_anchors)
            .unwrap(),
        leader_url: "https://leader.example".to_string(),
        election_term: 2,
        committed_at: 11,
        signer_public_key: keypair.public_key().to_hex(),
    };
    body.chain_digest = budget_snapshot_anchor_chain_digest(&body).unwrap();
    let chain = vec![SignedBudgetSnapshotAnchorCommitment {
        signature: keypair.sign_canonical(&body).unwrap().0,
        body,
    }];
    let provenance = BudgetSnapshotAnchorProvenance {
        schema: "chio.budget-snapshot-anchor-provenance.v1".to_string(),
        cluster_authenticator: budget_snapshot_anchor_authenticator("wrong-secret", &chain)
            .unwrap(),
        chain,
    };

    let error = store
        .import_budget_snapshot_with_anchor_provenance(
            &snapshot,
            &provenance,
            "https://leader.example",
            2,
            "cluster-secret",
        )
        .expect_err("a different cluster trust root must not install anchors");
    assert!(error.to_string().contains("cluster authentication failed"));
    assert!(store.list_usage_history_anchors().unwrap().is_empty());

    let _ = fs::remove_file(path);
}

#[test]
fn identical_local_migration_anchor_is_idempotent_but_does_not_prove_coverage() {
    let path = unique_db_path("chio-budget-local-migration-anchor");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let usage = usage_record("cap-local-anchor", 0, 7, 1_717_171_717, 42, 550, 375);
    install_usage_anchor(&store, &usage);

    store
        .import_snapshot_records_with_anchors(
            std::slice::from_ref(&usage),
            &[],
            std::slice::from_ref(&usage),
            &[],
            0,
        )
        .unwrap();
    assert_eq!(
        store.get_usage("cap-local-anchor", 0).unwrap(),
        Some(usage.clone())
    );
    assert_eq!(store.list_usage_history_anchors().unwrap(), vec![usage]);
    assert_eq!(store.budget_snapshot_covered_head().unwrap(), 0);

    let _ = fs::remove_file(path);
}

#[test]
fn full_snapshot_rejects_an_unproved_claimed_head_atomically() {
    let path = unique_db_path("chio-budget-forged-snapshot-head");
    let store = SqliteBudgetStore::open(&path).unwrap();

    let error = store
        .import_snapshot_records_with_anchors(
            &[],
            &[ack_head_event(1, "forged-head-event", "http://origin")],
            &[],
            &[],
            u64::MAX,
        )
        .expect_err("a claimed head above the imported contiguous prefix must fail");
    assert!(error.to_string().contains("records prove 1"));
    assert_eq!(store.max_mutation_event_seq().unwrap(), 0);
    assert!(store.list_all_usages().unwrap().is_empty());
    assert!(store.list_abandoned_event_seqs().unwrap().is_empty());
    assert_eq!(store.budget_snapshot_covered_head().unwrap(), 0);

    let _ = fs::remove_file(path);
}

#[test]
fn full_snapshot_proves_holes_only_with_atomic_abandoned_ranges() {
    let path = unique_db_path("chio-budget-snapshot-hole-proof");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let events = [
        ack_head_event(1, "snapshot-head-1", "http://origin"),
        ack_head_event(3, "snapshot-head-3", "http://origin"),
    ];

    let error = store
        .import_snapshot_records_with_anchors(&[], &events, &[], &[], 3)
        .expect_err("a missing sequence must cap snapshot coverage");
    assert!(error.to_string().contains("records prove 1"));
    assert_eq!(store.max_mutation_event_seq().unwrap(), 0);

    let error = store
        .import_snapshot_records_with_anchors(&[], &events, &[], &[(1, 2)], 3)
        .expect_err("an abandoned range must not cover a live event");
    assert!(error.to_string().contains("overlaps a mutation event"));
    assert_eq!(store.max_mutation_event_seq().unwrap(), 0);

    store
        .import_snapshot_records_with_anchors(&[], &events, &[], &[(2, 2)], 3)
        .unwrap();
    assert_eq!(store.budget_snapshot_covered_head().unwrap(), 3);
    assert_eq!(
        store.list_abandoned_event_seq_ranges().unwrap(),
        vec![(2, 2)]
    );
    assert_eq!(
        store
            .budget_ack_heads()
            .unwrap()
            .into_iter()
            .find(|(origin, _)| origin == "http://origin")
            .map(|(_, head)| head),
        Some(3)
    );

    let _ = fs::remove_file(path);
}

#[test]
fn full_snapshot_rejects_forged_origin_heads_atomically() {
    let path = unique_db_path("chio-budget-forged-origin-head");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let snapshot = BudgetStoreSnapshot {
        usages: Vec::new(),
        usage_history_anchors: Vec::new(),
        mutation_events: vec![ack_head_event(1, "origin-head-1", "http://origin")],
        abandoned_seq_ranges: Vec::new(),
        covered_head: 1,
        origin_ack_heads: vec![("http://origin".to_string(), 2)],
    };

    let error = store
        .import_budget_snapshot(&snapshot)
        .expect_err("an origin head above its retained event must fail");
    assert!(error
        .to_string()
        .contains("origin acknowledgement heads are not proved"));
    assert_eq!(store.max_mutation_event_seq().unwrap(), 0);
    assert!(store.list_all_usages().unwrap().is_empty());
    assert!(store.budget_ack_heads().unwrap().is_empty());

    let _ = fs::remove_file(path);
}

#[test]
fn full_snapshot_rejects_local_history_missing_from_payload_atomically() {
    let path = unique_db_path("chio-budget-snapshot-local-history");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let retained = [
        ack_head_event(1, "retained-event-1", "http://origin"),
        ack_head_event(3, "local-only-event-3", "http://origin"),
    ];
    store.import_snapshot_records(&[], &retained).unwrap();
    let before = store.export_budget_snapshot().unwrap();
    let incoming = BudgetStoreSnapshot {
        usages: vec![before.usages[0].clone()],
        usage_history_anchors: Vec::new(),
        mutation_events: vec![retained[0].clone()],
        abandoned_seq_ranges: Vec::new(),
        covered_head: 1,
        origin_ack_heads: vec![("http://origin".to_string(), 1)],
    };

    let error = store
        .import_budget_snapshot(&incoming)
        .expect_err("a peer snapshot must not discard unmatched local history");
    assert!(error
        .to_string()
        .contains("does not retain identical local event `local-only-event-3`"));
    assert_eq!(store.export_budget_snapshot().unwrap(), before);

    let _ = fs::remove_file(path);
}

#[test]
fn full_snapshot_proves_coverage_from_payload_without_local_rows() {
    let path = unique_db_path("chio-budget-snapshot-isolated-proof");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let retained = [
        ack_head_event(1, "isolated-event-1", "http://origin"),
        ack_head_event(3, "isolated-local-event-3", "http://origin"),
    ];
    store.import_snapshot_records(&[], &retained).unwrap();
    store.record_abandoned_event_seq_ranges(&[(2, 2)]).unwrap();
    let before = store.export_budget_snapshot().unwrap();
    let incoming = BudgetStoreSnapshot {
        usages: vec![before.usages[0].clone()],
        usage_history_anchors: Vec::new(),
        mutation_events: vec![retained[0].clone()],
        abandoned_seq_ranges: Vec::new(),
        covered_head: 3,
        origin_ack_heads: vec![("http://origin".to_string(), 3)],
    };

    let error = store
        .import_budget_snapshot(&incoming)
        .expect_err("local rows must not prove an incomplete peer payload");
    assert!(error.to_string().contains("imported records prove 1"));
    assert_eq!(store.export_budget_snapshot().unwrap(), before);

    let _ = fs::remove_file(path);
}

#[test]
fn full_snapshot_requires_the_exact_immutable_anchor_set() {
    let path = unique_db_path("chio-budget-snapshot-anchor-set");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let anchor = usage_record("cap-local-anchor-extra", 0, 2, 20, 2, 10, 3);
    install_usage_anchor(&store, &anchor);
    let before = store.export_budget_snapshot().unwrap();
    let incoming = BudgetStoreSnapshot {
        usages: Vec::new(),
        usage_history_anchors: Vec::new(),
        mutation_events: Vec::new(),
        abandoned_seq_ranges: Vec::new(),
        covered_head: 0,
        origin_ack_heads: Vec::new(),
    };

    let error = store
        .import_budget_snapshot(&incoming)
        .expect_err("immutable local anchors cannot be omitted from a full snapshot");
    assert!(error
        .to_string()
        .contains("history anchor set differs from immutable local migration anchors"));
    assert_eq!(store.export_budget_snapshot().unwrap(), before);

    let _ = fs::remove_file(path);
}

#[test]
fn reopen_rebuilds_forged_snapshot_proof_caches_from_genesis() {
    let path = unique_db_path("chio-budget-forged-proof-cache");
    {
        let store = SqliteBudgetStore::open(&path).unwrap();
        let connection = store.connection().unwrap();
        connection
            .execute(
                "UPDATE budget_snapshot_coverage SET covered_head = 42 WHERE singleton = 1",
                [],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE budget_ack_head_watermark SET head_seq = 42 WHERE singleton = 1",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO budget_origin_ack_heads(authority_id, head_seq) VALUES ('forged', 42)",
                [],
            )
            .unwrap();
    }

    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(reopened.budget_snapshot_covered_head().unwrap(), 0);
    assert!(reopened.budget_ack_heads().unwrap().is_empty());
    let connection = reopened.connection().unwrap();
    let caches: (i64, i64, i64) = connection
        .query_row(
            r#"
            SELECT
                (SELECT covered_head FROM budget_snapshot_coverage WHERE singleton = 1),
                (SELECT head_seq FROM budget_ack_head_watermark WHERE singleton = 1),
                (SELECT COUNT(*) FROM budget_origin_ack_heads)
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(caches, (0, 0, 0));

    let _ = fs::remove_file(path);
}

#[test]
fn snapshot_export_keeps_every_same_sequence_usage_in_identity_order() {
    let path = unique_db_path("chio-budget-same-seq-snapshot");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let records = (0..1_025)
        .map(|index| usage_record(&format!("cap-{index:04}"), 0, 1, 1_717_171_717, 42, 1, 0))
        .collect::<Vec<_>>();
    install_usage_anchors(&store, &records);

    let snapshot = store.export_budget_snapshot().unwrap();
    assert_eq!(snapshot.usages, records);
    assert_eq!(snapshot.usage_history_anchors, records);
    assert_eq!(snapshot.covered_head, 0);
    assert!(snapshot.mutation_events.is_empty());
    assert!(snapshot.origin_ack_heads.is_empty());

    let _ = fs::remove_file(path);
}

#[test]
fn snapshot_export_is_consistent_while_another_connection_commits() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier};

    let path = unique_db_path("chio-budget-concurrent-snapshot");
    let reader = SqliteBudgetStore::open(&path).unwrap();
    let writer = SqliteBudgetStore::open(&path).unwrap();
    let started = Arc::new(Barrier::new(2));
    let done = Arc::new(AtomicBool::new(false));
    let writer_started = Arc::clone(&started);
    let writer_done = Arc::clone(&done);
    let handle = std::thread::spawn(move || {
        writer_started.wait();
        let authority = authority("http://origin", "http://origin#term-1", 1);
        for index in 0..64 {
            assert!(writer
                .try_charge_cost_with_ids_and_authority(
                    "cap-concurrent-snapshot",
                    0,
                    Some(64),
                    1,
                    Some(1),
                    Some(64),
                    Some(&format!("hold-concurrent-{index}")),
                    Some(&format!("event-concurrent-{index}")),
                    Some(&authority),
                )
                .unwrap());
        }
        writer_done.store(true, Ordering::Release);
    });
    started.wait();

    let mut exports = 0;
    while exports < 8 || (!done.load(Ordering::Acquire) && exports < 512) {
        let snapshot = reader.export_budget_snapshot().unwrap();
        exports += 1;
        let Some(last_event) = snapshot.mutation_events.last() else {
            continue;
        };
        assert_eq!(snapshot.covered_head, last_event.event_seq);
        assert!(snapshot
            .mutation_events
            .windows(2)
            .all(|pair| pair[1].event_seq == pair[0].event_seq + 1));
        let usage = snapshot
            .usages
            .iter()
            .find(|usage| usage.capability_id == "cap-concurrent-snapshot")
            .unwrap();
        assert_eq!(usage.seq, last_event.event_seq);
        assert_eq!(usage.invocation_count, last_event.invocation_count_after);
        assert_eq!(
            usage.total_cost_exposed,
            last_event.total_cost_exposed_after
        );
        assert_eq!(
            snapshot.origin_ack_heads,
            vec![("http://origin".to_string(), snapshot.covered_head)]
        );
    }
    handle.join().unwrap();

    let _ = fs::remove_file(path);
}

#[test]
fn migration_anchor_does_not_bootstrap_coverage_over_later_events() {
    let path = unique_db_path("chio-budget-anchor-plus-events");
    let anchor = usage_record("cap-anchor", 0, 7, 1_717_171_717, 42, 550, 375);
    let events = [
        ack_head_event(43, "snapshot-head-43", "http://origin"),
        ack_head_event(44, "snapshot-head-44", "http://origin"),
    ];
    {
        let store = SqliteBudgetStore::open(&path).unwrap();
        install_usage_anchor(&store, &anchor);
        store
            .import_snapshot_records_with_anchors(
                std::slice::from_ref(&anchor),
                &events,
                std::slice::from_ref(&anchor),
                &[],
                0,
            )
            .unwrap();
        assert_eq!(store.budget_snapshot_covered_head().unwrap(), 0);
        assert!(store
            .try_charge_cost_with_ids_and_authority(
                "cap-after-snapshot",
                0,
                Some(2),
                1,
                None,
                None,
                None,
                Some("snapshot-head-45"),
                Some(&authority("http://origin", "http://origin#term-1", 1,)),
            )
            .unwrap());
        assert_eq!(store.max_mutation_event_seq().unwrap(), 45);
    }

    let reopened = SqliteBudgetStore::open(&path).expect("reopen anchored snapshot");
    assert_eq!(reopened.budget_snapshot_covered_head().unwrap(), 0);
    assert_eq!(reopened.list_usage_history_anchors().unwrap(), vec![anchor]);

    let _ = fs::remove_file(path);
}

#[test]
fn import_snapshot_records_duplicate_event_rejects_peer_transport_sequence_injection_sqlite() {
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
    let error = target
        .import_snapshot_records(std::slice::from_ref(&usage), &[replayed_event])
        .expect_err("duplicate event transport fields must be immutable");
    assert!(error
        .to_string()
        .contains("reused for a different mutation"));

    let replicated_events = target
        .list_mutation_events(10, Some("cap-import-transport"), Some(0))
        .unwrap();
    assert_eq!(replicated_events.len(), 1);
    assert_eq!(
        replicated_events[0].event_id,
        "hold-import-transport-0:authorize"
    );
    assert_eq!(
        target.max_mutation_event_seq().unwrap(),
        events[0].event_seq
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
fn budget_store_open_hold_rejects_missing_authorize_event_sqlite() {
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

    let error = store
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
        .expect_err("an open hold without its authorization event must fail closed");
    assert!(error.to_string().contains("authorization event"));

    let events = store
        .list_mutation_events(10, Some("cap-recover"), Some(0))
        .unwrap();
    assert!(events.is_empty());

    let _ = fs::remove_file(path);
}

#[test]
fn upsert_usage_preserves_newer_split_cost_state() {
    let path = unique_db_path("chio-budget-upsert-cost");
    let store = SqliteBudgetStore::open(&path).unwrap();

    // Higher-seq record written first
    install_usage_anchor(&store, &usage_record("cap-1", 0, 5, 10, 10, 500, 0));

    // Lower-seq record written second (stale replica)
    let error = store
        .upsert_usage(&usage_record("cap-1", 0, 3, 12, 5, 300, 0))
        .expect_err("stale usage snapshot must be rejected");
    assert!(error.to_string().contains("anchor"));

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_usage_totals(&records[0], 500, 0);
    assert_eq!(records[0].seq, 10);

    let _ = fs::remove_file(path);
}

#[test]
fn upsert_usage_does_not_resurrect_split_cost_state_from_stale_seq() {
    let path = unique_db_path("chio-budget-upsert-split");
    let store = SqliteBudgetStore::open(&path).unwrap();

    install_usage_anchor(&store, &usage_record("cap-1", 0, 1, 20, 20, 0, 75));
    let error = store
        .upsert_usage(&usage_record("cap-1", 0, 1, 10, 10, 100, 0))
        .expect_err("stale split-cost snapshot must be rejected");
    assert!(error.to_string().contains("anchor"));

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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("secure directory");
    }
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("secure directory");
    }
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
            invocation_quotas: Vec::new(),
            cumulative_approval: None,
            admission_binding: None,
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("secure directory");
    }
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
            invocation_quotas: Vec::new(),
            cumulative_approval: None,
            admission_binding: None,
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
        admission_binding: None,
        capability_id: format!("cap-o-{seq}"),
        grant_index: 0,
        kind: BudgetMutationKind::AuthorizeExposure,
        allowed: Some(true),
        authorization_outcome: None,
        invocation_state_before: BudgetInvocationState::Absent,
        invocation_state_after: BudgetInvocationState::Absent,
        monetary_state_before: BudgetMonetaryState::None,
        monetary_state_after: BudgetMonetaryState::None,
        recorded_at: seq as i64,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        invocation_quota_usages: Vec::new(),
        invocation_quota_mutations: Vec::new(),
        cumulative_approval: None,
        cumulative_approval_mutation: None,
        cumulative_approval_set_digest: None,
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
        admission_binding: None,
        capability_id: format!("cap-p-{seq}"),
        grant_index: 0,
        kind: BudgetMutationKind::AuthorizeExposure,
        allowed: Some(true),
        authorization_outcome: None,
        invocation_state_before: BudgetInvocationState::Absent,
        invocation_state_after: BudgetInvocationState::Absent,
        monetary_state_before: BudgetMonetaryState::None,
        monetary_state_after: BudgetMonetaryState::None,
        recorded_at: seq as i64,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        invocation_quota_usages: Vec::new(),
        invocation_quota_mutations: Vec::new(),
        cumulative_approval: None,
        cumulative_approval_mutation: None,
        cumulative_approval_set_digest: None,
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
        admission_binding: None,
        capability_id: format!("cap-g-{seq}"),
        grant_index: 0,
        kind: BudgetMutationKind::AuthorizeExposure,
        allowed: Some(true),
        authorization_outcome: None,
        invocation_state_before: BudgetInvocationState::Absent,
        invocation_state_after: BudgetInvocationState::Absent,
        monetary_state_before: BudgetMonetaryState::None,
        monetary_state_after: BudgetMonetaryState::None,
        recorded_at: seq as i64,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        invocation_quota_usages: Vec::new(),
        invocation_quota_mutations: Vec::new(),
        cumulative_approval: None,
        cumulative_approval_mutation: None,
        cumulative_approval_set_digest: None,
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
        admission_binding: None,
        capability_id: format!("cap-m-{seq}"),
        grant_index: 0,
        kind: BudgetMutationKind::AuthorizeExposure,
        allowed: Some(true),
        authorization_outcome: None,
        invocation_state_before: BudgetInvocationState::Absent,
        invocation_state_after: BudgetInvocationState::Absent,
        monetary_state_before: BudgetMonetaryState::None,
        monetary_state_after: BudgetMonetaryState::None,
        recorded_at: seq as i64,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        invocation_quota_usages: Vec::new(),
        invocation_quota_mutations: Vec::new(),
        cumulative_approval: None,
        cumulative_approval_mutation: None,
        cumulative_approval_set_digest: None,
        total_cost_exposed_after: 1,
        total_cost_realized_spend_after: 0,
        authority: Some(BudgetEventAuthority {
            authority_id: origin.to_string(),
            lease_id: format!("{origin}#term-{seq}"),
            lease_epoch: seq,
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
        admission_binding: None,
        capability_id: format!("cap-w-{seq}"),
        grant_index: 0,
        kind: BudgetMutationKind::AuthorizeExposure,
        allowed: Some(true),
        authorization_outcome: None,
        invocation_state_before: BudgetInvocationState::Absent,
        invocation_state_after: BudgetInvocationState::Absent,
        monetary_state_before: BudgetMonetaryState::None,
        monetary_state_after: BudgetMonetaryState::None,
        recorded_at: seq as i64,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        invocation_quota_usages: Vec::new(),
        invocation_quota_mutations: Vec::new(),
        cumulative_approval: None,
        cumulative_approval_mutation: None,
        cumulative_approval_set_digest: None,
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
    assert_eq!(store.budget_snapshot_covered_head()?, 3);

    // Delete the middle event (seq 2): the watermark reset forces re-verification
    // and the head caps at 1, NOT the stale-high 3.
    store.delete_mutation_event("e2")?;
    assert_eq!(
        store.budget_snapshot_covered_head()?,
        1,
        "snapshot coverage must not trust an allocator high-water mark past a hole"
    );
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
