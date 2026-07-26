use super::*;

#[test]
fn elected_leader_snapshot_bootstraps_pre_upgrade_usage_anchors() {
    let source_budget_db = unique_temp_path("cluster-source-legacy-budget", "sqlite3");
    let target_budget_db = unique_temp_path("cluster-target-legacy-budget", "sqlite3");
    let source_authority_db = unique_temp_path("cluster-source-anchor-authority", "sqlite3");
    let target_authority_db = unique_temp_path("cluster-target-anchor-authority", "sqlite3");
    let mut source_state = state_with_cluster(
        "http://node-a",
        &["http://node-b"],
        None,
        None,
        Some(source_budget_db.clone()),
    );
    source_state.config.authority_db_path = Some(source_authority_db.clone());
    let mut target_state = state_with_cluster(
        "http://node-b",
        &["http://node-a"],
        None,
        None,
        Some(target_budget_db.clone()),
    );
    target_state.config.authority_db_path = Some(target_authority_db.clone());
    update_peer_reachable(&source_state, "http://node-b");
    update_peer_reachable(&target_state, "http://node-a");
    assert_eq!(
        current_leader_url(&source_state).as_deref(),
        Some("http://node-a")
    );
    assert_eq!(
        current_leader_url(&target_state).as_deref(),
        Some("http://node-a")
    );

    drop(SqliteBudgetStore::open(&source_budget_db).test_unwrap());
    let source_connection = rusqlite::Connection::open(&source_budget_db).test_unwrap();
    source_connection
        .execute(
            "INSERT INTO budget_usage_anchor_migration_gate(singleton) VALUES (1)",
            [],
        )
        .test_unwrap();
    source_connection
        .execute(
            r#"
            INSERT INTO capability_grant_budgets (
                capability_id, grant_index, invocation_count, updated_at, seq,
                total_cost_exposed, total_cost_realized_spend
            ) VALUES ('cap-pre-upgrade', 0, 3, 1717171717, 42, 55, 21)
            "#,
            [],
        )
        .test_unwrap();
    source_connection
        .execute(
            r#"
            INSERT INTO budget_usage_history_anchors (
                capability_id, grant_index, invocation_count, updated_at, seq,
                total_cost_exposed, total_cost_realized_spend, anchored_schema_version
            ) VALUES ('cap-pre-upgrade', 0, 3, 1717171717, 42, 55, 21, 6)
            "#,
            [],
        )
        .test_unwrap();
    source_connection
        .execute("DELETE FROM budget_usage_anchor_migration_gate", [])
        .test_unwrap();
    drop(source_connection);

    let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
    assert_eq!(snapshot.budget_usage_history_anchors.len(), 1);
    assert!(snapshot.budget_anchor_provenance.is_some());
    apply_cluster_snapshot(&target_state, "http://node-a", snapshot).test_unwrap();

    let target_store = SqliteBudgetStore::open(&target_budget_db).test_unwrap();
    let imported = target_store
        .get_usage("cap-pre-upgrade", 0)
        .test_unwrap()
        .test_expect("fresh follower imported the leader-committed baseline");
    assert_eq!(imported.invocation_count, 3);
    assert_eq!(
        target_store.list_usage_history_anchors().test_unwrap(),
        vec![imported]
    );

    drop(target_store);
    drop(source_state);
    drop(target_state);
    for path in [
        source_budget_db,
        target_budget_db,
        source_authority_db,
        target_authority_db,
    ] {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn snapshot_preserves_exact_budget_origin_heads_and_next_delta() {
    let source_budget_db = unique_temp_path("cluster-source-budget-origin", "sqlite3");
    let target_budget_db = unique_temp_path("cluster-target-budget-origin", "sqlite3");
    let source_state = state_with_cluster(
        "http://node-a",
        &["http://node-b"],
        None,
        None,
        Some(source_budget_db.clone()),
    );
    let target_state = state_with_cluster(
        "http://node-b",
        &["http://node-a"],
        None,
        None,
        Some(target_budget_db.clone()),
    );

    let authority = BudgetEventAuthority {
        authority_id: "http://node-a".to_string(),
        lease_id: "http://node-a#term-1".to_string(),
        lease_epoch: 1,
    };
    let source_store = SqliteBudgetStore::open(&source_budget_db).test_unwrap();
    assert!(source_store
        .try_charge_cost_with_ids_and_authority(
            "cap-snapshot",
            0,
            Some(20),
            9,
            Some(100),
            Some(1_000),
            Some("hold-snapshot"),
            Some("hold-snapshot:authorize"),
            Some(&authority),
        )
        .test_unwrap());

    let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
    assert_eq!(snapshot.replication.budget_seq, 1);
    assert!(snapshot.budget_usage_history_anchors.is_empty());
    assert_eq!(snapshot.budget_mutation_events.len(), 1);
    assert_eq!(snapshot.budget_mutation_events[0].event_seq, 1);
    assert_eq!(
        snapshot.budget_origin_ack_heads,
        vec![BudgetOriginAck {
            origin_id: "http://node-a".to_string(),
            event_seq: 1,
        }]
    );
    apply_cluster_snapshot(&target_state, "http://node-a", snapshot).test_unwrap();

    let target_store = SqliteBudgetStore::open(&target_budget_db).test_unwrap();
    assert_eq!(target_store.budget_snapshot_covered_head().test_unwrap(), 1);
    assert!(target_store
        .list_usage_history_anchors()
        .test_unwrap()
        .is_empty());
    let installed_cursor = peer_budget_cursor(&target_state, "http://node-a").test_unwrap();
    assert_eq!(installed_cursor.seq, 1);

    source_store
        .reduce_charge_cost_with_ids_and_authority(
            "cap-snapshot",
            0,
            4,
            Some("hold-snapshot"),
            Some("hold-snapshot:release"),
            Some(&authority),
        )
        .test_unwrap();
    let next_snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
    let response = BudgetDeltaResponse {
        records: next_snapshot.budgets,
        mutation_events: next_snapshot
            .budget_mutation_events
            .into_iter()
            .filter(|event| event.event_seq > installed_cursor.seq)
            .collect(),
        abandoned_seqs: Vec::new(),
    };
    let outcome = import_budget_delta_response(
        &target_store,
        &response,
        Some(installed_cursor),
        &mut PullRoundBudget::new(),
    )
    .test_unwrap();
    assert_eq!(outcome.applied_count, 1);
    assert_eq!(outcome.next_cursor.test_unwrap().seq, 2);
    assert_eq!(target_store.budget_snapshot_covered_head().test_unwrap(), 2);

    drop(source_store);
    drop(target_store);
    drop(source_state);
    drop(target_state);
    let _ = std::fs::remove_file(source_budget_db);
    let _ = std::fs::remove_file(target_budget_db);
}

#[test]
fn snapshot_rejects_forged_budget_origin_head_without_partial_import() {
    let source_budget_db = unique_temp_path("cluster-source-forged-origin", "sqlite3");
    let target_budget_db = unique_temp_path("cluster-target-forged-origin", "sqlite3");
    let source_state = state_with_cluster(
        "http://node-a",
        &["http://node-b"],
        None,
        None,
        Some(source_budget_db.clone()),
    );
    let target_state = state_with_cluster(
        "http://node-b",
        &["http://node-a"],
        None,
        None,
        Some(target_budget_db.clone()),
    );
    let source_store = SqliteBudgetStore::open(&source_budget_db).test_unwrap();
    let authority = BudgetEventAuthority {
        authority_id: "http://node-a".to_string(),
        lease_id: "http://node-a#term-1".to_string(),
        lease_epoch: 1,
    };
    assert!(source_store
        .try_charge_cost_with_ids_and_authority(
            "cap-forged-origin",
            0,
            Some(1),
            1,
            Some(1),
            Some(1),
            Some("hold-forged-origin"),
            Some("hold-forged-origin:authorize"),
            Some(&authority),
        )
        .test_unwrap());
    let mut snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
    snapshot.budget_origin_ack_heads[0].event_seq = 2;

    let error = apply_cluster_snapshot(&target_state, "http://node-a", snapshot).test_unwrap_err();
    assert!(error
        .to_string()
        .contains("origin acknowledgement heads are not proved"));
    let target_store = SqliteBudgetStore::open(&target_budget_db).test_unwrap();
    assert!(target_store
        .list_mutation_events_after_seq(10, 0)
        .test_unwrap()
        .is_empty());
    assert!(target_store.list_all_usages().test_unwrap().is_empty());

    drop(source_store);
    drop(target_store);
    drop(source_state);
    drop(target_state);
    let _ = std::fs::remove_file(source_budget_db);
    let _ = std::fs::remove_file(target_budget_db);
}

#[test]
fn snapshot_rejects_local_only_history_without_promoting_peer_state() {
    let source_budget_db = unique_temp_path("cluster-source-local-history", "sqlite3");
    let target_budget_db = unique_temp_path("cluster-target-local-history", "sqlite3");
    let source_state = state_with_cluster(
        "http://node-a",
        &["http://node-b"],
        None,
        None,
        Some(source_budget_db.clone()),
    );
    let target_state = state_with_cluster(
        "http://node-b",
        &["http://node-a"],
        None,
        None,
        Some(target_budget_db.clone()),
    );
    let authority = BudgetEventAuthority {
        authority_id: "http://node-a".to_string(),
        lease_id: "http://node-a#term-1".to_string(),
        lease_epoch: 1,
    };
    let source_store = SqliteBudgetStore::open(&source_budget_db).test_unwrap();
    assert!(source_store
        .try_charge_cost_with_ids_and_authority(
            "cap-local-history-1",
            0,
            Some(1),
            1,
            Some(1),
            Some(1),
            Some("hold-local-history-1"),
            Some("hold-local-history-1:authorize"),
            Some(&authority),
        )
        .test_unwrap());
    let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();

    let event_1 =
        budget_mutation_record_from_view(&snapshot.budget_mutation_events[0]).test_unwrap();
    let mut local_event_3 = event_1.clone();
    local_event_3.event_id = "hold-local-history-3:authorize".to_string();
    local_event_3.hold_id = Some("hold-local-history-3".to_string());
    local_event_3.capability_id = "cap-local-history-3".to_string();
    local_event_3.recorded_at = 3;
    local_event_3.event_seq = 3;
    local_event_3.usage_seq = Some(3);

    let target_store = SqliteBudgetStore::open(&target_budget_db).test_unwrap();
    target_store
        .import_snapshot_records(&[], &[event_1, local_event_3])
        .test_unwrap();
    let target_before = target_store.export_budget_snapshot().test_unwrap();

    update_peer_reachable(&target_state, "http://node-a");
    update_peer_budget_acks(
        &target_state,
        "http://node-a",
        &[BudgetOriginAck {
            origin_id: "http://node-a".to_string(),
            event_seq: 100,
        }],
    );
    update_peer_state(&target_state, "http://node-a", |peer| {
        peer.force_snapshot = true
    });

    let error = apply_cluster_snapshot(&target_state, "http://node-a", snapshot).test_unwrap_err();
    assert!(error
        .to_string()
        .contains("does not retain identical local event `hold-local-history-3:authorize`"));
    assert_eq!(
        target_store.export_budget_snapshot().test_unwrap(),
        target_before
    );
    assert!(peer_should_force_snapshot(&target_state, "http://node-a"));
    assert_eq!(
        with_peer_state(&target_state, "http://node-a", |peer| peer
            .budget_import_acks
            .get("http://node-a")
            .copied()),
        Some(Some(100))
    );
    let write = BudgetWriteToken {
        origin_id: "http://node-a".to_string(),
        event_seq: 100,
        budget_term: 1,
    };
    let commit = budget_write_quorum_commit_view(&target_state, &write).test_unwrap();
    assert!(!commit.quorum_committed);
    assert_eq!(commit.committed_nodes, 1);

    drop(source_store);
    drop(target_store);
    drop(source_state);
    drop(target_state);
    let _ = std::fs::remove_file(source_budget_db);
    let _ = std::fs::remove_file(target_budget_db);
}
