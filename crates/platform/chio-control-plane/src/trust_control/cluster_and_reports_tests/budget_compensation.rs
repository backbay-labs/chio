use super::*;

#[test]
fn budget_authorize_compensation_tracks_the_authorize_generation(
) -> Result<(), Box<dyn std::error::Error>> {
    let budget_db = unique_temp_path("budget-authorize-compensation-generation", "sqlite3");
    let state = state_with_cluster(
        "http://node-a",
        &["http://node-b"],
        None,
        None,
        Some(budget_db.clone()),
    );
    let store = SqliteBudgetStore::open(&budget_db)?;
    let payload = TryChargeCostRequest {
        capability_id: "cap-compensation".to_string(),
        grant_index: 0,
        max_invocations: Some(10),
        cost_units: 60,
        max_cost_per_invocation: Some(100),
        max_total_cost_units: Some(500),
        hold_id: Some("hold-compensation".to_string()),
        event_id: Some("hold-compensation:authorize".to_string()),
    };
    let authorize_request = |request: &TryChargeCostRequest| BudgetAuthorizeHoldRequest {
        capability_id: request.capability_id.clone(),
        grant_index: request.grant_index,
        max_invocations: request.max_invocations,
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: None,
        requested_exposure_units: request.cost_units,
        max_cost_per_invocation: request.max_cost_per_invocation,
        max_total_cost_units: request.max_total_cost_units,
        hold_id: request.hold_id.clone(),
        event_id: request.event_id.clone(),
        authority: None,
    };
    let authorized = match store.authorize_budget_hold(authorize_request(&payload))? {
        BudgetAuthorizeHoldDecision::Authorized(authorized) => authorized,
        decision => {
            return Err(std::io::Error::other(format!(
                "initial authorization returned {decision:?}"
            ))
            .into());
        }
    };
    let authorize_event_seq = authorized
        .metadata
        .budget_commit_index
        .ok_or_else(|| std::io::Error::other("authorization event sequence missing"))?;

    let intervening = store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
        capability_id: payload.capability_id.clone(),
        grant_index: payload.grant_index,
        max_invocations: payload.max_invocations,
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: None,
        requested_exposure_units: 40,
        max_cost_per_invocation: payload.max_cost_per_invocation,
        max_total_cost_units: payload.max_total_cost_units,
        hold_id: Some("hold-intervening".to_string()),
        event_id: Some("hold-intervening:authorize".to_string()),
        authority: None,
    })?;
    assert!(matches!(
        intervening,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    let usage_before_rollback = store
        .get_usage(&payload.capability_id, payload.grant_index)?
        .ok_or_else(|| std::io::Error::other("budget usage missing before rollback"))?;
    assert!(usage_before_rollback.seq > authorize_event_seq);

    rollback_budget_authorize_exposure(&state, &payload, None, authorize_event_seq)?;
    let rollback_event_id = format!("hold-compensation:authorize:rollback:{authorize_event_seq}");
    let events = store.list_mutation_events(10, Some(&payload.capability_id), Some(0))?;
    assert!(events
        .iter()
        .any(|event| event.event_id == rollback_event_id));
    let usage_after_rollback = store
        .get_usage(&payload.capability_id, payload.grant_index)?
        .ok_or_else(|| std::io::Error::other("budget usage missing after rollback"))?;
    assert_eq!(usage_after_rollback.invocation_count, 1);
    assert_eq!(usage_after_rollback.total_cost_exposed, 40);

    let replay_error = store
        .authorize_budget_hold(authorize_request(&payload))
        .test_unwrap_err();
    assert!(replay_error.to_string().contains("cannot be reopened"));

    let retry_payload = TryChargeCostRequest {
        capability_id: payload.capability_id.clone(),
        grant_index: payload.grant_index,
        max_invocations: payload.max_invocations,
        cost_units: payload.cost_units,
        max_cost_per_invocation: payload.max_cost_per_invocation,
        max_total_cost_units: payload.max_total_cost_units,
        hold_id: Some("hold-compensation-retry".to_string()),
        event_id: Some("hold-compensation-retry:authorize".to_string()),
    };
    let retried = match store.authorize_budget_hold(authorize_request(&retry_payload))? {
        BudgetAuthorizeHoldDecision::Authorized(authorized) => authorized,
        decision => {
            return Err(std::io::Error::other(format!(
                "authorization retry returned {decision:?}"
            ))
            .into());
        }
    };
    assert!(retried
        .metadata
        .budget_commit_index
        .is_some_and(|event_seq| event_seq > authorize_event_seq));

    rollback_budget_authorize_exposure(&state, &payload, None, authorize_event_seq)?;
    let usage_after_compensation_retry = store
        .get_usage(&payload.capability_id, payload.grant_index)?
        .ok_or_else(|| std::io::Error::other("budget usage missing after compensation retry"))?;
    assert_eq!(usage_after_compensation_retry.invocation_count, 2);
    assert_eq!(usage_after_compensation_retry.total_cost_exposed, 100);

    let _ = std::fs::remove_file(budget_db);
    Ok(())
}

#[test]
fn apply_cluster_snapshot_fails_when_authority_fence_persistence_fails() {
    let authority_db_path = unique_temp_path("cluster-authority-fence-dir", "d");
    std::fs::create_dir_all(&authority_db_path).test_unwrap();

    let source_state = state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
    let target_state = state_with_cluster(
        "http://node-b",
        &["http://node-a"],
        Some(authority_db_path.clone()),
        None,
        None,
    );

    for state in [&source_state, &target_state] {
        let cluster = state.cluster.as_ref().test_unwrap();
        let mut guard = cluster.lock().test_unwrap();
        for peer in guard.peers.values_mut() {
            peer.health = PeerHealth::Healthy;
            peer.last_contact_at = Some(unix_timestamp_now());
        }
    }

    let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
    let error = apply_cluster_snapshot(&target_state, "http://node-a", snapshot).test_unwrap_err();
    let error_text = error.to_string();
    assert!(
        error_text.contains("directory") || error_text.contains("open database file"),
        "unexpected error: {error_text}"
    );

    let _ = std::fs::remove_dir_all(authority_db_path);
}
