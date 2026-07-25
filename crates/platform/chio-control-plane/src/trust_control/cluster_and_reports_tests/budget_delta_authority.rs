use super::*;

fn mutation_event(seq: u64) -> BudgetMutationEventView {
    BudgetMutationEventView {
        event_id: format!("event-{seq}"),
        hold_id: Some("hold-1".to_string()),
        capability_id: "cap-1".to_string(),
        grant_index: 0,
        kind: "authorize_exposure".to_string(),
        allowed: Some(true),
        lifecycle: BudgetMutationLifecycleView::default(),
        recorded_at: 1,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: Some(1),
        max_total_cost_units: Some(1),
        invocation_count_after: 1,
        total_cost_exposed_after: 1,
        total_cost_realized_spend_after: 0,
        authority: None,
    }
}

#[test]
fn budget_delta_rejects_noncanonical_tombstones_without_installing_them() {
    let cursor = |seq| BudgetCursor {
        seq,
        updated_at: 1,
        capability_id: "cap-1".to_string(),
        grant_index: 0,
    };
    let cases = [
        (vec![mutation_event(1)], vec![1], None),
        (vec![mutation_event(1)], vec![2], None),
        (Vec::new(), vec![1], None),
        (vec![mutation_event(1)], vec![0], None),
        (vec![mutation_event(3)], vec![1, 1], None),
        (vec![mutation_event(2)], vec![1], Some(cursor(1))),
    ];
    for (index, (mutation_events, abandoned_seqs, current_cursor)) in cases.into_iter().enumerate()
    {
        let budget_db = unique_temp_path(&format!("invalid-budget-tombstone-{index}"), "sqlite3");
        let store = SqliteBudgetStore::open(&budget_db).test_unwrap();
        let response = BudgetDeltaResponse {
            records: Vec::new(),
            mutation_events,
            abandoned_seqs,
        };

        let result = import_budget_delta_response(
            &store,
            &response,
            current_cursor,
            &mut PullRoundBudget::new(),
        );
        assert!(
            matches!(result, Err(PullError::Protocol(_))),
            "invalid tombstone case {index} must be a protocol error, got {result:?}"
        );
        assert!(store
            .list_mutation_events_after_seq(10, 0)
            .test_unwrap()
            .is_empty());
        assert!(store
            .list_abandoned_event_seqs_after(0)
            .test_unwrap()
            .is_empty());
        drop(store);
        let _ = std::fs::remove_file(budget_db);
    }
}
