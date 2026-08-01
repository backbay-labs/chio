use super::*;

#[test]
fn clustered_structured_budget_authority_is_disabled_without_consensus_log() {
    let state = state_with_cluster(
        "http://127.0.0.1:4100",
        &["http://127.0.0.1:4101"],
        None,
        None,
        None,
    );
    let response = match super::super::super::budget_handlers::structured_budget_store(&state) {
        Ok(_) => panic!("clustered structured budget authority was enabled"),
        Err(response) => response,
    };
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn configured_budget_path_does_not_activate_structured_authority() {
    let budget_db = unique_temp_path("chio-structured-budget-disabled", "sqlite3");
    let state = state_with_cluster(
        "http://127.0.0.1:4100",
        &[],
        None,
        None,
        Some(budget_db.clone()),
    );
    assert!(state.budget_store.is_some());
    assert!(state.joint_authority_store.is_none());
    let response = match super::super::super::budget_handlers::structured_budget_store(&state) {
        Ok(_) => panic!("configured path activated structured budget authority"),
        Err(response) => response,
    };
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    drop(state);
    let _ = std::fs::remove_file(budget_db);
}
