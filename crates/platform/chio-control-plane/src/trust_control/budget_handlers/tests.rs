use super::{budget_internal_error, generated_budget_event_id, validate_budget_request_identity};
use axum::body::to_bytes;
use axum::http::StatusCode;
use chio_kernel::budget_store::BudgetStoreError;
use chio_test_support::prelude::*;
use std::collections::HashSet;

#[test]
fn generated_budget_event_id_is_unique_per_call() {
    // Each omitted-eventId write must get a distinct id so the mutation event
    // is stored under a known, unique key and the witness can look up THIS
    // write's exact event_seq.
    let first = generated_budget_event_id();
    let second = generated_budget_event_id();
    assert_ne!(first, second, "consecutive ids must differ");
    assert!(first.starts_with("cluster-budget-write-"));
    // A tight burst (same wall-clock nanos possible) is still all-distinct via
    // the monotonic counter.
    let ids: HashSet<String> = (0..10_000).map(|_| generated_budget_event_id()).collect();
    assert_eq!(ids.len(), 10_000, "all minted ids must be unique");
}

#[test]
fn optional_budget_identity_rejects_partial_or_empty_values() {
    for (hold_id, event_id) in [
        (None, None),
        (None, Some("event-only")),
        (Some("hold"), Some("hold:event")),
    ] {
        assert!(validate_budget_request_identity(hold_id, event_id).is_ok());
    }
    for (hold_id, event_id) in [
        (Some("hold"), None),
        (Some(""), Some("event")),
        (Some("hold"), Some("")),
        (None, Some("")),
    ] {
        let response = match validate_budget_request_identity(hold_id, event_id) {
            Ok(()) => panic!("invalid budget identity was accepted"),
            Err(response) => response,
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn fenced_budget_error_is_service_unavailable_without_internal_details() {
    let response = budget_internal_error(
        &BudgetStoreError::Fenced {
            expected_epoch: 41,
            actual_epoch: Some(42),
        },
        "budget serving owner changed",
    );
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .test_expect("read public fenced response");
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("budget serving owner changed"));
    assert!(!body.contains("41"));
    assert!(!body.contains("42"));
}
