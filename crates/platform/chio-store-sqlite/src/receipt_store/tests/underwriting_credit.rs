use super::super::*;
use super::support::*;

#[test]
fn underwriting_decision_report_tracks_supersession_and_appeal_filters() {
    let path = unique_db_path("chio-underwriting-decision-report");
    let mut store = SqliteReceiptStore::open(&path).test_unwrap();
    let subject_key = "subject-underwriting";

    let initial = signed_underwriting_decision_fixture(
        subject_key,
        "uwd-report-1",
        1_700_000_100,
        chio_kernel::UnderwritingDecisionOutcome::Approve,
        chio_kernel::UnderwritingReviewState::Approved,
        chio_kernel::UnderwritingDecisionLifecycleState::Active,
        None,
        Some(usd(500)),
    );
    let replacement = signed_underwriting_decision_fixture(
        subject_key,
        "uwd-report-2",
        1_700_000_200,
        chio_kernel::UnderwritingDecisionOutcome::ReduceCeiling,
        chio_kernel::UnderwritingReviewState::Approved,
        chio_kernel::UnderwritingDecisionLifecycleState::Active,
        Some("uwd-report-1"),
        Some(usd(300)),
    );
    let denied = signed_underwriting_decision_fixture(
        subject_key,
        "uwd-report-3",
        1_700_000_150,
        chio_kernel::UnderwritingDecisionOutcome::Deny,
        chio_kernel::UnderwritingReviewState::Denied,
        chio_kernel::UnderwritingDecisionLifecycleState::Active,
        None,
        None,
    );

    store.record_underwriting_decision(&initial).test_unwrap();
    store
        .record_underwriting_decision(&replacement)
        .test_unwrap();
    store.record_underwriting_decision(&denied).test_unwrap();

    let accepted_appeal = store
        .create_underwriting_appeal(&chio_kernel::UnderwritingAppealCreateRequest {
            decision_id: "uwd-report-1".to_string(),
            requested_by: "analyst@example.com".to_string(),
            reason: "updated evidence package".to_string(),
            note: Some("replacement requested".to_string()),
        })
        .test_unwrap();
    store
        .resolve_underwriting_appeal(&chio_kernel::UnderwritingAppealResolveRequest {
            appeal_id: accepted_appeal.appeal_id.clone(),
            resolution: chio_kernel::UnderwritingAppealResolution::Accepted,
            resolved_by: "uw-lead@example.com".to_string(),
            note: Some("replacement decision issued".to_string()),
            replacement_decision_id: Some("uwd-report-2".to_string()),
        })
        .test_unwrap();

    let open_appeal = store
        .create_underwriting_appeal(&chio_kernel::UnderwritingAppealCreateRequest {
            decision_id: "uwd-report-2".to_string(),
            requested_by: "subject@example.com".to_string(),
            reason: "requesting improved terms".to_string(),
            note: None,
        })
        .test_unwrap();
    let rejected_appeal = store
        .create_underwriting_appeal(&chio_kernel::UnderwritingAppealCreateRequest {
            decision_id: "uwd-report-3".to_string(),
            requested_by: "subject@example.com".to_string(),
            reason: "seeking reconsideration".to_string(),
            note: Some("no new evidence".to_string()),
        })
        .test_unwrap();
    store
        .resolve_underwriting_appeal(&chio_kernel::UnderwritingAppealResolveRequest {
            appeal_id: rejected_appeal.appeal_id.clone(),
            resolution: chio_kernel::UnderwritingAppealResolution::Rejected,
            resolved_by: "uw-lead@example.com".to_string(),
            note: Some("original denial stands".to_string()),
            replacement_decision_id: None,
        })
        .test_unwrap();

    let report = store
        .query_underwriting_decisions(&chio_kernel::UnderwritingDecisionQuery {
            agent_subject: Some(subject_key.to_string()),
            limit: Some(10),
            ..chio_kernel::UnderwritingDecisionQuery::default()
        })
        .test_unwrap();

    assert_eq!(report.summary.matching_decisions, 3);
    assert_eq!(report.summary.returned_decisions, 3);
    assert_eq!(report.summary.active_decisions, 2);
    assert_eq!(report.summary.superseded_decisions, 1);
    assert_eq!(report.summary.open_appeals, 1);
    assert_eq!(report.summary.accepted_appeals, 1);
    assert_eq!(report.summary.rejected_appeals, 1);
    assert_eq!(report.summary.total_quoted_premium_units, 800);
    assert_eq!(
        report.summary.total_quoted_premium_currency.as_deref(),
        Some("USD")
    );
    assert_eq!(
        report
            .summary
            .quoted_premium_totals_by_currency
            .get("USD")
            .copied(),
        Some(800)
    );

    let initial_row = report
        .decisions
        .iter()
        .find(|row| row.decision.body.decision_id == "uwd-report-1")
        .test_unwrap();
    assert_eq!(
        initial_row.lifecycle_state,
        chio_kernel::UnderwritingDecisionLifecycleState::Superseded
    );
    assert_eq!(initial_row.open_appeal_count, 0);
    assert_eq!(
        initial_row.latest_appeal_status,
        Some(chio_kernel::UnderwritingAppealStatus::Accepted)
    );

    let replacement_row = report
        .decisions
        .iter()
        .find(|row| row.decision.body.decision_id == "uwd-report-2")
        .test_unwrap();
    assert_eq!(
        replacement_row.lifecycle_state,
        chio_kernel::UnderwritingDecisionLifecycleState::Active
    );
    assert_eq!(replacement_row.open_appeal_count, 1);
    assert_eq!(
        replacement_row.latest_appeal_id.as_deref(),
        Some(open_appeal.appeal_id.as_str())
    );
    assert_eq!(
        replacement_row.latest_appeal_status,
        Some(chio_kernel::UnderwritingAppealStatus::Open)
    );

    let denied_row = report
        .decisions
        .iter()
        .find(|row| row.decision.body.decision_id == "uwd-report-3")
        .test_unwrap();
    assert_eq!(
        denied_row.latest_appeal_status,
        Some(chio_kernel::UnderwritingAppealStatus::Rejected)
    );

    let open_report = store
        .query_underwriting_decisions(&chio_kernel::UnderwritingDecisionQuery {
            agent_subject: Some(subject_key.to_string()),
            appeal_status: Some(chio_kernel::UnderwritingAppealStatus::Open),
            limit: Some(10),
            ..chio_kernel::UnderwritingDecisionQuery::default()
        })
        .test_unwrap();
    assert_eq!(open_report.summary.matching_decisions, 1);
    assert_eq!(open_report.summary.open_appeals, 1);
    assert_eq!(open_report.decisions.len(), 1);
    assert_eq!(
        open_report.decisions[0].decision.body.decision_id,
        "uwd-report-2"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn credit_facility_report_tracks_effective_lifecycle_states() {
    let path = unique_db_path("chio-credit-facility-report");
    let mut store = SqliteReceiptStore::open(&path).test_unwrap();
    let subject_key = "subject-credit";
    let far_future = 4_102_444_800;

    let original = signed_credit_facility_fixture(
        subject_key,
        "cfd-report-1",
        1_700_000_100,
        far_future,
        chio_kernel::CreditFacilityDisposition::Grant,
        chio_kernel::CreditFacilityLifecycleState::Active,
        None,
    );
    let replacement = signed_credit_facility_fixture(
        subject_key,
        "cfd-report-2",
        1_700_000_200,
        far_future,
        chio_kernel::CreditFacilityDisposition::Grant,
        chio_kernel::CreditFacilityLifecycleState::Active,
        Some("cfd-report-1"),
    );
    let denied = signed_credit_facility_fixture(
        subject_key,
        "cfd-report-3",
        1_700_000_300,
        far_future,
        chio_kernel::CreditFacilityDisposition::Deny,
        chio_kernel::CreditFacilityLifecycleState::Denied,
        None,
    );
    let expired = signed_credit_facility_fixture(
        subject_key,
        "cfd-report-4",
        1_700_000_400,
        1,
        chio_kernel::CreditFacilityDisposition::Grant,
        chio_kernel::CreditFacilityLifecycleState::Active,
        None,
    );
    let manual_review = signed_credit_facility_fixture(
        subject_key,
        "cfd-report-5",
        1_700_000_500,
        far_future,
        chio_kernel::CreditFacilityDisposition::ManualReview,
        chio_kernel::CreditFacilityLifecycleState::Active,
        None,
    );

    store.record_credit_facility(&original).test_unwrap();
    store.record_credit_facility(&replacement).test_unwrap();
    store.record_credit_facility(&denied).test_unwrap();
    store.record_credit_facility(&expired).test_unwrap();
    store.record_credit_facility(&manual_review).test_unwrap();

    let report = store
        .query_credit_facilities(&chio_kernel::CreditFacilityListQuery {
            agent_subject: Some(subject_key.to_string()),
            limit: Some(10),
            ..chio_kernel::CreditFacilityListQuery::default()
        })
        .test_unwrap();

    assert_eq!(report.summary.matching_facilities, 5);
    assert_eq!(report.summary.returned_facilities, 5);
    assert_eq!(report.summary.active_facilities, 2);
    assert_eq!(report.summary.superseded_facilities, 1);
    assert_eq!(report.summary.denied_facilities, 1);
    assert_eq!(report.summary.expired_facilities, 1);
    assert_eq!(report.summary.granted_facilities, 3);
    assert_eq!(report.summary.manual_review_facilities, 1);
    assert_eq!(
        report.facilities[0].facility.body.facility_id,
        "cfd-report-5"
    );

    let original_row = report
        .facilities
        .iter()
        .find(|row| row.facility.body.facility_id == "cfd-report-1")
        .test_unwrap();
    assert_eq!(
        original_row.lifecycle_state,
        chio_kernel::CreditFacilityLifecycleState::Superseded
    );
    assert_eq!(
        original_row.superseded_by_facility_id.as_deref(),
        Some("cfd-report-2")
    );

    let expired_only = store
        .query_credit_facilities(&chio_kernel::CreditFacilityListQuery {
            agent_subject: Some(subject_key.to_string()),
            lifecycle_state: Some(chio_kernel::CreditFacilityLifecycleState::Expired),
            limit: Some(10),
            ..chio_kernel::CreditFacilityListQuery::default()
        })
        .test_unwrap();
    assert_eq!(expired_only.summary.matching_facilities, 1);
    assert_eq!(expired_only.summary.expired_facilities, 1);
    assert_eq!(
        expired_only.facilities[0].facility.body.facility_id,
        "cfd-report-4"
    );

    let _ = fs::remove_file(path);
}
