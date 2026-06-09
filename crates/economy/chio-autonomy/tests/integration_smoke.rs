use chio_autonomy::{
    AutonomousEvidenceKind, AutonomousEvidenceReference, AutonomousPricingSupportBoundary,
};

#[test]
fn autonomy_support_boundary_defaults_fail_closed() {
    let boundary = AutonomousPricingSupportBoundary::default();

    assert!(boundary.delegated_authority_required);
    assert!(boundary.live_bind_supported);
    assert!(boundary.reserve_optimization_required);
    assert!(boundary.operator_override_supported);
}

#[test]
fn autonomy_public_evidence_reference_is_constructible() {
    let reference = AutonomousEvidenceReference {
        kind: AutonomousEvidenceKind::UnderwritingDecision,
        reference_id: "uw-1".to_string(),
        observed_at: Some(1),
        locator: Some("receipt://uw-1".to_string()),
    };

    assert_eq!(reference.reference_id, "uw-1");
    assert_eq!(reference.observed_at, Some(1));
}
