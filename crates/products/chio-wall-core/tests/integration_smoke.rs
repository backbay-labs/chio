use chio_wall_core::{
    ChioWallBuyerMotion, ChioWallControlProfile, ChioWallControlSurface, ChioWallInformationDomain,
    CHIO_WALL_CONTROL_PROFILE_SCHEMA,
};

#[test]
fn wall_control_profile_validates_fail_closed_boundary() {
    let profile = ChioWallControlProfile {
        schema: CHIO_WALL_CONTROL_PROFILE_SCHEMA.to_string(),
        profile_id: "wall-profile".to_string(),
        workflow_id: "wf-1".to_string(),
        buyer_motion: ChioWallBuyerMotion::ControlRoomBarrierReview,
        control_surface: ChioWallControlSurface::ToolAccessDomainBoundary,
        source_domain: ChioWallInformationDomain::Research,
        protected_domain: ChioWallInformationDomain::Execution,
        retained_artifact_policy: "retain-minimum".to_string(),
        intended_use: "boundary review".to_string(),
        fail_closed: true,
    };
    assert!(profile.validate().is_ok());

    let invalid = ChioWallControlProfile {
        protected_domain: ChioWallInformationDomain::Research,
        ..profile
    };
    assert!(invalid.validate().is_err());
}
