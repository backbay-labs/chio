use chio_market::{LiabilityProviderSupportBoundary, LIABILITY_PROVIDER_ARTIFACT_SCHEMA};

#[test]
fn market_support_boundary_defaults_are_explicit() {
    let boundary = LiabilityProviderSupportBoundary::default();

    assert!(boundary.curated_registry_only);
    assert!(!boundary.automatic_trust_admission);
    assert!(!boundary.permissionless_federation_supported);
    assert!(!boundary.bound_coverage_supported);
    assert_eq!(
        LIABILITY_PROVIDER_ARTIFACT_SCHEMA,
        "chio.market.provider.v1"
    );
}
