use chio_federation::{
    quorum::FederationAntiEclipsePolicy, quorum::CHIO_FEDERATION_QUORUM_REPORT_SCHEMA,
};

#[test]
fn federation_defaults_require_multi_party_visibility() {
    let policy = FederationAntiEclipsePolicy::default();

    assert_eq!(policy.minimum_distinct_operators, 2);
    assert!(policy.require_origin_publisher);
    assert!(policy.require_indexer_observation);
    assert_eq!(policy.max_upstream_hops, 1);
    assert_eq!(
        CHIO_FEDERATION_QUORUM_REPORT_SCHEMA,
        "chio.federation-quorum-report.v1"
    );
}
