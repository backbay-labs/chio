use chio_governance::generic::GenericGovernanceAuthorityScope;

#[test]
fn governance_authority_scope_validates_non_empty_namespace() {
    let valid = GenericGovernanceAuthorityScope {
        namespace: "registry/health".to_string(),
        allowed_listing_operator_ids: vec!["operator-1".to_string()],
        allowed_actor_kinds: Vec::new(),
        policy_reference: None,
    };
    assert!(valid.validate().is_ok());

    let invalid = GenericGovernanceAuthorityScope {
        namespace: String::new(),
        ..valid
    };
    assert!(invalid.validate().is_err());
}
