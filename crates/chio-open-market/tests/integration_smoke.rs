use chio_open_market::fee_schedule::OpenMarketEconomicsScope;

#[test]
fn open_market_scope_requires_non_empty_namespace() {
    let valid = OpenMarketEconomicsScope {
        namespace: "registry/health".to_string(),
        allowed_listing_operator_ids: vec!["operator-1".to_string()],
        allowed_actor_kinds: Vec::new(),
        allowed_admission_classes: Vec::new(),
        policy_reference: None,
    };
    assert!(valid.validate().is_ok());

    let invalid = OpenMarketEconomicsScope {
        namespace: String::new(),
        ..valid
    };
    assert!(invalid.validate().is_err());
}
