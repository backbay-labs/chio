use chio_underwriting::{UnderwritingDecisionPolicy, UnderwritingPolicyInputQuery};

#[test]
fn underwriting_public_defaults_validate() {
    assert!(UnderwritingDecisionPolicy::default().validate().is_ok());

    let query = UnderwritingPolicyInputQuery {
        tool_server: Some("tool-server".to_string()),
        ..UnderwritingPolicyInputQuery::default()
    };
    assert!(query.validate().is_ok());
}
