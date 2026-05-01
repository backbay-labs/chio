#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::Constraint;

    #[test]
    fn capability_lineage_record_parses_scope_json() {
        let record = CapabilityLineageRecord::from_scope_json(CapabilityLineageScopeJsonInput {
            capability_id: "cap-1".to_string(),
            subject_key: "agent-1".to_string(),
            issuer_key: "issuer-1".to_string(),
            issued_at: 10,
            expires_at: 20,
            scope_json: r#"{"grants":[{"server_id":"srv","tool_name":"read","operations":["invoke"],"constraints":[],"max_invocations":10}],"resource_grants":[],"prompt_grants":[]}"#,
            delegation_depth: 0,
            parent_capability_id: None,
        })
        .unwrap_or_else(|error| panic!("parse capability lineage scope json: {error}"));

        assert_eq!(record.scope.grants.len(), 1);
        assert_eq!(record.scope.grants[0].tool_name, "read");
    }

    #[test]
    fn metric_value_clamps_inputs() {
        assert_eq!(MetricValue::known(-1.0), MetricValue::Known(0.0));
        assert_eq!(MetricValue::known(2.0), MetricValue::Known(1.0));
    }

    #[test]
    fn scope_reduction_detects_narrower_constraints() {
        let parent = ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "write".to_string(),
                operations: vec![Operation::Invoke, Operation::Delegate],
                constraints: vec![],
                max_invocations: Some(100),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: vec![],
            prompt_grants: vec![],
        };
        let child = ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "write".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![Constraint::PathPrefix("/safe".to_string())],
                max_invocations: Some(10),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: vec![],
            prompt_grants: vec![],
        };

        assert!(scope_reduced(&parent, &child));
        assert!(budget_reduced(&parent, &child));
    }
}
