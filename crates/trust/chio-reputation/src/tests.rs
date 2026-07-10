#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::capability::scope::Constraint;

    #[test]
    fn reputation_config_default_is_fail_closed_on_empty_trust_set() {
        let config = ReputationConfig::default();
        assert!(
            !config.has_trusted_kernel_keys(),
            "default should expose the misconfigured state via has_trusted_kernel_keys"
        );
        assert!(
            config.trusted_kernel_keys.is_empty(),
            "default config must leave the trust set explicitly empty so callers cannot \
             accidentally rely on an implicit trust anchor"
        );
    }

    #[test]
    fn reputation_config_builder_populates_trusted_keys() {
        let key_a = "ed25519:0000000000000000000000000000000000000000000000000000000000000000";
        let key_b = "ed25519:1111111111111111111111111111111111111111111111111111111111111111";
        let config = ReputationConfig::default()
            .with_trusted_kernel_keys([key_a.to_string(), key_b.to_string()]);
        assert!(config.has_trusted_kernel_keys());
        assert_eq!(config.trusted_kernel_keys.len(), 2);
        assert!(config.trusted_kernel_keys.contains(key_a));
        assert!(config.trusted_kernel_keys.contains(key_b));
    }

    #[test]
    fn reputation_config_builder_accepts_str_and_string() {
        // Both String and &str must work via Into<String>.
        let static_key = "ed25519:2222222222222222222222222222222222222222222222222222222222222222";
        let owned_key =
            String::from("ed25519:3333333333333333333333333333333333333333333333333333333333333333");
        let config = ReputationConfig::default()
            .with_trusted_kernel_keys(vec![static_key, owned_key.as_str()]);
        assert_eq!(config.trusted_kernel_keys.len(), 2);
    }

    #[test]
    fn reputation_config_builder_with_empty_iter_remains_fail_closed() {
        let config = ReputationConfig::default().with_trusted_kernel_keys::<_, String>(Vec::new());
        assert!(!config.has_trusted_kernel_keys());
    }

    #[test]
    fn reputation_config_builder_drops_blank_or_padded_trusted_keys() {
        let valid_key = "ed25519:4444444444444444444444444444444444444444444444444444444444444444";
        let config = ReputationConfig::default().with_trusted_kernel_keys([
            " ".to_string(),
            format!(" {valid_key}"),
            valid_key.to_string(),
            format!("{valid_key} "),
        ]);

        assert_eq!(config.trusted_kernel_keys.len(), 1);
        assert!(config.trusted_kernel_keys.contains(valid_key));

        let malformed_only = ReputationConfig::default().with_trusted_kernel_keys([
            String::new(),
            " ".to_string(),
            format!("{valid_key} "),
        ]);
        assert!(!malformed_only.has_trusted_kernel_keys());
    }

    #[test]
    fn empty_trusted_keys_emits_warning_once_on_integrity_check() {
        use chio_core::crypto::Keypair;
        use chio_core::receipt::{body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction};

        // Ensure a clean slate so this test does not depend on global ordering.
        reset_empty_trusted_keys_warning_for_tests();
        assert!(!EMPTY_TRUSTED_KEYS_WARNED.load(Ordering::Acquire));

        let kernel = Keypair::generate();
        let body = ChioReceiptBody {
            id: "id".to_string(),
            timestamp: 0,
            capability_id: "cap".to_string(),
            tool_server: "srv".to_string(),
            tool_name: "noop".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({}))
                .unwrap_or_else(|error| panic!("hash receipt parameters: {error}")),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            decision: Some(Decision::Allow),
            content_hash: "hash".to_string(),
            policy_hash: "policy".to_string(),
            evidence: vec![],
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kernel.public_key(),
            bbs_projection_version: None,
        };
        let receipt = ChioReceipt::sign(body, &kernel)
            .unwrap_or_else(|error| panic!("sign test receipt: {error}"));

        let config = ReputationConfig::default();
        assert!(
            !receipt_integrity_valid(&receipt, &config),
            "empty trusted-kernel-keys must fail integrity check"
        );
        assert!(
            EMPTY_TRUSTED_KEYS_WARNED.load(Ordering::Acquire),
            "first call with empty trust set must flip the warn-once flag"
        );
        // Subsequent calls remain fail-closed but the flag stays set so we
        // do not flood the log.
        assert!(!receipt_integrity_valid(&receipt, &config));
    }

    #[test]
    fn populated_trusted_keys_validate_signed_receipt() {
        use chio_core::crypto::Keypair;
        use chio_core::receipt::{body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction};

        let kernel = Keypair::generate();
        let body = ChioReceiptBody {
            id: "id-populated".to_string(),
            timestamp: 1_700_000_000,
            capability_id: "cap-1".to_string(),
            tool_server: "srv".to_string(),
            tool_name: "echo".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"k": "v"}))
                .unwrap_or_else(|error| panic!("hash receipt parameters: {error}")),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            decision: Some(Decision::Allow),
            content_hash: "hash".to_string(),
            policy_hash: "policy".to_string(),
            evidence: vec![],
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kernel.public_key(),
            bbs_projection_version: None,
        };
        let receipt = ChioReceipt::sign(body, &kernel)
            .unwrap_or_else(|error| panic!("sign test receipt: {error}"));

        let config = ReputationConfig::default()
            .with_trusted_kernel_keys([kernel.public_key().to_hex()]);
        assert!(config.has_trusted_kernel_keys());
        assert!(
            receipt_integrity_valid(&receipt, &config),
            "trusted-and-signed receipt must pass integrity check"
        );

        // Receipt signed by a different kernel should still fail even when the
        // trust set is populated, demonstrating the trust set is enforced (not
        // bypassed) once non-empty.
        let other_kernel = Keypair::generate();
        let other_config = ReputationConfig::default()
            .with_trusted_kernel_keys([other_kernel.public_key().to_hex()]);
        assert!(!receipt_integrity_valid(&receipt, &other_config));
    }

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

    #[test]
    fn orphan_child_grant_is_not_counted_as_reduced() {
        let parent = ChioScope {
            grants: vec![
                ToolGrant {
                    server_id: "srv".to_string(),
                    tool_name: "read".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: Some(10),
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                },
                ToolGrant {
                    server_id: "srv".to_string(),
                    tool_name: "write".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: Some(10),
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                },
            ],
            resource_grants: vec![],
            prompt_grants: vec![],
        };
        let child = ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "delete".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![Constraint::PathPrefix("/safe".to_string())],
                max_invocations: Some(1),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: vec![],
            prompt_grants: vec![],
        };

        assert!(!scope_reduced(&parent, &child));
        assert!(!budget_reduced(&parent, &child));
    }

    #[test]
    fn expanded_child_operations_are_not_counted_as_reduced() {
        let parent_grant = ToolGrant {
            server_id: "srv".to_string(),
            tool_name: "write".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: Some(10),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };
        let child_grant = ToolGrant {
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: vec![Constraint::PathPrefix("/safe".to_string())],
            max_invocations: Some(1),
            ..parent_grant.clone()
        };

        assert!(!grant_scope_reduced(&parent_grant, &child_grant));
    }
}
