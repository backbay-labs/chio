#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use chio_core::capability::{
        RuntimeAssuranceTier, WorkloadCredentialKind, WorkloadIdentity, WorkloadIdentityScheme,
    };

    use crate::models::{
        ComputerUseMode, ComputerUseRule, DefaultAction, EgressRule, Extensions,
        ForbiddenPathsRule, HushSpec, InputInjectionRule, OriginMatch, OriginProfile,
        OriginDefaultBehavior, OriginsExtension, PatchIntegrityRule, PostureExtension,
        PostureState, PostureTransition, RemoteDesktopChannelsRule, Rules, SecretPattern,
        SecretPatternsRule, Severity, ShellCommandsRule, ToolAccessRule, WorkloadIdentityMatch,
    };

    use super::{
        evaluate, evaluate_with_context, selected_origin_profile_id, Condition, Decision,
        EvaluationAction, OriginContext, PostureContext, RuntimeAttestationContext, RuntimeContext,
    };

    fn origin_profile(id: &str, match_rules: OriginMatch) -> OriginProfile {
        OriginProfile {
            id: id.to_string(),
            match_rules: Some(match_rules),
            posture: None,
            tool_access: None,
            egress: None,
            data: None,
            budgets: None,
            bridge: None,
            explanation: None,
        }
    }

    fn enterprise_origin_spec(profiles: Vec<OriginProfile>) -> HushSpec {
        HushSpec {
            hushspec: "1.0".to_string(),
            name: Some("enterprise-origin-tests".to_string()),
            description: None,
            extends: None,
            merge_strategy: None,
            rules: Some(Rules::default()),
            extensions: Some(Extensions {
                posture: None,
                origins: Some(OriginsExtension {
                    default_behavior: None,
                    profiles,
                }),
                detection: None,
                reputation: None,
                runtime_assurance: None,
                chio: None,
            }),
            metadata: None,
        }
    }

    fn runtime_assurance_spec(
        required: Option<RuntimeAssuranceTier>,
        preferred: Option<RuntimeAssuranceTier>,
    ) -> HushSpec {
        HushSpec {
            hushspec: "1.0".to_string(),
            name: Some("runtime-assurance-tests".to_string()),
            description: None,
            extends: None,
            merge_strategy: None,
            rules: Some(Rules {
                tool_access: Some(ToolAccessRule {
                    enabled: true,
                    allow: vec!["payments.charge".to_string()],
                    block: Vec::new(),
                    require_confirmation: Vec::new(),
                    default: DefaultAction::Allow,
                    max_args_size: None,
                    require_runtime_assurance_tier: required,
                    prefer_runtime_assurance_tier: preferred,
                    require_workload_identity: None,
                    prefer_workload_identity: None,
                }),
                ..Rules::default()
            }),
            extensions: Some(Extensions {
                posture: None,
                origins: None,
                detection: None,
                reputation: None,
                runtime_assurance: None,
                chio: None,
            }),
            metadata: None,
        }
    }

    fn spec_with_rules(rules: Rules) -> HushSpec {
        HushSpec {
            hushspec: "1.0".to_string(),
            name: Some("evaluate-branch-tests".to_string()),
            description: None,
            extends: None,
            merge_strategy: None,
            rules: Some(rules),
            extensions: Some(Extensions::default()),
            metadata: None,
        }
    }

    fn action(action_type: &str, target: &str) -> EvaluationAction {
        EvaluationAction {
            action_type: action_type.to_string(),
            target: Some(target.to_string()),
            content: None,
            origin: None,
            posture: None,
            args_size: None,
            runtime_attestation: None,
        }
    }

    fn workload_identity_spec_with_path_prefixes(path_prefixes: Vec<&str>) -> HushSpec {
        spec_with_rules(Rules {
            tool_access: Some(ToolAccessRule {
                enabled: true,
                allow: vec!["payments.charge".to_string()],
                block: Vec::new(),
                require_confirmation: Vec::new(),
                default: DefaultAction::Allow,
                max_args_size: None,
                require_runtime_assurance_tier: None,
                prefer_runtime_assurance_tier: None,
                require_workload_identity: Some(WorkloadIdentityMatch {
                    scheme: Some(WorkloadIdentityScheme::Spiffe),
                    trust_domain: Some("prod.chio".to_string()),
                    path_prefixes: path_prefixes
                        .into_iter()
                        .map(str::to_string)
                        .collect(),
                    credential_kinds: vec![WorkloadCredentialKind::X509Svid],
                }),
                prefer_workload_identity: None,
            }),
            ..Rules::default()
        })
    }

    fn workload_identity_tool_call(path: &str) -> EvaluationAction {
        EvaluationAction {
            action_type: "tool_call".to_string(),
            target: Some("payments.charge".to_string()),
            content: None,
            origin: None,
            posture: None,
            args_size: None,
            runtime_attestation: Some(RuntimeAttestationContext {
                tier: RuntimeAssuranceTier::Verified,
                valid: true,
                verifier: Some("verifier.chio".to_string()),
                workload_identity: Some(WorkloadIdentity {
                    scheme: WorkloadIdentityScheme::Spiffe,
                    credential_kind: WorkloadCredentialKind::X509Svid,
                    uri: format!("spiffe://prod.chio{path}"),
                    trust_domain: "prod.chio".to_string(),
                    path: path.to_string(),
                }),
            }),
        }
    }

    #[test]
    fn enterprise_origin_matches_provider_tenant_and_organization_exactly() {
        let spec = enterprise_origin_spec(vec![origin_profile(
            "enterprise",
            OriginMatch {
                provider: Some("provider-a".to_string()),
                tenant_id: Some("tenant-123".to_string()),
                organization_id: Some("org-456".to_string()),
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: Vec::new(),
                sensitivity: None,
                actor_role: None,
            },
        )]);

        let matched = selected_origin_profile_id(
            &spec,
            &OriginContext {
                provider: Some("provider-a".to_string()),
                tenant_id: Some("tenant-123".to_string()),
                organization_id: Some("org-456".to_string()),
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: Vec::new(),
                sensitivity: None,
                actor_role: None,
            },
        );

        assert_eq!(matched.as_deref(), Some("enterprise"));
    }

    #[test]
    fn enterprise_origin_denies_when_organization_is_missing() {
        let spec = enterprise_origin_spec(vec![origin_profile(
            "enterprise",
            OriginMatch {
                provider: Some("provider-a".to_string()),
                tenant_id: Some("tenant-123".to_string()),
                organization_id: Some("org-456".to_string()),
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: Vec::new(),
                sensitivity: None,
                actor_role: None,
            },
        )]);

        let matched = selected_origin_profile_id(
            &spec,
            &OriginContext {
                provider: Some("provider-a".to_string()),
                tenant_id: Some("tenant-123".to_string()),
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: Vec::new(),
                sensitivity: None,
                actor_role: None,
            },
        );

        assert_eq!(matched, None);
    }

    #[test]
    fn enterprise_origin_matches_required_group_subset() {
        let spec = enterprise_origin_spec(vec![origin_profile(
            "group-match",
            OriginMatch {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: vec!["eng".to_string(), "ops".to_string()],
                roles: Vec::new(),
                sensitivity: None,
                actor_role: None,
            },
        )]);

        let matched = selected_origin_profile_id(
            &spec,
            &OriginContext {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: vec!["ops".to_string(), "eng".to_string(), "finance".to_string()],
                roles: Vec::new(),
                sensitivity: None,
                actor_role: None,
            },
        );

        assert_eq!(matched.as_deref(), Some("group-match"));
    }

    #[test]
    fn enterprise_origin_denies_when_required_group_is_missing() {
        let spec = enterprise_origin_spec(vec![origin_profile(
            "group-match",
            OriginMatch {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: vec!["eng".to_string(), "ops".to_string()],
                roles: Vec::new(),
                sensitivity: None,
                actor_role: None,
            },
        )]);

        let matched = selected_origin_profile_id(
            &spec,
            &OriginContext {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: vec!["eng".to_string()],
                roles: Vec::new(),
                sensitivity: None,
                actor_role: None,
            },
        );

        assert_eq!(matched, None);
    }

    #[test]
    fn enterprise_origin_matches_required_role_subset() {
        let spec = enterprise_origin_spec(vec![origin_profile(
            "role-match",
            OriginMatch {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: vec!["operator".to_string()],
                sensitivity: None,
                actor_role: Some("viewer".to_string()),
            },
        )]);

        let matched = selected_origin_profile_id(
            &spec,
            &OriginContext {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: vec!["operator".to_string(), "admin".to_string()],
                sensitivity: None,
                actor_role: Some("viewer".to_string()),
            },
        );

        assert_eq!(matched.as_deref(), Some("role-match"));
    }

    #[test]
    fn tool_access_runtime_assurance_requirement_denies_lower_tier() {
        let spec = runtime_assurance_spec(Some(RuntimeAssuranceTier::Attested), None);
        let result = evaluate(
            &spec,
            &EvaluationAction {
                action_type: "tool_call".to_string(),
                target: Some("payments.charge".to_string()),
                content: None,
                origin: None,
                posture: None,
                args_size: None,
                runtime_attestation: Some(RuntimeAttestationContext {
                    tier: RuntimeAssuranceTier::Basic,
                    valid: true,
                    verifier: Some("verifier.chio".to_string()),
                    workload_identity: None,
                }),
            },
        );

        assert_eq!(result.decision, Decision::Deny);
        assert!(
            result
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("below required")),
            "expected assurance-tier denial reason"
        );
    }

    #[test]
    fn tool_access_runtime_assurance_preference_warns_when_missing() {
        let spec = runtime_assurance_spec(None, Some(RuntimeAssuranceTier::Attested));
        let result = evaluate(
            &spec,
            &EvaluationAction {
                action_type: "tool_call".to_string(),
                target: Some("payments.charge".to_string()),
                content: None,
                origin: None,
                posture: None,
                args_size: None,
                runtime_attestation: None,
            },
        );

        assert_eq!(result.decision, Decision::Warn);
        assert!(
            result
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("below preferred")),
            "expected assurance-tier warning reason"
        );
    }

    #[test]
    fn tool_access_runtime_assurance_requirement_allows_matching_tier() {
        let spec = runtime_assurance_spec(Some(RuntimeAssuranceTier::Attested), None);
        let result = evaluate(
            &spec,
            &EvaluationAction {
                action_type: "tool_call".to_string(),
                target: Some("payments.charge".to_string()),
                content: None,
                origin: None,
                posture: None,
                args_size: None,
                runtime_attestation: Some(RuntimeAttestationContext {
                    tier: RuntimeAssuranceTier::Verified,
                    valid: true,
                    verifier: Some("verifier.chio".to_string()),
                    workload_identity: None,
                }),
            },
        );

        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn enterprise_origin_denies_when_required_role_is_missing() {
        let spec = enterprise_origin_spec(vec![origin_profile(
            "role-match",
            OriginMatch {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: vec!["operator".to_string()],
                sensitivity: None,
                actor_role: None,
            },
        )]);

        let matched = selected_origin_profile_id(
            &spec,
            &OriginContext {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: vec!["viewer".to_string()],
                sensitivity: None,
                actor_role: Some("operator".to_string()),
            },
        );

        assert_eq!(matched, None);
    }

    #[test]
    fn enterprise_origin_matches_actor_role_when_roles_list_is_empty() {
        let spec = enterprise_origin_spec(vec![origin_profile(
            "legacy-actor-role",
            OriginMatch {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: Vec::new(),
                sensitivity: None,
                actor_role: Some("approver".to_string()),
            },
        )]);

        let matched = selected_origin_profile_id(
            &spec,
            &OriginContext {
                provider: Some("provider-a".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: vec!["operator".to_string()],
                sensitivity: None,
                actor_role: Some("approver".to_string()),
            },
        );

        assert_eq!(matched.as_deref(), Some("legacy-actor-role"));
    }

    #[test]
    fn origin_default_deny_blocks_unmatched_origin_before_base_rules_allow() {
        let mut spec = enterprise_origin_spec(vec![origin_profile(
            "trusted",
            OriginMatch {
                provider: Some("trusted-provider".to_string()),
                tenant_id: Some("tenant-1".to_string()),
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: Vec::new(),
                sensitivity: None,
                actor_role: None,
            },
        )]);
        spec.rules = Some(Rules {
            tool_access: Some(ToolAccessRule {
                enabled: true,
                allow: Vec::new(),
                block: Vec::new(),
                require_confirmation: Vec::new(),
                default: DefaultAction::Allow,
                max_args_size: None,
                require_runtime_assurance_tier: None,
                prefer_runtime_assurance_tier: None,
                require_workload_identity: None,
                prefer_workload_identity: None,
            }),
            ..Rules::default()
        });
        let origins = spec
            .extensions
            .as_mut()
            .and_then(|extensions| extensions.origins.as_mut())
            .expect("test spec should contain origins extension");
        origins.default_behavior = Some(OriginDefaultBehavior::Deny);

        let mut request = action("tool_call", "read_file");
        request.origin = Some(OriginContext {
            provider: Some("untrusted-provider".to_string()),
            tenant_id: Some("tenant-1".to_string()),
            organization_id: None,
            space_id: None,
            space_type: None,
            visibility: None,
            external_participants: None,
            tags: Vec::new(),
            groups: Vec::new(),
            roles: Vec::new(),
            sensitivity: None,
            actor_role: None,
        });

        let result = evaluate(&spec, &request);

        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(
            result.matched_rule.as_deref(),
            Some("extensions.origins.default_behavior")
        );

        let missing_origin_result = evaluate(&spec, &action("tool_call", "read_file"));
        assert_eq!(missing_origin_result.decision, Decision::Deny);
        assert_eq!(
            missing_origin_result.reason.as_deref(),
            Some("origin context is required by origins policy")
        );
    }

    #[test]
    fn origin_minimal_profile_preserves_base_rule_fallback_for_unmatched_origin() {
        let mut spec = enterprise_origin_spec(vec![origin_profile(
            "trusted",
            OriginMatch {
                provider: Some("trusted-provider".to_string()),
                tenant_id: None,
                organization_id: None,
                space_id: None,
                space_type: None,
                visibility: None,
                external_participants: None,
                tags: Vec::new(),
                groups: Vec::new(),
                roles: Vec::new(),
                sensitivity: None,
                actor_role: None,
            },
        )]);
        spec.rules = Some(Rules {
            tool_access: Some(ToolAccessRule {
                enabled: true,
                allow: Vec::new(),
                block: Vec::new(),
                require_confirmation: Vec::new(),
                default: DefaultAction::Allow,
                max_args_size: None,
                require_runtime_assurance_tier: None,
                prefer_runtime_assurance_tier: None,
                require_workload_identity: None,
                prefer_workload_identity: None,
            }),
            ..Rules::default()
        });
        let origins = spec
            .extensions
            .as_mut()
            .and_then(|extensions| extensions.origins.as_mut())
            .expect("test spec should contain origins extension");
        origins.default_behavior = Some(OriginDefaultBehavior::MinimalProfile);

        let mut action = action("tool_call", "read_file");
        action.origin = Some(OriginContext {
            provider: Some("untrusted-provider".to_string()),
            tenant_id: None,
            organization_id: None,
            space_id: None,
            space_type: None,
            visibility: None,
            external_participants: None,
            tags: Vec::new(),
            groups: Vec::new(),
            roles: Vec::new(),
            sensitivity: None,
            actor_role: None,
        });

        let result = evaluate(&spec, &action);

        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(
            result.matched_rule.as_deref(),
            Some("rules.tool_access.default")
        );
    }

    #[test]
    fn tool_access_workload_identity_requirement_denies_mismatched_identity() {
        let spec = HushSpec {
            hushspec: "1.0".to_string(),
            name: Some("workload-identity-tests".to_string()),
            description: None,
            extends: None,
            merge_strategy: None,
            rules: Some(Rules {
                tool_access: Some(ToolAccessRule {
                    enabled: true,
                    allow: vec!["payments.charge".to_string()],
                    block: Vec::new(),
                    require_confirmation: Vec::new(),
                    default: DefaultAction::Allow,
                    max_args_size: None,
                    require_runtime_assurance_tier: None,
                    prefer_runtime_assurance_tier: None,
                    require_workload_identity: Some(WorkloadIdentityMatch {
                        scheme: Some(WorkloadIdentityScheme::Spiffe),
                        trust_domain: Some("prod.chio".to_string()),
                        path_prefixes: vec!["/payments".to_string()],
                        credential_kinds: vec![WorkloadCredentialKind::X509Svid],
                    }),
                    prefer_workload_identity: None,
                }),
                ..Rules::default()
            }),
            extensions: Some(Extensions::default()),
            metadata: None,
        };

        let result = evaluate(
            &spec,
            &EvaluationAction {
                action_type: "tool_call".to_string(),
                target: Some("payments.charge".to_string()),
                content: None,
                origin: None,
                posture: None,
                args_size: None,
                runtime_attestation: Some(RuntimeAttestationContext {
                    tier: RuntimeAssuranceTier::Verified,
                    valid: true,
                    verifier: Some("verifier.chio".to_string()),
                    workload_identity: Some(WorkloadIdentity {
                        scheme: WorkloadIdentityScheme::Spiffe,
                        credential_kind: WorkloadCredentialKind::X509Svid,
                        uri: "spiffe://dev.chio/payments/worker".to_string(),
                        trust_domain: "dev.chio".to_string(),
                        path: "/payments/worker".to_string(),
                    }),
                }),
            },
        );

        assert_eq!(result.decision, Decision::Deny);
        assert!(
            result
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("workload identity")),
            "expected workload-identity denial reason"
        );
    }

    #[test]
    fn tool_access_workload_identity_requirement_allows_exact_and_child_segment_prefixes() {
        let exact_spec = workload_identity_spec_with_path_prefixes(vec!["/payments"]);
        let exact_result = evaluate(&exact_spec, &workload_identity_tool_call("/payments"));
        assert_eq!(exact_result.decision, Decision::Allow);

        let child_spec = workload_identity_spec_with_path_prefixes(vec!["/payments/"]);
        let child_result = evaluate(&child_spec, &workload_identity_tool_call("/payments/worker"));
        assert_eq!(child_result.decision, Decision::Allow);
    }

    #[test]
    fn tool_access_workload_identity_requirement_denies_sibling_prefix_confusion() {
        let spec = workload_identity_spec_with_path_prefixes(vec!["/payments"]);
        let result = evaluate(&spec, &workload_identity_tool_call("/payments-v2/worker"));

        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(
            result.matched_rule.as_deref(),
            Some("rules.tool_access.require_workload_identity")
        );
    }

    #[test]
    fn tool_access_workload_identity_preference_warns_when_missing() {
        let spec = HushSpec {
            hushspec: "1.0".to_string(),
            name: Some("workload-identity-preference".to_string()),
            description: None,
            extends: None,
            merge_strategy: None,
            rules: Some(Rules {
                tool_access: Some(ToolAccessRule {
                    enabled: true,
                    allow: vec!["payments.charge".to_string()],
                    block: Vec::new(),
                    require_confirmation: Vec::new(),
                    default: DefaultAction::Allow,
                    max_args_size: None,
                    require_runtime_assurance_tier: None,
                    prefer_runtime_assurance_tier: None,
                    require_workload_identity: None,
                    prefer_workload_identity: Some(WorkloadIdentityMatch {
                        scheme: Some(WorkloadIdentityScheme::Spiffe),
                        trust_domain: Some("prod.chio".to_string()),
                        path_prefixes: vec!["/payments".to_string()],
                        credential_kinds: Vec::new(),
                    }),
                }),
                ..Rules::default()
            }),
            extensions: Some(Extensions::default()),
            metadata: None,
        };

        let result = evaluate(
            &spec,
            &EvaluationAction {
                action_type: "tool_call".to_string(),
                target: Some("payments.charge".to_string()),
                content: None,
                origin: None,
                posture: None,
                args_size: None,
                runtime_attestation: Some(RuntimeAttestationContext {
                    tier: RuntimeAssuranceTier::Verified,
                    valid: true,
                    verifier: Some("verifier.chio".to_string()),
                    workload_identity: None,
                }),
            },
        );

        assert_eq!(result.decision, Decision::Warn);
        assert!(
            result
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("workload identity")),
            "expected workload-identity warning reason"
        );
    }

    #[test]
    fn evaluate_with_context_disables_rule_blocks_when_condition_is_false() {
        let spec = spec_with_rules(Rules {
            egress: Some(EgressRule {
                enabled: true,
                allow: Vec::new(),
                block: vec!["api.example.com".to_string()],
                default: DefaultAction::Allow,
            }),
            ..Rules::default()
        });
        let conditions = HashMap::from([(
            "egress".to_string(),
            Condition {
                context: Some(HashMap::from([(
                    "environment".to_string(),
                    serde_json::json!("prod"),
                )])),
                ..Condition::default()
            },
        )]);

        let dev_result = evaluate_with_context(
            &spec,
            &action("egress", "api.example.com"),
            &RuntimeContext {
                environment: Some("dev".to_string()),
                ..RuntimeContext::default()
            },
            &conditions,
        );
        assert_eq!(dev_result.decision, Decision::Allow);

        let prod_result = evaluate_with_context(
            &spec,
            &action("egress", "api.example.com"),
            &RuntimeContext {
                environment: Some("prod".to_string()),
                ..RuntimeContext::default()
            },
            &conditions,
        );
        assert_eq!(prod_result.decision, Decision::Deny);
        assert_eq!(
            prod_result.matched_rule.as_deref(),
            Some("rules.egress.block")
        );
    }

    #[test]
    fn evaluate_with_context_denies_fail_closed_on_unknown_condition_key() {
        let spec = spec_with_rules(Rules {
            egress: Some(EgressRule {
                enabled: true,
                allow: Vec::new(),
                block: Vec::new(),
                default: DefaultAction::Allow,
            }),
            ..Rules::default()
        });
        // `egres` is a typo of the `egress` rule block. An unrecognized key must
        // not silently no-op; the evaluator denies rather than filtering with a
        // misconfigured condition map.
        let conditions = HashMap::from([("egres".to_string(), Condition::default())]);

        let result = evaluate_with_context(
            &spec,
            &action("egress", "api.example.com"),
            &RuntimeContext::default(),
            &conditions,
        );

        assert_eq!(result.decision, Decision::Deny);
        assert!(
            result.reason.as_deref().is_some_and(|reason| reason
                .contains("invalid policy condition keys")
                && reason.contains("egres")),
            "expected fail-closed reason naming the bad key, got: {:?}",
            result.reason
        );
    }

    #[test]
    fn generated_glob_compile_errors_fail_closed_for_allow_rules() {
        let spec = spec_with_rules(Rules {
            tool_access: Some(ToolAccessRule {
                enabled: true,
                allow: vec!["*".repeat(600_000)],
                block: Vec::new(),
                require_confirmation: Vec::new(),
                default: DefaultAction::Block,
                max_args_size: None,
                require_runtime_assurance_tier: None,
                prefer_runtime_assurance_tier: None,
                require_workload_identity: None,
                prefer_workload_identity: None,
            }),
            ..Rules::default()
        });

        let result = evaluate(&spec, &action("tool_call", "read_file"));

        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.matched_rule.as_deref(), Some("rules.tool_access.allow"));
        assert!(
            result
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("invalid policy glob pattern")),
            "expected invalid glob denial reason, got {:?}",
            result.reason
        );
    }

    #[test]
    fn file_read_forbidden_path_exception_allows_the_target() {
        let spec = spec_with_rules(Rules {
            forbidden_paths: Some(ForbiddenPathsRule {
                enabled: true,
                patterns: vec!["/secret/**".to_string()],
                exceptions: vec!["/secret/public.txt".to_string()],
            }),
            ..Rules::default()
        });

        let result = evaluate(&spec, &action("file_read", "/secret/public.txt"));

        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(
            result.matched_rule.as_deref(),
            Some("rules.forbidden_paths.exceptions")
        );
    }

    #[test]
    fn file_write_secret_scanning_denies_matching_content() {
        let spec = spec_with_rules(Rules {
            secret_patterns: Some(SecretPatternsRule {
                enabled: true,
                patterns: vec![SecretPattern {
                    name: "api_key".to_string(),
                    pattern: "API_KEY=".to_string(),
                    severity: Severity::Critical,
                    description: None,
                }],
                skip_paths: Vec::new(),
            }),
            ..Rules::default()
        });

        let mut write_action = action("file_write", "/workspace/.env");
        write_action.content = Some("API_KEY=secret".to_string());

        let result = evaluate(&spec, &write_action);

        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(
            result.matched_rule.as_deref(),
            Some("rules.secret_patterns.patterns.api_key")
        );
    }

    #[test]
    fn file_write_secret_scanning_denies_invalid_regex() {
        let spec = spec_with_rules(Rules {
            secret_patterns: Some(SecretPatternsRule {
                enabled: true,
                patterns: vec![SecretPattern {
                    name: "broken".to_string(),
                    pattern: "(".to_string(),
                    severity: Severity::Critical,
                    description: None,
                }],
                skip_paths: Vec::new(),
            }),
            ..Rules::default()
        });

        let mut write_action = action("file_write", "/workspace/app.rs");
        write_action.content = Some("no secret here".to_string());

        let result = evaluate(&spec, &write_action);

        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(
            result.matched_rule.as_deref(),
            Some("rules.secret_patterns.patterns.broken")
        );
        assert!(
            result
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("invalid secret pattern regex")),
            "unexpected reason: {:?}",
            result.reason
        );
    }

    #[test]
    fn patch_integrity_rejects_forbidden_patterns() {
        let spec = spec_with_rules(Rules {
            patch_integrity: Some(PatchIntegrityRule {
                enabled: true,
                max_additions: 20,
                max_deletions: 20,
                forbidden_patterns: vec!["TODO".to_string()],
                require_balance: false,
                max_imbalance_ratio: 2.0,
            }),
            ..Rules::default()
        });
        let mut patch = action("patch_apply", "src/lib.rs");
        patch.content = Some("--- a/src/lib.rs\n+++ b/src/lib.rs\n+// TODO: remove".to_string());

        let result = evaluate(&spec, &patch);

        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(
            result.matched_rule.as_deref(),
            Some("rules.patch_integrity.forbidden_patterns[0]")
        );
    }

    #[test]
    fn patch_integrity_rejects_imbalanced_changes() {
        let spec = spec_with_rules(Rules {
            patch_integrity: Some(PatchIntegrityRule {
                enabled: true,
                max_additions: 20,
                max_deletions: 20,
                forbidden_patterns: Vec::new(),
                require_balance: true,
                max_imbalance_ratio: 1.5,
            }),
            ..Rules::default()
        });
        let mut patch = action("patch_apply", "src/lib.rs");
        patch.content =
            Some("--- a/src/lib.rs\n+++ b/src/lib.rs\n+one\n+two\n+three\n-old".to_string());

        let result = evaluate(&spec, &patch);

        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(
            result.matched_rule.as_deref(),
            Some("rules.patch_integrity.max_imbalance_ratio")
        );
    }

    #[test]
    fn shell_commands_deny_forbidden_patterns() {
        let spec = spec_with_rules(Rules {
            shell_commands: Some(ShellCommandsRule {
                enabled: true,
                forbidden_patterns: vec!["rm\\s+-rf".to_string()],
            }),
            ..Rules::default()
        });

        let result = evaluate(&spec, &action("shell_command", "rm -rf /tmp/cache"));

        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(
            result.matched_rule.as_deref(),
            Some("rules.shell_commands.forbidden_patterns[0]")
        );
    }

    #[test]
    fn remote_desktop_controls_can_override_guardrail_computer_use() {
        let spec = spec_with_rules(Rules {
            computer_use: Some(ComputerUseRule {
                enabled: true,
                mode: ComputerUseMode::Guardrail,
                allowed_actions: Vec::new(),
            }),
            remote_desktop_channels: Some(RemoteDesktopChannelsRule {
                enabled: true,
                clipboard: false,
                file_transfer: false,
                audio: true,
                drive_mapping: false,
            }),
            ..Rules::default()
        });

        let result = evaluate(&spec, &action("computer_use", "remote.clipboard"));

        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(
            result.matched_rule.as_deref(),
            Some("rules.remote_desktop_channels.clipboard")
        );
    }

    #[test]
    fn input_injection_requires_explicit_allowed_types() {
        let spec = spec_with_rules(Rules {
            input_injection: Some(InputInjectionRule {
                enabled: true,
                allowed_types: Vec::new(),
                require_postcondition_probe: false,
            }),
            ..Rules::default()
        });

        let result = evaluate(&spec, &action("input_inject", "paste"));

        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(
            result.matched_rule.as_deref(),
            Some("rules.input_injection.allowed_types")
        );
    }

    #[test]
    fn input_injection_allows_whitelisted_types() {
        let spec = spec_with_rules(Rules {
            input_injection: Some(InputInjectionRule {
                enabled: true,
                allowed_types: vec!["paste".to_string()],
                require_postcondition_probe: false,
            }),
            ..Rules::default()
        });

        let result = evaluate(&spec, &action("input_inject", "paste"));

        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(
            result.matched_rule.as_deref(),
            Some("rules.input_injection.allowed_types")
        );
    }

    #[test]
    fn posture_transitions_track_the_next_state_when_capability_is_allowed() {
        let spec = HushSpec {
            hushspec: "1.0".to_string(),
            name: Some("posture-transition".to_string()),
            description: None,
            extends: None,
            merge_strategy: None,
            rules: Some(Rules::default()),
            extensions: Some(Extensions {
                posture: Some(PostureExtension {
                    initial: "review".to_string(),
                    states: BTreeMap::from([
                        (
                            "review".to_string(),
                            PostureState {
                                description: None,
                                capabilities: vec!["shell".to_string()],
                                budgets: BTreeMap::new(),
                            },
                        ),
                        (
                            "locked".to_string(),
                            PostureState {
                                description: None,
                                capabilities: Vec::new(),
                                budgets: BTreeMap::new(),
                            },
                        ),
                    ]),
                    transitions: vec![PostureTransition {
                        from: "review".to_string(),
                        to: "locked".to_string(),
                        on: crate::models::TransitionTrigger::Timeout,
                        after: None,
                    }],
                }),
                origins: None,
                detection: None,
                reputation: None,
                runtime_assurance: None,
                chio: None,
            }),
            metadata: None,
        };
        let mut shell = action("shell_command", "echo ok");
        shell.posture = Some(PostureContext {
            current: Some("review".to_string()),
            signal: Some("timeout".to_string()),
        });

        let result = evaluate(&spec, &shell);

        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(
            result.posture,
            Some(super::PostureResult {
                current: "review".to_string(),
                next: "locked".to_string(),
            })
        );
    }

    #[test]
    fn posture_capability_guard_denies_missing_capabilities() {
        let spec = HushSpec {
            hushspec: "1.0".to_string(),
            name: Some("posture-guard".to_string()),
            description: None,
            extends: None,
            merge_strategy: None,
            rules: Some(Rules::default()),
            extensions: Some(Extensions {
                posture: Some(PostureExtension {
                    initial: "review".to_string(),
                    states: BTreeMap::from([(
                        "review".to_string(),
                        PostureState {
                            description: None,
                            capabilities: vec!["file_access".to_string()],
                            budgets: BTreeMap::new(),
                        },
                    )]),
                    transitions: Vec::new(),
                }),
                origins: None,
                detection: None,
                reputation: None,
                runtime_assurance: None,
                chio: None,
            }),
            metadata: None,
        };
        let mut shell = action("shell_command", "echo blocked");
        shell.posture = Some(PostureContext {
            current: Some("review".to_string()),
            signal: None,
        });

        let result = evaluate(&spec, &shell);

        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(
            result.matched_rule.as_deref(),
            Some("extensions.posture.states.review.capabilities")
        );
    }
}
