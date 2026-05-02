#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use chio_kernel_core::{
    NormalizedConstraint, NormalizedMonetaryAmount, NormalizedOperation, NormalizedPromptGrant,
    NormalizedResourceGrant, NormalizedScope, NormalizedToolGrant,
};
use proptest::prelude::*;

fn proptest_config_for_lane(default_cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(default_cases);
    ProptestConfig::with_cases(cases)
}

fn ident_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_-]{0,12}".prop_map(|value| value)
}

fn operation_strategy() -> impl Strategy<Value = NormalizedOperation> {
    prop_oneof![
        Just(NormalizedOperation::Invoke),
        Just(NormalizedOperation::ReadResult),
        Just(NormalizedOperation::Read),
        Just(NormalizedOperation::Subscribe),
        Just(NormalizedOperation::Get),
        Just(NormalizedOperation::Delegate),
    ]
}

fn tool_grant(
    server_id: String,
    tool_name: String,
    operations: Vec<NormalizedOperation>,
) -> NormalizedToolGrant {
    NormalizedToolGrant {
        server_id,
        tool_name,
        operations,
        constraints: Vec::new(),
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn scope_with_grant(grant: NormalizedToolGrant) -> NormalizedScope {
    NormalizedScope {
        grants: vec![grant],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    }
}

proptest! {
    #![proptest_config(proptest_config_for_lane(96))]

    #[test]
    fn wildcard_parent_covers_exact_child_tool_grant(
        server in ident_strategy(),
        tool in ident_strategy(),
        operation in operation_strategy(),
    ) {
        let child = tool_grant(server, tool, vec![operation]);
        let parent = tool_grant(
            "*".to_string(),
            "*".to_string(),
            vec![
                NormalizedOperation::Invoke,
                NormalizedOperation::ReadResult,
                NormalizedOperation::Read,
                NormalizedOperation::Subscribe,
                NormalizedOperation::Get,
                NormalizedOperation::Delegate,
            ],
        );

        prop_assert!(child.is_subset_of(&parent));
        prop_assert!(scope_with_grant(child).is_subset_of(&scope_with_grant(parent)));
    }

    #[test]
    fn missing_parent_operation_denies_tool_subset(
        server in ident_strategy(),
        tool in ident_strategy(),
    ) {
        let child = tool_grant(server, tool, vec![NormalizedOperation::Delegate]);
        let parent = tool_grant(
            "*".to_string(),
            "*".to_string(),
            vec![NormalizedOperation::Invoke, NormalizedOperation::Read],
        );

        prop_assert!(!child.is_subset_of(&parent));
    }

    #[test]
    fn parent_constraints_must_be_preserved_by_child(
        server in ident_strategy(),
        tool in ident_strategy(),
        path in ident_strategy(),
    ) {
        let required = NormalizedConstraint::PathPrefix(format!("/tenant/{path}"));
        let extra = NormalizedConstraint::MaxArgsSize(4096);
        let mut parent = tool_grant(server.clone(), tool.clone(), vec![NormalizedOperation::Invoke]);
        parent.constraints = vec![required.clone()];

        let mut child_with_required = tool_grant(server.clone(), tool.clone(), vec![NormalizedOperation::Invoke]);
        child_with_required.constraints = vec![required, extra];
        prop_assert!(child_with_required.is_subset_of(&parent));

        let child_without_required = tool_grant(server, tool, vec![NormalizedOperation::Invoke]);
        prop_assert!(!child_without_required.is_subset_of(&parent));
    }

    #[test]
    fn monetary_caps_are_subset_only_when_currency_matches_and_units_do_not_widen(
        child_units in 0_u64..1_000_000,
        parent_units in 0_u64..1_000_000,
    ) {
        let mut child = tool_grant(
            "srv".to_string(),
            "tool".to_string(),
            vec![NormalizedOperation::Invoke],
        );
        child.max_total_cost = Some(NormalizedMonetaryAmount {
            units: child_units,
            currency: "USD".to_string(),
        });
        let mut parent = tool_grant(
            "srv".to_string(),
            "tool".to_string(),
            vec![NormalizedOperation::Invoke],
        );
        parent.max_total_cost = Some(NormalizedMonetaryAmount {
            units: parent_units,
            currency: "USD".to_string(),
        });

        prop_assert_eq!(child.is_subset_of(&parent), child_units <= parent_units);

        parent.max_total_cost = Some(NormalizedMonetaryAmount {
            units: parent_units.max(child_units),
            currency: "EUR".to_string(),
        });
        prop_assert!(!child.is_subset_of(&parent));
    }

    #[test]
    fn resource_and_prompt_prefix_patterns_must_have_matching_parent_grants(
        tenant in ident_strategy(),
        doc in ident_strategy(),
        prompt in ident_strategy(),
    ) {
        let child = NormalizedScope {
            grants: Vec::new(),
            resource_grants: vec![NormalizedResourceGrant {
                uri_pattern: format!("file://{tenant}/{doc}.txt"),
                operations: vec![NormalizedOperation::Read],
            }],
            prompt_grants: vec![NormalizedPromptGrant {
                prompt_name: format!("review.security.{prompt}"),
                operations: vec![NormalizedOperation::Get],
            }],
        };
        let parent = NormalizedScope {
            grants: Vec::new(),
            resource_grants: vec![NormalizedResourceGrant {
                uri_pattern: format!("file://{tenant}/*"),
                operations: vec![NormalizedOperation::Read, NormalizedOperation::Subscribe],
            }],
            prompt_grants: vec![NormalizedPromptGrant {
                prompt_name: "review.security.*".to_string(),
                operations: vec![NormalizedOperation::Get],
            }],
        };
        prop_assert!(child.is_subset_of(&parent));

        let missing_prompt_parent = NormalizedScope {
            prompt_grants: Vec::new(),
            ..parent.clone()
        };
        prop_assert!(!child.is_subset_of(&missing_prompt_parent));
    }
}
