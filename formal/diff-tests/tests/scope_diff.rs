#![cfg(not(target_arch = "wasm32"))]

//! Differential tests: scope subsumption logic.
//!
//! Compares the reference specification's `is_subset_of` against both the
//! production `chio_core::capability::ChioScope::is_subset_of` logic and the
//! normalized proof-facing AST in `chio-kernel-core`.

use chio_formal_diff_tests::generators::{
    arb_paired_grant, arb_paired_normalized_grant, arb_paired_normalized_prompt_grant,
    arb_paired_normalized_resource_grant, arb_paired_normalized_scope,
    arb_paired_normalized_scope_pair, arb_paired_prompt_grant, arb_paired_resource_grant,
    arb_paired_scope_pair, arb_spec_scope, arb_spec_tool_grant, spec_grant_to_normalized,
    spec_prompt_grant_to_normalized, spec_resource_grant_to_normalized, spec_scope_to_normalized,
};
use chio_formal_diff_tests::spec::{
    SpecChioScope, SpecConstraint, SpecMonetaryAmount, SpecOperation, SpecPromptGrant,
    SpecResourceGrant, SpecRuntimeAssuranceTier, SpecToolGrant,
};

use chio_core::capability::{
    Constraint, MonetaryAmount, Operation, PromptGrant, ResourceGrant, RuntimeAssuranceTier,
    ToolGrant,
};
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;

/// Read case count from `PROPTEST_CASES` env var, falling back to the given default.
fn case_count(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: case_count(256),
        max_shrink_iters: 10_000,
        ..ProptestConfig::default()
    }
}

#[test]
fn tool_grant_budget_caps_match_spec_impl_and_normalized() {
    let parent = tool_grant("srv-a", "file_read")
        .with_operations(vec![SpecOperation::Invoke, SpecOperation::ReadResult])
        .with_max_invocations(Some(10))
        .with_max_cost_per_invocation(Some(amount(500, "USD")))
        .with_max_total_cost(Some(amount(1_500, "USD")));

    assert_tool_subset_all(
        &tool_grant("srv-a", "file_read")
            .with_operations(vec![SpecOperation::Invoke])
            .with_max_invocations(Some(5))
            .with_max_cost_per_invocation(Some(amount(250, "USD")))
            .with_max_total_cost(Some(amount(1_000, "USD"))),
        &parent,
        true,
        "child may narrow every budget cap",
    );
    assert_tool_subset_all(
        &tool_grant("srv-a", "file_read")
            .with_max_invocations(None)
            .with_max_cost_per_invocation(Some(amount(250, "USD")))
            .with_max_total_cost(Some(amount(1_000, "USD"))),
        &parent,
        false,
        "child may not remove a parent invocation cap",
    );
    assert_tool_subset_all(
        &tool_grant("srv-a", "file_read")
            .with_max_invocations(Some(11))
            .with_max_cost_per_invocation(Some(amount(250, "USD")))
            .with_max_total_cost(Some(amount(1_000, "USD"))),
        &parent,
        false,
        "child may not raise a parent invocation cap",
    );
    assert_tool_subset_all(
        &tool_grant("srv-a", "file_read")
            .with_max_invocations(Some(5))
            .with_max_cost_per_invocation(None)
            .with_max_total_cost(Some(amount(1_000, "USD"))),
        &parent,
        false,
        "child may not remove a parent per-invocation cost cap",
    );
    assert_tool_subset_all(
        &tool_grant("srv-a", "file_read")
            .with_max_invocations(Some(5))
            .with_max_cost_per_invocation(Some(amount(501, "USD")))
            .with_max_total_cost(Some(amount(1_000, "USD"))),
        &parent,
        false,
        "child may not raise a parent per-invocation cost cap",
    );
    assert_tool_subset_all(
        &tool_grant("srv-a", "file_read")
            .with_max_invocations(Some(5))
            .with_max_cost_per_invocation(Some(amount(250, "EUR")))
            .with_max_total_cost(Some(amount(1_000, "USD"))),
        &parent,
        false,
        "child may not change parent per-invocation cap currency",
    );
    assert_tool_subset_all(
        &tool_grant("srv-a", "file_read")
            .with_max_invocations(Some(5))
            .with_max_cost_per_invocation(Some(amount(250, "USD")))
            .with_max_total_cost(None),
        &parent,
        false,
        "child may not remove a parent total cost cap",
    );
}

#[test]
fn tool_grant_dpop_and_constraints_match_spec_impl_and_normalized() {
    let parent = tool_grant("srv-a", "shell_exec")
        .with_constraints(vec![
            SpecConstraint::PathPrefix("/app".to_string()),
            SpecConstraint::MinimumRuntimeAssurance(SpecRuntimeAssuranceTier::Attested),
        ])
        .with_dpop_required(Some(true));

    assert_tool_subset_all(
        &tool_grant("srv-a", "shell_exec")
            .with_constraints(vec![
                SpecConstraint::PathPrefix("/app".to_string()),
                SpecConstraint::MinimumRuntimeAssurance(SpecRuntimeAssuranceTier::Attested),
                SpecConstraint::MaxArgsSize(1_024),
            ])
            .with_dpop_required(Some(true)),
        &parent,
        true,
        "child may add constraints while preserving parent DPoP",
    );
    assert_tool_subset_all(
        &tool_grant("srv-a", "shell_exec")
            .with_constraints(vec![SpecConstraint::PathPrefix("/app".to_string())])
            .with_dpop_required(Some(true)),
        &parent,
        false,
        "child may not drop a parent constraint",
    );
    assert_tool_subset_all(
        &tool_grant("srv-a", "shell_exec")
            .with_constraints(parent.constraints.clone())
            .with_dpop_required(Some(false)),
        &parent,
        false,
        "child may not disable parent-required DPoP",
    );
    assert_tool_subset_all(
        &tool_grant("srv-a", "shell_exec")
            .with_constraints(parent.constraints.clone())
            .with_dpop_required(None),
        &parent,
        false,
        "child may not omit parent-required DPoP",
    );

    let optional_parent = tool_grant("srv-a", "shell_exec").with_dpop_required(None);
    assert_tool_subset_all(
        &tool_grant("srv-a", "shell_exec").with_dpop_required(Some(true)),
        &optional_parent,
        true,
        "child may require DPoP when parent does not",
    );
}

#[test]
fn wildcard_direction_matches_spec_impl_and_normalized() {
    assert_tool_subset_all(
        &tool_grant("srv-a", "file_read"),
        &tool_grant("*", "*"),
        true,
        "parent wildcard covers a specific child",
    );
    assert_tool_subset_all(
        &tool_grant("*", "file_read"),
        &tool_grant("srv-a", "file_read"),
        false,
        "child server wildcard cannot widen a specific parent server",
    );
    assert_tool_subset_all(
        &tool_grant("srv-a", "*"),
        &tool_grant("srv-a", "file_read"),
        false,
        "child tool wildcard cannot widen a specific parent tool",
    );
}

#[test]
fn resource_and_prompt_patterns_match_spec_impl_and_normalized() {
    assert_resource_subset_all(
        &resource_grant("chio://receipts/session/*"),
        &resource_grant("chio://receipts/*"),
        true,
        "parent resource glob covers a narrower child glob",
    );
    assert_resource_subset_all(
        &resource_grant("chio://lineage/*"),
        &resource_grant("chio://receipts/*"),
        false,
        "unrelated resource glob is not covered",
    );
    assert_resource_subset_all(
        &resource_grant("chio://receipts/*"),
        &resource_grant("chio://receipts/session/*"),
        false,
        "child resource glob cannot widen a narrower parent glob",
    );

    assert_prompt_subset_all(
        &prompt_grant("risk_high"),
        &prompt_grant("risk_*"),
        true,
        "parent prompt glob covers a specific child prompt",
    );
    assert_prompt_subset_all(
        &prompt_grant("risk_*"),
        &prompt_grant("risk_high"),
        false,
        "child prompt glob cannot widen a specific parent prompt",
    );
}

fn assert_tool_subset_all(
    child: &SpecToolGrant,
    parent: &SpecToolGrant,
    expected: bool,
    label: &str,
) {
    let spec = child.is_subset_of(parent);
    let implementation = impl_tool_grant(child).is_subset_of(&impl_tool_grant(parent));
    let normalized =
        spec_grant_to_normalized(child).is_subset_of(&spec_grant_to_normalized(parent));

    assert_eq!(spec, expected, "{label}: reference spec result drifted");
    assert_eq!(
        implementation, expected,
        "{label}: production chio-core result drifted"
    );
    assert_eq!(
        normalized, expected,
        "{label}: normalized proof-facing result drifted"
    );
}

fn assert_resource_subset_all(
    child: &SpecResourceGrant,
    parent: &SpecResourceGrant,
    expected: bool,
    label: &str,
) {
    let spec = child.is_subset_of(parent);
    let implementation = impl_resource_grant(child).is_subset_of(&impl_resource_grant(parent));
    let normalized = spec_resource_grant_to_normalized(child)
        .is_subset_of(&spec_resource_grant_to_normalized(parent));

    assert_eq!(spec, expected, "{label}: reference spec result drifted");
    assert_eq!(
        implementation, expected,
        "{label}: production chio-core result drifted"
    );
    assert_eq!(
        normalized, expected,
        "{label}: normalized proof-facing result drifted"
    );
}

fn assert_prompt_subset_all(
    child: &SpecPromptGrant,
    parent: &SpecPromptGrant,
    expected: bool,
    label: &str,
) {
    let spec = child.is_subset_of(parent);
    let implementation = impl_prompt_grant(child).is_subset_of(&impl_prompt_grant(parent));
    let normalized = spec_prompt_grant_to_normalized(child)
        .is_subset_of(&spec_prompt_grant_to_normalized(parent));

    assert_eq!(spec, expected, "{label}: reference spec result drifted");
    assert_eq!(
        implementation, expected,
        "{label}: production chio-core result drifted"
    );
    assert_eq!(
        normalized, expected,
        "{label}: normalized proof-facing result drifted"
    );
}

fn tool_grant(server_id: &str, tool_name: &str) -> SpecToolGrant {
    SpecToolGrant {
        server_id: server_id.to_string(),
        tool_name: tool_name.to_string(),
        operations: vec![SpecOperation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

trait ToolGrantBuilder {
    fn with_operations(self, operations: Vec<SpecOperation>) -> Self;
    fn with_constraints(self, constraints: Vec<SpecConstraint>) -> Self;
    fn with_max_invocations(self, max_invocations: Option<u32>) -> Self;
    fn with_max_cost_per_invocation(
        self,
        max_cost_per_invocation: Option<SpecMonetaryAmount>,
    ) -> Self;
    fn with_max_total_cost(self, max_total_cost: Option<SpecMonetaryAmount>) -> Self;
    fn with_dpop_required(self, dpop_required: Option<bool>) -> Self;
}

impl ToolGrantBuilder for SpecToolGrant {
    fn with_operations(mut self, operations: Vec<SpecOperation>) -> Self {
        self.operations = operations;
        self
    }

    fn with_constraints(mut self, constraints: Vec<SpecConstraint>) -> Self {
        self.constraints = constraints;
        self
    }

    fn with_max_invocations(mut self, max_invocations: Option<u32>) -> Self {
        self.max_invocations = max_invocations;
        self
    }

    fn with_max_cost_per_invocation(
        mut self,
        max_cost_per_invocation: Option<SpecMonetaryAmount>,
    ) -> Self {
        self.max_cost_per_invocation = max_cost_per_invocation;
        self
    }

    fn with_max_total_cost(mut self, max_total_cost: Option<SpecMonetaryAmount>) -> Self {
        self.max_total_cost = max_total_cost;
        self
    }

    fn with_dpop_required(mut self, dpop_required: Option<bool>) -> Self {
        self.dpop_required = dpop_required;
        self
    }
}

fn amount(units: u64, currency: &str) -> SpecMonetaryAmount {
    SpecMonetaryAmount {
        units,
        currency: currency.to_string(),
    }
}

fn resource_grant(uri_pattern: &str) -> SpecResourceGrant {
    SpecResourceGrant {
        uri_pattern: uri_pattern.to_string(),
        operations: vec![SpecOperation::Read],
    }
}

fn prompt_grant(prompt_name: &str) -> SpecPromptGrant {
    SpecPromptGrant {
        prompt_name: prompt_name.to_string(),
        operations: vec![SpecOperation::Get],
    }
}

fn impl_tool_grant(grant: &SpecToolGrant) -> ToolGrant {
    ToolGrant {
        server_id: grant.server_id.clone(),
        tool_name: grant.tool_name.clone(),
        operations: grant
            .operations
            .iter()
            .copied()
            .map(impl_operation)
            .collect(),
        constraints: grant.constraints.iter().map(impl_constraint).collect(),
        max_invocations: grant.max_invocations,
        max_cost_per_invocation: grant
            .max_cost_per_invocation
            .as_ref()
            .map(impl_monetary_amount),
        max_total_cost: grant.max_total_cost.as_ref().map(impl_monetary_amount),
        dpop_required: grant.dpop_required,
    }
}

fn impl_resource_grant(grant: &SpecResourceGrant) -> ResourceGrant {
    ResourceGrant {
        uri_pattern: grant.uri_pattern.clone(),
        operations: grant
            .operations
            .iter()
            .copied()
            .map(impl_operation)
            .collect(),
    }
}

fn impl_prompt_grant(grant: &SpecPromptGrant) -> PromptGrant {
    PromptGrant {
        prompt_name: grant.prompt_name.clone(),
        operations: grant
            .operations
            .iter()
            .copied()
            .map(impl_operation)
            .collect(),
    }
}

fn impl_operation(operation: SpecOperation) -> Operation {
    match operation {
        SpecOperation::Invoke => Operation::Invoke,
        SpecOperation::ReadResult => Operation::ReadResult,
        SpecOperation::Read => Operation::Read,
        SpecOperation::Subscribe => Operation::Subscribe,
        SpecOperation::Get => Operation::Get,
        SpecOperation::Delegate => Operation::Delegate,
    }
}

fn impl_constraint(constraint: &SpecConstraint) -> Constraint {
    match constraint {
        SpecConstraint::PathPrefix(value) => Constraint::PathPrefix(value.clone()),
        SpecConstraint::DomainExact(value) => Constraint::DomainExact(value.clone()),
        SpecConstraint::DomainGlob(value) => Constraint::DomainGlob(value.clone()),
        SpecConstraint::RegexMatch(value) => Constraint::RegexMatch(value.clone()),
        SpecConstraint::MaxLength(value) => Constraint::MaxLength(*value),
        SpecConstraint::MaxArgsSize(value) => Constraint::MaxArgsSize(*value),
        SpecConstraint::GovernedIntentRequired => Constraint::GovernedIntentRequired,
        SpecConstraint::RequireApprovalAbove { threshold_units } => {
            Constraint::RequireApprovalAbove {
                threshold_units: *threshold_units,
            }
        }
        SpecConstraint::SellerExact(value) => Constraint::SellerExact(value.clone()),
        SpecConstraint::MinimumRuntimeAssurance(tier) => {
            Constraint::MinimumRuntimeAssurance(impl_runtime_assurance_tier(*tier))
        }
        SpecConstraint::Custom(key, value) => Constraint::Custom(key.clone(), value.clone()),
    }
}

fn impl_runtime_assurance_tier(tier: SpecRuntimeAssuranceTier) -> RuntimeAssuranceTier {
    match tier {
        SpecRuntimeAssuranceTier::None => RuntimeAssuranceTier::None,
        SpecRuntimeAssuranceTier::Basic => RuntimeAssuranceTier::Basic,
        SpecRuntimeAssuranceTier::Attested => RuntimeAssuranceTier::Attested,
        SpecRuntimeAssuranceTier::Verified => RuntimeAssuranceTier::Verified,
    }
}

fn impl_monetary_amount(amount: &SpecMonetaryAmount) -> MonetaryAmount {
    MonetaryAmount {
        units: amount.units,
        currency: amount.currency.clone(),
    }
}

proptest! {
    #![proptest_config(config())]

    /// Core differential test: scope subset produces the same result in spec and impl.
    #[test]
    fn scope_subset_spec_matches_impl(
        ((spec_a, impl_a), (spec_b, impl_b)) in arb_paired_scope_pair()
    ) {
        let spec_result = spec_a.is_subset_of(&spec_b);
        let impl_result = impl_a.is_subset_of(&impl_b);

        prop_assert_eq!(
            spec_result, impl_result,
            "Scope subset mismatch!\n  spec: {}\n  impl: {}\n  child grants: {}\n  parent grants: {}",
            spec_result, impl_result, spec_a.grants.len(), spec_b.grants.len()
        );
    }

    /// Tool grant subset differential test.
    #[test]
    fn grant_subset_spec_matches_impl(
        (spec_parent, impl_parent) in arb_paired_grant(),
        (spec_child, impl_child) in arb_paired_grant(),
    ) {
        let spec_result = spec_child.is_subset_of(&spec_parent);
        let impl_result = impl_child.is_subset_of(&impl_parent);

        prop_assert_eq!(
            spec_result, impl_result,
            "Grant subset mismatch!\n  spec: {}\n  impl: {}\n  child: {:?}\n  parent: {:?}",
            spec_result, impl_result, spec_child, spec_parent
        );
    }

    /// Resource grant subset differential test.
    #[test]
    fn resource_grant_subset_spec_matches_impl(
        (spec_parent, impl_parent) in arb_paired_resource_grant(),
        (spec_child, impl_child) in arb_paired_resource_grant(),
    ) {
        let spec_result = spec_child.is_subset_of(&spec_parent);
        let impl_result = impl_child.is_subset_of(&impl_parent);

        prop_assert_eq!(
            spec_result, impl_result,
            "Resource grant subset mismatch!\n  spec: {}\n  impl: {}\n  child: {:?}\n  parent: {:?}",
            spec_result, impl_result, spec_child, spec_parent
        );
    }

    /// Prompt grant subset differential test.
    #[test]
    fn prompt_grant_subset_spec_matches_impl(
        (spec_parent, impl_parent) in arb_paired_prompt_grant(),
        (spec_child, impl_child) in arb_paired_prompt_grant(),
    ) {
        let spec_result = spec_child.is_subset_of(&spec_parent);
        let impl_result = impl_child.is_subset_of(&impl_parent);

        prop_assert_eq!(
            spec_result, impl_result,
            "Prompt grant subset mismatch!\n  spec: {}\n  impl: {}\n  child: {:?}\n  parent: {:?}",
            spec_result, impl_result, spec_child, spec_parent
        );
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn normalized_scope_projection_matches_spec(
        (spec, normalized) in arb_paired_normalized_scope()
    ) {
        let expected = spec_scope_to_normalized(&spec);
        prop_assert_eq!(expected, normalized);
    }

    #[test]
    fn normalized_scope_subset_spec_matches_impl(
        ((spec_a, normalized_a), (spec_b, normalized_b)) in arb_paired_normalized_scope_pair()
    ) {
        let spec_result = spec_a.is_subset_of(&spec_b);
        let normalized_result = normalized_a.is_subset_of(&normalized_b);

        prop_assert_eq!(
            spec_result, normalized_result,
            "Normalized scope subset mismatch!\n  spec: {}\n  normalized: {}\n  child grants: {}\n  parent grants: {}",
            spec_result, normalized_result, spec_a.grants.len(), spec_b.grants.len()
        );
    }

    #[test]
    fn normalized_grant_projection_matches_spec(
        (spec, normalized) in arb_paired_normalized_grant()
    ) {
        let expected = spec_grant_to_normalized(&spec);
        prop_assert_eq!(expected, normalized);
    }

    #[test]
    fn normalized_grant_subset_spec_matches_impl(
        (spec_parent, normalized_parent) in arb_paired_normalized_grant(),
        (spec_child, normalized_child) in arb_paired_normalized_grant(),
    ) {
        let spec_result = spec_child.is_subset_of(&spec_parent);
        let normalized_result = normalized_child.is_subset_of(&normalized_parent);

        prop_assert_eq!(
            spec_result, normalized_result,
            "Normalized grant subset mismatch!\n  spec: {}\n  normalized: {}\n  child: {:?}\n  parent: {:?}",
            spec_result, normalized_result, spec_child, spec_parent
        );
    }

    #[test]
    fn normalized_resource_projection_matches_spec(
        (spec, normalized) in arb_paired_normalized_resource_grant()
    ) {
        let expected = spec_resource_grant_to_normalized(&spec);
        prop_assert_eq!(expected, normalized);
    }

    #[test]
    fn normalized_resource_subset_spec_matches_impl(
        (spec_parent, normalized_parent) in arb_paired_normalized_resource_grant(),
        (spec_child, normalized_child) in arb_paired_normalized_resource_grant(),
    ) {
        let spec_result = spec_child.is_subset_of(&spec_parent);
        let normalized_result = normalized_child.is_subset_of(&normalized_parent);

        prop_assert_eq!(
            spec_result, normalized_result,
            "Normalized resource subset mismatch!\n  spec: {}\n  normalized: {}\n  child: {:?}\n  parent: {:?}",
            spec_result, normalized_result, spec_child, spec_parent
        );
    }

    #[test]
    fn normalized_prompt_projection_matches_spec(
        (spec, normalized) in arb_paired_normalized_prompt_grant()
    ) {
        let expected = spec_prompt_grant_to_normalized(&spec);
        prop_assert_eq!(expected, normalized);
    }

    #[test]
    fn normalized_prompt_subset_spec_matches_impl(
        (spec_parent, normalized_parent) in arb_paired_normalized_prompt_grant(),
        (spec_child, normalized_child) in arb_paired_normalized_prompt_grant(),
    ) {
        let spec_result = spec_child.is_subset_of(&spec_parent);
        let normalized_result = normalized_child.is_subset_of(&normalized_parent);

        prop_assert_eq!(
            spec_result, normalized_result,
            "Normalized prompt subset mismatch!\n  spec: {}\n  normalized: {}\n  child: {:?}\n  parent: {:?}",
            spec_result, normalized_result, spec_child, spec_parent
        );
    }

    /// P1: Empty scope is a subset of any scope.
    #[test]
    fn empty_scope_is_subset(scope in arb_spec_scope()) {
        let empty = SpecChioScope {
            grants: vec![],
            resource_grants: vec![],
            prompt_grants: vec![],
        };
        prop_assert!(
            empty.is_subset_of(&scope),
            "Empty scope must be a subset of any scope"
        );
    }

    /// P2: A scope is a subset of itself (reflexivity).
    #[test]
    fn scope_subset_reflexive(scope in arb_spec_scope()) {
        // Only holds for scopes where each grant is a subset of itself.
        // This is true when the grant subsumption check is reflexive,
        // which it is (same server, same tool, same ops, same constraints).
        prop_assert!(
            scope.is_subset_of(&scope),
            "Scope must be a subset of itself"
        );
    }

    /// P3: Removing a grant from a scope produces a subset.
    #[test]
    fn remove_grant_is_subset(scope in arb_spec_scope(), idx in any::<usize>()) {
        if scope.grants.is_empty() {
            return Ok(());
        }
        let remove_idx = idx % scope.grants.len();
        let mut child_grants = scope.grants.clone();
        child_grants.remove(remove_idx);
        let child = SpecChioScope {
            grants: child_grants,
            resource_grants: scope.resource_grants.clone(),
            prompt_grants: scope.prompt_grants.clone(),
        };

        prop_assert!(
            child.is_subset_of(&scope),
            "Removing a grant must produce a subset"
        );
    }

    /// P4: Removing an operation from a grant produces a grant that is a subset.
    #[test]
    fn remove_operation_is_subset(
        grant in arb_spec_tool_grant(),
        op_idx in any::<usize>(),
    ) {
        if grant.operations.is_empty() {
            return Ok(());
        }
        let remove_idx = op_idx % grant.operations.len();
        let mut child_ops = grant.operations.clone();
        child_ops.remove(remove_idx);

        if child_ops.is_empty() {
            // Edge case: no operations left. Still a subset since
            // all (zero) child ops are in parent.
            return Ok(());
        }

        let child = SpecToolGrant {
            operations: child_ops,
            ..grant.clone()
        };

        prop_assert!(
            child.is_subset_of(&grant),
            "Removing an operation must produce a subset"
        );
    }

    /// P5: Reducing max_invocations produces a subset.
    #[test]
    fn reduce_budget_is_subset(
        grant in arb_spec_tool_grant(),
    ) {
        if let Some(max) = grant.max_invocations {
            if max > 0 {
                let child = SpecToolGrant {
                    max_invocations: Some(max / 2),
                    ..grant.clone()
                };
                prop_assert!(
                    child.is_subset_of(&grant),
                    "Reducing budget must produce a subset"
                );
            }
        }
    }

    /// P6: Wildcard tool name subsumes any specific tool name.
    #[test]
    fn wildcard_subsumes(
        server_idx in 0usize..10,
        tool_idx in 0usize..10,
    ) {
        let server = format!("srv-{server_idx}");
        let tool = format!("tool-{tool_idx}");
        let parent = SpecToolGrant {
            server_id: server.clone(),
            tool_name: "*".to_string(),
            operations: vec![SpecOperation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };
        let child = SpecToolGrant {
            server_id: server,
            tool_name: tool,
            operations: vec![SpecOperation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };

        prop_assert!(
            child.is_subset_of(&parent),
            "Wildcard tool must subsume any specific tool"
        );
    }

    /// P7: Different servers never produce a subset relationship.
    #[test]
    fn different_servers_not_subset(
        tool in arb_spec_tool_grant(),
    ) {
        let child = SpecToolGrant {
            server_id: format!("{}-different", tool.server_id),
            ..tool.clone()
        };
        prop_assert!(
            !child.is_subset_of(&tool),
            "Different servers must not be subsets"
        );
    }

    /// P8: Monotonicity -- if child is subset of parent, and parent is subset
    /// of grandparent, then child is subset of grandparent (transitivity).
    ///
    /// This is the key delegation chain property: multi-hop delegation preserves
    /// the subset relationship.
    #[test]
    fn subset_transitivity(scope in arb_spec_scope()) {
        // Construct grandparent -> parent -> child by progressive removal.
        let grandparent = scope.clone();

        // Parent: keep first half of grants
        let half = scope.grants.len() / 2;
        let parent = SpecChioScope {
            grants: scope.grants[..half].to_vec(),
            resource_grants: scope.resource_grants.clone(),
            prompt_grants: scope.prompt_grants.clone(),
        };

        // Child: keep first quarter of grants
        let quarter = half / 2;
        let child = SpecChioScope {
            grants: scope.grants[..quarter].to_vec(),
            resource_grants: scope.resource_grants.clone(),
            prompt_grants: scope.prompt_grants.clone(),
        };

        if parent.is_subset_of(&grandparent) && child.is_subset_of(&parent) {
            prop_assert!(
                child.is_subset_of(&grandparent),
                "Subset must be transitive: child <= parent <= grandparent implies child <= grandparent"
            );
        }
    }
}
