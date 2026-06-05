use chio_core_types::capability::ChioScope;

pub(crate) fn is_scope_subset(child: &ChioScope, parent: &ChioScope) -> bool {
    child.is_subset_of(parent)
}

#[cfg(test)]
mod tests {
    use chio_core_types::capability::{ChioScope, Constraint, Operation, ToolGrant};

    use super::is_scope_subset;

    #[test]
    fn scope_subset_requires_child_constraints_when_parent_is_restricted() {
        let parent = ToolGrant {
            server_id: "files".to_string(),
            tool_name: "read".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::PathPrefix("/secret".to_string())],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };
        let child = ToolGrant {
            server_id: "files".to_string(),
            tool_name: "read".to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        };

        let parent_scope = ChioScope {
            grants: vec![parent],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        };
        let child_scope = ChioScope {
            grants: vec![child],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        };

        assert!(
            !is_scope_subset(&child_scope, &parent_scope),
            "expected scope cannot drop parent constraints"
        );
    }
}
