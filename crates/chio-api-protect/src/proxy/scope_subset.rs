use super::*;

pub(crate) fn is_scope_subset(child: &ChioScope, parent: &ChioScope) -> bool {
    let grants_ok = child.grants.iter().all(|child_grant| {
        parent
            .grants
            .iter()
            .any(|p| tool_grant_subset(child_grant, p))
    });
    let resources_ok = child.resource_grants.iter().all(|child_grant| {
        parent
            .resource_grants
            .iter()
            .any(|p| resource_grant_subset(child_grant, p))
    });
    let prompts_ok = child.prompt_grants.iter().all(|child_grant| {
        parent
            .prompt_grants
            .iter()
            .any(|p| prompt_grant_subset(child_grant, p))
    });
    grants_ok && resources_ok && prompts_ok
}

pub(crate) fn tool_grant_subset(child: &ToolGrant, parent: &ToolGrant) -> bool {
    if parent.server_id != "*" && parent.server_id != child.server_id {
        return false;
    }
    if parent.tool_name != "*" && parent.tool_name != child.tool_name {
        return false;
    }
    child
        .operations
        .iter()
        .all(|op| parent.operations.contains(op))
}

pub(crate) fn resource_grant_subset(child: &ResourceGrant, parent: &ResourceGrant) -> bool {
    if parent.uri_pattern != "*" && parent.uri_pattern != child.uri_pattern {
        return false;
    }
    child
        .operations
        .iter()
        .all(|op| parent.operations.contains(op))
}

pub(crate) fn prompt_grant_subset(child: &PromptGrant, parent: &PromptGrant) -> bool {
    if parent.prompt_name != "*" && parent.prompt_name != child.prompt_name {
        return false;
    }
    child
        .operations
        .iter()
        .all(|op| parent.operations.contains(op))
}
