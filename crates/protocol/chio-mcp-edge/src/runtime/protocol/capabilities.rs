use super::*;

pub(in crate::runtime) fn select_capability_for_request(
    capabilities: &[CapabilityToken],
    tool_name: &str,
    server_id: &str,
    arguments: &Value,
    model_metadata: Option<&ModelMetadata>,
) -> Option<CapabilityToken> {
    capabilities
        .iter()
        .find(|capability| {
            chio_kernel::capability_matches_request_with_model_metadata(
                capability,
                tool_name,
                server_id,
                arguments,
                model_metadata,
            )
            .unwrap_or(false)
        })
        .cloned()
}

pub(in crate::runtime) fn select_capability_for_resource(
    capabilities: &[CapabilityToken],
    uri: &str,
) -> Option<CapabilityToken> {
    capabilities
        .iter()
        .find(|capability| {
            chio_kernel::capability_matches_resource_request(capability, uri).unwrap_or(false)
        })
        .cloned()
}

pub(in crate::runtime) fn select_capability_for_resource_subscription(
    capabilities: &[CapabilityToken],
    uri: &str,
) -> Option<CapabilityToken> {
    capabilities
        .iter()
        .find(|capability| {
            chio_kernel::capability_matches_resource_subscription(capability, uri).unwrap_or(false)
        })
        .cloned()
}

pub(in crate::runtime) fn select_capability_for_prompt(
    capabilities: &[CapabilityToken],
    prompt_name: &str,
) -> Option<CapabilityToken> {
    capabilities
        .iter()
        .find(|capability| {
            chio_kernel::capability_matches_prompt_request(capability, prompt_name).unwrap_or(false)
        })
        .cloned()
}

pub(in crate::runtime) fn select_capability_for_resource_pattern(
    capabilities: &[CapabilityToken],
    pattern: &str,
) -> Option<CapabilityToken> {
    capabilities
        .iter()
        .find(|capability| {
            chio_kernel::capability_matches_resource_pattern(capability, pattern).unwrap_or(false)
        })
        .cloned()
}

pub(in crate::runtime) fn tool_is_authorized(
    capabilities: &[CapabilityToken],
    binding: &ExposedToolBinding,
) -> bool {
    capabilities.iter().any(|capability| {
        capability.scope.grants.iter().any(|grant| {
            matches_server(&grant.server_id, &binding.server_id)
                && matches_name(&grant.tool_name, &binding.tool_name)
                && grant.operations.contains(&Operation::Invoke)
        })
    })
}

pub(in crate::runtime) fn matches_server(pattern: &str, server_id: &str) -> bool {
    pattern == "*" || pattern == server_id
}

pub(in crate::runtime) fn matches_name(pattern: &str, tool_name: &str) -> bool {
    pattern == "*" || pattern == tool_name
}
