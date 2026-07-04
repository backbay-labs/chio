pub(crate) fn select_capability_for_request(
    capabilities: &[chio_core::capability::token::CapabilityToken],
    tool: &str,
    server: &str,
    params: &serde_json::Value,
) -> Option<chio_core::capability::token::CapabilityToken> {
    capabilities
        .iter()
        .find(|capability| {
            chio_kernel::capability_matches_request(capability, tool, server, params)
                .unwrap_or(false)
        })
        .cloned()
        .or_else(|| capabilities.first().cloned())
}
