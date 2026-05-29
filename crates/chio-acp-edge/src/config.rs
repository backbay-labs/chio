// Edge configuration controlling permission defaults and categorization.

/// Configuration for the ACP edge.
#[derive(Debug, Clone)]
pub struct AcpEdgeConfig {
    /// Whether to require explicit permission for all tools.
    pub require_permission: bool,
    /// Default ACP category for unmapped tools.
    pub default_category: AcpCategory,
}

impl Default for AcpEdgeConfig {
    fn default() -> Self {
        Self {
            require_permission: true,
            default_category: AcpCategory::Tool,
        }
    }
}
