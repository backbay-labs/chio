// Edge configuration surfaced in the published Agent Card.

/// Configuration for the A2A edge.
#[derive(Debug, Clone)]
pub struct A2aEdgeConfig {
    /// Name to advertise in the Agent Card.
    pub agent_name: String,
    /// Description for the Agent Card.
    pub agent_description: String,
    /// Version of the agent.
    pub agent_version: String,
    /// URL where the A2A endpoint is hosted.
    pub endpoint_url: String,
    /// Protocol binding (default: "JSONRPC").
    pub protocol_binding: String,
}

impl Default for A2aEdgeConfig {
    fn default() -> Self {
        Self {
            agent_name: "Chio A2A Edge".to_string(),
            agent_description: "Chio-governed tools exposed as A2A skills".to_string(),
            agent_version: "0.1.0".to_string(),
            endpoint_url: "http://localhost:8080".to_string(),
            protocol_binding: "JSONRPC".to_string(),
        }
    }
}
