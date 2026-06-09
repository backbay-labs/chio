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

impl A2aEdgeConfig {
    fn validate_for_agent_card(&self) -> Result<(), A2aEdgeError> {
        reject_invalid_agent_card_field("name", &self.agent_name)?;
        reject_invalid_agent_card_field("version", &self.agent_version)?;
        reject_invalid_agent_card_field("endpoint URL", &self.endpoint_url)?;
        reject_invalid_agent_card_field("protocol binding", &self.protocol_binding)?;
        Ok(())
    }
}

fn reject_invalid_agent_card_field(field: &str, value: &str) -> Result<(), A2aEdgeError> {
    if value.trim().is_empty() {
        return Err(A2aEdgeError::InvalidRequest(format!(
            "agent card {field} must not be empty"
        )));
    }
    if value.trim() != value {
        return Err(A2aEdgeError::InvalidRequest(format!(
            "agent card {field} must not include leading or trailing whitespace"
        )));
    }
    Ok(())
}
