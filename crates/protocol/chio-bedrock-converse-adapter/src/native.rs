//! Bedrock Converse native wire-shaped types: `toolConfig`, `toolUse`, and `toolResult`.

use serde::{Deserialize, Serialize};

/// Bedrock `toolConfig` subset used by Converse requests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ToolConfig {
    /// Tool specifications offered to the model.
    pub tools: Vec<ToolSpec>,
}

impl ToolConfig {
    /// Construct a tool config from the provided tool specs.
    pub fn new(tools: Vec<ToolSpec>) -> Self {
        Self { tools }
    }
}

/// Bedrock tool specification subset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ToolSpec {
    /// Tool name registered with Bedrock.
    pub name: String,
    /// Human-readable tool description.
    pub description: Option<String>,
    /// JSON schema object for tool input.
    pub input_schema: serde_json::Value,
}

impl ToolSpec {
    /// Construct a tool specification.
    pub fn new(
        name: impl Into<String>,
        description: Option<String>,
        input_schema: serde_json::Value,
    ) -> Self {
        Self {
            name: name.into(),
            description,
            input_schema,
        }
    }
}

/// Bedrock `toolUse` content block.
///
/// Wire shape:
///
/// ```json
/// { "toolUseId": "...", "name": "...", "input": { ... } }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ToolUseBlock {
    /// Bedrock-issued tool-use identifier.
    pub tool_use_id: String,
    /// Tool name requested by the model.
    pub name: String,
    /// JSON arguments object for the tool invocation.
    pub input: serde_json::Value,
}

impl ToolUseBlock {
    /// Construct a Bedrock tool-use block.
    pub fn new(
        tool_use_id: impl Into<String>,
        name: impl Into<String>,
        input: serde_json::Value,
    ) -> Self {
        Self {
            tool_use_id: tool_use_id.into(),
            name: name.into(),
            input,
        }
    }
}

/// Bedrock `toolResult` status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolResultStatus {
    /// Tool execution completed and produced output.
    Success,
    /// Tool execution was denied or failed.
    Error,
}

/// Bedrock `toolResult` content block subset.
///
/// Wire shape:
///
/// ```json
/// { "toolUseId": "...", "content": [...], "status": "success" }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ToolResultBlock {
    /// Identifier from the matching [`ToolUseBlock::tool_use_id`].
    pub tool_use_id: String,
    /// Content returned to Bedrock.
    pub content: serde_json::Value,
    /// Success or error status for the result.
    pub status: ToolResultStatus,
}

impl ToolResultBlock {
    /// Construct an allow-path tool result.
    pub fn allow(tool_use_id: impl Into<String>, content: serde_json::Value) -> Self {
        Self {
            tool_use_id: tool_use_id.into(),
            content,
            status: ToolResultStatus::Success,
        }
    }

    /// Construct a deny/error-path tool result.
    pub fn deny(tool_use_id: impl Into<String>, content: serde_json::Value) -> Self {
        Self {
            tool_use_id: tool_use_id.into(),
            content,
            status: ToolResultStatus::Error,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tool_config_round_trips() {
        let spec = ToolSpec::new(
            "search_web",
            Some("Search the web".to_string()),
            json!({"type": "object", "properties": {"query": {"type": "string"}}}),
        );
        let cfg = ToolConfig::new(vec![spec]);
        let bytes = serde_json::to_vec(&cfg).unwrap();
        let back: ToolConfig = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(cfg, back);
        let rendered = serde_json::to_string(&cfg).unwrap();
        assert!(rendered.contains("inputSchema"));
    }

    #[test]
    fn tool_use_block_round_trips_camel_case_id() {
        let block = ToolUseBlock::new("tooluse_01", "search_web", json!({"query": "chio"}));
        let bytes = serde_json::to_vec(&block).unwrap();
        let back: ToolUseBlock = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(block, back);
        let rendered = serde_json::to_string(&block).unwrap();
        assert!(rendered.contains("toolUseId"));
    }

    #[test]
    fn tool_result_allow_and_deny_statuses() {
        let allow = ToolResultBlock::allow("tooluse_01", json!([{"json": {"ok": true}}]));
        assert_eq!(allow.status, ToolResultStatus::Success);

        let deny = ToolResultBlock::deny("tooluse_01", json!([{"text": "policy_deny"}]));
        assert_eq!(deny.status, ToolResultStatus::Error);
        let rendered = serde_json::to_string(&deny).unwrap();
        assert!(rendered.contains("\"status\":\"error\""));
    }
}
