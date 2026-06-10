//! Cohere-native message and content blocks for `/v2/chat`.
//!
//! Cohere v2 surfaces tool calls as a `tool_plan` string and a `tool_calls`
//! array on the assistant `message`. Tool results travel back as a `tool`
//! role message carrying `tool_call_id` and a `content` block list.
//! Pinned to API version `2025-04` (see
//! [`crate::transport::COHERE_API_VERSION`]).

use serde::{Deserialize, Serialize};

/// Tool-call block emitted on the assistant turn.
///
/// Wire shape:
///
/// ```json
/// {
///   "id": "call_...",
///   "type": "function",
///   "function": { "name": "...", "arguments": "<json string>" }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolCallBlock {
    /// Cohere-allocated tool call id.
    pub id: String,
    /// Always `function` for the v2 surface.
    #[serde(rename = "type")]
    pub kind: String,
    /// Wrapped function descriptor.
    pub function: ToolCallFunction,
}

/// Inner `function` block for a tool call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolCallFunction {
    /// Tool name registered on the request `tools` array.
    pub name: String,
    /// JSON-encoded arguments string. Cohere serialises arguments as a JSON
    /// string the same way OpenAI does on the v1 surface.
    pub arguments: String,
}

impl ToolCallBlock {
    /// Construct a freshly-typed tool-call block.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        arguments: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            kind: "function".to_string(),
            function: ToolCallFunction {
                name: name.into(),
                arguments: arguments.into(),
            },
        }
    }
}

/// Tool-result block fed back to Cohere on the next user turn.
///
/// Wire shape (v2):
///
/// ```json
/// {
///   "role": "tool",
///   "tool_call_id": "call_...",
///   "content": [{ "type": "text", "text": "<json string>" }]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolResultMessage {
    /// Always `tool`.
    pub role: String,
    /// Cohere tool_call_id matching the originating tool call.
    pub tool_call_id: String,
    /// Content block list. The adapter emits a single `text` block whose
    /// `text` is the canonical JSON tool result.
    pub content: Vec<ToolResultContent>,
}

/// Content block inside a Cohere tool message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolResultContent {
    /// Always `text` for the v2 tool-result envelope.
    #[serde(rename = "type")]
    pub kind: String,
    /// JSON-encoded tool result text.
    pub text: String,
}

impl ToolResultMessage {
    /// Construct a tool-result message with a single text block.
    pub fn new(tool_call_id: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            role: "tool".to_string(),
            tool_call_id: tool_call_id.into(),
            content: vec![ToolResultContent {
                kind: "text".to_string(),
                text: text.into(),
            }],
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn tool_call_round_trips() {
        let block = ToolCallBlock::new("call_1", "get_weather", "{\"city\":\"Paris\"}");
        let bytes = serde_json::to_vec(&block).unwrap();
        let back: ToolCallBlock = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(block, back);
        assert_eq!(back.kind, "function");
    }

    #[test]
    fn tool_result_round_trips() {
        let msg = ToolResultMessage::new("call_1", "{\"temp\":18}".to_string());
        let bytes = serde_json::to_vec(&msg).unwrap();
        let back: ToolResultMessage = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(msg, back);
        assert_eq!(back.role, "tool");
        assert_eq!(back.content.len(), 1);
        assert_eq!(back.content[0].kind, "text");
    }
}
