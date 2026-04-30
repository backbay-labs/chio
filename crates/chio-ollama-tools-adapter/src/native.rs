//! Ollama-native message shapes for `/api/chat`.
//!
//! Ollama renders tool calls as OpenAI-style `tool_calls` entries on the
//! assistant message. Tool results travel back as `tool` role messages on
//! the next user turn. Pinned to API version `2025-04` (see
//! [`crate::transport::OLLAMA_API_VERSION`]).

use serde::{Deserialize, Serialize};

/// Tool-call entry emitted on the assistant turn.
///
/// Wire shape:
///
/// ```json
/// { "function": { "name": "...", "arguments": { ... } } }
/// ```
///
/// Ollama omits the explicit `id` field that OpenAI uses; the adapter
/// synthesises a stable id from the tool name and ordinal index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolCallPart {
    /// Wrapped function descriptor.
    pub function: ToolCallFunction,
}

/// Inner `function` block for a tool call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolCallFunction {
    /// Tool name registered on the request `tools` array.
    pub name: String,
    /// JSON arguments object the model wants the tool invoked with.
    /// Ollama keeps this as a JSON value (not a JSON string), unlike OpenAI.
    pub arguments: serde_json::Value,
}

impl ToolCallPart {
    /// Construct a freshly-typed tool-call part.
    pub fn new(name: impl Into<String>, arguments: serde_json::Value) -> Self {
        Self {
            function: ToolCallFunction {
                name: name.into(),
                arguments,
            },
        }
    }
}

/// Tool-result message fed back to Ollama on the next user turn.
///
/// Wire shape:
///
/// ```json
/// { "role": "tool", "name": "...", "content": "..." }
/// ```
///
/// Ollama serialises the tool result as a `content` string (canonical JSON
/// of the structured result, or the deny-payload string).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolResultMessage {
    /// Always `tool`.
    pub role: String,
    /// Tool name matching [`ToolCallFunction::name`].
    pub name: String,
    /// JSON-encoded tool result string.
    pub content: String,
}

impl ToolResultMessage {
    /// Construct a tool-result message.
    pub fn new(name: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: "tool".to_string(),
            name: name.into(),
            content: content.into(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tool_call_round_trips() {
        let part = ToolCallPart::new("get_weather", json!({"city": "Paris"}));
        let bytes = serde_json::to_vec(&part).unwrap();
        let back: ToolCallPart = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(part, back);
    }

    #[test]
    fn tool_result_round_trips() {
        let msg = ToolResultMessage::new("get_weather", "{\"temp\":18}".to_string());
        let bytes = serde_json::to_vec(&msg).unwrap();
        let back: ToolResultMessage = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(msg, back);
        assert_eq!(back.role, "tool");
    }
}
