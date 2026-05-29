//! Groq-native content shapes for the OpenAI-compatible `chat/completions`
//! API.
//!
//! Groq renders tool calls as `choices[].message.tool_calls[]` entries and
//! consumes tool results as `tool` role messages on the next turn. The two
//! structs here are the adapter's normalized projection of those wire shapes:
//! the OpenAI-compatible `tool_calls[].function.{name, arguments}` envelope is
//! parsed into a [`FunctionCallPart`] (with `arguments` decoded from its
//! JSON-encoded string into a [`serde_json::Value`]), and a gated tool result
//! is held as a [`FunctionResponsePart`] before it is lowered onto a `tool`
//! message. Pinned to API version `2025-04` (see
//! [`crate::transport::GROQ_API_VERSION`]).

use serde::{Deserialize, Serialize};

/// Normalized tool call lifted from a Groq `tool_calls[]` entry.
///
/// The upstream wire entry is
/// `{ "id": "...", "type": "function", "function": { "name": "...",
/// "arguments": "<json-string>" } }`; this struct holds the decoded name and
/// arguments object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionCallPart {
    /// Tool name from `tool_calls[].function.name`.
    pub name: String,
    /// Decoded `tool_calls[].function.arguments` JSON object.
    pub args: serde_json::Value,
}

impl FunctionCallPart {
    /// Construct a freshly-typed function-call part.
    pub fn new(name: impl Into<String>, args: serde_json::Value) -> Self {
        Self {
            name: name.into(),
            args,
        }
    }
}

/// Normalized tool result lowered back to Groq on the next turn.
///
/// Groq consumes a tool result as a message
/// `{ "role": "tool", "tool_call_id": "...", "content": "<json-string>" }`.
/// This struct carries the matching function name and the gated JSON result
/// payload; the caller serializes it onto the `tool` message it appends to the
/// conversation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionResponsePart {
    /// Function name matching [`FunctionCallPart::name`].
    pub name: String,
    /// JSON object Groq consumes as the tool result content.
    pub response: serde_json::Value,
}

impl FunctionResponsePart {
    /// Construct a function-response part.
    pub fn new(name: impl Into<String>, response: serde_json::Value) -> Self {
        Self {
            name: name.into(),
            response,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn function_call_round_trips() {
        let part = FunctionCallPart::new("get_weather", json!({"city": "Paris"}));
        let bytes = serde_json::to_vec(&part).unwrap();
        let back: FunctionCallPart = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(part, back);
    }

    #[test]
    fn function_response_round_trips() {
        let part = FunctionResponsePart::new("get_weather", json!({"temp": 18}));
        let bytes = serde_json::to_vec(&part).unwrap();
        let back: FunctionResponsePart = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(part, back);
    }
}
