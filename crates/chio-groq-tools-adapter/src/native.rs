//! Groq-native content-part shapes for `chat/completions`.
//!
//! Groq renders tool calls as `tool_calls` parts inside a `Content` and
//! tool results as `functionResponse` parts. Pinned to API version
//! `2025-04` (see [`crate::transport::GROQ_API_VERSION`]).

use serde::{Deserialize, Serialize};

/// Function-call part emitted on the model turn.
///
/// Wire shape:
///
/// ```json
/// { "functionCall": { "name": "...", "args": { ... } } }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionCallPart {
    /// Tool name registered on the request `tools.functionDeclarations`.
    pub name: String,
    /// JSON arguments object the model wants the tool invoked with.
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

/// Function-response part fed back to Groq on the next user turn.
///
/// Wire shape:
///
/// ```json
/// { "functionResponse": { "name": "...", "response": { ... } } }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionResponsePart {
    /// Function name matching [`FunctionCallPart::name`].
    pub name: String,
    /// JSON object Groq consumes as the tool result.
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
