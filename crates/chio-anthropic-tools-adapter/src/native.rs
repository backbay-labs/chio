//! Anthropic-native content-block types.
//!
//! These mirror the wire shapes documented in the Anthropic Messages API
//! reference (`messages.create` request and response bodies, version
//! `2023-06-01`). The fabric never inspects native bytes directly: T2 lifts
//! a [`ToolUseBlock`] into a [`chio_tool_call_fabric::ToolInvocation`] and
//! T3 lowers a [`chio_tool_call_fabric::VerdictResult`] back into a
//! [`ToolResultBlock`] for the next request.
//!
//! T1 ships only the structural shapes; the lift/lower implementations
//! land in T2.
//!
//! ## Server-tool variants
//!
//! [`ServerToolName`] and [`server_tools_allowed`] are gated behind the
//! `computer-use` cargo feature. Default builds compile without them so
//! production traffic cannot accidentally request a beta server tool. T4
//! adds the matching `chio-manifest` `server_tools` allowlist that the
//! adapter consults at lift time.

use serde::{Deserialize, Serialize};

/// Tool-use block emitted by Anthropic on the assistant turn.
///
/// Wire shape (from `messages.create` response):
///
/// ```json
/// { "type": "tool_use", "id": "toolu_01...", "name": "...", "input": { ... } }
/// ```
///
/// `id` becomes [`chio_tool_call_fabric::ProvenanceStamp::request_id`] when
/// T2 lifts the block. `input` is the canonical-JSON arguments object the
/// kernel evaluates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolUseBlock {
    /// Block discriminator. Always `"tool_use"`.
    #[serde(rename = "type")]
    pub block_type: String,
    /// Anthropic-issued tool-use identifier (e.g. `toolu_01ABC...`).
    pub id: String,
    /// Tool name registered on the assistant manifest.
    pub name: String,
    /// JSON arguments object the model wants the tool invoked with.
    pub input: serde_json::Value,
}

impl ToolUseBlock {
    /// Construct a freshly-typed tool-use block.
    ///
    /// T1 helper used by tests; T2 will use it from the lift implementation.
    pub fn new(id: impl Into<String>, name: impl Into<String>, input: serde_json::Value) -> Self {
        Self {
            block_type: "tool_use".to_string(),
            id: id.into(),
            name: name.into(),
            input,
        }
    }
}

/// Tool-result block returned to Anthropic on the next user turn.
///
/// Wire shape (from `messages.create` request, content blocks of role `user`):
///
/// ```json
/// { "type": "tool_result", "tool_use_id": "toolu_01...", "content": [...], "is_error": false }
/// ```
///
/// T2 builds these from the kernel verdict and the executed tool result;
/// `is_error: true` carries the deny reason on the deny path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolResultBlock {
    /// Block discriminator. Always `"tool_result"`.
    #[serde(rename = "type")]
    pub block_type: String,
    /// Identifier from the matching [`ToolUseBlock::id`].
    pub tool_use_id: String,
    /// Content blocks (text / image / etc.) returned to the model.
    pub content: serde_json::Value,
    /// `true` when the kernel denied the call or execution failed.
    #[serde(default)]
    pub is_error: bool,
}

impl ToolResultBlock {
    /// Construct an `Allow`-path tool result.
    pub fn allow(tool_use_id: impl Into<String>, content: serde_json::Value) -> Self {
        Self {
            block_type: "tool_result".to_string(),
            tool_use_id: tool_use_id.into(),
            content,
            is_error: false,
        }
    }

    /// Construct a `Deny`-path tool result. Carries `is_error: true` and a
    /// content payload describing the deny reason; T2 fills in the exact
    /// text from [`chio_tool_call_fabric::DenyReason`].
    pub fn deny(tool_use_id: impl Into<String>, content: serde_json::Value) -> Self {
        Self {
            block_type: "tool_result".to_string(),
            tool_use_id: tool_use_id.into(),
            content,
            is_error: true,
        }
    }
}

/// Anthropic server-tool catalog (computer-use beta).
///
/// Default builds do not compile this enum. Enabling the `computer-use`
/// cargo feature exposes the three server-tool names that ship under the
/// `anthropic-beta: computer-use-2025-01-24` header. The corresponding
/// [`ToolUseBlock::name`] strings are the exact wire identifiers Anthropic
/// uses; lifting any of them in T2 requires the operator's manifest to
/// list the tool in its `server_tools` allowlist (T4).
#[cfg(feature = "computer-use")]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServerToolName {
    /// `computer_use_20241022`. Screen capture, mouse, keyboard.
    #[serde(rename = "computer_use_20241022")]
    ComputerUse20241022,
    /// `bash_20241022`. Shell access via the Anthropic-managed sandbox.
    #[serde(rename = "bash_20241022")]
    Bash20241022,
    /// `text_editor_20241022`. Filesystem text-edit operations.
    #[serde(rename = "text_editor_20241022")]
    TextEditor20241022,
}

#[cfg(feature = "computer-use")]
impl ServerToolName {
    /// Wire identifier emitted on the Anthropic Messages payload.
    pub fn wire_name(&self) -> &'static str {
        match self {
            ServerToolName::ComputerUse20241022 => "computer_use_20241022",
            ServerToolName::Bash20241022 => "bash_20241022",
            ServerToolName::TextEditor20241022 => "text_editor_20241022",
        }
    }
}

/// Constant catalog of every server-tool wire name the beta surface
/// supports. Available only under the `computer-use` feature so default
/// builds neither know about nor index into the array.
#[cfg(feature = "computer-use")]
pub const SERVER_TOOL_WIRE_NAMES: &[&str] = &[
    "computer_use_20241022",
    "bash_20241022",
    "text_editor_20241022",
];

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tool_use_block_round_trips() {
        let block = ToolUseBlock::new("toolu_01ABC", "search_web", json!({"query": "chio"}));
        let bytes = serde_json::to_vec(&block).unwrap();
        let back: ToolUseBlock = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(block, back);
        assert_eq!(block.block_type, "tool_use");
    }

    #[test]
    fn tool_result_block_allow_and_deny() {
        let allow = ToolResultBlock::allow("toolu_01ABC", json!([{"type": "text", "text": "ok"}]));
        assert!(!allow.is_error);
        assert_eq!(allow.block_type, "tool_result");

        let deny = ToolResultBlock::deny(
            "toolu_01ABC",
            json!([{"type": "text", "text": "policy_deny: rule_1"}]),
        );
        assert!(deny.is_error);
        assert_eq!(deny.block_type, "tool_result");
    }

    #[test]
    fn tool_result_serialises_is_error() {
        let allow = ToolResultBlock::allow("toolu_01", json!("ok"));
        let s = serde_json::to_string(&allow).unwrap();
        assert!(s.contains("\"is_error\":false"));
        let deny = ToolResultBlock::deny("toolu_01", json!("blocked"));
        let s = serde_json::to_string(&deny).unwrap();
        assert!(s.contains("\"is_error\":true"));
    }

    #[cfg(feature = "computer-use")]
    #[test]
    fn server_tool_wire_names() {
        assert_eq!(
            ServerToolName::ComputerUse20241022.wire_name(),
            "computer_use_20241022"
        );
        assert_eq!(ServerToolName::Bash20241022.wire_name(), "bash_20241022");
        assert_eq!(
            ServerToolName::TextEditor20241022.wire_name(),
            "text_editor_20241022"
        );
        assert_eq!(SERVER_TOOL_WIRE_NAMES.len(), 3);
    }

    #[cfg(feature = "computer-use")]
    #[test]
    fn server_tool_round_trips_serde() {
        let cases = [
            ServerToolName::ComputerUse20241022,
            ServerToolName::Bash20241022,
            ServerToolName::TextEditor20241022,
        ];
        for tool in cases {
            let s = serde_json::to_string(&tool).unwrap();
            let back: ServerToolName = serde_json::from_str(&s).unwrap();
            assert_eq!(tool, back);
        }
    }
}
