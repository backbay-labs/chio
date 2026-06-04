//! Example guard: tool-name-based allow/deny.
//!
//! Demonstrates GEXM-01: basic tool name inspection using the SDK.
//! Allows all tools except those on a deny list.

use chio_guard_sdk::prelude::*;
use chio_guard_sdk_macros::chio_guard;

const BLOCKED_TOOLS: &[&str] = &["dangerous_tool", "rm_rf", "drop_database"];
const BLOCKED_REASON: &str = "tool is blocked by policy";
const INVALID_TOOL_NAME_REASON: &str = "tool name is empty or not canonical";

#[chio_guard]
fn evaluate(req: GuardRequest) -> GuardVerdict {
    verdict_for_request(&req)
}

fn verdict_for_request(req: &GuardRequest) -> GuardVerdict {
    match decide_tool_name(req.tool_name.as_str()) {
        ToolGateDecision::Allow => GuardVerdict::allow(),
        ToolGateDecision::Deny { reason } => GuardVerdict::deny(reason),
    }
}

fn decide_tool_name(tool_name: &str) -> ToolGateDecision {
    let trimmed = tool_name.trim();
    if trimmed.is_empty() || trimmed != tool_name {
        return ToolGateDecision::Deny {
            reason: INVALID_TOOL_NAME_REASON,
        };
    }
    if BLOCKED_TOOLS.contains(&tool_name) {
        return ToolGateDecision::Deny {
            reason: BLOCKED_REASON,
        };
    }
    ToolGateDecision::Allow
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolGateDecision {
    Allow,
    Deny { reason: &'static str },
}

#[cfg(test)]
mod tests {
    use super::{
        decide_tool_name, verdict_for_request, ToolGateDecision, BLOCKED_REASON,
        INVALID_TOOL_NAME_REASON,
    };
    use chio_guard_sdk::prelude::*;

    fn request(tool_name: &str) -> GuardRequest {
        GuardRequest {
            tool_name: tool_name.to_string(),
            server_id: "test-server".to_string(),
            agent_id: "test-agent".to_string(),
            arguments: serde_json::json!({}),
            scopes: vec![],
            action_type: None,
            extracted_path: None,
            extracted_target: None,
            filesystem_roots: vec![],
            matched_grant_index: None,
        }
    }

    #[test]
    fn policy_allows_exact_safe_tool_names() {
        assert_eq!(decide_tool_name("read_file"), ToolGateDecision::Allow);
        assert_eq!(decide_tool_name("safe_tool"), ToolGateDecision::Allow);
    }

    #[test]
    fn policy_denies_exact_blocked_tool_names() {
        assert_eq!(
            decide_tool_name("dangerous_tool"),
            ToolGateDecision::Deny {
                reason: BLOCKED_REASON
            }
        );
        assert_eq!(
            decide_tool_name("rm_rf"),
            ToolGateDecision::Deny {
                reason: BLOCKED_REASON
            }
        );
        assert_eq!(
            decide_tool_name("drop_database"),
            ToolGateDecision::Deny {
                reason: BLOCKED_REASON
            }
        );
    }

    #[test]
    fn policy_rejects_empty_or_padded_tool_names() {
        assert_eq!(
            decide_tool_name(""),
            ToolGateDecision::Deny {
                reason: INVALID_TOOL_NAME_REASON
            }
        );
        assert_eq!(
            decide_tool_name(" dangerous_tool "),
            ToolGateDecision::Deny {
                reason: INVALID_TOOL_NAME_REASON
            }
        );
        assert_eq!(
            decide_tool_name(" safe_tool "),
            ToolGateDecision::Deny {
                reason: INVALID_TOOL_NAME_REASON
            }
        );
    }

    #[test]
    fn verdict_for_request_uses_policy_decision() {
        assert!(matches!(
            verdict_for_request(&request("read_file")),
            GuardVerdict::Allow
        ));
        assert!(matches!(
            verdict_for_request(&request("dangerous_tool")),
            GuardVerdict::Deny { reason } if reason == BLOCKED_REASON
        ));
        assert!(matches!(
            verdict_for_request(&request(" read_file")),
            GuardVerdict::Deny { reason } if reason == INVALID_TOOL_NAME_REASON
        ));
    }
}
