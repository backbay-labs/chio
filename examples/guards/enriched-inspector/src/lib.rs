//! Example guard: enriched field inspection + host functions.
//!
//! Demonstrates GEXM-02 (reading action_type and extracted_path)
//! and GEXM-03 (calling chio::log and chio::get_config host functions).
//!
//! Policy: blocks file_write actions to /etc (or a configurable
//! blocked_path from guard config). Allows everything else.

use chio_guard_sdk::prelude::*;
use chio_guard_sdk_macros::chio_guard;

const CONFIG_BLOCKED_PATH_KEY: &str = "blocked_path";
const DEFAULT_BLOCKED_PATH: &str = "/etc";
const PROTECTED_PATH_REASON: &str = "write to protected path blocked by policy";
const DEFAULT_PATH_REASON: &str = "write to /etc blocked";
const INVALID_ACTION_TYPE_REASON: &str = "action_type is empty or not canonical";
const MISSING_WRITE_PATH_REASON: &str = "file_write missing normalized path evidence";
const INVALID_WRITE_PATH_REASON: &str = "file_write path evidence is not normalized";
const INVALID_CONFIG_REASON: &str = "blocked_path config is empty or not normalized";

#[chio_guard]
fn evaluate(req: GuardRequest) -> GuardVerdict {
    // GEXM-03: Use host functions
    log(log_level::INFO, "enriched inspector evaluating request");

    let blocked_path = get_config(CONFIG_BLOCKED_PATH_KEY);

    verdict_for_request(&req, blocked_path.as_deref())
}

fn verdict_for_request(req: &GuardRequest, configured_blocked_path: Option<&str>) -> GuardVerdict {
    match decide_request(req, configured_blocked_path) {
        EnrichedInspectorDecision::Allow => GuardVerdict::allow(),
        EnrichedInspectorDecision::Deny { reason } => GuardVerdict::deny(reason),
    }
}

fn decide_request(
    req: &GuardRequest,
    configured_blocked_path: Option<&str>,
) -> EnrichedInspectorDecision {
    let Some(action_type) = req.action_type.as_deref() else {
        return EnrichedInspectorDecision::Allow;
    };
    let Some(action_type) = canonical_action_type(action_type) else {
        return EnrichedInspectorDecision::Deny {
            reason: INVALID_ACTION_TYPE_REASON,
        };
    };
    if action_type != "file_write" {
        return EnrichedInspectorDecision::Allow;
    }

    let Some(path) = req.extracted_path.as_deref() else {
        return EnrichedInspectorDecision::Deny {
            reason: MISSING_WRITE_PATH_REASON,
        };
    };
    if !is_normalized_absolute_path(path) {
        return EnrichedInspectorDecision::Deny {
            reason: INVALID_WRITE_PATH_REASON,
        };
    }

    if let Some(root) = configured_blocked_path {
        let Some(root) = normalized_blocked_root(root) else {
            return EnrichedInspectorDecision::Deny {
                reason: INVALID_CONFIG_REASON,
            };
        };
        if path_is_under(path, root) {
            return EnrichedInspectorDecision::Deny {
                reason: PROTECTED_PATH_REASON,
            };
        }
    }

    if path_is_under(path, DEFAULT_BLOCKED_PATH) {
        return EnrichedInspectorDecision::Deny {
            reason: DEFAULT_PATH_REASON,
        };
    }

    EnrichedInspectorDecision::Allow
}

fn canonical_action_type(action_type: &str) -> Option<&str> {
    if action_type.is_empty() || action_type.trim() != action_type {
        return None;
    }
    Some(action_type)
}

fn normalized_blocked_root(root: &str) -> Option<&str> {
    if root == "/" {
        return Some(root);
    }
    let root = root.trim_end_matches('/');
    if is_normalized_absolute_path(root) {
        Some(root)
    } else {
        None
    }
}

fn is_normalized_absolute_path(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    if !path.starts_with('/') {
        return false;
    }
    path.split('/')
        .skip(1)
        .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn path_is_under(path: &str, root: &str) -> bool {
    if root == "/" {
        return path.starts_with('/');
    }
    let root = root.trim_end_matches('/');
    if root.is_empty() {
        return false;
    }
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_action_type, decide_request, is_normalized_absolute_path,
        normalized_blocked_root, path_is_under, verdict_for_request, EnrichedInspectorDecision,
        DEFAULT_PATH_REASON, INVALID_ACTION_TYPE_REASON, INVALID_CONFIG_REASON,
        INVALID_WRITE_PATH_REASON, MISSING_WRITE_PATH_REASON, PROTECTED_PATH_REASON,
    };
    use chio_guard_sdk::prelude::*;

    fn request(action_type: Option<&str>, extracted_path: Option<&str>) -> GuardRequest {
        GuardRequest {
            tool_name: "write_file".to_string(),
            server_id: "test-server".to_string(),
            agent_id: "test-agent".to_string(),
            arguments: serde_json::json!({}),
            scopes: vec![],
            action_type: action_type.map(String::from),
            extracted_path: extracted_path.map(String::from),
            extracted_target: None,
            filesystem_roots: vec![],
            matched_grant_index: None,
        }
    }

    #[test]
    fn path_is_under_respects_segment_boundaries() {
        assert!(path_is_under("/etc", "/etc"));
        assert!(path_is_under("/etc/passwd", "/etc"));
        assert!(!path_is_under("/etcetera/passwd", "/etc"));
        assert!(path_is_under("/var/secret/key", "/var/secret/"));
        assert!(!path_is_under("/var/secrets/key", "/var/secret/"));
    }

    #[test]
    fn normalized_path_requires_absolute_non_dot_components() {
        assert!(is_normalized_absolute_path("/"));
        assert!(is_normalized_absolute_path("/etc/passwd"));
        assert!(!is_normalized_absolute_path(""));
        assert!(!is_normalized_absolute_path("etc/passwd"));
        assert!(!is_normalized_absolute_path("/etc/../passwd"));
        assert!(!is_normalized_absolute_path("/etc/./passwd"));
        assert!(!is_normalized_absolute_path("/etc//passwd"));
    }

    #[test]
    fn configured_root_accepts_trailing_slash_only_after_validation() {
        assert_eq!(normalized_blocked_root("/var/secret/"), Some("/var/secret"));
        assert_eq!(normalized_blocked_root("/"), Some("/"));
        assert_eq!(normalized_blocked_root(""), None);
        assert_eq!(normalized_blocked_root("var/secret"), None);
        assert_eq!(normalized_blocked_root("/var/../secret"), None);
    }

    #[test]
    fn action_type_must_be_canonical_when_present() {
        assert_eq!(canonical_action_type("file_write"), Some("file_write"));
        assert_eq!(canonical_action_type(""), None);
        assert_eq!(canonical_action_type(" file_write"), None);
        assert_eq!(canonical_action_type("file_write "), None);
    }

    #[test]
    fn policy_allows_missing_action_type_and_non_write_actions() {
        assert_eq!(
            decide_request(&request(None, None), None),
            EnrichedInspectorDecision::Allow
        );
        assert_eq!(
            decide_request(&request(Some("file_access"), Some("/etc/passwd")), None),
            EnrichedInspectorDecision::Allow
        );
    }

    #[test]
    fn policy_rejects_malformed_enriched_write_evidence() {
        assert_eq!(
            decide_request(&request(Some(" file_write"), Some("/etc/passwd")), None),
            EnrichedInspectorDecision::Deny {
                reason: INVALID_ACTION_TYPE_REASON
            }
        );
        assert_eq!(
            decide_request(&request(Some("file_write"), None), None),
            EnrichedInspectorDecision::Deny {
                reason: MISSING_WRITE_PATH_REASON
            }
        );
        assert_eq!(
            decide_request(&request(Some("file_write"), Some("etc/passwd")), None),
            EnrichedInspectorDecision::Deny {
                reason: INVALID_WRITE_PATH_REASON
            }
        );
    }

    #[test]
    fn policy_applies_configured_root_before_default_root() {
        assert_eq!(
            decide_request(
                &request(Some("file_write"), Some("/var/secret/key.pem")),
                Some("/var/secret/")
            ),
            EnrichedInspectorDecision::Deny {
                reason: PROTECTED_PATH_REASON
            }
        );
        assert_eq!(
            decide_request(
                &request(Some("file_write"), Some("/var/secrets/key.pem")),
                Some("/var/secret/")
            ),
            EnrichedInspectorDecision::Allow
        );
    }

    #[test]
    fn policy_fails_closed_on_malformed_configured_root() {
        assert_eq!(
            decide_request(
                &request(Some("file_write"), Some("/tmp/output.txt")),
                Some("var/secret")
            ),
            EnrichedInspectorDecision::Deny {
                reason: INVALID_CONFIG_REASON
            }
        );
    }

    #[test]
    fn policy_denies_default_root_with_segment_boundary() {
        assert_eq!(
            decide_request(&request(Some("file_write"), Some("/etc/passwd")), None),
            EnrichedInspectorDecision::Deny {
                reason: DEFAULT_PATH_REASON
            }
        );
        assert_eq!(
            decide_request(&request(Some("file_write"), Some("/etcetera/passwd")), None),
            EnrichedInspectorDecision::Allow
        );
    }

    #[test]
    fn verdict_for_request_uses_policy_decision() {
        assert!(matches!(
            verdict_for_request(&request(Some("file_write"), Some("/tmp/out.txt")), None),
            GuardVerdict::Allow
        ));
        assert!(matches!(
            verdict_for_request(&request(Some("file_write"), None), None),
            GuardVerdict::Deny { reason } if reason == MISSING_WRITE_PATH_REASON
        ));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnrichedInspectorDecision {
    Allow,
    Deny { reason: &'static str },
}
