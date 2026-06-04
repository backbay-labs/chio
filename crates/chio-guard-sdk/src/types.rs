//! ABI types shared between the WASM guest guard and the Chio host runtime.
//!
//! These types serialize to JSON identically to the host-side types defined in
//! `chio-wasm-guards/src/abi.rs`. Every `#[serde(...)]` annotation must match
//! the host exactly; mismatches cause deserialization failures at runtime.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ABI constants
// ---------------------------------------------------------------------------

/// Return code from the guest `evaluate` function indicating "allow".
pub const VERDICT_ALLOW: i32 = 0;

/// Return code from the guest `evaluate` function indicating "deny".
pub const VERDICT_DENY: i32 = 1;

/// Fallback reason used when a deny verdict supplies only whitespace.
pub const DEFAULT_DENY_REASON: &str = "guard denied request";

pub(crate) fn normalize_deny_reason(reason: impl AsRef<str>) -> String {
    let trimmed = reason.as_ref().trim();
    if trimmed.is_empty() {
        DEFAULT_DENY_REASON.to_owned()
    } else {
        trimmed.to_owned()
    }
}

// ---------------------------------------------------------------------------
// GuardRequest
// ---------------------------------------------------------------------------

/// Read-only request context passed to the WASM guard.
///
/// Serialized as JSON by the host and written into guest linear memory before
/// calling `evaluate`. The field order and serde annotations match the host
/// definition in `chio-wasm-guards/src/abi.rs` exactly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuardRequest {
    /// Tool being invoked.
    pub tool_name: String,
    /// Server hosting the tool.
    pub server_id: String,
    /// Agent making the request.
    pub agent_id: String,
    /// Tool arguments as an opaque JSON value.
    pub arguments: serde_json::Value,
    /// Capability scopes granted (serialized scope names).
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Host-extracted action type from extract_action().
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,
    /// Normalized file path for filesystem actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extracted_path: Option<String>,
    /// Target domain string for network egress actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extracted_target: Option<String>,
    /// Session-scoped filesystem roots from the kernel context.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filesystem_roots: Vec<String>,
    /// Index of the matched grant in the capability scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_grant_index: Option<usize>,
}

// ---------------------------------------------------------------------------
// GuardVerdict
// ---------------------------------------------------------------------------

/// Verdict returned by a guest guard's evaluate function.
///
/// Guest-side `Deny` carries a required `String` reason because a guard that
/// denies should always explain why. The host-side `GuardVerdict::Deny` uses
/// `Option<String>` because the reason may be absent when the guest does not
/// export `chio_deny_reason`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardVerdict {
    /// The guard allows the request.
    Allow,
    /// The guard denies the request with a mandatory reason.
    Deny { reason: String },
}

impl GuardVerdict {
    /// Create an Allow verdict.
    #[must_use]
    pub fn allow() -> Self {
        Self::Allow
    }

    /// Create a Deny verdict with a reason.
    #[must_use]
    pub fn deny(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self::Deny {
            reason: normalize_deny_reason(reason),
        }
    }
}

// ---------------------------------------------------------------------------
// GuestDenyResponse
// ---------------------------------------------------------------------------

/// Structured deny response written by the guest into shared memory.
///
/// The guest serializes this as JSON and returns it via `chio_deny_reason`.
/// The host reads it and extracts the human-readable reason.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestDenyResponse {
    /// Human-readable reason for the denial.
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn verdict_constants_match_host() {
        assert_eq!(VERDICT_ALLOW, 0);
        assert_eq!(VERDICT_DENY, 1);
    }

    #[test]
    fn guard_request_round_trip_all_fields() {
        let req = GuardRequest {
            tool_name: "read_file".to_string(),
            server_id: "fs-server".to_string(),
            agent_id: "agent-42".to_string(),
            arguments: serde_json::json!({"path": "/etc/passwd"}),
            scopes: vec!["fs-server:read_file".to_string()],
            action_type: Some("file_access".to_string()),
            extracted_path: Some("/etc/passwd".to_string()),
            extracted_target: Some("example.com".to_string()),
            filesystem_roots: vec!["/home".to_string(), "/tmp".to_string()],
            matched_grant_index: Some(0),
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: GuardRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.tool_name, req.tool_name);
        assert_eq!(deserialized.server_id, req.server_id);
        assert_eq!(deserialized.agent_id, req.agent_id);
        assert_eq!(deserialized.arguments, req.arguments);
        assert_eq!(deserialized.scopes, req.scopes);
        assert_eq!(deserialized.action_type, req.action_type);
        assert_eq!(deserialized.extracted_path, req.extracted_path);
        assert_eq!(deserialized.extracted_target, req.extracted_target);
        assert_eq!(deserialized.filesystem_roots, req.filesystem_roots);
        assert_eq!(deserialized.matched_grant_index, req.matched_grant_index);
    }

    #[test]
    fn guard_request_defaults_for_optional_fields() {
        let json = serde_json::json!({
            "tool_name": "test_tool",
            "server_id": "test_server",
            "agent_id": "agent-1",
            "arguments": {"key": "value"}
        });

        let req: GuardRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.tool_name, "test_tool");
        assert!(req.scopes.is_empty(), "scopes should default to empty Vec");
        assert!(
            req.action_type.is_none(),
            "action_type should default to None"
        );
        assert!(
            req.extracted_path.is_none(),
            "extracted_path should default to None"
        );
        assert!(
            req.extracted_target.is_none(),
            "extracted_target should default to None"
        );
        assert!(
            req.filesystem_roots.is_empty(),
            "filesystem_roots should default to empty Vec"
        );
        assert!(
            req.matched_grant_index.is_none(),
            "matched_grant_index should default to None"
        );
    }

    #[test]
    fn guard_request_omits_none_and_empty_fields() {
        let req = GuardRequest {
            tool_name: "t".to_string(),
            server_id: "s".to_string(),
            agent_id: "a".to_string(),
            arguments: serde_json::Value::Null,
            scopes: vec![],
            action_type: None,
            extracted_path: None,
            extracted_target: None,
            filesystem_roots: Vec::new(),
            matched_grant_index: None,
        };

        let json = serde_json::to_value(&req).unwrap();
        assert!(
            json.get("action_type").is_none(),
            "None fields should be omitted"
        );
        assert!(
            json.get("extracted_path").is_none(),
            "None fields should be omitted"
        );
        assert!(
            json.get("extracted_target").is_none(),
            "None fields should be omitted"
        );
        assert!(
            json.get("matched_grant_index").is_none(),
            "None fields should be omitted"
        );
        assert!(
            json.get("filesystem_roots").is_none(),
            "Empty Vec should be omitted"
        );
    }

    #[test]
    fn guard_verdict_allow_constructor() {
        let v = GuardVerdict::allow();
        assert!(matches!(v, GuardVerdict::Allow));
    }

    #[test]
    fn guard_verdict_deny_constructor() {
        let v = GuardVerdict::deny("not permitted");
        match v {
            GuardVerdict::Deny { reason } => assert_eq!(reason, "not permitted"),
            GuardVerdict::Allow => panic!("expected Deny"),
        }
    }

    #[test]
    fn guard_verdict_deny_constructor_normalizes_blank_reason() {
        let v = GuardVerdict::deny(" \t\n");
        assert!(matches!(
            v,
            GuardVerdict::Deny { reason } if reason == DEFAULT_DENY_REASON
        ));
    }

    #[test]
    fn guest_deny_response_serializes() {
        let resp = GuestDenyResponse {
            reason: "blocked by policy".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json, serde_json::json!({"reason": "blocked by policy"}));
    }
}
