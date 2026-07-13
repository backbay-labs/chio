//! Host-guest ABI for WASM guard invocation.
//!
//! This module defines the data types that cross the WASM boundary and the
//! trait that any WASM runtime backend must implement.

use serde::{Deserialize, Serialize};

use crate::error::WasmGuardError;

// ---------------------------------------------------------------------------
// ABI constants
// ---------------------------------------------------------------------------

/// Return code from the guest `evaluate` function indicating "allow".
pub const VERDICT_ALLOW: i32 = 0;

/// Return code from the guest `evaluate` function indicating "deny".
pub const VERDICT_DENY: i32 = 1;

// ---------------------------------------------------------------------------
// Data types exchanged across the WASM boundary
// ---------------------------------------------------------------------------

/// Read-only request context passed to the WASM guard.
///
/// This is serialized as JSON and written into guest linear memory before
/// calling `evaluate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// One of: "file_access", "file_write", "network_egress", "shell_command",
    /// "mcp_tool", "patch", "unknown".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,
    /// Normalized file path for filesystem actions (FileAccess, FileWrite, Patch).
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

/// Verdict returned by a WASM guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardVerdict {
    /// The guard allows the request.
    Allow,
    /// The guard denies the request with an optional reason.
    Deny { reason: Option<String> },
}

impl GuardVerdict {
    /// Returns `true` if the verdict allows the request.
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns `true` if the verdict denies the request.
    #[must_use]
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

// ---------------------------------------------------------------------------
// Backend trait
// ---------------------------------------------------------------------------

/// Trait that abstracts the WASM runtime engine.
///
/// Implementors load a `.wasm` module, instantiate it with fuel metering,
/// and execute the guest `evaluate` function.
pub trait WasmGuardAbi: Send + Sync {
    /// Load a WASM module from raw bytes.
    ///
    /// The `fuel_limit` controls the maximum number of fuel units the guest
    /// may consume before the runtime terminates it. The caller denies the
    /// resulting error for blocking guards; advisory guards remain non-blocking.
    fn load_module(&mut self, wasm_bytes: &[u8], fuel_limit: u64) -> Result<(), WasmGuardError>;

    /// Invoke the loaded guard with the given request.
    ///
    /// Returns the guard's verdict. If the guest traps, runs out of fuel,
    /// or returns an unexpected value, the implementation must return
    /// `Err(WasmGuardError)`. The caller treats the invocation as denied for a
    /// blocking guard and as allowed for an explicitly advisory guard.
    fn evaluate(&mut self, request: &GuardRequest) -> Result<GuardVerdict, WasmGuardError>;

    /// Return the name of the runtime backend (e.g. "wasmtime", "mock").
    fn backend_name(&self) -> &str;

    /// Return fuel consumed during the last `evaluate()` call, if tracked.
    ///
    /// Backends that support fuel metering (e.g. Wasmtime) return
    /// `Some(consumed)` after each evaluation. Backends without fuel
    /// tracking (e.g. mock) return `None`.
    fn last_fuel_consumed(&self) -> Option<u64> {
        None
    }

    /// Drop cached pre-instantiation state after a reload publishes a new
    /// module epoch.
    fn clear_instance_pre_cache(&mut self) {}
}

// ---------------------------------------------------------------------------
// Guest-side deny reason protocol
// ---------------------------------------------------------------------------

/// Structured deny response optionally written by the guest into shared memory.
///
/// The guest may write this as JSON starting at offset 0 in a designated
/// "deny_reason" exported memory region. If the region is absent or the
/// JSON is malformed, the host uses a generic denial message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestDenyResponse {
    /// Human-readable reason for the denial.
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_request_serializes_with_enrichment() {
        let req = GuardRequest {
            tool_name: "read_file".to_string(),
            server_id: "fs-server".to_string(),
            agent_id: "agent-42".to_string(),
            arguments: serde_json::json!({"path": "/etc/passwd"}),
            scopes: vec!["fs-server:read_file".to_string()],
            action_type: Some("file_access".to_string()),
            extracted_path: Some("/etc/passwd".to_string()),
            extracted_target: None,
            filesystem_roots: vec!["/home".to_string(), "/tmp".to_string()],
            matched_grant_index: Some(0),
        };

        let json: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(json["action_type"], "file_access");
        assert_eq!(json["extracted_path"], "/etc/passwd");
        assert!(
            json.get("extracted_target").is_none(),
            "None fields with skip_serializing_if should be absent"
        );
        assert_eq!(json["filesystem_roots"][0], "/home");
        assert_eq!(json["filesystem_roots"][1], "/tmp");
        assert_eq!(json["matched_grant_index"], 0);
    }

    #[test]
    fn guard_request_deserializes_without_enrichment() {
        // JSON with only the original 5 fields (no enrichment)
        let json = serde_json::json!({
            "tool_name": "test_tool",
            "server_id": "test_server",
            "agent_id": "agent-1",
            "arguments": {"key": "value"},
            "scopes": ["test_server:test_tool"]
        });

        let req: GuardRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.tool_name, "test_tool");
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
    fn guard_request_no_session_metadata() {
        // This test proves session_metadata field is gone.
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
        // Serialize and verify no session_metadata key
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            !json.contains("session_metadata"),
            "session_metadata should not appear in serialized output"
        );
    }
}
