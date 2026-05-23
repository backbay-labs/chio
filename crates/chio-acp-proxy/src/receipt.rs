use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

/// How strongly an ACP audit entry is tied to live capability enforcement.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AcpEnforcementMode {
    /// The proxy only observed the event; no live cryptographic enforcement
    /// context was attached.
    AuditOnly,
    /// A live capability check allowed the operation before the event was
    /// forwarded.
    CryptographicallyEnforced,
}

/// Session-scoped capability context captured from a live ACP access check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AcpCapabilityAuditContext {
    pub capability_id: String,
    pub enforcement_mode: AcpEnforcementMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_request_id: Option<String>,
}

/// Generates unsigned audit entries from ACP tool-call events.
///
/// These are **not** signed Chio receipts (`ChioReceipt`). They are
/// structured audit log entries that capture tool-call metadata,
/// a content hash, a timestamp, and the server identity. A downstream
/// component with access to the signing key can promote them into
/// fully signed Chio receipts when needed.
#[derive(Debug, Clone)]
pub struct ReceiptLogger {
    server_id: String,
}

/// An unsigned audit entry produced for an observed ACP tool-call event.
///
/// This is intentionally distinct from a signed `ChioReceipt`. The
/// proxy does not hold private key material; it records the event
/// with a content hash so that a signing service can attest to it
/// later without re-parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcpToolCallAuditEntry {
    pub tool_call_id: String,
    pub title: String,
    pub kind: Option<String>,
    pub status: String,
    pub session_id: String,
    /// Seconds since the Unix epoch (UTC).
    pub timestamp: String,
    pub server_id: String,
    /// SHA-256 hex digest of the canonical JSON representation of
    /// the originating tool-call event.
    pub content_hash: String,
    /// The capability ID that authorized the live operation, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    /// The authoritative Chio receipt emitted during the live authorization check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_receipt_id: Option<String>,
    /// Kernel request id that produced `authorization_receipt_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_request_id: Option<String>,
    /// Whether the event was tied to live cryptographic enforcement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement_mode: Option<AcpEnforcementMode>,
}

impl ReceiptLogger {
    /// Create a logger that tags audit entries with the given server ID.
    pub fn new(server_id: impl Into<String>) -> Self {
        Self {
            server_id: server_id.into(),
        }
    }

    /// Generate an audit entry for a new tool-call event.
    pub fn log_tool_call(
        &self,
        session_id: &str,
        event: &ToolCallEvent,
        capability_context: Option<&AcpCapabilityAuditContext>,
    ) -> AcpToolCallAuditEntry {
        let content_hash = compute_content_hash(event);
        let mut entry = AcpToolCallAuditEntry {
            tool_call_id: event.tool_call_id.clone(),
            title: event.title.clone().unwrap_or_default(),
            kind: event.kind.clone(),
            status: event
                .status
                .clone()
                .unwrap_or_else(|| "started".to_string()),
            session_id: session_id.to_string(),
            timestamp: now_unix_secs(),
            server_id: self.server_id.clone(),
            content_hash,
            capability_id: None,
            authorization_receipt_id: None,
            authorization_request_id: None,
            enforcement_mode: Some(AcpEnforcementMode::AuditOnly),
        };
        apply_capability_context(&mut entry, capability_context);
        entry
    }

    /// Optionally generate an audit entry for a tool-call update event.
    ///
    /// Returns `Some` only when the update carries a status change.
    pub fn log_tool_call_update(
        &self,
        session_id: &str,
        event: &ToolCallUpdateEvent,
        capability_context: Option<&AcpCapabilityAuditContext>,
    ) -> Option<AcpToolCallAuditEntry> {
        let status = event.status.as_deref()?;
        let content_hash = compute_update_content_hash(event);
        let mut entry = AcpToolCallAuditEntry {
            tool_call_id: event.tool_call_id.clone(),
            title: String::new(),
            kind: None,
            status: status.to_string(),
            session_id: session_id.to_string(),
            timestamp: now_unix_secs(),
            server_id: self.server_id.clone(),
            content_hash,
            capability_id: None,
            authorization_receipt_id: None,
            authorization_request_id: None,
            enforcement_mode: Some(AcpEnforcementMode::AuditOnly),
        };
        apply_capability_context(&mut entry, capability_context);
        Some(entry)
    }
}

fn apply_capability_context(
    entry: &mut AcpToolCallAuditEntry,
    capability_context: Option<&AcpCapabilityAuditContext>,
) {
    if let Some(context) = capability_context {
        entry.capability_id = Some(context.capability_id.clone());
        entry.authorization_receipt_id = context.authorization_receipt_id.clone();
        entry.authorization_request_id = context.authorization_request_id.clone();
        entry.enforcement_mode = Some(context.enforcement_mode);
    }
}

/// Return the current time as seconds since the Unix epoch (UTC).
fn now_unix_secs() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    format!("{secs}")
}

/// Compute a SHA-256 hex digest of a `ToolCallEvent` serialized as JSON.
fn compute_content_hash(event: &ToolCallEvent) -> String {
    let json = serde_json::to_string(event).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let result = hasher.finalize();
    hex_encode(&result)
}

/// Compute a SHA-256 hex digest of a `ToolCallUpdateEvent` serialized as JSON.
fn compute_update_content_hash(event: &ToolCallUpdateEvent) -> String {
    let json = serde_json::to_string(event).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let result = hasher.finalize();
    hex_encode(&result)
}

/// Encode a byte slice as lowercase hex.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}
