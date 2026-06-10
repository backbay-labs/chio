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
    /// ACP tool-call id signed into the live authorization receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_correlation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_parameter_hash: Option<String>,
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
    /// ACP tool-call id signed into the live authorization receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_tool_call_id: Option<String>,
    /// Correlation id signed into the live authorization receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_correlation_id: Option<String>,
    /// ACP operation signed into the live authorization receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_operation: Option<String>,
    /// ACP resource signed into the live authorization receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_resource: Option<String>,
    /// Canonical SHA-256 hash of the full authorized ACP parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_parameter_hash: Option<String>,
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
            authorization_tool_call_id: None,
            authorization_correlation_id: None,
            authorization_operation: None,
            authorization_resource: None,
            authorization_parameter_hash: None,
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
            authorization_tool_call_id: None,
            authorization_correlation_id: None,
            authorization_operation: None,
            authorization_resource: None,
            authorization_parameter_hash: None,
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
        entry.authorization_tool_call_id = context.authorization_tool_call_id.clone();
        entry.authorization_correlation_id = context.authorization_correlation_id.clone();
        entry.authorization_operation = context.authorization_operation.clone();
        entry.authorization_resource = context.authorization_resource.clone();
        entry.authorization_parameter_hash = context.authorization_parameter_hash.clone();
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

/// Build a canonical-hash input for a `ToolCallEvent`.
///
/// The returned JSON object contains only the explicit ACP wire fields. The
/// `#[serde(flatten)] extra` map on `ToolCallEvent` is intentionally
/// excluded so that previously-unknown JSON keys cannot silently change the
/// `content_hash` of an event and break downstream `entry.content_hash`
/// comparisons. The full event (including `extra`) is still serialized for
/// wire fidelity by `parse_session_update` and the audit pipeline; only the
/// hash input is restricted.
fn tool_call_event_canonical_hash_input(event: &ToolCallEvent) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert(
        "toolCallId".to_string(),
        serde_json::Value::String(event.tool_call_id.clone()),
    );
    if let Some(title) = &event.title {
        map.insert(
            "title".to_string(),
            serde_json::Value::String(title.clone()),
        );
    }
    if let Some(kind) = &event.kind {
        map.insert("kind".to_string(), serde_json::Value::String(kind.clone()));
    }
    if let Some(status) = &event.status {
        map.insert(
            "status".to_string(),
            serde_json::Value::String(status.clone()),
        );
    }
    serde_json::Value::Object(map)
}

/// Build a canonical-hash input for a `ToolCallUpdateEvent`.
///
/// See `tool_call_event_canonical_hash_input` for the rationale.
fn tool_call_update_event_canonical_hash_input(
    event: &ToolCallUpdateEvent,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert(
        "toolCallId".to_string(),
        serde_json::Value::String(event.tool_call_id.clone()),
    );
    if let Some(status) = &event.status {
        map.insert(
            "status".to_string(),
            serde_json::Value::String(status.clone()),
        );
    }
    serde_json::Value::Object(map)
}

/// Compute a SHA-256 hex digest of a `ToolCallEvent` serialized as canonical JSON.
///
/// Hashes only the explicit ACP wire fields; the `extra` map captured by
/// `#[serde(flatten)]` is excluded so unknown JSON fields cannot silently
/// alter the content hash. See `tool_call_event_canonical_hash_input`.
///
/// # Wire-format compatibility note
///
/// This canonicalization is INTENTIONALLY not backward-compatible with the
/// prior `serde_json::to_string(event)` digest. The v1 receipt wire format
/// is grounded on the canonical JSON pipeline so receipts produced by
/// independent implementations agree on a single content hash for the same
/// logical event. Previously stored receipts computed with the v0
/// (non-canonical) digest will therefore not match a freshly computed v1
/// digest of the same event payload, and
/// `content_hash`-based deduplication or comparability across the
/// v0/v1 boundary is not supported by design. v0 stores must be
/// rebuilt or migrated by re-deriving content hashes from the
/// preserved event payload before being mixed with v1 receipts.
fn compute_content_hash(event: &ToolCallEvent) -> String {
    let canonical_input = tool_call_event_canonical_hash_input(event);
    let json = chio_core::canonical::canonical_json_bytes(&canonical_input).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json.as_slice());
    let result = hasher.finalize();
    hex_encode(&result)
}

/// Compute a SHA-256 hex digest of a `ToolCallUpdateEvent` serialized as canonical JSON.
///
/// Hashes only the explicit ACP wire fields; the `extra` map captured by
/// `#[serde(flatten)]` is excluded. See `tool_call_update_event_canonical_hash_input`.
///
/// See the wire-format compatibility note on `compute_content_hash`:
/// this digest is intentionally v1-only and is not comparable with the
/// v0 `serde_json::to_string` digest. v0/v1 cross-version comparison
/// is not supported by design.
fn compute_update_content_hash(event: &ToolCallUpdateEvent) -> String {
    let canonical_input = tool_call_update_event_canonical_hash_input(event);
    let json = chio_core::canonical::canonical_json_bytes(&canonical_input).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json.as_slice());
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
