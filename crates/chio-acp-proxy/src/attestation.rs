// Attestation traits for ACP proxy kernel integration.
//
// These traits allow optional injection of a receipt signer and
// capability checker into the proxy's message interceptor. When
// present, the proxy produces signed Chio receipts and validates
// capability tokens for file and terminal operations.

use chio_core::receipt::ChioReceipt;

/// Request payload passed to a receipt signer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcpReceiptRequest {
    /// The audit entry to promote into a signed receipt.
    pub audit_entry: AcpToolCallAuditEntry,
    /// The tool server ID to use in the receipt.
    pub tool_server: String,
    /// The tool name to use in the receipt.
    pub tool_name: String,
}

/// Error type for receipt signing failures.
#[derive(Debug, thiserror::Error)]
pub enum ReceiptSignError {
    /// Signing key material is unavailable or corrupted.
    #[error("signing key unavailable: {0}")]
    KeyUnavailable(String),

    /// Canonical serialization of the receipt body failed.
    #[error("serialization failed: {0}")]
    SerializationFailed(String),

    /// The cryptographic signing operation itself failed.
    #[error("signing operation failed: {0}")]
    SigningFailed(String),
}

/// Trait for signing ACP audit entries into full Chio receipts.
///
/// Implementations hold the Ed25519 key material needed to produce
/// signed receipts. The proxy itself never touches private keys
/// directly -- it delegates through this trait.
pub trait ReceiptSigner: Send + Sync {
    /// Sign an ACP audit entry, producing a fully signed Chio receipt.
    fn sign_acp_receipt(
        &self,
        request: &AcpReceiptRequest,
    ) -> Result<ChioReceipt, ReceiptSignError>;
}

/// Request payload passed to a capability checker.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcpCapabilityRequest {
    /// Session ID the operation belongs to.
    pub session_id: String,
    /// ACP tool-call id, when known before the authoritative authorization
    /// receipt is minted. Enforced receipts require this value to be signed
    /// into the authorization context before a later ACP audit entry can be
    /// promoted to mediated/prevent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// Correlates the live authorization receipt with the later ACP audit event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_correlation_id: Option<String>,
    /// The kind of operation being checked: "fs_read", "fs_write", or "terminal".
    pub operation: String,
    /// The resource being accessed (path for fs, command for terminal).
    pub resource: String,
    /// Canonical SHA-256 hash of the full ACP operation parameters.
    pub authorization_parameter_hash: String,
    /// Full ACP operation parameters covered by the live authorization.
    ///
    /// This keeps authorization receipts bound to the actual file or terminal
    /// request payload instead of only a reduced resource string plus hash.
    pub operation_payload: Value,
    /// Optional execution nonce presented by strict nonce-enabled clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_nonce: Option<chio_kernel::SignedExecutionNonce>,
    /// Optional capability token string presented by the agent.
    pub token: Option<String>,
}

/// Verdict from a capability check.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcpVerdict {
    /// Whether access is allowed.
    pub allowed: bool,
    /// The capability ID that authorized access, if any.
    pub capability_id: Option<String>,
    /// The signed authorization receipt emitted by the authoritative check, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    /// Kernel request id that produced `receipt_id`, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_request_id: Option<String>,
    /// Execution nonce returned by a strict-mode authorization preflight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_nonce: Option<chio_kernel::SignedExecutionNonce>,
    /// Human-readable reason for the decision.
    pub reason: String,
}

/// Error type for capability check failures.
#[derive(Debug, thiserror::Error)]
pub enum CapabilityCheckError {
    /// The token was malformed or could not be parsed.
    #[error("invalid token: {0}")]
    InvalidToken(String),

    /// The token's signature could not be verified.
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// The capability has expired.
    #[error("capability expired")]
    Expired,

    /// The capability has been revoked.
    #[error("capability revoked: {0}")]
    Revoked(String),

    /// An internal error prevented the check from completing.
    /// Fail-closed: this results in deny.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Trait for checking capability tokens against ACP operations.
///
/// Implementations validate that the presented token (if any)
/// authorizes the requested file or terminal operation. When no
/// checker is installed, the proxy falls back to its built-in
/// path-prefix and command-allowlist guards.
pub trait CapabilityChecker: Send + Sync {
    /// Check whether the given request is authorized.
    ///
    /// Implementations MUST fail closed: if any error occurs during
    /// validation, the result must be deny.
    fn check_access(
        &self,
        request: &AcpCapabilityRequest,
    ) -> Result<AcpVerdict, CapabilityCheckError>;
}

/// Attestation mode for ACP sessions.
///
/// Controls how the proxy handles receipt signing failures.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcpAttestationMode {
    /// Best-effort: signing failures are logged but do not block operations.
    #[default]
    BestEffort,
    /// Required: signing failures mark the session as non-compliant.
    Required,
}
