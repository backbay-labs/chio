//! Shared HTTP substrate response types.

use chio_kernel::SignedExecutionNonce;
use serde::{Deserialize, Serialize};

use crate::{GuardEvidence, HttpReceipt, Verdict};

/// Response body for sidecar HTTP request evaluation.
///
/// On an `Allow` verdict from a kernel configured with
/// `ExecutionNonceConfig`, the response carries a short-lived signed nonce
/// that the client MUST re-present as `ToolCallRequest::execution_nonce`
/// before executing the tool call. In strict mode, nonce preflight responses
/// carry `Verdict::Incomplete` plus this field; callers must retry with the
/// nonce before any side effect is authorized. The field is `None` on
/// `Deny`/`Cancel`, on deployments without a nonce config, and on advisory
/// sidecar aliases that do not perform kernel dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateResponse {
    pub verdict: Verdict,
    pub receipt: HttpReceipt,
    #[serde(default)]
    pub evidence: Vec<GuardEvidence>,
    /// Optional signed execution nonce. Present only when the kernel
    /// issues one (allow verdict + strict/opt-in nonce mode). See
    /// `docs/protocols/STRUCTURAL-SECURITY-FIXES.md` section 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_nonce: Option<SignedExecutionNonce>,
}

/// Response body for receipt verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReceiptResponse {
    pub signature_valid: bool,
    pub signer_trusted: bool,
    pub receipt_id_valid: bool,
    pub parameter_hash_valid: bool,
    pub receipt_kind: String,
    pub boundary_class: String,
    pub trust_level: String,
    pub result: String,
    pub authorized: bool,
    pub signer_key_hex: String,
    pub ok: bool,
}

impl VerifyReceiptResponse {
    #[must_use]
    pub fn from_http_receipt(receipt: &HttpReceipt, signer_trusted: bool) -> Self {
        let signature_valid = receipt.verify_signature().unwrap_or(false);
        let receipt_id_valid = receipt.receipt_id_valid().unwrap_or(false);
        let parameter_hash_valid = is_lower_hex_64(&receipt.content_hash);
        let semantic_valid = receipt.receipt_kind
            == chio_core_types::receipt::kinds::ReceiptKind::MediatedDecision
            && receipt.boundary_class == chio_core_types::receipt::kinds::BoundaryClass::Prevent
            && receipt.observation_outcome.is_none()
            && receipt.trust_level == chio_core_types::receipt::kinds::TrustLevel::Mediated;
        let ok = signature_valid
            && signer_trusted
            && receipt_id_valid
            && parameter_hash_valid
            && semantic_valid;
        let authorized = ok && receipt.verdict.is_allowed();

        Self {
            signature_valid,
            signer_trusted,
            receipt_id_valid,
            parameter_hash_valid,
            receipt_kind: receipt.receipt_kind.as_str().to_string(),
            boundary_class: receipt.boundary_class.as_str().to_string(),
            trust_level: receipt.trust_level.as_str().to_string(),
            result: verdict_result(&receipt.verdict).to_string(),
            authorized,
            signer_key_hex: receipt.kernel_key.to_hex(),
            ok,
        }
    }
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn verdict_result(verdict: &Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "allow",
        Verdict::Deny { .. } => "deny",
        Verdict::Cancel { .. } => "cancelled",
        Verdict::Incomplete { .. } => "incomplete",
    }
}

/// Sidecar health states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SidecarStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Response body for sidecar health checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: SidecarStatus,
    pub version: String,
    /// Backend of the embedded kernel's receipt log ("durable" or "ephemeral").
    #[serde(default)]
    pub receipt_backend: String,
    /// Backend of the embedded kernel's revocation state ("durable", "remote",
    /// or "ephemeral").
    #[serde(default)]
    pub revocation_backend: String,
}
