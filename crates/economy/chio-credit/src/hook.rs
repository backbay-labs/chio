//! Credit evaluator hook trait routing signed receipts to IOU envelopes.
//!
//! This defines the integration point a kernel evaluator would invoke
//! from its post-dispatch observer slot (the async-kernel observer) to
//! route the `chio-credit` crate into receipt finalization. The hook
//! receives a fully signed [`ChioReceipt`] after
//! receipt finalization and returns either zero or one
//! [`IouEnvelope`]. Fail-closed semantics: signature-invalid or
//! malformed receipts mint nothing.
//!
//! The trait is intentionally minimal so the economic crate owns IOU
//! semantics; a kernel wiring this hook only needs to invoke it on each
//! finalized receipt and stash the result. Persistence is handled
//! by the store binding in [`crate::store_binding`].

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{PublicKey, Signature, SigningAlgorithm};
use crate::receipt::body::ChioReceipt;

/// Schema string emitted on the wire for IOU envelope bodies.
pub const IOU_ENVELOPE_SCHEMA: &str = "chio.credit.iou-envelope.v1";

/// Errors that may arise while evaluating a finalized receipt for IOU
/// minting. Hook errors are fail-closed: callers MUST NOT mint or
/// persist an IOU when an error is returned.
#[derive(Debug, Error)]
pub enum CreditEvaluatorError {
    /// The supplied receipt failed signature verification.
    #[error("receipt signature verification failed for receipt {receipt_id}")]
    SignatureInvalid { receipt_id: String },
    /// The supplied receipt was signed by a kernel key outside the configured trust set.
    #[error("receipt {receipt_id} was signed by untrusted kernel key {kernel_key}")]
    SignerUntrusted {
        receipt_id: String,
        kernel_key: String,
    },
    /// The supplied receipt could not be canonically encoded.
    #[error("canonical encoding failed: {0}")]
    Canonical(String),
    /// The signing backend rejected the IOU body.
    #[error("iou signing failed: {0}")]
    Signing(String),
    /// The financial metadata or pricing context was malformed.
    #[error("invalid pricing context: {0}")]
    PricingContext(String),
}

/// Body of an [`IouEnvelope`], excluding the signature. The body is
/// the signed payload; the signature covers canonical JSON of the
/// body only.
///
/// IOU bodies bind to the originating receipt by `receipt_id` plus
/// the receipt's content/policy hashes so a downstream auditor can
/// confirm the IOU references the same bytes the kernel signed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IouEnvelopeBody {
    /// Schema tag (`chio.credit.iou-envelope.v1`).
    pub schema: String,
    /// Stable identifier for this IOU. Recommended UUIDv7.
    pub iou_id: String,
    /// `id` of the [`ChioReceipt`] that finalized this IOU.
    pub receipt_id: String,
    /// `timestamp` carried over from the originating receipt so the
    /// IOU lifecycle entry can sort by issuance time without joining
    /// against the receipt store.
    pub receipt_timestamp: u64,
    /// Cluster operator (tenant) that owes the obligation, or `None`
    /// for single-tenant deployments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Tool server that was invoked. Carried over from the receipt
    /// for cheap denormalised queries.
    pub tool_server: String,
    /// Tool that was invoked.
    pub tool_name: String,
    /// Capability id from the receipt.
    pub capability_id: String,
    /// Cost charged in currency minor units (e.g. USD cents). Always
    /// strictly greater than zero. Zero-price receipts skip IOU
    /// minting entirely.
    pub amount_units: u64,
    /// ISO 4217 currency code.
    pub currency: String,
    /// Issuer public key, expected to match the kernel signing
    /// identity that produced the underlying receipt.
    pub issuer_key: PublicKey,
}

/// Signed IOU envelope. Produced by [`CreditEvaluatorHook::evaluate`]
/// after a finalized receipt is observed, and persisted by the
/// store binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IouEnvelope {
    /// Body that was signed.
    #[serde(flatten)]
    pub body: IouEnvelopeBody,
    /// Signing algorithm used for `signature`; absent defaults to Ed25519.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<SigningAlgorithm>,
    /// Detached signature over canonical JSON of `body`.
    pub signature: Signature,
}

impl IouEnvelope {
    /// Verify the IOU envelope signature against the embedded issuer
    /// key. Returns `Ok(true)` when the signature is valid.
    pub fn verify_signature(&self) -> Result<bool, CreditEvaluatorError> {
        self.body
            .issuer_key
            .verify_canonical(&self.body, &self.signature)
            .map_err(|err| CreditEvaluatorError::Canonical(err.to_string()))
    }
}

/// Hook routing signed finalized receipts into IOU envelopes.
///
/// Implementations MUST:
///
/// - Return `Ok(None)` for receipts whose decision is not `Allow`,
///   for receipts without manifest pricing context, or for
///   zero-price receipts.
/// - Return `Err(CreditEvaluatorError::SignatureInvalid)` if the
///   receipt's signature does not verify against its embedded
///   kernel key.
/// - Never mutate the supplied receipt.
///
/// The trait is dyn-compatible so kernel observer slots can hold a
/// `&dyn CreditEvaluatorHook`.
pub trait CreditEvaluatorHook: Send + Sync {
    /// Evaluate `receipt` and either mint an IOU envelope or skip.
    fn evaluate(&self, receipt: &ChioReceipt) -> Result<Option<IouEnvelope>, CreditEvaluatorError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: `IOU_ENVELOPE_SCHEMA` is the documented value and
    /// is byte-stable.
    #[test]
    fn iou_envelope_schema_is_stable() {
        assert_eq!(IOU_ENVELOPE_SCHEMA, "chio.credit.iou-envelope.v1");
    }
}
