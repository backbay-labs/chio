//! Cross-platform mobile receipt-chain validation shell.
//!
//! # Trust contract
//!
//! This module is a shape-only verifier for mobile attestation receipts.
//! Wave 1A flagged it as a "permissive shell"; Wave 3.2 keeps the surface
//! intentionally narrow so deployments do not accidentally treat
//! receipt-chain acceptance as proof of device integrity. The function is
//! reachable through the `chio_custody_hw::verify_mobile_receipt_chain`
//! re-export but does not feed any production capability-mint path; the
//! issuer surface in [`crate::issuer`] consults the typed attestation
//! verifiers in [`super::app_attest`] and [`super::play_integrity`]
//! directly, never the receipt-chain shell.
//!
//! Fail-closed checks performed here:
//!
//! - Both envelopes must parse as JSON objects with a `schema` field.
//! - The receipt and evidence `schema` strings must both be non-empty.
//! - The evidence `platform` must be either `app_attest` or
//!   `play_integrity`. Any other platform string is rejected.
//!
//! The shell intentionally does NOT cross-check the `schema` field
//! against the `platform` field: schema is the JSON envelope version,
//! platform selects the concrete attestation verifier downstream. Real
//! attestation acceptance happens in
//! [`super::app_attest::verify_app_attest`] and
//! [`super::play_integrity::verify_play_integrity`]; a successful return
//! from this function is NOT proof of device integrity.

use serde::Deserialize;

use super::errors::AttestationError;

const PLATFORM_APP_ATTEST: &str = "app_attest";
const PLATFORM_PLAY_INTEGRITY: &str = "play_integrity";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMobileReceiptChain {
    pub receipt_schema: String,
    pub evidence_schema: String,
    pub platform: String,
}

#[derive(Debug, Deserialize)]
struct ReceiptEnvelope {
    schema: String,
}

#[derive(Debug, Deserialize)]
struct EvidenceEnvelope {
    schema: String,
    platform: String,
}

pub fn verify_mobile_receipt_chain(
    receipt_json: &str,
    evidence_json: &str,
) -> Result<VerifiedMobileReceiptChain, AttestationError> {
    let receipt: ReceiptEnvelope = serde_json::from_str(receipt_json)
        .map_err(|error| AttestationError::InvalidCbor(format!("receipt JSON: {error}")))?;
    let evidence: EvidenceEnvelope = serde_json::from_str(evidence_json)
        .map_err(|error| AttestationError::InvalidCbor(format!("evidence JSON: {error}")))?;
    if receipt.schema.is_empty() {
        return Err(AttestationError::InvalidCbor(
            "receipt schema must be a non-empty string".to_string(),
        ));
    }
    if evidence.schema.is_empty() {
        return Err(AttestationError::InvalidCbor(
            "evidence schema must be a non-empty string".to_string(),
        ));
    }
    if evidence.platform != PLATFORM_APP_ATTEST && evidence.platform != PLATFORM_PLAY_INTEGRITY {
        return Err(AttestationError::UnsupportedFormat(evidence.platform));
    }
    Ok(VerifiedMobileReceiptChain {
        receipt_schema: receipt.schema,
        evidence_schema: evidence.schema,
        platform: evidence.platform,
    })
}
