//! Cross-platform mobile receipt-chain validation shell.

use serde::Deserialize;

use super::errors::AttestationError;

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
    if evidence.platform != "app_attest" && evidence.platform != "play_integrity" {
        return Err(AttestationError::UnsupportedFormat(evidence.platform));
    }
    Ok(VerifiedMobileReceiptChain {
        receipt_schema: receipt.schema,
        evidence_schema: evidence.schema,
        platform: evidence.platform,
    })
}
