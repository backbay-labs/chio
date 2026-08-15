//! `chio.finding.recovery-context.v1`: the unsigned carrier for a bounded,
//! no-charge redelivery of an already-settled finding.
//!
//! The carrier is evidence transport, not bearer authority. Recovery-aware
//! admission strict-parses and re-verifies the original signed capability,
//! the complete purchase context, the purchase-authority-signed settled
//! record, and the trusted-kernel-signed Allow receipt. Keeping the exact
//! canonical bytes prevents a typed round trip from hiding substitution.

use serde::{Deserialize, Serialize};

use crate::validate::{require_canonical_json_text, require_hex64, FindingError};

/// Unsigned recovery evidence carrier.
pub const FINDING_RECOVERY_CONTEXT_SCHEMA_V1: &str = "chio.finding.recovery-context.v1";

/// Bound on the canonical carrier and on each embedded canonical artifact.
pub const FINDING_RECOVERY_CONTEXT_MAX_CANONICAL_BYTES: usize = 1_048_576;

/// Evidence needed to authorize one recovery attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingRecoveryContext {
    pub schema: String,
    /// Deterministic identity shared by every re-mint of this recovery.
    pub recovery_id: String,
    /// Exact canonical original signed capability.
    pub original_capability_json: String,
    /// Exact canonical unsigned purchase context used at paid admission.
    pub purchase_context_json: String,
    /// Exact canonical purchase-authority-signed settled record.
    pub purchase_record_envelope_json: String,
    /// Exact canonical trusted-kernel-signed original Allow receipt.
    pub original_delivery_receipt_json: String,
}

impl FindingRecoveryContext {
    /// Validate the carrier shape and canonical artifact byte preservation.
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_RECOVERY_CONTEXT_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.recovery_id, "recovery_id")?;
        let members = [
            ("original_capability_json", &self.original_capability_json),
            ("purchase_context_json", &self.purchase_context_json),
            (
                "purchase_record_envelope_json",
                &self.purchase_record_envelope_json,
            ),
            (
                "original_delivery_receipt_json",
                &self.original_delivery_receipt_json,
            ),
        ];
        let mut total = 0_usize;
        for (field, value) in members {
            require_canonical_json_text(
                value,
                field,
                FINDING_RECOVERY_CONTEXT_MAX_CANONICAL_BYTES,
            )?;
            total = total
                .checked_add(value.len())
                .ok_or(FindingError::SizeLimitExceeded("recovery_context"))?;
        }
        if total > FINDING_RECOVERY_CONTEXT_MAX_CANONICAL_BYTES {
            return Err(FindingError::SizeLimitExceeded("recovery_context"));
        }
        Ok(())
    }
}

/// Parse canonical recovery-context bytes, rejecting aliases and unknown
/// fields before any contained artifact is trusted.
pub fn parse_finding_recovery_context(raw: &[u8]) -> Result<FindingRecoveryContext, FindingError> {
    if raw.is_empty() || raw.len() > FINDING_RECOVERY_CONTEXT_MAX_CANONICAL_BYTES {
        return Err(FindingError::SizeLimitExceeded("recovery_context"));
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| FindingError::NonCanonicalBytes("recovery_context"))?;
    let canonical = chio_core_types::canonical_json_bytes_from_str(text)
        .map_err(|_| FindingError::NonCanonicalBytes("recovery_context"))?;
    if canonical.as_slice() != raw {
        return Err(FindingError::NonCanonicalBytes("recovery_context"));
    }
    let context: FindingRecoveryContext =
        serde_json::from_slice(raw).map_err(|_| FindingError::InvalidField("recovery_context"))?;
    let reserialized = chio_core_types::canonical_json_bytes(&context)
        .map_err(|_| FindingError::Canonicalization)?;
    if reserialized.as_slice() != raw {
        return Err(FindingError::NonCanonicalBytes("recovery_context"));
    }
    context.validate()?;
    Ok(context)
}

/// Derive the identity shared by every re-mint of one recovery authority.
/// Length prefixes keep the preimage injective even when identifiers contain
/// delimiter bytes.
#[must_use]
pub fn derive_finding_recovery_id(
    original_capability_id: &str,
    purchase_key: &str,
    original_delivery_receipt_id: &str,
) -> String {
    const DOMAIN: &[u8] = b"chio.finding.recovery.v1\0";
    let members = [
        original_capability_id.as_bytes(),
        purchase_key.as_bytes(),
        original_delivery_receipt_id.as_bytes(),
    ];
    let mut preimage = Vec::with_capacity(
        DOMAIN.len()
            + members
                .iter()
                .map(|member| 8_usize.saturating_add(member.len()))
                .sum::<usize>(),
    );
    preimage.extend_from_slice(DOMAIN);
    for member in members {
        preimage.extend_from_slice(&(member.len() as u64).to_be_bytes());
        preimage.extend_from_slice(member);
    }
    chio_core_types::crypto::sha256_hex(&preimage)
}
