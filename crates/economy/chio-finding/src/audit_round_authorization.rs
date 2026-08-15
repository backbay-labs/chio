//! `chio.finding.audit-round-authorization.v1`: governance authorization
//! for one exact audit epoch precommitment.
//!
//! The authorization signs every independently chosen epoch field while
//! clearing the epoch's own content address and the authorization-envelope
//! digest. The resulting cycle-free digest is inserted into this artifact;
//! the exact signed authorization envelope digest is then inserted into the
//! final epoch before its content address is computed.

use chio_core_types::canonical_json_bytes;
use chio_core_types::crypto::{sha256_hex, PublicKey};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::audit_epoch::FindingAuditEpoch;
use crate::validate::{require_hex64, require_nonzero, require_window, FindingError};

/// Governance-signed authorization for one exact audit round.
pub const FINDING_AUDIT_ROUND_AUTHORIZATION_SCHEMA_V1: &str =
    chio_core_types::signed_artifact::CHIO_FINDING_AUDIT_ROUND_AUTHORIZATION_V1_SCHEMA;

/// Authorization body for one audit epoch precommitment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingAuditRoundAuthorization {
    pub schema: String,
    pub epoch_precommitment_sha256: String,
    pub authorized_at: u64,
    pub expires_at: u64,
}

/// Governance-signed envelope for the authorization.
pub type SignedFindingAuditRoundAuthorization =
    SignedExportEnvelope<FindingAuditRoundAuthorization>;

impl FindingAuditRoundAuthorization {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_AUDIT_ROUND_AUTHORIZATION_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(
            &self.epoch_precommitment_sha256,
            "epoch_precommitment_sha256",
        )?;
        require_nonzero(self.authorized_at, "authorized_at")?;
        require_window(
            self.authorized_at,
            self.expires_at,
            "authorized_at",
            "expires_at",
        )?;
        Ok(())
    }
}

/// Digest every independently chosen epoch field without creating a hash
/// cycle through the authorization envelope or the final epoch id.
pub fn audit_epoch_precommitment_sha256(epoch: &FindingAuditEpoch) -> Result<String, FindingError> {
    let mut precommitment = epoch.clone();
    precommitment.audit_epoch_id.clear();
    precommitment.authorization_digest.clear();
    let bytes = canonical_json_bytes(&precommitment).map_err(|_| FindingError::Canonicalization)?;
    Ok(sha256_hex(&bytes))
}

/// Verify an authorization against the deployment's pinned governance root.
pub fn verify_signed_audit_round_authorization(
    signed: &SignedFindingAuditRoundAuthorization,
    pinned_governance_authority: &PublicKey,
) -> Result<(), FindingError> {
    signed.body.validate()?;
    crate::envelope::verify_pinned_envelope(
        signed,
        pinned_governance_authority,
        "audit_round_authorization",
    )
}
