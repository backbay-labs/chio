//! `chio.finding.audit-epoch.v1`: the venue's signed precommitment for one
//! audit round, published BEFORE any listing is selected.
//!
//! Random auditing is an operator assumption unless the round commits its
//! inputs before it samples. This artifact commits the eligible listing
//! snapshot, the fee schedule the round runs under, the selection algorithm,
//! the published rate, the available budget, and a commitment to the
//! randomness.
//!
//! The seed itself is NOT a member and has no encoding here. Publishing a
//! seed alongside its commitment would make the commitment decorative; the
//! seed is revealed only afterwards, in `chio.finding.audit-report.v1`,
//! where [`derive_audit_seed_commitment`] re-derives this commitment from
//! it. Two artifacts, never one mutable one.

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::validate::{
    require_bounded_id, require_currency, require_hex64, require_i_json_u64, require_nonzero,
    FindingError,
};

/// Venue-signed audit epoch precommitment.
pub const FINDING_AUDIT_EPOCH_SCHEMA_V1: &str =
    chio_core_types::signed_artifact::CHIO_FINDING_AUDIT_EPOCH_V1_SCHEMA;

/// Domain separator for the audit seed commitment. The trailing NUL keeps
/// the separator unambiguous against the seed text that follows it.
const AUDIT_SEED_COMMITMENT_DOMAIN: &[u8] = b"chio.finding.audit-seed.v1\0";

/// Upper bound on the published audit rate, in basis points.
pub const MAX_PUBLISHED_RATE_BPS: u64 = 10_000;

/// Commit to an audit seed: sha256 over the domain-separated seed. The
/// epoch publishes only this value, and the report's revealed seed must
/// reproduce it exactly.
#[must_use]
pub fn derive_audit_seed_commitment(revealed_seed: &str) -> String {
    let mut preimage = Vec::with_capacity(AUDIT_SEED_COMMITMENT_DOMAIN.len() + revealed_seed.len());
    preimage.extend_from_slice(AUDIT_SEED_COMMITMENT_DOMAIN);
    preimage.extend_from_slice(revealed_seed.as_bytes());
    chio_core_types::crypto::sha256_hex(&preimage)
}

/// Audit epoch precommitment body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingAuditEpoch {
    pub schema: String,
    /// Content-addressed: sha256 of the canonical body with
    /// `audit_epoch_id` cleared.
    pub audit_epoch_id: String,
    pub epoch_index: u64,
    /// Digest of the eligible listing snapshot this round samples from.
    pub eligible_snapshot_digest: String,
    pub eligible_listing_count: u64,
    pub fee_schedule_envelope_sha256: String,
    /// Commitment to the randomness, never the randomness itself.
    pub seed_commitment: String,
    pub selection_algorithm_id: String,
    /// The published audit rate in basis points.
    pub published_rate_bps: u64,
    pub available_budget: MonetaryAmount,
    /// Digest of the governance authorization for this round.
    pub authorization_digest: String,
    pub committed_at: u64,
}

/// Venue-signed envelope for the epoch.
pub type SignedFindingAuditEpoch = SignedExportEnvelope<FindingAuditEpoch>;

impl FindingAuditEpoch {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_AUDIT_EPOCH_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.audit_epoch_id, "audit_epoch_id")?;
        require_i_json_u64(self.epoch_index, "epoch_index")?;
        require_hex64(&self.eligible_snapshot_digest, "eligible_snapshot_digest")?;
        require_nonzero(self.eligible_listing_count, "eligible_listing_count")?;
        require_hex64(
            &self.fee_schedule_envelope_sha256,
            "fee_schedule_envelope_sha256",
        )?;
        require_hex64(&self.seed_commitment, "seed_commitment")?;
        require_bounded_id(&self.selection_algorithm_id, "selection_algorithm_id")?;
        require_nonzero(self.published_rate_bps, "published_rate_bps")?;
        if self.published_rate_bps > MAX_PUBLISHED_RATE_BPS {
            return Err(FindingError::InvalidField("published_rate_bps"));
        }
        require_nonzero(self.available_budget.units, "available_budget")?;
        require_currency(&self.available_budget.currency, "available_budget.currency")?;
        require_hex64(&self.authorization_digest, "authorization_digest")?;
        require_nonzero(self.committed_at, "committed_at")?;
        self.verify_audit_epoch_id()
    }

    /// Recompute and compare the content-addressed epoch id.
    pub fn verify_audit_epoch_id(&self) -> Result<(), FindingError> {
        let expected = compute_audit_epoch_id(self)?;
        if expected == self.audit_epoch_id {
            Ok(())
        } else {
            Err(FindingError::ArtifactIdMismatch("audit_epoch_id"))
        }
    }
}

/// Content-addressed epoch id: sha256 over the canonical body with
/// `audit_epoch_id` cleared.
pub fn compute_audit_epoch_id(epoch: &FindingAuditEpoch) -> Result<String, FindingError> {
    let mut body = epoch.clone();
    body.audit_epoch_id = String::new();
    let bytes =
        chio_core_types::canonical_json_bytes(&body).map_err(|_| FindingError::Canonicalization)?;
    Ok(chio_core_types::crypto::sha256_hex(&bytes))
}

/// Verify a signed epoch against the externally pinned audit authority.
pub fn verify_signed_audit_epoch(
    signed: &SignedFindingAuditEpoch,
    pinned_audit_authority: &PublicKey,
) -> Result<(), FindingError> {
    signed.body.validate()?;
    crate::envelope::verify_pinned_envelope(signed, pinned_audit_authority, "audit_epoch")
}
