//! `chio.finding.audit-epoch.v1`: the venue's signed precommitment for one
//! audit round, published after the eligible listing snapshot is fixed and
//! an independent randomness witness has generated and committed a seed.
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
use chio_core_types::crypto::{PublicKey, Signature};
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

/// Domain separator for the independently witnessed seed commitment.
const AUDIT_SEED_WITNESS_DOMAIN: &str = "chio.finding.audit-seed-witness.v1";

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

/// Exact bytes the independent randomness witness signs after the eligible
/// listing snapshot is fixed.
///
/// The witness controls and withholds the seed until the report. Binding the
/// already committed snapshot digest prevents the venue from selecting or
/// weighting listings after learning the seed commitment.
#[must_use]
pub fn audit_seed_witness_signing_bytes(
    audit_authority: &PublicKey,
    epoch_index: u64,
    eligible_snapshot_digest: &str,
    seed_commitment: &str,
    eligible_snapshot_at: u64,
    seed_witnessed_at: u64,
) -> Vec<u8> {
    format!(
        "{AUDIT_SEED_WITNESS_DOMAIN}\0{}\0{epoch_index}\0{eligible_snapshot_digest}\0{eligible_snapshot_at}\0{seed_commitment}\0{seed_witnessed_at}",
        audit_authority.to_hex()
    )
    .into_bytes()
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
    /// The externally pinned signer of the enclosing epoch envelope. The
    /// witness statement binds its commitment to this exact authority.
    pub audit_authority: PublicKey,
    /// Time the independently trusted witness generated and committed the
    /// seed. This must be strictly after the eligible snapshot was fixed.
    pub seed_witnessed_at: u64,
    /// Time the venue fixed the eligible listing snapshot, before the
    /// witness generated the seed.
    pub eligible_snapshot_at: u64,
    /// Independently pinned randomness-witness key.
    pub seed_witness: PublicKey,
    /// Strict Ed25519 signature over [`audit_seed_witness_signing_bytes`].
    pub seed_witness_signature: Signature,
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
        crate::envelope::require_ed25519(&self.audit_authority, "audit_epoch")?;
        crate::envelope::require_ed25519(&self.seed_witness, "audit_seed_witness")?;
        if self.audit_authority == self.seed_witness {
            return Err(FindingError::InvalidField("seed_witness"));
        }
        require_nonzero(self.seed_witnessed_at, "seed_witnessed_at")?;
        require_nonzero(self.eligible_snapshot_at, "eligible_snapshot_at")?;
        if self.eligible_snapshot_at >= self.seed_witnessed_at {
            return Err(FindingError::InvalidField("seed_witnessed_at"));
        }
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
        if self.seed_witnessed_at > self.committed_at {
            return Err(FindingError::InvalidField("committed_at"));
        }
        self.verify_seed_witness()?;
        self.verify_audit_epoch_id()
    }

    /// Verify the independently pinned seed witness embedded in this body.
    pub fn verify_seed_witness(&self) -> Result<(), FindingError> {
        let message = audit_seed_witness_signing_bytes(
            &self.audit_authority,
            self.epoch_index,
            &self.eligible_snapshot_digest,
            &self.seed_commitment,
            self.eligible_snapshot_at,
            self.seed_witnessed_at,
        );
        if self
            .seed_witness
            .verify_strict(&message, &self.seed_witness_signature)
        {
            Ok(())
        } else {
            Err(FindingError::EnvelopeSignatureInvalid("audit_seed_witness"))
        }
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
    pinned_seed_witness: &PublicKey,
) -> Result<(), FindingError> {
    signed.body.validate()?;
    if signed.body.audit_authority != *pinned_audit_authority {
        return Err(FindingError::AuthorityMismatch("audit_epoch"));
    }
    if signed.body.seed_witness != *pinned_seed_witness {
        return Err(FindingError::AuthorityMismatch("audit_seed_witness"));
    }
    crate::envelope::verify_pinned_envelope(signed, pinned_audit_authority, "audit_epoch")
}
