//! `chio.finding.key-revocation.v1`: the governance-signed statement that a
//! pinned authority key stopped being trustworthy from a stated instant.
//!
//! Every other fact the challenge lane reads about an authority comes from
//! the profile, and the profile is signed by the deployment's governance
//! root. Revocation is the one fact that arrives after the profile is
//! published, so it needs a carrier of its own; giving it any weaker carrier
//! would make a key's standing the weakest link in the chain rather than the
//! same link. The root that pinned a key is therefore the only root that can
//! withdraw it, and the statement names the exact policy it withdraws:
//! the revocation feed the profile pins for that key, the authority the
//! policy identifies, and the key epoch it covers. A statement published on
//! a feed the policy does not name, or about an epoch the policy does not
//! pin, is a statement about a different key.
//!
//! `revoked_from` is venue trusted time and is compared against artifact
//! timestamps, never against "now": whether a key was trustworthy when it
//! signed is a fact about that instant, and it does not change with the
//! reader's clock.

use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::envelope::require_ed25519;
use crate::validate::{require_bounded_id, require_nonzero, FindingError};

/// Governance-signed authority key revocation.
pub const FINDING_KEY_REVOCATION_SCHEMA_V1: &str =
    chio_core_types::signed_artifact::CHIO_FINDING_KEY_REVOCATION_V1_SCHEMA;

/// Authority key revocation body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingKeyRevocation {
    pub schema: String,
    /// The revocation feed this statement is published on. It must equal the
    /// `revocation_status_ref` the profile pins for the key, or the statement
    /// speaks for a source this deployment never trusted for it.
    pub revocation_status_ref: String,
    /// The pinned authority whose key this statement withdraws.
    pub authority_id: String,
    pub key: PublicKey,
    /// The key epoch the pinned policy names. A rotation opens a new epoch,
    /// so a statement about an earlier one says nothing about the key in use.
    pub key_epoch: u64,
    /// Venue trusted time from which the key is no longer trustworthy.
    pub revoked_from: u64,
    pub recorded_at: u64,
}

/// Governance-signed envelope for the revocation.
pub type SignedFindingKeyRevocation = SignedExportEnvelope<FindingKeyRevocation>;

impl FindingKeyRevocation {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_KEY_REVOCATION_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_bounded_id(&self.revocation_status_ref, "revocation_status_ref")?;
        require_bounded_id(&self.authority_id, "authority_id")?;
        require_ed25519(&self.key, "key")?;
        require_nonzero(self.key_epoch, "key_epoch")?;
        require_nonzero(self.revoked_from, "revoked_from")?;
        require_nonzero(self.recorded_at, "recorded_at")?;
        Ok(())
    }
}

/// Verify a signed revocation against the externally pinned governance root.
/// The body names the authority it withdraws, never the signer, so the pin is
/// the only thing that authorizes this statement.
pub fn verify_signed_key_revocation(
    signed: &SignedFindingKeyRevocation,
    pinned_governance_authority: &PublicKey,
) -> Result<(), FindingError> {
    signed.body.validate()?;
    crate::envelope::verify_pinned_envelope(signed, pinned_governance_authority, "key_revocation")
}
