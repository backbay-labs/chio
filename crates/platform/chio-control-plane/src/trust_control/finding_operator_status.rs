//! Local authority-status signer for the single-operator pilot.

use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_core::{AnchorInclusionProof, Keypair};
use chio_finding::{
    FindingAuthorityStatus, SignedFindingAuthorityStatus, FINDING_AUTHORITY_STATUS_SCHEMA_V1,
};
use chio_settle::{
    finding_anchor_checkpoint_statement_sha256, FindingAnchorCheckpointPublication,
    SignedFindingAnchorCheckpointPublication, FINDING_ANCHOR_CHECKPOINT_PUBLICATION_SCHEMA_V1,
};

use super::finding_challenge_coordinator::FindingAuthorityStatusResolver;
use super::FindingAuthorityPin;

/// Signs current non-revoked role readings under the profile's independent
/// authority-status key. Key revocation administration is outside the
/// single-operator pilot scope; a pin outside its configured window fails
/// closed.
pub struct FindingOperatorAuthorityStatusResolver {
    authority_status_pin: FindingAuthorityPin,
    signer: Keypair,
}

impl FindingOperatorAuthorityStatusResolver {
    pub fn new(authority_status_pin: FindingAuthorityPin, signer: Keypair) -> Result<Self, String> {
        if authority_status_pin
            .key()
            .map_err(|error| error.to_string())?
            != signer.public_key()
        {
            return Err("authority-status private key does not match its market pin".to_owned());
        }
        Ok(Self {
            authority_status_pin,
            signer,
        })
    }

    fn require_live(&self, now: u64) -> Result<(), String> {
        if !self.authority_status_pin.covers(now) {
            return Err("authority-status signing window is not live".to_owned());
        }
        Ok(())
    }
}

impl FindingAuthorityStatusResolver for FindingOperatorAuthorityStatusResolver {
    fn resolve(
        &self,
        pin: &FindingAuthorityPin,
        now: u64,
    ) -> Result<SignedFindingAuthorityStatus, String> {
        self.require_live(now)?;
        if !pin.covers(now) {
            return Err("requested authority pin is not live".to_owned());
        }
        SignedExportEnvelope::sign(
            FindingAuthorityStatus {
                schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_owned(),
                status_ref: pin.revocation_status_ref.clone(),
                authority_id: pin.authority_id.clone(),
                key: pin.key().map_err(|error| error.to_string())?,
                key_epoch: pin.key_epoch,
                revoked_from: None,
                observed_at: now,
            },
            &self.signer,
        )
        .map_err(|error| error.to_string())
    }

    fn checkpoint_publication(
        &self,
        proof: &AnchorInclusionProof,
        now: u64,
    ) -> Result<SignedFindingAnchorCheckpointPublication, String> {
        self.require_live(now)?;
        SignedExportEnvelope::sign(
            FindingAnchorCheckpointPublication {
                schema: FINDING_ANCHOR_CHECKPOINT_PUBLICATION_SCHEMA_V1.to_owned(),
                checkpoint_statement_sha256: finding_anchor_checkpoint_statement_sha256(proof)
                    .map_err(|error| error.to_string())?,
                checkpoint_seq: proof.checkpoint_statement.checkpoint_seq,
                published_at: proof.checkpoint_statement.issued_at,
                observed_at: now,
            },
            &self.signer,
        )
        .map_err(|error| error.to_string())
    }
}
