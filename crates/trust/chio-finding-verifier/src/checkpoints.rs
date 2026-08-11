//! Checkpoint membership with the full wrapper cross-check.
//!
//! `ReceiptInclusionProof::verify` proves only the inner Merkle path
//! against a caller-supplied root. This module supplies the additional
//! binding ARCHITECTURE 4.1.1 requires: checkpoint identity and
//! signature, wrapper sequence and range checks, BOTH leaf-index fields,
//! the inclusion proof's tree size against the checkpoint's signed tree
//! size, the pinned canonical leaf definition (full canonical
//! receipt envelope bytes), duplicate rejection, and profile-pinned log
//! identity/signer.

use std::collections::{BTreeMap, BTreeSet};

use chio_finding::{
    verify_signed_authority_status, FindingAuthorityKeyPolicy, FindingChallengeVerifierProfile,
};
use chio_kernel::checkpoint::{
    checkpoint_log_id, validate_checkpoint, verify_checkpoint_transparency_records,
    CheckpointTransparencySummary, KernelCheckpoint,
};

use crate::verify::{policy_covers, FindingCheckpointSignerStatusTrust, ResolvedReceiptEvidence};

fn has_strict_checkpoint_signature(checkpoint: &KernelCheckpoint) -> bool {
    matches!(
        checkpoint
            .body
            .kernel_key
            .verify_canonical_strict(&checkpoint.body, &checkpoint.signature),
        Ok(true)
    )
}

/// Membership failures. Every variant is a rejection.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CheckpointMembershipError {
    #[error("no checkpoints supplied")]
    NoCheckpoints,
    #[error("duplicate checkpoint seq {0}")]
    DuplicateCheckpoint(u64),
    #[error("checkpoint {0} failed structural validation")]
    CheckpointInvalid(u64),
    #[error("checkpoint {0} signature invalid")]
    CheckpointSignatureInvalid(u64),
    #[error("checkpoint transparency records are invalid")]
    TransparencyInvalid,
    #[error("checkpoint {0} log id is not pinned by the profile")]
    LogNotPinned(u64),
    #[error("checkpoint {0} signer does not match the pinned log signer")]
    SignerNotPinned(u64),
    #[error("checkpoint {0} was issued outside the pinned signer window")]
    SignerInactive(u64),
    #[error("checkpoint {0} was issued after the Finding")]
    IssuedAfterFinding(u64),
    #[error("checkpoint {0} was issued after report evaluation")]
    IssuedAfterEvaluation(u64),
    #[error("checkpoint {0} has no authenticated signer-status reading")]
    SignerStatusUnavailable(u64),
    #[error("checkpoint {0} signer-status trust configuration is invalid")]
    SignerStatusTrustInvalid(u64),
    #[error("checkpoint {0} has duplicate signer-status readings")]
    DuplicateSignerStatus(u64),
    #[error("checkpoint {0} signer-status signature is invalid")]
    SignerStatusSignatureInvalid(u64),
    #[error("checkpoint {0} signer-status reading is stale or temporally inconsistent")]
    SignerStatusStale(u64),
    #[error(
        "checkpoint {0} signer is revoked and its issuance time is not independently anchored"
    )]
    SignerRevoked(u64),
    #[error("checkpoint {0} signer authority expired before evaluation")]
    SignerExpiredAtEvaluation(u64),
    #[error("inclusion proof references unknown checkpoint seq {0}")]
    UnknownCheckpoint(u64),
    #[error("duplicate inclusion proof for receipt seq {0}")]
    DuplicateProof(u64),
    #[error("receipt seq {0} outside the checkpoint batch range")]
    ReceiptSeqOutOfRange(u64),
    #[error("receipt seq {0} was issued after checkpoint seq {1}")]
    ReceiptIssuedAfterCheckpoint(u64, u64),
    #[error("outer leaf index does not equal the inner proof leaf index")]
    LeafIndexMismatch,
    #[error("inner proof tree size does not equal the checkpoint tree size")]
    TreeSizeMismatch,
    #[error("leaf index does not equal receipt_seq - batch_start_seq")]
    LeafOffsetMismatch,
    #[error("proof merkle root does not equal the checkpoint root")]
    RootMismatch,
    #[error("inclusion path failed against the checkpoint root")]
    InclusionInvalid,
    #[error("checkpoint identity does not equal the finding's evidence_checkpoint_ref")]
    CheckpointRefMismatch,
}

/// Verify that every resolved receipt is a member of a profile-pinned,
/// signature-valid checkpoint. The canonical leaf is the full canonical
/// receipt envelope bytes supplied in the resolved evidence.
pub fn verify_checkpoint_membership(
    receipts: &[ResolvedReceiptEvidence],
    checkpoints: &[KernelCheckpoint],
    transparency: &CheckpointTransparencySummary,
    profile: &FindingChallengeVerifierProfile,
    evidence_checkpoint_ref: &str,
) -> Result<(), CheckpointMembershipError> {
    verify_checkpoint_membership_inner(
        receipts,
        checkpoints,
        transparency,
        profile,
        Some(evidence_checkpoint_ref),
        None,
        None,
    )
}

/// Verify production evidence against the Finding's pinned checkpoint. The
/// checkpoint must already exist when the Finding is issued, and its signer
/// must have fresh independently authenticated standing at evaluation time.
pub(crate) fn verify_production_checkpoint_membership(
    receipts: &[ResolvedReceiptEvidence],
    checkpoints: &[KernelCheckpoint],
    transparency: &CheckpointTransparencySummary,
    profile: &FindingChallengeVerifierProfile,
    evidence_checkpoint_ref: &str,
    finding_issued_at: u64,
    status_context: (u64, Option<&FindingCheckpointSignerStatusTrust>),
) -> Result<(), CheckpointMembershipError> {
    verify_checkpoint_membership_inner(
        receipts,
        checkpoints,
        transparency,
        profile,
        Some(evidence_checkpoint_ref),
        Some((finding_issued_at, CheckpointIssuanceCeiling::Finding)),
        Some(status_context),
    )
}

/// Verify checkpoint membership for evidence created after the Finding was
/// signed. The receipt still has to land in the profile-pinned checkpoint log,
/// but it cannot be named by the Finding's earlier evidence checkpoint ref.
pub(crate) fn verify_post_finding_checkpoint_membership(
    receipts: &[ResolvedReceiptEvidence],
    checkpoints: &[KernelCheckpoint],
    transparency: &CheckpointTransparencySummary,
    profile: &FindingChallengeVerifierProfile,
    evaluation_time: u64,
    signer_status: Option<&FindingCheckpointSignerStatusTrust>,
) -> Result<(), CheckpointMembershipError> {
    verify_checkpoint_membership_inner(
        receipts,
        checkpoints,
        transparency,
        profile,
        None,
        Some((evaluation_time, CheckpointIssuanceCeiling::Evaluation)),
        Some((evaluation_time, signer_status)),
    )
}

fn verify_checkpoint_membership_inner(
    receipts: &[ResolvedReceiptEvidence],
    checkpoints: &[KernelCheckpoint],
    transparency: &CheckpointTransparencySummary,
    profile: &FindingChallengeVerifierProfile,
    evidence_checkpoint_ref: Option<&str>,
    latest_issued_at: Option<(u64, CheckpointIssuanceCeiling)>,
    status_context: Option<(u64, Option<&FindingCheckpointSignerStatusTrust>)>,
) -> Result<(), CheckpointMembershipError> {
    if checkpoints.is_empty() {
        return Err(CheckpointMembershipError::NoCheckpoints);
    }
    verify_checkpoint_transparency_records(checkpoints, transparency)
        .map_err(|_| CheckpointMembershipError::TransparencyInvalid)?;
    let pinned_logs: BTreeMap<&str, _> = profile
        .checkpoint_logs
        .iter()
        .map(|log| (log.log_id.as_str(), &log.signer))
        .collect();
    let mut by_seq = BTreeMap::new();
    for checkpoint in checkpoints {
        let seq = checkpoint.body.checkpoint_seq;
        if validate_checkpoint(checkpoint).is_err() {
            return Err(CheckpointMembershipError::CheckpointInvalid(seq));
        }
        if !has_strict_checkpoint_signature(checkpoint) {
            return Err(CheckpointMembershipError::CheckpointSignatureInvalid(seq));
        }
        let log_id = checkpoint_log_id(checkpoint);
        // Checkpoint-reference grammar: `<log_id>#<checkpoint_seq>`. Every
        // supplied checkpoint identity must equal the finding's single
        // evidence_checkpoint_ref; substitution denies.
        if let Some(evidence_checkpoint_ref) = evidence_checkpoint_ref {
            if format!("{log_id}#{seq}") != evidence_checkpoint_ref {
                return Err(CheckpointMembershipError::CheckpointRefMismatch);
            }
        }
        let Some(pinned_signer) = pinned_logs.get(log_id.as_str()) else {
            return Err(CheckpointMembershipError::LogNotPinned(seq));
        };
        if checkpoint.body.kernel_key != pinned_signer.key {
            return Err(CheckpointMembershipError::SignerNotPinned(seq));
        }
        if !policy_covers(pinned_signer, checkpoint.body.issued_at) {
            return Err(CheckpointMembershipError::SignerInactive(seq));
        }
        if let Some((latest, ceiling)) = latest_issued_at {
            if checkpoint.body.issued_at > latest {
                return Err(match ceiling {
                    CheckpointIssuanceCeiling::Finding => {
                        CheckpointMembershipError::IssuedAfterFinding(seq)
                    }
                    CheckpointIssuanceCeiling::Evaluation => {
                        CheckpointMembershipError::IssuedAfterEvaluation(seq)
                    }
                });
            }
        }
        if let Some((trusted_time, signer_status)) = status_context {
            verify_checkpoint_signer_status(
                pinned_signer,
                seq,
                checkpoint.body.issued_at,
                trusted_time,
                signer_status,
            )?;
        }
        if by_seq.insert(seq, checkpoint).is_some() {
            return Err(CheckpointMembershipError::DuplicateCheckpoint(seq));
        }
    }
    let mut proved_receipt_seqs = BTreeSet::new();
    for evidence in receipts {
        let proof = &evidence.inclusion_proof;
        let Some(checkpoint) = by_seq.get(&proof.checkpoint_seq) else {
            return Err(CheckpointMembershipError::UnknownCheckpoint(
                proof.checkpoint_seq,
            ));
        };
        if !proved_receipt_seqs.insert(proof.receipt_seq) {
            return Err(CheckpointMembershipError::DuplicateProof(proof.receipt_seq));
        }
        let body = &checkpoint.body;
        if evidence.receipt.timestamp > body.issued_at {
            return Err(CheckpointMembershipError::ReceiptIssuedAfterCheckpoint(
                proof.receipt_seq,
                body.checkpoint_seq,
            ));
        }
        if proof.receipt_seq < body.batch_start_seq || proof.receipt_seq > body.batch_end_seq {
            return Err(CheckpointMembershipError::ReceiptSeqOutOfRange(
                proof.receipt_seq,
            ));
        }
        // Both leaf-index fields must agree: the outer wrapper field is
        // inert in the shipped verify path and could silently disagree.
        if proof.leaf_index != proof.proof.leaf_index {
            return Err(CheckpointMembershipError::LeafIndexMismatch);
        }
        // The inclusion proof's tree size must equal the signed
        // checkpoint's tree size.
        if proof.proof.tree_size != body.tree_size {
            return Err(CheckpointMembershipError::TreeSizeMismatch);
        }
        // The leaf position must equal the receipt's offset in the batch.
        let expected_index = proof.receipt_seq - body.batch_start_seq;
        if u64::try_from(proof.leaf_index) != Ok(expected_index) {
            return Err(CheckpointMembershipError::LeafOffsetMismatch);
        }
        // The wrapper's claimed root must equal the SIGNED root; the path
        // then verifies against the signed root, never the claimed one.
        if proof.merkle_root != body.merkle_root {
            return Err(CheckpointMembershipError::RootMismatch);
        }
        if !proof
            .proof
            .verify(&evidence.canonical_receipt_bytes, &body.merkle_root)
        {
            return Err(CheckpointMembershipError::InclusionInvalid);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum CheckpointIssuanceCeiling {
    Finding,
    Evaluation,
}

fn verify_checkpoint_signer_status(
    signer: &FindingAuthorityKeyPolicy,
    checkpoint_seq: u64,
    checkpoint_issued_at: u64,
    trusted_time: u64,
    trust: Option<&FindingCheckpointSignerStatusTrust>,
) -> Result<(), CheckpointMembershipError> {
    if trusted_time >= signer.valid_until {
        return Err(CheckpointMembershipError::SignerExpiredAtEvaluation(
            checkpoint_seq,
        ));
    }
    let Some(trust) = trust else {
        return Err(CheckpointMembershipError::SignerStatusUnavailable(
            checkpoint_seq,
        ));
    };
    if trust.max_age_secs == 0 {
        return Err(CheckpointMembershipError::SignerStatusTrustInvalid(
            checkpoint_seq,
        ));
    }
    if trust.status_authority == signer.key {
        return Err(CheckpointMembershipError::SignerStatusTrustInvalid(
            checkpoint_seq,
        ));
    }
    let mut matching = trust.signed_statuses.iter().filter(|signed| {
        let status = &signed.body;
        status.status_ref == signer.revocation_status_ref
            && status.authority_id == signer.authority_id
            && status.key == signer.key
            && status.key_epoch == signer.key_epoch
    });
    let Some(signed_status) = matching.next() else {
        return Err(CheckpointMembershipError::SignerStatusUnavailable(
            checkpoint_seq,
        ));
    };
    if matching.next().is_some() {
        return Err(CheckpointMembershipError::DuplicateSignerStatus(
            checkpoint_seq,
        ));
    }
    verify_signed_authority_status(signed_status, &trust.status_authority)
        .map_err(|_| CheckpointMembershipError::SignerStatusSignatureInvalid(checkpoint_seq))?;
    let status = &signed_status.body;
    if status.observed_at < checkpoint_issued_at
        || status.observed_at > trusted_time
        || trusted_time.saturating_sub(status.observed_at) > trust.max_age_secs
    {
        return Err(CheckpointMembershipError::SignerStatusStale(checkpoint_seq));
    }
    // A checkpoint's issued_at is signer-controlled. Once the independently
    // authenticated feed reports revocation, the signer can backdate a new
    // checkpoint, so no such unanchored checkpoint remains admissible.
    if status.revoked_from.is_some() {
        return Err(CheckpointMembershipError::SignerRevoked(checkpoint_seq));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use chio_core_types::crypto::{Keypair, PublicKey, Signature};
    use chio_core_types::receipt::lineage::SignedExportEnvelope;
    use chio_finding::{
        FindingAuthorityKeyPolicy, FindingAuthorityStatus, FINDING_AUTHORITY_STATUS_SCHEMA_V1,
    };
    use chio_kernel::checkpoint::{build_checkpoint, verify_checkpoint_signature};

    use crate::verify::FindingCheckpointSignerStatusTrust;

    use super::{
        has_strict_checkpoint_signature, verify_checkpoint_signer_status, CheckpointMembershipError,
    };

    #[test]
    fn strict_checkpoint_signature_rejects_a_weak_ed25519_key() -> Result<(), Box<dyn Error>> {
        let weak_key = PublicKey::from_hex(
            "0100000000000000000000000000000000000000000000000000000000000000",
        )?;
        let forged_signature = Signature::from_hex(
            "0100000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000",
        )?;
        let signer = Keypair::from_seed(&[7; 32]);
        let mut checkpoint = build_checkpoint(1, 1, 1, &[b"receipt".to_vec()], &signer)?;
        checkpoint.body.kernel_key = weak_key;
        checkpoint.signature = forged_signature;

        assert!(verify_checkpoint_signature(&checkpoint)?);
        assert!(!has_strict_checkpoint_signature(&checkpoint));
        Ok(())
    }

    #[test]
    fn checkpoint_status_authority_must_differ_from_signer() -> Result<(), Box<dyn Error>> {
        let signer = Keypair::from_seed(&[31; 32]);
        let signer_key = signer.public_key();
        let policy = FindingAuthorityKeyPolicy {
            authority_id: "checkpoint-signer".to_owned(),
            key: signer_key.clone(),
            key_epoch: 1,
            valid_from: 1,
            valid_until: 200,
            rotation_policy_ref: "rotation/checkpoint-signer".to_owned(),
            revocation_status_ref: "revocations/checkpoint-signer".to_owned(),
        };
        let signed_status = SignedExportEnvelope::sign(
            FindingAuthorityStatus {
                schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_owned(),
                status_ref: policy.revocation_status_ref.clone(),
                authority_id: policy.authority_id.clone(),
                key: signer_key.clone(),
                key_epoch: policy.key_epoch,
                revoked_from: None,
                observed_at: 105,
            },
            &signer,
        )?;
        let trust = FindingCheckpointSignerStatusTrust {
            signed_statuses: vec![signed_status],
            status_authority: signer_key,
            max_age_secs: 60,
        };

        assert_eq!(
            verify_checkpoint_signer_status(&policy, 7, 100, 110, Some(&trust)),
            Err(CheckpointMembershipError::SignerStatusTrustInvalid(7))
        );
        Ok(())
    }
}
