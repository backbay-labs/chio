//! Shared receipt, checkpoint, and role-authority helpers.
//!
//! Signature and inclusion checks are not reimplemented here. The strict
//! receipt verifier and the full checkpoint-membership cross-check already
//! exist in the evidence verifier, and a second implementation would be a
//! second thing to get wrong. What this module adds is the binding layer the
//! challenge lane needs on top of them: that a resolved artifact IS the one
//! the submission named and that its signer is the role the committed profile
//! pins.

use chio_core_types::canonical_json_bytes;
use chio_core_types::crypto::{sha256_hex, PublicKey};
use chio_finding::{
    verify_signed_authority_status, FindingAuthorityKeyPolicy, FindingChallengeVerifierProfile,
    FindingCheckpointRef, FindingReceiptRole, FindingReceiptSignerRole,
    SignedFindingAuthorityStatus,
};
use chio_finding_verifier::ResolvedReceiptEvidence;
use chio_kernel::checkpoint::{checkpoint_body_sha256, KernelCheckpoint};

/// Maximum age of a role status reading at the trusted evaluation time.
pub(crate) const MAX_AUTHORITY_STATUS_AGE_SECS: u64 = 3_600;

/// Whether a resolved receipt IS the artifact a content-bound reference
/// names: the same identifier, the same canonical bytes, and a typed view
/// that does not drift from those bytes.
pub(crate) fn receipt_matches_reference(
    evidence: &ResolvedReceiptEvidence,
    receipt_id: &str,
    receipt_sha256: &str,
) -> bool {
    if evidence.receipt.id != receipt_id {
        return false;
    }
    if sha256_hex(&evidence.canonical_receipt_bytes) != receipt_sha256 {
        return false;
    }
    // The bytes offered as the checkpoint leaf must be the bytes of this
    // receipt, or membership would prove a different projection than the one
    // every other check reads.
    match canonical_json_bytes(&evidence.receipt) {
        Ok(bytes) => bytes == evidence.canonical_receipt_bytes,
        Err(_) => false,
    }
}

/// Whether a resolved checkpoint IS the artifact a content-bound reference
/// names. The digest convention is the canonical checkpoint body, the same
/// one the transparency records publish.
pub(crate) fn checkpoint_matches_reference(
    checkpoint: &KernelCheckpoint,
    reference: &FindingCheckpointRef,
) -> bool {
    match checkpoint_body_sha256(&checkpoint.body) {
        Ok(digest) => digest == reference.checkpoint_sha256,
        Err(_) => false,
    }
}

/// The key policy the profile pins for one receipt role. Profile validation
/// guarantees exactly one signer per role, so this is unambiguous.
pub(crate) fn role_policy(
    profile: &FindingChallengeVerifierProfile,
    role: FindingReceiptRole,
) -> Option<&FindingAuthorityKeyPolicy> {
    profile
        .receipt_signers
        .iter()
        .find(|signer: &&FindingReceiptSignerRole| signer.role == role)
        .map(|signer| &signer.policy)
}

/// Whether a pinned key policy covers an instant. Outside its window the key
/// is not an authority for that moment, whatever it is today.
pub(crate) fn policy_covers(policy: &FindingAuthorityKeyPolicy, instant: u64) -> bool {
    policy.valid_from <= instant && instant < policy.valid_until
}

/// Whether an independently signed status reading establishes that one role
/// key was live when it acted and remains fresh at evaluation time.
pub(crate) fn authority_status_establishes_role(
    signed: &SignedFindingAuthorityStatus,
    pinned_status_authority: &PublicKey,
    policy: &FindingAuthorityKeyPolicy,
    acted_at: u64,
    evaluated_at: u64,
) -> bool {
    if acted_at > evaluated_at
        || verify_signed_authority_status(signed, pinned_status_authority).is_err()
    {
        return false;
    }
    let status = &signed.body;
    status.status_ref == policy.revocation_status_ref
        && status.authority_id == policy.authority_id
        && status.key == policy.key
        && status.key_epoch == policy.key_epoch
        && status.observed_at >= acted_at
        && status.observed_at <= evaluated_at
        && evaluated_at.saturating_sub(status.observed_at) <= MAX_AUTHORITY_STATUS_AGE_SECS
        && status
            .revoked_from
            .is_none_or(|revoked_from| revoked_from > acted_at)
}

#[cfg(test)]
mod tests {
    use chio_core_types::crypto::Keypair;

    use super::*;

    #[test]
    fn authority_policy_excludes_its_expiration_boundary() {
        let policy = FindingAuthorityKeyPolicy {
            authority_id: "finding-receipt-authority".to_owned(),
            key: Keypair::from_seed(&[7_u8; 32]).public_key(),
            key_epoch: 1,
            valid_from: 10,
            valid_until: 20,
            rotation_policy_ref: "rotations/finding-receipt-authority".to_owned(),
            revocation_status_ref: "revocations/finding-receipt-authority".to_owned(),
        };

        assert!(policy_covers(&policy, 10));
        assert!(policy_covers(&policy, 19));
        assert!(!policy_covers(&policy, 20));
    }
}
