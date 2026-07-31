//! Shared receipt, checkpoint, and role-authority helpers.
//!
//! Signature and inclusion checks are not reimplemented here. The strict
//! receipt verifier and the full checkpoint-membership cross-check already
//! exist in the evidence verifier, and a second implementation would be a
//! second thing to get wrong. What this module adds is the binding layer the
//! challenge lane needs on top of them: that a resolved artifact IS the one
//! the submission named, that its signer is the role the committed profile
//! pins, and that a membership failure is classified as a contradiction or
//! merely as an input that could not be established.

use chio_core_types::canonical_json_bytes;
use chio_core_types::crypto::sha256_hex;
use chio_finding::{
    FindingAuthorityKeyPolicy, FindingChallengeVerifierProfile, FindingCheckpointRef,
    FindingReceiptRole, FindingReceiptSignerRole,
};
use chio_finding_verifier::{CheckpointMembershipError, ResolvedReceiptEvidence};
use chio_kernel::checkpoint::{checkpoint_body_sha256, KernelCheckpoint};

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
    policy.valid_from <= instant && instant <= policy.valid_until
}

/// Whether a membership failure positively contradicts the claimed proof, as
/// opposed to leaving membership unresolved.
///
/// The distinction decides a verdict, and only one failure carries the
/// authority to settle it. The checkpoint is the venue's signed artifact; the
/// inclusion wrapper around each receipt is not signed by anyone, and the
/// caller resolves it. So an inclusion path that fails against the signed
/// root, from a wrapper the checkpoint itself agrees with, is evidence that
/// the claimed anchoring never happened: the venue's own root does not carry
/// those bytes at the position its sequencing implies.
///
/// Everything else leaves membership unresolved. A checkpoint that is
/// malformed, that does not verify under the log signer the profile pins, or
/// that arrives unpinned, duplicated, misidentified, or not at all is an
/// unauthenticated blob anyone could present. A wrapper that disagrees with
/// the signed checkpoint about the root, the tree size, or the leaf position,
/// or that repeats a receipt sequence, is a resolver defect. Neither says
/// anything about the seller, in either direction.
pub(crate) fn membership_contradicts(error: &CheckpointMembershipError) -> bool {
    match error {
        CheckpointMembershipError::InclusionInvalid => true,
        CheckpointMembershipError::NoCheckpoints
        | CheckpointMembershipError::DuplicateProof(_)
        | CheckpointMembershipError::ReceiptSeqOutOfRange(_)
        | CheckpointMembershipError::LeafIndexMismatch
        | CheckpointMembershipError::TreeSizeMismatch
        | CheckpointMembershipError::LeafOffsetMismatch
        | CheckpointMembershipError::RootMismatch
        | CheckpointMembershipError::CheckpointInvalid(_)
        | CheckpointMembershipError::CheckpointSignatureInvalid(_)
        | CheckpointMembershipError::DuplicateCheckpoint(_)
        | CheckpointMembershipError::LogNotPinned(_)
        | CheckpointMembershipError::SignerNotPinned(_)
        | CheckpointMembershipError::UnknownCheckpoint(_)
        | CheckpointMembershipError::CheckpointRefMismatch => false,
    }
}
