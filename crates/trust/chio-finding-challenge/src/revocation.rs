//! What an offered revocation statement establishes about one signing key.
//!
//! Revocation is the only fact in this lane that arrives after the profile
//! was published, and it is the one fact that can turn a receipt the venue's
//! log commits, signed by the authority the profile pins, inside its validity
//! window, into affirmative fraud. It therefore carries the same burden as
//! every other authority here: a signature from the pinned governance root,
//! over a body that names the exact key policy it withdraws.
//!
//! Binding to the policy is what makes the feed matter. The profile pins a
//! `revocation_status_ref` per authority key, so a statement counts only when
//! it was published on that feed, for that `authority_id`, over that `key`,
//! at that `key_epoch`. Without those four, a governance signature over any
//! deployment's revocation would revoke any other deployment's key, and a
//! statement about a rotated-out epoch would revoke its successor.
//!
//! Everything a statement fails to prove leaves the key's standing unknown,
//! and unknown is reported as unknown. A blob that does not authenticate is
//! not evidence that the key was sound, and it is not evidence that it was
//! not.

use chio_core_types::crypto::PublicKey;
use chio_finding::{
    verify_signed_authority_status, verify_signed_key_revocation, FindingAuthorityKeyPolicy,
};

use crate::input::{FindingRetainedAuthorityPolicy, FindingRevokedKeyProof};
use crate::receipts::MAX_AUTHORITY_STATUS_AGE_SECS;

/// What the offered statements establish about one key at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyRevocationStanding {
    /// No offered statement speaks about this key.
    NoneOffered,
    /// A statement speaks about this key but is not the profile's own, so
    /// nothing about the key's standing follows from it.
    NotEstablished,
    /// Established, holding from at or before the instant under test.
    RevokedAtOrBefore,
    /// Established, holding only from after the instant under test.
    RevokedAfter,
}

/// Classify every offered statement that speaks about `key` against the
/// policy the profile pins for it.
///
/// The unestablished case wins over the established ones. A statement the
/// evaluator cannot authenticate leaves the key's standing open, and an open
/// question is not settled by another statement that happens to authenticate.
pub(crate) fn revocation_standing(
    proofs: &[FindingRevokedKeyProof<'_>],
    policy: Option<&FindingAuthorityKeyPolicy>,
    key: &PublicKey,
    governance_policy: FindingRetainedAuthorityPolicy<'_>,
    pinned_status_authority: &PublicKey,
    evaluated_at: u64,
    instant: u64,
) -> KeyRevocationStanding {
    let mut standing = KeyRevocationStanding::NoneOffered;
    for proof in proofs {
        // The claimed subject is read from unverified bytes on purpose: a blob
        // that claims to withdraw this key is exactly what must not be
        // silently discarded when it fails to authenticate.
        if proof.statement.body.key != *key {
            continue;
        }
        if !policy.is_some_and(|policy| {
            authenticates(
                proof,
                policy,
                governance_policy,
                pinned_status_authority,
                evaluated_at,
            )
        }) {
            return KeyRevocationStanding::NotEstablished;
        }
        if proof.statement.body.revoked_from <= instant {
            standing = KeyRevocationStanding::RevokedAtOrBefore;
        } else if standing != KeyRevocationStanding::RevokedAtOrBefore {
            standing = KeyRevocationStanding::RevokedAfter;
        }
    }
    standing
}

/// Whether one statement is the committed profile's own revocation for the
/// key policy it claims to withdraw.
fn authenticates(
    proof: &FindingRevokedKeyProof<'_>,
    policy: &FindingAuthorityKeyPolicy,
    governance_policy: FindingRetainedAuthorityPolicy<'_>,
    pinned_status_authority: &PublicKey,
    evaluated_at: u64,
) -> bool {
    if verify_signed_key_revocation(proof.statement, governance_policy.key).is_err() {
        return false;
    }
    let body = &proof.statement.body;
    if body.revocation_status_ref != policy.revocation_status_ref
        || body.authority_id != policy.authority_id
        || body.key != policy.key
        || body.key_epoch != policy.key_epoch
        || body.recorded_at < governance_policy.valid_from
        || body.recorded_at >= governance_policy.valid_until
        || body.recorded_at > evaluated_at
    {
        return false;
    }
    if verify_signed_authority_status(proof.governance_authority_status, pinned_status_authority)
        .is_err()
    {
        return false;
    }
    if verify_signed_authority_status(proof.publication_status, pinned_status_authority).is_err() {
        return false;
    }
    let publication = &proof.publication_status.body;
    if publication.status_ref != policy.revocation_status_ref
        || publication.authority_id != policy.authority_id
        || publication.key != policy.key
        || publication.key_epoch != policy.key_epoch
        || publication.revoked_from != Some(body.revoked_from)
        || publication.observed_at < body.recorded_at
        || publication.observed_at > evaluated_at
    {
        return false;
    }
    let status = &proof.governance_authority_status.body;
    status.status_ref == governance_policy.revocation_status_ref
        && status.authority_id == governance_policy.authority_id
        && status.key == *governance_policy.key
        && status.key_epoch == governance_policy.key_epoch
        && status.observed_at >= publication.observed_at
        && status.observed_at <= evaluated_at
        && evaluated_at.saturating_sub(status.observed_at) <= MAX_AUTHORITY_STATUS_AGE_SECS
        && status.revoked_from.is_none_or(|revoked_from| {
            revoked_from > publication.observed_at && revoked_from <= status.observed_at
        })
}
