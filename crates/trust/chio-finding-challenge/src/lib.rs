//! The pure finding-challenge evaluator: a signed challenge plus the exact
//! evidence its class selects, in; one typed verdict the caller signs, out.
//!
//! The crate boundary is the guarantee. This evaluator performs no fetching,
//! no tool invocation, no clock read, no storage access, and no signing. It
//! takes every input as an argument and returns a value, so an adjudication
//! cannot depend on anything that was not handed to it and cannot be made to
//! depend on when it ran. Resolution (pulling receipt bytes, checkpoints,
//! retained blobs, revocation state) belongs to the coordinator that owns the
//! clock and the store; signing the outcome belongs to the pinned evaluator
//! authority.
//!
//! Three verdicts, and the difference between them is load-bearing:
//!
//! - `Upheld` means affirmative fraud was established under the profile the
//!   publication committed. It is the only verdict that may enter the penalty
//!   lane.
//! - `Rejected` means the evidence was evaluable and did not show fraud.
//! - `Indeterminate` means authority, retention, resolver, or infrastructure
//!   inputs could not be established, in which case the evaluator says so
//!   rather than clearing or condemning the seller.
//!
//! [`FindingChallengeReason`] encodes that distinction structurally: the
//! verdict is DERIVED from the reason, so no caller can pair an
//! infrastructure failure with a sanction or read a clean evaluation as an
//! unresolved one.
//!
//! A submission that never becomes evaluable at all (a cross-class pairing, a
//! standing artifact that does not bind, a recipe preimage that does not hash
//! to the finding's commitment) returns [`FindingChallengeEvaluation::Inadmissible`]
//! and yields no verdict and no signable outcome.

#![forbid(unsafe_code)]

mod digest_mismatch;
mod evaluate;
mod evidence_invalid;
mod ingress;
mod input;
mod reason;
mod receipts;
mod replay_contradiction;
mod revocation;
mod standing;

pub use evaluate::evaluate_finding_challenge;
pub use ingress::FindingIngressError;
pub use input::{
    FindingChallengeAdjudication, FindingChallengeClassEvidence, FindingChallengeEvaluation,
    FindingChallengeEvaluationInput, FindingChallengeInadmissible, FindingDigestMismatchEvidence,
    FindingEvidenceInvalidEvidence, FindingReplayContradictionEvidence,
    FindingResolvedReproduction, FindingRevokedKeyProof,
};
pub use reason::{FindingChallengeReason, FindingChallengeReasonClass};
