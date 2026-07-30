//! Class-independent gates, then dispatch to the one branch the challenge
//! selected.
//!
//! Everything here runs before any class evidence is read, and every failure
//! is inadmissibility rather than a verdict: a submission that does not bind
//! the finding it names, or pairs a class with a finding the closed
//! compatibility matrix refuses, was never a challenge against this seller.

use chio_core_types::crypto::{sha256_hex, PublicKey};
use chio_finding::{
    ensure_challenge_class_compatibility, signed_envelope_sha256, verify_finding,
    verify_pinned_envelope, verify_signed_challenge, Finding, FindingChallenge,
    FindingChallengeAuthorization, FindingChallengeEvidence, FindingChallengeVerifierProfile,
};
use chio_finding_verifier::MAX_RAW_FINDING_BYTES;

use crate::digest_mismatch::evaluate_digest_mismatch;
use crate::evidence_invalid::evaluate_evidence_invalid;
use crate::ingress::strict_parse;
use crate::input::{
    FindingChallengeClassEvidence, FindingChallengeEvaluation, FindingChallengeEvaluationInput,
    FindingChallengeInadmissible,
};
use crate::replay_contradiction::evaluate_replay_contradiction;

/// The class-independent facts every branch reads, established once.
pub(crate) struct EvaluationContext<'a> {
    pub(crate) challenge: &'a FindingChallenge,
    pub(crate) finding: &'a Finding,
    pub(crate) profile: &'a FindingChallengeVerifierProfile,
    pub(crate) profile_envelope_sha256: &'a str,
    /// The buyer whose standing the submission rests on, when the submission
    /// is a buyer filing. A venue audit has no challenger and no standing.
    pub(crate) challenger: Option<&'a PublicKey>,
}

/// Adjudicate one challenge.
///
/// The evaluator is pure over its arguments: no fetch, no tool call, no clock
/// read, no storage access, and no signing. The caller signs the returned
/// verdict under the pinned evaluator authority.
pub fn evaluate_finding_challenge(
    input: &FindingChallengeEvaluationInput<'_>,
) -> FindingChallengeEvaluation {
    match adjudicate(input) {
        Ok(evaluation) => evaluation,
        Err(inadmissible) => FindingChallengeEvaluation::Inadmissible(inadmissible),
    }
}

fn adjudicate(
    input: &FindingChallengeEvaluationInput<'_>,
) -> Result<FindingChallengeEvaluation, FindingChallengeInadmissible> {
    // The challenge is re-verified from its own bytes. The caller has done
    // this at ingress; doing it again costs one signature check and removes
    // the assumption.
    verify_signed_challenge(input.challenge, input.pinned_audit_authority)
        .map_err(FindingChallengeInadmissible::ChallengeRejected)?;
    let challenge = &input.challenge.body;

    // The profile is a precondition, not evidence: with an unverified profile
    // no role key below means anything.
    verify_pinned_envelope(input.profile, input.governance_authority, "profile")
        .map_err(FindingChallengeInadmissible::ProfileRejected)?;
    input
        .profile
        .body
        .validate()
        .map_err(FindingChallengeInadmissible::ProfileRejected)?;
    let profile_envelope_sha256 = signed_envelope_sha256(input.profile)
        .map_err(FindingChallengeInadmissible::ProfileRejected)?;
    if profile_envelope_sha256 != challenge.profile_envelope_sha256 {
        return Err(FindingChallengeInadmissible::ProfileBindingMismatch);
    }

    // Strict raw ingress for the finding: the typed view is derived from the
    // exact bytes whose digest the challenge binds, never handed in beside
    // them.
    let (finding, finding_bytes) =
        strict_parse::<Finding>(input.raw_finding, MAX_RAW_FINDING_BYTES)
            .map_err(FindingChallengeInadmissible::FindingIngress)?;
    verify_finding(&finding).map_err(FindingChallengeInadmissible::FindingRejected)?;
    if sha256_hex(&finding_bytes) != challenge.finding_artifact_sha256 {
        return Err(FindingChallengeInadmissible::FindingBindingMismatch(
            "finding_artifact_sha256",
        ));
    }
    if finding.finding_id != challenge.finding_id {
        return Err(FindingChallengeInadmissible::FindingBindingMismatch(
            "finding_id",
        ));
    }

    // The closed compatibility matrix is the only gate between a challenge
    // class and the finding it targets, and it needs both.
    ensure_challenge_class_compatibility(
        challenge.evidence.kind(),
        finding.guarantee_class,
        finding.evidence_class,
    )
    .map_err(FindingChallengeInadmissible::ClassIncompatible)?;

    let challenger = match &challenge.authorization {
        FindingChallengeAuthorization::BuyerSubmission(submission) => Some(&submission.challenger),
        FindingChallengeAuthorization::VenueAudit(_) => None,
    };
    let context = EvaluationContext {
        challenge,
        finding: &finding,
        profile: &input.profile.body,
        profile_envelope_sha256: &profile_envelope_sha256,
        challenger,
    };

    let adjudication = match (&challenge.evidence, input.evidence) {
        (
            FindingChallengeEvidence::DigestMismatch {
                failed_delivery_envelope_sha256,
                deny_receipt_ref,
                deny_checkpoint_ref,
            },
            FindingChallengeClassEvidence::DigestMismatch(evidence),
        ) => evaluate_digest_mismatch(
            &context,
            failed_delivery_envelope_sha256,
            deny_receipt_ref,
            deny_checkpoint_ref,
            evidence,
        )?,
        (
            FindingChallengeEvidence::EvidenceInvalid {
                challenged_evidence_receipt_refs,
                challenged_checkpoint_ref,
                purchase_record_envelope_sha256,
            },
            FindingChallengeClassEvidence::EvidenceInvalid(evidence),
        ) => evaluate_evidence_invalid(
            &context,
            challenged_evidence_receipt_refs,
            challenged_checkpoint_ref,
            purchase_record_envelope_sha256,
            evidence,
        )?,
        (
            FindingChallengeEvidence::ReplayContradiction {
                reproduction,
                recipe_preimage,
                purchase_record_envelope_sha256,
            },
            FindingChallengeClassEvidence::ReplayContradiction(evidence),
        ) => evaluate_replay_contradiction(
            &context,
            reproduction,
            recipe_preimage,
            purchase_record_envelope_sha256,
            evidence,
        )?,
        _ => return Err(FindingChallengeInadmissible::ClassEvidenceMismatch),
    };
    Ok(FindingChallengeEvaluation::Adjudicated(adjudication))
}
