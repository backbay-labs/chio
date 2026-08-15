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
    verify_signed_authority_status, verify_signed_challenge, verify_signed_profile, Finding,
    FindingAuthorityKeyPolicy, FindingChallenge, FindingChallengeAuthorization,
    FindingChallengeEvidence, FindingChallengeVerifierProfile, SignedFindingAuthorityStatus,
};
use chio_finding_verifier::MAX_RAW_FINDING_BYTES;

use crate::digest_mismatch::evaluate_digest_mismatch;
use crate::evidence_invalid::evaluate_evidence_invalid;
use crate::ingress::strict_parse;
use crate::input::{
    FindingChallengeClassEvidence, FindingChallengeEvaluation, FindingChallengeEvaluationInput,
    FindingChallengeInadmissible, FindingRetainedAuthorityPolicy,
};
use crate::receipts::MAX_AUTHORITY_STATUS_AGE_SECS;
use crate::replay_contradiction::evaluate_replay_contradiction;

/// The class-independent facts every branch reads, established once.
pub(crate) struct EvaluationContext<'a> {
    pub(crate) challenge: &'a FindingChallenge,
    pub(crate) finding: &'a Finding,
    pub(crate) profile: &'a FindingChallengeVerifierProfile,
    pub(crate) profile_envelope_sha256: &'a str,
    /// The deployment's pinned governance root, the authority that signed
    /// this profile and the only one that may withdraw a key it pins.
    pub(crate) governance_policy: FindingRetainedAuthorityPolicy<'a>,
    /// Authority policy frozen by the exact retained venue admission.
    pub(crate) purchase_authority: &'a FindingAuthorityKeyPolicy,
    pub(crate) failed_delivery_authority: &'a FindingAuthorityKeyPolicy,
    pub(crate) purchase_authority_status: Option<&'a SignedFindingAuthorityStatus>,
    pub(crate) pinned_authority_status_key: &'a PublicKey,
    pub(crate) evaluated_at: u64,
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
    if input.evaluated_at < challenge.filed_at {
        return Err(FindingChallengeInadmissible::EvaluationPredatesFiling);
    }

    let status_key = input.pinned_authority_status_key;
    if status_key == input.governance_authority
        || status_key == input.pinned_audit_authority
        || status_key == &input.pinned_purchase_authority.key
        || status_key == &input.pinned_failed_delivery_authority.key
        || input
            .profile
            .body
            .receipt_signers
            .iter()
            .any(|signer| status_key == &signer.policy.key)
    {
        return Err(FindingChallengeInadmissible::AuthorityStatusRoleCollision);
    }

    // The profile is a precondition, not evidence: with an unverified profile
    // no role key below means anything.
    verify_signed_profile(input.profile, input.governance_authority)
        .map_err(FindingChallengeInadmissible::ProfileRejected)?;
    require_distinct_challenge_role_keys(input)?;
    let governance_policy = input.pinned_governance_policy;
    if governance_policy.key != input.governance_authority
        || governance_policy.authority_id.trim().is_empty()
        || governance_policy.authority_id.trim() != governance_policy.authority_id
        || governance_policy.key_epoch == 0
        || governance_policy.valid_until <= governance_policy.valid_from
        || governance_policy.revocation_status_ref.trim().is_empty()
        || governance_policy.revocation_status_ref.trim() != governance_policy.revocation_status_ref
    {
        return Err(FindingChallengeInadmissible::RetainedGovernancePolicyInvalid);
    }
    if input.profile.body.issued_at < governance_policy.valid_from
        || input.profile.body.issued_at >= governance_policy.valid_until
    {
        return Err(FindingChallengeInadmissible::RetainedGovernancePolicyNotLiveAtProfileIssuance);
    }
    if !governance_status_establishes_profile_issuance(input, governance_policy) {
        return Err(FindingChallengeInadmissible::RetainedGovernanceStatusNotEstablished);
    }
    let profile_envelope_sha256 = signed_envelope_sha256(input.profile)
        .map_err(FindingChallengeInadmissible::ProfileRejected)?;
    if profile_envelope_sha256 != input.pinned_admission_profile_envelope_sha256 {
        return Err(FindingChallengeInadmissible::AdmissionProfileBindingMismatch);
    }
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
        governance_policy: input.pinned_governance_policy,
        purchase_authority: input.pinned_purchase_authority,
        failed_delivery_authority: input.pinned_failed_delivery_authority,
        purchase_authority_status: input.purchase_authority_status,
        pinned_authority_status_key: input.pinned_authority_status_key,
        evaluated_at: input.evaluated_at,
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
            input.pinned_authority_status_key,
            input.evaluated_at,
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
            input.pinned_authority_status_key,
            input.evaluated_at,
            reproduction,
            recipe_preimage,
            purchase_record_envelope_sha256,
            evidence,
        )?,
        _ => return Err(FindingChallengeInadmissible::ClassEvidenceMismatch),
    };
    Ok(FindingChallengeEvaluation::Adjudicated(adjudication))
}

fn require_distinct_challenge_role_keys(
    input: &FindingChallengeEvaluationInput<'_>,
) -> Result<(), FindingChallengeInadmissible> {
    let profile = &input.profile.body;
    let authority_roles = [
        input.governance_authority,
        input.pinned_audit_authority,
        input.pinned_authority_status_key,
        &input.pinned_purchase_authority.key,
        &input.pinned_failed_delivery_authority.key,
        &profile.verifier_report_signer.key,
    ];
    for (index, key) in authority_roles.iter().enumerate() {
        if authority_roles
            .iter()
            .skip(index.saturating_add(1))
            .any(|candidate| candidate == key)
        {
            return Err(FindingChallengeInadmissible::AuthorityStatusRoleCollision);
        }
    }

    for signer in &profile.receipt_signers {
        if authority_roles.iter().any(|key| *key == &signer.policy.key) {
            return Err(FindingChallengeInadmissible::AuthorityStatusRoleCollision);
        }
    }
    for (index, signer) in profile.receipt_signers.iter().enumerate() {
        if profile
            .receipt_signers
            .iter()
            .skip(index.saturating_add(1))
            .any(|candidate| candidate.policy.key == signer.policy.key)
        {
            return Err(FindingChallengeInadmissible::AuthorityStatusRoleCollision);
        }
    }

    for checkpoint in &profile.checkpoint_logs {
        if authority_roles
            .iter()
            .any(|key| *key == &checkpoint.signer.key)
        {
            return Err(FindingChallengeInadmissible::AuthorityStatusRoleCollision);
        }
    }
    for (index, checkpoint) in profile.checkpoint_logs.iter().enumerate() {
        if profile
            .checkpoint_logs
            .iter()
            .skip(index.saturating_add(1))
            .any(|candidate| candidate.signer.key == checkpoint.signer.key)
        {
            return Err(FindingChallengeInadmissible::AuthorityStatusRoleCollision);
        }
    }
    Ok(())
}

fn governance_status_establishes_profile_issuance(
    input: &FindingChallengeEvaluationInput<'_>,
    policy: FindingRetainedAuthorityPolicy<'_>,
) -> bool {
    if input.profile.body.issued_at > input.evaluated_at
        || verify_signed_authority_status(
            input.governance_authority_status,
            input.pinned_authority_status_key,
        )
        .is_err()
    {
        return false;
    }
    let status = &input.governance_authority_status.body;
    status.status_ref == policy.revocation_status_ref
        && status.authority_id == policy.authority_id
        && status.key == *policy.key
        && status.key_epoch == policy.key_epoch
        && status.observed_at >= input.profile.body.issued_at
        && status.observed_at <= input.evaluated_at
        && input.evaluated_at.saturating_sub(status.observed_at) <= MAX_AUTHORITY_STATUS_AGE_SECS
        && status
            .revoked_from
            .is_none_or(|revoked_from| revoked_from > input.profile.body.issued_at)
}
