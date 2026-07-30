//! The `evidence_invalid` branch.
//!
//! The contested subset is cross-checked against the finding first: a
//! challenge may only contest receipts the finding actually named, under the
//! checkpoint the finding actually named. Then the subset is re-verified, and
//! only affirmative invalidity under the profile effective at publication can
//! support fraud: a signature that does not verify, a checkpoint proof that
//! contradicts the claimed membership, a receipt whose own commitment
//! contradicts its content, or a key proven revoked at publication time.
//!
//! Everything else that can go wrong here is an operational fact rather than
//! a seller's act. A blob that did not resolve, a signer this profile does not
//! establish for that role and time, a checkpoint that was never supplied, or
//! a key revoked only after publication all leave the question open, and the
//! evaluator says so instead of reading an outage as innocence or as guilt.
//!
//! The passes are ordered deliberately: resolution, then affirmative
//! invalidity, then unestablished inputs. Resolution runs first so a blob
//! nobody resolved can never be read as a contradiction, and invalidity runs
//! before the authority pass so a positively invalid receipt is not excused
//! by a key-lifecycle gap.

use chio_core_types::receipt::body::chio_receipt_id;
use chio_finding::{
    FindingChallengeFacet, FindingCheckpointRef, FindingEvidenceInvalidFacet,
    FindingEvidenceInvalidity, FindingReceiptRef, FindingReceiptRole,
};
use chio_finding_verifier::{
    verify_checkpoint_membership, verify_receipt_strict, ReceiptStrictError,
    ResolvedReceiptEvidence,
};

use crate::evaluate::EvaluationContext;
use crate::input::{
    FindingChallengeAdjudication, FindingChallengeInadmissible, FindingEvidenceInvalidEvidence,
};
use crate::reason::FindingChallengeReason;
use crate::receipts::{
    checkpoint_matches_reference, membership_contradicts, policy_covers, receipt_matches_reference,
    role_policy,
};
use crate::standing::bind_purchase_record;

pub(crate) fn evaluate_evidence_invalid(
    context: &EvaluationContext<'_>,
    challenged_refs: &[FindingReceiptRef],
    challenged_checkpoint_ref: &FindingCheckpointRef,
    purchase_record_envelope_sha256: &str,
    evidence: &FindingEvidenceInvalidEvidence<'_>,
) -> Result<FindingChallengeAdjudication, FindingChallengeInadmissible> {
    bind_purchase_record(
        context,
        evidence.purchase_record,
        purchase_record_envelope_sha256,
    )?;

    // A challenge may only contest evidence the finding itself named, under
    // the checkpoint the finding itself named. Anything else is a challenge
    // about a different artifact.
    for reference in challenged_refs {
        if !context
            .finding
            .evidence_receipt_ids
            .contains(&reference.receipt_id)
        {
            return Err(FindingChallengeInadmissible::EvidenceBindingMismatch(
                "challenged_evidence_receipt_refs",
            ));
        }
    }
    if challenged_checkpoint_ref.checkpoint_ref != context.finding.evidence_checkpoint_ref {
        return Err(FindingChallengeInadmissible::EvidenceBindingMismatch(
            "challenged_checkpoint_ref",
        ));
    }
    if evidence.challenged_receipts.len() != challenged_refs.len() {
        return Err(FindingChallengeInadmissible::EvidenceSetMismatch(
            "challenged_receipts",
        ));
    }

    let challenged_ids: Vec<String> = challenged_refs
        .iter()
        .map(|reference| reference.receipt_id.clone())
        .collect();

    // Pass 1: resolution. The supplied bytes must BE the artifacts the
    // finding and the challenge name.
    for (reference, resolved) in challenged_refs.iter().zip(evidence.challenged_receipts) {
        if !receipt_matches_reference(resolved, &reference.receipt_id, &reference.receipt_sha256)
            || !recomputes_to(resolved, &reference.receipt_id)
        {
            return Ok(adjudication(
                &challenged_ids,
                FindingEvidenceInvalidity::InputsUnavailable,
                FindingChallengeReason::EvidenceReceiptNotEstablished,
            ));
        }
    }
    if !checkpoint_matches_reference(evidence.challenged_checkpoint, challenged_checkpoint_ref) {
        return Ok(adjudication(
            &challenged_ids,
            FindingEvidenceInvalidity::InputsUnavailable,
            FindingChallengeReason::EvidenceCheckpointNotEstablished,
        ));
    }

    // Pass 2: affirmative invalidity.
    for resolved in evidence.challenged_receipts {
        if let Err(error) = verify_receipt_strict(&resolved.receipt) {
            return Ok(match error {
                // The bytes do not recompute to the identifier they claim,
                // so they are not provably the finding's receipt at all.
                ReceiptStrictError::ReceiptIdMismatch => adjudication(
                    &challenged_ids,
                    FindingEvidenceInvalidity::InputsUnavailable,
                    FindingChallengeReason::EvidenceReceiptNotEstablished,
                ),
                ReceiptStrictError::SignatureInvalid
                | ReceiptStrictError::BbsBindingInvalid
                | ReceiptStrictError::UnsupportedKeyAlgorithm
                | ReceiptStrictError::WeakKernelKey => adjudication(
                    &challenged_ids,
                    FindingEvidenceInvalidity::SignatureInvalid,
                    FindingChallengeReason::EvidenceSignatureInvalid,
                ),
            });
        }
        // The receipt's own action commitment must match the parameters it
        // carries. A receipt that contradicts itself does not bind the claim
        // it was offered for.
        if !matches!(resolved.receipt.action.verify_hash(), Ok(true)) {
            return Ok(adjudication(
                &challenged_ids,
                FindingEvidenceInvalidity::SemanticCrossBindingFailure,
                FindingChallengeReason::EvidenceSemanticCrossBindingFailure,
            ));
        }
        if revoked_at_or_before(evidence, resolved, context.finding.issued_at) {
            return Ok(adjudication(
                &challenged_ids,
                FindingEvidenceInvalidity::KeyRevokedAtPublication,
                FindingChallengeReason::EvidenceKeyRevokedAtPublication,
            ));
        }
    }
    if let Err(error) = verify_checkpoint_membership(
        evidence.challenged_receipts,
        core::slice::from_ref(evidence.challenged_checkpoint),
        context.profile,
        &challenged_checkpoint_ref.checkpoint_ref,
    ) {
        let (invalidity, reason) = if membership_contradicts(&error) {
            (
                FindingEvidenceInvalidity::CheckpointContradiction,
                FindingChallengeReason::EvidenceCheckpointContradiction,
            )
        } else {
            (
                FindingEvidenceInvalidity::InputsUnavailable,
                FindingChallengeReason::EvidenceCheckpointNotEstablished,
            )
        };
        return Ok(adjudication(&challenged_ids, invalidity, reason));
    }

    // Pass 3: inputs the profile does not establish for this evidence.
    let Some(production_policy) = role_policy(context.profile, FindingReceiptRole::Production)
    else {
        return Ok(adjudication(
            &challenged_ids,
            FindingEvidenceInvalidity::InputsUnavailable,
            FindingChallengeReason::EvidenceAuthorityNotEstablished,
        ));
    };
    for resolved in evidence.challenged_receipts {
        if resolved.receipt.kernel_key != production_policy.key
            || !policy_covers(production_policy, context.finding.issued_at)
        {
            return Ok(adjudication(
                &challenged_ids,
                FindingEvidenceInvalidity::InputsUnavailable,
                FindingChallengeReason::EvidenceAuthorityNotEstablished,
            ));
        }
        if revokes_after(evidence, resolved, context.finding.issued_at) {
            return Ok(adjudication(
                &challenged_ids,
                FindingEvidenceInvalidity::InputsUnavailable,
                FindingChallengeReason::EvidenceKeyRevokedAfterPublication,
            ));
        }
    }

    Ok(adjudication(
        &challenged_ids,
        FindingEvidenceInvalidity::NoAffirmativeInvalidity,
        FindingChallengeReason::ChallengedEvidenceValid,
    ))
}

fn recomputes_to(resolved: &ResolvedReceiptEvidence, receipt_id: &str) -> bool {
    matches!(chio_receipt_id(&resolved.receipt.body()), Ok(id) if id == receipt_id)
}

/// Whether a resolved proof establishes that this receipt's signing key was
/// already revoked or compromised when the finding was published.
fn revoked_at_or_before(
    evidence: &FindingEvidenceInvalidEvidence<'_>,
    resolved: &ResolvedReceiptEvidence,
    published_at: u64,
) -> bool {
    evidence.revoked_keys.iter().any(|proof| {
        *proof.key == resolved.receipt.kernel_key && proof.revoked_from <= published_at
    })
}

/// Whether the only revocation proof for this key begins after publication.
fn revokes_after(
    evidence: &FindingEvidenceInvalidEvidence<'_>,
    resolved: &ResolvedReceiptEvidence,
    published_at: u64,
) -> bool {
    evidence
        .revoked_keys
        .iter()
        .any(|proof| *proof.key == resolved.receipt.kernel_key && proof.revoked_from > published_at)
}

/// Build the facet and the verdict from one decision. The facet's invalidity
/// member carries its own total verdict mapping, and the outcome validator
/// rechecks that it equals the top-level verdict, so the two are constructed
/// together here rather than chosen separately.
fn adjudication(
    challenged_receipt_ids: &[String],
    invalidity: FindingEvidenceInvalidity,
    reason: FindingChallengeReason,
) -> FindingChallengeAdjudication {
    debug_assert_eq!(invalidity.verdict(), reason.verdict());
    FindingChallengeAdjudication::new(
        FindingChallengeFacet::EvidenceInvalid(FindingEvidenceInvalidFacet {
            challenged_receipt_ids: challenged_receipt_ids.to_vec(),
            invalidity,
        }),
        reason,
    )
}
