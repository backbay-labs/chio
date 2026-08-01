//! The `evidence_invalid` branch.
//!
//! The contested subset is cross-checked against the finding first: a
//! challenge may only contest receipts the finding actually named, under the
//! checkpoint the finding actually named. Then the subset is re-verified, and
//! only affirmative invalidity under the profile effective at publication can
//! support fraud: a signature that does not verify, a receipt whose own
//! commitment contradicts its content, or a key the pinned governance root
//! withdrew as of publication time.
//!
//! Everything else that can go wrong here is an operational fact rather than
//! a seller's act. A blob that did not resolve, a signer this profile does not
//! establish for that role and time, a checkpoint that was never supplied, an
//! invalid resolver-supplied inclusion path, a revocation that is not the
//! profile's own, or a key withdrawn only after publication all leave the
//! question open, and the evaluator says so instead of reading an outage as
//! innocence or as guilt.
//!
//! The passes are ordered deliberately: resolution, then anchoring, then
//! affirmative invalidity, then unestablished inputs. Resolution runs first
//! so a blob nobody resolved can never be read as a contradiction. Anchoring
//! runs next because a receipt's content address covers its body while its
//! signature lives outside that address, and the digests the challenge
//! carries are the challenger's own claim: the venue's signed checkpoint,
//! whose leaf IS the canonical receipt envelope, is the only artifact that
//! pins the exact bytes, so bytes nobody proved to be that leaf can never be
//! read as the seller's act. Invalidity then runs before the authority pass
//! so a positively invalid receipt is not excused by a key-lifecycle gap.

use chio_core_types::receipt::body::chio_receipt_id;
use chio_finding::{
    FindingAuthorityKeyPolicy, FindingChallengeFacet, FindingCheckpointRef,
    FindingEvidenceInvalidFacet, FindingEvidenceInvalidity, FindingReceiptRef, FindingReceiptRole,
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
    checkpoint_matches_reference, policy_covers, receipt_matches_reference, role_policy,
};
use crate::revocation::{revocation_standing, KeyRevocationStanding};
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

    // Pass 2: anchoring. Membership against the log the finding committed is
    // what makes a byte string the seller's artifact rather than the
    // challenger's, so it is established before anything about those bytes
    // can support fraud.
    if verify_checkpoint_membership(
        evidence.challenged_receipts,
        core::slice::from_ref(evidence.challenged_checkpoint),
        evidence.checkpoint_transparency,
        context.profile,
        &challenged_checkpoint_ref.checkpoint_ref,
    )
    .is_err()
    {
        // Bytes that fail strict verification and are not the checkpointed
        // leaf establish nothing: anyone holding the finding's receipt can
        // mint them, because the envelope's signature is outside the content
        // address the finding names.
        for resolved in evidence.challenged_receipts {
            if verify_receipt_strict(&resolved.receipt).is_err() {
                return Ok(adjudication(
                    &challenged_ids,
                    FindingEvidenceInvalidity::InputsUnavailable,
                    FindingChallengeReason::EvidenceReceiptNotEstablished,
                ));
            }
        }
        // Inclusion paths live only in the resolver-supplied wrapper. A path
        // that does not reach the signed checkpoint root can therefore be
        // malformed caller input, not affirmative proof that the seller's
        // receipt was absent from the checkpoint.
        return Ok(adjudication(
            &challenged_ids,
            FindingEvidenceInvalidity::InputsUnavailable,
            FindingChallengeReason::EvidenceCheckpointNotEstablished,
        ));
    }

    // A revocation is only the profile's own when it withdraws the exact key
    // policy the profile pins, so that policy is resolved before any pass can
    // read a revocation. Its absence is settled in pass 4, where every other
    // unestablished authority is.
    let production_policy = role_policy(context.profile, FindingReceiptRole::Production);

    // Pass 3: affirmative invalidity, over bytes the venue's log commits.
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
        if standing_of(context, evidence, resolved, production_policy)
            == KeyRevocationStanding::RevokedAtOrBefore
        {
            return Ok(adjudication(
                &challenged_ids,
                FindingEvidenceInvalidity::KeyRevokedAtPublication,
                FindingChallengeReason::EvidenceKeyRevokedAtPublication,
            ));
        }
    }

    // Pass 4: inputs the profile does not establish for this evidence.
    let Some(production_policy) = production_policy else {
        return Ok(adjudication(
            &challenged_ids,
            FindingEvidenceInvalidity::InputsUnavailable,
            FindingChallengeReason::EvidenceAuthorityNotEstablished,
        ));
    };
    for resolved in evidence.challenged_receipts {
        // A key policy states when the key was an authority, so the instant
        // it is tested at is the one the receipt was signed at.
        if resolved.receipt.kernel_key != production_policy.key
            || !policy_covers(production_policy, resolved.receipt.timestamp)
        {
            return Ok(adjudication(
                &challenged_ids,
                FindingEvidenceInvalidity::InputsUnavailable,
                FindingChallengeReason::EvidenceAuthorityNotEstablished,
            ));
        }
        let reason = match standing_of(context, evidence, resolved, Some(production_policy)) {
            KeyRevocationStanding::NotEstablished => {
                FindingChallengeReason::EvidenceKeyRevocationNotEstablished
            }
            KeyRevocationStanding::RevokedAfter => {
                FindingChallengeReason::EvidenceKeyRevokedAfterPublication
            }
            KeyRevocationStanding::NoneOffered | KeyRevocationStanding::RevokedAtOrBefore => {
                continue
            }
        };
        return Ok(adjudication(
            &challenged_ids,
            FindingEvidenceInvalidity::InputsUnavailable,
            reason,
        ));
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

/// What the offered statements establish about this receipt's signing key at
/// the instant the finding was published. Publication time, not "now", is the
/// instant that decides whether a withdrawn key could have produced evidence
/// the finding was entitled to name.
fn standing_of(
    context: &EvaluationContext<'_>,
    evidence: &FindingEvidenceInvalidEvidence<'_>,
    resolved: &ResolvedReceiptEvidence,
    policy: Option<&FindingAuthorityKeyPolicy>,
) -> KeyRevocationStanding {
    revocation_standing(
        evidence.revoked_keys,
        policy,
        &resolved.receipt.kernel_key,
        context.governance_authority,
        context.finding.issued_at,
    )
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
