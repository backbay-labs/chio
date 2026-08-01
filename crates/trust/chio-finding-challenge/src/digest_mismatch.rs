//! The `digest_mismatch` branch.
//!
//! This branch is live only for an authenticated seller-origin mismatch under
//! the marked identity output profile: the kernel compared the delivered
//! reveal against the digest the signed finding itself committed, under a
//! frozen empty transform plan, and they differed. Everything adjacent looks
//! similar and is not fraud. A generic digest denial carries no
//! finding-delivery overlay, so nothing establishes that the expectation was
//! the seller's own commitment. An output-policy denial compares against an
//! expectation the operator chose. A media-type denial is about the envelope,
//! not the payload. None of those may reach the sanction gate, and each has
//! its own reason here so the refusal is legible rather than incidental.
//!
//! The failed-delivery terminal is the standing: it is the positive evidence
//! that the denied reveal moved no value, which is also why this branch can
//! never manufacture a payout.

use chio_core_types::receipt::body::ChioReceipt;
use chio_core_types::receipt::decision::Decision;
use chio_core_types::{
    DeliveryContract, DeliveryResult, FindingDelivery, FindingDeliverySettlementMode,
    FindingMediaTypeCheck, FindingTransformProfile, DELIVERY_CONTRACT_METADATA_KEY,
    FINDING_DELIVERY_METADATA_KEY,
};
use chio_finding::{
    signed_envelope_sha256, verify_signed_failed_delivery, FindingChallengeFacet,
    FindingChallengeStanding, FindingCheckpointRef, FindingDigestMismatchFacet,
    FindingHoldReleaseTerminal, FindingReceiptRef, FindingReceiptRole,
};
use chio_finding_verifier::{verify_checkpoint_membership, verify_receipt_strict};

use crate::evaluate::EvaluationContext;
use crate::input::{
    FindingChallengeAdjudication, FindingChallengeInadmissible, FindingDigestMismatchEvidence,
};
use crate::reason::FindingChallengeReason;
use crate::receipts::{
    checkpoint_matches_reference, policy_covers, receipt_matches_reference, role_policy,
};

/// A metadata block as it was found on the receipt.
enum MetadataBlock<T> {
    Absent,
    Malformed,
    Present(T),
}

pub(crate) fn evaluate_digest_mismatch(
    context: &EvaluationContext<'_>,
    failed_delivery_envelope_sha256: &str,
    deny_receipt_ref: &FindingReceiptRef,
    deny_checkpoint_ref: &FindingCheckpointRef,
    evidence: &FindingDigestMismatchEvidence<'_>,
) -> Result<FindingChallengeAdjudication, FindingChallengeInadmissible> {
    let committed = context.finding.payload_sha256.as_str();

    // Standing first: an unbound or unauthenticated terminal is not a
    // submission this evaluator ever adjudicates.
    let failed_delivery_digest = signed_envelope_sha256(evidence.failed_delivery)
        .map_err(FindingChallengeInadmissible::StandingRejected)?;
    if failed_delivery_digest != failed_delivery_envelope_sha256 {
        return Err(FindingChallengeInadmissible::StandingBindingMismatch(
            "failed_delivery_envelope_sha256",
        ));
    }
    let failed_delivery_authority = &context.profile.failed_delivery_authority;
    verify_signed_failed_delivery(evidence.failed_delivery, &failed_delivery_authority.key)
        .map_err(FindingChallengeInadmissible::StandingRejected)?;
    let terminal = &evidence.failed_delivery.body;
    if terminal.finding_id != context.finding.finding_id {
        return Err(FindingChallengeInadmissible::StandingBindingMismatch(
            "finding_id",
        ));
    }
    if terminal.listing_id != context.challenge.listing_id {
        return Err(FindingChallengeInadmissible::StandingBindingMismatch(
            "listing_id",
        ));
    }
    if let Some(challenger) = context.challenger {
        if terminal.buyer != *challenger {
            return Err(FindingChallengeInadmissible::StandingBindingMismatch(
                "buyer",
            ));
        }
        // The buyer's standing branch names the terminal by id; the digest
        // equality is already enforced by the challenge validator.
        match &context.challenge.authorization {
            chio_finding::FindingChallengeAuthorization::BuyerSubmission(submission) => {
                match &submission.standing {
                    FindingChallengeStanding::FailedDelivery {
                        failed_delivery_id, ..
                    } if *failed_delivery_id == terminal.failed_delivery_id => {}
                    _ => {
                        return Err(FindingChallengeInadmissible::StandingBindingMismatch(
                            "failed_delivery_id",
                        ))
                    }
                }
            }
            chio_finding::FindingChallengeAuthorization::VenueAudit(_) => {}
        }
    }
    // The terminal and the evidence branch must name one denial, not two.
    if terminal.deny_receipt_id != deny_receipt_ref.receipt_id {
        return Err(FindingChallengeInadmissible::EvidenceBindingMismatch(
            "deny_receipt_id",
        ));
    }
    if terminal.deny_receipt_sha256 != deny_receipt_ref.receipt_sha256 {
        return Err(FindingChallengeInadmissible::EvidenceBindingMismatch(
            "deny_receipt_sha256",
        ));
    }
    if terminal.deny_checkpoint_ref != deny_checkpoint_ref.checkpoint_ref {
        return Err(FindingChallengeInadmissible::EvidenceBindingMismatch(
            "deny_checkpoint_ref",
        ));
    }
    if terminal.deny_checkpoint_sha256 != deny_checkpoint_ref.checkpoint_sha256 {
        return Err(FindingChallengeInadmissible::EvidenceBindingMismatch(
            "deny_checkpoint_sha256",
        ));
    }
    // The terminal's own release semantics are closed; both members leave the
    // buyer whole, and a future member would have to be classified here
    // rather than inherit safety by omission.
    match terminal.release_terminal {
        FindingHoldReleaseTerminal::Released
        | FindingHoldReleaseTerminal::CancelledBeforeAuthorization => {}
    }

    // A terminal signed outside the authority's own validity window does not
    // establish anything about the denial it describes.
    if !policy_covers(failed_delivery_authority, terminal.recorded_at) {
        return Ok(unresolved(
            committed,
            FindingChallengeReason::DeliveryAuthorityNotEstablished,
        ));
    }

    // Resolution: the supplied artifacts must BE the ones named.
    if !receipt_matches_reference(
        evidence.deny_receipt,
        &deny_receipt_ref.receipt_id,
        &deny_receipt_ref.receipt_sha256,
    ) {
        return Ok(unresolved(
            committed,
            FindingChallengeReason::DeliveryEvidenceNotEstablished,
        ));
    }
    if !checkpoint_matches_reference(evidence.deny_checkpoint, deny_checkpoint_ref) {
        return Ok(unresolved(
            committed,
            FindingChallengeReason::DeliveryCheckpointNotEstablished,
        ));
    }
    if verify_receipt_strict(&evidence.deny_receipt.receipt).is_err() {
        return Ok(unresolved(
            committed,
            FindingChallengeReason::DeliveryEvidenceNotEstablished,
        ));
    }
    let Some(delivery_policy) = role_policy(context.profile, FindingReceiptRole::Delivery) else {
        return Ok(unresolved(
            committed,
            FindingChallengeReason::DeliveryAuthorityNotEstablished,
        ));
    };
    let receipt = &evidence.deny_receipt.receipt;
    if receipt.kernel_key != delivery_policy.key
        || !policy_covers(delivery_policy, receipt.timestamp)
    {
        return Ok(unresolved(
            committed,
            FindingChallengeReason::DeliveryAuthorityNotEstablished,
        ));
    }
    if verify_checkpoint_membership(
        core::slice::from_ref(evidence.deny_receipt),
        core::slice::from_ref(evidence.deny_checkpoint),
        evidence.checkpoint_transparency,
        context.profile,
        &deny_checkpoint_ref.checkpoint_ref,
    )
    .is_err()
    {
        return Ok(unresolved(
            committed,
            FindingChallengeReason::DeliveryCheckpointNotEstablished,
        ));
    }
    if !matches!(receipt.decision, Some(Decision::Deny { .. })) {
        return Ok(unresolved(
            committed,
            FindingChallengeReason::DeliveryEvidenceNotEstablished,
        ));
    }

    // The generic delivery-contract block carries the comparison the kernel
    // actually performed. Without it there is no observed digest at all.
    let contract = match typed_block::<DeliveryContract>(receipt, DELIVERY_CONTRACT_METADATA_KEY) {
        MetadataBlock::Present(contract) if contract.validate().is_ok() => contract,
        _ => {
            return Ok(unresolved(
                committed,
                FindingChallengeReason::DeliveryEvidenceNotEstablished,
            ))
        }
    };
    let delivered = contract.observed_digest.clone();

    // The finding-delivery overlay is what makes a denial seller-origin: the
    // kernel attaches it only for a purchase-marked grant whose transform
    // plan was frozen at admission, and every field in it derives from
    // kernel-verified state rather than request arguments.
    let overlay = match typed_block::<FindingDelivery>(receipt, FINDING_DELIVERY_METADATA_KEY) {
        MetadataBlock::Absent => {
            return Ok(adjudication(
                committed,
                &delivered,
                FindingChallengeReason::DenialNotSellerOrigin,
            ))
        }
        MetadataBlock::Malformed => {
            return Ok(unresolved(
                committed,
                FindingChallengeReason::DeliveryEvidenceNotEstablished,
            ))
        }
        MetadataBlock::Present(overlay) => overlay,
    };
    if overlay.validate().is_err()
        || overlay.finding_id != context.finding.finding_id
        || overlay.listing_id != context.challenge.listing_id
        || overlay.accepted_bid_envelope_sha256 != terminal.accepted_bid_envelope_sha256
        || overlay.reservation_id != terminal.reservation_id
        || overlay.purchase_intent_id != terminal.purchase_intent_id
        || overlay.authoritative_payment_operation_id != terminal.authoritative_payment_operation_id
    {
        return Ok(unresolved(
            committed,
            FindingChallengeReason::DeliveryEvidenceNotEstablished,
        ));
    }
    // Closed vocabularies, matched exhaustively: a transform profile or
    // settlement rail this evaluator has not classified must break the build
    // rather than fall through to a sanction.
    match overlay.transform_profile {
        FindingTransformProfile::Identity => {}
    }
    match overlay.settlement_mode {
        FindingDeliverySettlementMode::LocalReversibleHold => {}
    }

    match overlay.digest_check {
        DeliveryResult::Matched => {
            // Both authenticated metadata blocks describe the same digest
            // comparison. A disagreement between them, or a comparison
            // against anything other than the finding's own commitment,
            // establishes no result and cannot forfeit a buyer's bond.
            if contract.result != DeliveryResult::Matched
                || contract.observed_digest != contract.expected_digest
                || contract.expected_digest != committed
            {
                return Ok(unresolved(
                    committed,
                    FindingChallengeReason::DeliveryEvidenceNotEstablished,
                ));
            }
            let reason = match overlay.media_type_check {
                FindingMediaTypeCheck::Mismatched => {
                    FindingChallengeReason::DenialMediaTypeMismatch
                }
                FindingMediaTypeCheck::Matched | FindingMediaTypeCheck::NotEvaluated => {
                    FindingChallengeReason::DeliveredOutputMatchesCommitment
                }
            };
            Ok(adjudication(committed, &delivered, reason))
        }
        DeliveryResult::Mismatched => {
            // The two blocks are one kernel terminal's account of one
            // comparison. If they disagree, nothing is established.
            if contract.result != DeliveryResult::Mismatched
                || contract.observed_digest == contract.expected_digest
            {
                return Ok(unresolved(
                    committed,
                    FindingChallengeReason::DeliveryEvidenceNotEstablished,
                ));
            }
            // Only a mismatch against the seller's OWN commitment is seller
            // fraud. An expectation the operator chose is an output-policy
            // denial wearing the same shape.
            if contract.expected_digest != committed {
                return Ok(adjudication(
                    committed,
                    &delivered,
                    FindingChallengeReason::DenialOutputPolicyExpectation,
                ));
            }
            Ok(adjudication(
                committed,
                &delivered,
                FindingChallengeReason::SellerOriginDigestMismatch,
            ))
        }
    }
}

fn typed_block<T>(receipt: &ChioReceipt, key: &str) -> MetadataBlock<T>
where
    T: serde::de::DeserializeOwned,
{
    let Some(value) = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get(key))
    else {
        return MetadataBlock::Absent;
    };
    match serde_json::from_value(value.clone()) {
        Ok(block) => MetadataBlock::Present(block),
        Err(_) => MetadataBlock::Malformed,
    }
}

/// Build the facet and verdict together, so the facet can never claim a
/// mismatch the verdict does not support.
fn adjudication(
    committed: &str,
    delivered: &str,
    reason: FindingChallengeReason,
) -> FindingChallengeAdjudication {
    FindingChallengeAdjudication::new(
        FindingChallengeFacet::DigestMismatch(FindingDigestMismatchFacet {
            committed_payload_sha256: committed.to_string(),
            delivered_output_sha256: delivered.to_string(),
            // The identity profile is the only one this branch can uphold
            // under, and the outcome validator refuses any other value.
            transform_profile: "identity".to_string(),
            // A denied reveal moved no value; the standing terminal proves
            // it and the outcome validator requires it.
            realized_spend_units: 0,
        }),
        reason,
    )
}

/// The facet for a branch that established no distinct delivered digest. It
/// reports the commitment in both members, which the outcome validator
/// refuses to accept as `upheld`.
fn unresolved(committed: &str, reason: FindingChallengeReason) -> FindingChallengeAdjudication {
    adjudication(committed, committed, reason)
}
