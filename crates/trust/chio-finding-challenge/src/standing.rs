//! Standing binding for the two classes whose evidence rests on a settled
//! sale.
//!
//! A purchase record is standing only when it is the authority-signed record
//! for THIS finding, THIS listing, and, for a buyer filing, THIS challenger.
//! A venue audit carries no standing at all, so the record is bound to the
//! evidence branch alone.

use chio_core_types::canonical_json_bytes;
use chio_core_types::receipt::decision::Decision;
use chio_core_types::{
    DeliveryResult, FindingDelivery, FindingDeliverySettlementMode, FindingMediaTypeCheck,
    FindingTransformProfile, FINDING_DELIVERY_METADATA_KEY,
};
use chio_finding::{
    signed_envelope_sha256, verify_signed_purchase_record, FindingChallengeAuthorization,
    FindingChallengeStanding, FindingPurchaseRecord,
};
use chio_finding_verifier::{verify_checkpoint_membership, verify_receipt_strict};
use chio_kernel::checkpoint::checkpoint_log_id;

use crate::evaluate::EvaluationContext;
use crate::input::{FindingChallengeInadmissible, FindingPurchaseStandingEvidence};
use crate::receipts::{authority_status_establishes_role, policy_covers, role_policy};

/// Bind a signed purchase record to the challenge that offered it.
pub(crate) fn bind_purchase_record<'a>(
    context: &EvaluationContext<'_>,
    standing: &'a FindingPurchaseStandingEvidence<'a>,
    purchase_record_envelope_sha256: &str,
) -> Result<&'a FindingPurchaseRecord, FindingChallengeInadmissible> {
    let record = standing.purchase_record;
    let envelope_digest =
        signed_envelope_sha256(record).map_err(FindingChallengeInadmissible::StandingRejected)?;
    if envelope_digest != purchase_record_envelope_sha256 {
        return Err(FindingChallengeInadmissible::StandingBindingMismatch(
            "purchase_record_envelope_sha256",
        ));
    }
    let purchase_authority = context.purchase_authority;
    verify_signed_purchase_record(record, &purchase_authority.key)
        .map_err(FindingChallengeInadmissible::StandingRejected)?;
    let body = &record.body;
    authenticate_settlement(context, body, standing)?;
    // A key policy states when the key WAS an authority, not that it is one
    // now, so the instant the record is tested at is the one it settled at.
    // Without this, a key that expired or that governance withdrew could still
    // mint standing for any buyer it names, and standing is what admits a
    // challenge to the evidence-invalid and replay branches at all.
    if !policy_covers(purchase_authority, body.recorded_at) {
        return Err(FindingChallengeInadmissible::StandingAuthorityNotEstablished);
    }
    let Some(status) = context.purchase_authority_status else {
        return Err(FindingChallengeInadmissible::StandingAuthorityNotEstablished);
    };
    if !authority_status_establishes_role(
        status,
        context.pinned_authority_status_key,
        purchase_authority,
        body.recorded_at,
        context.evaluated_at,
    ) {
        return Err(FindingChallengeInadmissible::StandingAuthorityNotEstablished);
    }
    if body.finding_id != context.finding.finding_id {
        return Err(FindingChallengeInadmissible::StandingBindingMismatch(
            "finding_id",
        ));
    }
    if body.listing_id != context.challenge.listing_id {
        return Err(FindingChallengeInadmissible::StandingBindingMismatch(
            "listing_id",
        ));
    }
    if body.seller_backing_envelope_sha256 != context.challenge.backing_envelope_sha256 {
        return Err(FindingChallengeInadmissible::StandingBindingMismatch(
            "seller_backing_envelope_sha256",
        ));
    }
    if body.venue_admission_envelope_sha256 != context.challenge.venue_admission_envelope_sha256 {
        return Err(FindingChallengeInadmissible::StandingBindingMismatch(
            "venue_admission_envelope_sha256",
        ));
    }
    if let Some(challenger) = context.challenger {
        if body.buyer != *challenger {
            return Err(FindingChallengeInadmissible::StandingBindingMismatch(
                "buyer",
            ));
        }
        match &context.challenge.authorization {
            FindingChallengeAuthorization::BuyerSubmission(submission) => {
                match &submission.standing {
                    FindingChallengeStanding::FinalizedPurchase { purchase_key, .. }
                        if *purchase_key == body.purchase_key => {}
                    _ => {
                        return Err(FindingChallengeInadmissible::StandingBindingMismatch(
                            "purchase_key",
                        ))
                    }
                }
            }
            FindingChallengeAuthorization::VenueAudit(_) => {}
        }
    }
    Ok(body)
}

fn authenticate_settlement(
    context: &EvaluationContext<'_>,
    record: &FindingPurchaseRecord,
    standing: &FindingPurchaseStandingEvidence<'_>,
) -> Result<(), FindingChallengeInadmissible> {
    let resolved = standing.delivery_receipt;
    let receipt = &resolved.receipt;
    if canonical_json_bytes(receipt).ok().as_deref()
        != Some(resolved.canonical_receipt_bytes.as_slice())
        || verify_receipt_strict(receipt).is_err()
        || receipt.id != record.delivery_receipt_id
        || receipt.timestamp != record.recorded_at
        || !matches!(receipt.decision, Some(Decision::Allow))
    {
        return Err(FindingChallengeInadmissible::StandingSettlementNotEstablished);
    }
    let Some(delivery_policy) =
        role_policy(context.profile, chio_finding::FindingReceiptRole::Delivery)
    else {
        return Err(FindingChallengeInadmissible::StandingSettlementNotEstablished);
    };
    if receipt.kernel_key != delivery_policy.key
        || !policy_covers(delivery_policy, receipt.timestamp)
        || !authority_status_establishes_role(
            standing.delivery_authority_status,
            context.pinned_authority_status_key,
            delivery_policy,
            receipt.timestamp,
            context.evaluated_at,
        )
    {
        return Err(FindingChallengeInadmissible::StandingSettlementNotEstablished);
    }
    let checkpoint_ref = format!(
        "{}#{}",
        checkpoint_log_id(standing.delivery_checkpoint),
        standing.delivery_checkpoint.body.checkpoint_seq
    );
    if verify_checkpoint_membership(
        core::slice::from_ref(resolved),
        core::slice::from_ref(standing.delivery_checkpoint),
        standing.delivery_checkpoint_transparency,
        context.profile,
        &checkpoint_ref,
    )
    .is_err()
    {
        return Err(FindingChallengeInadmissible::StandingSettlementNotEstablished);
    }
    let Some(metadata) = receipt.metadata.as_ref() else {
        return Err(FindingChallengeInadmissible::StandingSettlementNotEstablished);
    };
    let Some(value) = metadata.get(FINDING_DELIVERY_METADATA_KEY) else {
        return Err(FindingChallengeInadmissible::StandingSettlementNotEstablished);
    };
    let Ok(delivery) = serde_json::from_value::<FindingDelivery>(value.clone()) else {
        return Err(FindingChallengeInadmissible::StandingSettlementNotEstablished);
    };
    if delivery.validate().is_err()
        || delivery.finding_id != record.finding_id
        || delivery.listing_id != record.listing_id
        || delivery.accepted_bid_envelope_sha256 != record.accepted_bid_envelope_sha256
        || delivery.venue_admission_envelope_sha256 != record.venue_admission_envelope_sha256
        || delivery.purchase_intent_id != record.purchase_intent_id
        || delivery.authoritative_payment_operation_id != record.authoritative_payment_operation_id
        || delivery.transform_profile != FindingTransformProfile::Identity
        || delivery.digest_check != DeliveryResult::Matched
        || delivery.media_type_check != FindingMediaTypeCheck::Matched
        || delivery.settlement_mode != FindingDeliverySettlementMode::LocalReversibleHold
        || receipt.content_hash != context.finding.payload_sha256
    {
        return Err(FindingChallengeInadmissible::StandingSettlementNotEstablished);
    }
    Ok(())
}
