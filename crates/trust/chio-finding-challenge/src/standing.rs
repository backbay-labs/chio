//! Standing binding for the two classes whose evidence rests on a settled
//! sale.
//!
//! A purchase record is standing only when it is the authority-signed record
//! for THIS finding, THIS listing, and, for a buyer filing, THIS challenger.
//! A venue audit carries no standing at all, so the record is bound to the
//! evidence branch alone.

use chio_core_types::canonical_json_bytes;
use chio_core_types::crypto::sha256_hex;
use chio_core_types::receipt::decision::Decision;
use chio_core_types::receipt::economics::SettlementStatus;
use chio_core_types::{
    DeliveryResult, FindingDelivery, FindingDeliverySettlementMode, FindingMediaTypeCheck,
    FindingTransformProfile, FINDING_DELIVERY_METADATA_KEY,
};
use chio_finding::{
    canonical_evm_payout_destination, signed_envelope_sha256, verify_signed_purchase_record,
    FindingChallengeAuthorization, FindingChallengeStanding, FindingPurchaseRecord,
};
use chio_finding_verifier::{verify_checkpoint_membership, verify_receipt_strict};
use chio_kernel::checkpoint::checkpoint_log_id;
use chio_open_market::bidding::{
    VerifiedReservationReceipt, ACCEPTED_BID_SCHEMA, BID_REQUEST_SCHEMA,
};
use chio_open_market::purchase_verification::{
    derive_payment_operation_id, derive_purchase_intent_id,
};

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
    authenticate_bid_and_reservation(context, record, standing)?;
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
    let Some(financial) = receipt.financial_metadata() else {
        return Err(FindingChallengeInadmissible::StandingSettlementNotEstablished);
    };
    if financial.cost_charged != record.realized_spend.units
        || financial.currency != record.realized_spend.currency
        || financial.settlement_status != SettlementStatus::Settled
    {
        return Err(FindingChallengeInadmissible::StandingSettlementNotEstablished);
    }
    Ok(())
}

fn authenticate_bid_and_reservation(
    context: &EvaluationContext<'_>,
    record: &FindingPurchaseRecord,
    standing: &FindingPurchaseStandingEvidence<'_>,
) -> Result<(), FindingChallengeInadmissible> {
    let bid = standing.bid_request;
    let accepted = standing.accepted_bid;
    if bid.body.schema != BID_REQUEST_SCHEMA
        || bid.body.validate().is_err()
        || !matches!(bid.verify_signature(), Ok(true))
        || accepted.body.schema != ACCEPTED_BID_SCHEMA
        || !matches!(accepted.verify_signature(), Ok(true))
    {
        return Err(FindingChallengeInadmissible::StandingSettlementNotEstablished);
    }
    let reservation = VerifiedReservationReceipt::from_signed(
        standing.reservation_receipt,
        &context.purchase_authority.key,
    )
    .map_err(|_| FindingChallengeInadmissible::StandingSettlementNotEstablished)?;
    let bid_body_digest = canonical_json_bytes(&bid.body)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| FindingChallengeInadmissible::StandingSettlementNotEstablished)?;
    let accepted_envelope_digest =
        signed_envelope_sha256(accepted).map_err(FindingChallengeInadmissible::StandingRejected)?;
    let payout_destination = bid
        .body
        .payout_destination
        .as_deref()
        .ok_or(FindingChallengeInadmissible::StandingSettlementNotEstablished)
        .and_then(|destination| {
            canonical_evm_payout_destination(destination)
                .map_err(|_| FindingChallengeInadmissible::StandingSettlementNotEstablished)
        })?;
    let reservation_id = reservation.receipt_id();
    let encumbrance_id =
        sha256_hex(format!("chio.finding.encumbrance.v1\0{reservation_id}").as_bytes());
    if accepted.signer_key != bid.signer_key
        || accepted.body.token_subject != bid.signer_key
        || accepted.body.agent_id != bid.body.agent_id
        || accepted.body.bid_digest != bid_body_digest
        || accepted.body.listing_id != bid.body.listing_id
        || accepted.body.bid_receipt_id != reservation_id
        || accepted.body.ask_digest != standing.reservation_receipt.body.ask_digest
        || accepted.body.listing_id != standing.reservation_receipt.body.listing_id
        || accepted.body.agent_id != standing.reservation_receipt.body.agent_id
        || accepted.body.quoted_price != *reservation.reserved_amount()
        || bid.body.max_price_per_call.currency != accepted.body.quoted_price.currency
        || bid.body.max_price_per_call.units < accepted.body.quoted_price.units
        || accepted_envelope_digest != record.accepted_bid_envelope_sha256
        || record.buyer != bid.signer_key
        || record.payer != bid.signer_key
        || record.listing_id != accepted.body.listing_id
        || record.accepted_price != accepted.body.quoted_price
        || record.payout_destination != payout_destination
        || record.purchase_intent_id != derive_purchase_intent_id(reservation_id)
        || record.authoritative_payment_operation_id != derive_payment_operation_id(reservation_id)
        || record.payment_reference != record.authoritative_payment_operation_id
        || record.encumbrance_id != encumbrance_id
    {
        return Err(FindingChallengeInadmissible::StandingSettlementNotEstablished);
    }
    Ok(())
}
