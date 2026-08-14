use super::*;

/// Whether a stored reservation is the same purchase the caller is
/// reserving. Identity is what the purchase is: who pays, for which
/// finding on which listing, under which digests, for how much.
///
/// Trusted times are excluded so an honest retry keeps the original durable
/// deadline instead of conflicting with its caller's later clock.
pub(super) fn reservation_matches(
    existing: &FindingPurchaseReservationRecord,
    input: &FindingPurchaseReservationInput<'_>,
) -> bool {
    existing.purchase_intent_id == input.purchase_intent_id
        && existing.authoritative_payment_operation_id == input.authoritative_payment_operation_id
        && existing.payer_hex == input.payer_hex
        && existing.agent_id == input.agent_id
        && existing.payout_destination == input.payout_destination
        && existing.finding_id == input.finding_id
        && existing.listing_id == input.listing_id
        && existing.bid_envelope_sha256 == input.bid_envelope_sha256
        && existing.ask_digest == input.ask_digest
        && existing.admission_envelope_sha256 == input.admission_envelope_sha256
        && existing.amount_units == input.amount_units
        && existing.currency == input.currency
}

pub(super) fn encumbrance_matches(
    existing: &FindingPurchaseEncumbranceRecord,
    input: &FindingPurchaseReservationInput<'_>,
) -> bool {
    existing.encumbrance_id == input.encumbrance_id
        && existing.allocation_id == input.allocation_id
        && existing.amount_units == input.amount_units
        && existing.currency == input.currency
}

pub(super) fn validate_reservation_input(
    input: &FindingPurchaseReservationInput<'_>,
) -> Result<(), FindingPurchaseStoreError> {
    require_identifier(input.reservation_id, "reservation_id")?;
    require_identifier(input.purchase_intent_id, "purchase_intent_id")?;
    require_identifier(
        input.authoritative_payment_operation_id,
        "authoritative_payment_operation_id",
    )?;
    require_identifier(input.agent_id, "agent_id")?;
    require_evm_payout_destination(input.payout_destination)?;
    require_identifier(input.listing_id, "listing_id")?;
    require_identifier(input.encumbrance_id, "encumbrance_id")?;
    require_hex64(input.payer_hex, "payer_hex")?;
    require_hex64(input.finding_id, "finding_id")?;
    require_hex64(input.bid_envelope_sha256, "bid_envelope_sha256")?;
    require_hex64(input.ask_digest, "ask_digest")?;
    require_hex64(input.admission_envelope_sha256, "admission_envelope_sha256")?;
    require_hex64(
        input.fee_schedule_envelope_sha256,
        "fee_schedule_envelope_sha256",
    )?;
    let _ = sqlite_i64(input.participation_epoch, "participation_epoch")?;
    require_hex64(input.allocation_id, "allocation_id")?;
    require_currency(input.currency)?;
    if input.amount_units == 0 {
        return Err(invariant("reservation amount must be nonzero"));
    }
    if input.maximum_sale_exposure_units == 0 {
        return Err(invariant("maximum sale exposure must be nonzero"));
    }
    require_trusted_time(input.created_at, "created_at")?;
    require_trusted_time(input.expires_at, "expires_at")?;
    if input.expires_at <= input.created_at {
        return Err(invariant("reservation expiry does not follow creation"));
    }
    Ok(())
}
