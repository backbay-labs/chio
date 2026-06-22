use super::error::CommerceOrderError;
use super::ids::COMMERCE_SETTLEMENT_PACKET_SCHEMA_ID;
use super::types::{CommerceOrderContext, CommercePaymentLifecycle, CommerceSettlementPacket};
use super::validation::{
    parse_rfc3339_utc, require_non_empty, validate_money, validate_sha256_hex,
};

pub(super) fn validate_settlement_packet(
    context: &CommerceOrderContext,
    payment: &CommercePaymentLifecycle,
    settlement: &CommerceSettlementPacket,
) -> Result<(), CommerceOrderError> {
    if settlement.schema != COMMERCE_SETTLEMENT_PACKET_SCHEMA_ID {
        return Err(CommerceOrderError::UnsupportedSchema {
            field: "settlement packet",
            schema: settlement.schema.clone(),
        });
    }
    for (field, value) in [
        ("id", &settlement.id),
        ("issued_at", &settlement.issued_at),
        ("order_id", &settlement.order_id),
        ("merchant_subject", &settlement.merchant_subject),
        ("psp", &settlement.psp),
        ("payment_intent_id", &settlement.payment_intent_id),
        ("currency", &settlement.currency),
        ("quote_sha256", &settlement.quote_sha256),
        ("settlement_rail", &settlement.settlement_rail),
        ("settlement_account_ref", &settlement.settlement_account_ref),
        ("dispatch_receipt_ref", &settlement.dispatch_receipt_ref),
        ("reconciliation_ref", &settlement.reconciliation_ref),
        ("status", &settlement.status),
    ] {
        require_non_empty(value, field).map_err(CommerceOrderError::SettlementFailed)?;
    }
    validate_money(
        settlement.amount_minor,
        &settlement.currency,
        "settlement amount",
    )
    .map_err(CommerceOrderError::SettlementFailed)?;
    validate_sha256_hex(&settlement.quote_sha256).map_err(|_| {
        CommerceOrderError::SettlementFailed(format!(
            "invalid quote_sha256: {}",
            settlement.quote_sha256
        ))
    })?;
    let _issued_at = parse_rfc3339_utc(&settlement.issued_at, "settlement issued_at")?;
    if settlement.id != context.settlement_packet_ref {
        return Err(CommerceOrderError::SettlementFailed(
            "settlement packet ref mismatch".to_string(),
        ));
    }
    if settlement.order_id != context.order_id {
        return Err(CommerceOrderError::SettlementFailed(
            "settlement packet order mismatch".to_string(),
        ));
    }
    if settlement.merchant_subject != context.merchant_subject {
        return Err(CommerceOrderError::SettlementFailed(
            "settlement packet merchant mismatch".to_string(),
        ));
    }
    if settlement.payment_intent_id != payment.payment_intent_id {
        return Err(CommerceOrderError::SettlementFailed(
            "settlement packet payment intent mismatch".to_string(),
        ));
    }
    if settlement.amount_minor != context.quote_amount_minor
        || settlement.currency != context.quote_currency
    {
        return Err(CommerceOrderError::SettlementFailed(
            "settlement packet amount or currency mismatch".to_string(),
        ));
    }
    if settlement.quote_sha256 != context.quote_sha256 {
        return Err(CommerceOrderError::SettlementFailed(
            "settlement packet quote digest mismatch".to_string(),
        ));
    }
    if settlement.reconciliation_ref != context.reconciliation_ref {
        return Err(CommerceOrderError::SettlementFailed(
            "settlement packet reconciliation mismatch".to_string(),
        ));
    }
    if !matches!(
        settlement.status.as_str(),
        "dispatched" | "reconciled" | "settled"
    ) {
        return Err(CommerceOrderError::SettlementFailed(format!(
            "unsupported settlement packet status: {}",
            settlement.status
        )));
    }
    Ok(())
}
