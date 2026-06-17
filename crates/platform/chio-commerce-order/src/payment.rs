use super::error::CommerceOrderError;
use super::ids::COMMERCE_PAYMENT_LIFECYCLE_SCHEMA_ID;
use super::types::{CommerceOrderContext, CommercePaymentLifecycle};
use super::validation::{parse_rfc3339_utc, require_non_empty, validate_money};

pub(super) fn validate_payment_lifecycle(
    context: &CommerceOrderContext,
    payment: &CommercePaymentLifecycle,
) -> Result<(), CommerceOrderError> {
    if payment.schema != COMMERCE_PAYMENT_LIFECYCLE_SCHEMA_ID {
        return Err(CommerceOrderError::UnsupportedSchema {
            field: "payment lifecycle",
            schema: payment.schema.clone(),
        });
    }
    for (field, value) in [
        ("id", &payment.id),
        ("issued_at", &payment.issued_at),
        ("order_id", &payment.order_id),
        ("merchant_subject", &payment.merchant_subject),
        ("psp", &payment.psp),
        ("payment_intent_id", &payment.payment_intent_id),
        ("currency", &payment.currency),
        ("payment_status", &payment.payment_status),
        ("capture_mode", &payment.capture_mode),
        ("capture_before", &payment.capture_before),
        ("captured_at", &payment.captured_at),
        ("transfer_group", &payment.transfer_group),
        ("fraud_outcome", &payment.fraud_outcome),
        ("dispute_status", &payment.dispute_status),
        ("refund_status", &payment.refund_status),
        ("chargeback_status", &payment.chargeback_status),
        (
            "transfer_reversal_status",
            &payment.transfer_reversal_status,
        ),
    ] {
        require_non_empty(value, field).map_err(CommerceOrderError::PaymentFailed)?;
    }
    validate_money(payment.amount_minor, &payment.currency, "payment amount")
        .map_err(CommerceOrderError::PaymentFailed)?;
    if payment.order_id != context.order_id {
        return Err(CommerceOrderError::PaymentFailed(
            "payment order mismatch".to_string(),
        ));
    }
    if payment.merchant_subject != context.merchant_subject {
        return Err(CommerceOrderError::PaymentFailed(
            "payment merchant mismatch".to_string(),
        ));
    }
    if payment.amount_minor != context.quote_amount_minor
        || payment.currency != context.quote_currency
    {
        return Err(CommerceOrderError::PaymentFailed(
            "payment amount or currency mismatch".to_string(),
        ));
    }
    if payment.transfer_group != context.order_id {
        return Err(CommerceOrderError::PaymentFailed(
            "payment transfer group mismatch".to_string(),
        ));
    }
    if payment.payment_status != "succeeded" {
        return Err(CommerceOrderError::PaymentFailed(
            "payment lifecycle is not succeeded".to_string(),
        ));
    }
    if payment.capture_mode != "manual" {
        return Err(CommerceOrderError::PaymentFailed(
            "payment capture mode is not manual".to_string(),
        ));
    }
    let capture_before = parse_rfc3339_utc(&payment.capture_before, "payment capture_before")?;
    let captured_at = parse_rfc3339_utc(&payment.captured_at, "payment captured_at")?;
    if captured_at > capture_before {
        return Err(CommerceOrderError::PaymentFailed(
            "payment captured after authorization expiry".to_string(),
        ));
    }
    if payment.fraud_outcome != "accepted" {
        return Err(CommerceOrderError::PaymentFailed(
            "fraud outcome was not accepted".to_string(),
        ));
    }
    validate_payment_status(
        "dispute_status",
        &payment.dispute_status,
        &["none", "open", "resolved"],
    )?;
    validate_payment_status(
        "refund_status",
        &payment.refund_status,
        &["none", "pending", "succeeded", "failed"],
    )?;
    validate_payment_status(
        "chargeback_status",
        &payment.chargeback_status,
        &["none", "open", "won", "lost"],
    )?;
    validate_payment_status(
        "transfer_reversal_status",
        &payment.transfer_reversal_status,
        &["none", "pending", "succeeded", "failed"],
    )?;
    if [
        &payment.dispute_status,
        &payment.refund_status,
        &payment.chargeback_status,
        &payment.transfer_reversal_status,
    ]
    .iter()
    .any(|status| status.as_str() != "none")
    {
        return Err(CommerceOrderError::PaymentFailed(
            "unresolved payment recovery state".to_string(),
        ));
    }
    Ok(())
}

fn validate_payment_status(
    field: &str,
    value: &str,
    allowed: &[&str],
) -> Result<(), CommerceOrderError> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(CommerceOrderError::PaymentFailed(format!(
            "unsupported {field}: {value}"
        )))
    }
}
