use super::error::CommerceOrderError;
use super::ids::COMMERCE_PAYMENT_LIFECYCLE_SCHEMA_ID;
use super::types::{CommerceOrderContext, CommercePaymentLifecycle};
use super::validation::{
    parse_rfc3339_utc, require_non_empty, validate_money, validate_sha256_hex,
};
use chio_core_types::crypto::{PublicKey, Signature};

pub(super) fn validate_payment_lifecycle(
    context: &CommerceOrderContext,
    payment: &CommercePaymentLifecycle,
    trusted_payment_signer_keys: &[PublicKey],
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
        ("quote_sha256", &payment.quote_sha256),
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
    let issuer = required_payment_field(payment.issuer.as_deref(), "payment issuer")?;
    let signature = required_payment_field(payment.signature.as_deref(), "payment signature")?;
    validate_sha256_hex(&payment.quote_sha256).map_err(|_| {
        CommerceOrderError::PaymentFailed(format!("invalid quote_sha256: {}", payment.quote_sha256))
    })?;
    validate_payment_object_ref(
        "authorization_ref",
        payment.authorization_ref.as_deref(),
        "auth_",
    )?;
    validate_payment_object_ref("capture_ref", payment.capture_ref.as_deref(), "cap_")?;
    validate_payment_object_ref("charge_ref", payment.charge_ref.as_deref(), "ch_")?;
    validate_payment_object_ref(
        "balance_transaction_ref",
        payment.balance_transaction_ref.as_deref(),
        "txn_",
    )?;
    verify_payment_lifecycle_signature(payment, issuer, signature, trusted_payment_signer_keys)?;
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
    if payment.quote_sha256 != context.quote_sha256 {
        return Err(CommerceOrderError::PaymentFailed(
            "payment quote digest mismatch".to_string(),
        ));
    }
    if payment.transfer_group != context.order_id {
        return Err(CommerceOrderError::PaymentFailed(
            "payment transfer group mismatch".to_string(),
        ));
    }
    if context.current_state == "failed_closed" {
        validate_payment_status(
            "payment_status",
            &payment.payment_status,
            &["succeeded", "failed"],
        )?;
    } else if payment.payment_status != "succeeded" {
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
    validate_recovery_posture(context, payment)?;
    Ok(())
}

fn required_payment_field<'a>(
    value: Option<&'a str>,
    field: &str,
) -> Result<&'a str, CommerceOrderError> {
    let Some(value) = value else {
        return Err(CommerceOrderError::PaymentFailed(format!(
            "{field} missing"
        )));
    };
    require_non_empty(value, field).map_err(CommerceOrderError::PaymentFailed)?;
    Ok(value)
}

fn validate_payment_object_ref(
    field: &str,
    value: Option<&str>,
    expected_prefix: &str,
) -> Result<(), CommerceOrderError> {
    let value = required_payment_field(value, field)?;
    if value.starts_with(expected_prefix) {
        Ok(())
    } else {
        Err(CommerceOrderError::PaymentFailed(format!(
            "payment {field} is not a supported PSP object ref"
        )))
    }
}

fn verify_payment_lifecycle_signature(
    payment: &CommercePaymentLifecycle,
    issuer: &str,
    signature: &str,
    trusted_payment_signer_keys: &[PublicKey],
) -> Result<(), CommerceOrderError> {
    if trusted_payment_signer_keys.is_empty() {
        return Err(CommerceOrderError::PaymentFailed(
            "payment signer trust roots missing".to_string(),
        ));
    }
    let signer_key = payment_issuer_public_key(issuer)?;
    if !trusted_payment_signer_keys.contains(&signer_key) {
        return Err(CommerceOrderError::PaymentFailed(
            "payment signer untrusted".to_string(),
        ));
    }
    let signature = Signature::from_hex(signature)
        .map_err(|_| CommerceOrderError::PaymentFailed("payment signature invalid".to_string()))?;
    let mut signature_body = serde_json::to_value(payment).map_err(|error| {
        CommerceOrderError::PaymentFailed(format!("payment signature body invalid: {error}"))
    })?;
    let body = signature_body.as_object_mut().ok_or_else(|| {
        CommerceOrderError::PaymentFailed("payment signature body invalid".to_string())
    })?;
    body.remove("signature");
    let verified = signer_key
        .verify_canonical(&signature_body, &signature)
        .map_err(|_| CommerceOrderError::PaymentFailed("payment signature invalid".to_string()))?;
    if verified {
        Ok(())
    } else {
        Err(CommerceOrderError::PaymentFailed(
            "payment signature invalid".to_string(),
        ))
    }
}

fn payment_issuer_public_key(issuer: &str) -> Result<PublicKey, CommerceOrderError> {
    let public_key_hex = issuer.strip_prefix("did:chio:").ok_or_else(|| {
        CommerceOrderError::PaymentFailed("payment issuer unsupported".to_string())
    })?;
    PublicKey::from_hex(public_key_hex)
        .map_err(|_| CommerceOrderError::PaymentFailed("payment issuer invalid".to_string()))
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

fn validate_recovery_posture(
    context: &CommerceOrderContext,
    payment: &CommercePaymentLifecycle,
) -> Result<(), CommerceOrderError> {
    let has_recovery_state = [
        &payment.dispute_status,
        &payment.refund_status,
        &payment.chargeback_status,
        &payment.transfer_reversal_status,
    ]
    .iter()
    .any(|status| status.as_str() != "none");

    match context.current_state.as_str() {
        "disputed" => {
            if payment.dispute_status == "none" {
                return Err(CommerceOrderError::PaymentFailed(
                    "disputed order missing dispute state".to_string(),
                ));
            }
        }
        "refunded" => {
            if payment.refund_status != "succeeded" {
                return Err(CommerceOrderError::PaymentFailed(
                    "refunded order missing succeeded refund".to_string(),
                ));
            }
            if !["none", "resolved"].contains(&payment.dispute_status.as_str()) {
                return Err(CommerceOrderError::PaymentFailed(
                    "refunded order has unresolved dispute".to_string(),
                ));
            }
        }
        "failed_closed" => {}
        _ if has_recovery_state => {
            return Err(CommerceOrderError::PaymentFailed(
                "unresolved payment recovery state".to_string(),
            ));
        }
        _ => {}
    }

    Ok(())
}
