use serde::Deserialize;

use super::error::CommerceOrderError;
use super::ids::COMMERCE_MANDATE_ALLOWANCE_LEDGER_SCHEMA_ID;
use super::types::{CommerceOrderContext, CommercePaymentLifecycle};
use super::validation::{
    parse_rfc3339_utc, require_non_empty, validate_money, validate_sha256_hex,
};

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct CommerceMandateLedger {
    pub(super) schema: String,
    pub(super) id: String,
    issued_at: String,
    order_id: String,
    merchant_subject: String,
    max_amount_minor: u64,
    currency: String,
    valid_from: String,
    expires_at: String,
    single_use: bool,
    used_occurrences: u64,
    max_occurrences: u64,
    ap2_checkout_mandate_hash: String,
    ap2_payment_mandate_hash: String,
    acp_delegated_payment_token_hash: String,
}

pub(super) fn validate_mandate_ledger(
    context: &CommerceOrderContext,
    payment: &CommercePaymentLifecycle,
    mandate: &CommerceMandateLedger,
) -> Result<(), CommerceOrderError> {
    if mandate.schema != COMMERCE_MANDATE_ALLOWANCE_LEDGER_SCHEMA_ID {
        return Err(CommerceOrderError::UnsupportedSchema {
            field: "mandate allowance ledger",
            schema: mandate.schema.clone(),
        });
    }
    for (field, value) in [
        ("id", &mandate.id),
        ("issued_at", &mandate.issued_at),
        ("order_id", &mandate.order_id),
        ("merchant_subject", &mandate.merchant_subject),
        ("currency", &mandate.currency),
        ("valid_from", &mandate.valid_from),
        ("expires_at", &mandate.expires_at),
    ] {
        require_non_empty(value, field).map_err(CommerceOrderError::MandateFailed)?;
    }
    for (field, digest) in [
        (
            "ap2_checkout_mandate_hash",
            &mandate.ap2_checkout_mandate_hash,
        ),
        (
            "ap2_payment_mandate_hash",
            &mandate.ap2_payment_mandate_hash,
        ),
        (
            "acp_delegated_payment_token_hash",
            &mandate.acp_delegated_payment_token_hash,
        ),
    ] {
        validate_sha256_hex(digest)
            .map_err(|_| CommerceOrderError::MandateFailed(format!("invalid {field}: {digest}")))?;
    }
    validate_money(
        mandate.max_amount_minor,
        &mandate.currency,
        "mandate maximum",
    )
    .map_err(CommerceOrderError::MandateFailed)?;
    if mandate.order_id != context.order_id {
        return Err(CommerceOrderError::MandateFailed(
            "mandate order mismatch".to_string(),
        ));
    }
    if mandate.merchant_subject != context.merchant_subject {
        return Err(CommerceOrderError::MandateFailed(
            "mandate merchant mismatch".to_string(),
        ));
    }
    if mandate.currency != context.quote_currency
        || mandate.max_amount_minor < context.quote_amount_minor
    {
        return Err(CommerceOrderError::MandateFailed(
            "mandate amount or currency mismatch".to_string(),
        ));
    }
    if mandate.used_occurrences == 0 || mandate.used_occurrences > mandate.max_occurrences {
        return Err(CommerceOrderError::MandateFailed(
            "mandate occurrence limit exceeded".to_string(),
        ));
    }
    if mandate.single_use && mandate.used_occurrences != 1 {
        return Err(CommerceOrderError::MandateFailed(
            "single-use mandate occurrence mismatch".to_string(),
        ));
    }

    let valid_from = parse_rfc3339_utc(&mandate.valid_from, "mandate valid_from")?;
    let expires_at = parse_rfc3339_utc(&mandate.expires_at, "mandate expires_at")?;
    let captured_at = parse_rfc3339_utc(&payment.captured_at, "payment captured_at")?;
    if expires_at <= valid_from {
        return Err(CommerceOrderError::MandateFailed(
            "mandate expired before validity window".to_string(),
        ));
    }
    if captured_at < valid_from || captured_at > expires_at {
        return Err(CommerceOrderError::MandateFailed(
            "mandate expired before payment capture".to_string(),
        ));
    }
    Ok(())
}
