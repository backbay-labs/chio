use std::collections::HashSet;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::error::CommerceOrderError;
use super::ids::{
    COMMERCE_MANDATE_ALLOWANCE_LEDGER_SCHEMA_ID, COMMERCE_PROTOCOL_PAYLOAD_SCHEMA_ID,
};
use super::types::{
    CommerceMandateProtocolPayload, CommerceOrderContext, CommercePaymentLifecycle,
};
use super::validation::{
    parse_rfc3339_utc, require_non_empty, validate_bundle_relative_path, validate_money,
    validate_sha256_hex,
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
    quote_sha256: String,
    valid_from: String,
    expires_at: String,
    single_use: bool,
    used_occurrences: u64,
    max_occurrences: u64,
    ap2_checkout_mandate_hash: String,
    ap2_payment_mandate_hash: String,
    acp_delegated_payment_token_hash: String,
    x402_payment_requirements_hash: String,
    protocol_projections: Vec<CommerceMandateProtocolProjection>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CommerceMandateProtocolProjection {
    protocol: String,
    purpose: String,
    digest: String,
    payload_path: String,
    order_id: String,
    amount_minor: u64,
    currency: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct CommerceMandateProtocolPayloadDocument {
    schema: String,
    protocol: String,
    purpose: String,
    order_id: String,
    amount_minor: u64,
    currency: String,
    #[serde(default)]
    merchant_subject: Option<String>,
}

pub(super) fn validate_mandate_ledger(
    context: &CommerceOrderContext,
    payment: &CommercePaymentLifecycle,
    mandate: &CommerceMandateLedger,
    protocol_payloads: &[CommerceMandateProtocolPayload],
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
        ("quote_sha256", &mandate.quote_sha256),
        ("valid_from", &mandate.valid_from),
        ("expires_at", &mandate.expires_at),
    ] {
        require_non_empty(value, field).map_err(CommerceOrderError::MandateFailed)?;
    }
    validate_sha256_hex(&mandate.quote_sha256).map_err(|_| {
        CommerceOrderError::MandateFailed(format!("invalid quote_sha256: {}", mandate.quote_sha256))
    })?;
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
        (
            "x402_payment_requirements_hash",
            &mandate.x402_payment_requirements_hash,
        ),
    ] {
        validate_sha256_hex(digest)
            .map_err(|_| CommerceOrderError::MandateFailed(format!("invalid {field}: {digest}")))?;
    }
    validate_protocol_projections(context, mandate, protocol_payloads)?;
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
    if mandate.quote_sha256 != context.quote_sha256 {
        return Err(CommerceOrderError::MandateFailed(
            "mandate quote digest mismatch".to_string(),
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

fn validate_protocol_projections(
    context: &CommerceOrderContext,
    mandate: &CommerceMandateLedger,
    protocol_payloads: &[CommerceMandateProtocolPayload],
) -> Result<(), CommerceOrderError> {
    let expected = [
        (
            "ap2",
            "checkout_mandate",
            Some(mandate.ap2_checkout_mandate_hash.as_str()),
        ),
        (
            "ap2",
            "payment_mandate",
            Some(mandate.ap2_payment_mandate_hash.as_str()),
        ),
        (
            "acp-commerce",
            "delegated_payment_token",
            Some(mandate.acp_delegated_payment_token_hash.as_str()),
        ),
        (
            "x402",
            "payment_requirements",
            Some(mandate.x402_payment_requirements_hash.as_str()),
        ),
        ("chio", "authority_projection", None),
    ];
    let mut seen = HashSet::new();
    validate_protocol_payloads(protocol_payloads)?;

    for projection in &mandate.protocol_projections {
        for (field, value) in [
            ("projection protocol", &projection.protocol),
            ("projection purpose", &projection.purpose),
            ("projection digest", &projection.digest),
            ("projection payload_path", &projection.payload_path),
            ("projection order_id", &projection.order_id),
            ("projection currency", &projection.currency),
        ] {
            require_non_empty(value, field).map_err(CommerceOrderError::MandateFailed)?;
        }
        validate_sha256_hex(&projection.digest).map_err(|_| {
            CommerceOrderError::MandateFailed(format!(
                "invalid mandate projection digest: {}",
                projection.digest
            ))
        })?;
        validate_supported_projection_protocol(&projection.protocol)?;
        validate_bundle_relative_path(&projection.payload_path).map_err(|_| {
            CommerceOrderError::MandateFailed(format!(
                "unsafe mandate projection payload path: {}",
                projection.payload_path
            ))
        })?;
        validate_money(
            projection.amount_minor,
            &projection.currency,
            "mandate projection amount",
        )
        .map_err(CommerceOrderError::MandateFailed)?;
        if !seen.insert((projection.protocol.as_str(), projection.purpose.as_str())) {
            return Err(CommerceOrderError::MandateFailed(format!(
                "duplicate mandate projection: {}/{}",
                projection.protocol, projection.purpose
            )));
        }
        if projection.order_id != context.order_id {
            return Err(CommerceOrderError::MandateFailed(format!(
                "mandate projection order mismatch: {}/{}",
                projection.protocol, projection.purpose
            )));
        }
        if projection.amount_minor != context.quote_amount_minor
            || projection.currency != context.quote_currency
        {
            return Err(CommerceOrderError::MandateFailed(format!(
                "mandate projection amount mismatch: {}/{}",
                projection.protocol, projection.purpose
            )));
        }
    }

    for (protocol, purpose, digest) in expected {
        let projection = mandate
            .protocol_projections
            .iter()
            .find(|projection| projection.protocol == protocol && projection.purpose == purpose)
            .ok_or_else(|| {
                CommerceOrderError::MandateFailed(format!(
                    "mandate projection missing: {protocol}/{purpose}"
                ))
            })?;
        if let Some(digest) = digest {
            if projection.digest != digest {
                return Err(CommerceOrderError::MandateFailed(format!(
                    "mandate projection digest mismatch: {protocol}/{purpose}"
                )));
            }
        }
        let payload = protocol_payloads
            .iter()
            .find(|payload| payload.protocol == protocol && payload.purpose == purpose)
            .ok_or_else(|| {
                CommerceOrderError::MandateFailed(format!(
                    "mandate projection payload missing: {protocol}/{purpose}"
                ))
            })?;
        let actual = hex::encode(Sha256::digest(&payload.payload_bytes));
        if actual != projection.digest {
            return Err(CommerceOrderError::MandateFailed(format!(
                "mandate projection payload digest mismatch: {protocol}/{purpose}"
            )));
        }
        validate_protocol_payload_document(context, projection, payload)?;
    }

    Ok(())
}

fn validate_protocol_payload_document(
    context: &CommerceOrderContext,
    projection: &CommerceMandateProtocolProjection,
    payload: &CommerceMandateProtocolPayload,
) -> Result<(), CommerceOrderError> {
    let document: CommerceMandateProtocolPayloadDocument =
        serde_json::from_slice(&payload.payload_bytes).map_err(|error| {
            CommerceOrderError::MandateFailed(format!(
                "mandate projection payload invalid JSON: {}/{}: {error}",
                projection.protocol, projection.purpose
            ))
        })?;
    if document.schema != COMMERCE_PROTOCOL_PAYLOAD_SCHEMA_ID {
        return Err(CommerceOrderError::MandateFailed(format!(
            "mandate projection payload schema mismatch: {}/{}",
            projection.protocol, projection.purpose
        )));
    }
    for (field, value) in [
        ("payload protocol", &document.protocol),
        ("payload purpose", &document.purpose),
        ("payload order_id", &document.order_id),
        ("payload currency", &document.currency),
    ] {
        require_non_empty(value, field).map_err(CommerceOrderError::MandateFailed)?;
    }
    if document.protocol != projection.protocol || document.purpose != projection.purpose {
        return Err(CommerceOrderError::MandateFailed(format!(
            "mandate projection payload identity mismatch: {}/{}",
            projection.protocol, projection.purpose
        )));
    }
    if document.order_id != context.order_id || document.order_id != projection.order_id {
        return Err(CommerceOrderError::MandateFailed(format!(
            "mandate projection payload order mismatch: {}/{}",
            projection.protocol, projection.purpose
        )));
    }
    if document.amount_minor != context.quote_amount_minor
        || document.amount_minor != projection.amount_minor
        || document.currency != context.quote_currency
        || document.currency != projection.currency
    {
        return Err(CommerceOrderError::MandateFailed(format!(
            "mandate projection payload amount mismatch: {}/{}",
            projection.protocol, projection.purpose
        )));
    }
    if let Some(merchant_subject) = &document.merchant_subject {
        require_non_empty(merchant_subject, "payload merchant_subject")
            .map_err(CommerceOrderError::MandateFailed)?;
        if merchant_subject != &context.merchant_subject {
            return Err(CommerceOrderError::MandateFailed(format!(
                "mandate projection payload merchant mismatch: {}/{}",
                projection.protocol, projection.purpose
            )));
        }
    }
    Ok(())
}

fn validate_protocol_payloads(
    protocol_payloads: &[CommerceMandateProtocolPayload],
) -> Result<(), CommerceOrderError> {
    let mut seen = HashSet::new();
    for payload in protocol_payloads {
        for (field, value) in [
            ("protocol payload protocol", &payload.protocol),
            ("protocol payload purpose", &payload.purpose),
        ] {
            require_non_empty(value, field).map_err(CommerceOrderError::MandateFailed)?;
        }
        validate_supported_projection_protocol(&payload.protocol)?;
        if payload.payload_bytes.is_empty() {
            return Err(CommerceOrderError::MandateFailed(format!(
                "mandate projection payload empty: {}/{}",
                payload.protocol, payload.purpose
            )));
        }
        if !seen.insert((payload.protocol.as_str(), payload.purpose.as_str())) {
            return Err(CommerceOrderError::MandateFailed(format!(
                "duplicate mandate projection payload: {}/{}",
                payload.protocol, payload.purpose
            )));
        }
    }
    Ok(())
}

fn validate_supported_projection_protocol(protocol: &str) -> Result<(), CommerceOrderError> {
    match protocol {
        "ap2" | "acp-commerce" | "x402" | "chio" => Ok(()),
        _ => Err(CommerceOrderError::MandateFailed(format!(
            "unsupported mandate protocol: {protocol}"
        ))),
    }
}
