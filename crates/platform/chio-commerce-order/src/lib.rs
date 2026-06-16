mod error;
mod ids;
mod mandate;
mod payment;
mod replay;
mod types;
mod validation;

pub use error::CommerceOrderError;
pub use ids::{
    COMMERCE_EVENT_LOG_SCHEMA_ID, COMMERCE_MANDATE_ALLOWANCE_LEDGER_SCHEMA_ID,
    COMMERCE_ORDER_CONTEXT_SCHEMA_ID, COMMERCE_ORDER_PASSPORT_SCHEMA_ID,
    COMMERCE_PAYMENT_LIFECYCLE_SCHEMA_ID,
};
pub use types::{
    CommerceOrderContext, CommerceOrderPassportReport, CommerceOrderVerificationBundle,
};

use mandate::{validate_mandate_ledger, CommerceMandateLedger};
use payment::validate_payment_lifecycle;
use replay::{replay_event_log, CommerceEventLog};
use types::CommercePaymentLifecycle;

const CLAIM_ORDER_REPLAY_CONSISTENT: &str = "claim.commerce.order_replay_consistent";
const CLAIM_PAYMENT_LIFECYCLE_BOUND: &str = "claim.commerce.payment_lifecycle_bound";
const CLAIM_MANDATE_ALLOWANCE_BOUND: &str = "claim.commerce.mandate_allowance_bound";

pub fn verify_commerce_order(
    bundle: &CommerceOrderVerificationBundle,
) -> Result<CommerceOrderPassportReport, CommerceOrderError> {
    bundle.order_context.validate_shape()?;
    verify_digest(
        "event log",
        &bundle.order_context.event_log_sha256,
        &bundle.event_log_bytes,
    )?;
    verify_digest(
        "payment lifecycle",
        &bundle.order_context.payment_lifecycle_sha256,
        &bundle.payment_lifecycle_bytes,
    )?;
    verify_digest(
        "mandate allowance ledger",
        &bundle.order_context.mandate_ledger_sha256,
        &bundle.mandate_ledger_bytes,
    )?;

    let event_log: CommerceEventLog = parse_json("event log", &bundle.event_log_bytes)?;
    let payment: CommercePaymentLifecycle =
        parse_json("payment lifecycle", &bundle.payment_lifecycle_bytes)?;
    let mandate: CommerceMandateLedger =
        parse_json("mandate allowance ledger", &bundle.mandate_ledger_bytes)?;

    let replay = replay_event_log(&event_log, &bundle.order_context, &payment, &mandate)?;
    validate_mandate_ledger(&bundle.order_context, &payment, &mandate)?;
    validate_payment_lifecycle(&bundle.order_context, &payment)?;

    Ok(CommerceOrderPassportReport {
        schema: COMMERCE_ORDER_PASSPORT_SCHEMA_ID.to_string(),
        id: format!("commerce-order-passport-{}", bundle.order_context.order_id),
        issued_at: bundle.order_context.issued_at.clone(),
        verdict: "verified".to_string(),
        order_id: bundle.order_context.order_id.clone(),
        current_state: replay.current_state,
        verified_claims: vec![
            CLAIM_ORDER_REPLAY_CONSISTENT.to_string(),
            CLAIM_PAYMENT_LIFECYCLE_BOUND.to_string(),
            CLAIM_MANDATE_ALLOWANCE_BOUND.to_string(),
        ],
    })
}

fn verify_digest(field: &str, expected: &str, bytes: &[u8]) -> Result<(), CommerceOrderError> {
    let actual = sha256_hex(bytes);
    if actual == expected {
        Ok(())
    } else {
        Err(CommerceOrderError::DigestMismatch {
            field: field.to_string(),
            expected: expected.to_string(),
            actual,
        })
    }
}

fn parse_json<T: for<'de> serde::Deserialize<'de>>(
    field: &'static str,
    bytes: &[u8],
) -> Result<T, CommerceOrderError> {
    serde_json::from_slice(bytes).map_err(|error| CommerceOrderError::InvalidArtifact {
        field,
        message: error.to_string(),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    hex::encode(Sha256::digest(bytes))
}
