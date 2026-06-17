use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::error::CommerceOrderError;
use super::ids::COMMERCE_EVENT_LOG_SCHEMA_ID;
use super::mandate::CommerceMandateLedger;
use super::types::{CommerceOrderContext, CommercePaymentLifecycle};
use super::validation::{parse_rfc3339_utc, require_non_empty};

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct CommerceEventLog {
    schema: String,
    id: String,
    issued_at: String,
    order_id: String,
    events: Vec<CommerceOrderEvent>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CommerceOrderEvent {
    event_id: String,
    order_id: String,
    prior_state: String,
    next_state: String,
    transition: String,
    occurred_at: String,
    authority_receipt_ref: String,
    evidence_refs: Vec<String>,
}

pub(super) struct CommerceReplayResult {
    pub(super) current_state: String,
}

pub(super) fn replay_event_log(
    event_log: &CommerceEventLog,
    context: &CommerceOrderContext,
    payment: &CommercePaymentLifecycle,
    mandate: &CommerceMandateLedger,
) -> Result<CommerceReplayResult, CommerceOrderError> {
    validate_log_shape(event_log, context)?;

    let mut seen_event_ids = BTreeSet::new();
    let mut current_state = "none".to_string();
    let mut saw_payment = false;
    let mut saw_mandate = false;
    let mut previous_event_occurred_at = None;
    let payment_captured_at = parse_rfc3339_utc(&payment.captured_at, "payment captured_at")?;
    for event in &event_log.events {
        let occurred_at = validate_event_shape(event, context)?;
        if let Some(previous_occurred_at) = previous_event_occurred_at.as_ref() {
            if &occurred_at < previous_occurred_at {
                return Err(CommerceOrderError::ReplayFailed(format!(
                    "commerce event timestamp regressed: {}",
                    event.event_id
                )));
            }
        }
        previous_event_occurred_at = Some(occurred_at);
        if !seen_event_ids.insert(event.event_id.as_str()) {
            return Err(CommerceOrderError::ReplayFailed(format!(
                "duplicate commerce event id: {}",
                event.event_id
            )));
        }
        if event.prior_state != current_state {
            return Err(CommerceOrderError::ReplayFailed(format!(
                "commerce event {} expected prior state {}, got {}",
                event.event_id, current_state, event.prior_state
            )));
        }
        if !is_allowed_transition(&event.prior_state, &event.next_state, &event.transition) {
            return Err(CommerceOrderError::ReplayFailed(format!(
                "unknown commerce transition: {} -> {} via {}",
                event.prior_state, event.next_state, event.transition
            )));
        }
        if event.next_state == "quote_bound" && !event.evidence_refs.contains(&context.quote_id) {
            return Err(CommerceOrderError::ReplayFailed(
                "quote event missing quote evidence".to_string(),
            ));
        }
        if event.next_state == "payment_verified" && !event.evidence_refs.contains(&payment.id) {
            return Err(CommerceOrderError::ReplayFailed(
                "payment event missing payment lifecycle evidence".to_string(),
            ));
        }
        if event.next_state == "payment_verified" && payment_captured_at > occurred_at {
            return Err(CommerceOrderError::ReplayFailed(
                "payment captured after replay event".to_string(),
            ));
        }
        if event.next_state == "mandate_bound" && !event.evidence_refs.contains(&mandate.id) {
            return Err(CommerceOrderError::ReplayFailed(
                "mandate event missing mandate allowance evidence".to_string(),
            ));
        }
        saw_payment |= event.next_state == "payment_verified";
        saw_mandate |= event.next_state == "mandate_bound";
        current_state = event.next_state.clone();
    }

    if !saw_mandate {
        return Err(CommerceOrderError::ReplayFailed(
            "commerce replay missing mandate binding".to_string(),
        ));
    }
    if !saw_payment {
        return Err(CommerceOrderError::ReplayFailed(
            "commerce replay missing payment verification".to_string(),
        ));
    }
    if current_state != context.current_state {
        return Err(CommerceOrderError::ReplayFailed(format!(
            "current state mismatch: replayed {current_state}, context declares {}",
            context.current_state
        )));
    }

    Ok(CommerceReplayResult { current_state })
}

fn validate_log_shape(
    event_log: &CommerceEventLog,
    context: &CommerceOrderContext,
) -> Result<(), CommerceOrderError> {
    if event_log.schema != COMMERCE_EVENT_LOG_SCHEMA_ID {
        return Err(CommerceOrderError::UnsupportedSchema {
            field: "event log",
            schema: event_log.schema.clone(),
        });
    }
    for (field, value) in [
        ("id", &event_log.id),
        ("issued_at", &event_log.issued_at),
        ("order_id", &event_log.order_id),
    ] {
        require_non_empty(value, field).map_err(CommerceOrderError::ReplayFailed)?;
    }
    if event_log.order_id != context.order_id {
        return Err(CommerceOrderError::ReplayFailed(
            "event log order mismatch".to_string(),
        ));
    }
    if event_log.events.is_empty() {
        return Err(CommerceOrderError::ReplayFailed(
            "commerce event log is empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_event_shape(
    event: &CommerceOrderEvent,
    context: &CommerceOrderContext,
) -> Result<DateTime<Utc>, CommerceOrderError> {
    for (field, value) in [
        ("event_id", &event.event_id),
        ("order_id", &event.order_id),
        ("prior_state", &event.prior_state),
        ("next_state", &event.next_state),
        ("transition", &event.transition),
        ("occurred_at", &event.occurred_at),
        ("authority_receipt_ref", &event.authority_receipt_ref),
    ] {
        require_non_empty(value, field).map_err(CommerceOrderError::ReplayFailed)?;
    }
    if event.order_id != context.order_id {
        return Err(CommerceOrderError::ReplayFailed(
            "commerce event order mismatch".to_string(),
        ));
    }
    let occurred_at = parse_rfc3339_utc(&event.occurred_at, "commerce event occurred_at")?;
    if event.evidence_refs.is_empty() {
        return Err(CommerceOrderError::ReplayFailed(format!(
            "commerce event {} has no evidence refs",
            event.event_id
        )));
    }
    Ok(occurred_at)
}

fn is_allowed_transition(prior_state: &str, next_state: &str, transition: &str) -> bool {
    matches!(
        (prior_state, next_state, transition),
        ("none", "intent_recorded", "record_intent")
            | ("intent_recorded", "provider_admitted", "admit_provider")
            | ("provider_admitted", "quote_bound", "bind_quote")
            | ("quote_bound", "mandate_bound", "bind_mandate")
            | ("mandate_bound", "budget_reserved", "reserve_budget")
            | ("budget_reserved", "payment_verified", "verify_payment")
            | (
                "payment_verified",
                "fulfillment_attested",
                "attest_fulfillment"
            )
            | (
                "fulfillment_attested",
                "settlement_dispatched",
                "dispatch_settlement"
            )
            | (
                "settlement_dispatched",
                "settlement_reconciled",
                "reconcile_settlement"
            )
            | ("settlement_reconciled", "completed", "complete_order")
    )
}
