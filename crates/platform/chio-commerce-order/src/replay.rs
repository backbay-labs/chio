use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::{
    crypto::PublicKey,
    receipt::{
        body::{ChioReceipt, CHIO_RECEIPT_SCHEMA},
        decision::Decision,
        kinds::{BoundaryClass, ReceiptKind, TrustLevel},
    },
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::error::CommerceOrderError;
use super::ids::COMMERCE_EVENT_LOG_SCHEMA_ID;
use super::mandate::CommerceMandateLedger;
use super::types::{
    CommerceEventAuthorityReceiptArtifact, CommerceOrderContext, CommercePaymentLifecycle,
    CommerceTrustMarketRequirement,
};
use super::validation::{parse_rfc3339_utc, require_non_empty, validate_sha256_hex};

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct CommerceEventLog {
    schema: String,
    id: String,
    issued_at: String,
    order_id: String,
    events: Vec<CommerceOrderEvent>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CommerceOrderEvent {
    event_id: String,
    idempotency_key: String,
    actor: String,
    order_id: String,
    prior_state: String,
    next_state: String,
    transition: String,
    occurred_at: String,
    authority_receipt_ref: String,
    evidence_refs: Vec<String>,
    event_sha256: String,
}

pub(super) struct CommerceReplayResult {
    pub(super) current_state: String,
    pub(super) settlement_dispatch_event_sha256: Option<String>,
    pub(super) settlement_dispatch_receipt_ref: Option<String>,
}

pub(super) fn replay_event_log(
    event_log: &CommerceEventLog,
    context: &CommerceOrderContext,
    payment: &CommercePaymentLifecycle,
    mandate: &CommerceMandateLedger,
    authority_receipts: &[CommerceEventAuthorityReceiptArtifact],
    trusted_event_authority_receipt_kernel_keys: &[PublicKey],
) -> Result<CommerceReplayResult, CommerceOrderError> {
    validate_log_shape(event_log, context)?;
    let authority_receipts = authority_receipts_by_ref(authority_receipts)?;

    let mut seen_event_ids = BTreeSet::new();
    let mut seen_idempotency_keys = BTreeSet::new();
    let mut current_state = "none".to_string();
    let mut saw_payment = false;
    let mut saw_mandate = false;
    let mut saw_budget_reservation = false;
    let mut mandate_bound_at = None;
    let mut budget_reserved_at = None;
    let mut previous_event_occurred_at = None;
    let mut settlement_dispatch_event_sha256 = None;
    let mut settlement_dispatch_receipt_ref = None;
    let payment_captured_at = parse_rfc3339_utc(&payment.captured_at, "payment captured_at")?;
    for event in &event_log.events {
        let occurred_at = validate_event_shape(event, context)?;
        validate_event_authority_receipt(
            event,
            &authority_receipts,
            trusted_event_authority_receipt_kernel_keys,
        )?;
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
        if !seen_idempotency_keys.insert(event.idempotency_key.as_str()) {
            return Err(CommerceOrderError::ReplayFailed(format!(
                "duplicate commerce idempotency key: {}",
                event.idempotency_key
            )));
        }
        if event.next_state == "budget_reserved" {
            if saw_budget_reservation {
                return Err(CommerceOrderError::ReplayFailed(
                    "commerce budget reserved more than once".to_string(),
                ));
            }
            saw_budget_reservation = true;
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
        if event.next_state == "intent_recorded"
            && !event.evidence_refs.contains(&context.intent_ref)
        {
            return Err(CommerceOrderError::ReplayFailed(
                "intent event missing intent evidence".to_string(),
            ));
        }
        if event.next_state == "provider_admitted"
            && !event
                .evidence_refs
                .contains(&context.provider_admission_ref)
        {
            return Err(CommerceOrderError::ReplayFailed(
                "provider event missing provider admission evidence".to_string(),
            ));
        }
        if event.next_state == "provider_admitted"
            && [
                &context.provider_passport_ref,
                &context.reputation_snapshot_ref,
                &context.federation_trust_bundle_ref,
            ]
            .iter()
            .any(|required_ref| !event.evidence_refs.contains(required_ref))
        {
            return Err(CommerceOrderError::ReplayFailed(
                "provider event missing provider trust evidence".to_string(),
            ));
        }
        if event.next_state == "provider_admitted" {
            if let Some(requirement) = active_trust_market_requirement(context) {
                require_provider_trust_market_refs(event, requirement)?;
            }
        }
        if event.next_state == "quote_bound" && !event.evidence_refs.contains(&context.quote_id) {
            return Err(CommerceOrderError::ReplayFailed(
                "quote event missing quote evidence".to_string(),
            ));
        }
        if [
            "payment_challenged",
            "payment_verified",
            "disputed",
            "refunded",
        ]
        .contains(&event.next_state.as_str())
            && !event.evidence_refs.contains(&payment.id)
        {
            return Err(CommerceOrderError::ReplayFailed(
                "payment state event missing payment lifecycle evidence".to_string(),
            ));
        }
        if event.next_state == "payment_verified" && payment_captured_at > occurred_at {
            return Err(CommerceOrderError::ReplayFailed(
                "payment captured after replay event".to_string(),
            ));
        }
        if event.next_state == "payment_verified"
            && [mandate_bound_at.as_ref(), budget_reserved_at.as_ref()]
                .into_iter()
                .flatten()
                .any(|authorization_occurred_at| &payment_captured_at < authorization_occurred_at)
        {
            return Err(CommerceOrderError::ReplayFailed(
                "payment captured before commerce authorization event".to_string(),
            ));
        }
        if event.next_state == "mandate_bound" && !event.evidence_refs.contains(&mandate.id) {
            return Err(CommerceOrderError::ReplayFailed(
                "mandate event missing mandate allowance evidence".to_string(),
            ));
        }
        if event.next_state == "mandate_bound" {
            mandate_bound_at = Some(occurred_at);
        }
        if event.next_state == "budget_reserved" {
            budget_reserved_at = Some(occurred_at);
        }
        if [
            "settlement_packet_assembled",
            "settlement_dispatched",
            "settlement_observed",
        ]
        .contains(&event.next_state.as_str())
            && !event.evidence_refs.contains(&context.settlement_packet_ref)
        {
            return Err(CommerceOrderError::ReplayFailed(
                "settlement event missing settlement packet evidence".to_string(),
            ));
        }
        if is_settlement_lifecycle_state(&event.next_state) {
            if let Some(requirement) = active_trust_market_requirement(context) {
                require_settlement_trust_market_refs(event, requirement)?;
            }
        }
        if event.next_state == "settlement_dispatched" {
            settlement_dispatch_event_sha256 = Some(event.event_sha256.clone());
            settlement_dispatch_receipt_ref = Some(event.authority_receipt_ref.clone());
        }
        if event.next_state == "settlement_reconciled"
            && !event.evidence_refs.contains(&context.reconciliation_ref)
        {
            return Err(CommerceOrderError::ReplayFailed(
                "reconciliation event missing reconciliation evidence".to_string(),
            ));
        }
        saw_payment |= event.next_state == "payment_verified";
        saw_mandate |= event.next_state == "mandate_bound";
        current_state = event.next_state.clone();
    }

    if current_state != "failed_closed" && !saw_mandate {
        return Err(CommerceOrderError::ReplayFailed(
            "commerce replay missing mandate binding".to_string(),
        ));
    }
    if current_state != "failed_closed" && !saw_payment {
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

    Ok(CommerceReplayResult {
        current_state,
        settlement_dispatch_event_sha256,
        settlement_dispatch_receipt_ref,
    })
}

fn authority_receipts_by_ref(
    authority_receipts: &[CommerceEventAuthorityReceiptArtifact],
) -> Result<BTreeMap<&str, ChioReceipt>, CommerceOrderError> {
    let mut by_ref = BTreeMap::new();
    for artifact in authority_receipts {
        require_non_empty(&artifact.receipt_ref, "authority receipt ref")
            .map_err(CommerceOrderError::ReplayFailed)?;
        if by_ref.contains_key(artifact.receipt_ref.as_str()) {
            return Err(CommerceOrderError::ReplayFailed(format!(
                "duplicate authority receipt artifact: {}",
                artifact.receipt_ref
            )));
        }
        by_ref.insert(
            artifact.receipt_ref.as_str(),
            parse_authority_receipt(artifact)?,
        );
    }
    Ok(by_ref)
}

fn parse_authority_receipt(
    artifact: &CommerceEventAuthorityReceiptArtifact,
) -> Result<ChioReceipt, CommerceOrderError> {
    let value: serde_json::Value =
        serde_json::from_slice(&artifact.receipt_bytes).map_err(|error| {
            CommerceOrderError::ReplayFailed(format!(
                "authority receipt artifact JSON invalid: {}: {error}",
                artifact.receipt_ref
            ))
        })?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            CommerceOrderError::ReplayFailed(format!(
                "authority receipt artifact schema missing: {}",
                artifact.receipt_ref
            ))
        })?;
    if schema != CHIO_RECEIPT_SCHEMA {
        return Err(CommerceOrderError::UnsupportedSchema {
            field: "authority receipt",
            schema: schema.to_string(),
        });
    }
    serde_json::from_value(value).map_err(|error| {
        CommerceOrderError::ReplayFailed(format!(
            "authority receipt artifact invalid: {}: {error}",
            artifact.receipt_ref
        ))
    })
}

fn validate_event_authority_receipt(
    event: &CommerceOrderEvent,
    authority_receipts: &BTreeMap<&str, ChioReceipt>,
    trusted_event_authority_receipt_kernel_keys: &[PublicKey],
) -> Result<(), CommerceOrderError> {
    let receipt = authority_receipts
        .get(event.authority_receipt_ref.as_str())
        .ok_or_else(|| {
            CommerceOrderError::ReplayFailed(format!(
                "authority receipt missing: {}",
                event.authority_receipt_ref
            ))
        })?;
    if trusted_event_authority_receipt_kernel_keys.is_empty() {
        return Err(CommerceOrderError::ReplayFailed(
            "authority receipt kernel trust roots missing".to_string(),
        ));
    }
    if !trusted_event_authority_receipt_kernel_keys.contains(&receipt.kernel_key) {
        return Err(CommerceOrderError::ReplayFailed(format!(
            "authority receipt kernel key untrusted: {}",
            event.authority_receipt_ref
        )));
    }
    let signature_valid = receipt.verify_signature().map_err(|error| {
        CommerceOrderError::ReplayFailed(format!(
            "authority receipt signature invalid: {}: {error}",
            event.authority_receipt_ref
        ))
    })?;
    if !signature_valid {
        return Err(CommerceOrderError::ReplayFailed(format!(
            "authority receipt signature invalid: {}",
            event.authority_receipt_ref
        )));
    }
    if !receipt.action.verify_hash().map_err(|error| {
        CommerceOrderError::ReplayFailed(format!(
            "authority receipt action hash invalid: {}: {error}",
            event.authority_receipt_ref
        ))
    })? {
        return Err(CommerceOrderError::ReplayFailed(format!(
            "authority receipt action hash invalid: {}",
            event.authority_receipt_ref
        )));
    }
    if receipt.receipt_kind != ReceiptKind::MediatedDecision
        || receipt.boundary_class != BoundaryClass::Prevent
        || receipt.trust_level != TrustLevel::Mediated
        || receipt.decision != Some(Decision::Allow)
    {
        return Err(CommerceOrderError::ReplayFailed(format!(
            "authority receipt did not authorize event: {}",
            event.authority_receipt_ref
        )));
    }
    if receipt.content_hash != event.event_sha256 {
        return Err(CommerceOrderError::ReplayFailed(format!(
            "authority receipt content hash mismatch: {}",
            event.event_id
        )));
    }
    Ok(())
}

fn active_trust_market_requirement(
    context: &CommerceOrderContext,
) -> Option<&CommerceTrustMarketRequirement> {
    context
        .trust_market_requirement
        .as_ref()
        .filter(|requirement| requirement.required)
}

fn require_provider_trust_market_refs(
    event: &CommerceOrderEvent,
    requirement: &CommerceTrustMarketRequirement,
) -> Result<(), CommerceOrderError> {
    if [
        requirement.provider_discovery_snapshot_ref.as_str(),
        requirement.provider_selection_report_ref.as_str(),
        requirement.trust_scorecard_ref.as_str(),
        requirement.reputation_import_ref.as_str(),
    ]
    .iter()
    .any(|required_ref| !has_evidence_ref(event, required_ref))
    {
        return Err(CommerceOrderError::ReplayFailed(
            "provider event missing trust-market evidence".to_string(),
        ));
    }
    Ok(())
}

fn require_settlement_trust_market_refs(
    event: &CommerceOrderEvent,
    requirement: &CommerceTrustMarketRequirement,
) -> Result<(), CommerceOrderError> {
    if [
        requirement.sla_commitment_ref.as_str(),
        requirement.collateral_position_ref.as_str(),
        requirement.guarantee_decision_ref.as_str(),
        requirement.adjudication_jurisdiction_ref.as_str(),
    ]
    .iter()
    .any(|required_ref| !has_evidence_ref(event, required_ref))
    {
        return Err(CommerceOrderError::ReplayFailed(
            "settlement event missing trust-market evidence".to_string(),
        ));
    }
    Ok(())
}

fn is_settlement_lifecycle_state(state: &str) -> bool {
    [
        "settlement_packet_assembled",
        "settlement_dispatched",
        "settlement_observed",
        "settlement_reconciled",
    ]
    .contains(&state)
}

fn has_evidence_ref(event: &CommerceOrderEvent, required_ref: &str) -> bool {
    event
        .evidence_refs
        .iter()
        .any(|evidence_ref| evidence_ref == required_ref)
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
        ("idempotency_key", &event.idempotency_key),
        ("event actor", &event.actor),
        ("order_id", &event.order_id),
        ("prior_state", &event.prior_state),
        ("next_state", &event.next_state),
        ("transition", &event.transition),
        ("occurred_at", &event.occurred_at),
        ("authority_receipt_ref", &event.authority_receipt_ref),
        ("event_sha256", &event.event_sha256),
    ] {
        require_non_empty(value, field).map_err(CommerceOrderError::ReplayFailed)?;
    }
    validate_sha256_hex(&event.event_sha256).map_err(|_| {
        CommerceOrderError::ReplayFailed(format!("invalid event_sha256: {}", event.event_sha256))
    })?;
    if event.order_id != context.order_id {
        return Err(CommerceOrderError::ReplayFailed(
            "commerce event order mismatch".to_string(),
        ));
    }
    if !is_order_actor(&event.actor, context) {
        return Err(CommerceOrderError::ReplayFailed(format!(
            "commerce event actor is not bound to order context: {}",
            event.actor
        )));
    }
    validate_event_digest(event)?;
    let occurred_at = parse_rfc3339_utc(&event.occurred_at, "commerce event occurred_at")?;
    if event.evidence_refs.is_empty() {
        return Err(CommerceOrderError::ReplayFailed(format!(
            "commerce event {} has no evidence refs",
            event.event_id
        )));
    }
    Ok(occurred_at)
}

fn is_order_actor(actor: &str, context: &CommerceOrderContext) -> bool {
    [
        context.agent_subject.as_str(),
        context.buyer_subject.as_str(),
        context.merchant_subject.as_str(),
    ]
    .contains(&actor)
}

fn validate_event_digest(event: &CommerceOrderEvent) -> Result<(), CommerceOrderError> {
    let mut body = serde_json::to_value(event).map_err(|error| {
        CommerceOrderError::ReplayFailed(format!("commerce event digest body invalid: {error}"))
    })?;
    let body_object = body.as_object_mut().ok_or_else(|| {
        CommerceOrderError::ReplayFailed("commerce event digest body invalid".to_string())
    })?;
    body_object.remove("event_sha256");
    let canonical = chio_core_types::canonical_json_bytes(&body).map_err(|error| {
        CommerceOrderError::ReplayFailed(format!(
            "commerce event canonical digest body invalid: {error}"
        ))
    })?;
    let actual = hex::encode(Sha256::digest(&canonical));
    if event.event_sha256 != actual {
        return Err(CommerceOrderError::ReplayFailed(format!(
            "commerce event digest mismatch: {}",
            event.event_id
        )));
    }
    Ok(())
}

fn is_allowed_transition(prior_state: &str, next_state: &str, transition: &str) -> bool {
    matches!(
        (prior_state, next_state, transition),
        ("none", "intent_recorded", "record_intent")
            | ("intent_recorded", "provider_admitted", "admit_provider")
            | ("provider_admitted", "quote_bound", "bind_quote")
            | ("quote_bound", "mandate_bound", "bind_mandate")
            | ("mandate_bound", "budget_reserved", "reserve_budget")
            | ("budget_reserved", "payment_challenged", "challenge_payment")
            | ("payment_challenged", "payment_verified", "verify_payment")
            | ("budget_reserved", "payment_verified", "verify_payment")
            | (
                "payment_verified",
                "fulfillment_requested",
                "request_fulfillment"
            )
            | (
                "fulfillment_requested",
                "fulfillment_attested",
                "attest_fulfillment"
            )
            | (
                "payment_verified",
                "fulfillment_attested",
                "attest_fulfillment"
            )
            | (
                "fulfillment_attested",
                "settlement_packet_assembled",
                "assemble_settlement_packet"
            )
            | (
                "settlement_packet_assembled",
                "settlement_dispatched",
                "dispatch_settlement"
            )
            | (
                "fulfillment_attested",
                "settlement_dispatched",
                "dispatch_settlement"
            )
            | (
                "settlement_dispatched",
                "settlement_observed",
                "observe_settlement"
            )
            | (
                "settlement_observed",
                "settlement_reconciled",
                "reconcile_settlement"
            )
            | (
                "settlement_dispatched",
                "settlement_reconciled",
                "reconcile_settlement"
            )
            | ("settlement_reconciled", "completed", "complete_order")
            | ("completed", "disputed", "open_dispute")
            | ("disputed", "refunded", "refund_payment")
            | ("provider_admitted", "failed_closed", "fail_closed")
            | ("quote_bound", "failed_closed", "fail_closed")
            | ("mandate_bound", "failed_closed", "fail_closed")
            | ("budget_reserved", "failed_closed", "fail_closed")
            | ("payment_challenged", "failed_closed", "fail_closed")
            | ("payment_verified", "failed_closed", "fail_closed")
            | ("fulfillment_requested", "failed_closed", "fail_closed")
            | ("fulfillment_attested", "failed_closed", "fail_closed")
            | (
                "settlement_packet_assembled",
                "failed_closed",
                "fail_closed"
            )
            | ("settlement_dispatched", "failed_closed", "fail_closed")
            | ("settlement_observed", "failed_closed", "fail_closed")
            | ("settlement_reconciled", "failed_closed", "fail_closed")
            | ("disputed", "failed_closed", "fail_closed")
    )
}
