use super::error::CommerceOrderError;
use super::ids::COMMERCE_SETTLEMENT_PACKET_SCHEMA_ID;
use super::types::{
    CommerceEventAuthorityReceiptArtifact, CommerceOrderContext, CommercePaymentLifecycle,
    CommerceSettlementPacket,
};
use super::validation::{
    parse_rfc3339_utc, require_non_empty, validate_money, validate_sha256_hex,
};
use chio_core_types::{
    crypto::PublicKey,
    receipt::{
        body::{ChioReceipt, CHIO_RECEIPT_SCHEMA},
        decision::Decision,
        kinds::{BoundaryClass, ReceiptKind, TrustLevel},
    },
};

pub(super) fn validate_settlement_packet(
    context: &CommerceOrderContext,
    payment: &CommercePaymentLifecycle,
    settlement: &CommerceSettlementPacket,
    authority_receipts: &[CommerceEventAuthorityReceiptArtifact],
    trusted_event_authority_receipt_kernel_keys: &[PublicKey],
    replayed_dispatch_receipt_ref: Option<&str>,
    replayed_dispatch_event_sha256: Option<&str>,
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
    if settlement.psp != payment.psp {
        return Err(CommerceOrderError::SettlementFailed(
            "settlement packet PSP mismatch".to_string(),
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
    validate_settlement_dispatch_receipt(
        settlement,
        authority_receipts,
        trusted_event_authority_receipt_kernel_keys,
        replayed_dispatch_receipt_ref,
        replayed_dispatch_event_sha256,
    )?;
    Ok(())
}

fn validate_settlement_dispatch_receipt(
    settlement: &CommerceSettlementPacket,
    authority_receipts: &[CommerceEventAuthorityReceiptArtifact],
    trusted_event_authority_receipt_kernel_keys: &[PublicKey],
    replayed_dispatch_receipt_ref: Option<&str>,
    replayed_dispatch_event_sha256: Option<&str>,
) -> Result<(), CommerceOrderError> {
    if trusted_event_authority_receipt_kernel_keys.is_empty() {
        return Err(CommerceOrderError::SettlementFailed(
            "settlement dispatch receipt trust roots missing".to_string(),
        ));
    }
    let artifact = authority_receipts
        .iter()
        .find(|artifact| artifact.receipt_ref == settlement.dispatch_receipt_ref)
        .ok_or_else(|| {
            CommerceOrderError::SettlementFailed(format!(
                "settlement dispatch receipt missing: {}",
                settlement.dispatch_receipt_ref
            ))
        })?;
    let receipt = parse_settlement_dispatch_receipt(artifact)?;
    let replayed_dispatch_receipt_ref = replayed_dispatch_receipt_ref.ok_or_else(|| {
        CommerceOrderError::SettlementFailed(
            "settlement dispatch event missing from replay".to_string(),
        )
    })?;
    if replayed_dispatch_receipt_ref != settlement.dispatch_receipt_ref {
        return Err(CommerceOrderError::SettlementFailed(
            "settlement dispatch receipt does not match replayed dispatch event".to_string(),
        ));
    }
    if let Some(replayed_dispatch_event_sha256) = replayed_dispatch_event_sha256 {
        if receipt.content_hash != replayed_dispatch_event_sha256 {
            return Err(CommerceOrderError::SettlementFailed(
                "settlement dispatch receipt content hash mismatch".to_string(),
            ));
        }
    }
    if !trusted_event_authority_receipt_kernel_keys.contains(&receipt.kernel_key) {
        return Err(CommerceOrderError::SettlementFailed(format!(
            "settlement dispatch receipt kernel key untrusted: {}",
            settlement.dispatch_receipt_ref
        )));
    }
    let signature_valid = receipt.verify_signature().map_err(|error| {
        CommerceOrderError::SettlementFailed(format!(
            "settlement dispatch receipt signature invalid: {}: {error}",
            settlement.dispatch_receipt_ref
        ))
    })?;
    if !signature_valid {
        return Err(CommerceOrderError::SettlementFailed(format!(
            "settlement dispatch receipt signature invalid: {}",
            settlement.dispatch_receipt_ref
        )));
    }
    let action_hash_valid = receipt.action.verify_hash().map_err(|error| {
        CommerceOrderError::SettlementFailed(format!(
            "settlement dispatch receipt action hash invalid: {}: {error}",
            settlement.dispatch_receipt_ref
        ))
    })?;
    if !action_hash_valid {
        return Err(CommerceOrderError::SettlementFailed(format!(
            "settlement dispatch receipt action hash invalid: {}",
            settlement.dispatch_receipt_ref
        )));
    }
    if receipt.receipt_kind != ReceiptKind::MediatedDecision
        || receipt.boundary_class != BoundaryClass::Prevent
        || receipt.trust_level != TrustLevel::Mediated
        || receipt.decision != Some(Decision::Allow)
        || receipt.tool_name != "dispatch_settlement"
    {
        return Err(CommerceOrderError::SettlementFailed(format!(
            "settlement dispatch receipt did not authorize dispatch: {}",
            settlement.dispatch_receipt_ref
        )));
    }
    require_receipt_action_string(
        &receipt,
        "authority_receipt_ref",
        &settlement.dispatch_receipt_ref,
    )?;
    require_receipt_action_string(&receipt, "order_id", &settlement.order_id)?;
    require_receipt_action_string(&receipt, "transition", "dispatch_settlement")?;
    Ok(())
}

fn parse_settlement_dispatch_receipt(
    artifact: &CommerceEventAuthorityReceiptArtifact,
) -> Result<ChioReceipt, CommerceOrderError> {
    let value: serde_json::Value =
        serde_json::from_slice(&artifact.receipt_bytes).map_err(|error| {
            CommerceOrderError::SettlementFailed(format!(
                "settlement dispatch receipt JSON invalid: {}: {error}",
                artifact.receipt_ref
            ))
        })?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            CommerceOrderError::SettlementFailed(format!(
                "settlement dispatch receipt schema missing: {}",
                artifact.receipt_ref
            ))
        })?;
    if schema != CHIO_RECEIPT_SCHEMA {
        return Err(CommerceOrderError::UnsupportedSchema {
            field: "settlement dispatch receipt",
            schema: schema.to_string(),
        });
    }
    serde_json::from_value(value).map_err(|error| {
        CommerceOrderError::SettlementFailed(format!(
            "settlement dispatch receipt invalid: {}: {error}",
            artifact.receipt_ref
        ))
    })
}

fn require_receipt_action_string(
    receipt: &ChioReceipt,
    field: &str,
    expected: &str,
) -> Result<(), CommerceOrderError> {
    let actual = receipt
        .action
        .parameters
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            CommerceOrderError::SettlementFailed(format!(
                "settlement dispatch receipt action missing {field}"
            ))
        })?;
    if actual != expected {
        return Err(CommerceOrderError::SettlementFailed(format!(
            "settlement dispatch receipt action mismatch: {field}"
        )));
    }
    Ok(())
}
