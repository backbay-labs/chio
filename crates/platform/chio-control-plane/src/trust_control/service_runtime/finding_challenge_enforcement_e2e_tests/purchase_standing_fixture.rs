//! Authenticated delivery evidence for settled-purchase challenge fixtures.

use super::*;

pub(super) fn clone_resolved(
    evidence: &ResolvedReceiptEvidence,
) -> Result<ResolvedReceiptEvidence, AnyError> {
    Ok(ResolvedReceiptEvidence {
        receipt: evidence.receipt.clone(),
        canonical_receipt_bytes: evidence.canonical_receipt_bytes.clone(),
        inclusion_proof: serde_json::from_value(serde_json::to_value(&evidence.inclusion_proof)?)?,
    })
}

pub(super) struct SettledPurchase {
    pub(super) purchase_key: String,
    pub(super) record: SignedFindingPurchaseRecord,
    pub(super) record_envelope_sha256: String,
    pub(super) delivery_receipt: ResolvedReceiptEvidence,
    pub(super) delivery_checkpoint: KernelCheckpoint,
    pub(super) delivery_checkpoint_transparency: CheckpointTransparencySummary,
    pub(super) delivery_authority_status: SignedFindingAuthorityStatus,
}

pub(super) struct SettledDeliveryEvidence {
    pub(super) receipt: ResolvedReceiptEvidence,
    pub(super) checkpoint: KernelCheckpoint,
    pub(super) checkpoint_transparency: CheckpointTransparencySummary,
    pub(super) authority_status: SignedFindingAuthorityStatus,
}

pub(super) fn settled_delivery_evidence(
    record: &FindingPurchaseRecord,
    reservation_id: &str,
    payload_sha256: &str,
    now: u64,
) -> Result<SettledDeliveryEvidence, AnyError> {
    let metadata = serde_json::json!({
        FINDING_DELIVERY_METADATA_KEY: FindingDelivery {
            schema: FINDING_DELIVERY_SCHEMA.to_string(),
            finding_id: record.finding_id.clone(),
            listing_id: record.listing_id.clone(),
            transform_profile: FindingTransformProfile::Identity,
            digest_check: DeliveryResult::Matched,
            media_type_check: FindingMediaTypeCheck::Matched,
            settlement_mode: FindingDeliverySettlementMode::LocalReversibleHold,
            accepted_bid_envelope_sha256: record.accepted_bid_envelope_sha256.clone(),
            venue_admission_envelope_sha256: record.venue_admission_envelope_sha256.clone(),
            reservation_id: reservation_id.to_owned(),
            purchase_intent_id: record.purchase_intent_id.clone(),
            authoritative_payment_operation_id: record
                .authoritative_payment_operation_id
                .clone(),
        }
    });
    let receipt = signed_receipt(
        &delivery_kernel(),
        now,
        "finding.reveal",
        ToolCallAction::from_parameters(serde_json::json!({ "finding": "reveal" }))?,
        Decision::Allow,
        payload_sha256,
        Some(metadata),
    )?;
    let leaves = vec![canonical_json_bytes(&receipt)?];
    let checkpoint = build_checkpoint(1, 1, 1, &leaves, &delivery_kernel())?;
    let receipt = resolve(receipt, &leaves, 0, 1, 1)?;
    let checkpoint_transparency =
        build_checkpoint_transparency(core::slice::from_ref(&checkpoint))?;
    let profile = verifier_profile()?;
    let delivery_policy = profile
        .body
        .receipt_signers
        .iter()
        .find(|signer| signer.role == FindingReceiptRole::Delivery)
        .ok_or("missing delivery role policy")?;
    let authority_status = SignedExportEnvelope::sign(
        FindingAuthorityStatus {
            schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_string(),
            status_ref: delivery_policy.policy.revocation_status_ref.clone(),
            authority_id: delivery_policy.policy.authority_id.clone(),
            key: delivery_policy.policy.key.clone(),
            key_epoch: delivery_policy.policy.key_epoch,
            revoked_from: None,
            observed_at: NOW,
        },
        &keypair(36),
    )?;
    Ok(SettledDeliveryEvidence {
        receipt,
        checkpoint,
        checkpoint_transparency,
        authority_status,
    })
}
