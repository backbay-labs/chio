use chio_transaction_passport::TransactionPassportError;

use super::{
    claim_failed, required_json_str, required_json_u64, validate_sha256_hex, AgentWebProofEnvelope,
    ProjectionManifest,
};

pub(super) fn validate_subject(
    value: &serde_json::Value,
    envelope: &AgentWebProofEnvelope,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    if manifest.source_version != envelope.source_protocol_version {
        return Err(claim_failed("x402 source version mismatch"));
    }
    if manifest.source_version != "0.5" {
        return Err(claim_failed("unsupported x402 source version"));
    }
    for (field, message) in [
        ("resource_digest", "missing x402 resource digest"),
        (
            "payment_requirements_digest",
            "missing x402 payment requirements digest",
        ),
        ("payment_proof_digest", "missing x402 payment proof digest"),
        ("settlement_digest", "missing x402 settlement digest"),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid x402 digest: {field}")))?;
    }
    let passport_ref = required_json_str(
        value,
        "transaction_passport_ref",
        "missing x402 transaction passport ref",
    )?;
    if passport_ref != envelope.transaction_passport_ref {
        return Err(claim_failed("x402 payment passport mismatch"));
    }
    required_json_str(value, "order_id", "missing x402 order id")?;
    required_json_str(value, "network", "missing x402 network")?;
    required_json_str(value, "asset", "missing x402 asset")?;
    let amount_units = required_json_u64(value, "amount_units", "missing x402 amount")?;
    if amount_units == 0 {
        return Err(claim_failed("x402 amount missing"));
    }
    let status = required_json_str(value, "status", "missing x402 status")?;
    if !matches!(status, "authorized" | "settled" | "refunded") {
        return Err(claim_failed("unsupported x402 status"));
    }
    if status == "refunded" {
        return Err(claim_failed("x402 payment was refunded"));
    }
    let payment_receipt_ref = required_json_str(
        value,
        "chio_payment_receipt_ref",
        "missing x402 payment receipt ref",
    )?;
    if !envelope
        .receipt_refs
        .iter()
        .any(|receipt_ref| receipt_ref == payment_receipt_ref)
    {
        return Err(claim_failed("x402 payment receipt ref is not bound"));
    }
    Ok(())
}
