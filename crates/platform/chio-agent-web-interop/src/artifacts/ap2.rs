use chio_transaction_passport::TransactionPassportError;

use super::{
    claim_failed, required_json_str, validate_sha256_hex, AgentWebProofEnvelope, ProjectionManifest,
};

pub(super) fn validate_subject(
    value: &serde_json::Value,
    envelope: &AgentWebProofEnvelope,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    if manifest.source_version != envelope.source_protocol_version {
        return Err(claim_failed("AP2 source version mismatch"));
    }
    if manifest.source_version != "0.2" {
        return Err(claim_failed("unsupported AP2 source version"));
    }
    for (field, message) in [
        (
            "checkout_mandate_digest",
            "missing AP2 checkout mandate digest",
        ),
        (
            "payment_mandate_digest",
            "missing AP2 payment mandate digest",
        ),
        (
            "payment_instrument_digest",
            "missing AP2 payment instrument digest",
        ),
        (
            "transaction_context_digest",
            "missing AP2 transaction context digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid AP2 digest: {field}")))?;
    }
    let passport_ref = required_json_str(
        value,
        "transaction_passport_ref",
        "missing AP2 transaction passport ref",
    )?;
    if passport_ref != envelope.transaction_passport_ref {
        return Err(claim_failed("AP2 mandate passport mismatch"));
    }
    required_json_str(value, "order_id", "missing AP2 order id")?;
    let credential_format =
        required_json_str(value, "credential_format", "missing AP2 credential format")?;
    if credential_format != "vdc" {
        return Err(claim_failed("unsupported AP2 credential format"));
    }
    let agent_mode = required_json_str(value, "agent_mode", "missing AP2 agent mode")?;
    if !matches!(agent_mode, "human-present" | "human-not-present") {
        return Err(claim_failed("unsupported AP2 agent mode"));
    }
    let status = required_json_str(value, "status", "missing AP2 status")?;
    if !matches!(status, "authorized" | "captured" | "settled") {
        return Err(claim_failed("unsupported AP2 status"));
    }
    let mandate_receipt_ref = required_json_str(
        value,
        "chio_mandate_receipt_ref",
        "missing AP2 mandate receipt ref",
    )?;
    if !envelope
        .receipt_refs
        .iter()
        .any(|receipt_ref| receipt_ref == mandate_receipt_ref)
    {
        return Err(claim_failed("AP2 mandate receipt ref is not bound"));
    }
    Ok(())
}
