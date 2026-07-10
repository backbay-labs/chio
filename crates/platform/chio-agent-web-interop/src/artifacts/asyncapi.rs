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
        return Err(claim_failed("AsyncAPI source version mismatch"));
    }
    if manifest.source_version != "3.0.0" {
        return Err(claim_failed("unsupported AsyncAPI source version"));
    }
    for (field, message) in [
        ("spec_digest", "missing AsyncAPI spec digest"),
        ("channel_digest", "missing AsyncAPI channel digest"),
        ("message_digest", "missing AsyncAPI message digest"),
        ("payload_digest", "missing AsyncAPI payload digest"),
        ("headers_digest", "missing AsyncAPI headers digest"),
        (
            "broker_identity_digest",
            "missing AsyncAPI broker identity digest",
        ),
        (
            "authorization_context_digest",
            "missing AsyncAPI authorization context digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid AsyncAPI digest: {field}")))?;
    }
    required_json_str(value, "operation_id", "missing AsyncAPI operation id")?;
    required_json_str(value, "channel", "missing AsyncAPI channel")?;
    let direction = required_json_str(value, "direction", "missing AsyncAPI direction")?;
    if !matches!(direction, "publish" | "subscribe") {
        return Err(claim_failed("unsupported AsyncAPI direction"));
    }
    let protocol = required_json_str(value, "protocol", "missing AsyncAPI protocol")?;
    if !matches!(protocol, "amqp" | "http" | "kafka" | "mqtt" | "nats") {
        return Err(claim_failed("unsupported AsyncAPI protocol"));
    }
    let message_receipt_ref = required_json_str(
        value,
        "chio_message_receipt_ref",
        "missing AsyncAPI message receipt ref",
    )?;
    if !envelope
        .receipt_refs
        .iter()
        .any(|receipt_ref| receipt_ref == message_receipt_ref)
    {
        return Err(claim_failed("AsyncAPI message receipt ref is not bound"));
    }
    Ok(())
}
