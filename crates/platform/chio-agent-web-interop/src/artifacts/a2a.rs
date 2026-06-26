use chio_transaction_passport::TransactionPassportError;

use super::super::evidence::validate_sha256_hex;
use super::{claim_failed, required_json_str, AgentWebProofEnvelope, ProjectionManifest};

pub(super) fn validate_subject(
    value: &serde_json::Value,
    envelope: &AgentWebProofEnvelope,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    let protocol_version = required_json_str(value, "protocol_version", "missing A2A version")?;
    if protocol_version != manifest.source_version
        || protocol_version != envelope.source_protocol_version
    {
        return Err(claim_failed("A2A protocol version mismatch"));
    }
    if protocol_version != "0.3.0" {
        return Err(claim_failed("unsupported A2A source version"));
    }
    for (field, message) in [
        ("task_id", "missing A2A task id"),
        ("message_id", "missing A2A message id"),
    ] {
        required_json_str(value, field, message)?;
    }
    let task_state = required_json_str(value, "task_state", "missing A2A task state")?;
    if !matches!(
        task_state,
        "submitted" | "working" | "input-required" | "completed" | "failed" | "canceled"
    ) {
        return Err(claim_failed("unsupported A2A task state"));
    }
    if task_state != "completed" {
        return Err(claim_failed("A2A task state was not successful"));
    }
    for (field, message) in [
        ("agent_card_digest", "missing A2A agent card digest"),
        (
            "agent_card_schema_digest",
            "missing A2A Agent Card schema digest",
        ),
        ("agent_card_url_digest", "missing A2A Agent Card URL digest"),
        ("skill_id_digest", "missing A2A skill id digest"),
        ("interface_url_digest", "missing A2A interface URL digest"),
        ("context_id_digest", "missing A2A context id digest"),
        ("task_input_digest", "missing A2A task input digest"),
        ("task_state_digest", "missing A2A task state digest"),
        ("message_parts_digest", "missing A2A message parts digest"),
        ("message_send_digest", "missing A2A message/send digest"),
        ("result_digest", "missing A2A result digest"),
        (
            "metadata_chio_skill_selector_digest",
            "missing A2A Chio skill selector metadata digest",
        ),
        ("task_artifacts_digest", "missing A2A task artifacts digest"),
        (
            "streaming_lifecycle_digest",
            "missing A2A streaming lifecycle digest",
        ),
        (
            "cancel_lifecycle_digest",
            "missing A2A cancel lifecycle digest",
        ),
        (
            "push_notification_config_digest",
            "missing A2A push notification config digest",
        ),
        (
            "authorization_context_digest",
            "missing A2A authorization context digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid A2A digest: {field}")))?;
    }
    Ok(())
}
