use chio_transaction_passport::TransactionPassportError;

use super::super::evidence::validate_sha256_hex;
use super::{
    claim_failed, required_json_bool, required_json_str, AgentWebProofEnvelope, ProjectionManifest,
};

pub(super) fn validate_subject(
    value: &serde_json::Value,
    envelope: &AgentWebProofEnvelope,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    let protocol_version =
        required_json_str(value, "protocol_version", "missing AG-UI protocol version")?;
    if protocol_version != manifest.source_version
        || protocol_version != envelope.source_protocol_version
    {
        return Err(claim_failed("AG-UI protocol version mismatch"));
    }
    if protocol_version != "events-v1" {
        return Err(claim_failed("unsupported AG-UI source version"));
    }
    for (field, message) in [
        ("event_id", "missing AG-UI event id"),
        ("capability_id", "missing AG-UI capability id"),
        (
            "target_component_type",
            "missing AG-UI target component type",
        ),
    ] {
        required_json_str(value, field, message)?;
    }
    let event_type = required_json_str(value, "event_type", "missing AG-UI event type")?;
    if !matches!(
        event_type,
        "text_stream"
            | "state_update"
            | "navigation"
            | "lifecycle"
            | "form_action"
            | "notification"
            | "error"
    ) {
        return Err(claim_failed("unsupported AG-UI event type"));
    }
    let classification =
        required_json_str(value, "classification", "missing AG-UI classification")?;
    if !matches!(
        classification,
        "display" | "mutate" | "navigate" | "create" | "destroy" | "submit" | "alert"
    ) {
        return Err(claim_failed("unsupported AG-UI classification"));
    }
    let transport = required_json_str(value, "transport", "missing AG-UI transport")?;
    if !matches!(transport, "sse" | "websocket") {
        return Err(claim_failed("unsupported AG-UI transport"));
    }
    let allowed = required_json_bool(value, "allowed", "missing AG-UI allowed decision")?;
    if !allowed {
        return Err(claim_failed("AG-UI event was not allowed"));
    }
    for (field, message) in [
        ("agent_id_digest", "missing AG-UI agent id digest"),
        ("session_id_digest", "missing AG-UI session digest"),
        (
            "target_component_id_digest",
            "missing AG-UI target component id digest",
        ),
        ("payload_digest", "missing AG-UI payload digest"),
        ("receipt_digest", "missing AG-UI receipt digest"),
        (
            "authorization_context_digest",
            "missing AG-UI authorization context digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid AG-UI digest: {field}")))?;
    }
    validate_event_sequence(value)?;
    Ok(())
}

fn validate_event_sequence(value: &serde_json::Value) -> Result<(), TransactionPassportError> {
    let sequence = value
        .get("event_sequence")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| claim_failed("missing AG-UI event sequence"))?;
    if sequence.len() < 3 {
        return Err(claim_failed(
            "AG-UI event sequence must include start-content-end",
        ));
    }

    let phases = sequence
        .iter()
        .map(|event| required_json_str(event, "phase", "missing AG-UI sequence phase"))
        .collect::<Result<Vec<_>, _>>()?;
    let starts_with_start = phases.first().copied() == Some("start");
    let ends_with_end = phases.last().copied() == Some("end");
    let has_content = phases
        .iter()
        .enumerate()
        .any(|(index, phase)| index > 0 && index + 1 < phases.len() && *phase == "content");
    if !starts_with_start || !has_content || !ends_with_end {
        return Err(claim_failed(
            "AG-UI event sequence must include start-content-end",
        ));
    }

    for event in sequence {
        required_json_str(event, "event_id", "missing AG-UI sequence event id")?;
        for (field, message) in [
            ("payload_digest", "missing AG-UI sequence payload digest"),
            ("receipt_digest", "missing AG-UI sequence receipt digest"),
        ] {
            let digest = required_json_str(event, field, message)?;
            validate_sha256_hex(digest)
                .map_err(|_| claim_failed(format!("invalid AG-UI sequence digest: {field}")))?;
        }
    }
    Ok(())
}
