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
    if manifest.source_version != envelope.source_protocol_version {
        return Err(claim_failed("Slack source version mismatch"));
    }
    if manifest.source_version != "web-api-2026-06" {
        return Err(claim_failed("unsupported Slack source version"));
    }
    let method_name = required_json_str(value, "method_name", "missing Slack method name")?;
    if !matches!(
        method_name,
        "chat.postMessage" | "chat.update" | "chat.delete" | "files.upload"
    ) {
        return Err(claim_failed("unsupported Slack method"));
    }
    required_json_str(value, "message_id", "missing Slack message id")?;
    required_json_str(value, "event_id", "missing Slack event id")?;
    for (field, message) in [
        ("workspace_id_digest", "missing Slack workspace digest"),
        ("channel_id_digest", "missing Slack channel digest"),
        ("request_body_digest", "missing Slack request body digest"),
        (
            "response_error_digest",
            "missing Slack response error digest",
        ),
        ("oauth_scope_set_digest", "missing Slack OAuth scope digest"),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid Slack digest: {field}")))?;
    }
    let response_ok = required_json_bool(value, "response_ok", "missing Slack response ok result")?;
    if !response_ok {
        return Err(claim_failed("Slack response was not successful"));
    }
    let receipt_refs = value
        .get("receipt_refs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| claim_failed("missing Slack receipt refs"))?;
    if receipt_refs.is_empty() {
        return Err(claim_failed("missing Slack receipt refs"));
    }
    for receipt_ref in receipt_refs {
        let receipt_ref = receipt_ref
            .as_str()
            .ok_or_else(|| claim_failed("invalid Slack receipt ref"))?;
        if !envelope
            .receipt_refs
            .iter()
            .any(|bound| bound == receipt_ref)
        {
            return Err(claim_failed("Slack receipt ref is not bound"));
        }
    }
    let mediated = required_json_bool(
        value,
        "mediated_by_chio_receipt",
        "missing Slack Chio receipt mediation",
    )?;
    if !mediated {
        return Err(claim_failed(
            "Slack action was not mediated by Chio receipt",
        ));
    }
    Ok(())
}
