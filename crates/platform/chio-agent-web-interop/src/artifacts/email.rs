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
        return Err(claim_failed("email source version mismatch"));
    }
    if manifest.source_version != "v1" {
        return Err(claim_failed("unsupported email source version"));
    }
    let provider_protocol = required_json_str(
        value,
        "provider_protocol",
        "missing email provider protocol",
    )?;
    if provider_protocol != "gmail-api" {
        return Err(claim_failed("unsupported email provider protocol"));
    }
    required_json_str(value, "message_id", "missing email message id")?;
    required_json_str(value, "thread_id", "missing email thread id")?;
    let method = required_json_str(value, "method", "missing email method")?;
    if !matches!(method, "send" | "modify" | "read") {
        return Err(claim_failed("unsupported email method"));
    }
    for (field, message) in [
        ("mailbox_account_digest", "missing email mailbox digest"),
        ("subject_digest", "missing email subject digest"),
        ("oauth_scope_set_digest", "missing email OAuth scope digest"),
        (
            "provider_response_digest",
            "missing email provider response digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid email digest: {field}")))?;
    }
    if method == "send" {
        let message_digest = required_json_str(
            value,
            "rfc5322_message_digest",
            "missing email message digest",
        )?;
        validate_sha256_hex(message_digest)
            .map_err(|_| claim_failed("invalid email digest: rfc5322_message_digest"))?;
    }
    for field in ["recipient_digest_list", "attachment_digest_list"] {
        let digests = value
            .get(field)
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| claim_failed(format!("missing email digest list: {field}")))?;
        for digest in digests {
            let digest = digest
                .as_str()
                .ok_or_else(|| claim_failed(format!("invalid email digest list: {field}")))?;
            validate_sha256_hex(digest)
                .map_err(|_| claim_failed(format!("invalid email digest list: {field}")))?;
        }
    }
    let receipt_refs = value
        .get("receipt_refs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| claim_failed("missing email receipt refs"))?;
    if receipt_refs.is_empty() {
        return Err(claim_failed("missing email receipt refs"));
    }
    for receipt_ref in receipt_refs {
        let receipt_ref = receipt_ref
            .as_str()
            .ok_or_else(|| claim_failed("invalid email receipt ref"))?;
        if !envelope
            .receipt_refs
            .iter()
            .any(|bound| bound == receipt_ref)
        {
            return Err(claim_failed("email receipt ref is not bound"));
        }
    }
    let mediated = required_json_bool(
        value,
        "mediated_by_chio_receipt",
        "missing email Chio receipt mediation",
    )?;
    if !mediated {
        return Err(claim_failed(
            "email action was not mediated by Chio receipt",
        ));
    }
    Ok(())
}
