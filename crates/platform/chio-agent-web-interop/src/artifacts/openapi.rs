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
        return Err(claim_failed("OpenAPI source version mismatch"));
    }
    if manifest.source_version != "3.1.0" {
        return Err(claim_failed("unsupported OpenAPI source version"));
    }
    for (field, message) in [
        ("spec_digest", "missing OpenAPI spec digest"),
        ("request_digest", "missing OpenAPI request digest"),
        ("response_digest", "missing OpenAPI response digest"),
        (
            "authorization_context_digest",
            "missing OpenAPI authorization context digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid OpenAPI digest: {field}")))?;
    }
    required_json_str(value, "operation_id", "missing OpenAPI operation id")?;
    let method = required_json_str(value, "method", "missing OpenAPI method")?;
    if !matches!(
        method,
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "TRACE"
    ) {
        return Err(claim_failed("unsupported OpenAPI method"));
    }
    let path_template = required_json_str(value, "path_template", "missing OpenAPI path")?;
    if !path_template.starts_with('/') {
        return Err(claim_failed("unsupported OpenAPI path"));
    }
    let status_code = required_json_u64(value, "status_code", "missing OpenAPI status code")?;
    if !(100..=599).contains(&status_code) {
        return Err(claim_failed("unsupported OpenAPI status code"));
    }
    if !(200..=299).contains(&status_code) {
        return Err(claim_failed("OpenAPI response status was not successful"));
    }
    let operation_receipt_ref = required_json_str(
        value,
        "chio_operation_receipt_ref",
        "missing OpenAPI operation receipt ref",
    )?;
    if !envelope
        .receipt_refs
        .iter()
        .any(|receipt_ref| receipt_ref == operation_receipt_ref)
    {
        return Err(claim_failed("OpenAPI operation receipt ref is not bound"));
    }
    Ok(())
}
