use chio_transaction_passport::TransactionPassportError;

use super::super::evidence::validate_sha256_hex;
use super::{claim_failed, required_json_str};

pub(super) fn validate_subject(
    value: &serde_json::Value,
    envelope_signature_ref: &str,
) -> Result<(), TransactionPassportError> {
    let webhook_id = required_json_str(value, "webhook_id", "missing Standard Webhooks id")?;
    let webhook_timestamp = required_json_str(
        value,
        "webhook_timestamp",
        "missing Standard Webhooks timestamp",
    )?;
    let webhook_signature = required_json_str(
        value,
        "webhook_signature",
        "missing Standard Webhooks signature",
    )?;
    let body_digest = required_json_str(value, "body_digest", "missing Standard Webhooks body")?;
    let endpoint_url_digest = required_json_str(
        value,
        "endpoint_url_digest",
        "missing Standard Webhooks endpoint digest",
    )?;
    for digest_value in [endpoint_url_digest, body_digest] {
        validate_sha256_hex(digest_value).map_err(|_| {
            claim_failed(format!("invalid Standard Webhooks digest: {digest_value}"))
        })?;
    }
    if webhook_id.is_empty() || webhook_timestamp.is_empty() || webhook_signature.is_empty() {
        return Err(claim_failed("missing Standard Webhooks field"));
    }
    validate_signature_ref(webhook_signature)?;
    validate_signature_ref(envelope_signature_ref)?;
    if webhook_signature != envelope_signature_ref {
        return Err(claim_failed("external signature mismatch"));
    }
    Ok(())
}

fn validate_signature_ref(signature_ref: &str) -> Result<(), TransactionPassportError> {
    let Some((version, signature)) = signature_ref.split_once(',') else {
        return Err(claim_failed("invalid Standard Webhooks signature"));
    };
    if version != "v1" || signature.is_empty() || signature.chars().any(char::is_whitespace) {
        return Err(claim_failed("invalid Standard Webhooks signature"));
    }
    Ok(())
}
