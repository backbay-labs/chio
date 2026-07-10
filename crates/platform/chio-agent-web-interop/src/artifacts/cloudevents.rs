use chio_transaction_passport::TransactionPassportError;

use super::super::evidence::validate_sha256_hex;
use super::{claim_failed, required_json_str, ProjectionManifest};

pub(super) fn validate_subject(
    value: &serde_json::Value,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    let specversion = required_json_str(value, "specversion", "missing CloudEvents specversion")?;
    if specversion != "1.0" || !manifest.source_version.starts_with("1.0") {
        return Err(claim_failed("CloudEvents specversion mismatch"));
    }
    for (field, message) in [
        ("id", "missing CloudEvents id"),
        ("source", "missing CloudEvents source"),
        ("type", "missing CloudEvents type"),
    ] {
        required_json_str(value, field, message)?;
    }
    if let Some(data_digest) = value.get("data_digest").and_then(serde_json::Value::as_str) {
        validate_sha256_hex(data_digest)
            .map_err(|_| claim_failed(format!("invalid CloudEvents data digest: {data_digest}")))?;
    }
    Ok(())
}
