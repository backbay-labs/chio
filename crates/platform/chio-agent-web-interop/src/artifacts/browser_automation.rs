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
        return Err(claim_failed("browser automation source version mismatch"));
    }
    let protocol = required_json_str(value, "protocol", "missing browser protocol")?;
    if !matches!(protocol, "webdriver" | "webdriver-bidi" | "cdp") {
        return Err(claim_failed("unsupported browser protocol"));
    }
    let protocol_version = required_json_str(
        value,
        "protocol_version",
        "missing browser protocol version",
    )?;
    if format!("{protocol}-{protocol_version}") != manifest.source_version {
        return Err(claim_failed("browser protocol version mismatch"));
    }
    if protocol == "cdp" && protocol_version == "tip-of-tree" {
        return Err(claim_failed("unpinned CDP protocol version"));
    }
    required_json_str(value, "command_name", "missing browser command name")?;
    for (field, message) in [
        (
            "browser_session_id_digest",
            "missing browser session id digest",
        ),
        ("user_context_digest", "missing browser user context digest"),
        ("target_url_digest", "missing browser target URL digest"),
        (
            "command_parameters_digest",
            "missing browser command parameters digest",
        ),
        ("locator_digest", "missing browser locator digest"),
        (
            "navigation_result_digest",
            "missing browser navigation result digest",
        ),
        ("screenshot_digest", "missing browser screenshot digest"),
        (
            "network_egress_digest",
            "missing browser network egress digest",
        ),
        (
            "authorization_context_digest",
            "missing browser authorization context digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid browser digest: {field}")))?;
    }
    let storage_access =
        required_json_str(value, "storage_access", "missing browser storage access")?;
    if !matches!(storage_access, "none" | "read" | "write" | "read-write") {
        return Err(claim_failed("unsupported browser storage access"));
    }
    if storage_access != "none" {
        let digest = required_json_str(
            value,
            "storage_scope_digest",
            "missing browser storage scope digest",
        )?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed("invalid browser digest: storage_scope_digest"))?;
    }
    if let Some(download_digest) = value
        .get("download_digest")
        .and_then(serde_json::Value::as_str)
    {
        validate_sha256_hex(download_digest)
            .map_err(|_| claim_failed("invalid browser digest: download_digest"))?;
    }
    let mediated = required_json_bool(
        value,
        "mediated_by_chio_receipt",
        "missing browser Chio receipt mediation",
    )?;
    if !mediated {
        return Err(claim_failed(
            "browser command was not mediated by Chio receipt",
        ));
    }
    let receipt_ref = required_json_str(
        value,
        "chio_command_receipt_ref",
        "missing browser command receipt ref",
    )?;
    if !envelope
        .receipt_refs
        .iter()
        .any(|bound_ref| bound_ref == receipt_ref)
    {
        return Err(claim_failed("browser command receipt ref is not bound"));
    }
    Ok(())
}
