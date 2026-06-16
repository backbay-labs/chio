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
        return Err(claim_failed("RPA source version mismatch"));
    }
    let runner = required_json_str(value, "runner", "missing RPA runner")?;
    if !matches!(
        runner,
        "uia" | "apple-accessibility" | "at-spi" | "vendor-rpa" | "chio-runner"
    ) {
        return Err(claim_failed("unsupported RPA runner"));
    }
    let runner_version = required_json_str(value, "runner_version", "missing RPA runner version")?;
    if format!("{runner}-{runner_version}") != manifest.source_version {
        return Err(claim_failed("RPA runner version mismatch"));
    }
    required_json_str(value, "action_name", "missing RPA action name")?;
    let mutation_classification = required_json_str(
        value,
        "mutation_classification",
        "missing RPA mutation classification",
    )?;
    if !matches!(
        mutation_classification,
        "ui-read" | "ui-write" | "file-download" | "clipboard" | "credential-entry"
    ) {
        return Err(claim_failed("unsupported RPA mutation classification"));
    }
    for (field, message) in [
        ("transcript_digest", "missing RPA transcript digest"),
        (
            "desktop_session_digest",
            "missing RPA desktop session digest",
        ),
        ("user_context_digest", "missing RPA user context digest"),
        (
            "application_identity_digest",
            "missing RPA application identity digest",
        ),
        (
            "window_identity_digest",
            "missing RPA window identity digest",
        ),
        (
            "control_locator_digest",
            "missing RPA control locator digest",
        ),
        (
            "action_parameters_digest",
            "missing RPA action parameters digest",
        ),
        ("pre_state_digest", "missing RPA pre-state digest"),
        ("post_state_digest", "missing RPA post-state digest"),
        ("screenshot_digest", "missing RPA screenshot digest"),
        (
            "authorization_context_digest",
            "missing RPA authorization context digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid RPA digest: {field}")))?;
    }
    let mediated = required_json_bool(
        value,
        "mediated_by_chio_receipt",
        "missing RPA Chio receipt mediation",
    )?;
    if !mediated {
        return Err(claim_failed("RPA action was not mediated by Chio receipt"));
    }
    Ok(())
}
