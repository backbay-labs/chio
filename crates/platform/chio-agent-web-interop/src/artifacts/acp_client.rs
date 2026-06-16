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
        required_json_str(value, "protocol_version", "missing ACP-Client version")?;
    if protocol_version != manifest.source_version
        || protocol_version != envelope.source_protocol_version
    {
        return Err(claim_failed("ACP-Client protocol version mismatch"));
    }
    if protocol_version != "v1" {
        return Err(claim_failed("unsupported ACP-Client source version"));
    }
    required_json_str(value, "capability_id", "missing ACP-Client capability id")?;
    let category = required_json_str(value, "category", "missing ACP-Client category")?;
    if !matches!(category, "filesystem" | "terminal" | "tool" | "browser") {
        return Err(claim_failed("unsupported ACP-Client category"));
    }
    required_json_bool(
        value,
        "requires_permission",
        "missing ACP-Client permission requirement",
    )?;
    let permission_decision = required_json_str(
        value,
        "permission_decision",
        "missing ACP-Client permission decision",
    )?;
    if !matches!(permission_decision, "allow" | "deny") {
        return Err(claim_failed("unsupported ACP-Client permission decision"));
    }
    let bridge_fidelity = required_json_str(
        value,
        "bridge_fidelity",
        "missing ACP-Client bridge fidelity",
    )?;
    if !matches!(bridge_fidelity, "lossless" | "adapted" | "unsupported") {
        return Err(claim_failed("unsupported ACP-Client bridge fidelity"));
    }
    if bridge_fidelity == "unsupported" && permission_decision == "allow" {
        return Err(claim_failed("unsupported ACP-Client bridge allowed"));
    }
    for (field, message) in [
        (
            "source_envelope_digest",
            "missing ACP-Client source envelope digest",
        ),
        ("arguments_digest", "missing ACP-Client arguments digest"),
        ("client_session_digest", "missing ACP-Client session digest"),
        ("agent_id_digest", "missing ACP-Client agent id digest"),
        (
            "authorization_context_digest",
            "missing ACP-Client authorization context digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid ACP-Client digest: {field}")))?;
    }
    Ok(())
}
