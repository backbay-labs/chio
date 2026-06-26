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
    if permission_decision == "deny" {
        return Err(claim_failed("ACP-Client permission was denied"));
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
    let jsonrpc_method = required_json_str(value, "jsonrpc_method", "missing ACP-Client method")?;
    if !matches!(
        jsonrpc_method,
        "session/request_permission"
            | "fs/read_text_file"
            | "fs/write_text_file"
            | "terminal/create"
            | "session/update"
    ) {
        return Err(claim_failed("unsupported ACP-Client method"));
    }
    let receipt_id = required_json_str(value, "chio_receipt_id", "missing ACP-Client receipt id")?;
    if !envelope
        .receipt_refs
        .iter()
        .any(|receipt_ref| receipt_ref == receipt_id)
    {
        return Err(claim_failed(
            "ACP-Client receipt id is not bound by proof envelope",
        ));
    }
    let evidence_path_kind = required_json_str(
        value,
        "evidence_path_kind",
        "missing ACP-Client evidence path kind",
    )?;
    if evidence_path_kind == "unsigned-audit" {
        return Err(claim_failed(
            "ACP-Client unsigned audit path cannot satisfy signed receipt projection",
        ));
    }
    if evidence_path_kind != "signed-receipt" {
        return Err(claim_failed("unsupported ACP-Client evidence path kind"));
    }
    for (field, message) in [
        ("jsonrpc_id_digest", "missing ACP-Client JSON-RPC id digest"),
        ("params_digest", "missing ACP-Client params digest"),
        (
            "permission_request_digest",
            "missing ACP-Client permission request digest",
        ),
        (
            "file_path_scope_digest",
            "missing ACP-Client file path scope digest",
        ),
        (
            "terminal_command_scope_digest",
            "missing ACP-Client terminal command scope digest",
        ),
        (
            "receipt_signature_digest",
            "missing ACP-Client receipt signature digest",
        ),
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
