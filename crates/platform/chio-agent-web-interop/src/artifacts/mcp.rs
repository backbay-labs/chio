use chio_transaction_passport::TransactionPassportError;

use super::super::evidence::validate_sha256_hex;
use super::{claim_failed, required_json_str, AgentWebProofEnvelope, ProjectionManifest};

pub(super) fn validate_subject(
    value: &serde_json::Value,
    envelope: &AgentWebProofEnvelope,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    let protocol_version = required_json_str(value, "protocol_version", "missing MCP version")?;
    if protocol_version != manifest.source_version
        || protocol_version != envelope.source_protocol_version
    {
        return Err(claim_failed("MCP protocol version mismatch"));
    }
    if protocol_version != "2025-11-25" {
        return Err(claim_failed("unsupported MCP source version"));
    }
    let transport = required_json_str(value, "transport", "missing MCP transport")?;
    if !matches!(transport, "stdio" | "streamable-http") {
        return Err(claim_failed("unsupported MCP transport"));
    }
    required_json_str(value, "tool_name", "missing MCP tool name")?;
    for (field, message) in [
        (
            "server_identity_digest",
            "missing MCP server identity digest",
        ),
        ("session_id_digest", "missing MCP session digest"),
        ("arguments_digest", "missing MCP arguments digest"),
        ("result_digest", "missing MCP result digest"),
        (
            "authorization_context_digest",
            "missing MCP authorization context digest",
        ),
        (
            "protected_resource_metadata_digest",
            "missing MCP protected-resource metadata digest",
        ),
        (
            "authorization_server_metadata_digest",
            "missing MCP authorization-server metadata digest",
        ),
        ("dpop_proof_digest", "missing MCP DPoP proof digest"),
        (
            "proof_envelope_resource_read_digest",
            "missing MCP proof-envelope resource read digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid MCP digest: {field}")))?;
    }
    Ok(())
}
