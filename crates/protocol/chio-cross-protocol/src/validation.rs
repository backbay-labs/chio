use chio_core::capability::token::CapabilityToken;
use serde_json::Value;

use crate::capability_bridge::{parent_capability_hash, CrossProtocolCapabilityRef};
use crate::discovery::DiscoveryProtocol;
use crate::error::BridgeError;
use crate::execution::CrossProtocolExecutionRequest;

pub(crate) fn validate_execution_request_boundary(
    request: &CrossProtocolExecutionRequest,
) -> Result<(), BridgeError> {
    validate_request_identity_field("origin_request_id", &request.origin_request_id)?;
    validate_request_identity_field("kernel_request_id", &request.kernel_request_id)?;
    validate_request_identity_field("target_server_id", &request.target_server_id)?;
    validate_request_identity_field("target_tool_name", &request.target_tool_name)?;
    validate_request_identity_field("agent_id", &request.agent_id)?;
    if request.approval_token.is_some() && !request.approval_tokens.is_empty() {
        return Err(BridgeError::InvalidRequest(
            "cross-protocol execution must not mix singular and threshold approval tokens"
                .to_string(),
        ));
    }
    if request.approval_tokens.len() > 32 {
        return Err(BridgeError::InvalidRequest(
            "cross-protocol threshold approval set exceeds 32 tokens".to_string(),
        ));
    }
    if request.approval_tokens.is_empty() != request.threshold_approval_proposal.is_none() {
        return Err(BridgeError::InvalidRequest(
            "cross-protocol threshold approval tokens and proposal must be supplied together"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_request_identity_field(field_name: &str, value: &str) -> Result<(), BridgeError> {
    if value.trim().is_empty() {
        return Err(BridgeError::InvalidRequest(format!(
            "{field_name} must be a non-empty string"
        )));
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(BridgeError::InvalidRequest(format!(
            "{field_name} must be unpadded and contain no control characters"
        )));
    }
    Ok(())
}

pub(crate) fn validate_provided_capability_ref(
    cap_ref: &CrossProtocolCapabilityRef,
    capability: &CapabilityToken,
    source_protocol: DiscoveryProtocol,
) -> Result<(), BridgeError> {
    if cap_ref.origin_protocol != source_protocol {
        return Err(BridgeError::InvalidRequest(format!(
            "capabilityRef originProtocol {} does not match source protocol {}",
            cap_ref.origin_protocol, source_protocol
        )));
    }

    if cap_ref.chio_capability_id != capability.id {
        return Err(BridgeError::CapabilityRefMismatch {
            expected: capability.id.clone(),
            actual: cap_ref.chio_capability_id.clone(),
        });
    }

    let expected_hash = parent_capability_hash(capability)?;
    if cap_ref.parent_capability_hash != expected_hash {
        return Err(BridgeError::InvalidRequest(
            "capabilityRef parentCapabilityHash does not match active capability lineage"
                .to_string(),
        ));
    }

    Ok(())
}

pub(crate) fn schema_extension<'a>(schema: &'a Value, key: &str) -> Option<&'a Value> {
    schema.as_object()?.get(key)
}

pub(crate) fn schema_bool_extension(schema: &Value, key: &str) -> Option<bool> {
    schema_extension(schema, key)?.as_bool()
}

pub(crate) fn schema_string_extension(schema: &Value, key: &str) -> Result<Option<String>, String> {
    let Some(value) = schema_extension(schema, key) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(|value| Some(value.to_string()))
        .ok_or_else(|| format!("{key} must be a string when present"))
}
