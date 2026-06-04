use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;

const DEFAULT_KERNEL_KEY: &str = "chio-mcp-integration-local-kernel";
const DEFAULT_POLICY_HASH: &str = "chio-mcp-registry-policy-v1";
const DEFAULT_SIGNING_KEY: &str = "chio-mcp-integration-local-verifier";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum McpReceiptError {
    #[error("capability id is required")]
    MissingCapabilityId,
    #[error("tenant id is required")]
    MissingTenantId,
    #[error("tool name is required")]
    MissingToolName,
    #[error("receipt verification failed")]
    VerificationFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolReceiptOptions {
    pub timestamp: u64,
    pub receipt_id: String,
    pub signing_key: String,
}

impl Default for ToolReceiptOptions {
    fn default() -> Self {
        Self {
            timestamp: 1_710_000_200,
            receipt_id: "rcpt-mcp-local".to_string(),
            signing_key: DEFAULT_SIGNING_KEY.to_string(),
        }
    }
}

pub fn emit_tool_call_receipt(
    capability_id: &str,
    tenant_id: &str,
    tool_name: &str,
    arguments: serde_json::Value,
    result: serde_json::Value,
) -> Result<serde_json::Value, McpReceiptError> {
    emit_tool_call_receipt_with_options(
        capability_id,
        tenant_id,
        tool_name,
        arguments,
        result,
        ToolReceiptOptions::default(),
    )
}

pub fn emit_tool_call_receipt_with_options(
    capability_id: &str,
    tenant_id: &str,
    tool_name: &str,
    arguments: serde_json::Value,
    result: serde_json::Value,
    options: ToolReceiptOptions,
) -> Result<serde_json::Value, McpReceiptError> {
    validate_non_empty(capability_id, McpReceiptError::MissingCapabilityId)?;
    validate_non_empty(tenant_id, McpReceiptError::MissingTenantId)?;
    validate_non_empty(tool_name, McpReceiptError::MissingToolName)?;

    let action = json!({
        "parameters": arguments,
        "parameter_hash": hash_json(&arguments)
    });
    let mut receipt = json!({
        "id": options.receipt_id,
        "timestamp": options.timestamp,
        "capability_id": capability_id,
        "tool_server": "chio-mcp",
        "tool_name": tool_name,
        "action": action,
        "decision": { "verdict": "allow" },
        "content_hash": hash_json(&result),
        "policy_hash": DEFAULT_POLICY_HASH,
        "evidence": [
            {
                "guard_name": "McpPolicyEnforcementGuard",
                "verdict": true,
                "details": "MCP tools/call mediated before result release"
            }
        ],
        "metadata": {
            "surface": "mcp-registry",
            "version": 1,
            "transport": "streamable-http",
            "oauth": "pkce"
        },
        "tenant_id": tenant_id,
        "kernel_key": DEFAULT_KERNEL_KEY
    });
    let signature = sign_json(&receipt, &options.signing_key);
    receipt["signature"] = serde_json::Value::String(signature);
    Ok(receipt)
}

pub fn verify_tool_call_receipt(receipt: &serde_json::Value) -> bool {
    let Some(signature) = receipt.get("signature").and_then(serde_json::Value::as_str) else {
        return false;
    };
    let mut body = receipt.clone();
    if let Some(object) = body.as_object_mut() {
        object.remove("signature");
    } else {
        return false;
    }
    let metadata = body.get("metadata").and_then(serde_json::Value::as_object);
    if metadata.and_then(|value| value.get("surface")) != Some(&json!("mcp-registry")) {
        return false;
    }
    sign_json(&body, DEFAULT_SIGNING_KEY) == signature
}

fn validate_non_empty(value: &str, error: McpReceiptError) -> Result<(), McpReceiptError> {
    if value.trim().is_empty() || value.trim() != value {
        return Err(error);
    }
    Ok(())
}

fn hash_json(value: &serde_json::Value) -> String {
    let canonical = canonical_json(value);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn sign_json(value: &serde_json::Value, signing_key: &str) -> String {
    let material = format!("{}{}", canonical_json(value), signing_key);
    let mut hasher = Sha256::new();
    hasher.update(material.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn canonical_json(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}
