use chio_core::capability::scope::Operation;
use sha2::{Digest, Sha256};

use super::types::{
    ChioPolicy, DefaultCapability, KernelPolicyConfig, PolicyAssetDigest, PolicyError, PolicyFormat,
};

pub(super) fn parse_operations(operations: &[String]) -> Result<Vec<Operation>, PolicyError> {
    operations
        .iter()
        .map(|op| match op.as_str() {
            "invoke" => Ok(Operation::Invoke),
            "read_result" => Ok(Operation::ReadResult),
            "read" => Ok(Operation::Read),
            "subscribe" => Ok(Operation::Subscribe),
            "get" => Ok(Operation::Get),
            "delegate" => Ok(Operation::Delegate),
            _ => Err(PolicyError::Invalid(format!(
                "unsupported capability operation: {op}"
            ))),
        })
        .collect()
}

pub(super) fn runtime_hash_for_chio_yaml(
    policy: &ChioPolicy,
    default_capabilities: &[DefaultCapability],
) -> Result<String, PolicyError> {
    let fingerprint = serde_json::json!({
        "format": PolicyFormat::ChioYaml.as_str(),
        "kernel": policy.kernel,
        "guards": policy.guards,
        "default_capabilities": default_capabilities,
    });
    hash_json_value(&fingerprint)
}

pub(super) fn runtime_hash_for_hushspec(
    kernel: &KernelPolicyConfig,
    default_capabilities: &[DefaultCapability],
    spec: &chio_policy::HushSpec,
    auxiliary_assets: &[PolicyAssetDigest],
) -> Result<String, PolicyError> {
    let rules = spec.rules.as_ref();
    let extensions = spec.extensions.as_ref();
    let fingerprint = serde_json::json!({
        "format": PolicyFormat::HushSpec.as_str(),
        "kernel": kernel,
        "default_capabilities": default_capabilities,
        "rules": {
            "forbidden_paths": rules.and_then(|entry| entry.forbidden_paths.as_ref()),
            "path_allowlist": rules.and_then(|entry| entry.path_allowlist.as_ref()),
            "egress": rules.and_then(|entry| entry.egress.as_ref()),
            "secret_patterns": rules.and_then(|entry| entry.secret_patterns.as_ref()),
            "patch_integrity": rules.and_then(|entry| entry.patch_integrity.as_ref()),
            "shell_commands": rules.and_then(|entry| entry.shell_commands.as_ref()),
            "tool_access": rules.and_then(|entry| entry.tool_access.as_ref()),
        },
        "reputation": extensions.and_then(|entry| entry.reputation.as_ref()),
        "auxiliary_assets": auxiliary_assets,
    });
    hash_json_value(&fingerprint)
}

pub(super) fn hash_json_value(value: &serde_json::Value) -> Result<String, PolicyError> {
    let encoded = serde_json::to_vec(value)?;
    Ok(hash_bytes(&encoded))
}

pub(super) fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
