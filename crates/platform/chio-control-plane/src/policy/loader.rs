use std::path::{Path, PathBuf};

use super::capabilities::{
    build_default_capabilities_from_scope, build_runtime_default_capabilities,
};
use super::guards::{build_guard_pipeline, build_post_invocation_pipeline};
use super::issuance::{
    materialize_reputation_issuance_policy, materialize_runtime_assurance_policy,
};
use super::types::{
    ChioPolicy, KernelPolicyConfig, LoadedPolicy, PolicyAssetDigest, PolicyError, PolicyFormat,
    PolicyIdentity,
};
use super::util::{
    hash_bytes, hash_json_value, runtime_hash_for_chio_yaml, runtime_hash_for_hushspec,
};

struct HexApproverDirectory;

impl chio_kernel::threshold_approval::ApproverDirectory for HexApproverDirectory {
    fn resolve_approver(
        &self,
        identifier: &str,
    ) -> Result<chio_kernel::threshold_approval::ResolvedApproverIdentity, String> {
        let public_key = chio_core::PublicKey::from_hex(identifier)
            .map_err(|error| format!("approver identifier is not a public key: {error}"))?;
        if public_key.to_hex() != identifier {
            return Err("approver public key identifier is not canonical".to_owned());
        }
        Ok(chio_kernel::threshold_approval::ResolvedApproverIdentity {
            identifier: identifier.to_owned(),
            public_key,
            directory_version: "self-authenticating-public-key-v1".to_owned(),
        })
    }
}

/// Load a policy from a YAML file.
///
/// Auto-detects whether the file is a HushSpec policy (contains `hushspec:`
/// top-level key) or a Chio YAML policy. HushSpec inputs are resolved,
/// validated, compiled, and kept alive as runtime state rather than being
/// reduced to an empty fallback policy shell.
pub fn load_policy(path: &Path) -> Result<LoadedPolicy, PolicyError> {
    let contents = std::fs::read_to_string(path)?;
    let source_hash = hash_bytes(contents.as_bytes());

    if chio_policy::is_hushspec_format(&contents) {
        return load_hushspec_policy(path, source_hash);
    }

    let policy: ChioPolicy = serde_yml::from_str(&contents)?;
    policy.kernel.validate()?;
    let default_capabilities = build_runtime_default_capabilities(&policy)?;
    let runtime_hash = runtime_hash_for_chio_yaml(&policy, &default_capabilities)?;

    Ok(LoadedPolicy {
        format: PolicyFormat::ChioYaml,
        identity: PolicyIdentity {
            source_hash,
            runtime_hash,
        },
        kernel: policy.kernel.clone(),
        default_capabilities,
        guard_pipeline: build_guard_pipeline(&policy.guards)?,
        post_invocation_pipeline: build_post_invocation_pipeline(&policy.guards)?,
        issuance_policy: None,
        runtime_assurance_policy: None,
        threshold_approval: None,
    })
}

/// Load a HushSpec policy and compile it into the runtime policy materialization.
fn load_hushspec_policy(path: &Path, source_hash: String) -> Result<LoadedPolicy, PolicyError> {
    let spec = chio_policy::resolve_from_path(path)?;
    let validation = chio_policy::validate(&spec);
    if !validation.is_valid() {
        let messages: Vec<String> = validation.errors.iter().map(|e| e.to_string()).collect();
        return Err(PolicyError::Invalid(format!(
            "HushSpec validation failed: {}",
            messages.join("; ")
        )));
    }

    let source_dir = path.parent();
    let auxiliary_assets = hushspec_auxiliary_asset_digests(&spec, source_dir)?;
    let source_hash = hushspec_source_hash_with_assets(&source_hash, &auxiliary_assets)?;
    let compiled = chio_policy::compile_policy_with_source_and_approver_directory(
        &spec,
        Some(path),
        &HexApproverDirectory,
    )?;
    let kernel = KernelPolicyConfig::default();
    let default_capabilities =
        build_default_capabilities_from_scope(&compiled.default_scope, kernel.max_capability_ttl);
    let issuance_policy = materialize_reputation_issuance_policy(&spec)?;
    let runtime_assurance_policy = materialize_runtime_assurance_policy(&spec)?;
    let runtime_hash =
        runtime_hash_for_hushspec(&kernel, &default_capabilities, &spec, &auxiliary_assets)?;
    let threshold_approval = compiled
        .threshold_approval
        .map(|requirement| {
            chio_core::capability::threshold_approval::ThresholdApprovalRequirement::new(
                runtime_hash.clone(),
                requirement.threshold,
                requirement.eligible_approvers,
                requirement.directory_version,
                requirement.timeout_seconds,
            )
        })
        .transpose()
        .map_err(PolicyError::Invalid)?;

    Ok(LoadedPolicy {
        format: PolicyFormat::HushSpec,
        identity: PolicyIdentity {
            source_hash,
            runtime_hash,
        },
        kernel,
        default_capabilities,
        guard_pipeline: compiled.guards,
        post_invocation_pipeline: compiled.post_invocation,
        issuance_policy,
        runtime_assurance_policy,
        threshold_approval,
    })
}

fn hushspec_auxiliary_asset_digests(
    spec: &chio_policy::HushSpec,
    source_dir: Option<&Path>,
) -> Result<Vec<PolicyAssetDigest>, PolicyError> {
    let mut assets = Vec::new();
    let Some(threat_intel) = spec
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.detection.as_ref())
        .and_then(|detection| detection.threat_intel.as_ref())
    else {
        return Ok(assets);
    };
    if !threat_intel.enabled.unwrap_or(true) {
        return Ok(assets);
    }
    let Some(pattern_db) = threat_intel.pattern_db.as_deref() else {
        return Ok(assets);
    };

    let resolved_path = resolve_policy_asset_path(pattern_db, source_dir);
    let bytes = std::fs::read(&resolved_path).map_err(|error| {
        PolicyError::Invalid(format!(
            "failed to read HushSpec auxiliary asset detection.threat_intel.pattern_db '{}' (resolved to '{}'): {error}",
            pattern_db,
            resolved_path.display()
        ))
    })?;
    let identity_path = std::fs::canonicalize(&resolved_path)
        .unwrap_or_else(|_| resolved_path.clone())
        .display()
        .to_string();
    assets.push(PolicyAssetDigest {
        field: "extensions.detection.threat_intel.pattern_db",
        path: identity_path,
        sha256: hash_bytes(&bytes),
    });
    Ok(assets)
}

fn resolve_policy_asset_path(path: &str, source_dir: Option<&Path>) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        return candidate;
    }

    match source_dir {
        Some(dir) => dir.join(candidate),
        None => candidate,
    }
}

fn hushspec_source_hash_with_assets(
    source_hash: &str,
    auxiliary_assets: &[PolicyAssetDigest],
) -> Result<String, PolicyError> {
    if auxiliary_assets.is_empty() {
        return Ok(source_hash.to_string());
    }
    hash_json_value(&serde_json::json!({
        "format": PolicyFormat::HushSpec.as_str(),
        "source_hash": source_hash,
        "auxiliary_assets": auxiliary_assets,
    }))
}

/// Parse a policy from a YAML string.
pub fn parse_policy(yaml: &str) -> Result<ChioPolicy, PolicyError> {
    let policy: ChioPolicy = serde_yml::from_str(yaml)?;
    policy.kernel.validate()?;
    Ok(policy)
}
