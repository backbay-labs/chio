//! Policy YAML loading and guard pipeline construction.
//!
//! Reads a Chio policy file and produces a configured `GuardPipeline` plus
//! initial capability definitions for the agent.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chio_data_guards::{
    QueryResultGuard, QueryResultGuardConfig, SqlGuardConfig, SqlQueryGuard, VectorDbGuard,
    VectorGuardConfig, WarehouseCostGuard, WarehouseCostGuardConfig,
};
use chio_external_guards::{
    external::{BackoffStrategy, CircuitBreakerConfig, RetryConfig},
    AsyncGuardAdapter, AzureCategory, AzureContentSafetyConfig, AzureContentSafetyGuard,
    SafeBrowsingConfig, SafeBrowsingGuard, ScopedAsyncGuard,
};
use chio_reputation::{
    ReputationConfig as LocalReputationConfig, ReputationWeights as LocalReputationWeights,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use chio_core::capability::{
    AttestationTrustPolicy, AttestationTrustRule, ChioScope, MonetaryAmount, Operation,
    PromptGrant, ResourceGrant, RuntimeAssuranceTier, ToolGrant,
};
use chio_guards::{
    ContentReviewConfig, ContentReviewGuard, EgressAllowlistGuard, ForbiddenPathGuard,
    GuardPipeline, InternalNetworkGuard, McpToolGuard, PatchIntegrityGuard, PathAllowlistGuard,
    PostInvocationPipeline, SanitizerHook, SecretLeakGuard, ShellCommandGuard,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultCapability {
    pub scope: ChioScope,
    pub ttl: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyFormat {
    ChioYaml,
    HushSpec,
}

impl PolicyFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChioYaml => "chio_yaml",
            Self::HushSpec => "hushspec",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyIdentity {
    pub source_hash: String,
    pub runtime_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct PolicyAssetDigest {
    field: &'static str,
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReputationIssuancePolicy {
    pub scoring: LocalReputationConfig,
    pub probationary_receipt_count: u64,
    pub probationary_min_days: u64,
    pub probationary_score_ceiling: f64,
    pub tiers: Vec<ReputationTierPolicy>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReputationTierPolicy {
    pub name: String,
    pub score_range: [f64; 2],
    pub max_scope: TierScopeCeiling,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeAssuranceIssuancePolicy {
    pub tiers: Vec<RuntimeAssuranceTierPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_trust_policy: Option<AttestationTrustPolicy>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeAssuranceTierPolicy {
    pub name: String,
    pub minimum_attestation_tier: RuntimeAssuranceTier,
    pub max_scope: TierScopeCeiling,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierScopeCeiling {
    pub operations: Vec<Operation>,
    pub max_invocations: Option<u32>,
    pub max_cost_per_invocation: Option<MonetaryAmount>,
    pub max_total_cost: Option<MonetaryAmount>,
    pub max_delegation_depth: Option<u32>,
    pub ttl_seconds: u64,
    pub constraints_required: bool,
}

/// Runtime-ready policy materialization used by the CLI and kernel setup.
pub struct LoadedPolicy {
    pub format: PolicyFormat,
    pub identity: PolicyIdentity,
    pub kernel: KernelPolicyConfig,
    pub default_capabilities: Vec<DefaultCapability>,
    pub guard_pipeline: GuardPipeline,
    pub post_invocation_pipeline: PostInvocationPipeline,
    pub issuance_policy: Option<ReputationIssuancePolicy>,
    pub runtime_assurance_policy: Option<RuntimeAssuranceIssuancePolicy>,
}

impl LoadedPolicy {
    pub fn format_name(&self) -> &'static str {
        self.format.as_str()
    }
}

/// Errors that can occur during policy loading.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("failed to read policy file: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse policy YAML: {0}")]
    Yaml(#[from] serde_yml::Error),

    #[error("failed to resolve HushSpec policy: {0}")]
    Resolve(#[from] chio_policy::ResolveError),

    #[error("failed to compile HushSpec policy: {0}")]
    Compile(#[from] chio_policy::CompileError),

    #[error("failed to serialize policy identity: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid policy: {0}")]
    Invalid(String),
}

/// Top-level Chio policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChioPolicy {
    /// Kernel-level configuration.
    #[serde(default)]
    pub kernel: KernelPolicyConfig,

    /// Guard configuration.
    #[serde(default)]
    pub guards: GuardPolicyConfig,

    /// Initial capabilities to issue to the agent.
    #[serde(default)]
    pub capabilities: CapabilityPolicyConfig,
}

/// Kernel-level configuration from the policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelPolicyConfig {
    /// Maximum TTL (seconds) for any capability.
    #[serde(default = "default_max_capability_ttl")]
    pub max_capability_ttl: u64,

    /// Maximum allowed delegation chain depth.
    #[serde(default = "default_delegation_depth_limit")]
    pub delegation_depth_limit: u32,

    /// Whether nested sampling requests may be issued through the client.
    #[serde(default)]
    pub allow_sampling: bool,

    /// Whether sampling requests may include tool-use affordances.
    #[serde(default)]
    pub allow_sampling_tool_use: bool,

    /// Whether nested elicitation requests may be issued through the client.
    #[serde(default)]
    pub allow_elicitation: bool,

    /// Whether durable receipts plus kernel-signed checkpoints are mandatory
    /// prerequisites for this deployment.
    #[serde(default)]
    pub require_web3_evidence: bool,

    /// Allow local process-only receipt logs when no durable receipt store is
    /// configured. This is intended for tests and local scaffolds only.
    #[serde(default)]
    pub allow_ephemeral_receipt_log: bool,

    /// Number of receipts between Merkle checkpoint snapshots.
    #[serde(default = "default_checkpoint_batch_size")]
    pub checkpoint_batch_size: u64,
}

impl Default for KernelPolicyConfig {
    fn default() -> Self {
        Self {
            max_capability_ttl: default_max_capability_ttl(),
            delegation_depth_limit: default_delegation_depth_limit(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: false,
            checkpoint_batch_size: default_checkpoint_batch_size(),
        }
    }
}

fn default_max_capability_ttl() -> u64 {
    3600
}

fn default_delegation_depth_limit() -> u32 {
    5
}

fn default_checkpoint_batch_size() -> u64 {
    chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE
}

/// Guard configuration from the policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardPolicyConfig {
    /// Forbidden-path guard configuration.
    #[serde(default)]
    pub forbidden_path: Option<ForbiddenPathConfig>,

    /// Path allowlist guard configuration.
    #[serde(default)]
    pub path_allowlist: Option<PolicyPathAllowlistConfig>,

    /// Shell command guard configuration.
    #[serde(default)]
    pub shell_command: Option<ShellCommandConfig>,

    /// Egress allowlist guard configuration.
    #[serde(default)]
    pub egress_allowlist: Option<EgressAllowlistConfig>,

    /// Internal-network SSRF guard configuration.
    #[serde(default)]
    pub internal_network: Option<InternalNetworkConfig>,

    /// MCP tool access guard configuration.
    #[serde(default)]
    pub tool_access: Option<ToolAccessConfig>,

    /// Secret leak guard configuration.
    #[serde(default)]
    pub secret_patterns: Option<SecretPatternsConfig>,

    /// Patch integrity guard configuration.
    #[serde(default)]
    pub patch_integrity: Option<PatchIntegrityConfig>,

    /// SQL query guard configuration.
    #[serde(default)]
    pub sql_query: Option<SqlGuardConfig>,

    /// Vector database guard configuration.
    #[serde(default)]
    pub vector_db: Option<VectorGuardConfig>,

    /// Warehouse cost guard configuration.
    #[serde(default)]
    pub warehouse_cost: Option<WarehouseCostGuardConfig>,

    /// Query-result post-invocation guard configuration.
    #[serde(default)]
    pub query_result: Option<QueryResultGuardConfig>,

    /// Outbound content-review guard configuration.
    #[serde(default)]
    pub content_review: Option<ContentReviewConfig>,

    /// Cloud guardrail adapters backed by external providers.
    #[serde(default)]
    pub cloud_guardrails: Option<CloudGuardrailsPolicyConfig>,

    /// Threat-intel adapters backed by external providers.
    #[serde(default)]
    pub threat_intel: Option<ThreatIntelPolicyConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudGuardrailsPolicyConfig {
    #[serde(default)]
    pub azure_content_safety: Option<AzureContentSafetyPolicyConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatIntelPolicyConfig {
    #[serde(default)]
    pub safe_browsing: Option<SafeBrowsingPolicyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAdapterPolicyConfig {
    #[serde(default = "default_external_cache_ttl_seconds")]
    pub cache_ttl_seconds: u64,
    #[serde(default = "default_external_rate_per_second")]
    pub rate_per_second: f64,
    #[serde(default = "default_external_rate_burst")]
    pub rate_burst: u32,
    #[serde(default = "default_external_circuit_failure_threshold")]
    pub circuit_failure_threshold: u32,
    #[serde(default = "default_external_retry_max_retries")]
    pub retry_max_retries: u32,
}

impl Default for ExternalAdapterPolicyConfig {
    fn default() -> Self {
        Self {
            cache_ttl_seconds: default_external_cache_ttl_seconds(),
            rate_per_second: default_external_rate_per_second(),
            rate_burst: default_external_rate_burst(),
            circuit_failure_threshold: default_external_circuit_failure_threshold(),
            retry_max_retries: default_external_retry_max_retries(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AzureContentSafetyPolicyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub endpoint: String,
    pub api_key: String,
    #[serde(default)]
    pub api_version: Option<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub severity_threshold: Option<u32>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub tool_patterns: Vec<String>,
    #[serde(default)]
    pub adapter: ExternalAdapterPolicyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeBrowsingPolicyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub api_key: String,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_version: Option<String>,
    #[serde(default)]
    pub threat_types: Vec<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub tool_patterns: Vec<String>,
    #[serde(default)]
    pub adapter: ExternalAdapterPolicyConfig,
}

fn default_external_cache_ttl_seconds() -> u64 {
    60
}

fn default_external_rate_per_second() -> f64 {
    20.0
}

fn default_external_rate_burst() -> u32 {
    20
}

fn default_external_circuit_failure_threshold() -> u32 {
    5
}

fn default_external_retry_max_retries() -> u32 {
    3
}

/// Configuration for the forbidden-path guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenPathConfig {
    /// Whether this guard is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Exact glob patterns to use instead of the built-in defaults.
    #[serde(default)]
    pub patterns: Option<Vec<String>>,

    /// Additional glob patterns to block (added to the built-in defaults).
    #[serde(default)]
    pub additional_patterns: Vec<String>,

    /// Paths to exempt from the forbidden list.
    #[serde(default)]
    pub exceptions: Vec<String>,
}

/// Configuration for the path-allowlist guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPathAllowlistConfig {
    /// Whether this guard is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Allowed paths for read-style file access.
    #[serde(default)]
    pub read: Vec<String>,

    /// Allowed paths for write-style file access.
    #[serde(default)]
    pub write: Vec<String>,

    /// Allowed paths for patch-style operations.
    #[serde(default)]
    pub patch: Vec<String>,
}

/// Configuration for the shell command guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellCommandConfig {
    /// Whether this guard is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Additional command patterns to deny.
    #[serde(default)]
    pub forbidden_patterns: Vec<String>,
}

/// Configuration for the egress allowlist guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressAllowlistConfig {
    /// Whether this guard is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Domains to allow (glob patterns). These replace the built-in defaults.
    #[serde(default)]
    pub allowed_domains: Vec<String>,

    /// Domains to explicitly block (takes precedence over allow).
    #[serde(default)]
    pub blocked_domains: Vec<String>,
}

/// Configuration for the internal-network SSRF guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalNetworkConfig {
    /// Whether this guard is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Additional hostnames to block beyond the built-in metadata/internal list.
    #[serde(default)]
    pub extra_blocked_hosts: Vec<String>,

    /// Enable DNS rebinding detection heuristics.
    #[serde(default = "default_true")]
    pub dns_rebinding_detection: bool,
}

/// Default behavior when a tool is not explicitly allowed or blocked.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ToolAccessDefaultAction {
    #[default]
    Allow,
    Block,
}

/// Configuration for the MCP tool access guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolAccessConfig {
    /// Whether this guard is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Tool patterns to allow.
    #[serde(default)]
    pub allow: Vec<String>,

    /// Tool patterns to block.
    #[serde(default)]
    pub block: Vec<String>,

    /// Default action for tools not present in either list.
    #[serde(default)]
    pub default_action: ToolAccessDefaultAction,

    /// Maximum serialized argument size in bytes.
    #[serde(default)]
    pub max_args_size: Option<usize>,

    /// Tool patterns that must be elevated to approval-gated capabilities.
    #[serde(default)]
    pub require_confirmation: Vec<String>,
}

/// Configuration for the secret leak guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretPatternsConfig {
    /// Whether this guard is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// File patterns to skip during leak detection.
    #[serde(default)]
    pub skip_paths: Vec<String>,
}

/// Configuration for the patch integrity guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchIntegrityConfig {
    /// Whether this guard is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Maximum lines added in a single patch.
    #[serde(default = "default_patch_max_additions")]
    pub max_additions: usize,

    /// Maximum lines deleted in a single patch.
    #[serde(default = "default_patch_max_deletions")]
    pub max_deletions: usize,

    /// Patterns forbidden in added lines.
    #[serde(default = "default_patch_forbidden_patterns")]
    pub forbidden_patterns: Vec<String>,

    /// Require additions and deletions to stay within the configured ratio.
    #[serde(default)]
    pub require_balance: bool,

    /// Maximum allowed additions/deletions ratio.
    #[serde(default = "default_patch_max_imbalance_ratio")]
    pub max_imbalance_ratio: f64,
}

/// Configuration for initial capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPolicyConfig {
    /// Default capabilities issued to every agent at session start.
    #[serde(default)]
    pub default: Option<DefaultCapabilityConfig>,
}

/// Default capability configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultCapabilityConfig {
    /// Tool grants to include in the default capability.
    #[serde(default)]
    pub tools: Vec<ToolGrantConfig>,

    /// Resource grants to include in the default capability.
    #[serde(default)]
    pub resources: Vec<ResourceGrantConfig>,

    /// Prompt grants to include in the default capability.
    #[serde(default)]
    pub prompts: Vec<PromptGrantConfig>,
}

/// A tool grant specified in the policy YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolGrantConfig {
    /// Server pattern (e.g. "*" for any, or "my-server").
    pub server: String,
    /// Tool pattern (e.g. "*" for any, or "read_file").
    pub tool: String,
    /// Operations to grant.
    #[serde(default = "default_operations")]
    pub operations: Vec<String>,
    /// TTL in seconds for this grant.
    #[serde(default = "default_grant_ttl")]
    pub ttl: u64,
}

/// A resource grant specified in the policy YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceGrantConfig {
    /// Resource URI pattern (for example `repo://docs/*`).
    pub uri: String,
    /// Operations to grant.
    #[serde(default = "default_resource_operations")]
    pub operations: Vec<String>,
    /// TTL in seconds for this grant.
    #[serde(default = "default_grant_ttl")]
    pub ttl: u64,
}

/// A prompt grant specified in the policy YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptGrantConfig {
    /// Prompt name pattern.
    pub prompt: String,
    /// Operations to grant.
    #[serde(default = "default_prompt_operations")]
    pub operations: Vec<String>,
    /// TTL in seconds for this grant.
    #[serde(default = "default_grant_ttl")]
    pub ttl: u64,
}

fn default_true() -> bool {
    true
}

fn default_operations() -> Vec<String> {
    vec!["invoke".to_string()]
}

fn default_grant_ttl() -> u64 {
    300
}

fn default_resource_operations() -> Vec<String> {
    vec!["read".to_string()]
}

fn default_prompt_operations() -> Vec<String> {
    vec!["get".to_string()]
}

fn default_forbidden_path_patterns() -> Vec<String> {
    vec![
        "**/.ssh/**",
        "**/id_rsa*",
        "**/id_ed25519*",
        "**/id_ecdsa*",
        "**/.aws/**",
        "**/.env",
        "**/.env.*",
        "**/.git-credentials",
        "**/.gitconfig",
        "**/.gnupg/**",
        "**/.kube/**",
        "**/.docker/**",
        "**/.npmrc",
        "**/.password-store/**",
        "**/pass/**",
        "**/.1password/**",
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

fn default_patch_max_additions() -> usize {
    1000
}

fn default_patch_max_deletions() -> usize {
    500
}

fn default_patch_forbidden_patterns() -> Vec<String> {
    vec![
        r"(?i)disable[ _\-]?(security|auth|ssl|tls)".to_string(),
        r"(?i)skip[ _\-]?(verify|validation|check)".to_string(),
        r"(?i)rm\s+-rf\s+/".to_string(),
        r"(?i)chmod\s+777".to_string(),
        r"(?i)eval\s*\(".to_string(),
        r"(?i)exec\s*\(".to_string(),
        r"(?i)reverse[_\-]?shell".to_string(),
        r"(?i)bind[_\-]?shell".to_string(),
        r"base64[_\-]?decode.*exec".to_string(),
    ]
}

fn default_patch_max_imbalance_ratio() -> f64 {
    10.0
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
    let compiled = chio_policy::compile_policy_with_source(&spec, Some(path))?;
    let kernel = KernelPolicyConfig::default();
    let default_capabilities =
        build_default_capabilities_from_scope(&compiled.default_scope, kernel.max_capability_ttl);
    let issuance_policy = materialize_reputation_issuance_policy(&spec)?;
    let runtime_assurance_policy = materialize_runtime_assurance_policy(&spec)?;
    let runtime_hash =
        runtime_hash_for_hushspec(&kernel, &default_capabilities, &spec, &auxiliary_assets)?;

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

fn materialize_reputation_issuance_policy(
    spec: &chio_policy::HushSpec,
) -> Result<Option<ReputationIssuancePolicy>, PolicyError> {
    let Some(reputation) = spec
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.reputation.as_ref())
    else {
        return Ok(None);
    };

    let mut scoring = LocalReputationConfig::default();
    let mut probationary_receipt_count = 1_000;
    let mut probationary_min_days = 30;
    let mut probationary_score_ceiling = 0.60;

    if let Some(config) = &reputation.scoring {
        if let Some(weights) = &config.weights {
            scoring.weights = LocalReputationWeights {
                boundary_pressure: weights
                    .boundary_pressure
                    .unwrap_or(scoring.weights.boundary_pressure),
                resource_stewardship: weights
                    .resource_stewardship
                    .unwrap_or(scoring.weights.resource_stewardship),
                least_privilege: weights
                    .least_privilege
                    .unwrap_or(scoring.weights.least_privilege),
                history_depth: weights
                    .history_depth
                    .unwrap_or(scoring.weights.history_depth),
                tool_diversity: weights
                    .tool_diversity
                    .unwrap_or(scoring.weights.tool_diversity),
                delegation_hygiene: weights
                    .delegation_hygiene
                    .unwrap_or(scoring.weights.delegation_hygiene),
                reliability: weights.reliability.unwrap_or(scoring.weights.reliability),
                incident_correlation: weights
                    .incident_correlation
                    .unwrap_or(scoring.weights.incident_correlation),
            };
        }
        scoring.temporal_decay_half_life_days = config
            .temporal_decay_half_life_days
            .unwrap_or(scoring.temporal_decay_half_life_days);
        probationary_receipt_count = config
            .probationary_receipt_count
            .unwrap_or(probationary_receipt_count);
        probationary_min_days = config
            .probationary_min_days
            .unwrap_or(probationary_min_days);
        probationary_score_ceiling = config
            .probationary_score_ceiling
            .unwrap_or(probationary_score_ceiling);
        scoring.history_receipt_target = probationary_receipt_count;
        scoring.history_day_target = probationary_min_days;
    }

    let mut tiers = reputation
        .tiers
        .iter()
        .map(|(name, tier)| {
            Ok(ReputationTierPolicy {
                name: name.clone(),
                score_range: tier.score_range,
                max_scope: TierScopeCeiling {
                    operations: parse_operations(&tier.max_scope.operations)?,
                    max_invocations: tier.max_scope.max_invocations,
                    max_cost_per_invocation: tier.max_scope.max_cost_per_invocation.clone(),
                    max_total_cost: tier.max_scope.max_total_cost.clone(),
                    max_delegation_depth: tier.max_scope.max_delegation_depth,
                    ttl_seconds: tier.max_scope.ttl_seconds,
                    constraints_required: tier.max_scope.constraints_required.unwrap_or(false),
                },
            })
        })
        .collect::<Result<Vec<_>, PolicyError>>()?;
    tiers.sort_by(|left, right| {
        left.score_range[0]
            .partial_cmp(&right.score_range[0])
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                left.score_range[1]
                    .partial_cmp(&right.score_range[1])
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| left.name.cmp(&right.name))
    });

    Ok(Some(ReputationIssuancePolicy {
        scoring,
        probationary_receipt_count,
        probationary_min_days,
        probationary_score_ceiling,
        tiers,
    }))
}

fn materialize_runtime_assurance_policy(
    spec: &chio_policy::HushSpec,
) -> Result<Option<RuntimeAssuranceIssuancePolicy>, PolicyError> {
    let Some(runtime_assurance) = spec
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.runtime_assurance.as_ref())
    else {
        return Ok(None);
    };

    let mut tiers = runtime_assurance
        .tiers
        .iter()
        .map(|(name, tier)| {
            Ok(RuntimeAssuranceTierPolicy {
                name: name.clone(),
                minimum_attestation_tier: tier.minimum_attestation_tier,
                max_scope: TierScopeCeiling {
                    operations: parse_operations(&tier.max_scope.operations)?,
                    max_invocations: tier.max_scope.max_invocations,
                    max_cost_per_invocation: tier.max_scope.max_cost_per_invocation.clone(),
                    max_total_cost: tier.max_scope.max_total_cost.clone(),
                    max_delegation_depth: tier.max_scope.max_delegation_depth,
                    ttl_seconds: tier.max_scope.ttl_seconds,
                    constraints_required: tier.max_scope.constraints_required.unwrap_or(false),
                },
            })
        })
        .collect::<Result<Vec<_>, PolicyError>>()?;
    tiers.sort_by(|left, right| {
        left.minimum_attestation_tier
            .cmp(&right.minimum_attestation_tier)
            .then_with(|| left.name.cmp(&right.name))
    });

    let attestation_trust_policy = if runtime_assurance.trusted_verifiers.is_empty() {
        None
    } else {
        Some(AttestationTrustPolicy {
            rules: runtime_assurance
                .trusted_verifiers
                .iter()
                .map(|(name, rule)| AttestationTrustRule {
                    name: name.clone(),
                    schema: rule.schema.clone(),
                    verifier: rule.verifier.clone(),
                    effective_tier: rule.effective_tier,
                    verifier_family: rule.verifier_family,
                    max_evidence_age_seconds: rule.max_evidence_age_seconds,
                    allowed_attestation_types: rule.allowed_attestation_types.clone(),
                    required_assertions: rule.required_assertions.clone(),
                })
                .collect(),
        })
    };

    Ok(Some(RuntimeAssuranceIssuancePolicy {
        tiers,
        attestation_trust_policy,
    }))
}

/// Parse a policy from a YAML string.
pub fn parse_policy(yaml: &str) -> Result<ChioPolicy, PolicyError> {
    let policy: ChioPolicy = serde_yml::from_str(yaml)?;
    Ok(policy)
}

/// Build a `GuardPipeline` from a policy's guard configuration.
pub fn build_guard_pipeline(config: &GuardPolicyConfig) -> Result<GuardPipeline, PolicyError> {
    let mut pipeline = GuardPipeline::new();

    if let Some(fp) = &config.forbidden_path {
        if fp.enabled {
            if fp.patterns.is_none()
                && fp.additional_patterns.is_empty()
                && fp.exceptions.is_empty()
            {
                pipeline.add(Box::new(ForbiddenPathGuard::new()));
            } else {
                let mut patterns = fp
                    .patterns
                    .clone()
                    .unwrap_or_else(default_forbidden_path_patterns);
                patterns.extend(fp.additional_patterns.clone());
                pipeline.add(Box::new(
                    ForbiddenPathGuard::with_patterns(patterns, fp.exceptions.clone())
                        .map_err(|error| PolicyError::Invalid(error.to_string()))?,
                ));
            }
        }
    }

    if let Some(pa) = &config.path_allowlist {
        if pa.enabled {
            pipeline.add(Box::new(PathAllowlistGuard::with_config(
                chio_guards::path_allowlist::PathAllowlistConfig {
                    enabled: true,
                    file_access_allow: pa.read.clone(),
                    file_write_allow: pa.write.clone(),
                    patch_allow: pa.patch.clone(),
                },
            )));
        }
    }

    if let Some(sc) = &config.shell_command {
        if sc.enabled {
            if sc.forbidden_patterns.is_empty() {
                pipeline.add(Box::new(ShellCommandGuard::new()));
            } else {
                pipeline.add(Box::new(
                    ShellCommandGuard::try_with_patterns(sc.forbidden_patterns.clone(), true)
                        .map_err(|error| PolicyError::Invalid(error.to_string()))?,
                ));
            }
        }
    }

    if let Some(eg) = &config.egress_allowlist {
        if eg.enabled {
            if eg.allowed_domains.is_empty() && eg.blocked_domains.is_empty() {
                pipeline.add(Box::new(EgressAllowlistGuard::new()));
            } else {
                pipeline.add(Box::new(
                    EgressAllowlistGuard::with_lists(
                        eg.allowed_domains.clone(),
                        eg.blocked_domains.clone(),
                    )
                    .map_err(|error| PolicyError::Invalid(error.to_string()))?,
                ));
            }
        }
    }

    if let Some(internal_network) = &config.internal_network {
        if internal_network.enabled {
            pipeline.add(Box::new(InternalNetworkGuard::with_config(
                internal_network.extra_blocked_hosts.clone(),
                internal_network.dns_rebinding_detection,
            )));
        }
    }

    if let Some(tool_access) = &config.tool_access {
        if tool_access.enabled {
            let default_action = match tool_access.default_action {
                ToolAccessDefaultAction::Allow => chio_guards::mcp_tool::McpDefaultAction::Allow,
                ToolAccessDefaultAction::Block => chio_guards::mcp_tool::McpDefaultAction::Block,
            };
            pipeline.add(Box::new(McpToolGuard::with_config(
                chio_guards::mcp_tool::McpToolConfig {
                    enabled: true,
                    allow: tool_access.allow.clone(),
                    block: tool_access.block.clone(),
                    default_action,
                    max_args_size: tool_access.max_args_size,
                },
            )));
        }
    }

    if let Some(secret_patterns) = &config.secret_patterns {
        if secret_patterns.enabled {
            let guard = SecretLeakGuard::with_config(chio_guards::secret_leak::SecretLeakConfig {
                enabled: true,
                skip_paths: secret_patterns.skip_paths.clone(),
                custom_patterns: Vec::new(),
            })
            .map_err(|error| PolicyError::Invalid(error.to_string()))?;
            pipeline.add(Box::new(guard));
        }
    }

    if let Some(patch_integrity) = &config.patch_integrity {
        if patch_integrity.enabled {
            pipeline.add(Box::new(
                PatchIntegrityGuard::with_config(
                    chio_guards::patch_integrity::PatchIntegrityConfig {
                        enabled: true,
                        max_additions: patch_integrity.max_additions,
                        max_deletions: patch_integrity.max_deletions,
                        forbidden_patterns: patch_integrity.forbidden_patterns.clone(),
                        require_balance: patch_integrity.require_balance,
                        max_imbalance_ratio: patch_integrity.max_imbalance_ratio,
                    },
                )
                .map_err(|error| PolicyError::Invalid(error.to_string()))?,
            ));
        }
    }

    if let Some(sql_query) = &config.sql_query {
        pipeline.add(Box::new(
            SqlQueryGuard::try_new(sql_query.clone()).map_err(PolicyError::Invalid)?,
        ));
    }

    if let Some(vector_db) = &config.vector_db {
        pipeline.add(Box::new(VectorDbGuard::new(vector_db.clone())));
    }

    if let Some(warehouse_cost) = &config.warehouse_cost {
        pipeline.add(Box::new(WarehouseCostGuard::new(warehouse_cost.clone())));
    }

    if let Some(content_review) = &config.content_review {
        pipeline.add(Box::new(
            ContentReviewGuard::with_config(content_review.clone())
                .map_err(|error| PolicyError::Invalid(error.to_string()))?,
        ));
    }

    if let Some(cloud_guardrails) = &config.cloud_guardrails {
        if let Some(azure) = &cloud_guardrails.azure_content_safety {
            if azure.enabled {
                pipeline.add(Box::new(build_azure_content_safety_guard(azure)?));
            }
        }
    }

    if let Some(threat_intel) = &config.threat_intel {
        if let Some(safe_browsing) = &threat_intel.safe_browsing {
            if safe_browsing.enabled {
                pipeline.add(Box::new(build_safe_browsing_guard(safe_browsing)?));
            }
        }
    }

    Ok(pipeline)
}

fn build_azure_content_safety_guard(
    config: &AzureContentSafetyPolicyConfig,
) -> Result<ScopedAsyncGuard<AzureContentSafetyGuard>, PolicyError> {
    validate_required_secret(
        "cloud_guardrails.azure_content_safety.api_key",
        &config.api_key,
    )?;
    validate_https_url(
        "cloud_guardrails.azure_content_safety.endpoint",
        &config.endpoint,
    )?;

    let mut guard_config =
        AzureContentSafetyConfig::new(config.api_key.clone(), config.endpoint.clone());
    if let Some(api_version) = &config.api_version {
        if api_version.trim().is_empty() {
            return Err(PolicyError::Invalid(
                "cloud_guardrails.azure_content_safety.api_version cannot be empty".to_string(),
            ));
        }
        guard_config.api_version = api_version.clone();
    }
    if let Some(timeout_seconds) = config.timeout_seconds {
        if timeout_seconds == 0 {
            return Err(PolicyError::Invalid(
                "cloud_guardrails.azure_content_safety.timeout_seconds must be greater than 0"
                    .to_string(),
            ));
        }
        guard_config.timeout = Duration::from_secs(timeout_seconds);
    }
    if let Some(severity_threshold) = config.severity_threshold {
        if severity_threshold > 7 {
            return Err(PolicyError::Invalid(
                "cloud_guardrails.azure_content_safety.severity_threshold must be between 0 and 7"
                    .to_string(),
            ));
        }
        guard_config.severity_threshold = severity_threshold;
    }
    if !config.categories.is_empty() {
        guard_config.categories = config
            .categories
            .iter()
            .map(|category| parse_azure_category(category))
            .collect::<Result<Vec<_>, _>>()?;
    }

    let guard = AzureContentSafetyGuard::new(guard_config)
        .map_err(|error| PolicyError::Invalid(error.to_string()))?;
    let adapter = configure_async_guard_adapter(
        AsyncGuardAdapter::builder(Arc::new(guard)),
        &config.adapter,
        "cloud_guardrails.azure_content_safety.adapter",
    )?;
    Ok(ScopedAsyncGuard::new(adapter, config.tool_patterns.clone()))
}

const SAFE_BROWSING_DEFAULT_BASE_URL: &str = "https://safebrowsing.googleapis.com/v4";

fn build_safe_browsing_guard(
    config: &SafeBrowsingPolicyConfig,
) -> Result<ScopedAsyncGuard<SafeBrowsingGuard>, PolicyError> {
    validate_required_secret("threat_intel.safe_browsing.api_key", &config.api_key)?;
    let mut guard_config = SafeBrowsingConfig::new(config.api_key.clone());
    let base_url = if let Some(base_url) = config.base_url.as_deref() {
        validate_https_url("threat_intel.safe_browsing.base_url", base_url)?;
        base_url.to_string()
    } else {
        chio_external_guards::validate_external_guard_url_without_dns(
            "threat_intel.safe_browsing.base_url",
            SAFE_BROWSING_DEFAULT_BASE_URL,
        )
        .map_err(|error| PolicyError::Invalid(error.to_string()))?;
        SAFE_BROWSING_DEFAULT_BASE_URL.to_string()
    };
    guard_config.base_url = Some(base_url);
    if let Some(client_id) = &config.client_id {
        if client_id.trim().is_empty() {
            return Err(PolicyError::Invalid(
                "threat_intel.safe_browsing.client_id cannot be empty".to_string(),
            ));
        }
        guard_config.client_id = client_id.clone();
    }
    if let Some(client_version) = &config.client_version {
        if client_version.trim().is_empty() {
            return Err(PolicyError::Invalid(
                "threat_intel.safe_browsing.client_version cannot be empty".to_string(),
            ));
        }
        guard_config.client_version = client_version.clone();
    }
    if !config.threat_types.is_empty() {
        if config
            .threat_types
            .iter()
            .any(|threat_type| threat_type.trim().is_empty())
        {
            return Err(PolicyError::Invalid(
                "threat_intel.safe_browsing.threat_types cannot contain empty values".to_string(),
            ));
        }
        guard_config.threat_types = config.threat_types.clone();
    }
    if let Some(timeout_seconds) = config.timeout_seconds {
        if timeout_seconds == 0 {
            return Err(PolicyError::Invalid(
                "threat_intel.safe_browsing.timeout_seconds must be greater than 0".to_string(),
            ));
        }
        guard_config.timeout = Duration::from_secs(timeout_seconds);
    }

    let guard = SafeBrowsingGuard::new(guard_config)
        .map_err(|error| PolicyError::Invalid(error.to_string()))?;
    let adapter = configure_async_guard_adapter(
        AsyncGuardAdapter::builder(Arc::new(guard)),
        &config.adapter,
        "threat_intel.safe_browsing.adapter",
    )?;
    Ok(ScopedAsyncGuard::new(adapter, config.tool_patterns.clone()))
}

fn configure_async_guard_adapter<E>(
    builder: chio_external_guards::AsyncGuardAdapterBuilder<E>,
    config: &ExternalAdapterPolicyConfig,
    field_prefix: &str,
) -> Result<AsyncGuardAdapter<E>, PolicyError>
where
    E: chio_external_guards::ExternalGuard,
{
    if !config.rate_per_second.is_finite() || config.rate_per_second <= 0.0 {
        return Err(PolicyError::Invalid(format!(
            "{field_prefix}.rate_per_second must be greater than 0"
        )));
    }
    if config.rate_burst == 0 {
        return Err(PolicyError::Invalid(format!(
            "{field_prefix}.rate_burst must be greater than 0"
        )));
    }
    if config.cache_ttl_seconds == 0 {
        return Err(PolicyError::Invalid(format!(
            "{field_prefix}.cache_ttl_seconds must be greater than 0"
        )));
    }
    if config.circuit_failure_threshold == 0 {
        return Err(PolicyError::Invalid(format!(
            "{field_prefix}.circuit_failure_threshold must be greater than 0"
        )));
    }

    let circuit = CircuitBreakerConfig {
        failure_threshold: config.circuit_failure_threshold,
        ..CircuitBreakerConfig::default()
    };

    let retry = RetryConfig {
        max_retries: config.retry_max_retries,
        strategy: BackoffStrategy::Exponential,
        ..RetryConfig::default()
    };

    Ok(builder
        .circuit(circuit)
        .retry(retry)
        .cache_ttl(Duration::from_secs(config.cache_ttl_seconds))
        .rate_limit(config.rate_per_second, config.rate_burst)
        .build())
}

fn validate_required_secret(field: &str, value: &str) -> Result<(), PolicyError> {
    if value.trim().is_empty() {
        return Err(PolicyError::Invalid(format!("{field} cannot be empty")));
    }
    Ok(())
}

fn validate_https_url(field: &str, value: &str) -> Result<(), PolicyError> {
    chio_external_guards::validate_external_guard_url(field, value)
        .map_err(|error| PolicyError::Invalid(error.to_string()))
}

fn parse_azure_category(category: &str) -> Result<AzureCategory, PolicyError> {
    match category.trim().to_ascii_lowercase().as_str() {
        "hate" => Ok(AzureCategory::Hate),
        "self_harm" | "selfharm" => Ok(AzureCategory::SelfHarm),
        "sexual" => Ok(AzureCategory::Sexual),
        "violence" => Ok(AzureCategory::Violence),
        _ => Err(PolicyError::Invalid(format!(
            "unsupported azure content safety category: {category}"
        ))),
    }
}

/// Build a `PostInvocationPipeline` from a policy's guard configuration.
pub fn build_post_invocation_pipeline(
    config: &GuardPolicyConfig,
) -> Result<PostInvocationPipeline, PolicyError> {
    let mut pipeline = PostInvocationPipeline::new();

    if let Some(query_result) = &config.query_result {
        let guard = QueryResultGuard::new(query_result.clone()).map_err(PolicyError::Invalid)?;
        pipeline.add(Box::new(guard.into_owned_hook(ChioScope::default())));
    }

    if let Some(secret_patterns) = &config.secret_patterns {
        if secret_patterns.enabled {
            pipeline.add(Box::new(SanitizerHook::new()));
        }
    }

    Ok(pipeline)
}

/// Convert policy tool grant configs into one or more capabilities grouped by TTL.
pub fn build_runtime_default_capabilities(
    policy: &ChioPolicy,
) -> Result<Vec<DefaultCapability>, PolicyError> {
    let mut grants_by_ttl =
        build_default_capability_map(&policy.capabilities, policy.kernel.max_capability_ttl)?;

    let has_explicit_tool_caps = policy
        .capabilities
        .default
        .as_ref()
        .is_some_and(|default| !default.tools.is_empty());
    if !has_explicit_tool_caps {
        if let Some(scope) = synthesize_tool_access_scope(&policy.guards)? {
            grants_by_ttl
                .entry(policy.kernel.max_capability_ttl)
                .or_default()
                .grants
                .extend(scope.grants);
        }
    }

    Ok(default_capability_map_into_vec(grants_by_ttl))
}

/// Convert policy tool grant configs into one or more capabilities grouped by TTL.
pub fn build_default_capabilities(
    config: &CapabilityPolicyConfig,
    max_capability_ttl: u64,
) -> Result<Vec<DefaultCapability>, PolicyError> {
    Ok(default_capability_map_into_vec(
        build_default_capability_map(config, max_capability_ttl)?,
    ))
}

fn build_default_capability_map(
    config: &CapabilityPolicyConfig,
    max_capability_ttl: u64,
) -> Result<BTreeMap<u64, ChioScope>, PolicyError> {
    let default = match &config.default {
        Some(default) => default,
        None => return Ok(BTreeMap::new()),
    };

    let mut grants_by_ttl: BTreeMap<u64, ChioScope> = BTreeMap::new();

    for grant_config in &default.tools {
        if grant_config.ttl > max_capability_ttl {
            return Err(PolicyError::Invalid(format!(
                "default capability TTL {} exceeds kernel max_capability_ttl {}",
                grant_config.ttl, max_capability_ttl
            )));
        }

        let operations = parse_operations(&grant_config.operations)?;

        grants_by_ttl
            .entry(grant_config.ttl)
            .or_default()
            .grants
            .push(ToolGrant {
                server_id: grant_config.server.clone(),
                tool_name: grant_config.tool.clone(),
                operations,
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            });
    }

    for grant_config in &default.resources {
        if grant_config.ttl > max_capability_ttl {
            return Err(PolicyError::Invalid(format!(
                "default capability TTL {} exceeds kernel max_capability_ttl {}",
                grant_config.ttl, max_capability_ttl
            )));
        }

        let operations = parse_operations(&grant_config.operations)?;

        grants_by_ttl
            .entry(grant_config.ttl)
            .or_default()
            .resource_grants
            .push(ResourceGrant {
                uri_pattern: grant_config.uri.clone(),
                operations,
            });
    }

    for grant_config in &default.prompts {
        if grant_config.ttl > max_capability_ttl {
            return Err(PolicyError::Invalid(format!(
                "default capability TTL {} exceeds kernel max_capability_ttl {}",
                grant_config.ttl, max_capability_ttl
            )));
        }

        let operations = parse_operations(&grant_config.operations)?;

        grants_by_ttl
            .entry(grant_config.ttl)
            .or_default()
            .prompt_grants
            .push(PromptGrant {
                prompt_name: grant_config.prompt.clone(),
                operations,
            });
    }

    Ok(grants_by_ttl)
}

fn default_capability_map_into_vec(
    grants_by_ttl: BTreeMap<u64, ChioScope>,
) -> Vec<DefaultCapability> {
    grants_by_ttl
        .into_iter()
        .filter(|(_, scope)| {
            !scope.grants.is_empty()
                || !scope.resource_grants.is_empty()
                || !scope.prompt_grants.is_empty()
        })
        .map(|(ttl, scope)| DefaultCapability { scope, ttl })
        .collect()
}

fn build_default_capabilities_from_scope(scope: &ChioScope, ttl: u64) -> Vec<DefaultCapability> {
    if scope.grants.is_empty() && scope.resource_grants.is_empty() && scope.prompt_grants.is_empty()
    {
        Vec::new()
    } else {
        vec![DefaultCapability {
            scope: scope.clone(),
            ttl,
        }]
    }
}

fn synthesize_tool_access_scope(
    config: &GuardPolicyConfig,
) -> Result<Option<ChioScope>, PolicyError> {
    let Some(tool_access) = config.tool_access.as_ref() else {
        return Ok(None);
    };
    if !tool_access.enabled {
        return Ok(None);
    }

    if tool_access.allow.is_empty() && tool_access.default_action == ToolAccessDefaultAction::Block
    {
        return Ok(None);
    }

    if tool_access.allow.is_empty() && tool_access.default_action == ToolAccessDefaultAction::Allow
    {
        if !tool_access.require_confirmation.is_empty()
            && !tool_access
                .require_confirmation
                .iter()
                .any(|pattern| pattern == "*")
        {
            return Err(PolicyError::Invalid(
                "guards.tool_access.require_confirmation with default_action=allow requires either explicit allow entries or a wildcard '*' confirmation pattern".to_string(),
            ));
        }
        return Ok(Some(ChioScope {
            grants: vec![ToolGrant {
                server_id: "*".to_string(),
                tool_name: "*".to_string(),
                operations: vec![Operation::Invoke],
                constraints: compile_wildcard_tool_constraints(tool_access),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        }));
    }

    for allow_pattern in &tool_access.allow {
        if tool_pattern_has_wildcard(allow_pattern)
            && confirmation_overlap(allow_pattern, &tool_access.require_confirmation)?
            && !tool_access
                .require_confirmation
                .iter()
                .any(|pattern| pattern == "*" || pattern == allow_pattern)
        {
            return Err(PolicyError::Invalid(format!(
                "guards.tool_access.require_confirmation cannot narrow wildcard allow pattern '{allow_pattern}'; use an exact matching confirmation pattern or '*'"
            )));
        }
    }

    let mut grants = Vec::with_capacity(tool_access.allow.len());
    for tool_name in &tool_access.allow {
        grants.push(ToolGrant {
            server_id: "*".to_string(),
            tool_name: tool_name.clone(),
            operations: vec![Operation::Invoke],
            constraints: compile_tool_constraints(tool_access, tool_name)?,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        });
    }

    Ok(Some(ChioScope {
        grants,
        ..ChioScope::default()
    }))
}

fn compile_wildcard_tool_constraints(
    tool_access: &ToolAccessConfig,
) -> Vec<chio_core::capability::Constraint> {
    let mut constraints = Vec::new();
    if let Some(max_args_size) = tool_access.max_args_size {
        constraints.push(chio_core::capability::Constraint::MaxArgsSize(
            max_args_size,
        ));
    }
    if tool_access
        .require_confirmation
        .iter()
        .any(|pattern| pattern == "*")
    {
        constraints
            .push(chio_core::capability::Constraint::RequireApprovalAbove { threshold_units: 0 });
    }
    constraints
}

fn tool_pattern_has_wildcard(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?')
}

const MAX_TOOL_ACCESS_GLOB_PATTERN_BYTES: usize = 512;
const MAX_TOOL_ACCESS_GLOB_OVERLAP_STATES: usize = 16_384;

fn compile_tool_constraints(
    tool_access: &ToolAccessConfig,
    tool_pattern: &str,
) -> Result<Vec<chio_core::capability::Constraint>, PolicyError> {
    let mut constraints = Vec::new();
    if let Some(max_args_size) = tool_access.max_args_size {
        constraints.push(chio_core::capability::Constraint::MaxArgsSize(
            max_args_size,
        ));
    }
    if confirmation_overlap(tool_pattern, &tool_access.require_confirmation)? {
        constraints
            .push(chio_core::capability::Constraint::RequireApprovalAbove { threshold_units: 0 });
    }
    Ok(constraints)
}

fn confirmation_overlap(
    tool_pattern: &str,
    confirmation_patterns: &[String],
) -> Result<bool, PolicyError> {
    for pattern in confirmation_patterns {
        if tool_patterns_overlap(tool_pattern, pattern)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn tool_patterns_overlap(left: &str, right: &str) -> Result<bool, PolicyError> {
    validate_tool_overlap_pattern_len(left, "left")?;
    validate_tool_overlap_pattern_len(right, "right")?;
    validate_tool_overlap_budget(left, right)?;
    if left == "*" || right == "*" {
        return Ok(true);
    }
    // Confirmation constraints are synthesized onto one grant, so a pair of
    // leading unbounded globs must fail closed instead of risking a gap.
    if left.starts_with('*') && right.starts_with('*') {
        return Ok(true);
    }
    let mut memo = HashMap::new();
    Ok(pattern_suffixes_overlap(
        left.as_bytes(),
        0,
        right.as_bytes(),
        0,
        &mut memo,
    ))
}

fn validate_tool_overlap_pattern_len(pattern: &str, side: &str) -> Result<(), PolicyError> {
    if pattern.len() > MAX_TOOL_ACCESS_GLOB_PATTERN_BYTES {
        return Err(PolicyError::Invalid(format!(
            "guards.tool_access {side} glob pattern exceeds {MAX_TOOL_ACCESS_GLOB_PATTERN_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_tool_overlap_budget(left: &str, right: &str) -> Result<(), PolicyError> {
    let state_count = (left.len() + 1).saturating_mul(right.len() + 1);
    if state_count > MAX_TOOL_ACCESS_GLOB_OVERLAP_STATES {
        return Err(PolicyError::Invalid(format!(
            "guards.tool_access glob overlap exceeds {MAX_TOOL_ACCESS_GLOB_OVERLAP_STATES} recursive states"
        )));
    }
    Ok(())
}

fn pattern_suffixes_overlap(
    left: &[u8],
    left_index: usize,
    right: &[u8],
    right_index: usize,
    memo: &mut HashMap<(usize, usize), bool>,
) -> bool {
    if let Some(result) = memo.get(&(left_index, right_index)) {
        return *result;
    }
    let result = if left_index == left.len() {
        pattern_suffix_can_match_empty(right, right_index)
    } else if right_index == right.len() {
        pattern_suffix_can_match_empty(left, left_index)
    } else {
        match (left[left_index], right[right_index]) {
            (b'*', _) => {
                pattern_suffixes_overlap(left, left_index + 1, right, right_index, memo)
                    || pattern_suffixes_overlap(left, left_index, right, right_index + 1, memo)
            }
            (_, b'*') => {
                pattern_suffixes_overlap(left, left_index, right, right_index + 1, memo)
                    || pattern_suffixes_overlap(left, left_index + 1, right, right_index, memo)
            }
            (left_byte, right_byte) => {
                pattern_bytes_compatible(left_byte, right_byte)
                    && pattern_suffixes_overlap(left, left_index + 1, right, right_index + 1, memo)
            }
        }
    };
    memo.insert((left_index, right_index), result);
    result
}

fn pattern_suffix_can_match_empty(pattern: &[u8], index: usize) -> bool {
    pattern[index..].iter().all(|byte| *byte == b'*')
}

fn pattern_bytes_compatible(left: u8, right: u8) -> bool {
    left == right || left == b'?' || right == b'?'
}

fn parse_operations(operations: &[String]) -> Result<Vec<Operation>, PolicyError> {
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

fn runtime_hash_for_chio_yaml(
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

fn runtime_hash_for_hushspec(
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

fn hash_json_value(value: &serde_json::Value) -> Result<String, PolicyError> {
    let encoded = serde_json::to_vec(value)?;
    Ok(hash_bytes(&encoded))
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;
    use std::net::IpAddr;
    use std::path::PathBuf;

    const EXAMPLE_POLICY: &str = r#"
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5

guards:
  forbidden_path:
    enabled: true
    additional_patterns:
      - "/custom/secret/*"
  path_allowlist:
    enabled: true
    read:
      - "/workspace/project/**"
    write:
      - "/workspace/project/**"
  shell_command:
    enabled: true
  egress_allowlist:
    enabled: true
    allowed_domains:
      - "*.github.com"
      - "*.openai.com"
      - "api.anthropic.com"
  internal_network:
    enabled: true

capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
"#;

    const FULL_GUARD_POLICY: &str = r#"
kernel:
  max_capability_ttl: 3600

guards:
  forbidden_path:
    enabled: true
    patterns:
      - "/workspace/secret/**"
    exceptions:
      - "/workspace/secret/allowed.txt"
  path_allowlist:
    enabled: true
    read:
      - "/workspace/**"
    write:
      - "/workspace/**"
    patch:
      - "/workspace/**"
  shell_command:
    enabled: true
    forbidden_patterns:
      - "(?i)rm\\s+-rf\\s+/"
  egress_allowlist:
    enabled: true
    allowed_domains:
      - "*.openai.com"
    blocked_domains:
      - "evil.example"
  internal_network:
    enabled: true
    extra_blocked_hosts:
      - "internal.corp.example.com"
    dns_rebinding_detection: true
  tool_access:
    enabled: true
    default_action: block
    allow:
      - read_file
      - bash
    max_args_size: 2048
  secret_patterns:
    enabled: true
    skip_paths:
      - "**/fixtures/**"
  patch_integrity:
    enabled: true
    max_additions: 200
    max_deletions: 100
    forbidden_patterns:
      - "eval\\("
    require_balance: true
    max_imbalance_ratio: 3.0
"#;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/policies")
            .join(name)
    }

    fn sample_threat_intel_pattern_db(label: &str) -> String {
        format!(
            r#"
[
  {{
    "id": "known-prompt-injection",
    "category": "prompt_injection",
    "stage": "perception",
    "label": "{label}",
    "embedding": [1.0, 0.0, 0.0]
  }}
]
"#
        )
    }

    #[test]
    fn parse_example_policy() {
        let policy = parse_policy(EXAMPLE_POLICY).test_unwrap();
        assert_eq!(policy.kernel.max_capability_ttl, 3600);
        assert_eq!(policy.kernel.delegation_depth_limit, 5);
        assert!(!policy.kernel.allow_sampling);
        assert!(!policy.kernel.allow_sampling_tool_use);
        assert!(!policy.kernel.allow_elicitation);
        assert!(!policy.kernel.require_web3_evidence);
        assert_eq!(
            policy.kernel.checkpoint_batch_size,
            chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE
        );
        assert!(policy.guards.forbidden_path.is_some());
        assert!(policy.guards.path_allowlist.is_some());
        assert!(policy.guards.shell_command.is_some());
        assert!(policy.guards.egress_allowlist.is_some());
        assert!(policy.guards.internal_network.is_some());
    }

    #[test]
    fn parse_policy_web3_evidence_gate_fields() {
        let yaml = r#"
kernel:
  require_web3_evidence: true
  checkpoint_batch_size: 32
"#;

        let policy = parse_policy(yaml).test_unwrap();
        assert!(policy.kernel.require_web3_evidence);
        assert_eq!(policy.kernel.checkpoint_batch_size, 32);
    }

    #[test]
    fn build_pipeline_from_policy() {
        let policy = parse_policy(EXAMPLE_POLICY).test_unwrap();
        let pipeline = build_guard_pipeline(&policy.guards).test_unwrap();
        assert_eq!(pipeline.len(), 5);
    }

    #[test]
    fn parse_full_guard_policy() {
        let policy = parse_policy(FULL_GUARD_POLICY).test_unwrap();
        assert!(policy.guards.forbidden_path.is_some());
        assert!(policy.guards.path_allowlist.is_some());
        assert!(policy.guards.shell_command.is_some());
        assert!(policy.guards.egress_allowlist.is_some());
        assert!(policy.guards.internal_network.is_some());
        assert!(policy.guards.tool_access.is_some());
        assert!(policy.guards.secret_patterns.is_some());
        assert!(policy.guards.patch_integrity.is_some());
    }

    #[test]
    fn build_pipeline_from_full_guard_policy() {
        let policy = parse_policy(FULL_GUARD_POLICY).test_unwrap();
        let pipeline = build_guard_pipeline(&policy.guards).test_unwrap();
        assert_eq!(pipeline.len(), 8);
    }

    #[test]
    fn build_pipeline_rejects_invalid_egress_patterns() {
        let policy = parse_policy(
            r#"
guards:
  egress_allowlist:
    enabled: true
    allowed_domains:
      - "["
"#,
        )
        .test_unwrap();

        let error = match build_guard_pipeline(&policy.guards) {
            Ok(_) => panic!("invalid egress patterns should fail"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("invalid egress allowlist pattern"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn build_pipeline_rejects_invalid_patch_patterns() {
        let policy = parse_policy(
            r#"
guards:
  patch_integrity:
    enabled: true
    forbidden_patterns:
      - "["
"#,
        )
        .test_unwrap();

        let error = match build_guard_pipeline(&policy.guards) {
            Ok(_) => panic!("invalid patch integrity patterns should fail"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("invalid patch integrity forbidden pattern"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn build_pipeline_rejects_invalid_shell_command_patterns() {
        let policy = parse_policy(
            r#"
guards:
  shell_command:
    enabled: true
    forbidden_patterns:
      - "["
"#,
        )
        .test_unwrap();

        let error = match build_guard_pipeline(&policy.guards) {
            Ok(_) => panic!("invalid shell command patterns should fail"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("invalid shell-command forbidden pattern"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn build_post_invocation_pipeline_from_secret_patterns() {
        let policy = parse_policy(FULL_GUARD_POLICY).test_unwrap();
        let pipeline = build_post_invocation_pipeline(&policy.guards).test_unwrap();
        assert_eq!(pipeline.len(), 1);
    }

    #[test]
    fn build_pipeline_from_data_guard_policy() {
        let policy = parse_policy(
            r#"
guards:
  sql_query:
    operation_allowlist: [select]
    table_allowlist: [orders]
  vector_db:
    collection_allowlist: [memories]
  warehouse_cost:
    max_bytes_scanned: 1000
  query_result:
    redact_pii_patterns:
      - "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
"#,
        )
        .test_unwrap();

        let pipeline = build_guard_pipeline(&policy.guards).test_unwrap();
        let post_invocation = build_post_invocation_pipeline(&policy.guards).test_unwrap();
        assert_eq!(pipeline.len(), 3);
        assert_eq!(post_invocation.len(), 1);
    }

    #[test]
    fn build_pipeline_from_content_review_policy() {
        let policy = parse_policy(
            r#"
guards:
  content_review:
    enabled: true
    default_rules:
      banned_words:
        - "classified"
"#,
        )
        .test_unwrap();

        let pipeline = build_guard_pipeline(&policy.guards).test_unwrap();
        assert_eq!(pipeline.len(), 1);
    }

    #[test]
    fn build_pipeline_from_external_guard_policy() {
        let policy = parse_policy(
            r#"
guards:
  cloud_guardrails:
    azure_content_safety:
      enabled: true
      endpoint: "https://example.cognitiveservices.azure.com"
      api_key: "azure-key"
      tool_patterns: ["slack_*"]
  threat_intel:
    safe_browsing:
      enabled: true
      api_key: "sb-key"
      base_url: "https://safebrowsing.googleapis.com/v4"
      tool_patterns: ["fetch_url"]
"#,
        )
        .test_unwrap();

        let pipeline = build_guard_pipeline(&policy.guards).test_unwrap();
        assert_eq!(pipeline.len(), 2);
    }

    #[test]
    fn build_pipeline_validates_safe_browsing_default_base_url() {
        chio_external_guards::validate_external_guard_url_without_dns(
            "threat_intel.safe_browsing.base_url",
            SAFE_BROWSING_DEFAULT_BASE_URL,
        )
        .test_expect("default safe browsing base URL should pass external guard validation");

        let policy = parse_policy(
            r#"
guards:
  threat_intel:
    safe_browsing:
      enabled: true
      api_key: "sb-key"
"#,
        )
        .test_unwrap();

        let pipeline = build_guard_pipeline(&policy.guards).test_unwrap();
        assert_eq!(pipeline.len(), 1);
    }

    #[test]
    fn build_pipeline_rejects_invalid_external_guard_config() {
        let policy = parse_policy(
            r#"
guards:
  cloud_guardrails:
    azure_content_safety:
      enabled: true
      endpoint: "not-a-url"
      api_key: "azure-key"
  threat_intel:
    safe_browsing:
      enabled: true
      api_key: ""
"#,
        )
        .test_unwrap();

        let error = match build_guard_pipeline(&policy.guards) {
            Ok(_) => panic!("invalid external guard config should fail"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("cloud_guardrails.azure_content_safety.endpoint must be a valid URL"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn build_pipeline_rejects_insecure_external_guard_urls() {
        let policy = parse_policy(
            r#"
guards:
  cloud_guardrails:
    azure_content_safety:
      enabled: true
      endpoint: "http://example.cognitiveservices.azure.com"
      api_key: "azure-key"
  threat_intel:
    safe_browsing:
      enabled: true
      api_key: "sb-key"
      base_url: "http://safebrowsing.googleapis.com/v4"
"#,
        )
        .test_unwrap();

        let error = match build_guard_pipeline(&policy.guards) {
            Ok(_) => panic!("insecure external guard config should fail"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains(
                    "cloud_guardrails.azure_content_safety.endpoint must use https or localhost-only http"
                ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn build_pipeline_allows_localhost_http_external_guard_urls() {
        let policy = parse_policy(
            r#"
guards:
  cloud_guardrails:
    azure_content_safety:
      enabled: true
      endpoint: "http://127.0.0.1:8080"
      api_key: "azure-key"
  threat_intel:
    safe_browsing:
      enabled: true
      api_key: "sb-key"
      base_url: "http://localhost:9000/v4"
"#,
        )
        .test_unwrap();

        build_guard_pipeline(&policy.guards)
            .test_expect("localhost-only http endpoints should remain allowed for local testing");
    }

    #[test]
    fn build_pipeline_rejects_private_network_external_guard_urls_even_over_https() {
        let policy = parse_policy(
            r#"
guards:
  cloud_guardrails:
    azure_content_safety:
      enabled: true
      endpoint: "https://169.254.169.254/content-safety"
      api_key: "azure-key"
  threat_intel:
    safe_browsing:
      enabled: true
      api_key: "sb-key"
      base_url: "https://192.168.1.10/v4"
"#,
        )
        .test_unwrap();

        let error = build_guard_pipeline(&policy.guards)
            .err()
            .test_expect("private-network external guard URLs should fail closed");
        assert!(
            error
                .to_string()
                .contains("must not target localhost, link-local, or private-network hosts"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn external_guard_dns_resolution_rejects_rebound_private_addresses() {
        let error = chio_external_guards::validate_external_guard_url_with_resolver(
            "cloud_guardrails.azure_content_safety.endpoint",
            "https://guard.example.test/moderate",
            |_host, _port| Ok(vec![IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 8))]),
        )
        .test_expect_err("private DNS answers should fail closed");

        assert!(
            error.to_string().contains("resolved to disallowed address"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn external_guard_validation_rejects_ipv4_multicast_addresses() {
        let error = validate_https_url(
            "cloud_guardrails.azure_content_safety.endpoint",
            "https://224.0.0.1/moderate",
        )
        .test_expect_err("IPv4 multicast should fail closed");
        assert!(
            error
                .to_string()
                .contains("must not target localhost, link-local, or private-network hosts"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn external_guard_validation_rejects_ipv4_mapped_ipv6_private_addresses() {
        for endpoint in [
            "https://[::ffff:169.254.169.254]/moderate",
            "https://[::ffff:10.0.0.1]/moderate",
        ] {
            let error =
                validate_https_url("cloud_guardrails.azure_content_safety.endpoint", endpoint)
                    .test_expect_err("IPv4-mapped IPv6 private endpoint should fail closed");
            assert!(
                error
                    .to_string()
                    .contains("must not target localhost, link-local, or private-network hosts"),
                "unexpected error for {endpoint}: {error}"
            );
        }
    }

    #[test]
    fn build_pipeline_rejects_dot_localhost_external_guard_urls() {
        let policy = parse_policy(
            r#"
guards:
  cloud_guardrails:
    azure_content_safety:
      enabled: true
      endpoint: "http://metadata.localhost:8080/moderate"
      api_key: "azure-key"
"#,
        )
        .test_unwrap();

        let error = build_guard_pipeline(&policy.guards)
            .err()
            .test_expect(".localhost endpoints should fail closed");
        assert!(
            error
                .to_string()
                .contains("must use https or localhost-only http")
                || error
                    .to_string()
                    .contains("must not target localhost, link-local, or private-network hosts"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn query_result_policy_pipeline_redacts_wrapped_value_output() {
        let policy = parse_policy(
            r#"
guards:
  query_result:
    redact_pii_patterns:
      - "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
"#,
        )
        .test_unwrap();

        let pipeline = build_post_invocation_pipeline(&policy.guards).test_unwrap();
        let context = chio_guards::post_invocation::PostInvocationContext::synthetic("sql");
        let outcome = pipeline.evaluate_with_context_and_evidence(
            &context,
            &serde_json::json!({
                "kind": "value",
                "value": {
                    "rows": [
                        {"email": "alice@example.com"}
                    ]
                }
            }),
        );

        match outcome.verdict {
            chio_kernel::PostInvocationVerdict::Redact(value) => {
                assert_eq!(value["value"]["rows"][0]["email"], "[REDACTED]");
            }
            other => panic!("expected Redact, got {other:?}"),
        }
    }

    #[test]
    fn build_post_invocation_pipeline_rejects_excessive_redact_pii_patterns() {
        let patterns = (0..65)
            .map(|idx| format!("      - \"pattern-{idx}\"\n"))
            .collect::<String>();
        let policy = parse_policy(&format!(
            "guards:\n  query_result:\n    redact_pii_patterns:\n{patterns}"
        ))
        .test_unwrap();

        let error = build_post_invocation_pipeline(&policy.guards)
            .err()
            .test_expect("excessive PII pattern count should fail closed");
        assert!(
            error.to_string().contains("allows at most 64 patterns"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn build_scope_from_policy() {
        let policy = parse_policy(EXAMPLE_POLICY).test_unwrap();
        let capabilities =
            build_default_capabilities(&policy.capabilities, policy.kernel.max_capability_ttl)
                .test_unwrap();
        assert_eq!(capabilities.len(), 1);
        assert_eq!(capabilities[0].scope.grants.len(), 1);
        assert_eq!(capabilities[0].scope.grants[0].server_id, "*");
        assert_eq!(capabilities[0].scope.grants[0].tool_name, "*");
        assert_eq!(capabilities[0].ttl, 300);
    }

    #[test]
    fn build_scope_with_resources_and_prompts() {
        let yaml = r#"
kernel:
  max_capability_ttl: 3600
capabilities:
  default:
    resources:
      - uri: "repo://docs/*"
        operations: [read]
        ttl: 120
    prompts:
      - prompt: "summarize_*"
        operations: [get]
        ttl: 120
"#;

        let policy = parse_policy(yaml).test_unwrap();
        let capabilities =
            build_default_capabilities(&policy.capabilities, policy.kernel.max_capability_ttl)
                .test_unwrap();

        assert_eq!(capabilities.len(), 1);
        assert!(capabilities[0].scope.grants.is_empty());
        assert_eq!(capabilities[0].scope.resource_grants.len(), 1);
        assert_eq!(capabilities[0].scope.prompt_grants.len(), 1);
        assert_eq!(
            capabilities[0].scope.resource_grants[0].uri_pattern,
            "repo://docs/*"
        );
        assert_eq!(
            capabilities[0].scope.prompt_grants[0].prompt_name,
            "summarize_*"
        );
        assert_eq!(
            capabilities[0].scope.resource_grants[0].operations,
            vec![Operation::Read]
        );
        assert_eq!(
            capabilities[0].scope.prompt_grants[0].operations,
            vec![Operation::Get]
        );
        assert_eq!(capabilities[0].ttl, 120);
    }

    #[test]
    fn yaml_tool_access_synthesizes_default_capabilities() {
        let policy = parse_policy(
            r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - read_file
      - list_directory
"#,
        )
        .test_unwrap();

        let capabilities = build_runtime_default_capabilities(&policy).test_unwrap();
        assert_eq!(capabilities.len(), 1);
        assert_eq!(capabilities[0].ttl, 3600);
        assert_eq!(capabilities[0].scope.grants.len(), 2);
        assert_eq!(capabilities[0].scope.grants[0].tool_name, "read_file");
        assert_eq!(capabilities[0].scope.grants[1].tool_name, "list_directory");
    }

    #[test]
    fn yaml_tool_access_synthesizes_security_constraints() {
        let policy = parse_policy(
            r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - write_file
      - read_file
    max_args_size: 2048
    require_confirmation:
      - write_*
"#,
        )
        .test_unwrap();

        let capabilities = build_runtime_default_capabilities(&policy).test_unwrap();
        assert_eq!(capabilities.len(), 1);
        assert_eq!(
            capabilities[0].scope.grants[0].constraints,
            vec![
                chio_core::capability::Constraint::MaxArgsSize(2048),
                chio_core::capability::Constraint::RequireApprovalAbove { threshold_units: 0 },
            ]
        );
        assert_eq!(
            capabilities[0].scope.grants[1].constraints,
            vec![chio_core::capability::Constraint::MaxArgsSize(2048)]
        );
    }

    #[test]
    fn yaml_tool_access_default_allow_with_scoped_confirmation_is_rejected() {
        let policy = parse_policy(
            r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: allow
    block:
      - shell_exec
    max_args_size: 2048
    require_confirmation:
      - git_push
"#,
        )
        .test_unwrap();

        let error = build_runtime_default_capabilities(&policy).test_expect_err(
            "scoped confirmation cannot be represented by a synthesized wildcard grant",
        );
        assert!(error.to_string().contains(
            "guards.tool_access.require_confirmation with default_action=allow requires either explicit allow entries or a wildcard '*' confirmation pattern"
        ));
    }

    #[test]
    fn yaml_tool_access_default_allow_with_wildcard_confirmation_preserves_wildcard_capability() {
        let policy = parse_policy(
            r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: allow
    block:
      - shell_exec
    max_args_size: 2048
    require_confirmation:
      - "*"
"#,
        )
        .test_unwrap();

        let capabilities = build_runtime_default_capabilities(&policy).test_unwrap();
        assert_eq!(capabilities.len(), 1);
        assert_eq!(capabilities[0].scope.grants.len(), 1);
        assert_eq!(capabilities[0].scope.grants[0].tool_name, "*");
        assert_eq!(
            capabilities[0].scope.grants[0].constraints,
            vec![
                chio_core::capability::Constraint::MaxArgsSize(2048),
                chio_core::capability::Constraint::RequireApprovalAbove { threshold_units: 0 },
            ]
        );
    }

    #[test]
    fn yaml_tool_access_explicit_wildcard_allow_with_scoped_confirmation_is_rejected() {
        let policy = parse_policy(
            r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - "*"
    require_confirmation:
      - git_push
"#,
        )
        .test_unwrap();

        let error = build_runtime_default_capabilities(&policy)
            .test_expect_err("scoped confirmation cannot narrow an explicit wildcard allow grant");
        assert!(error.to_string().contains(
            "guards.tool_access.require_confirmation cannot narrow wildcard allow pattern '*'"
        ));
    }

    #[test]
    fn yaml_tool_access_question_wildcard_allow_with_scoped_confirmation_is_rejected() {
        let policy = parse_policy(
            r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - db_?
    require_confirmation:
      - db_a
"#,
        )
        .test_unwrap();

        let error = build_runtime_default_capabilities(&policy).test_expect_err(
            "scoped confirmation cannot narrow a question-mark wildcard allow grant",
        );
        assert!(error.to_string().contains(
            "guards.tool_access.require_confirmation cannot narrow wildcard allow pattern 'db_?'"
        ));
    }

    #[test]
    fn yaml_tool_access_matching_wildcard_confirmation_preserves_explicit_wildcard_allow() {
        let policy = parse_policy(
            r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - git_*
    require_confirmation:
      - git_*
"#,
        )
        .test_unwrap();

        let capabilities = build_runtime_default_capabilities(&policy).test_unwrap();
        assert_eq!(capabilities.len(), 1);
        assert_eq!(capabilities[0].scope.grants.len(), 1);
        assert_eq!(capabilities[0].scope.grants[0].tool_name, "git_*");
        assert_eq!(
            capabilities[0].scope.grants[0].constraints,
            vec![chio_core::capability::Constraint::RequireApprovalAbove { threshold_units: 0 }]
        );
    }

    #[test]
    fn wildcard_overlap_conservatively_rejects_ambiguous_leading_globs() {
        assert!(!tool_patterns_overlap("read_file", "*_write").test_unwrap());
        assert!(!tool_patterns_overlap("*_write", "git_push").test_unwrap());
        // Leading unbounded globs are intentionally treated as overlapping so
        // capability synthesis fails closed instead of under-confirming.
        assert!(tool_patterns_overlap("*_read", "*_write").test_unwrap());
        assert!(!tool_patterns_overlap("bb*", "?a").test_unwrap());
        assert!(tool_patterns_overlap("read_*", "*_read").test_unwrap());
    }

    #[test]
    fn wildcard_overlap_rejects_oversized_patterns_before_recursing() {
        let oversized = "*".repeat(MAX_TOOL_ACCESS_GLOB_PATTERN_BYTES + 1);
        let error = tool_patterns_overlap(&oversized, "read_file")
            .test_expect_err("oversized overlap pattern should fail policy loading");
        assert!(error.to_string().contains("glob pattern exceeds"));
    }

    #[test]
    fn wildcard_overlap_rejects_excessive_recursive_state_budget() {
        let pattern = "a".repeat(200);
        let error = tool_patterns_overlap(&pattern, &pattern)
            .test_expect_err("large overlap state space should fail policy loading");
        assert!(error.to_string().contains("recursive states"));
    }

    #[test]
    fn yaml_tool_access_rejects_leading_wildcard_confirmation_overlap() {
        let policy = parse_policy(
            r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: block
    allow:
      - "*_read"
    require_confirmation:
      - "*_write"
"#,
        )
        .test_unwrap();

        let error = build_runtime_default_capabilities(&policy)
            .test_expect_err("leading wildcard confirmation overlap is unrepresentable");

        assert!(error
            .to_string()
            .contains("cannot narrow wildcard allow pattern '*_read'"));
    }

    #[test]
    fn explicit_tool_capabilities_skip_tool_access_synthesis() {
        let policy = parse_policy(
            r#"
kernel:
  max_capability_ttl: 3600
guards:
  tool_access:
    enabled: true
    default_action: allow
capabilities:
  default:
    tools:
      - server: "filesystem"
        tool: "read_file"
        ttl: 60
"#,
        )
        .test_unwrap();

        let capabilities = build_runtime_default_capabilities(&policy).test_unwrap();
        assert_eq!(capabilities.len(), 1);
        assert_eq!(capabilities[0].ttl, 60);
        assert_eq!(capabilities[0].scope.grants.len(), 1);
        assert_eq!(capabilities[0].scope.grants[0].tool_name, "read_file");
    }

    #[test]
    fn empty_policy_defaults() {
        let policy = parse_policy("{}").test_unwrap();
        assert_eq!(policy.kernel.max_capability_ttl, 3600);
        assert_eq!(policy.kernel.delegation_depth_limit, 5);
        assert!(!policy.kernel.allow_sampling);
        assert!(!policy.kernel.allow_sampling_tool_use);
        assert!(!policy.kernel.allow_elicitation);
        let pipeline = build_guard_pipeline(&policy.guards).test_unwrap();
        assert_eq!(pipeline.len(), 0);
    }

    #[test]
    fn kernel_nested_flow_flags_parse() {
        let yaml = r#"
kernel:
  allow_sampling: true
  allow_sampling_tool_use: true
  allow_elicitation: true
"#;

        let policy = parse_policy(yaml).test_unwrap();
        assert!(policy.kernel.allow_sampling);
        assert!(policy.kernel.allow_sampling_tool_use);
        assert!(policy.kernel.allow_elicitation);
    }

    #[test]
    fn disabled_guards_not_added() {
        let yaml = r#"
guards:
  forbidden_path:
    enabled: false
  path_allowlist:
    enabled: false
  shell_command:
    enabled: false
  egress_allowlist:
    enabled: false
  internal_network:
    enabled: false
"#;
        let policy = parse_policy(yaml).test_unwrap();
        let pipeline = build_guard_pipeline(&policy.guards).test_unwrap();
        assert_eq!(pipeline.len(), 0);
    }

    #[test]
    fn internal_network_guard_requires_explicit_policy() {
        let without_egress = parse_policy(
            r#"
guards:
  shell_command:
    enabled: true
"#,
        )
        .test_unwrap();
        let without_egress_pipeline = build_guard_pipeline(&without_egress.guards).test_unwrap();
        assert_eq!(without_egress_pipeline.len(), 1);

        let with_egress = parse_policy(
            r#"
guards:
  egress_allowlist:
    enabled: true
    allowed_domains:
      - "*.openai.com"
"#,
        )
        .test_unwrap();
        let with_egress_pipeline = build_guard_pipeline(&with_egress.guards).test_unwrap();
        assert_eq!(with_egress_pipeline.len(), 1);

        let with_internal_network = parse_policy(
            r#"
guards:
  internal_network:
    enabled: true
    extra_blocked_hosts:
      - "internal.corp.example.com"
    dns_rebinding_detection: false
"#,
        )
        .test_unwrap();
        let with_internal_network_pipeline =
            build_guard_pipeline(&with_internal_network.guards).test_unwrap();
        assert_eq!(with_internal_network_pipeline.len(), 1);
    }

    #[test]
    fn policy_path_allowlist_guard_denies_out_of_root_session_tool() {
        use chio_kernel::Guard;

        let yaml = r#"
guards:
  path_allowlist:
    enabled: true
    read:
      - "**"
    write:
      - "**"
"#;
        let policy = parse_policy(yaml).test_unwrap();
        let pipeline = build_guard_pipeline(&policy.guards).test_unwrap();
        assert_eq!(pipeline.len(), 1);

        let kp = chio_core::crypto::Keypair::generate();
        let scope = ChioScope::default();
        let agent_id = kp.public_key().to_hex();
        let server_id = "filesystem".to_string();
        let cap_body = chio_core::capability::CapabilityTokenBody {
            id: "cap-test".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: scope.clone(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
        };
        let cap = chio_core::capability::CapabilityToken::sign(cap_body, &kp).test_unwrap();
        let request = chio_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap,
            tool_name: "filesystem".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({"path": "/etc/passwd"}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        let session_roots = vec!["/workspace/project".to_string()];
        let ctx = chio_kernel::GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: Some(session_roots.as_slice()),
            matched_grant_index: None,
        };

        let result = pipeline.evaluate(&ctx);
        assert!(result.is_err(), "out-of-root filesystem tool should deny");
    }

    #[test]
    fn minimal_capabilities() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "my-server"
        tool: "read_file"
        ttl: 600
"#;
        let policy = parse_policy(yaml).test_unwrap();
        let capabilities =
            build_default_capabilities(&policy.capabilities, policy.kernel.max_capability_ttl)
                .test_unwrap();
        assert_eq!(capabilities.len(), 1);
        assert_eq!(capabilities[0].scope.grants.len(), 1);
        assert_eq!(capabilities[0].scope.grants[0].server_id, "my-server");
        assert_eq!(capabilities[0].scope.grants[0].tool_name, "read_file");
        assert_eq!(capabilities[0].ttl, 600);
    }

    #[test]
    fn splits_default_capabilities_by_ttl() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "filesystem"
        tool: "read_file"
        ttl: 60
      - server: "network"
        tool: "fetch"
        ttl: 3600
      - server: "filesystem"
        tool: "write_file"
        ttl: 60
"#;
        let policy = parse_policy(yaml).test_unwrap();
        let capabilities =
            build_default_capabilities(&policy.capabilities, policy.kernel.max_capability_ttl)
                .test_unwrap();

        assert_eq!(capabilities.len(), 2);
        assert_eq!(capabilities[0].ttl, 60);
        assert_eq!(capabilities[0].scope.grants.len(), 2);
        assert_eq!(capabilities[1].ttl, 3600);
        assert_eq!(capabilities[1].scope.grants.len(), 1);
    }

    #[test]
    fn rejects_ttl_above_kernel_max() {
        let yaml = r#"
kernel:
  max_capability_ttl: 60
capabilities:
  default:
    tools:
      - server: "filesystem"
        tool: "read_file"
        ttl: 300
"#;
        let policy = parse_policy(yaml).test_unwrap();
        let err =
            build_default_capabilities(&policy.capabilities, policy.kernel.max_capability_ttl)
                .test_unwrap_err();
        assert!(err
            .to_string()
            .contains("exceeds kernel max_capability_ttl"));
    }

    #[test]
    fn rejects_unknown_operations() {
        let yaml = r#"
capabilities:
  default:
    tools:
      - server: "filesystem"
        tool: "read_file"
        operations: [invoke, teleport]
        ttl: 60
"#;
        let policy = parse_policy(yaml).test_unwrap();
        let err =
            build_default_capabilities(&policy.capabilities, policy.kernel.max_capability_ttl)
                .test_unwrap_err();
        assert!(err.to_string().contains("unsupported capability operation"));
    }

    #[test]
    fn runtime_hash_ignores_yaml_formatting_noise() {
        let policy_a = parse_policy(
            r#"
kernel:
  max_capability_ttl: 3600
guards:
  shell_command:
    enabled: true
capabilities:
  default:
    tools:
      - server: "*"
        tool: "read_file"
        ttl: 300
"#,
        )
        .test_unwrap();
        let policy_b = parse_policy(
            r#"

kernel: { max_capability_ttl: 3600 }
guards:
  shell_command: { enabled: true }
capabilities:
  default:
    tools:
      - { server: "*", tool: "read_file", ttl: 300 }
"#,
        )
        .test_unwrap();

        let caps_a =
            build_default_capabilities(&policy_a.capabilities, policy_a.kernel.max_capability_ttl)
                .test_unwrap();
        let caps_b =
            build_default_capabilities(&policy_b.capabilities, policy_b.kernel.max_capability_ttl)
                .test_unwrap();

        let hash_a = runtime_hash_for_chio_yaml(&policy_a, &caps_a).test_unwrap();
        let hash_b = runtime_hash_for_chio_yaml(&policy_b, &caps_b).test_unwrap();
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn load_hushspec_policy_materializes_runtime_state() {
        let loaded = load_policy(&fixture_path("hushspec-tool-allow.yaml")).test_unwrap();

        assert_eq!(loaded.format, PolicyFormat::HushSpec);
        assert_eq!(loaded.guard_pipeline.len(), 1);
        assert_eq!(loaded.default_capabilities.len(), 1);
        assert_eq!(
            loaded.default_capabilities[0].ttl,
            default_max_capability_ttl()
        );
        assert_eq!(loaded.default_capabilities[0].scope.grants.len(), 2);
        assert_eq!(
            loaded.default_capabilities[0].scope.grants[0].tool_name,
            "read_file"
        );
        assert_ne!(loaded.identity.source_hash, loaded.identity.runtime_hash);
    }

    #[test]
    fn load_hushspec_policy_identity_tracks_threat_intel_pattern_db_bytes() {
        let policy_dir = std::env::temp_dir().join(format!(
            "chio-hushspec-asset-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .test_unwrap()
                .as_millis()
        ));
        std::fs::create_dir_all(&policy_dir).test_unwrap();
        let pattern_db = policy_dir.join("pattern-db.json");
        let policy_path = policy_dir.join("policy.yaml");

        std::fs::write(&pattern_db, sample_threat_intel_pattern_db("first")).test_unwrap();
        std::fs::write(
            &policy_path,
            r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    default: block
    allow:
      - read_file
extensions:
  detection:
    threat_intel:
      enabled: true
      pattern_db: "pattern-db.json"
"#,
        )
        .test_unwrap();

        let first = load_policy(&policy_path).test_unwrap();
        std::fs::write(&pattern_db, sample_threat_intel_pattern_db("second")).test_unwrap();
        let second = load_policy(&policy_path).test_unwrap();

        assert_ne!(first.identity.source_hash, second.identity.source_hash);
        assert_ne!(first.identity.runtime_hash, second.identity.runtime_hash);

        let _ = std::fs::remove_dir_all(policy_dir);
    }

    #[test]
    fn load_hushspec_block_all_issues_no_default_capabilities() {
        let loaded = load_policy(&fixture_path("hushspec-block-all.yaml")).test_unwrap();
        assert_eq!(loaded.format, PolicyFormat::HushSpec);
        assert!(loaded.default_capabilities.is_empty());
        assert_eq!(loaded.guard_pipeline.len(), 1);
    }

    #[test]
    fn load_hushspec_resolves_extends_before_compiling() {
        let loaded = load_policy(&fixture_path("hushspec-extended.yaml")).test_unwrap();

        assert_eq!(loaded.format, PolicyFormat::HushSpec);
        assert_eq!(loaded.guard_pipeline.len(), 2);
        assert_eq!(loaded.default_capabilities.len(), 1);
        assert_eq!(loaded.default_capabilities[0].scope.grants.len(), 2);
        assert_eq!(
            loaded.default_capabilities[0].scope.grants[1].tool_name,
            "list_directory"
        );
    }

    #[test]
    fn load_hushspec_materializes_reputation_issuance_policy() {
        let loaded = load_policy(&fixture_path("hushspec-reputation.yaml")).test_unwrap();

        let issuance_policy = loaded
            .issuance_policy
            .test_expect("reputation issuance policy should materialize");
        assert_eq!(issuance_policy.probationary_receipt_count, 1000);
        assert_eq!(issuance_policy.probationary_min_days, 30);
        assert_eq!(issuance_policy.probationary_score_ceiling, 0.60);
        assert_eq!(issuance_policy.tiers.len(), 4);
        assert_eq!(issuance_policy.tiers[0].name, "probationary");
        assert_eq!(
            issuance_policy.tiers[0].max_scope.max_total_cost,
            Some(MonetaryAmount {
                units: 1_000,
                currency: "USD".to_string(),
            })
        );
        assert_eq!(
            issuance_policy
                .tiers
                .last()
                .test_expect("elevated tier")
                .max_scope
                .operations,
            vec![
                Operation::Read,
                Operation::Get,
                Operation::Invoke,
                Operation::ReadResult,
                Operation::Delegate,
                Operation::Subscribe,
            ]
        );
    }

    #[test]
    fn chio_yaml_guard_surface_matches_hushspec_fixture() {
        let chio_policy = parse_policy(FULL_GUARD_POLICY).test_unwrap();
        let chio_pipeline = build_guard_pipeline(&chio_policy.guards).test_unwrap();
        let chio_post_invocation =
            build_post_invocation_pipeline(&chio_policy.guards).test_unwrap();
        let chio_capabilities = build_runtime_default_capabilities(&chio_policy).test_unwrap();

        let hushspec = load_policy(&fixture_path("hushspec-guard-heavy.yaml")).test_unwrap();

        assert_eq!(chio_pipeline.len(), hushspec.guard_pipeline.len());
        assert_eq!(
            chio_post_invocation.len(),
            hushspec.post_invocation_pipeline.len()
        );
        assert_eq!(chio_capabilities.len(), hushspec.default_capabilities.len());
        assert_eq!(
            chio_capabilities[0].ttl,
            hushspec.default_capabilities[0].ttl
        );
        assert_eq!(
            serde_json::to_value(&chio_capabilities[0].scope.grants).test_unwrap(),
            serde_json::to_value(&hushspec.default_capabilities[0].scope.grants).test_unwrap()
        );
    }

    #[test]
    fn hushspec_materializes_runtime_assurance_policy() {
        let spec = chio_policy::HushSpec::parse(
            r#"
hushspec: "0.1.0"
name: runtime-assurance
rules:
  tool_access:
    enabled: true
    allow: ["payments.charge"]
extensions:
  runtime_assurance:
    tiers:
      baseline:
        minimum_attestation_tier: none
        max_scope:
          operations: ["invoke"]
          max_invocations: 5
          max_cost_per_invocation:
            units: 50
            currency: USD
          max_total_cost:
            units: 100
            currency: USD
          max_delegation_depth: 0
          ttl_seconds: 30
      attested:
        minimum_attestation_tier: attested
        max_scope:
          operations: ["invoke", "read_result"]
          max_invocations: 20
          max_cost_per_invocation:
            units: 250
            currency: USD
          max_total_cost:
            units: 1000
            currency: USD
          max_delegation_depth: 0
          ttl_seconds: 300
    trusted_verifiers:
      azure_contoso:
        schema: chio.runtime-attestation.azure-maa.jwt.v1
        verifier: https://maa.contoso.test/
        effective_tier: verified
        verifier_family: azure_maa
        max_evidence_age_seconds: 120
        allowed_attestation_types: [sgx]
        required_assertions:
          attestationType: sgx
"#,
        )
        .test_unwrap();

        let runtime_assurance_policy = materialize_runtime_assurance_policy(&spec)
            .test_unwrap()
            .test_expect("runtime assurance policy should materialize");
        assert_eq!(runtime_assurance_policy.tiers.len(), 2);
        assert_eq!(runtime_assurance_policy.tiers[0].name, "baseline");
        assert_eq!(
            runtime_assurance_policy.tiers[1].minimum_attestation_tier,
            RuntimeAssuranceTier::Attested
        );
        assert_eq!(
            runtime_assurance_policy.tiers[1].max_scope.max_total_cost,
            Some(MonetaryAmount {
                units: 1_000,
                currency: "USD".to_string(),
            })
        );
        let trust_policy = runtime_assurance_policy
            .attestation_trust_policy
            .test_expect("trusted verifier policy should materialize");
        assert_eq!(trust_policy.rules.len(), 1);
        assert_eq!(trust_policy.rules[0].name, "azure_contoso");
        assert_eq!(
            trust_policy.rules[0].effective_tier,
            RuntimeAssuranceTier::Verified
        );
        assert_eq!(
            trust_policy.rules[0].verifier_family,
            Some(chio_core::appraisal::AttestationVerifierFamily::AzureMaa)
        );
        assert_eq!(
            trust_policy.rules[0].allowed_attestation_types,
            vec!["sgx".to_string()]
        );
        assert_eq!(
            trust_policy.rules[0]
                .required_assertions
                .get("attestationType")
                .map(String::as_str),
            Some("sgx")
        );
    }
}
