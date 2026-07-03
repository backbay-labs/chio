use chio_data_guards::{
    QueryResultGuardConfig, SqlGuardConfig, VectorGuardConfig, WarehouseCostGuardConfig,
};
use chio_guards::ContentReviewConfig;
use serde::{Deserialize, Serialize};

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

pub(super) fn default_true() -> bool {
    true
}

pub(super) fn default_forbidden_path_patterns() -> Vec<String> {
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
