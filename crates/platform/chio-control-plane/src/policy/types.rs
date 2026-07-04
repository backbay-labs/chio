use chio_core::capability::{
    runtime_attestation::RuntimeAssuranceTier,
    scope::{ChioScope, MonetaryAmount, Operation},
    trust_policy::AttestationTrustPolicy,
};
use chio_guards::{GuardPipeline, PostInvocationPipeline};
use chio_reputation::ReputationConfig as LocalReputationConfig;
use serde::{Deserialize, Serialize};

use super::capability_config::CapabilityPolicyConfig;
use super::guard_config::GuardPolicyConfig;

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
pub(super) struct PolicyAssetDigest {
    pub(super) field: &'static str,
    pub(super) path: String,
    pub(super) sha256: String,
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

pub(super) fn default_max_capability_ttl() -> u64 {
    3600
}

fn default_delegation_depth_limit() -> u32 {
    5
}

fn default_checkpoint_batch_size() -> u64 {
    chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE
}
