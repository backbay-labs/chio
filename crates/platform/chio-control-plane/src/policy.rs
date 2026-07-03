//! Policy YAML loading and guard pipeline construction.
//!
//! Reads a Chio policy file and produces a configured `GuardPipeline` plus
//! initial capability definitions for the agent.

#[path = "policy/capabilities.rs"]
mod capabilities;
#[path = "policy/capability_config.rs"]
mod capability_config;
#[path = "policy/guard_config.rs"]
mod guard_config;
#[path = "policy/guards.rs"]
mod guards;
#[path = "policy/issuance.rs"]
mod issuance;
#[path = "policy/loader.rs"]
mod loader;
#[path = "policy/tool_access.rs"]
mod tool_access;
#[path = "policy/types.rs"]
mod types;
#[path = "policy/util.rs"]
mod util;

pub use capabilities::{build_default_capabilities, build_runtime_default_capabilities};
pub use capability_config::{
    CapabilityPolicyConfig, DefaultCapabilityConfig, PromptGrantConfig, ResourceGrantConfig,
    ToolGrantConfig,
};
pub use guard_config::{
    AzureContentSafetyPolicyConfig, CloudGuardrailsPolicyConfig, EgressAllowlistConfig,
    ExternalAdapterPolicyConfig, ForbiddenPathConfig, GuardPolicyConfig, InternalNetworkConfig,
    PatchIntegrityConfig, PolicyPathAllowlistConfig, SafeBrowsingPolicyConfig,
    SecretPatternsConfig, ShellCommandConfig, ThreatIntelPolicyConfig, ToolAccessConfig,
    ToolAccessDefaultAction,
};
pub use guards::{build_guard_pipeline, build_post_invocation_pipeline};
pub use loader::{load_policy, parse_policy};
pub use types::{
    ChioPolicy, DefaultCapability, KernelPolicyConfig, LoadedPolicy, PolicyError, PolicyFormat,
    PolicyIdentity, ReputationIssuancePolicy, ReputationTierPolicy, RuntimeAssuranceIssuancePolicy,
    RuntimeAssuranceTierPolicy, TierScopeCeiling,
};

#[cfg(test)]
#[path = "policy/tests.rs"]
mod tests;
