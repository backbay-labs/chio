//! HushSpec policy schema types.
//!
//! These types define the canonical YAML schema for AI agent security
//! policies.

mod enums;
mod extensions;
mod rules;
mod yaml_safety;

use serde::{Deserialize, Serialize};
use yaml_safety::{
    has_libyml_scalar_join_overflow_risk, has_non_mapping_document_start,
    has_unclosed_double_quoted_value_scalar,
};

pub use enums::{
    Classification, ComputerUseMode, DefaultAction, DetectionLevel, LifecycleState, MergeStrategy,
    OriginDefaultBehavior, Severity, TransitionTrigger,
};
pub use extensions::{
    BridgePolicy, BridgeTarget, ChioApproverSet, ChioExtension, ChioHumanInLoopAdvanced,
    ChioK8sNamespaces, ChioMarketHours, ChioRollback, ChioSigning, DetectionExtension, Extensions,
    JailbreakDetection, OriginBudgets, OriginDataPolicy, OriginMatch, OriginProfile,
    OriginsExtension, PostureExtension, PostureState, PostureTransition, PromptInjectionDetection,
    ReputationDemotion, ReputationExtension, ReputationPromotion, ReputationRequiredMetrics,
    ReputationScoringConfig, ReputationTier, ReputationTierScope, ReputationTrigger,
    ReputationWeights, RuntimeAssuranceExtension, RuntimeAssuranceTierRule,
    RuntimeAssuranceVerifierRule, ThreatIntelDetection,
};
pub use rules::{
    BrowserAutomationRule, CodeExecutionRule, ComputerUseRule, EgressRule, ForbiddenPathsRule,
    HumanInLoopRule, HumanInLoopTimeoutAction, InputInjectionRule, PatchIntegrityRule,
    PathAllowlistRule, RemoteDesktopChannelsRule, Rules, SecretPattern, SecretPatternsRule,
    ShellCommandsRule, ToolAccessRule, VelocityRule, WorkloadIdentityMatch, RULE_BLOCK_NAMES,
};

// ---------------------------------------------------------------------------
// Top-level spec
// ---------------------------------------------------------------------------

/// A HushSpec policy document.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HushSpec {
    pub hushspec: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_strategy: Option<MergeStrategy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Rules>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Extensions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<GovernanceMetadata>,
}

impl HushSpec {
    /// Parse a HushSpec document from a YAML string.
    pub fn parse(yaml: &str) -> Result<Self, serde_yml::Error> {
        if has_non_mapping_document_start(yaml) {
            return Err(<serde_yml::Error as serde::de::Error>::custom(
                "YAML policy must start with a mapping",
            ));
        }
        if has_unclosed_double_quoted_value_scalar(yaml) {
            return Err(<serde_yml::Error as serde::de::Error>::custom(
                "YAML contains an unterminated double-quoted scalar",
            ));
        }
        if has_libyml_scalar_join_overflow_risk(yaml) {
            return Err(<serde_yml::Error as serde::de::Error>::custom(
                "YAML contains an unsupported scalar whitespace run",
            ));
        }

        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| serde_yml::from_str(yaml)))
            .unwrap_or_else(|_| {
                Err(<serde_yml::Error as serde::de::Error>::custom(
                    "YAML parser panicked while parsing policy",
                ))
            })
    }

    /// Serialize this spec to a YAML string.
    pub fn to_yaml(&self) -> Result<String, serde_yml::Error> {
        serde_yml::to_string(self)
    }
}

// ---------------------------------------------------------------------------
// Governance metadata
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<Classification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_ticket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<LifecycleState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_date: Option<String>,
}

// ---------------------------------------------------------------------------
// Default value helpers
// ---------------------------------------------------------------------------

fn default_1000() -> usize {
    1000
}

fn default_500() -> usize {
    500
}

fn default_allow() -> DefaultAction {
    DefaultAction::Allow
}

fn default_block() -> DefaultAction {
    DefaultAction::Block
}

fn default_guardrail() -> ComputerUseMode {
    ComputerUseMode::Guardrail
}

fn default_imbalance_ratio() -> f64 {
    10.0
}

fn default_true() -> bool {
    true
}

fn default_velocity_window_secs() -> u64 {
    60
}

fn default_burst_factor() -> f64 {
    1.0
}

#[cfg(test)]
mod tests;
