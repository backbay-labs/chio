use std::collections::BTreeMap;

use super::default_true;
use super::enums::{DetectionLevel, OriginDefaultBehavior, TransitionTrigger};
use super::rules::{EgressRule, ToolAccessRule};
use chio_core::appraisal::AttestationVerifierFamily;
use chio_core::capability::{runtime_attestation::RuntimeAssuranceTier, scope::MonetaryAmount};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Extensions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureExtension>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origins: Option<OriginsExtension>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection: Option<DetectionExtension>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reputation: Option<ReputationExtension>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance: Option<RuntimeAssuranceExtension>,
    /// Chio-specific extension slot. The kernel does not interpret this
    /// block; it is carried verbatim for chio-bridge consumers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chio: Option<ChioExtension>,
}

// ---------------------------------------------------------------------------
// Chio extension
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ChioExtension {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub market_hours: Option<ChioMarketHours>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<ChioSigning>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k8s_namespaces: Option<ChioK8sNamespaces>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback: Option<ChioRollback>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_in_loop: Option<ChioHumanInLoopAdvanced>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChioMarketHours {
    pub tz: String,
    pub open: String,
    pub close: String,
    #[serde(default)]
    pub days: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChioSigning {
    pub algo: String,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChioK8sNamespaces {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub human_in_loop: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChioRollback {
    #[serde(default)]
    pub on_guard_fail: bool,
    #[serde(default)]
    pub on_timeout: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ChioHumanInLoopAdvanced {
    #[serde(default)]
    pub approve_when: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approvers: Option<ChioApproverSet>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChioApproverSet {
    pub n: u32,
    #[serde(default)]
    pub of: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureExtension {
    pub initial: String,
    pub states: BTreeMap<String, PostureState>,
    pub transitions: Vec<PostureTransition>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub budgets: BTreeMap<String, i64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureTransition {
    pub from: String,
    pub to: String,
    pub on: TransitionTrigger,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginsExtension {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_behavior: Option<OriginDefaultBehavior>,
    #[serde(default)]
    pub profiles: Vec<OriginProfile>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginProfile {
    pub id: String,
    #[serde(rename = "match", default, skip_serializing_if = "Option::is_none")]
    pub match_rules: Option<OriginMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_access: Option<ToolAccessRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<OriginDataPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budgets: Option<OriginBudgets>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<BridgePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_participants: Option<bool>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_role: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginDataPolicy {
    #[serde(default)]
    pub allow_external_sharing: bool,
    #[serde(default)]
    pub redact_before_send: bool,
    #[serde(default)]
    pub block_sensitive_outputs: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginBudgets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_calls: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell_commands: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgePolicy {
    #[serde(default)]
    pub allow_cross_origin: bool,
    #[serde(default)]
    pub allowed_targets: Vec<BridgeTarget>,
    #[serde(default)]
    pub require_approval: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeTarget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_type: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionExtension {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_injection: Option<PromptInjectionDetection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jailbreak: Option<JailbreakDetection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_intel: Option<ThreatIntelDetection>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationExtension {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoring: Option<ReputationScoringConfig>,
    #[serde(default)]
    pub tiers: BTreeMap<String, ReputationTier>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationScoringConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weights: Option<ReputationWeights>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temporal_decay_half_life_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probationary_receipt_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probationary_score_ceiling: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probationary_min_days: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationWeights {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary_pressure: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_stewardship: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub least_privilege: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_depth: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_diversity: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_hygiene: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliability: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_correlation: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationTier {
    pub score_range: [f64; 2],
    pub max_scope: ReputationTierScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion: Option<ReputationPromotion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub demotion: Option<ReputationDemotion>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationTierScope {
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_invocations: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_per_invocation: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_cost: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_delegation_depth: Option<u32>,
    pub ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints_required: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationPromotion {
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_receipts: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_metrics: Option<ReputationRequiredMetrics>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationRequiredMetrics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary_pressure_max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliability_min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub least_privilege_min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_hygiene_min: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationDemotion {
    pub target: String,
    #[serde(default)]
    pub triggers: Vec<ReputationTrigger>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationTrigger {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAssuranceExtension {
    #[serde(default)]
    pub tiers: BTreeMap<String, RuntimeAssuranceTierRule>,
    #[serde(default)]
    pub trusted_verifiers: BTreeMap<String, RuntimeAssuranceVerifierRule>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAssuranceTierRule {
    pub minimum_attestation_tier: RuntimeAssuranceTier,
    pub max_scope: ReputationTierScope,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAssuranceVerifierRule {
    pub schema: String,
    pub verifier: String,
    pub effective_tier: RuntimeAssuranceTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_family: Option<AttestationVerifierFamily>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_evidence_age_seconds: Option<u64>,
    #[serde(default)]
    pub allowed_attestation_types: Vec<String>,
    #[serde(default)]
    pub required_assertions: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptInjectionDetection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warn_at_or_above: Option<DetectionLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_at_or_above: Option<DetectionLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_scan_bytes: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailbreakDetection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_threshold: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warn_threshold: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_input_bytes: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatIntelDetection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern_db: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub similarity_threshold: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_k: Option<usize>,
}
