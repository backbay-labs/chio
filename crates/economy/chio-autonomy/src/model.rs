use serde::{Deserialize, Serialize};

use crate::capability::{runtime_attestation::RuntimeAssuranceTier, scope::MonetaryAmount};
use crate::market::LiabilityCoverageClass;
use crate::receipt::lineage::SignedExportEnvelope;
use crate::web3::settlement::Web3SettlementLifecycleState;

pub const CHIO_AUTONOMOUS_PRICING_INPUT_SCHEMA: &str = "chio.autonomous-pricing-input.v1";
pub const CHIO_AUTONOMOUS_PRICING_AUTHORITY_ENVELOPE_SCHEMA: &str =
    "chio.autonomous-pricing-authority-envelope.v1";
pub const CHIO_AUTONOMOUS_PRICING_DECISION_SCHEMA: &str = "chio.autonomous-pricing-decision.v1";
pub const CHIO_CAPITAL_POOL_OPTIMIZATION_SCHEMA: &str = "chio.capital-pool-optimization.v1";
pub const CHIO_CAPITAL_POOL_SIMULATION_REPORT_SCHEMA: &str =
    "chio.capital-pool-simulation-report.v1";
pub const CHIO_AUTONOMOUS_EXECUTION_DECISION_SCHEMA: &str = "chio.autonomous-execution-decision.v1";
pub const CHIO_AUTONOMOUS_ROLLBACK_PLAN_SCHEMA: &str = "chio.autonomous-rollback-plan.v1";
pub const CHIO_AUTONOMOUS_COMPARISON_REPORT_SCHEMA: &str = "chio.autonomous-comparison-report.v1";
pub const CHIO_AUTONOMOUS_DRIFT_REPORT_SCHEMA: &str = "chio.autonomous-drift-report.v1";
pub const CHIO_AUTONOMOUS_QUALIFICATION_MATRIX_SCHEMA: &str =
    "chio.autonomous-qualification-matrix.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomousEvidenceKind {
    UnderwritingDecision,
    ExposureLedger,
    CreditScorecard,
    CapitalBook,
    CreditFacility,
    CreditLossLifecycle,
    Web3SettlementReceipt,
    LiabilityQuoteResponse,
    LiabilityAutoBindDecision,
    ClaimWorkflow,
    RuntimeAssuranceAppraisal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomousPricingAction {
    Reprice,
    Renew,
    Decline,
    Bind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomousPricingDisposition {
    Reprice,
    Renew,
    Decline,
    BindWithinEnvelope,
    ManualReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomousDecisionReviewState {
    AutoApproved,
    HumanReviewRequired,
    ShadowOnly,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomousAutomationMode {
    Shadow,
    Advisory,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomousAuthorityEnvelopeKind {
    OperatorPolicy,
    RegulatedRole,
    DelegatedMarketAuthority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomousPricingExplanationDirection {
    Increase,
    Decrease,
    Hold,
    Escalate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapitalOptimizationAction {
    IncreaseReserve,
    DecreaseReserve,
    ShiftCapacity,
    HoldCapacity,
    DeferClaim,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapitalPoolSimulationMode {
    WhatIf,
    Shadow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomousExecutionAction {
    Reprice,
    Renew,
    Decline,
    Bind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomousExecutionLifecycleState {
    Prepared,
    Executed,
    Interrupted,
    RolledBack,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomousDriftKind {
    LossRatioSpike,
    PremiumVariance,
    CapitalUtilization,
    SettlementFailureRate,
    OverrideRate,
    ModelVersionMismatch,
    EvidenceStaleness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomousDriftSeverity {
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomousSafeState {
    ShadowModeOnly,
    DelegatedOnly,
    BindDisabled,
    FullPause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomousRollbackAction {
    SwitchToSafeState,
    CancelPendingExecution,
    RequireHumanApproval,
    RevertToDelegatedAuthority,
    FreezeModelVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomousComparisonDisposition {
    Match,
    NarrowerThanManual,
    WiderThanManual,
    ManualOverride,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomousQualificationOutcome {
    Pass,
    FailClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousEvidenceReference {
    pub kind: AutonomousEvidenceKind,
    pub reference_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousPricingSupportBoundary {
    pub delegated_authority_required: bool,
    pub live_bind_supported: bool,
    pub reserve_optimization_required: bool,
    pub operator_override_supported: bool,
}

impl Default for AutonomousPricingSupportBoundary {
    fn default() -> Self {
        Self {
            delegated_authority_required: true,
            live_bind_supported: true,
            reserve_optimization_required: true,
            operator_override_supported: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousModelProvenance {
    pub model_id: String,
    pub model_version: String,
    pub engine_family: String,
    pub published_at: u64,
    pub training_cutoff: u64,
    pub input_hash: String,
    pub explanation_version: String,
    pub supports_counterfactuals: bool,
    pub supports_shadow_evaluation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousPricingInputArtifact {
    pub schema: String,
    pub input_id: String,
    pub generated_at: u64,
    pub subject_key: String,
    pub provider_id: String,
    pub coverage_class: LiabilityCoverageClass,
    pub currency: String,
    pub requested_coverage_amount: MonetaryAmount,
    pub receipt_history_window_secs: u64,
    pub reputation_score_bps: u32,
    pub runtime_assurance_tier: RuntimeAssuranceTier,
    pub pending_loss_units: u64,
    pub settled_loss_units: u64,
    pub available_capital_units: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_web3_settlement_state: Option<Web3SettlementLifecycleState>,
    pub evidence_refs: Vec<AutonomousEvidenceReference>,
    pub support_boundary: AutonomousPricingSupportBoundary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedAutonomousPricingInput = SignedExportEnvelope<AutonomousPricingInputArtifact>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousPricingAuthorityEnvelopeArtifact {
    pub schema: String,
    pub envelope_id: String,
    pub issued_at: u64,
    pub subject_key: String,
    pub provider_id: String,
    pub currency: String,
    pub kind: AutonomousAuthorityEnvelopeKind,
    pub automation_mode: AutonomousAutomationMode,
    pub permitted_actions: Vec<AutonomousPricingAction>,
    pub authority_chain_refs: Vec<String>,
    pub max_coverage_amount: MonetaryAmount,
    pub max_premium_amount: MonetaryAmount,
    pub max_rate_change_bps: u32,
    pub max_daily_decisions: u32,
    pub requires_human_review_for_bind: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_human_review_above_premium: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regulated_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_authority_reference: Option<String>,
    pub not_before: u64,
    pub not_after: u64,
    pub support_boundary: AutonomousPricingSupportBoundary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedAutonomousPricingAuthorityEnvelope =
    SignedExportEnvelope<AutonomousPricingAuthorityEnvelopeArtifact>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousPricingExplanationFactor {
    pub code: String,
    pub description: String,
    pub direction: AutonomousPricingExplanationDirection,
    pub weight_bps: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<AutonomousEvidenceReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousPricingDecisionArtifact {
    pub schema: String,
    pub decision_id: String,
    pub issued_at: u64,
    pub pricing_input: AutonomousPricingInputArtifact,
    pub model: AutonomousModelProvenance,
    pub authority_envelope: AutonomousPricingAuthorityEnvelopeArtifact,
    pub disposition: AutonomousPricingDisposition,
    pub review_state: AutonomousDecisionReviewState,
    pub suggested_coverage_amount: MonetaryAmount,
    pub suggested_premium_amount: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_ceiling_factor_bps: Option<u32>,
    pub confidence_bps: u32,
    pub explanation_factors: Vec<AutonomousPricingExplanationFactor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparison_baseline_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedAutonomousPricingDecision = SignedExportEnvelope<AutonomousPricingDecisionArtifact>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapitalPoolOptimizationSupportBoundary {
    pub live_mutation_supported: bool,
    pub scenario_comparison_supported: bool,
    pub cross_currency_optimization_supported: bool,
    pub web3_reconciliation_required: bool,
    pub operator_override_required: bool,
}

impl Default for CapitalPoolOptimizationSupportBoundary {
    fn default() -> Self {
        Self {
            live_mutation_supported: false,
            scenario_comparison_supported: true,
            cross_currency_optimization_supported: false,
            web3_reconciliation_required: true,
            operator_override_required: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapitalPoolRecommendation {
    pub action: CapitalOptimizationAction,
    pub source_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_ref: Option<String>,
    pub amount: MonetaryAmount,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapitalPoolOptimizationArtifact {
    pub schema: String,
    pub optimization_id: String,
    pub issued_at: u64,
    pub subject_key: String,
    pub currency: String,
    pub pricing_decision_ref: String,
    pub capital_book_ref: String,
    pub facility_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_claim_refs: Vec<String>,
    pub target_reserve_ratio_bps: u32,
    pub max_facility_utilization_bps: u32,
    pub max_bind_capacity_units: u64,
    pub recommendations: Vec<CapitalPoolRecommendation>,
    pub support_boundary: CapitalPoolOptimizationSupportBoundary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedCapitalPoolOptimization = SignedExportEnvelope<CapitalPoolOptimizationArtifact>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapitalPoolSimulationDelta {
    pub metric_name: String,
    pub baseline_units: u64,
    pub candidate_units: u64,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapitalPoolSimulationReport {
    pub schema: String,
    pub simulation_id: String,
    pub generated_at: u64,
    pub subject_key: String,
    pub currency: String,
    pub baseline_optimization: CapitalPoolOptimizationArtifact,
    pub candidate_optimization: CapitalPoolOptimizationArtifact,
    pub simulation_mode: CapitalPoolSimulationMode,
    pub deltas: Vec<CapitalPoolSimulationDelta>,
    pub recommended_operator_action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedCapitalPoolSimulationReport = SignedExportEnvelope<CapitalPoolSimulationReport>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousExecutionSafetyGate {
    pub name: String,
    pub passed: bool,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousExecutionRollbackControl {
    pub rollback_plan_ref: String,
    pub interruptible: bool,
    pub human_interrupt_contact: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousExecutionDecisionArtifact {
    pub schema: String,
    pub execution_id: String,
    pub issued_at: u64,
    pub pricing_decision_ref: String,
    pub optimization_ref: String,
    pub authority_envelope_ref: String,
    pub subject_key: String,
    pub provider_id: String,
    pub currency: String,
    pub action: AutonomousExecutionAction,
    pub lifecycle_state: AutonomousExecutionLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_response_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_bind_decision_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_coverage_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_dispatch_ref: Option<String>,
    pub safety_gates: Vec<AutonomousExecutionSafetyGate>,
    pub rollback_control: AutonomousExecutionRollbackControl,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedAutonomousExecutionDecision =
    SignedExportEnvelope<AutonomousExecutionDecisionArtifact>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousRollbackPlanArtifact {
    pub schema: String,
    pub plan_id: String,
    pub issued_at: u64,
    pub subject_key: String,
    pub safe_state: AutonomousSafeState,
    pub triggers: Vec<AutonomousDriftKind>,
    pub actions: Vec<AutonomousRollbackAction>,
    pub requires_operator_ack: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedAutonomousRollbackPlan = SignedExportEnvelope<AutonomousRollbackPlanArtifact>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousComparisonDelta {
    pub field: String,
    pub automated_value: String,
    pub manual_value: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousComparisonReport {
    pub schema: String,
    pub comparison_id: String,
    pub generated_at: u64,
    pub pricing_decision_ref: String,
    pub manual_decision_ref: String,
    pub disposition: AutonomousComparisonDisposition,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deltas: Vec<AutonomousComparisonDelta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedAutonomousComparisonReport = SignedExportEnvelope<AutonomousComparisonReport>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousDriftSignal {
    pub kind: AutonomousDriftKind,
    pub severity: AutonomousDriftSeverity,
    pub metric_name: String,
    pub observed_value: u64,
    pub threshold_value: u64,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<AutonomousEvidenceReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousDriftReport {
    pub schema: String,
    pub drift_report_id: String,
    pub generated_at: u64,
    pub subject_key: String,
    pub pricing_decision_ref: String,
    pub optimization_ref: String,
    pub drift_signals: Vec<AutonomousDriftSignal>,
    pub rollback_plan: AutonomousRollbackPlanArtifact,
    pub comparison_report: AutonomousComparisonReport,
    pub fail_safe_engaged: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedAutonomousDriftReport = SignedExportEnvelope<AutonomousDriftReport>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousQualificationCase {
    pub id: String,
    pub name: String,
    pub requirement_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drift_kind: Option<AutonomousDriftKind>,
    pub expected_outcome: AutonomousQualificationOutcome,
    pub observed_outcome: AutonomousQualificationOutcome,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousQualificationMatrix {
    pub schema: String,
    pub profile_id: String,
    pub cases: Vec<AutonomousQualificationCase>,
}
