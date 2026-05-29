//! Chio autonomous pricing, capital optimization, and fail-safe automation types.
//!
//! These contracts extend the delegated underwriting, market, capital, and
//! web3 surfaces into one bounded automation layer. The automation layer
//! remains evidence-referential: it carries explicit references back to prior
//! Chio truth rather than replacing those signed artifacts.

#![forbid(unsafe_code)]

pub use chio_core_types::{capability, receipt};
pub use chio_market as market;
pub use chio_web3 as web3;

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::capability::{MonetaryAmount, RuntimeAssuranceTier};
use crate::market::LiabilityCoverageClass;
use crate::receipt::SignedExportEnvelope;
use crate::web3::Web3SettlementLifecycleState;

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

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AutonomyContractError {
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),

    #[error("missing field: {0}")]
    MissingField(&'static str),

    #[error("duplicate value: {0}")]
    DuplicateValue(String),

    #[error("unknown reference: {0}")]
    UnknownReference(String),

    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),

    #[error("invalid decision: {0}")]
    InvalidDecision(String),

    #[error("invalid optimization: {0}")]
    InvalidOptimization(String),

    #[error("invalid execution: {0}")]
    InvalidExecution(String),

    #[error("invalid drift: {0}")]
    InvalidDrift(String),

    #[error("invalid qualification case: {0}")]
    InvalidQualificationCase(String),
}

pub fn validate_autonomous_pricing_input(
    input: &AutonomousPricingInputArtifact,
) -> Result<(), AutonomyContractError> {
    if input.schema != CHIO_AUTONOMOUS_PRICING_INPUT_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            input.schema.clone(),
        ));
    }
    ensure_non_empty(&input.input_id, "autonomous_pricing_input.input_id")?;
    ensure_non_empty(&input.subject_key, "autonomous_pricing_input.subject_key")?;
    ensure_non_empty(&input.provider_id, "autonomous_pricing_input.provider_id")?;
    validate_currency_code(&input.currency, "autonomous_pricing_input.currency")?;
    validate_positive_money(
        &input.requested_coverage_amount,
        "autonomous_pricing_input.requested_coverage_amount",
    )?;
    if input
        .requested_coverage_amount
        .currency
        .trim()
        .to_ascii_uppercase()
        != input.currency
    {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous pricing input coverage amount currency must match currency".to_string(),
        ));
    }
    if input.receipt_history_window_secs == 0 {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous pricing input receipt_history_window_secs must be non-zero".to_string(),
        ));
    }
    if input.reputation_score_bps > 10_000 {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous pricing input reputation_score_bps must be <= 10000".to_string(),
        ));
    }
    if input.available_capital_units == 0 {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous pricing input available_capital_units must be non-zero".to_string(),
        ));
    }
    if input.evidence_refs.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_pricing_input.evidence_refs",
        ));
    }

    let mut ids = HashSet::new();
    let mut kinds = HashSet::new();
    for evidence in &input.evidence_refs {
        ensure_non_empty(
            &evidence.reference_id,
            "autonomous_pricing_input.evidence_refs.reference_id",
        )?;
        if !ids.insert(evidence.reference_id.as_str()) {
            return Err(AutonomyContractError::DuplicateValue(
                evidence.reference_id.clone(),
            ));
        }
        kinds.insert(evidence.kind);
    }
    for required in [
        AutonomousEvidenceKind::UnderwritingDecision,
        AutonomousEvidenceKind::ExposureLedger,
        AutonomousEvidenceKind::CreditScorecard,
        AutonomousEvidenceKind::CapitalBook,
    ] {
        if !kinds.contains(&required) {
            return Err(AutonomyContractError::UnknownReference(format!(
                "autonomous pricing input missing required evidence {:?}",
                required
            )));
        }
    }
    if (input.pending_loss_units > 0 || input.settled_loss_units > 0)
        && !kinds.contains(&AutonomousEvidenceKind::CreditLossLifecycle)
    {
        return Err(AutonomyContractError::UnknownReference(
            "autonomous pricing input with loss units must include credit_loss_lifecycle evidence"
                .to_string(),
        ));
    }
    if input.latest_web3_settlement_state.is_some()
        && !kinds.contains(&AutonomousEvidenceKind::Web3SettlementReceipt)
    {
        return Err(AutonomyContractError::UnknownReference(
            "autonomous pricing input with latest_web3_settlement_state must include web3_settlement_receipt evidence"
                .to_string(),
        ));
    }
    Ok(())
}

pub fn validate_autonomous_pricing_authority_envelope(
    envelope: &AutonomousPricingAuthorityEnvelopeArtifact,
) -> Result<(), AutonomyContractError> {
    if envelope.schema != CHIO_AUTONOMOUS_PRICING_AUTHORITY_ENVELOPE_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            envelope.schema.clone(),
        ));
    }
    ensure_non_empty(
        &envelope.envelope_id,
        "autonomous_authority_envelope.envelope_id",
    )?;
    ensure_non_empty(
        &envelope.subject_key,
        "autonomous_authority_envelope.subject_key",
    )?;
    ensure_non_empty(
        &envelope.provider_id,
        "autonomous_authority_envelope.provider_id",
    )?;
    validate_currency_code(&envelope.currency, "autonomous_authority_envelope.currency")?;
    if envelope.permitted_actions.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_authority_envelope.permitted_actions",
        ));
    }
    ensure_unique_copy_values(
        &envelope.permitted_actions,
        "autonomous_authority_envelope.permitted_actions",
    )?;
    if envelope.authority_chain_refs.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_authority_envelope.authority_chain_refs",
        ));
    }
    ensure_unique_strings(
        &envelope.authority_chain_refs,
        "autonomous_authority_envelope.authority_chain_refs",
    )?;
    validate_positive_money(
        &envelope.max_coverage_amount,
        "autonomous_authority_envelope.max_coverage_amount",
    )?;
    validate_positive_money(
        &envelope.max_premium_amount,
        "autonomous_authority_envelope.max_premium_amount",
    )?;
    if envelope
        .max_coverage_amount
        .currency
        .trim()
        .to_ascii_uppercase()
        != envelope.currency
    {
        return Err(AutonomyContractError::InvalidEnvelope(
            "autonomous authority max_coverage_amount currency must match envelope currency"
                .to_string(),
        ));
    }
    if envelope
        .max_premium_amount
        .currency
        .trim()
        .to_ascii_uppercase()
        != envelope.currency
    {
        return Err(AutonomyContractError::InvalidEnvelope(
            "autonomous authority max_premium_amount currency must match envelope currency"
                .to_string(),
        ));
    }
    if envelope.max_rate_change_bps == 0 || envelope.max_rate_change_bps > 10_000 {
        return Err(AutonomyContractError::InvalidEnvelope(
            "autonomous authority max_rate_change_bps must be between 1 and 10000".to_string(),
        ));
    }
    if envelope.max_daily_decisions == 0 {
        return Err(AutonomyContractError::InvalidEnvelope(
            "autonomous authority max_daily_decisions must be non-zero".to_string(),
        ));
    }
    if let Some(threshold) = envelope.requires_human_review_above_premium.as_ref() {
        validate_positive_money(
            threshold,
            "autonomous_authority_envelope.requires_human_review_above_premium",
        )?;
        if threshold.currency.trim().to_ascii_uppercase() != envelope.currency {
            return Err(AutonomyContractError::InvalidEnvelope(
                "autonomous authority premium review threshold currency must match envelope currency"
                    .to_string(),
            ));
        }
        if threshold.units > envelope.max_premium_amount.units {
            return Err(AutonomyContractError::InvalidEnvelope(
                "autonomous authority premium review threshold cannot exceed max_premium_amount"
                    .to_string(),
            ));
        }
    }
    if envelope.not_before >= envelope.not_after {
        return Err(AutonomyContractError::InvalidEnvelope(
            "autonomous authority not_before must be earlier than not_after".to_string(),
        ));
    }
    match envelope.kind {
        AutonomousAuthorityEnvelopeKind::OperatorPolicy => {}
        AutonomousAuthorityEnvelopeKind::RegulatedRole => {
            ensure_non_empty(
                envelope.regulated_role.as_deref().unwrap_or_default(),
                "autonomous_authority_envelope.regulated_role",
            )?;
        }
        AutonomousAuthorityEnvelopeKind::DelegatedMarketAuthority => {
            ensure_non_empty(
                envelope
                    .delegated_authority_reference
                    .as_deref()
                    .unwrap_or_default(),
                "autonomous_authority_envelope.delegated_authority_reference",
            )?;
        }
    }
    if envelope.automation_mode != AutonomousAutomationMode::Active
        && envelope
            .permitted_actions
            .contains(&AutonomousPricingAction::Bind)
    {
        return Err(AutonomyContractError::InvalidEnvelope(
            "only active automation envelopes may permit bind".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_autonomous_pricing_decision(
    decision: &AutonomousPricingDecisionArtifact,
) -> Result<(), AutonomyContractError> {
    if decision.schema != CHIO_AUTONOMOUS_PRICING_DECISION_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            decision.schema.clone(),
        ));
    }
    ensure_non_empty(
        &decision.decision_id,
        "autonomous_pricing_decision.decision_id",
    )?;
    validate_autonomous_pricing_input(&decision.pricing_input)?;
    validate_autonomous_pricing_authority_envelope(&decision.authority_envelope)?;
    validate_model_provenance(&decision.model)?;
    validate_positive_money(
        &decision.suggested_coverage_amount,
        "autonomous_pricing_decision.suggested_coverage_amount",
    )?;
    validate_positive_money(
        &decision.suggested_premium_amount,
        "autonomous_pricing_decision.suggested_premium_amount",
    )?;
    if decision
        .suggested_coverage_amount
        .currency
        .trim()
        .to_ascii_uppercase()
        != decision.authority_envelope.currency
        || decision
            .suggested_premium_amount
            .currency
            .trim()
            .to_ascii_uppercase()
            != decision.authority_envelope.currency
    {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous pricing decision money fields must match envelope currency".to_string(),
        ));
    }
    if decision.pricing_input.subject_key != decision.authority_envelope.subject_key
        || decision.pricing_input.provider_id != decision.authority_envelope.provider_id
        || decision.pricing_input.currency != decision.authority_envelope.currency
    {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous pricing decision input must match authority envelope subject/provider/currency"
                .to_string(),
        ));
    }
    if decision.suggested_coverage_amount.units
        > decision.authority_envelope.max_coverage_amount.units
    {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous pricing decision coverage exceeds authority envelope".to_string(),
        ));
    }
    if decision.suggested_premium_amount.units
        > decision.authority_envelope.max_premium_amount.units
    {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous pricing decision premium exceeds authority envelope".to_string(),
        ));
    }
    if let Some(ceiling_factor_bps) = decision.suggested_ceiling_factor_bps {
        if ceiling_factor_bps == 0 || ceiling_factor_bps > 10_000 {
            return Err(AutonomyContractError::InvalidDecision(
                "autonomous pricing decision suggested_ceiling_factor_bps must be between 1 and 10000"
                    .to_string(),
            ));
        }
    }
    if decision.confidence_bps == 0 || decision.confidence_bps > 10_000 {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous pricing decision confidence_bps must be between 1 and 10000".to_string(),
        ));
    }
    if decision.explanation_factors.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_pricing_decision.explanation_factors",
        ));
    }
    let mut factor_codes = HashSet::new();
    for factor in &decision.explanation_factors {
        ensure_non_empty(
            &factor.code,
            "autonomous_pricing_decision.explanation_factors.code",
        )?;
        ensure_non_empty(
            &factor.description,
            "autonomous_pricing_decision.explanation_factors.description",
        )?;
        if factor.weight_bps == 0 || factor.weight_bps > 10_000 {
            return Err(AutonomyContractError::InvalidDecision(
                "autonomous pricing explanation factor weight_bps must be between 1 and 10000"
                    .to_string(),
            ));
        }
        if !factor_codes.insert(factor.code.as_str()) {
            return Err(AutonomyContractError::DuplicateValue(factor.code.clone()));
        }
    }
    if decision.authority_envelope.automation_mode == AutonomousAutomationMode::Shadow
        && decision.review_state != AutonomousDecisionReviewState::ShadowOnly
    {
        return Err(AutonomyContractError::InvalidDecision(
            "shadow automation decisions must use review_state shadow_only".to_string(),
        ));
    }
    if decision.review_state == AutonomousDecisionReviewState::ShadowOnly
        && decision.authority_envelope.automation_mode != AutonomousAutomationMode::Shadow
    {
        return Err(AutonomyContractError::InvalidDecision(
            "review_state shadow_only requires a shadow automation envelope".to_string(),
        ));
    }
    if decision.disposition == AutonomousPricingDisposition::ManualReview
        && decision.review_state == AutonomousDecisionReviewState::AutoApproved
    {
        return Err(AutonomyContractError::InvalidDecision(
            "manual-review pricing decisions cannot be auto approved".to_string(),
        ));
    }
    if let Some(threshold) = decision
        .authority_envelope
        .requires_human_review_above_premium
        .as_ref()
    {
        if decision.review_state == AutonomousDecisionReviewState::AutoApproved
            && decision.suggested_premium_amount.units > threshold.units
        {
            return Err(AutonomyContractError::InvalidDecision(
                "auto-approved pricing decisions cannot exceed the premium review threshold"
                    .to_string(),
            ));
        }
    }
    if decision.disposition == AutonomousPricingDisposition::BindWithinEnvelope {
        if !decision
            .authority_envelope
            .permitted_actions
            .contains(&AutonomousPricingAction::Bind)
        {
            return Err(AutonomyContractError::InvalidDecision(
                "bind-within-envelope decisions require bind permission in the authority envelope"
                    .to_string(),
            ));
        }
        if !decision
            .authority_envelope
            .support_boundary
            .live_bind_supported
        {
            return Err(AutonomyContractError::InvalidDecision(
                "bind-within-envelope decisions require live_bind_supported".to_string(),
            ));
        }
        if decision.authority_envelope.requires_human_review_for_bind
            && decision.review_state == AutonomousDecisionReviewState::AutoApproved
        {
            return Err(AutonomyContractError::InvalidDecision(
                "bind-within-envelope decisions cannot be auto approved when human review is required for bind"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

pub fn validate_capital_pool_optimization(
    optimization: &CapitalPoolOptimizationArtifact,
) -> Result<(), AutonomyContractError> {
    if optimization.schema != CHIO_CAPITAL_POOL_OPTIMIZATION_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            optimization.schema.clone(),
        ));
    }
    ensure_non_empty(
        &optimization.optimization_id,
        "capital_pool_optimization.optimization_id",
    )?;
    ensure_non_empty(
        &optimization.subject_key,
        "capital_pool_optimization.subject_key",
    )?;
    validate_currency_code(&optimization.currency, "capital_pool_optimization.currency")?;
    ensure_non_empty(
        &optimization.pricing_decision_ref,
        "capital_pool_optimization.pricing_decision_ref",
    )?;
    ensure_non_empty(
        &optimization.capital_book_ref,
        "capital_pool_optimization.capital_book_ref",
    )?;
    if optimization.facility_refs.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "capital_pool_optimization.facility_refs",
        ));
    }
    ensure_unique_strings(
        &optimization.facility_refs,
        "capital_pool_optimization.facility_refs",
    )?;
    ensure_unique_strings(
        &optimization.pending_claim_refs,
        "capital_pool_optimization.pending_claim_refs",
    )?;
    if optimization.target_reserve_ratio_bps == 0 || optimization.target_reserve_ratio_bps > 10_000
    {
        return Err(AutonomyContractError::InvalidOptimization(
            "capital pool optimization target_reserve_ratio_bps must be between 1 and 10000"
                .to_string(),
        ));
    }
    if optimization.max_facility_utilization_bps == 0
        || optimization.max_facility_utilization_bps > 10_000
    {
        return Err(AutonomyContractError::InvalidOptimization(
            "capital pool optimization max_facility_utilization_bps must be between 1 and 10000"
                .to_string(),
        ));
    }
    if optimization.max_bind_capacity_units == 0 {
        return Err(AutonomyContractError::InvalidOptimization(
            "capital pool optimization max_bind_capacity_units must be non-zero".to_string(),
        ));
    }
    if optimization.recommendations.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "capital_pool_optimization.recommendations",
        ));
    }
    for recommendation in &optimization.recommendations {
        ensure_non_empty(
            &recommendation.source_ref,
            "capital_pool_optimization.recommendations.source_ref",
        )?;
        ensure_non_empty(
            &recommendation.rationale,
            "capital_pool_optimization.recommendations.rationale",
        )?;
        validate_positive_money(
            &recommendation.amount,
            "capital_pool_optimization.recommendations.amount",
        )?;
        if recommendation.amount.currency.trim().to_ascii_uppercase() != optimization.currency {
            return Err(AutonomyContractError::InvalidOptimization(
                "capital pool optimization recommendation amounts must match optimization currency"
                    .to_string(),
            ));
        }
        if recommendation.action == CapitalOptimizationAction::ShiftCapacity
            && recommendation
                .destination_ref
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(AutonomyContractError::InvalidOptimization(
                "shift-capacity recommendations require destination_ref".to_string(),
            ));
        }
    }
    Ok(())
}

pub fn validate_capital_pool_simulation_report(
    report: &CapitalPoolSimulationReport,
) -> Result<(), AutonomyContractError> {
    if report.schema != CHIO_CAPITAL_POOL_SIMULATION_REPORT_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            report.schema.clone(),
        ));
    }
    ensure_non_empty(
        &report.simulation_id,
        "capital_pool_simulation.simulation_id",
    )?;
    ensure_non_empty(&report.subject_key, "capital_pool_simulation.subject_key")?;
    validate_currency_code(&report.currency, "capital_pool_simulation.currency")?;
    validate_capital_pool_optimization(&report.baseline_optimization)?;
    validate_capital_pool_optimization(&report.candidate_optimization)?;
    if report.baseline_optimization.subject_key != report.subject_key
        || report.candidate_optimization.subject_key != report.subject_key
    {
        return Err(AutonomyContractError::InvalidOptimization(
            "capital pool simulation subject_key must match both baseline and candidate optimizations"
                .to_string(),
        ));
    }
    if report.baseline_optimization.currency != report.currency
        || report.candidate_optimization.currency != report.currency
    {
        return Err(AutonomyContractError::InvalidOptimization(
            "capital pool simulation currency must match both baseline and candidate optimizations"
                .to_string(),
        ));
    }
    if report.baseline_optimization.optimization_id == report.candidate_optimization.optimization_id
    {
        return Err(AutonomyContractError::DuplicateValue(
            report.baseline_optimization.optimization_id.clone(),
        ));
    }
    if !report
        .baseline_optimization
        .support_boundary
        .scenario_comparison_supported
        || !report
            .candidate_optimization
            .support_boundary
            .scenario_comparison_supported
    {
        return Err(AutonomyContractError::InvalidOptimization(
            "capital pool simulation requires scenario_comparison_supported on both optimizations"
                .to_string(),
        ));
    }
    if report.deltas.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "capital_pool_simulation.deltas",
        ));
    }
    for delta in &report.deltas {
        ensure_non_empty(
            &delta.metric_name,
            "capital_pool_simulation.deltas.metric_name",
        )?;
        ensure_non_empty(
            &delta.description,
            "capital_pool_simulation.deltas.description",
        )?;
    }
    ensure_non_empty(
        &report.recommended_operator_action,
        "capital_pool_simulation.recommended_operator_action",
    )?;
    Ok(())
}

pub fn validate_autonomous_execution_decision(
    decision: &AutonomousExecutionDecisionArtifact,
) -> Result<(), AutonomyContractError> {
    if decision.schema != CHIO_AUTONOMOUS_EXECUTION_DECISION_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            decision.schema.clone(),
        ));
    }
    for (value, field) in [
        (&decision.execution_id, "autonomous_execution.execution_id"),
        (
            &decision.pricing_decision_ref,
            "autonomous_execution.pricing_decision_ref",
        ),
        (
            &decision.optimization_ref,
            "autonomous_execution.optimization_ref",
        ),
        (
            &decision.authority_envelope_ref,
            "autonomous_execution.authority_envelope_ref",
        ),
        (&decision.subject_key, "autonomous_execution.subject_key"),
        (&decision.provider_id, "autonomous_execution.provider_id"),
    ] {
        ensure_non_empty(value, field)?;
    }
    validate_currency_code(&decision.currency, "autonomous_execution.currency")?;
    if decision.safety_gates.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_execution.safety_gates",
        ));
    }
    let mut gate_names = HashSet::new();
    for gate in &decision.safety_gates {
        ensure_non_empty(&gate.name, "autonomous_execution.safety_gates.name")?;
        ensure_non_empty(
            &gate.description,
            "autonomous_execution.safety_gates.description",
        )?;
        if !gate_names.insert(gate.name.as_str()) {
            return Err(AutonomyContractError::DuplicateValue(gate.name.clone()));
        }
    }
    validate_rollback_control(&decision.rollback_control)?;

    let all_gates_passed = decision.safety_gates.iter().all(|gate| gate.passed);
    if decision.lifecycle_state == AutonomousExecutionLifecycleState::Executed && !all_gates_passed
    {
        return Err(AutonomyContractError::InvalidExecution(
            "executed autonomous actions require all safety gates to pass".to_string(),
        ));
    }
    if decision.lifecycle_state == AutonomousExecutionLifecycleState::Blocked && all_gates_passed {
        return Err(AutonomyContractError::InvalidExecution(
            "blocked autonomous actions require at least one failed safety gate".to_string(),
        ));
    }

    match decision.action {
        AutonomousExecutionAction::Reprice | AutonomousExecutionAction::Renew => {
            ensure_non_empty(
                decision.quote_response_ref.as_deref().unwrap_or_default(),
                "autonomous_execution.quote_response_ref",
            )?;
            if decision.auto_bind_decision_ref.is_some()
                || decision.bound_coverage_ref.is_some()
                || decision.settlement_dispatch_ref.is_some()
            {
                return Err(AutonomyContractError::InvalidExecution(
                    "reprice and renew automation cannot embed bind or settlement references"
                        .to_string(),
                ));
            }
        }
        AutonomousExecutionAction::Decline => {
            if decision.auto_bind_decision_ref.is_some()
                || decision.bound_coverage_ref.is_some()
                || decision.settlement_dispatch_ref.is_some()
            {
                return Err(AutonomyContractError::InvalidExecution(
                    "decline automation cannot embed bind or settlement references".to_string(),
                ));
            }
        }
        AutonomousExecutionAction::Bind => {
            ensure_non_empty(
                decision.quote_response_ref.as_deref().unwrap_or_default(),
                "autonomous_execution.quote_response_ref",
            )?;
            ensure_non_empty(
                decision
                    .auto_bind_decision_ref
                    .as_deref()
                    .unwrap_or_default(),
                "autonomous_execution.auto_bind_decision_ref",
            )?;
            ensure_non_empty(
                decision.bound_coverage_ref.as_deref().unwrap_or_default(),
                "autonomous_execution.bound_coverage_ref",
            )?;
            if decision.lifecycle_state == AutonomousExecutionLifecycleState::Executed {
                ensure_non_empty(
                    decision
                        .settlement_dispatch_ref
                        .as_deref()
                        .unwrap_or_default(),
                    "autonomous_execution.settlement_dispatch_ref",
                )?;
            }
        }
    }

    Ok(())
}

pub fn validate_autonomous_comparison_report(
    report: &AutonomousComparisonReport,
) -> Result<(), AutonomyContractError> {
    if report.schema != CHIO_AUTONOMOUS_COMPARISON_REPORT_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            report.schema.clone(),
        ));
    }
    ensure_non_empty(&report.comparison_id, "autonomous_comparison.comparison_id")?;
    ensure_non_empty(
        &report.pricing_decision_ref,
        "autonomous_comparison.pricing_decision_ref",
    )?;
    ensure_non_empty(
        &report.manual_decision_ref,
        "autonomous_comparison.manual_decision_ref",
    )?;
    if report.disposition != AutonomousComparisonDisposition::Match && report.deltas.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_comparison.deltas",
        ));
    }
    if report.disposition == AutonomousComparisonDisposition::ManualOverride {
        ensure_non_empty(
            report.override_reference.as_deref().unwrap_or_default(),
            "autonomous_comparison.override_reference",
        )?;
    }
    for delta in &report.deltas {
        for (value, field) in [
            (&delta.field, "autonomous_comparison.deltas.field"),
            (
                &delta.automated_value,
                "autonomous_comparison.deltas.automated_value",
            ),
            (
                &delta.manual_value,
                "autonomous_comparison.deltas.manual_value",
            ),
            (
                &delta.description,
                "autonomous_comparison.deltas.description",
            ),
        ] {
            ensure_non_empty(value, field)?;
        }
    }
    Ok(())
}

pub fn validate_autonomous_drift_report(
    report: &AutonomousDriftReport,
) -> Result<(), AutonomyContractError> {
    if report.schema != CHIO_AUTONOMOUS_DRIFT_REPORT_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            report.schema.clone(),
        ));
    }
    ensure_non_empty(&report.drift_report_id, "autonomous_drift.drift_report_id")?;
    ensure_non_empty(&report.subject_key, "autonomous_drift.subject_key")?;
    ensure_non_empty(
        &report.pricing_decision_ref,
        "autonomous_drift.pricing_decision_ref",
    )?;
    ensure_non_empty(
        &report.optimization_ref,
        "autonomous_drift.optimization_ref",
    )?;
    validate_autonomous_rollback_plan(&report.rollback_plan)?;
    validate_autonomous_comparison_report(&report.comparison_report)?;
    if report.drift_signals.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_drift.drift_signals",
        ));
    }
    let mut critical_kinds = HashSet::new();
    for signal in &report.drift_signals {
        ensure_non_empty(&signal.metric_name, "autonomous_drift.metric_name")?;
        ensure_non_empty(&signal.description, "autonomous_drift.description")?;
        if signal.threshold_value == 0 {
            return Err(AutonomyContractError::InvalidDrift(
                "autonomous drift threshold_value must be non-zero".to_string(),
            ));
        }
        if signal.severity == AutonomousDriftSeverity::Critical {
            critical_kinds.insert(signal.kind);
        }
    }
    if !critical_kinds.is_empty() && !report.fail_safe_engaged {
        return Err(AutonomyContractError::InvalidDrift(
            "critical drift signals require fail_safe_engaged".to_string(),
        ));
    }
    for kind in critical_kinds {
        if !report.rollback_plan.triggers.contains(&kind) {
            return Err(AutonomyContractError::InvalidDrift(format!(
                "rollback plan does not cover critical drift trigger {:?}",
                kind
            )));
        }
    }
    Ok(())
}

pub fn validate_autonomous_rollback_plan(
    plan: &AutonomousRollbackPlanArtifact,
) -> Result<(), AutonomyContractError> {
    if plan.schema != CHIO_AUTONOMOUS_ROLLBACK_PLAN_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            plan.schema.clone(),
        ));
    }
    ensure_non_empty(&plan.plan_id, "autonomous_rollback.plan_id")?;
    ensure_non_empty(&plan.subject_key, "autonomous_rollback.subject_key")?;
    if plan.triggers.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_rollback.triggers",
        ));
    }
    if plan.actions.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_rollback.actions",
        ));
    }
    ensure_unique_copy_values(&plan.triggers, "autonomous_rollback.triggers")?;
    ensure_unique_copy_values(&plan.actions, "autonomous_rollback.actions")?;
    Ok(())
}

pub fn validate_autonomous_qualification_matrix(
    matrix: &AutonomousQualificationMatrix,
) -> Result<(), AutonomyContractError> {
    if matrix.schema != CHIO_AUTONOMOUS_QUALIFICATION_MATRIX_SCHEMA {
        return Err(AutonomyContractError::UnsupportedSchema(
            matrix.schema.clone(),
        ));
    }
    ensure_non_empty(&matrix.profile_id, "autonomous_qualification.profile_id")?;
    if matrix.cases.is_empty() {
        return Err(AutonomyContractError::MissingField(
            "autonomous_qualification.cases",
        ));
    }
    let mut seen_ids = HashSet::new();
    for case in &matrix.cases {
        ensure_non_empty(&case.id, "autonomous_qualification.cases.id")?;
        ensure_non_empty(&case.name, "autonomous_qualification.cases.name")?;
        ensure_non_empty(&case.notes, "autonomous_qualification.cases.notes")?;
        if case.requirement_ids.is_empty() {
            return Err(AutonomyContractError::InvalidQualificationCase(format!(
                "qualification case `{}` requires at least one requirement id",
                case.id
            )));
        }
        ensure_unique_strings(
            &case.requirement_ids,
            "autonomous_qualification.cases.requirement_ids",
        )?;
        if !seen_ids.insert(case.id.as_str()) {
            return Err(AutonomyContractError::DuplicateValue(case.id.clone()));
        }
    }
    Ok(())
}

fn validate_model_provenance(
    model: &AutonomousModelProvenance,
) -> Result<(), AutonomyContractError> {
    for (value, field) in [
        (&model.model_id, "autonomous_model.model_id"),
        (&model.model_version, "autonomous_model.model_version"),
        (&model.engine_family, "autonomous_model.engine_family"),
        (&model.input_hash, "autonomous_model.input_hash"),
        (
            &model.explanation_version,
            "autonomous_model.explanation_version",
        ),
    ] {
        ensure_non_empty(value, field)?;
    }
    if model.training_cutoff > model.published_at {
        return Err(AutonomyContractError::InvalidDecision(
            "autonomous model training_cutoff must be <= published_at".to_string(),
        ));
    }
    Ok(())
}

fn validate_rollback_control(
    control: &AutonomousExecutionRollbackControl,
) -> Result<(), AutonomyContractError> {
    ensure_non_empty(
        &control.rollback_plan_ref,
        "autonomous_execution.rollback_control.rollback_plan_ref",
    )?;
    ensure_non_empty(
        &control.human_interrupt_contact,
        "autonomous_execution.rollback_control.human_interrupt_contact",
    )?;
    Ok(())
}

fn validate_positive_money(
    amount: &MonetaryAmount,
    field: &'static str,
) -> Result<(), AutonomyContractError> {
    if amount.units == 0 {
        return Err(AutonomyContractError::InvalidDecision(format!(
            "{field} must be greater than zero"
        )));
    }
    validate_currency_code(&amount.currency, field)
}

fn validate_currency_code(
    currency: &str,
    field: &'static str,
) -> Result<(), AutonomyContractError> {
    let normalized = currency.trim().to_ascii_uppercase();
    if normalized.len() != 3
        || !normalized
            .chars()
            .all(|character| character.is_ascii_uppercase())
    {
        return Err(AutonomyContractError::InvalidDecision(format!(
            "{field} must be a 3-letter uppercase currency code"
        )));
    }
    Ok(())
}

fn ensure_non_empty(value: &str, field: &'static str) -> Result<(), AutonomyContractError> {
    if value.trim().is_empty() {
        return Err(AutonomyContractError::MissingField(field));
    }
    Ok(())
}

fn ensure_unique_strings(
    values: &[String],
    field: &'static str,
) -> Result<(), AutonomyContractError> {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(value.as_str()) {
            return Err(AutonomyContractError::DuplicateValue(format!(
                "{field}:{value}"
            )));
        }
    }
    Ok(())
}

fn ensure_unique_copy_values<T>(
    values: &[T],
    field: &'static str,
) -> Result<(), AutonomyContractError>
where
    T: Copy + Eq + std::hash::Hash + std::fmt::Debug,
{
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(*value) {
            return Err(AutonomyContractError::DuplicateValue(format!(
                "{field}:{value:?}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_fixture<T>(fixture: &'static str, body: &str) -> T
    where
        T: serde::de::DeserializeOwned,
    {
        serde_json::from_str(body)
            .unwrap_or_else(|error| panic!("{fixture} fixture must parse: {error}"))
    }

    fn require_valid<T, E>(result: Result<T, E>, context: &'static str) -> T
    where
        E: std::fmt::Debug,
    {
        result.unwrap_or_else(|error| panic!("{context} should validate: {error:?}"))
    }

    fn sample_input() -> AutonomousPricingInputArtifact {
        AutonomousPricingInputArtifact {
            schema: CHIO_AUTONOMOUS_PRICING_INPUT_SCHEMA.to_string(),
            input_id: "api-1".to_string(),
            generated_at: 1_743_379_200,
            subject_key: "subject-1".to_string(),
            provider_id: "carrier-1".to_string(),
            coverage_class: LiabilityCoverageClass::ProfessionalLiability,
            currency: "USD".to_string(),
            requested_coverage_amount: MonetaryAmount {
                units: 120_000,
                currency: "USD".to_string(),
            },
            receipt_history_window_secs: 2_592_000,
            reputation_score_bps: 8_200,
            runtime_assurance_tier: RuntimeAssuranceTier::Verified,
            pending_loss_units: 0,
            settled_loss_units: 2_500,
            available_capital_units: 600_000,
            latest_web3_settlement_state: Some(Web3SettlementLifecycleState::Settled),
            evidence_refs: vec![
                AutonomousEvidenceReference {
                    kind: AutonomousEvidenceKind::UnderwritingDecision,
                    reference_id: "uwd-1".to_string(),
                    observed_at: Some(1_743_379_100),
                    locator: Some("underwriting:uwd-1".to_string()),
                },
                AutonomousEvidenceReference {
                    kind: AutonomousEvidenceKind::ExposureLedger,
                    reference_id: "eld-1".to_string(),
                    observed_at: Some(1_743_379_100),
                    locator: Some("ledger:eld-1".to_string()),
                },
                AutonomousEvidenceReference {
                    kind: AutonomousEvidenceKind::CreditScorecard,
                    reference_id: "score-1".to_string(),
                    observed_at: Some(1_743_379_050),
                    locator: Some("scorecard:score-1".to_string()),
                },
                AutonomousEvidenceReference {
                    kind: AutonomousEvidenceKind::CapitalBook,
                    reference_id: "cb-1".to_string(),
                    observed_at: Some(1_743_379_150),
                    locator: Some("capital-book:cb-1".to_string()),
                },
                AutonomousEvidenceReference {
                    kind: AutonomousEvidenceKind::CreditLossLifecycle,
                    reference_id: "loss-1".to_string(),
                    observed_at: Some(1_743_378_900),
                    locator: Some("loss:loss-1".to_string()),
                },
                AutonomousEvidenceReference {
                    kind: AutonomousEvidenceKind::Web3SettlementReceipt,
                    reference_id: "receipt-web3-1".to_string(),
                    observed_at: Some(1_743_379_000),
                    locator: Some("web3-settlement:receipt-web3-1".to_string()),
                },
            ],
            support_boundary: AutonomousPricingSupportBoundary::default(),
            note: Some(
                "Feeds one bounded autonomous pricing decision over Chio truth.".to_string(),
            ),
        }
    }

    fn sample_authority_envelope() -> AutonomousPricingAuthorityEnvelopeArtifact {
        AutonomousPricingAuthorityEnvelopeArtifact {
            schema: CHIO_AUTONOMOUS_PRICING_AUTHORITY_ENVELOPE_SCHEMA.to_string(),
            envelope_id: "ape-1".to_string(),
            issued_at: 1_743_379_200,
            subject_key: "subject-1".to_string(),
            provider_id: "carrier-1".to_string(),
            currency: "USD".to_string(),
            kind: AutonomousAuthorityEnvelopeKind::DelegatedMarketAuthority,
            automation_mode: AutonomousAutomationMode::Active,
            permitted_actions: vec![
                AutonomousPricingAction::Reprice,
                AutonomousPricingAction::Renew,
                AutonomousPricingAction::Decline,
                AutonomousPricingAction::Bind,
            ],
            authority_chain_refs: vec![
                "underwriting-committee-approval".to_string(),
                "operator-treasury-approval".to_string(),
            ],
            max_coverage_amount: MonetaryAmount {
                units: 150_000,
                currency: "USD".to_string(),
            },
            max_premium_amount: MonetaryAmount {
                units: 6_000,
                currency: "USD".to_string(),
            },
            max_rate_change_bps: 750,
            max_daily_decisions: 20,
            requires_human_review_for_bind: false,
            requires_human_review_above_premium: Some(MonetaryAmount {
                units: 5_000,
                currency: "USD".to_string(),
            }),
            regulated_role: None,
            delegated_authority_reference: Some("lpa-1".to_string()),
            not_before: 1_743_379_200,
            not_after: 1_743_465_600,
            support_boundary: AutonomousPricingSupportBoundary::default(),
            note: Some("Binds automation to one delegated pricing authority envelope.".to_string()),
        }
    }

    fn sample_decision() -> AutonomousPricingDecisionArtifact {
        AutonomousPricingDecisionArtifact {
            schema: CHIO_AUTONOMOUS_PRICING_DECISION_SCHEMA.to_string(),
            decision_id: "apd-1".to_string(),
            issued_at: 1_743_379_260,
            pricing_input: sample_input(),
            model: AutonomousModelProvenance {
                model_id: "pricing-model-chio-1".to_string(),
                model_version: "2026.03.31".to_string(),
                engine_family: "gradient_boosted_policy".to_string(),
                published_at: 1_743_379_000,
                training_cutoff: 1_743_292_800,
                input_hash: "4e4efc0ad4f8c80ad4c76f2f3ae2122e9b6cf407cdb2d43516c8f8e4dfd2c1df"
                    .to_string(),
                explanation_version: "counterfactual-v1".to_string(),
                supports_counterfactuals: true,
                supports_shadow_evaluation: true,
            },
            authority_envelope: sample_authority_envelope(),
            disposition: AutonomousPricingDisposition::BindWithinEnvelope,
            review_state: AutonomousDecisionReviewState::AutoApproved,
            suggested_coverage_amount: MonetaryAmount {
                units: 110_000,
                currency: "USD".to_string(),
            },
            suggested_premium_amount: MonetaryAmount {
                units: 4_800,
                currency: "USD".to_string(),
            },
            suggested_ceiling_factor_bps: Some(9_000),
            confidence_bps: 8_700,
            explanation_factors: vec![
                AutonomousPricingExplanationFactor {
                    code: "strong-runtime-assurance".to_string(),
                    description: "Verified runtime assurance supports automated bind posture."
                        .to_string(),
                    direction: AutonomousPricingExplanationDirection::Decrease,
                    weight_bps: 2_500,
                    evidence_refs: vec![AutonomousEvidenceReference {
                        kind: AutonomousEvidenceKind::RuntimeAssuranceAppraisal,
                        reference_id: "raa-1".to_string(),
                        observed_at: Some(1_743_379_000),
                        locator: Some("appraisal:raa-1".to_string()),
                    }],
                },
                AutonomousPricingExplanationFactor {
                    code: "settled-web3-history".to_string(),
                    description:
                        "Recent settled web3 history reduces uncertainty for automated renewal and bind."
                            .to_string(),
                    direction: AutonomousPricingExplanationDirection::Decrease,
                    weight_bps: 2_000,
                    evidence_refs: vec![AutonomousEvidenceReference {
                        kind: AutonomousEvidenceKind::Web3SettlementReceipt,
                        reference_id: "receipt-web3-1".to_string(),
                        observed_at: Some(1_743_379_000),
                        locator: Some("web3-settlement:receipt-web3-1".to_string()),
                    }],
                },
            ],
            comparison_baseline_ref: Some("uwd-1".to_string()),
            note: Some("Auto-approves one renewal/bind decision inside the active envelope.".to_string()),
        }
    }

    fn sample_optimization() -> CapitalPoolOptimizationArtifact {
        CapitalPoolOptimizationArtifact {
            schema: CHIO_CAPITAL_POOL_OPTIMIZATION_SCHEMA.to_string(),
            optimization_id: "cpo-1".to_string(),
            issued_at: 1_743_379_320,
            subject_key: "subject-1".to_string(),
            currency: "USD".to_string(),
            pricing_decision_ref: "apd-1".to_string(),
            capital_book_ref: "cb-1".to_string(),
            facility_refs: vec!["facility-1".to_string(), "facility-2".to_string()],
            pending_claim_refs: vec!["claim-1".to_string()],
            target_reserve_ratio_bps: 3_500,
            max_facility_utilization_bps: 7_000,
            max_bind_capacity_units: 250_000,
            recommendations: vec![
                CapitalPoolRecommendation {
                    action: CapitalOptimizationAction::IncreaseReserve,
                    source_ref: "pool:primary".to_string(),
                    destination_ref: None,
                    amount: MonetaryAmount {
                        units: 25_000,
                        currency: "USD".to_string(),
                    },
                    rationale: "Raise reserve coverage before new autonomous binds.".to_string(),
                },
                CapitalPoolRecommendation {
                    action: CapitalOptimizationAction::ShiftCapacity,
                    source_ref: "facility-2".to_string(),
                    destination_ref: Some("facility-1".to_string()),
                    amount: MonetaryAmount {
                        units: 15_000,
                        currency: "USD".to_string(),
                    },
                    rationale: "Move capacity toward the lower-loss facility.".to_string(),
                },
            ],
            support_boundary: CapitalPoolOptimizationSupportBoundary::default(),
            note: Some("Keeps optimization bounded and override-ready.".to_string()),
        }
    }

    fn sample_simulation() -> CapitalPoolSimulationReport {
        let baseline = sample_optimization();
        let mut candidate = sample_optimization();
        candidate.optimization_id = "cpo-2".to_string();
        candidate.target_reserve_ratio_bps = 4_000;
        candidate.max_bind_capacity_units = 230_000;
        CapitalPoolSimulationReport {
            schema: CHIO_CAPITAL_POOL_SIMULATION_REPORT_SCHEMA.to_string(),
            simulation_id: "cps-1".to_string(),
            generated_at: 1_743_379_380,
            subject_key: "subject-1".to_string(),
            currency: "USD".to_string(),
            baseline_optimization: baseline,
            candidate_optimization: candidate,
            simulation_mode: CapitalPoolSimulationMode::WhatIf,
            deltas: vec![
                CapitalPoolSimulationDelta {
                    metric_name: "reserve_ratio_bps".to_string(),
                    baseline_units: 3_500,
                    candidate_units: 4_000,
                    description: "Candidate scenario raises the reserve floor by 500 bps."
                        .to_string(),
                },
                CapitalPoolSimulationDelta {
                    metric_name: "max_bind_capacity_units".to_string(),
                    baseline_units: 250_000,
                    candidate_units: 230_000,
                    description:
                        "Candidate scenario trims bind capacity to create more reserve headroom."
                            .to_string(),
                },
            ],
            recommended_operator_action:
                "Adopt the candidate reserve posture for the next renewal cohort.".to_string(),
            note: Some(
                "Compares baseline and candidate capital strategies without mutating live state."
                    .to_string(),
            ),
        }
    }

    fn sample_execution_decision() -> AutonomousExecutionDecisionArtifact {
        AutonomousExecutionDecisionArtifact {
            schema: CHIO_AUTONOMOUS_EXECUTION_DECISION_SCHEMA.to_string(),
            execution_id: "aed-1".to_string(),
            issued_at: 1_743_379_440,
            pricing_decision_ref: "apd-1".to_string(),
            optimization_ref: "cpo-1".to_string(),
            authority_envelope_ref: "ape-1".to_string(),
            subject_key: "subject-1".to_string(),
            provider_id: "carrier-1".to_string(),
            currency: "USD".to_string(),
            action: AutonomousExecutionAction::Bind,
            lifecycle_state: AutonomousExecutionLifecycleState::Executed,
            quote_response_ref: Some("quote-response-1".to_string()),
            auto_bind_decision_ref: Some("auto-bind-1".to_string()),
            bound_coverage_ref: Some("bound-coverage-1".to_string()),
            settlement_dispatch_ref: Some("dispatch-web3-1".to_string()),
            safety_gates: vec![
                AutonomousExecutionSafetyGate {
                    name: "authority-within-envelope".to_string(),
                    passed: true,
                    description:
                        "Coverage and premium remain inside the active authority envelope."
                            .to_string(),
                },
                AutonomousExecutionSafetyGate {
                    name: "capital-headroom".to_string(),
                    passed: true,
                    description: "Capital-pool optimization preserved minimum reserve headroom."
                        .to_string(),
                },
            ],
            rollback_control: AutonomousExecutionRollbackControl {
                rollback_plan_ref: "arp-1".to_string(),
                interruptible: true,
                human_interrupt_contact: "ops@chio.example".to_string(),
            },
            note: Some(
                "Executes one bounded autonomous bind over the official web3 lane.".to_string(),
            ),
        }
    }

    fn sample_comparison_report() -> AutonomousComparisonReport {
        AutonomousComparisonReport {
            schema: CHIO_AUTONOMOUS_COMPARISON_REPORT_SCHEMA.to_string(),
            comparison_id: "acr-1".to_string(),
            generated_at: 1_743_379_500,
            pricing_decision_ref: "apd-1".to_string(),
            manual_decision_ref: "uwd-manual-1".to_string(),
            disposition: AutonomousComparisonDisposition::NarrowerThanManual,
            deltas: vec![AutonomousComparisonDelta {
                field: "premium_units".to_string(),
                automated_value: "4800".to_string(),
                manual_value: "5100".to_string(),
                description: "Automation priced inside the manual ceiling.".to_string(),
            }],
            override_reference: None,
            note: Some(
                "Shows automation staying narrower than the comparable manual decision."
                    .to_string(),
            ),
        }
    }

    fn sample_rollback_plan() -> AutonomousRollbackPlanArtifact {
        AutonomousRollbackPlanArtifact {
            schema: CHIO_AUTONOMOUS_ROLLBACK_PLAN_SCHEMA.to_string(),
            plan_id: "arp-1".to_string(),
            issued_at: 1_743_379_560,
            subject_key: "subject-1".to_string(),
            safe_state: AutonomousSafeState::DelegatedOnly,
            triggers: vec![
                AutonomousDriftKind::SettlementFailureRate,
                AutonomousDriftKind::PremiumVariance,
            ],
            actions: vec![
                AutonomousRollbackAction::SwitchToSafeState,
                AutonomousRollbackAction::CancelPendingExecution,
                AutonomousRollbackAction::RequireHumanApproval,
            ],
            requires_operator_ack: true,
            note: Some("Falls back to delegated pricing when automation drifts beyond the accepted envelope.".to_string()),
        }
    }

    fn sample_drift_report() -> AutonomousDriftReport {
        AutonomousDriftReport {
            schema: CHIO_AUTONOMOUS_DRIFT_REPORT_SCHEMA.to_string(),
            drift_report_id: "adr-1".to_string(),
            generated_at: 1_743_379_620,
            subject_key: "subject-1".to_string(),
            pricing_decision_ref: "apd-1".to_string(),
            optimization_ref: "cpo-1".to_string(),
            drift_signals: vec![AutonomousDriftSignal {
                kind: AutonomousDriftKind::SettlementFailureRate,
                severity: AutonomousDriftSeverity::Critical,
                metric_name: "failed_settlement_rate_bps".to_string(),
                observed_value: 275,
                threshold_value: 100,
                description: "Settlement failures exceeded the automation safe-state threshold."
                    .to_string(),
                evidence_refs: vec![AutonomousEvidenceReference {
                    kind: AutonomousEvidenceKind::Web3SettlementReceipt,
                    reference_id: "receipt-web3-1".to_string(),
                    observed_at: Some(1_743_379_000),
                    locator: Some("web3-settlement:receipt-web3-1".to_string()),
                }],
            }],
            rollback_plan: sample_rollback_plan(),
            comparison_report: sample_comparison_report(),
            fail_safe_engaged: true,
            note: Some(
                "Fail-safe engaged after settlement drift breached the critical threshold."
                    .to_string(),
            ),
        }
    }

    #[test]
    fn shadow_mode_requires_shadow_review_state() {
        let mut decision = sample_decision();
        decision.authority_envelope.automation_mode = AutonomousAutomationMode::Shadow;
        decision.authority_envelope.permitted_actions = vec![AutonomousPricingAction::Reprice];
        decision.disposition = AutonomousPricingDisposition::Reprice;
        assert!(matches!(
            validate_autonomous_pricing_decision(&decision),
            Err(AutonomyContractError::InvalidDecision(_))
        ));
    }

    #[test]
    fn capital_pool_simulation_requires_matching_subject() {
        let mut report = sample_simulation();
        report.candidate_optimization.subject_key = "subject-2".to_string();
        assert!(matches!(
            validate_capital_pool_simulation_report(&report),
            Err(AutonomyContractError::InvalidOptimization(_))
        ));
    }

    #[test]
    fn bind_execution_requires_settlement_dispatch_when_executed() {
        let mut execution = sample_execution_decision();
        execution.settlement_dispatch_ref = None;
        assert!(matches!(
            validate_autonomous_execution_decision(&execution),
            Err(AutonomyContractError::MissingField(_))
        ));
    }

    #[test]
    fn critical_drift_requires_fail_safe() {
        let mut report = sample_drift_report();
        report.fail_safe_engaged = false;
        assert!(matches!(
            validate_autonomous_drift_report(&report),
            Err(AutonomyContractError::InvalidDrift(_))
        ));
    }

    #[test]
    fn reference_artifacts_parse_and_validate() {
        let envelope: AutonomousPricingAuthorityEnvelopeArtifact = parse_fixture(
            "CHIO_AUTONOMOUS_PRICING_AUTHORITY_ENVELOPE",
            include_str!("../../../docs/standards/CHIO_AUTONOMOUS_PRICING_AUTHORITY_ENVELOPE.json"),
        );
        let decision: AutonomousPricingDecisionArtifact = parse_fixture(
            "CHIO_AUTONOMOUS_PRICING_DECISION_EXAMPLE",
            include_str!("../../../docs/standards/CHIO_AUTONOMOUS_PRICING_DECISION_EXAMPLE.json"),
        );
        let optimization: CapitalPoolOptimizationArtifact = parse_fixture(
            "CHIO_CAPITAL_POOL_OPTIMIZATION_EXAMPLE",
            include_str!("../../../docs/standards/CHIO_CAPITAL_POOL_OPTIMIZATION_EXAMPLE.json"),
        );
        let simulation: CapitalPoolSimulationReport = parse_fixture(
            "CHIO_CAPITAL_POOL_SIMULATION_EXAMPLE",
            include_str!("../../../docs/standards/CHIO_CAPITAL_POOL_SIMULATION_EXAMPLE.json"),
        );
        let execution: AutonomousExecutionDecisionArtifact = parse_fixture(
            "CHIO_AUTONOMOUS_EXECUTION_EXAMPLE",
            include_str!("../../../docs/standards/CHIO_AUTONOMOUS_EXECUTION_EXAMPLE.json"),
        );
        let comparison: AutonomousComparisonReport = parse_fixture(
            "CHIO_AUTONOMOUS_COMPARISON_REPORT_EXAMPLE",
            include_str!("../../../docs/standards/CHIO_AUTONOMOUS_COMPARISON_REPORT_EXAMPLE.json"),
        );
        let drift: AutonomousDriftReport = parse_fixture(
            "CHIO_AUTONOMOUS_DRIFT_REPORT_EXAMPLE",
            include_str!("../../../docs/standards/CHIO_AUTONOMOUS_DRIFT_REPORT_EXAMPLE.json"),
        );
        let matrix: AutonomousQualificationMatrix = parse_fixture(
            "CHIO_AUTONOMOUS_QUALIFICATION_MATRIX",
            include_str!("../../../docs/standards/CHIO_AUTONOMOUS_QUALIFICATION_MATRIX.json"),
        );

        require_valid(
            validate_autonomous_pricing_authority_envelope(&envelope),
            "autonomous pricing authority envelope",
        );
        require_valid(
            validate_autonomous_pricing_decision(&decision),
            "autonomous pricing decision",
        );
        require_valid(
            validate_capital_pool_optimization(&optimization),
            "capital pool optimization",
        );
        require_valid(
            validate_capital_pool_simulation_report(&simulation),
            "capital pool simulation report",
        );
        require_valid(
            validate_autonomous_execution_decision(&execution),
            "autonomous execution decision",
        );
        require_valid(
            validate_autonomous_comparison_report(&comparison),
            "autonomous comparison report",
        );
        require_valid(
            validate_autonomous_drift_report(&drift),
            "autonomous drift report",
        );
        require_valid(
            validate_autonomous_qualification_matrix(&matrix),
            "autonomous qualification matrix",
        );
    }

    #[test]
    fn pricing_input_requires_capital_book_evidence() {
        let mut input = sample_input();
        input
            .evidence_refs
            .retain(|evidence| evidence.kind != AutonomousEvidenceKind::CapitalBook);
        assert!(matches!(
            validate_autonomous_pricing_input(&input),
            Err(AutonomyContractError::UnknownReference(_))
        ));
    }

    #[test]
    fn pricing_input_requires_web3_evidence_when_settlement_state_present() {
        let mut input = sample_input();
        input
            .evidence_refs
            .retain(|evidence| evidence.kind != AutonomousEvidenceKind::Web3SettlementReceipt);
        assert!(matches!(
            validate_autonomous_pricing_input(&input),
            Err(AutonomyContractError::UnknownReference(_))
        ));
    }

    #[test]
    fn delegated_authority_requires_reference() {
        let mut envelope = sample_authority_envelope();
        envelope.delegated_authority_reference = None;
        assert!(matches!(
            validate_autonomous_pricing_authority_envelope(&envelope),
            Err(AutonomyContractError::MissingField(
                "autonomous_authority_envelope.delegated_authority_reference"
            ))
        ));
    }

    #[test]
    fn non_active_authority_cannot_permit_bind() {
        let mut envelope = sample_authority_envelope();
        envelope.automation_mode = AutonomousAutomationMode::Advisory;
        assert!(matches!(
            validate_autonomous_pricing_authority_envelope(&envelope),
            Err(AutonomyContractError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn pricing_decision_rejects_duplicate_explanation_codes() {
        let mut decision = sample_decision();
        decision
            .explanation_factors
            .push(decision.explanation_factors[0].clone());
        assert!(matches!(
            validate_autonomous_pricing_decision(&decision),
            Err(AutonomyContractError::DuplicateValue(_))
        ));
    }

    #[test]
    fn bind_decision_cannot_auto_approve_when_human_review_required() {
        let mut decision = sample_decision();
        decision.authority_envelope.requires_human_review_for_bind = true;
        assert!(matches!(
            validate_autonomous_pricing_decision(&decision),
            Err(AutonomyContractError::InvalidDecision(_))
        ));
    }

    #[test]
    fn optimization_shift_capacity_requires_destination_ref() {
        let mut optimization = sample_optimization();
        optimization.recommendations[1].destination_ref = None;
        assert!(matches!(
            validate_capital_pool_optimization(&optimization),
            Err(AutonomyContractError::InvalidOptimization(_))
        ));
    }

    #[test]
    fn capital_pool_simulation_requires_scenario_comparison_support() {
        let mut report = sample_simulation();
        report
            .candidate_optimization
            .support_boundary
            .scenario_comparison_supported = false;
        assert!(matches!(
            validate_capital_pool_simulation_report(&report),
            Err(AutonomyContractError::InvalidOptimization(_))
        ));
    }

    #[test]
    fn comparison_report_manual_override_requires_reference() {
        let mut report = sample_comparison_report();
        report.disposition = AutonomousComparisonDisposition::ManualOverride;
        report.override_reference = None;
        assert!(matches!(
            validate_autonomous_comparison_report(&report),
            Err(AutonomyContractError::MissingField(
                "autonomous_comparison.override_reference"
            ))
        ));
    }

    #[test]
    fn rollback_plan_rejects_duplicate_triggers() {
        let mut plan = sample_rollback_plan();
        plan.triggers.push(plan.triggers[0]);
        assert!(matches!(
            validate_autonomous_rollback_plan(&plan),
            Err(AutonomyContractError::DuplicateValue(_))
        ));
    }

    #[test]
    fn qualification_matrix_requires_requirement_ids() {
        let mut matrix: AutonomousQualificationMatrix = parse_fixture(
            "CHIO_AUTONOMOUS_QUALIFICATION_MATRIX",
            include_str!("../../../docs/standards/CHIO_AUTONOMOUS_QUALIFICATION_MATRIX.json"),
        );
        matrix.cases[0].requirement_ids.clear();
        assert!(matches!(
            validate_autonomous_qualification_matrix(&matrix),
            Err(AutonomyContractError::InvalidQualificationCase(_))
        ));
    }

    #[test]
    fn pricing_decision_rejects_future_training_cutoff() {
        let mut decision = sample_decision();
        decision.model.training_cutoff = decision.model.published_at + 1;
        assert!(matches!(
            validate_autonomous_pricing_decision(&decision),
            Err(AutonomyContractError::InvalidDecision(_))
        ));
    }
}
