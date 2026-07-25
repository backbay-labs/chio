//! Underwriting decision, simulation, and appeal contracts for the Chio
//! protocol.
//!
//! This crate computes underwriting decisions and premiums from signed Chio
//! evidence; `chio-market` and `chio-credit` consume its outputs. It defines
//! the risk taxonomy and reason codes, evidence references (receipt,
//! reputation, certification), the deterministic premium-pricing model
//! (`price_premium`, risk multipliers, decline reasons), and reputation-tiered
//! marketplace credit limits. It builds on the appraisal surface.
//!
//! # Modules
//!
//! - [`decision`] -- decision policy, artifacts, evaluator, lists, and simulations.
//! - [`premium`] -- premium pricing, risk multipliers, and decline floors.
//! - [`marketplace_limits`] -- reputation-tiered marketplace credit limits.

#![forbid(unsafe_code)]

pub use chio_appraisal as appraisal;
pub use chio_core_types::{canonical, capability, crypto, receipt};

pub mod decision;
pub mod marketplace_limits;
pub mod premium;
pub use decision::{
    build_fiscal_underwriting_decision_artifact, build_underwriting_decision_artifact,
    evaluate_underwriting_policy_input, self_test_fiscal_decision_premium_adapter,
    FiscalDecisionPremiumSchedule, FiscalUnderwritingDecisionError, SignedUnderwritingDecision,
    UnderwritingBudgetAction, UnderwritingBudgetRecommendation, UnderwritingDecisionArtifact,
    UnderwritingDecisionFinding, UnderwritingDecisionLifecycleState,
    UnderwritingDecisionListReport, UnderwritingDecisionOutcome, UnderwritingDecisionPolicy,
    UnderwritingDecisionQuery, UnderwritingDecisionReasonCode, UnderwritingDecisionReport,
    UnderwritingDecisionRow, UnderwritingDecisionSummary, UnderwritingPremiumQuote,
    UnderwritingPremiumState, UnderwritingRemediation, UnderwritingReviewState,
    UnderwritingSimulationDelta, UnderwritingSimulationReport, UnderwritingSimulationRequest,
    APPROVE_PREMIUM_BASIS_POINTS, REDUCE_CEILING_PREMIUM_BASIS_POINTS,
};
pub use marketplace_limits::{
    compute_fiscal_marketplace_credit_limit, compute_marketplace_credit_limit,
    self_test_fiscal_tier_limits_adapter, FiscalTierLimits, MarketplaceCreditLimitDecision,
    MarketplaceCreditLimitRequest, MarketplaceLimitTier, MARKETPLACE_TIER_LIMIT_CURRENCY,
    MARKETPLACE_TIER_LIMIT_UNITS,
};
pub use premium::{
    price_fiscal_premium, price_premium, risk_multiplier,
    self_test_fiscal_insurance_premium_adapter, FiscalInsurancePremiumSchedule, LookbackWindow,
    PremiumDeclineReason, PremiumInputs, PremiumQuote, DEFAULT_BEHAVIORAL_PENALTY_CAP,
    DEFAULT_BEHAVIORAL_PENALTY_PER_SIGMA, PREMIUM_DECLINE_FLOOR, PREMIUM_HIGH_RISK_FLOOR,
    PREMIUM_LOW_RISK_FLOOR, PREMIUM_MEDIUM_RISK_FLOOR,
};

use serde::{Deserialize, Serialize};

use crate::appraisal::AttestationVerifierFamily;
use crate::capability::runtime_attestation::RuntimeAssuranceTier;
use crate::receipt::lineage::SignedExportEnvelope;

pub const UNDERWRITING_POLICY_INPUT_SCHEMA: &str = "chio.underwriting.policy-input.v1";
pub const UNDERWRITING_COMPLIANCE_EVIDENCE_SCHEMA: &str =
    "chio.underwriting.compliance-evidence.v1";
pub const UNDERWRITING_RISK_TAXONOMY_VERSION: &str = "chio.underwriting.taxonomy.v1";
pub const UNDERWRITING_DECISION_POLICY_SCHEMA: &str = "chio.underwriting.decision-policy.v1";
pub const UNDERWRITING_DECISION_POLICY_VERSION: &str =
    "chio.underwriting.decision-policy.default.v1";
pub const UNDERWRITING_DECISION_REPORT_SCHEMA: &str = "chio.underwriting.decision-report.v1";
pub const UNDERWRITING_SIMULATION_REPORT_SCHEMA: &str = "chio.underwriting.simulation-report.v1";
pub const UNDERWRITING_DECISION_ARTIFACT_SCHEMA: &str = "chio.underwriting.decision.v1";
pub const UNDERWRITING_APPEAL_SCHEMA: &str = "chio.underwriting.appeal.v1";
pub const MAX_UNDERWRITING_RECEIPT_LIMIT: usize = 200;
pub const MAX_UNDERWRITING_DECISION_LIMIT: usize = 200;

pub(crate) fn bounded_underwriting_limit(
    limit: Option<usize>,
    default: usize,
    max: usize,
) -> usize {
    limit.unwrap_or(default).clamp(1, max)
}

fn validate_optional_underwriting_filter(value: Option<&str>, field: &str) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if value.trim() != value {
        return Err(format!("{field} must not contain surrounding whitespace"));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum UnderwritingRiskClass {
    Baseline,
    Guarded,
    Elevated,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnderwritingReasonCode {
    ProbationaryHistory,
    LowReputation,
    ImportedTrustDependency,
    MissingCertification,
    FailedCertification,
    RevokedCertification,
    MissingRuntimeAssurance,
    WeakRuntimeAssurance,
    PendingSettlementExposure,
    FailedSettlementExposure,
    MeteredBillingMismatch,
    DelegatedCallChain,
    SharedEvidenceProofRequired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnderwritingEvidenceKind {
    Receipt,
    ReputationInspection,
    CertificationArtifact,
    RuntimeAssuranceEvidence,
    SettlementReconciliation,
    MeteredBillingReconciliation,
    SharedEvidenceReference,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingEvidenceReference {
    pub kind: UnderwritingEvidenceKind,
    pub reference_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingSignal {
    pub class: UnderwritingRiskClass,
    pub reason: UnderwritingReasonCode,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<UnderwritingEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnderwritingCertificationState {
    Active,
    Superseded,
    Revoked,
    NotFound,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingRiskTaxonomy {
    pub version: String,
    pub supported_classes: Vec<UnderwritingRiskClass>,
    pub supported_reasons: Vec<UnderwritingReasonCode>,
}

impl Default for UnderwritingRiskTaxonomy {
    fn default() -> Self {
        Self {
            version: UNDERWRITING_RISK_TAXONOMY_VERSION.to_string(),
            supported_classes: vec![
                UnderwritingRiskClass::Baseline,
                UnderwritingRiskClass::Guarded,
                UnderwritingRiskClass::Elevated,
                UnderwritingRiskClass::Critical,
            ],
            supported_reasons: vec![
                UnderwritingReasonCode::ProbationaryHistory,
                UnderwritingReasonCode::LowReputation,
                UnderwritingReasonCode::ImportedTrustDependency,
                UnderwritingReasonCode::MissingCertification,
                UnderwritingReasonCode::FailedCertification,
                UnderwritingReasonCode::RevokedCertification,
                UnderwritingReasonCode::MissingRuntimeAssurance,
                UnderwritingReasonCode::WeakRuntimeAssurance,
                UnderwritingReasonCode::PendingSettlementExposure,
                UnderwritingReasonCode::FailedSettlementExposure,
                UnderwritingReasonCode::MeteredBillingMismatch,
                UnderwritingReasonCode::DelegatedCallChain,
                UnderwritingReasonCode::SharedEvidenceProofRequired,
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingReceiptEvidence {
    pub matching_receipts: u64,
    pub returned_receipts: u64,
    pub allow_count: u64,
    pub deny_count: u64,
    pub cancelled_count: u64,
    pub incomplete_count: u64,
    pub governed_receipts: u64,
    pub approval_receipts: u64,
    pub approved_receipts: u64,
    pub call_chain_receipts: u64,
    pub runtime_assurance_receipts: u64,
    pub pending_settlement_receipts: u64,
    pub failed_settlement_receipts: u64,
    pub actionable_settlement_receipts: u64,
    pub metered_receipts: u64,
    pub actionable_metered_receipts: u64,
    pub shared_evidence_reference_count: u64,
    pub shared_evidence_proof_required_count: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipt_refs: Vec<UnderwritingEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingReputationEvidence {
    pub subject_key: String,
    pub effective_score: f64,
    pub probationary: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_tier: Option<String>,
    pub imported_signal_count: usize,
    pub accepted_imported_signal_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingCertificationEvidence {
    pub tool_server_id: String,
    pub state: UnderwritingCertificationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingRuntimeAssuranceEvidence {
    pub governed_receipts: u64,
    pub runtime_assurance_receipts: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highest_tier: Option<RuntimeAssuranceTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_verifier_family: Option<AttestationVerifierFamily>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_verifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_evidence_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_verifier_families: Vec<AttestationVerifierFamily>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingComplianceEvidence {
    pub schema: String,
    pub agent_id: String,
    pub score: u32,
    pub generated_at: u64,
    pub total_receipts: u64,
    pub deny_receipts: u64,
    pub observed_capabilities: u64,
    pub revoked_capabilities: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_age_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingPolicyInputQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_limit: Option<usize>,
}

impl Default for UnderwritingPolicyInputQuery {
    fn default() -> Self {
        Self {
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            since: None,
            until: None,
            receipt_limit: Some(100),
        }
    }
}

impl UnderwritingPolicyInputQuery {
    #[must_use]
    pub fn receipt_limit_or_default(&self) -> usize {
        bounded_underwriting_limit(self.receipt_limit, 100, MAX_UNDERWRITING_RECEIPT_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.receipt_limit = Some(self.receipt_limit_or_default());
        normalized
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_optional_underwriting_filter(self.capability_id.as_deref(), "capability_id")?;
        validate_optional_underwriting_filter(self.agent_subject.as_deref(), "agent_subject")?;
        validate_optional_underwriting_filter(self.tool_server.as_deref(), "tool_server")?;
        validate_optional_underwriting_filter(self.tool_name.as_deref(), "tool_name")?;
        if self.capability_id.is_none()
            && self.agent_subject.is_none()
            && self.tool_server.is_none()
        {
            return Err(
                "underwriting input queries require at least one anchor: --capability, --agent-subject, or --tool-server".to_string(),
            );
        }
        if self.tool_name.is_some() && self.tool_server.is_none() {
            return Err(
                "underwriting input queries that specify --tool-name must also specify --tool-server"
                    .to_string(),
            );
        }
        if matches!((self.since, self.until), (Some(since), Some(until)) if since > until) {
            return Err("underwriting input query has since > until".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingPolicyInput {
    pub schema: String,
    pub generated_at: u64,
    pub filters: UnderwritingPolicyInputQuery,
    pub taxonomy: UnderwritingRiskTaxonomy,
    pub receipts: UnderwritingReceiptEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reputation: Option<UnderwritingReputationEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certification: Option<UnderwritingCertificationEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance: Option<UnderwritingRuntimeAssuranceEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_score: Option<UnderwritingComplianceEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<UnderwritingSignal>,
}

pub type SignedUnderwritingPolicyInput = SignedExportEnvelope<UnderwritingPolicyInput>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnderwritingAppealStatus {
    Open,
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingAppealRecord {
    pub schema: String,
    pub appeal_id: String,
    pub decision_id: String,
    pub requested_by: String,
    pub reason: String,
    pub status: UnderwritingAppealStatus,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_decision_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingAppealCreateRequest {
    pub decision_id: String,
    pub requested_by: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnderwritingAppealResolution {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingAppealResolveRequest {
    pub appeal_id: String,
    pub resolution: UnderwritingAppealResolution,
    pub resolved_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_decision_id: Option<String>,
}
