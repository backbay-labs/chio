//! Credit, capital, and bonded-execution contracts for the Chio protocol.
//!
//! This crate models credit limits, IOUs, and bonded execution for metered
//! tool access. It defines the credit-evaluator hook and IOU envelope types, a
//! local credit account that mints signed IOUs, an exposure ledger, and an IOU
//! envelope store binding. It composes the appraisal and underwriting surfaces
//! so credit decisions reference prior signed Chio truth rather than restating
//! it.
//!
//! # Modules
//!
//! - [`hook`] -- credit-evaluator hook and the IOU envelope types.
//! - [`local_account`] -- in-memory account that signs IOU envelopes.
//! - [`risk_reports`] -- loss-lifecycle, backtest, and provider-risk reports.
//! - [`store_binding`] -- durable-store trait for persisting IOU envelopes.

#![forbid(unsafe_code)]

pub use chio_appraisal as appraisal;
pub use chio_core_types::{capability, crypto, receipt};
pub use chio_underwriting as underwriting;

pub mod clearing;
pub mod factor;
pub mod financial_credentials;
pub mod hook;
pub mod iou_v2;
pub mod local_account;
pub mod obligation;
pub mod risk_reports;
pub mod store_binding;

pub use hook::{
    CreditEvaluatorError, CreditEvaluatorHook, IouEnvelope, IouEnvelopeBody, IOU_ENVELOPE_SCHEMA,
};
pub use iou_v2::{
    verify_iou_envelope_v2, IouEnvelopeBodyV2, IouEnvelopeCryptoFloorV2, IouEnvelopeIssuerTrustV2,
    IouEnvelopeMintContextV2, IouEnvelopeReceiptTrustV2, IouEnvelopeV2Error,
    IouEnvelopeVerificationContextV2, SignedIouEnvelopeV2, VerifiedIouEnvelopeV2,
    CHIO_RECEIVABLE_IOU_ENVELOPE_V1_SCHEMA, RECEIVABLE_IOU_ENVELOPE_V1_SCHEMA,
};
pub use local_account::LocalCreditAccount;
pub use risk_reports::{
    CreditBacktestQuery, CreditBacktestReasonCode, CreditBacktestReport, CreditBacktestSummary,
    CreditBacktestWindow, CreditCertificationState, CreditLossLifecycleArtifact,
    CreditLossLifecycleEventKind, CreditLossLifecycleFinding, CreditLossLifecycleListQuery,
    CreditLossLifecycleListReport, CreditLossLifecycleListSummary, CreditLossLifecycleQuery,
    CreditLossLifecycleReasonCode, CreditLossLifecycleReport, CreditLossLifecycleRow,
    CreditLossLifecycleSummary, CreditLossLifecycleSupportBoundary, CreditProviderFacilitySnapshot,
    CreditProviderRiskPackage, CreditProviderRiskPackageQuery,
    CreditProviderRiskPackageSupportBoundary, CreditRecentLossEntry, CreditRecentLossHistory,
    CreditRecentLossSummary, CreditReserveControlAppealState, CreditReserveControlExecutionState,
    CreditRuntimeAssuranceState, SignedCreditLossLifecycle, SignedCreditProviderRiskPackage,
};
pub use store_binding::{IouEnvelopeStore, IouEnvelopeStoreError};

use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::appraisal::AttestationVerifierFamily;
use crate::capability::{
    governance::GovernedAutonomyTier, runtime_attestation::RuntimeAssuranceTier,
    scope::MonetaryAmount,
};
use crate::receipt::{
    decision::Decision, economics::SettlementStatus, lineage::SignedExportEnvelope,
};
use crate::underwriting::{
    UnderwritingDecisionLifecycleState, UnderwritingDecisionOutcome, UnderwritingReviewState,
    UnderwritingRiskClass,
};

pub const EXPOSURE_LEDGER_SCHEMA: &str = "chio.credit.exposure-ledger.v1";
pub const CREDIT_SCORECARD_SCHEMA: &str = "chio.credit.scorecard.v1";
pub const CREDIT_FACILITY_REPORT_SCHEMA: &str = "chio.credit.facility-report.v1";
pub const CREDIT_FACILITY_ARTIFACT_SCHEMA: &str = "chio.credit.facility.v1";
pub const CREDIT_FACILITY_LIST_REPORT_SCHEMA: &str = "chio.credit.facility-list.v1";
pub const CREDIT_BOND_REPORT_SCHEMA: &str = "chio.credit.bond-report.v1";
pub const CREDIT_BOND_ARTIFACT_SCHEMA: &str = "chio.credit.bond.v1";
pub const CREDIT_BOND_LIST_REPORT_SCHEMA: &str = "chio.credit.bond-list.v1";
pub const CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA: &str = "chio.credit.loss-lifecycle-report.v1";
pub const CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA: &str = "chio.credit.loss-lifecycle.v1";
pub const CREDIT_LOSS_LIFECYCLE_LIST_REPORT_SCHEMA: &str = "chio.credit.loss-lifecycle-list.v1";
pub const CREDIT_BACKTEST_REPORT_SCHEMA: &str = "chio.credit.backtest-report.v1";
pub const CREDIT_PROVIDER_RISK_PACKAGE_SCHEMA: &str = "chio.credit.provider-risk-package.v1";
pub const CAPITAL_BOOK_REPORT_SCHEMA: &str = "chio.credit.capital-book.v1";
pub const CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA: &str =
    "chio.credit.capital-instruction.v1";
pub const CAPITAL_EXECUTION_AUTHORITY_STEP_PROOF_SCHEMA: &str =
    "chio.credit.capital-authority-step-proof.v1";
pub const CAPITAL_ALLOCATION_DECISION_ARTIFACT_SCHEMA: &str = "chio.credit.capital-allocation.v1";
pub const CREDIT_BONDED_EXECUTION_SIMULATION_REPORT_SCHEMA: &str =
    "chio.credit.bonded-execution-simulation-report.v1";
pub const MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT: usize = 200;
pub const MAX_EXPOSURE_LEDGER_DECISION_LIMIT: usize = 200;
pub const MAX_CREDIT_FACILITY_LIST_LIMIT: usize = 100;
pub const MAX_CREDIT_BOND_LIST_LIMIT: usize = 100;
pub const MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT: usize = 100;
pub const MAX_CREDIT_BACKTEST_WINDOW_LIMIT: usize = 24;
pub const MAX_CREDIT_PROVIDER_LOSS_LIMIT: usize = 25;

pub(crate) fn bounded_limit_or_default(limit: Option<usize>, default: usize, max: usize) -> usize {
    limit.unwrap_or(default).clamp(1, max)
}

fn validate_optional_query_filter(
    value: &Option<String>,
    flag: &'static str,
) -> Result<(), String> {
    if let Some(value) = value {
        if value.trim().is_empty() {
            return Err(format!(
                "exposure ledger query filter {flag} must be non-empty"
            ));
        }
        if value.trim() != value {
            return Err(format!(
                "exposure ledger query filter {flag} must not contain surrounding whitespace"
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExposureLedgerQuery {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_limit: Option<usize>,
}

impl Default for ExposureLedgerQuery {
    fn default() -> Self {
        Self {
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            since: None,
            until: None,
            receipt_limit: Some(100),
            decision_limit: Some(50),
        }
    }
}

impl ExposureLedgerQuery {
    #[must_use]
    pub fn receipt_limit_or_default(&self) -> usize {
        bounded_limit_or_default(self.receipt_limit, 100, MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT)
    }

    #[must_use]
    pub fn decision_limit_or_default(&self) -> usize {
        bounded_limit_or_default(self.decision_limit, 50, MAX_EXPOSURE_LEDGER_DECISION_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.receipt_limit = Some(self.receipt_limit_or_default());
        normalized.decision_limit = Some(self.decision_limit_or_default());
        normalized
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_optional_query_filter(&self.capability_id, "--capability")?;
        validate_optional_query_filter(&self.agent_subject, "--agent-subject")?;
        validate_optional_query_filter(&self.tool_server, "--tool-server")?;
        validate_optional_query_filter(&self.tool_name, "--tool-name")?;
        if self.capability_id.is_none()
            && self.agent_subject.is_none()
            && self.tool_server.is_none()
        {
            return Err(
                "exposure ledger queries require at least one anchor: --capability, --agent-subject, or --tool-server".to_string(),
            );
        }
        if self.tool_name.is_some() && self.tool_server.is_none() {
            return Err(
                "exposure ledger queries that specify --tool-name must also specify --tool-server"
                    .to_string(),
            );
        }
        if let (Some(since), Some(until)) = (self.since, self.until) {
            if since > until {
                return Err(
                    "exposure ledger queries require --since to be less than or equal to --until"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExposureLedgerEvidenceKind {
    Receipt,
    SettlementReconciliation,
    MeteredBillingReconciliation,
    UnderwritingDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExposureLedgerEvidenceReference {
    pub kind: ExposureLedgerEvidenceKind,
    pub reference_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExposureLedgerSupportBoundary {
    pub governed_receipts_authoritative: bool,
    pub underwriting_decisions_authoritative: bool,
    pub settlement_reconciliation_authoritative: bool,
    pub cross_currency_netting_supported: bool,
    pub claim_adjudication_supported: bool,
    pub recovery_lifecycle_supported: bool,
}

impl Default for ExposureLedgerSupportBoundary {
    fn default() -> Self {
        Self {
            governed_receipts_authoritative: true,
            underwriting_decisions_authoritative: true,
            settlement_reconciliation_authoritative: true,
            cross_currency_netting_supported: false,
            claim_adjudication_supported: false,
            recovery_lifecycle_supported: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExposureLedgerCurrencyPosition {
    pub currency: String,
    pub governed_max_exposure_units: u64,
    pub reserved_units: u64,
    pub settled_units: u64,
    pub pending_units: u64,
    pub failed_units: u64,
    pub provisional_loss_units: u64,
    pub recovered_units: u64,
    pub quoted_premium_units: u64,
    pub active_quoted_premium_units: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExposureLedgerReceiptEntry {
    pub receipt_id: String,
    pub timestamp: u64,
    pub capability_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_key: Option<String>,
    pub tool_server: String,
    pub tool_name: String,
    pub decision: Decision,
    pub settlement_status: SettlementStatus,
    pub action_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_max_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub financial_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserve_required_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisional_loss_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovered_amount: Option<MonetaryAmount>,
    pub metered_action_required: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<ExposureLedgerEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExposureLedgerDecisionEntry {
    pub decision_id: String,
    pub issued_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    pub outcome: UnderwritingDecisionOutcome,
    pub lifecycle_state: UnderwritingDecisionLifecycleState,
    pub review_state: UnderwritingReviewState,
    pub risk_class: UnderwritingRiskClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_decision_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quoted_premium_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<ExposureLedgerEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExposureLedgerSummary {
    pub matching_receipts: u64,
    pub returned_receipts: u64,
    pub matching_decisions: u64,
    pub returned_decisions: u64,
    pub active_decisions: u64,
    pub superseded_decisions: u64,
    pub actionable_receipts: u64,
    pub pending_settlement_receipts: u64,
    pub failed_settlement_receipts: u64,
    pub currencies: Vec<String>,
    pub mixed_currency_book: bool,
    pub truncated_receipts: bool,
    pub truncated_decisions: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExposureLedgerReport {
    pub schema: String,
    pub generated_at: u64,
    pub filters: ExposureLedgerQuery,
    pub support_boundary: ExposureLedgerSupportBoundary,
    pub summary: ExposureLedgerSummary,
    pub positions: Vec<ExposureLedgerCurrencyPosition>,
    pub receipts: Vec<ExposureLedgerReceiptEntry>,
    pub decisions: Vec<ExposureLedgerDecisionEntry>,
}

pub type SignedExposureLedgerReport = SignedExportEnvelope<ExposureLedgerReport>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditScorecardConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditScorecardBand {
    Prime,
    Standard,
    Guarded,
    Probationary,
    Restricted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditScorecardDimensionKind {
    ReputationSupport,
    SettlementDiscipline,
    LossPressure,
    ExposureStewardship,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditScorecardReasonCode {
    SparseReceiptHistory,
    SparseDayHistory,
    LowConfidence,
    PendingSettlementBacklog,
    FailedSettlementBacklog,
    ProvisionalLossPressure,
    MixedCurrencyBook,
    LowReputation,
    ImportedTrustDependency,
    MissingDecisionCoverage,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditScorecardAnomalySeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditScorecardEvidenceKind {
    Receipt,
    SettlementReconciliation,
    UnderwritingDecision,
    ReputationInspection,
    ComplianceScore,
    ExposureLedger,
    CreditBond,
    CreditLossLifecycle,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditScorecardEvidenceReference {
    pub kind: CreditScorecardEvidenceKind,
    pub reference_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditScorecardSupportBoundary {
    pub subject_scoped_only: bool,
    pub cross_currency_netting_supported: bool,
    pub capital_allocation_supported: bool,
    pub facility_policy_supported: bool,
}

impl Default for CreditScorecardSupportBoundary {
    fn default() -> Self {
        Self {
            subject_scoped_only: true,
            cross_currency_netting_supported: false,
            capital_allocation_supported: false,
            facility_policy_supported: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditScorecardDimension {
    pub kind: CreditScorecardDimensionKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    pub weight: f64,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CreditScorecardEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditScorecardProbationStatus {
    pub probationary: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<CreditScorecardReasonCode>,
    pub receipt_count: u64,
    pub span_days: u64,
    pub target_receipt_count: u64,
    pub target_span_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditScorecardAnomaly {
    pub code: CreditScorecardReasonCode,
    pub severity: CreditScorecardAnomalySeverity,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CreditScorecardEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditScorecardReputationContext {
    pub effective_score: f64,
    pub probationary: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_tier: Option<String>,
    pub imported_signal_count: usize,
    pub accepted_imported_signal_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditScorecardSummary {
    pub matching_receipts: u64,
    pub returned_receipts: u64,
    pub matching_decisions: u64,
    pub returned_decisions: u64,
    pub currencies: Vec<String>,
    pub mixed_currency_book: bool,
    pub confidence: CreditScorecardConfidence,
    pub band: CreditScorecardBand,
    pub overall_score: f64,
    pub anomaly_count: u64,
    pub probationary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditScorecardReport {
    pub schema: String,
    pub generated_at: u64,
    pub filters: ExposureLedgerQuery,
    pub support_boundary: CreditScorecardSupportBoundary,
    pub summary: CreditScorecardSummary,
    pub reputation: CreditScorecardReputationContext,
    pub positions: Vec<ExposureLedgerCurrencyPosition>,
    pub probation: CreditScorecardProbationStatus,
    pub dimensions: Vec<CreditScorecardDimension>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anomalies: Vec<CreditScorecardAnomaly>,
}

pub type SignedCreditScorecardReport = SignedExportEnvelope<CreditScorecardReport>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditFacilityDisposition {
    Grant,
    ManualReview,
    Deny,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditFacilityLifecycleState {
    Active,
    Superseded,
    Denied,
    Expired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditFacilityCapitalSource {
    OperatorInternal,
    ManualProviderReview,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditFacilityReasonCode {
    ScoreRestricted,
    ProbationaryScore,
    LowConfidence,
    MixedCurrencyBook,
    MixedRuntimeAssuranceProvenance,
    MissingRuntimeAssurance,
    CertificationNotActive,
    FailedSettlementBacklog,
    PendingSettlementBacklog,
    FacilityGranted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityTerms {
    pub credit_limit: MonetaryAmount,
    pub utilization_ceiling_bps: u16,
    pub reserve_ratio_bps: u16,
    pub concentration_cap_bps: u16,
    pub ttl_seconds: u64,
    pub capital_source: CreditFacilityCapitalSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityPrerequisites {
    pub minimum_runtime_assurance_tier: RuntimeAssuranceTier,
    pub runtime_assurance_met: bool,
    pub certification_required: bool,
    pub certification_met: bool,
    pub manual_review_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityFinding {
    pub code: CreditFacilityReasonCode,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CreditScorecardEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilitySupportBoundary {
    pub provider_neutral_policy: bool,
    pub cross_currency_allocation_supported: bool,
    pub bond_execution_supported: bool,
}

impl Default for CreditFacilitySupportBoundary {
    fn default() -> Self {
        Self {
            provider_neutral_policy: true,
            cross_currency_allocation_supported: false,
            bond_execution_supported: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityReport {
    pub schema: String,
    pub generated_at: u64,
    pub filters: ExposureLedgerQuery,
    pub scorecard: CreditScorecardSummary,
    pub disposition: CreditFacilityDisposition,
    pub prerequisites: CreditFacilityPrerequisites,
    pub support_boundary: CreditFacilitySupportBoundary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms: Option<CreditFacilityTerms>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<CreditFacilityFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityArtifact {
    pub schema: String,
    pub facility_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub lifecycle_state: CreditFacilityLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_facility_id: Option<String>,
    pub report: CreditFacilityReport,
}

pub type SignedCreditFacility = SignedExportEnvelope<CreditFacilityArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityListQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<CreditFacilityDisposition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<CreditFacilityLifecycleState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl Default for CreditFacilityListQuery {
    fn default() -> Self {
        Self {
            facility_id: None,
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            disposition: None,
            lifecycle_state: None,
            limit: Some(50),
        }
    }
}

impl CreditFacilityListQuery {
    #[must_use]
    pub fn limit_or_default(&self) -> usize {
        bounded_limit_or_default(self.limit, 50, MAX_CREDIT_FACILITY_LIST_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.limit = Some(self.limit_or_default());
        normalized
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityRow {
    pub facility: SignedCreditFacility,
    pub lifecycle_state: CreditFacilityLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by_facility_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityListSummary {
    pub matching_facilities: u64,
    pub returned_facilities: u64,
    pub active_facilities: u64,
    pub superseded_facilities: u64,
    pub denied_facilities: u64,
    pub expired_facilities: u64,
    pub granted_facilities: u64,
    pub manual_review_facilities: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityListReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: CreditFacilityListQuery,
    pub summary: CreditFacilityListSummary,
    pub facilities: Vec<CreditFacilityRow>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditBondDisposition {
    Lock,
    Hold,
    Release,
    Impair,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditBondLifecycleState {
    Active,
    Superseded,
    Released,
    Impaired,
    Expired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditBondReasonCode {
    ActiveFacilityMissing,
    MixedCurrencyBook,
    PendingSettlementBacklog,
    FailedSettlementBacklog,
    ProvisionalLossOutstanding,
    ReserveLocked,
    ReserveHeld,
    ReserveReleased,
    UnderCollateralized,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondTerms {
    pub facility_id: String,
    pub credit_limit: MonetaryAmount,
    pub collateral_amount: MonetaryAmount,
    pub reserve_requirement_amount: MonetaryAmount,
    pub outstanding_exposure_amount: MonetaryAmount,
    pub reserve_ratio_bps: u16,
    pub coverage_ratio_bps: u16,
    pub capital_source: CreditFacilityCapitalSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondPrerequisites {
    pub active_facility_required: bool,
    pub active_facility_met: bool,
    pub runtime_assurance_met: bool,
    pub certification_required: bool,
    pub certification_met: bool,
    pub currency_coherent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondFinding {
    pub code: CreditBondReasonCode,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CreditScorecardEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondSupportBoundary {
    pub reserve_accounting_authoritative: bool,
    pub external_escrow_execution_supported: bool,
    pub autonomy_gating_supported: bool,
}

impl Default for CreditBondSupportBoundary {
    fn default() -> Self {
        Self {
            reserve_accounting_authoritative: true,
            external_escrow_execution_supported: false,
            autonomy_gating_supported: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondReport {
    pub schema: String,
    pub generated_at: u64,
    pub filters: ExposureLedgerQuery,
    pub exposure: ExposureLedgerSummary,
    pub scorecard: CreditScorecardSummary,
    pub disposition: CreditBondDisposition,
    pub prerequisites: CreditBondPrerequisites,
    pub support_boundary: CreditBondSupportBoundary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_facility_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms: Option<CreditBondTerms>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<CreditBondFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondArtifact {
    pub schema: String,
    pub bond_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub lifecycle_state: CreditBondLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_bond_id: Option<String>,
    pub report: CreditBondReport,
}

pub type SignedCreditBond = SignedExportEnvelope<CreditBondArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondListQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facility_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<CreditBondDisposition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<CreditBondLifecycleState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl Default for CreditBondListQuery {
    fn default() -> Self {
        Self {
            bond_id: None,
            facility_id: None,
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            disposition: None,
            lifecycle_state: None,
            limit: Some(50),
        }
    }
}

impl CreditBondListQuery {
    #[must_use]
    pub fn limit_or_default(&self) -> usize {
        bounded_limit_or_default(self.limit, 50, MAX_CREDIT_BOND_LIST_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.limit = Some(self.limit_or_default());
        normalized
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondRow {
    pub bond: SignedCreditBond,
    pub lifecycle_state: CreditBondLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by_bond_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondListSummary {
    pub matching_bonds: u64,
    pub returned_bonds: u64,
    pub active_bonds: u64,
    pub superseded_bonds: u64,
    pub released_bonds: u64,
    pub impaired_bonds: u64,
    pub expired_bonds: u64,
    pub locked_bonds: u64,
    pub held_bonds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondListReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: CreditBondListQuery,
    pub summary: CreditBondListSummary,
    pub bonds: Vec<CreditBondRow>,
}

include!("credit/capital_and_execution.rs");
