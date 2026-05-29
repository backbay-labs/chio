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
//! - [`store_binding`] -- durable-store trait for persisting IOU envelopes.

#![forbid(unsafe_code)]

pub use chio_appraisal as appraisal;
pub use chio_core_types::{capability, crypto, receipt};
pub use chio_underwriting as underwriting;

pub mod hook;
pub mod local_account;
pub mod store_binding;

pub use hook::{
    CreditEvaluatorError, CreditEvaluatorHook, IouEnvelope, IouEnvelopeBody, IOU_ENVELOPE_SCHEMA,
};
pub use local_account::LocalCreditAccount;
pub use store_binding::{IouEnvelopeStore, IouEnvelopeStoreError};

use serde::{Deserialize, Serialize};

use crate::appraisal::AttestationVerifierFamily;
use crate::capability::{GovernedAutonomyTier, MonetaryAmount, RuntimeAssuranceTier};
use crate::receipt::{Decision, SettlementStatus, SignedExportEnvelope};
use crate::underwriting::{
    UnderwritingCertificationState, UnderwritingComplianceEvidence,
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
        self.receipt_limit
            .unwrap_or(100)
            .clamp(1, MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT)
    }

    #[must_use]
    pub fn decision_limit_or_default(&self) -> usize {
        self.decision_limit
            .unwrap_or(50)
            .clamp(1, MAX_EXPOSURE_LEDGER_DECISION_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.receipt_limit = Some(self.receipt_limit_or_default());
        normalized.decision_limit = Some(self.decision_limit_or_default());
        normalized
    }

    pub fn validate(&self) -> Result<(), String> {
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
        self.limit
            .unwrap_or(50)
            .clamp(1, MAX_CREDIT_FACILITY_LIST_LIMIT)
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
        self.limit
            .unwrap_or(50)
            .clamp(1, MAX_CREDIT_BOND_LIST_LIMIT)
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditLossLifecycleEventKind {
    Delinquency,
    Recovery,
    ReserveRelease,
    ReserveSlash,
    WriteOff,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditLossLifecycleReasonCode {
    ActiveBondRequired,
    BondNotActive,
    DelinquencyEvidenceMissing,
    OutstandingDelinquencyRequired,
    AmountRequired,
    AmountCurrencyMismatch,
    AmountExceedsOutstandingDelinquency,
    OutstandingExposureBlocksReserveRelease,
    ReserveAlreadyReleased,
    DelinquencyRecorded,
    RecoveryRecorded,
    ReserveReleased,
    ReserveSlashed,
    WriteOffRecorded,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditReserveControlExecutionState {
    PendingExecution,
    Executed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditReserveControlAppealState {
    Unsupported,
    Open,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleQuery {
    pub bond_id: String,
    pub event_kind: CreditLossLifecycleEventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<MonetaryAmount>,
}

impl CreditLossLifecycleQuery {
    pub fn validate(&self) -> Result<(), String> {
        if self.bond_id.trim().is_empty() {
            return Err("credit loss lifecycle requests require --bond-id".to_string());
        }
        if self.amount.as_ref().is_some_and(|amount| amount.units == 0) {
            return Err("credit loss lifecycle amounts must be greater than zero".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleSummary {
    pub bond_id: String,
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
    pub current_bond_lifecycle_state: CreditBondLifecycleState,
    pub projected_bond_lifecycle_state: CreditBondLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_delinquent_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_recovered_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_written_off_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_released_reserve_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_slashed_reserve_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outstanding_delinquent_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub releaseable_reserve_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserve_control_source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_state: Option<CreditReserveControlExecutionState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appeal_state: Option<CreditReserveControlAppealState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appeal_window_ends_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_amount: Option<MonetaryAmount>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleFinding {
    pub code: CreditLossLifecycleReasonCode,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CreditScorecardEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleSupportBoundary {
    pub immutable_lifecycle_authoritative: bool,
    pub bond_lifecycle_projection_authoritative: bool,
    pub external_claim_adjudication_supported: bool,
    pub automatic_capital_execution_supported: bool,
    pub reserve_control_execution_supported: bool,
    pub appeal_window_supported: bool,
}

impl Default for CreditLossLifecycleSupportBoundary {
    fn default() -> Self {
        Self {
            immutable_lifecycle_authoritative: true,
            bond_lifecycle_projection_authoritative: true,
            external_claim_adjudication_supported: false,
            automatic_capital_execution_supported: false,
            reserve_control_execution_supported: true,
            appeal_window_supported: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: CreditLossLifecycleQuery,
    pub summary: CreditLossLifecycleSummary,
    pub support_boundary: CreditLossLifecycleSupportBoundary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<CreditLossLifecycleFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleArtifact {
    pub schema: String,
    pub event_id: String,
    pub issued_at: u64,
    pub bond_id: String,
    pub event_kind: CreditLossLifecycleEventKind,
    pub projected_bond_lifecycle_state: CreditBondLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserve_control_source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_chain: Vec<CapitalExecutionAuthorityStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_window: Option<CapitalExecutionWindow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rail: Option<CapitalExecutionRail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_execution: Option<CapitalExecutionObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconciled_state: Option<CapitalExecutionReconciledState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_state: Option<CreditReserveControlExecutionState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appeal_state: Option<CreditReserveControlAppealState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appeal_window_ends_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub report: CreditLossLifecycleReport,
}

pub type SignedCreditLossLifecycle = SignedExportEnvelope<CreditLossLifecycleArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleListQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
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
    pub event_kind: Option<CreditLossLifecycleEventKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl Default for CreditLossLifecycleListQuery {
    fn default() -> Self {
        Self {
            event_id: None,
            bond_id: None,
            facility_id: None,
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            event_kind: None,
            limit: Some(50),
        }
    }
}

impl CreditLossLifecycleListQuery {
    #[must_use]
    pub fn limit_or_default(&self) -> usize {
        self.limit
            .unwrap_or(50)
            .clamp(1, MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT)
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
pub struct CreditLossLifecycleRow {
    pub event: SignedCreditLossLifecycle,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleListSummary {
    pub matching_events: u64,
    pub returned_events: u64,
    pub delinquency_events: u64,
    pub recovery_events: u64,
    pub reserve_release_events: u64,
    pub reserve_slash_events: u64,
    pub write_off_events: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleListReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: CreditLossLifecycleListQuery,
    pub summary: CreditLossLifecycleListSummary,
    pub events: Vec<CreditLossLifecycleRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBacktestQuery {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_after_seconds: Option<u64>,
}

impl Default for CreditBacktestQuery {
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
            window_seconds: Some(7 * 86_400),
            window_count: Some(4),
            stale_after_seconds: Some(30 * 86_400),
        }
    }
}

impl CreditBacktestQuery {
    #[must_use]
    pub fn receipt_limit_or_default(&self) -> usize {
        self.receipt_limit
            .unwrap_or(100)
            .clamp(1, MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT)
    }

    #[must_use]
    pub fn decision_limit_or_default(&self) -> usize {
        self.decision_limit
            .unwrap_or(50)
            .clamp(1, MAX_EXPOSURE_LEDGER_DECISION_LIMIT)
    }

    #[must_use]
    pub fn window_seconds_or_default(&self) -> u64 {
        self.window_seconds.unwrap_or(7 * 86_400).max(1)
    }

    #[must_use]
    pub fn window_count_or_default(&self) -> usize {
        self.window_count
            .unwrap_or(4)
            .clamp(1, MAX_CREDIT_BACKTEST_WINDOW_LIMIT)
    }

    #[must_use]
    pub fn stale_after_seconds_or_default(&self) -> u64 {
        self.stale_after_seconds.unwrap_or(30 * 86_400).max(1)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.receipt_limit = Some(self.receipt_limit_or_default());
        normalized.decision_limit = Some(self.decision_limit_or_default());
        normalized.window_seconds = Some(self.window_seconds_or_default());
        normalized.window_count = Some(self.window_count_or_default());
        normalized.stale_after_seconds = Some(self.stale_after_seconds_or_default());
        normalized
    }

    #[must_use]
    pub fn exposure_query(&self) -> ExposureLedgerQuery {
        ExposureLedgerQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            since: self.since,
            until: self.until,
            receipt_limit: self.receipt_limit,
            decision_limit: self.decision_limit,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        self.exposure_query().validate()?;
        if self.agent_subject.is_none() {
            return Err(
                "credit backtests require --agent-subject because scorecards and facilities are subject-scoped"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditBacktestReasonCode {
    ScoreBandShift,
    FacilityDispositionShift,
    MixedCurrencyBook,
    StaleEvidence,
    FacilityOverUtilization,
    PendingSettlementBacklog,
    FailedSettlementBacklog,
    MissingRuntimeAssurance,
    CertificationNotActive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBacktestWindow {
    pub index: u64,
    pub window_started_at: u64,
    pub window_ended_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub newest_receipt_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_band: Option<CreditScorecardBand>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_disposition: Option<CreditFacilityDisposition>,
    pub simulated_scorecard: CreditScorecardSummary,
    pub simulated_disposition: CreditFacilityDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulated_terms: Option<CreditFacilityTerms>,
    pub stale_evidence: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utilization_bps: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<CreditBacktestReasonCode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBacktestSummary {
    pub windows_evaluated: u64,
    pub drift_windows: u64,
    pub score_band_changes: u64,
    pub facility_disposition_changes: u64,
    pub manual_review_windows: u64,
    pub denied_windows: u64,
    pub stale_evidence_windows: u64,
    pub mixed_currency_windows: u64,
    pub over_utilized_windows: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditBacktestReport {
    pub schema: String,
    pub generated_at: u64,
    pub query: CreditBacktestQuery,
    pub summary: CreditBacktestSummary,
    pub windows: Vec<CreditBacktestWindow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditProviderRiskPackageQuery {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recent_loss_limit: Option<usize>,
}

impl Default for CreditProviderRiskPackageQuery {
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
            recent_loss_limit: Some(10),
        }
    }
}

impl CreditProviderRiskPackageQuery {
    #[must_use]
    pub fn recent_loss_limit_or_default(&self) -> usize {
        self.recent_loss_limit
            .unwrap_or(10)
            .clamp(1, MAX_CREDIT_PROVIDER_LOSS_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.receipt_limit = Some(
            self.receipt_limit
                .unwrap_or(100)
                .clamp(1, MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT),
        );
        normalized.decision_limit = Some(
            self.decision_limit
                .unwrap_or(50)
                .clamp(1, MAX_EXPOSURE_LEDGER_DECISION_LIMIT),
        );
        normalized.recent_loss_limit = Some(self.recent_loss_limit_or_default());
        normalized
    }

    #[must_use]
    pub fn exposure_query(&self) -> ExposureLedgerQuery {
        ExposureLedgerQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            since: self.since,
            until: self.until,
            receipt_limit: self.receipt_limit,
            decision_limit: self.decision_limit,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        self.exposure_query().validate()?;
        if self.agent_subject.is_none() {
            return Err(
                "provider risk packages require --agent-subject because the package is subject-scoped"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditRecentLossEntry {
    pub receipt_id: String,
    pub observed_at: u64,
    pub settlement_status: SettlementStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub financial_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisional_loss_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovered_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<ExposureLedgerEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditRecentLossSummary {
    pub matching_loss_events: u64,
    pub returned_loss_events: u64,
    pub failed_settlement_events: u64,
    pub provisional_loss_events: u64,
    pub recovered_events: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditRecentLossHistory {
    pub summary: CreditRecentLossSummary,
    pub entries: Vec<CreditRecentLossEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditRuntimeAssuranceState {
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
    pub stale: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditCertificationState {
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<UnderwritingCertificationState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditProviderRiskPackageSupportBoundary {
    pub signed_exposure_authoritative: bool,
    pub signed_scorecard_authoritative: bool,
    pub facility_policy_authoritative: bool,
    pub compliance_score_reference_supported: bool,
    pub external_capital_review_supported: bool,
    pub autonomous_pricing_supported: bool,
    pub liability_market_supported: bool,
}

impl Default for CreditProviderRiskPackageSupportBoundary {
    fn default() -> Self {
        Self {
            signed_exposure_authoritative: true,
            signed_scorecard_authoritative: true,
            facility_policy_authoritative: true,
            compliance_score_reference_supported: true,
            external_capital_review_supported: true,
            autonomous_pricing_supported: false,
            liability_market_supported: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreditProviderFacilitySnapshot {
    pub facility_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub disposition: CreditFacilityDisposition,
    pub lifecycle_state: CreditFacilityLifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credit_limit: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_facility_id: Option<String>,
    pub signer_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditProviderRiskPackage {
    pub schema: String,
    pub generated_at: u64,
    pub subject_key: String,
    pub filters: CreditProviderRiskPackageQuery,
    pub support_boundary: CreditProviderRiskPackageSupportBoundary,
    pub exposure: SignedExposureLedgerReport,
    pub scorecard: SignedCreditScorecardReport,
    pub facility_report: CreditFacilityReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_score: Option<UnderwritingComplianceEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_facility: Option<CreditProviderFacilitySnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance: Option<CreditRuntimeAssuranceState>,
    pub certification: CreditCertificationState,
    pub recent_loss_history: CreditRecentLossHistory,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<CreditScorecardEvidenceReference>,
}

pub type SignedCreditProviderRiskPackage = SignedExportEnvelope<CreditProviderRiskPackage>;

include!("credit/capital_and_execution.rs");
