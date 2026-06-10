use serde::{Deserialize, Serialize};

use crate::appraisal::AttestationVerifierFamily;
use crate::capability::{runtime_attestation::RuntimeAssuranceTier, scope::MonetaryAmount};
use crate::receipt::{economics::SettlementStatus, lineage::SignedExportEnvelope};
use crate::underwriting::{UnderwritingCertificationState, UnderwritingComplianceEvidence};
use crate::{
    bounded_limit_or_default, CapitalExecutionAuthorityStep, CapitalExecutionObservation,
    CapitalExecutionRail, CapitalExecutionReconciledState, CapitalExecutionWindow,
    CreditBondLifecycleState, CreditFacilityDisposition, CreditFacilityLifecycleState,
    CreditFacilityReport, CreditFacilityTerms, CreditScorecardBand,
    CreditScorecardEvidenceReference, CreditScorecardSummary, ExposureLedgerEvidenceReference,
    ExposureLedgerQuery, SignedCreditScorecardReport, SignedExposureLedgerReport,
    MAX_CREDIT_BACKTEST_WINDOW_LIMIT, MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT,
    MAX_CREDIT_PROVIDER_LOSS_LIMIT, MAX_EXPOSURE_LEDGER_DECISION_LIMIT,
    MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT,
};

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
        bounded_limit_or_default(self.limit, 50, MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT)
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
        bounded_limit_or_default(self.receipt_limit, 100, MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT)
    }

    #[must_use]
    pub fn decision_limit_or_default(&self) -> usize {
        bounded_limit_or_default(self.decision_limit, 50, MAX_EXPOSURE_LEDGER_DECISION_LIMIT)
    }

    #[must_use]
    pub fn window_seconds_or_default(&self) -> u64 {
        self.window_seconds.unwrap_or(7 * 86_400).max(1)
    }

    #[must_use]
    pub fn window_count_or_default(&self) -> usize {
        bounded_limit_or_default(self.window_count, 4, MAX_CREDIT_BACKTEST_WINDOW_LIMIT)
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
        bounded_limit_or_default(self.recent_loss_limit, 10, MAX_CREDIT_PROVIDER_LOSS_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.receipt_limit = Some(bounded_limit_or_default(
            self.receipt_limit,
            100,
            MAX_EXPOSURE_LEDGER_RECEIPT_LIMIT,
        ));
        normalized.decision_limit = Some(bounded_limit_or_default(
            self.decision_limit,
            50,
            MAX_EXPOSURE_LEDGER_DECISION_LIMIT,
        ));
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
