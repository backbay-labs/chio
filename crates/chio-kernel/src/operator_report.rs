use serde::{Deserialize, Serialize};

use chio_core::appraisal::AttestationVerifierFamily;
use chio_core::capability::{
    GovernedCallChainProvenance, MeteredSettlementMode, MonetaryAmount, RuntimeAssuranceTier,
};
use chio_core::receipt::{
    ChioReceipt, Decision, EconomicAuthorizationReceiptMetadata,
    FinancialBudgetAuthorityReceiptMetadata, GovernedTransactionReceiptMetadata,
    MeteredUsageEvidenceReceiptMetadata, SettlementStatus, SignedExportEnvelope,
};
use chio_core::session::ChioIdentityAssertion;
use chio_core::{
    ChioGovernedAuthorizationBinding, ChioPortableClaimCatalog, ChioPortableIdentityBinding,
};
use chio_credit::{
    CreditBondDisposition, CreditBondListReport, CreditFacilityDisposition,
    CreditFacilityListReport, ExposureLedgerQuery,
};
use chio_underwriting::{UnderwritingDecisionListReport, UnderwritingDecisionOutcome};

use crate::cost_attribution::CostAttributionQuery;
use crate::evidence_export::{
    EvidenceChildReceiptScope, EvidenceExportQuery, EvidenceLineageReferences,
};
use crate::receipt_analytics::{AnalyticsTimeBucket, ReceiptAnalyticsResponse};
use crate::receipt_query::{ReceiptQuery, ReceiptReadBoundary, ReceiptReadContext};
use crate::receipt_store::FederatedEvidenceShareSummary;
use crate::CostAttributionReport;

/// Maximum number of budget rows returned in a single operator report.
pub const MAX_OPERATOR_BUDGET_LIMIT: usize = 200;
/// Maximum number of shared-evidence reference rows returned in one query.
pub const MAX_SHARED_EVIDENCE_LIMIT: usize = 200;
/// Maximum number of settlement backlog rows returned in one report.
pub const MAX_SETTLEMENT_BACKLOG_LIMIT: usize = 200;
/// Maximum number of receipt detail rows returned in one behavioral feed.
pub const MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT: usize = 200;
/// Maximum number of metered-billing reconciliation rows returned in one report.
pub const MAX_METERED_BILLING_LIMIT: usize = 200;
/// Maximum number of authorization-context rows returned in one report.
pub const MAX_AUTHORIZATION_CONTEXT_LIMIT: usize = 200;
/// Maximum number of economic projection rows returned in one report.
pub const MAX_ECONOMIC_RECEIPT_LIMIT: usize = 200;
/// Stable schema identifier for Chio's normative OAuth-family authorization profile.
pub const CHIO_OAUTH_AUTHORIZATION_PROFILE_SCHEMA: &str = "chio.oauth.authorization-profile.v1";
/// Stable schema identifier for Chio's sender-constraint profile.
pub const CHIO_OAUTH_SENDER_CONSTRAINT_SCHEMA: &str = "chio.oauth.sender-constraint.v1";
/// Stable schema identifier for Chio authorization-context reports.
pub const CHIO_OAUTH_AUTHORIZATION_CONTEXT_REPORT_SCHEMA: &str =
    "chio.oauth.authorization-context-report.v1";
/// Stable schema identifier for the deterministic economic completion flow bundle.
pub const ECONOMIC_COMPLETION_FLOW_SCHEMA: &str = "chio.economic-completion-flow.v1";
/// Stable schema identifier for Chio authorization-profile metadata artifacts.
pub const CHIO_OAUTH_AUTHORIZATION_METADATA_SCHEMA: &str = "chio.oauth.authorization-metadata.v1";
/// Stable schema identifier for Chio enterprise IAM reviewer packs.
pub const CHIO_OAUTH_AUTHORIZATION_REVIEW_PACK_SCHEMA: &str =
    "chio.oauth.authorization-review-pack.v1";
/// Stable identifier for Chio's first governed authorization-details profile.
pub const CHIO_OAUTH_AUTHORIZATION_PROFILE_ID: &str = "chio-governed-rar-v1";
/// Detail type for the primary governed tool action.
pub const CHIO_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE: &str = "chio_governed_tool";
/// Detail type for governed commerce scope.
pub const CHIO_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE: &str = "chio_governed_commerce";
/// Detail type for governed metered-billing scope.
pub const CHIO_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE: &str =
    "chio_governed_metered_billing";
/// Stable label for Chio's capability-subject sender binding.
pub const CHIO_OAUTH_SENDER_BINDING_CAPABILITY_SUBJECT: &str = "capability_subject";
/// Stable label for Chio's Chio-native DPoP proof requirement.
pub const CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP: &str = "chio_dpop_v1";
/// Stable label for Chio's bounded mTLS-thumbprint sender adapter.
pub const CHIO_OAUTH_SENDER_PROOF_CHIO_MTLS: &str = "chio_mtls_thumbprint_v1";
/// Stable label for Chio's bounded attestation-bound sender adapter.
pub const CHIO_OAUTH_SENDER_PROOF_CHIO_ATTESTATION: &str = "chio_attestation_binding_v1";
/// Stable request-time parameter for Chio governed authorization details.
pub const CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_PARAMETER: &str = "authorization_details";
/// Stable request-time parameter for Chio governed transaction context.
pub const CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_PARAMETER: &str = "chio_transaction_context";
/// Stable access-token claim for Chio governed authorization details.
pub const CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_CLAIM: &str = "authorization_details";
/// Stable access-token claim for Chio governed transaction context.
pub const CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_CLAIM: &str = "chio_transaction_context";

/// Filter surface for the operator-facing reporting API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OperatorReportQuery {
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
    pub group_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_bucket: Option<AnalyticsTimeBucket>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metered_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub economic_limit: Option<usize>,
    /// Auth-derived read authority. This is never accepted from request bodies.
    #[serde(skip)]
    pub read_context: Option<ReceiptReadContext>,
}

impl Default for OperatorReportQuery {
    fn default() -> Self {
        Self {
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            since: None,
            until: None,
            group_limit: Some(50),
            time_bucket: Some(AnalyticsTimeBucket::Day),
            attribution_limit: Some(100),
            budget_limit: Some(50),
            settlement_limit: Some(50),
            metered_limit: Some(50),
            authorization_limit: Some(50),
            economic_limit: Some(50),
            read_context: None,
        }
    }
}

impl OperatorReportQuery {
    #[must_use]
    pub fn to_receipt_analytics_query(&self) -> crate::ReceiptAnalyticsQuery {
        crate::ReceiptAnalyticsQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            since: self.since,
            until: self.until,
            group_limit: self.group_limit,
            time_bucket: self.time_bucket,
            read_context: self.read_context.clone(),
        }
    }

    #[must_use]
    pub fn to_cost_attribution_query(&self) -> CostAttributionQuery {
        CostAttributionQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            since: self.since,
            until: self.until,
            limit: self.attribution_limit,
            read_context: self.read_context.clone(),
        }
    }

    pub fn to_evidence_export_query(&self) -> Result<EvidenceExportQuery, String> {
        let (tenant, read_boundary) = match self.read_context.as_ref() {
            Some(ReceiptReadContext {
                boundary: ReceiptReadBoundary::AdminAll,
                ..
            }) => (None, Some(ReceiptReadBoundary::AdminAll)),
            Some(ReceiptReadContext {
                boundary: ReceiptReadBoundary::TenantScoped { tenant },
                ..
            }) => (
                Some(tenant.clone()),
                Some(ReceiptReadBoundary::tenant_scoped(tenant.clone())),
            ),
            None => {
                return Err(
                    "operator report evidence export requires an explicit read context".to_string(),
                );
            }
        };
        Ok(EvidenceExportQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            since: self.since,
            until: self.until,
            tenant,
            read_boundary,
        })
    }

    #[must_use]
    pub fn direct_evidence_export_supported(&self) -> bool {
        self.tool_server.is_none() && self.tool_name.is_none()
    }

    #[must_use]
    pub fn budget_limit_or_default(&self) -> usize {
        self.budget_limit
            .unwrap_or(50)
            .clamp(1, MAX_OPERATOR_BUDGET_LIMIT)
    }

    #[must_use]
    pub fn settlement_limit_or_default(&self) -> usize {
        self.settlement_limit
            .unwrap_or(50)
            .clamp(1, MAX_SETTLEMENT_BACKLOG_LIMIT)
    }

    #[must_use]
    pub fn metered_limit_or_default(&self) -> usize {
        self.metered_limit
            .unwrap_or(50)
            .clamp(1, MAX_METERED_BILLING_LIMIT)
    }

    #[must_use]
    pub fn authorization_limit_or_default(&self) -> usize {
        self.authorization_limit
            .unwrap_or(50)
            .clamp(1, MAX_AUTHORIZATION_CONTEXT_LIMIT)
    }

    #[must_use]
    pub fn economic_limit_or_default(&self) -> usize {
        self.economic_limit
            .unwrap_or(50)
            .clamp(1, MAX_ECONOMIC_RECEIPT_LIMIT)
    }

    #[must_use]
    pub fn to_shared_evidence_query(&self) -> SharedEvidenceQuery {
        SharedEvidenceQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            since: self.since,
            until: self.until,
            issuer: None,
            partner: None,
            limit: self.group_limit,
            read_context: self.read_context.clone(),
        }
    }
}

/// Filter surface for the signed insurer/risk behavioral feed export.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedQuery {
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
    /// Auth-derived read authority. This is never accepted from request bodies.
    #[serde(skip)]
    pub read_context: Option<ReceiptReadContext>,
}

impl Default for BehavioralFeedQuery {
    fn default() -> Self {
        Self {
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            since: None,
            until: None,
            receipt_limit: Some(100),
            read_context: None,
        }
    }
}

impl BehavioralFeedQuery {
    #[must_use]
    pub fn receipt_limit_or_default(&self) -> usize {
        self.receipt_limit
            .unwrap_or(100)
            .clamp(1, MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.receipt_limit = Some(self.receipt_limit_or_default());
        normalized
    }

    #[must_use]
    pub fn to_operator_report_query(&self) -> OperatorReportQuery {
        OperatorReportQuery {
            capability_id: self.capability_id.clone(),
            agent_subject: self.agent_subject.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            since: self.since,
            until: self.until,
            read_context: self.read_context.clone(),
            ..OperatorReportQuery::default()
        }
    }

    #[must_use]
    pub fn to_receipt_query(&self) -> ReceiptQuery {
        ReceiptQuery {
            capability_id: self.capability_id.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            outcome: None,
            since: self.since,
            until: self.until,
            min_cost: None,
            max_cost: None,
            cursor: None,
            limit: self.receipt_limit_or_default(),
            agent_subject: self.agent_subject.clone(),
            tenant_filter: None,
            read_context: self.read_context.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SharedEvidenceQuery {
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
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    /// Auth-derived read authority. This is never accepted from request bodies.
    #[serde(skip)]
    pub read_context: Option<ReceiptReadContext>,
}

impl Default for SharedEvidenceQuery {
    fn default() -> Self {
        Self {
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            since: None,
            until: None,
            issuer: None,
            partner: None,
            limit: Some(50),
            read_context: None,
        }
    }
}

impl SharedEvidenceQuery {
    #[must_use]
    pub fn limit_or_default(&self) -> usize {
        self.limit.unwrap_or(50).clamp(1, MAX_SHARED_EVIDENCE_LIMIT)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BudgetUtilizationSummary {
    pub matching_grants: u64,
    pub returned_grants: u64,
    pub distinct_capabilities: u64,
    pub distinct_subjects: u64,
    pub total_invocations: u64,
    pub total_cost_charged: u64,
    pub near_limit_count: u64,
    pub exhausted_count: u64,
    pub rows_missing_scope: u64,
    pub rows_missing_lineage: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BudgetDimensionUsage {
    pub used: u64,
    pub limit: u64,
    pub remaining: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utilization_rate: Option<f64>,
    pub near_limit: bool,
    pub exhausted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BudgetDimensionProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocations: Option<BudgetDimensionUsage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub money: Option<BudgetDimensionUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BudgetUtilizationRow {
    pub capability_id: String,
    pub grant_index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    pub invocation_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_invocations: Option<u32>,
    pub total_cost_charged: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_cost_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_cost_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_utilization_rate: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_utilization_rate: Option<f64>,
    pub near_limit: bool,
    pub exhausted: bool,
    pub updated_at: i64,
    pub scope_resolved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_resolution_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dimensions: Option<BudgetDimensionProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BudgetUtilizationReport {
    pub summary: BudgetUtilizationSummary,
    pub rows: Vec<BudgetUtilizationRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceReport {
    pub matching_receipts: u64,
    pub evidence_ready_receipts: u64,
    pub uncheckpointed_receipts: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_coverage_rate: Option<f64>,
    pub lineage_covered_receipts: u64,
    pub lineage_gap_receipts: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage_coverage_rate: Option<f64>,
    pub pending_settlement_receipts: u64,
    pub failed_settlement_receipts: u64,
    pub direct_evidence_export_supported: bool,
    pub child_receipt_scope: EvidenceChildReceiptScope,
    pub proofs_complete: bool,
    pub export_query: EvidenceExportQuery,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_scope_note: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReconciliationState {
    Open,
    Reconciled,
    Ignored,
    RetryScheduled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SettlementReconciliationSummary {
    pub matching_receipts: u64,
    pub returned_receipts: u64,
    pub pending_receipts: u64,
    pub failed_receipts: u64,
    pub actionable_receipts: u64,
    pub reconciled_receipts: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SettlementReconciliationRow {
    pub receipt_id: String,
    pub timestamp: u64,
    pub capability_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_key: Option<String>,
    pub tool_server: String,
    pub tool_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_reference: Option<String>,
    pub settlement_status: SettlementStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_charged: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_authority: Option<FinancialBudgetAuthorityReceiptMetadata>,
    pub reconciliation_state: SettlementReconciliationState,
    pub action_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SettlementReconciliationReport {
    pub summary: SettlementReconciliationSummary,
    pub receipts: Vec<SettlementReconciliationRow>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MeteredBillingReconciliationState {
    Open,
    Reconciled,
    Ignored,
    RetryScheduled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MeteredBillingEvidenceRecord {
    pub usage_evidence: MeteredUsageEvidenceReceiptMetadata,
    pub billed_cost: MonetaryAmount,
    pub recorded_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MeteredBillingReconciliationSummary {
    pub matching_receipts: u64,
    pub returned_receipts: u64,
    pub evidence_attached_receipts: u64,
    pub missing_evidence_receipts: u64,
    pub over_quoted_units_receipts: u64,
    pub over_max_billed_units_receipts: u64,
    pub over_quoted_cost_receipts: u64,
    pub financial_mismatch_receipts: u64,
    pub actionable_receipts: u64,
    pub reconciled_receipts: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MeteredBillingReconciliationRow {
    pub receipt_id: String,
    pub timestamp: u64,
    pub capability_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_key: Option<String>,
    pub tool_server: String,
    pub tool_name: String,
    pub settlement_mode: MeteredSettlementMode,
    pub provider: String,
    pub quote_id: String,
    pub billing_unit: String,
    pub quoted_units: u64,
    pub quoted_cost: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_billed_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub financial_cost_charged: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub financial_currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_authority: Option<FinancialBudgetAuthorityReceiptMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<MeteredBillingEvidenceRecord>,
    pub reconciliation_state: MeteredBillingReconciliationState,
    pub action_required: bool,
    pub evidence_missing: bool,
    pub exceeds_quoted_units: bool,
    pub exceeds_max_billed_units: bool,
    pub exceeds_quoted_cost: bool,
    pub financial_mismatch: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MeteredBillingReconciliationReport {
    pub summary: MeteredBillingReconciliationSummary,
    pub receipts: Vec<MeteredBillingReconciliationRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EconomicReceiptProjectionSummary {
    pub matching_receipts: u64,
    pub returned_receipts: u64,
    pub metered_receipts: u64,
    pub pending_settlement_receipts: u64,
    pub failed_settlement_receipts: u64,
    pub settlement_actionable_receipts: u64,
    pub metering_actionable_receipts: u64,
    pub metering_evidence_missing_receipts: u64,
    pub metering_financial_mismatch_receipts: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EconomicReceiptSettlementProjection {
    pub settlement_status: SettlementStatus,
    pub reconciliation_state: SettlementReconciliationState,
    pub action_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EconomicReceiptMeteringProjection {
    pub reconciliation_state: MeteredBillingReconciliationState,
    pub action_required: bool,
    pub evidence_missing: bool,
    pub exceeds_quoted_units: bool,
    pub exceeds_max_billed_units: bool,
    pub exceeds_quoted_cost: bool,
    pub financial_mismatch: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<MeteredBillingEvidenceRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EconomicReceiptProjectionRow {
    pub receipt_id: String,
    pub timestamp: u64,
    pub capability_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_key: Option<String>,
    pub tool_server: String,
    pub tool_name: String,
    pub economic_authorization: EconomicAuthorizationReceiptMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_authority: Option<FinancialBudgetAuthorityReceiptMetadata>,
    pub settlement: EconomicReceiptSettlementProjection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metering: Option<EconomicReceiptMeteringProjection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EconomicReceiptProjectionReport {
    pub summary: EconomicReceiptProjectionSummary,
    pub receipts: Vec<EconomicReceiptProjectionRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EconomicCompletionFlowSummary {
    pub matching_receipts: u64,
    pub returned_receipts: u64,
    pub matching_underwriting_decisions: u64,
    pub returned_underwriting_decisions: u64,
    pub matching_credit_facilities: u64,
    pub returned_credit_facilities: u64,
    pub matching_credit_bonds: u64,
    pub returned_credit_bonds: u64,
    pub pending_settlement_receipts: u64,
    pub failed_settlement_receipts: u64,
    pub metering_actionable_receipts: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_underwriting_decision_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_underwriting_outcome: Option<UnderwritingDecisionOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_credit_facility_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_credit_facility_disposition: Option<CreditFacilityDisposition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_credit_bond_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_credit_bond_disposition: Option<CreditBondDisposition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EconomicCompletionFlowReport {
    pub schema: String,
    pub generated_at: u64,
    pub filters: ExposureLedgerQuery,
    pub summary: EconomicCompletionFlowSummary,
    pub economic_receipts: EconomicReceiptProjectionReport,
    pub underwriting_decisions: UnderwritingDecisionListReport,
    pub credit_facilities: CreditFacilityListReport,
    pub credit_bonds: CreditBondListReport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GovernedAuthorizationCommerceDetail {
    pub seller: String,
    pub shared_payment_token_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GovernedAuthorizationMeteredBillingDetail {
    pub settlement_mode: MeteredSettlementMode,
    pub provider: String,
    pub quote_id: String,
    pub billing_unit: String,
    pub quoted_units: u64,
    pub quoted_cost: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_billed_units: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GovernedAuthorizationDetail {
    #[serde(rename = "type")]
    pub detail_type: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commerce: Option<GovernedAuthorizationCommerceDetail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metered_billing: Option<GovernedAuthorizationMeteredBillingDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GovernedAuthorizationTransactionContext {
    pub intent_id: String,
    pub intent_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_token_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_approved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance_tier: Option<RuntimeAssuranceTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance_schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance_verifier_family: Option<AttestationVerifierFamily>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance_verifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance_evidence_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_chain: Option<GovernedCallChainProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_assertion: Option<ChioIdentityAssertion>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GovernedTransactionDiagnostics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asserted_call_chain: Option<GovernedCallChainProvenance>,
    #[serde(default, skip_serializing_if = "EvidenceLineageReferences::is_empty")]
    pub lineage_references: EvidenceLineageReferences,
}

impl GovernedTransactionDiagnostics {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.asserted_call_chain.is_none() && self.lineage_references.is_empty()
    }
}

fn default_authorization_context_report_schema() -> String {
    CHIO_OAUTH_AUTHORIZATION_CONTEXT_REPORT_SCHEMA.to_string()
}

fn default_chio_oauth_authorization_profile() -> ChioOAuthAuthorizationProfile {
    ChioOAuthAuthorizationProfile::default()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthAuthorizationProfile {
    pub schema: String,
    pub id: String,
    pub authoritative_source: String,
    pub authorization_detail_types: Vec<String>,
    pub transaction_context_fields: Vec<String>,
    #[serde(default)]
    pub portable_claim_catalog: ChioPortableClaimCatalog,
    #[serde(default)]
    pub portable_identity_binding: ChioPortableIdentityBinding,
    #[serde(default)]
    pub governed_auth_binding: ChioGovernedAuthorizationBinding,
    #[serde(default)]
    pub request_time_contract: ChioOAuthRequestTimeContract,
    #[serde(default)]
    pub resource_binding: ChioOAuthResourceBinding,
    #[serde(default)]
    pub artifact_boundary: ChioOAuthArtifactBoundary,
    pub sender_constraints: ChioOAuthSenderConstraintProfile,
    pub unsupported_shapes_fail_closed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthRequestTimeContract {
    pub authorization_details_parameter: String,
    pub transaction_context_parameter: String,
    pub access_token_authorization_details_claim: String,
    pub access_token_transaction_context_claim: String,
    pub request_time_authorization_details_supported: bool,
    pub request_time_transaction_context_supported: bool,
    pub governed_receipts_authoritative_post_execution: bool,
}

impl Default for ChioOAuthRequestTimeContract {
    fn default() -> Self {
        Self {
            authorization_details_parameter:
                CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_PARAMETER.to_string(),
            transaction_context_parameter: CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_PARAMETER
                .to_string(),
            access_token_authorization_details_claim:
                CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_CLAIM.to_string(),
            access_token_transaction_context_claim:
                CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_CLAIM.to_string(),
            request_time_authorization_details_supported: true,
            request_time_transaction_context_supported: true,
            governed_receipts_authoritative_post_execution: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthResourceBinding {
    pub protected_resource_field: String,
    pub request_resource_parameter: String,
    pub access_token_audience_claim: String,
    pub access_token_resource_claim: String,
    pub request_resource_must_match_protected_resource: bool,
    pub bearer_token_must_include_audience_or_resource: bool,
}

impl Default for ChioOAuthResourceBinding {
    fn default() -> Self {
        Self {
            protected_resource_field: "resource".to_string(),
            request_resource_parameter: "resource".to_string(),
            access_token_audience_claim: "aud".to_string(),
            access_token_resource_claim: "resource".to_string(),
            request_resource_must_match_protected_resource: true,
            bearer_token_must_include_audience_or_resource: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthArtifactBoundary {
    pub access_tokens_runtime_admission_supported: bool,
    pub approval_tokens_runtime_admission_supported: bool,
    pub capabilities_runtime_admission_supported: bool,
    pub reviewer_evidence_runtime_admission_supported: bool,
    pub governed_receipts_audit_evidence_supported: bool,
}

impl Default for ChioOAuthArtifactBoundary {
    fn default() -> Self {
        Self {
            access_tokens_runtime_admission_supported: true,
            approval_tokens_runtime_admission_supported: false,
            capabilities_runtime_admission_supported: false,
            reviewer_evidence_runtime_admission_supported: false,
            governed_receipts_audit_evidence_supported: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthSenderConstraintProfile {
    pub schema: String,
    pub subject_binding: String,
    pub proof_types_supported: Vec<String>,
    pub proof_required_when: String,
    pub runtime_assurance_binding_fields: Vec<String>,
    pub delegated_call_chain_field: String,
    pub unsupported_sender_shapes_fail_closed: bool,
}

impl Default for ChioOAuthSenderConstraintProfile {
    fn default() -> Self {
        Self {
            schema: CHIO_OAUTH_SENDER_CONSTRAINT_SCHEMA.to_string(),
            subject_binding: CHIO_OAUTH_SENDER_BINDING_CAPABILITY_SUBJECT.to_string(),
            proof_types_supported: vec![
                CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP.to_string(),
                CHIO_OAUTH_SENDER_PROOF_CHIO_MTLS.to_string(),
                CHIO_OAUTH_SENDER_PROOF_CHIO_ATTESTATION.to_string(),
            ],
            proof_required_when: "matchedGrant.dpopRequired == true".to_string(),
            runtime_assurance_binding_fields: vec![
                "runtimeAssuranceTier".to_string(),
                "runtimeAssuranceSchema".to_string(),
                "runtimeAssuranceVerifierFamily".to_string(),
                "runtimeAssuranceVerifier".to_string(),
                "runtimeAssuranceEvidenceSha256".to_string(),
            ],
            delegated_call_chain_field: "callChain".to_string(),
            unsupported_sender_shapes_fail_closed: true,
        }
    }
}

impl Default for ChioOAuthAuthorizationProfile {
    fn default() -> Self {
        Self {
            schema: CHIO_OAUTH_AUTHORIZATION_PROFILE_SCHEMA.to_string(),
            id: CHIO_OAUTH_AUTHORIZATION_PROFILE_ID.to_string(),
            authoritative_source: "governed_receipt_projection".to_string(),
            authorization_detail_types: vec![
                CHIO_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE.to_string(),
                CHIO_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE.to_string(),
                CHIO_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE.to_string(),
            ],
            transaction_context_fields: vec![
                "intentId".to_string(),
                "intentHash".to_string(),
                "approvalTokenId".to_string(),
                "approvalApproved".to_string(),
                "approverKey".to_string(),
                "runtimeAssuranceTier".to_string(),
                "runtimeAssuranceSchema".to_string(),
                "runtimeAssuranceVerifierFamily".to_string(),
                "runtimeAssuranceVerifier".to_string(),
                "runtimeAssuranceEvidenceSha256".to_string(),
                "callChain".to_string(),
                "identityAssertion".to_string(),
            ],
            portable_claim_catalog: ChioPortableClaimCatalog::default(),
            portable_identity_binding: ChioPortableIdentityBinding::default(),
            governed_auth_binding: ChioGovernedAuthorizationBinding::default(),
            request_time_contract: ChioOAuthRequestTimeContract::default(),
            resource_binding: ChioOAuthResourceBinding::default(),
            artifact_boundary: ChioOAuthArtifactBoundary::default(),
            sender_constraints: ChioOAuthSenderConstraintProfile::default(),
            unsupported_shapes_fail_closed: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationContextSummary {
    pub matching_receipts: u64,
    pub returned_receipts: u64,
    pub approval_receipts: u64,
    pub approved_receipts: u64,
    pub commerce_receipts: u64,
    pub metered_billing_receipts: u64,
    pub runtime_assurance_receipts: u64,
    pub call_chain_receipts: u64,
    pub asserted_call_chain_receipts: u64,
    pub observed_call_chain_receipts: u64,
    pub verified_call_chain_receipts: u64,
    pub max_amount_receipts: u64,
    pub sender_bound_receipts: u64,
    pub dpop_bound_receipts: u64,
    pub runtime_assurance_bound_receipts: u64,
    pub delegated_sender_bound_receipts: u64,
    pub session_anchor_receipts: u64,
    pub request_lineage_receipts: u64,
    pub receipt_lineage_statement_receipts: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationContextSenderConstraint {
    pub subject_key: String,
    pub subject_key_source: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub issuer_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub issuer_key_source: String,
    pub matched_grant_index: u32,
    pub proof_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_schema: Option<String>,
    pub runtime_assurance_bound: bool,
    pub delegated_call_chain_bound: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationContextRow {
    pub receipt_id: String,
    pub timestamp: u64,
    pub capability_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_key: Option<String>,
    pub tool_server: String,
    pub tool_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    pub authorization_details: Vec<GovernedAuthorizationDetail>,
    pub transaction_context: GovernedAuthorizationTransactionContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_transaction_diagnostics: Option<GovernedTransactionDiagnostics>,
    pub sender_constraint: AuthorizationContextSenderConstraint,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationContextReport {
    #[serde(default = "default_authorization_context_report_schema")]
    pub schema: String,
    #[serde(default = "default_chio_oauth_authorization_profile")]
    pub profile: ChioOAuthAuthorizationProfile,
    pub summary: AuthorizationContextSummary,
    pub receipts: Vec<AuthorizationContextRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthAuthorizationDiscoveryMetadata {
    pub protected_resource_metadata_paths: Vec<String>,
    pub authorization_server_metadata_path_template: String,
    pub discovery_informational_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthAuthorizationSupportBoundary {
    pub governed_receipts_authoritative: bool,
    pub hosted_request_time_authorization_supported: bool,
    pub resource_indicator_binding_supported: bool,
    pub sender_constrained_projection: bool,
    pub runtime_assurance_projection: bool,
    pub delegated_call_chain_projection: bool,
    pub generic_token_issuance_supported: bool,
    pub oidc_identity_assertions_supported: bool,
    pub mtls_transport_binding_in_profile: bool,
    pub approval_tokens_runtime_authorization_supported: bool,
    pub capabilities_runtime_authorization_supported: bool,
    pub reviewer_evidence_runtime_authorization_supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthAuthorizationExampleMapping {
    pub authorization_detail_types: Vec<String>,
    pub transaction_context_fields: Vec<String>,
    pub sender_constraint_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthAuthorizationMetadataReport {
    pub schema: String,
    pub generated_at: u64,
    pub profile: ChioOAuthAuthorizationProfile,
    pub report_schema: String,
    pub discovery: ChioOAuthAuthorizationDiscoveryMetadata,
    pub support_boundary: ChioOAuthAuthorizationSupportBoundary,
    pub example_mapping: ChioOAuthAuthorizationExampleMapping,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthAuthorizationReviewPackSummary {
    pub matching_receipts: u64,
    pub returned_receipts: u64,
    pub dpop_required_receipts: u64,
    pub runtime_assurance_receipts: u64,
    pub delegated_call_chain_receipts: u64,
    pub asserted_call_chain_receipts: u64,
    pub observed_call_chain_receipts: u64,
    pub verified_call_chain_receipts: u64,
    pub session_anchor_receipts: u64,
    pub request_lineage_receipts: u64,
    pub receipt_lineage_statement_receipts: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthAuthorizationReviewPackRecord {
    pub receipt_id: String,
    pub capability_id: String,
    pub authorization_context: AuthorizationContextRow,
    pub governed_transaction: GovernedTransactionReceiptMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_transaction_diagnostics: Option<GovernedTransactionDiagnostics>,
    pub signed_receipt: ChioReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthAuthorizationReviewPack {
    pub schema: String,
    pub generated_at: u64,
    pub filters: OperatorReportQuery,
    pub metadata: ChioOAuthAuthorizationMetadataReport,
    pub summary: ChioOAuthAuthorizationReviewPackSummary,
    pub records: Vec<ChioOAuthAuthorizationReviewPackRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SharedEvidenceReferenceSummary {
    pub matching_shares: u64,
    pub matching_references: u64,
    pub matching_local_receipts: u64,
    pub remote_tool_receipts: u64,
    pub remote_lineage_records: u64,
    pub distinct_remote_subjects: u64,
    pub proof_required_shares: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SharedEvidenceReferenceRow {
    pub share: FederatedEvidenceShareSummary,
    pub capability_id: String,
    pub subject_key: String,
    pub issuer_key: String,
    pub delegation_depth: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_anchor_capability_id: Option<String>,
    pub matched_local_receipts: u64,
    pub allow_count: u64,
    pub deny_count: u64,
    pub cancelled_count: u64,
    pub incomplete_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SharedEvidenceReferenceReport {
    pub summary: SharedEvidenceReferenceSummary,
    pub references: Vec<SharedEvidenceReferenceRow>,
}

/// Stable schema identifier for insurer-facing behavioral feed exports.
pub const BEHAVIORAL_FEED_SCHEMA: &str = "chio.behavioral-feed.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedPrivacyBoundary {
    pub matching_receipts: u64,
    pub returned_receipts: u64,
    pub direct_evidence_export_supported: bool,
    pub child_receipt_scope: EvidenceChildReceiptScope,
    pub proofs_complete: bool,
    pub export_query: EvidenceExportQuery,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_scope_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedDecisionSummary {
    pub allow_count: u64,
    pub deny_count: u64,
    pub cancelled_count: u64,
    pub incomplete_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedSettlementSummary {
    pub pending_receipts: u64,
    pub settled_receipts: u64,
    pub failed_receipts: u64,
    pub not_applicable_receipts: u64,
    pub actionable_receipts: u64,
    pub reconciled_receipts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedGovernedActionSummary {
    pub governed_receipts: u64,
    pub approval_receipts: u64,
    pub approved_receipts: u64,
    pub commerce_receipts: u64,
    pub max_amount_receipts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedMeteredBillingSummary {
    pub metered_receipts: u64,
    pub evidence_attached_receipts: u64,
    pub missing_evidence_receipts: u64,
    pub over_quoted_units_receipts: u64,
    pub over_max_billed_units_receipts: u64,
    pub over_quoted_cost_receipts: u64,
    pub financial_mismatch_receipts: u64,
    pub actionable_receipts: u64,
    pub reconciled_receipts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedReputationSummary {
    pub subject_key: String,
    pub effective_score: f64,
    pub probationary: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_tier: Option<String>,
    pub imported_signal_count: usize,
    pub accepted_imported_signal_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedReceiptRow {
    pub receipt_id: String,
    pub timestamp: u64,
    pub capability_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_key: Option<String>,
    pub tool_server: String,
    pub tool_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    #[serde(default)]
    pub authorized: bool,
    pub settlement_status: SettlementStatus,
    pub reconciliation_state: SettlementReconciliationState,
    pub action_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_charged: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempted_cost: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_authority: Option<FinancialBudgetAuthorityReceiptMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed: Option<GovernedTransactionReceiptMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_transaction_diagnostics: Option<GovernedTransactionDiagnostics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metered_reconciliation: Option<BehavioralFeedMeteredBillingRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedMeteredBillingRow {
    pub reconciliation_state: MeteredBillingReconciliationState,
    pub action_required: bool,
    pub evidence_missing: bool,
    pub exceeds_quoted_units: bool,
    pub exceeds_max_billed_units: bool,
    pub exceeds_quoted_cost: bool,
    pub financial_mismatch: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<MeteredBillingEvidenceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedReceiptSelection {
    pub matching_receipts: u64,
    pub receipts: Vec<BehavioralFeedReceiptRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedReport {
    pub schema: String,
    pub generated_at: u64,
    pub filters: BehavioralFeedQuery,
    pub privacy: BehavioralFeedPrivacyBoundary,
    pub decisions: BehavioralFeedDecisionSummary,
    pub settlements: BehavioralFeedSettlementSummary,
    pub governed_actions: BehavioralFeedGovernedActionSummary,
    pub metered_billing: BehavioralFeedMeteredBillingSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reputation: Option<BehavioralFeedReputationSummary>,
    pub shared_evidence: SharedEvidenceReferenceSummary,
    pub receipts: Vec<BehavioralFeedReceiptRow>,
}

pub type SignedBehavioralFeed = SignedExportEnvelope<BehavioralFeedReport>;

// ===========================================================================
// Additive scoring and advisory signals on top of ComplianceReport and
// BehavioralFeedReport. These helpers do not mutate the existing structs.
// ===========================================================================

impl ComplianceReport {
    /// Compute a weighted compliance score on top of this report.
    ///
    /// Thin convenience wrapper over
    /// [`crate::compliance_score::compliance_score`]. See that module for
    /// the scoring model and weights.
    #[must_use]
    pub fn compliance_score(
        &self,
        inputs: &crate::compliance_score::ComplianceScoreInputs,
        config: &crate::compliance_score::ComplianceScoreConfig,
        agent_id: &str,
        now: u64,
    ) -> crate::compliance_score::ComplianceScore {
        crate::compliance_score::compliance_score(self, inputs, config, agent_id, now)
    }
}

/// EMA (exponentially-weighted moving average) baseline state for a
/// single (agent, metric) pair. Used by behavioral profiling to detect
/// z-score anomalies without storing every historical sample.
///
/// The baseline uses Welford-style incremental tracking of mean and
/// variance so callers can compute a z-score for any new sample
/// without re-reading history.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EmaBaselineState {
    /// Number of samples folded into the baseline.
    pub sample_count: u64,
    /// Exponentially-weighted mean.
    pub ema_mean: f64,
    /// Exponentially-weighted variance.
    pub ema_variance: f64,
    /// Last update timestamp (unix seconds).
    pub last_update: u64,
}

impl EmaBaselineState {
    /// Fold a new sample into the baseline with the provided smoothing
    /// factor `alpha` (0.0..=1.0). Higher alpha weighs recent samples
    /// more heavily.
    ///
    /// `alpha` is clamped to `(0.0, 1.0]`. `now` is recorded as
    /// `last_update`.
    pub fn update(&mut self, sample: f64, alpha: f64, now: u64) {
        let alpha = alpha.clamp(f64::MIN_POSITIVE, 1.0);
        if self.sample_count == 0 {
            self.ema_mean = sample;
            self.ema_variance = 0.0;
        } else {
            let prev_mean = self.ema_mean;
            self.ema_mean = prev_mean + alpha * (sample - prev_mean);
            // Incremental EWMA variance, following West (1979) / Welford.
            let diff = sample - prev_mean;
            self.ema_variance = (1.0 - alpha) * (self.ema_variance + alpha * diff * diff);
        }
        self.sample_count = self.sample_count.saturating_add(1);
        self.last_update = now;
    }

    /// Standard deviation (sqrt of EWMA variance).
    #[must_use]
    pub fn stddev(&self) -> f64 {
        self.ema_variance.max(0.0).sqrt()
    }

    /// Z-score for a new sample. Returns `None` when the baseline has
    /// fewer than two samples or zero variance (no meaningful signal).
    #[must_use]
    pub fn z_score(&self, sample: f64) -> Option<f64> {
        if self.sample_count < 2 {
            return None;
        }
        let stddev = self.stddev();
        if stddev <= f64::EPSILON {
            return None;
        }
        Some((sample - self.ema_mean) / stddev)
    }
}

/// Summary of behavioral-anomaly signals derived from receipts over a
/// window. Used by `BehavioralProfileGuard` and surfaced in operator
/// UIs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralAnomalyScore {
    /// Agent subject this anomaly score applies to.
    pub agent_id: String,
    /// Baseline statistic the z-score is computed against.
    pub baseline: EmaBaselineState,
    /// Current-window sample value (e.g. call count per window).
    pub current_sample: f64,
    /// Computed z-score, or `None` when baseline is too small.
    pub z_score: Option<f64>,
    /// Threshold above which an advisory signal is raised.
    pub sigma_threshold: f64,
    /// Whether the current sample crossed the threshold.
    pub anomaly: bool,
    /// Unix timestamp (seconds) at which the score was computed.
    pub generated_at: u64,
}

/// Compute a behavioral-anomaly score from a pre-existing baseline plus
/// a current-window sample. Exposes the same math the guard uses so
/// callers can surface anomaly scores in dashboards without rerunning
/// the guard.
#[must_use]
pub fn behavioral_anomaly_score(
    agent_id: &str,
    baseline: &EmaBaselineState,
    current_sample: f64,
    sigma_threshold: f64,
    now: u64,
) -> BehavioralAnomalyScore {
    let z_score = baseline.z_score(current_sample);
    let anomaly = z_score.is_some_and(|z| z.abs() > sigma_threshold);
    BehavioralAnomalyScore {
        agent_id: agent_id.to_string(),
        baseline: baseline.clone(),
        current_sample,
        z_score,
        sigma_threshold,
        anomaly,
        generated_at: now,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OperatorReport {
    pub generated_at: u64,
    pub filters: OperatorReportQuery,
    pub activity: ReceiptAnalyticsResponse,
    pub cost_attribution: CostAttributionReport,
    pub budget_utilization: BudgetUtilizationReport,
    pub compliance: ComplianceReport,
    pub settlement_reconciliation: SettlementReconciliationReport,
    pub metered_billing_reconciliation: MeteredBillingReconciliationReport,
    pub authorization_context: AuthorizationContextReport,
    pub shared_evidence: SharedEvidenceReferenceReport,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use chio_core::capability::{GovernedCallChainContext, GovernedProvenanceEvidenceClass};
    use chio_core::receipt::{
        FinancialBudgetAuthorityReceiptMetadata, FinancialBudgetAuthorizeReceiptMetadata,
        FinancialBudgetHoldAuthorityMetadata, FinancialBudgetTerminalReceiptMetadata,
    };

    #[test]
    fn operator_report_behavioral_feed_query_clamps_limit_and_translates_filters() {
        let query = BehavioralFeedQuery {
            capability_id: Some("cap-1".to_string()),
            agent_subject: Some("subject-1".to_string()),
            tool_server: Some("shell".to_string()),
            tool_name: Some("bash".to_string()),
            since: Some(10),
            until: Some(20),
            receipt_limit: Some(5_000),
            read_context: Some(ReceiptReadContext::local_operator_admin_all()),
        };

        assert_eq!(
            query.receipt_limit_or_default(),
            MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT
        );
        assert_eq!(
            query.normalized().receipt_limit,
            Some(MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT)
        );

        let operator_query = query.to_operator_report_query();
        assert_eq!(operator_query.capability_id.as_deref(), Some("cap-1"));
        assert_eq!(operator_query.agent_subject.as_deref(), Some("subject-1"));
        assert_eq!(operator_query.tool_server.as_deref(), Some("shell"));
        assert_eq!(operator_query.tool_name.as_deref(), Some("bash"));
        assert_eq!(operator_query.since, Some(10));
        assert_eq!(operator_query.until, Some(20));
        assert_eq!(operator_query.metered_limit_or_default(), 50);

        let receipt_query = query.to_receipt_query();
        assert_eq!(receipt_query.limit, MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT);
        assert_eq!(receipt_query.agent_subject.as_deref(), Some("subject-1"));
    }

    #[test]
    fn operator_report_query_direct_export_support_requires_no_tool_filters() {
        let unrestricted = OperatorReportQuery::default();
        assert!(unrestricted.direct_evidence_export_supported());

        let with_tool_filter = OperatorReportQuery {
            tool_server: Some("shell".to_string()),
            ..OperatorReportQuery::default()
        };
        assert!(!with_tool_filter.direct_evidence_export_supported());
    }

    #[test]
    fn operator_report_query_clamps_metered_limit() {
        let query = OperatorReportQuery {
            metered_limit: Some(5_000),
            ..OperatorReportQuery::default()
        };

        assert_eq!(query.metered_limit_or_default(), MAX_METERED_BILLING_LIMIT);
    }

    #[test]
    fn operator_report_query_clamps_authorization_limit() {
        let query = OperatorReportQuery {
            authorization_limit: Some(5_000),
            ..OperatorReportQuery::default()
        };

        assert_eq!(
            query.authorization_limit_or_default(),
            MAX_AUTHORIZATION_CONTEXT_LIMIT
        );
    }

    #[test]
    fn operator_report_query_clamps_economic_limit() {
        let query = OperatorReportQuery {
            economic_limit: Some(5_000),
            ..OperatorReportQuery::default()
        };

        assert_eq!(
            query.economic_limit_or_default(),
            MAX_ECONOMIC_RECEIPT_LIMIT
        );
    }

    #[test]
    fn governed_transaction_diagnostics_serialization_omits_empty_fields() {
        let diagnostics = GovernedTransactionDiagnostics::default();

        assert!(diagnostics.is_empty());
        assert_eq!(
            serde_json::to_value(diagnostics).unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn governed_transaction_diagnostics_preserves_asserted_call_chain_and_lineage_references() {
        let diagnostics = GovernedTransactionDiagnostics {
            asserted_call_chain: Some(GovernedCallChainProvenance::asserted(
                GovernedCallChainContext {
                    chain_id: "chain-1".to_string(),
                    parent_request_id: "req-parent-1".to_string(),
                    parent_receipt_id: Some("rcpt-parent-1".to_string()),
                    origin_subject: "origin".to_string(),
                    delegator_subject: "delegator".to_string(),
                },
            )),
            lineage_references: EvidenceLineageReferences {
                session_anchor_id: Some("anchor-1".to_string()),
                request_lineage_id: Some("req-lineage-1".to_string()),
                receipt_lineage_statement_id: Some("stmt-1".to_string()),
            },
        };

        let value = serde_json::to_value(&diagnostics).unwrap();

        assert_eq!(
            value["assertedCallChain"]["evidenceClass"],
            serde_json::json!("asserted")
        );
        assert_eq!(value["lineageReferences"]["sessionAnchorId"], "anchor-1");
        assert_eq!(
            diagnostics
                .asserted_call_chain
                .as_ref()
                .map(|call_chain| call_chain.evidence_class),
            Some(GovernedProvenanceEvidenceClass::Asserted)
        );
    }

    #[test]
    fn settlement_reconciliation_row_serialization_preserves_budget_authority_metadata() {
        let budget_authority = FinancialBudgetAuthorityReceiptMetadata {
            guarantee_level: "ha_quorum_commit".to_string(),
            authority_profile: "ha".to_string(),
            metering_profile: "metered".to_string(),
            hold_id: "hold-1".to_string(),
            budget_term: Some("term-7".to_string()),
            authority: Some(FinancialBudgetHoldAuthorityMetadata {
                authority_id: "http://leader-a".to_string(),
                lease_id: "lease-7".to_string(),
                lease_epoch: 7,
            }),
            authorize: FinancialBudgetAuthorizeReceiptMetadata {
                event_id: Some("hold-1:authorize".to_string()),
                budget_commit_index: Some(41),
                exposure_units: 120,
                committed_cost_units_after: 120,
            },
            terminal: Some(FinancialBudgetTerminalReceiptMetadata {
                disposition: "reconciled".to_string(),
                event_id: Some("hold-1:reconcile".to_string()),
                budget_commit_index: Some(42),
                exposure_units: 120,
                realized_spend_units: 75,
                committed_cost_units_after: 75,
            }),
        };
        let row = SettlementReconciliationRow {
            receipt_id: "rcpt-1".to_string(),
            timestamp: 42,
            capability_id: "cap-1".to_string(),
            subject_key: Some("subject-1".to_string()),
            tool_server: "payments".to_string(),
            tool_name: "charge".to_string(),
            payment_reference: Some("payref-1".to_string()),
            settlement_status: SettlementStatus::Pending,
            cost_charged: Some(75),
            currency: Some("usd".to_string()),
            budget_authority: Some(budget_authority.clone()),
            reconciliation_state: SettlementReconciliationState::Open,
            action_required: true,
            note: None,
            updated_at: None,
        };

        let value = serde_json::to_value(&row).unwrap();

        assert_eq!(
            value["budgetAuthority"]["guarantee_level"],
            serde_json::json!("ha_quorum_commit")
        );
        assert_eq!(
            value["budgetAuthority"]["hold_id"],
            serde_json::json!("hold-1")
        );
        assert_eq!(
            value["budgetAuthority"]["authority"]["authority_id"],
            serde_json::json!("http://leader-a")
        );
    }

    #[test]
    fn metered_and_behavioral_rows_serialize_budget_authority_metadata() {
        let budget_authority = FinancialBudgetAuthorityReceiptMetadata {
            guarantee_level: "ha_quorum_commit".to_string(),
            authority_profile: "ha".to_string(),
            metering_profile: "metered".to_string(),
            hold_id: "hold-2".to_string(),
            budget_term: Some("term-8".to_string()),
            authority: Some(FinancialBudgetHoldAuthorityMetadata {
                authority_id: "http://leader-b".to_string(),
                lease_id: "lease-8".to_string(),
                lease_epoch: 8,
            }),
            authorize: FinancialBudgetAuthorizeReceiptMetadata {
                event_id: Some("hold-2:authorize".to_string()),
                budget_commit_index: Some(51),
                exposure_units: 150,
                committed_cost_units_after: 150,
            },
            terminal: None,
        };

        let metered = MeteredBillingReconciliationRow {
            receipt_id: "rcpt-2".to_string(),
            timestamp: 99,
            capability_id: "cap-2".to_string(),
            subject_key: None,
            tool_server: "meter".to_string(),
            tool_name: "bill".to_string(),
            settlement_mode: MeteredSettlementMode::AllowThenSettle,
            provider: "provider-1".to_string(),
            quote_id: "quote-1".to_string(),
            billing_unit: "tokens".to_string(),
            quoted_units: 10,
            quoted_cost: MonetaryAmount {
                units: 50,
                currency: "USD".to_string(),
            },
            max_billed_units: Some(10),
            financial_cost_charged: Some(50),
            financial_currency: Some("USD".to_string()),
            budget_authority: Some(budget_authority.clone()),
            evidence: None,
            reconciliation_state: MeteredBillingReconciliationState::Open,
            action_required: true,
            evidence_missing: true,
            exceeds_quoted_units: false,
            exceeds_max_billed_units: false,
            exceeds_quoted_cost: false,
            financial_mismatch: false,
            note: None,
            updated_at: None,
        };
        let behavioral = BehavioralFeedReceiptRow {
            receipt_id: "rcpt-3".to_string(),
            timestamp: 100,
            capability_id: "cap-3".to_string(),
            subject_key: None,
            issuer_key: None,
            tool_server: "meter".to_string(),
            tool_name: "bill".to_string(),
            decision: Some(Decision::Allow),
            authorized: true,
            settlement_status: SettlementStatus::Settled,
            reconciliation_state: SettlementReconciliationState::Reconciled,
            action_required: false,
            cost_charged: Some(50),
            attempted_cost: Some(60),
            currency: Some("USD".to_string()),
            budget_authority: Some(budget_authority),
            governed: None,
            governed_transaction_diagnostics: None,
            metered_reconciliation: None,
        };

        let metered_value = serde_json::to_value(&metered).unwrap();
        let behavioral_value = serde_json::to_value(&behavioral).unwrap();

        assert_eq!(
            metered_value["budgetAuthority"]["guarantee_level"],
            serde_json::json!("ha_quorum_commit")
        );
        assert_eq!(
            behavioral_value["budgetAuthority"]["hold_id"],
            serde_json::json!("hold-2")
        );
    }
}
