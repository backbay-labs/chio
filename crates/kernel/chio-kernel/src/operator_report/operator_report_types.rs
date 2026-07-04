use super::*;

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
