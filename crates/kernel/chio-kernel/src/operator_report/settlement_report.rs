use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReconciliationState {
    Open,
    Reconciled,
    Ignored,
    RetryScheduled,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
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
