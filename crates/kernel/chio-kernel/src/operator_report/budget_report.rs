use super::*;

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
