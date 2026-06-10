use chio_core::receipt::{
    economics::FinancialBudgetAuthorityReceiptMetadata, economics::SettlementStatus,
};
use serde::{Deserialize, Serialize};

use crate::receipt_query::ReceiptReadContext;

/// Maximum number of detailed attribution rows returned in a single report.
pub const MAX_COST_ATTRIBUTION_LIMIT: usize = 200;

/// Query parameters for delegation-chain cost attribution reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CostAttributionQuery {
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
    pub limit: Option<usize>,
    /// Auth-derived read authority. This is never accepted from request bodies.
    #[serde(skip)]
    pub read_context: Option<ReceiptReadContext>,
}

impl Default for CostAttributionQuery {
    fn default() -> Self {
        Self {
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            since: None,
            until: None,
            limit: Some(100),
            read_context: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CostAttributionSummary {
    pub matching_receipts: u64,
    pub returned_receipts: u64,
    pub total_cost_charged: u64,
    pub total_attempted_cost: u64,
    pub max_delegation_depth: u64,
    pub distinct_root_subjects: u64,
    pub distinct_leaf_subjects: u64,
    pub lineage_gap_count: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CostAttributionChainHop {
    pub capability_id: String,
    pub subject_key: String,
    pub issuer_key: String,
    pub delegation_depth: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_capability_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RootCostAttributionRow {
    pub root_subject_key: String,
    pub receipt_count: u64,
    pub total_cost_charged: u64,
    pub total_attempted_cost: u64,
    pub distinct_leaf_subjects: u64,
    pub max_delegation_depth: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LeafCostAttributionRow {
    pub root_subject_key: String,
    pub leaf_subject_key: String,
    pub receipt_count: u64,
    pub total_cost_charged: u64,
    pub total_attempted_cost: u64,
    pub max_delegation_depth: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CostAttributionReceiptRow {
    pub seq: u64,
    pub receipt_id: String,
    pub timestamp: u64,
    pub capability_id: String,
    pub tool_server: String,
    pub tool_name: String,
    pub decision_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_subject_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaf_subject_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_index: Option<u32>,
    pub delegation_depth: u64,
    pub cost_charged: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempted_cost: Option<u64>,
    pub currency: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_remaining: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_status: Option<SettlementStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_authority: Option<FinancialBudgetAuthorityReceiptMetadata>,
    pub lineage_complete: bool,
    pub chain: Vec<CostAttributionChainHop>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CostAttributionReport {
    pub summary: CostAttributionSummary,
    pub by_root: Vec<RootCostAttributionRow>,
    pub by_leaf: Vec<LeafCostAttributionRow>,
    pub receipts: Vec<CostAttributionReceiptRow>,
}
