use serde::{Deserialize, Serialize};

use crate::receipt_query::ReceiptReadContext;

/// Maximum number of grouped analytics rows to return per dimension.
pub const MAX_ANALYTICS_GROUP_LIMIT: usize = 200;

/// Supported time bucket widths for aggregated receipt analytics.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnalyticsTimeBucket {
    Hour,
    Day,
}

impl AnalyticsTimeBucket {
    #[must_use]
    pub fn width_secs(self) -> u64 {
        match self {
            Self::Hour => 3_600,
            Self::Day => 86_400,
        }
    }
}

/// Filters for aggregated receipt analytics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptAnalyticsQuery {
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
    /// Auth-derived read authority. This is never accepted from request bodies.
    #[serde(skip)]
    pub read_context: Option<ReceiptReadContext>,
}

impl Default for ReceiptAnalyticsQuery {
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
            read_context: None,
        }
    }
}

/// Shared aggregated metrics derived from receipts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptAnalyticsMetrics {
    pub total_receipts: u64,
    pub allow_count: u64,
    pub deny_count: u64,
    pub cancelled_count: u64,
    pub incomplete_count: u64,
    pub total_cost_charged: u64,
    pub total_attempted_cost: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliability_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_rate: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_utilization_rate: Option<f64>,
}

impl ReceiptAnalyticsMetrics {
    #[must_use]
    pub fn from_raw(
        total_receipts: u64,
        allow_count: u64,
        deny_count: u64,
        cancelled_count: u64,
        incomplete_count: u64,
        total_cost_charged: u64,
        total_attempted_cost: u64,
    ) -> Self {
        let terminal_total = allow_count
            .saturating_add(cancelled_count)
            .saturating_add(incomplete_count);
        let attempted_total = total_cost_charged.saturating_add(total_attempted_cost);

        Self {
            total_receipts,
            allow_count,
            deny_count,
            cancelled_count,
            incomplete_count,
            total_cost_charged,
            total_attempted_cost,
            reliability_score: ratio_option(allow_count, terminal_total),
            compliance_rate: ratio_option(
                total_receipts.saturating_sub(deny_count),
                total_receipts,
            ),
            budget_utilization_rate: ratio_option(total_cost_charged, attempted_total),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentAnalyticsRow {
    pub subject_key: String,
    pub metrics: ReceiptAnalyticsMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ToolAnalyticsRow {
    pub tool_server: String,
    pub tool_name: String,
    pub metrics: ReceiptAnalyticsMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TimeAnalyticsRow {
    pub bucket_start: u64,
    pub bucket_end: u64,
    pub metrics: ReceiptAnalyticsMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptAnalyticsResponse {
    pub summary: ReceiptAnalyticsMetrics,
    pub by_agent: Vec<AgentAnalyticsRow>,
    pub by_tool: Vec<ToolAnalyticsRow>,
    pub by_time: Vec<TimeAnalyticsRow>,
}

fn ratio_option(numerator: u64, denominator: u64) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64)
    }
}
