//! CLI-style cost queries for cumulative cost by session, agent, tool, or time range.
//!
//! This module powers the `chio receipts cost` CLI command, allowing operators
//! to query cost data across multiple dimensions.

use chio_core::capability::MonetaryAmount;
use serde::{Deserialize, Serialize};

use crate::cost::CostMetadata;

/// Maximum number of results returned by a single cost query.
pub const MAX_COST_QUERY_LIMIT: usize = 500;

/// Query parameters for cost aggregation.
///
/// All filters are optional. When omitted, the query matches all records.
/// Multiple filters are ANDed together.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CostQuery {
    /// Filter by session ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// Filter by agent ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,

    /// Filter by tool server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,

    /// Filter by tool name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,

    /// Start of time range (inclusive, Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,

    /// End of time range (exclusive, Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,

    /// Currency filter -- only include costs in this currency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,

    /// Maximum number of detailed records to return.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,

    /// Aggregation group-by dimension.
    #[serde(default)]
    pub group_by: GroupBy,
}

/// Grouping dimension for cost aggregation.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupBy {
    /// No grouping -- return individual receipt costs.
    #[default]
    None,
    /// Group by session.
    Session,
    /// Group by agent.
    Agent,
    /// Group by tool (server:tool_name).
    Tool,
}

/// Result of a cost query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostQueryResult {
    /// Summary statistics.
    pub summary: CostSummary,
    /// Grouped cost rows (empty when group_by is None).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<CostGroup>,
    /// Whether the result was truncated due to limit.
    pub truncated: bool,
}

/// Summary statistics for a cost query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CostSummary {
    /// Total number of matching receipts.
    pub receipt_count: u64,
    /// Total compute time in milliseconds.
    pub total_compute_time_ms: u64,
    /// Total data transferred in bytes.
    pub total_data_bytes: u64,
    /// Total monetary cost (if all in the same currency).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_monetary_cost: Option<MonetaryAmount>,
    /// Distinct agents in the result set.
    pub distinct_agents: u64,
    /// Distinct tools in the result set.
    pub distinct_tools: u64,
}

/// A grouped cost row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostGroup {
    /// Group key (session ID, agent ID, or "server:tool").
    pub key: String,
    /// Number of receipts in this group.
    pub receipt_count: u64,
    /// Total compute time for this group.
    pub total_compute_time_ms: u64,
    /// Total data bytes for this group.
    pub total_data_bytes: u64,
    /// Total monetary cost for this group (if same currency).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_monetary_cost: Option<MonetaryAmount>,
}

/// Execute a cost query against an in-memory collection of cost metadata.
///
/// For production use this would query a receipt store backend, but the
/// logic is the same: filter, aggregate, summarize.
pub fn execute_cost_query(records: &[CostMetadata], query: &CostQuery) -> CostQueryResult {
    let limit = query
        .limit
        .unwrap_or(MAX_COST_QUERY_LIMIT)
        .min(MAX_COST_QUERY_LIMIT);

    let filtered: Vec<&CostMetadata> = records
        .iter()
        .filter(|record| record_matches_query(record, query))
        .collect();

    let truncated = filtered.len() > limit;
    let capped: Vec<&CostMetadata> = filtered.iter().take(limit).copied().collect();

    let mut agents = std::collections::HashSet::new();
    let mut tools = std::collections::HashSet::new();
    let mut total_compute = 0u64;
    let mut total_data = 0u64;
    let mut total_money_units = 0u64;
    let mut money_currency: Option<String> = None;
    let mut mixed_currency = false;

    for r in &capped {
        agents.insert(&r.agent_id);
        tools.insert(format!("{}:{}", r.tool_server, r.tool_name));
        total_compute = total_compute.saturating_add(r.total_compute_time_ms());
        total_data = total_data.saturating_add(r.total_data_bytes());
        if let Some(ref cost) = r.total_monetary_cost {
            match &money_currency {
                None => {
                    money_currency = Some(cost.currency.clone());
                    total_money_units = cost.units;
                }
                Some(c) if c == &cost.currency => {
                    total_money_units = total_money_units.saturating_add(cost.units);
                }
                _ => {
                    mixed_currency = true;
                }
            }
        }
    }

    let total_monetary_cost = if mixed_currency {
        None
    } else {
        money_currency.map(|c| MonetaryAmount {
            units: total_money_units,
            currency: c,
        })
    };

    let summary = CostSummary {
        receipt_count: capped.len() as u64,
        total_compute_time_ms: total_compute,
        total_data_bytes: total_data,
        total_monetary_cost,
        distinct_agents: agents.len() as u64,
        distinct_tools: tools.len() as u64,
    };

    let groups = match query.group_by {
        GroupBy::None => vec![],
        GroupBy::Session | GroupBy::Agent | GroupBy::Tool => build_groups(&capped, &query.group_by),
    };

    CostQueryResult {
        summary,
        groups,
        truncated,
    }
}

fn record_matches_query(record: &CostMetadata, query: &CostQuery) -> bool {
    if let Some(ref session_id) = query.session_id {
        if record.session_id.as_ref() != Some(session_id) {
            return false;
        }
    }
    if let Some(ref agent_id) = query.agent_id {
        if &record.agent_id != agent_id {
            return false;
        }
    }
    if let Some(ref tool_server) = query.tool_server {
        if &record.tool_server != tool_server {
            return false;
        }
    }
    if let Some(ref tool_name) = query.tool_name {
        if &record.tool_name != tool_name {
            return false;
        }
    }
    if let Some(since) = query.since {
        if record.timestamp < since {
            return false;
        }
    }
    if let Some(until) = query.until {
        if record.timestamp >= until {
            return false;
        }
    }
    if let Some(ref currency) = query.currency {
        match record.total_monetary_cost.as_ref() {
            Some(cost) if &cost.currency == currency => {}
            _ => return false,
        }
    }
    true
}

fn build_groups(records: &[&CostMetadata], group_by: &GroupBy) -> Vec<CostGroup> {
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct GroupAccumulator {
        receipt_count: u64,
        compute_ms: u64,
        data_bytes: u64,
        currency: Option<String>,
        money_units: u64,
        mixed_currency: bool,
    }

    let mut map: BTreeMap<String, GroupAccumulator> = BTreeMap::new();

    for r in records {
        let key = match group_by {
            GroupBy::Session => r
                .session_id
                .clone()
                .unwrap_or_else(|| "<no-session>".to_string()),
            GroupBy::Agent => r.agent_id.clone(),
            GroupBy::Tool => format!("{}:{}", r.tool_server, r.tool_name),
            GroupBy::None => continue,
        };

        let entry = map.entry(key).or_default();

        entry.receipt_count = entry.receipt_count.saturating_add(1);
        entry.compute_ms = entry.compute_ms.saturating_add(r.total_compute_time_ms());
        entry.data_bytes = entry.data_bytes.saturating_add(r.total_data_bytes());

        if let Some(ref cost) = r.total_monetary_cost {
            match entry.currency.as_ref() {
                None => {
                    entry.currency = Some(cost.currency.clone());
                    entry.money_units = cost.units;
                }
                Some(currency) if currency == &cost.currency => {
                    entry.money_units = entry.money_units.saturating_add(cost.units);
                }
                Some(_) => {
                    entry.mixed_currency = true;
                }
            }
        }
    }

    map.into_iter()
        .map(|(key, accumulator)| CostGroup {
            key,
            receipt_count: accumulator.receipt_count,
            total_compute_time_ms: accumulator.compute_ms,
            total_data_bytes: accumulator.data_bytes,
            total_monetary_cost: if accumulator.mixed_currency {
                None
            } else {
                accumulator.currency.map(|currency| MonetaryAmount {
                    units: accumulator.money_units,
                    currency,
                })
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cost::{CostDimension, CostMetadata};

    fn make_record(
        id: &str,
        ts: u64,
        agent: &str,
        server: &str,
        tool: &str,
        cost_units: u64,
    ) -> CostMetadata {
        let mut m = CostMetadata::new(
            id.to_string(),
            ts,
            agent.to_string(),
            server.to_string(),
            tool.to_string(),
        );
        m.add_dimension(CostDimension::ComputeTime { duration_ms: 100 });
        m.add_dimension(CostDimension::DataVolume {
            bytes_read: 500,
            bytes_written: 200,
        });
        m.add_dimension(CostDimension::ApiCost {
            amount: MonetaryAmount {
                units: cost_units,
                currency: "USD".to_string(),
            },
            provider: "test".to_string(),
        });
        m.session_id = Some("sess-1".to_string());
        m.compute_total_monetary_cost();
        m
    }

    #[test]
    fn query_no_filter() {
        let records = vec![
            make_record("r1", 1000, "a1", "s1", "t1", 50),
            make_record("r2", 2000, "a2", "s1", "t2", 100),
        ];
        let result = execute_cost_query(&records, &CostQuery::default());
        assert_eq!(result.summary.receipt_count, 2);
        assert_eq!(result.summary.total_compute_time_ms, 200);
        assert_eq!(result.summary.total_data_bytes, 1400);
        assert_eq!(
            result.summary.total_monetary_cost.as_ref().unwrap().units,
            150
        );
        assert!(!result.truncated);
    }

    #[test]
    fn query_filter_by_agent() {
        let records = vec![
            make_record("r1", 1000, "a1", "s1", "t1", 50),
            make_record("r2", 2000, "a2", "s1", "t2", 100),
        ];
        let query = CostQuery {
            agent_id: Some("a1".to_string()),
            ..Default::default()
        };
        let result = execute_cost_query(&records, &query);
        assert_eq!(result.summary.receipt_count, 1);
    }

    #[test]
    fn query_filter_by_time_range() {
        let records = vec![
            make_record("r1", 1000, "a1", "s1", "t1", 50),
            make_record("r2", 2000, "a1", "s1", "t1", 100),
            make_record("r3", 3000, "a1", "s1", "t1", 200),
        ];
        let query = CostQuery {
            since: Some(1500),
            until: Some(2500),
            ..Default::default()
        };
        let result = execute_cost_query(&records, &query);
        assert_eq!(result.summary.receipt_count, 1);
    }

    #[test]
    fn query_group_by_agent() {
        let records = vec![
            make_record("r1", 1000, "a1", "s1", "t1", 50),
            make_record("r2", 2000, "a2", "s1", "t2", 100),
            make_record("r3", 3000, "a1", "s1", "t1", 75),
        ];
        let query = CostQuery {
            group_by: GroupBy::Agent,
            ..Default::default()
        };
        let result = execute_cost_query(&records, &query);
        assert_eq!(result.groups.len(), 2);

        let a1_group = result.groups.iter().find(|g| g.key == "a1").unwrap();
        assert_eq!(a1_group.receipt_count, 2);
        assert_eq!(a1_group.total_monetary_cost.as_ref().unwrap().units, 125);
    }

    #[test]
    fn query_group_by_agent_mixed_currency_has_no_total() {
        let usd = make_record("r1", 1000, "a1", "s1", "t1", 50);
        let mut eur = make_record("r2", 2000, "a1", "s1", "t2", 100);
        eur.total_monetary_cost = Some(MonetaryAmount {
            units: 100,
            currency: "EUR".to_string(),
        });
        let records = vec![usd, eur];
        let query = CostQuery {
            group_by: GroupBy::Agent,
            ..Default::default()
        };
        let result = execute_cost_query(&records, &query);
        let group = result.groups.iter().find(|g| g.key == "a1").unwrap();

        assert!(group.total_monetary_cost.is_none());
    }

    #[test]
    fn query_group_by_tool() {
        let records = vec![
            make_record("r1", 1000, "a1", "s1", "t1", 50),
            make_record("r2", 2000, "a1", "s1", "t2", 100),
        ];
        let query = CostQuery {
            group_by: GroupBy::Tool,
            ..Default::default()
        };
        let result = execute_cost_query(&records, &query);
        assert_eq!(result.groups.len(), 2);
        assert!(result.groups.iter().any(|g| g.key == "s1:t1"));
        assert!(result.groups.iter().any(|g| g.key == "s1:t2"));
    }

    #[test]
    fn query_truncation() {
        let records: Vec<CostMetadata> = (0..600)
            .map(|i| make_record(&format!("r{i}"), i as u64, "a1", "s1", "t1", 1))
            .collect();
        let result = execute_cost_query(&records, &CostQuery::default());
        assert!(result.truncated);
        assert_eq!(result.summary.receipt_count, MAX_COST_QUERY_LIMIT as u64);
    }

    #[test]
    fn query_empty_records() {
        let records: Vec<CostMetadata> = vec![];
        let result = execute_cost_query(&records, &CostQuery::default());
        assert_eq!(result.summary.receipt_count, 0);
        assert_eq!(result.summary.total_compute_time_ms, 0);
        assert_eq!(result.summary.total_data_bytes, 0);
        assert!(result.summary.total_monetary_cost.is_none());
        assert!(!result.truncated);
    }

    #[test]
    fn query_group_by_session() {
        let records = vec![
            make_record("r1", 1000, "a1", "s1", "t1", 50),
            make_record("r2", 2000, "a1", "s1", "t1", 100),
        ];
        let query = CostQuery {
            group_by: GroupBy::Session,
            ..Default::default()
        };
        let result = execute_cost_query(&records, &query);
        assert_eq!(result.groups.len(), 1);
        assert_eq!(result.groups[0].key, "sess-1");
        assert_eq!(result.groups[0].receipt_count, 2);
    }

    #[test]
    fn query_filter_by_tool_server() {
        let records = vec![
            make_record("r1", 1000, "a1", "s1", "t1", 50),
            make_record("r2", 2000, "a1", "s2", "t1", 100),
        ];
        let query = CostQuery {
            tool_server: Some("s1".to_string()),
            ..Default::default()
        };
        let result = execute_cost_query(&records, &query);
        assert_eq!(result.summary.receipt_count, 1);
    }

    #[test]
    fn query_filter_by_tool_name() {
        let records = vec![
            make_record("r1", 1000, "a1", "s1", "t1", 50),
            make_record("r2", 2000, "a1", "s1", "t2", 100),
        ];
        let query = CostQuery {
            tool_name: Some("t2".to_string()),
            ..Default::default()
        };
        let result = execute_cost_query(&records, &query);
        assert_eq!(result.summary.receipt_count, 1);
        assert_eq!(
            result.summary.total_monetary_cost.as_ref().unwrap().units,
            100
        );
    }

    #[test]
    fn query_currency_filter() {
        let mut r1 = make_record("r1", 1000, "a1", "s1", "t1", 50);
        r1.total_monetary_cost = Some(MonetaryAmount {
            units: 50,
            currency: "USD".to_string(),
        });
        let mut r2 = make_record("r2", 2000, "a1", "s1", "t1", 100);
        r2.total_monetary_cost = Some(MonetaryAmount {
            units: 100,
            currency: "EUR".to_string(),
        });
        let records = vec![r1, r2];
        let query = CostQuery {
            currency: Some("EUR".to_string()),
            ..Default::default()
        };
        let result = execute_cost_query(&records, &query);
        assert_eq!(result.summary.receipt_count, 1);
        assert_eq!(
            result
                .summary
                .total_monetary_cost
                .as_ref()
                .unwrap()
                .currency,
            "EUR"
        );
    }
}
