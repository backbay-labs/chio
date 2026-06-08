//! Billing-export-compatible cost records.
//!
//! This module transforms Chio cost metadata into a format suitable for
//! external billing systems. Records follow a flat, denormalized schema
//! that can be directly ingested by CSV/JSON billing pipelines.

use chio_core::capability::scope::MonetaryAmount;
use serde::{Deserialize, Serialize};

use crate::cost::CostMetadata;

/// Schema identifier for billing export records.
pub const BILLING_EXPORT_SCHEMA: &str = "chio.billing-export.v1";

/// A single billing record suitable for export to external systems.
///
/// Each record corresponds to one receipt's cost and is designed to be
/// ingested by CSV or JSON-lines billing pipelines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingRecord {
    /// Schema version.
    pub schema: String,
    /// Receipt ID.
    pub receipt_id: String,
    /// Unix timestamp (seconds) of the invocation.
    pub timestamp: u64,
    /// ISO 8601 timestamp for human-readable export.
    pub timestamp_iso: String,
    /// Session ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Agent that triggered the cost.
    pub agent_id: String,
    /// Tool server.
    pub tool_server: String,
    /// Tool name.
    pub tool_name: String,
    /// Compute time in milliseconds.
    pub compute_time_ms: u64,
    /// Total data transferred in bytes.
    pub data_bytes: u64,
    /// Monetary cost amount (minor units).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_units: Option<u64>,
    /// Currency code for cost_units.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    /// Upstream provider that charged the cost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

/// A batch of billing records ready for export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingExport {
    /// Schema version.
    pub schema: String,
    /// Export timestamp (Unix seconds).
    pub exported_at: u64,
    /// Total number of records in this export.
    pub record_count: u64,
    /// Total monetary cost across all records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_cost: Option<MonetaryAmount>,
    /// The billing records.
    pub records: Vec<BillingRecord>,
}

/// Convert a collection of cost metadata into a billing export.
pub fn create_billing_export(records: &[CostMetadata], exported_at: u64) -> BillingExport {
    let mut billing_records = Vec::with_capacity(records.len());
    let mut total_units = 0u64;
    let mut currency: Option<String> = None;
    let mut mixed = false;

    for meta in records {
        let iso = unix_to_iso(meta.timestamp);

        // Find the first API cost provider for the billing record.
        let provider = meta.dimensions.iter().find_map(|d| {
            if let crate::cost::CostDimension::ApiCost { provider, .. } = d {
                Some(provider.clone())
            } else {
                None
            }
        });

        let (cost_u, cur) = match &meta.total_monetary_cost {
            Some(m) => (Some(m.units), Some(m.currency.clone())),
            None => (None, None),
        };

        if let Some(ref c) = cur {
            if let Some(ref units) = cost_u {
                match &currency {
                    None => {
                        currency = Some(c.clone());
                        total_units = *units;
                    }
                    Some(existing) if existing == c => {
                        total_units = total_units.saturating_add(*units);
                    }
                    _ => {
                        mixed = true;
                    }
                }
            }
        }

        billing_records.push(BillingRecord {
            schema: BILLING_EXPORT_SCHEMA.to_string(),
            receipt_id: meta.receipt_id.clone(),
            timestamp: meta.timestamp,
            timestamp_iso: iso,
            session_id: meta.session_id.clone(),
            agent_id: meta.agent_id.clone(),
            tool_server: meta.tool_server.clone(),
            tool_name: meta.tool_name.clone(),
            compute_time_ms: meta.total_compute_time_ms(),
            data_bytes: meta.total_data_bytes(),
            cost_units: cost_u,
            currency: cur,
            provider,
        });
    }

    let total_cost = if mixed {
        None
    } else {
        currency.map(|c| MonetaryAmount {
            units: total_units,
            currency: c,
        })
    };

    BillingExport {
        schema: BILLING_EXPORT_SCHEMA.to_string(),
        exported_at,
        record_count: billing_records.len() as u64,
        total_cost,
        records: billing_records,
    }
}

/// Convert a Unix timestamp to an ISO 8601 string.
///
/// Uses UTC. Falls back to a placeholder if the timestamp cannot be
/// represented.
fn unix_to_iso(ts: u64) -> String {
    use chrono::{DateTime, Utc};

    match DateTime::from_timestamp(ts as i64, 0) {
        Some(dt) => {
            let utc: DateTime<Utc> = dt;
            utc.format("%Y-%m-%dT%H:%M:%SZ").to_string()
        }
        None => format!("unix:{ts}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cost::{CostDimension, CostMetadata};

    #[test]
    fn billing_export_single_record() {
        let mut meta = CostMetadata::new(
            "r1".to_string(),
            1700000000,
            "agent-1".to_string(),
            "srv-1".to_string(),
            "tool-a".to_string(),
        );
        meta.add_dimension(CostDimension::ComputeTime { duration_ms: 200 });
        meta.add_dimension(CostDimension::ApiCost {
            amount: MonetaryAmount {
                units: 75,
                currency: "USD".to_string(),
            },
            provider: "openai".to_string(),
        });
        meta.compute_total_monetary_cost();

        let export = create_billing_export(&[meta], 1700000100);
        assert_eq!(export.record_count, 1);
        assert_eq!(export.records[0].compute_time_ms, 200);
        assert_eq!(export.records[0].cost_units, Some(75));
        assert_eq!(export.records[0].currency.as_deref(), Some("USD"));
        assert_eq!(export.records[0].provider.as_deref(), Some("openai"));
        assert!(export.records[0].timestamp_iso.contains("2023"));
    }

    #[test]
    fn billing_export_total_cost() {
        let make = |id: &str, units: u64| {
            let mut m = CostMetadata::new(
                id.to_string(),
                1700000000,
                "a".to_string(),
                "s".to_string(),
                "t".to_string(),
            );
            m.add_dimension(CostDimension::ApiCost {
                amount: MonetaryAmount {
                    units,
                    currency: "USD".to_string(),
                },
                provider: "p".to_string(),
            });
            m.compute_total_monetary_cost();
            m
        };

        let records = vec![make("r1", 100), make("r2", 200)];
        let export = create_billing_export(&records, 0);
        assert_eq!(export.total_cost.as_ref().unwrap().units, 300);
    }

    #[test]
    fn unix_to_iso_roundtrip() {
        let iso = unix_to_iso(1700000000);
        assert!(iso.starts_with("2023-"));
        assert!(iso.ends_with('Z'));
    }

    #[test]
    fn billing_export_empty_records() {
        let export = create_billing_export(&[], 1700000000);
        assert_eq!(export.record_count, 0);
        assert!(export.records.is_empty());
        assert!(export.total_cost.is_none());
    }

    #[test]
    fn billing_export_mixed_currencies_no_total() {
        let make_with_currency = |id: &str, units: u64, currency: &str| {
            let mut m = CostMetadata::new(
                id.to_string(),
                1700000000,
                "a".to_string(),
                "s".to_string(),
                "t".to_string(),
            );
            m.add_dimension(CostDimension::ApiCost {
                amount: MonetaryAmount {
                    units,
                    currency: currency.to_string(),
                },
                provider: "p".to_string(),
            });
            m.compute_total_monetary_cost();
            m
        };

        let records = vec![
            make_with_currency("r1", 100, "USD"),
            make_with_currency("r2", 200, "EUR"),
        ];
        let export = create_billing_export(&records, 0);
        // Mixed currencies should produce no total
        assert!(export.total_cost.is_none());
        assert_eq!(export.record_count, 2);
    }

    #[test]
    fn billing_record_serde_roundtrip() {
        let record = BillingRecord {
            schema: BILLING_EXPORT_SCHEMA.to_string(),
            receipt_id: "r-1".to_string(),
            timestamp: 1700000000,
            timestamp_iso: "2023-11-14T22:13:20Z".to_string(),
            session_id: Some("sess-1".to_string()),
            agent_id: "agent-1".to_string(),
            tool_server: "srv".to_string(),
            tool_name: "tool".to_string(),
            compute_time_ms: 200,
            data_bytes: 1024,
            cost_units: Some(50),
            currency: Some("USD".to_string()),
            provider: Some("openai".to_string()),
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: BillingRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.receipt_id, "r-1");
        assert_eq!(back.cost_units, Some(50));
    }
}
