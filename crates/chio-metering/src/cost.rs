//! Per-receipt cost attribution metadata.
//!
//! Each receipt can carry cost metadata describing the resources consumed
//! during the tool invocation: compute time, data volume transferred, and
//! monetary API cost.

use chio_core::capability::MonetaryAmount;
use serde::{Deserialize, Serialize};

/// Schema identifier for cost metadata embedded in receipts.
pub const COST_METADATA_SCHEMA: &str = "chio.cost-metadata.v1";

/// A single dimension of cost measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "dimension", rename_all = "snake_case")]
pub enum CostDimension {
    /// Wall-clock compute time in milliseconds.
    ComputeTime {
        /// Duration in milliseconds.
        duration_ms: u64,
    },
    /// Data volume transferred in bytes.
    DataVolume {
        /// Bytes read from upstream.
        bytes_read: u64,
        /// Bytes written to upstream.
        bytes_written: u64,
    },
    /// Monetary cost charged by an upstream API.
    ApiCost {
        /// The cost amount in minor currency units.
        amount: MonetaryAmount,
        /// Provider that charged this cost (e.g. "openai", "anthropic").
        provider: String,
    },
    /// Warehouse query cost recorded by the `WarehouseCostGuard` in
    /// `chio-data-guards`.  Captures the dry-run cost estimate for a
    /// warehouse-class query (BigQuery, Snowflake, Redshift, etc.).
    ///
    /// `estimated_cost_usd` is a decimal string rather than a fixed-width
    /// integer because `rust_decimal` is not part of the Chio workspace;
    /// this follows the precedent set by
    /// `Constraint::MaxTransactionAmountUsd` in `chio-core-types`.
    WarehouseQuery {
        /// Bytes the warehouse reported it will scan to satisfy the query.
        bytes_scanned: u64,
        /// Decimal-string estimate of the monetary cost in USD (e.g.
        /// `"0.25"`).  Parsed against the guard's `max_cost_per_query_usd`
        /// limit; preserved verbatim on the receipt for auditability.
        estimated_cost_usd: String,
    },
    /// Custom cost dimension for extensibility.
    Custom {
        /// Name of the custom dimension.
        name: String,
        /// Numeric value.
        value: u64,
        /// Optional unit label (e.g. "tokens", "requests").
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unit: Option<String>,
    },
}

/// Cost metadata attached to a single receipt.
///
/// This struct is serialized as JSON and stored in the receipt's `metadata`
/// field under the `"cost"` key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostMetadata {
    /// Schema version for forward compatibility.
    pub schema: String,
    /// Receipt ID this cost metadata belongs to.
    pub receipt_id: String,
    /// Unix timestamp (seconds) of the receipt.
    pub timestamp: u64,
    /// Session that produced this receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Agent that made the invocation.
    pub agent_id: String,
    /// Tool server that handled the invocation.
    pub tool_server: String,
    /// Tool that was invoked.
    pub tool_name: String,
    /// Individual cost dimensions.
    pub dimensions: Vec<CostDimension>,
    /// Total monetary cost across all API cost dimensions, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_monetary_cost: Option<MonetaryAmount>,
}

impl CostMetadata {
    /// Create a new cost metadata record.
    pub fn new(
        receipt_id: String,
        timestamp: u64,
        agent_id: String,
        tool_server: String,
        tool_name: String,
    ) -> Self {
        Self {
            schema: COST_METADATA_SCHEMA.to_string(),
            receipt_id,
            timestamp,
            session_id: None,
            agent_id,
            tool_server,
            tool_name,
            dimensions: Vec::new(),
            total_monetary_cost: None,
        }
    }

    /// Add a cost dimension.
    pub fn add_dimension(&mut self, dim: CostDimension) {
        self.dimensions.push(dim);
    }

    /// Compute and set the total monetary cost from all ApiCost dimensions.
    ///
    /// Only sums dimensions with the same currency. If dimensions use different
    /// currencies, the total is set to the first currency encountered and
    /// cross-currency amounts are ignored (use oracle conversion for those).
    pub fn compute_total_monetary_cost(&mut self) {
        self.total_monetary_cost = None;
        let mut total_units: u64 = 0;
        let mut currency: Option<String> = None;

        for dim in &self.dimensions {
            if let CostDimension::ApiCost { amount, .. } = dim {
                match &currency {
                    None => {
                        currency = Some(amount.currency.clone());
                        total_units = amount.units;
                    }
                    Some(c) if c == &amount.currency => {
                        total_units = total_units.saturating_add(amount.units);
                    }
                    _ => {
                        // Cross-currency -- skip without oracle
                    }
                }
            }
        }

        if let Some(cur) = currency {
            self.total_monetary_cost = Some(MonetaryAmount {
                units: total_units,
                currency: cur,
            });
        }
    }

    /// Total compute time across all ComputeTime dimensions.
    #[must_use]
    pub fn total_compute_time_ms(&self) -> u64 {
        self.dimensions
            .iter()
            .filter_map(|d| match d {
                CostDimension::ComputeTime { duration_ms } => Some(*duration_ms),
                _ => None,
            })
            .fold(0u64, u64::saturating_add)
    }

    /// Total data volume (read + written) across all DataVolume dimensions.
    #[must_use]
    pub fn total_data_bytes(&self) -> u64 {
        self.dimensions
            .iter()
            .filter_map(|d| match d {
                CostDimension::DataVolume {
                    bytes_read,
                    bytes_written,
                } => Some(bytes_read.saturating_add(*bytes_written)),
                _ => None,
            })
            .fold(0u64, u64::saturating_add)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_metadata_roundtrip() {
        let mut meta = CostMetadata::new(
            "r-1".to_string(),
            1700000000,
            "agent-1".to_string(),
            "srv-1".to_string(),
            "tool-a".to_string(),
        );
        meta.add_dimension(CostDimension::ComputeTime { duration_ms: 150 });
        meta.add_dimension(CostDimension::DataVolume {
            bytes_read: 1024,
            bytes_written: 512,
        });
        meta.add_dimension(CostDimension::ApiCost {
            amount: MonetaryAmount {
                units: 50,
                currency: "USD".to_string(),
            },
            provider: "openai".to_string(),
        });
        meta.compute_total_monetary_cost();

        let json = serde_json::to_string(&meta).unwrap();
        let deserialized: CostMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.receipt_id, "r-1");
        assert_eq!(deserialized.dimensions.len(), 3);
        assert_eq!(deserialized.total_monetary_cost.as_ref().unwrap().units, 50);
    }

    #[test]
    fn compute_total_sums_same_currency() {
        let mut meta = CostMetadata::new(
            "r-2".to_string(),
            1700000000,
            "agent-1".to_string(),
            "srv-1".to_string(),
            "tool-a".to_string(),
        );
        meta.add_dimension(CostDimension::ApiCost {
            amount: MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            },
            provider: "a".to_string(),
        });
        meta.add_dimension(CostDimension::ApiCost {
            amount: MonetaryAmount {
                units: 200,
                currency: "USD".to_string(),
            },
            provider: "b".to_string(),
        });
        meta.compute_total_monetary_cost();
        assert_eq!(meta.total_monetary_cost.as_ref().unwrap().units, 300);
        assert_eq!(meta.total_monetary_cost.as_ref().unwrap().currency, "USD");
    }

    #[test]
    fn total_compute_time() {
        let mut meta = CostMetadata::new(
            "r-3".to_string(),
            0,
            "a".to_string(),
            "s".to_string(),
            "t".to_string(),
        );
        meta.add_dimension(CostDimension::ComputeTime { duration_ms: 100 });
        meta.add_dimension(CostDimension::ComputeTime { duration_ms: 250 });
        assert_eq!(meta.total_compute_time_ms(), 350);
    }

    #[test]
    fn total_data_bytes() {
        let mut meta = CostMetadata::new(
            "r-4".to_string(),
            0,
            "a".to_string(),
            "s".to_string(),
            "t".to_string(),
        );
        meta.add_dimension(CostDimension::DataVolume {
            bytes_read: 100,
            bytes_written: 50,
        });
        meta.add_dimension(CostDimension::DataVolume {
            bytes_read: 200,
            bytes_written: 30,
        });
        assert_eq!(meta.total_data_bytes(), 380);
    }

    #[test]
    fn compute_total_with_zero_costs() {
        let mut meta = CostMetadata::new(
            "r-zero".to_string(),
            0,
            "a".to_string(),
            "s".to_string(),
            "t".to_string(),
        );
        meta.add_dimension(CostDimension::ApiCost {
            amount: MonetaryAmount {
                units: 0,
                currency: "USD".to_string(),
            },
            provider: "free".to_string(),
        });
        meta.compute_total_monetary_cost();
        assert_eq!(meta.total_monetary_cost.as_ref().unwrap().units, 0);
    }

    #[test]
    fn compute_total_with_mixed_currencies_takes_first() {
        let mut meta = CostMetadata::new(
            "r-mixed".to_string(),
            0,
            "a".to_string(),
            "s".to_string(),
            "t".to_string(),
        );
        meta.add_dimension(CostDimension::ApiCost {
            amount: MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            },
            provider: "a".to_string(),
        });
        meta.add_dimension(CostDimension::ApiCost {
            amount: MonetaryAmount {
                units: 200,
                currency: "EUR".to_string(),
            },
            provider: "b".to_string(),
        });
        meta.compute_total_monetary_cost();
        // Only USD should be summed, EUR skipped
        assert_eq!(meta.total_monetary_cost.as_ref().unwrap().units, 100);
        assert_eq!(meta.total_monetary_cost.as_ref().unwrap().currency, "USD");
    }

    #[test]
    fn no_api_costs_produces_no_total() {
        let mut meta = CostMetadata::new(
            "r-none".to_string(),
            0,
            "a".to_string(),
            "s".to_string(),
            "t".to_string(),
        );
        meta.add_dimension(CostDimension::ComputeTime { duration_ms: 500 });
        meta.compute_total_monetary_cost();
        assert!(meta.total_monetary_cost.is_none());
    }

    #[test]
    fn recompute_total_clears_stale_cost_when_no_api_costs_remain() {
        let mut meta = CostMetadata::new(
            "r-stale".to_string(),
            0,
            "a".to_string(),
            "s".to_string(),
            "t".to_string(),
        );
        meta.add_dimension(CostDimension::ApiCost {
            amount: MonetaryAmount {
                units: 42,
                currency: "USD".to_string(),
            },
            provider: "p".to_string(),
        });
        meta.compute_total_monetary_cost();
        assert_eq!(meta.total_monetary_cost.as_ref().unwrap().units, 42);

        meta.dimensions.clear();
        meta.compute_total_monetary_cost();

        assert!(meta.total_monetary_cost.is_none());
    }

    #[test]
    fn empty_dimensions_produce_zero_totals() {
        let meta = CostMetadata::new(
            "r-empty".to_string(),
            0,
            "a".to_string(),
            "s".to_string(),
            "t".to_string(),
        );
        assert_eq!(meta.total_compute_time_ms(), 0);
        assert_eq!(meta.total_data_bytes(), 0);
    }

    #[test]
    fn custom_dimension_roundtrip() {
        let dim = CostDimension::Custom {
            name: "tokens".to_string(),
            value: 4096,
            unit: Some("tokens".to_string()),
        };
        let json = serde_json::to_string(&dim).unwrap();
        let back: CostDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(back, dim);
    }

    #[test]
    fn warehouse_query_dimension_roundtrip() {
        let dim = CostDimension::WarehouseQuery {
            bytes_scanned: 50 * 1024 * 1024 * 1024,
            estimated_cost_usd: "0.25".to_string(),
        };
        let json = serde_json::to_string(&dim).unwrap();
        let back: CostDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(back, dim);
        // Also verify the serde tag carries through.
        assert!(json.contains("\"dimension\":\"warehouse_query\""));
        assert!(json.contains("\"bytes_scanned\""));
        assert!(json.contains("\"estimated_cost_usd\""));
    }
}
