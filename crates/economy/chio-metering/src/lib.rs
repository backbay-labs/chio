//! Receipt metering and economics for the Chio protocol.
//!
//! This crate provides per-receipt cost attribution, cumulative cost queries,
//! monetary budget enforcement via chio-link oracle integration, and
//! billing-export-compatible cost metadata.
//!
//! # Modules
//!
//! - [`cost`] -- Per-receipt cost metadata (compute time, data volume, API cost)
//! - [`query`] -- CLI-style cost queries by session, agent, tool, or time range
//! - [`budget`] -- Monetary budget enforcement with denominated currency
//! - [`budget_hierarchy`] -- Tree-structured budget governance across
//!   organizational scopes (org -> department -> team -> agent)
//! - [`export`] -- Billing-export-compatible cost records

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod budget;
pub mod budget_hierarchy;
pub mod cost;
pub mod export;
pub mod query;

pub use budget::{BudgetEnforcer, BudgetEnforcerSnapshot, BudgetPolicy, BudgetViolation};
pub use budget_hierarchy::{
    AggregateSpend, BudgetDecision, BudgetDenyReason, BudgetError, BudgetLimits, BudgetNode,
    BudgetNodeId, BudgetTree, BudgetWindow, PerWindowSpend, SpendSnapshot,
};
pub use cost::{CostDimension, CostMetadata};
pub use export::{BillingExport, BillingRecord};
pub use query::{CostQuery, CostQueryResult, CostSummary};
