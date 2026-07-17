# chio-metering

Attributes cost to receipts and enforces spending limits against that cost.
The crate owns two independent budget models: a flat enforcer scoped to a
session, agent, or tool, and a tree-shaped hierarchy where every ancestor node
caps a draft spend. Query and billing-export projections read the same cost
records. The crate holds no state beyond a single call: no persistence, no
receipt signing, no kernel execution.

## Responsibilities

- Attach cost metadata to a receipt across five dimensions: compute time,
  data volume, monetary API cost, warehouse-query cost, and an open-ended
  custom dimension (`cost::CostMetadata`, `cost::CostDimension`).
- Filter and aggregate cost metadata by session, agent, tool, time range, and
  currency, with grouping and a 500-record result cap
  (`query::execute_cost_query`).
- Enforce a flat budget policy scoped to total, per-session, per-agent, and
  per-tool spend (`budget::BudgetEnforcer`).
- Enforce a tree-shaped budget hierarchy where every ancestor node caps a
  draft spend across four dimensions (spend, tokens, requests, warehouse
  bytes) and reports the offending scope closest to the root
  (`budget_hierarchy::BudgetTree`).
- Project cost metadata into a flat, denormalized billing-export schema for
  external billing pipelines (`export::create_billing_export`).

## Public API

Re-exported at the crate root:

- `cost::{CostMetadata, CostDimension}` - a receipt's cost record and its
  per-dimension breakdown.
- `budget::{BudgetEnforcer, BudgetPolicy, BudgetViolation}` - flat budget
  tracking and enforcement.
- `budget_hierarchy::{BudgetTree, BudgetNode, BudgetNodeId, BudgetWindow,
  BudgetLimits, AggregateSpend, SpendSnapshot, PerWindowSpend,
  BudgetDecision, BudgetDenyReason, BudgetError}` - tree-shaped, parent-capped
  budget policy and evaluation.
- `export::{BillingExport, BillingRecord}` - the flattened billing-record
  schema.
- `query::{CostQuery, CostQueryResult, CostSummary}` - query parameters and
  results.

Public but not re-exported at the crate root, so callers reach them through
the module path:

- `query::execute_cost_query`, `query::GroupBy`, `query::CostGroup` - the
  query entry point and its grouping types.
- `export::create_billing_export` - the export entry point.

## Testing

`cargo test -p chio-metering`

## See also

- `chio-core` - supplies `MonetaryAmount` (`capability::scope`), used by
  `cost`, `budget`, `query`, and `export`.
- `chio-data-guards` - `WarehouseCostGuard` constructs
  `CostDimension::WarehouseQuery` values from dry-run warehouse cost
  estimates.
