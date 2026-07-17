# chio-metering architecture

## Overview

`chio-metering` is a pure, storage-agnostic library: every entry point takes
caller-supplied data (a `CostMetadata` slice, a `SpendSnapshot`) and returns
an aggregate, a decision, or a projection, with no I/O and no state held
between calls; it forbids unsafe code. The crate holds two independent budget
models side by side rather than layering one on the other: `budget` is a flat
enforcer scoped to a single session, agent, or tool, while `budget_hierarchy`
is a tree of nodes where every ancestor caps a draft spend. `cost`, `query`,
and `export` operate on the same `CostMetadata` record from three angles:
attribution, aggregation, and billing projection.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public module declarations and crate-root re-exports. |
| `src/cost.rs` | `CostMetadata` and `CostDimension`: per-receipt cost dimensions and derived totals (`total_compute_time_ms`, `total_data_bytes`, `compute_total_monetary_cost`). |
| `src/budget.rs` | `BudgetEnforcer` and `BudgetPolicy`: flat total/session/agent/tool spend tracking (`check`, `record`). |
| `src/budget_hierarchy.rs` | `BudgetTree`: tree-shaped budget policy, construction validation, ancestor/descendant traversal, snapshot-based `evaluate`, and JSON (de)serialization. |
| `src/query.rs` | `execute_cost_query`: in-memory filter, group, and summarize over a `CostMetadata` slice. |
| `src/export.rs` | `create_billing_export`: flattens `CostMetadata` into `BillingRecord`/`BillingExport`. |

## Boundaries

- No persistence: `budget_hierarchy` takes a `SpendSnapshot` the caller reads
  from its own store (SQLite, Redis, in-memory); this crate never reads or
  writes one.
- No exchange-rate conversion: `budget::BudgetEnforcer::check` assumes
  `cost_units` is already denominated in the policy currency, and
  `budget_hierarchy::evaluate` fails closed on a spend cap when the draft
  carries a positive spend in a different or unstated currency (it denies
  rather than converting). Nothing in this crate calls an oracle;
  cross-currency conversion is the caller's responsibility and must run
  before evaluation.
- No receipt signing or kernel execution: this crate produces metadata and
  decisions for the kernel and guards to act on, not receipts themselves.
- No external billing transport: `export::create_billing_export` returns a
  `BillingExport` value; writing it to CSV, JSON-lines, or a billing API is
  left to the caller.

## Invariants and failure modes

- `BudgetTree::insert` and `BudgetTree::deserialize` reject invalid shape
  before a tree exists: duplicate node ids, a missing parent, a cycle in the
  parent chain, or a `max_spend_units` limit with no (or blank) `currency`.
- `BudgetTree::evaluate` never mutates the `SpendSnapshot` it is given; it
  borrows `&SpendSnapshot` and returns a `BudgetDecision`.
- `BudgetTree::evaluate` walks every ancestor from leaf to root without
  stopping at the first violation; when multiple ancestors are in violation,
  the reported `BudgetDenyReason` names the one closest to the root, so the
  broadest policy boundary surfaces first.
- A disabled `BudgetNode` (`enabled: false`) denies every draft charged to it
  or any descendant with `BudgetDenyReason::NodeDisabled`, regardless of
  limits.
- An `id` absent from the tree denies with `BudgetDenyReason::UnknownNode`
  rather than panicking.
- Spend aggregation (`AggregateSpend::saturating_add`), cost totals in
  `CostMetadata`, query summaries, and flat budget counters all saturate at
  `u64::MAX` instead of overflowing.
- Multi-currency aggregates (`CostMetadata::compute_total_monetary_cost`,
  `query::execute_cost_query`, `export::create_billing_export`) drop the
  monetary total to `None` rather than mixing currencies; the first currency
  encountered wins the partial sum and later ones are excluded from it.

## Dependencies

Internal: `chio-core` supplies `MonetaryAmount`
(`chio_core::capability::scope::MonetaryAmount`), used by `cost`, `budget`,
`query`, and `export`. `budget_hierarchy` does not depend on `chio-core`: it
represents spend as a raw `u64` unit count plus an optional currency string
(`AggregateSpend`, `BudgetLimits`), a separate representation from
`MonetaryAmount` used by the rest of the crate. External: `serde`/`serde_json`
for artifact and tree serialization, `thiserror` for `BudgetError`, and
`chrono` for Unix-to-ISO-8601 timestamp formatting in `export`.
