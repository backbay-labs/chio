# chio-metering Architecture

`chio-metering` owns cost attribution and budget-decision data structures for
receipt economics. It is intentionally storage-agnostic: callers provide
receipt cost metadata, current spend snapshots, and export timestamps, while
this crate performs deterministic aggregation, validation, and policy checks.

## Boundaries

- `chio-core` owns shared monetary amount types consumed by cost metadata and
  budget policies.
- `cost` owns per-receipt cost dimensions and derived totals for compute time,
  data volume, API spend, warehouse queries, and custom dimensions.
- `query` owns in-memory filtering, result limiting, grouping, and cumulative
  summaries for receipt cost records.
- `export` owns the flattened billing-record projection and export batch totals.
- `budget` owns flat per-session, per-agent, per-tool, and total budget counters.
- `budget_hierarchy` owns tree-shaped organizational budget configuration,
  construction validation, ancestor traversal, and snapshot-based evaluation.
- This crate does not own persistence, exchange-rate conversion, receipt
  signing, kernel execution, or external billing transport.

## Trust Invariants

- Invalid budget-tree shape rejects at construction or deserialization time.
- Spend limits that set `max_spend_units` must include a non-empty currency, so
  monetary caps cannot silently become inert.
- A spend-capped node denies drafts whose currency is absent or mismatched. A
  snapshot currency must match when present and may be absent only at zero.
- Budget evaluation never mutates caller-provided snapshots.
- Hierarchical monetary aggregation rejects overflow. Query totals, billing
  totals, and flat budget counters saturate instead of wrapping.
- Mixed-currency summaries omit aggregate monetary totals unless every included
  monetary record uses the same currency.
- Hierarchical budget evaluation walks from leaf to root and returns the
  broadest offending policy scope.

## Testing Focus

Unit tests cover cost metadata serialization, saturating totals, flat budget
violations, query filters, query grouping, export records, hierarchy insertion,
hierarchy serialization, ancestor traversal, disabled nodes, and construction
validation. Integration tests exercise hierarchy enforcement around parent
caps, rolling-window reset behavior, multiple dimensions, and unknown node
denial, including currency mismatches and monetary overflow.
