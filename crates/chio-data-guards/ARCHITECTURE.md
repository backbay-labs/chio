# chio-data-guards Architecture

## Role

`chio-data-guards` is the workspace boundary for data-store semantic enforcement. It turns tool-call arguments and result payloads into data-layer decisions that the kernel can compose with capability matching, receipt signing, and other guard verdicts.

The crate is intentionally narrower than `chio-guards`. `chio-guards` classifies broad tool actions. `chio-data-guards` understands database-shaped semantics such as SQL operations, vector collection access, warehouse dry-run estimates, and query result redaction.

## Public Surface

- `SqlQueryGuard` parses SQL and enforces table, column, predicate, and operation policies.
- `QueryResultGuard` applies row, column, and PII shaping after invocation.
- `VectorDbGuard` enforces vector database collection, namespace, operation class, and `top_k` policy.
- `WarehouseCostGuard` evaluates dry-run cost estimates before expensive warehouse queries run.
- The config types are public because control-plane and CLI code need to load operator policy before guard construction.

The crate has two direct workspace dependents, `chio-control-plane` and `chio-cli`. Several product and conformance crates depend on it through those surfaces. Changes here must preserve the exported type names and denial semantics unless a caller migration is explicit.

## Security Contracts

- Guard failures are fail-closed for data-layer traffic the guard can classify.
- Unknown non-data traffic passes through this crate and is denied, allowed, or mediated by the composing guard pipeline.
- Capability constraints remain authoritative when present. The guard reads `Constraint::OperationClass`, `Constraint::MaxRowsReturned`, table allowlists, and column denylists where the specific sub-guard can evaluate them.
- Operator allowlists are case-insensitive where the guarded substrate commonly treats identifiers case-insensitively.
- Redaction and result shaping must never silently skip malformed rows when a constraint requires knowing row shape.

## Internal Boundaries

- `sql_parser.rs` owns parsed SQL statement analysis.
- `sql_guard.rs` owns SQL policy evaluation over `SqlAnalysis`.
- `result_guard.rs` owns post-invocation row and column shaping.
- `vector_guard.rs` owns vector SDK argument extraction and vector-specific checks.
- `warehouse_cost_guard.rs` owns dry-run estimate extraction, decimal comparison, and metering dimension creation.
- `config.rs` and `error.rs` keep shared SQL config and denial error types stable for external callers.

The default redactor under `redactors/default` is a sibling package. It is related, but not part of this crate's API surface.

## Current Design Pressure

Each sub-guard has its own argument extraction logic because the data sources differ. That keeps policy local, but it also means helper behavior can diverge. The warehouse guard already treats field path overrides as dotted JSON paths. The vector guard documented the same concept, but its extractor only looked at top-level keys. That mismatch is small in code size but material in behavior: nested SDK payloads could be denied despite a correctly configured path override.

## Current Slice

This slice aligns vector field extraction with the documented JSON field-path contract while preserving top-level key compatibility. The change is intentionally internal: callers keep using `VectorGuardConfig::field_paths`, existing default keys still work, and nested payload support becomes available for vendor adapters that wrap vector call parameters under request or options objects.
