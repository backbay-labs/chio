# chio-data-guards

Data-layer guards for the Chio kernel: guards that reason about the semantics
of a data-store access, not just which tool was called. `SqlQueryGuard` parses
SQL text, `VectorDbGuard` inspects vector-database call shape,
`WarehouseCostGuard` evaluates warehouse dry-run cost, and `QueryResultGuard`
reshapes query results after invocation. The crate is a sibling of
`chio-guards`: it reuses that crate's `Guard` trait plumbing and action
classification instead of redefining them, so pipelines compose guards from
both crates transparently.

## Responsibilities

- Parse SQL text and enforce operation, table, column, and predicate-denylist
  policy on database tool calls (`SqlQueryGuard`), rejecting multi-statement
  payloads and anything that fails to parse.
- Enforce collection, namespace, operation-class, and `top_k` policy on
  vector-database tool calls (`VectorDbGuard`), matched by vendor substring
  against the database identifier or tool name.
- Enforce pre-execution byte and cost ceilings on warehouse queries from
  caller-supplied dry-run metadata (`WarehouseCostGuard`); the guard never
  contacts a warehouse itself.
- Truncate rows, redact denylisted columns, and redact PII-pattern matches in
  query tool responses after invocation (`QueryResultGuard`).
- Fail closed: an unconfigured or empty policy denies every matching request
  unless a guard's `allow_all` escape hatch is set, and `allow_all` never
  overrides a parse or classification failure.

## Public API

| Guard | Config | `Guard::name()` |
|-------|--------|------------------|
| `SqlQueryGuard` | `SqlGuardConfig` | `sql-query` |
| `VectorDbGuard` | `VectorGuardConfig` | `vector-db` |
| `WarehouseCostGuard` | `WarehouseCostGuardConfig` | `warehouse-cost` |
| `QueryResultGuard` | `QueryResultGuardConfig` | `query-result` |

`QueryResultGuard` is post-invocation only: its `Guard::evaluate` impl always
returns `Allow`. Install it via `as_hook`/`into_owned_hook` into a
`PostInvocationPipeline` rather than expecting it to deny pre-invocation.

- `SqlQueryGuard::analyze(&self, query: &str) -> Result<SqlAnalysis, SqlGuardDenyReason>` -
  parses and evaluates a query; the primary SQL integration and test entry point.
- `VectorDbGuard::{check, extract_call}` - evaluate an extracted `VectorCall`
  against a `ChioScope`, denying with `VectorGuardDenyReason`.
- `WarehouseCostGuard::{check, extract_estimate, record_cost}` - evaluate a
  `DryRunEstimate`; `record_cost` produces a `chio_metering::CostDimension` for
  the outgoing receipt.
- `QueryResultGuard::{redact_result, redact_result_for_request, as_hook,
  into_owned_hook}` - redact a response in place, or adapt the guard into a
  `PostInvocationHook` (`QueryResultHook`, or `result_guard::OwnedQueryResultHook`
  for a `'static` owned variant).
- `SqlAnalysis`, `VectorCall`, `DryRunEstimate` - normalized views each guard
  evaluates.
- `DEFAULT_REDACTION_MARKER` - default value of
  `QueryResultGuardConfig::redaction_marker` (`"[REDACTED]"`).

## Testing

`cargo test -p chio-data-guards`

## See also

- `chio-guards` - supplies the `Guard`/`GuardPipeline` plumbing, action
  classification, and `PostInvocationHook` contract this crate builds on.
- `chio-kernel` - supplies `Guard`, `GuardContext`, `GuardDecision`, and
  `KernelError`.
- `chio-control-plane` - loads operator policy and wires these guards into its
  `GuardPipeline`.
