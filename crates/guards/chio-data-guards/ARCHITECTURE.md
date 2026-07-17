# chio-data-guards architecture

## Overview

`chio-data-guards` runs inside the kernel's guard pipeline as part of the
enforcement path, not an untrusted edge: its verdicts gate whether a tool call
proceeds. Each pre-invocation guard is a narrow `chio_kernel::Guard`
implementation that classifies the call via `chio_guards::extract_action_checked`,
evaluates policy fail-closed, and returns `Allow` unconditionally for any
action shape it does not recognize: guards in this crate are additive, and
deny-by-default is enforced by the pipeline that composes them, not by an
individual guard. `QueryResultGuard` is the exception: it runs after the tool
responds and reshapes the response instead of denying it. No guard performs
I/O of its own (`WarehouseCostGuard` reads a dry-run estimate the caller
already attached to the arguments rather than contacting a warehouse), and the
crate forbids unsafe code.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate facade: declares the seven modules and re-exports their public types. |
| `src/config.rs` | `SqlGuardConfig`, `SqlDialect`, `SqlOperation`, and their allowlist/lookup helpers. |
| `src/sql_parser.rs` | Wraps `sqlparser` to produce `SqlAnalysis` (operation class, tables, projected columns, `WHERE` presence) so the guard never sees parser types. |
| `src/sql_guard.rs` | `SqlQueryGuard`: evaluates `SqlAnalysis` against `SqlGuardConfig`; the SQL `chio_kernel::Guard` impl. |
| `src/error.rs` | `SqlGuardDenyReason`, the structured denial enum for the SQL guard. |
| `src/vector_guard.rs` | `VectorDbGuard`: vendor-substring detection, configurable field-path argument extraction, collection/namespace/operation-class/`top_k` policy. |
| `src/warehouse_cost_guard.rs` | `WarehouseCostGuard`: dry-run estimate extraction, decimal-string comparison, `CostDimension` emission. |
| `src/result_guard.rs` | `QueryResultGuard`: row truncation, column redaction, PII regex redaction; `PostInvocationHook` and `chio_kernel::Guard` impls. |

## Guard evaluation

Common path for the three pre-invocation guards:

1. `chio_guards::extract_action_checked` classifies the request's tool name and
   arguments into a `ToolAction`. A classification error denies immediately.
2. The guard checks the action is its shape and, for the vector and warehouse
   guards, that the database identifier or tool name matches a configured
   vendor substring. A non-matching action or substring returns `Allow`
   unconditionally, regardless of `allow_all`.
3. The guard extracts a normalized view from the arguments: `SqlAnalysis` (via
   `sqlparser`), a `VectorCall`, or a `DryRunEstimate`. Extraction failure
   denies.
4. The guard evaluates policy against that view. The vector and result guards
   also read the matched grant's `Constraint`s from the capability scope via
   `ctx.matched_grant_index`, falling back to the strictest constraint across
   every grant in scope when no match is attributed. Any failing check denies
   with a structured `*DenyReason`; an unconfigured policy denies unless
   `allow_all` is set.

`QueryResultGuard` runs after the tool responds instead of before it.
`redact_result_for_request` locates the row array (or, if a constrained
response is not row-shaped, replaces every value with the redaction marker),
truncates it to the matched grant's (or scope-wide strictest)
`MaxRowsReturned`, redacts `ColumnDenylist` matches, then applies configured
PII regex patterns. Its `chio_kernel::Guard::evaluate` impl always returns
`Allow`; `as_hook`/`into_owned_hook` build the real integration point, a
`PostInvocationHook` for `chio_guards::post_invocation::PostInvocationPipeline`.

## Invariants and failure modes

- Classification, parse, and extraction failures deny regardless of
  `allow_all`; `allow_all` only widens the allowlist checks that run after a
  successful parse.
- An empty policy denies every matching request unless `allow_all` is set
  (`SqlGuardConfig`/`VectorGuardConfig`/`WarehouseCostGuardConfig::is_empty`);
  every guard constructor logs a warning when `allow_all` is true.
- `sql_parser::parse` rejects multi-statement SQL outright, so a trailing
  `DROP TABLE` cannot hide behind an allowed leading `SELECT`.
- `SqlQueryGuard::enforce_columns` fails closed on unresolved (`"?"`)
  projections whenever a column allowlist is active: a computed expression or
  an unresolved join target could otherwise read any column from any table.
- `VectorDbGuard` fails closed when a `top_k` ceiling is configured but the
  call omits `top_k`, and when an `OperationClass` constraint is active but the
  call omits an operation verb.
- Operator-supplied regex (SQL predicate denylist, `QueryResultGuard` PII
  patterns) is bounded by pattern count, length, and a complexity score before
  compilation. `SqlQueryGuard::new` (infallible) falls back to a deny-all guard
  on invalid regex; `SqlQueryGuard::try_new` and `QueryResultGuard::new` return
  `Err` instead so policy loading can reject invalid configuration directly.
- `QueryResultGuard` redacts fail-closed: a constrained response that does not
  resolve to a recognized row shape has every value replaced by the marker
  instead of passing through unredacted.

## Dependencies

Internal: `chio-core` supplies `ChioScope`, `Constraint`, and `ToolGrant`, the
capability-scope types the vector and result guards read. `chio-kernel`
supplies `Guard`, `GuardContext`, `GuardDecision`, and `KernelError`, the trait
and types every guard here implements against. `chio-guards` supplies
`extract_action_checked`, `ToolAction`, and the
`PostInvocationHook`/`PostInvocationContext`/`PostInvocationVerdict` contract
`QueryResultGuard` implements. `chio-metering` supplies `CostDimension`, which
`WarehouseCostGuard::record_cost` produces. External: `sqlparser` backs
`sql_parser.rs`; `regex` backs predicate and PII pattern matching;
`serde`/`serde_json` (de)serialize guard configuration and inspect tool-call
arguments; `thiserror` derives the deny-reason enums; `tracing` emits
structured denial warnings. No dependency aliasing.
