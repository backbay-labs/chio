# chio-workflow-preflight architecture

## Overview

`chio-workflow-preflight` is a pure library: no I/O, no runtime state, no
`chio-*` dependencies. Its one entry point, `evaluate_workflow_preflight`,
maps one input type (`WorkflowPreflightPlan`) to one output type
(`WorkflowPreflightReport`). Its role is a pre-execution gate: the report is
planning evidence that can support proof claims about bounded child scope,
but the crate has no code path that can populate a live-authority claim.

It is kept separate from `chio-workflow` (which owns workflow execution) so
that read-only planning checks can run in proof-room fixture generation and
the CLI's `workflow preflight` command without pulling in execution state or
a runtime.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public API surface and `evaluate_workflow_preflight`; declares the private verified-claim constants. |
| `src/types.rs` | All data types (plan, scope, report, check, error, verdict) and the two schema constants. |
| `src/scope.rs` | `collect_child_scope_checks`: child-scope-vs-parent-scope containment, including the `"*"` wildcard and an overflow-safe aggregate budget check. |
| `src/validation.rs` | `validate_plan_shape` (hard structural validation) and `collect_plan_gate_checks` (route, approval, registry, budget-pool, revocation, and planning-artifact checks). |

## Evaluation flow

`evaluate_workflow_preflight` runs two phases that fail differently:

1. **Shape validation** (`validate_plan_shape`, hard failure): schema tag
   matches `WORKFLOW_PREFLIGHT_PLAN_SCHEMA`; required string fields (`id`,
   `issued_at`, task ids, currencies, revocation fields) are non-blank;
   `child_tasks` is non-empty; every scope's `actions` and `resources` are
   non-empty and every scope entry is non-blank; `revocation.root_sha256` is
   exactly 64 lowercase hex characters. Any failure returns
   `Err(WorkflowPreflightError)` and no policy check runs.
2. **Policy checks** (soft failure, always `Ok`):
   - `collect_child_scope_checks` walks each child task and pushes one
     `workflow_preflight_child_scope_exceeds_parent` check per violation:
     parent/child task-id linkage, containment of actions, resources, route
     refs, approval refs, and required schemas (a parent entry of `"*"`
     exempts that field from the containment check), currency match, the
     per-child budget, and the aggregate of all child budgets against the
     parent budget. Every violation in this module shares one check code
     regardless of which field failed.
   - `collect_plan_gate_checks` runs six independent passes with distinct
     check codes: route support and route-ref conflicts
     (`workflow_preflight_route_conflict`, `..._route_not_supported`),
     approval status and conflicts (`..._approval_conflict`,
     `..._approval_not_ready`), schema-registry coverage
     (`..._schema_not_supported`), budget-pool currency and totals
     (`..._budget_currency_mismatch`, `..._budget_pool_exceeded`),
     revocation freshness (`..._revocation_not_fresh`), and
     planning-artifact authority claims
     (`..._planning_artifact_claims_authority`: any artifact with a
     non-empty `satisfies_claims` is rejected outright, regardless of its
     `artifact_class`).

The verdict is `Accepted` only if both passes produce zero checks; otherwise
`Rejected`. `verified_claims` is populated with two fixed claim strings
(`claim.workflow.preflight_child_scope_bounded`,
`claim.workflow.preflight_planning_only`) only on `Accepted`, and is empty on
`Rejected`. `live_authority_claims` is always `Vec::new()` and
`evidence_class` is always `"planning"`, independent of verdict. The report's
`id` is `workflow-preflight-report-<plan.id>`; `plan_id` echoes the input
plan's `id` verbatim.

## Invariants and failure modes

- Fail-closed shape validation: a structurally malformed plan never reaches
  policy checking; `evaluate_workflow_preflight` returns `Err` instead.
- Every plan and report struct derives `#[serde(deny_unknown_fields)]`:
  unrecognized JSON fields fail deserialization instead of being dropped.
- `live_authority_claims` has no producing code path in this crate; it is
  always empty. A consumer that needs live-authority evidence must get it
  from a runtime component, not from this crate's report.
- Planning artifacts can never satisfy a live-authority claim: a non-empty
  `satisfies_claims` on a `WorkflowPlanningArtifact` is rejected regardless
  of `artifact_class`.
- Budget aggregation (both the child-scope total and the budget-pool total)
  uses `checked_add` and treats overflow as a rejection, not a panic or a
  silent wraparound.
- The `"*"` wildcard is recognized only for `actions`, `resources`,
  `route_refs`, `approval_refs`, and `required_schemas` in a parent scope;
  `currency` and `budget_minor` have no wildcard and are always checked.

## Dependencies

No internal `chio-*` dependencies: this is a leaf crate. External: `serde`
and `serde_json` for plan and report (de)serialization, `thiserror` for
`WorkflowPreflightError`. Consumed by `chio-workflow` (re-exported under its
`preflight` module and used by `chio-cli`'s `workflow preflight` command) and
directly by `chio-proof-room` (evaluates `preflight-plan.json` fixtures into
report JSON for the proof room).
