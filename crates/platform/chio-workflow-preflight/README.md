# chio-workflow-preflight

Read-only verifier for workflow preflight plans. Given a parent task's scope,
its child tasks, and plan-wide gates (route support, approvals, schema
registry, budget pool, revocation freshness), it checks whether the child
tasks stay inside the parent's authority and returns a report recording the
verdict. The report is planning evidence only: it never executes a workflow,
mints a capability, dispatches a tool, or mutates a runtime store, and it can
never claim live runtime authority.

Distinct from `chio-workflow`: that crate owns workflow execution
(`SkillGrant`, `SkillManifest`, `WorkflowReceipt`, `WorkflowAuthority`) and
re-exports this crate's public API under its `preflight` module. This crate
has no `chio-*` dependencies of its own.

## Responsibilities

- Validate plan shape: schema tag, required non-empty fields, non-empty
  parent/child scopes, and a 64-character lowercase hex SHA-256 revocation
  root. A shape failure returns `Err(WorkflowPreflightError)` before any
  policy check runs.
- Check that every child task's requested scope (actions, resources, route
  refs, approval refs, required schemas, currency, budget) is contained in
  the parent task's scope, including the aggregate child budget against the
  parent budget.
- Check plan-wide gates: route support, approval status, schema-registry
  coverage, budget-pool currency and totals, revocation freshness, and that
  no planning artifact claims to satisfy a live-authority claim.
- Return a `WorkflowPreflightReport` with an `Accepted` or `Rejected`
  verdict and the list of rejected checks. A structurally valid plan always
  returns `Ok`, even when the verdict is `Rejected`.

## Public API

- `evaluate_workflow_preflight(&WorkflowPreflightPlan) -> Result<WorkflowPreflightReport, WorkflowPreflightError>`
  - the entry point.
- `WorkflowPreflightPlan`, `WorkflowPreflightParentTask`, `WorkflowPreflightChildTask`,
  `WorkflowPreflightScope` - the input plan and its scopes.
- `WorkflowRoutePlanPreflight`, `WorkflowApprovalPreflight`, `WorkflowRegistrySupport`,
  `WorkflowBudgetPool`, `WorkflowRevocationPreflight`, `WorkflowPlanningArtifact` -
  plan-wide gate inputs.
- `WorkflowPreflightReport`, `WorkflowPreflightVerdict`, `WorkflowPreflightCheck` -
  the output report and its rejection entries.
- `WorkflowPreflightError` - `UnsupportedSchema` and `InvalidPlan`.
- `WORKFLOW_PREFLIGHT_PLAN_SCHEMA`, `WORKFLOW_PREFLIGHT_REPORT_SCHEMA` -
  `"chio.workflow.preflight-plan.v1"` and `"chio.workflow.preflight-report.v1"`.

## Usage

```rust
use chio_workflow_preflight::{evaluate_workflow_preflight, WorkflowPreflightPlan};

let plan: WorkflowPreflightPlan = serde_json::from_slice(&plan_bytes)?;
let report = evaluate_workflow_preflight(&plan)?;
```

## Testing

`cargo test -p chio-workflow-preflight`

Integration tests read fixtures from
`fixtures/proof-room/workflow-preflight/<case>/preflight-plan.json` at the
workspace root.

## See also

- `chio-workflow` - re-exports this crate's public API under its `preflight`
  module; owns workflow execution, which this crate does not touch.
- `chio-proof-room` - depends on this crate directly to render
  workflow-preflight proof-room fixtures.
- `chio-cli` - runs the `workflow preflight` command through `chio-workflow`'s
  re-export.
