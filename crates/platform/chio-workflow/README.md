# chio-workflow

`chio-workflow` is the skill and workflow authority for Chio. It extends the
single-tool capability model with multi-step skill composition: a skill is
declared once as a `SkillManifest` (ordered steps, per-step I/O contracts,
budget and time envelopes), authorized once as a `SkillGrant`, driven through
`WorkflowAuthority`, and closed out as a signed `WorkflowReceipt` covering the
complete execution trace.

The crate also re-exports `chio-workflow-preflight`'s plan checks under
`chio_workflow::preflight` (and flattened at the crate root) so callers have
one import path. Preflight is a read-only, planning-time check with no
`chio-core` dependency and no signing; this crate is the stateful, signed
execution authority that runs after a plan is accepted.

## Responsibilities

- Define `SkillGrant`, extending the capability model to authorize an ordered
  sequence of `"server_id:tool_name"` steps under one budget/time/execution-
  count envelope instead of a `ToolGrant` per tool.
- Define `SkillManifest`, `SkillStep`, and `IoContract`: the skill author's
  declaration of steps, per-step field contracts, and budget/time envelopes,
  with `validate_io_contracts` checking that each step's required input
  fields were produced by an earlier step.
- Drive execution through `WorkflowAuthority`: match a grant against a
  manifest at `begin`, validate each step's authorization, order, and
  elapsed time before it runs, record every step outcome (including
  failures) for the audit trail, and enforce the budget envelope in
  `record_step`.
- Produce `WorkflowReceipt`, one signed artifact for the full execution
  trace, with optional detached vendor co-signatures
  (`add_vendor_signature`, `verify_vendor_signatures`).
- Re-export `chio-workflow-preflight`'s `evaluate_workflow_preflight` plan
  checker as `chio_workflow::preflight` and flattened at the crate root.

## Public API

Re-exported at the crate root (`chio_workflow::*`):

- `WorkflowAuthority`, `WorkflowExecution`, `WorkflowError` - execution
  lifecycle: `new`, `begin`, `validate_step`, `record_step`, `finalize`,
  `execution_count`. `WorkflowError` covers unauthorized skill/step,
  out-of-order step, budget exceeded or currency mismatch, time limit
  exceeded, execution limit reached, invalid state, and signing failure.
- `SkillGrant` - `new`, `authorizes_step`, `is_step_in_order`.
- `SkillManifest`, `SkillStep`, `IoContract` - `new`, `step_count`,
  `tool_dependencies`, `validate_io_contracts`.
- `WorkflowReceipt`, `WorkflowReceiptBody`, `WorkflowVendorSignature`,
  `VendorSignatureRequirement`, `WorkflowReceiptError`, `StepRecord` -
  `sign`, `body`, `verify`, `add_vendor_signature`,
  `verify_vendor_signatures`, `successful_steps`, `is_complete`.
- `evaluate_workflow_preflight`, `WorkflowPreflightPlan`,
  `WorkflowPreflightReport`, `WorkflowPreflightVerdict`,
  `WorkflowPreflightError` - re-exported from `chio-workflow-preflight`,
  also available as `chio_workflow::preflight::*`.

Module-path only (not flattened at the root):

- `receipt::{WorkflowOutcome, StepOutcome}` - workflow and per-step outcome
  enums.
- `authority::StepExecutionRecordInput` - the input struct to `record_step`.
- `grant::SKILL_GRANT_SCHEMA`, `manifest::SKILL_MANIFEST_SCHEMA`,
  `receipt::WORKFLOW_RECEIPT_SCHEMA` - schema identifier constants.

## Testing

`cargo test -p chio-workflow`

`tests/preflight.rs` reads a fixture plan from
`fixtures/proof-room/workflow-preflight/valid-child-scope/` at the workspace
root; run it from within the workspace, not as an extracted package.

## See also

- `chio-workflow-preflight` - the read-only plan checker this crate
  re-exports as `preflight`. It has no `chio-core` dependency and performs
  no signing; this crate adds the stateful, signed execution authority on
  top.
- `chio-core` - supplies `capability::scope::MonetaryAmount` for budget
  envelopes and `crypto::{Keypair, PublicKey, Signature}` for receipt
  signing and verification.
- `chio-attest-buyer-core`, `chio-attest-loopback`, `chio-selective-disclosure`
  - consume `receipt::*` types to verify workflow execution trust artifacts.
- `chio-cli` - drives `evaluate_workflow_preflight` from its `proof doctor`
  and `proof fixture` tooling.
