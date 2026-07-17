# chio-workflow architecture

## Overview

`chio-workflow` is a stateful library crate: `WorkflowAuthority` holds an
in-process execution ledger (atomics and a `Mutex<HashMap<..>>`) and a
signing `Keypair`, though the crate performs no network or disk I/O itself.
Its trust position sits above individual tool capabilities: it does not
evaluate guard policy for a single tool call (`chio-kernel`'s guard pipeline
does that), and `chio-kernel` does not depend on it in this workspace.
Instead it is consumed directly by the trust/attestation crates that verify
`WorkflowReceipt`s and by `chio-cli`, which runs the bundled
`chio-workflow-preflight` facade. The design keeps three artifacts as
independent serde types: a manifest (what a skill is), a grant (what an
agent may run), and a receipt (what happened), so a grant can be checked
against a manifest without a kernel, and a receipt can be verified by a
third party holding only the signer's public key.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate root: declares modules, flattens the public API, wraps `chio-workflow-preflight` as `preflight`. |
| `src/grant.rs` | `SkillGrant`: capability-model extension authorizing an ordered `"server:tool"` step sequence under one budget/time/execution-count envelope. |
| `src/manifest.rs` | `SkillManifest`, `SkillStep`, `IoContract`: skill declaration and `validate_io_contracts` cross-step field checking. |
| `src/authority.rs` | `WorkflowAuthority`: execution lifecycle (`begin`, `validate_step`, `record_step`, `finalize`), `WorkflowExecution` state, `WorkflowError`. |
| `src/receipt.rs` | `WorkflowReceipt`, `WorkflowReceiptBody`: signing, verification, vendor co-signatures, `WorkflowOutcome`, `StepRecord`, `StepOutcome`. |

## Execution lifecycle

1. A skill author builds a `SkillManifest` (steps, I/O contracts, budget and
   time envelope); a grantor issues a `SkillGrant` naming the same
   `skill_id`/`skill_version` and the `"server:tool"` steps the agent may
   run.
2. `WorkflowAuthority::begin` rejects a skill/version mismatch or any
   manifest step the grant does not authorize, reserves one slot against
   `grant.max_executions` if set, and returns a `WorkflowExecution` seeded
   with the grant's budget and time limits (falling back to the manifest's).
3. Before each step runs, `validate_step` checks the execution is still
   active, the step is authorized, and, under `strict_ordering` (the
   default), that the step index equals the number of completed steps.
4. After the tool call, `record_step` always appends a `StepRecord`, even
   when the step is over budget or over time, so the audit trail stays
   complete. It deactivates the execution on a step budget breach, a
   step/execution currency mismatch, the aggregate budget envelope being
   exceeded, the time limit being exceeded, or a `Failed`/`Denied` outcome.
5. `finalize` computes `duration_ms` and, if no step already failed or was
   denied and no terminal outcome is set yet, re-checks the time limit
   against wall-clock elapsed time, catching a workflow that expired
   between the last `record_step` and `finalize`.
6. It resolves the receipt's `WorkflowOutcome` (a recorded step failure or
   denial first, then any outcome already set by `record_step` or step 5,
   then a final aggregate-budget check, else `Completed`), signs the
   `WorkflowReceiptBody` with the authority's `Keypair`, and releases the
   reserved execution slot.

## Invariants and failure modes

- `begin` fails closed on a skill/version mismatch, any unauthorized step,
  and a reached `max_executions` limit; the limit is reserved when `begin`
  starts, not released until `finalize`, so concurrent `begin` calls cannot
  both succeed past the limit.
- A step cost whose currency does not match the step's or the execution's
  budget currency is rejected without adding to `budget_spent`, and drives
  the execution to a `Denied` outcome.
- A recorded `Failed` or `Denied` step outcome always wins the final
  `WorkflowOutcome`, even over a time limit that `finalize` discovers has
  since elapsed.
- Execution ids mix a monotonic per-authority counter with the agent id
  (`wf-{unix_secs}-{counter}-{agent_id}`) so multiple `begin` calls in the
  same wall-clock second never collide.
- `WorkflowReceipt::verify` fails closed on a schema string other than
  `WORKFLOW_RECEIPT_SCHEMA` before it checks the signature.
- `finalize` deactivates the execution unconditionally and signs a receipt
  for whatever `WorkflowOutcome` the execution reached; it returns an error
  only on a signing failure or a poisoned execution-counter lock, never as
  a decision to discard the execution.

## Dependencies

`chio-core` supplies `capability::scope::MonetaryAmount` for budget
envelopes and `crypto::{Keypair, PublicKey, Signature}` for receipt signing
and verification; the workspace `chio-core` package is used directly, with
no `package =` aliasing. `chio-workflow-preflight` is re-exported wholesale
as the `preflight` module; it has no `chio-core` dependency and shares no
types with the rest of this crate (its own `WorkflowPreflightScope` carries
a plain `budget_minor`/`currency` pair rather than `MonetaryAmount`).
`serde`/`serde_json` provide the wire format for grants, manifests, and
receipts; `thiserror` derives `WorkflowError` and `WorkflowReceiptError`;
`tracing` emits `debug` events from `begin` and `finalize`.
