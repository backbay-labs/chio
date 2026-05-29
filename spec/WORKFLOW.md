# Chio Workflow

**Version:** 1.0
**Date:** 2026-04-14
**Status:** Normative

This specification defines the skill and workflow authority system for Chio
runtimes. It extends the Chio capability model with multi-step tool
compositions, I/O contracts between steps, budget envelopes, and signed
workflow receipts. Implementations MUST follow the grant, manifest, receipt,
and authority lifecycle described herein.

---

## 1. Purpose

A skill is an ordered sequence of tool invocations that composes multiple
tools into a single authorized unit of work. The workflow system provides:

- **SkillGrant**: extends the capability model for ordered tool sequences
  with budget envelopes and execution limits
- **SkillManifest**: declares tool dependencies, I/O contracts between
  steps, and budget requirements
- **WorkflowReceipt**: captures the complete execution trace as a single
  signed, verifiable artifact
- **WorkflowAuthority**: validates each step against declared scope,
  ordering, budget, and time constraints

---

## 2. SkillGrant

A `SkillGrant` authorizes an agent to execute a named skill. Unlike
individual tool grants, a skill grant binds an entire tool sequence under a
single authorization with a shared budget envelope.

### 2.1 Schema

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `schema` | string | Yes | -- | MUST be `"chio.skill-grant.v1"` |
| `skill_id` | string | Yes | -- | Unique skill identifier (e.g., `"search-and-summarize"`) |
| `skill_version` | string | Yes | -- | Version of the skill manifest this grant authorizes |
| `authorized_steps` | string[] | Yes | -- | Tool steps in declared order; format `"server_id:tool_name"` |
| `max_executions` | u32 | No | `null` (unlimited) | Maximum number of complete skill executions |
| `budget_envelope` | MonetaryAmount | No | `null` | Budget for the entire execution |
| `max_duration_secs` | u64 | No | `null` | Maximum wall-clock seconds per execution |
| `strict_ordering` | bool | No | `true` | Whether steps MUST execute in declared order |

### 2.2 Step Authorization

A step is authorized if `"server_id:tool_name"` appears in the
`authorized_steps` list. Invocations of tools not in the list MUST be
rejected.

### 2.3 Ordering Modes

When `strict_ordering` is `true` (the default), each step MUST execute at
index equal to the number of previously completed steps. A step submitted
out of order MUST be rejected with `StepOutOfOrder`.

When `strict_ordering` is `false` (relaxed mode), steps may execute in any
order. All steps MUST still be in the `authorized_steps` list.

---

## 3. SkillManifest

A `SkillManifest` is authored by the skill developer and declares the full
execution plan for a skill.

### 3.1 Schema

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `schema` | string | Yes | -- | MUST be `"chio.skill-manifest.v1"` |
| `skill_id` | string | Yes | -- | Unique skill identifier |
| `version` | string | Yes | -- | Semantic version |
| `name` | string | Yes | -- | Human-readable name |
| `description` | string | No | `null` | Human-readable description |
| `steps` | SkillStep[] | Yes | -- | Ordered steps in the skill |
| `budget_envelope` | MonetaryAmount | No | `null` | Budget for a single execution |
| `max_duration_secs` | u64 | No | `null` | Maximum wall-clock seconds |
| `author` | string | No | `null` | Author identifier |

### 3.2 SkillStep

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `index` | usize | Yes | -- | Step index (0-based) |
| `server_id` | string | Yes | -- | Tool server hosting this step's tool |
| `tool_name` | string | Yes | -- | Tool to invoke |
| `label` | string | No | `null` | Human-readable step label |
| `input_contract` | IoContract | No | `null` | Input data contract |
| `output_contract` | IoContract | No | `null` | Output data contract |
| `budget_limit` | MonetaryAmount | No | `null` | Per-step budget limit |
| `retryable` | bool | No | `false` | Whether this step can be retried |
| `max_retries` | u32 | No | `null` | Maximum retries (only relevant when `retryable` is `true`) |

### 3.3 IoContract

The `IoContract` type describes data flow between steps.

| Field | Type | Description |
|-------|------|-------------|
| `required_fields` | string[] | Field names required by the step (inputs) or guaranteed (outputs) |
| `produced_fields` | string[] | Field names this step produces |
| `optional_fields` | string[] | Optional field names |
| `json_schema` | JSON | Optional JSON Schema for the data structure |

### 3.4 I/O Contract Validation

Implementations MUST validate that I/O contracts form a consistent data
flow:

- For each step after the first, every field in `input_contract.required_fields`
  MUST appear in the `output_contract.produced_fields` of some preceding step.
- The first step's input requirements come from the caller, not from
  preceding steps, and are therefore not validated against the manifest.
- Violations MUST be reported with the step index, tool name, and missing
  field name.

### 3.5 Tool Dependencies

The manifest's tool dependencies are the list of `"server_id:tool_name"`
strings derived from each step. The workflow authority uses this list to
verify the grant covers all required tools.

---

## 4. WorkflowReceipt

A `WorkflowReceipt` captures the complete execution of a skill as a single
signed artifact.

### 4.1 WorkflowReceiptBody

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique receipt ID |
| `schema` | string | MUST be `"chio.workflow-receipt.v1"` |
| `started_at` | u64 | Unix timestamp when execution started |
| `completed_at` | u64 | Unix timestamp when execution completed |
| `skill_id` | string | Skill ID from the manifest |
| `skill_version` | string | Skill version from the manifest |
| `agent_id` | string | Agent that executed the workflow |
| `session_id` | string | Session binding (nullable) |
| `capability_id` | string | Capability that authorized the workflow |
| `outcome` | WorkflowOutcome | Overall outcome |
| `steps` | StepRecord[] | Per-step execution records |
| `total_cost` | MonetaryAmount | Total cost (nullable) |
| `duration_ms` | u64 | Wall-clock duration in milliseconds |
| `kernel_key` | PublicKey | Kernel public key |

### 4.1.1 Schema Handling

`chio.workflow-receipt.v1` is the only Chio-owned workflow receipt schema
accepted before public release. Verifiers MUST reject unknown schema values
fail-closed.

### 4.2 WorkflowReceipt (Signed)

| Field | Type | Description |
|-------|------|-------------|
| _(all WorkflowReceiptBody fields)_ | -- | Inlined from body |
| `signature` | Signature | Ed25519 signature over canonical JSON of the body |
| `vendor_signatures` | VendorWorkflowSignature[] | Optional detached vendor co-signatures for the canonical workflow body |

The signature MUST be computed over `canonical_json_bytes(body)` using
RFC 8785 canonical JSON.

Each vendor co-signature signs the same canonical workflow body as the
kernel signature. A verifier supplied with required vendor signers MUST
reject missing vendor signatures, unknown vendor ids, duplicate vendor
ids, public-key mismatches, and invalid signatures.

### 4.3 WorkflowOutcome

| Variant | Fields | Description |
|---------|--------|-------------|
| `Completed` | -- | All steps completed successfully |
| `Denied` | `reason: string` | Workflow denied before execution started |
| `StepFailed` | `step_index: usize, reason: string` | A step failed, halting the workflow |
| `BudgetExceeded` | `limit_units: u64, spent_units: u64, currency: string` | Budget envelope exceeded |
| `TimedOut` | `limit_secs: u64, elapsed_secs: u64` | Time limit exceeded |
| `Cancelled` | `reason: string` | Cancelled by agent or operator |

### 4.4 StepRecord

| Field | Type | Description |
|-------|------|-------------|
| `step_index` | usize | Step index in the manifest |
| `server_id` | string | Tool server |
| `tool_name` | string | Tool name |
| `allowed` | bool | Whether the step was authorized to execute |
| `tool_receipt_id` | string | Receipt ID for the underlying tool call (nullable) |
| `outcome` | StepOutcome | Step-level outcome |
| `duration_ms` | u64 | Step duration in milliseconds |
| `cost` | MonetaryAmount | Cost attributed to this step (nullable) |
| `output_hash` | string | SHA-256 hash of step output (nullable) |
| `bilateral_dsse_sha256` | string | Optional SHA-256 hash of the strict bilateral DSSE envelope for this step |
| `governance_receipt_id` | string | Optional governance receipt id authorizing this step |
| `parent_receipt_sha256` | string | Optional SHA-256 hash of the previous step receipt in the workflow chain |
| `consistency_anchor` | string | Optional per-step consistency anchor value |
| `destructive` | bool | Optional destructive-action marker |

Destructive steps MUST be backed by a live capability lease and a matching
governance receipt when the verifier's action-class policy marks the step as
receipt-backed.

### 4.5 StepOutcome

| Value | Description |
|-------|-------------|
| `success` | Step completed successfully |
| `denied` | Step denied by policy |
| `failed` | Step failed during execution |
| `skipped` | Step skipped (workflow aborted before reaching it) |

### 4.6 Signature Verification

Verification reconstructs the `WorkflowReceiptBody` from the receipt fields
and verifies the Ed25519 signature over its canonical JSON serialization
using the embedded `kernel_key`.

A tampered receipt (any field modified after signing) MUST fail verification.

---

## 5. WorkflowAuthority Lifecycle

The `WorkflowAuthority` manages the lifecycle of skill executions. It holds
the kernel signing key and tracks execution counts for limit enforcement.

### 5.1 begin

```
begin(manifest, grant, agent_id, capability_id, session_id)
  -> Result<WorkflowExecution, WorkflowError>
```

Preconditions (all MUST be checked):

1. `grant.skill_id == manifest.skill_id` and
   `grant.skill_version == manifest.version`. Fail: `UnauthorizedSkill`.
2. If `grant.max_executions` is set, `execution_count < limit`. Fail:
   `ExecutionLimitReached`.
3. Every step in the manifest MUST be authorized by the grant. For each
   step, `grant.authorized_steps` MUST contain
   `"step.server_id:step.tool_name"`. Fail: `UnauthorizedStep`.

On success, returns a `WorkflowExecution` with:

- Budget limit from `grant.budget_envelope` or `manifest.budget_envelope`
  (grant takes precedence).
- Time limit from `grant.max_duration_secs` or `manifest.max_duration_secs`
  (grant takes precedence).
- `active` set to `true`.
- Empty `step_records` and zero `budget_spent`.

### 5.2 validate_step

```
validate_step(execution, step, grant) -> Result<(), WorkflowError>
```

Preconditions (checked in order):

1. `execution.active` MUST be `true`. Fail: `InvalidState`.
2. The step MUST be authorized by the grant. Fail: `UnauthorizedStep`.
3. If strict ordering is enabled, `step.index == execution.completed_steps()`.
   Fail: `StepOutOfOrder`.
4. If a time limit is set, elapsed time MUST be less than the limit. Fail:
   `TimeLimitExceeded`.

### 5.3 record_step

```
record_step(execution, step, outcome, duration_ms, cost, tool_receipt_id, output_hash)
  -> Result<(), WorkflowError>
```

Behavior:

1. If `execution.active` is `false`, return `InvalidState`.
2. Add `cost.units` (if present) to `execution.budget_spent` using
   saturating addition.
3. Append a `StepRecord` to `execution.step_records`. The record is
   always appended, even if the budget is about to be exceeded, so the
   audit trail includes the offending step.
4. After recording, check the budget envelope. If
   `budget_spent > budget_limit.units`, set `active` to `false` and return
   `BudgetExceeded`.
5. If `outcome` is `Failed` or `Denied`, set `active` to `false`.

The step record is written before the budget check so that the finalized
receipt contains evidence of the step that triggered the budget breach.

### 5.4 finalize

```
finalize(execution) -> Result<WorkflowReceipt, WorkflowError>
```

Behavior:

1. Set `execution.active` to `false`.
2. Determine the `WorkflowOutcome` by inspecting step records and budget:
   - If any step has `outcome == Failed` or `outcome == Denied`, the
     outcome is `StepFailed`.
   - If `budget_spent > budget_limit.units`, the outcome is
     `BudgetExceeded`.
   - Otherwise the outcome is `Completed`.
3. Construct `WorkflowReceiptBody` with all execution data.
4. Sign the body: `keypair.sign_canonical(body)`.
5. Increment the authority's `execution_count`.
6. Return the signed `WorkflowReceipt`.

---

## 6. WorkflowError

| Error | Fields | Description |
|-------|--------|-------------|
| `UnauthorizedSkill` | `skill_id, version` | Grant does not authorize the requested skill |
| `UnauthorizedStep` | `step_index, server, tool` | Step not in the grant's authorized list |
| `StepOutOfOrder` | `step_index, expected` | Step submitted out of sequence |
| `BudgetExceeded` | `limit_units, spent_units, currency` | Budget envelope exceeded |
| `TimeLimitExceeded` | `elapsed_secs, limit_secs` | Time limit exceeded |
| `ExecutionLimitReached` | `limit` | Maximum executions reached |
| `InvalidState` | `message` | Workflow is not in the correct state |
| `SigningFailed` | `message` | Receipt signing error |

---

## 7. Example

A two-step "search and summarize" skill:

```yaml
# Skill Manifest
schema: chio.skill-manifest.v1
skill_id: search-and-summarize
version: "1.0.0"
name: Search and Summarize
steps:
  - index: 0
    server_id: search-srv
    tool_name: search
    label: Search
    output_contract:
      produced_fields: [results]
  - index: 1
    server_id: llm-srv
    tool_name: summarize
    label: Summarize
    input_contract:
      required_fields: [results]
    output_contract:
      produced_fields: [summary]
budget_envelope:
  units: 1000
  currency: USD
```

```yaml
# Skill Grant
schema: chio.skill-grant.v1
skill_id: search-and-summarize
skill_version: "1.0.0"
authorized_steps:
  - search-srv:search
  - llm-srv:summarize
budget_envelope:
  units: 1000
  currency: USD
max_executions: 10
strict_ordering: true
```

Execution flow:

1. `authority.begin(manifest, grant, agent, capability, session)` --
   validates grant matches manifest, creates execution.
2. `authority.validate_step(execution, step_0, grant)` -- checks
   authorization, ordering, time.
3. Invoke `search-srv:search`, collect result.
4. `authority.record_step(execution, step_0, Success, 100ms, $0.50)` --
   records cost, checks budget.
5. `authority.validate_step(execution, step_1, grant)` -- checks
   authorization, ordering, time.
6. Invoke `llm-srv:summarize`, collect result.
7. `authority.record_step(execution, step_1, Success, 200ms, $1.00)` --
   records cost, checks budget.
8. `authority.finalize(execution)` -- signs receipt, increments count.
