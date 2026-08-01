# RFC-0003: Durable admission operations for effect-before-receipt recovery

- Status: Draft, corrected 2026-07-12
- Date: 2026-07-04
- Extends: ADR-0013, ADR-0008, and the `AdmissionOperation` contract in
  `docs/superpowers/specs/2026-07-09-protocol-primitives-design.md` section 4.6
- Depends on: RFC-0006 single-writer discipline
- Specialized by: RFC-0013 money-path durability and WS3 outcome pricing
- Correction design:
  `docs/superpowers/specs/2026-07-12-admission-operation-design.md`
- Closes findings: F04 and F31; provides the coordinator used by F70

## Summary

The kernel can currently execute a tool effect before its signed receipt is
durable. A crash in that interval can leave an effect absent from the receipt
log. This RFC extends the already-designed durable `AdmissionOperation` to every
configured monetary or side-effecting call. The operation commits before the
first authoritative participant mutation, commits `DispatchCommitted` before
both top-level and nested tool handoff, and retains a terminal request replay
tombstone after receipt or incident resolution.

RFC-0003 does not create a separate delete-on-success dispatch-intent journal.
Budget, payment, approval, nonce, provider acceptance, receipt, observer, and
obligation state are participants in one fenced saga keyed by `operation_id`.
Rows that share the receipt database use one composable receipt-side projection
transaction. Cross-database participants are idempotently reconciled by the saga
and are not described as atomically committed with the receipt.

## Motivation

The failure window begins when the kernel first commits a tool handoff and ends
when the receipt-side projection commits. `PostAdmissionDropGuard` protects
in-process cancellation only. It cannot survive process death, establish whether
a remote tool accepted a request, prevent a completed request id from being
inserted again, or serialize two recovery processes over the same SQLite file.

The earlier form of this RFC used a separate `chio_dispatch_intents` row and
deleted it with receipt insertion. That model is rejected for three reasons:

1. The protocol-primitives design already owns a durable operation that orders
   budget, approval, nonce, capture, and dispatch.
2. Deleting the request-keyed row removes replay protection because generic
   `ChioReceipt` bodies do not carry `request_id`.
3. A second intent reconciler cannot atomically or deterministically coordinate
   the payment and operation participants.

The corrected design makes the existing operation authoritative and retains its
terminal binding.

## Scope

In scope:

- durable operation identity and request replay namespace;
- effect-class gating and pre-effect persistence;
- one dispatch boundary used by top-level and nested evaluation;
- composable receipt-side finalization;
- provider-acceptance extension for WS3;
- deterministic boot recovery and incident binding;
- exclusive SQLite serving ownership and owner-epoch fencing;
- health, migration, crash tests, and rollout.

Out of scope:

- distributed transactions across stores or payment rails;
- blind replay of an ambiguous tool call;
- a production FROST implementation;
- changing receipt checkpoint counting or Merkle semantics;
- treating an operational operation row as signed audit evidence.

## Existing operation contract

RFC-0003 reuses the exact protocol-primitives identity:

```text
operation_id = SHA256("chio.admission-operation.v1\0" || canonical_json({
  kind,
  coordinator_authority_id,
  request_namespace_digest,
  request_id,
  capability_id,
  authorization_capability_hash,
  request_binding_hash
}))
```

The operation remains:

```text
AdmissionOperationV1 {
  kind,
  operation_id,
  coordinator_authority_id,
  request_namespace_digest,
  request_id,
  capability_id,
  authorization_capability_hash,
  request_binding_hash,
  policy_hash,
  effect_class,
  threshold_proposal_hash?,
  supplemental_authorization_digest?,
  broker_attempt_id?,
  budget_hold_id?,
  approval_set_hash?,
  execution_nonce_id?,
  outcome_eligibility_digest?,
  tool_outcome_id?,
  terminal_result_id?,
  terminal_result_digest?,
  state,
  dispatch_state,
  coordinator_lease_epoch,
  version,
  last_error?,
  terminal_receipt_id?,
  terminal_incident_id?,
}
```

`operation_id` is SHA-256 over the domain-separated RFC 8785 body containing
`kind`, `coordinator_authority_id`, `request_namespace_digest`, `request_id`,
`capability_id`, `authorization_capability_hash`, and `request_binding_hash`.
The authenticated namespace is part of both the operation identity and replay
unique key, so equal caller identifiers in different tenants cannot collide on
the global operation primary key.

This RFC adds effect bindings to the immutable canonical request binding:

- authenticated replay-namespace digest;
- tool server and tool name;
- RFC 8785 parameter hash from `ToolCallAction::from_parameters`;
- `SideEffectClass`;
- governed-intent, pricing, rail-profile, and optional WS3 eligibility digests.

Approval membership, supplemental authorization artifacts, execution nonce
references, provider acknowledgements, and terminal receipt, incident, or typed
mutation-result ids/digests are
not part of operation identity. Each is compare-and-swap attached to its
previously null participant or terminal field exactly once. All required
participant evidence is immutable before `ReadyToDispatch`, while terminal
references are written only by the receipt projection.

`operation_id` is the primary key. The operation store also enforces unique
`(request_namespace_digest, request_id)`. The namespace digest is SHA-256 over a
domain-separated RFC 8785 body containing the coordinator authority and the
authenticated tenant, or the fixed local-system tenant for a non-multitenant
deployment. Caller input cannot select the authenticated tenant.

A duplicate request is idempotent only when the namespace, `operation_id`, and
complete binding match. A different body conflicts before any participant
mutation. A matching terminal request returns its existing receipt or incident
or its exact typed mutation-result id/digest and bytes, and never dispatches or
submits again.

## State and invariants

The protocol-primitives saga states remain authoritative. RFC-0003 uses these
effect-relevant milestones:

```text
Prepared
  -> participant reservations
  -> ReadyToDispatch
  -> DispatchCommitted
  -> Finalizing
  -> Completed

Prepared|ReadyToDispatch -> CompensatedBeforeDispatch
DispatchCommitted -> NotAcceptedAfterDispatchCommit
DispatchCommitted|Finalizing -> OutcomeUnknownAfterDispatch

GovernedEconomicMutation:
Prepared -> MutationReady -> MutationSubmitted
Prepared|MutationReady|MutationSubmitted -> EconomicMutationNotApplied
MutationSubmitted -> EconomicMutationApplied
```

`MutationReady` means every late authorization/agreement binding is attached.
`MutationSubmitted` commits before the authoritative apply call. The participant
deduplicates by `operation_id`; recovery queries it first and any identical retry
returns the retained result without repeating the resource CAS. The two mutation
terminal projections require kind `GovernedEconomicMutation` and only the source
states shown above.

The invariants are:

```text
Prepared is durable before any authoritative participant mutation.

DispatchCommitted is durable before invoke or invoke_stream.

Completed, CompensatedBeforeDispatch, NotAcceptedAfterDispatchCommit, and
OutcomeUnknownAfterDispatch remain tool-dispatch replay tombstones.
EconomicMutationApplied and EconomicMutationNotApplied remain governed-mutation
replay tombstones.

release_monetary_hold(operation_id) implies verified MonetaryReleaseAuthority:
  NoEffect(VerifiedNoEffectProof)
  or ContractualZeroCharge(VerifiedContractualZeroCharge).

effect_possible(operation_id) implies no blind redispatch and no automatic
release of invocation or monetary reservations.
```

The operation row is never deleted. Compaction may replace terminal detail with
an authenticated terminal-key index after checkpoint finality, but the namespace,
request id, operation id, request binding, and terminal receipt or incident id
or terminal mutation-result id/digest remain queryable for the request-id
namespace lifetime.

## Rust contracts

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectClass {
    ReadOnly,
    SideEffecting,
    Monetary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionProjectionCapabilities {
    pub operation_terminal: bool,
    pub incident_terminal: bool,
    pub tool_outcome: bool,
    pub authorization_consumption: bool,
    pub outcome_eligibility: bool,
    pub observation_attempt_zero: bool,
    pub obligation: bool,
    pub economic_mutation_terminal: bool,
}

pub struct AdmissionProjectionContext {
    pub operation_id: String,
    pub request_id: String,
    pub expected_operation_version: u64,
    pub coordinator_lease_epoch: u64,
}

pub struct AdmissionCompletedProjection {
    pub context: AdmissionProjectionContext,
    pub receipt: ChioReceipt,
    pub tool_outcome: Option<ToolOutcomeTerminalEvidence>,
    pub payment_evidence: Option<PaymentTerminalEvidence>,
    pub authorization: Option<AuthorizationReceiptConsumption>,
    pub eligibility: Option<OutcomeEligibilityFinalization>,
    pub observer_work: Option<ObservationAttemptZero>,
    pub obligation: Option<ObligationProjection>,
}

pub enum AdmissionTerminalProjection {
    Completed(AdmissionCompletedProjection),
    CompensatedBeforeDispatch {
        context: AdmissionProjectionContext,
        proof: VerifiedPreDispatchNoEffect,
        evidence: AdmissionReceiptOrIncident,
    },
    NotAcceptedAfterDispatchCommit {
        context: AdmissionProjectionContext,
        proof: VerifiedTransportNotAccepted,
        evidence: AdmissionReceiptOrIncident,
    },
    OutcomeUnknownAfterDispatch {
        context: AdmissionProjectionContext,
        incident: AdmissionIncident,
    },
    EconomicMutationApplied {
        context: AdmissionProjectionContext,
        result: VerifiedEconomicMutationApplied,
        audit_event: GovernedMutationAuditEvent,
    },
    EconomicMutationNotApplied {
        context: AdmissionProjectionContext,
        result: VerifiedEconomicMutationNotApplied,
        audit_event: GovernedMutationAuditEvent,
    },
}
```

`AdmissionOperationStore` supplies the begin, compare-and-swap transition,
participant-lookup, recovery-claim, and terminal-load operations already required
by the protocol-primitives design. `ReceiptStore` adds:

```rust
fn admission_projection_capabilities(&self) -> AdmissionProjectionCapabilities;

fn commit_admission_projection(
    &self,
    projection: &AdmissionTerminalProjection,
) -> Result<AdmissionTerminal, ReceiptStoreError>;
```

Default implementations report no capabilities and fail before append. A
monetary or side-effecting production call cannot use `append_chio_receipt`,
`append_chio_receipt_with_pending_observation`, or another specialized append
method to bypass operation finalization.

## Terminal projection transaction

For the local SQLite profile, the operation row is co-located with receipt,
incident, tool-outcome, eligibility, observer, authorization-consumption,
obligation, and governed-mutation audit/result tables.
`commit_admission_projection` runs on the RFC-0006 writer actor inside one
`BEGIN IMMEDIATE` transaction:

1. Verify the store owner lease and coordinator epoch.
2. Load the exact `operation_id`, namespace, request id, and expected version.
3. Match the closed terminal variant and require its legal source state.
4. Verify its exact tool outcome or mutation result, release authority, receipt
   or incident, payment evidence, and optional eligibility bindings.
5. For `Completed`, append the receipt, apply every typed local projection and
   retain the operation with its receipt id.
6. For `CompensatedBeforeDispatch`, atomically bind verified no-effect evidence
   and a denial receipt or incident from a state before `DispatchCommitted`.
7. For `NotAcceptedAfterDispatchCommit`, require cancellation-fenced
   `NotAccepted`, retain captured invocation quota, release only reversible
   monetary exposure, and bind its receipt or incident.
8. For `OutcomeUnknownAfterDispatch`, insert the incident, freeze participants
   and retain the operation from `DispatchCommitted` or `Finalizing`.
9. For `EconomicMutationApplied`, require kind `GovernedEconomicMutation`, bind
   the exact private-verified applied result id/digest, append its audit event,
   and retain that terminal state.
10. For `EconomicMutationNotApplied`, require the same kind and exact
    private-verified permanently-not-applied result, append its audit event, and
    retain that terminal state.
11. Commit once and then fan out the result to the caller.

The transaction rejects a missing required projection, an unexpected duplicate,
a stale version or epoch, a partial pre-existing subset, or any digest mismatch.
No receipt or incident, terminal operation, tool outcome or mutation-result
binding, mutation audit event, eligibility event, attempt-zero work,
authorization consumption, or obligation row becomes visible on failure.

The payment journal and budget hold may live in the budget database. They are
not mutated inside this receipt transaction. The projection binds verified
terminal payment evidence, and the saga closes or confirms the payment
participant idempotently in either crash ordering. Documentation must say
"one atomic receipt-side projection", not "one atomic money-path commit."

A separately stored or remote governed-mutation authority is likewise an
idempotent saga participant. It applies or rejects by `operation_id`, retains a
versioned signed terminal result, and supports side-effect-free lookup. After an
ambiguous response, recovery verifies that result and commits the corresponding
local mutation terminal projection. It never repeats the resource mutation or
claims that participant state and the local operation committed atomically.

## Outcome, status, and release contracts

The 2026-07-12 admission design's canonical `ToolOutcomeRecordV1` is a required
operation participant. It binds operation/request, dispatch version and fence,
tool and transport attempt, terminal transport evidence, content-addressed raw
output digest/blob, reported cost, post-return evaluation id, resolved guarded
output, post-guard decision, pricing verdict, settlement disposition, writer
owner epoch and row version.
The blob is durable before the insert-once row. `record_tool_returned`,
`resolve_tool_outcome`, and side-effect-free `lookup_by_operation` are owned by
protocol-primitives Task 6. Receipt finalization verifies the terminal record.

`DispatchStatusProvider` optionally queries an exact operation and handoff
attempt and returns only verified `NotAccepted`, `Pending`, `Accepted {
acceptance_ref }`, `Completed { tool_outcome_ref }`, or `Unknown`. Without a
provider, an ambiguous committed handoff is incident-only: no redispatch and no
hold release. WS3 and other stronger acceptance/delivery contracts require a
provider. `Accepted` is usable only with the authenticated acceptance envelope
and current monotonic external attempt checkpoint. It proves cancellation is no
longer possible, not completion.
`Completed` is usable only when the provider also implements authenticated
`fetch_completed_outcome(ref)`. The private verified response binds the exact
operation, request, attempt, transport identity/key epoch, bytes/digest, reported
cost and terminal evidence. The coordinator persists those bytes locally through
`record_tool_returned` before continuing. A bare ref, failed fetch or binding
mismatch is outcome-unknown.
`NotAccepted` is usable only when the provider's external attempt-continuity
anchor proves the exact slot permanently `Cancelled` at a monotonic
sequence/version/predecessor. Behind, divergent, unavailable or locally restored
status is `Unknown` and freezes the hold.

An installed economic effect-slot provider is equivalent only when its external
`Ready -> NoEffect` CAS is the permanent cancellation fence and competes with the
only `Ready -> DispatchCommitted` handoff. After local `DispatchCommitted`, a
cancellation winner constructs `VerifiedTransportNotAccepted` and reaches
`NotAcceptedAfterDispatchCommit`; a handoff winner cannot cancel. This closes the
local-operation/effect-slot two-commit gap without misusing pre-dispatch
compensation.

Post-return guards and pricing use the admission design's durable
`PostReturnEvaluationRecordV1`. It freezes exact pipeline/policy versions,
trusted time and every input before evaluation, persists each external/stateful
result, and permits recovery only through frozen pure evaluation or idempotent
authenticated participant lookup. Non-replayable ambiguity freezes the hold;
raw output alone never authorizes a new guard or pricing decision.

Only private-constructor verified types authorize release. The closed
`VerifiedNoEffectProof` contains either `VerifiedPreDispatchNoEffect`, which
binds the operation/lease and complete no-handoff/no-final-prepayment participant
queries, or `VerifiedTransportNotAccepted`, which binds the exact operation,
attempt, request/dispatch versions, transport identity/key epoch, signed terminal
status, cancellation fence, time, verifier, and the current authenticated
monotonic transport-slot checkpoint from outside the provider queue backup
domain, terminal as `Cancelled` or typed `NoEffect`. A local signed status without
that continuity cannot authorize release.
`VerifiedContractualZeroCharge` binds the final outcome record, exact pricing or
eligibility policy, terminal verdict and zero amount. The closed
`MonetaryReleaseAuthority` accepts one of those types; caller bytes, age,
`Authorized`, unavailable status and missing receipts do not qualify.

## Kernel control flow

The kernel extracts one helper used by
`async_evaluation_core.rs` and `nested_flow_evaluation.rs`:

```text
prepare_admission_operation
authorize_participants
commit_dispatch
invoke_tool
record_outcome
commit_settle_action
commit_admission_projection
```

The detailed order is:

1. Complete parsing, capability, revocation, DPoP, policy, governed-intent,
   approval, nonce, guard, and runtime-admission validation without mutating
   replay or budget state.
2. Derive the authenticated namespace and canonical request binding. Persist
   `Prepared` before any reservation or external authorization.
3. Reserve every budget, payment, approval, nonce, and optional WS3 participant
   by `operation_id`, recording each acknowledgement through a fenced operation
   compare-and-swap.
4. Immediately before tool handoff, capture invocation reservations and persist
   `DispatchCommitted`. A failure compensates before dispatch and emits a
   terminal-projection-bound `CompensatedBeforeDispatch` tombstone.
5. Invoke the top-level or nested transport only after step 4 commits. The
   `PostAdmissionDropGuard` carries `operation_id` and cannot reverse invocation
   admission after `DispatchCommitted`.
6. Durably write the returned output blob and insert-once
   `ToolOutcomeRecordV1`, then compare-and-swap its guarded output, cost, verdict
   and settlement disposition. If no return can be proved, build an
   outcome-unknown incident. For a monetary call, persist the exact capture or
   release action and amount before calling the rail.
7. After terminal rail evidence, build the signed receipt and commit the typed
   completed terminal projection. Return `Allow` only after that commit.

No direct `invoke`, `invoke_stream`, or payment call may exist between
participant reservation and the durable dispatch boundary. A
constructor-inventory test covers ordinary, nested-flow, restored-session, CLI,
strict MCP, remote MCP, and hosted conformance construction.

## WS3 provider acceptance extension

WS3 may add a provider-authenticated durable acceptance participant. Its
eligibility and immutable lifecycle events are keyed by `operation_id` and bind
the same request namespace, parameter hash, listing, provider, pricing, guard
policy, and quote digests.

The accepted lifecycle is:

```text
prepared -> dispatch_committed -> dispatch_accepted
dispatch_accepted -> output_ready -> delivery_started
delivery_started -> delivery_acknowledged | delivery_cancelled | delivery_unknown
delivery_acknowledged|delivery_cancelled -> receipt_bound
delivery_unknown -> incident_bound
dispatch_accepted -> provider_incident_bound
prepared|dispatch_committed -> not_accepted
dispatch_committed -> platform_outcome_unknown
```

`dispatch_committed` is kernel state, not provider SLA evidence. Only a verified
`chio.outcome.dispatch-acceptance.v1` from a qualified restart-safe queue enters
`dispatch_accepted`. The provider protocol is `LocalQueuedStaged ->
DispatchAnchorAccepted -> LocalExecutable`: staged work cannot execute before
the external attempt slot reaches `Accepted` and a worker wins the external
`Accepted -> Executing` lease/fence CAS. `Pending -> Cancelled` competes with
acceptance and permanently disables the staged row; accepted, executing and
completed slots cannot cancel. Recovery reads the anchor first and reconstructs
accepted work from its rollback-independent invocation blob. A crash after an
effect but before anchored completion uses authenticated tool-side status or a
qualified same-key idempotent invocation; otherwise it remains unknown and does
not rerun. A lost acknowledgement is resolved through the provider's status
query by `operation_id`; socket acceptance, in-memory enqueue, and function
entry do not qualify. Only a receiver-bound acknowledgement over the
exact final output may reach `delivery_acknowledged` and permit capture; missing
or ambiguous delivery reaches `delivery_unknown`, freezes the hold, and emits no
success receipt. Only a private verified receiver nonacceptance proof with a
permanent cancellation fence may reach `delivery_cancelled` and permit release.

The receipt-side projection verifies the stored canonical eligibility,
acceptance, and delivery envelopes, compare-and-swaps the lifecycle, appends its immutable
event, and binds the receipt or incident in the same transaction. Eligibility
rows remain after terminal operation completion because they are denominator
evidence. They do not substitute for the terminal request tombstone.

## Boot recovery

Only the serving owner may claim recovery work. Recovery first reads the
operation, then queries any participant whose commit may have preceded the last
operation update.

| Operation truth | Participant evidence | Recovery action |
|---|---|---|
| before `DispatchCommitted` | no participant reports handoff or final prepayment | compensate reversible reservations; retain `CompensatedBeforeDispatch` |
| before `DispatchCommitted` | final prepayment moved | record proved refund if available; otherwise incident, never hold release |
| `DispatchCommitted` | `VerifiedNoEffectProof::NotAcceptedAfterDispatch(VerifiedTransportNotAccepted)` | commit `NotAcceptedAfterDispatchCommit`, release reversible hold, retain invocation capture, and never redispatch |
| `DispatchCommitted` | terminal `ToolOutcomeRecordV1`, or authenticated provider fetch that is first persisted locally | resume journaled guard/pricing evaluation and exact settlement path |
| `DispatchCommitted` | unknown or unavailable transport | retain `OutcomeUnknownAfterDispatch`; freeze monetary hold |
| settle action durable | rail query or idempotent replay | complete only the stored action and amount |
| terminal projection committed | matching tombstone and receipt or incident | finish participant acknowledgements; return existing result |

This table removes the unsafe assumption that an RFC-0013 `Authorized` payment
row proves the tool did not run. If the operation reached `DispatchCommitted`,
recovery cannot release merely because `Settling` was not yet recorded.

A participant row without an operation, a receipt without a matching completed
operation, an impossible state pair, or a stale coordinator epoch is an invariant
incident. Serving remains fail-closed until recovery or operator review resolves
the invariant. Missing receipts never prove non-execution.

## SQLite serving ownership

RFC-0006 serving ownership is shared per database, not per store object.
Production provisioning, running through `chio store provision` or the trusted
lock broker, atomically initializes the durable UUID and creates/fsyncs its
protected UUID lock inode. Serving code cannot create or replace that inode.

1. `open_serving` requires an already provisioned database and existing lock,
   opens it with no-follow semantics, verifies owner/group/mode/link count and
   recorded device/inode, then locks it and rechecks UUID and database identity.
   Missing or partial provisioning fails before actors start.
2. A `BEGIN IMMEDIATE` transaction increments `owner_epoch` and records a random
   lease id. The resulting shared `SqliteServingOwner` starts one writer and the
   applicable recovery coordinators. In-process receipt, operation, outcome,
   budget/payment, obligation, and other stores clone this handle.
3. Every mutation and recovery claim carries and transactionally checks
   `StoreMutationFence { store_uuid, lease_id, owner_epoch }`. A stale or
   cross-database fence returns `Fenced` before mutation.
4. Separately configured receipt, budget/payment, or obligation database files
   are separately provisioned and have distinct owner/fence values. The receipt
   profile co-locates operation and required local projection tables; external
   payment participants remain an operation-keyed saga.
5. Another mutable open fails `AlreadyServing`. An explicit read-only open may
   inspect or verify but cannot start workers or mutate rows.

Existing multi-handle tests over one file use cloned handles or a read-only
observer. Multi-process serving requires a remote linearizable store and leader
epochs; SQLite transaction serialization alone does not provide that model.

## Health

The supervised runtime exposes:

- serving lease id and owner epoch;
- operation writer and recovery-worker liveness;
- nonterminal counts by state and effect class;
- oldest `DispatchCommitted` and `OutcomeUnknownAfterDispatch` age;
- projection rollback, replay-conflict, fencing, and invariant-incident counts;
- WS3 unresolved acceptance count when that extension is enabled.

Readiness is false when the writer or recovery worker is dead, the serving lease
is lost, the configured store lacks required projection capabilities, or an
operation/receipt invariant incident is unresolved. A backlog alone is reported
and bounded by policy; it is not silently ignored.

## Configuration

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableAdmissionMode {
    Off,
    Monetary,
    SideEffecting,
    All,
}
```

Coverage is cumulative:

- `Off`: explicit tests and unsafe local development only;
- `Monetary`: monetary calls;
- `SideEffecting`: monetary and non-monetary side effects;
- `All`: all mediated calls, including explicitly read-only calls.

The compiled production default is `SideEffecting`. Unannotated tools already
classify as side-effecting, so a missing manifest annotation cannot bypass the
journal. `All` is an explicit deployment choice that trades read-only write
latency for request replay tombstones. A release build with durable receipts
rejects `Off` unless an unsafe development flag is also set.

## Schema and receipt impact

- `AdmissionOperation` storage gains the effect and terminal bindings above.
- Receipt metadata binds `operation_id`, terminal operation state, and dispatch
  state. The generic receipt wire body does not need a new `request_id`; the
  retained operation supplies the authenticated request-to-receipt lookup.
- WS3 eligibility and acceptance families remain signed artifacts and immutable
  event rows. Base operation rows remain operational, not signed receipts.
- Receipt sequence, checkpoint interval, and Merkle leaf semantics are unchanged.

## Migration

This RFC is a design correction before RFC-0003 implementation lands. New
deployments create the operation extension directly and do not create
`chio_dispatch_intents`.

If an experimental database contains intent rows:

1. serving remains stopped while migration holds the database lock;
2. each row maps to one namespaced operation using the canonical existing
   `operation_id` derivation;
3. an open row maps to the most conservative recoverable state;
4. a receipt-resolved row maps to `Completed` and retains the receipt id;
5. an outcome-unknown row maps to `OutcomeUnknownAfterDispatch`;
6. any row whose namespace, request binding, or terminal receipt cannot be
   reconstructed becomes a migration incident and prevents serving;
7. only after row-count and digest reconciliation does migration retire the old
   table.

No migration deletes the only replay key for a completed request.

## Verification plan

- Unit: namespace and operation identity are canonical; duplicate equal replay is
  idempotent; conflicting replay rejects before participant mutation.
- State machine: every illegal transition, stale version, and stale lease epoch
  rejects. `DispatchCommitted` cannot compensate invocation quota. Governed
  mutation recovery queries the exact signed participant result: applied work is
  never resubmitted, permanently-not-applied work binds its typed terminal result,
  and unresolved `MutationReady`/`MutationSubmitted` remains pending rather than
  guessing.
- Projection: fail each local projection step and assert all rows roll back. A
  drained observer row is not recreated by terminal replay.
- Crash matrix: kill before and after every participant call, operation update,
  tool return, durable outcome blob/row, outcome resolution, settle-action write,
  post-return evaluation start/result/finalization, rail call, and terminal
  projection commit. Stateful guard ambiguity without authenticated lookup freezes
  rather than rerunning against current state.
- Regression: `crash_after_tool_before_settling_never_releases_hold` leaves an
  outcome-unknown incident or resumes a queried outcome.
- Replay: `completed_request_id_remains_non_replayable` covers byte-identical and
  conflicting requests even though the generic receipt lacks `request_id`.
- Path parity: top-level and nested evaluation produce the same operation history
  and recovery behavior.
- Ownership: privileged provision and partial-provision failures, relative/absolute,
  symlink, hardlink, rename and copied-same-UUID mutable opens yield one owner;
  lock replacement fails; stale or cross-database fences cannot mutate receipt,
  budget/payment, obligation, outcome or operation rows; read-only inspection
  cannot start workers.
- Transport status: provider positives and wrong operation/attempt/identity/epoch/
  fence negatives; completed refs require authenticated fetch and local raw-outcome
  persistence; bare/unavailable/mismatched refs and provider absence always take
  incident-only recovery.
- Provider execution fence: race local stage against external acceptance and
  cancellation, then race executor claim against cancellation. Only the winner of
  the current external CAS may execute. Kill after the effect but before terminal
  outcome persistence and completion CAS; absent authenticated tool-side status
  or qualified same-key idempotent invocation, recovery remains unknown and does
  not rerun.
- Mode: membership is monotonic and production defaults to `SideEffecting`.
- WS3: lost acceptance acknowledgement is queried; unresolved handoff never enters
  the provider SLA denominator and blocks corpus completeness. Missing delivery
  acknowledgement freezes the hold unless a receiver-signed, cancellation-fenced
  nonacceptance proof verifies.
- Soak: sustained side-effecting and monetary load with periodic kills leaves no
  request without exactly one live or terminal operation.

## Acceptance criteria

- Every configured effecting request has a durable `Prepared` operation before
  participant mutation and `DispatchCommitted` before tool handoff.
- After restart, each operation resolves to `Completed`,
  `CompensatedBeforeDispatch`, `NotAcceptedAfterDispatchCommit`,
  `OutcomeUnknownAfterDispatch`, `EconomicMutationApplied`,
  `EconomicMutationNotApplied`, or an explicitly pending participant state.
  Pending governed mutations are exactly `MutationReady` or `MutationSubmitted`
  with participant identity, request digest, expected resource version/fence and
  typed result lookup truth retained. No effect is absent from both operation and
  receipt-or-incident-or-terminal-result truth.
- A completed request cannot dispatch again after receipt success or compaction.
- The post-tool, pre-settle crash window never releases a hold without terminal
  outcome or authenticated non-acceptance proof.
- Receipt, terminal operation, and all required local sidecars are visible
  together or not at all.
- Top-level and nested-flow tool calls cross the same durable boundary.
- One SQLite file has at most one mutable serving owner and stale epochs are
  fenced.
- Configuration contains all four modes and the code, migration, roadmap, and
  rollout use the same default and ordering.

## Risks and alternatives

- Every side-effecting call adds durable operation and transition writes. The
  default excludes explicitly read-only calls, and group commit bounds writer
  overhead without weakening pre-handoff durability.
- Mutating participant idempotency is required. An unqueryable transport may use
  only the explicit incident-only ambiguity contract; it cannot claim restart
  status, WS3 delivery, redispatch, or automatic hold release.
- OS locking is local-process exclusion, not distributed consensus. Remote HA
  deployments require a linearizable operation store with leader fencing.
- A single database for budget and receipt state was considered. It can simplify
  a local deployment but is a breaking configuration migration and does not solve
  external rail atomicity. The persisted saga is the required portable contract.
- Keeping a separate dispatch-intent row was rejected because it duplicates the
  operation coordinator and invites divergent recovery.
- Deleting an intent after receipt was rejected because the generic receipt does
  not retain request replay identity.

## Rollout and sequencing

1. Extend the protocol-primitives `AdmissionOperation` plan to every configured
   monetary and side-effecting call.
2. Land the operation store, composable receipt projection, terminal retention,
   serving lock, and epoch fencing behind explicit pre-release configuration.
3. Route both kernel evaluator paths through the shared coordinator.
4. Soak `Monetary`, then `SideEffecting`; all crash, replay, projection, and owner
   gates must be green.
5. Release with `SideEffecting` as the compiled production default. `All` remains
   an explicit option; `Off` remains unsafe-development-only.
6. RFC-0013 registers its payment participant and recovery queries with this
   coordinator. WS3 registers provider acceptance and eligibility participants.
