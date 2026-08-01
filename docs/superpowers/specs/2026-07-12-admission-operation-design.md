# Admission Operation Durability Design

- Date: 2026-07-12
- Status: Approved correction to RFC-0003, RFC-0013, and the agent-economy program
- Extends: `2026-07-09-protocol-primitives-design.md` section 4.6
- Owners: `chio-kernel` (contract), `chio-store-sqlite` (local persistence),
  `chio-control-plane` (serving ownership and recovery)

## Goal

Make the existing durable `AdmissionOperation` the only coordinator for a
mediated request. Dispatch intent, budget and payment state, approval and nonce
reservations, receipt persistence, observer work, and economic projections are
participants in that operation. A crash must not make a possibly completed
effect safe to run again or a corresponding hold safe to release.

The closed operation kinds are `ToolDispatch`, `GovernedActiveResponse`, and
`GovernedEconomicMutation`. The last lets an authoritative store such as WS2
assignment consume the same operation id in its resource CAS without pretending
the mutation is a tool call or adding a new coordinator.

## Non-goals

- A distributed transaction across SQLite databases or an external rail.
- Blind replay after an ambiguous tool handoff.
- A second dispatch-intent coordinator beside `AdmissionOperation`.
- Treating operational rows as signed audit evidence.

## Corrected invariant

The protocol-primitives design already defines a persisted, fenced saga:

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

RFC-0003 and RFC-0013 extend this record and do not create another request
coordinator. The following rules are normative:

1. `Prepared` commits before the first authoritative participant mutation or
   external authorization.
2. Every participant stores `operation_id` as its idempotency and ownership key
   and supports side-effect-free lookup by that key.
3. `DispatchCommitted` commits before both top-level and nested-flow tool
   handoff. No code path invokes a tool while the operation is in an earlier
   dispatch state.
4. `Completed`, `CompensatedBeforeDispatch`,
   `NotAcceptedAfterDispatchCommit`, and `OutcomeUnknownAfterDispatch` are
   retained tool-dispatch replay tombstones. `EconomicMutationApplied` and
   `EconomicMutationNotApplied` are retained terminals for
   `GovernedEconomicMutation`. An
   operation row is never deleted on receipt success.
5. Receipt-side projections commit through one typed transaction. Payment and
   other cross-database participants remain saga participants and are never
   described as atomically committed with the receipt.
6. A reversible hold may be released only from the closed verified
   `MonetaryReleaseAuthority`: a durable no-effect proof (including
   cancellation-fenced `NotAccepted`) or a contract-bound terminal zero-charge
   outcome. Age, `Authorized`, a missing receipt, an unavailable transport, and
   an outcome-unknown incident are not release authority.

The safety predicates are:

```text
unique(request_namespace_digest, request_id) -> one operation_id

terminal(operation_id) -> not redispatchable(request_id)

release_hold(operation_id) ->
  dispatch_not_committed(operation_id)
  or authenticated_not_accepted_and_cancelled(operation_id)
  or known_zero_charge_outcome(operation_id)

effect_possible(operation_id) ->
  invocation_quota_not_reopened(operation_id)
  and hold_not_auto_released(operation_id)
```

## Identity and retention

The existing `operation_id` derivation remains authoritative:

```text
SHA256("chio.admission-operation.v1\0" || canonical_json({
  kind,
  coordinator_authority_id,
  request_namespace_digest,
  request_id,
  capability_id,
  authorization_capability_hash,
  request_binding_hash
}))
```

`request_binding_hash` covers every immutable normalized field that can change
the operation, including arguments, governed intent, policy requirements,
destination, pricing selection, and settlement mode. It excludes the
authority-generated threshold proposal, approval membership, supplemental authorization artifacts,
execution nonce references, and other evidence that may be supplied after an
initial `ApprovalRequired` result. The verifier compare-and-swap attaches each
proposal or verified participant binding from null exactly once before
`ReadyToDispatch`;
a matching retry is idempotent and a replacement is a conflict. RFC-0003 adds
tool target, parameter hash, effect class, and optional outcome eligibility
digest to the immutable binding. RFC-0013 adds rail profile and pre-action
economic-intent digests. Neither RFC defines a second identity.

`operation_id` is the primary key. The operation store also enforces a unique
authenticated replay key `(request_namespace_digest, request_id)`, where
`request_namespace_digest` is SHA-256 over the domain-separated canonical
coordinator-authority id and authenticated tenant id (or the fixed local-system
tenant for a non-multitenant deployment). Caller data cannot choose that tenant.
A repeated request is idempotent only when the namespace, operation identity,
and complete binding match. A matching terminal operation returns its bound
receipt, incident, or typed mutation result. A conflict rejects before
participant mutation.

Terminal rows remain queryable for the lifetime of the request-id namespace.
Compaction may replace full detail with an authenticated terminal-key index
after checkpoint finality, but it must retain `(request_namespace_digest,
request_id, operation_id, request_binding_hash,
receipt_id|incident_id|terminal_result_id+terminal_result_digest)`.
Compaction may never make a
completed request insertable again.

## Participant model

The operation coordinates these participants:

| Participant | Authority | Required operation behavior |
|---|---|---|
| invocation and monetary hold | `BudgetStore` | reserve, query, capture, compensate by `operation_id` |
| payment rail journal | RFC-0013 payment participant | persist rail action before call; query terminal state by `operation_id` |
| approval and nonce replay | approval and nonce stores | `reserved`, `committed`, `cancelled`; retain tombstones |
| tool transport | dispatcher or qualified provider transport | handoff only after `DispatchCommitted`; typed status query when installed, otherwise incident-only ambiguous recovery |
| tool outcome | operation-owned `ToolOutcomeStore` | durably persist returned bytes/cost before post-return work; resolve final outcome; lookup by `operation_id` |
| governed economic mutation | authoritative mutation service | idempotent apply/query by `operation_id`; return a signed applied or not-applied result bound to resource version/fence |
| receipt, incident, and local sidecars | receipt store | one closed `commit_admission_projection` terminal transaction |
| recovery | operation coordinator | lease-fenced participant queries and compare-and-swap transitions |

The saga records participant acknowledgement after each authoritative commit.
If a participant commit may have preceded the operation update, recovery queries
that participant by `operation_id` and advances the operation without repeating
the side effect. A participant that cannot provide idempotent lookup cannot be
retried by recovery. An unqueryable transport may still run under the
`SideEffecting` default only with the explicit conservative contract that an
ambiguous committed handoff becomes `OutcomeUnknownAfterDispatch`, freezes every
reversible hold, and never redispatches. WS3 and any stronger delivery claim
require the typed status provider and cannot use that fallback.

This is explicitly not cross-database atomicity. The local receipt-side commit
is atomic because its rows share one SQLite writer. Budget and payment
participants may live in the budget database and are reconciled through the
fenced saga. The design does not rely on SQLite `ATTACH` across WAL databases.

## Durable tool outcome participant

Both dispatch paths convert a successful transport return into one operation-owned
record before running post-return guards, deriving settlement, or responding:

```rust
pub struct ToolOutcomeRecordV1 {
    pub outcome_id: String,
    pub operation_id: String,
    pub request_id: String,
    pub dispatch_operation_version: u64,
    pub dispatch_fence: u64,
    pub tool_server: String,
    pub tool_name: String,
    pub transport_attempt_id: String,
    pub transport_terminal_evidence_digest: String,
    pub raw_output_digest: String,
    pub raw_output_blob_ref: String,
    pub reported_cost: Option<MonetaryAmount>,
    pub resolved_output_digest: Option<String>,
    pub resolved_output_blob_ref: Option<String>,
    pub post_return_evaluation_id: Option<String>,
    pub post_guard_decision_digest: Option<String>,
    pub pricing_verdict_digest: Option<String>,
    pub settlement_disposition: Option<SettlementDisposition>,
    pub writer_owner_epoch: u64,
    pub version: u64,
}
```

The content-addressed blob is durably written and digest-verified before its row
commits. `record_tool_returned` is insert-once by `operation_id`; then
the post-return evaluation journal below produces the only input accepted by
`resolve_tool_outcome`, which compare-and-swaps the final guarded output and exact
capture, release, or no-charge disposition. `lookup_by_operation` is
side-effect-free. A crash before the first record remains outcome-unknown and
freezes the hold. A crash after it can resume guards and settle derivation from
the exact durable bytes and cost. The receipt projection verifies the final
outcome id, version, output digest, cost and disposition.

`PostReturnEvaluationRecordV1` is insert-once by operation and binds the raw
outcome id/version, exact ordered guard and pricing-policy versions/digests,
trusted evaluation time, normalized request context, deterministic external-call
ids, and expected evidence classes before evaluation begins. Every pure guard may
replay only against those frozen inputs. Every external or stateful guard must
persist its authenticated response before the next stage and support idempotent
lookup by the recorded call id; an ambiguous call without lookup support freezes
the operation. A terminal evaluation row binds every ordered guard result and
dependency digest, final output blob/digest, pricing verdict, and settlement
disposition. Recovery resumes from persisted stages or participant lookup. It
never reruns a time-varying guard against current state and never derives release
or capture from raw bytes alone.

## Verified release authority

`VerifiedNoEffectProof` is the closed enum
`BeforeDispatch(VerifiedPreDispatchNoEffect) |
NotAcceptedAfterDispatch(VerifiedTransportNotAccepted)`. Both payload constructors
are private. `VerifiedPreDispatchNoEffect` binds the operation and expected
version, coordinator lease, complete participant-query root, and proof that no
transport attempt or final prepayment exists. `VerifiedTransportNotAccepted`
binds operation id, exact handoff attempt, request and dispatch versions,
transport identity and key epoch, signed status-envelope digest, terminal
`NotAccepted` status, cancellation fence, verified time, verifier identity, and
an authenticated monotonic transport-slot checkpoint with anchor identity,
namespace, sequence, predecessor, version, and terminal `Cancelled` or typed
`NoEffect` state. That
checkpoint lives outside the transport queue/database backup domain. Its
constructor resolves the trusted transport key and continuity anchor, verifies
the current checkpoint and status, proves the cancellation fence prevents later
acceptance, rejects a behind/divergent/unavailable/restored provider view, and
rejects final prepayment. The
two payloads cannot convert into each other.

`VerifiedContractualZeroCharge` is distinct. It binds the final
`ToolOutcomeRecordV1`, exact pricing/eligibility policy, terminal verdict and zero
amount. It may release a reversible hold after a completed effect only when that
predeclared contract recomputes zero. `MonetaryReleaseAuthority` is the closed
enum `NoEffect(VerifiedNoEffectProof) | ContractualZeroCharge(
VerifiedContractualZeroCharge)`. No caller-built proof or missing receipt is
release authority.

`VerifiedEconomicMutationApplied` and `VerifiedEconomicMutationNotApplied` also
have private constructors. Both verify a versioned signed participant result
binding operation/request, participant identity and key epoch, resource id,
expected and resulting resource version/fence, immutable request digest, result
id/digest, and terminal applied or permanently-not-applied status. They are not
tool outcomes or payment release proofs. A remote participant must retain the
result and provide side-effect-free lookup by `operation_id`.

## Composable terminal projection

The one-off `AtomicReceiptProjection::SettlementObservationV1` capability is
replaced by a versioned capability set and one closed request type:

```rust
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

pub enum AdmissionReceiptOrIncident {
    Receipt(ChioReceipt),
    Incident(AdmissionIncident),
}

pub trait ReceiptStore: Send + Sync {
    fn admission_projection_capabilities(
        &self,
    ) -> AdmissionProjectionCapabilities;

    fn commit_admission_projection(
        &self,
        projection: &AdmissionTerminalProjection,
    ) -> Result<AdmissionTerminal, ReceiptStoreError>;
}
```

The production SQLite operation row is co-located with the receipt-side tables,
so `commit_admission_projection` performs these local changes in one
`BEGIN IMMEDIATE` writer transaction:

1. fence the coordinator lease and compare-and-swap the expected operation;
2. enforce the variant's legal source state and verify its release proof,
   outcome, receipt, incident, mutation result, payment and optional eligibility
   bindings;
3. for `Completed`, append the receipt and apply authorization, eligibility,
   observer and obligation projections before retaining `Completed` with its id;
4. for `CompensatedBeforeDispatch`, require a state strictly before
   `DispatchCommitted`, atomically bind the verified no-effect proof and exact
   denial receipt or incident, and retain that terminal state;
5. for `NotAcceptedAfterDispatchCommit`, require `DispatchCommitted`, retain
   captured invocation quota, bind the cancellation-fenced proof and receipt or
   incident, release only reversible monetary exposure, and retain the distinct
   terminal state; and
6. for `OutcomeUnknownAfterDispatch`, require `DispatchCommitted` or
   `Finalizing`, insert the incident, freeze participants, and retain that
   terminal state;
7. for `EconomicMutationApplied`, require kind `GovernedEconomicMutation`, bind
   the exact verified applied result id/digest, append its audit event, and retain
   `EconomicMutationApplied`; and
8. for `EconomicMutationNotApplied`, require the same kind and a verified
   permanently-not-applied result, append its audit event, and retain
   `EconomicMutationNotApplied`.

The store validates required capabilities at startup. It rejects missing,
duplicate, unexpected, or cross-bound projections and rolls back all local
changes. New projection kinds require a new typed field, capability flag, and
store conformance tests. Arbitrary SQL callbacks are forbidden.

The authoritative mutation service may be remote or separately stored. It is an
idempotent saga participant, not part of the local projection transaction. The
coordinator persists `Prepared`, calls apply by `operation_id`, then queries and
verifies the signed terminal result before the local projection. A crash between
participant commit and local terminalization resumes from lookup and never
repeats the mutation. Co-location may optimize the transaction but is not a
portable atomicity claim.

The payment journal is not mutated inside this receipt transaction when it is in
the budget database. `PaymentTerminalEvidence` is the verified terminal
participant snapshot and digest. The coordinator closes or confirms the payment
participant idempotently and can recover either ordering. WS1 must say
"one atomic receipt-side projection" rather than "one atomic money-path commit."

## Dispatch and payment ordering

Both evaluator paths use the same coordinator helper:

```text
prepare_admission_operation
authorize_participants
commit_dispatch
invoke_tool
record_outcome
commit_settle_action
commit_admission_projection
```

`commit_dispatch` captures invocation reservations and persists
`DispatchCommitted` before the first `invoke` or `invoke_stream`. It is called
from both `async_evaluation_core.rs` and `nested_flow_evaluation.rs`; neither
file owns a second partial implementation.

`record_outcome` means the two-step `ToolOutcomeRecordV1` commit above, not an
in-memory value. For a reversible rail, the resolved tool outcome and exact
capture or release action are
persisted before the rail call. For final prepayment, authorization is already a
money-moving participant result and cannot be relabeled as a releasable hold.
The receipt projection is attempted only after terminal rail evidence is
available. Pending or ambiguous rail results leave the saga recoverable or
incident-bound and do not produce a success receipt.

## Recovery truth table

| Operation truth | Participant query | Allowed recovery |
|---|---|---|
| before `DispatchCommitted` | no participant reports handoff or final prepayment | compensate reversible reservations and retain `CompensatedBeforeDispatch` |
| before `DispatchCommitted`, final prepayment moved | rail query | bind refund evidence if separately proved; otherwise incident, never hold release |
| `DispatchCommitted`, no transport acceptance proof | optional `DispatchStatusProvider` | verified `NotAccepted` plus cancellation fence commits `NotAcceptedAfterDispatchCommit`; absent/unknown becomes `OutcomeUnknownAfterDispatch` |
| durable provider acceptance | provider status | resume completed outcome or remain pending; never infer non-execution |
| outcome known, settle action absent | stored outcome | commit the exact derived action; never choose a different amount |
| settle action durable | rail status/idempotent operation | complete only the stored action; pending remains recoverable; conflict incidents |
| receipt projection committed | operation tombstone and receipt | close remaining participant acknowledgements idempotently; never redispatch |

A crash after tool execution but before the live code selects `Settling` leaves
`DispatchCommitted`. That state cannot take the old RFC-0013 `Authorized ->
release` shortcut. Recovery must obtain a terminal outcome from an idempotent
transport query or retain `OutcomeUnknownAfterDispatch` with the hold frozen.

`DispatchStatusProvider` returns only verified `NotAccepted`, `Pending`,
`Accepted { acceptance_ref }`, `Completed { tool_outcome_ref }`, or `Unknown` for
an exact operation and attempt. An accepted reference is usable only when its
authenticated envelope and current external monotonic attempt checkpoint are
retrievable; it proves that cancellation and no-effect release are no longer
possible, not that the effect completed. For `Completed`, a separate authenticated
`fetch_completed_outcome(tool_outcome_ref)` must return exact bytes, reported
cost, terminal evidence, operation/request/attempt binding, and transport key
epoch. Its private verified result is content-addressed and committed through
`record_tool_returned` before any post-return evaluation. A bare reference,
unavailable fetch, digest mismatch, or transport without retrieval becomes
`OutcomeUnknownAfterDispatch` and freezes the hold. Generic transports may omit
the provider. A provider without rollback-independent slot continuity may report
pending/completed evidence but cannot construct `VerifiedTransportNotAccepted`;
its apparent cancellation is `Unknown`. Every ambiguous committed handoff takes
the incident-only `OutcomeUnknownAfterDispatch` path. Recovery does not blind
replay, release a hold, or treat a missing receipt as proof that the tool did not
run. Outcome-priced WS3 transports must implement the provider.

Any provider that can construct `VerifiedTransportNotAccepted` also enforces an
execution-fenced attempt lifecycle outside its rollbackable queue state. Local
work is staged non-executable; external `Accepted` and `Cancelled` compete from
one `Pending` slot; only an external `Accepted -> Executing` lease/fence winner
may invoke; and accepted, executing, or completed work can never cancel. Recovery
reads the anchor first. After a possible effect, it uses authenticated tool-side
status or a qualified same-key idempotent invocation, otherwise it remains
unknown without rerunning. This invariant, not the provider signature alone,
makes terminal external `Cancelled` or typed `NoEffect` a no-effect proof.

The shared economic effect slot is one such qualified transport boundary. After
the admission row reaches `DispatchCommitted`, its external `Ready -> NoEffect`
CAS competes with `Ready -> DispatchCommitted`, permanently fences the handoff,
and constructs `VerifiedTransportNotAccepted` for
`NotAcceptedAfterDispatchCommit`. Invocation capture remains consumed. If the
handoff CAS won, the slot cannot cancel and the operation follows completed,
pending or outcome-unknown recovery.

## SQLite serving ownership

V1 permits one mutable serving owner per SQLite file:

1. A privileged `chio store provision` or trusted lock broker initializes the
   durable store UUID and protected UUID lock inode. `open_serving` only opens
   and verifies that existing inode, then holds its OS advisory lock in
   RFC-0006's canonical protected serving-lock root for the
   store lifetime. Path aliases and copied files with the same UUID contend on
   one lock; UUID, lock-inode, or underlying-file replacement fails startup.
2. In one `BEGIN IMMEDIATE` transaction it verifies the durable store UUID,
   increments `chio_serving_owner.owner_epoch`, and records a random lease id.
3. The shared `SqliteServingOwner` starts exactly one writer actor and, for the operation store, one recovery
   coordinator. In-process users clone handles rather than reopening the file.
4. Every mutable receipt, budget/payment, obligation, outcome, operation,
   projection, and recovery claim carries the full `StoreMutationFence`
   `(store_uuid, lease_id, owner_epoch)` and checks it in SQL. A stale worker
   receives `Fenced`.
5. A second mutable open fails `AlreadyServing`. CLI inspection and verifier
   clients use an explicit read-only open that cannot start workers.

Existing tests that intentionally open multiple mutable handles over one file
must be converted to cloned-handle tests or explicit read-only observer tests.
Multi-process serving is outside the local SQLite profile and requires a remote
linearizable store with leader epochs.

## Configuration and rollout

```rust
pub enum DurableAdmissionMode {
    Off,
    Monetary,
    SideEffecting,
    All,
}
```

The sets are cumulative. `Monetary` covers monetary calls;
`SideEffecting` covers monetary plus non-monetary effects; `All` also covers
explicitly annotated read-only calls. The compiled production default is
`SideEffecting`; unannotated tools already classify as side-effecting and cannot
bypass it. `Off` is allowed only for explicit tests and unsafe local development
with ephemeral receipts.

Pre-release qualification soaks `Monetary`, then `SideEffecting`. Production
starts and remains at `SideEffecting`; `All` is an explicit deployment option
when read-only request replay tombstones are worth the write latency. There is no
missing enum variant and no later production default flip.

## Tests

- Kill after tool return but before outcome or settle-action persistence;
  restart must not release the hold, reopen invocation quota, or redispatch.
- Kill immediately before and after raw outcome-blob and row commit, resolved
  outcome CAS, and settle-action commit. Recovery either freezes unknown or uses
  the exact durable bytes, cost, verdict and disposition.
- Kill before and after every participant call and operation update; recovery
  reaches `Completed`, `CompensatedBeforeDispatch`,
  `NotAcceptedAfterDispatchCommit`, or `OutcomeUnknownAfterDispatch` without
  repeating an effect.
- Replay a completed generic request id with identical and conflicting bodies;
  both resolve from or conflict with the tombstone without tool invocation.
- Fail each terminal projection independently; no receipt or incident, terminal
  operation, no-effect proof, outcome binding, eligibility, observer row,
  authorization consumption, or obligation may partially commit.
- Exercise top-level and nested-flow dispatch with the same kill matrix.
- Race two processes opening one database; exactly one obtains the serving
  lease across relative, absolute, symlink, hardlink, renamed and copied-same-UUID
  paths. Lock replacement fails. Race a stale epoch against a new owner; every
  stale mutation is fenced.
- With no `DispatchStatusProvider`, an ambiguous committed handoff always becomes
  incident-only and freezes the hold. With a provider, forged status, wrong
  identity/epoch/attempt, missing cancellation fence or external continuity
  checkpoint, restored/behind/divergent status, and conflicting outcome reject.
- Restore a qualified provider before acceptance and after enqueue/execution.
  Race non-executable local staging against external acceptance/cancellation and
  race executor claim against cancellation. A worker may invoke only after it
  wins the current external `Accepted -> Executing` lease/fence CAS; a cancelled
  slot never executes and an accepted/executing/completed slot never cancels.
  Restore after the effect but before completion; only authenticated tool-side
  status or qualified same-key idempotent invocation may finish it. Otherwise it
  stays outcome-unknown without rerun. A locally signed stale `NotAccepted` or
  anchor outage remains outcome-unknown and cannot release.
- Provider-completed recovery mutates every fetched byte, cost, operation,
  attempt, key epoch and evidence digest. Only the exact authenticated response
  persists a raw outcome; a bare or unavailable ref remains outcome-unknown.
- Crash before and after post-return evaluation start, each external guard call
  and result persistence, and final evaluation CAS. Recovery uses frozen pure
  inputs or idempotent authenticated lookup; non-replayable ambiguity freezes the
  hold and cannot choose a different guard or pricing result.
- Assert the four mode membership sets and production default `SideEffecting`.

## Implementation phases

1. Extend canonical `AdmissionOperationV1` and the store plan with the effect,
   payment, `ToolOutcomeRecordV1`, verified release authority, closed terminal
   projection, terminal receipt, and incident bindings in this
   document. Do not add a second intent state machine.
2. Implement the composable terminal projection, outcome/blob store, retained
   post-return evaluation journal, terminal migration, UUID-derived OS lock and owner-epoch fencing in
   `chio-store-sqlite`.
3. Thread `operation_id` through RFC-0013 payment participants and both kernel
   evaluator paths. Remove the `Authorized -> release` recovery shortcut after
   `DispatchCommitted`.
4. Run the crash matrix, multi-process ownership tests, and request replay tests
   with the production default fixed at `SideEffecting`.
