# Economic State Continuity Design

- Status: Approved architecture amendment
- Date: 2026-07-12
- Owners: `chio-core-types` (contract), `chio-control-plane` (anchor adapter),
  `chio-store-sqlite` (staging/cache), and each economic resource owner
- Consumers: WS4 clearing, WS5 channels, WS7 claims/coverage, and future
  rollback-sensitive economic lifecycles

## Goal

Prevent a coordinated restore of local databases from reopening an economic
resource version, reservation, authorization slot, or terminal disposition that
has already authorized or observed an external effect.

SQLite ownership and row compare-and-swap prevent concurrent live writers. They
do not prove that a restored database is the newest history. Any consumer that
claims a lifecycle cannot regress must therefore reconcile to an authenticated
monotonic head outside its database backup and restore domain before serving.

## Non-goals

- General distributed transactions across arbitrary stores.
- Payment-rail or chain finality.
- A SQLite implementation presented as anti-rollback authority.
- Replacing `AdmissionOperation`, FROST, or consumer-specific state validation.

## Canonical contract

`chio.economy.resource-head.v1` binds:

- anchor id and namespace;
- `resource_family`, trusted scope id, and stable resource id;
- resource version and lifecycle fence;
- typed lifecycle-state code and canonical state digest;
- optional operation id and effect idempotency key;
- optional FROST authorization-slot id, authorization id, and action digest;
- optional terminal result id and digest;
- trusted-clock high-water; and
- head version and predecessor digest.

The state digest commits the complete consumer-owned canonical state, including
amount/currency or token binding, parties, reservations, immutable source
artifacts, and every child resource key. The anchor retains the canonical state
blob or a rollback-independent content-addressed availability receipt so a local
projection can be reconstructed after restore.

Reading a current resource head is not dispatch authority. Every protected
external effect also has a permanent `chio.economy.effect-slot.v1` resource keyed
by trusted scope, resource, operation id and effect kind. It binds authenticated
request namespace/id/binding, `AdmissionOperation` dispatch state/version/fence,
target identity/key epoch, action and parameter digests, resource-head digest,
optional FROST authorization slot, effect idempotency key, and state:

```text
Ready -> DispatchCommitted | NoEffect
DispatchCommitted -> Completed | NoEffect | Unknown
Unknown -> Completed | NoEffect
```

The effect slot is created as `Ready` in the same batch that reserves or admits
the action. Immediately before target handoff, the coordinator verifies the
matching local authoritative handoff state (`DispatchCommitted` for tool
dispatch or `MutationSubmitted` for governed economic mutation), version and
fence, then compare-and-swaps the external slot to `DispatchCommitted`. Only the successful CAS returns the private,
non-reconstructible `VerifiedEconomicEffectDispatch` accepted by the supported
dispatcher. Merely reading a `Ready` or `DispatchCommitted` slot cannot mint that
type. A restored local operation therefore cannot repeat the first handoff.

Once the external slot reaches `DispatchCommitted`, an effect may have happened.
Recovery queries authenticated target status by the exact operation/slot/key. It
may bind `Completed` with the exact terminal result or `NoEffect` with a private
verified cancellation/no-acceptance proof. It may retry only when the target was
separately qualified to enforce the same idempotency key and return the same
effect/result. Otherwise it advances or retains `Unknown`, locks the resource and
never invokes again. `Unknown -> Completed | NoEffect` accepts later authenticated
status but never blind replay. An idempotency-key string without target
qualification is not authority.

The anchor also enforces one permanent replay mapping from authenticated
`(request_namespace_digest, request_id)` to the exact operation, request binding
and effect-slot set. Equal replay resolves the retained slots/results; a different
binding conflicts before any new resource batch. Restoring the local admission
tombstone therefore cannot create another operation for the same request.

`Ready -> NoEffect` is an atomic permanent cancellation competing with
`Ready -> DispatchCommitted`. Before the local admission handoff state, it may
bind `VerifiedPreDispatchNoEffect`. If the local operation already reached
`DispatchCommitted` or `MutationSubmitted`, the winning cancellation CAS instead
constructs private `VerifiedEconomicEffectNotDispatched`, binding the exact
operation state/version/fence, slot/head, target and cancellation checkpoint. For
a tool dispatch it converts only to the admission contract's
`VerifiedTransportNotAccepted`, terminalizes as
`NotAcceptedAfterDispatchCommit`, retains invocation capture and may release only
reversible exposure. For a governed mutation it converts only to the typed
permanently-not-applied result. If `Ready -> DispatchCommitted` won, cancellation
cannot be constructed and recovery follows target status/unknown rules.
`Completed` and `NoEffect` retain the complete canonical result/proof bytes in
the anchor or bind a rollback-independent content-availability receipt. Digest-
only terminal state cannot recover a restored local projection and is invalid.

`chio.economy.state-batch.v1` is a bounded sorted transition set:

```text
EconomicStateBatchV1 {
  schema,
  batch_id,
  anchor_id,
  namespace,
  checkpoint_sequence,
  previous_checkpoint_digest,
  expected_heads_root,
  next_heads_root,
  transitions: [
    { resource_key, expected_head_digest?, next_head, transition_proof_digest }
  ],
  operation_id?,
  issued_at,
  signer_key_id,
  signer_key_epoch,
}
```

Resource keys are unique and lexicographically sorted. `batch_id` is SHA-256 over
the domain-separated RFC 8785 body excluding `batch_id`. The signed envelope
digest is the checkpoint digest. The configured maximum transition count and
canonical byte limit are checked before signing and by the anchor.

`EconomicStateAnchor::compare_and_swap_batch` is linearizable across every key
in one batch. It accepts only a private `VerifiedEconomicStateBatchAdvance` whose
constructor verifies:

1. pinned anchor identity, namespace, signer key and key epoch;
2. checkpoint sequence plus one and exact predecessor;
3. exact current expected head for every key and roots over the sorted sets;
4. checked, non-regressing head version, resource version, lifecycle fence and
   trusted clock;
5. unchanged resource identity and consumer-owned immutable bindings;
6. a consumer verifier's private legal-transition proof for every head; and
7. one operation id, action digest and effect-slot key wherever the transition
   prepares an external effect; exact FROST slot/authorization bindings are
   additionally required only when the registered action class is mapped
   `n_of_m`, and are forbidden otherwise.

The anchor re-verifies the signed batch and transition proofs before CAS. Caller
JSON, a locally signed row, elapsed time, or a valid FROST signature without the
matching current resource head cannot advance it.

## Persistence protocol

Every irreversible transition uses:

```text
DbStaged -> EconomicAnchorAdvanced -> DbFinalized
AdmissionHandoffCommitted -> EffectSlotDispatchCommitted -> EffectExecutable
```

The local staged transaction stores the exact next canonical state and batch
bytes but does not expose capacity, release reservations, or permit an effect.
The external resource batch CAS is the lifecycle linearization point. Local
finalization requires the exact anchored checkpoint. A separate external
effect-slot CAS is the only first-handoff authority; neither local state nor a
read of the current resource head can authorize dispatch.

Recovery reads the anchor first. Readiness remains false until every protected
local head exactly matches it:

- an operationless unanchored local stage may retry only under its owning
  authority; an operation-bound stage may retry only through the current
  `AdmissionOperation` coordinator lease after verifying the exact legal
  nonterminal state. A compensated, terminal, stale-lease or mismatched operation
  discards/compensates the stage and can never create a ready effect slot;
- an anchored head ahead of local state is reconstructed from the retained
  canonical blob and finalized;
- a local finalized head ahead of or divergent from the anchor is quarantined;
- missing, unavailable, wrong-key, behind, or divergent anchor state denies
  protected mutation and dispatch; and
- a stale process or restored SQLite owner is still rejected by
  `StoreMutationFence` in addition to the external head check.

No age-based or operator convenience path may synthesize a newer head. Restoring
both the receipt and consumer databases cannot reopen an anchored resource.

## Consumer batches

### WS4 clearing

One batch covers the round lifecycle head and every included obligation
disposition/reservation head. Reservation, proposal, finalization, abort, first
dispatch, reconciliation, and reservation release each advance that same
authoritative set. Finalization and abort race on the round head. An abort batch
cannot release obligations from an anchored finalized or dispatching round.
First dispatch requires the anchored finalized head plus separate fresh WS1
settlement authority and one effect slot per immutable settlement intent.

### WS5 channels

One batch covers the channel lifecycle, escrow reservation and optional live
service reservation. Service admission and close race on the same channel head.
A payer-authorized service reservation becomes executable only after the anchor
commits it and its operation-specific effect slot wins the handoff CAS.
`ClosePending`, final close, realized release and refund each advance the same
heads; release/refund dispatch uses separate effect slots. A restored `Open`
projection cannot admit service after anchored close, repeat a tool effect or
recover previously consumed capacity.

### WS7 claims and coverage

One batch covers the semantic trigger-instance head, claim lifecycle and shared
liability-coverage ledger. Claim creation, contest outcome, payout reservation,
submission, reconciliation and verified reservation release update the affected
heads atomically at the anchor. Every payout instruction uses its own effect
slot. The legacy claim path uses the same coverage
head. A restored database cannot create a second claim for an anchored semantic
trigger or reuse reserved/paid coverage.

## FROST binding

FROST prevents a second message for one authorization slot through its separate
external slot checkpoint. For an irreversible consumer transition, the economic
batch binds that slot id, authorization id, action digest and signed-envelope
digest. The consumer verifies the completed slot and current resource heads,
then advances the economic batch. A threshold signature without this anchor CAS
is evidence only and cannot make an effect executable.

## Testing

- Model and property-test sorted multi-key CAS, stale expected roots, duplicate
  keys, sequence gaps, transition-proof mismatch, size bounds and checked
  version/fence/clock monotonicity.
- Kill before and after local stage, anchor CAS, local finalization, effect-slot
  CAS and external effect. Exact recovery completes once; ambiguity does not
  repeat an effect.
- Restore `AdmissionOperation` and receipt SQLite before dispatch after an effect
  slot commits. The permanent external slot prevents a second first handoff.
  Authenticated completed/no-effect status resolves; unavailable or unqualified
  targets remain unknown and locked.
- Restore same-epoch snapshots before finalization, close and payout after the
  anchor advances. Startup repairs to the anchored head or remains unready; it
  never serves the restored lifecycle.
- Race WS4 finalization/abort, WS5 service admission/close, and WS7
  legacy/parametric coverage reservation through the external batch CAS.
- Reject missing/unavailable, wrong identity/key/namespace, behind, ahead and
  divergent anchor views before protected dispatch.
- Prove no production configuration installs SQLite as `EconomicStateAnchor`.

## Activation

The core contract and external adapter qualification are a shared prerequisite.
Each consumer still owns its legal-transition verifier and exact batch. Artifact
work may land earlier, but WS4 dispatch, WS5 service/close, and WS7 payout remain
disabled until their restore/race matrices pass against a production-qualified
external anchor.
