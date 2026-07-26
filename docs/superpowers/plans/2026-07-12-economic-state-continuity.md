# Economic State Continuity Implementation Plan

> Execute with the Superpowers subagent workflow and verify each task before its
> commit.

**Goal:** Ship the shared external multi-resource continuity contract required
before rollback-sensitive WS4, WS5, or WS7 execution can activate.

**Architecture:** `chio-core-types` owns canonical heads, batches and the anchor
port. `chio-control-plane` owns a configured external linearizable adapter.
`chio-store-sqlite` stores only staged/cache projections under the shared serving
fence. Consumer crates own legal transition proofs and batch composition.

## Task 1: Define Canonical Heads And Batches

**Files:**

- Create `crates/core/chio-core-types/src/economic_continuity.rs`.
- Modify `crates/core/chio-core-types/src/lib.rs`.
- Create `spec/schemas/chio-economy/resource-head.v1.json`.
- Create `spec/schemas/chio-economy/state-batch.v1.json`.
- Create `spec/schemas/chio-economy/effect-slot.v1.json`.
- Modify the schema registry, hash manifest and known-schema allowlists.

**Work:**

- [ ] Implement bounded canonical resource keys, heads, effect slots, sorted
  batch transitions, domain-separated ids and exact RFC 8785 digests.
- [ ] Enforce a permanent authenticated request replay mapping to one operation,
  request binding and effect-slot set. Equal replay returns retained truth;
  conflicting replay rejects before a batch CAS, including after local tombstone
  restore.
- [ ] Enforce effect-slot transitions `Ready -> DispatchCommitted | NoEffect`,
  `DispatchCommitted -> Completed | NoEffect | Unknown`, and authenticated
  `Unknown -> Completed | NoEffect`. Before local handoff, `NoEffect` requires
  the exact private pre-dispatch proof. After `AdmissionOperation` reaches
  `DispatchCommitted`/`MutationSubmitted`, the atomic winning `Ready -> NoEffect`
  CAS constructs only a cancellation-fenced `VerifiedTransportNotAccepted` or
  typed permanently-not-applied result; invocation capture is not reversed. No
  terminal state reopens. `Completed`/`NoEffect`
  retain canonical result/proof bytes or rollback-independent availability;
  digest-only terminal slots reject.
- [ ] Reject duplicate/unsorted keys, empty or oversized batches, invalid
  predecessor/root, regressing version/fence/clock and inconsistent effect or
  FROST bindings. Every effect requires operation/action/slot bindings; FROST
  fields are required exactly for registered `n_of_m` actions and forbidden for
  non-quorum actions.
- [ ] Add signed positive, one-field-tampered and unknown-version fixtures with
  runtime/CLI registry parity.

## Task 2: Implement The Verified Anchor Port

**Files:**

- Extend `crates/core/chio-core-types/src/economic_continuity.rs`.
- Create `crates/platform/chio-control-plane/src/economic_state_anchor.rs`.
- Modify `crates/platform/chio-control-plane/src/lib.rs` and composition wiring.

**Work:**

- [ ] Define `EconomicStateAnchor` authenticated read and linearizable bounded
  multi-key CAS APIs plus private `VerifiedEconomicStateBatchAdvance`,
  `VerifiedEconomicEffectDispatch`, verified target-status and qualified
  idempotent-recovery constructors. A resource-head read cannot construct dispatch
  authority.
- [ ] Pin anchor identity/namespace/signer key in trusted configuration. Recheck
  the signed batch and consumer transition-proof digests in the adapter.
- [ ] Provide no SQLite or in-memory production fallback. Test doubles are
  fixture-only and rejected by production composition.
- [ ] Expose readiness that is false on missing, unavailable, wrong-key, behind,
  ahead or divergent state until exact reconciliation completes.

## Task 3: Add Fenced Local Staging And Recovery

**Files:**

- Create `crates/platform/chio-store-sqlite/src/economic_state_cache.rs`.
- Modify `crates/platform/chio-store-sqlite/src/lib.rs`.
- Create `crates/platform/chio-control-plane/src/economic_state_recovery.rs`.

**Work:**

- [ ] Store exact staged batch/state blobs and anchored local heads using the one
  shared `SqliteServingOwner` and `StoreMutationFence`.
- [ ] Implement `DbStaged -> EconomicAnchorAdvanced -> DbFinalized` recovery.
  Repair an anchored-ahead local cache from retained canonical bytes; discard or
  retry only an exact legal unanchored stage; quarantine divergence. For an
  operation-bound stage, only the current `AdmissionOperation` coordinator lease
  may retry after verifying the exact nonterminal operation state; a compensated,
  terminal or mismatched operation forces discard/compensation and cannot expose
  the staged resource.
- [ ] Create each operation-specific effect slot as `Ready` with its resource
  batch. Immediately before handoff, require the matching local
  `AdmissionOperation` handoff state/version/fence (`DispatchCommitted` for tool
  dispatch, `MutationSubmitted` for governed mutation) and atomically advance the
  external slot to `DispatchCommitted`. Only that CAS returns first-handoff authority.
- [ ] Recover a committed effect slot only through authenticated target status or
  a separately qualified same-key idempotent target. Otherwise retain `Unknown`
  and lock the resource without invoking.

## Task 4: Qualify The Shared Substrate

**Files:**

- Create `crates/tooling/chio-conformance/tests/economic_state_continuity.rs`.
- Add focused control-plane and SQLite recovery tests beside the new modules.

**Work:**

- [ ] Property-test sorted atomic multi-key CAS and every invalid transition.
- [ ] Kill and restore before/after local stage, anchor CAS, local finalize,
  `AdmissionOperation::DispatchCommitted`, effect-slot CAS, target call and
  terminal status. Same-epoch old snapshots never regain first-handoff authority.
- [ ] Race admission compensation against unanchored batch recovery. Only the
  current operation lease may retry, and a compensated/terminal operation can
  never leave an externally ready effect slot.
- [ ] Kill in the exact gap after local `DispatchCommitted`/`MutationSubmitted`
  and before effect-slot CAS. Race cancellation against handoff: cancellation
  yields the post-commit not-accepted/permanently-not-applied terminal, handoff
  yields one dispatch token, and neither path uses pre-dispatch compensation.
- [ ] Race conflicting batches and prove exactly one current expected-head set
  wins. A stale serving owner or external checkpoint cannot mutate or dispatch.
- [ ] Run targeted tests, schema/codegen checks, workspace clippy and format.

## Task 5: Integrate Consumers Without Weak Fallbacks

- [ ] WS4 binds round plus obligation heads and passes finalization/abort,
  per-intent effect-slot, first-dispatch and restore matrices.
- [ ] WS5 binds channel plus escrow/service reservations and passes
  service-admission/close, tool/release/refund effect-slot and restore matrices.
- [ ] WS7 binds semantic-trigger, claim and shared coverage heads for both legacy
  and parametric paths and passes duplicate-claim, reservation/payout effect-slot
  and restore matrices.
- [ ] Keep each protected path disabled until its consumer-specific matrix passes
  against a production-qualified external adapter. Fixtures alone do not satisfy
  activation.

Commit: `feat(economy): anchor irreversible resource lifecycles`
