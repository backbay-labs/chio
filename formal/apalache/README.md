# Apalache Kernel-State Subset

This directory contains the focused Apalache-shaped TLA+ subset. It does not
replace the broader TLC-shaped models in `formal/tla/`. It extracts the
trust-boundary invariants selected for the kernel-state subset and keeps their
state spaces bounded enough for hosted CI.

## Bounds

The original four specs extend `Common.tla` and use the same reference bounds:

- `Authorities = 1..3`
- `CapSet = 1..6`
- `EpochMax = 4`

The common bounds mirror the bounded CI runner contract: hosted
`ubuntu-24.04`, Apalache installed by `tools/install-apalache.sh`, Z3 default
solver, and 30 minute per-invariant timeout in CI.

`PostAdmissionDropGuard.tla` has a purpose-built state space:

- `Invocations = 1..2`
- `ChildMax = 1`
- four ledger resources: monetary hold, invocation slot, admission lease,
  and child budget; payment authorization remains outside the ledger
- positive bound `--length=8`

The second invocation covers arbitrary ordering of two independently keyed
lifecycles. The model has per-invocation monetary ledgers and receipt counters;
its only cross-invocation aggregate is `ActiveChildShares`, which enforces the
shared `ChildMax` capacity. Shared monetary-store races remain outside this
result. One buffered child is enough to distinguish flush, discard, and
parent-ordering behavior. Receipt cardinality is represented by exact
per-invocation counters and ordering by a child-before-parent witness because
the attempted sequence encoding expanded every bounded index at every
transition under Apalache 0.50.1. Each safety row in CI carries its own length
and timeout fields.

## Invariants

| Invariant | Spec | Config | Purpose |
| --- | --- | --- | --- |
| `MonotoneLogApalache` | `MonotoneLogApalache.tla` | `MCMonotoneLogApalache.cfg` | Port of `formal/tla/RevocationPropagation.tla` `MonotoneLog` with explicit Apalache type annotations. |
| `RevocationCutCompleteness` | `RevocationCutCompleteness.tla` | `MCRevocationCutCompleteness.cfg` | Lifts Lean `revocation_is_cut` into a bounded state-machine invariant over transitive delegation cuts. |
| `ReceiptBeforeAllow` | `ReceiptBeforeAllow.tla` | `MCReceiptBeforeAllow.cfg` | A call may appear in an authority's allowed set only after a receipt with the same call identity and capability exists in the log. Call identities cannot be reused or published twice. Receipt persistence and allow publication are separate actions. This is modeled ordering evidence, not a discharge of concrete cross-row crash recovery. |
| `KernelTransitionCancelSafe` | `KernelTransitionCancelSafe.tla` | `MCKernelTransitionCancelSafe.cfg` | Models an interrupted kernel transition and proves rollback leaves budget and receipt state unchanged. |
| `ReservationConservation` | `PostAdmissionDropGuard.tla` | `MCPostAdmissionDropGuard.cfg` | Every admitted resource preserves the counted partition, reaches a terminal disposition, and shares the global `ChildMax` capacity without active-child oversubscription. |
| `TerminalReceiptExactlyOne` | `PostAdmissionDropGuard.tla` | `MCPostAdmissionDropGuard.cfg` | A committed parent append has exactly one record, an outcome-unknown append has at most one and cannot be retried, and clean pre-dispatch unwind appends none. |
| `ChildReceiptsFlushed` | `PostAdmissionDropGuard.tla` | `MCPostAdmissionDropGuard.cfg` | Under successful append availability, buffered child records are flushed before the parent terminal record. Outcome-unknown child presence and failed-suffix handling remain outside the model. |
| `RetainedIffAborted` | `PostAdmissionDropGuard.tla` | `MCPostAdmissionDropGuard.cfg` | Admission leases remain retained after every non-allow post-dispatch terminal. Monetary holds are committed after a returned output is reconciled, but remain retained after server errors and dropped futures. Raw URL errors map to incomplete terminals and use the same retention transition with and without nested bridge activity. A failed pre-dispatch cleanup retains only the affected resources. |

## Local smoke commands

```bash
apalache-mc check --length=6 --config=formal/apalache/MCMonotoneLogApalache.cfg formal/apalache/MonotoneLogApalache.tla
apalache-mc check --length=6 --config=formal/apalache/MCRevocationCutCompleteness.cfg formal/apalache/RevocationCutCompleteness.tla
apalache-mc check --length=6 --config=formal/apalache/MCReceiptBeforeAllow.cfg formal/apalache/ReceiptBeforeAllow.tla
apalache-mc check --length=6 --config=formal/apalache/MCKernelTransitionCancelSafe.cfg formal/apalache/KernelTransitionCancelSafe.tla
apalache-mc check --length=8 --config=formal/apalache/MCPostAdmissionDropGuard.cfg formal/apalache/PostAdmissionDropGuard.tla
apalache-mc check --length=0 --config=formal/tla/MCDistributedRevocationDomains.cfg formal/tla/DistributedRevocation.tla
apalache-mc check --length=6 --config=formal/tla/MCDistributedRevocation.cfg formal/tla/DistributedRevocation.tla
./scripts/check-apalache-negative.sh
./scripts/check-distributed-revocation-refinement.sh
```

The negative command is the falsifiability gate. It stages imported modules,
runs every entry in `_negative_tests/REGISTRY.toml`, and treats a
counterexample as success only when Apalache exits 12, reports an Error
outcome for exactly the registered invariant, and writes a structurally valid
ITF trace.

The scheduled temporal workflow runs `RevocationEventuallySeen` against the
local model and `RevocationEventuallyObservedDistributed` against the
distributed model. The second property is conditional on weak-fair connected
catch-up opportunities and partition healing.
