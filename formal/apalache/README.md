# Apalache Kernel-State Subset

This directory contains the focused Apalache-shaped TLA+ subset. It does not
replace the broader TLC-shaped models in `formal/tla/`. It extracts the four
trust-boundary invariants selected for the kernel-state subset and keeps their
state spaces bounded enough for hosted CI.

## Bounds

All specs extend `Common.tla` and use the same reference bounds:

- `Authorities = 1..3`
- `CapSet = 1..6`
- `EpochMax = 4`

The common bounds mirror the bounded CI runner contract: hosted
`ubuntu-24.04`, Apalache installed by `tools/install-apalache.sh`, Z3 default
solver, and 30 minute per-invariant timeout in CI.

## Invariants

| Invariant | Spec | Config | Purpose |
| --- | --- | --- | --- |
| `MonotoneLogApalache` | `MonotoneLogApalache.tla` | `MCMonotoneLogApalache.cfg` | Port of `formal/tla/RevocationPropagation.tla` `MonotoneLog` with explicit Apalache type annotations. |
| `RevocationCutCompleteness` | `RevocationCutCompleteness.tla` | `MCRevocationCutCompleteness.cfg` | Lifts Lean `revocation_is_cut` into a bounded state-machine invariant over transitive delegation cuts. |
| `ReceiptBeforeAllow` | `ReceiptBeforeAllow.tla` | `MCReceiptBeforeAllow.cfg` | Names the Apalache invariant that replaces the prior joint discharge of `RETIRED-SQLITE-CROSS-ROW`, with receipt persistence and allow publication split into separate actions. |
| `KernelTransitionCancelSafe` | `KernelTransitionCancelSafe.tla` | `MCKernelTransitionCancelSafe.cfg` | Models an interrupted kernel transition and proves rollback leaves budget and receipt state unchanged. |

## Local smoke commands

```bash
apalache-mc check --length=6 --config=formal/apalache/MCMonotoneLogApalache.cfg formal/apalache/MonotoneLogApalache.tla
apalache-mc check --length=6 --config=formal/apalache/MCRevocationCutCompleteness.cfg formal/apalache/RevocationCutCompleteness.tla
apalache-mc check --length=6 --config=formal/apalache/MCReceiptBeforeAllow.cfg formal/apalache/ReceiptBeforeAllow.tla
apalache-mc check --length=6 --config=formal/apalache/MCKernelTransitionCancelSafe.cfg formal/apalache/KernelTransitionCancelSafe.tla
```

The nightly workflow also runs the existing `RevocationEventuallySeen`
liveness check via `--temporal=` against `formal/tla/RevocationPropagation.tla`.
