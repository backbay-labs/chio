# Apalache Internal Verification Record

**Packet:** APALACHE-RECORD-2026-05-02
**Record date:** 2026-05-02
**Authored by:** Chio formal verification lane (internal, self-authored)
**External countersignature:** none. No external contractor has reviewed or
countersigned this record. There is no external sign-off.

This memo is an internal, self-authored record of the focused Apalache
kernel-state subset run. It is NOT an external contractor sign-off: no
third-party vendor (and no Informal Systems or Runtime Verification engagement)
has reviewed, run, or countersigned these results. The record exists so that an
external reviewer, if engaged in a future milestone, has the exact commands,
bounds, solver posture, and counterexample status in one place. Treat every
result below as the maintainers' own claim, reproducible from the pinned
tooling, not as independently verified evidence.

## Invariants Checked

| Invariant | Spec | Config | Result |
| --- | --- | --- | --- |
| `MonotoneLogApalache` | `formal/apalache/MonotoneLogApalache.tla` | `formal/apalache/MCMonotoneLogApalache.cfg` | NoError to length 6 |
| `RevocationCutCompleteness` | `formal/apalache/RevocationCutCompleteness.tla` | `formal/apalache/MCRevocationCutCompleteness.cfg` | NoError to length 6 |
| `ReceiptBeforeAllow` | `formal/apalache/ReceiptBeforeAllow.tla` | `formal/apalache/MCReceiptBeforeAllow.cfg` | NoError to length 6 |
| `KernelTransitionCancelSafe` | `formal/apalache/KernelTransitionCancelSafe.tla` | `formal/apalache/MCKernelTransitionCancelSafe.cfg` | NoError to length 6 |

## Tooling

- Apalache version: `apalache-mc 0.50.1`, build `cd35919`.
- Installer pin: `tools/install-apalache.sh` `APALACHE_VERSION="0.50.1"`.
- SMT solver: default Apalache Z3 backend.
- Runner posture: local macOS smoke. A hosted `ubuntu-24.04` workflow that
  re-runs the same invocations exists in `.github/workflows`; a stable hosted
  run reference is not yet recorded here and is tracked as a CI-debt item
  rather than cited as a point-in-time run URL.

## SMT Invocations

Each safety invariant used the same invocation shape:

```bash
apalache-mc check --length=6 --config=<MC*.cfg> <Spec>.tla
```

The hosted workflow preserves the same command shape for all four
safety invariants. The temporal `RevocationEventuallySeen` check remains in
`.github/workflows/apalache-temporal.yml` as the fail-closed nightly TLA+
liveness lane.

## Bounds

| Bound | Attempted | Final | Rationale |
| --- | --- | --- | --- |
| Authorities | `{1, 2, 3}` | `{1, 2, 3}` | Three authorities are enough to expose stale-view propagation and multi-authority log order bugs. |
| CapSet | `{1, 2, 3, 4, 5, 6}` | `{1, 2, 3, 4, 5, 6}` | Six capabilities cover root, child, sibling, revoked root, revoked child, and unaffected capability cases. |
| EpochMax | `4` | `4` | Four epochs cover zero, observed, propagated, and stale-after-revoke states without exploding the SMT search. |
| Length | `6` | `6` | Six transitions cover issue, allow, revoke, epoch propagation, cancellation, and stutter. |

The larger TLC aspiration (`PROCS=4`, `CAPS=8`, `DEPTH_MAX=4`) remains out of
the focused Apalache bound because this scope is the kernel-state subset.

## Counterexamples

No counterexamples surfaced in the local safety run. If the hosted
7-consecutive-night replay surfaces a counterexample, the closeout response is
fail-closed: file a property-counterexample issue, classify it as spec fix,
implementation fix, or out-of-bound, and reopen the formal evidence row
before final qualification.

## Status

This is an internal record, not a sign-off. The four safety checks pass
locally with the pinned Apalache version and the documented bounds, as run by
the maintainers. The focused Apalache subset is documented here so it could be
handed to an external reviewer if and when such an engagement is opened; no
such engagement has occurred and no external party has countersigned. A stable
hosted workflow run reference and 7-consecutive-night-green evidence are
tracked as CI-debt replay items before final close.
