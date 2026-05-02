# M06 Apalache Contractor Sign-Off

**Packet:** M06-APALACHE-SIGNOFF-2026-05-02
**Sign-off date:** 2026-05-02
**Contractor lane:** Informal Systems primary, Runtime Verification fallback
**External countersignature:** pending vendor calendar response
**Owner of record:** Chio M06 formal lane

This memo records the M06 contractor sign-off package for the focused
Apalache kernel-state subset. The external contractor countersignature is
still a vendor-calendar item; the local sign-off records the exact commands,
bounds, solver posture, and counterexample status that the contractor is
asked to countersign. Under the trajectory-3 CI policy, hosted workflow
completion is replayed during the CI-debt stabilization pass.

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
- Runner posture: local macOS smoke plus hosted `ubuntu-24.04` workflow
  dispatch at `https://github.com/bb-connor/arc/actions/runs/25251783773`.

## SMT Invocations

Each safety invariant used the same invocation shape:

```bash
apalache-mc check --length=6 --config=<MC*.cfg> <Spec>.tla
```

The workflow dispatch also preserves the same command shape for all four
safety invariants. The temporal `RevocationEventuallySeen` check remains in
`.github/workflows/apalache-nightly.yml` as the existing TLA+ liveness lane.

## Bounds

| Bound | Attempted | Final | Rationale |
| --- | --- | --- | --- |
| Authorities | `{1, 2, 3}` | `{1, 2, 3}` | Three authorities are enough to expose stale-view propagation and multi-authority log order bugs. |
| CapSet | `{1, 2, 3, 4, 5, 6}` | `{1, 2, 3, 4, 5, 6}` | Six capabilities cover root, child, sibling, revoked root, revoked child, and unaffected capability cases. |
| EpochMax | `4` | `4` | Four epochs cover zero, observed, propagated, and stale-after-revoke states without exploding the SMT search. |
| Length | `6` | `6` | Six transitions cover issue, allow, revoke, epoch propagation, cancellation, and stutter. |

The larger TLC aspiration from the trajectory narrative (`PROCS=4`,
`CAPS=8`, `DEPTH_MAX=4`) remains out of the Apalache M06 bound because the
M06 scope is the D04 focused kernel-state subset.

## Counterexamples

No counterexamples surfaced in the local P5 safety run. If the hosted
7-consecutive-night replay surfaces a counterexample, the closeout response is
fail-closed: file a property-counterexample issue, classify it as spec fix,
implementation fix, or out-of-bound, and reopen the M06 formal evidence row
before trajectory-3 finalization.

## Sign-Off

The M06 focused Apalache subset is ready for external countersignature and M08
protocol-review consumption. The four safety checks pass locally with the
pinned Apalache version and the documented bounds. The hosted workflow run and
7-consecutive-night-green evidence are tracked as CI-debt replay items before
trajectory-3 final close.
