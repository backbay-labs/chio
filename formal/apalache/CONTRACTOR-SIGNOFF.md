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

## Post-Admission Drop Guard Verification (2026-07-10)

This dated addition records the local positive and falsifiability checks for
`PostAdmissionDropGuard.tla`. It is part of the same internal, self-authored
record. No external reviewer ran or countersigned these results.

### Positive Result

```bash
timeout 1800 apalache-mc check \
  --length=8 \
  --config=formal/apalache/MCPostAdmissionDropGuard.cfg \
  formal/apalache/PostAdmissionDropGuard.tla
```

| Spec | Invariants | Bound | Result | Wall clock |
| --- | --- | --- | --- | --- |
| `PostAdmissionDropGuard.tla` | `ReservationConservation`, `TerminalReceiptExactlyOne`, `ChildReceiptsFlushed`, `RetainedIffAborted` | length 8 | `NoError`, exit 0 | 1214.491 seconds |

Apalache reported `Checker reports no error up to computation length 8` and
an internal total of 1214.491 seconds on the integrated tree.

### Bounds and Abstractions

| Dimension | Attempted | Final | Rationale |
| --- | --- | --- | --- |
| Invocations | `1..2`, with every local choice duplicated symmetrically | `1..2`, with local choices on invocation 1 and a fixed dispatch-to-drop role on invocation 2 | Two identities preserve arbitrary ordering of independently keyed lifecycles. The model has no shared accumulator, and removing the duplicate local role changes no transition shape. |
| Admission profiles | All 12 valid profiles on both identities | All 12 valid profiles on invocation 1; `{slot, lease, child}` on invocation 2 | Hold and slot are mutually exclusive in production. The fixed second profile exercises every non-monetary resource during interleavings. |
| Buffered children | `ChildMax = 1` | `ChildMax = 1` | One child distinguishes flush, discard, and child-before-parent ordering. Additional children repeat the same loop shape. |
| Ledger resources | hold, slot, lease, child | hold, slot, lease, child | These are the four resources touched by pre-dispatch and post-dispatch unwind paths. |
| Cleanup failures | Dynamic `SUBSET admitted_resources[i]` | The 12 static valid profiles, filtered to subsets of the admitted resources | Negative calibration showed that Apalache 0.50.1 did not expose three pre-dispatch mutations through the dynamic powerset. The static domain represents the same reachable subsets and made all three counterexamples solver-visible. |
| Receipt representation | Bounded receipt sequence | Exact per-invocation child and parent counters plus a child-before-parent witness | The sequence encoding expanded every bounded index at each transition and was stopped at State 5 after 5 minutes 31 seconds. Counters preserve cardinality, attribution, and the checked ordering witness. |
| Search length | 8 | 8 | Two interleaved Admit, StartDispatch, StreamChunk, and Drop paths require eight transitions. The bound was not reduced during optimization. |
| Timeout | 1800 seconds | 1800 seconds | Timeout remains fail-closed in the hosted workflow. |

An intermediate static failure domain included four hold-plus-slot masks that
the admission relation forbids. That search was stopped after 903.01 seconds
at State 7. Removing only those unreachable masks produced the final
12-profile domain; it did not change a reachable state, the search length, or
an invariant.

### Negative Calibration

The registered falsifiability suite ran at length 4 with Apalache 0.50.1.
Every row exited 12, reported `The outcome is: Error`, and produced a parseable
non-empty ITF trace. The integrated nine-entry gate run completed in 84.83
seconds.

| Broken model | Falsified invariant | Result |
| --- | --- | --- |
| `ReceiptBeforeAllowBroken.tla` | `ReceiptBeforeAllow` | violation trace reproduced |
| `RevocationCutCompletenessBroken.tla` | `RevocationCutCompleteness` | violation trace reproduced |
| `DropGuardDiscardChildBufferBroken.tla` | `ChildReceiptsFlushed` | violation trace reproduced |
| `DropGuardSkipChildBudgetReleaseBroken.tla` | `ReservationConservation` | violation trace reproduced |
| `DropGuardSkipInvocationReversalBroken.tla` | `ReservationConservation` | violation trace reproduced |
| `DropGuardNoFaultReceiptBroken.tla` | `TerminalReceiptExactlyOne` | violation trace reproduced |
| `DropGuardReleaseOnIncompleteStreamBroken.tla` | `RetainedIffAborted` | violation trace reproduced |
| `DropGuardNoRetainOnPostInvocationDenyBroken.tla` | `RetainedIffAborted` | violation trace reproduced |
| `DropGuardReleaseOnPostDispatchAbortBroken.tla` | `RetainedIffAborted` | violation trace reproduced |

### Tooling and Hosted Status

- Apalache: `0.50.1`, build `cd35919`.
- Java: Eclipse Temurin OpenJDK `21.0.11+10-LTS`.
- Host: Ubuntu Linux on `aarch64`, kernel `6.17.0-1011-oracle`.
- Solver: default Apalache Z3 backend.

No hosted run reference is available at the time of this local record. The
landing pull request must pass both the positive `apalache-subset` job and the
separate `apalache-negative` job. The two hosted acceptance items remain open
until those jobs pass.
