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

## Post-Admission Drop Guard Verification (2026-07-14)

This dated addition records the local positive and falsifiability checks for
`PostAdmissionDropGuard.tla`. It is part of the same internal, self-authored
record. No external reviewer ran or countersigned these results.

### Positive Result

```bash
timeout 10800 apalache-mc check \
  --length=8 \
  --config=formal/apalache/MCPostAdmissionDropGuard.cfg \
  formal/apalache/PostAdmissionDropGuard.tla
```

| Spec | Invariants | Bound | Result | Wall clock |
| --- | --- | --- | --- | --- |
| `PostAdmissionDropGuard.tla` | `ReservationConservation`, `TerminalReceiptExactlyOne`, `ChildReceiptsFlushed`, `RetainedIffAborted` | length 8 | `NoError`, exit 0 | 3058 seconds |

Apalache reported `Checker reports no error up to computation length 8` and
an internal total of 3056.345 seconds on the integrated tree after the
outcome-unknown retention transition was corrected. The wrapper elapsed time
was 3058 seconds. The 10800-second timeout is the configured fail-closed
ceiling, not the observed duration.

### Bounds and Abstractions

| Dimension | Attempted | Final | Rationale |
| --- | --- | --- | --- |
| Invocations | `1..2`, with every local choice duplicated symmetrically | `1..2`, with local choices on invocation 1 and a fixed dispatch-to-drop role on invocation 2 | Two identities preserve arbitrary ordering of independently keyed lifecycles. Monetary ledgers remain per invocation; `ActiveChildShares` is the one cross-invocation aggregate and enforces shared child capacity. Removing the duplicate local role changes no transition shape. |
| Admission profiles | All 12 valid profiles on both identities | All 12 valid profiles on invocation 1; `{slot, lease, child}` on invocation 2 | Hold and slot are mutually exclusive in production. The fixed second profile exercises every non-monetary resource during interleavings. |
| Buffered children | `ChildMax = 1` | `ChildMax = 1` | One child distinguishes flush, discard, and child-before-parent ordering. The same bound caps active admitted child shares across both invocations; the oversubscription mutation calibrates that guard. |
| Ledger resources | hold, slot, lease, child | hold, slot, lease, child | Pre-dispatch cleanup may reverse or release these resources. Returned outputs reconcile and commit the hold. Outcome-unknown server errors and dropped futures retain the hold and lease while committing the slot and child budget fail closed. |
| Cleanup failures | Dynamic `SUBSET admitted_resources[i]` | The 12 static valid profiles, filtered to subsets of the admitted resources | Negative calibration showed that Apalache 0.50.1 did not expose three pre-dispatch mutations through the dynamic powerset. The static domain represents the same reachable subsets and made all three counterexamples solver-visible. |
| Receipt representation | Bounded receipt sequence | Exact per-invocation child and parent counters plus a child-before-parent witness | The sequence encoding expanded every bounded index at each transition and was stopped at State 5 after 5 minutes 31 seconds. Counters preserve cardinality, attribution, and the checked ordering witness. |
| Search length | 8 | 8 | Two interleaved Admit, StartDispatch, StreamChunk, and Drop paths require eight transitions. The bound was not reduced during optimization. |
| Timeout | 1800 seconds | 10800 seconds | The unchanged production bounds remain fail-closed while allowing for host contention during the longest bounded checks. |

An intermediate static failure domain included four hold-plus-slot masks that
the admission relation forbids. That search was stopped after 903.01 seconds
at State 7. Removing only those unreachable masks produced the final
12-profile domain; it did not change a reachable state, the search length, or
an invariant.

### Negative Calibration

The registered 16-entry falsifiability suite completed in 161 seconds with
Apalache 0.50.1. Every row exited 12, reported `The outcome is: Error`, and
produced exactly one parseable non-empty `violation1.itf.json` trace. No row
timed out or returned a tool error. The registry, mapping, model, config, and
evidence-parser input digest for this run was
`5f7f4a018f73f6bbab5c031b489c41e435728834f32f08b38e8babb3c78fe4e8`.

| Broken model | Falsified invariant | Result |
| --- | --- | --- |
| `DistributedRevocationRevocationGateBroken.tla` | `NoAllowAfterRevokeDistributed` | exit 12, Error, one validated ITF trace |
| `DistributedRevocationSignerPinBroken.tla` | `SignerPinnedHighWater` | exit 12, Error, one validated ITF trace |
| `DistributedRevocationSkewBroken.tla` | `ClockSkewBound` | exit 12, Error, one validated ITF trace |
| `DistributedRevocationPartitionBroken.tla` | `PartitionSuspendResume` | exit 12, Error, one validated ITF trace |
| `DistributedRevocationFreshnessBroken.tla` | `StaleEvaluationDenied` | exit 12, Error, one validated ITF trace |
| `DistributedRevocationEvaluationCountWitness.tla` | `RejectedRawEvaluationCountBound` | exit 12, Error, one validated ITF trace |
| `ReceiptBeforeAllowBroken.tla` | `ReceiptBeforeAllow` | exit 12, Error, one validated ITF trace |
| `RevocationCutCompletenessBroken.tla` | `RevocationCutCompleteness` | exit 12, Error, one validated ITF trace |
| `DropGuardDiscardChildBufferBroken.tla` | `ChildReceiptsFlushed` | exit 12, Error, one validated ITF trace |
| `DropGuardSkipChildBudgetReleaseBroken.tla` | `ReservationConservation` | exit 12, Error, one validated ITF trace |
| `DropGuardChildOversubscriptionBroken.tla` | `ReservationConservation` | exit 12, Error, one validated ITF trace |
| `DropGuardSkipInvocationReversalBroken.tla` | `ReservationConservation` | exit 12, Error, one validated ITF trace |
| `DropGuardNoFaultReceiptBroken.tla` | `TerminalReceiptExactlyOne` | exit 12, Error, one validated ITF trace |
| `DropGuardReleaseOnIncompleteStreamBroken.tla` | `RetainedIffAborted` | exit 12, Error, one validated ITF trace |
| `DropGuardNoRetainOnPostInvocationDenyBroken.tla` | `RetainedIffAborted` | exit 12, Error, one validated ITF trace |
| `DropGuardReleaseOnPostDispatchAbortBroken.tla` | `RetainedIffAborted` | exit 12, Error, one validated ITF trace |

### Integrated Matrix and Trace Gates

The configured positive matrix passed locally with no timeouts. The elapsed
times below include process startup and teardown.

| Model | Bound | Result | Wall clock |
| --- | --- | --- | --- |
| `MonotoneLogApalache` | length 6 | `NoError`, exit 0 | 8 seconds |
| `RevocationCutCompleteness` | length 6 | `NoError`, exit 0 | 136 seconds |
| `ReceiptBeforeAllow` | length 6 | `NoError`, exit 0 | 164 seconds |
| `KernelTransitionCancelSafe` | length 6 | `NoError`, exit 0 | 53 seconds |
| `PostAdmissionDropGuard` | length 8 | `NoError`, exit 0 | 3058 seconds |
| `RevocationPropagation` | length 6 | `NoError`, exit 0 | 7065 seconds |
| `DistributedRevocation` domain shape | length 0 | `NoError`, exit 0 | 6 seconds |
| `DistributedRevocation` behavior | length 6 | `NoError`, exit 0 | 215 seconds |
| `DelegationDepthBound` | length 6 | `NoError`, exit 0 | 124 seconds |

The receipt-trace gate passed in 477 seconds. It covered the native runtime
corpus, the checked fixture, four real runtime negative projections, registry
validation, and artifact bindings. The distributed revocation refinement gate
passed in 184 seconds: four producer tests, stale and future fail-closed kernel
tests, four exact emitted ITF projections, and four Apalache length-12 checks.

### Temporal Status

The complete distributed temporal script passed three consecutive local runs
with wall times of 1363, 1400, and 1169 seconds. Each run checked the same
projection-refinement property at length 5, fairness witness at length 3, and
distributed liveness property at length 24. The respective Apalache totals
were:

| Local run | Refinement | Witness | Liveness | Result |
| --- | --- | --- | --- | --- |
| 1 | 890.138 seconds | 2.470 seconds | 466.856 seconds | all `NoError`, exit 0 |
| 2 | 914.353 seconds | 2.171 seconds | 479.240 seconds | all `NoError`, exit 0 |
| 3 | 751.233 seconds | 2.128 seconds | 411.792 seconds | all `NoError`, exit 0 |

This is a local zero-failure observation only. It is not the required hosted
qualifying streak.

The separate `RevocationEventuallySeen` command did not pass locally. The
unchanged length-24 check reached the fixed 3600-second ceiling and exited 124
after 3602 seconds of wrapper time. It reported no counterexample or tool
error, but reached only length 2. Its last completed semantic progress was the
fifth `SafetyInv` obligation group at length 2, where invariants 0, 1, 2, 6,
and 7 had held. A timeout is not acceptance evidence. The workflow therefore
keeps this exact check fail-closed and preserves its bounds and constants.

### Tooling and Hosted Status

- Apalache: `0.50.1`, build `cd35919`.
- Java: Eclipse Temurin OpenJDK `21.0.11+10-LTS`.
- Host: Ubuntu Linux on `aarch64`, kernel `6.17.0-1011-oracle`.
- Solver: default Apalache Z3 backend.

No hosted run reference is available at the time of this local record. The
landing pull request must pass both the positive `apalache-subset` job and the
separate `apalache-negative` job. The two hosted acceptance items remain open
until those jobs pass.
