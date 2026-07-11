# FV-C1: Receipt trace validation against the TLA+ specs

- Status: Implemented (2026-07-11)
- Theme: C - Turn verification into product surface
- Depends on: `formal/tla/RevocationPropagation.tla` and Apalache 0.50.1
- Product surface: `chio trust trace-verify`

## Summary

The receipt trace lane observes real kernel execution at three boundaries:
successful revocation commit, completed tool-call revocation admission, and
receipt append. A synchronous `RuntimeTraceObserver` receives those events.
`RuntimeTraceRecorder` joins admission and receipt callbacks by the signed
request ID, accounts for every callback exactly once, and refuses to sign an
incomplete or ambiguous stream.

The validator accepts canonical NDJSON signed by a caller-pinned observer,
reverifies every embedded receipt and action hash, and emits a full-state ITF
projection containing all six `RevocationPropagation` variables. That ITF is
the sole state source for direct Apalache invariant evaluation and for the
generated bounded-reachability input. The nightly lane retains the log, ITF,
Apalache witness, validation report, artifact binding record, and calibrated
negative reports.

## Trust Boundary

`ASSUME-TRACE-OBSERVER` states that an installed synchronous observer receives
every successful revocation commit, completed revocation admission, and
receipt append exactly once and in callback order before finalization. It also
requires mutation-free recording and callback fields that are not rewritten
before recording. The kernel supplies its depth limit in the callbacks. The
recorder detects inconsistent depth limits, missing admission-to-receipt joins,
duplicate admissions, duplicate effective revocations, unaccounted callbacks,
and callbacks after finalization. Events lost before the observer receives them remain an audited
assumption. The assumption does not assert that an observed kernel decision is
safe.

Observation signatures depend on `ASSUME-ED25519`; trace IDs and artifact
bindings depend on `ASSUME-SHA256`; canonical signed bytes depend on
`ASSUME-CANONICAL-JSON`.

## Runtime Capture

The native conformance capture constructs a genuinely attenuated delegated
capability, registers a real tool server, and executes this sequence through
`ChioKernel`:

1. A delegated tool call is admitted, dispatched, and appended with an allow
   receipt.
2. The capability is revoked through the configured revocation store.
3. A second tool call is rejected and appended with a deny receipt.

The deterministic nightly observer key is checked against a separate in-tree
pin. The trace ID hashes caller context, canonical captured events, the signed
delegation-depth limit, and the calibration mode. Ordinary conformance fixture
receipts are not repackaged as runtime evidence.

The acceptance test enumerates exactly 50 checked replay manifests, verifies
their names and contiguous seed indices, binds each manifest digest into a
unique capture context, and independently executes the real three-step kernel
path for every manifest.

## ITF Projection

The projection contains `state`, `depth`, `rev_epoch`, `receipt_log`,
`pending`, and `clock` at every state. Real admitted delegation depth produces
explicit `Attenuate` states. Propagation produces an explicit hidden state when
an observed epoch requires it. Visible metadata carries model sequence,
runtime callback sequence, admission sequence, authority, capability, verdict,
receipt time, and epoch.

`TraceEvaluateRevocationPropagation.tla` evaluates the four production-model
invariants through a deterministic pinned Apalache `check` replay, not
`tracee`. `TraceEvaluationInput.tla` is generated only by parsing the ITF. The
model alternates an exact state-load transition with an expression-evaluation
transition, then falsifies a terminal export invariant to obtain one complete
Apalache witness:

- `NoAllowAfterRevoke`
- `MonotoneLog`
- `AttenuationPreserving`
- `RevocationFreshness`

The trace must also contain an allow receipt, an ordered receipt pair, an
attenuated admission, and a nonzero revocation epoch. Apalache must return one
exact expression witness with every expression Boolean at every evaluated ITF
state.
Failure diagnostics are derived from that witness and identify the failed
invariant, evaluated state, ITF state index, associated visible step, and input
predecessor.

`TraceCheckRevocationPropagation.tla` then checks each visible prefix against
the real transition relation. `TraceInput.tla` is generated only by parsing
visible metadata from the emitted ITF. No parallel Rust event projection is
used as a second state source.

## Falsifiability

`formal/tla/trace/negative-registry.toml` is exact and fail-closed. Every new
formal trace invariant has a negative produced from real kernel callbacks:

- A revocation store reports a committed revoke but hides it from admission,
  falsifying `NoAllowAfterRevoke`.
- The observer calibration maps a second real receipt append to a duplicate
  logical time, falsifying `MonotoneLog`.
- The observer calibration maps a real admitted delegation above the signed
  kernel depth limit, falsifying `AttenuationPreserving`.
- The observer calibration maps a real committed revocation to a future epoch,
  falsifying `RevocationFreshness`.
- A callback wrapper drops a real admission callback, and recorder
  finalization fails before any trace can be signed.

The lane requires the actual Apalache expression for each registered invariant
to be `false`. Hand-written fixture traces remain decoder regressions and do
not satisfy runtime negative coverage.

## Artifact Integrity

The validator hashes the production model, trace-check model,
trace-evaluation model, canonical input log, emitted ITF, Apalache witness,
resolved checker executable, and resolved timeout wrapper. Both executables are
hashed before and after every invocation. `check-receipt-trace-bindings.py` opens artifacts without
following symlinks, checks file identity before and after reading, confirms
that all report hashes match, rereads every input before output, and writes an
atomic binding record. Strict proof reports require and hash every positive
and negative trace artifact. Metadata-only proof reports record trace
validation as `not_run` and contain no generated trace artifact hashes.

## Acceptance

- The runtime recorder is installed on the real revoke, admission, and receipt
  append paths and fails closed on incomplete streams.
- The full-state ITF is the sole state input to invariant evaluation and
  reachability.
- All four invariant witness classes are nonzero.
- All four formal invariant mutations from real kernel runs are rejected with
  the expected Apalache expression set to `false`.
- Exactly 50 replay manifests independently drive real runtime capture.
- The known-good checked fixture passes; the allow-after-revoke fixture fails.
- Strict qualification binds all models, logs, ITFs, witnesses, keys, reports,
  the checker executable, and the negative registry.
- `chio trust trace-verify` runs the same offline validation path and fails
  closed when Apalache or any trust input is unavailable.

## Claim Boundary

The approved claim covers callback-complete signed traces projected to
`Revoke`, `Attenuate`, propagation, and `Evaluate` behavior in
`RevocationPropagation`. It is bounded implementation evidence, not a proof of
the entire kernel, distributed delivery, SQLite cross-row crash recovery, or
observer delivery below `ASSUME-TRACE-OBSERVER`.
