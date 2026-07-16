# Runtime Trace Validation

## Signed Revocation Trace

`chio-trace-validate` checks callback-complete kernel traces against
`RevocationPropagation.tla`. The kernel emits synchronous events after a
successful revocation commit, after revocation admission completes, and after
a receipt is appended. Each transition receives a kernel-assigned causal
sequence before internal locks are released. `RuntimeTraceRecorder` joins
admissions to receipts by the signed request ID, restores causal order from
those sequences, and refuses to sign incomplete or ambiguous streams.

## Trust Boundary

Input is canonical NDJSON with one `chio.trace-observation.v1` envelope per
line. Every body binds the trace identity, model sequence, runtime callback
count, callback sequence, signed delegation-depth limit, authority key, and a
typed event. Evaluate events additionally bind the admission sequence, request
ID, logical receipt time, admitted depth, revocation result, full signed
receipt, observed epoch, the capability IDs checked at admission, and the exact
capability associated with a nonzero epoch. That source either caused a denial
or witnesses the calibrated allow-after-revoke case.

The verifier requires an out-of-band observer public key. It verifies every
envelope, receipt signature, and action hash; requires one exact trace identity
and length; and accounts for the union of revoke, admission, and append
callback sequences as `1..runtimeEventCount`. A receipt's embedded key is not a
trust root.

The checked subject list starts with the presented receipt capability, contains
one unique ID per delegation level, and must contain every nonzero revocation
source. Visible observations must be in strictly increasing callback-sequence
order. Because the current TLA abstraction combines admission and receipt
append into one `Evaluate` action, the recorder fails closed if a checked
subject is revoked strictly between those two runtime callbacks.

`ASSUME-TRACE-OBSERVER` is the remaining observability boundary: every callback
must reach the installed observer exactly once before finalization with its
kernel-assigned source sequence and fields unchanged. Callback reordering is
not assumed away; the recorder validates a complete contiguous sequence and
sorts it before signing. The assumption also requires mutation-free recording.
The kernel supplies and the recorder cross-checks the signed depth limit. It
does not assert that an observed decision is safe. The nightly observer is
deterministic, test-only, and checked against
`fixtures/native-conformance-observer-key.txt`.

## Formal Input

The emitted ITF contains every production-model variable: `state`, `depth`,
`rev_epoch`, `receipt_log`, `pending`, and `clock`. Real delegation depth
produces explicit `Attenuate` states and an observed remote epoch produces an
explicit propagation state. Both direct invariant evaluation and generated
prefix reachability derive their state or visible action input only from this
ITF.

For an evaluation with a nonzero observed epoch, the model capability is the
exact revoked source, which may be a delegation ancestor. The signed envelope
retains both that source and the presented child in the embedded receipt. This
is an explicit abstraction from ancestor-cut enforcement to the single-subject
TLA state, not an assertion that the two capability IDs are equal.

`TraceEvaluateRevocationPropagation.tla` is executed with the pinned Apalache
`check` command, not `tracee`. The validator parses the ITF into a generated
`TraceEvaluationInput.tla`, deterministically alternates state-load and
expression-evaluation transitions, and uses a terminal export invariant to
obtain one complete Apalache witness. The witness contains all four invariants
and four witness classes at every ITF state. The validator uses those actual
Apalache values for diagnostics. It then uses
`TraceCheckRevocationPropagation.tla` to check bounded prefix reachability.

The negative registry requires a real kernel execution that falsifies each
invariant, plus a real dropped-admission callback that makes recorder
finalization fail. Hand-written fixtures do not satisfy this calibration
requirement.

## Local Verification

```bash
./tools/install-apalache.sh
chio trust trace-verify \
  --log receipts.ndjson \
  --trusted-key "$(cat observer-public-key.txt)" \
  --spec revocation-propagation
```

The command is offline. Logs above 500 model events are rejected rather than
windowed because cross-window state carry has not been established.

## Divergence Triage

The validator reports the failed invariant, actual evaluated state, ITF state
index, associated visible event, and input predecessor. Use
`formal/issue-templates/property-counterexample.md` to classify an exporter,
model, or kernel defect before changing the evidence boundary.

The checked good fixture exercises allow, attenuation, revoke, and a
post-revocation deny. The allow-after-revoke fixture must fail event three on
`NoAllowAfterRevoke`. The 50-manifest acceptance lane separately performs 50
real kernel captures; it does not relabel replay-manifest contents as trace
events.

## Distributed Revocation Trace

`scripts/check-distributed-revocation-refinement.sh` runs deterministic
production schedules and writes four ITF projections under
`$CARGO_TARGET_DIR/formal/distributed-revocation/traces` (or workspace
`target` when `CARGO_TARGET_DIR` is unset):

- loss, duplication, and out-of-order delivery
- forged-root rejection against a pinned signer
- partition, dropped push, heal, and contiguous catch-up
- wall-clock denial after the installed root exceeds its freshness window

`scripts/validate-distributed-revocation-trace.py` validates the exact ITF
schema and every adjacent projected action, then generates one concrete TLA+
behavior per trace. The pinned Apalache version checks every generated state
and projected transition against `TraceCheckDistributedRevocation.tla`. A
delivered or caught-up view carries the exact signed-root issuance timestamp;
the validator and TLA projection bind that timestamp to the installed fixture
epoch. The freshness schedule starts from the production root timestamp. A
missing trace, extra trace, unknown action, malformed state, projection
violation, deadlock, timeout, or tool-version mismatch fails closed.

This is deterministic scalar schedule projection, not a full-state refinement
proof and not evidence that every production execution refines the model. The
partition field represents the test scheduler; the shipped transport is not
fault-injected by this gate. The production path uses one pinned origin and one
`RevocationView`, so multi-origin isolation remains model-only. The gate also
does not claim a finite number of evaluations before observation.
