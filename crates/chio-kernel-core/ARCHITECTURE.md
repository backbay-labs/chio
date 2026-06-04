# chio-kernel-core Architecture

## Role

`chio-kernel-core` is the portable, pure-compute kernel subset. It is a
`no_std + alloc` crate by source and is built for hosted Rust plus
`wasm32-unknown-unknown` by the portable-kernel proof. It owns verdict
evaluation, capability verification, portable scope matching, receipt signing,
portable passport verification, normalized proof-facing projections, and
feature-gated revocation snapshot reads.

The full `chio-kernel` crate owns runtime orchestration: async dispatch,
persistent receipt, budget, revocation, and DPoP stores, transport, session
state, payment adapters, and other I/O.

## Module Boundaries

- `evaluate.rs` is the pure hot path for capability, subject, scope, guard, and
  delegated-budget admission.
- `capability_verify.rs` verifies signatures, trust roots, crypto floors,
  time windows, chain binding, and sibling budget splits without I/O.
- `scope.rs` is the fail-closed portable matcher. Constraints it cannot
  evaluate locally become explicit constraint errors.
- `budget_split.rs` is the pure sibling-sum registry contract used by hosted
  and portable callers.
- `passport_verify.rs` is the minimal signed-envelope verifier for browser,
  mobile, and FFI passport projections.
- `receipts.rs` delegates pure receipt signing to the shared signing backend.
- `revocation_view.rs` is behind `revocation-view` and gives hosted readers an
  atomic read-only revocation snapshot cache.
- `normalized.rs`, `formal_core.rs`, and Kani harnesses define the proof-facing
  subset and must stay aligned with runtime semantics.

## Constraints

The crate must preserve fail-closed behavior, canonical JSON byte stability,
signed capability and receipt compatibility, guard ordering, subject binding,
delegation chain binding, sibling budget enforcement, and the portable
`no_std + alloc` build. Public API compatibility matters because
`chio-kernel`, browser, mobile, C++ FFI, and AG-UI proxy surfaces import these
types directly.

No module in this crate should reach into `std`, wall-clock globals, filesystem,
network, async runtimes, stores, or policy engines. Hosted-only code must be
feature gated.

## Current Pain Points

The hot path now has one shared post-verification boundary for subject binding,
scope matching, guard ordering, and deferred delegated-budget admission. That
removed the prior duplicated ordering risk.

The remaining verification-ordering risk is inside the full capability
verifier. `verify_capability_full` owns the current production semantics for
browser, mobile, C++ FFI, AG-UI proxy, and hosted kernel callers, but it runs
chain-binding checks before the base verifier has proven issuer trust,
signature validity, crypto-floor compliance, or token time bounds. The result is
still fail-closed, but untrusted, forged, or expired attenuated tokens can reach
the trust-root resolver and can be reported as chain-binding failures instead of
the more fundamental admission failure.

That ordering is a poor security boundary for the portable TCB. The verifier
should prove base token admissibility first, then check chain binding, then
mutate sibling-budget state last. This preserves public API compatibility while
making the verifier phases explicit enough that downstream portable adapters do
not accidentally grow resolver work or budget mutation before signature and time
admission.

## Improvement In This Slice

Refactor full capability verification into explicit internal phases:

- base verification: issuer trust, signature, crypto floor, and time window
- chain-binding verification: negotiated feature gate and issuer trust-root
  binding, only after base verification succeeds
- sibling-budget admission: last, only after the signed token and its binding are
  acceptable

Add focused regressions proving untrusted, signature-invalid, and expired
attenuated tokens stop at the base verifier and do not call the trust-root
resolver. No public API, wire format, canonical JSON, or dependent crate changes
are planned. Dependent gates should only need to prove the existing callers still
compile and preserve the same successful verification paths.
