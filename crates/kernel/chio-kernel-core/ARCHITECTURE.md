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

The crate preserves fail-closed behavior, canonical JSON byte stability,
signed capability and receipt compatibility, guard ordering, subject binding,
delegation chain binding, sibling budget enforcement, and the portable
`no_std + alloc` build. Public API compatibility matters because
`chio-kernel`, browser, mobile, C++ FFI, and AG-UI proxy surfaces import these
types directly.

No module in this crate reaches into `std`, wall-clock globals, filesystem,
network, async runtimes, stores, or policy engines. Hosted-only code is
feature gated.

## Verification Ordering

The hot path has one shared post-verification boundary for subject binding,
scope matching, guard ordering, and deferred delegated-budget admission.

`verify_capability_full` owns the production verification semantics for
browser, mobile, C++ FFI, AG-UI proxy, and hosted kernel callers. It runs in
explicit phases so that untrusted, forged, or expired attenuated tokens fail at
the earliest applicable admission check rather than reaching the trust-root
resolver or sibling-budget mutation:

- base verification: issuer trust, signature, crypto floor, and time window
- chain-binding verification: negotiated feature gate and issuer trust-root
  binding, only after base verification succeeds
- sibling-budget admission: last, only after the signed token and its binding
  are acceptable
