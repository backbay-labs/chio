# chio-kernel-core architecture

## Overview

`chio-kernel-core` is the pure-compute subset of Chio capability evaluation,
built `no_std + alloc` so the same verdict-producing code runs inside the
browser, mobile apps, C++ FFI hosts, and the hosted sidecar (`chio-kernel`)
without modification. It sits inside the trust boundary:
`formal/proof-manifest.toml` names `evaluate.rs`, `capability_verify.rs`,
`scope.rs`, `normalized.rs`, and `receipts.rs` as covered surface for the
bounded verified core. The crate performs no I/O and holds no state beyond
what a caller explicitly supplies (a `BudgetRegistry`, a `RevocationView`);
revocation-store lookups, budget persistence, DPoP nonce replay,
governed-transaction policy, payment authorization, and tool dispatch all
stay in `chio-kernel`.

## Module map

| Path | Responsibility |
|------|-----------------|
| `src/lib.rs` | Crate root (`#![no_std]`, `extern crate alloc`, `#![deny(unsafe_code)]`); declares modules, re-exports the public API, defines `Verdict`. |
| `src/evaluate.rs` | Pure hot path: capability verification, subject binding, scope match, guard pipeline, deferred sibling-budget admission. |
| `src/capability_verify.rs` | Signature, issuer trust, crypto floor, time window, and delegation chain-binding verification. |
| `src/scope.rs` | Fail-closed portable matcher for tool grants; constraints it cannot evaluate return an explicit error. |
| `src/budget_split.rs` | Sibling-sum delegation budget registry (`BudgetSplit`, `BudgetRegistry`, `InMemoryBudgetRegistry`). |
| `src/guard.rs` | `Guard` trait, `GuardContext`, `PortableToolCallRequest`. |
| `src/receipts.rs` | WYSIWYS receipt signing over a `SigningBackend`. |
| `src/passport_verify.rs` | Minimal signed-envelope verifier for portable passport projections. |
| `src/normalized.rs` | Proof-facing normalized AST and `is_subset_of` mirrors for the bounded verified core. |
| `src/revocation_view.rs` | (feature `revocation-view`) Arc-swap-backed read-only revocation epoch snapshot. |
| `src/clock.rs` | `Clock` trait + `FixedClock`; abstracts wall-clock time. |
| `src/rng.rs` | `Rng` trait + `NullRng`; abstracts entropy. |
| `src/formal_core.rs` | `pub(crate)` pure helpers shared by runtime code and formal verification lanes. |
| `src/formal_aeneas.rs` | `pub(crate)` Aeneas-extraction-safe decision core behind `formal_core`. |
| `src/kani_harnesses.rs`, `src/kani_public_harnesses.rs` | Kani proof harnesses; compiled only under `cfg(kani)`. |
| `src/fuzz.rs` | (feature `fuzz`) libFuzzer entry point for receipt-log replay. |

## Evaluation ordering

`evaluate_with_full_floor` (the path production kernels use) runs, in order:

1. Capability base verification: issuer trust, signature under the
   configured crypto floor, time window.
2. Delegation chain shape, when the token carries a delegation chain:
   per-link signatures and the final delegatee against the token subject.
   Attenuated tokens additionally bind `attenuation_proof.parent_scope_hash`
   to the trust root via a `TrustRootResolver`, gated by the negotiated
   `DELEGATION_CHAIN_BINDING` feature.
3. Subject binding: `request.agent_id` must equal the verified capability's
   subject.
4. Portable scope match: `scope::resolve_matching_grants` picks the most
   specific grant covering `(server, tool)`; an unevaluable constraint fails
   closed with `ConstraintError`.
5. Guard pipeline: every `&dyn Guard` runs in order; `Deny`,
   `PendingApproval`, or `Err` from any guard fails the whole evaluation.
6. Sibling-budget admission, last: only after steps 1-5 pass does
   `admit_delegated_budget` mutate the caller's real `BudgetRegistry`, so a
   forged or out-of-scope token never consumes a sibling's share.

`evaluate` and `evaluate_with_crypto_floor` run the same shape without chain
binding (no `TrustRootResolver`) and deny any token that carries an
`attenuation_proof`.

## Invariants and failure modes

- No module reaches into `std`, wall-clock globals, filesystem, network,
  async runtimes, stores, or policy engines; hosted-only surfaces
  (`revocation_view`, `fuzz`, the `dudect` test harnesses) are feature-gated.
- Every verification and matching path fails closed: unknown budget
  parents, unsupported scope constraints, missing chain-binding trust roots,
  and clock values outside `[issued_at, expires_at)` all deny.
- `BudgetSplit` tracks a `holders` refcount per child edge rather than a
  boolean owner. Overlapping evaluations of the same delegated capability
  each take a lease; the edge frees, returning its share to the parent, only
  when the last holder releases. `verify_child_admission` (verifier-only
  callers with no release path) commits a fresh child's share for
  sibling-sum accounting without taking a lease.
- `receipts::sign_receipt` recomputes `sha256_hex(canonical_content)` inside
  the trust boundary and refuses to sign on a mismatch with the caller's
  `content_hash`, closing the render-A / sign-B forgery.
  `sign_receipt_relaying_trusted_body` is the narrower, explicit trust seam
  for FFI/WASM adapters that cannot hold the content preimage.
- `RevocationView::install_if_newer` only installs a snapshot whose `epoch`
  strictly exceeds the current one, so a stale or replayed gossip frame
  cannot rewind a verifier's view.
- Public API compatibility is load-bearing: `chio-kernel` and the
  browser/mobile/FFI/AG-UI-proxy adapters all import these types directly.

## Dependencies

`chio-core-types` (path dependency, `default-features = false`) supplies the
capability, scope, receipt, and crypto types this crate verifies, matches,
and signs against; this crate forwards its own `std` feature to
`chio-core-types/std` rather than depending on the `chio-core` facade, which
would pull in the economic and trust domain crates. `serde` / `serde_json`
(both `alloc`-only) handle canonical JSON and the normalized AST. `arc-swap`
(optional, `revocation-view`) backs the lock-free snapshot cache. `arbitrary`
(optional, `fuzz`) and `dudect-bencher` (optional, `dudect`) are dev/CI-only
instrumentation kept out of production builds.

## Extension points

- `Guard` - synchronous guard trait; adapters plug in domain-specific checks
  that run inside the hot path.
- `Clock` / `Rng` - inject platform time and entropy instead of calling
  `std` directly.
- `TrustRootResolver` - per-issuer trust-root scope-hash lookup for
  delegation chain-binding; blanket-implemented for
  `Fn(&PublicKey) -> Option<ScopeHash>`.
- `BudgetRegistry` - sibling-sum delegation budget accounting;
  `InMemoryBudgetRegistry` and `NoopBudgetRegistry` are the in-crate
  implementations.
