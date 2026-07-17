# chio-kernel-core

The pure-compute subset of Chio capability evaluation: verdict evaluation,
capability verification, portable scope matching, delegation-budget
enforcement, and receipt signing, built as a `no_std + alloc` library. The
same code compiles for the hosted kernel, the browser
(`wasm32-unknown-unknown`), Cloudflare Workers (`wasm32-wasip1`), and mobile
(UniFFI) targets because it never performs I/O and never calls into `std`.

`chio-kernel` wraps this crate with the async dispatch, persistent stores
(receipt, budget, revocation, DPoP), transport, and session state that turn a
pure verdict into a governed, audited tool call. Reach for `chio-kernel-core`
directly when you need enforcement logic on a constrained or non-native
target; the portable-kernel contract is documented in
`docs/protocols/PORTABLE-KERNEL-ARCHITECTURE.md`.

## Responsibilities

- Evaluate a `(capability, request, guards)` tuple to an Allow/Deny verdict:
  capability verification, subject binding, scope match, then the sync guard
  pipeline, fail-closed at every step (`evaluate`).
- Verify a capability token's signature, issuer trust, crypto floor, time
  window, and delegation chain-binding without I/O (`capability_verify`).
- Match a tool-call request against a `ChioScope`'s grants; constraints the
  portable matcher cannot safely evaluate return an explicit error instead of
  widening scope (`scope`).
- Enforce sibling-sum delegation budgets so children of a delegated
  capability cannot jointly oversubscribe the parent's share (`budget_split`).
- Sign receipts with WYSIWYS content-hash recomputation inside the trust
  boundary (`receipts`).
- Verify portable passport envelopes offline for browser/mobile/edge
  adapters (`passport_verify`).
- Project verified capabilities and verdicts into the proof-facing
  normalized AST used by the bounded verified core (`normalized`).
- Cache the latest signed revocation epoch root for lock-free dispatch reads
  (`revocation_view`, feature-gated).

## Public API

| Module | Key items |
|--------|-----------|
| `evaluate` | `evaluate`, `evaluate_with_crypto_floor`, `evaluate_with_crypto_floor_and_budgets`, `evaluate_with_full_floor`, `EvaluateInput`, `EvaluationVerdict`, `KernelCoreError` |
| `capability_verify` | `verify_capability`, `verify_capability_with_floor`, `verify_capability_with_floor_and_trust_root`, `verify_capability_with_floor_and_resolver`, `verify_capability_full`, `VerifiedCapability`, `CapabilityError`, `TrustRootResolver` |
| `guard` | `Guard`, `GuardContext`, `PortableToolCallRequest` |
| `scope` | `resolve_matching_grants`, `resolve_capability_grants`, `MatchedGrant`, `ScopeMatchError` |
| `budget_split` | `BudgetRegistry`, `BudgetSplit`, `InMemoryBudgetRegistry`, `NoopBudgetRegistry`, `MAX_BUDGET_SHARE_BPS`, `BudgetSplitError` |
| `receipts` | `sign_receipt`, `sign_receipt_with_handle`, `sign_receipt_relaying_trusted_body`, `ReceiptSigningError` |
| `passport_verify` | `verify_passport`, `verify_parsed_passport`, `PortablePassportEnvelope`, `VerifiedPassport`, `VerifyError`, `PORTABLE_PASSPORT_SCHEMA` |
| `normalized` | `NormalizedEvaluationVerdict`, `NormalizedVerifiedCapability`, `NormalizedScope`, `NormalizedCapability`, `NormalizationError` |
| `clock`, `rng` | `Clock`, `FixedClock`, `Rng`, `NullRng` |
| `revocation_view` (feature `revocation-view`) | `RevocationView`, `RevocationSnapshot`, `RevocationViewError`, `RevocationViewSubject` |

`Verdict` (`Allow` / `Deny` / `PendingApproval`) lives at the crate root; the
core itself only ever produces the first two.

## Feature flags

| Flag | Effect |
|------|--------|
| `std` (default) | Forwards to `chio-core-types/std`, `serde/std`, `serde_json/std` for hosted builds. |
| `revocation-view` (default) | Enables the `revocation_view` module. Implies `std` (`arc-swap` needs a hosted runtime). |
| `fuzz` | Exposes the `fuzz` module, the libFuzzer entry point for receipt-log replay. Implies `std`; pulls in `arbitrary`. Enabled only by the standalone `chio-fuzz` workspace. |
| `dudect` | Enables the `dudect_mac_eq` / `dudect_scope_subset` constant-time harnesses under `tests/dudect/`. Implies `std`; pulls in `dudect-bencher`. |

## Testing

```
cargo test -p chio-kernel-core
```

The portable-kernel proof builds this crate for the host and for
`wasm32-unknown-unknown`, both with `--no-default-features`:

```
scripts/check-portable-kernel.sh
```

Timing-leak harnesses run separately, feature-gated and in release mode:

```
cargo test -p chio-kernel-core --features dudect --release dudect_mac_eq
cargo test -p chio-kernel-core --features dudect --release dudect_scope_subset
```

Kani proofs (`src/kani_harnesses.rs`, `src/kani_public_harnesses.rs`) compile
only under `cfg(kani)` and run through the Kani toolchain, not `cargo test`.

## See also

- `chio-core-types` - defines the capability, receipt, and crypto types this
  crate verifies, matches, and signs against.
- `chio-kernel` - the hosted runtime kernel; wraps this crate's pure
  evaluation with async dispatch, persistent stores, and transport.
- `chio-kernel-browser`, `chio-kernel-mobile`, `chio-cpp-kernel-ffi`,
  `chio-ag-ui-proxy` - portable adapters that call `evaluate_with_full_floor`
  directly on their target platform.
