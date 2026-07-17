# chio-kernel-browser architecture

## Overview

`chio-kernel-browser` is the `wasm-bindgen` boundary crate for
`chio-kernel-core`: an edge that accepts JSON from browser JavaScript and
returns JSON, while every evaluation, signing, and verification decision still
runs inside the portable `no_std + alloc` kernel core. It supplies exactly what
a pure-compute crate cannot supply itself, wall-clock time and CSPRNG entropy,
plus the wasm-bindgen / JSON marshalling layer around them. All `wasm-bindgen`
and Web platform dependencies stay behind `cfg(target_arch = "wasm32")`, so the
crate also builds and tests as an ordinary host-native `no_std` crate. `[lib]`
declares `crate-type = ["cdylib", "rlib"]`: `cdylib` for `wasm-pack`, `rlib` so
`cargo test` and `cargo doc` work natively.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate root: `no_std + alloc` setup, `#![deny(unsafe_code)]`, module wiring, and the public re-export surface. Gates `wasm` (wasm32) and `tests` (native test) modules by cfg. |
| `src/clock.rs` | `BrowserClock`: `chio_kernel_core::Clock` over `js_sys::Date::now()` (wasm32) or a `0`-returning stub (native). |
| `src/rng.rs` | `WebCryptoRng` / `WebCryptoRngError`: `chio_kernel_core::Rng` over `window.crypto.getRandomValues` (wasm32) or an always-erroring stub (native). |
| `src/wire.rs` | JSON DTOs exchanged across the wasm boundary and their conversions to/from `chio-kernel-core` / `chio-core-types`. |
| `src/pure.rs` | Target-independent evaluate / sign / verify logic shared by the wasm entry points and the native tests: budget-registry seeding, the WYSIWYS signer, the trusted-body relay signer, receipt verification, hex and authority parsing. |
| `src/wasm.rs` | `#[wasm_bindgen]` entry points and JSON/`JsValue` parsing, encoding, and error shaping. Compiled for `wasm32` only. |
| `src/tests.rs` | Native-only regression suite over the `pure.rs` paths. |

## Call lifecycle

### Evaluate and verify

1. JS calls `evaluate`, `verify_capability`, `verify_capability_with_context`,
   or `verify_receipt` with JSON (or, for `verify_receipt`, raw envelope bytes
   plus a `JsValue` issuer list).
2. `wasm.rs` parses the input into the matching `wire.rs` DTO, returning a
   `BindingError`-shaped `JsValue` on failure.
3. `wasm.rs` constructs a `BrowserClock` and calls the paired `pure.rs`
   function.
4. `pure.rs` decodes trusted-issuer hex, seeds an `InMemoryBudgetRegistry` from
   any parent-budget snapshots, and calls the portable kernel function
   (`evaluate_with_full_floor`, `verify_capability_full`) - or, for receipts,
   runs the embedded-key signature, parameter-hash, and receipt-id checks
   directly.
5. The result is mapped into a wire DTO; `EvaluationVerdictJson::from_core`
   downgrades a raw kernel `Allow` to `"pending_approval"`.
6. `wasm.rs` serializes the DTO to `JsValue` via `serde-wasm-bindgen` and
   returns it.

### Sign

1. JS calls `sign_receipt` or `sign_receipt_relaying_trusted_body` with a JSON
   body and a hex signing seed (optionally minted first by
   `mint_signing_seed_hex`, which reads `WebCryptoRng`).
2. `wasm.rs` parses the body and decodes the seed.
3. `pure.rs` refuses an all-zero seed, builds an `Ed25519Backend` from it, and
   overwrites `body.kernel_key` with the derived public key.
4. `sign_receipt_pure` requires the `canonical_content` preimage and signs
   through `chio_kernel_core::sign_receipt`, which recomputes `content_hash`
   and refuses on mismatch; `sign_receipt_relaying_trusted_body_pure` trusts
   the supplied `content_hash` and signs through
   `sign_receipt_relaying_trusted_body` instead.
5. `wasm.rs` serializes the resulting `ChioReceipt`, or a `BindingError`, to
   `JsValue`.

## Invariants and failure modes

- Browser evaluation never returns authoritative `allow`: `evaluate_pure`
  always runs with `guards: &[]`, and `EvaluationVerdictJson::from_core`
  hardcodes `authorized: false`.
- The default signer (`sign_receipt_pure`) requires the `canonical_content`
  preimage and refuses to sign without it (`canonical_content_required`); the
  recompute-free trusted-body relay is reachable only through the separately
  named `sign_receipt_relaying_trusted_body_pure` /
  `sign_receipt_relaying_trusted_body`, never as a fallback.
- Both signers refuse an all-zero 32-byte seed (`weak_entropy`) before
  constructing an `Ed25519Backend`.
- `WebCryptoRng::fill_bytes` zeroes its destination on a `getRandomValues`
  failure rather than erroring (the `Rng` trait has no error channel); callers
  detect the all-zero result and refuse to use it. `WebCryptoRng::try_new`
  fails closed when no `Window` / `Crypto` global exists.
- `BrowserClock::now_unix_secs` fails closed to `0` on a non-finite or
  non-positive `Date.now()`, which biases every time-bound check toward "not
  yet valid".
- `verify_receipt_pure`'s `ok` requires signature validity, parameter-hash
  validity, receipt-id validity, and explicit issuer trust; an empty
  `trusted_issuers` slice still reports signature and hash status but leaves
  `signer_trusted` and `ok` false.
- Attenuated, budget-shared, or delegated capability tokens fail closed when
  `capability_trust_roots` omits the issuer's `ScopeHash`.

## Dependencies

Internal: `chio-kernel-core` (`default-features = false`) supplies the
portable evaluation, signing, verification, and budget-registry logic plus the
`Clock` / `Rng` traits this crate implements; `chio-core-types`
(`default-features = false`) supplies the capability, receipt, and crypto
types the wire DTOs wrap. External: `serde` / `serde_json` (alloc-only) drive
DTO (de)serialization on every target. On `wasm32` only: `wasm-bindgen`,
`js-sys`, and `web-sys` (`Crypto`, `Window`, `Performance`) provide the JS FFI
and platform globals, and `serde-wasm-bindgen` converts DTOs to/from
`JsValue`; `wasm-bindgen-test` is a `wasm32` dev-dependency driving
`tests/*_wasm.rs`.
