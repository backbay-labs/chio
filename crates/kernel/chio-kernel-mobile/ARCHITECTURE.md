# chio-kernel-mobile architecture

## Overview

`chio-kernel-mobile` is a UniFFI adapter over `chio-kernel-core`: it holds no
independent evaluation logic and runs in-process inside the mobile app, with
no IPC boundary between the Rust code and the Swift/Kotlin caller. Its own
responsibility is the FFI boundary - JSON parsing, hex decoding, platform
`Clock`/`Rng` adapters, and mapping `chio-kernel-core` / `chio-custody-hw`
errors onto the flat `[Error]` enum UniFFI projects into each language.
`crate-type = ["staticlib", "cdylib", "rlib"]` builds one artifact Xcode links
statically (iOS) and one Android's NDK loads as a shared object, both driven
from `src/chio_kernel_mobile.udl`, which is the source of truth for the
generated bindings.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | FFI entry points, request/response JSON shapes, `VerifiedCapability` / `PortablePassportMetadata` records, error mapping. Includes the UniFFI-generated scaffolding via `uniffi::include_scaffolding!`. |
| `src/clock.rs` | `MobileClock`: `chio_kernel_core::Clock` over `SystemTime::now()`, clamped to `0` if the clock reads before `UNIX_EPOCH`. |
| `src/errors.rs` | `ChioMobileError`: the flat, string-payload error enum matching the UDL `[Error]` interface variant-for-variant. |
| `src/rng.rs` | `MobileRng`: `chio_kernel_core::Rng` over `getrandom`, zeroing the buffer on OS entropy failure. |
| `src/chio_kernel_mobile.udl` | UniFFI interface definition; source of truth for the generated Swift/Kotlin bindings. |
| `build.rs` | Runs `uniffi::generate_scaffolding` against the UDL at build time; warns if an Android target build is missing NDK env vars. |

## Request lifecycle

1. A mobile host serializes a Chio type (`CapabilityToken`,
   `PortableToolCallRequest`, `ChioReceiptBody`, `PortablePassportEnvelope`)
   to JSON with its own Chio SDK and passes the string across the UniFFI
   boundary.
2. The matching `pub fn` in `lib.rs` deserializes the JSON and decodes any
   hex-encoded keys, seeds, challenges, or nonces (`decode_hex_argument`,
   `decode_canonical_content_hex`), failing closed on malformed input.
3. Time-bound checks use the caller-supplied `now_secs` when it is a positive
   value, otherwise `MobileClock::now_unix_secs()`.
4. The call dispatches into `chio-kernel-core` (`evaluate_with_full_floor`,
   `verify_capability_full`, `sign_receipt` /
   `sign_receipt_relaying_trusted_body`, `passport_verify::verify_passport`)
   or `chio-custody-hw` (`verify_app_attest`, `verify_play_integrity`,
   `verify_mobile_receipt_chain`) for the actual decision.
5. Errors from either dependency are mapped onto `ChioMobileError` variants;
   the result is serialized back to JSON (or a UDL record) and returned, or
   thrown as `ChioMobileError` on parse or verification failure.

## Invariants and failure modes

- No entry point performs network or filesystem I/O; every function is safe
  to call while the device is offline.
- JSON parse failures stop at the boundary as `InvalidJson`; hex decode
  failures as `InvalidHex`.
- `sign_receipt` recomputes `content_hash` over the caller-supplied canonical
  content preimage inside the trust boundary (WYSIWYS) and refuses to sign on
  mismatch (`SigningFailed`), and rejects an all-zero signing seed
  (`WeakEntropy`). `sign_receipt_relaying_trusted_body` is the only entry
  point that skips the recompute, and only for a body an upstream trusted
  producer already minted.
- Both signing entry points require `body.kernel_key` to equal the public key
  derived from the signing seed, or fail with `KernelKeyMismatch`.
- `evaluate` and `verify_capability_with_context` seed an
  `InMemoryBudgetRegistry` from caller-supplied parent-budget snapshots before
  dispatching to kernel-core, so delegated/attenuated tokens are checked
  against sibling-sum budget enforcement without fabricating missing parent
  shares.
- `evaluate_with_full_floor` and `verify_capability_full` run at
  `CapabilityCryptoFloor::AllowClassical` and resolve attenuated/delegated
  tokens against the caller-supplied `capability_trust_roots` map; an
  attenuated or delegated token whose issuer has no entry in that map fails
  closed.
- A kernel-core `PendingApproval` verdict is returned as a fail-closed `deny`
  in the `evaluate` JSON response; this crate has no approval-flow surface.
- App Attest and Play Integrity verification always run in production mode
  (`production: true`, `allow_development_fixture: false`,
  `allow_caller_supplied_jwks: false`); development fixtures and
  caller-supplied JWKS are never reachable through this crate.
- `verify_mobile_receipt` is shape-only: it validates both JSON envelopes and
  the evidence `platform` tag, but the response is always
  `"authoritative": false, "authorized": false`. It is not proof of device
  integrity.
- The crate's own source contains no `unsafe` code: `clock.rs`, `errors.rs`,
  and `rng.rs` each carry `#![forbid(unsafe_code)]`. The crate root does not,
  because it includes UniFFI's generated `extern "C"` scaffolding.

## Dependencies

- `chio-kernel-core` - portable evaluation, capability verification, budget
  enforcement, receipt signing, and passport verification; this crate wraps
  its Rust API rather than reimplementing any of it.
- `chio-core-types` - `CapabilityToken`, `ChioReceiptBody`,
  `Ed25519Backend`/`Keypair`/`PublicKey`, and the scope/attenuation types the
  FFI shapes deserialize into. Pulled with default features, since mobile
  targets always have `std` available.
- `chio-custody-hw` - App Attest, Play Integrity, and mobile-receipt-chain
  verification. Pulled with `default-features = false` so mobile builds skip
  the `passkey` (webauthn-rs/OpenSSL) and `sqlite-store` (rusqlite) features
  the issuer-side default build needs.
- `uniffi` - build-time scaffolding generation (`build-dependencies`, `build`
  feature) plus the `include_scaffolding!` macro and `[Error]`/record support
  at the crate root (`cli` feature).
- `getrandom` - the cross-platform entropy source behind `MobileRng`
  (`SecRandomCopyBytes` on iOS, `/dev/urandom` or `getrandom(2)` on Android).
- `hex`, `sha2`, `serde`/`serde_json` - hex codec, challenge/nonce hashing,
  and JSON envelope (de)serialization at the FFI boundary.
