# chio-kernel-mobile

Mobile FFI for the portable Chio kernel core. `chio-kernel-mobile` wraps
`chio-kernel-core`'s evaluation, capability, and receipt APIs in JSON-in /
JSON-out Rust functions and projects them across the C ABI via UniFFI, so
Swift (iOS) and Kotlin (Android) hosts can evaluate verdicts, verify
capabilities and passports, sign receipts, and check mobile device
attestation entirely on-device.

`chio-kernel-core` owns the portable evaluation logic; `chio-kernel` is the
desktop sidecar built on the same core, and `chio-kernel-browser` is the
wasm-bindgen equivalent for browsers. This crate adds what a mobile app needs
on top: platform `Clock`/`Rng` adapters, the JSON envelope shapes, App Attest
/ Play Integrity verification via `chio-custody-hw`, and the UniFFI
scaffolding itself.

## Responsibilities

- Wrap `chio-kernel-core`'s `evaluate_with_full_floor`, `sign_receipt` /
  `sign_receipt_relaying_trusted_body`, `verify_capability_full`, and
  `passport_verify::verify_passport` behind JSON-in / JSON-out functions
  UniFFI exports to Swift and Kotlin.
- Provide `MobileClock` (`chio_kernel_core::Clock` over `SystemTime::now()`,
  clamped to `0` before `UNIX_EPOCH`) and `MobileRng` (`chio_kernel_core::Rng`
  over `getrandom`).
- Verify Apple App Attest and Android Play Integrity evidence through
  `chio-custody-hw`, and shape-check mobile receipts against that evidence.
- Decode and validate hex-encoded keys, seeds, challenges, and nonces at the
  FFI boundary, failing closed on malformed input.
- Seed an `InMemoryBudgetRegistry` from caller-supplied parent-budget
  snapshots so delegated/attenuated capabilities can be evaluated or verified
  across the FFI boundary.
- Map `chio-kernel-core` and `chio-custody-hw` errors onto the flat
  `ChioMobileError` enum the UDL `[Error]` interface exports.

## Public API

`src/chio_kernel_mobile.udl` is the source of truth for the generated
Swift/Kotlin surface; every entry point below is a `pub fn` in `src/lib.rs`
with a matching UDL declaration.

| Function | Purpose |
|----------|---------|
| `evaluate(request_json)` | Evaluate a tool-call request against a capability; a kernel-core deny (including `PendingApproval`) is returned as JSON, not thrown. |
| `sign_receipt(body_json, canonical_content_hex, signing_seed_hex)` | WYSIWYS signer: recomputes `content_hash` over the caller-supplied canonical preimage, refusing to sign on mismatch. |
| `sign_receipt_relaying_trusted_body(body_json, signing_seed_hex)` | Relay-sign a body an upstream trusted producer already minted, without recomputing `content_hash`. |
| `verify_capability(token_json, authority_pub_hex)` | Verify a capability against one trusted authority key, using the device clock. |
| `verify_capability_with_context(request_json)` | Verify a capability with explicit trust roots and parent-budget snapshots for delegated tokens. |
| `verify_passport(envelope_json, issuer_pub_hex, now_secs)` | Verify a portable-passport envelope (v1 wire format). |
| `attest_app_attest(key_id, challenge_hex)` | Build the App Attest challenge envelope platform evidence must bind to. |
| `verify_app_attest_evidence(key_id, challenge_hex, app_id, attestation_cbor_hex, previous_counter)` | Verify an Apple App Attest attestation object via `chio-custody-hw`. |
| `attest_play_integrity(nonce_hex)` | Build the Play Integrity challenge envelope platform evidence must bind to. |
| `verify_play_integrity_evidence(token, expected_nonce, expected_package_name, expected_audience, jwks_json)` | Verify a Play Integrity JWS against the pinned Google JWKS. |
| `verify_mobile_receipt(receipt_json, evidence_json)` | Shape-check a receipt against attestation evidence; returns a non-authoritative status. |

Also exported: the `VerifiedCapability` and `PortablePassportMetadata` UDL
records, the `ChioMobileError` error enum, and the `MobileClock` / `MobileRng`
adapters.

Mobile hosts call the generated Swift/Kotlin bindings, not this Rust API
directly. See `bindings/swift/ChioKernel.md` and `bindings/kotlin/ChioKernel.md`
for the per-language call signatures, and `bindings/README.md` for the
bindgen workflow and the offline evaluate/sign/queue/sync pattern.

## Testing

- `cargo test -p chio-kernel-mobile` runs `tests/ffi_roundtrip.rs` (Rust-side
  round-trip coverage of every entry point) plus the `#[cfg(test)]` unit
  tests in `clock.rs` and `rng.rs`.
- `tests/cross_ffi_parity.rs` includes `chio-cpp-kernel-ffi`'s source directly
  and compares its `evaluate` output against this crate's for shared verdict
  cases.
- `tests/oracle_round_trip.rs` signs the iOS/Android fixtures under
  `tests/fixtures/receipts/` and validates the resulting export record
  against `spec/audit-log/export-schema.v1.json` (fixture-only, no network
  call).
- `./scripts/qualify-mobile-kernel.sh` (from the repo root) runs the host FFI
  tests plus iOS/Android target builds where the toolchain is installed, and
  records lane results under `target/release-qualification/mobile-kernel/`.

## See also

- `chio-kernel-core` - the portable evaluation core this crate wraps.
- `chio-kernel` - the desktop sidecar built on the same core.
- `chio-kernel-browser` - the wasm-bindgen equivalent for browsers.
- `chio-custody-hw` - App Attest, Play Integrity, and mobile-receipt-chain verification.
- `chio-cpp-kernel-ffi` - the C ABI counterpart exercised by the cross-FFI parity tests.
