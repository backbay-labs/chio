# TRJ4-033 Evidence - Mobile Threat Coverage

## PR2 status

Covered. PR2 adds conformance tests under `crates/chio-conformance/tests/threats/` and flips the three mobile threat-model rows from `pending` to `covered`.

## Deterministic coverage added

- App Attest replay and rollback behavior:
  - wrong challenge rejects with `app-attest-challenge-mismatch`
  - same-or-lower counter rejects with `app-attest-counter-rollback`
  - production path rejects missing x5c fail-closed
- Device key binding:
  - App Attest key id must match credential id from `authData`
  - mobile FFI rejects malformed App Attest evidence as `AttestationRejected`
- Play Integrity token replay:
  - wrong nonce rejects
  - expired token rejects
  - wrong audience rejects
  - downgraded token algorithm rejects

## Validation

- `cargo test -p chio-custody-hw -- --nocapture` passed.
- `cargo test -p chio-kernel-mobile --test ffi_roundtrip -- --nocapture` passed.
- `cargo clippy -p chio-kernel-mobile --lib --test ffi_roundtrip -- -D warnings` passed.
- `cargo test -p chio-conformance --test threats` covers the three mobile rows in PR2.

## Limitation

The committed conformance tests use deterministic verifier fixtures, not field-captured device fixture packs. They are suitable for CI fail-closed coverage of parser, binding, and verdict behavior; field fixture packs remain a higher-assurance follow-up.
