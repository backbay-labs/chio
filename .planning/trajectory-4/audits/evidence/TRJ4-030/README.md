# TRJ4-030 Evidence - Apple App Attest Verifier

## PR1 status

Implemented fail-closed verifier structure in `crates/chio-custody-hw/src/attestation/app_attest.rs`.

Covered in PR1:

- Parses production WebAuthn-style CBOR object with `fmt`, `authData`, and `attStmt`.
- Rejects non-`apple-appattest` format.
- Validates x5c certificate signatures to the pinned Apple App Attestation root when x5c is present.
- Requires the Apple nonce extension to contain `SHA256(authData || SHA256(challenge))`.
- Enforces app id hash binding against the RP ID hash in `authData`.
- Decodes key id as hex or base64url-no-pad and requires it to match the credential id in `authData`.
- Enforces counter monotonicity through `previous_counter`.
- Keeps synthetic compact CBOR fixtures behind `allow_development_fixture = true`.
- Replaces the mobile `attest_app_attest` unavailable call site with a bound challenge envelope and adds `verify_app_attest_evidence`.

## Deterministic tests

- `app_attest_verifier_accepts_synthetic_cbor_fixture`
- `app_attest_verifier_rejects_fixture_shape_unless_enabled`
- `app_attest_verifier_rejects_counter_rollback`
- `app_attest_webauthn_shape_rejects_missing_x5c_fail_closed`
- `verify_app_attest_evidence_rejects_malformed_cbor_fail_closed`

## Validation

- `cargo test -p chio-custody-hw --test attestation_app_attest -- --nocapture` passed: 7 tests.
- `cargo test -p chio-kernel-mobile --test ffi_roundtrip -- --nocapture` passed: 21 tests.
- `cargo clippy -p chio-custody-hw --all-targets -- -D warnings` passed.

## Remaining gap

No real-device App Attest x5c fixtures are available in-repo. The verifier is fail-closed on missing x5c and missing nonce extension, but acceptance against Apple-issued leaf/intermediate certificates still needs internal iOS test-fleet fixture capture.
