# TRJ4-031 Evidence - Play Integrity Verifier

## PR1 status

Implemented fail-closed verifier structure in `crates/chio-custody-hw/src/attestation/play_integrity.rs`.

Covered in PR1:

- Parses the JWS header and requires `kid`.
- Selects the verification key from caller-supplied JWKS.
- Requires token `alg` to match the selected JWK `alg`.
- Verifies the JWS through `jsonwebtoken`.
- Requires `aud` and `exp`.
- Checks audience, nonce, package name, app recognition verdict, and device integrity verdict.
- Supports both top-level `nonce` and `requestDetails.nonce`, rejecting if both appear and differ.
- Replaces the mobile `attest_play_integrity` unavailable call site with a bound nonce envelope and adds `verify_play_integrity_evidence`.

## Deterministic tests

- `play_integrity_verifier_accepts_signed_fixture`
- `play_integrity_verifier_rejects_nonce_replay`
- `play_integrity_verifier_rejects_wrong_audience`
- `play_integrity_verifier_rejects_alg_downgrade`
- `play_integrity_verifier_rejects_expired_token_fail_closed`
- `play_integrity_verifier_rejects_unrecognized_app`
- `verify_play_integrity_evidence_rejects_bad_jws_fail_closed`

## Validation

- `cargo test -p chio-custody-hw --test attestation_play_integrity -- --nocapture` passed: 10 tests.
- `cargo test -p chio-kernel-mobile --test ffi_roundtrip -- --nocapture` passed: 21 tests.
- `cargo clippy -p chio-custody-hw --all-targets -- -D warnings` passed.

## Remaining gap

No real Google-signed Play Integrity tokens are available in-repo. PR1 uses deterministic JWKS/JWS fixtures to lock parser and fail-closed claim behavior. Real-device Android fixture capture and Google JWKS rotation evidence remain open.
