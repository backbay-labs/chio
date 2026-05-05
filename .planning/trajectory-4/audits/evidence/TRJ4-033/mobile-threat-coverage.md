# TRJ4-033 Evidence - Mobile threat coverage

## Coverage rows

- `mobile_attestation_replay`: `crates/chio-conformance/tests/threats/mobile_attestation_replay.rs`
- `device_key_extraction`: `crates/chio-conformance/tests/threats/device_key_extraction.rs`
- `play_integrity_token_replay`: `crates/chio-conformance/tests/threats/play_integrity_token_replay.rs`

## Assertions

- App Attest rejects stale challenge binding and mismatched key IDs.
- Play Integrity rejects nonce replay, stale `exp`, wrong audience, and downgraded device-integrity verdicts.
- `spec/security/chio-threat-model.v1.json` flips all three mobile rows from `pending` to `covered` and removes the `deferred_to` marker.

## Validation

- `cargo test -p chio-custody-hw --test attestation_app_attest --test attestation_play_integrity`
- `bash scripts/build-ios-framework.sh`

## Limitation

The conformance tests use deterministic verifier fixtures. They prove fail-closed parser, binding, and verdict behavior without requiring a live iOS or Android device in CI. Field-captured App Attest and Play Integrity fixture packs remain useful for higher-assurance regression coverage.
