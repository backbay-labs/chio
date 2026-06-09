# Play Integrity Fixtures

Deterministic signed JWS fixtures are generated in
`tests/attestation_play_integrity.rs`. Real Play Integrity tokens from
a production APK are not committed here because they carry app and account
metadata; use the generation script to capture live tokens against a real device.
