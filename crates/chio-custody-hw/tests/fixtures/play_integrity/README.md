# Play Integrity Fixtures

P3 uses deterministic signed JWS fixtures generated in
`tests/attestation_play_integrity.rs`. Real Play Integrity tokens from
the internal-track APK are recorded at P5 closeout, because those
tokens carry app and account metadata that should not be committed
during scaffold work.
