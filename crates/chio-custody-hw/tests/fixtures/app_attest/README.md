# App Attest Fixtures

P2 uses synthetic CBOR fixtures in `tests/attestation_app_attest.rs` to
exercise the fail-closed parser and pinned Apple root path without
committing private TestFlight device material. Real App Attest CBOR
blobs from the design-partner binary are recorded at P5 closeout.
