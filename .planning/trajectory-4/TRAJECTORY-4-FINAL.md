# Trajectory 4 Final

**Status**: integrated on `main` via PR #579.
**Main SHA**: `066e6ea342de44fb08f0f578d14ad2cea995cfc4`.
**Release tag**: `v3.20.0-trj4`.
**Tagged at**: 2026-05-05T04:32:56Z.

## Closed

- Phase A preflight and trajectory-3 replay anchors landed.
- T0.B substrate hardening landed, including HTTP egress contract enforcement and SSRF negative coverage.
- T0.C mobile attestation landed, including App Attest and Play Integrity verifier paths, Swift binary target wiring, and xcframework evidence.
- T0.D threat coverage reached 20 covered / 0 pending / 0 uncovered.
- T1.0 through T1.3 protocol primitives landed, including capability negotiation, schema-tagged capability tokens, attenuation witnesses, receipt v2 body-hash signing, receipt DAG checks, and anchor-batch artifacts.
- T1.4 archaeology landed, including hosted MCP extraction, provider adapter core extraction, adapter refactors, cargo-vet gate, and exemption burn-down from 819 to 769.
- T1.5 SRE foundations landed, including `chio-metrics-spec`, Prometheus rule packs, `chio-log-redact`, and log-redaction gates.
- T1.6 receipt explain landed with v1, v2, receipt DB, input-file, and control-plane lookup coverage.
- T2.1 hybrid PQ cross-surface conformance landed, including signing-backend abstraction, hybrid schema fields, conformance tiers, and cross-surface no-bypass fixtures.

## Integration Resolution

- Per-lane PRs #570 through #576 were superseded by integrated PR #579 after local merge testing found cross-lane conflicts.
- Lane A plus Lane B conflicts were resolved by keeping all threat modules and all required `chio-conformance` dev dependencies.
- Lane C plus Lane F conflicts were resolved by preserving both signed capability negotiation and signed conformance-tier fields in federation handshakes.
- PR #579 was admin-squash-merged after hosted Actions remained queued with stale cancelled rollup entries and local close-bar gates passed.

## Validation

- `bash scripts/trj4-preflight.sh`: 33 passes / 0 failures.
- `bash scripts/check-threat-coverage.sh`: 20 covered / 0 pending / 0 uncovered.
- `cargo fmt --all -- --check`.
- `git diff --check`.
- `cargo vet --locked`: 349 fully audited / 769 exempted.
- `python3 scripts/check-cargo-vet-exemptions.py --base <trj4-start> --head supply-chain/config.toml`: base 819 / head 769.
- `cargo test -p chio-conformance --test threats -- --nocapture`.
- `cargo test -p chio-conformance --test protocol_primitives_t1 -- --nocapture`.
- `cargo test -p chio-conformance --test cross_surface -- --nocapture`.
- `cargo test -p chio-federation --test trust_establishment`.
- `cargo test -p chio-kernel-browser`.
- `cargo test -p chio-custody-hw --test attestation_app_attest --test attestation_play_integrity`.
- `cargo check -p chio-kernel-mobile --target aarch64-apple-ios --lib`.
- `cargo test -p chio-cli receipt_explain_tests -- --nocapture`.
- `cargo test -p chio-metrics-spec`.
- `cargo test -p chio-log-redact`.
- `bash scripts/check-sre-metrics-registry.sh`.
- `bash scripts/check-log-redaction.sh`.
- `swift package describe` in `sdks/swift`.
- Focused combined clippy over `chio-federation`, `chio-kernel-browser`, and `chio-conformance` conflict surfaces.

## Slipped

- Hosted GitHub Actions and release-artifact workflows were still queued at final-summary creation time:
  - `v3.18.1-trj3.1` release-binaries / reproducible-build / SBOM / sidecar / C++ SDK runs remained queued.
  - `v3.20.0-trj4` release-binaries / reproducible-build / SBOM / sidecar / C++ SDK runs were triggered and queued.
  - SLSA remains downstream of the release-binaries workflow.
- Real external partner or assessor programs remain out of scope for this trajectory, consistent with the synthesis cuts.

## Follow-up

- Watch queued release workflows and attach produced artifact URLs to this file or `releases.toml` when they complete.
- If hosted Actions remain unavailable, use the local gate evidence above as the merge and release qualification record for `v3.20.0-trj4`.
