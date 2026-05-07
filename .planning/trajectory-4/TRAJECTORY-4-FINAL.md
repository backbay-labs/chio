> **SUPERSEDED**: this document's closeout claim is retracted by [TRAJECTORY-4-CLOSEOUT-ERRATUM.md](./TRAJECTORY-4-CLOSEOUT-ERRATUM.md). The trj4 release is reopened pending the wave-based closeout in /Users/connor/.claude/plans/typed-coalescing-hejlsberg.md.

# Trajectory 4 Final

**Status**: RETRACTED. Previously recorded as integrated on `main` via PR #579; the closeout claim is reopened by the erratum referenced in the banner above. The artifacts cited below remain on `main` for provenance, but the closure is not authoritative.
**Main SHA**: `066e6ea342de44fb08f0f578d14ad2cea995cfc4` (recorded for provenance, no longer treated as a closeout SHA).
**Release tag**: `v3.20.0-trj4` (retracted; see `releases.toml` `trj4_release_status = "reopened"`).
**Tagged at**: 2026-05-05T04:32:56Z (retracted same day).

## Reopened (formerly "Closed")

Each row below previously claimed closure on the integrated trj4 branch. Per the erratum, every row is reopened pending the wave plan; the one-line note records the gap the post-merge audit found.

- Phase A preflight and trajectory-3 replay anchors landed. **Reopened**: preflight gate is intact, but downstream wave gates supersede it.
- T0.B substrate hardening landed, including HTTP egress contract enforcement and SSRF negative coverage. **Reopened**: SSRF lane and substrate-hardening infrastructure (mutation, Kani, equivalence, multi-region, TLA+) are not fully wired; covered by Wave 2 / Wave 3 of the wave plan.
- T0.C mobile attestation landed, including App Attest and Play Integrity verifier paths, Swift binary target wiring, and xcframework evidence. **Reopened**: production-hardening of mobile attestation is still required; covered by Wave 6.
- T0.D threat coverage reached 20 covered / 0 pending / 0 uncovered. **Reopened**: gate currently passes on file-exists+no-`unimplemented!()`; 9 of the 20 covered rows have weak or meta-only coverage; covered by Wave 0 / Wave 4.
- T1.0 through T1.3 protocol primitives landed, including capability negotiation, schema-tagged capability tokens, attenuation witnesses, receipt v2 body-hash signing, receipt DAG checks, and anchor-batch artifacts. **Reopened**: types and schemas landed but kernel/verifier hot-path consumption is missing; chain-binding, sibling-sum budget, attenuation witness soundness covered by Wave 1; rollouts covered by Wave 2.
- T1.4 archaeology landed, including hosted MCP extraction, provider adapter core extraction, adapter refactors, cargo-vet gate, and exemption burn-down from 819 to 769. **Reopened**: cargo-vet gate is gameable per `(name, version, criteria)` analysis; covered by Wave 0 (E0.3) and ongoing burn-down.
- T1.5 SRE foundations landed, including `chio-metrics-spec`, Prometheus rule packs, `chio-log-redact`, and log-redaction gates. **Reopened**: full log-redact migration and observability completeness covered by Wave 14.
- T1.6 receipt explain landed with v1, v2, receipt DB, input-file, and control-plane lookup coverage. **Reopened**: behavior left intact; closure claim retracted pending wave-based recheck.
- T2.1 hybrid PQ cross-surface conformance landed, including signing-backend abstraction, hybrid schema fields, conformance tiers, and cross-surface no-bypass fixtures. **Reopened**: cross-surface executable suite covered by Wave 5.

## Integration Resolution (provenance, not closure)

- Per-lane PRs #570 through #576 were superseded by integrated PR #579 after local merge testing found cross-lane conflicts.
- Lane A plus Lane B conflicts were resolved by keeping all threat modules and all required `chio-conformance` dev dependencies.
- Lane C plus Lane F conflicts were resolved by preserving both signed capability negotiation and signed conformance-tier fields in federation handshakes.
- PR #579 was admin-squash-merged after hosted Actions remained queued with stale cancelled rollup entries and local close-bar gates passed.

## Validation (recorded for provenance; no longer treated as closure evidence)

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

## Slipped (still slipped, plus more reopened)

- Hosted GitHub Actions and release-artifact workflows were still queued at final-summary creation time:
  - `v3.18.1-trj3.1` release-binaries / reproducible-build / SBOM / sidecar / C++ SDK runs remained queued.
  - `v3.20.0-trj4` release-binaries / reproducible-build / SBOM / sidecar / C++ SDK runs were triggered and queued.
  - SLSA remains downstream of the release-binaries workflow.
- Real external partner or assessor programs remain out of scope for this trajectory, consistent with the synthesis cuts.
- Approximately 30 P0/P1 audit findings against the integrated trj4 surface, covered by Waves 0 through 16 of the wave plan.

## Follow-up

- Read `TRAJECTORY-4-CLOSEOUT-ERRATUM.md` first.
- Then read `/Users/connor/.claude/plans/typed-coalescing-hejlsberg.md` for the wave-based closeout.
- Per-wave summaries land at `.planning/trajectory-4/closeout/wave-NN-summary.md` as each wave finishes.
- The hosted release workflows referenced above are still observed as background; the artifacts produced may be linked here when they complete, but completion does NOT re-close trj4 - the wave plan does.
