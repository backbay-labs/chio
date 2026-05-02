# M08 Threat-Model Handoff Package

**Trajectory:** trajectory-3
**Milestone:** M08
**Phase:** P0
**Owner:** vendor-coord
**Package status:** ready for vendor intake after @bb-connor signature

## Purpose

This handoff package gives NCC Group and Trail of Bits a bounded review
surface for the Chio independent crypto and protocol review. The package
is intentionally scoped to the cemented v3.0 protocol and its direct
implementation surfaces so vendor scoping does not drift into
trajectory-4 work.

## Included files

The vendor ZIP should include these paths from the repository root:

- `AGENTS.md`
- `docs/README.md`
- `spec/PROTOCOL.md`
- `spec/security/`
- `.planning/trajectory-3/08-independent-crypto-protocol-review.md`
- `.planning/trajectory-3/audits/M08-RFP.md`
- `.planning/trajectory-3/audits/M08-vendor-evidence.md`
- `.planning/trajectory-3/research/m08/RESEARCH.md`

The implementation source review surface is referenced by path in the
RFP and should be shared through repository access or a source archive:

- `crates/chio-attest-verify/`
- `crates/chio-revocation-oracle/`
- `crates/chio-kernel-core/`
- `crates/chio-otel-receipt-exporter/`

## Build and test command

The vendor smoke command is:

```bash
cargo build --workspace && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check
```

Hosted CI is not the M08 source of truth until M03.P2 closes the
pre-trajectory-3 bypass-window regressions. Vendors should use the
command above only as an orientation smoke check during intake.

## Review-surface counts

Counts pinned on 2026-05-02:

| Surface | Count command | Count |
|---------|---------------|-------|
| `spec/PROTOCOL.md` | `wc -l spec/PROTOCOL.md` | 2431 lines |
| `crates/chio-attest-verify/src/` | `find crates/chio-attest-verify/src -name '*.rs' -print0 \| xargs -0 wc -l` | 3097 Rust lines |
| `crates/chio-revocation-oracle/src/` | `find crates/chio-revocation-oracle/src -name '*.rs' -print0 \| xargs -0 wc -l` | 1025 Rust lines |
| `crates/chio-kernel-core/src/` | `find crates/chio-kernel-core/src -name '*.rs' -print0 \| xargs -0 wc -l` | 4746 Rust lines |
| `spec/security/chio-threat-model.v1.json` | `jq '.threats \| length' spec/security/chio-threat-model.v1.json` | 17 rows |

## Reproducible ZIP command

From the repository root:

```bash
mkdir -p .planning/trajectory-3/audits/M08-handoff-package/dist
git archive \
  --format=zip \
  --output=.planning/trajectory-3/audits/M08-handoff-package/dist/chio-m08-handoff.zip \
  HEAD \
  AGENTS.md \
  docs/README.md \
  spec/PROTOCOL.md \
  spec/security \
  .planning/trajectory-3/08-independent-crypto-protocol-review.md \
  .planning/trajectory-3/audits/M08-RFP.md \
  .planning/trajectory-3/audits/M08-vendor-evidence.md \
  .planning/trajectory-3/research/m08/RESEARCH.md
sha256sum .planning/trajectory-3/audits/M08-handoff-package/dist/chio-m08-handoff.zip
```

Do not commit the ZIP unless a vendor requests a checked-in attachment.
The README is the tracked package manifest; the ZIP is an outbound
artifact generated at send time.

## Addenda expected later

The package will receive append-only addenda after these milestones
close:

- M04 mutation gate and verdict-matrix evidence.
- M05 threat-coverage reconciliation and dispatch-allow evidence.
- M06 Apalache focused invariants, cargo-vet, SBOM, and CVE-monitoring
  evidence.

## Security review requested (M08 trust-boundary)

The package is intentionally fail-closed: if a reviewer cannot verify a
capability, quote, revocation, guard, manifest, or receipt decision from
the provided materials, the expected finding class is "unverifiable" or
"deny by default", not "allow by assumption".
