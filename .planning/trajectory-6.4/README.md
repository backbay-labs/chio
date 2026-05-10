# Chiodos 6.4 Freshness And Semantic Assurance

Baseline SHA: `384733b8bf5575c6106a3e32c4d6e5de4b2ddfad`

Branch: `codex/chiodos-6-4-freshness-assurance`

## Scope

Chiodos 6.4 hardens the offline verifier before runtime authority issuance, pheromone transit, or hidden predicates. The active product goal is a verifier surface that rejects stale trust, revoked roots, loose disclosure claims, and structurally valid packages that evade semantic checks.

Planning names and ticket metadata stay in `.planning/trajectory-6.4` only. Production crates, fixtures, schemas, scripts, CLI text, and protocol docs use product names.

## In Scope

- Strict trust bundle schema `chio.chiodos.verifier-trust-bundle.v3`.
- Signed revocation checkpoints for verifier-owned trust material.
- Offline revocation checks for peers, vendors, BBS issuers, lease authorities, and governance authorities.
- Authority lifecycle enforcement through key ids, validity windows, and active status.
- Required verifier context schema `chio.chiodos.verification-context.v1`.
- Reveal-set BBS projection contracts with verifier-owned required fields and indices.
- Verifier report schema `chio.chiodos.verifier-report.v2`.
- Schema validation and negative-corpus gates for Chiodos JSON artifacts.
- Signed semantic negative fixtures that reach the intended verifier checks.

## Out Of Scope

- Hidden range predicates.
- VC Data Integrity BBS interop.
- zkVM proofs.
- Live network workflow orchestration.
- Pheromone transit runtime.
- Runtime authority issuance.
- FROST quorum classes.
- Settlement execution.

## Final Gate Checklist

- `cargo test -p chio-chiodos`
- `cargo test -p chio-cli chiodos`
- `cargo test -p chiodos-three-vendor-example`
- `cargo test -p chio-spec-validate`
- `cargo test -p chio-selective-disclosure --features bbs --test bbs_selective_disclosure`
- `cargo test -p chio-conformance --features chiodos-bbs --test chiodos_selective_disclosure`
- `bash scripts/check-chiodos-proof-package.sh`
- `bash scripts/check-chiodos-proof-package.sh --schema-only`
- `bash scripts/check-chiodos-proof-package.sh --negative-only`
- `bash scripts/check-bounded-ship-bar.sh`
- `bash scripts/check-bounded-ship-bar.sh --diagnostic`
- `bash scripts/check-threat-coverage-mutants.sh`
- `cargo fmt --all -- --check`
- `cargo clippy -p chio-chiodos -p chio-cli -p chio-spec-validate -p chiodos-three-vendor-example --tests -- -D warnings`

