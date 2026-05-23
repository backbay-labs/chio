# Chio 6.5 Runtime Authority Issuance

Baseline SHA: `4635d22978376da4134c2ca2874c6b02702a8e91`

Branch: `codex/chio-6-5-runtime-authority-issuance`

## Scope

Chio 6.5 builds the local runtime producer for artifacts that the 6.4
offline verifier already checks. The lane emits capability leases,
lease-scope bindings, governance receipts, revocation checkpoints,
verification contexts, and verifier trust-bundle inputs.

Planning names and ticket metadata stay in `.planning/trajectory-6.5` only.
Production crates, fixtures, schemas, scripts, CLI text, and protocol docs
use product names.

## In Scope

- `chio-federation-authority` runtime issuance crate.
- `chio.federation.authority-profile.v1`.
- `chio.federation.issuance-request.v1`.
- `chio.federation.issuance-bundle.v1`.
- Local signing-key input for CLI/test use outside committed fixtures.
- `chio federation authority issue`.
- `chio federation authority checkpoint`.
- `chio federation authority trust-bundle assemble`.
- Runtime-issued three-vendor fixture artifacts.
- Workflow reference action classes `workflow.grant_issue` and
  `workflow.aggregate_publish`.
- Schema registry hygiene for historical Chio schemas.

## Out Of Scope

- Networked workflow orchestration.
- Pheromone transit runtime.
- Hidden range predicates.
- VC Data Integrity BBS interop.
- zkVM proofs.
- FROST quorum classes.
- Partition-contingency lease execution.
- Settlement execution.

## Final Gate Checklist

- `cargo test -p chio-federation-authority`
- `cargo test -p chio-attest-buyer-core`
- `cargo test -p chio-governance`
- `cargo test -p chio-workflow`
- `cargo test -p chio-cli chio`
- `cargo test -p chio-three-vendor-example`
- `cargo test -p chio-spec-validate`
- `cargo test -p chio-selective-disclosure --features bbs --test bbs_selective_disclosure`
- `cargo test -p chio-conformance --features chio-bbs --test chio_selective_disclosure`
- `bash scripts/check-chio-authority-issuance.sh`
- `bash scripts/check-chio-proof-package.sh`
- `bash scripts/check-chio-proof-package.sh --schema-only`
- `bash scripts/check-chio-proof-package.sh --negative-only`
- `bash scripts/check-bounded-ship-bar.sh`
- `bash scripts/check-bounded-ship-bar.sh --diagnostic`
- `bash scripts/check-threat-coverage-mutants.sh`
- `cargo fmt --all -- --check`
- `cargo clippy -p chio-federation-authority -p chio-attest-buyer-core -p chio-cli -p chio-governance -p chio-workflow -p chio-spec-validate -p chio-three-vendor-example --tests -- -D warnings`

