# Chio 6.3 Authority Wire Contract

Status: merged to `main` before Chio 6.4.

Baseline SHA: `290246bfca03d58e140cf5e3d38b956c770342e6`

Branch: `codex/chio-6-3-authority-wire-contract`

## Scope

Chio 6.3 hardens the verifier surface shipped in 6.2. The active product goal is a verifier-owned destructive authority contract for offline buyer and auditor proof packages.

The lane keeps planning names and ticket metadata in `.planning/trajectory-6.3` only. Production crates, fixtures, schemas, scripts, CLI text, and protocol docs use product names.

## In Scope

- Strict trust bundle schema `chio.federation.verifier-trust-bundle.v1`.
- Verifier-owned lease authorities and governance authorities.
- Signed capability leases and governance receipts checked against verifier-owned authority keys.
- Package-carried `chio.federation.lease-scope-binding.v1` artifacts.
- Canonical recomputation of lease scope digests from scope-binding preimages.
- Workflow step binding across receipt ids, tool names, output hashes, DSSE envelopes, parent links, governance receipt refs, and consistency anchors.
- Frozen schemas and Chio CI gate coverage.
- Regenerated three-vendor package, trust bundle, verifier report, and negative corpus.

## Out Of Scope

- Hidden range predicates.
- VC Data Integrity BBS interop.
- zkVM proofs.
- Live network workflow orchestration.
- Pheromone transit runtime.
- FROST quorum classes.
- Settlement execution.

## Final Gate Checklist

- `cargo test -p chio-governance`
- `cargo test -p chio-workflow`
- `cargo test -p chio-federation strict_chio`
- `cargo test -p chio-selective-disclosure --features bbs --test bbs_selective_disclosure`
- `cargo test -p chio-conformance --features chio-bbs --test chio_selective_disclosure`
- `cargo test -p chio-attest-buyer-core`
- `cargo test -p chio-cli chio`
- `cargo test -p chio-three-vendor-example`
- `bash scripts/check-chio-proof-package.sh`
- `bash scripts/check-bounded-ship-bar.sh`
- `bash scripts/check-bounded-ship-bar.sh --diagnostic`
- `bash scripts/check-threat-coverage-mutants.sh`
- `cargo fmt --all -- --check`
- `cargo clippy -p chio-attest-buyer-core -p chio-cli -p chio-federation -p chio-workflow -p chio-governance -p chio-three-vendor-example --tests -- -D warnings`
