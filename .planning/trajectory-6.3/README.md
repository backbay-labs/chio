# Chiodos 6.3 Authority Wire Contract

Baseline SHA: `290246bfca03d58e140cf5e3d38b956c770342e6`

Branch: `codex/chiodos-6-3-authority-wire-contract`

## Scope

Chiodos 6.3 hardens the verifier surface shipped in 6.2. The active product goal is a verifier-owned destructive authority contract for offline buyer and auditor proof packages.

The lane keeps planning names and ticket metadata in `.planning/trajectory-6.3` only. Production crates, fixtures, schemas, scripts, CLI text, and protocol docs use product names.

## In Scope

- Strict trust bundle schema `chio.chiodos.verifier-trust-bundle.v2`.
- Verifier-owned lease authorities and governance authorities.
- Signed capability leases and governance receipts checked against verifier-owned authority keys.
- Package-carried `chio.chiodos-lease-scope-binding.v1` artifacts.
- Canonical recomputation of lease scope digests from scope-binding preimages.
- Workflow step binding across receipt ids, tool names, output hashes, DSSE envelopes, parent links, governance receipt refs, and consistency anchors.
- Frozen schemas and Chiodos CI gate coverage.
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
- `cargo test -p chio-federation strict_chiodos`
- `cargo test -p chio-selective-disclosure --features bbs --test bbs_selective_disclosure`
- `cargo test -p chio-conformance --features chiodos-bbs --test chiodos_selective_disclosure`
- `cargo test -p chio-chiodos`
- `cargo test -p chio-cli chiodos`
- `cargo test -p chiodos-three-vendor-example`
- `bash scripts/check-chiodos-proof-package.sh`
- `bash scripts/check-bounded-ship-bar.sh`
- `bash scripts/check-bounded-ship-bar.sh --diagnostic`
- `bash scripts/check-threat-coverage-mutants.sh`
- `cargo fmt --all -- --check`
- `cargo clippy -p chio-chiodos -p chio-cli -p chio-federation -p chio-workflow -p chio-governance -p chiodos-three-vendor-example --tests -- -D warnings`
