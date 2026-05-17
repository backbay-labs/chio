# Chiodos 7.2: Live Runtime Proof Parity And Local Orchestration

Baseline: `51cb21735c7d237ccc20f005bbdb7f855adff3c9`

Branch: `codex/chiodos-7-2-runtime-proof-parity`

This lane is stacked on the local Chiodos 7.1 runtime-policy branch because
7.0 and 7.1 are present in the workspace but not merged to `main`.

## Goal

Turn the live runtime admission spine into verifier-grade runtime evidence. A
local loopback run must produce structured runtime evidence that binds admission
reports, kernel receipts, bilateral evidence, workflow evidence, regenerated
proof-package output, and verifier reports.

## Non-Goals

- dynamic trust or peer discovery
- settlement execution
- live downstream notification dispatch
- hidden predicates, VC Data Integrity BBS, zkVM, FROST, or new transports
- pheromone-driven lease issuance, governance issuance, trust mutation, or
  policy mutation
- planning or ticket names outside `.planning`

## Final Gates

- `cargo test -p chio-chiodos-runtime runtime_proof_parity`
- `cargo test -p chio-kernel chiodos_runtime`
- `cargo test -p chio-cli --bin chio chiodos_runtime`
- `cargo test -p chio-spec-validate`
- `bash scripts/check-chiodos-runtime-proof-parity.sh`
- `bash scripts/check-chiodos-runtime-proof-parity.sh --schema-only`
- `bash scripts/check-chiodos-runtime-proof-parity.sh --negative-only`
- existing runtime policy, runtime spine, proof-package, authority issuance, and
  pheromone runtime gates
- `cargo fmt --all -- --check`
