# Chiodos 7.1: Verifier-Owned Runtime Policy And Proof Parity

Baseline: `51cb21735c7d237ccc20f005bbdb7f855adff3c9`

Branch: `codex/chiodos-7-1-verifier-owned-runtime-policy`

This lane is stacked on the local Chiodos 7.0 runtime-spine branch because 7.0 is present in the workspace but not merged to `main`.

## Goal

Turn observe-only pheromone evidence into verifier-owned runtime policy while hardening the runtime trust boundary. Pheromones and reputation remain evidence inputs. Signed Chiodos runtime policy makes the admission decision.

## Non-Goals

- dynamic trust or peer discovery
- authority issuance, governance issuance, or pheromone-driven lease mutation
- settlement execution
- live downstream notification dispatch
- hidden predicates, VC Data Integrity BBS, zkVM, FROST, or new transports
- planning or ticket names outside `.planning`

## Final Gates

- `cargo test -p chio-chiodos-runtime runtime_policy`
- `cargo test -p chio-kernel chiodos_runtime`
- `cargo test -p chio-cli --bin chio chiodos_runtime`
- `cargo test -p chio-spec-validate`
- `bash scripts/check-chiodos-runtime-policy.sh`
- `bash scripts/check-chiodos-runtime-policy.sh --schema-only`
- `bash scripts/check-chiodos-runtime-policy.sh --negative-only`
- existing runtime spine and proof-package gates
- `cargo fmt --all -- --check`
