# Chiodos 6.7 Local Pheromone Runtime Consumption

Baseline SHA: `edeb4ab87f9403f770b8f63ed36ebe5a94ecf6c5`

Branch: `codex/chiodos-6-7-pheromone-runtime-consumption`

## Scope

Chiodos 6.7 turns local pheromone transit evidence into a local runtime
consumption surface. The lane adds durable receiver state, batch verification,
workflow-context resolution against verified Chiodos evidence, advisory
concentration queries, metrics, CLI entry points, executable negatives, and
gates.

Planning names and ticket metadata stay in `.planning/trajectory-6.7` only.
Production crates, schemas, fixtures, scripts, CLI text, and protocol docs use
product names.

## In Scope

- `chio-pheromone-runtime` local runtime crate.
- Sender-owned and treaty-scoped federation pheromone queues.
- Strict pheromone gossip batch verification.
- Durable SQLite pheromone receiver state.
- Replay and diversity state that survives process restart.
- Workflow-context resolution against verified Chiodos proof evidence.
- Advisory concentration queries with caller-supplied peer weights.
- CLI commands for local receive and query workflows.
- Pheromone runtime metric registry entries.
- Executable positive and negative runtime fixtures.

## Out Of Scope

- Network transport or daemon relay scheduling.
- Peer discovery.
- Production catch-up replay.
- Pheromone-driven lease or governance decisions.
- Hidden predicates.
- VC Data Integrity BBS interop.
- zkVM proofs.
- FROST quorum classes.
- Settlement execution.

## Final Gate Checklist

- `cargo test -p chio-pheromone`
- `cargo test -p chio-federation pheromone`
- `cargo test -p chio-pheromone-runtime`
- `cargo test -p chio-store-sqlite pheromone`
- `cargo test -p chio-chiodos`
- `cargo test -p chio-cli chiodos`
- `cargo test -p chiodos-three-vendor-example`
- `cargo test -p chio-spec-validate`
- `cargo test -p chio-metrics-spec`
- `bash scripts/check-chiodos-pheromone-runtime.sh`
- `bash scripts/check-chiodos-pheromone-runtime.sh --schema-only`
- `bash scripts/check-chiodos-pheromone-runtime.sh --negative-only`
- `bash scripts/check-chiodos-pheromone-transit.sh`
- `bash scripts/check-chiodos-authority-issuance.sh`
- `bash scripts/check-chiodos-proof-package.sh`
- `bash scripts/check-chiodos-proof-package.sh --schema-only`
- `bash scripts/check-chiodos-proof-package.sh --negative-only`
- `bash scripts/check-bounded-ship-bar.sh`
- `bash scripts/check-bounded-ship-bar.sh --diagnostic`
- `bash scripts/check-threat-coverage-mutants.sh`
- `cargo fmt --all -- --check`
- `cargo clippy -p chio-pheromone -p chio-federation -p chio-pheromone-runtime -p chio-store-sqlite -p chio-cli -p chiodos-three-vendor-example --tests -- -D warnings`
