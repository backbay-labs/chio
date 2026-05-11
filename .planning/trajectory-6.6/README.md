# Chiodos 6.6 Pheromone Transit Evidence Floor

Baseline SHA: `82d090edd254b1f11247e5a146f31f832dcafc79`

Branch: `codex/chiodos-6-6-pheromone-transit`

## Scope

Chiodos 6.6 adds the first production pheromone substrate and local transit
evidence surface. The lane proves that a signed pheromone deposit can bind
workflow context, move through a bounded hub relay chain, and verify locally
against treaty, ladder, workflow, passport, replay, diversity, and
observation-cost rules.

Planning names and ticket metadata stay in `.planning/trajectory-6.6` only.
Production crates, schemas, fixtures, scripts, CLI text, and protocol docs use
product names.

## In Scope

- `chio-pheromone` substrate crate.
- Agent-passport signed pheromone deposits.
- Signed deposit `workflow_context`.
- Unsigned gossip-envelope `transit_chain`.
- Treaty-scoped direct and hub-relay verification.
- In-memory reference substrate and deterministic fixtures.
- Federation local FIFO gossip queues for pheromone artifacts.
- Pheromone schemas and schema registry entries.
- Three-vendor fixture evidence linked to existing workflow receipts.

## Out Of Scope

- Live network orchestration or daemon transport.
- Pheromone-driven lease or governance decisions.
- Persistent storage adapters.
- Reputation crate dependency or production reputation admission.
- Hidden range predicates.
- VC Data Integrity BBS interop.
- zkVM proofs.
- FROST quorum classes.
- Settlement execution.

## Final Gate Checklist

- `cargo test -p chio-pheromone`
- `cargo test -p chio-federation pheromone`
- `cargo test -p chio-chiodos`
- `cargo test -p chio-chiodos-authority`
- `cargo test -p chio-cli chiodos`
- `cargo test -p chiodos-three-vendor-example`
- `cargo test -p chio-spec-validate`
- `bash scripts/check-chiodos-pheromone-transit.sh`
- `bash scripts/check-chiodos-pheromone-transit.sh --schema-only`
- `bash scripts/check-chiodos-pheromone-transit.sh --negative-only`
- `bash scripts/check-chiodos-authority-issuance.sh`
- `bash scripts/check-chiodos-proof-package.sh`
- `bash scripts/check-chiodos-proof-package.sh --schema-only`
- `bash scripts/check-chiodos-proof-package.sh --negative-only`
- `bash scripts/check-bounded-ship-bar.sh`
- `bash scripts/check-bounded-ship-bar.sh --diagnostic`
- `bash scripts/check-threat-coverage-mutants.sh`
- `cargo fmt --all -- --check`
- `cargo clippy -p chio-pheromone -p chio-federation -p chio-chiodos -p chio-chiodos-authority -p chio-cli -p chiodos-three-vendor-example --tests -- -D warnings`
