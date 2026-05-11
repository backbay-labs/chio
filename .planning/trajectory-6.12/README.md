# Chiodos 6.12 Relay Alert Routing

## Baseline

- Branch: `codex/chiodos-6-12-relay-alert-routing`
- Baseline main SHA: `14b4de6256efff1676326ec8e192ee05162136bf`
- Active rule: trajectory and ticket names stay under `.planning`.

## Goal

Turn the relay observability surface into routeable, bounded, operator-safe alert artifacts:

- alert routing profiles without inline secrets or dynamic sink URLs
- alert reports derived from canonical observability reports and bounded event reports
- capped suppression that cannot hide critical relay conditions
- trend reports over committed observability and event report artifacts
- dashboard cards that render missing relay alert evidence as `unknown`
- gate coverage for schemas, negatives, CLI, dashboard, and existing relay evidence floors

## Non-Goals

- dynamic notification dispatch
- dynamic trust or peer discovery
- raw SQLite as alert truth
- pheromone-driven authority decisions
- hidden predicates, VC Data Integrity BBS, zkVM, FROST, settlement, or new transports

## Final Gate Checklist

- `cargo test -p chio-pheromone-relay alert`
- `cargo test -p chio-cli --bin chio chiodos_pheromone`
- `cargo test -p chio-metrics-spec`
- `cargo test -p chio-spec-validate`
- dashboard tests and build
- `bash scripts/check-chiodos-pheromone-relay-alert-routing.sh`
- `bash scripts/check-chiodos-pheromone-relay-alert-routing.sh --schema-only`
- `bash scripts/check-chiodos-pheromone-relay-alert-routing.sh --negative-only`
- existing relay observability, directory lifecycle, relay ops, relay, runtime, authority, proof-package, bounded, diagnostic, and threat-mutant gates
- `cargo fmt --all -- --check`
- targeted clippy for `chio-pheromone-relay`, `chio-cli`, `chio-metrics-spec`, and `chio-spec-validate`
