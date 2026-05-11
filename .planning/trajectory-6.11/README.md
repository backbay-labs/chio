# Chiodos 6.11: Relay Observability And Operator Dashboard

Baseline SHA: `5c29d7edc2085ea21029403592365668c6df896a`

Branch: `codex/chiodos-6-11-relay-observability`

## Scope

This lane makes the live pheromone relay operable without raw SQLite inspection. The product surface is read-only and operator-facing: canonical observability reports, metrics snapshots, bounded event reports, CLI generation commands, authenticated HTTP observability endpoints, dashboard cards, alert examples, fixtures, and executable semantic negatives.

## Non-Goals

- Dynamic trust or peer discovery.
- Relay policy mutation.
- Pheromone-driven authority, lease, governance, settlement, or workflow execution.
- Hidden predicates, VC DI BBS, zkVM, FROST, new transports, or multi-region HA.

## Product Rules

- Planning labels and ticket ids stay under `.planning`.
- Production code, CLI text, schemas, fixtures, scripts, and docs use product names.
- The canonical backend report is the source for CLI, dashboard, and alert examples.
- Dashboard code must render relay state as unknown when the relay report is unavailable.
- Metrics labels must stay bounded. Peer ids, treaty ids, hashes, nonces, cursors, and outbox ids are not metric labels.

## Exit Gates

- `bash scripts/check-chiodos-pheromone-relay-observability.sh`
- `bash scripts/check-chiodos-pheromone-relay-observability.sh --schema-only`
- `bash scripts/check-chiodos-pheromone-relay-observability.sh --negative-only`
- Existing directory lifecycle, relay ops, relay, runtime, transit, authority, proof-package, bounded, diagnostic, and threat-mutant gates as feasible on the merge train.
- `cargo fmt --all -- --check`
- Targeted clippy for touched crates.
