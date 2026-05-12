# Chiodos 6.17 Archive Lifecycle Closeout Review

Baseline SHA: `bc2a196a299e55aa5920771fcaf84e9ee7fc7f7c`

Branch: `codex/chiodos-6-17-archive-closeout-review`

## Scope

Chiodos 6.17 makes signed relay alert assurance export bundles operationally closeable after an incident window. The lane is report-only: it verifies each bundle through trusted exporter roots, replays the assurance package, runs retention classification, summarizes recovery drill status, and emits archive and closeout reports.

The lane does not package archives, delete evidence, move files, upload files, send notifications, store downstream credentials, mutate relay policy, add dynamic trust, add new transports, or claim that a person was paged.

## Contracts

- `chio.pheromone.relay-alert-assurance-archive-profile.v1`
- `chio.pheromone.relay-alert-assurance-archive-report.v1`
- `chio.pheromone.relay-alert-assurance-closeout-profile.v1`
- `chio.pheromone.relay-alert-assurance-closeout-report.v1`
- `chio.pheromone.relay-alert-assurance-archive-negative-fixture-corpus.v1`

## Closeout Order

1. Assurance package
2. Export
3. Verify
4. Replay
5. Retention plan
6. Recovery drill
7. Archive plan
8. Closeout review
9. Bounded events
10. Raw store last

## Final Gates

- `cargo test -p chio-pheromone-relay alert_assurance_archive --test relay`
- `cargo test -p chio-cli --bin chio chiodos_pheromone_relay_alert_assurance`
- `cargo test -p chio-spec-validate`
- `bash scripts/check-chiodos-pheromone-relay-alert-assurance-archive.sh`
- `bash scripts/check-chiodos-pheromone-relay-alert-assurance-archive.sh --schema-only`
- `bash scripts/check-chiodos-pheromone-relay-alert-assurance-archive.sh --negative-only`
- `cargo fmt --all -- --check`
- Targeted clippy for touched crates with `-D warnings`
