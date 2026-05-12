# Chiodos 6.15 Alert Assurance Normalization

Baseline: `main@ac4ebdc4ba3a8ce3a5fd34b68b73e43e0e9ebd03`

Branch: `codex/chiodos-6-15-alert-assurance-normalization`

## Goal

Harden the post-6.14 operator flow by turning local downstream alert exports into canonical Chio delivery evidence, closing source-bound drift gaps, producing route-owner review packets, and binding the full alert chain into one operator-safe assurance package.

Chio still does not send notifications, store downstream credentials, call downstream APIs, use dynamic URLs, mutate relay policy, or claim that humans were paged.

## Product Surface

- Downstream evidence normalization profile and report.
- Source-bound long-window delivery drift report v2.
- Route-owner profile and review packet.
- Alert assurance package.
- CLI commands under `chio chiodos pheromone relay alert`.
- Existing dashboard extended with an alert assurance card.
- Gate script with default, schema-only, and negative-only modes.

## Boundaries

- Trajectory and ticket names stay only under `.planning`.
- Production code, fixtures, schemas, CLI text, scripts, and docs use product names only.
- Normalization emits existing Chio delivery evidence. It does not become a second delivery truth source.
- Route-owner review is an operator review artifact, not governance approval.
- Alert assurance reports can record missing, stale, delayed, failed, duplicated, or drifted downstream evidence, but cannot claim live notification delivery.

## Final Gates

- `cargo test -p chio-pheromone-relay alert_assurance`
- `cargo test -p chio-cli --bin chio chiodos_pheromone_relay_alert_assurance`
- `cargo test -p chio-spec-validate`
- `cargo test -p chio-metrics-spec`
- dashboard tests and build
- `bash scripts/check-chiodos-pheromone-relay-alert-assurance.sh`
- `bash scripts/check-chiodos-pheromone-relay-alert-assurance.sh --schema-only`
- `bash scripts/check-chiodos-pheromone-relay-alert-assurance.sh --negative-only`
- existing delivery, handoff, alert routing, observability, directory lifecycle, relay ops, relay, runtime, transit, authority issuance, proof-package, bounded, diagnostic, and threat-mutant gates
- `cargo fmt --all -- --check`
- targeted clippy for touched crates with `-D warnings`
