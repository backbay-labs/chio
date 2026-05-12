# Chiodos 6.14 Relay Delivery Evidence

Baseline: `main@0969c0cf60e4c676840efba5626d730566ff8f51`

Branch: `codex/chiodos-6-14-alert-delivery-evidence`

## Goal

Close the operator handoff gap after relay alert readiness. Chio must prove that downstream systems consumed handoff artifacts and produced bounded delivery, acknowledgement, rejection, or drift evidence from local files.

Chio still does not send live notifications, store downstream credentials, or call Alertmanager, PagerDuty, OpsGenie, Slack, email, webhook, or SIEM APIs.

## Product Surface

- Relay alert delivery profile, delivery report, acknowledgement report, handoff drift report, and negative corpus schemas.
- Local-file evaluators for delivery import, acknowledgement, and drift.
- CLI commands under `chio chiodos pheromone relay alert delivery`.
- Dashboard cards showing handoff and delivery status while preserving firing alert visibility when delivery evidence is absent.
- Gate script with schema-only and negative-only modes.

## Boundaries

- Trajectory and ticket names stay only under `.planning`.
- Production code, fixtures, schemas, CLI text, dashboard text, scripts, and docs use product names only.
- Downstream delivery artifacts are verifier inputs from local files, not live dispatch targets.
- Labels and reports use bounded route, severity, status, and recommendation codes only.

## Final Gates

- `cargo test -p chio-pheromone-relay alert_delivery`
- `cargo test -p chio-cli --bin chio chiodos_pheromone_relay_alert_delivery`
- `cargo test -p chio-metrics-spec`
- `cargo test -p chio-spec-validate`
- dashboard tests and build
- `bash scripts/check-chiodos-pheromone-relay-alert-delivery.sh`
- `bash scripts/check-chiodos-pheromone-relay-alert-delivery.sh --schema-only`
- `bash scripts/check-chiodos-pheromone-relay-alert-delivery.sh --negative-only`
- existing alert handoff, alert routing, observability, directory, relay ops, relay, runtime, authority, proof-package, bounded, diagnostic, and threat-mutant gates as closeout allows
- `cargo fmt --all -- --check`
- targeted clippy for touched crates with `-D warnings`
