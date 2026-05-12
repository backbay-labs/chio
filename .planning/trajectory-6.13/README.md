# Chiodos 6.13 Relay Alert Handoff Readiness

Baseline: `03d87368810639141432c0816cc5b2a8414b1bfe`

Branch: `codex/chiodos-6-13-alert-handoff-readiness`

## Objective

Close the operator handoff gap after relay alert routing by proving alert artifacts are fresh, bounded, routeable by downstream systems, visible in operator surfaces, and safe to hand off without live delivery from Chio.

This lane remains artifact-first. Chio writes handoff readiness evidence. Alertmanager, PagerDuty, OpsGenie, Slack, email, and webhook systems remain downstream consumers.

## Boundary

- No credentialed live notification dispatch from Chio.
- No inline secrets, dynamic endpoints, request bodies, or credential material in handoff artifacts.
- No dynamic trust, peer discovery, policy mutation, hidden predicates, VC DI BBS, zkVM, FROST, settlement, or new transport protocols.
- Production code, fixtures, schemas, scripts, CLI text, and docs use product names only.

## Final Gates

- `cargo test -p chio-pheromone-relay alert`
- `cargo test -p chio-cli --bin chio chiodos_pheromone_relay`
- `cargo test -p chio-metrics-spec`
- `cargo test -p chio-spec-validate`
- dashboard tests and dashboard build
- `bash scripts/check-chiodos-pheromone-relay-alert-handoff.sh`
- `bash scripts/check-chiodos-pheromone-relay-alert-handoff.sh --schema-only`
- `bash scripts/check-chiodos-pheromone-relay-alert-handoff.sh --negative-only`
- Existing alert routing, observability, directory lifecycle, relay ops, relay, runtime, transit, authority issuance, proof-package, bounded, diagnostic, and threat-mutant gates.

## Closeout Checklist

- Handoff profile, handoff report, drill report, and negative corpus schemas are registered.
- CLI can generate dry-run handoff reports from generated alert and trend reports.
- Dashboard keeps firing alerts visible when trend reports are missing.
- Dashboard primary route is selected by highest-severity firing alert.
- Alert and trend reports are regenerated inside gates.
- Review threads are resolved before merge.
