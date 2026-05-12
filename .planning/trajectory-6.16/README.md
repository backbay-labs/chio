# Chiodos 6.16 Alert Assurance Export

Baseline: `main@df0e1cc61ded5bba6424e26f7ca338e6d09f139e`

Branch: `codex/chiodos-6-16-alert-assurance-export`

## Goal

Make relay alert assurance packages portable and reviewable after an incident window closes through signed local export bundles, offline verification, deterministic replay, retention reports, and recovery drills.

Chio still does not send notifications, store downstream credentials, call downstream APIs, delete retained evidence, mutate relay policy, or claim that humans were paged.

## Product Surface

- Signed relay alert assurance export manifest and export report.
- Trusted exporter profile for offline verification.
- Replay report that rebuilds assurance from bundled reports.
- Retention profile and dry-run retention report.
- Recovery drill report for missing, stale, tampered, and unsafe evidence.
- CLI commands under `chio chiodos pheromone relay alert assurance`.
- Existing dashboard extended with optional export, replay, and retention lifecycle state.
- Gate script with default, schema-only, and negative-only modes.

## Boundaries

- Trajectory and ticket names stay only under `.planning`.
- Production code, fixtures, schemas, CLI text, scripts, and docs use product names only.
- Export bundles are local directories, not uploads or archives.
- Export signatures prove the local manifest, not downstream truth or human notification.
- Retention reports classify evidence but never delete files.
- Raw downstream drops remain outside default export bundles.

## Final Gates

- `cargo test -p chio-pheromone-relay alert_assurance_export`
- `cargo test -p chio-cli --bin chio chiodos_pheromone_relay_alert_assurance_export`
- `cargo test -p chio-spec-validate`
- `cargo test -p chio-metrics-spec`
- dashboard tests and build
- `bash scripts/check-chiodos-pheromone-relay-alert-assurance-export.sh`
- `bash scripts/check-chiodos-pheromone-relay-alert-assurance-export.sh --schema-only`
- `bash scripts/check-chiodos-pheromone-relay-alert-assurance-export.sh --negative-only`
- existing assurance, delivery, handoff, alert routing, observability, directory lifecycle, relay ops, relay, runtime, transit, authority issuance, proof-package, bounded, diagnostic, and threat-mutant gates
- `cargo fmt --all -- --check`
- targeted clippy for touched crates with `-D warnings`
