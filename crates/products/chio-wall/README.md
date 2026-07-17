# chio-wall

`chio-wall` is the Chio-Wall companion-product CLI, a public entry point
binary (`public_entrypoint = true`) built on Chio. It produces and checks the
bounded Chio-Wall control-path evidence package for one fixed
research-to-execution tool-access denial scenario, and runs a production SIEM
export serve loop over a Chio receipt database. The typed package contracts it
builds and validates live in `chio-wall-core`; this crate owns command
orchestration, guard evaluation, receipt signing, file output, and serve-mode
wiring.

## Responsibilities

- Build the fixed Chio-Wall control-path scenario (one workflow, one policy,
  one denied cross-domain tool call) and write it as a validated
  `chio-wall-core` package: control profile, policy snapshot, authorization
  context, guard outcome, denied-access record, buyer-review package, and
  control package.
- Evaluate the scenario's tool call through `chio_guards::McpToolGuard` and
  sign a Chio capability token and receipt recording the fail-closed denial.
- Persist the receipt to a temporary SQLite store and export a Chio evidence
  bundle (`chio_control_plane::evidence_export`) alongside the control-path
  package.
- Re-read every artifact from disk after writing it and reconcile file
  contents, cross-file references, and the package's file listing before
  reporting success.
- Run `siem-export`: an at-least-once `chio_siem::ExporterManager` serve loop
  with operator-configured SOC export sinks, alert backends, a receipt-log
  health watchdog, and a Prometheus scrape endpoint.

## Public API

`chio-wall` is a bin-only crate (no `[lib]` target). Its surface is the CLI:

| Command | Flags | Effect |
|---------|-------|--------|
| `chio-wall control-path export` | `--output <dir>` | Writes the control-path package and `chio-evidence/` bundle into an empty `<dir>`. |
| `chio-wall control-path validate` | `--output <dir>` | Exports the package into `<dir>/control-path/`, then writes `validation-report.json` and `expansion-decision.json`. |
| `chio-wall siem-export` | `--receipt-db <path> --cursor-db <path>` | Runs the SIEM export serve loop until interrupted. |
| global | `--json` | Boolean flag; emits JSON instead of the human-readable summary for `control-path` commands (`siem-export` ignores it). |

## Usage

```bash
cargo run -p chio-wall -- control-path export --output target/chio-wall-control-path-export
cargo run -p chio-wall -- control-path validate --output target/chio-wall-control-path-validation
cargo run -p chio-wall -- siem-export --receipt-db kernel-receipts.sqlite3 --cursor-db chio-wall-siem-cursor.sqlite3
```

## Environment (`siem-export`)

| Variable | Effect |
|----------|--------|
| `CHIO_SIEM_WEBHOOK_URL`, `CHIO_SIEM_WEBHOOK_BEARER_TOKEN` | Configures the generic webhook SOC export sink. |
| `CHIO_SIEM_ALERT_PAGERDUTY_ROUTING_KEY`, `CHIO_SIEM_ALERT_PAGERDUTY_ENDPOINT` | Configures the PagerDuty alert backend. |
| `CHIO_SIEM_ALERT_OPSGENIE_API_KEY`, `CHIO_SIEM_ALERT_OPSGENIE_ENDPOINT` | Configures the OpsGenie alert backend. |
| `CHIO_SIEM_METRICS_ADDR` | Overrides the Prometheus scrape bind address (default `127.0.0.1:9090`). |

At least one real SOC export sink must be configured or `siem-export` fails
closed at startup; a configured alert backend alone does not satisfy this (see
`ARCHITECTURE.md`).

## Testing

`cargo test -p chio-wall` runs the unit tests embedded in `commands.rs`,
`metrics_server.rs`, and `registry_metrics_sink.rs`, plus the `tests/cli.rs`
black-box tests that run the built binary.

## See also

- `chio-wall-core` - the typed control-path contracts this CLI builds and validates.
- `chio-siem` - the exporter manager, alert backends, and metrics-sink trait `siem-export` drives.
- `chio-control-plane` - `CliError` and the shared `evidence_export` used for the Chio evidence bundle.
- `docs/chio-wall/` - product scope, supported claims, and operating posture.
