# chio-wall architecture

## Overview

`chio-wall` is a public entry point binary (`[package.metadata.chio]
public_entrypoint = true`) with no library target. It has two independent
command surfaces: a one-shot control-path package export/validate pipeline,
and a long-running `siem-export` serve process. Both orchestrate trusted Chio
primitives (`chio-kernel`, `chio-guards`, `chio-core` signing,
`chio-store-sqlite`) rather than reimplementing them; `chio-wall` itself holds
no cryptographic trust boundary beyond what those crates already enforce. The
control-path scenario is fixed, not parameterized: every export builds the
same workflow ID, policy, and denied tool call, so the package demonstrates
one bounded buyer motion rather than serving as a general policy-authoring
tool.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/main.rs` | clap CLI surface (`Cli`, `Commands`, `ControlPathCommands`) and command dispatch. |
| `src/commands.rs` | Scenario construction, guard evaluation, capability/receipt signing, control-path export and validate, the SIEM serve loop, SOC/alert backend wiring, and the receipt-log watchdog. |
| `src/metrics_server.rs` | Dependency-free `GET /metrics` Prometheus scrape endpoint for the `siem-export` process. |
| `src/registry_metrics_sink.rs` | `RegistryMetricsSink`: forwards `chio_siem::SiemMetricsSink` callbacks into `chio-metrics-spec` runtime families. |

## Command flows

**`control-path export`** (`export_control_path`):
1. `ensure_empty_directory` creates `--output` if absent, and rejects it if it
   exists as a symlink, a non-directory, or non-empty.
2. Build the fixed control profile, policy snapshot, and authorization
   context; evaluate the scenario's tool call through
   `chio_guards::McpToolGuard` (fail-closed default) to get the guard outcome;
   derive the denied-access record. Validate each against `chio-wall-core`.
3. Write the five JSON artifacts, then stage a temporary SQLite receipt store
   (`tempfile::tempdir`, outside `--output`), sign a capability token and a
   `Deny` receipt into it, checkpoint it, and export it as `chio-evidence/`
   via `chio_control_plane::evidence_export::cmd_evidence_export`. The staging
   database is deleted afterward.
4. Build and write the buyer-review package, the control package, and
   `control-path-summary.json`.
5. `verify_control_path_export` re-reads every file from disk, re-validates
   it, cross-checks field equality across files, and rejects any undeclared
   entry under `--output`, before the command reports success.

**`control-path validate`**: runs the export pipeline into
`<output>/control-path/`, then writes `validation-report.json` (decision,
scenario fields, the control-path summary, and doc references) and
`expansion-decision.json` (selected scenario fields plus a `deferred_scope`
list).

**`siem-export`** (`serve_siem_export`): builds a `chio_siem::ExporterManager`
against `--receipt-db`/`--cursor-db` with a `RegistryMetricsSink`; registers
configured SOC exporters and, if any alert backend is configured, one
`AlertingExporter` sharing the same sink; fails closed unless a real SOC sink
is registered; pre-registers Prometheus series at zero; spawns the
receipt-log watchdog and the metrics scrape endpoint; runs the manager loop
until `ctrl_c`, then cancels and joins every spawned task.

## Invariants and failure modes

- Guard evaluation is fail-closed by construction (`McpDefaultAction::Block`);
  `build_denied_access_record` errors if the scenario's guard outcome is ever
  `Allow`, since the scenario is defined to deny.
- `verify_control_path_export` treats on-disk state as the source of truth: it
  does not trust the in-memory objects that produced the files. It also
  closes the package root (`ensure_only_expected_package_entries`), so a
  leftover staging file or any other undeclared entry fails the export.
- `chio-wall` calls `chio-wall-core`'s `.validate()` for per-object schema
  validation rather than re-implementing shape checks; its own
  `ensure_equal`/`ensure_*` helpers check cross-file and on-disk consistency
  instead, a concern `chio-wall-core` does not have (it never touches a
  filesystem).
- `siem-export` refuses to start with zero registered SOC export sinks, and
  explicitly rejects an alerting-only configuration: `AlertingExporter` marks
  every event processed (advancing the cursor) but only dispatches
  high-severity denials, so alerting alone would silently drop unexported
  receipts.
- The receipt-log watchdog opens the receipt database read-only
  (`receipt_store_health_read_only`); a missing database is reported as
  missing, never created.
- `preregister_serve_metrics` seeds the SOC-export, DLQ-depth, and
  alert-dispatch series (under a `disabled` sentinel route when no alert
  backend is configured) at zero, so `absent_over_time`-based alert rules
  fire only on a true scrape gap.
- The metrics endpoint reads until the request line's newline, bounded to
  2048 bytes, before routing, so a fragmented `GET /metrics` read cannot be
  misrouted to a 404.
- `non_empty_env` trims environment values before use, so a mounted secret
  with a trailing newline does not reach a URL or bearer-token field verbatim.

## Dependencies

Internal: `chio-wall-core` supplies the package contracts and validators;
`chio-guards` evaluates the tool-access guard; `chio-core` supplies capability
and receipt signing plus canonical JSON hashing; `chio-kernel` supplies
`build_checkpoint` and receipt-health sampling; `chio-store-sqlite` is the
receipt store; `chio-siem` supplies `ExporterManager`, exporters, and alert
backends; `chio-metrics-spec` supplies the runtime metric families rendered by
both the SIEM alert pack and the scrape endpoint; `chio-control-plane`
supplies `CliError` and `evidence_export`. No dependency aliasing.

External: `clap` (derive) for the CLI, `tokio` for the async serve loop and
metrics server, `chrono` for date-stamped IDs, `tempfile` for the receipt
staging directory.
