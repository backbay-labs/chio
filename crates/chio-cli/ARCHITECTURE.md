# chio-cli Architecture

`chio-cli` owns the operator-facing `chio` binary. The crate is a thin product
shell over the core protocol, kernel, control plane, remote MCP, storage, guard,
passport, federation, replay, arena, and market crates. It should validate CLI
input, select local or remote backends, format operator output, and delegate
protocol behavior to the owning library crates.

## Boundaries

- `src/main.rs` wires the binary surface and keeps command modules reachable
  through the single `include!` entrypoint used by `src/bin/chio.rs`.
- `src/cli/types.rs` owns clap-visible command shapes, environment fallbacks,
  and help text.
- `src/cli/dispatch.rs` and `src/cli/dispatch/*` route parsed commands to
  command implementations without owning protocol semantics.
- `src/cli/runtime.rs`, `src/cli/session.rs`, `src/cli/mcp.rs`, and
  `src/cli/replay.rs` adapt operator input into calls against kernel, control
  plane, MCP, and replay library APIs.
- `src/doctor/*` owns local diagnostics. Probes report actionable operator
  health without mutating state unless `--fix` explicitly requests a safe
  repair.

## Invariants

- Secrets accepted by the CLI must prefer documented environment variables over
  argv forms and must not leak through help output.
- User-supplied identifiers and token mappings are validated before they cross
  into service configuration or durable stores.
- JSON output remains machine-readable and newline-terminated. Human output can
  be descriptive, but must not be the only path for automation.
- Shared protocol behavior belongs in the owning library crate. This crate can
  reject malformed CLI input, assemble requests, and render results.
- Tests should exercise command parsing, failure-closed validation, and
  operator-visible output contracts at the narrowest level that proves the
  product behavior.

## Trust Serve Tenant Token Input Slice

### Current Boundary

`TrustCommands::Serve` accepts repeated `--tenant-read-token TENANT=TOKEN`
arguments and passes those strings through `cmd_trust_serve` into
`TrustServiceConfig`. The parsed tenant id becomes the read-boundary tenant
principal, and the parsed token becomes bearer material for tenant-scoped
receipt reads.

### Pain Point

The CLI parser rejects blank and padded tenant-token mappings, but it currently
accepts internal control characters in either side of the mapping. The
control-plane service-config validator has the same gap. That lets a shell
quoted `tenant=token` value create a tenant principal or bearer token that is
not visible as a normal single-line operator identifier, then pushes that value
into service state and request-auth comparison.

### Security And API Constraints

- Preserve the public `--tenant-read-token TENANT=TOKEN` CLI shape.
- Preserve valid tenant ids and token values byte-for-byte.
- Do not trim or normalize ambiguous values. Reject them before service state is
  built.
- Keep the same `CliError` taxonomy and existing service config fields.

### Affected Dependents

The owning product change is in `chio-cli` input parsing. A narrow transitive
`chio-control-plane` validator update is required because `TrustServiceConfig`
is public and direct callers should receive the same fail-closed invariant as
the CLI path.

### Completed Material Improvement

Reject control characters in CLI tenant-read-token mappings and in
`TrustServiceConfig::validate`. Add focused regressions for both the product
parser and the service-config boundary.
