# chiodome-bilateral-example Architecture Notes

## Module Boundaries

This package owns the C1 cross-org refund demo and the C3 KB MCP integration
script. The Rust binary emits a signed `payments.refund` receipt, a bilateral
DSSE signature-slice envelope, and a single-leaf Web3 checkpoint statement.
The shell script owns the KB MCP replay and full `chio mcp serve` orchestration.

## Pain Points

The Rust side currently places process environment reading, CLI seed parsing,
deterministic key derivation, receipt construction, DSSE signing and
verification, checkpoint construction, fixture writing, and tests in
`src/main.rs`. That makes the binary process the only boundary for fixture
generation even though the meaningful unit is a deterministic local runner.
Tests can validate internal primitives, but not the full seeded output flow
without reaching through process-global environment variables.

## Security And API Constraints

The demo must preserve dry local execution, deterministic seeded fixture bytes,
symlink refusal for generated JSON outputs, Org B receipt signing, two-signature
DSSE verification, RFC6962 single-leaf checkpoint binding, and attacker-key
rejection. The public binary name, `--release-fixture-seed` flag,
`CHIODOME_DEMO_OUT`, and `CHIODOME_DEMO_FIXTURE_SEED` behavior must remain
compatible.

## Affected Dependents

The README and fixture docs call `cargo run --bin chiodome-bilateral-demo`.
Release fixture regeneration depends on seeded output under
`examples/chiodome-bilateral/fixtures/`. No downstream crate API changes are
required because this package did not previously expose a library target.

## Completed Material Improvement

The C1 runner now lives in a library-owned configuration and execution
boundary, with `src/main.rs` kept as a thin process wrapper. Tests cover CLI
seed precedence over the environment seed and a full seeded run that writes all
three artifacts to a temp directory without mutating global environment
variables.
