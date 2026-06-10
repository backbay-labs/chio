# chiodome-bilateral-example Architecture Notes

## Module Boundaries

This package owns the C1 cross-org refund demo and the C3 KB MCP integration
script. The Rust binary emits a signed `payments.refund` receipt, a bilateral
DSSE signature-slice envelope, and a single-leaf Web3 checkpoint statement.
The shell script owns the KB MCP replay and full `chio mcp serve` orchestration.

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
required.

## Library And Binary Split

The C1 runner lives in a library-owned configuration and execution boundary,
with `src/main.rs` as a thin process wrapper. Tests cover CLI seed precedence
over the environment seed and a full seeded run that writes all three artifacts
to a temp directory without mutating global environment variables.
