# Chiodome Canary Evidence

Date: 2026-05-09

Baseline commit: `7f56cf5383fc1caa7a4f06b4cd59e45177f00496`

## Deterministic Fixture Run

Command:

```bash
CHIODOME_DEMO_OUT=examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome cargo run -q --bin chiodome-bilateral-demo -- --release-fixture-seed=42
```

Result: exit 0.

Artifacts written:

- `examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/receipt.json`
- `examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/envelope.json`
- `examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/checkpoint.json`

The runner reported Org A public key
`c578c6e4c6853f7b889ddc13c2190f22033ff3390666399c89aaaf14d49fa0ba`,
Org B public key
`e08a8e8decf2772e856c02ca9ae61fb6954118b1025bd5bad574ead68ef043a7`,
and checkpoint root
`18f67a939b2cc6303b33bc1dec7fbb1c5ee3cac91adbb096461bcd11add2a0e6`.

## KB MCP Replay

Command:

```bash
CHIO_RECEIPT_DIR=./transcripts examples/chiodome-bilateral/scripts/run-with-kb-mcp.sh --check
```

Result: exit 0.

The replay produced 5 response frames and 5 mediation transcripts under
`examples/chiodome-bilateral/transcripts/`. At least one frame carried
the `chio_verified` attestation header.

## Golden Explain

Command:

```bash
cargo run -q -p chio-cli -- receipt explain --input-file examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/receipt.json rcpt-c-refund-demo-0001
```

Result: exit 0, written to
`examples/chiodome-bilateral/golden/receipt-explain.txt`.

## Tests

Command:

```bash
cargo test -p chiodome-bilateral-example
```

Result: exit 0, 4 tests passed.

## Bounded Claim

This evidence proves deterministic canary generation, replay transcript
generation, and local example tests. This fixture set is outside active
package-release scope. It does not claim full production KB MCP
signed-receipt operation or selective-disclosure proof completion.
