# T1 Lane C Protocol Primitives Evidence

## Scope

Lane C owns T1.0, T1.1, T1.2, T1.3, and T1.6.

## Implemented Surfaces

- T1.0: `chio.capabilities.v1`, schema-aware capability signing, and
  signed-artifact compatibility registry.
- T1.1: default-on delegation primitives, typed caveats, attenuation witness
  generation and verification, and capability v2 signing.
- T1.2: receipt v2 body-hash input, typed signing wrapper, replay set keyed
  only by `body_hash`, DAG parent-set hash, and ordinal checks.
- T1.3: `chio.anchor_batch.v1` Merkle batching, inclusion verification, and
  public-witness semantics documentation.
- T1.6: `chio receipt explain <receipt-id>` CLI narrator for v1 and v2 receipts.
  Lookup accepts `--input-file`, local `--receipt-db`, and remote
  `--control-url` receipt query sources.

## Evidence Gate Pointers

- Protocol: `spec/PROTOCOL.md`
- Schemas: `spec/schemas/chio-wire/v1/capability/*.schema.json`,
  `spec/schemas/chio-wire/v1/receipt/v2.schema.json`,
  `spec/schemas/chio-wire/v1/receipt/lineage_statement.v2.schema.json`,
  `spec/schemas/chio-wire/v1/anchor/batch.schema.json`,
  `spec/schemas/registry.json`
- Registries: `spec/registries/claim-registry.v1.json`,
  `spec/registries/proof-manifest.v1.json`,
  `spec/registries/theorem-inventory.v1.json`
- Public witness semantics: `docs/security/public-witness-semantics.md`
- Negative tests: `crates/chio-conformance/tests/protocol_primitives_t1.rs`
- Focused Rust tests: `crates/chio-core-types/src/capability.rs`,
  `crates/chio-core-types/src/receipt.rs`, `crates/chio-anchor/src/batch.rs`

## Proof Report

`scripts/generate-proof-report.sh --no-run-gates` is the local non-gating
generation path when the formal toolchain is unavailable. The formal generated
report target remains `target/formal/proof-report.json`, and the tracked
Lane C snapshot is committed at `evidence/TRJ4-180/proof-report.json`.

## Focused validation

- `cargo fmt --all -- --check`
- `cargo test -p chio-cli receipt_explain_tests -- --nocapture`
- `cargo clippy -p chio-cli --bin chio -- -D warnings`
