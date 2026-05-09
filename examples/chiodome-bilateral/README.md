# chiodome-bilateral

Demo scaffolding. Two halves:

1. **Cross-org refund (C1):** an end-to-end demo runner that produces a
   DSSE signature-slice envelope plus a single-leaf `Web3CheckpointStatement`
   for one synthetic refund. The cosigning surface is
   `chio_federation::bilateral_dsse::sign_dsse_envelope`.
2. **KB MCP integration (C3):** an `mcp-remote` stdio-to-HTTP bridge plus a
   `chio mcp serve` policy wrapper around the local KB MCP at
   `:8111/mcp/`. The default `--check` path produces mediation transcripts
   and wrapper attestation frames, not kernel-signed Chio receipts. The
   documented `--full` path can assert signed receipts only when pointed at a
   real receipt DB.

The two halves can be exercised independently. C1 is a self-contained
single-process Rust binary; C3 is an orchestration shell script that runs
KB MCP plus the Chio CLI.

## Prerequisites

- Cargo workspace builds. Run from the repo root:
  ```
  cargo build -p chiodome-bilateral-example
  ```
- For the KB MCP half:
  - The local KB MCP stack at `ops/knowledge-base/` (port `8111`,
    endpoint `/mcp/`).
  - `mcp-remote` (a stdio-to-HTTP bridge for MCP). Install:
    `npx -y mcp-remote --version`.
  - `chio mcp serve --policy ./policy.yaml -- <wrapped command>` from
    `crates/chio-cli`. Build with `cargo build -p chio-cli` (release
    optional).

## Running the cross-org refund demo (C1)

```
# From repo root. Non-deterministic run (fresh keypairs):
cargo run --bin chiodome-bilateral-demo

# Reproducible run (matches pinned fixture hashes; this is what the
# fixture-regeneration check verifies):
cargo run --bin chiodome-bilateral-demo -- --release-fixture-seed=42
# or, equivalently:
CHIODOME_DEMO_FIXTURE_SEED=42 cargo run --bin chiodome-bilateral-demo
```

Default output directory is `examples/chiodome-bilateral/fixtures/`; override
with `CHIODOME_DEMO_OUT=<dir>`. The runner prints the public keys of the two
synthetic kernels, the signed receipt id, the DSSE envelope's signature
count, and the merkle root of the emitted checkpoint statement.

`--release-fixture-seed=<u64>` (or `CHIODOME_DEMO_FIXTURE_SEED=<u64>`)
seeds both keypairs deterministically so reruns produce byte-identical
artefacts. Without the seed, `Keypair::generate()` rolls fresh randomness
per run and only the schema/scenario/tool-name fields are stable.

What lands on disk:

| File | Producer | Schema |
|------|----------|--------|
| `receipt.json` | `chio_core::receipt::ChioReceipt::sign` | `chio.receipt_v1` |
| `envelope.json` | `chio_federation::bilateral_dsse::sign_dsse_envelope` | DSSE v1 + `chio.bilateral-cosign-signature-slice.v1` predicate |
| `checkpoint.json` | this demo (single-leaf root) | `chio.checkpoint_statement.v1` |

## Inspecting receipts (`chio receipt explain`)

After the demo writes `fixtures/receipt.json`, point the explainer at it:

```
cargo run -p chio-cli -- receipt explain --input-file examples/chiodome-bilateral/fixtures/receipt.json
```

The CLI prints decision provenance, evidence, financial metadata, and the
canonical-JSON digest the DSSE envelope subject claims to bind.

## Running the KB MCP integration (C3)

The script has two modes.

### `--check` (default; smoke gate)

```
./scripts/run-with-kb-mcp.sh        # equivalent to --check
./scripts/run-with-kb-mcp.sh --check
```

Runs a noninteractive replay of `fixtures/jsonrpc-replay/kb-replay.jsonrpc`
against `chio mcp wrap --e2e-fixture
fixtures/jsonrpc-replay/kb-stub-server-fixture.json`. This exercises the
wrap loop end-to-end with NO running KB MCP server, NO `mcp-remote`, and
NO network. For each `tools/call` response frame the script writes one
mediation-transcript JSON to `${CHIO_RECEIPT_DIR}` (default
`./fixtures/kb-receipts/`, gitignored) and asserts:

- at least one transcript landed (exit 1 if not),
- at least one frame carries the `_meta.chio_verified` attestation
  header (the wrapper-injected attestation envelope).

This is the default smoke gate for the replay-only wrapper path. It is
**not** behind `CHIODOME_DEMO_ASSERT_RECEIPTS=1`.

### `--full` (real KB MCP)

```
./scripts/run-with-kb-mcp.sh --full
```

Documents the canonical `chio mcp serve --policy ./policy.yaml --
mcp-remote http://127.0.0.1:8111/mcp/` invocation against a real KB MCP
backend. The script does **not** auto-spawn the KB MCP server; bring it
up out-of-band (`make -C ops/knowledge-base run`) first, then drive the
serve command with `< fixtures/jsonrpc-replay/kb-replay.jsonrpc` and
`--receipt-db <path>` (export the same path as `CHIO_RECEIPT_DB`) so
the kernel persists one signed receipt per allowed `tools/call` to the
SQLite receipt store. Set `CHIODOME_DEMO_ASSERT_RECEIPTS=1` and export
`CHIO_RECEIPT_DB` to make `--full` exit 1 if the receipt DB is empty;
the assertion call is `chio --receipt-db ${CHIO_RECEIPT_DB} receipt
list --limit 1`, which prints one JSON-line receipt per row.
`CHIODOME_DEMO_ASSERT_RECEIPTS=1` without `CHIO_RECEIPT_DB` is a hard
error (the script exits 1). The current script replaced the previous
"empty `${CHIO_RECEIPT_DIR}` directory" assertion with this DB-backed
one because the kernel now persists receipts to the SQLite store, not
the mediation-transcript directory.

### Bounded honesty

The `--check` mediation-transcript path does **not** produce
kernel-signed Chio receipts; it persists the wrap-mode attestation
frames the kernel injected into each response. The full kernel-signed
`chio mcp serve` path requires a running KB MCP and is documented (not
auto-driven). This demo keeps C3 PARTIAL on that distinction; follow-up
deliverables include packaging a self-contained KB MCP stub binary so
`--check` can drive the serve path end-to-end without the npx +
ops/knowledge-base prerequisites.

See the script's inline comments for variable knobs (`KB_MCP_PORT`,
`CHIO_RECEIPT_DIR` for the `--check` mediation-transcript directory,
`CHIO_RECEIPT_DB` for the `--full` SQLite receipt store assertion,
`CHIO_POLICY_FILE`, etc.).

## Bounded claims (read this first)

This demo is a **single-kernel local proof of the cosign surface**. It does
**not** claim:

- Transparency-log inclusion (no public log; no Rekor/OTS witness on the
  C1 path).
- Distributed-quorum linearizability or HA. The "two kernels" are two
  `Keypair` identities in one process; cross-host transport is the follow-up
  follow-up (DSSE-aware `BilateralCoSigningProtocol`).
- Multi-witness consensus or chain-bound finality.
- Production-grade KB MCP integration. The KB tool surface and the
  `mcp-remote` bridge are both demo artifacts; production deployments
  should review the bearer-token, retry, and tool-allow-list semantics.

The cosigning surface itself **is** load-bearing within its bounded profile:
the demo uses the DSSE signature-slice envelope and explicitly does **not**
call the legacy `co_sign_with_origin` path because the two preimages share
zero bytes; see `crates/chio-federation/src/bilateral_dsse.rs` for the full
rationale.

## File map

```
examples/chiodome-bilateral/
  Cargo.toml                  # workspace member; binary `chiodome-bilateral-demo`
  README.md                   # this file
  policy.yaml                 # policy for `chio mcp serve --policy`
  src/main.rs                 # the C1 cross-org refund runner + tests
  scripts/run-with-kb-mcp.sh  # the C3 KB-MCP-plus-Chio orchestration script
                              # (--check default smoke gate, --full canonical)
  fixtures/
    .gitignore                # excludes the runtime-generated kb-receipts/
    README.md                 # fixture explainer (deterministic seeded run)
    receipt.json              # produced by the runner under seed 42
    envelope.json             # ditto
    checkpoint.json           # ditto
    jsonrpc-replay/
      README.md               # replay-fixture explainer
      kb-replay.jsonrpc       # newline-delimited JSON-RPC client frames
      kb-stub-server-fixture.json   # `chio mcp wrap --e2e-fixture` stub
    kb-receipts/              # runtime-generated; gitignored
```

## Evidence trail

- Cites `bilateral_dsse` as the load-bearing primitive. The demo's
  `Cargo.toml` and `src/main.rs` headers spell out which file each
  consumed surface lives in.
- Tests: `cargo test --bin chiodome-bilateral-demo` (4 tests; round-trip
  envelope verification, receipt signing, anchor merkle-root binding,
  attacker-key rejection).
