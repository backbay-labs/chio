# chiodome-bilateral fixtures

Three artifacts live here once `chiodome-bilateral-demo` runs:

| File | Producer | Schema | Bound to |
|------|----------|--------|----------|
| `receipt.json` | `chio_core::receipt::ChioReceipt::sign` | `chio.receipt_v1` (v1 receipt body; B2 receipt-v2 negotiation lives downstream) | Org B's keypair |
| `envelope.json` | `chio_federation::bilateral_dsse::sign_dsse_envelope` | DSSE v1 + `chio.bilateral-cosign-signature-slice.v1` predicate | both org keypairs |
| `checkpoint.json` | this demo (single-leaf merkle root) | `chio.checkpoint_statement.v1` | Org B's keypair |

## Reproduce

The fixtures shipped here are pinned under **fixture seed 42**:

```
cargo run --bin chiodome-bilateral-demo -- --release-fixture-seed=42
# or, equivalently:
CHIODOME_DEMO_FIXTURE_SEED=42 cargo run --bin chiodome-bilateral-demo
```

Running with `--release-fixture-seed=<u64>` (or the env var
`CHIODOME_DEMO_FIXTURE_SEED=<u64>`) seeds **both** keypairs deterministically
from the supplied number, producing byte-identical `receipt.json`,
`envelope.json`, and `checkpoint.json` across runs. Without the flag, the
demo falls back to `Keypair::generate()` and emits a fresh, non-reproducible
fixture (useful when you want to exercise the signing paths but do not
need to match the pinned hashes).

Override the output directory with `CHIODOME_DEMO_OUT=...`. The pinned
seed (42) is the seed used to capture the v0.1.0-bounded-chiodome
release fixture.

### Pinned hashes (seed 42)

The seeded run emits:

```
org_a public key:  c578c6e4c6853f7b889ddc13c2190f22033ff3390666399c89aaaf14d49fa0ba
org_b public key:  e08a8e8decf2772e856c02ca9ae61fb6954118b1025bd5bad574ead68ef043a7
checkpoint root:   0x18f67a939b2cc6303b33bc1dec7fbb1c5ee3cac91adbb096461bcd11add2a0e6
```

Reviewers can verify these match the `kernel_key` / `merkle_root` fields
in the pinned `*.json` files by rerunning the seeded command and diffing
against the checked-in fixtures.

## Real-run vs placeholder

This directory ships **real** end-to-end run output. The `receipt.json`,
`envelope.json`, and `checkpoint.json` here were produced by
`cargo run --bin chiodome-bilateral-demo -- --release-fixture-seed=42`
against the repository checkout; they include real Ed25519 signatures
over the canonical body bytes. The fixed `timestamp`, `tool_name`,
`capability_id`, ids, **and (under the seed) the keypairs and signatures**
are deterministic and byte-stable across runs.

To regenerate the pinned set:

```
rm -f examples/chiodome-bilateral/fixtures/{receipt,envelope,checkpoint}.json
cargo run --bin chiodome-bilateral-demo -- --release-fixture-seed=42
git add examples/chiodome-bilateral/fixtures/
```

Verify reproducibility:

```
mkdir -p /tmp/run1 /tmp/run2
CHIODOME_DEMO_OUT=/tmp/run1 cargo run --bin chiodome-bilateral-demo -- --release-fixture-seed=42
CHIODOME_DEMO_OUT=/tmp/run2 cargo run --bin chiodome-bilateral-demo -- --release-fixture-seed=42
diff -q /tmp/run1 /tmp/run2   # MUST be empty
```

## Inspecting

After a real run:

```
cargo run -p chio-cli -- receipt explain --input-file ./fixtures/receipt.json
```

The CLI prints the decision, evidence, financial metadata, canonical-JSON
digest, and any embedded inclusion proof. The DSSE envelope and the
checkpoint statement are inspected with whatever JSON tool you prefer
(`jq`, your editor, etc.) -- the chio CLI explainer for those two
artifacts is a follow-up.

## Bounded claims

The fixtures here represent a **single-kernel local proof**:

- The two "kernels" are two `Keypair` identities in the same process. No
  cross-host transport, no DSSE-aware federation transport.
- The checkpoint covers a single-receipt batch (`tree_size: 1`,
  `merkle_root == leaf_hash(canonical_json(receipt))` per RFC 6962, i.e.
  `SHA256(0x00 || canonical_json(receipt))`, matching the convention used
  by `chio_anchor::batch` and `chio_anchor::evm`). No transparency log,
  no chain anchor, no consistency proof.
- The KB MCP default check writes mediation transcripts under
  `kb-receipts/` (created lazily on first run). Kernel-signed KB receipts
  require the documented `--full` path with a configured SQLite receipt DB.
  The cross-org refund fixtures here are independent of the KB MCP path.
