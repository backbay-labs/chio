# Bar 3 baseline -- bilateral demo end-to-end with `chio receipt explain`

**Bar**: 3 (Lane C: one forcing demo).
**Baseline captured**: 2026-05-08.
**Baseline SHA**: `708c7bb33df43594f5e76542b05fca7a56d9689e`.
**Baseline branch**: `planning branch`.
**Authoritative source**: `examples/` directory listing + `crates/chio-federation/src/bilateral.rs` + `ops/knowledge-base/` + `crates/chio-cli/src/cli/trust_commands.rs`.

This file records the CURRENT (pre-release work) state of Bar 3 so the post-release work
delta is measurable against a fixed reference. Bar 3 close criteria are
normative in `.planning/trajectory-5/debate/00-SYNTHESIS.md` Lane C and
`SHIP-BAR-TRACKER.md` Bar 3 row.

---

## examples/ directory state (current, pre-release work)

```
$ ls examples/ | grep -i 'chiodome\|bounded'
(no matches)
```

`examples/chiodome-bilateral/` does NOT exist at baseline.
(The synthesis text and earlier per-lane docs sometimes referred to
`examples/bounded-chiodome/`; that name is a drift artifact corrected
across the planning set. The canonical demo path is
`examples/chiodome-bilateral/`; the bounded canary package retains the
`v0.1.0-bounded-chiodome` identifier.) Verified by:

```
$ ls examples/
EXAMPLE_SURFACE_MATRIX.md  README.md  _shared
agent-commerce-network     anthropic-sdk    cross-provider-policy
docker     eval-receipt-ingest    guards
hello-a2a    hello-acp     hello-chi
hello-django   hello-dotnet   hello-drogon
hello-elysia   hello-express
[... continues with hello-* examples]
```

None of the `hello-*` examples exercise the cross-org bilateral path.

| Field | Baseline value |
|---|---|
| `examples/chiodome-bilateral/` exists | NO |
| Bilateral demo runs end-to-end against production code | ZERO times |
| `cargo run --example chiodome-bilateral` | command fails (no such example) |

## KB MCP stack (current, pre-release work)

The KB MCP stack is real and runnable. Verified by `ls -la ops/knowledge-base/`:

```
.dockerignore        DOGFOOD-REVIEW.md   Dockerfile.kb-mcp   README.md
.env.example         chio_kb/             config/
[plus additional subdirs]
```

| Field | Baseline value |
|---|---|
| `ops/knowledge-base/` exists | YES |
| KB MCP HTTP endpoint | `:8111/mcp/` (per `ops/knowledge-base/README.md` lines 136-151 mcp-remote example) |
| KB MCP transport | HTTP only (NOT stdio) |
| Wrapped by `chio mcp serve --policy` directly | NO -- `chio mcp serve` wraps stdio commands; KB MCP serves HTTP. The bridge is `mcp-remote` (Node.js stdio<->HTTP shim). |

## mcp-remote bridge (current, pre-release work)

```
$ grep -rn "mcp-remote" docs/ ops/
docs/architecture/CHIO_RUNTIME_BOUNDARIES.md:11: ... chio-mcp-remote ...
docs/architecture/CHIO_RUNTIME_BOUNDARIES.md:21: ... chio-mcp-remote ...
ops/knowledge-base/README.md:136: Claude Desktop with `mcp-remote`:
ops/knowledge-base/README.md:143:   "args": ["mcp-remote", "http://localhost:8111/mcp/"]
ops/knowledge-base/README.md:147:   "args": ["mcp-remote", "http://localhost:8000/mcp"]
```

| Field | Baseline value |
|---|---|
| `mcp-remote` documented for KB MCP | YES (`ops/knowledge-base/README.md:136-151`) |
| `mcp-remote` invocation pattern | `npx -y mcp-remote http://localhost:8111/mcp/` |
| `chio mcp serve --policy ... -- npx -y mcp-remote ...` (the wrapped command Lane C demo will use) | NOT YET in any example or smoke test |
| Air-gapped CI runner npm cache pre-warm | NOT YET captured |

The W3 Lane C fix-log "R4 BLOCKER 2 (KB MCP HTTP/stdio bridge)" resolves
this by having the demo use `mcp-remote`. Pre-requisite: Node.js 18+ on
PATH; CI runners pre-warm npm cache.

## Bilateral cosign primitives in `chio-federation` (current, pre-release work)

Verified by `grep -n "CoSigningBody\|DualSignedReceipt"
crates/chio-federation/src/bilateral.rs`:

```
7://! [`DualSignedReceipt`] artifact (which carries both signatures side-by-
19://! * Verification is strict: a `DualSignedReceipt` only verifies when BOTH
24://!   [`CoSigningBody`]: receipt body bytes + both kernel IDs.
37:/// [`DualSignedReceipt::org_a_signature`] and
38:/// [`DualSignedReceipt::org_b_signature`].
41:pub struct CoSigningBody {
52:impl CoSigningBody {
83:///   over the canonical [`CoSigningBody`].
90:/// signatures via [`DualSignedReceipt::verify`].
93:pub struct DualSignedReceipt {
```

| Primitive | Location | Notes |
|---|---|---|
| `CoSigningBody` | `crates/chio-federation/src/bilateral.rs:41-77` | Canonical-JSON signing body; current production primitive |
| `DualSignedReceipt` | `crates/chio-federation/src/bilateral.rs:93+` | Strict verification (both signatures); NOT a §6-conformant DSSE artifact (preimage shares zero bytes with §6 PAE) |
| `bilateral_dsse.rs` | DOES NOT EXIST | Lane B B4 creates this module per `.planning/trajectory-5/lane-b-wiring/dsse-bilateral-signing.md` |

## DSSE PAE signing (current, pre-release work)

DSSE PAE signing is NOT IMPLEMENTED. Lane B sub-lane B4 lands it per
`spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6 lines 338-353.

| Field | Baseline value |
|---|---|
| `bilateral_dsse.rs` module | DOES NOT EXIST |
| Ed25519-over-DSSE-PAE signing surface | DOES NOT EXIST |
| Production hot path emitting §6 envelope | NO -- `crates/chio-federation/src/bilateral.rs::CoSigningBody` is the only signing body |

## `chio receipt explain` (current, pre-release work)

Verified by `grep -rn "explain" crates/chio-cli/src/`:

```
crates/chio-cli/src/cli/trust_commands.rs:2423:fn cmd_receipt_explain(...)
crates/chio-cli/src/cli/trust_commands.rs:2430:    load_receipt_for_explain(args.receipt_id, &backend)?
crates/chio-cli/src/cli/trust_commands.rs:2432:    let report = explain_receipt_value(args.receipt_id, value, args.depth, args.fanout_limit)?;
[...]
```

| Field | Baseline value |
|---|---|
| `chio receipt explain` exists in CLI | YES (entry point at `crates/chio-cli/src/cli/trust_commands.rs:2423`) |
| Runs against a real receipt | YES (functional today; loads from `--input-file` / `--receipt-db` / `--control-url`) |
| Output shape | textual `report` from `explain_receipt_value`; depth and fanout_limit args supported |
| Inspects a bilateral cosigned receipt | NOT TODAY -- the bilateral path does not produce a receipt the explain command has been validated against; no golden fixture for bilateral output exists |
| Surfaces "policy verdict disagreement" as top-level diagnostic | NOT TODAY (release work-C4.1 adds this per W3 R4-MINOR-9 fix; effort bumped M->L) |
| Renders bilateral chain with parent->child arrows | NOT TODAY (release work-C4.1 adds this) |

## Aggregate baseline state

| Bar 3 sub-criterion | Baseline (pre-release work) | Target (post-release work) |
|---|---|---|
| `examples/chiodome-bilateral/` exists | NO | YES |
| Two-kernel cross-org bilateral cosigned invocation runs | ZERO times | runs end-to-end on fresh checkout |
| Receipts are inspectable via `chio receipt explain` against a bilateral receipt | NO | YES, with golden output |
| `examples/chiodome-bilateral/fixtures/` capture of demo run | NO | YES, diff-stable |
| Two-kernel transcripts | NONE | committed under `examples/chiodome-bilateral/transcripts/` |
| Capability lease + budget bond minted via `chio-credit` `CREDIT_BOND_ARTIFACT_SCHEMA` | not exercised | minted; consumed at receipt-write |
| Anchored through `crates/chio-anchor::Web3CheckpointStatement` | not exercised | anchored (no live deployment) |
| Selective-disclosure auditor view (behind `zk` Cargo feature flag) | none | runs (or deferred to v0.2 per R6) |
| Wrapped at `chio mcp serve --policy` against `ops/knowledge-base/` via `mcp-remote` | none | wrapped |
| Bounded package status recorded in `releases.toml` `[v0_1_0_bounded_chiodome]` | ABSENT IN #620; package truth is not authored by the planning PR | `release_status = "canary_assurance_complete"` only after Lane B integration, canary regeneration from merged `main`, and integrated merge SHA recording |

## Re-measurement protocol (release close)

The release work closeout wave runs:

1. `examples/chiodome-bilateral/` exists with a `Makefile` or
   `cargo run --example` recipe; `cargo run --example chiodome-bilateral`
   produces an `audits/evidence/c-bilateral-smoke.json` with all
   eight artifacts present (per `SHIP-BAR-TRACKER.md` Bar 3
   "Machine-readable signal").
2. Two-kernel transcripts under `examples/chiodome-bilateral/transcripts/`.
3. `chio receipt explain` golden output committed under
   `examples/chiodome-bilateral/golden/<receipt-body-hash>.txt`;
   matches the explain output for the captured receipt.
4. If package metadata is recorded, root `releases.toml`
   `[v0_1_0_bounded_chiodome].release_status` and `integrated_merge_sha`
   are moved only by the release owner after merged-main regeneration.
5. `.github/workflows/chiodome-demo-continuous.yml` (release work-C6.3) is
   green for 7 consecutive nights pre-tag.
6. `tools/diff-stable.py` (or Rust binary) (release work-C6.4) verifies the
   fixture tarball is diff-stable across runs.
7. `scripts/check-bounded-ship-bar.sh` Bar-3 block PASSes against
   committed evidence.

When all of the above are green, the Bar 3 row in `SHIP-BAR-TRACKER.md`
flips NONE -> DONE.

## Pointers

- Lane C README: `.planning/trajectory-5/lane-c-demo/README.md`
- Lane C PLAN: `.planning/trajectory-5/lane-c-demo/PLAN.md`
- Lane C tickets: `.planning/trajectory-5/lane-c-demo/planning docs`
- Architecture: `.planning/trajectory-5/lane-c-demo/architecture.md`
- Bilateral cosign flow: `.planning/trajectory-5/lane-c-demo/bilateral-cosign-flow.md`
- KB MCP integration: `.planning/trajectory-5/lane-c-demo/kb-mcp-integration.md`
- Selective disclosure: `.planning/trajectory-5/lane-c-demo/selective-disclosure.md`
- Release bar: `.planning/trajectory-5/lane-c-demo/release-bar.md`
- Wave-2 sign-off: `.planning/trajectory-5/reviews/lane-c-wave2.md`
- Ship-bar tracker Bar 3 row: `.planning/trajectory-5/SHIP-BAR-TRACKER.md`
- Lane B B4 (DSSE-conformant signing surface Lane C consumes):
  `.planning/trajectory-5/lane-b-wiring/dsse-bilateral-signing.md`

End of Bar 3 baseline.
