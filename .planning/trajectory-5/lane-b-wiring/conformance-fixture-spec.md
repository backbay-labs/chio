# Conformance Fixture Spec (Pattern for Every Lane B Ticket)

This document is the PATTERN every Lane B ticket follows. It defines how a "signed negative conformance fixture" is structured, how it proves the absence of a bypass, where it lives, and how the Evidence Gate verifies that it "fails when wiring is removed".

The trj4 erratum's failure mode (synthesis lines 9-13) was fixtures that passed without exercising the production hot path. Every Lane B fixture must defend against that.

## Where fixtures live

`crates/chio-conformance/tests/<name>.rs`. One fixture file per primitive. The release work ship-bar item 2 (synthesis lines 152-155) names this directory explicitly:

> "The three Lane B primitives ... are each protected by a signed negative conformance fixture in `crates/chio-conformance/tests/` that exercises the production call site and fails when the enforcement is removed."

Companion helpers (mock kernels, real-budget-registry counters, peer-pin scaffolding) live in `crates/chio-conformance/tests/common/` to keep individual fixture files focused.

## The five required parts of a Lane B fixture

Every fixture has all five.

### 1. A docstring naming the threat and the spec MUST citation

Top of file. Format:

```rust
//! W<wave>.<sublane> negative conformance test: <one-line summary>.
//!
//! Threat: <plain-language description of the attack or defect this fixture
//!          defends against. Reference the trj4 erratum's "structural framing
//!          without runtime wiring" pattern when applicable>.
//!
//! Spec citation: PROTOCOL.md §<section> lines <range>:
//!   "<verbatim quote of the MUST that this fixture proves is enforced>"
//!
//! The fixture exercises the production code path through
//! `<crate>::<entry-point>` (lines <range>) and fails closed when the
//! wiring is removed. Reverse-test recorded in the PR description.
```

See `crates/chio-conformance/tests/anchor_batch_forged_root_rejected.rs:1-21` for the existing template the new fixtures follow.

### 2. A real-kernel or real-anchor build (NOT a mock)

The fixture instantiates the production type, not a fake. Patterns:

- **Kernel-touching fixtures (B1, B2)**: build a real `ChioKernel` via the same shape as `crates/chio-conformance/tests/v2_receipt_kernel_round_trip.rs:92-115`:
  ```rust
  let config = KernelConfig { keypair: Keypair::generate(), /* ... */ };
  let mut kernel = ChioKernel::new(config);
  let store = SqliteReceiptStore::open(receipt_store_path).unwrap();
  kernel.set_receipt_store(Box::new(store));
  kernel.register_tool_server(Box::new(EchoToolServer::new()));
  ```
  No mock kernels. No "FakeKernel" wrappers. The same `ChioKernel` that production callers use.
- **Anchor fixtures (B3)**: build a real `AnchorBatch` via `chio_anchor::build_anchor_batch` with a real `Keypair` and real checkpoint IDs. See `crates/chio-conformance/tests/anchor_batch_forged_root_rejected.rs:32-45` for the existing template.

### 3. The fixture exercises a public production entry point

Not a private helper. Not a near-copy of the production logic. The same function that the production hot path calls. Examples:

| Sub-lane | Entry point exercised |
|---|---|
| B1 | `ChioKernel::evaluate_tool_call_blocking` (the public mint API; same path every other production caller hits) |
| B2 | `ChioKernel::evaluate_tool_call_blocking` (same; the receipt-version resolution is internal to this dispatch) |
| B3 | `chio_anchor::verify_anchor_batch_with_witness_policy` (the sync wrapper itself - the function being gated) |

A fixture that calls `ChioKernel::record_chio_receipt_v2` directly without going through `evaluate_tool_call_blocking` is REJECTED at PR review: the production hot path begins at `evaluate_tool_call_blocking`, and the W2.1 mint hook at `crates/chio-kernel/src/kernel/responses.rs:1405-1427` is reachable only through that entry. Bypassing it is exactly the trj4 anti-pattern.

### 4. An assertion that observes the production-path side effect

A fixture that only asserts on the return value passes the schema check but not the "exercises the production code path" check. Lane B fixtures additionally observe a side effect that proves the wiring ran:

- B1: count `BudgetRegistry::try_admit_share` calls. Production with the real registry mutates the count; the deleted `verify_capability_full_without_budget_admit` (with `NoopBudgetRegistry`) does not.
- B2: count v1 vs v2 receipt rows in the `chio_receipts` and `chio_receipts_v2` tables of the real `SqliteReceiptStore`. A pre-B2 kernel that warn-and-downgrades emits exactly one v1 row; a post-B2 kernel emits zero rows AND returns the typed error.
- B3: assert the typed `AnchorError::SyncRouteRequiresAdvisoryPolicy` from the sync wrapper. This is the side effect (a return value here is sufficient because the function's contract IS the routing rule).

### 5. A reverse-test recorded in the PR description

The Evidence Gate close bar from synthesis line 113 ("signed negative conformance test that fails when wiring is removed") is operationalized as: every Lane B PR description includes a "Reverse-test" section showing the fixture FAILING when the wiring is intentionally reverted on a draft branch.

PR description format (REQUIRED for every Lane B ticket that introduces a fixture):

```markdown
## Reverse-test

Branch: `release work-b<n>.<m>-revert-test` (draft, not for merge)

Reverted commits:
- <SHA> (the wiring change)

`cargo test -p chio-conformance --test <fixture_name>` output:
- Sub-test 1 (the negative case): **FAILED** with `<expected error message>`.
- Sub-test 2 (the happy-path case): PASSED (preserved).

This proves the fixture exercises the production hot path and is not a
schema-only check. Lane B Evidence Gate close bar satisfied.
```

A PR without a reverse-test section is not closeable. The reverse-test branch can be deleted after the main PR merges (its commit history persists in the PR description's quoted output).

## Anti-patterns explicitly rejected

The following anti-patterns mirror the trj4 erratum failure modes. Lane B PR review rejects on sight:

1. **Schema-only check**: a fixture that constructs a typed value (e.g. `KernelError::ReceiptNegotiationDowngrade { ... }`) and asserts it serializes/deserializes correctly. This proves the type exists, not that the runtime emits it.
2. **Near-copy of the production logic**: a fixture that re-implements the verification flow inline (e.g. its own `verify_capability_full_inline` with the same checks). The fixture is testing its own copy, not the production code path.
3. **Mocked downstream**: a fixture that uses a `FakeBudgetRegistry` whose `try_admit_share` always returns `Ok(())`. The fixture passes whether or not the kernel actually calls the registry, because the fake answers correctly anyway. Real registry, observed mutations.
4. **Happy-path-only**: a fixture with one `#[test]` that asserts the good case works. Lane B fixtures MUST include the negative case (the failure mode the spec MUST is defending against).
5. **`#[ignore]` or feature-gated**: a fixture marked `#[ignore]` or behind a Cargo feature flag that is not on by default. CI must run every Lane B fixture on every push. The fixture cannot be silently skipped.

## Reference fixtures (existing patterns to copy)

These existing fixtures already follow the pattern; new Lane B fixtures pattern-match against them:

| Existing fixture | Pattern |
|---|---|
| `crates/chio-conformance/tests/anchor_batch_forged_root_rejected.rs` | Real `Keypair`, real `build_anchor_batch`, asserts `expect_err` with message check. (B3 pattern.) |
| `crates/chio-conformance/tests/v2_receipt_kernel_round_trip.rs` | Real `ChioKernel`, real `SqliteReceiptStore`, real tool-call dispatch, observes `chio_receipts_v2` table. (B1, B2 pattern.) |
| `crates/chio-conformance/tests/budget_split_rejects_oversubscribed_siblings.rs` | Real budget registry, real capability verification, observes registry rejection. (B1 sibling pattern.) |
| `crates/chio-conformance/tests/attenuation_witness_rejects_inflated_parent_scope.rs` | Real chain-binding, asserts `CapabilityError::AttenuationViolation` from the production verifier. (B1 chain-binding pattern.) |

## Lane B fixture inventory (deliverable)

After Lane B closes, FOUR new fixtures exist in `crates/chio-conformance/tests/` (B4 added per R4 BLOCKER 1):

| Fixture | Sub-lane | What it proves |
|---|---|---|
| `verify_full_is_only_production_entry.rs` | B1 | Hosted dispatch routes through `verify_capability_full` and mutates the real `BudgetRegistry`; partial-entry symbols are not reachable from production. |
| `receipt_v2_required_under_v2_negotiation.rs` | B2 | Stale-pin v2-negotiated dispatch fails closed with `KernelError::ReceiptNegotiationDowngrade`; no v1 fallback receipt is minted. |
| `anchor_batch_sync_path_rejected_under_public_witness.rs` | B3 | Sync `verify_anchor_batch_with_witness_policy` rejects `require_public_witness=true` with `AnchorError::SyncRouteRequiresAdvisoryPolicy`; advisory-mode sync route still works. |
| `b4_bilateral_dsse_pae_only_is_conformant.rs` | B4 (NEW per R4 BLOCKER 1) | The legacy `CoSigningBody` preimage and the DSSE PAE preimage share zero bytes; the §6-conformant verifier accepts the DSSE envelope but rejects forged envelopes built from legacy signature bytes; tampered PAE bytes are rejected. |

Plus four companion CI gate scripts (B3 reframed per R3 BLOCKER #2 as best-effort fast-feedback, NOT soundness):

| Script | Sub-lane | What it lints |
|---|---|---|
| `scripts/check-tool-server-async.sh` | B0 | No production module implements sync `fn invoke` for `ToolServerConnection`. |
| `scripts/check-verify-capability-full.sh` | B1 | No production caller in `crates/chio-kernel/src/` or `crates/chio-cli/src/` invokes a partial verifier entry. |
| `scripts/check-anchor-batch-async-witness.sh` | B3 | **Best-effort fast-feedback** (NOT a soundness guarantee per R3 BLOCKER #2): the runtime gate at `batch.rs:227-235` is the load-bearing defense; the lint catches obvious literal-struct-init-same-file cases only. False-positives AND false-negatives both tolerated. |

The fixtures are the runtime guarantee. The gate scripts are documentation/early-warning. Each Lane B sub-lane (except B0) has a runtime fixture; B0/B1/B3 have lint scripts that are advisory.

### B4 negative-conformance fixture pattern (per R4 BLOCKER 1)

The B4 fixture defends against the failure mode R4 identified: claiming spec §6 conformance via the legacy `DualSignedReceipt` (whose preimage shares zero bytes with the §6 PAE preimage). The fixture pattern is documented in `templates/CONFORMANCE-FIXTURE-PATTERN.md` §8a and in `lane-b-wiring/dsse-bilateral-signing.md` "Conformance fixture design".

Key assertions (paraphrased; full code in `dsse-bilateral-signing.md`):

1. The legacy `CoSigningBody` canonical-JSON bytes and the DSSE PAE bytes share ZERO bytes (the R4 finding).
2. The `verify_dsse_envelope` function (NEW in B4) accepts the §6 envelope.
3. Tampered PAE bytes are rejected.
4. Mismatched payload-type is rejected.
5. A forged "DSSE envelope" using legacy signature bytes is rejected (proves the §6 verifier is shape-aware, not just signature-aware).

The reverse-test: revert B4.3 (production hot-path emission) on a draft branch; the fixture FAILS because the demo no longer produces a §6-conformant envelope.

## Lane C demo path note: `mcp-remote` stdio<->HTTP bridge

The Lane B fixtures above exercise the production hot path directly through `crates/chio-conformance/tests/`. They do NOT depend on any external transport. Lane C's bilateral demo (`examples/chiodome-bilateral/`), however, dogfoods the same primitives end-to-end through a `chio mcp serve --policy ... -- npx -y mcp-remote http://localhost:8111/mcp/` invocation that wraps the local KB MCP HTTP server.

The bridge is not a Lane B concern (Lane B fixtures use the in-process kernel via `ChioKernel::evaluate_tool_call_blocking`), but the B-pattern accommodates the C-demo path as follows:

1. **B-pattern fixtures stay transport-agnostic**: all four Lane B fixtures call the production hot path in-process. They do not require `chio mcp serve` or `mcp-remote` to be installed in CI. This keeps Lane B's fixture set deterministic and air-gappable.

2. **C-pattern fixtures may layer the bridge**: when Lane C's smoke harness wraps a Lane B primitive (e.g. exercising the receipt-v2 negotiation through the wrapped MCP transport), the C fixture documents the bridge as a precondition (Node.js 18+ on PATH, `npx mcp-remote` available). The C fixture asserts the same side-effect the B fixture does (e.g. a v2 row in `chio_receipts_v2`), which proves the bridge does not silently downgrade the protocol.

3. **B fixtures are the load-bearing guarantee**: if a Lane C demo failure points at a Lane B primitive, the corresponding B fixture (B1.6/B2.5/B3.5/B4.5) is the canonical truth signal. The C-side bridge wrap is end-to-end coverage, not a substitute for the B fixture.

This documents the structural relationship so a future reviewer asking "where does the demo diverge from the conformance fixtures?" finds the answer in the B-pattern itself rather than having to reconstruct it from Lane C's `kb-mcp-integration.md`.
