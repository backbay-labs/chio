# Chio Federation Treaty API Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move public Chio federation treaty command internals off direct `chio_chiodos_runtime::` calls.

**Architecture:** `chio-federation` owns treaty scope parsing, governance ladder intersection, and cross-boundary admission helpers for the Chio public federation surface. The hidden Chiodos wrappers remain compatibility entrypoints, but the Chio-named handlers use a Chio federation API.

**Tech Stack:** Rust workspace crates `chio-federation` and `chio-cli`, Clap/source-boundary tests, focused federation treaty tests.

---

### Task 1: Add Federation Handler Boundary Regression

**Files:**
- Modify: `crates/chio-cli/src/main.rs`

- [x] **Step 1: Write the failing test**

Add `chio_federation_treaty_handlers_do_not_call_historical_runtime_directly`,
which reads `cli/chiodos/dispatch/treaty.rs` and asserts it does not contain
`chio_chiodos_runtime::`.

- [x] **Step 2: Run the red test**

Run:

```bash
cargo test -p chio-cli --bin chio chio_federation_treaty_handlers_do_not_call_historical_runtime_directly
```

Expected before implementation: FAIL because the Chio federation treaty handler
body directly calls `chio_chiodos_runtime::`.

### Task 2: Add Chio Federation Treaty API

**Files:**
- Create: `crates/chio-federation/src/treaty.rs`
- Modify: `crates/chio-federation/src/lib.rs`

- [x] **Step 1: Add treaty data types and error type**

Add Chio federation treaty scope, governance ladder manifest, ladder
intersection, cross-boundary admission report, evidence ref, and admission input
types with `deny_unknown_fields`. Add `FederationTreatyError` with a stable
`code()` accessor.

- [x] **Step 2: Add treaty helper functions**

Add JSON parsers, JSON serializers, SHA-256 helpers,
`compute_ladder_intersection`, and `evaluate_cross_boundary_admission` behind
the `chio-federation` boundary.

- [x] **Step 3: Reexport the treaty API**

Reexport the new treaty module types, constants, and helpers from
`crates/chio-federation/src/lib.rs`.

### Task 3: Switch CLI Treaty Handlers

**Files:**
- Modify: `crates/chio-cli/src/cli/chiodos/dispatch/treaty.rs`

- [x] **Step 1: Use `chio_federation` from Chio-named handlers**

Replace direct `chio_chiodos_runtime::` calls in the treaty intersect/admit
handler bodies with `chio_federation::` functions and types. Keep hidden
`cmd_chiodos_treaty_*` wrappers delegating to the Chio-named handlers.

### Task 4: Add Federation Treaty Behavior Tests

**Files:**
- Create: `crates/chio-federation/tests/treaty.rs`

- [x] **Step 1: Test Chio schema emission**

Add `chio_treaty_intersection_emits_chio_schema`, which builds a two-party
treaty and verifies `compute_ladder_intersection` emits
`chio.federation.ladder-intersection.v1`.

- [x] **Step 2: Test destructive CRDT fail-closed behavior**

Add `chio_treaty_intersection_rejects_destructive_crdt`, which verifies
destructive `crdt_commutative` ladder material rejects with
`chiodos_ladder_destructive_crdt_not_allowed`.

### Task 5: Verify

**Files:**
- All files touched above

- [x] **Step 1: Run focused tests**

Run:

```bash
cargo test -p chio-federation treaty
cargo test -p chio-cli --bin chio chio_federation_treaty_handlers_do_not_call_historical_runtime_directly
cargo test -p chio-cli --bin chio chio_federation_treaty_dispatch_uses_chio_handlers
cargo test -p chio-cli --bin chio chiodos_treaty_verify_packet_subcommand_parses
```

- [x] **Step 2: Run focused lints and hygiene**

Run:

```bash
cargo clippy -p chio-federation --all-targets -- -D warnings
cargo clippy -p chio-cli --bin chio -- -D warnings
cargo fmt --all -- --check
git diff --check
rg -n $'\xE2\x80\x94|\xE2\x80\x93' crates/chio-federation/src/lib.rs crates/chio-federation/src/treaty.rs crates/chio-federation/tests/treaty.rs crates/chio-cli/src/cli/chiodos/dispatch/treaty.rs crates/chio-cli/src/main.rs docs/architecture/CHIO_FINAL_ARCHITECTURE.md docs/superpowers/plans/2026-05-19-chio-federation-treaty-api-boundary.md
rg -n "chio_chiodos_runtime::" crates/chio-cli/src/cli/chiodos/dispatch/treaty.rs
```

Expected: all commands exit 0 except the dash scan and source-boundary scan
exit 1 with no matches.
