# Chio Runtime Explicit Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `chio-runtime` wildcard facade with an explicit runtime API boundary.

**Architecture:** `chio-runtime` still delegates to the historical runtime core while the implementation split continues, but it must not reexport that whole crate. The public surface should expose runtime admission, trust-floor, orchestration, operations, and proof-regeneration APIs only.

**Tech Stack:** Rust workspace crates `chio-runtime`, `chio-cli`, Cargo test, Clippy.

---

### Task 1: Runtime Boundary Regression

**Files:**
- Modify: `crates/chio-runtime/tests/runtime_boundary.rs`

- [x] **Step 1: Write the failing test**

Add `runtime_boundary_does_not_wildcard_reexport_historical_core`, which reads `../src/lib.rs` and asserts it does not contain `pub use chio_runtime_core::*`.

- [x] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-runtime runtime_boundary_does_not_wildcard_reexport_historical_core`

Expected before implementation: FAIL on the wildcard reexport assertion.

### Task 2: Explicit Runtime Exports

**Files:**
- Modify: `crates/chio-runtime/src/lib.rs`

- [x] **Step 1: Replace wildcard with explicit exports**

Export runtime admission, runtime trust-floor, orchestration, operations, proof-regeneration, parser, serializer, validator, schema, and store APIs explicitly from `chio_runtime_core`.

- [x] **Step 2: Keep Chio error alias**

Keep `pub type ChioRuntimeError = chio_runtime_core::ChioRuntimeError;` so callers have a Chio-named alias while the deep split continues.

- [x] **Step 3: Run focused runtime tests**

Run: `cargo test -p chio-runtime`

Expected after implementation: PASS.

### Task 3: CLI Compatibility Check

**Files:**
- No direct CLI edits expected.

- [x] **Step 1: Run runtime CLI parser coverage**

Run: `cargo test -p chio-cli --bin chio_runtime`

Expected after implementation: PASS, proving current CLI `chio_runtime::` references still compile through the explicit boundary.

### Task 4: Final Verification

**Files:**
- Modify: `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`
- Create: `docs/superpowers/plans/2026-05-19-chio-runtime-explicit-boundary.md`

- [x] **Step 1: Update architecture evidence**

Record that `crates/chio-runtime/src/lib.rs` no longer wildcard-reexports the historical runtime core.

- [x] **Step 2: Run verification gates**

Run:

```bash
cargo test -p chio-runtime
cargo test -p chio-cli --bin chio_runtime
cargo clippy -p chio-runtime --all-targets -- -D warnings
cargo clippy -p chio-cli --bin chio -- -D warnings
cargo fmt --all -- --check
git diff --check
rg -n $'\xE2\x80\x94|\xE2\x80\x93' crates/chio-runtime/src/lib.rs crates/chio-runtime/tests/runtime_boundary.rs docs/architecture/CHIO_FINAL_ARCHITECTURE.md docs/superpowers/plans/2026-05-19-chio-runtime-explicit-boundary.md
rg -n "pub use chio_runtime_core::\\*" crates/chio-runtime/src/lib.rs
```

Expected: all commands exit 0 except the dash scan exits 1 with no matches.
