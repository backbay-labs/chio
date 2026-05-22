# Chio Runtime Error Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop `chio-runtime` from exposing `ChioRuntimeError` as a type alias for the historical runtime error.

**Architecture:** `chio-runtime` remains an explicit facade over the historical runtime core while the deeper split continues. The named public runtime error should be Chio-owned even before every fallible helper and store trait is wrapped.

**Tech Stack:** Rust workspace crate `chio-runtime`, existing runtime boundary tests, focused CLI parser coverage.

---

### Task 1: Add Error Boundary Regression

**Files:**
- Modify: `crates/chio-runtime/tests/runtime_boundary.rs`

- [x] **Step 1: Write the failing test**

Add `runtime_error_boundary_is_chio_owned`, which proves the public runtime
error type resolves to `chio_runtime::ChioRuntimeError`.

- [x] **Step 2: Run the red test**

Run:

```bash
cargo test -p chio-runtime runtime_error_boundary_is_chio_owned
```

Expected before implementation: FAIL because `ChioRuntimeError` is still a type
alias for `chio_runtime_core::error::ChioRuntimeError`.

### Task 2: Implement Opaque Runtime Error Type

**Files:**
- Modify: `crates/chio-runtime/src/lib.rs`

- [x] **Step 1: Remove the historical error reexport**

Stop reexporting `ChioRuntimeError` through `chio-runtime`.

- [x] **Step 2: Replace the alias**

Replace `pub type ChioRuntimeError = chio_runtime_core::ChioRuntimeError`
with a Chio-owned `ChioRuntimeError` wrapper that preserves a `code()` accessor
and standard error behavior for future facade wrappers.

### Task 3: Update Architecture Evidence

**Files:**
- Modify: `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`

- [x] **Step 1: Record the boundary change**

Update the architecture ledger and backlog evidence to state that
`ChioRuntimeError` is no longer a type alias, while deeper fallible helper and
store-trait wrapping remains a later crate-split item.

### Task 4: Verify

**Files:**
- All files touched above

- [x] **Step 1: Run focused tests**

Run:

```bash
cargo test -p chio-runtime
cargo test -p chio-cli --bin chio_runtime
```

- [x] **Step 2: Run focused lints and hygiene**

Run:

```bash
cargo clippy -p chio-runtime --all-targets -- -D warnings
cargo clippy -p chio-cli --bin chio -- -D warnings
cargo fmt --all -- --check
git diff --check
rg -n $'\xE2\x80\x94|\xE2\x80\x93' crates/chio-runtime/src/lib.rs crates/chio-runtime/tests/runtime_boundary.rs docs/architecture/CHIO_FINAL_ARCHITECTURE.md docs/superpowers/plans/2026-05-19-chio-runtime-error-boundary.md
rg -n "ChioRuntimeError,|pub type ChioRuntimeError|ChioRuntimeError = chio_runtime_core" crates/chio-runtime/src/lib.rs
```

Expected: all commands exit 0 except the dash scan and source leak scan exit 1
with no matches.
