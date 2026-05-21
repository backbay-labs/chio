# Chio Runtime Admission Hook Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop `chio-runtime` from publicly reexporting the historical `ChiodosRuntimeAdmissionHook` name.

**Architecture:** `chio-runtime` is the Chio-named runtime boundary. The kernel admission hook can still delegate to the hardened historical hook internally, but callers should construct and name `ChioRuntimeAdmissionHook`.

**Tech Stack:** Rust workspace crate `chio-runtime`, `chio-kernel` runtime admission hook trait, existing runtime boundary tests.

---

### Task 1: Add Hook Boundary Regression

**Files:**
- Modify: `crates/chio-runtime/tests/runtime_boundary.rs`

- [x] **Step 1: Write the failing test**

Add `runtime_admission_hook_boundary_is_chio_owned`, which imports
`ChioRuntimeAdmissionHook` from `chio-runtime` and proves the public type name
resolves to the Chio runtime crate.

- [x] **Step 2: Run the red test**

Run:

```bash
cargo test -p chio-runtime runtime_admission_hook_boundary_is_chio_owned
```

Expected before implementation: FAIL because only
`ChiodosRuntimeAdmissionHook` is publicly available.

### Task 2: Implement Chio-Named Hook Wrapper

**Files:**
- Modify: `crates/chio-runtime/Cargo.toml`
- Modify: `crates/chio-runtime/src/lib.rs`

- [x] **Step 1: Add the kernel trait dependency**

Add `chio-kernel` so `chio-runtime` can implement the public
`RuntimeAdmissionHook` trait for the wrapper.

- [x] **Step 2: Replace the direct reexport**

Stop reexporting `ChiodosRuntimeAdmissionHook`. Add `ChioRuntimeAdmissionHook`
as a newtype wrapper with matching builder methods and a delegated
`RuntimeAdmissionHook` implementation.

### Task 3: Update Architecture Evidence

**Files:**
- Modify: `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`

- [x] **Step 1: Record the boundary change**

Update the architecture ledger and backlog evidence to state that the public
runtime hook is Chio-named while the implementation still delegates internally.

### Task 4: Verify

**Files:**
- All files touched above

- [x] **Step 1: Run focused tests**

Run:

```bash
cargo test -p chio-runtime
cargo test -p chio-cli --bin chio chiodos_runtime
```

- [x] **Step 2: Run focused lints and hygiene**

Run:

```bash
cargo clippy -p chio-runtime --all-targets -- -D warnings
cargo clippy -p chio-cli --bin chio -- -D warnings
cargo fmt --all -- --check
git diff --check
rg -n $'\xE2\x80\x94|\xE2\x80\x93' crates/chio-runtime/Cargo.toml crates/chio-runtime/src/lib.rs crates/chio-runtime/tests/runtime_boundary.rs docs/architecture/CHIO_FINAL_ARCHITECTURE.md docs/superpowers/plans/2026-05-19-chio-runtime-admission-hook-boundary.md
rg -n "ChiodosRuntimeAdmissionHook,|pub type ChioRuntimeAdmissionHook|ChioRuntimeAdmissionHook = chio_chiodos_runtime" crates/chio-runtime/src/lib.rs
```

Expected: all commands exit 0 except the dash scan and source leak scan exit 1
with no matches.
