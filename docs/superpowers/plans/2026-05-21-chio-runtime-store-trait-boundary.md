# Chio Runtime Store Trait Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move runtime admission input and store-trait ownership to the
Chio-named runtime facade.

**Architecture:** `chio-runtime` should expose Chio-owned admission input and
store traits while delegating to the historical runtime core internally. The
historical store implementations remain usable, but public admission
evaluation should not require callers to name historical runtime traits.

**Tech Stack:** Rust facade crate, focused source public-surface tests, CLI
runtime admission dispatch.

---

### Task 1: Chio Runtime Admission Store Boundary

**Files:**
- Modify: `crates/chio-runtime/tests/runtime_boundary.rs`
- Modify: `crates/chio-runtime/src/lib.rs`
- Modify: `crates/chio-cli/src/cli/chiodos/dispatch/runtime/admission.rs`
- Modify: `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`

- [x] **Step 1: Add failing public-surface test**

Add a runtime boundary test that rejects direct reexports of
`RuntimeAdmissionInput`, `RuntimeAdmissionStore`, and `RuntimeTrustFloorStore`
from the historical runtime crate, and requires Chio-owned replacements.

- [x] **Step 2: Run red**

Run: `cargo test -p chio-runtime --test runtime_boundary runtime_admission_store_boundary_is_chio_owned`

Expected: failure showing the current historical reexports.

- [x] **Step 3: Implement Chio-owned facade types**

Add `ChioRuntimeAdmissionInput`, `ChioRuntimeAdmissionStore`, and
`ChioRuntimeTrustFloorStore` in `crates/chio-runtime/src/lib.rs`. Use internal
adapters to call the historical runtime core while returning
`ChioRuntimeError` from the public facade.

- [x] **Step 4: Update CLI dispatch**

Change public runtime admission dispatch to use
`ChioRuntimeAdmissionInput` and `&dyn ChioRuntimeAdmissionStore`.

- [x] **Step 5: Run green**

Run focused runtime and CLI tests plus clippy on touched crates.

- [x] **Step 6: Verify hygiene**

Run `cargo fmt --all -- --check`, `git diff --check`, and touched-file unicode
dash scans.
