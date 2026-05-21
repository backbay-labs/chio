# Chio Runtime Schema Ownership Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and superpowers:verification-before-completion. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `chio-runtime` own its public Chio runtime schema constants instead of reexporting them from the historical runtime crate.

**Architecture:** The runtime facade may still delegate data types and hardened implementations to `chio-chiodos-runtime` while the crate split continues, but public Chio schema IDs must be declared at the Chio runtime boundary. Historical runtime schema IDs remain compatibility inputs inside the historical implementation, not public Chio facade exports.

**Tech Stack:** Rust integration tests, `chio-runtime`, cargo test filters, source-level public API guard tests.

---

### Task 1: Add A Red Public-Surface Guard

**Files:**
- Modify: `crates/chio-runtime/tests/public_surface.rs`

- [x] **Step 1: Assert schema constants are not reexported from the historical crate**

Add a test that scans `../src/lib.rs` and fails if the `pub use chio_chiodos_runtime::{ ... }` facade block exports `CHIO_RUNTIME_*_SCHEMA`.

- [x] **Step 2: Run the focused test and verify red**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo test -p chio-runtime --test public_surface chio_runtime_schema_constants_are_owned_locally -- --nocapture
```

Expected: fail before implementation with the Chio runtime schema constants still present in the historical reexport block.

### Task 2: Move Public Constants To Chio Runtime

**Files:**
- Modify: `crates/chio-runtime/src/lib.rs`

- [x] **Step 1: Remove Chio schema constants from the historical reexport block**

Keep runtime structs, stores, and helper traits in the reexport block for now. Remove only the `CHIO_RUNTIME_*_SCHEMA` names.

- [x] **Step 2: Define local public Chio schema constants**

Add literal `pub const` definitions for each Chio runtime schema ID exposed by the facade.

- [x] **Step 3: Preserve implementation delegation**

Do not remove `chio-chiodos-runtime` dependency or historical implementation calls in this slice.

### Task 3: Verify

**Files:**
- All files above

- [x] **Step 1: Run focused runtime facade tests**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo test -p chio-runtime --test public_surface
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo test -p chio-runtime
```

- [x] **Step 2: Run hygiene checks**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo fmt --all -- --check
git diff --check
git diff --cached --check
rg -n 'CHIO_RUNTIME_[A-Z0-9_]+_SCHEMA' crates/chio-runtime/src/lib.rs
rg -n $'\xE2\x80\x94|\xE2\x80\x93' docs/superpowers/plans/2026-05-21-chio-runtime-schema-ownership.md crates/chio-runtime/src/lib.rs crates/chio-runtime/tests/public_surface.rs
```

Expected: runtime constants appear only in local `pub const` definitions, and the dash scan exits 1 with no output.
