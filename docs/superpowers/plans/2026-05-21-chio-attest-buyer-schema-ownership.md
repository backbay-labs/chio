# Chio Attest Buyer Schema Ownership Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and superpowers:verification-before-completion. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `chio-attest-buyer` own its public Chio schema constants instead of aliasing them from the historical runtime crate.

**Architecture:** The public buyer attestation crate may still delegate strict DSSE verification to the hardened historical verifier core, but public Chio schema IDs must be owned at the Chio buyer boundary. Historical runtime shapes should remain private conversion targets, not public schema constant sources.

**Tech Stack:** Rust integration tests, `chio-attest-buyer`, cargo test filters, source-level public API guard tests.

---

### Task 1: Add A Red Public-Surface Guard

**Files:**
- Modify: `crates/chio-attest-buyer/tests/public_surface.rs`

- [x] **Step 1: Assert Chio schema constants are not runtime aliases**

Add a test that scans `../src/lib.rs` and fails when a public schema constant is initialized from `chio_runtime_core::`.

- [x] **Step 2: Run the focused test and verify red**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo test -p chio-attest-buyer --test public_surface chio_attest_buyer_schema_constants_are_owned_locally -- --nocapture
```

Expected: fail before implementation with lines showing `chio_runtime_core::CHIO_*_SCHEMA`.

### Task 2: Move Public Constants To Chio Attest Buyer

**Files:**
- Modify: `crates/chio-attest-buyer/src/lib.rs`

- [x] **Step 1: Replace public schema aliases with literal Chio IDs**

Define the public `CHIO_ATTEST_BUYER_*` and `CHIO_FEDERATION_*` constants as string literals in `chio-attest-buyer`.

- [x] **Step 2: Keep historical verifier delegation unchanged**

Do not remove the `chio-runtime-core` dependency in this slice; strict DSSE and full-review replay still delegate to the historical verifier core.

### Task 3: Verify

**Files:**
- All files above

- [x] **Step 1: Run focused public-surface and buyer tests**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo test -p chio-attest-buyer --test public_surface
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo test -p chio-attest-buyer
```

- [x] **Step 2: Run hygiene checks**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo fmt --all -- --check
git diff --check
git diff --cached --check
rg -n 'pub const CHIO_[A-Z0-9_]+_SCHEMA: &str =\s*chio_runtime_core::' crates/chio-attest-buyer/src/lib.rs
rg -n $'\xE2\x80\x94|\xE2\x80\x93' docs/superpowers/plans/2026-05-21-chio-attest-buyer-schema-ownership.md crates/chio-attest-buyer/src/lib.rs crates/chio-attest-buyer/tests/public_surface.rs
```

Expected: all pass, except both `rg` checks exit 1 with no output.
