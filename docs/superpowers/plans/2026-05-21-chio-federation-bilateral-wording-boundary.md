# Chio Federation Bilateral Wording Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and superpowers:verification-before-completion. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove Chiodos wording from the production public Chio federation bilateral and pheromone gossip surfaces.

**Architecture:** `chio-federation` already exports Chio-named bilateral DSSE functions and verifier config types. Production documentation comments, private helper names, and user-facing error strings in those Chio modules should match that public boundary. Historical Chiodos wording may remain in compatibility tests and deprecated signed-artifact fixtures, but not in live production text.

**Tech Stack:** Rust integration tests, `chio-federation`, source-level public API guard tests, cargo test filters.

---

### Task 1: Add A Red Public-Surface Wording Guard

**Files:**
- Modify: `crates/chio-federation/tests/public_surface.rs`

- [x] **Step 1: Assert production bilateral modules do not expose Chiodos wording**

Add a test that scans the production portions of `bilateral.rs`,
`bilateral_dsse.rs`, `bilateral_verifier.rs`, and `pheromone_gossip.rs` and
fails on `Chiodos`, `CHIODOS`, or `chiodos`.

- [x] **Step 2: Run the focused test and verify red**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo test -p chio-federation --test public_surface chio_federation_bilateral_production_text_is_chio_named -- --nocapture
```

Expected: fail before implementation with production comments and error strings that still say Chiodos.

### Task 2: Rename Production Wording To Chio

**Files:**
- Modify: `crates/chio-federation/src/bilateral_dsse.rs`
- Modify: `crates/chio-federation/src/bilateral_verifier.rs`
- Modify: `crates/chio-federation/src/bilateral.rs`
- Modify: `crates/chio-federation/src/pheromone_gossip.rs`

- [x] **Step 1: Replace public documentation and error strings**

Change production documentation comments and verifier error strings from strict
Chiodos wording to strict Chio wording.

- [x] **Step 2: Rename private helper symbols**

Rename private helper symbols such as `validate_chiodos_predicate` so production
source no longer exposes Chiodos wording in the live Chio modules.

- [x] **Step 3: Preserve signed wire constants**

Do not change predicate type string values, payload types, or serialized field
names in this slice.

### Task 3: Verify

**Files:**
- All files above

- [x] **Step 1: Run focused federation tests**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo test -p chio-federation --test public_surface
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo test -p chio-federation bilateral
```

- [x] **Step 2: Run hygiene checks**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo clippy -p chio-federation --all-targets -- -D warnings
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo fmt --all -- --check
git diff --check
git diff --cached --check
rg -n $'\xE2\x80\x94|\xE2\x80\x93' docs/superpowers/plans/2026-05-21-chio-federation-bilateral-wording-boundary.md crates/chio-federation/src/bilateral.rs crates/chio-federation/src/bilateral_dsse.rs crates/chio-federation/src/bilateral_verifier.rs crates/chio-federation/src/pheromone_gossip.rs crates/chio-federation/tests/public_surface.rs docs/architecture/CHIO_FINAL_ARCHITECTURE.md
```

Expected: all pass, except the dash scan exits 1 with no output.
