# Chio Runtime Active Namespace Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove stale historical runtime subject namespace text from active
Chio runtime dispatch tests.

**Architecture:** Active Chio runtime policy examples should use Chio-native
subject namespaces. Historical `chiodos.runtime` values belong only in
compatibility schemas, signed legacy fixtures, or historical runtime crate
tests.

**Tech Stack:** Rust CLI source guard tests and runtime dispatch test fixture.

---

### Task 1: Active Runtime Namespace Boundary

**Files:**
- Modify: `crates/chio-cli/src/main.rs`
- Modify: `crates/chio-cli/src/cli/chiodos/dispatch/runtime/admission.rs`
- Modify: `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`

- [x] **Step 1: Add failing active-surface guard**

Add a focused CLI test that scans the active runtime admission dispatch module
and rejects the historical `chiodos.runtime` subject namespace.

- [x] **Step 2: Run red**

Run: `cargo test -p chio-cli --bin chio chio_runtime_active_subject_namespaces_are_chio_native`

Expected: failure showing the active runtime admission dispatch still contains
the historical namespace.

- [x] **Step 3: Cut active fixture to Chio namespace**

Change the active runtime admission dispatch test policy fixture to use
`chio.runtime`.

- [x] **Step 4: Run green**

Run the focused CLI test and the existing Chio runtime CLI boundary test set.

- [x] **Step 5: Verify hygiene**

Run `cargo fmt --all -- --check`, `git diff --check`, and touched-file unicode
dash scans.
