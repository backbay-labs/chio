# Chio Attest Legacy Handler Ownership Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route Chio attest historical Chio verification through a Chio-named legacy handler while keeping `chio attest buyer verify-proof` as a hidden compatibility wrapper.

**Architecture:** `chio attest buyer verify-proof` is the explicit read-only historical verification surface. The hidden `chio attest verify` compatibility spelling may remain during migration, but public Chio attest dispatch must not call `cmd_chio_verify` directly. The byte-preserving verifier implementation remains unchanged.

**Tech Stack:** Rust, `chio-cli`, source-level dispatch ownership regression, focused parser tests.

---

### Task 1: Add Attest Legacy Dispatch Ownership Regression

**Files:**
- Modify: `crates/chio-cli/src/main.rs`
- Inspect: `crates/chio-cli/src/cli/dispatch.rs`

- [x] **Step 1: Write the failing test**

Add `chio_attest_legacy_dispatch_uses_chio_handler`. It extracts `dispatch_chio_attest_command`, asserts it contains `cmd_chio_attest_legacy_chio_v1_verify(`, and asserts it does not contain `cmd_chio_verify(`.

- [x] **Step 2: Verify red**

Run:

```bash
cargo test -p chio-cli chio_attest_legacy_dispatch_uses_chio_handler --bin chio
```

Expected: fail because Chio attest dispatch still calls `cmd_chio_verify`.

### Task 2: Invert Legacy Verifier Handler Ownership

**Files:**
- Modify: `crates/chio-cli/src/cli/chio/dispatch/verify.rs`
- Modify: `crates/chio-cli/src/cli/chio/dispatch.rs`
- Modify: `crates/chio-cli/src/cli/dispatch.rs`

- [x] **Step 1: Add Chio-named legacy verifier handler**

Add `cmd_chio_attest_legacy_chio_v1_verify` with the existing byte-preserving verification implementation.

- [x] **Step 2: Delegate hidden Chio wrapper**

Keep `cmd_chio_verify` and have it call the Chio-named legacy verifier.

- [x] **Step 3: Route Chio attest dispatch through Chio handler**

Update both hidden `chio attest verify` and explicit `chio attest buyer verify-proof` arms to call `cmd_chio_attest_legacy_chio_v1_verify`.

### Task 3: Verify

**Files:**
- All files touched above

- [x] **Step 1: Run focused tests**

Run:

```bash
cargo test -p chio-cli chio_attest_legacy_dispatch_uses_chio_handler --bin chio
cargo test -p chio-cli chio_attest_legacy_chio_v1_verify_surface_parses --bin chio
cargo test -p chio-cli legacy_chio_surface_is_hidden_from_root_help --bin chio
```

- [x] **Step 2: Run focused lint and hygiene**

Run:

```bash
cargo clippy -p chio-cli --bin chio -- -D warnings
cargo fmt --all -- --check
git diff --check
rg -n "\x{2014}|\x{2013}" $(git diff --name-only --diff-filter=ACM) $(git ls-files --others --exclude-standard)
```
