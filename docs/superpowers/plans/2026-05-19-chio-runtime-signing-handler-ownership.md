# Chio Runtime Signing Handler Ownership Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make public `chio runtime` signing and peer-weight hash dispatch route through Chio-named runtime handlers while retaining Chiodos-named compatibility wrappers.

**Architecture:** This is a P1 command-ownership slice from `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`. It does not change signed runtime artifact bytes, schema IDs, canonical JSON, or hash behavior. It changes implementation ownership direction for the low-risk runtime signing/hash commands first.

**Tech Stack:** Rust, `chio-cli`, Clap parser tests, source-level CLI ownership regression.

---

### Task 1: Add Runtime Signing Dispatch Ownership Regression

**Files:**
- Modify: `crates/chio-cli/src/main.rs`
- Inspect: `crates/chio-cli/src/cli/dispatch.rs`

- [x] **Step 1: Write the failing test**

Add a test that reads `cli/dispatch.rs`, extracts `dispatch_chio_runtime_command`, and asserts it contains:

```rust
cmd_chio_runtime_sign_trust_input(
cmd_chio_runtime_sign_policy(
cmd_chio_runtime_peer_weights_hash(
cmd_chio_runtime_sign_peer_weights(
cmd_chio_runtime_sign_pheromone_query_report(
```

It must also assert the extracted body does not contain the matching old signing/hash handler names:

```rust
cmd_chiodos_runtime_sign_trust_input(
cmd_chiodos_runtime_sign_policy(
cmd_chiodos_runtime_peer_weights_hash(
cmd_chiodos_runtime_sign_peer_weights(
cmd_chiodos_runtime_sign_pheromone_query_report(
```

- [x] **Step 2: Verify red**

Run:

```bash
cargo test -p chio-cli chio_runtime_signing_dispatch_uses_chio_handlers --bin chio
```

Expected: fail because public runtime signing dispatch still calls `cmd_chiodos_runtime_*`.

### Task 2: Invert Runtime Signing Handler Ownership

**Files:**
- Modify: `crates/chio-cli/src/cli/chiodos/dispatch/runtime/signing.rs`
- Modify: `crates/chio-cli/src/cli/chiodos/dispatch/runtime.rs`
- Modify: `crates/chio-cli/src/cli/chiodos/dispatch.rs`
- Modify: `crates/chio-cli/src/cli/dispatch.rs`

- [x] **Step 1: Add Chio-named runtime signing/hash handlers**

Add these implementation owners:

```rust
cmd_chio_runtime_sign_trust_input
cmd_chio_runtime_sign_policy
cmd_chio_runtime_peer_weights_hash
cmd_chio_runtime_sign_peer_weights
cmd_chio_runtime_sign_pheromone_query_report
```

- [x] **Step 2: Delegate Chiodos compatibility wrappers**

Keep the existing `cmd_chiodos_runtime_*` signing/hash function names, but have them call the corresponding Chio-named implementation.

- [x] **Step 3: Route public runtime dispatch through Chio handlers**

Update `dispatch_chio_runtime_command` so the signing/hash arms call only the Chio-named handlers.

### Task 3: Verify

**Files:**
- All files touched above

- [x] **Step 1: Run focused tests**

Run:

```bash
cargo test -p chio-cli chio_runtime_signing_dispatch_uses_chio_handlers --bin chio
cargo test -p chio-cli chiodos_runtime_sign_trust_input_subcommand_parses --bin chio
```

- [x] **Step 2: Run focused lint and hygiene**

Run:

```bash
cargo clippy -p chio-cli --bin chio -- -D warnings
cargo fmt --all -- --check
git diff --check
rg -n "\x{2014}|\x{2013}" $(git diff --name-only --diff-filter=ACM) $(git ls-files --others --exclude-standard)
```
