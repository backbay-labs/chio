# Chio Runtime Command Handler Ownership Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make public `chio runtime ...` dispatch route only through Chio-named runtime handlers while hidden Chio runtime commands remain compatibility delegates.

**Architecture:** This completes the P1 runtime command-ownership slice from `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`. The patch must not change runtime artifact bytes, schema constants, canonical hash behavior, admission logic, orchestration state transitions, or loopback harness behavior.

**Tech Stack:** Rust, `chio-cli`, Clap parser tests, source-level CLI ownership regression.

---

### Task 1: Add Full Runtime Dispatch Ownership Regression

**Files:**
- Modify: `crates/chio-cli/src/main.rs`
- Inspect: `crates/chio-cli/src/cli/dispatch.rs`

- [x] **Step 1: Write the failing test**

Add a test that extracts `dispatch_chio_runtime_command` from `cli/dispatch.rs` and asserts the public dispatch body does not contain `cmd_chio_runtime_`.

- [x] **Step 2: Verify red**

Run:

```bash
cargo test -p chio-cli chio_runtime_dispatch_uses_only_chio_handlers --bin chio
```

Expected: fail because admission, pheromone evaluate, orchestration, ops, and loopback still call Chio-named handlers.

### Task 2: Invert Remaining Runtime Handler Ownership

**Files:**
- Modify: `crates/chio-cli/src/cli/chio/dispatch/runtime/admission.rs`
- Modify: `crates/chio-cli/src/cli/chio/dispatch/runtime/orchestration.rs`
- Modify: `crates/chio-cli/src/cli/chio/dispatch/runtime/ops.rs`
- Modify: `crates/chio-cli/src/cli/chio/dispatch/runtime/loopback.rs`
- Modify: `crates/chio-cli/src/cli/chio/dispatch/runtime.rs`
- Modify: `crates/chio-cli/src/cli/chio/dispatch.rs`
- Modify: `crates/chio-cli/src/cli/dispatch.rs`

- [x] **Step 1: Add Chio-named implementation owners**

Add Chio-named handlers for runtime admission, pheromone evaluation, orchestration, ops, retention, and loopback.

- [x] **Step 2: Delegate Chio compatibility wrappers**

Keep the existing `cmd_chio_runtime_*` function names and have them call the matching Chio implementation.

- [x] **Step 3: Route public runtime dispatch through Chio handlers**

Update `dispatch_chio_runtime_command` so every arm calls a Chio-named handler.

- [x] **Step 4: Route hidden runtime dispatch through Chio wrappers**

Update `dispatch_chio_runtime_command` so hidden compatibility commands call Chio-named wrappers for all runtime arms.

### Task 3: Verify

**Files:**
- All files touched above

- [x] **Step 1: Run focused tests**

Run:

```bash
cargo test -p chio-cli chio_runtime_dispatch_uses_only_chio_handlers --bin chio
cargo test -p chio-cli chio_runtime_signing_dispatch_uses_chio_handlers --bin chio
cargo test -p chio-cli chio_runtime_sign_trust_input_subcommand_parses --bin chio
```

- [x] **Step 2: Run focused lint and hygiene**

Run:

```bash
cargo clippy -p chio-cli --bin chio -- -D warnings
cargo fmt --all -- --check
git diff --check
rg -n "\x{2014}|\x{2013}" $(git diff --name-only --diff-filter=ACM) $(git ls-files --others --exclude-standard)
```
