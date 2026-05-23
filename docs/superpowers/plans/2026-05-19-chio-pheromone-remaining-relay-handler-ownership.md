# Chio Pheromone Remaining Relay Handler Ownership Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make public `chio pheromone relay` alert, delivery, assurance, directory, and supervisor subcommands route through Chio-named handlers while retaining hidden Chio compatibility wrappers.

**Architecture:** This completes the P1 relay command-ownership cutover left after the core relay slice. Public dispatch must call Chio-named handlers; old Chio-named functions remain only as hidden compatibility wrappers that delegate to the Chio implementations. No signed artifact bytes, schemas, relay authorization logic, or report contents should change beyond user-facing Chio labels.

**Tech Stack:** Rust, `chio-cli`, source-level CLI ownership regression, focused parser and clippy gates.

---

### Task 1: Add Remaining Relay Dispatch Ownership Regression

**Files:**
- Modify: `crates/chio-cli/src/main.rs`
- Inspect: `crates/chio-cli/src/cli/dispatch.rs`

- [x] **Step 1: Write the failing test**

Add `chio_pheromone_remaining_relay_dispatch_uses_chio_handlers`. It extracts `dispatch_chio_pheromone_command` from `cli/dispatch.rs`, asserts the public body contains Chio-named handlers for:

```rust
cmd_chio_pheromone_relay_alert_evaluate(
cmd_chio_pheromone_relay_alert_handoff(
cmd_chio_pheromone_relay_alert_normalize(
cmd_chio_pheromone_relay_alert_review(
cmd_chio_pheromone_relay_alert_delivery_import(
cmd_chio_pheromone_relay_alert_delivery_acknowledge(
cmd_chio_pheromone_relay_alert_delivery_drift(
cmd_chio_pheromone_relay_alert_delivery_drift_window(
cmd_chio_pheromone_relay_alert_assurance_package(
cmd_chio_pheromone_relay_alert_assurance_export(
cmd_chio_pheromone_relay_alert_assurance_verify(
cmd_chio_pheromone_relay_alert_assurance_replay(
cmd_chio_pheromone_relay_alert_assurance_retention_plan(
cmd_chio_pheromone_relay_alert_assurance_recovery_drill(
cmd_chio_pheromone_relay_alert_assurance_archive_plan(
cmd_chio_pheromone_relay_alert_assurance_closeout_review(
cmd_chio_pheromone_relay_directory_inspect(
cmd_chio_pheromone_relay_directory_promote(
cmd_chio_pheromone_relay_directory_reject(
cmd_chio_pheromone_relay_supervisor_lint(
```

It also asserts the extracted public body does not contain the matching `cmd_chio_*` names.

- [x] **Step 2: Verify red**

Run:

```bash
cargo test -p chio-cli chio_pheromone_remaining_relay_dispatch_uses_chio_handlers --bin chio
```

Expected: fail because the public remaining relay arms still call Chio-named handlers.

### Task 2: Invert Remaining Relay Handler Ownership

**Files:**
- Modify: `crates/chio-cli/src/cli/chio/dispatch/pheromone/alerts.rs`
- Modify: `crates/chio-cli/src/cli/chio/dispatch/pheromone/delivery.rs`
- Modify: `crates/chio-cli/src/cli/chio/dispatch/pheromone/assurance.rs`
- Modify: `crates/chio-cli/src/cli/chio/dispatch/pheromone/directory.rs`
- Modify: `crates/chio-cli/src/cli/chio/dispatch/pheromone.rs`
- Modify: `crates/chio-cli/src/cli/chio/dispatch.rs`
- Modify: `crates/chio-cli/src/cli/dispatch.rs`

- [x] **Step 1: Add Chio-named implementation owners**

For every handler listed in Task 1, move implementation ownership to `cmd_chio_*`.

- [x] **Step 2: Delegate Chio compatibility wrappers**

Keep old `cmd_chio_*` function names with the same signatures and have them call the matching Chio-named implementation.

- [x] **Step 3: Route public dispatch through Chio handlers**

Update `dispatch_chio_pheromone_command` so every remaining relay arm calls a Chio-named handler.

- [x] **Step 4: Route hidden relay compatibility through Chio wrappers**

Update `dispatch_chio_pheromone_relay_command` so every remaining relay arm calls the matching Chio wrapper.

### Task 3: Verify

**Files:**
- All files touched above

- [x] **Step 1: Run focused tests**

Run:

```bash
cargo test -p chio-cli chio_pheromone_remaining_relay_dispatch_uses_chio_handlers --bin chio
cargo test -p chio-cli chio_pheromone_core_relay_dispatch_uses_chio_handlers --bin chio
cargo test -p chio-cli chio_native_pheromone_surface_parses --bin chio
```

- [x] **Step 2: Run focused lint and hygiene**

Run:

```bash
cargo clippy -p chio-cli --bin chio -- -D warnings
cargo fmt --all -- --check
git diff --check
rg -n "\x{2014}|\x{2013}" $(git diff --name-only --diff-filter=ACM) $(git ls-files --others --exclude-standard)
```
