# Chio Pheromone Core Relay Handler Ownership Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make public `chio pheromone relay` core commands route through Chio-named relay handlers while retaining Chiodos-named compatibility wrappers.

**Architecture:** This is a P1 command-ownership slice from `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`. It covers core relay commands only: lint, serve, enqueue, tick, catchup, status, observe, metrics, and trend. Alert, delivery, assurance, directory, and supervisor relay subcommands remain separate follow-up work.

**Tech Stack:** Rust, `chio-cli`, source-level CLI ownership regression, focused parser and clippy gates.

---

### Task 1: Add Core Relay Dispatch Ownership Regression

**Files:**
- Modify: `crates/chio-cli/src/main.rs`
- Inspect: `crates/chio-cli/src/cli/dispatch.rs`

- [x] **Step 1: Write the failing test**

Add a test that extracts `dispatch_chio_pheromone_command` and asserts public core relay arms contain the Chio-named handlers:

```rust
cmd_chio_pheromone_relay_lint(
cmd_chio_pheromone_relay_serve(
cmd_chio_pheromone_relay_enqueue(
cmd_chio_pheromone_relay_tick(
cmd_chio_pheromone_relay_catchup(
cmd_chio_pheromone_relay_status(
cmd_chio_pheromone_relay_observe(
cmd_chio_pheromone_relay_metrics(
cmd_chio_pheromone_relay_trend(
```

It must also assert the extracted body does not contain those specific old core handler names.

- [x] **Step 2: Verify red**

Run:

```bash
cargo test -p chio-cli chio_pheromone_core_relay_dispatch_uses_chio_handlers --bin chio
```

Expected: fail because the public core relay arms still call Chiodos-named handlers.

### Task 2: Invert Core Relay Handler Ownership

**Files:**
- Modify: `crates/chio-cli/src/cli/chiodos/dispatch/pheromone/relay.rs`
- Modify: `crates/chio-cli/src/cli/chiodos/dispatch/pheromone.rs`
- Modify: `crates/chio-cli/src/cli/chiodos/dispatch.rs`
- Modify: `crates/chio-cli/src/cli/dispatch.rs`

- [x] **Step 1: Add Chio-named core relay handlers**

Move implementation ownership to `cmd_chio_pheromone_relay_*` for the nine core relay commands.

- [x] **Step 2: Delegate Chiodos compatibility wrappers**

Keep old `cmd_chiodos_pheromone_relay_*` core function names as delegates.

- [x] **Step 3: Route public dispatch through Chio handlers**

Update public `dispatch_chio_pheromone_command` core relay arms to call Chio-named handlers.

### Task 3: Verify

**Files:**
- All files touched above

- [x] **Step 1: Run focused tests**

Run:

```bash
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
