# Chio Federation Handler Ownership Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make public `chio federation ...` dispatch route through Chio-named federation handlers while hidden Chio federation commands delegate for compatibility.

**Architecture:** This is a P1 command-ownership slice from `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`. It does not change signed federation artifact bytes or schema IDs; it changes ownership direction so the public Chio federation path no longer calls `cmd_chio_*` handlers directly.

**Tech Stack:** Rust, `chio-cli`, Clap parser tests, source-level CLI ownership regression.

---

### Task 1: Add Public Dispatch Ownership Regression

**Files:**
- Modify: `crates/chio-cli/src/main.rs`
- Inspect: `crates/chio-cli/src/cli/dispatch.rs`

- [x] **Step 1: Write the failing test**

Add a test that reads `cli/dispatch.rs`, extracts the body of `dispatch_chio_treaty_command`, and asserts:

```rust
assert!(body.contains("cmd_chio_federation_treaty_intersect("));
assert!(body.contains("cmd_chio_federation_treaty_admit("));
assert!(body.contains("cmd_chio_federation_treaty_verify_packet("));
assert!(!body.contains("cmd_chio_treaty_"));
```

- [x] **Step 2: Run red**

Run:

```bash
cargo test -p chio-cli chio_federation_treaty_dispatch_uses_chio_handlers --bin chio
```

Expected: fail because `dispatch_chio_treaty_command` currently calls `cmd_chio_treaty_*`.

### Task 2: Invert Treaty Handler Ownership

**Files:**
- Modify: `crates/chio-cli/src/cli/chio/dispatch/treaty.rs`
- Modify: `crates/chio-cli/src/cli/chio/dispatch.rs`
- Modify: `crates/chio-cli/src/cli/dispatch.rs`

- [x] **Step 1: Add Chio-named treaty handlers**

Add `cmd_chio_federation_treaty_intersect`, `cmd_chio_federation_treaty_admit`, and `cmd_chio_federation_treaty_verify_packet` with the existing implementation bodies.

- [x] **Step 2: Delegate hidden Chio handlers**

Keep `cmd_chio_treaty_intersect`, `cmd_chio_treaty_admit`, and `cmd_chio_treaty_verify_packet`, but make them call the corresponding Chio-named function.

- [x] **Step 3: Route public dispatch through Chio handlers**

Update `dispatch_chio_treaty_command` so public `chio federation treaty ...` calls only `cmd_chio_federation_treaty_*`.

### Task 3: Verify

**Files:**
- All files touched above

- [x] **Step 1: Run focused tests**

Run:

```bash
cargo test -p chio-cli chio_federation_treaty_dispatch_uses_chio_handlers --bin chio
cargo test -p chio-cli chio_treaty_verify_packet_subcommand_parses --bin chio
```

- [x] **Step 2: Run focused lint and hygiene**

Run:

```bash
cargo clippy -p chio-cli --bin chio -- -D warnings
cargo fmt --all -- --check
git diff --check
rg -n "\x{2014}|\x{2013}" $(git diff --name-only --diff-filter=ACM) $(git ls-files --others --exclude-standard)
```

### Task 4: Invert Federation Authority Handler Ownership

**Files:**
- Modify: `crates/chio-cli/src/main.rs`
- Modify: `crates/chio-cli/src/cli/chio/dispatch/authority.rs`
- Modify: `crates/chio-cli/src/cli/chio/dispatch.rs`
- Modify: `crates/chio-cli/src/cli/dispatch.rs`

- [x] **Step 1: Write the failing authority dispatch ownership test**

Add a test that reads `cli/dispatch.rs`, extracts `dispatch_chio_authority_command`, and asserts it contains:

```rust
cmd_chio_federation_authority_issue(
cmd_chio_federation_authority_checkpoint(
cmd_chio_federation_authority_trust_bundle_assemble(
```

It must also assert the extracted body does not contain `cmd_chio_authority_`.

- [x] **Step 2: Verify red**

Run:

```bash
cargo test -p chio-cli chio_federation_authority_dispatch_uses_chio_handlers --bin chio
```

Expected: fail because public authority dispatch still calls `cmd_chio_authority_*`.

- [x] **Step 3: Add Chio-named authority handlers and compatibility wrappers**

Add `cmd_chio_federation_authority_issue`, `cmd_chio_federation_authority_checkpoint`, and `cmd_chio_federation_authority_trust_bundle_assemble` as implementation owners. Keep `cmd_chio_authority_*` wrappers and have them delegate.

- [x] **Step 4: Route public dispatch through Chio handlers**

Update `dispatch_chio_authority_command` to call only `cmd_chio_federation_authority_*`, and add a hidden Chio authority dispatcher that calls the compatibility wrappers.

- [x] **Step 5: Verify green**

Run:

```bash
cargo test -p chio-cli chio_federation_authority_dispatch_uses_chio_handlers --bin chio
cargo test -p chio-cli chio_authority_issue_subcommand_parses --bin chio
```

- [x] **Step 6: Re-run lint and hygiene after the authority cutover**

Run:

```bash
cargo clippy -p chio-cli --bin chio -- -D warnings
cargo fmt --all -- --check
git diff --check
rg -n "\x{2014}|\x{2013}" $(git diff --name-only --diff-filter=ACM) $(git ls-files --others --exclude-standard)
```
