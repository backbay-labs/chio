# Chio Attest Buyer Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce `chio-attest-buyer` as the public buyer attestation boundary and invert CLI dispatch so Chio-native buyer commands own the path while hidden Chio compatibility delegates to them.

**Architecture:** This is the first extraction slice, not the final schema cutover. `chio-attest-buyer` owns the public verification API and currently bridges to the proven historical buyer core so strict DSSE semantics are preserved. CLI code should route `chio attest buyer ...` to Chio-named handlers; the hidden `chio attest buyer ...` path may delegate to those handlers for compatibility.

**Tech Stack:** Rust workspace crate, `chio-cli`, `chio-runtime-core`, `serde_json`, existing buyer review fixtures and tests.

---

### Task 1: Add Buyer Boundary Regression

**Files:**
- Create: `crates/chio-attest-buyer/Cargo.toml`
- Create: `crates/chio-attest-buyer/src/lib.rs`
- Create: `crates/chio-attest-buyer/tests/buyer_packet.rs`
- Modify: `Cargo.toml`

- [x] **Step 1: Write the failing boundary test**

Create a test that imports `chio_attest_buyer::verify_buyer_attestation_packet` and proves hash-only packet verification stays unresolved without hydrated DSSE.

- [x] **Step 2: Run the red test**

Run:

```bash
cargo test -p chio-attest-buyer buyer_packet_without_hydrated_dsse_is_unresolved
```

Expected: fail before implementation because the new buyer boundary crate/API is not implemented.

### Task 2: Implement the Boundary Crate

**Files:**
- Modify: `crates/chio-attest-buyer/Cargo.toml`
- Modify: `crates/chio-attest-buyer/src/lib.rs`

- [x] **Step 1: Expose the public buyer verification API**

Export the buyer packet/review functions, buyer artifact/report types, JSON helpers, and schema constants through `chio-attest-buyer`.

- [x] **Step 2: Keep `chio-attest-verify` out of buyer proof**

Run:

```bash
rg -n "chio_attest_buyer|BuyerAttestation" crates/chio-attest-verify
```

Expected: no matches.

### Task 3: Invert CLI Buyer Dispatch

**Files:**
- Modify: `crates/chio-cli/Cargo.toml`
- Modify: `crates/chio-cli/src/cli/dispatch.rs`
- Modify: `crates/chio-cli/src/cli/chio/dispatch/buyer.rs`

- [x] **Step 1: Add `chio-attest-buyer` to CLI dependencies**

`crates/chio-cli/Cargo.toml` should depend on the new crate.

- [x] **Step 2: Add Chio-named buyer command handlers**

Add `cmd_chio_attest_buyer_package`, `cmd_chio_attest_buyer_verify`, `cmd_chio_attest_buyer_explain`, and `cmd_chio_attest_buyer_verify_packet` as the native handler names.

- [x] **Step 3: Delegate hidden Chio buyer handlers to Chio handlers**

Keep the hidden compatibility functions, but make them call the Chio-native functions rather than the public Chio command path calling `cmd_chio_*`.

### Task 4: Verify

**Files:**
- All files touched above

- [x] **Step 1: Run focused tests**

Run:

```bash
cargo test -p chio-attest-buyer
cargo test -p chio-cli chio_attest_buyer --bin chio
```

- [x] **Step 2: Run focused lints and hygiene**

Run:

```bash
cargo clippy -p chio-attest-buyer --all-targets -- -D warnings
cargo clippy -p chio-cli --bin chio -- -D warnings
cargo fmt --all -- --check
git diff --check
rg -n "\x{2014}|\x{2013}" $(git diff --name-only --diff-filter=ACM)
```
