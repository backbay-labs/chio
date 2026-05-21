# Chio Attest Buyer Error Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop `chio-attest-buyer` from exposing `ChiodosRuntimeError` through its public buyer proof API.

**Architecture:** `chio-attest-buyer` still delegates to the hardened historical buyer core while the crate split continues, but callers should see a Chio-owned error type and Chio-owned fallible helper functions. Historical runtime errors are implementation detail behind the boundary.

**Tech Stack:** Rust workspace crate `chio-attest-buyer`, existing buyer packet and full-review tests, focused CLI parser coverage.

---

### Task 1: Add Error Boundary Regression

**Files:**
- Modify: `crates/chio-attest-buyer/tests/buyer_review.rs`

- [x] **Step 1: Write the failing test**

Add `buyer_error_boundary_is_chio_owned`, which proves the public error type is
`chio_attest_buyer::BuyerAttestationError` and that a fallible public parser
preserves the existing error code through that Chio-owned type.

- [x] **Step 2: Run the red test**

Run:

```bash
cargo test -p chio-attest-buyer buyer_error_boundary_is_chio_owned
```

Expected before implementation: FAIL because `BuyerAttestationError` is still a
type alias for `chio_chiodos_runtime::error::ChiodosRuntimeError`.

### Task 2: Implement Opaque Chio Error Boundary

**Files:**
- Modify: `crates/chio-attest-buyer/src/lib.rs`

- [x] **Step 1: Replace the alias**

Replace `pub type BuyerAttestationError = ChiodosRuntimeError` with an opaque
public `BuyerAttestationError` struct that keeps the historical error private
and exposes a stable `code()` accessor.

- [x] **Step 2: Wrap fallible public helpers**

Stop reexporting fallible historical helper functions directly. Add local
wrappers for buyer JSON parsing, report serialization, hash helpers, packet
verification, review verification, trust-context verification, and receipt
lineage verification. Each wrapper converts the historical runtime error into
`BuyerAttestationError`.

### Task 3: Update Architecture Evidence

**Files:**
- Modify: `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`

- [x] **Step 1: Record the boundary change**

Update the architecture ledger and backlog evidence to state that fallible
buyer helper APIs now expose `BuyerAttestationError`, while reexported buyer
data types remain a later cutover item.

### Task 4: Verify

**Files:**
- All files touched above

- [x] **Step 1: Run focused tests**

Run:

```bash
cargo test -p chio-attest-buyer
cargo test -p chio-cli --bin chio chio_attest_buyer
```

- [x] **Step 2: Run focused lints and hygiene**

Run:

```bash
cargo clippy -p chio-attest-buyer --all-targets -- -D warnings
cargo clippy -p chio-cli --bin chio -- -D warnings
cargo fmt --all -- --check
git diff --check
rg -n $'\xE2\x80\x94|\xE2\x80\x93' crates/chio-attest-buyer/src/lib.rs crates/chio-attest-buyer/tests/buyer_review.rs docs/architecture/CHIO_FINAL_ARCHITECTURE.md docs/superpowers/plans/2026-05-19-chio-attest-buyer-error-boundary.md
rg -n "pub type BuyerAttestationError|ChiodosRuntimeError,|verify_buyer_attestation_packet,|buyer_attestation_packet_from_json," crates/chio-attest-buyer/src/lib.rs
```

Expected: all commands exit 0 except the dash scan and source leak scan exit 1
with no matches.
