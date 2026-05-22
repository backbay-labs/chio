# Chio Attest Buyer Data Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move public buyer attestation data types behind the `chio-attest-buyer` crate boundary instead of reexporting historical runtime types.

**Architecture:** Keep `chio-runtime-core` as the private verifier backend for this slice, but define the public buyer packet, review, lineage, bilateral invocation, and evidence manifest structs directly in `chio-attest-buyer`. Convert at the facade edge when delegating to historical verification, hashing, and report JSON helpers.

**Tech Stack:** Rust, serde derives, `chio-attest-buyer`, `chio-runtime-core`, `chio-cli` buyer and treaty dispatch tests.

---

### Task 1: Buyer Type Boundary Regression Tests

**Files:**
- Modify: `crates/chio-attest-buyer/tests/buyer_review.rs`

- [x] **Step 1: Write failing type-name and source-boundary tests**

Add:

```rust
#[test]
fn buyer_public_data_types_are_chio_owned() {
    assert_eq!(
        std::any::type_name::<chio_attest_buyer::BuyerAttestationPacket>(),
        "chio_attest_buyer::BuyerAttestationPacket"
    );
    assert_eq!(
        std::any::type_name::<chio_attest_buyer::BuyerAttestationReviewPackage>(),
        "chio_attest_buyer::BuyerAttestationReviewPackage"
    );
    assert_eq!(
        std::any::type_name::<chio_attest_buyer::ReceiptLineageStatement>(),
        "chio_attest_buyer::ReceiptLineageStatement"
    );
    assert_eq!(
        std::any::type_name::<chio_attest_buyer::BilateralInvocation>(),
        "chio_attest_buyer::BilateralInvocation"
    );
}

#[test]
fn buyer_boundary_does_not_reexport_historical_runtime_types() {
    let lib = include_str!("../src/lib.rs");
    assert!(!lib.contains("pub use chio_runtime_core::{"));
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-attest-buyer buyer_public_data_types -- --nocapture`

Expected: FAIL because the public type names still resolve to `chio_runtime_core::types::*`.

### Task 2: Define Chio-Owned Buyer Data Types

**Files:**
- Modify: `crates/chio-attest-buyer/Cargo.toml`
- Modify: `crates/chio-attest-buyer/src/lib.rs`

- [x] **Step 1: Add serde as a normal dependency**

Add `serde = { workspace = true }` to `[dependencies]`.

- [x] **Step 2: Replace historical data reexports with local structs and constants**

Define the public structs currently used by the buyer facade directly in `crates/chio-attest-buyer/src/lib.rs` with the same fields and derives:

```rust
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerAttestationPacket {
    pub schema: String,
    pub packet_id: String,
    pub buyer_id: String,
    pub capability_id: String,
    pub treaty_scope_sha256: String,
    pub ladder_intersection_sha256: String,
    pub cross_boundary_admission_report_sha256: String,
    pub continuation_sha256: String,
    pub receipt_lineage_statement_sha256: String,
    pub bilateral_invocation_sha256: String,
    pub bilateral_dsse_sha256: String,
    pub workflow_receipt_sha256: String,
    pub proof_package_sha256: String,
    pub verifier_report_sha256: String,
    pub budget_refs: Vec<String>,
    pub settlement_claimed: bool,
}
```

Repeat this pattern for the review package, review report, review source, review trust context, lineage, bilateral invocation, cross-kernel continuation, cross-boundary admission report, evidence ref, receipt lineage bundle, and runtime evidence manifest shapes.

- [x] **Step 3: Keep constants as Chio facade constants**

Replace historical constant reexports with local `pub const` aliases:

```rust
pub const CHIO_ATTEST_BUYER_ATTESTATION_PACKET_SCHEMA: &str =
    chio_runtime_core::CHIO_ATTEST_BUYER_ATTESTATION_PACKET_SCHEMA;
```

### Task 3: Convert at the Historical Backend Edge

**Files:**
- Modify: `crates/chio-attest-buyer/src/lib.rs`

- [x] **Step 1: Add conversion helpers**

Add private helpers such as:

```rust
fn historical_packet(packet: &BuyerAttestationPacket) -> chio_runtime_core::BuyerAttestationPacket {
    chio_runtime_core::BuyerAttestationPacket {
        schema: packet.schema.clone(),
        packet_id: packet.packet_id.clone(),
        buyer_id: packet.buyer_id.clone(),
        capability_id: packet.capability_id.clone(),
        treaty_scope_sha256: packet.treaty_scope_sha256.clone(),
        ladder_intersection_sha256: packet.ladder_intersection_sha256.clone(),
        cross_boundary_admission_report_sha256: packet.cross_boundary_admission_report_sha256.clone(),
        continuation_sha256: packet.continuation_sha256.clone(),
        receipt_lineage_statement_sha256: packet.receipt_lineage_statement_sha256.clone(),
        bilateral_invocation_sha256: packet.bilateral_invocation_sha256.clone(),
        bilateral_dsse_sha256: packet.bilateral_dsse_sha256.clone(),
        workflow_receipt_sha256: packet.workflow_receipt_sha256.clone(),
        proof_package_sha256: packet.proof_package_sha256.clone(),
        verifier_report_sha256: packet.verifier_report_sha256.clone(),
        budget_refs: packet.budget_refs.clone(),
        settlement_claimed: packet.settlement_claimed,
    }
}
```

Add matching conversions for the rest of the public buyer structs used by hashing, verification, and JSON emission.

- [x] **Step 2: Update parser and verifier functions**

Change public JSON parsers to parse local structs directly with serde and map JSON failures into `BuyerAttestationError`. Convert local inputs to historical inputs only inside the verifier and hash wrappers, then convert historical reports back into Chio-owned report structs.

- [x] **Step 3: Run the focused buyer tests**

Run: `cargo test -p chio-attest-buyer buyer_public_data_types -- --nocapture`

Expected: PASS.

### Task 4: Verification

**Files:**
- Test: `crates/chio-attest-buyer/tests/*.rs`
- Test through callers: `crates/chio-cli/src/cli/chio/dispatch/buyer.rs` and `crates/chio-cli/src/cli/chio/dispatch/treaty.rs`

- [x] **Step 1: Run buyer crate tests**

Run: `cargo test -p chio-attest-buyer`

Expected: PASS.

- [x] **Step 2: Run CLI buyer and treaty filters**

Run: `cargo test -p chio-cli --bin chio_buyer`

Expected: PASS.

Run: `cargo test -p chio-cli --bin chio_treaty`

Expected: PASS.

- [x] **Step 3: Run clippy checks**

Run: `cargo clippy -p chio-attest-buyer --all-targets -- -D warnings`

Expected: PASS.

Run: `cargo clippy -p chio-cli --bin chio -- -D warnings`

Expected: PASS.

- [x] **Step 4: Run hygiene checks**

Run: `cargo fmt --all -- --check`

Expected: PASS.

Run: `git diff --check`

Expected: PASS.

Run: `rg -n $'\xE2\x80\x94|\xE2\x80\x93' crates/chio-attest-buyer/src/lib.rs crates/chio-attest-buyer/tests/buyer_review.rs docs/superpowers/plans/2026-05-19-chio-attest-buyer-data-boundary.md docs/architecture/CHIO_FINAL_ARCHITECTURE.md`

Expected: no matches, exit 1.
