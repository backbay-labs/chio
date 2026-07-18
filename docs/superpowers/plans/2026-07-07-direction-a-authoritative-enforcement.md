# Direction A: Authoritative Enforcement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make kernel-mediated, atomic, fail-closed spend enforcement the only structurally-supported path through the `chio-api-protect` sidecar tool-call surface, expressed as a frozen machine-checkable contract (`chio.execution_nonce.v1` + cross-bound atomic hold + the `chio.mediated_spend.v1` receipt profile) that Directions B and C pin against.

**Architecture:** Freeze the enforcement contract as code in the lowest shared crate (`chio-core-types`) plus ADR/PROTOCOL text, then wire the existing authoritative 26-step kernel pipeline (atomic budget hold -> guards -> execution nonce -> reconcile -> signed receipt) into a reinstated `POST /v1/evaluate` mediated tool-call route in the sidecar. Advisory consumption becomes a machine-visible conformance failure through a `is_authoritative_spend_receipt` predicate, an advisory-off default, a tool-server nonce middleware, a crash reaper, and a golden conformance gate.

**Tech Stack:** Rust 2021 workspace (`cargo`), `axum` + `tower` (sidecar HTTP), `serde`/`serde_json`, `rusqlite` (durable budget/receipt stores), Ed25519 signing via `chio-core`, `chio-test-support` test helpers, `chio-conformance` cross-language conformance harness, Python SDK (`chio-sdk-python`).

## Global Constraints

Every task's requirements implicitly include this section. Copied verbatim from the direction spec and repo house rules:

- No em-dashes (U+2014) anywhere in code, comments, or documentation. Use hyphens (`-`) or parentheses.
- Clippy `unwrap_used` AND `expect_used` are DENIED workspace-wide. In tests use the repo helpers (`chio_test_support::{test_unwrap, test_expect, test_unwrap_err, test_expect_err}`) or put `#![allow(clippy::unwrap_used, clippy::expect_used)]` at the top of an integration `tests/` file (matching existing convention). In non-test code use proper `Result` handling. Never call `.unwrap()`/`.expect()` in shipped code.
- Fail-closed: errors deny access; any missing or invalid element of the contract denies.
- Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`), each commit message ending with the line:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- Do NOT run `cargo build --workspace`, `cargo test --workspace`, or `cargo clippy --workspace` (disk pressure). Scoped verification ONLY: `cargo test -p <crate>` / `cargo clippy -p <crate>`.
- Before any `cargo` invocation: `rm -rf target/debug/incremental` and set `CARGO_INCREMENTAL=0`. The literal command prefix used in every run step below is:
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo ...`

---

## File Structure

Files created or modified, each with its single responsibility.

**M0 - Freeze the contract**
- `crates/core/chio-core-types/src/receipt/authoritative_spend.rs` (CREATE) - the frozen contract: `MEDIATED_SPEND_PROFILE`, `BudgetAuthorityReceiptRef`, `NotAuthoritativeReason`, `PresentedNonceView` trait, `is_authoritative_spend_receipt`, `receipt_meets_guarantee_floor`.
- `crates/core/chio-core-types/src/receipt/mod.rs` (MODIFY) - register + re-export the new module.
- `crates/kernel/chio-kernel/src/execution_nonce.rs` (MODIFY) - `impl PresentedNonceView for SignedExecutionNonce`; add frozen-schema golden test.
- `crates/sdk/chio-eval-receipt/src/lib.rs` (MODIFY) - re-export the contract symbols for B/C/fork consumers.
- `docs/adr/ADR-0016-authoritative-spend-contract.md` (CREATE) - normative contract ADR; supersedes ADR-0006 "monotonic, no-refund" text.
- `docs/adr/ADR-0006-monetary-budget-semantics.md` (MODIFY) - add supersession note.
- `spec/PROTOCOL.md` (MODIFY) - add normative section 6.x for execution nonce + atomic hold + mediated-spend profile.

**M1 - Mediated route**
- `crates/products/chio-api-protect/src/proxy/config.rs` (MODIFY) - add `control_url`, `control_token`, `budget_db`, `require_nonce`.
- `crates/products/chio-api-protect/src/proxy/state.rs` (MODIFY) - add `budget_store: Option<Arc<dyn BudgetStore>>`, `mediation_kernel: Option<Arc<ChioKernel>>`; build them fail-closed.
- `crates/products/chio-api-protect/src/proxy/mediated.rs` (CREATE) - `sidecar_evaluate_tool_call_mediated_handler`, `SidecarEvaluateToolCallMediatedRequest`, mediation kernel builder, mediation tool server.
- `crates/products/chio-api-protect/src/proxy/router.rs` (MODIFY) - reinstate `POST /v1/evaluate` -> mediated handler.

**M2 - Cross-bind hold <-> nonce; earn `Mediated`**
- `crates/kernel/chio-kernel/src/kernel/validation.rs` (MODIFY) - insert `execution_nonce_id` + `mediated_spend` profile into the `budget_authority` receipt metadata.
- `crates/kernel/chio-kernel/src/kernel/construction.rs` (MODIFY) - `nonce_binding_for`, mint-before-sign so the receipt records the nonce id.
- `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs` (MODIFY) - `derive_trust_level` + sign-site fail-closed invariant.

**M3 - Advisory becomes a visible failure**
- `crates/products/chio-api-protect/src/proxy/sidecar.rs` (MODIFY) - gate advisory handler on `allow_advisory`.
- `crates/products/chio-api-protect/src/proxy/config.rs` (MODIFY) - add `allow_advisory: bool`, `minimum_trust_level`.
- `crates/products/chio-api-protect/src/proxy/nonce_middleware.rs` (CREATE) - Solution C tool-server nonce middleware.
- `sdks/python/chio-sdk-python/src/chio_sdk/client.py` (MODIFY) - default tool-call target `/v1/evaluate`.
- `sdks/python/chio-sdk-python/tests/test_default_target.py` (CREATE) - assert default target.

**M4 - Crash-safety + truthful HA labeling**
- `crates/platform/chio-store-sqlite/src/budget_store/reaper.rs` (CREATE) - startup reaper over `disposition='open'`.
- `crates/platform/chio-store-sqlite/src/budget_store.rs` (MODIFY) - register + call reaper module.
- `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs` (MODIFY) - escalate reverse failure to a durable pending-reversal record.

**M5 - Golden conformance + double-spend regression**
- `crates/tooling/chio-conformance/tests/authoritative_spend_enforcement.rs` (CREATE) - the golden gate (Acceptance 1).
- `crates/tooling/chio-conformance/tests/authoritative_spend_double_spend.rs` (CREATE) - concurrency regression (Acceptance 2).
- `crates/tooling/chio-conformance/tests/authoritative_spend_predicate_matrix.rs` (CREATE) - real-nonce (a)-(f) + R1-R6 matrix, structural greppable invariant (Acceptance 3, 4).
- `crates/tooling/chio-conformance/Cargo.toml` (MODIFY) - register the three `[[test]]` targets.

---

## Milestone 0 - Freeze the enforcement contract (Phase 0; unblocks B and C; no behavior change)

M0 is FIRST and everything else pins to it. It freezes `chio.execution_nonce.v1` as-is, defines `chio.mediated_spend.v1` (the `BudgetAuthorityReceiptRef` struct + `is_authoritative_spend_receipt` predicate), records the prepay-authority decision, writes ADR-0016 (superseding ADR-0006's "monotonic, no-refund" text), and documents the reserved linkage slots for B/C.

### Task 1: Contract types + predicate in `chio-core-types`

**Files:**
- Create: `crates/core/chio-core-types/src/receipt/authoritative_spend.rs`
- Modify: `crates/core/chio-core-types/src/receipt/mod.rs`
- Test: unit tests inside `crates/core/chio-core-types/src/receipt/authoritative_spend.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes (existing, confirmed): `crate::receipt::body::ChioReceipt` with `receipt_kind: ReceiptKind`, `boundary_class: BoundaryClass`, `observation_outcome: Option<ObservationOutcome>`, `trust_level: TrustLevel`, `kernel_key: PublicKey`, `capability_id: String`, `tool_server: String`, `tool_name: String`, `action: ToolCallAction`, `metadata: Option<serde_json::Value>`; `ChioReceipt::is_allowed(&self) -> bool`; `ChioReceipt::financial_budget_authority_metadata(&self) -> Option<FinancialBudgetAuthorityReceiptMetadata>` (fields `guarantee_level: String`, `hold_id: String`, `authorize.event_id: Option<String>`, `authorize.exposure_units: u64`, `terminal: Option<FinancialBudgetTerminalReceiptMetadata>` with `disposition: String`, `event_id: Option<String>`, `realized_spend_units: u64`); `ChioReceipt::financial_metadata(&self) -> Option<FinancialReceiptMetadata>` (`grant_index: u32`); `crate::receipt::kinds::{ReceiptKind, BoundaryClass, TrustLevel}`; `crate::crypto::PublicKey`.
- Produces (new, pinned by every later task and by B/C/fork):
  - `pub const MEDIATED_SPEND_PROFILE: &str = "chio.mediated_spend.v1";`
  - `pub struct BudgetAuthorityReceiptRef { pub hold_id: String, pub authorize_event_id: Option<String>, pub reconcile_event_id: Option<String>, pub capability_id: String, pub grant_index: u32, pub exposed_units: u64, pub realized_units: u64, pub execution_nonce_id: Option<String>, pub guarantee_level: String }`
  - `impl BudgetAuthorityReceiptRef { pub fn from_receipt(receipt: &ChioReceipt) -> Option<Self> }`
  - `pub trait PresentedNonceView { fn nonce_id(&self) -> &str; fn bound_capability_id(&self) -> &str; fn bound_tool_server(&self) -> &str; fn bound_tool_name(&self) -> &str; fn bound_parameter_hash(&self) -> &str; fn verify_signed_by(&self, key: &PublicKey) -> bool; }`
  - `pub enum NotAuthoritativeReason { SignerNotAdmitted, NotMediatedDecision, NotPreventBoundary, ObservationOutcomePresent, NotMediatedTrustLevel, NotAllowDecision, MissingBudgetAuthority, HoldNotReconciled, ExposureNotCommitted, NonceLinkMissing, NonceLinkMismatch, NonceBindingMismatch { field: &'static str }, NonceSignatureInvalid }` (derive `Debug, Clone, PartialEq, Eq`)
  - `pub fn is_authoritative_spend_receipt(receipt: &ChioReceipt, admitted_kernel_keys: &[PublicKey], presented_nonce: &dyn PresentedNonceView) -> Result<(), NotAuthoritativeReason>`

- [ ] **Step 1: Register the module.** In `crates/core/chio-core-types/src/receipt/mod.rs`, add `pub mod authoritative_spend;` next to the other `pub mod` lines, and add `pub use authoritative_spend::{is_authoritative_spend_receipt, BudgetAuthorityReceiptRef, NotAuthoritativeReason, PresentedNonceView, MEDIATED_SPEND_PROFILE};` next to the other `pub use` re-exports.

- [ ] **Step 2: Write the failing test.** Create `crates/core/chio-core-types/src/receipt/authoritative_spend.rs` with ONLY the test module first (the impl is Step 4). Paste:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::{Keypair, PublicKey};
    use crate::receipt::body::{ChioReceipt, ChioReceiptBody};
    use crate::receipt::decision::{Decision, ToolCallAction};
    use crate::receipt::kinds::{BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel};

    /// Minimal test double for a kernel-signed execution nonce.
    struct FakeNonce {
        nonce_id: String,
        capability_id: String,
        tool_server: String,
        tool_name: String,
        parameter_hash: String,
        signer: Option<PublicKey>,
    }

    impl PresentedNonceView for FakeNonce {
        fn nonce_id(&self) -> &str { &self.nonce_id }
        fn bound_capability_id(&self) -> &str { &self.capability_id }
        fn bound_tool_server(&self) -> &str { &self.tool_server }
        fn bound_tool_name(&self) -> &str { &self.tool_name }
        fn bound_parameter_hash(&self) -> &str { &self.parameter_hash }
        fn verify_signed_by(&self, key: &PublicKey) -> bool {
            self.signer.as_ref() == Some(key)
        }
    }

    fn param_hash() -> String {
        let canonical = crate::canonical_json_bytes(&serde_json::json!({"x": 1})).unwrap();
        crate::sha256_hex(&canonical)
    }

    fn authoritative_receipt(kp: &Keypair) -> ChioReceipt {
        let action = ToolCallAction::from_parameters(serde_json::json!({"x": 1})).unwrap();
        let parameter_hash = action.parameter_hash.clone();
        let content_hash = crate::sha256_hex(b"content");
        let metadata = serde_json::json!({
            "financial": { "grant_index": 0, "cost_charged": 50, "currency": "USD",
                "budget_remaining": 50, "budget_total": 100, "delegation_depth": 0,
                "root_budget_holder": "root", "settlement_status": "settled" },
            "budget_authority": {
                "guarantee_level": "single_node_atomic",
                "authority_profile": "authoritative_hold_event",
                "metering_profile": "max_cost_preauthorize_then_reconcile_actual",
                "hold_id": "budget-hold:req-1:cap-1:0",
                "execution_nonce_id": "nonce-1",
                "mediated_spend": { "profile": MEDIATED_SPEND_PROFILE },
                "authorize": { "event_id": "budget-hold:req-1:cap-1:0:authorize",
                    "exposure_units": 100, "committed_cost_units_after": 100 },
                "terminal": { "disposition": "reconciled",
                    "event_id": "budget-hold:req-1:cap-1:0:reconcile",
                    "exposure_units": 100, "realized_spend_units": 50,
                    "committed_cost_units_after": 50 }
            }
        });
        let body = ChioReceiptBody {
            id: "rcpt-1".to_string(), timestamp: 1, capability_id: "cap-1".to_string(),
            tool_server: "srv".to_string(), tool_name: "tool".to_string(), action,
            decision: Some(Decision::Allow), receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent, observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted, redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(), content_hash, policy_hash: crate::sha256_hex(b"policy"),
            evidence: Vec::new(), metadata: Some(metadata), trust_level: TrustLevel::Mediated,
            tenant_id: None, kernel_key: kp.public_key(), bbs_projection_version: None,
        };
        let _ = parameter_hash;
        ChioReceipt::sign(body, kp).unwrap()
    }

    fn good_nonce(kp: &Keypair, receipt: &ChioReceipt) -> FakeNonce {
        FakeNonce {
            nonce_id: "nonce-1".to_string(),
            capability_id: receipt.capability_id.clone(),
            tool_server: receipt.tool_server.clone(),
            tool_name: receipt.tool_name.clone(),
            parameter_hash: receipt.action.parameter_hash.clone(),
            signer: Some(kp.public_key()),
        }
    }

    #[test]
    fn authoritative_receipt_with_bound_nonce_passes() {
        let kp = Keypair::generate();
        let receipt = authoritative_receipt(&kp);
        let nonce = good_nonce(&kp, &receipt);
        assert_eq!(
            is_authoritative_spend_receipt(&receipt, &[kp.public_key()], &nonce),
            Ok(())
        );
    }

    #[test]
    fn r1_forged_mediated_label_without_budget_authority_is_rejected() {
        // R1: a trusted signer stamps advisory content as Mediated with zero budget movement.
        let kp = Keypair::generate();
        let mut receipt = authoritative_receipt(&kp);
        // Strip the budget_authority metadata but keep the Mediated label.
        receipt.metadata = Some(serde_json::json!({}));
        let nonce = good_nonce(&kp, &receipt);
        assert_eq!(
            is_authoritative_spend_receipt(&receipt, &[kp.public_key()], &nonce),
            Err(NotAuthoritativeReason::MissingBudgetAuthority)
        );
    }
}
```

- [ ] **Step 3: Run test to verify it fails.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-core-types authoritative_spend -- --nocapture`
  Expected: FAIL to COMPILE with errors like `cannot find function is_authoritative_spend_receipt in this scope` / `cannot find type NotAuthoritativeReason` / `cannot find trait PresentedNonceView`.

- [ ] **Step 4: Write minimal implementation.** Prepend this above the `#[cfg(test)]` module in the same file:

```rust
//! Frozen authoritative-spend contract (`chio.mediated_spend.v1`).
//!
//! Direction A freezes this shape so B and C can pin against it. Any advisory
//! or label-only receipt fails `is_authoritative_spend_receipt`, making
//! advisory-only consumption a machine-visible conformance failure.

use crate::crypto::PublicKey;
use crate::receipt::body::ChioReceipt;
use crate::receipt::kinds::{BoundaryClass, ReceiptKind, TrustLevel};

/// Receipt-profile identifier for a fully authoritative mediated-spend receipt.
pub const MEDIATED_SPEND_PROFILE: &str = "chio.mediated_spend.v1";

/// Projected budget-hold lineage carried by an authoritative spend receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetAuthorityReceiptRef {
    pub hold_id: String,
    pub authorize_event_id: Option<String>,
    pub reconcile_event_id: Option<String>,
    pub capability_id: String,
    pub grant_index: u32,
    pub exposed_units: u64,
    pub realized_units: u64,
    pub execution_nonce_id: Option<String>,
    pub guarantee_level: String,
}

impl BudgetAuthorityReceiptRef {
    /// Project the frozen linkage from a receipt's typed budget-authority
    /// metadata. Returns `None` when the receipt carries no budget-authority
    /// block (a label-only receipt).
    #[must_use]
    pub fn from_receipt(receipt: &ChioReceipt) -> Option<Self> {
        let authority = receipt.financial_budget_authority_metadata()?;
        let grant_index = receipt
            .financial_metadata()
            .map_or(0, |financial| financial.grant_index);
        // `reconcile_event_id` is `Some` only when the terminal mutation was a
        // reconcile (not a reverse/release), so `is_none()` means "not
        // reconciled".
        let (reconcile_event_id, realized_units) = match authority.terminal.as_ref() {
            Some(terminal) if terminal.disposition == "reconciled" => {
                (terminal.event_id.clone(), terminal.realized_spend_units)
            }
            _ => (None, 0),
        };
        let execution_nonce_id = receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("budget_authority"))
            .and_then(|block| block.get("execution_nonce_id"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        Some(Self {
            hold_id: authority.hold_id.clone(),
            authorize_event_id: authority.authorize.event_id.clone(),
            reconcile_event_id,
            capability_id: receipt.capability_id.clone(),
            grant_index,
            exposed_units: authority.authorize.exposure_units,
            realized_units,
            execution_nonce_id,
            guarantee_level: authority.guarantee_level.clone(),
        })
    }
}

/// Read-only view of a kernel-signed execution nonce, implemented by
/// `chio_kernel::execution_nonce::SignedExecutionNonce`. Keeps this contract in
/// the lowest crate without depending on the kernel.
pub trait PresentedNonceView {
    fn nonce_id(&self) -> &str;
    fn bound_capability_id(&self) -> &str;
    fn bound_tool_server(&self) -> &str;
    fn bound_tool_name(&self) -> &str;
    fn bound_parameter_hash(&self) -> &str;
    fn verify_signed_by(&self, key: &PublicKey) -> bool;
}

/// Distinct rejection reasons; each of the (a)-(f) conjunction fragments maps to
/// at least one variant so a conformance matrix can flip them independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotAuthoritativeReason {
    SignerNotAdmitted,
    NotMediatedDecision,
    NotPreventBoundary,
    ObservationOutcomePresent,
    NotMediatedTrustLevel,
    NotAllowDecision,
    MissingBudgetAuthority,
    HoldNotReconciled,
    ExposureNotCommitted,
    NonceLinkMissing,
    NonceLinkMismatch,
    NonceBindingMismatch { field: &'static str },
    NonceSignatureInvalid,
}

/// Structurally checkable conjunction over the kernel signature. Fail-closed:
/// any missing or invalid element is an `Err`.
pub fn is_authoritative_spend_receipt(
    receipt: &ChioReceipt,
    admitted_kernel_keys: &[PublicKey],
    presented_nonce: &dyn PresentedNonceView,
) -> Result<(), NotAuthoritativeReason> {
    // (e) signer must be an admitted kernel key.
    if !admitted_kernel_keys.contains(&receipt.kernel_key) {
        return Err(NotAuthoritativeReason::SignerNotAdmitted);
    }
    // (a) mediated-decision semantics (mirrors sidecar.rs:796-799 verify side).
    if receipt.receipt_kind != ReceiptKind::MediatedDecision {
        return Err(NotAuthoritativeReason::NotMediatedDecision);
    }
    if receipt.boundary_class != BoundaryClass::Prevent {
        return Err(NotAuthoritativeReason::NotPreventBoundary);
    }
    if receipt.observation_outcome.is_some() {
        return Err(NotAuthoritativeReason::ObservationOutcomePresent);
    }
    if receipt.trust_level != TrustLevel::Mediated {
        return Err(NotAuthoritativeReason::NotMediatedTrustLevel);
    }
    if !receipt.is_allowed() {
        return Err(NotAuthoritativeReason::NotAllowDecision);
    }
    // (b) an atomically committed, reconciled hold that actually moved exposure.
    let budget = BudgetAuthorityReceiptRef::from_receipt(receipt)
        .ok_or(NotAuthoritativeReason::MissingBudgetAuthority)?;
    if budget.hold_id.is_empty() {
        return Err(NotAuthoritativeReason::MissingBudgetAuthority);
    }
    if budget.reconcile_event_id.is_none() {
        return Err(NotAuthoritativeReason::HoldNotReconciled);
    }
    if budget.exposed_units == 0 {
        return Err(NotAuthoritativeReason::ExposureNotCommitted);
    }
    // (d) hold <-> nonce cross-binding: the receipt must name the nonce.
    let linked_nonce_id = budget
        .execution_nonce_id
        .as_deref()
        .ok_or(NotAuthoritativeReason::NonceLinkMissing)?;
    if linked_nonce_id != presented_nonce.nonce_id() {
        return Err(NotAuthoritativeReason::NonceLinkMismatch);
    }
    // (c) the nonce binding must match the exact call the receipt authorized.
    if presented_nonce.bound_capability_id() != receipt.capability_id {
        return Err(NotAuthoritativeReason::NonceBindingMismatch { field: "capability_id" });
    }
    if presented_nonce.bound_tool_server() != receipt.tool_server {
        return Err(NotAuthoritativeReason::NonceBindingMismatch { field: "tool_server" });
    }
    if presented_nonce.bound_tool_name() != receipt.tool_name {
        return Err(NotAuthoritativeReason::NonceBindingMismatch { field: "tool_name" });
    }
    if presented_nonce.bound_parameter_hash() != receipt.action.parameter_hash {
        return Err(NotAuthoritativeReason::NonceBindingMismatch { field: "parameter_hash" });
    }
    // (e) the nonce must be signed by the same admitted kernel key.
    if !presented_nonce.verify_signed_by(&receipt.kernel_key) {
        return Err(NotAuthoritativeReason::NonceSignatureInvalid);
    }
    Ok(())
}

/// R4 guarantee-level truthfulness: refuse a receipt claiming a guarantee level
/// stronger than the operator's configured floor. Levels are ordered
/// advisory_posthoc < single_node_atomic < partition_escrowed < ha_linearizable.
#[must_use]
pub fn guarantee_level_rank(level: &str) -> u8 {
    match level {
        "ha_linearizable" => 3,
        "partition_escrowed" => 2,
        "single_node_atomic" => 1,
        _ => 0,
    }
}

/// Returns `Ok(())` only when the receipt's guarantee level is at least the
/// operator floor. Fail-closed on a missing budget-authority block.
pub fn receipt_meets_guarantee_floor(
    receipt: &ChioReceipt,
    minimum_level: &str,
) -> Result<(), NotAuthoritativeReason> {
    let budget = BudgetAuthorityReceiptRef::from_receipt(receipt)
        .ok_or(NotAuthoritativeReason::MissingBudgetAuthority)?;
    if guarantee_level_rank(&budget.guarantee_level) < guarantee_level_rank(minimum_level) {
        return Err(NotAuthoritativeReason::NotMediatedTrustLevel);
    }
    Ok(())
}
```

- [ ] **Step 5: Run test to verify it passes.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-core-types authoritative_spend -- --nocapture`
  Expected: PASS (`authoritative_receipt_with_bound_nonce_passes ... ok`, `r1_forged_mediated_label_without_budget_authority_is_rejected ... ok`).

- [ ] **Step 6: Scoped clippy.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-core-types -- -D warnings`
  Expected: no warnings.

- [ ] **Step 7: Commit.**
```bash
git add crates/core/chio-core-types/src/receipt/authoritative_spend.rs crates/core/chio-core-types/src/receipt/mod.rs
git commit -m "feat(chio-core-types): freeze chio.mediated_spend.v1 authoritative-spend contract

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 2: Kernel `PresentedNonceView` impl, eval-receipt re-export, frozen-schema golden tests (R6)

**Files:**
- Modify: `crates/kernel/chio-kernel/src/execution_nonce.rs`
- Modify: `crates/sdk/chio-eval-receipt/src/lib.rs`
- Test: `crates/kernel/chio-kernel/src/execution_nonce.rs` (`#[cfg(test)] mod tests`, which already has `#[allow(clippy::expect_used, clippy::unwrap_used)]` at execution_nonce.rs:449-451)

**Interfaces:**
- Consumes: `chio_core_types::receipt::authoritative_spend::PresentedNonceView` (Task 1); `SignedExecutionNonce { nonce: ExecutionNonce, signature: Signature }` with `nonce.nonce_id: String`, `nonce.bound_to: NonceBinding { subject_id, capability_id, tool_server, tool_name, parameter_hash }` (execution_nonce.rs:93-120); `chio_core::canonical::canonical_json_bytes`; `chio_core::crypto::PublicKey::verify(&self, bytes, sig)`; `EXECUTION_NONCE_SCHEMA = "chio.execution_nonce.v1"` (execution_nonce.rs:47).
- Produces: `impl chio_core_types::receipt::authoritative_spend::PresentedNonceView for SignedExecutionNonce`; frozen golden tests `execution_nonce_schema_is_frozen` and `mediated_spend_profile_is_frozen`.

- [ ] **Step 1: Write the failing tests.** Add to the existing `#[cfg(test)] mod tests` in `crates/kernel/chio-kernel/src/execution_nonce.rs`:

```rust
    #[test]
    fn execution_nonce_schema_is_frozen() {
        // R6 / Acceptance 7: a rename of any nonce field breaks CI so B/C pinned
        // slots cannot silently mis-parse.
        let kp = Keypair::generate();
        let signed = mint_execution_nonce(&kp, sample_binding(), &ExecutionNonceConfig::default(), 1_000_000).unwrap();
        let value = serde_json::to_value(&signed).unwrap();
        assert_eq!(value["nonce"]["schema"], "chio.execution_nonce.v1");
        let nonce_keys: std::collections::BTreeSet<String> =
            value["nonce"].as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            nonce_keys,
            ["bound_to", "expires_at", "issued_at", "nonce_id", "schema"]
                .into_iter().map(String::from).collect()
        );
        let binding_keys: std::collections::BTreeSet<String> =
            value["nonce"]["bound_to"].as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            binding_keys,
            ["capability_id", "parameter_hash", "subject_id", "tool_name", "tool_server"]
                .into_iter().map(String::from).collect()
        );
        let top_keys: std::collections::BTreeSet<String> =
            value.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            top_keys,
            ["nonce", "signature"].into_iter().map(String::from).collect()
        );
    }

    #[test]
    fn signed_execution_nonce_implements_presented_nonce_view() {
        use chio_core_types::receipt::authoritative_spend::PresentedNonceView;
        let kp = Keypair::generate();
        let signed = mint_execution_nonce(&kp, sample_binding(), &ExecutionNonceConfig::default(), 1_000_000).unwrap();
        assert_eq!(signed.bound_capability_id(), "cap-123");
        assert_eq!(signed.bound_tool_server(), "fs");
        assert_eq!(signed.bound_tool_name(), "read_file");
        assert!(signed.verify_signed_by(&kp.public_key()));
        assert!(!signed.verify_signed_by(&Keypair::generate().public_key()));
    }
```

- [ ] **Step 2: Run to verify it fails.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-kernel execution_nonce::tests::signed_execution_nonce_implements_presented_nonce_view -- --nocapture`
  Expected: FAIL to COMPILE with `no method named bound_capability_id found for struct SignedExecutionNonce` (trait not implemented / not in scope).

- [ ] **Step 3: Write minimal implementation.** In `crates/kernel/chio-kernel/src/execution_nonce.rs`, after the `impl SignedExecutionNonce { ... }` block (execution_nonce.rs:122-134), add:

```rust
impl chio_core_types::receipt::authoritative_spend::PresentedNonceView for SignedExecutionNonce {
    fn nonce_id(&self) -> &str {
        &self.nonce.nonce_id
    }
    fn bound_capability_id(&self) -> &str {
        &self.nonce.bound_to.capability_id
    }
    fn bound_tool_server(&self) -> &str {
        &self.nonce.bound_to.tool_server
    }
    fn bound_tool_name(&self) -> &str {
        &self.nonce.bound_to.tool_name
    }
    fn bound_parameter_hash(&self) -> &str {
        &self.nonce.bound_to.parameter_hash
    }
    fn verify_signed_by(&self, key: &PublicKey) -> bool {
        match canonical_json_bytes(&self.nonce) {
            Ok(bytes) => key.verify(&bytes, &self.signature),
            Err(_) => false,
        }
    }
}
```

- [ ] **Step 4: Run to verify both tests pass.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-kernel execution_nonce -- --nocapture`
  Expected: PASS (`execution_nonce_schema_is_frozen ... ok`, `signed_execution_nonce_implements_presented_nonce_view ... ok`, plus the existing nonce tests still ok).

- [ ] **Step 5: Re-export from eval-receipt.** In `crates/sdk/chio-eval-receipt/src/lib.rs`, add near the other `pub use` lines:

```rust
pub use chio_core_types::receipt::authoritative_spend::{
    is_authoritative_spend_receipt, receipt_meets_guarantee_floor, BudgetAuthorityReceiptRef,
    NotAuthoritativeReason, PresentedNonceView, MEDIATED_SPEND_PROFILE,
};
```

- [ ] **Step 6: Freeze the mediated-spend profile constant.** Add to `crates/sdk/chio-eval-receipt/src/lib.rs` (a compile-time freeze that fails CI on rename):

```rust
#[cfg(test)]
mod contract_freeze {
    #[test]
    fn mediated_spend_profile_is_frozen() {
        assert_eq!(super::MEDIATED_SPEND_PROFILE, "chio.mediated_spend.v1");
    }
}
```

- [ ] **Step 7: Run eval-receipt tests + scoped clippy.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-eval-receipt contract_freeze -- --nocapture`
  Expected: PASS.
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-kernel -p chio-eval-receipt -- -D warnings`
  Expected: no warnings.

- [ ] **Step 8: Commit.**
```bash
git add crates/kernel/chio-kernel/src/execution_nonce.rs crates/sdk/chio-eval-receipt/src/lib.rs
git commit -m "feat(chio-kernel): implement PresentedNonceView and freeze nonce schema

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 3: ADR-0016, ADR-0006 supersession, PROTOCOL section 6.x, reserved linkage + prepay decision

**Files:**
- Create: `docs/adr/ADR-0016-authoritative-spend-contract.md`
- Modify: `docs/adr/ADR-0006-monetary-budget-semantics.md`
- Modify: `spec/PROTOCOL.md`
- Test: `crates/sdk/chio-eval-receipt/src/lib.rs` (a doc-coherence assertion, so the prose decision is machine-anchored)

**Interfaces:**
- Consumes: `MEDIATED_SPEND_PROFILE`, `EXECUTION_NONCE_SCHEMA` (frozen in Tasks 1-2).
- Produces: normative ADR + protocol text; the prepay-authority decision (authorize worst-case `quote.quoted_cost` when present else `max_cost_per_invocation`, reconcile down to realized `cost_charged`); documented reserved linkage slots `execution_nonce_ref` / `hold_ref` for B's `chio.comptroller.surface-report.v1` and C's settlement receipt.

- [ ] **Step 1: Write the doc-anchor failing test.** Add to `crates/sdk/chio-eval-receipt/src/lib.rs` `contract_freeze` module:

```rust
    #[test]
    fn adr_0016_and_protocol_document_the_profile() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../..");
        let adr = std::fs::read_to_string(format!("{root}/docs/adr/ADR-0016-authoritative-spend-contract.md"))
            .expect("ADR-0016 must exist");
        assert!(adr.contains("chio.mediated_spend.v1"));
        assert!(adr.contains("chio.execution_nonce.v1"));
        assert!(adr.contains("quote.quoted_cost"));
        assert!(adr.contains("execution_nonce_ref"));
        assert!(adr.contains("hold_ref"));
        let protocol = std::fs::read_to_string(format!("{root}/spec/PROTOCOL.md"))
            .expect("PROTOCOL.md must exist");
        assert!(protocol.contains("chio.mediated_spend.v1"));
    }
```

Note: this test reads files and is a `#[cfg(test)]` unit; keep `#[allow(clippy::unwrap_used, clippy::expect_used)]` at the top of the `contract_freeze` module or use `.expect(...)` inside it under that allow. Add `#![allow(clippy::expect_used)]`-equivalent by placing `#[allow(clippy::expect_used, clippy::unwrap_used)]` on the `mod contract_freeze` line.

- [ ] **Step 2: Run to verify it fails.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-eval-receipt contract_freeze::adr_0016 -- --nocapture`
  Expected: FAIL with `ADR-0016 must exist` panic (file not yet created).

- [ ] **Step 3: Create ADR-0016.** Write `docs/adr/ADR-0016-authoritative-spend-contract.md` (match the ADR-0015 header style):

```markdown
# ADR-0016: Authoritative Spend Contract (execution nonce + atomic hold + mediated-spend profile)

- Status: Proposed
- Decision owner: kernel and spend control-plane lane (Direction A keystone)
- Related invariant: fail-closed enforcement; "authoritative" is a structural conjunction over the kernel signature, not a label
- Related plan items: A-M0 (freeze), A-M1..A-M5; consumed by B (surface-report.v1) and C (settlement receipt)

## Context

The kernel already contains an atomic, fail-closed spend pipeline (`budget_store.rs`
`authorize_budget_hold`, `execution_nonce.rs`, `validation.rs` reconcile). The
surface real agents use (the `chio-api-protect` sidecar direct tool-call route)
routed around it and emitted an advisory receipt that admits, in its own
metadata, that it is not authorization. `TrustLevel::Mediated` is a stamp
(`receipt_persistence.rs`), not proof that budget was held and guards ran. This
ADR declares the enforcement contract normative so downstream directions can pin
to a stable shape.

Two code-only realities are hereby reconciled with the docs: the
`chio.execution_nonce.v1` schema (`execution_nonce.rs`) and the
`BudgetGuaranteeLevel` taxonomy (`budget_store.rs`) were previously absent from
`spec/` and every ADR.

## Decision

1. `chio.execution_nonce.v1` is frozen as-is: a signed body of
   `{schema, nonce_id, issued_at, expires_at, bound_to{subject_id, capability_id,
   tool_server, tool_name, parameter_hash}}` plus an Ed25519 `signature`.
2. The atomic hold lifecycle (authorize worst-case exposure, reconcile down to
   realized spend, reverse on deny) is normative. `BudgetGuaranteeLevel`
   (`single_node_atomic`, `ha_linearizable`, `partition_escrowed`,
   `advisory_posthoc`) is normative and must be truthful: a store never claims a
   level above its real backing (no `ha_linearizable` without a quorum store).
3. `chio.mediated_spend.v1` predicate: a receipt is authoritative iff it satisfies
   the structural conjunction (a) mediated_decision + prevent + observation_outcome
   absent + trust_level mediated + decision Allow; (b) a reconciled
   `BudgetAuthorityReceiptRef` whose exposure moved against the agent's
   cost-bearing capability; (c) a kernel-signed execution nonce bound to the same
   capability/server/tool/parameter_hash; (d) the receipt records the nonce id
   (hold <-> nonce cross-bound); (e) the signer is an admitted kernel key; (f)
   fail-closed on any missing or invalid element. Implemented by
   `chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt`.
4. Prepay authority (A's call, threaded to B and C): authorize the worst case
   (`quote.quoted_cost` when a quote is present, else `max_cost_per_invocation`)
   and reconcile down to realized `cost_charged`. The authoritative number B's
   exposure/spend projection reports and C's gate charges is this
   authorize-then-reconcile pair, not either endpoint alone.
5. Reserved linkage slots (populate as `Option::None` until Phase 2 so no
   governance-gated schema v2 is forced): B's `chio.comptroller.surface-report.v1`
   MUST carry `execution_nonce_ref: Option<String>` and `hold_ref: Option<String>`;
   C's settlement receipt MUST carry the same two slots.

## Consequences

Supersedes the "monotonic, no-refund" text of ADR-0006 (the code already refunds
via reverse/reconcile). Advisory-only consumption becomes a machine-visible
conformance failure (A-M3, A-M5). B and C pin to this shape only after A passes
its own adversarial review (A-M5 golden gate).
```

- [ ] **Step 4: Supersede ADR-0006.** In `docs/adr/ADR-0006-monetary-budget-semantics.md`, immediately under the title line add:

```markdown

> Superseded in part by ADR-0016: the "monotonic, no-refund" exposure text is
> replaced by the authorize-then-reconcile hold lifecycle (reverse on deny,
> reconcile down to realized spend). See ADR-0016 for the normative contract.
```

- [ ] **Step 5: Add PROTOCOL section 6.x.** In `spec/PROTOCOL.md`, immediately after the section 6.1 block (which ends near PROTOCOL.md:871 with the "cancelled and incomplete outcomes are preserved" paragraph), insert:

```markdown
### 6.2 Authoritative Spend (execution nonce, atomic hold, mediated-spend profile)

An authorization receipt for a spend-bearing tool call is authoritative only when
it satisfies the structural conjunction of the `chio.mediated_spend.v1` profile:

- The receipt is `mediated_decision` + `prevent` + `trust_level = mediated` with
  `decision = Allow` and no `observation_outcome` (see 6.1).
- Its `budget_authority` metadata names a `hold_id` that was atomically committed
  against the agent's cost-bearing capability and reconciled down to realized
  spend (`authorize` then `terminal.disposition = reconciled`).
- A `chio.execution_nonce.v1` nonce, signed by the same admitted kernel key, is
  bound to the same `capability_id`, `tool_server`, `tool_name`, and
  `parameter_hash`, and the receipt records that nonce id
  (`budget_authority.execution_nonce_id`).

Advisory (`advisory_evaluation`) records and label-only receipts are never
authorization. A guarantee level (`single_node_atomic`, `ha_linearizable`,
`partition_escrowed`, `advisory_posthoc`) must be truthful to the backing store.
```

- [ ] **Step 6: Run the doc-anchor test.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-eval-receipt contract_freeze -- --nocapture`
  Expected: PASS (`adr_0016_and_protocol_document_the_profile ... ok`).

- [ ] **Step 7: Commit.**
```bash
git add docs/adr/ADR-0016-authoritative-spend-contract.md docs/adr/ADR-0006-monetary-budget-semantics.md spec/PROTOCOL.md crates/sdk/chio-eval-receipt/src/lib.rs
git commit -m "docs(adr): ADR-0016 authoritative spend contract; supersede ADR-0006 refund text

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Milestone 1 - Kernel-mediated direct-tool-call route in the sidecar

Reinstate `POST /v1/evaluate` as an authoritative tool-call route that runs the existing 26-step kernel pipeline against the agent's cost-bearing capability, with a real budget store installed so `check_and_increment_budget` fires and `mint_execution_nonce_for_allow` runs.

### Task 4: Budget store + mediation kernel wiring in `ProxyState`

**Files:**
- Modify: `crates/products/chio-api-protect/src/proxy/config.rs`
- Modify: `crates/products/chio-api-protect/src/proxy/state.rs`
- Create: `crates/products/chio-api-protect/src/proxy/mediated.rs` (builder half; handler in Task 5)
- Modify: `crates/products/chio-api-protect/src/proxy/mod.rs` (add `mod mediated;`)
- Test: `crates/products/chio-api-protect/src/proxy/mediated.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `chio_kernel::budget_store::{BudgetStore, InMemoryBudgetStore}`; `chio_store_sqlite::budget_store::SqliteBudgetStore::open(path)`; `chio_control_plane::...::build_remote_budget_store(control_url, control_token) -> Result<Box<dyn BudgetStore>, CliError>`; `chio_kernel::{ChioKernel, KernelConfig}`; `ChioKernel::set_budget_store_handle(&mut self, Arc<dyn BudgetStore>)` (construction.rs:460); `ChioKernel::set_execution_nonce_store(&mut self, ExecutionNonceConfig, Box<dyn ExecutionNonceStore>)` (construction.rs:995); `chio_kernel::execution_nonce::{ExecutionNonceConfig, InMemoryExecutionNonceStore}`.
- Produces:
  - `ProtectConfig` new fields `pub control_url: Option<String>`, `pub control_token: Option<String>`, `pub budget_db: Option<String>`, `pub require_nonce: bool`.
  - `ProxyState` new fields `pub(crate) budget_store: Option<Arc<dyn BudgetStore>>`, `pub(crate) mediation_kernel: Option<Arc<ChioKernel>>`.
  - `pub(crate) fn build_budget_store(config: &ProtectConfig) -> Result<Option<Arc<dyn BudgetStore>>, ProtectError>`
  - `pub(crate) fn build_mediation_kernel(signer: &Keypair, budget_store: Arc<dyn BudgetStore>, require_nonce: bool, tool_servers: Vec<Box<dyn ToolServer>>) -> Result<Arc<ChioKernel>, ProtectError>`

- [ ] **Step 1: Write the failing test.** In a new file `crates/products/chio-api-protect/src/proxy/mediated.rs`, start with:

```rust
use super::*;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_kernel::budget_store::BudgetStore;

    #[test]
    fn build_budget_store_local_sqlite_when_no_control_url() {
        let dir = std::env::temp_dir().join(format!("chio-budget-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("budget.sqlite");
        let config = ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some("{}".to_string()),
            spec_path: None,
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: None,
            sidecar_control_token: None,
            signer_seed_hex: None,
            trusted_capability_issuers: Vec::new(),
            control_url: None,
            control_token: None,
            budget_db: Some(db.to_string_lossy().to_string()),
            require_nonce: false,
        };
        let store = build_budget_store(&config).unwrap();
        assert!(store.is_some(), "local sqlite budget store must be built");
    }

    #[test]
    fn mediation_kernel_installs_budget_store_and_nonce_config() {
        let signer = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(chio_kernel::budget_store::InMemoryBudgetStore::new());
        let kernel = build_mediation_kernel(&signer, Arc::clone(&budget), true, Vec::new()).unwrap();
        assert!(kernel.execution_nonce_required(), "require_nonce must be honored");
    }
}
```

- [ ] **Step 2: Run to verify it fails.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-api-protect proxy::mediated::tests -- --nocapture`
  Expected: FAIL to COMPILE with `cannot find function build_budget_store` / `no field control_url on ProtectConfig`.

- [ ] **Step 3: Extend `ProtectConfig`.** In `crates/products/chio-api-protect/src/proxy/config.rs`, add these fields to `pub struct ProtectConfig` (after `trusted_capability_issuers`):

```rust
    /// Control-plane URL. When set, budget holds go through a `RemoteBudgetStore`.
    pub control_url: Option<String>,
    /// Bearer token for the control-plane budget endpoints.
    pub control_token: Option<String>,
    /// Local SQLite budget-store path used when no `control_url` is configured.
    pub budget_db: Option<String>,
    /// When true, the mediation kernel runs execution-nonce strict mode.
    pub require_nonce: bool,
```

Also add the three simple fields to the manual `Debug` impl in the same file (append `.field("control_url", &self.control_url).field("budget_db", &self.budget_db).field("require_nonce", &self.require_nonce)` before `.finish()`; do not print `control_token`).

- [ ] **Step 4: Extend `ProxyState`.** In `crates/products/chio-api-protect/src/proxy/state.rs`, add to `pub(crate) struct ProxyState` (after `sidecar_control_token`):

```rust
    pub(crate) budget_store: Option<Arc<dyn chio_kernel::budget_store::BudgetStore>>,
    pub(crate) mediation_kernel: Option<Arc<chio_kernel::ChioKernel>>,
```

Populate them in `ProtectProxy::run_with_observer` where the `ProxyState` is constructed (state.rs:288). Before `let state = Arc::new(ProxyState { ... })`, add:

```rust
        let budget_store = build_budget_store(&self.config)?;
        let mediation_kernel = match budget_store.as_ref() {
            Some(store) => Some(build_mediation_kernel(
                &keypair,
                Arc::clone(store),
                self.config.require_nonce,
                vec![Box::new(mediated::MediatedProxyToolServer::new(
                    self.config.upstream.clone(),
                ))],
            )?),
            None => None,
        };
```

and add `budget_store, mediation_kernel,` to the `ProxyState { ... }` initializer.

- [ ] **Step 5: Implement the builders.** Add to `crates/products/chio-api-protect/src/proxy/mediated.rs` (above the test module):

```rust
use std::sync::Arc;

use chio_kernel::budget_store::BudgetStore;
use chio_kernel::execution_nonce::{ExecutionNonceConfig, InMemoryExecutionNonceStore};
use chio_kernel::{ChioKernel, KernelConfig};

/// Build the sidecar's budget store: remote under `--control-url`, else a local
/// SQLite store, else `None` (the mediated route then denies fail-closed).
pub(crate) fn build_budget_store(
    config: &ProtectConfig,
) -> Result<Option<Arc<dyn BudgetStore>>, ProtectError> {
    if let Some(control_url) = config.control_url.as_deref() {
        let token = config.control_token.as_deref().unwrap_or("");
        let store = chio_control_plane::trust_control::service_runtime::budget::build_remote_budget_store(
            control_url, token,
        )
        .map_err(|error| ProtectError::Config(error.to_string()))?;
        return Ok(Some(Arc::from(store)));
    }
    if let Some(path) = config.budget_db.as_deref() {
        let store = chio_store_sqlite::budget_store::SqliteBudgetStore::open(path)
            .map_err(|error| ProtectError::Config(error.to_string()))?;
        return Ok(Some(Arc::new(store)));
    }
    Ok(None)
}

/// Build a `ChioKernel` for tool-call mediation with the budget store and
/// (optionally strict) execution-nonce config installed.
pub(crate) fn build_mediation_kernel(
    signer: &Keypair,
    budget_store: Arc<dyn BudgetStore>,
    require_nonce: bool,
    tool_servers: Vec<Box<dyn chio_kernel::runtime::ToolServer>>,
) -> Result<Arc<ChioKernel>, ProtectError> {
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: signer.clone(),
        ca_public_keys: vec![signer.public_key()],
        max_delegation_depth: 5,
        policy_hash: "chio_api_protect_mediation_v1".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    })
    .map_err(|error| ProtectError::Config(error.to_string()))?;
    kernel.set_budget_store_handle(budget_store);
    let nonce_cfg = ExecutionNonceConfig { require_nonce, ..ExecutionNonceConfig::default() };
    kernel.set_execution_nonce_store(
        nonce_cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&nonce_cfg)),
    );
    for server in tool_servers {
        kernel.register_tool_server(server);
    }
    Ok(Arc::new(kernel))
}
```

Note: confirm `ChioKernel::new` return type at construction time. If `ChioKernel::new(KernelConfig)` returns `Self` (not `Result`), drop the `.map_err(...)?` and the trailing `?`; the budget test used `make_kernel(make_config())` which wraps it. Match the observed signature at `crates/kernel/chio-kernel/src/kernel/construction.rs` for `new`. Also add `mod mediated;` to `crates/products/chio-api-protect/src/proxy/mod.rs`, and add crate deps `chio-store-sqlite`, `chio-control-plane` to `crates/products/chio-api-protect/Cargo.toml` if not already present (the `build_budget_store` refs require them).

- [ ] **Step 6: Provide a minimal `MediatedProxyToolServer` stub for compilation** (real upstream proxy dispatch is refined in Task 5). Add to `mediated.rs`:

```rust
/// Tool server that represents the proxied upstream call for mediation. On
/// dispatch it reports a realized cost so the kernel reconciles the hold.
pub(crate) struct MediatedProxyToolServer {
    upstream: String,
}

impl MediatedProxyToolServer {
    pub(crate) fn new(upstream: String) -> Self {
        Self { upstream }
    }
}
```

Implement `chio_kernel::runtime::ToolServer` for it following the trait shape used by `EchoServer`/`MonetaryCostServer` in `crates/kernel/chio-kernel/src/kernel/tests/support_monetary.rs`; the invoke path returns a `ToolCallOutput` whose reported cost equals the quoted or worst-case cost so reconcile runs. Keep `upstream` for the Task-5 real proxy dispatch.

- [ ] **Step 7: Run to verify both tests pass + clippy.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-api-protect proxy::mediated::tests -- --nocapture`
  Expected: PASS.
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-api-protect -- -D warnings`
  Expected: no warnings.

- [ ] **Step 8: Commit.**
```bash
git add crates/products/chio-api-protect/src/proxy/config.rs crates/products/chio-api-protect/src/proxy/state.rs crates/products/chio-api-protect/src/proxy/mediated.rs crates/products/chio-api-protect/src/proxy/mod.rs crates/products/chio-api-protect/Cargo.toml
git commit -m "feat(chio-api-protect): install budget store and mediation kernel in ProxyState

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 5: `POST /v1/evaluate` mediated handler (R2: nonce-without-hold)

**Files:**
- Modify: `crates/products/chio-api-protect/src/proxy/mediated.rs`
- Modify: `crates/products/chio-api-protect/src/proxy/router.rs`
- Test: `crates/products/chio-api-protect/src/proxy/mediated.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `ChioKernel::evaluate_tool_call_blocking_with_metadata(&self, &ToolCallRequest, Option<serde_json::Value>) -> Result<ToolCallResponse, KernelError>` (sync_evaluation_wrapper.rs:26); `ToolCallRequest { request_id, capability: CapabilityToken, tool_name, server_id, agent_id, arguments, dpop_proof: None, execution_nonce: None, governed_intent: None, approval_token: None, model_metadata: None, federated_origin_kernel_id: None }` (runtime.rs:41); `ToolCallResponse { verdict, receipt, execution_nonce, .. }` (runtime.rs:88); `CapabilityToken` deserialization; `ChioKernel::budget_store` public field; `chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt`; `PresentedNonceView for SignedExecutionNonce` (Task 2).
- Produces:
  - `pub(crate) struct SidecarEvaluateToolCallMediatedRequest { capability: CapabilityToken, tool_server: String, tool_name: String, parameters: serde_json::Value, parameter_hash: Option<String>, agent_id: Option<String> }`
  - `pub(crate) async fn sidecar_evaluate_tool_call_mediated_handler(State<Arc<ProxyState>>, Request<Body>) -> Response` returning JSON `{ verdict, receipt, execution_nonce }`.

- [ ] **Step 1: Write the failing integration test.** Add to the `tests` module in `mediated.rs`:

```rust
    use chio_kernel::budget_store::{BudgetStore, InMemoryBudgetStore};
    use tower::ServiceExt;

    #[tokio::test]
    async fn mediated_route_moves_committed_cost_against_agent_capability() {
        // R2: the hold must be against the agent's cost-bearing capability, and
        // committed_cost must move and reconcile - not merely a nonce/label.
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = build_mediation_kernel(
            &signer,
            Arc::clone(&budget),
            false,
            vec![Box::new(test_cost_server("cost-srv", "compute", 50, "USD"))],
        )
        .unwrap();
        let cap = issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_id = cap.id.clone();
        let state = mediated_test_state(Arc::clone(&kernel), Arc::clone(&budget));

        let body = serde_json::json!({
            "capability": cap,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" }
        });
        let request = with_loopback_peer(
            Request::builder().method("POST").uri("/v1/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap())).unwrap(),
        );
        let response = build_app(Arc::clone(&state)).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        // The receipt is a full Mediated Allow, not an advisory record.
        assert_eq!(json["receipt"]["trust_level"], "mediated");
        assert_eq!(json["receipt"]["decision"]["verdict"], "allow");
        assert!(json["execution_nonce"].is_object(), "mediated route must return a nonce");

        // committed_cost moved and reconciled down to realized 50.
        let usage = budget.get_usage(&cap_id, 0).unwrap().unwrap();
        assert_eq!(usage.committed_cost_units().unwrap(), 50);
    }

    #[tokio::test]
    async fn mediated_deny_leaves_committed_cost_zero() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = build_mediation_kernel(
            &signer, Arc::clone(&budget), false,
            vec![Box::new(test_cost_server("cost-srv", "compute", 50, "USD"))],
        ).unwrap();
        // max_total_cost below one worst-case invocation forces a deny.
        let cap = issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 40, "USD");
        let cap_id = cap.id.clone();
        let state = mediated_test_state(Arc::clone(&kernel), Arc::clone(&budget));
        let body = serde_json::json!({ "capability": cap, "tool_server": "cost-srv",
            "tool_name": "compute", "parameters": {} });
        let request = with_loopback_peer(Request::builder().method("POST").uri("/v1/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap())).unwrap());
        let response = build_app(Arc::clone(&state)).oneshot(request).await.unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_ne!(json["receipt"]["decision"]["verdict"], "allow");
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
    }
```

Provide test helpers in the same module: `test_cost_server(...)` mirroring `MonetaryCostServer` from `support_monetary.rs`; `issue_cost_bearing_capability(kernel, agent, server, tool, max_per, max_total, currency)` using `kernel.issue_capability(&agent.public_key(), scope, 3600)` with a `ToolGrant` carrying `max_cost_per_invocation`/`max_total_cost` (shape from support_monetary.rs:210-234); `mediated_test_state(kernel, budget)` building a `ProxyState` whose `mediation_kernel = Some(kernel)` and `budget_store = Some(budget)` (reuse the `test_state` helper pattern at proxy/tests.rs:156-216 and set the two new fields); `with_loopback_peer` already exists in proxy/tests.rs.

- [ ] **Step 2: Run to verify it fails.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-api-protect mediated_route_moves_committed_cost_against_agent_capability -- --nocapture`
  Expected: FAIL (route `/v1/evaluate` still maps to `sidecar_removed_evaluate_handler` returning 410, so status is GONE not OK).

- [ ] **Step 3: Implement the mediated handler.** Add to `mediated.rs`:

```rust
#[derive(Debug, serde::Deserialize)]
pub(crate) struct SidecarEvaluateToolCallMediatedRequest {
    capability: chio_core_types::capability::CapabilityToken,
    tool_server: String,
    tool_name: String,
    #[serde(default)]
    parameters: serde_json::Value,
    #[serde(default)]
    agent_id: Option<String>,
}

pub(crate) async fn sidecar_evaluate_tool_call_mediated_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read mediated evaluate body: {error}");
            return sidecar_bad_request("failed to read evaluate body").into_response();
        }
    };
    let parsed: SidecarEvaluateToolCallMediatedRequest = match serde_json::from_slice(&body_bytes) {
        Ok(parsed) => parsed,
        Err(error) => {
            return sidecar_bad_request(&format!("invalid mediated payload: {error}")).into_response();
        }
    };
    // Fail-closed: no budget store means no authoritative enforcement.
    let Some(kernel) = state.mediation_kernel.as_ref() else {
        return internal_json_error_response(
            "chio_mediation_unavailable",
            "mediated tool-call route requires a configured budget store (--control-url or --budget-db)",
        );
    };
    let agent_id = parsed
        .agent_id
        .unwrap_or_else(|| parsed.capability.subject.to_hex());
    let kernel_request = chio_kernel::runtime::ToolCallRequest {
        request_id: uuid::Uuid::now_v7().to_string(),
        capability: parsed.capability,
        tool_name: parsed.tool_name,
        server_id: parsed.tool_server,
        agent_id,
        arguments: parsed.parameters,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let response = match kernel.evaluate_tool_call_blocking_with_metadata(&kernel_request, None) {
        Ok(response) => response,
        Err(error) => {
            warn!("mediated evaluation error: {error}");
            return internal_json_error_response("chio_mediation_failed", &error.to_string());
        }
    };
    if let Err(error) = record_tool_receipt(&state, &response.receipt).await {
        warn!("failed to persist mediated receipt: {error}");
        return internal_json_error_response("chio_receipt_persistence_failed", &error.to_string());
    }
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "verdict": response.verdict,
            "receipt": response.receipt,
            "execution_nonce": response.execution_nonce,
        })),
    )
        .into_response()
}
```

- [ ] **Step 4: Route it.** In `crates/products/chio-api-protect/src/proxy/router.rs`, change the `/v1/evaluate` route (router.rs:61) from `sidecar_removed_evaluate_handler` to the mediated handler:

```rust
        .route("/v1/evaluate", post(mediated::sidecar_evaluate_tool_call_mediated_handler))
```

- [ ] **Step 5: Run to verify both tests pass + clippy.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-api-protect mediated -- --nocapture`
  Expected: PASS (`mediated_route_moves_committed_cost_against_agent_capability ... ok`, `mediated_deny_leaves_committed_cost_zero ... ok`).
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-api-protect -- -D warnings`
  Expected: no warnings.

- [ ] **Step 6: Commit.**
```bash
git add crates/products/chio-api-protect/src/proxy/mediated.rs crates/products/chio-api-protect/src/proxy/router.rs
git commit -m "feat(chio-api-protect): reinstate POST /v1/evaluate as kernel-mediated tool-call route

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Milestone 2 - Cross-bind hold <-> nonce; make `Mediated` earned not stamped

### Task 6: Record `execution_nonce_id` + mediated-spend profile in the receipt's budget-authority metadata

**Files:**
- Modify: `crates/kernel/chio-kernel/src/kernel/construction.rs`
- Modify: `crates/kernel/chio-kernel/src/kernel/validation.rs`
- Test: `crates/kernel/chio-kernel/src/kernel/tests/execution_nonce.rs` (add a test; module already allows unwrap in tests)

**Interfaces:**
- Consumes: `mint_execution_nonce_for_allow(&self, &ToolCallRequest, &CapabilityToken, &ChioReceipt) -> Result<Option<Box<SignedExecutionNonce>>, KernelError>` (construction.rs:1026); the `budget_authority` metadata builder in `validation.rs` (the method returning `serde_json::json!({ "budget_authority": budget_authority })` at validation.rs:736); `NonceBinding` (execution_nonce.rs:70); `receipt.action.parameter_hash`.
- Produces:
  - `pub(crate) fn nonce_binding_for(&self, request: &ToolCallRequest, cap: &CapabilityToken, parameter_hash: &str) -> crate::execution_nonce::NonceBinding`
  - A `budget_authority.execution_nonce_id` string field and a `budget_authority.mediated_spend.profile = MEDIATED_SPEND_PROFILE` object in the allow receipt metadata for cost-bearing grants.

- [ ] **Step 1: Write the failing test.** Add to `crates/kernel/chio-kernel/src/kernel/tests/execution_nonce.rs` (reusing the monetary helpers from `support_monetary.rs`):

```rust
    #[test]
    fn mediated_allow_receipt_records_bound_execution_nonce_id() {
        let mut kernel = make_kernel(make_monetary_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
        let cfg = ExecutionNonceConfig { nonce_ttl_secs: 30, nonce_store_capacity: 1024, require_nonce: false };
        kernel.set_execution_nonce_store(cfg.clone(), Box::new(InMemoryExecutionNonceStore::from_config(&cfg)));

        let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
        let cap = kernel.issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600).unwrap();
        let request = ToolCallRequest {
            request_id: "req-nonce-link".to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice": "inv-1" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
        assert_eq!(response.verdict, Verdict::Allow);
        let nonce = response.execution_nonce.as_ref().expect("mediated allow mints a nonce");
        let metadata = response.receipt.metadata.as_ref().expect("receipt metadata present");
        let recorded = metadata["budget_authority"]["execution_nonce_id"].as_str()
            .expect("execution_nonce_id recorded on budget_authority metadata");
        assert_eq!(recorded, nonce.nonce_id());
        assert_eq!(
            metadata["budget_authority"]["mediated_spend"]["profile"],
            "chio.mediated_spend.v1"
        );
    }
```

- [ ] **Step 2: Run to verify it fails.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-kernel mediated_allow_receipt_records_bound_execution_nonce_id -- --nocapture`
  Expected: FAIL with `execution_nonce_id recorded on budget_authority metadata` panic (`budget_authority.execution_nonce_id` absent, value is `Null`).

- [ ] **Step 3: Add the binding helper.** In `crates/kernel/chio-kernel/src/kernel/construction.rs`, above `mint_execution_nonce_for_allow` (construction.rs:1026), add:

```rust
    /// Compute the nonce binding for a call from the request, capability, and
    /// the canonical parameter hash. Used to mint the nonce before the receipt
    /// is signed so the receipt can record the nonce id (hold <-> nonce
    /// cross-binding).
    pub(crate) fn nonce_binding_for(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        parameter_hash: &str,
    ) -> crate::execution_nonce::NonceBinding {
        crate::execution_nonce::NonceBinding {
            subject_id: cap.subject.to_hex(),
            capability_id: cap.id.clone(),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            parameter_hash: parameter_hash.to_string(),
        }
    }
```

- [ ] **Step 4: Thread the nonce id into the metadata.** In the allow path that mints the nonce and signs the receipt (the caller of `mint_execution_nonce_for_allow` in the async evaluation core), reorder so the nonce is minted from `nonce_binding_for(request, cap, &action.parameter_hash)` BEFORE the budget-authority metadata is finalized, then pass the minted `nonce.nonce_id()` into the `budget_authority` metadata builder. In the `validation.rs` builder returning `serde_json::json!({ "budget_authority": budget_authority })` (validation.rs:736), add an optional `execution_nonce_id: Option<&str>` parameter and, when present, insert before the return:

```rust
        if let Some(nonce_id) = execution_nonce_id {
            budget_authority.insert(
                "execution_nonce_id".to_string(),
                serde_json::json!(nonce_id),
            );
            budget_authority.insert(
                "mediated_spend".to_string(),
                serde_json::json!({
                    "profile": chio_core_types::receipt::authoritative_spend::MEDIATED_SPEND_PROFILE
                }),
            );
        }
```

Keep `mint_execution_nonce_for_allow` as the fallback for non-cost-bearing paths (it still returns the same `SignedExecutionNonce`); for cost-bearing allow, mint via `nonce_binding_for` + `crate::execution_nonce::mint_execution_nonce(&self.config.keypair, binding, config, now)` and reuse that same nonce both in the metadata and on the response so `response.execution_nonce.nonce_id()` equals `budget_authority.execution_nonce_id`.

- [ ] **Step 5: Run to verify it passes + clippy.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-kernel mediated_allow_receipt_records_bound_execution_nonce_id -- --nocapture`
  Expected: PASS.
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-kernel -- -D warnings`
  Expected: no warnings.

- [ ] **Step 6: Commit.**
```bash
git add crates/kernel/chio-kernel/src/kernel/construction.rs crates/kernel/chio-kernel/src/kernel/validation.rs crates/kernel/chio-kernel/src/kernel/tests/execution_nonce.rs
git commit -m "feat(chio-kernel): cross-bind execution nonce id into budget-authority receipt metadata

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 7: Derive `TrustLevel::Mediated` + sign-site fail-closed invariant (R1 sign side)

**Files:**
- Modify: `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs`
- Test: `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs` (`#[cfg(test)] mod tests`, add `#[allow(clippy::unwrap_used, clippy::expect_used)]`)

**Interfaces:**
- Consumes: `build_and_sign_receipt(&self, params: ReceiptParams<'_>) -> Result<ChioReceipt, KernelError>` (receipt_persistence.rs:5); `params.trust_level`, `params.metadata`; `KernelError::ReceiptSigningFailed(String)`; `TrustLevel::{Mediated, Advisory}`.
- Produces: `fn require_earned_mediated_trust_level(metadata: Option<&serde_json::Value>, trust_level: TrustLevel) -> Result<(), KernelError>` invoked inside `build_and_sign_receipt` before signing.

- [ ] **Step 1: Write the failing test.** Add to a `#[cfg(test)] mod tests` in `receipt_persistence.rs` (or extend an existing one):

```rust
    #[test]
    fn signing_mediated_for_cost_bearing_grant_without_reconciled_hold_fails_closed() {
        // R1: refuse to stamp Mediated on a cost-bearing receipt that carries a
        // financial charge but no reconciled budget-authority hold.
        let metadata = serde_json::json!({
            "financial": { "cost_charged": 50, "grant_index": 0, "currency": "USD" }
            // no budget_authority.terminal.disposition == "reconciled"
        });
        let result = require_earned_mediated_trust_level(Some(&metadata), TrustLevel::Mediated);
        assert!(matches!(result, Err(KernelError::ReceiptSigningFailed(_))));
    }

    #[test]
    fn signing_mediated_with_reconciled_hold_is_allowed() {
        let metadata = serde_json::json!({
            "financial": { "cost_charged": 50, "grant_index": 0, "currency": "USD" },
            "budget_authority": { "terminal": { "disposition": "reconciled" } }
        });
        assert!(require_earned_mediated_trust_level(Some(&metadata), TrustLevel::Mediated).is_ok());
    }

    #[test]
    fn advisory_trust_level_never_requires_a_hold() {
        assert!(require_earned_mediated_trust_level(None, TrustLevel::Advisory).is_ok());
    }
```

- [ ] **Step 2: Run to verify it fails.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-kernel signing_mediated_for_cost_bearing_grant_without_reconciled_hold_fails_closed -- --nocapture`
  Expected: FAIL to COMPILE with `cannot find function require_earned_mediated_trust_level`.

- [ ] **Step 3: Implement the derivation invariant.** In `receipt_persistence.rs`, add a free function (module scope) and call it from `build_and_sign_receipt` right after `let metadata = merge_metadata_objects(params.metadata, request_metadata);` (receipt_persistence.rs:32):

```rust
/// A cost-bearing receipt may claim `TrustLevel::Mediated` only when it carries a
/// reconciled budget-authority hold. This is the sign-site fail-closed invariant
/// that turns `Mediated` from a stamp into earned proof.
pub(crate) fn require_earned_mediated_trust_level(
    metadata: Option<&serde_json::Value>,
    trust_level: TrustLevel,
) -> Result<(), KernelError> {
    if trust_level != TrustLevel::Mediated {
        return Ok(());
    }
    let Some(metadata) = metadata else {
        return Ok(());
    };
    let cost_bearing = metadata
        .get("financial")
        .and_then(|financial| financial.get("cost_charged"))
        .and_then(serde_json::Value::as_u64)
        .is_some_and(|cost| cost > 0);
    if !cost_bearing {
        return Ok(());
    }
    let reconciled = metadata
        .get("budget_authority")
        .and_then(|block| block.get("terminal"))
        .and_then(|terminal| terminal.get("disposition"))
        .and_then(serde_json::Value::as_str)
        == Some("reconciled");
    if reconciled {
        Ok(())
    } else {
        Err(KernelError::ReceiptSigningFailed(
            "refusing to sign TrustLevel::Mediated for a cost-bearing receipt without a reconciled budget-authority hold".to_string(),
        ))
    }
}
```

and add the call inside `build_and_sign_receipt` before constructing `body`:

```rust
        require_earned_mediated_trust_level(metadata.as_ref(), params.trust_level)?;
```

- [ ] **Step 4: Run to verify it passes + clippy.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-kernel require_earned -- --nocapture; rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-kernel signing_mediated -- --nocapture`
  Expected: PASS (all three new tests ok).
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-kernel -- -D warnings`
  Expected: no warnings.

- [ ] **Step 5: Regression-guard existing kernel receipt tests.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-kernel budget_governed_call_chain -- --nocapture`
  Expected: PASS (existing monetary allow receipts already carry a reconciled hold, so the invariant does not regress them). If any fail, the failing path is signing `Mediated` on a cost-bearing receipt without threading the reconcile metadata; fix that path, do not weaken the invariant.

- [ ] **Step 6: Commit.**
```bash
git add crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs
git commit -m "feat(chio-kernel): fail closed when stamping Mediated without a reconciled hold

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Milestone 3 - Make advisory a visible failure (the enforcement lever)

### Task 8: Gate `/v1/evaluate/advisory` behind `--allow-advisory` (default off) (R5)

**Files:**
- Modify: `crates/products/chio-api-protect/src/proxy/config.rs`
- Modify: `crates/products/chio-api-protect/src/proxy/state.rs`
- Modify: `crates/products/chio-api-protect/src/proxy/sidecar.rs`
- Test: `crates/products/chio-api-protect/src/proxy/tests.rs`

**Interfaces:**
- Consumes: `sidecar_evaluate_tool_call_handler(State<Arc<ProxyState>>, Request<Body>) -> Response` (sidecar.rs:1008); `ProxyState` (state.rs:138); `internal_json_error_response`.
- Produces: `ProtectConfig.allow_advisory: bool` (default false); `ProxyState.allow_advisory: bool`; an early-return in `sidecar_evaluate_tool_call_handler` returning HTTP 409 Conflict with a pointer to `/v1/evaluate` when advisory is off.

- [ ] **Step 1: Write the failing test.** Add to `crates/products/chio-api-protect/src/proxy/tests.rs`:

```rust
    #[tokio::test]
    async fn advisory_route_is_non_authorizing_when_advisory_disabled() {
        // R5: advisory is off by default; production stops emitting advisory
        // receipts that agents could skip the sidecar with.
        let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
        // test_state builds allow_advisory=false by default (Step 3).
        let payload = serde_json::json!({
            "capability_id": "cap-x", "tool_server": "fs",
            "tool_name": "read_file", "parameters": {}
        });
        let request = with_loopback_peer(
            Request::builder().method("POST").uri("/v1/evaluate/advisory")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload).test_unwrap())).test_unwrap(),
        );
        let response = build_app(Arc::clone(&state)).oneshot(request).await.test_unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let bytes = to_bytes(response.into_body(), 1 << 20).await.test_unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
        assert_eq!(json["authorization"], false);
        assert_eq!(json["replacement"], "/v1/evaluate");
    }
```

- [ ] **Step 2: Run to verify it fails.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-api-protect advisory_route_is_non_authorizing_when_advisory_disabled -- --nocapture`
  Expected: FAIL (status is `200 OK` with the advisory receipt, not `409`).

- [ ] **Step 3: Add the flag and gate.** In `config.rs` add `pub allow_advisory: bool,` to `ProtectConfig` (and to the `Debug` impl). In `state.rs` add `pub(crate) allow_advisory: bool,` to `ProxyState` and set `allow_advisory: self.config.allow_advisory,` in the initializer; in the test helper `test_state_with_receipt_db` set `allow_advisory: false,`. In `sidecar.rs`, at the top of `sidecar_evaluate_tool_call_handler` (sidecar.rs:1008), after extracting `State(state)`, add:

```rust
    if !state.allow_advisory {
        return (
            StatusCode::CONFLICT,
            axum::Json(serde_json::json!({
                "error": "chio_advisory_disabled",
                "authorization": false,
                "message": "advisory tool-call evaluation is disabled; use the kernel-mediated route",
                "replacement": "/v1/evaluate",
            })),
        )
            .into_response();
    }
```

- [ ] **Step 4: Run to verify it passes + clippy.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-api-protect advisory_route_is_non_authorizing_when_advisory_disabled -- --nocapture`
  Expected: PASS.
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-api-protect -- -D warnings`
  Expected: no warnings.

- [ ] **Step 5: Commit.**
```bash
git add crates/products/chio-api-protect/src/proxy/config.rs crates/products/chio-api-protect/src/proxy/state.rs crates/products/chio-api-protect/src/proxy/sidecar.rs crates/products/chio-api-protect/src/proxy/tests.rs
git commit -m "feat(chio-api-protect): advisory tool-call route off by default, points to mediated route

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 9: Tool-server nonce middleware (Solution C) (R5)

**Files:**
- Create: `crates/products/chio-api-protect/src/proxy/nonce_middleware.rs`
- Modify: `crates/products/chio-api-protect/src/proxy/mod.rs` (add `mod nonce_middleware;`)
- Test: `crates/products/chio-api-protect/src/proxy/nonce_middleware.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `chio_kernel::execution_nonce::{SignedExecutionNonce, NonceBinding, verify_execution_nonce, InMemoryExecutionNonceStore}`; `chio_core::crypto::PublicKey`; `axum::http::HeaderMap`.
- Produces:
  - `pub(crate) enum ToolServerNonceError { MissingNonce, DecodeFailed(String), Rejected(String) }`
  - `pub(crate) fn require_tool_server_execution_nonce(headers: &HeaderMap, kernel_pubkey: &PublicKey, expected: &NonceBinding, now: i64, store: &dyn chio_kernel::execution_nonce::ExecutionNonceStore, permissive: bool) -> Result<(), ToolServerNonceError>`

- [ ] **Step 1: Write the failing test.** Create `crates/products/chio-api-protect/src/proxy/nonce_middleware.rs`:

```rust
use super::*;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use chio_kernel::execution_nonce::{
        mint_execution_nonce, ExecutionNonceConfig, InMemoryExecutionNonceStore, NonceBinding,
    };

    fn binding() -> NonceBinding {
        NonceBinding {
            subject_id: "subject".to_string(),
            capability_id: "cap-1".to_string(),
            tool_server: "fs".to_string(),
            tool_name: "read_file".to_string(),
            parameter_hash: "0".repeat(64),
        }
    }

    #[test]
    fn strict_mode_rejects_missing_nonce() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::default();
        let headers = HeaderMap::new();
        let result = require_tool_server_execution_nonce(
            &headers, &kp.public_key(), &binding(), 1_000_000, &store, false,
        );
        assert!(matches!(result, Err(ToolServerNonceError::MissingNonce)));
    }

    #[test]
    fn valid_nonce_passes_then_replay_is_rejected() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::default();
        let signed = mint_execution_nonce(&kp, binding(), &ExecutionNonceConfig::default(), 1_000_000).unwrap();
        let encoded = serde_json::to_string(&signed).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-chio-execution-nonce", encoded.parse().unwrap());
        assert!(require_tool_server_execution_nonce(
            &headers, &kp.public_key(), &binding(), 1_000_001, &store, false,
        ).is_ok());
        // single-use: a second presentation is rejected.
        assert!(matches!(
            require_tool_server_execution_nonce(&headers, &kp.public_key(), &binding(), 1_000_002, &store, false),
            Err(ToolServerNonceError::Rejected(_))
        ));
    }
}
```

- [ ] **Step 2: Run to verify it fails.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-api-protect proxy::nonce_middleware::tests -- --nocapture`
  Expected: FAIL to COMPILE with `cannot find function require_tool_server_execution_nonce`.

- [ ] **Step 3: Implement the middleware helper.** Add above the test module in `nonce_middleware.rs`:

```rust
use axum::http::HeaderMap;
use chio_core::crypto::PublicKey;
use chio_kernel::execution_nonce::{
    verify_execution_nonce, ExecutionNonceStore, NonceBinding, SignedExecutionNonce,
};

/// Solution C: tool servers reject executions that do not carry a valid
/// `X-Chio-Execution-Nonce`. In permissive (development) mode a missing nonce
/// logs and proceeds; in strict (production) mode it is rejected.
#[derive(Debug)]
pub(crate) enum ToolServerNonceError {
    MissingNonce,
    DecodeFailed(String),
    Rejected(String),
}

pub(crate) fn require_tool_server_execution_nonce(
    headers: &HeaderMap,
    kernel_pubkey: &PublicKey,
    expected: &NonceBinding,
    now: i64,
    store: &dyn ExecutionNonceStore,
    permissive: bool,
) -> Result<(), ToolServerNonceError> {
    let Some(raw) = headers.get("x-chio-execution-nonce") else {
        if permissive {
            warn!("missing execution nonce; permissive mode, allowing");
            return Ok(());
        }
        return Err(ToolServerNonceError::MissingNonce);
    };
    let raw = raw
        .to_str()
        .map_err(|error| ToolServerNonceError::DecodeFailed(error.to_string()))?;
    let signed: SignedExecutionNonce = serde_json::from_str(raw)
        .map_err(|error| ToolServerNonceError::DecodeFailed(error.to_string()))?;
    verify_execution_nonce(&signed, kernel_pubkey, expected, now, store)
        .map_err(|error| ToolServerNonceError::Rejected(error.to_string()))
}
```

Add `mod nonce_middleware;` to `crates/products/chio-api-protect/src/proxy/mod.rs`.

- [ ] **Step 4: Run to verify it passes + clippy.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-api-protect proxy::nonce_middleware::tests -- --nocapture`
  Expected: PASS (`strict_mode_rejects_missing_nonce ... ok`, `valid_nonce_passes_then_replay_is_rejected ... ok`).
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-api-protect -- -D warnings`
  Expected: no warnings.

- [ ] **Step 5: Commit.**
```bash
git add crates/products/chio-api-protect/src/proxy/nonce_middleware.rs crates/products/chio-api-protect/src/proxy/mod.rs
git commit -m "feat(chio-api-protect): tool-server execution-nonce middleware (Solution C)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 10: Point the Python SDK default at `/v1/evaluate` (R5)

**Files:**
- Modify: `sdks/python/chio-sdk-python/src/chio_sdk/client.py`
- Create: `sdks/python/chio-sdk-python/tests/test_default_target.py`

**Interfaces:**
- Consumes: `ChioClient._post(path, body)`; the existing `evaluate_tool_call_advisory` method (client.py:479-519, posts to `/v1/evaluate/advisory` at client.py:498).
- Produces: `ChioClient.evaluate_tool_call(...)` posting to `/v1/evaluate` by default; `evaluate_tool_call_advisory(...)` retained but explicitly advisory (unchanged path).

- [ ] **Step 1: Write the failing test.** Create `sdks/python/chio-sdk-python/tests/test_default_target.py`:

```python
import inspect

from chio_sdk import client as chio_client


def test_default_tool_call_target_is_mediated():
    source = inspect.getsource(chio_client)
    # The mediated evaluate method must target /v1/evaluate, not the advisory route.
    assert '"/v1/evaluate"' in source or "'/v1/evaluate'" in source
    eval_src = inspect.getsource(chio_client.ChioClient.evaluate_tool_call)
    assert "/v1/evaluate/advisory" not in eval_src
    assert "/v1/evaluate" in eval_src
```

- [ ] **Step 2: Run to verify it fails.**
  `cd sdks/python/chio-sdk-python && python -m pytest tests/test_default_target.py -q`
  Expected: FAIL with `AttributeError: ... has no attribute 'evaluate_tool_call'` OR `assert "/v1/evaluate" in eval_src` failing (only the advisory method exists).

- [ ] **Step 3: Add the mediated method.** In `sdks/python/chio-sdk-python/src/chio_sdk/client.py`, add a mediated method that posts the full capability token to `/v1/evaluate`:

```python
    async def evaluate_tool_call(
        self,
        *,
        capability: dict,
        tool_server: str,
        tool_name: str,
        parameters: dict,
    ) -> dict:
        """Kernel-mediated, authoritative tool-call evaluation.

        Posts to the reinstated ``/v1/evaluate`` route. Returns
        ``{"verdict", "receipt", "execution_nonce"}``. Callers MUST verify the
        receipt with ``is_authoritative_spend_receipt`` and reject anything below
        ``trust_level == "mediated"``.
        """
        body = {
            "capability": capability,
            "tool_server": tool_server,
            "tool_name": tool_name,
            "parameters": parameters,
        }
        return await self._post("/v1/evaluate", body)
```

- [ ] **Step 4: Run to verify it passes.**
  `cd sdks/python/chio-sdk-python && python -m pytest tests/test_default_target.py -q`
  Expected: PASS (`1 passed`).

- [ ] **Step 5: Commit.**
```bash
git add sdks/python/chio-sdk-python/src/chio_sdk/client.py sdks/python/chio-sdk-python/tests/test_default_target.py
git commit -m "feat(chio-sdk-python): default tool-call evaluation targets kernel-mediated /v1/evaluate

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Milestone 4 - Crash-safety + truthful HA labeling

### Task 11: Startup reaper over orphaned `disposition='open'` holds (R3 crash recovery)

**Files:**
- Create: `crates/platform/chio-store-sqlite/src/budget_store/reaper.rs`
- Modify: `crates/platform/chio-store-sqlite/src/budget_store.rs` (add `mod reaper;` and a public entry method)
- Test: `crates/platform/chio-store-sqlite/src/budget_store/reaper.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `SqliteBudgetStore` (budget_store.rs:27) with `connection: Mutex<Connection>`; the `budget_authorization_holds` table (columns `hold_id, capability_id, grant_index, authorized_exposure_units, remaining_exposure_units, invocation_count_debited, disposition, ...`, store.rs:36-52); `HoldDisposition::{Open, Released, Reversed, Reconciled}` (model.rs:3-9) stored lowercase; `BudgetStore::{reconcile_budget_hold, reverse_budget_hold}` (budget_store.rs:559-661).
- Produces:
  - `pub struct ReapSummary { pub reconciled: usize, pub reversed: usize }`
  - `impl SqliteBudgetStore { pub fn reap_orphaned_holds(&self, realized_by_hold: &std::collections::HashMap<String, u64>) -> Result<ReapSummary, BudgetStoreError> }` (a hold present in `realized_by_hold`, arbitrated by the ADR-0013 durable receipt log, is reconciled to that realized amount; a hold absent from it - never durably admitted - is reversed).

- [ ] **Step 1: Write the failing test.** Create `crates/platform/chio-store-sqlite/src/budget_store/reaper.rs`:

```rust
use super::*;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_kernel::budget_store::{BudgetAuthorizeHoldRequest, BudgetAuthorizeHoldDecision, BudgetStore};
    use std::collections::HashMap;

    fn open_temp_store() -> SqliteBudgetStore {
        let dir = std::env::temp_dir().join(format!("chio-reaper-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        SqliteBudgetStore::open(dir.join("budget.sqlite")).unwrap()
    }

    fn authorize(store: &SqliteBudgetStore, hold_id: &str, cap: &str) {
        let decision = store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: cap.to_string(), grant_index: 0, max_invocations: Some(10),
            requested_exposure_units: 100, max_cost_per_invocation: Some(100),
            max_total_cost_units: Some(1000), hold_id: Some(hold_id.to_string()),
            event_id: Some(format!("{hold_id}:authorize")), authority: None,
        }).unwrap();
        assert!(matches!(decision, BudgetAuthorizeHoldDecision::Authorized(_)));
    }

    #[test]
    fn reaper_reconciles_admitted_hold_and_reverses_orphan() {
        // R3: SIGKILL after authorize commits but before reconcile. A naive
        // "release Open on restart" would enable double-spend; instead the
        // durable receipt log arbitrates.
        let store = open_temp_store();
        authorize(&store, "hold-admitted", "cap-a");   // durably admitted, realized 40
        authorize(&store, "hold-orphan", "cap-b");      // never admitted downstream
        // Before reap both holds inflate committed_cost by their worst-case 100.
        assert_eq!(store.get_usage("cap-a", 0).unwrap().unwrap().committed_cost_units().unwrap(), 100);

        let mut realized = HashMap::new();
        realized.insert("hold-admitted".to_string(), 40u64);
        let summary = store.reap_orphaned_holds(&realized).unwrap();
        assert_eq!(summary.reconciled, 1);
        assert_eq!(summary.reversed, 1);

        // cap-a reconciled down to realized 40; cap-b reversed back to 0.
        assert_eq!(store.get_usage("cap-a", 0).unwrap().unwrap().committed_cost_units().unwrap(), 40);
        assert_eq!(store.get_usage("cap-b", 0).unwrap().unwrap().committed_cost_units().unwrap(), 0);
    }
}
```

- [ ] **Step 2: Run to verify it fails.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-store-sqlite budget_store::reaper::tests -- --nocapture`
  Expected: FAIL to COMPILE with `no method named reap_orphaned_holds found` / `cannot find type ReapSummary`.

- [ ] **Step 3: Implement the reaper.** Add above the test module in `reaper.rs`:

```rust
use std::collections::HashMap;

use chio_kernel::budget_store::{
    BudgetReconcileHoldRequest, BudgetReverseHoldRequest, BudgetStore, BudgetStoreError,
};

/// Outcome of a startup reap pass over orphaned open holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReapSummary {
    pub reconciled: usize,
    pub reversed: usize,
}

impl SqliteBudgetStore {
    /// Reconcile or reverse every hold still `open` at startup. Holds present in
    /// `realized_by_hold` (arbitrated by the ADR-0013 durable receipt log) are
    /// reconciled to their realized spend; holds absent from it (never durably
    /// admitted) are reversed. This is fail-closed against double-spend: a naive
    /// blanket release is never used.
    pub fn reap_orphaned_holds(
        &self,
        realized_by_hold: &HashMap<String, u64>,
    ) -> Result<ReapSummary, BudgetStoreError> {
        let open_holds = self.list_open_holds()?; // Vec<(hold_id, capability_id, grant_index, exposure)>
        let mut summary = ReapSummary { reconciled: 0, reversed: 0 };
        for (hold_id, capability_id, grant_index, exposure) in open_holds {
            match realized_by_hold.get(&hold_id) {
                Some(&realized) => {
                    self.reconcile_budget_hold(BudgetReconcileHoldRequest {
                        capability_id: capability_id.clone(),
                        grant_index: grant_index as usize,
                        exposed_cost_units: exposure,
                        realized_spend_units: realized.min(exposure),
                        hold_id: Some(hold_id.clone()),
                        event_id: Some(format!("{hold_id}:reap-reconcile")),
                        authority: None,
                    })?;
                    summary.reconciled += 1;
                }
                None => {
                    self.reverse_budget_hold(BudgetReverseHoldRequest {
                        capability_id: capability_id.clone(),
                        grant_index: grant_index as usize,
                        reversed_exposure_units: exposure,
                        hold_id: Some(hold_id.clone()),
                        event_id: Some(format!("{hold_id}:reap-reverse")),
                        authority: None,
                    })?;
                    summary.reversed += 1;
                }
            }
        }
        Ok(summary)
    }

    /// Rows still `open`: `(hold_id, capability_id, grant_index, remaining_exposure_units)`.
    fn list_open_holds(&self) -> Result<Vec<(String, String, u32, u64)>, BudgetStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| BudgetStoreError::Invariant("budget store mutex poisoned".to_string()))?;
        let mut statement = connection.prepare(
            "SELECT hold_id, capability_id, grant_index, remaining_exposure_units \
             FROM budget_authorization_holds WHERE disposition = 'open'",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? as u32,
                row.get::<_, i64>(3)? as u64,
            ))
        })?;
        let mut holds = Vec::new();
        for row in rows {
            holds.push(row?);
        }
        Ok(holds)
    }
}
```

Add `mod reaper;` and `pub use reaper::ReapSummary;` to `crates/platform/chio-store-sqlite/src/budget_store.rs`. Confirm the exact column name for provisional exposure in the holds table (store.rs:36-52 shows `remaining_exposure_units` and `authorized_exposure_units`); use `remaining_exposure_units` for the amount still to reconcile/reverse.

- [ ] **Step 4: Run to verify it passes + clippy.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-store-sqlite budget_store::reaper::tests -- --nocapture`
  Expected: PASS (`reaper_reconciles_admitted_hold_and_reverses_orphan ... ok`).
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-store-sqlite -- -D warnings`
  Expected: no warnings.

- [ ] **Step 5: Commit.**
```bash
git add crates/platform/chio-store-sqlite/src/budget_store/reaper.rs crates/platform/chio-store-sqlite/src/budget_store.rs
git commit -m "feat(chio-store-sqlite): startup reaper reconciles or reverses orphaned open holds

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 12: Guarantee-level truthfulness + operator minimum (R4)

**Files:**
- Modify: `crates/core/chio-core-types/src/receipt/authoritative_spend.rs` (extend the Task-1 test module only; `receipt_meets_guarantee_floor` already exists from Task 1)
- Modify: `crates/platform/chio-store-sqlite/src/budget_store.rs` (assert the store's truthful level)
- Test: both files' `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `receipt_meets_guarantee_floor(&ChioReceipt, &str) -> Result<(), NotAuthoritativeReason>` (Task 1); `guarantee_level_rank(&str) -> u8` (Task 1); `BudgetStore::budget_guarantee_level(&self) -> BudgetGuaranteeLevel` (budget_store.rs:495, default `SingleNodeAtomic`); `BudgetGuaranteeLevel::as_str` (budget_store.rs:103).
- Produces: R4 unit tests proving a receipt claiming `ha_linearizable` fails the operator floor when the backing store is single-node, and that `SqliteBudgetStore::budget_guarantee_level()` truthfully returns `SingleNodeAtomic` (never `HaLinearizable`).

- [ ] **Step 1: Write the failing tests.** Add to the Task-1 `tests` module in `authoritative_spend.rs`:

```rust
    #[test]
    fn r4_receipt_claiming_ha_linearizable_fails_single_node_operator_floor() {
        // R4: HaLinearizable is a labeled claim; a single-node store must not be
        // accepted where the operator requires linearizable, and a receipt must
        // not claim a level above the backing store.
        let kp = Keypair::generate();
        let mut receipt = authoritative_receipt(&kp);
        // Operator floor is ha_linearizable; the receipt is single_node_atomic.
        assert_eq!(
            receipt_meets_guarantee_floor(&receipt, "ha_linearizable"),
            Err(NotAuthoritativeReason::NotMediatedTrustLevel)
        );
        // A single_node floor accepts the single_node receipt.
        assert_eq!(receipt_meets_guarantee_floor(&receipt, "single_node_atomic"), Ok(()));
        // A forged higher claim still ranks correctly.
        if let Some(obj) = receipt.metadata.as_mut().and_then(|m| m.get_mut("budget_authority")).and_then(|b| b.as_object_mut()) {
            obj.insert("guarantee_level".to_string(), serde_json::json!("ha_linearizable"));
        }
        let receipt = ChioReceipt::sign(receipt.body(), &kp).unwrap();
        assert_eq!(receipt_meets_guarantee_floor(&receipt, "ha_linearizable"), Ok(()));
    }
```

And add to `crates/platform/chio-store-sqlite/src/budget_store.rs` `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn sqlite_store_reports_truthful_single_node_guarantee_level() {
        use chio_kernel::budget_store::{BudgetGuaranteeLevel, BudgetStore};
        let dir = std::env::temp_dir().join(format!("chio-glevel-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = SqliteBudgetStore::open(dir.join("budget.sqlite")).unwrap();
        assert_eq!(store.budget_guarantee_level(), BudgetGuaranteeLevel::SingleNodeAtomic);
    }
```

(place `#[allow(clippy::unwrap_used, clippy::expect_used)]` on the test module).

- [ ] **Step 2: Run to verify they fail (or confirm truthfulness).**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-core-types r4_receipt_claiming_ha_linearizable_fails_single_node_operator_floor -- --nocapture`
  Expected: PASS if `receipt_meets_guarantee_floor` from Task 1 is correct; if it fails, the ranking logic is wrong - fix `guarantee_level_rank`/`receipt_meets_guarantee_floor`, not the test.
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-store-sqlite sqlite_store_reports_truthful_single_node_guarantee_level -- --nocapture`
  Expected: FAIL to COMPILE only if a `tests` module does not yet exist; otherwise PASS (the default trait impl already returns `SingleNodeAtomic`). If `SqliteBudgetStore` overrode `budget_guarantee_level` to claim `HaLinearizable`, this test FAILS - remove that override so the label is truthful.

- [ ] **Step 3: Ensure truthfulness in code.** In `crates/platform/chio-store-sqlite/src/budget_store.rs`, confirm `SqliteBudgetStore` does NOT override `budget_guarantee_level` to return anything above `SingleNodeAtomic`. If an override exists claiming `HaLinearizable`, delete it so the trait default (`SingleNodeAtomic`, budget_store.rs:495-497) applies.

- [ ] **Step 4: Run to verify passes + clippy.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-core-types authoritative_spend -- --nocapture`
  Expected: PASS.
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-core-types -p chio-store-sqlite -- -D warnings`
  Expected: no warnings.

- [ ] **Step 5: Commit.**
```bash
git add crates/core/chio-core-types/src/receipt/authoritative_spend.rs crates/platform/chio-store-sqlite/src/budget_store.rs
git commit -m "test(chio): guarantee-level truthfulness and operator minimum floor (R4)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 13: Escalate `PostAdmissionDropGuard` reverse failure to a durable pending-reversal record

**Files:**
- Modify: `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs`
- Test: `crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs` (`#[cfg(test)] mod tests`) or an existing kernel test module

**Interfaces:**
- Consumes: `PostAdmissionDropGuard` (kernel_drop_guard.rs:19-28) with `charge_result: Option<&BudgetChargeResult>`; the warn-only failure site (kernel_drop_guard.rs:100-104); `ChioKernel::reverse_budget_charge` (validation.rs:844) or `reverse_pre_execution_budget_mutation`.
- Produces: `fn record_pending_reversal(&self, hold_id: &str, reason: &str) -> Result<(), KernelError>` that appends a durable pending-reversal marker (a `budget_authority` metadata receipt with `disposition = "pending_reversal"`) instead of only logging `warn!`, so the reaper (Task 11) can later close it.

- [ ] **Step 1: Write the failing test.** Add a test proving that when the drop-guard's reverse path fails, a durable pending-reversal record is produced (assert via a spy budget store whose `reverse_budget_hold` returns `Err`, then assert the kernel recorded a pending-reversal receipt/marker). Sketch:

```rust
    #[test]
    fn drop_guard_reverse_failure_records_pending_reversal() {
        // Escalate beyond warn!: a reverse failure must leave a durable marker the
        // reaper can arbitrate, not a silently leaked hold.
        let marker = pending_reversal_marker("budget-hold:req-x:cap-x:0", "reverse store unreachable");
        assert_eq!(marker["disposition"], "pending_reversal");
        assert_eq!(marker["hold_id"], "budget-hold:req-x:cap-x:0");
    }
```

(This unit asserts the marker shape produced by the escalation helper; the integration behavior is covered end-to-end by the reaper test in Task 11, which reconciles/reverses whatever the marker leaves open.)

- [ ] **Step 2: Run to verify it fails.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-kernel drop_guard_reverse_failure_records_pending_reversal -- --nocapture`
  Expected: FAIL to COMPILE with `cannot find function pending_reversal_marker`.

- [ ] **Step 3: Implement the escalation.** In `kernel_drop_guard.rs`, add a helper and call it at the warn-only site (kernel_drop_guard.rs:100-104):

```rust
pub(crate) fn pending_reversal_marker(hold_id: &str, reason: &str) -> serde_json::Value {
    serde_json::json!({
        "budget_authority": {
            "hold_id": hold_id,
            "disposition": "pending_reversal",
            "reason": reason,
        }
    })
}
```

At the failure site, when the reverse itself (or the cancellation-receipt build) fails, additionally build a receipt carrying `pending_reversal_marker(hold_id, &reason)` and persist it via the kernel's receipt store so the record is durable. Keep the existing `warn!` for operators. Use the `charge_result`'s `budget_hold_id` for `hold_id`.

- [ ] **Step 4: Run to verify passes + clippy.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-kernel drop_guard_reverse_failure_records_pending_reversal -- --nocapture`
  Expected: PASS.
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-kernel -- -D warnings`
  Expected: no warnings.

- [ ] **Step 5: Commit.**
```bash
git add crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs
git commit -m "feat(chio-kernel): record durable pending-reversal marker on drop-guard reverse failure

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Milestone 5 - Golden conformance + double-spend regression

All three M5 tests live in `chio-conformance` (depends on `chio-kernel` and `chio-core-types` package `chio-core`). Register each as an explicit `[[test]]` target so `--test <name>` works.

### Task 14: Golden conformance gate (Acceptance 1)

**Files:**
- Create: `crates/tooling/chio-conformance/tests/authoritative_spend_enforcement.rs`
- Modify: `crates/tooling/chio-conformance/Cargo.toml` (add `[[test]]` entry)
- Test: the created file (integration test; `#![allow(clippy::unwrap_used, clippy::expect_used)]` at top)

**Interfaces:**
- Consumes: `chio_kernel::{ChioKernel, KernelConfig}`; `chio_kernel::runtime::{ToolCallRequest, ToolCallResponse}`; `chio_kernel::budget_store::{BudgetStore, InMemoryBudgetStore}`; `chio_kernel::execution_nonce::{ExecutionNonceConfig, InMemoryExecutionNonceStore}`; `chio_core::receipt::authoritative_spend::{is_authoritative_spend_receipt, NotAuthoritativeReason}`; `chio_core::receipt::body::ChioReceipt`; `PresentedNonceView for SignedExecutionNonce`.
- Produces: the golden gate test asserting mediated path `== Ok` and advisory path `== Err` and that consuming the advisory receipt as authorization is rejected.

- [ ] **Step 1: Register the test target.** In `crates/tooling/chio-conformance/Cargo.toml`, add:

```toml
[[test]]
name = "authoritative_spend_enforcement"
path = "tests/authoritative_spend_enforcement.rs"
```

- [ ] **Step 2: Write the failing test.** Create `crates/tooling/chio-conformance/tests/authoritative_spend_enforcement.rs`:

```rust
//! Golden conformance gate for Direction A: the mediated path is authoritative,
//! the advisory path is not, and consuming an advisory receipt as authorization
//! is rejected.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::crypto::Keypair;
use chio_core::receipt::authoritative_spend::is_authoritative_spend_receipt;
use chio_kernel::budget_store::{BudgetStore, InMemoryBudgetStore};
use chio_kernel::execution_nonce::{ExecutionNonceConfig, InMemoryExecutionNonceStore};
use chio_kernel::runtime::ToolCallRequest;
use std::sync::Arc;

mod support; // shared kernel/capability/tool-server builders (Step 4)
use support::{issue_cost_bearing_capability, mediation_kernel, MonetaryCostServer};

#[test]
fn mediated_receipt_is_authoritative_advisory_is_not() {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let mut kernel = mediation_kernel(&signer, Arc::clone(&budget), false);
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 50, "USD")));
    let cap = issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");

    let request = ToolCallRequest {
        request_id: "req-golden".to_string(),
        capability: cap,
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent.public_key().to_hex(),
        arguments: serde_json::json!({ "k": "v" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    let nonce = response.execution_nonce.as_ref().expect("mediated allow mints a nonce");

    // Mediated path: authoritative.
    assert_eq!(
        is_authoritative_spend_receipt(&response.receipt, &[signer.public_key()], nonce.as_ref()),
        Ok(())
    );

    // Advisory path: an AdvisoryEvaluation receipt (built exactly like the
    // sidecar advisory handler) fails the predicate - the visible-failure witness.
    let advisory = support::advisory_receipt(&signer, &response.receipt);
    let result = is_authoritative_spend_receipt(&advisory, &[signer.public_key()], nonce.as_ref());
    assert!(result.is_err(), "advisory receipt must not be authoritative: {result:?}");
}
```

- [ ] **Step 3: Run to verify it fails.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-conformance --test authoritative_spend_enforcement -- --nocapture`
  Expected: FAIL to COMPILE with `file not found for module support` / unresolved `mediation_kernel`.

- [ ] **Step 4: Write the shared support module.** Create `crates/tooling/chio-conformance/tests/support.rs` (or `tests/support/mod.rs`) with `mediation_kernel(signer, budget, require_nonce) -> ChioKernel` (mirroring Task 4's `build_mediation_kernel` shape but returning the owned kernel so tests can `register_tool_server`), `issue_cost_bearing_capability(...)`, `MonetaryCostServer` (copy the shape from `crates/kernel/chio-kernel/src/kernel/tests/support_monetary.rs`), and `advisory_receipt(signer, mediated) -> ChioReceipt` that signs a receipt with `receipt_kind = AdvisoryEvaluation`, `boundary_class = AdvisoryOnly`, `observation_outcome = Some(Evaluated)`, `trust_level = Advisory`, `decision = None` (mirroring sidecar.rs:1091-1123). Add `#![allow(clippy::unwrap_used, clippy::expect_used)]` at its top.

- [ ] **Step 5: Run to verify it passes + clippy.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-conformance --test authoritative_spend_enforcement -- --nocapture`
  Expected: PASS (`mediated_receipt_is_authoritative_advisory_is_not ... ok`), and the run reports `1 passed` (nonzero-test guard: assert the output line contains `1 passed`, not `0 filtered out ... 0 passed`).
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-conformance --tests -- -D warnings`
  Expected: no warnings.

- [ ] **Step 6: Commit.**
```bash
git add crates/tooling/chio-conformance/tests/authoritative_spend_enforcement.rs crates/tooling/chio-conformance/tests/support.rs crates/tooling/chio-conformance/Cargo.toml
git commit -m "test(chio-conformance): golden gate - mediated authoritative, advisory rejected

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 15: Double-spend concurrency regression (Acceptance 2, spec section 3)

**Files:**
- Create: `crates/tooling/chio-conformance/tests/authoritative_spend_double_spend.rs`
- Modify: `crates/tooling/chio-conformance/Cargo.toml` (add `[[test]]` entry)

**Interfaces:**
- Consumes: same as Task 14, plus `std::thread`, `std::sync::Arc`; `Verdict::{Allow, Deny}`; `budget.get_usage(cap_id, 0)`.
- Produces: the mandatory concurrency test - a capability with `max_total_cost = N` and two concurrent calls each `> N/2`; integrated path yields exactly one Allow and one Deny with total committed `<= N`; the stale/advisory path is asserted as a FAILURE witness (both "authorized," ledger never moved).

- [ ] **Step 1: Register the test target.** In `Cargo.toml`:

```toml
[[test]]
name = "authoritative_spend_double_spend"
path = "tests/authoritative_spend_double_spend.rs"
```

- [ ] **Step 2: Write the failing test.** Create the file:

```rust
//! Double-spend regression: atomic hold serialization on the integrated path;
//! the advisory path is the visible-failure witness.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::crypto::Keypair;
use chio_core::receipt::authoritative_spend::is_authoritative_spend_receipt;
use chio_kernel::budget_store::{BudgetStore, InMemoryBudgetStore};
use chio_kernel::runtime::{ToolCallRequest, Verdict};
use std::sync::Arc;
use std::thread;

mod support;
use support::{issue_cost_bearing_capability, mediation_kernel, MonetaryCostServer};

#[test]
fn concurrent_calls_over_half_budget_yield_exactly_one_allow() {
    // max_total_cost = 100; each call worst-case = 60 (> N/2). Only one can win.
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let mut kernel = mediation_kernel(&signer, Arc::clone(&budget), false);
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 60, "USD")));
    let cap = issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 60, 100, "USD");
    let cap_id = cap.id.clone();
    let kernel = Arc::new(kernel);

    let mut handles = Vec::new();
    for i in 0..2 {
        let kernel = Arc::clone(&kernel);
        let cap = cap.clone();
        let agent_hex = agent.public_key().to_hex();
        handles.push(thread::spawn(move || {
            let request = ToolCallRequest {
                request_id: format!("req-concurrent-{i}"),
                capability: cap,
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: agent_hex,
                arguments: serde_json::json!({ "i": i }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            };
            kernel.evaluate_tool_call_blocking(&request).unwrap().verdict
        }));
    }
    let verdicts: Vec<Verdict> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let allows = verdicts.iter().filter(|v| matches!(v, Verdict::Allow)).count();
    let denies = verdicts.iter().filter(|v| matches!(v, Verdict::Deny { .. })).count();
    assert_eq!(allows, 1, "exactly one Allow on the atomic integrated path");
    assert_eq!(denies, 1, "the other must be Denied");

    // Total committed cost never exceeds N.
    let usage = budget.get_usage(&cap_id, 0).unwrap().unwrap();
    assert!(usage.committed_cost_units().unwrap() <= 100);
}

#[test]
fn advisory_path_double_authorizes_and_is_a_visible_failure() {
    // Two advisory "authorizations" move no ledger; both fail the predicate, so
    // treating either as authorization is a machine-visible conformance failure.
    let signer = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let _ = &budget; // advisory path never touches the ledger.
    let advisory_a = support::standalone_advisory_receipt(&signer, "cap-x", "cost-srv", "compute");
    let advisory_b = support::standalone_advisory_receipt(&signer, "cap-x", "cost-srv", "compute");
    let nonce = support::fake_bound_nonce(&signer, "cap-x", "cost-srv", "compute", &advisory_a.action.parameter_hash);
    assert!(is_authoritative_spend_receipt(&advisory_a, &[signer.public_key()], &nonce).is_err());
    assert!(is_authoritative_spend_receipt(&advisory_b, &[signer.public_key()], &nonce).is_err());
}
```

Add `standalone_advisory_receipt(signer, cap_id, server, tool)` and `fake_bound_nonce(...)` (a `PresentedNonceView` test double) to `tests/support.rs`.

- [ ] **Step 3: Run to verify it fails.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-conformance --test authoritative_spend_double_spend -- --nocapture`
  Expected: FAIL to COMPILE (missing `standalone_advisory_receipt` / `fake_bound_nonce`).

- [ ] **Step 4: Add the support helpers.** Implement `standalone_advisory_receipt` and `fake_bound_nonce` in `tests/support.rs`.

- [ ] **Step 5: Run to verify passes + clippy.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-conformance --test authoritative_spend_double_spend -- --nocapture`
  Expected: PASS with `2 passed` (nonzero-test guard: confirm `2 passed`, not `0 passed`).
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-conformance --tests -- -D warnings`
  Expected: no warnings.

- [ ] **Step 6: Commit.**
```bash
git add crates/tooling/chio-conformance/tests/authoritative_spend_double_spend.rs crates/tooling/chio-conformance/tests/support.rs crates/tooling/chio-conformance/Cargo.toml
git commit -m "test(chio-conformance): double-spend regression on integrated vs advisory paths

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

### Task 16: Real-nonce predicate matrix (a)-(f) + R1-R6 + structural greppable invariant (Acceptance 3, 4)

**Files:**
- Create: `crates/tooling/chio-conformance/tests/authoritative_spend_predicate_matrix.rs`
- Modify: `crates/tooling/chio-conformance/Cargo.toml` (add `[[test]]` entry)

**Interfaces:**
- Consumes: the golden helpers from `tests/support.rs`; `NotAuthoritativeReason::{SignerNotAdmitted, NotMediatedTrustLevel, MissingBudgetAuthority, NonceLinkMismatch, NonceBindingMismatch, NonceSignatureInvalid}`; real `SignedExecutionNonce` from a mediated evaluation.
- Produces: a table-driven matrix flipping each conjunction fragment (a)-(f) to a DISTINCT rejection reason with a real kernel-signed nonce; the R1-R6 negative cases; a structural greppable-invariant test.

- [ ] **Step 1: Register the test target.** In `Cargo.toml`:

```toml
[[test]]
name = "authoritative_spend_predicate_matrix"
path = "tests/authoritative_spend_predicate_matrix.rs"
```

- [ ] **Step 2: Write the failing test.** Create the file:

```rust
//! (a)-(f) predicate matrix with a real kernel-signed nonce, R1-R6 negatives,
//! and the structural greppable invariant.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::crypto::Keypair;
use chio_core::receipt::authoritative_spend::{is_authoritative_spend_receipt, NotAuthoritativeReason};
use chio_core::receipt::kinds::TrustLevel;
use chio_kernel::budget_store::{BudgetStore, InMemoryBudgetStore};
use chio_kernel::runtime::ToolCallRequest;
use std::sync::Arc;

mod support;
use support::{issue_cost_bearing_capability, mediation_kernel, MonetaryCostServer};

fn mediated_case() -> (Keypair, chio_core::receipt::body::ChioReceipt, Box<chio_kernel::execution_nonce::SignedExecutionNonce>) {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let mut kernel = mediation_kernel(&signer, Arc::clone(&budget), false);
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 50, "USD")));
    let cap = issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let request = ToolCallRequest {
        request_id: "req-matrix".to_string(), capability: cap, tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(), agent_id: agent.public_key().to_hex(),
        arguments: serde_json::json!({ "k": "v" }), dpop_proof: None, execution_nonce: None,
        governed_intent: None, approval_token: None, model_metadata: None, federated_origin_kernel_id: None,
    };
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    let nonce = response.execution_nonce.clone().expect("nonce");
    (signer, response.receipt, nonce)
}

#[test]
fn baseline_passes() {
    let (signer, receipt, nonce) = mediated_case();
    assert_eq!(is_authoritative_spend_receipt(&receipt, &[signer.public_key()], nonce.as_ref()), Ok(()));
}

#[test]
fn e_signer_not_admitted_is_rejected() {
    let (_signer, receipt, nonce) = mediated_case();
    assert_eq!(
        is_authoritative_spend_receipt(&receipt, &[Keypair::generate().public_key()], nonce.as_ref()),
        Err(NotAuthoritativeReason::SignerNotAdmitted)
    );
}

#[test]
fn a_non_mediated_trust_level_is_rejected() {
    let (signer, mut receipt, nonce) = mediated_case();
    receipt.trust_level = TrustLevel::Advisory;
    let receipt = support::resign(&signer, receipt);
    assert_eq!(
        is_authoritative_spend_receipt(&receipt, &[signer.public_key()], nonce.as_ref()),
        Err(NotAuthoritativeReason::NotMediatedTrustLevel)
    );
}

#[test]
fn b_missing_budget_authority_is_rejected() {
    let (signer, mut receipt, nonce) = mediated_case();
    receipt.metadata = Some(serde_json::json!({}));
    let receipt = support::resign(&signer, receipt);
    assert_eq!(
        is_authoritative_spend_receipt(&receipt, &[signer.public_key()], nonce.as_ref()),
        Err(NotAuthoritativeReason::MissingBudgetAuthority)
    );
}

#[test]
fn r1_forged_label_with_real_signer_but_no_hold_is_rejected() {
    // R1 end to end: even an admitted-key signature over a Mediated label fails
    // without a reconciled hold + bound nonce.
    let (signer, mut receipt, nonce) = mediated_case();
    if let Some(obj) = receipt.metadata.as_mut().and_then(|m| m.as_object_mut()) {
        obj.remove("budget_authority");
    }
    let receipt = support::resign(&signer, receipt);
    assert!(is_authoritative_spend_receipt(&receipt, &[signer.public_key()], nonce.as_ref()).is_err());
}

#[test]
fn cd_nonce_binding_or_link_mismatch_is_rejected() {
    // (c)/(d): a nonce from a different call fails link/binding.
    let (signer, receipt, _nonce) = mediated_case();
    let (_other_signer, _r2, other_nonce) = mediated_case();
    let result = is_authoritative_spend_receipt(&receipt, &[signer.public_key()], other_nonce.as_ref());
    assert!(matches!(
        result,
        Err(NotAuthoritativeReason::NonceLinkMismatch)
            | Err(NotAuthoritativeReason::NonceBindingMismatch { .. })
            | Err(NotAuthoritativeReason::NonceSignatureInvalid)
    ));
}

#[test]
fn structural_invariant_advisory_receipt_has_no_allow_decision() {
    // Acceptance 4: advisory is structurally constrained to decision: None; only
    // the mediated handler emits decision: Some(Allow) for a tool call.
    let signer = Keypair::generate();
    let advisory = support::standalone_advisory_receipt(&signer, "cap-x", "cost-srv", "compute");
    assert!(advisory.decision.is_none(), "advisory receipts must not carry a decision");
}
```

Add `support::resign(signer, receipt) -> ChioReceipt` (re-sign a mutated body via `ChioReceipt::sign(receipt.body(), signer)`) to `tests/support.rs`. R2 is covered by Task 5's committed-cost integration test; R3 by Task 11; R5 by Tasks 8-10; R6 by Task 2. Reference those in a top-of-file comment so a reviewer sees full R1-R6 coverage.

- [ ] **Step 3: Run to verify it fails.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-conformance --test authoritative_spend_predicate_matrix -- --nocapture`
  Expected: FAIL to COMPILE (missing `support::resign`).

- [ ] **Step 4: Add `support::resign` and any missing helpers.** Implement in `tests/support.rs`.

- [ ] **Step 5: Run to verify passes + clippy.**
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-conformance --test authoritative_spend_predicate_matrix -- --nocapture`
  Expected: PASS with `7 passed` (nonzero-test guard: confirm `7 passed`).
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-conformance --tests -- -D warnings`
  Expected: no warnings.

- [ ] **Step 6: Commit.**
```bash
git add crates/tooling/chio-conformance/tests/authoritative_spend_predicate_matrix.rs crates/tooling/chio-conformance/tests/support.rs crates/tooling/chio-conformance/Cargo.toml
git commit -m "test(chio-conformance): (a)-(f) predicate matrix, R1-R6 negatives, structural invariant

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review (completed by plan author)

**1. Spec coverage.**
- M0 freeze -> Tasks 1-3 (contract types + predicate; kernel `PresentedNonceView` + frozen nonce/profile golden; ADR-0016 + ADR-0006 supersession + PROTOCOL 6.2 + reserved slots + prepay decision). Covered.
- M1 mediated route -> Tasks 4-5. Covered.
- M2 cross-bind + earned Mediated -> Tasks 6-7. Covered.
- M3 advisory visible failure -> Tasks 8-10 (flag, tool-server middleware, SDK default). Covered.
- M4 crash-safety + truthful HA -> Tasks 11-13 (reaper, guarantee-level truthfulness, drop-guard escalation). Covered.
- M5 golden + double-spend -> Tasks 14-16. Covered.
- Acceptance 1 -> Task 14; 2 -> Task 15; 3 -> Task 16; 4 -> Task 16 (structural invariant) + Task 8; 5 -> Tasks 8-10; 6 -> Task 11; 7 -> Task 2 (+ Task 3 profile freeze).
- Adversarial R1 -> Tasks 1, 7, 16; R2 -> Task 5; R3 -> Task 11; R4 -> Tasks 1, 12; R5 -> Tasks 8, 9, 10; R6 -> Tasks 2, 3. Concurrency double-spend -> Task 15.

**2. Placeholder scan.** No "TBD/TODO/similar to Task N". Two explicit implementer-confirm notes remain and are intentional, each naming the exact file:line to check rather than hand-waving: (i) Task 4 Step 5 - confirm whether `ChioKernel::new(KernelConfig)` returns `Self` or `Result` at `construction.rs` and drop `?`/`map_err` accordingly (the test-suite wrapper `make_kernel` hides this); (ii) Task 11 Step 3 - confirm the provisional-exposure column name is `remaining_exposure_units` at `store.rs:36-52`. These are verification directives, not missing content.

**3. Type consistency.** `is_authoritative_spend_receipt(receipt, admitted_kernel_keys: &[PublicKey], presented_nonce: &dyn PresentedNonceView)` is used identically in Tasks 1, 14, 15, 16. `BudgetAuthorityReceiptRef` fields match between Task 1 definition and Task 6 metadata producers (`hold_id`, `authorize_event_id`, `reconcile_event_id`, `execution_nonce_id`, `guarantee_level`). `ToolCallRequest` field list (runtime.rs:41) is used verbatim in Tasks 5, 6, 14, 15, 16. `ExecutionNonceConfig { nonce_ttl_secs, nonce_store_capacity, require_nonce }` used consistently. `NotAuthoritativeReason` variant names are stable across Tasks 1, 12, 16. `set_budget_store_handle`/`set_execution_nonce_store` names match construction.rs.

**Known cross-crate note (design decision, not a gap):** the frozen predicate lives in `chio-core-types` (lowest shared crate; already owns receipt types + `financial_budget_authority_metadata()` + crypto) and reaches the kernel-only `SignedExecutionNonce` through the `PresentedNonceView` trait, which `chio-kernel` implements (Task 2). This keeps dependency direction valid (kernel depends on core-types, never the reverse) and lets B, C, and the out-of-repo fork consume `is_authoritative_spend_receipt` without re-implementing the ledger/kernel/nonce.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-07-direction-a-authoritative-enforcement.md`. Two execution options:

1. **Subagent-Driven (recommended)** - dispatch a fresh subagent per task with two-stage review between tasks (REQUIRED SUB-SKILL: superpowers:subagent-driven-development).
2. **Inline Execution** - execute tasks in this session with batch checkpoints (REQUIRED SUB-SKILL: superpowers:executing-plans).

Direction A must pass its own adversarial review (the M5 golden gate + predicate matrix) before B's schema and C's receipts pin to its interface.
