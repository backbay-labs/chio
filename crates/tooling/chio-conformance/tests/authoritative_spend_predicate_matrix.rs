//! (a)-(f) predicate matrix with a real kernel-signed nonce, negatives for
//! each predicate leg, and the structural signing invariant.
//!
//! Committed-cost integration: authoritative_spend_enforcement.rs
//! Reaper crash-safety: chio-kernel crate tests
//! Advisory visible failure: authoritative_spend_double_spend.rs +
//!     hot_path_enforcement.rs
//! Profile freeze: chio-kernel execution_nonce schema tests
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::crypto::Keypair;
use chio_core::receipt::authoritative_spend::{
    is_authoritative_spend_receipt, BudgetAuthorityReceiptRef, NotAuthoritativeReason,
};
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::{Decision, ToolCallAction};
use chio_core::receipt::kinds::{
    BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_core::sha256_hex;
use chio_kernel::budget_store::{BudgetStore, InMemoryBudgetStore};
use chio_kernel::execution_nonce::SignedExecutionNonce;
use chio_kernel::runtime::ToolCallRequest;
use std::sync::Arc;

mod support;
use support::{issue_cost_bearing_capability, mediation_kernel, MonetaryCostServer};

fn mediated_case() -> (Keypair, ChioReceipt, Box<SignedExecutionNonce>) {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let mut kernel = mediation_kernel(&signer, Arc::clone(&budget), false);
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 50, "USD")));
    let cap =
        issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
    let request = ToolCallRequest {
        request_id: "req-matrix".to_string(),
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
    let nonce = response.execution_nonce.clone().expect("nonce");
    (signer, response.receipt, nonce)
}

/// Extract the `execution_nonce_id` that the receipt's budget_authority block
/// records as the linked nonce for the spend.
fn linked_nonce_id(receipt: &ChioReceipt) -> String {
    BudgetAuthorityReceiptRef::from_receipt(receipt)
        .expect("budget_authority")
        .execution_nonce_id
        .expect("execution_nonce_id")
}

#[test]
fn baseline_passes() {
    let (signer, receipt, nonce) = mediated_case();
    assert_eq!(
        is_authoritative_spend_receipt(&receipt, &[signer.public_key()], nonce.as_ref()),
        Ok(())
    );
}

#[test]
fn e_signer_not_admitted_is_rejected() {
    let (_signer, receipt, nonce) = mediated_case();
    assert_eq!(
        is_authoritative_spend_receipt(
            &receipt,
            &[Keypair::generate().public_key()],
            nonce.as_ref()
        ),
        Err(NotAuthoritativeReason::SignerNotAdmitted)
    );
}

#[test]
fn a_non_mediated_trust_level_is_rejected() {
    // trust_level is part of the signed receipt body, and signing a
    // mediated-decision receipt with a non-mediated trust level is refused, so a
    // holder cannot relabel a mediated receipt to a weaker trust level: the
    // tamper invalidates the signature and is caught at verification. This is a
    // stronger guarantee than the defensive NotMediatedTrustLevel structural
    // conjunct, which no validly signed receipt can reach.
    let (signer, mut receipt, nonce) = mediated_case();
    receipt.trust_level = TrustLevel::Advisory;
    assert_eq!(
        is_authoritative_spend_receipt(&receipt, &[signer.public_key()], nonce.as_ref()),
        Err(NotAuthoritativeReason::ReceiptSignatureInvalid)
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
    // Even an admitted-key signature over a Mediated label fails without a
    // reconciled hold + bound nonce.
    let (signer, mut receipt, nonce) = mediated_case();
    if let Some(obj) = receipt.metadata.as_mut().and_then(|m| m.as_object_mut()) {
        obj.remove("budget_authority");
    }
    let receipt = support::resign(&signer, receipt);
    assert!(
        is_authoritative_spend_receipt(&receipt, &[signer.public_key()], nonce.as_ref()).is_err()
    );
}

#[test]
fn d_nonce_link_mismatch_is_rejected() {
    // (d): the presented nonce_id does not match the execution_nonce_id recorded
    // in the receipt's budget_authority block.
    let (signer, receipt, _real_nonce) = mediated_case();
    let correct_id = linked_nonce_id(&receipt);
    let wrong_nonce = support::fake_nonce_with_id(
        &signer,
        &format!("{}-wrong", correct_id),
        &receipt.capability_id,
        &receipt.tool_server,
        &receipt.tool_name,
        &receipt.action.parameter_hash,
    );
    assert_eq!(
        is_authoritative_spend_receipt(&receipt, &[signer.public_key()], &wrong_nonce),
        Err(NotAuthoritativeReason::NonceLinkMismatch)
    );
}

#[test]
fn c_nonce_binding_mismatch_is_rejected() {
    // (c): nonce_id matches the receipt's linked id, but the nonce's bound
    // capability_id differs from the receipt's capability_id.
    let (signer, receipt, _real_nonce) = mediated_case();
    let nonce_id = linked_nonce_id(&receipt);
    let misbound = support::fake_nonce_with_id(
        &signer,
        &nonce_id,
        "wrong-capability",
        &receipt.tool_server,
        &receipt.tool_name,
        &receipt.action.parameter_hash,
    );
    assert_eq!(
        is_authoritative_spend_receipt(&receipt, &[signer.public_key()], &misbound),
        Err(NotAuthoritativeReason::NonceBindingMismatch {
            field: "capability_id"
        })
    );
}

#[test]
fn f_nonce_signature_invalid_is_rejected() {
    // (f): nonce_id and all binding fields match the receipt, but the nonce was
    // signed by a key other than the admitted kernel key.
    let (signer, receipt, _real_nonce) = mediated_case();
    let nonce_id = linked_nonce_id(&receipt);
    let wrong_signer = Keypair::generate();
    let bad_sig = support::fake_nonce_with_id(
        &wrong_signer,
        &nonce_id,
        &receipt.capability_id,
        &receipt.tool_server,
        &receipt.tool_name,
        &receipt.action.parameter_hash,
    );
    assert_eq!(
        is_authoritative_spend_receipt(&receipt, &[signer.public_key()], &bad_sig),
        Err(NotAuthoritativeReason::NonceSignatureInvalid)
    );
}

#[test]
fn structural_invariant_advisory_receipt_rejects_allow_decision_at_sign() {
    // ChioReceipt::sign returns Err when advisory_evaluation carries
    // decision: Some(Allow). validate_decision in receipt/metadata.rs enforces
    // this at every signing call site, so no advisory path can emit an Allow
    // decision.
    let signer = Keypair::generate();
    let action = ToolCallAction::from_parameters(serde_json::json!({})).expect("action");
    let body = ChioReceiptBody {
        id: String::new(),
        timestamp: 0,
        capability_id: "cap-x".to_string(),
        tool_server: "cost-srv".to_string(),
        tool_name: "compute".to_string(),
        action,
        decision: Some(Decision::Allow),
        receipt_kind: ReceiptKind::AdvisoryEvaluation,
        boundary_class: BoundaryClass::AdvisoryOnly,
        observation_outcome: Some(ObservationOutcome::Evaluated),
        tool_origin: ToolOrigin::HostExecutedUnmediated,
        redaction_mode: RedactionMode::None,
        actor_chain: Vec::new(),
        content_hash: sha256_hex(b"content"),
        policy_hash: sha256_hex(b"policy"),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::Advisory,
        tenant_id: None,
        kernel_key: signer.public_key(),
        bbs_projection_version: None,
    };
    assert!(
        ChioReceipt::sign(body, &signer).is_err(),
        "advisory_evaluation with decision: Some(Allow) must be rejected at signing"
    );
}
