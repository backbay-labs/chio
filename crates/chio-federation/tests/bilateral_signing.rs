//! Bilateral cross-kernel co-signing tests.
//!
//! Covers the happy path (two kernels both sign the same receipt and either
//! side can verify the dual-signed artifact), the wrong-peer-key rejection
//! (a third-party key cannot impersonate either org), and the tampered-body
//! rejection (a mutated body fails verification fail-closed).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core_types::crypto::{sha256_hex, Ed25519Backend, Keypair, Signature, SigningBackend};
use chio_core_types::receipt::{
    ChioReceipt, ChioReceiptBody, Decision, ToolCallAction, TrustLevel,
};
use chio_federation::{
    co_sign_with_origin, BilateralCoSigningError, CoSigningBody, DualSignedReceipt,
    ExpectedBilateralPeers, InProcessCoSigner, BILATERAL_DUAL_RECEIPT_SCHEMA,
};

fn sample_action() -> ToolCallAction {
    ToolCallAction::from_parameters(serde_json::json!({
        "path": "/data/federation-test.txt"
    }))
    .unwrap()
}

fn sample_receipt(tool_host_kp: &Keypair) -> ChioReceipt {
    let body = ChioReceiptBody {
        id: "rcpt-fed-20.3".to_string(),
        timestamp: 1_734_000_000,
        capability_id: "cap-fed-001".to_string(),
        tool_server: "srv-orgb-files".to_string(),
        tool_name: "file_read".to_string(),
        action: sample_action(),
        decision: Decision::Allow,
        content_hash: sha256_hex(br#"{"ok":true}"#),
        policy_hash: "fed-policy-hash".to_string(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: tool_host_kp.public_key(),
    };
    ChioReceipt::sign(body, tool_host_kp).unwrap()
}

#[test]
fn happy_path_dual_signs_and_verifies_on_both_sides() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let tool_host_kernel_id = "kernel.org-b";

    let cosigner = InProcessCoSigner::new(
        origin_kernel_id,
        origin_kp.clone(),
        tool_host_kp.public_key(),
    );

    let receipt = sample_receipt(&tool_host_kp);
    let dual = co_sign_with_origin(
        origin_kernel_id,
        &origin_kp.public_key(),
        tool_host_kernel_id,
        &tool_host_kp,
        receipt.clone(),
        &cosigner,
    )
    .expect("co-sign happy path");

    assert_eq!(dual.org_a_kernel_id, origin_kernel_id);
    assert_eq!(dual.org_b_kernel_id, tool_host_kernel_id);
    assert_eq!(dual.body.id, receipt.id);

    // Both sides can verify with the same pinned peer keys.
    dual.verify(&origin_kp.public_key(), &tool_host_kp.public_key())
        .expect("dual-signed receipt verifies with both pinned peer keys");
    dual.verify_pinned(ExpectedBilateralPeers {
        org_a_kernel_id: origin_kernel_id,
        org_a_public_key: &origin_kp.public_key(),
        org_b_kernel_id: tool_host_kernel_id,
        org_b_public_key: &tool_host_kp.public_key(),
    })
    .expect("dual-signed receipt verifies with independently pinned identities");
}

#[test]
fn verify_pinned_rejects_self_declared_identity_substitution() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let tool_host_kernel_id = "kernel.org-b";

    let cosigner = InProcessCoSigner::new(
        origin_kernel_id,
        origin_kp.clone(),
        tool_host_kp.public_key(),
    );
    let receipt = sample_receipt(&tool_host_kp);
    let mut dual = co_sign_with_origin(
        origin_kernel_id,
        &origin_kp.public_key(),
        tool_host_kernel_id,
        &tool_host_kp,
        receipt,
        &cosigner,
    )
    .unwrap();

    dual.org_a_kernel_id = "kernel.attacker-a".to_string();
    dual.org_b_kernel_id = "kernel.attacker-b".to_string();

    let err = dual
        .verify_pinned(ExpectedBilateralPeers {
            org_a_kernel_id: origin_kernel_id,
            org_a_public_key: &origin_kp.public_key(),
            org_b_kernel_id: tool_host_kernel_id,
            org_b_public_key: &tool_host_kp.public_key(),
        })
        .expect_err("self-declared kernel IDs must not override pinned peer IDs");
    assert_eq!(err, BilateralCoSigningError::PeerIdentityMismatch);
}

#[test]
fn verify_pinned_rejects_duplicate_peer_keys() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let tool_host_kernel_id = "kernel.org-b";

    let cosigner = InProcessCoSigner::new(
        origin_kernel_id,
        origin_kp.clone(),
        tool_host_kp.public_key(),
    );
    let receipt = sample_receipt(&tool_host_kp);
    let dual = co_sign_with_origin(
        origin_kernel_id,
        &origin_kp.public_key(),
        tool_host_kernel_id,
        &tool_host_kp,
        receipt,
        &cosigner,
    )
    .unwrap();

    let err = dual
        .verify_pinned(ExpectedBilateralPeers {
            org_a_kernel_id: origin_kernel_id,
            org_a_public_key: &origin_kp.public_key(),
            org_b_kernel_id: tool_host_kernel_id,
            org_b_public_key: &origin_kp.public_key(),
        })
        .expect_err("distinct peers must not share the same verification key");
    assert_eq!(err, BilateralCoSigningError::PeerIdentityMismatch);
}

#[test]
fn verify_fails_when_wrong_peer_key_is_supplied_for_either_side() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let attacker_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let tool_host_kernel_id = "kernel.org-b";

    let cosigner = InProcessCoSigner::new(
        origin_kernel_id,
        origin_kp.clone(),
        tool_host_kp.public_key(),
    );
    let receipt = sample_receipt(&tool_host_kp);
    let dual = co_sign_with_origin(
        origin_kernel_id,
        &origin_kp.public_key(),
        tool_host_kernel_id,
        &tool_host_kp,
        receipt,
        &cosigner,
    )
    .unwrap();

    // Swap origin key with a stranger's -- origin signature must fail.
    let err = dual
        .verify(&attacker_kp.public_key(), &tool_host_kp.public_key())
        .expect_err("attacker origin key must be rejected");
    assert_eq!(err, BilateralCoSigningError::OrgASignatureInvalid);

    // Swap tool-host key with a stranger's -- tool-host signature must fail.
    let err = dual
        .verify(&origin_kp.public_key(), &attacker_kp.public_key())
        .expect_err("attacker tool-host key must be rejected");
    assert_eq!(err, BilateralCoSigningError::OrgBSignatureInvalid);
}

#[test]
fn verify_fails_when_body_is_tampered() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let tool_host_kernel_id = "kernel.org-b";

    let cosigner = InProcessCoSigner::new(
        origin_kernel_id,
        origin_kp.clone(),
        tool_host_kp.public_key(),
    );
    let receipt = sample_receipt(&tool_host_kp);
    let mut dual = co_sign_with_origin(
        origin_kernel_id,
        &origin_kp.public_key(),
        tool_host_kernel_id,
        &tool_host_kp,
        receipt,
        &cosigner,
    )
    .unwrap();

    // Mutate a covered field in the body.
    dual.body.tool_name = "file_write".to_string();
    let err = dual
        .verify(&origin_kp.public_key(), &tool_host_kp.public_key())
        .expect_err("tampered body must be rejected");
    // The origin signature is checked first, so we get OrgASignatureInvalid.
    assert_eq!(err, BilateralCoSigningError::OrgASignatureInvalid);
}

#[test]
fn verify_fails_when_detached_signatures_cover_receipt_with_bad_embedded_signature() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let tool_host_kernel_id = "kernel.org-b";

    let mut receipt = sample_receipt(&tool_host_kp);
    receipt.content_hash = sha256_hex(b"tampered-after-receipt-signing");
    let (org_a_signature, org_b_signature) = detached_dual_signatures(
        &receipt,
        &origin_kp,
        &tool_host_kp,
        origin_kernel_id,
        tool_host_kernel_id,
    );
    let dual = DualSignedReceipt {
        schema: BILATERAL_DUAL_RECEIPT_SCHEMA.to_string(),
        body: receipt,
        org_a_kernel_id: origin_kernel_id.to_string(),
        org_b_kernel_id: tool_host_kernel_id.to_string(),
        org_a_signature,
        org_b_signature,
    };

    let err = dual
        .verify(&origin_kp.public_key(), &tool_host_kp.public_key())
        .expect_err("embedded Chio receipt signature must be verified");
    assert_eq!(err, BilateralCoSigningError::ReceiptMismatch);
}

#[test]
fn verify_fails_when_embedded_receipt_kernel_key_is_not_tool_host_key() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let rogue_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let tool_host_kernel_id = "kernel.org-b";

    let receipt = sample_receipt(&rogue_kp);
    let (org_a_signature, org_b_signature) = detached_dual_signatures(
        &receipt,
        &origin_kp,
        &tool_host_kp,
        origin_kernel_id,
        tool_host_kernel_id,
    );
    let dual = DualSignedReceipt {
        schema: BILATERAL_DUAL_RECEIPT_SCHEMA.to_string(),
        body: receipt,
        org_a_kernel_id: origin_kernel_id.to_string(),
        org_b_kernel_id: tool_host_kernel_id.to_string(),
        org_a_signature,
        org_b_signature,
    };

    let err = dual
        .verify(&origin_kp.public_key(), &tool_host_kp.public_key())
        .expect_err("embedded receipt kernel_key must be the tool-host key");
    assert_eq!(err, BilateralCoSigningError::OrgBSignatureInvalid);
}

#[test]
fn cosigner_rejects_forged_org_b_signature() {
    // Attacker tries to dump a receipt signed by their own key and have
    // the origin kernel co-sign it. The origin verifies Org B's declared
    // signature against the pinned tool-host key before signing, so this
    // must fail fail-closed.
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let attacker_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let tool_host_kernel_id = "kernel.org-b";

    let cosigner = InProcessCoSigner::new(
        origin_kernel_id,
        origin_kp.clone(),
        tool_host_kp.public_key(),
    );

    let err = co_sign_with_origin(
        origin_kernel_id,
        &origin_kp.public_key(),
        tool_host_kernel_id,
        &attacker_kp,
        sample_receipt(&attacker_kp),
        &cosigner,
    )
    .expect_err("origin must refuse to co-sign an attacker-signed body");
    assert_eq!(err, BilateralCoSigningError::OrgBSignatureInvalid);
}

#[test]
fn canonical_body_roundtrip_is_stable() {
    let origin_kp = Keypair::generate();
    let tool_host_kp = Keypair::generate();
    let receipt = sample_receipt(&tool_host_kp);

    let body_a = CoSigningBody::from_receipt(&receipt, "kernel.org-a", "kernel.org-b").unwrap();
    let body_b = CoSigningBody::from_receipt(&receipt, "kernel.org-a", "kernel.org-b").unwrap();
    assert_eq!(
        body_a.canonical_bytes().unwrap(),
        body_b.canonical_bytes().unwrap()
    );

    // Demonstrate that a DualSignedReceipt serializes and deserializes without
    // drift (receipt body stays intact, both signatures survive).
    let cosigner =
        InProcessCoSigner::new("kernel.org-a", origin_kp.clone(), tool_host_kp.public_key());
    let dual = co_sign_with_origin(
        "kernel.org-a",
        &origin_kp.public_key(),
        "kernel.org-b",
        &tool_host_kp,
        receipt,
        &cosigner,
    )
    .unwrap();

    let json = serde_json::to_string(&dual).unwrap();
    let restored: DualSignedReceipt = serde_json::from_str(&json).unwrap();
    restored
        .verify(&origin_kp.public_key(), &tool_host_kp.public_key())
        .expect("round-tripped dual receipt must still verify");
}

fn detached_dual_signatures(
    receipt: &ChioReceipt,
    origin_kp: &Keypair,
    tool_host_kp: &Keypair,
    origin_kernel_id: &str,
    tool_host_kernel_id: &str,
) -> (Signature, Signature) {
    let bytes = CoSigningBody::from_receipt(receipt, origin_kernel_id, tool_host_kernel_id)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let org_a_signature = Ed25519Backend::new(origin_kp.clone())
        .sign_bytes(&bytes)
        .unwrap();
    let org_b_signature = Ed25519Backend::new(tool_host_kp.clone())
        .sign_bytes(&bytes)
        .unwrap();
    (org_a_signature, org_b_signature)
}
