use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::{sha256_hex, Ed25519Backend, Keypair};
use chio_core_types::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
    kinds::TrustLevel,
    signing::ReceiptSigningHandle,
};
use serde_json::json;

use chio_test_support::ctx::TestUnwrap;

fn receipt_body(keypair: &Keypair) -> ChioReceiptBody {
    ChioReceiptBody {
        id: "rcpt-boundary-1".to_string(),
        timestamp: 1_700_000_000,
        capability_id: "cap-boundary-1".to_string(),
        tool_server: "srv-boundary".to_string(),
        tool_name: "echo".to_string(),
        action: ToolCallAction::from_parameters(json!({"b": 2, "a": 1}))
            .test_unwrap("build receipt action"),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: sha256_hex(b"content"),
        policy_hash: sha256_hex(b"policy"),
        evidence: vec![],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    }
}

#[test]
fn canonical_json_is_byte_stable_across_object_order() {
    let left = json!({"b": 2, "a": 1, "nested": {"z": true, "m": false}});
    let right = json!({"nested": {"m": false, "z": true}, "a": 1, "b": 2});

    let left_bytes = canonical_json_bytes(&left).test_unwrap("canonicalize left json");
    let right_bytes = canonical_json_bytes(&right).test_unwrap("canonicalize right json");

    assert_eq!(left_bytes, right_bytes);
}

#[test]
fn receipt_signature_body_excludes_signature_field() {
    let keypair = Keypair::from_seed(&[7; 32]);
    let receipt = ChioReceipt::sign(receipt_body(&keypair), &keypair).test_unwrap("sign receipt");

    let signed_body_bytes =
        canonical_json_bytes(&receipt.body()).test_unwrap("canonicalize receipt body");
    let signed_body_text =
        std::str::from_utf8(&signed_body_bytes).test_unwrap("receipt body is utf8");

    assert!(!signed_body_text.contains("signature"));
    assert!(receipt
        .verify_signature()
        .test_unwrap("verify signed receipt"));
}

#[test]
fn tampering_any_signed_receipt_field_fails_verification() {
    let keypair = Keypair::from_seed(&[8; 32]);
    let receipt = ChioReceipt::sign(receipt_body(&keypair), &keypair).test_unwrap("sign receipt");

    let mut tampered_tool = receipt.clone();
    tampered_tool.tool_name = "other".to_string();
    assert!(!tampered_tool
        .verify_signature()
        .test_unwrap("verify tampered tool receipt"));

    let mut tampered_policy = receipt.clone();
    tampered_policy.policy_hash = sha256_hex(b"other-policy");
    assert!(!tampered_policy
        .verify_signature()
        .test_unwrap("verify tampered policy receipt"));

    let mut tampered_decision = receipt.clone();
    tampered_decision.decision = Some(Decision::Deny {
        reason: "tampered".to_string(),
        guard: "test".to_string(),
    });
    assert!(!tampered_decision
        .verify_signature()
        .test_unwrap("verify tampered decision receipt"));
}

fn receipt_body_with_content_hash(keypair: &Keypair, content_hash: String) -> ChioReceiptBody {
    let mut body = receipt_body(keypair);
    body.content_hash = content_hash;
    body
}

#[test]
fn signing_handle_recomputes_content_hash_over_canonical_content() {
    // Object key order must not change the recomputed hash (RFC 8785).
    let content_unordered = json!({"b": 2, "a": 1});
    let handle = ReceiptSigningHandle::from_content(&content_unordered)
        .test_unwrap("build handle from content");

    let expected = sha256_hex(
        &canonical_json_bytes(&json!({"a": 1, "b": 2})).test_unwrap("canonicalize ordered content"),
    );
    assert_eq!(handle.content_hash(), expected);
    assert_eq!(handle.canonical_content(), br#"{"a":1,"b":2}"#);
}

#[test]
fn debug_redacts_preimage() {
    // The preimage carries the canonical tool output, which for value receipts
    // can contain user data or secrets. `Debug` MUST NOT print the raw bytes;
    // it prints the recomputed hash and the length only.
    let secret = json!({"password": "hunter2-super-secret-value", "ssn": "078-05-1120"});
    let handle = ReceiptSigningHandle::from_content(&secret).test_unwrap("build handle");

    // Confirm the secret really lives inside the handle's canonical content so
    // the assertions below are non-tautological.
    let canonical = String::from_utf8(handle.canonical_content().to_vec())
        .test_unwrap("canonical content is utf8");
    assert!(canonical.contains("hunter2-super-secret-value"));
    assert!(canonical.contains("078-05-1120"));

    let debug_output = format!("{handle:?}");

    // No fragment of the preimage may appear in the Debug rendering.
    assert!(
        !debug_output.contains("hunter2-super-secret-value"),
        "Debug leaked the preimage password: {debug_output}"
    );
    assert!(
        !debug_output.contains("078-05-1120"),
        "Debug leaked the preimage ssn: {debug_output}"
    );
    assert!(
        !debug_output.contains("password"),
        "Debug leaked a preimage field name: {debug_output}"
    );
    // The non-secret hash and a redaction marker should still be present for
    // diagnostics.
    assert!(
        debug_output.contains(handle.content_hash()),
        "Debug should surface the non-secret content_hash: {debug_output}"
    );
    assert!(
        debug_output.contains("<redacted>"),
        "Debug should mark the preimage as redacted: {debug_output}"
    );
}

#[test]
fn sign_with_handle_rejects_render_a_sign_b() {
    let keypair = Keypair::from_seed(&[11; 32]);

    let content_a = json!({"shown": "to-the-human"});
    let content_b = json!({"secretly": "signed-instead"});

    // Handle bound to A; body claims the hash of B.
    let handle = ReceiptSigningHandle::from_content(&content_a).test_unwrap("handle over A");
    let hash_b = sha256_hex(&canonical_json_bytes(&content_b).test_unwrap("canonicalize B"));
    let body = receipt_body_with_content_hash(&keypair, hash_b);

    let result = ChioReceipt::sign_with_handle(body, &keypair, handle);
    assert!(
        result.is_err(),
        "render-A/sign-B must be refused at the keypair signing boundary"
    );
}

#[test]
fn sign_with_handle_accepts_matching_content() {
    let keypair = Keypair::from_seed(&[12; 32]);

    let content = json!({"shown": "to-the-human"});
    let handle = ReceiptSigningHandle::from_content(&content).test_unwrap("handle over content");
    let recomputed = handle.content_hash().to_string();
    let body = receipt_body_with_content_hash(&keypair, recomputed.clone());

    let receipt =
        ChioReceipt::sign_with_handle(body, &keypair, handle).test_unwrap("sign with handle");
    assert!(receipt
        .verify_signature()
        .test_unwrap("verify handle-signed receipt"));
    assert_eq!(receipt.content_hash, recomputed);
}

#[test]
fn sign_with_backend_using_handle_rejects_mismatch() {
    let keypair = Keypair::from_seed(&[13; 32]);
    let backend = Ed25519Backend::new(keypair.clone());

    let content = json!({"ok": true});
    let handle = ReceiptSigningHandle::from_content(&content).test_unwrap("handle over content");
    // Body claims a hash that does not match the handle's content.
    let body = receipt_body_with_content_hash(&keypair, sha256_hex(b"a-different-thing"));

    let result = ChioReceipt::sign_with_backend_using_handle(body, &backend, handle);
    assert!(
        result.is_err(),
        "backend handle signing must refuse a content_hash mismatch"
    );
}

#[test]
fn sign_with_backend_using_handle_accepts_matching_content() {
    let keypair = Keypair::from_seed(&[14; 32]);
    let backend = Ed25519Backend::new(keypair.clone());

    let content = json!({"ok": true});
    let handle = ReceiptSigningHandle::from_content(&content).test_unwrap("handle over content");
    let recomputed = handle.content_hash().to_string();
    let body = receipt_body_with_content_hash(&keypair, recomputed.clone());

    let receipt = ChioReceipt::sign_with_backend_using_handle(body, &backend, handle)
        .test_unwrap("backend sign with handle");
    assert!(receipt
        .verify_signature()
        .test_unwrap("verify backend handle-signed receipt"));
    assert_eq!(receipt.content_hash, recomputed);
}

#[test]
fn json_formatting_does_not_change_receipt_verification() {
    let keypair = Keypair::from_seed(&[9; 32]);
    let receipt = ChioReceipt::sign(receipt_body(&keypair), &keypair).test_unwrap("sign receipt");

    let pretty = serde_json::to_string_pretty(&receipt).test_unwrap("serialize pretty receipt");
    let compact = serde_json::to_string(&receipt).test_unwrap("serialize compact receipt");
    let from_pretty: ChioReceipt =
        serde_json::from_str(&pretty).test_unwrap("parse pretty receipt");
    let from_compact: ChioReceipt =
        serde_json::from_str(&compact).test_unwrap("parse compact receipt");

    assert!(from_pretty
        .verify_signature()
        .test_unwrap("verify pretty receipt"));
    assert!(from_compact
        .verify_signature()
        .test_unwrap("verify compact receipt"));
    assert_eq!(
        from_pretty.signature.to_hex(),
        from_compact.signature.to_hex()
    );
}
