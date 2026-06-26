// Threat test for threat ID `kernel_impersonation`.
//
// Threat: kernel_impersonation (Kernel impersonation).
// Surfaces: hosted_mcp, native_chio.
//
// Coverage strategy: import the production body-only signing primitive
// `chio_kernel_core::sign_receipt_relaying_trusted_body` (the kernel-key
// guard this threat exercises) and the
// `chio_core::receipt::body::ChioReceipt::verify_signature` verifier
// directly. (The sibling WYSIWYS recompute gate that closes render-A/sign-B
// lives in `chio_kernel_core::sign_receipt` and is covered by the
// `chio-kernel-core` `tests/portable_build.rs` suite; this threat targets the
// orthogonal kernel-key impersonation guard, which both primitives share.)
// Two attacker models are exercised:
//
//   1. Mint-side impersonation. Build a `ChioReceiptBody` whose
//      `kernel_key` field claims the legitimate kernel public key
//      `K_kernel`. Pass an Ed25519 signing backend whose actual
//      keypair is the attacker key `K_attacker`. The production
//      signing primitive MUST refuse with
//      `ReceiptSigningError::KernelKeyMismatch` so the attacker
//      cannot produce a forged-but-internally-consistent receipt.
//
//   2. Verify-side impersonation. Sign a receipt with the attacker
//      keypair and then mutate the embedded `kernel_key` field on
//      the resulting receipt to claim `K_kernel`. The production
//      `ChioReceipt::verify_signature` MUST then return `Ok(false)`
//      because the canonical-JSON signature was produced over a body
//      whose `kernel_key` field differs from the on-the-wire claim.
//
// Production call sites:
//   `crates/chio-kernel-core/src/receipts.rs`
//     (`sign_receipt_relaying_trusted_body`).
//   `crates/chio-core-types/src/receipt.rs:292`
//     (`ChioReceipt::verify_signature`).
//
// Revert-to-prove-it-fails recipe: delete the kernel_key /
// backend_key mismatch guard inside `sign_receipt_relaying_trusted_body`
// in `crates/chio-kernel-core/src/receipts.rs` (so the body's
// `kernel_key` field is no longer compared to the signing backend's
// public key before signing). The mint-side deny-arm assertion below
// fails because the attacker can mint a forged receipt that claims
// the legitimate kernel's `kernel_key` while signing with their own
// key.

use chio_core::crypto::{Ed25519Backend, Keypair};
use chio_core::receipt::{body::ChioReceiptBody, decision::Decision, decision::ToolCallAction};
use chio_kernel_core::receipts::{sign_receipt_relaying_trusted_body, ReceiptSigningError};

fn sample_body(kernel_key: chio_core::crypto::PublicKey) -> ChioReceiptBody {
    let action = match ToolCallAction::from_parameters(serde_json::json!({"path": "/tmp/x"})) {
        Ok(action) => action,
        Err(err) => panic!("ToolCallAction::from_parameters: {err}"),
    };
    ChioReceiptBody {
        id: "rcpt-test-001".to_string(),
        timestamp: 1_700_000_000,
        capability_id: "cap-test-001".to_string(),
        tool_server: "fs".to_string(),
        tool_name: "read_file".to_string(),
        action,
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: "0".repeat(64),
        policy_hash: "1".repeat(64),
        evidence: Vec::new(),
        metadata: None,
        trust_level: Default::default(),
        tenant_id: None,
        kernel_key,
        bbs_projection_version: None,
    }
}

#[test]
fn threat_kernel_impersonation_signing_with_mismatched_key_rejected() {
    // covers: kernel_impersonation
    //
    // Attacker scenario: the attacker controls a signing backend
    // (K_attacker) but tries to mint a receipt that claims the
    // kernel's public key (K_kernel). The production sign_receipt
    // guard MUST reject.
    let kernel_kp = Keypair::generate();
    let attacker_kp = Keypair::generate();
    assert_ne!(kernel_kp.public_key(), attacker_kp.public_key());

    let body = sample_body(kernel_kp.public_key());

    let attacker_backend = Ed25519Backend::new(attacker_kp);

    let err = match sign_receipt_relaying_trusted_body(body, &attacker_backend) {
        Ok(_) => panic!(
            "production signing primitive MUST reject when body.kernel_key \
             does not match backend.public_key(); got Ok"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err, ReceiptSigningError::KernelKeyMismatch),
        "expected ReceiptSigningError::KernelKeyMismatch, got {err:?}"
    );
}

#[test]
fn threat_kernel_impersonation_tampered_kernel_key_field_fails_verification() {
    // covers: kernel_impersonation
    //
    // Attacker scenario: the attacker signs a receipt with K_attacker
    // and then swaps the on-the-wire `kernel_key` field to claim
    // K_kernel. The production verifier MUST reject because the
    // signature was canonicalized over the attacker key.
    let kernel_kp = Keypair::generate();
    let attacker_kp = Keypair::generate();
    assert_ne!(kernel_kp.public_key(), attacker_kp.public_key());

    // Sign a receipt that genuinely uses the attacker key.
    let attacker_backend = Ed25519Backend::new(attacker_kp.clone());
    let attacker_body = sample_body(attacker_kp.public_key());
    let mut tampered = match sign_receipt_relaying_trusted_body(attacker_body, &attacker_backend) {
        Ok(receipt) => receipt,
        Err(err) => panic!("attacker self-signed receipt failed to sign: {err:?}"),
    };

    // Sanity: the genuine receipt verifies.
    let genuine_ok = match tampered.verify_signature() {
        Ok(ok) => ok,
        Err(err) => panic!("attacker self-signed receipt verify failed: {err}"),
    };
    assert!(
        genuine_ok,
        "self-consistent attacker receipt must verify before tampering"
    );

    // Now claim the kernel's public key. The receipt is no longer
    // self-consistent: the signature was produced over the attacker
    // key, but the on-the-wire kernel_key claims K_kernel.
    tampered.kernel_key = kernel_kp.public_key();

    let result = match tampered.verify_signature() {
        Ok(ok) => ok,
        Err(err) => panic!("verify_signature unexpectedly raised: {err}"),
    };
    assert!(
        !result,
        "production ChioReceipt::verify_signature MUST return false when the on-the-wire kernel_key has been swapped to impersonate the kernel"
    );
}

#[test]
fn threat_kernel_impersonation_genuine_receipt_round_trips() {
    // covers: kernel_impersonation
    //
    // Sanity arm: a body whose kernel_key matches the signing
    // backend's public key produces a receipt whose signature
    // verifies cleanly under that same key. This guards against a
    // false-positive deny path (the mismatch guard rejecting
    // legitimate receipts).
    let kernel_kp = Keypair::generate();
    let backend = Ed25519Backend::new(kernel_kp.clone());
    let body = sample_body(kernel_kp.public_key());

    let receipt = match sign_receipt_relaying_trusted_body(body, &backend) {
        Ok(r) => r,
        Err(err) => panic!("legitimate sign_receipt_relaying_trusted_body failed: {err:?}"),
    };
    let ok = match receipt.verify_signature() {
        Ok(ok) => ok,
        Err(err) => panic!("legitimate receipt verify_signature: {err}"),
    };
    assert!(
        ok,
        "legitimate receipt must verify (otherwise the mismatch guard is over-rejecting)"
    );
}
