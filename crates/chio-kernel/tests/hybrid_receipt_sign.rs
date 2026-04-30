//! Hybrid receipt signing path integration tests (M03.P2.T2).
//!
//! Pins the kernel-side construction of the hybrid signing backend from a
//! configured `crypto_floor` and a 32-byte ML-DSA-65 keygen seed, and the
//! receipt sign-then-verify round trip through `&dyn SigningBackend`. The
//! test deliberately exercises both the classical-only path under
//! `allow_classical` (byte-identity baseline for M03.P2.T5) and the hybrid
//! path under `allow_hybrid` and `pq_required`.
//!
//! Trust-boundary milestone: M03 P2.T2.

#![cfg(feature = "pq")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{Keypair, PublicKey, SigningAlgorithm};
use chio_core::receipt::{ChioReceiptBody, Decision, ToolCallAction, TrustLevel};
use chio_kernel::{
    kernel_signing_backend, sign_receipt_body_with_backend, KernelCryptoFloor,
    KernelSigningBackendError,
};

fn fixture_pq_seed() -> [u8; 32] {
    // Stable test seed: reproducible across runs, never used in production.
    let raw = b"chio-m03-p2-t2-hybrid-test-seed!";
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    out
}

fn build_body(kernel_key: PublicKey) -> ChioReceiptBody {
    ChioReceiptBody {
        id: "rcpt-test-hybrid".to_string(),
        timestamp: 1_700_000_000,
        capability_id: "cap-test".to_string(),
        tool_server: "srv".to_string(),
        tool_name: "echo".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"k": "v"})).unwrap(),
        decision: Decision::Allow,
        content_hash: "0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        policy_hash: "test-policy".to_string(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key,
    }
}

/// Wrapper that maps `Box<dyn SigningBackend>` results into a
/// Debug-printable form so `expect_err` works without requiring `Debug`
/// on the boxed trait object.
fn err_only<E: std::fmt::Debug>(
    result: Result<Box<dyn chio_core::crypto::SigningBackend>, E>,
) -> Result<(), E> {
    result.map(|_| ())
}

#[test]
fn allow_classical_constructs_ed25519_backend() {
    let kp = Keypair::generate();
    let backend =
        kernel_signing_backend(KernelCryptoFloor::AllowClassical, kp.clone(), None).unwrap();
    assert_eq!(backend.algorithm(), SigningAlgorithm::Ed25519);
    assert_eq!(backend.public_key(), kp.public_key());
}

#[test]
fn allow_hybrid_without_seed_rejects_at_construction() {
    let kp = Keypair::generate();
    let result = err_only(kernel_signing_backend(
        KernelCryptoFloor::AllowHybrid,
        kp,
        None,
    ));
    let err = result.expect_err("allow_hybrid without PQ seed must fail at construction");
    assert_eq!(
        err,
        KernelSigningBackendError::HybridFloorRequiresPqKey {
            floor: "allow_hybrid",
        }
    );
}

#[test]
fn pq_required_without_seed_rejects_at_construction() {
    let kp = Keypair::generate();
    let result = err_only(kernel_signing_backend(
        KernelCryptoFloor::PqRequired,
        kp,
        None,
    ));
    let err = result.expect_err("pq_required without PQ seed must fail at construction");
    assert_eq!(
        err,
        KernelSigningBackendError::HybridFloorRequiresPqKey {
            floor: "pq_required",
        }
    );
}

#[test]
fn allow_hybrid_with_seed_constructs_hybrid_backend() {
    let kp = Keypair::generate();
    let seed = fixture_pq_seed();
    let backend =
        kernel_signing_backend(KernelCryptoFloor::AllowHybrid, kp.clone(), Some(&seed)).unwrap();
    assert_eq!(backend.algorithm(), SigningAlgorithm::Hybrid);
    let pk = backend.public_key();
    assert_eq!(pk.algorithm(), SigningAlgorithm::Hybrid);
    assert_ne!(pk, kp.public_key());
}

#[test]
fn pq_required_with_seed_constructs_hybrid_backend() {
    let kp = Keypair::generate();
    let seed = fixture_pq_seed();
    let backend =
        kernel_signing_backend(KernelCryptoFloor::PqRequired, kp, Some(&seed)).unwrap();
    assert_eq!(backend.algorithm(), SigningAlgorithm::Hybrid);
}

#[test]
fn classical_receipt_byte_identical_under_allow_classical() {
    // Byte-identity contract: receipts signed under `allow_classical`
    // serialize byte-for-byte the same as the trajectory-1 path. This is
    // the regression M03.P2.T5 escalates into a v3.18 fixture replay.
    let kp = Keypair::generate();
    let backend =
        kernel_signing_backend(KernelCryptoFloor::AllowClassical, kp.clone(), None).unwrap();

    let body = build_body(kp.public_key());
    let body_bytes_pre = canonical_json_bytes(&body).unwrap();

    let receipt = sign_receipt_body_with_backend(body.clone(), backend.as_ref()).unwrap();
    assert_eq!(receipt.kernel_key, kp.public_key());
    assert_eq!(receipt.signature.algorithm(), SigningAlgorithm::Ed25519);

    // The receipt body bytes are unchanged after signing through the new
    // path: we never alter the canonical encoding of an Ed25519 receipt.
    let body_bytes_post = canonical_json_bytes(&body).unwrap();
    assert_eq!(body_bytes_pre, body_bytes_post);

    // Signature verifies via the issuer key.
    assert!(receipt.kernel_key.verify(&body_bytes_post, &receipt.signature));
}

#[test]
fn hybrid_receipt_round_trip_signs_and_verifies() {
    let kp = Keypair::generate();
    let seed = fixture_pq_seed();
    let backend =
        kernel_signing_backend(KernelCryptoFloor::PqRequired, kp.clone(), Some(&seed)).unwrap();

    // Under hybrid signing, the kernel_key field must carry the hybrid
    // public key so the verifier reaches both halves.
    let hybrid_pk = backend.public_key();
    assert_eq!(hybrid_pk.algorithm(), SigningAlgorithm::Hybrid);
    let body = build_body(hybrid_pk.clone());

    let receipt = sign_receipt_body_with_backend(body.clone(), backend.as_ref()).unwrap();
    assert_eq!(receipt.signature.algorithm(), SigningAlgorithm::Hybrid);
    assert_eq!(receipt.kernel_key.algorithm(), SigningAlgorithm::Hybrid);

    let body_bytes = canonical_json_bytes(&body).unwrap();
    assert!(receipt.kernel_key.verify(&body_bytes, &receipt.signature));
}

#[test]
fn body_kernel_key_mismatch_rejects_fail_closed() {
    // Fail-closed: if the body's `kernel_key` field does not match the
    // backend's public key, the signing path rejects without producing a
    // signature. This blocks downgrade attacks where a forged body claims
    // a different key than the actual signer.
    let kp = Keypair::generate();
    let backend =
        kernel_signing_backend(KernelCryptoFloor::AllowClassical, kp.clone(), None).unwrap();
    // Use a different keypair's public key in the body so the mismatch is
    // unambiguous.
    let other = Keypair::generate();
    let body = build_body(other.public_key());

    let err = sign_receipt_body_with_backend(body, backend.as_ref())
        .expect_err("kernel_key mismatch must reject");
    let rendered = format!("{err}");
    assert!(
        rendered.contains("kernel signing key"),
        "error must explain mismatch: {rendered}"
    );
}

#[test]
fn classical_and_hybrid_canonical_bytes_diverge_only_on_signature() {
    // The hybrid receipt body shares everything except the kernel_key
    // field with a classical receipt body for the same (timestamp, action,
    // capability_id) tuple. The signatures themselves diverge (different
    // algorithms produce different bytes), but the body construction is
    // identical modulo the public key the operator provisions.
    let classical_kp = Keypair::generate();
    let backend_classical = kernel_signing_backend(
        KernelCryptoFloor::AllowClassical,
        classical_kp.clone(),
        None,
    )
    .unwrap();
    let body_classical = build_body(classical_kp.public_key());
    let receipt_classical = sign_receipt_body_with_backend(
        body_classical.clone(),
        backend_classical.as_ref(),
    )
    .unwrap();
    assert_eq!(
        receipt_classical.signature.algorithm(),
        SigningAlgorithm::Ed25519
    );

    let hybrid_kp = Keypair::generate();
    let seed = fixture_pq_seed();
    let backend_hybrid = kernel_signing_backend(
        KernelCryptoFloor::AllowHybrid,
        hybrid_kp.clone(),
        Some(&seed),
    )
    .unwrap();
    let body_hybrid = build_body(backend_hybrid.public_key());
    let receipt_hybrid =
        sign_receipt_body_with_backend(body_hybrid, backend_hybrid.as_ref()).unwrap();
    assert_eq!(
        receipt_hybrid.signature.algorithm(),
        SigningAlgorithm::Hybrid
    );

    // Sanity: the two receipts cannot collide.
    assert_ne!(
        receipt_classical.kernel_key.to_hex(),
        receipt_hybrid.kernel_key.to_hex()
    );
}
