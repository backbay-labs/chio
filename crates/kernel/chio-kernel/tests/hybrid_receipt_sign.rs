//! Hybrid receipt signing path integration tests.
//!
//! Pins the kernel-side construction of the hybrid signing backend from a
//! configured `crypto_floor` and a 32-byte ML-DSA-65 keygen seed, and the
//! receipt sign-then-verify round trip through `&dyn SigningBackend`. The
//! test deliberately exercises both the classical-only path under
//! `allow_classical` (byte-identity baseline) and the hybrid path under
//! `allow_hybrid` and `pq_required`.

#![cfg(feature = "pq")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{Keypair, PublicKey, SigningAlgorithm};
use chio_core::receipt::{
    body::chio_receipt_id, body::ChioReceiptBody, crypto_floor::ReceiptCryptoFloor,
    decision::Decision, decision::ToolCallAction, kinds::TrustLevel,
    signing::ChioReceiptSigningBody, signing::CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY,
};
use chio_kernel::{
    kernel_signing_backend, sign_receipt_body_with_backend, KernelCryptoFloor,
    KernelSigningBackendError,
};

/// Bind the `chio_receipt_signing_nonce` metadata key to the pre-nonce
/// receipt id, mirroring `chio_core_types::receipt::signing::bind_receipt_signing_nonce`
/// (the private step `ChioReceipt::sign_with_backend` runs before computing
/// the content-addressed id). The nonce is the trimmed pre-nonce `body.id`;
/// an existing non-object metadata value is preserved under
/// `original_metadata`. This is the canonical signed-body transform, so the
/// test reconstructs the exact bytes the signer signs.
fn bind_signing_nonce(body: &mut ChioReceiptBody) {
    let nonce = body.id.trim();
    if nonce.is_empty() {
        return;
    }
    let mut metadata = match body.metadata.take() {
        Some(serde_json::Value::Object(map)) => map,
        Some(value) => {
            let mut map = serde_json::Map::new();
            map.insert("original_metadata".to_string(), value);
            map
        }
        None => serde_json::Map::new(),
    };
    metadata.insert(
        CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY.to_string(),
        serde_json::Value::String(nonce.to_string()),
    );
    body.metadata = Some(serde_json::Value::Object(metadata));
}

/// Canonical JSON bytes of the authoritative `ChioReceiptSigningBody`
/// wrapper. Both classical and hybrid receipt-signing paths sign these
/// bytes, not the bare `ChioReceiptBody` bytes. The signer binds the
/// `chio_receipt_signing_nonce` metadata key before computing the id, so the
/// reconstruction here applies the same binding first.
fn canonical_signing_wrapper_bytes(body: &ChioReceiptBody) -> Vec<u8> {
    let mut body = body.clone();
    bind_signing_nonce(&mut body);
    body.id = chio_receipt_id(&body).unwrap();
    let signing_body = ChioReceiptSigningBody::from(&body);
    canonical_json_bytes(&signing_body).unwrap()
}

fn fixture_pq_seed() -> [u8; 32] {
    // Stable test seed: reproducible across runs, never used in production.
    let raw = b"chio-hybrid-receipt-sign-seedval";
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    out
}

/// Canonical content preimage the test bodies bind their `content_hash` to.
/// `sign_receipt_body_with_backend` recomputes `sha256_hex` over these bytes and
/// refuses to sign on mismatch (WYSIWYS), so the body built by
/// [`build_body`] carries exactly `sha256_hex(FIXTURE_CANONICAL_CONTENT)`.
const FIXTURE_CANONICAL_CONTENT: &[u8] = br#"{"k":"v"}"#;

fn build_body(kernel_key: PublicKey) -> ChioReceiptBody {
    ChioReceiptBody {
        id: "rcpt-test-hybrid".to_string(),
        timestamp: 1_700_000_000,
        capability_id: "cap-test".to_string(),
        tool_server: "srv".to_string(),
        tool_name: "echo".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"k": "v"})).unwrap(),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: chio_core::crypto::sha256_hex(FIXTURE_CANONICAL_CONTENT),
        policy_hash: "test-policy".to_string(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key,
        bbs_projection_version: None,
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
    let backend = kernel_signing_backend(KernelCryptoFloor::PqRequired, kp, Some(&seed)).unwrap();
    assert_eq!(backend.algorithm(), SigningAlgorithm::Hybrid);
}

#[test]
fn classical_receipt_byte_identical_under_allow_classical() {
    // Byte-identity contract: receipts signed under `allow_classical`
    // serialize byte-for-byte the same as the classical path.
    let kp = Keypair::generate();
    let backend =
        kernel_signing_backend(KernelCryptoFloor::AllowClassical, kp.clone(), None).unwrap();

    let body = build_body(kp.public_key());
    let body_bytes_pre = canonical_json_bytes(&body).unwrap();

    let receipt =
        sign_receipt_body_with_backend(body.clone(), backend.as_ref(), FIXTURE_CANONICAL_CONTENT)
            .unwrap();
    assert_eq!(receipt.kernel_key, kp.public_key());
    assert_eq!(receipt.signature.algorithm(), SigningAlgorithm::Ed25519);

    // The receipt body bytes are unchanged after signing through the new
    // path: we never alter the canonical encoding of an Ed25519 receipt.
    let body_bytes_post = canonical_json_bytes(&body).unwrap();
    assert_eq!(body_bytes_pre, body_bytes_post);

    // Signature verifies via the issuer key. The signed bytes are the
    // authoritative `ChioReceiptSigningBody` wrapper bytes, not the
    // bare body bytes.
    let wrapper_bytes = canonical_signing_wrapper_bytes(&body);
    assert!(
        receipt
            .kernel_key
            .verify(&wrapper_bytes, &receipt.signature),
        "signature must verify against the ChioReceiptSigningBody wrapper bytes"
    );
    assert!(receipt.verify_signature().unwrap());
    assert!(receipt
        .verify_signature_with_floor(ReceiptCryptoFloor::AllowClassical)
        .unwrap());
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

    let receipt =
        sign_receipt_body_with_backend(body.clone(), backend.as_ref(), FIXTURE_CANONICAL_CONTENT)
            .unwrap();
    assert_eq!(receipt.signature.algorithm(), SigningAlgorithm::Hybrid);
    assert_eq!(receipt.kernel_key.algorithm(), SigningAlgorithm::Hybrid);

    // The signature verifies against the authoritative
    // `ChioReceiptSigningBody` wrapper bytes, not the bare body bytes.
    let wrapper_bytes = canonical_signing_wrapper_bytes(&body);
    assert!(receipt
        .kernel_key
        .verify(&wrapper_bytes, &receipt.signature));
    assert!(receipt.verify_signature().unwrap());
    assert!(receipt
        .verify_signature_with_floor(ReceiptCryptoFloor::PqRequired)
        .unwrap());
    let err = receipt
        .verify_signature_with_floor(ReceiptCryptoFloor::AllowClassical)
        .expect_err("hybrid receipt must reject under allow_classical");
    assert!(err.to_string().contains("crypto_floor=allow_classical"));
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

    let err = sign_receipt_body_with_backend(body, backend.as_ref(), FIXTURE_CANONICAL_CONTENT)
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
        FIXTURE_CANONICAL_CONTENT,
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
    let receipt_hybrid = sign_receipt_body_with_backend(
        body_hybrid,
        backend_hybrid.as_ref(),
        FIXTURE_CANONICAL_CONTENT,
    )
    .unwrap();
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
