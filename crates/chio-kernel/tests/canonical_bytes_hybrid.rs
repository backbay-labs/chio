//! Receipt path consumes `CanonicalBytes` for hybrid signing (M03.P5.T3).
//!
//! Per D16, the M06 `Arc<CanonicalBytes>` newtype
//! ([`SharedCanonicalBytes`]) ships before M03.P1 opens, so the
//! receipt-signing path consumes it directly without a byte-equivalence
//! shim. This test pins the contract:
//!
//! 1. **Single canonicalization.** The hybrid signing entrypoint builds
//!    the canonical JSON byte buffer once and returns it alongside the
//!    signed receipt; downstream consumers receive the exact bytes the
//!    backend signed.
//! 2. **Byte-identity with the legacy classical entrypoint.** Under the
//!    classical [`Ed25519Backend`] path the canonical bytes returned by
//!    the new hybrid-canonical helper are byte-identical to the bytes
//!    the legacy `sign_receipt_body_with_backend` flow signs. This is
//!    the trajectory-1 byte-equivalence guarantee.
//! 3. **Hybrid round-trip verifies against the shared bytes.** The
//!    [`HybridBackend`] signs the shared canonical buffer; the
//!    public-key `verify` path against those EXACT bytes succeeds.
//! 4. **Kernel-key mismatch is fail-closed.** A body whose
//!    `kernel_key` does not match the backend's public key is rejected
//!    BEFORE canonicalization, so a stale-key body never produces a
//!    canonical buffer downstream consumers might persist.
//!
//! Trust-boundary milestone: M03 P5.T3.

#![cfg(feature = "pq")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{
    Ed25519Backend, HybridBackend, Keypair, MlDsa65Backend, PublicKey, SharedCanonicalBytes,
    SigningAlgorithm, SigningBackend,
};
use chio_core::receipt::{ChioReceiptBody, Decision, ToolCallAction, TrustLevel};
use chio_kernel::{
    sign_receipt_body_hybrid_canonical, sign_receipt_body_with_backend, SignedHybridReceipt,
};

fn fixture_classical_seed() -> [u8; 32] {
    let raw = b"chio-m03-p5-t3-canonbytes-class!";
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    out
}

fn fixture_pq_seed() -> [u8; 32] {
    let raw = b"chio-m03-p5-t3-canonbytes-pqseed";
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    out
}

fn build_body(kernel_key: PublicKey) -> ChioReceiptBody {
    ChioReceiptBody {
        id: "rcpt-canonical-bytes-hybrid".to_string(),
        timestamp: 1_700_000_002,
        capability_id: "cap-canon-bytes".to_string(),
        tool_server: "audit-server".to_string(),
        tool_name: "report".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"q": "canonical"})).unwrap(),
        decision: Decision::Allow,
        content_hash: "2222222222222222222222222222222222222222222222222222222222222222"
            .to_string(),
        policy_hash: "policy-canon".to_string(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key,
    }
}

#[test]
fn shared_canonical_bytes_match_legacy_classical_path() {
    // Contract 2: the canonical buffer the hybrid-canonical helper
    // emits under a classical backend is byte-identical to the buffer
    // the legacy classical entrypoint signs. Trajectory-1 deployments
    // see no byte drift when they switch to the canonical-bytes-aware
    // entrypoint.
    let kp = Keypair::from_seed(&fixture_classical_seed());
    let backend = Ed25519Backend::new(kp.clone());
    let body = build_body(kp.public_key());

    // Legacy path: re-canonicalize the body the way the existing
    // `sign_receipt_body_with_backend` flow does.
    let legacy_canonical_bytes = canonical_json_bytes(&body).unwrap();
    let legacy_receipt = sign_receipt_body_with_backend(body.clone(), &backend).unwrap();

    // New path: consume the M06 SharedCanonicalBytes newtype.
    let SignedHybridReceipt { receipt, canonical } =
        sign_receipt_body_hybrid_canonical(body, &backend).unwrap();

    // The shared buffer matches the legacy buffer byte-for-byte.
    assert_eq!(
        canonical.as_bytes(),
        legacy_canonical_bytes.as_slice(),
        "shared CanonicalBytes drifted from legacy canonical_json_bytes"
    );
    // The signed receipt is byte-identical to the legacy receipt.
    assert_eq!(
        canonical_json_bytes(&receipt).unwrap(),
        canonical_json_bytes(&legacy_receipt).unwrap(),
        "hybrid-canonical receipt envelope drifted from legacy receipt"
    );
    assert_eq!(receipt.signature.algorithm(), SigningAlgorithm::Ed25519);
}

#[test]
fn hybrid_signing_consumes_shared_canonical_bytes_and_verifies() {
    // Contract 1 + 3: the hybrid backend signs the shared canonical
    // buffer and the public key's verify path against those bytes
    // succeeds. The buffer is built ONCE and shared.
    let classical_kp = Keypair::from_seed(&fixture_classical_seed());
    let classical_backend = Ed25519Backend::new(classical_kp);
    let pq = MlDsa65Backend::from_seed(&fixture_pq_seed());
    let hybrid = HybridBackend::new(Box::new(classical_backend), pq).unwrap();

    let body = build_body(hybrid.public_key());
    let SignedHybridReceipt { receipt, canonical } =
        sign_receipt_body_hybrid_canonical(body, &hybrid).unwrap();

    assert_eq!(receipt.signature.algorithm(), SigningAlgorithm::Hybrid);

    // Verify against the EXACT shared bytes the backend signed. This
    // is the byte chain downstream consumers preserve.
    assert!(
        receipt
            .kernel_key
            .verify(canonical.as_bytes(), &receipt.signature),
        "hybrid signature MUST verify against shared CanonicalBytes"
    );
}

#[test]
fn shared_canonical_bytes_are_arc_shareable_without_recanonicalization() {
    // Contract 1: the returned canonical buffer is an
    // `Arc<CanonicalBytes>` (the M06 newtype) so multiple downstream
    // consumers can share a single allocation. Cloning the Arc is cheap
    // and does not reserialize.
    let classical_kp = Keypair::from_seed(&fixture_classical_seed());
    let classical_backend = Ed25519Backend::new(classical_kp);
    let pq = MlDsa65Backend::from_seed(&fixture_pq_seed());
    let hybrid = HybridBackend::new(Box::new(classical_backend), pq).unwrap();
    let body = build_body(hybrid.public_key());

    let signed = sign_receipt_body_hybrid_canonical(body, &hybrid).unwrap();
    let shared: SharedCanonicalBytes = signed.canonical.clone();

    // Two Arc handles to the same allocation (Arc::strong_count >= 2).
    assert!(
        Arc::strong_count(&shared) >= 2,
        "SharedCanonicalBytes MUST be Arc-shareable; strong_count = {}",
        Arc::strong_count(&shared)
    );
    assert_eq!(shared.as_bytes(), signed.canonical.as_bytes());
    // Pointer equality on the underlying allocation: cloning the Arc
    // does NOT reserialize the body.
    assert!(Arc::ptr_eq(&shared, &signed.canonical));
}

#[test]
fn kernel_key_mismatch_fails_closed_before_canonicalization() {
    // Contract 4: the helper rejects mismatched kernel keys BEFORE
    // building the canonical buffer, so a stale-key body never
    // produces a canonical artifact downstream consumers might
    // persist.
    let kp_a = Keypair::from_seed(&fixture_classical_seed());
    let kp_b = Keypair::generate();
    let backend = Ed25519Backend::new(kp_a);
    // Body declares kp_b's public key while the backend signs with
    // kp_a -- a misconfiguration the helper MUST reject.
    let body = build_body(kp_b.public_key());

    let result = sign_receipt_body_hybrid_canonical(body, &backend);
    let err = match result {
        Ok(_) => panic!("kernel-key mismatch MUST fail-closed"),
        Err(err) => err,
    };
    let msg = format!("{err:?}");
    assert!(
        msg.contains("kernel signing key does not match"),
        "expected kernel-key mismatch diagnostic, got {msg}"
    );
}

#[test]
fn shared_bytes_round_trip_through_serde_after_signing() {
    // Defence-in-depth: the receipt envelope produced by the
    // canonical-bytes-aware entrypoint serializes to the SAME bytes the
    // backend signed (modulo the added `signature`/`algorithm`
    // fields). Together with the `verify` check above, this proves the
    // shared-buffer pipeline produces a wire-stable artifact.
    let classical_kp = Keypair::from_seed(&fixture_classical_seed());
    let classical_backend = Ed25519Backend::new(classical_kp);
    let pq = MlDsa65Backend::from_seed(&fixture_pq_seed());
    let hybrid = HybridBackend::new(Box::new(classical_backend), pq).unwrap();
    let body = build_body(hybrid.public_key());

    let signed = sign_receipt_body_hybrid_canonical(body.clone(), &hybrid).unwrap();
    // Re-encode the body and verify the shared buffer byte-matches.
    let body_bytes = canonical_json_bytes(&body).unwrap();
    assert_eq!(signed.canonical.as_bytes(), body_bytes.as_slice());
    // The signed receipt itself round-trips through serde without
    // drift.
    let receipt_json = serde_json::to_vec(&signed.receipt).unwrap();
    let restored: chio_core::receipt::ChioReceipt = serde_json::from_slice(&receipt_json).unwrap();
    assert!(restored.verify_signature().unwrap());
}
