//! Receipt path consumes `CanonicalBytes` for hybrid signing.
//!
//! The `Arc<CanonicalBytes>` newtype ([`SharedCanonicalBytes`]) is
//! consumed directly by the receipt-signing path without a
//! byte-equivalence shim. This test pins the contract:
//!
//! 1. **Single canonicalization.** The hybrid signing entrypoint builds
//!    the canonical JSON byte buffer once and returns it alongside the
//!    signed receipt; downstream consumers receive the exact bytes the
//!    backend signed.
//! 2. **Byte-identity with the legacy classical entrypoint.** Under the
//!    classical [`Ed25519Backend`] path the canonical bytes returned by
//!    the new hybrid-canonical helper are byte-identical to the bytes
//!    the legacy `sign_receipt_body_with_backend` flow signs. This is
//!    the byte-equivalence guarantee.
//! 3. **Hybrid round-trip verifies against the shared bytes.** The
//!    [`HybridBackend`] signs the shared canonical buffer; the
//!    public-key `verify` path against those EXACT bytes succeeds.
//! 4. **Kernel-key mismatch is fail-closed.** A body whose
//!    `kernel_key` does not match the backend's public key is rejected
//!    BEFORE canonicalization, so a stale-key body never produces a
//!    canonical buffer downstream consumers might persist.
//!
//! Trust boundary: kernel-key / canonical-bytes binding for hybrid receipts.

#![cfg(feature = "pq")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{
    Ed25519Backend, HybridBackend, Keypair, MlDsa65Backend, PublicKey, SharedCanonicalBytes,
    SigningAlgorithm, SigningBackend,
};
use chio_core::receipt::{
    body::chio_receipt_id, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::TrustLevel, signing::bind_receipt_signing_nonce, signing::ChioReceiptSigningBody,
};
use chio_kernel::{
    sign_receipt_body_hybrid_canonical, sign_receipt_body_with_backend, SignedHybridReceipt,
};

/// Canonical JSON bytes of the authoritative `ChioReceiptSigningBody`
/// wrapper that both signing paths sign. The wrapper binds the
/// content-addressed receipt id (`chio_receipt_id`) to the
/// `ChioReceiptIdInput` that derived it. Tests use this helper to
/// compare produced bytes against the authoritative signed bytes.
fn canonical_signing_wrapper_bytes(body: &ChioReceiptBody) -> Vec<u8> {
    let mut body = body.clone();
    // Bind the signing nonce before computing the id, mirroring what every
    // signing entrypoint does, so this oracle reflects the authoritative bytes
    // both the classical and hybrid paths actually sign.
    bind_receipt_signing_nonce(&mut body);
    body.id = chio_receipt_id(&body).unwrap();
    let signing_body = ChioReceiptSigningBody::from(&body);
    canonical_json_bytes(&signing_body).unwrap()
}

fn fixture_classical_seed() -> [u8; 32] {
    let raw = b"chio-canonical-bytes-class-seed!";
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    out
}

fn fixture_pq_seed() -> [u8; 32] {
    let raw = b"chio-canonical-bytes-pq-seedval!";
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    out
}

/// Canonical content preimage the test bodies bind their `content_hash` to.
/// `sign_receipt_body_with_backend` recomputes `sha256_hex` over these bytes and
/// refuses to sign on mismatch (WYSIWYS, BAC-539), so the body built by
/// [`build_body`] carries exactly `sha256_hex(FIXTURE_CANONICAL_CONTENT)`.
const FIXTURE_CANONICAL_CONTENT: &[u8] = br#"{"q":"canonical"}"#;

fn build_body(kernel_key: PublicKey) -> ChioReceiptBody {
    ChioReceiptBody {
        id: "rcpt-canonical-bytes-hybrid".to_string(),
        timestamp: 1_700_000_002,
        capability_id: "cap-canon-bytes".to_string(),
        tool_server: "audit-server".to_string(),
        tool_name: "report".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"q": "canonical"})).unwrap(),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: chio_core::crypto::sha256_hex(FIXTURE_CANONICAL_CONTENT),
        policy_hash: "policy-canon".to_string(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key,
        bbs_projection_version: None,
    }
}

#[test]
fn shared_canonical_bytes_match_classical_signing_path() {
    // Contract 2: the canonical buffer the hybrid-canonical helper
    // emits under a classical backend is byte-identical to the buffer
    // the legacy classical entrypoint signs. Deployments
    // see no byte drift when they switch to the canonical-bytes-aware
    // entrypoint.
    let kp = Keypair::from_seed(&fixture_classical_seed());
    let backend = Ed25519Backend::new(kp.clone());
    let body = build_body(kp.public_key());

    // Authoritative signing-wrapper bytes: re-derive the way both
    // signing paths do internally (id from `ChioReceiptIdInput`, wrap
    // into `ChioReceiptSigningBody`, canonicalize). The bare body
    // bytes are NOT what either path signs; the wrapper is.
    let wrapper_bytes = canonical_signing_wrapper_bytes(&body);
    let legacy_receipt =
        sign_receipt_body_with_backend(body.clone(), &backend, FIXTURE_CANONICAL_CONTENT).unwrap();

    // New path: consume the SharedCanonicalBytes newtype.
    let SignedHybridReceipt { receipt, canonical } =
        sign_receipt_body_hybrid_canonical(body, &backend, FIXTURE_CANONICAL_CONTENT).unwrap();

    // The shared buffer matches the authoritative signing-wrapper
    // bytes byte-for-byte. This pins the contract that
    // `sign_receipt_body_hybrid_canonical` signs the
    // `ChioReceiptSigningBody` wrapper, NOT the bare `ChioReceiptBody`.
    assert_eq!(
        canonical.as_bytes(),
        wrapper_bytes.as_slice(),
        "shared CanonicalBytes drifted from authoritative ChioReceiptSigningBody bytes"
    );
    // The signed receipt is byte-identical to the legacy receipt: the
    // hybrid path and classical path produce the same signed envelope
    // when fed the same body and Ed25519 backend (Ed25519 signatures
    // are deterministic per RFC 8032).
    assert_eq!(
        canonical_json_bytes(&receipt).unwrap(),
        canonical_json_bytes(&legacy_receipt).unwrap(),
        "hybrid-canonical receipt envelope drifted from legacy receipt"
    );
    assert_eq!(receipt.signature.algorithm(), SigningAlgorithm::Ed25519);

    // Verify the produced signature against the exact shared wrapper
    // bytes the backend signed.
    assert!(
        receipt
            .kernel_key
            .verify(canonical.as_bytes(), &receipt.signature),
        "signature MUST verify against the exact ChioReceiptSigningBody bytes"
    );
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
        sign_receipt_body_hybrid_canonical(body, &hybrid, FIXTURE_CANONICAL_CONTENT).unwrap();

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
    // `Arc<CanonicalBytes>` newtype so multiple downstream
    // consumers can share a single allocation. Cloning the Arc is cheap
    // and does not reserialize.
    let classical_kp = Keypair::from_seed(&fixture_classical_seed());
    let classical_backend = Ed25519Backend::new(classical_kp);
    let pq = MlDsa65Backend::from_seed(&fixture_pq_seed());
    let hybrid = HybridBackend::new(Box::new(classical_backend), pq).unwrap();
    let body = build_body(hybrid.public_key());

    let signed =
        sign_receipt_body_hybrid_canonical(body, &hybrid, FIXTURE_CANONICAL_CONTENT).unwrap();
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

    let result = sign_receipt_body_hybrid_canonical(body, &backend, FIXTURE_CANONICAL_CONTENT);
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
fn content_hash_mismatch_fails_closed_render_a_sign_b() {
    // WYSIWYS (BAC-539): the shared-canonical hybrid path must refuse to sign
    // a body whose claimed `content_hash` does not match the canonical content
    // preimage handed to the signer (render content A, sign hash B). The refusal
    // happens before any cryptographic work.
    let kp = Keypair::from_seed(&fixture_classical_seed());
    let backend = Ed25519Backend::new(kp.clone());
    // `build_body` binds `content_hash = sha256_hex(FIXTURE_CANONICAL_CONTENT)`,
    // but we hand the signer a DIFFERENT preimage. The recompute must disagree
    // with the body's claim and refuse.
    let body = build_body(kp.public_key());
    let attacker_preimage = br#"{"q":"a-different-thing"}"#;

    let result = sign_receipt_body_hybrid_canonical(body, &backend, attacker_preimage);
    let err = match result {
        Ok(_) => panic!("render-A/sign-B MUST fail-closed on the hybrid-canonical path"),
        Err(err) => err,
    };
    let msg = format!("{err:?}");
    assert!(
        msg.contains("content_hash mismatch") && msg.contains("WYSIWYS refused"),
        "expected WYSIWYS content-hash mismatch diagnostic, got {msg}"
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

    let signed =
        sign_receipt_body_hybrid_canonical(body.clone(), &hybrid, FIXTURE_CANONICAL_CONTENT)
            .unwrap();
    // The shared buffer matches the authoritative
    // `ChioReceiptSigningBody` wrapper bytes, NOT the bare body bytes.
    let wrapper_bytes = canonical_signing_wrapper_bytes(&body);
    assert_eq!(signed.canonical.as_bytes(), wrapper_bytes.as_slice());
    // The signed receipt itself round-trips through serde without
    // drift.
    let receipt_json = serde_json::to_vec(&signed.receipt).unwrap();
    let restored: chio_core::receipt::body::ChioReceipt =
        serde_json::from_slice(&receipt_json).unwrap();
    assert!(restored.verify_signature().unwrap());
}

#[test]
fn hybrid_canonical_and_classical_paths_sign_identical_bytes_under_ed25519() {
    // `sign_receipt_body_hybrid_canonical` must sign
    // the authoritative `ChioReceiptSigningBody` wrapper (id plus
    // `ChioReceiptIdInput`), not the bare `ChioReceiptBody`. Under a
    // classical-only Ed25519 backend this means the signed bytes -- and
    // therefore the deterministic Ed25519 signature -- must match the
    // sibling non-hybrid path byte-for-byte for the same body.
    let kp = Keypair::from_seed(&fixture_classical_seed());
    let backend = Ed25519Backend::new(kp.clone());
    let body = build_body(kp.public_key());

    // Sign through both entrypoints.
    let classical_receipt =
        sign_receipt_body_with_backend(body.clone(), &backend, FIXTURE_CANONICAL_CONTENT).unwrap();
    let SignedHybridReceipt {
        receipt: hybrid_receipt,
        canonical,
    } = sign_receipt_body_hybrid_canonical(body.clone(), &backend, FIXTURE_CANONICAL_CONTENT)
        .unwrap();

    // The receipt id is content-addressed and identical across paths.
    assert_eq!(
        classical_receipt.id, hybrid_receipt.id,
        "receipt id must be identical across signing paths"
    );

    // The signed bytes are byte-identical: both paths canonicalize the
    // same `ChioReceiptSigningBody` wrapper.
    let expected_wrapper_bytes = canonical_signing_wrapper_bytes(&body);
    assert_eq!(
        canonical.as_bytes(),
        expected_wrapper_bytes.as_slice(),
        "hybrid-canonical path must sign the ChioReceiptSigningBody wrapper bytes"
    );

    // Ed25519 is deterministic per RFC 8032, so identical input bytes
    // and identical keys produce byte-identical signatures.
    assert_eq!(
        canonical_json_bytes(&classical_receipt.signature).unwrap(),
        canonical_json_bytes(&hybrid_receipt.signature).unwrap(),
        "Ed25519 signatures must be byte-identical across the two signing paths"
    );

    // The receipt envelopes themselves are byte-identical.
    assert_eq!(
        canonical_json_bytes(&classical_receipt).unwrap(),
        canonical_json_bytes(&hybrid_receipt).unwrap(),
        "signed receipt envelope must be byte-identical across paths"
    );

    // Cross-path verification: the classical path's signature MUST
    // verify against the hybrid path's shared canonical bytes (and
    // vice versa).
    assert!(
        classical_receipt
            .kernel_key
            .verify(canonical.as_bytes(), &classical_receipt.signature),
        "classical signature MUST verify against the hybrid path's shared canonical bytes"
    );
    assert!(
        hybrid_receipt
            .kernel_key
            .verify(&expected_wrapper_bytes, &hybrid_receipt.signature),
        "hybrid path signature MUST verify against independently computed wrapper bytes"
    );
}
