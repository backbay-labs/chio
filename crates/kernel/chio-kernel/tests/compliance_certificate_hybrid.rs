//! Hybrid `SessionComplianceCertificate` issuance and verification.
//!
//! Pins the kernel-side compliance certificate envelope under all three
//! `crypto_floor` settings: classical-only (byte-identity baseline),
//! hybrid (allow_hybrid + pq_required), and the cross-floor downgrade
//! rejection that closes threat model row `pq_signature_downgrade`.

#![cfg(feature = "pq")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{Ed25519Backend, HybridBackend, Keypair, MlDsa65Backend, SigningAlgorithm};
use chio_kernel::compliance_certificate::{
    issue_session_compliance_certificate, verify_session_compliance_certificate,
    ComplianceCertificateError, SessionComplianceCertificateBody,
};
use chio_kernel::KernelCryptoFloor;

fn fixture_pq_seed() -> [u8; 32] {
    let raw = b"chio-compliance-cert-hybrid-seed";
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    out
}

fn body_with_floor(floor: KernelCryptoFloor) -> SessionComplianceCertificateBody {
    SessionComplianceCertificateBody {
        session_id: "sess-test-hybrid".to_string(),
        policy_hash: "policy-hash-test".to_string(),
        receipt_count: 7,
        all_signatures_valid: true,
        crypto_floor: floor.as_str().to_string(),
        issued_at: 1_700_000_000,
    }
}

fn classical_backend() -> Ed25519Backend {
    Ed25519Backend::new(Keypair::generate())
}

fn hybrid_backend() -> HybridBackend {
    let classical = Ed25519Backend::new(Keypair::generate());
    let pq = MlDsa65Backend::from_seed(&fixture_pq_seed());
    HybridBackend::new(Box::new(classical), pq).unwrap()
}

#[test]
fn classical_certificate_round_trip_under_allow_classical() {
    let backend = classical_backend();
    let body = body_with_floor(KernelCryptoFloor::AllowClassical);
    let cert =
        issue_session_compliance_certificate(body, KernelCryptoFloor::AllowClassical, &backend)
            .unwrap();
    assert_eq!(cert.algorithm, SigningAlgorithm::Ed25519);
    assert_eq!(cert.signature.algorithm(), SigningAlgorithm::Ed25519);
    verify_session_compliance_certificate(&cert, KernelCryptoFloor::AllowClassical).unwrap();
}

#[test]
fn hybrid_certificate_round_trip_under_allow_hybrid() {
    let backend = hybrid_backend();
    let body = body_with_floor(KernelCryptoFloor::AllowHybrid);
    let cert = issue_session_compliance_certificate(body, KernelCryptoFloor::AllowHybrid, &backend)
        .unwrap();
    assert_eq!(cert.algorithm, SigningAlgorithm::Hybrid);
    assert_eq!(cert.signature.algorithm(), SigningAlgorithm::Hybrid);
    verify_session_compliance_certificate(&cert, KernelCryptoFloor::AllowHybrid).unwrap();
}

#[test]
fn hybrid_certificate_round_trip_under_pq_required() {
    let backend = hybrid_backend();
    let body = body_with_floor(KernelCryptoFloor::PqRequired);
    let cert = issue_session_compliance_certificate(body, KernelCryptoFloor::PqRequired, &backend)
        .unwrap();
    verify_session_compliance_certificate(&cert, KernelCryptoFloor::PqRequired).unwrap();
}

#[test]
fn body_floor_field_mismatch_rejects_at_issuance() {
    let backend = classical_backend();
    // Body claims pq_required but issuance call says allow_classical.
    // Fail-closed: a mis-stamped floor is a downgrade signal, NOT an
    // implicit override.
    let body = body_with_floor(KernelCryptoFloor::PqRequired);
    let err =
        issue_session_compliance_certificate(body, KernelCryptoFloor::AllowClassical, &backend)
            .expect_err("body/issuance floor mismatch must reject");
    assert!(matches!(
        err,
        ComplianceCertificateError::CryptoFloorMismatch { .. }
    ));
}

#[test]
fn classical_certificate_under_pq_required_rejects_at_verification() {
    // Forge: produce a classical certificate, then verify under
    // pq_required. Floor enforcement MUST reject before the cryptographic
    // check. Threat model row `pq_signature_downgrade`.
    let backend = classical_backend();
    let body = body_with_floor(KernelCryptoFloor::AllowClassical);
    let cert =
        issue_session_compliance_certificate(body, KernelCryptoFloor::AllowClassical, &backend)
            .unwrap();
    let err = verify_session_compliance_certificate(&cert, KernelCryptoFloor::PqRequired)
        .expect_err("classical cert under pq_required must reject");
    match err {
        ComplianceCertificateError::RejectedByCryptoFloor { floor, actual } => {
            assert_eq!(floor, "pq_required");
            assert_eq!(actual, "ed25519");
        }
        other => panic!("expected RejectedByCryptoFloor, got {other:?}"),
    }
}

#[test]
fn hybrid_certificate_under_allow_classical_rejects_at_verification() {
    let backend = hybrid_backend();
    let body = body_with_floor(KernelCryptoFloor::AllowHybrid);
    let cert = issue_session_compliance_certificate(body, KernelCryptoFloor::AllowHybrid, &backend)
        .unwrap();
    let err = verify_session_compliance_certificate(&cert, KernelCryptoFloor::AllowClassical)
        .expect_err("hybrid cert under allow_classical must reject");
    assert!(matches!(
        err,
        ComplianceCertificateError::RejectedByCryptoFloor {
            floor: "allow_classical",
            actual: "hybrid",
        }
    ));
}

#[test]
fn tampered_algorithm_field_rejects_before_signature_verification() {
    let backend = hybrid_backend();
    let body = body_with_floor(KernelCryptoFloor::AllowHybrid);
    let mut cert =
        issue_session_compliance_certificate(body, KernelCryptoFloor::AllowHybrid, &backend)
            .unwrap();
    cert.algorithm = SigningAlgorithm::Ed25519;

    let err = verify_session_compliance_certificate(&cert, KernelCryptoFloor::AllowHybrid)
        .expect_err("declared algorithm must match signature material");
    assert!(matches!(
        err,
        ComplianceCertificateError::AlgorithmMismatch {
            declared: "ed25519",
            actual: "hybrid",
        }
    ));
}

#[test]
fn tampered_body_rejects_signature_verification() {
    let backend = classical_backend();
    let body = body_with_floor(KernelCryptoFloor::AllowClassical);
    let mut cert =
        issue_session_compliance_certificate(body, KernelCryptoFloor::AllowClassical, &backend)
            .unwrap();
    cert.body.receipt_count = 99_999_999;
    let err = verify_session_compliance_certificate(&cert, KernelCryptoFloor::AllowClassical)
        .expect_err("tampered body must reject");
    assert!(matches!(
        err,
        ComplianceCertificateError::SignatureVerificationFailed
    ));
}

#[test]
fn canonical_body_bytes_byte_identical_under_allow_classical() {
    // Byte-identity contract: the canonical JSON of a compliance body
    // produced under `allow_classical` is byte-stable.
    let backend = classical_backend();
    let body = body_with_floor(KernelCryptoFloor::AllowClassical);
    let pre = canonical_json_bytes(&body).unwrap();
    let cert =
        issue_session_compliance_certificate(body, KernelCryptoFloor::AllowClassical, &backend)
            .unwrap();
    let post = canonical_json_bytes(&cert.body).unwrap();
    assert_eq!(pre, post);
}
