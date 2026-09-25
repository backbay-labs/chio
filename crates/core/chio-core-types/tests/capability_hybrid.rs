//! Capability token signing/verification under `crypto_floor`.
//!
//! Pins the dispatch table for `CapabilityToken::verify_signature_with_floor`
//! across all combinations of (signature algorithm, configured floor).
//! Threat model row `pq_signature_downgrade` is the surface this guards.

#![cfg(feature = "pq")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core_types::capability::{
    crypto_floor::{CapabilityCryptoFloor, CapabilityFloorVerifyError},
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core_types::crypto::{
    HybridBackend, Keypair, MlDsa65Backend, SigningAlgorithm, SigningBackend,
};

fn fixture_pq_seed() -> [u8; 32] {
    let raw = b"chio-capability-hybrid-seed-0001";
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    out
}

fn make_body(issuer: &chio_core_types::crypto::PublicKey) -> CapabilityTokenBody {
    CapabilityTokenBody {
        id: "cap-hybrid-test".to_string(),
        issuer: issuer.clone(),
        subject: Keypair::generate().public_key(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "echo".to_string(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        },
        issued_at: 1_700_000_000,
        expires_at: 1_700_003_600,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
    }
}

fn classical_token() -> CapabilityToken {
    let kp = Keypair::generate();
    let body = make_body(&kp.public_key());
    CapabilityToken::sign(body, &kp).unwrap()
}

fn hybrid_token() -> CapabilityToken {
    let kp = Keypair::generate();
    let pq = MlDsa65Backend::from_seed(&fixture_pq_seed());
    let classical = chio_core_types::crypto::Ed25519Backend::new(kp);
    let backend = HybridBackend::new(Box::new(classical), pq).unwrap();
    let body = make_body(&backend.public_key());
    CapabilityToken::sign_with_backend(body, &backend).unwrap()
}

#[test]
fn classical_token_under_allow_classical_verifies() {
    let cap = classical_token();
    assert_eq!(cap.signature.algorithm(), SigningAlgorithm::Ed25519);
    let ok = cap
        .verify_signature_with_floor(CapabilityCryptoFloor::AllowClassical)
        .unwrap();
    assert!(ok);
}

#[test]
fn classical_token_under_allow_hybrid_verifies() {
    let cap = classical_token();
    let ok = cap
        .verify_signature_with_floor(CapabilityCryptoFloor::AllowHybrid)
        .unwrap();
    assert!(ok);
}

#[test]
fn classical_token_under_pq_required_rejects_at_floor() {
    let cap = classical_token();
    let err = cap
        .verify_signature_with_floor(CapabilityCryptoFloor::PqRequired)
        .expect_err("classical token under pq_required must reject at floor");
    match err {
        CapabilityFloorVerifyError::RejectedByCryptoFloor {
            floor,
            signature_algorithm,
        } => {
            assert_eq!(floor, CapabilityCryptoFloor::PqRequired);
            assert_eq!(signature_algorithm, SigningAlgorithm::Ed25519);
        }
        other => panic!("expected RejectedByCryptoFloor, got {other:?}"),
    }
}

#[test]
fn hybrid_token_under_allow_classical_rejects_at_floor() {
    let cap = hybrid_token();
    assert_eq!(cap.signature.algorithm(), SigningAlgorithm::Hybrid);
    let err = cap
        .verify_signature_with_floor(CapabilityCryptoFloor::AllowClassical)
        .expect_err("hybrid token under allow_classical must reject at floor");
    match err {
        CapabilityFloorVerifyError::RejectedByCryptoFloor {
            floor,
            signature_algorithm,
        } => {
            assert_eq!(floor, CapabilityCryptoFloor::AllowClassical);
            assert_eq!(signature_algorithm, SigningAlgorithm::Hybrid);
        }
        other => panic!("expected RejectedByCryptoFloor, got {other:?}"),
    }
}

#[test]
fn hybrid_token_under_allow_hybrid_verifies() {
    let cap = hybrid_token();
    let ok = cap
        .verify_signature_with_floor(CapabilityCryptoFloor::AllowHybrid)
        .unwrap();
    assert!(ok);
}

#[test]
fn hybrid_token_under_pq_required_verifies() {
    let cap = hybrid_token();
    let ok = cap
        .verify_signature_with_floor(CapabilityCryptoFloor::PqRequired)
        .unwrap();
    assert!(ok);
}

#[test]
fn algorithm_envelope_field_mismatch_rejects_fail_closed() {
    // Forge: produce a hybrid signature, then claim Ed25519 in the
    // envelope field. The validator MUST reject before invoking the
    // cryptographic step. Threat model row `pq_signature_downgrade`.
    let mut cap = hybrid_token();
    cap.algorithm = Some(SigningAlgorithm::Ed25519);
    let err = cap
        .verify_signature_with_floor(CapabilityCryptoFloor::AllowHybrid)
        .expect_err("envelope mismatch must reject");
    match err {
        CapabilityFloorVerifyError::AlgorithmMismatch { declared, actual } => {
            assert_eq!(declared, SigningAlgorithm::Ed25519);
            assert_eq!(actual, SigningAlgorithm::Hybrid);
        }
        other => panic!("expected AlgorithmMismatch, got {other:?}"),
    }
}

#[test]
fn algorithm_envelope_field_absent_is_accepted() {
    // Trajectory-1 capability tokens omit the `algorithm` envelope field
    // entirely (Ed25519 default). The validator MUST accept the absence
    // and dispatch on signature material.
    let cap = classical_token();
    assert!(cap.algorithm.is_none());
    let ok = cap
        .verify_signature_with_floor(CapabilityCryptoFloor::AllowClassical)
        .unwrap();
    assert!(ok);
}

#[test]
fn floor_rejection_fires_before_crypto_check() {
    // Tamper the signature: corrupt the body so the signature is invalid.
    // Under a floor that disallows the algorithm, we expect a floor
    // rejection (NOT a SignatureVerificationFailed) because the floor
    // gate fires first. This proves the gate ordering documented in the
    // method's doc comment.
    let mut cap = hybrid_token();
    cap.id = "tampered".to_string();
    let err = cap
        .verify_signature_with_floor(CapabilityCryptoFloor::AllowClassical)
        .expect_err("tampered hybrid token under allow_classical must reject at floor");
    assert!(matches!(
        err,
        CapabilityFloorVerifyError::RejectedByCryptoFloor { .. }
    ));
}

#[test]
fn classical_verify_signature_works_on_classical_token() {
    // Byte-equivalence regression: `verify_signature` continues to work on
    // a classical token without observing the floor.
    let cap = classical_token();
    assert!(cap.verify_signature().unwrap());
}

#[test]
fn classical_verify_signature_works_on_hybrid_token() {
    // Sanity: verify_signature continues to dispatch correctly on a
    // hybrid token (no floor enforcement; pure cryptographic check).
    let cap = hybrid_token();
    assert!(cap.verify_signature().unwrap());
}

#[test]
fn capability_crypto_floor_serializes_snake_case() {
    for (variant, expected) in [
        (CapabilityCryptoFloor::AllowClassical, "\"allow_classical\""),
        (CapabilityCryptoFloor::AllowHybrid, "\"allow_hybrid\""),
        (CapabilityCryptoFloor::PqRequired, "\"pq_required\""),
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        assert_eq!(json, expected);
    }
}
