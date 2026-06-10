//! Integration test: model card lineage anchor proof.
//!
//! Asserts the published-card lineage anchor produced by
//! [`chio_weights::anchor_model_card`] verifies through the model-card
//! anchor surface and degrades cleanly when hybrid signing is absent.
//! The anchor digest format matches the lineage-anchor frontier digest so
//! consumers route both through one verifier.

use std::time::SystemTime;

use chio_attest_verify::VerifiedAttestation;
use chio_lineage::anchor::{CanonicalSource, SigningState};
use chio_weights::{
    anchor_model_card, verify_model_card_anchor, ModelCard, ModelCardLineageAnchor, StringSet,
    VerifiedModelCard, MODEL_CARD_ANCHOR_SCHEMA,
};
use chrono::{DateTime, TimeZone, Utc};
use sha2::{Digest, Sha256};

fn fixed_now() -> DateTime<Utc> {
    match Utc.with_ymd_and_hms(2026, 4, 30, 12, 0, 0) {
        chrono::LocalResult::Single(t) => t,
        _ => panic!("fixed_now fixture must construct"),
    }
}

fn good_card() -> ModelCard {
    let now = fixed_now();
    match ModelCard::new(
        "0000000000000000000000000000000000000000000000000000000000000001",
        StringSet::new(["tool:read", "tool:write"]),
        StringSet::new(["tool:exec"]),
        "public-internet",
        "https://example.com/issuer",
        now,
        now + chrono::Duration::days(30),
    ) {
        Ok(c) => c,
        Err(e) => panic!("good_card: {e}"),
    }
}

fn attestation_for(card_bytes: &[u8]) -> VerifiedAttestation {
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&Sha256::digest(card_bytes));
    VerifiedAttestation {
        subject_digest_sha256: digest,
        certificate_identity: "https://example.com/issuer".into(),
        certificate_oidc_issuer: "https://token.example.com".into(),
        rekor_log_index: 7,
        rekor_inclusion_verified: true,
        signed_at: SystemTime::UNIX_EPOCH,
    }
}

#[test]
fn published_card_anchor_verifies_round_trip() {
    let card = good_card();
    let bytes = match card.to_canonical_json() {
        Ok(b) => b,
        Err(e) => panic!("encode: {e}"),
    };
    let attestation = attestation_for(&bytes);
    let verified = VerifiedModelCard {
        card: card.clone(),
        attestation: attestation.clone(),
    };
    let anchor = match anchor_model_card(&verified, &bytes, "chio.lineage.graph/v1", None) {
        Ok(a) => a,
        Err(e) => panic!("anchor: {e}"),
    };

    assert_eq!(anchor.schema_version, MODEL_CARD_ANCHOR_SCHEMA);
    assert_eq!(anchor.graph_schema, "chio.lineage.graph/v1");
    assert!(matches!(
        anchor.canonical_source,
        CanonicalSource::EquivalenceShim
    ));
    assert_eq!(anchor.weights_hash, card.weights_hash);
    assert_eq!(anchor.card_issuer, card.issuer);
    assert_eq!(anchor.card_expires_at, card.expires_at);
    assert!(matches!(
        anchor.signing,
        SigningState::UnsignedSoftDepAbsent
    ));

    match verify_model_card_anchor(&anchor, &bytes, &attestation) {
        Ok(()) => {}
        Err(e) => panic!("verify must accept faithful anchor: {e}"),
    }
}

#[test]
fn anchor_carries_signed_state_when_signer_present() {
    let card = good_card();
    let bytes = match card.to_canonical_json() {
        Ok(b) => b,
        Err(e) => panic!("encode: {e}"),
    };
    let attestation = attestation_for(&bytes);
    let verified = VerifiedModelCard { card, attestation };
    let anchor = match anchor_model_card(
        &verified,
        &bytes,
        "chio.lineage.graph/v1",
        Some("hybrid:ed25519+ml-dsa-65"),
    ) {
        Ok(a) => a,
        Err(e) => panic!("anchor: {e}"),
    };
    // Signer hint is present but no signature payload was supplied, so
    // the anchor records `UnsignedSignerStubbed`. Constructing
    // `SigningState::Signed { signature_hex: "" }` here would expose the
    // forgery vector documented on the lineage `SigningState` enum:
    // verifiers matching `Signed { .. }` alone would treat an unsigned
    // anchor as authenticated.
    match anchor.signing {
        SigningState::UnsignedSignerStubbed { ref algorithm } => {
            assert_eq!(algorithm, "hybrid:ed25519+ml-dsa-65");
        }
        other => {
            panic!("signer hint without payload must produce UnsignedSignerStubbed, got {other:?}");
        }
    }
    assert!(!anchor.is_signed());
}

#[test]
fn verify_rejects_signed_state_with_empty_signature_payload() {
    // Regression: an attacker (or buggy producer) cannot forge an
    // authenticated-looking anchor by deserialising
    // `SigningState::Signed { signature_hex: "" }` over an otherwise
    // faithful proof. `verify_model_card_anchor` MUST fail-closed on the
    // empty-payload shape symmetrically with
    // `AnchoredFrontier::is_signed` over in `chio-lineage`.
    let card = good_card();
    let bytes = match card.to_canonical_json() {
        Ok(b) => b,
        Err(e) => panic!("encode: {e}"),
    };
    let attestation = attestation_for(&bytes);
    let verified = VerifiedModelCard {
        card,
        attestation: attestation.clone(),
    };
    let mut anchor = match anchor_model_card(&verified, &bytes, "chio.lineage.graph/v1", None) {
        Ok(a) => a,
        Err(e) => panic!("anchor: {e}"),
    };
    anchor.signing = SigningState::Signed {
        algorithm: "hybrid:ed25519+ml-dsa-65".to_string(),
        signature_hex: String::new(),
    };
    assert!(!anchor.is_signed());
    let res = verify_model_card_anchor(&anchor, &bytes, &attestation);
    assert!(matches!(
        res,
        Err(chio_weights::WeightsError::BundleRejected(_))
    ));
}

#[test]
fn verify_rejects_signed_state_with_malformed_signature_payloads() {
    let card = good_card();
    let bytes = match card.to_canonical_json() {
        Ok(b) => b,
        Err(e) => panic!("encode: {e}"),
    };
    let attestation = attestation_for(&bytes);
    let verified = VerifiedModelCard {
        card,
        attestation: attestation.clone(),
    };
    let mut anchor = match anchor_model_card(&verified, &bytes, "chio.lineage.graph/v1", None) {
        Ok(a) => a,
        Err(e) => panic!("anchor: {e}"),
    };

    for signature_hex in ["DEADBEEF", "dead beef", " deadbeef", "zz", "f"] {
        anchor.signing = SigningState::Signed {
            algorithm: "hybrid:ed25519+ml-dsa-65".to_string(),
            signature_hex: signature_hex.to_string(),
        };
        assert!(!anchor.is_signed());
        let res = verify_model_card_anchor(&anchor, &bytes, &attestation);
        assert!(
            matches!(res, Err(chio_weights::WeightsError::BundleRejected(_))),
            "verifier must reject malformed signature payload {signature_hex:?}"
        );
    }
}

#[test]
fn verify_rejects_signed_state_with_unverified_hex_payload() {
    let card = good_card();
    let bytes = match card.to_canonical_json() {
        Ok(b) => b,
        Err(e) => panic!("encode: {e}"),
    };
    let attestation = attestation_for(&bytes);
    let verified = VerifiedModelCard {
        card,
        attestation: attestation.clone(),
    };
    let mut anchor = match anchor_model_card(&verified, &bytes, "chio.lineage.graph/v1", None) {
        Ok(a) => a,
        Err(e) => panic!("anchor: {e}"),
    };
    anchor.signing = SigningState::Signed {
        algorithm: "hybrid:ed25519+ml-dsa-65".to_string(),
        signature_hex: "deadbeef".to_string(),
    };

    assert!(!anchor.is_signed());
    let res = verify_model_card_anchor(&anchor, &bytes, &attestation);
    assert!(
        matches!(res, Err(chio_weights::WeightsError::BundleRejected(_))),
        "verifier must reject unverified signature payloads"
    );
}

#[test]
fn anchor_artifact_serialises_through_serde_json_round_trip() {
    let card = good_card();
    let bytes = match card.to_canonical_json() {
        Ok(b) => b,
        Err(e) => panic!("encode: {e}"),
    };
    let attestation = attestation_for(&bytes);
    let verified = VerifiedModelCard {
        card,
        attestation: attestation.clone(),
    };
    let anchor = match anchor_model_card(&verified, &bytes, "chio.lineage.graph/v1", None) {
        Ok(a) => a,
        Err(e) => panic!("anchor: {e}"),
    };
    let json = match serde_json::to_vec(&anchor) {
        Ok(v) => v,
        Err(e) => panic!("serialize: {e}"),
    };
    let decoded: ModelCardLineageAnchor = match serde_json::from_slice(&json) {
        Ok(v) => v,
        Err(e) => panic!("deserialize: {e}"),
    };
    assert_eq!(decoded, anchor);
    match verify_model_card_anchor(&decoded, &bytes, &attestation) {
        Ok(()) => {}
        Err(e) => panic!("verify on round-tripped anchor: {e}"),
    }
}

#[test]
fn anchor_verifier_rejects_byte_tampered_card() {
    let card = good_card();
    let mut bytes = match card.to_canonical_json() {
        Ok(b) => b,
        Err(e) => panic!("encode: {e}"),
    };
    let attestation = attestation_for(&bytes);
    let verified = VerifiedModelCard {
        card,
        attestation: attestation.clone(),
    };
    let anchor = match anchor_model_card(&verified, &bytes, "chio.lineage.graph/v1", None) {
        Ok(a) => a,
        Err(e) => panic!("anchor: {e}"),
    };
    // Flip a byte in the card.
    if let Some(b) = bytes.last_mut() {
        *b ^= 0x01;
    }
    let res = verify_model_card_anchor(&anchor, &bytes, &attestation);
    assert!(res.is_err(), "verifier must reject tampered card bytes");
}
