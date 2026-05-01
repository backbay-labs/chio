//! Integration test: model card lineage anchor proof (M10 P5.T1).
//!
//! Asserts the published-card lineage anchor produced by
//! [`chio_weights::anchor_model_card`] verifies through the model-card
//! anchor surface and degrades cleanly when M03 hybrid signing is absent.
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
    match anchor.signing {
        SigningState::Signed { algorithm, .. } => {
            assert_eq!(algorithm, "hybrid:ed25519+ml-dsa-65");
        }
        SigningState::UnsignedSoftDepAbsent => {
            panic!("signer hint must produce signed state");
        }
    }
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
