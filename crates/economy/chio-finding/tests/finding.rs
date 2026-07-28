//! Integration coverage for the finding artifact family.

use chio_core_types::capability::runtime_attestation::RuntimeAssuranceTier;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_finding::{
    compute_finding_id,
    crypto::{Keypair, PublicKey},
    Finding, FindingDescriptor, FindingError, FindingEvidenceClass, FindingGuaranteeClass,
    FindingOutcomeClass, FINDING_SCHEMA_V1,
};
use chio_finding::{sign_finding, verify_finding, verify_finding_signature};

const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

fn hex64(fill: char) -> String {
    std::iter::repeat_n(fill, 64).collect()
}

fn recompute_finding_id(finding: &mut Finding) {
    finding.finding_id = match compute_finding_id(finding) {
        Ok(finding_id) => finding_id,
        Err(err) => panic!("finding id computation failed: {err}"),
    };
}

/// Draft with an EMPTY finding_id; not yet valid.
fn draft_finding_with_issuer(issuer: PublicKey) -> Finding {
    Finding {
        schema: FINDING_SCHEMA_V1.to_string(),
        finding_id: String::new(),
        descriptor: FindingDescriptor {
            topic: "repo:backbay/chio#test-failure".to_string(),
            context_sha256: hex64('a'),
            outcome_class: FindingOutcomeClass::VerifiedFix,
        },
        guarantee_class: FindingGuaranteeClass::DeterministicReplay,
        payload_sha256: hex64('b'),
        payload_media_type: "text/x-diff".to_string(),
        evidence_receipt_ids: vec!["r-1".to_string()],
        evidence_checkpoint_ref: "ckpt-1".to_string(),
        evidence_cost: MonetaryAmount {
            units: 4_200,
            currency: "USD".to_string(),
        },
        runtime_assurance_tier: None,
        evidence_class: FindingEvidenceClass::Verified,
        replay_recipe_sha256: Some(hex64('c')),
        intent_commitment_receipt_id: None,
        bond_ref: "bond-req-1".to_string(),
        status_feed_ref: "finding-status/test".to_string(),
        license_ref: None,
        price_hint_ref: None,
        issuer,
        issued_at: 1_784_880_000,
        expires_at: 1_792_656_000,
        signature: String::new(),
    }
}

/// Fully constructed finding: draft plus its content-addressed id.
fn base_finding(issuer: &Keypair) -> Finding {
    let mut finding = draft_finding_with_issuer(issuer.public_key());
    finding.finding_id = compute_finding_id(&finding).unwrap_or_default();
    finding
}

#[test]
fn valid_finding_passes_validation() {
    let issuer = Keypair::generate();
    assert!(base_finding(&issuer).validate().is_ok());
}

#[test]
fn wrong_schema_is_rejected() {
    let issuer = Keypair::generate();
    let mut finding = base_finding(&issuer);
    finding.schema = "chio.finding.v999".to_string();
    assert!(matches!(
        finding.validate(),
        Err(FindingError::UnsupportedSchema(_))
    ));
}

#[test]
fn empty_finding_id_is_rejected() {
    let issuer = Keypair::generate();
    let draft = draft_finding_with_issuer(issuer.public_key());
    assert!(matches!(
        draft.validate(),
        Err(FindingError::MalformedDigest("finding_id"))
    ));
}

#[test]
fn stale_finding_id_is_rejected() {
    let issuer = Keypair::generate();
    let mut finding = base_finding(&issuer);
    finding.descriptor.topic = "repo:backbay/chio#other-topic".to_string();
    assert!(matches!(
        finding.validate(),
        Err(FindingError::MalformedDigest("finding_id"))
    ));
}

#[test]
fn malformed_payload_digest_is_rejected() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    draft.payload_sha256 = "not-hex".to_string();
    draft.finding_id = compute_finding_id(&draft).unwrap_or_default();
    assert!(matches!(
        draft.validate(),
        Err(FindingError::MalformedDigest("payload_sha256"))
    ));
}

#[test]
fn deterministic_replay_requires_recipe() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    draft.replay_recipe_sha256 = None;
    draft.finding_id = compute_finding_id(&draft).unwrap_or_default();
    assert!(matches!(
        draft.validate(),
        Err(FindingError::MissingReplayRecipe)
    ));
}

#[test]
fn expiry_must_follow_issuance() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    draft.expires_at = draft.issued_at;
    draft.finding_id = compute_finding_id(&draft).unwrap_or_default();
    assert!(draft.validate().is_err());
}

#[test]
fn non_asserted_evidence_requires_receipts() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    draft.evidence_receipt_ids.clear();
    draft.finding_id = compute_finding_id(&draft).unwrap_or_default();
    assert!(matches!(
        draft.validate(),
        Err(FindingError::MissingEvidence)
    ));
}

#[test]
fn blank_evidence_receipt_id_is_rejected() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    draft.evidence_receipt_ids = vec![String::new()];
    draft.finding_id = compute_finding_id(&draft).unwrap_or_default();
    assert!(matches!(
        draft.validate(),
        Err(FindingError::EmptyField("evidence_receipt_ids[]"))
    ));
}

#[test]
fn attested_guarantee_requires_receipts_even_with_asserted_evidence_class() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    draft.guarantee_class = FindingGuaranteeClass::MeteredAttested;
    draft.evidence_class = FindingEvidenceClass::Asserted;
    draft.evidence_receipt_ids.clear();
    draft.finding_id = compute_finding_id(&draft).unwrap_or_default();
    assert!(matches!(
        draft.validate(),
        Err(FindingError::MissingEvidence)
    ));
}

#[test]
fn non_none_runtime_tier_requires_receipts() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    // Fully asserted otherwise, but claiming Verified runtime with no
    // receipts is an unbacked attestation-quality signal.
    draft.guarantee_class = FindingGuaranteeClass::Asserted;
    draft.evidence_class = FindingEvidenceClass::Asserted;
    draft.runtime_assurance_tier = Some(RuntimeAssuranceTier::Verified);
    draft.evidence_receipt_ids.clear();
    draft.finding_id = compute_finding_id(&draft).unwrap_or_default();
    assert!(matches!(
        draft.validate(),
        Err(FindingError::MissingEvidence)
    ));
}

#[test]
fn blank_intent_commitment_reference_is_rejected() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    draft.intent_commitment_receipt_id = Some(String::new());
    draft.finding_id = compute_finding_id(&draft).unwrap_or_default();
    assert!(matches!(
        draft.validate(),
        Err(FindingError::EmptyField("intent_commitment_receipt_id"))
    ));
}

#[test]
fn unknown_json_fields_are_rejected() {
    let issuer = Keypair::generate();
    let mut value = serde_json::to_value(base_finding(&issuer)).unwrap_or_default();
    if let Some(map) = value.as_object_mut() {
        map.insert("surprise".to_string(), serde_json::Value::Bool(true));
    }
    assert!(serde_json::from_value::<Finding>(value).is_err());
}

#[test]
fn signed_finding_roundtrip_verifies() {
    let issuer = Keypair::generate();
    let finding = base_finding(&issuer);
    let signed = match sign_finding(finding, &issuer) {
        Ok(signed) => signed,
        Err(err) => panic!("signing failed: {err}"),
    };
    assert!(!signed.signature.is_empty());
    assert!(verify_finding_signature(&signed).is_ok());
    assert!(signed.validate().is_ok());
    assert!(verify_finding(&signed).is_ok());
}

#[test]
fn tampered_signed_finding_fails_verification() {
    let issuer = Keypair::generate();
    let mut signed = match sign_finding(base_finding(&issuer), &issuer) {
        Ok(signed) => signed,
        Err(err) => panic!("signing failed: {err}"),
    };
    signed.expires_at += 1;
    assert!(matches!(
        verify_finding_signature(&signed),
        Err(FindingError::SignatureInvalid)
    ));
}

#[test]
fn non_canonical_signature_encodings_are_rejected() {
    let issuer = Keypair::generate();
    let signed = match sign_finding(base_finding(&issuer), &issuer) {
        Ok(signed) => signed,
        Err(err) => panic!("signing failed: {err}"),
    };
    let mut uppercase = signed.clone();
    uppercase.signature = uppercase.signature.to_uppercase();
    assert!(matches!(
        verify_finding_signature(&uppercase),
        Err(FindingError::SignatureInvalid)
    ));
    let mut prefixed = signed;
    prefixed.signature = format!("0x{}", prefixed.signature);
    assert!(matches!(
        verify_finding_signature(&prefixed),
        Err(FindingError::SignatureInvalid)
    ));
}

#[test]
fn signing_requires_the_issuer_key() {
    let issuer = Keypair::generate();
    let other = Keypair::generate();
    assert!(matches!(
        sign_finding(base_finding(&issuer), &other),
        Err(FindingError::Signing)
    ));
}

#[test]
fn i_json_maximum_values_are_accepted() {
    let issuer = Keypair::generate();
    let mut finding = draft_finding_with_issuer(issuer.public_key());
    finding.evidence_cost.units = I_JSON_MAX_SAFE_INTEGER;
    finding.issued_at = I_JSON_MAX_SAFE_INTEGER - 1;
    finding.expires_at = I_JSON_MAX_SAFE_INTEGER;
    recompute_finding_id(&mut finding);
    assert!(finding.validate().is_ok());
}

#[test]
fn evidence_cost_above_i_json_maximum_is_rejected() {
    let issuer = Keypair::generate();
    let mut finding = draft_finding_with_issuer(issuer.public_key());
    finding.evidence_cost.units = I_JSON_MAX_SAFE_INTEGER + 1;
    recompute_finding_id(&mut finding);
    assert!(matches!(
        finding.validate(),
        Err(FindingError::IJsonIntegerOutOfRange("evidence_cost.units"))
    ));
}

#[test]
fn issued_at_above_i_json_maximum_is_rejected() {
    let issuer = Keypair::generate();
    let mut finding = draft_finding_with_issuer(issuer.public_key());
    finding.issued_at = I_JSON_MAX_SAFE_INTEGER + 1;
    finding.expires_at = I_JSON_MAX_SAFE_INTEGER + 2;
    recompute_finding_id(&mut finding);
    assert!(matches!(
        finding.validate(),
        Err(FindingError::IJsonIntegerOutOfRange("issued_at"))
    ));
}

#[test]
fn expires_at_above_i_json_maximum_is_rejected() {
    let issuer = Keypair::generate();
    let mut finding = draft_finding_with_issuer(issuer.public_key());
    finding.expires_at = I_JSON_MAX_SAFE_INTEGER + 1;
    recompute_finding_id(&mut finding);
    assert!(matches!(
        finding.validate(),
        Err(FindingError::IJsonIntegerOutOfRange("expires_at"))
    ));
}

#[test]
fn explicit_none_runtime_tier_is_rejected() {
    let issuer = Keypair::generate();
    let mut finding = draft_finding_with_issuer(issuer.public_key());
    finding.runtime_assurance_tier = Some(RuntimeAssuranceTier::None);
    recompute_finding_id(&mut finding);
    assert!(matches!(
        finding.validate(),
        Err(FindingError::NonCanonicalRuntimeAssuranceTier)
    ));
}

#[test]
fn non_ed25519_issuer_is_rejected() {
    let mut sec1 = [0_u8; 65];
    sec1[0] = 0x04;
    let issuer = match PublicKey::from_p256_sec1(&sec1) {
        Ok(issuer) => issuer,
        Err(err) => panic!("P-256 test key construction failed: {err}"),
    };
    let mut finding = draft_finding_with_issuer(issuer);
    recompute_finding_id(&mut finding);
    assert!(matches!(
        finding.validate(),
        Err(FindingError::UnsupportedIssuerAlgorithm)
    ));
}

#[test]
fn signing_rejects_stale_finding_id() {
    let issuer = Keypair::generate();
    let mut finding = base_finding(&issuer);
    finding.descriptor.topic = "repo:backbay/chio#different-question".to_string();
    assert!(matches!(
        sign_finding(finding, &issuer),
        Err(FindingError::MalformedDigest("finding_id"))
    ));
}
