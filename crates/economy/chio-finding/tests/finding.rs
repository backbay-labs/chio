//! Integration coverage for the finding artifact family.

use std::error::Error;
use std::path::PathBuf;

use chio_core_types::capability::runtime_attestation::RuntimeAssuranceTier;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::{canonical_json_bytes, canonical_json_bytes_from_str};
use chio_finding::{
    compute_finding_id,
    crypto::{Keypair, PublicKey},
    Finding, FindingDescriptor, FindingError, FindingEvidenceClass, FindingGuaranteeClass,
    FindingOutcomeClass, FINDING_SCHEMA_V1, MAX_FINDING_EVIDENCE_RECEIPTS,
    MAX_FINDING_IDENTIFIER_BYTES, MAX_FINDING_TEXT_BYTES,
};
use chio_finding::{sign_finding, verify_finding, verify_finding_signature};
use serde_json::{json, Value};

const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;
const GOLDEN_FIXTURE_RAW: &str =
    include_str!("../../../../fixtures/proof-room/finding/verified-fix-basic/finding.json");

type TestResult = Result<(), Box<dyn Error>>;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../fixtures/proof-room/finding/verified-fix-basic/finding.json")
}

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-finding/v1/finding.schema.json")
}

fn validate_finding_schema(value: &Value) -> Result<(), chio_spec_validate::ValidateError> {
    let path = schema_path();
    let schema = chio_spec_validate::load_json(&path)?;
    chio_spec_validate::validate_value(&path, &schema, &fixture_path(), value)
}

fn assert_finding_schema_rejects(value: &Value, case: &str) -> TestResult {
    match validate_finding_schema(value) {
        Err(chio_spec_validate::ValidateError::SchemaViolation(_, _, _)) => Ok(()),
        Err(err) => Err(err.into()),
        Ok(()) => Err(std::io::Error::other(format!(
            "finding schema accepted invalid case: {case}"
        ))
        .into()),
    }
}

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
    recompute_finding_id(&mut finding);
    finding
}

fn assert_size_limit(issuer: &Keypair, field: &'static str, mutate: impl FnOnce(&mut Finding)) {
    let mut finding = base_finding(issuer);
    mutate(&mut finding);
    recompute_finding_id(&mut finding);
    assert_eq!(
        finding.validate(),
        Err(FindingError::SizeLimitExceeded(field))
    );
}

fn signed_asserted_finding_without_receipts() -> Result<Finding, FindingError> {
    let issuer = Keypair::from_seed(&[10_u8; 32]);
    let mut finding = draft_finding_with_issuer(issuer.public_key());
    finding.guarantee_class = FindingGuaranteeClass::Asserted;
    finding.evidence_class = FindingEvidenceClass::Asserted;
    finding.runtime_assurance_tier = None;
    finding.evidence_receipt_ids.clear();
    finding.replay_recipe_sha256 = None;
    finding.finding_id = compute_finding_id(&finding)?;
    sign_finding(finding, &issuer)
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
        Err(FindingError::FindingIdMismatch)
    ));
}

#[test]
fn malformed_payload_digest_is_rejected() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    draft.payload_sha256 = "not-hex".to_string();
    recompute_finding_id(&mut draft);
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
    recompute_finding_id(&mut draft);
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
    recompute_finding_id(&mut draft);
    assert!(draft.validate().is_err());
}

#[test]
fn invalid_currency_is_rejected() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    draft.evidence_cost.currency = "usd".to_string();
    recompute_finding_id(&mut draft);
    assert!(matches!(
        draft.validate(),
        Err(FindingError::InvalidCurrency(_))
    ));
}

#[test]
fn non_asserted_evidence_requires_receipts() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    draft.evidence_receipt_ids.clear();
    recompute_finding_id(&mut draft);
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
    recompute_finding_id(&mut draft);
    assert!(matches!(
        draft.validate(),
        Err(FindingError::EmptyField("evidence_receipt_ids[]"))
    ));
}

#[test]
fn duplicate_evidence_receipt_ids_are_rejected() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    draft.evidence_receipt_ids = vec!["r-1".to_string(), "r-1".to_string()];
    recompute_finding_id(&mut draft);
    assert!(matches!(
        draft.validate(),
        Err(FindingError::DuplicateEvidenceReceiptId)
    ));
}

#[test]
fn oversized_finding_fields_are_rejected() {
    let issuer = Keypair::generate();
    let oversized_id = "r".repeat(MAX_FINDING_IDENTIFIER_BYTES + 1);
    let oversized_text = "t".repeat(MAX_FINDING_TEXT_BYTES + 1);

    assert_size_limit(&issuer, "descriptor.topic", |finding| {
        finding.descriptor.topic = oversized_text.clone();
    });
    assert_size_limit(&issuer, "payload_media_type", |finding| {
        finding.payload_media_type = oversized_text;
    });
    assert_size_limit(&issuer, "evidence_checkpoint_ref", |finding| {
        finding.evidence_checkpoint_ref = oversized_id.clone();
    });
    assert_size_limit(&issuer, "evidence_receipt_ids[]", |finding| {
        finding.evidence_receipt_ids = vec![oversized_id.clone()];
    });
    assert_size_limit(&issuer, "intent_commitment_receipt_id", |finding| {
        finding.intent_commitment_receipt_id = Some(oversized_id.clone());
    });
    assert_size_limit(&issuer, "bond_ref", |finding| {
        finding.bond_ref = oversized_id.clone();
    });
    assert_size_limit(&issuer, "status_feed_ref", |finding| {
        finding.status_feed_ref = oversized_id.clone();
    });
    assert_size_limit(&issuer, "license_ref", |finding| {
        finding.license_ref = Some(oversized_id.clone());
    });
    assert_size_limit(&issuer, "price_hint_ref", |finding| {
        finding.price_hint_ref = Some(oversized_id);
    });
    assert_size_limit(&issuer, "evidence_receipt_ids", |finding| {
        finding.evidence_receipt_ids = (0..=MAX_FINDING_EVIDENCE_RECEIPTS)
            .map(|index| format!("receipt-{index}"))
            .collect();
    });
}

#[test]
fn attested_guarantee_requires_receipts_even_with_asserted_evidence_class() {
    let issuer = Keypair::generate();
    let mut draft = draft_finding_with_issuer(issuer.public_key());
    draft.guarantee_class = FindingGuaranteeClass::MeteredAttested;
    draft.evidence_class = FindingEvidenceClass::Asserted;
    draft.evidence_receipt_ids.clear();
    recompute_finding_id(&mut draft);
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
    recompute_finding_id(&mut draft);
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
    recompute_finding_id(&mut draft);
    assert!(matches!(
        draft.validate(),
        Err(FindingError::EmptyField("intent_commitment_receipt_id"))
    ));
}

#[test]
fn unknown_json_fields_are_rejected() {
    let issuer = Keypair::generate();
    let mut value = match serde_json::to_value(base_finding(&issuer)) {
        Ok(value) => value,
        Err(err) => panic!("finding serialization failed: {err}"),
    };
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
fn weak_identity_issuer_cannot_forge_a_finding() {
    // The compressed Edwards identity is a weak, low-order public key.
    // With loose Ed25519 verification, R=identity and S=0 verifies for
    // almost every message without possession of a private key.
    let issuer_hex = format!("01{}", "00".repeat(31));
    let issuer = match PublicKey::from_hex(&issuer_hex) {
        Ok(issuer) => issuer,
        Err(err) => panic!("weak Ed25519 test key construction failed: {err}"),
    };
    let mut finding = draft_finding_with_issuer(issuer);
    recompute_finding_id(&mut finding);
    finding.signature = format!("01{}", "00".repeat(63));

    assert!(matches!(
        verify_finding(&finding),
        Err(FindingError::WeakIssuerKey)
    ));
}

#[test]
fn signing_rejects_stale_finding_id() {
    let issuer = Keypair::generate();
    let mut finding = base_finding(&issuer);
    finding.descriptor.topic = "repo:backbay/chio#different-question".to_string();
    assert!(matches!(
        sign_finding(finding, &issuer),
        Err(FindingError::FindingIdMismatch)
    ));
}

#[test]
fn golden_verified_fix_fixture_validates() -> TestResult {
    let strict_canonical = canonical_json_bytes_from_str(GOLDEN_FIXTURE_RAW)?;
    let value: Value = serde_json::from_str(GOLDEN_FIXTURE_RAW)?;
    validate_finding_schema(&value)?;
    let finding: Finding = serde_json::from_str(GOLDEN_FIXTURE_RAW)?;
    assert_eq!(strict_canonical, canonical_json_bytes(&finding)?);
    verify_finding(&finding)?;
    Ok(())
}

#[test]
fn schema_rejects_integer_above_i_json_maximum() -> TestResult {
    let mut value = serde_json::to_value(signed_asserted_finding_without_receipts()?)?;
    value["evidence_cost"]["units"] = json!(I_JSON_MAX_SAFE_INTEGER + 1);
    assert_finding_schema_rejects(&value, "evidence_cost.units above I-JSON maximum")
}

#[test]
fn schema_rejects_runtime_assurance_none() -> TestResult {
    let mut value = serde_json::to_value(signed_asserted_finding_without_receipts()?)?;
    value["evidence_receipt_ids"] = json!(["r-1"]);
    value["runtime_assurance_tier"] = json!("none");
    assert_finding_schema_rejects(&value, "runtime_assurance_tier none")
}

#[test]
fn schema_rejects_prefixed_issuer() -> TestResult {
    let mut value = serde_json::to_value(signed_asserted_finding_without_receipts()?)?;
    let issuer = value
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| std::io::Error::other("serialized finding has no string issuer"))?
        .to_string();
    value["issuer"] = json!(format!("0x{issuer}"));
    assert_finding_schema_rejects(&value, "prefixed issuer")
}

#[test]
fn schema_rejects_explicit_null_for_optional_field() -> TestResult {
    let mut value = serde_json::to_value(signed_asserted_finding_without_receipts()?)?;
    value["evidence_receipt_ids"] = json!(["r-1"]);
    value["runtime_assurance_tier"] = Value::Null;
    assert_finding_schema_rejects(&value, "explicit null runtime_assurance_tier")
}

#[test]
fn schema_rejects_deterministic_replay_without_recipe() -> TestResult {
    let mut value = serde_json::to_value(signed_asserted_finding_without_receipts()?)?;
    value["evidence_receipt_ids"] = json!(["r-1"]);
    value["guarantee_class"] = json!("deterministic_replay");
    assert_finding_schema_rejects(&value, "deterministic replay without recipe")
}

#[test]
fn schema_rejects_invalid_currency() -> TestResult {
    let mut value = serde_json::to_value(signed_asserted_finding_without_receipts()?)?;
    value["evidence_cost"]["currency"] = json!("usd");
    assert_finding_schema_rejects(&value, "invalid ISO 4217 currency")
}

#[test]
fn schema_rejects_attested_guarantee_without_receipts() -> TestResult {
    let mut value = serde_json::to_value(signed_asserted_finding_without_receipts()?)?;
    value["guarantee_class"] = json!("metered_attested");
    assert_finding_schema_rejects(&value, "attested guarantee without receipts")
}

#[test]
fn schema_rejects_observed_evidence_without_receipts() -> TestResult {
    let mut value = serde_json::to_value(signed_asserted_finding_without_receipts()?)?;
    value["evidence_class"] = json!("observed");
    assert_finding_schema_rejects(&value, "observed evidence without receipts")
}

#[test]
fn schema_rejects_duplicate_evidence_receipts() -> TestResult {
    let finding = signed_asserted_finding_without_receipts()?;
    let mut value = serde_json::to_value(finding)?;
    value["evidence_receipt_ids"] = json!(["r-1", "r-1"]);
    assert_finding_schema_rejects(&value, "duplicate evidence receipt ids")
}

#[test]
fn schema_rejects_oversized_finding_fields() -> TestResult {
    let oversized_id = "r".repeat(MAX_FINDING_IDENTIFIER_BYTES + 1);
    let oversized_text = "t".repeat(MAX_FINDING_TEXT_BYTES + 1);

    let mut value = serde_json::to_value(signed_asserted_finding_without_receipts()?)?;
    value["descriptor"]["topic"] = json!(oversized_text.clone());
    assert_finding_schema_rejects(&value, "oversized descriptor topic")?;

    let mut value = serde_json::to_value(signed_asserted_finding_without_receipts()?)?;
    value["payload_media_type"] = json!(oversized_text);
    assert_finding_schema_rejects(&value, "oversized payload media type")?;

    for field in [
        "evidence_checkpoint_ref",
        "intent_commitment_receipt_id",
        "bond_ref",
        "status_feed_ref",
        "license_ref",
        "price_hint_ref",
    ] {
        let mut value = serde_json::to_value(signed_asserted_finding_without_receipts()?)?;
        value[field] = json!(oversized_id.clone());
        assert_finding_schema_rejects(&value, field)?;
    }

    let mut value = serde_json::to_value(signed_asserted_finding_without_receipts()?)?;
    value["evidence_receipt_ids"] = json!([oversized_id]);
    assert_finding_schema_rejects(&value, "oversized evidence receipt id")?;

    let mut value = serde_json::to_value(signed_asserted_finding_without_receipts()?)?;
    value["evidence_receipt_ids"] = json!((0..=MAX_FINDING_EVIDENCE_RECEIPTS)
        .map(|index| format!("receipt-{index}"))
        .collect::<Vec<_>>());
    assert_finding_schema_rejects(&value, "too many evidence receipt ids")
}

#[test]
fn schema_rejects_runtime_assurance_without_receipts() -> TestResult {
    let mut value = serde_json::to_value(signed_asserted_finding_without_receipts()?)?;
    value["runtime_assurance_tier"] = json!("basic");
    assert_finding_schema_rejects(&value, "runtime assurance without receipts")
}

#[test]
fn schema_accepts_fully_asserted_finding_without_receipts() -> TestResult {
    let finding = signed_asserted_finding_without_receipts()?;
    assert_eq!(finding.guarantee_class, FindingGuaranteeClass::Asserted);
    assert_eq!(finding.evidence_class, FindingEvidenceClass::Asserted);
    assert!(finding.runtime_assurance_tier.is_none());
    assert!(finding.evidence_receipt_ids.is_empty());
    validate_finding_schema(&serde_json::to_value(&finding)?)?;
    verify_finding(&finding)?;
    Ok(())
}

#[test]
#[ignore = "regenerates the deterministic golden fixture; run manually"]
fn regenerate_golden_fixture() -> TestResult {
    let issuer = Keypair::from_seed(&[9_u8; 32]);
    let mut finding = draft_finding_with_issuer(issuer.public_key());
    finding.finding_id = compute_finding_id(&finding)?;
    let finding = sign_finding(finding, &issuer)?;
    let json = serde_json::to_string_pretty(&finding)?;
    let path = fixture_path();
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("golden fixture path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    std::fs::write(path, format!("{json}\n"))?;
    Ok(())
}
