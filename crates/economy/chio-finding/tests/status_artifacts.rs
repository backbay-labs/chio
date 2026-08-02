//! Signed status-epoch and portable sparse-proof qualification tests.

use std::error::Error;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_finding::{
    build_status_inclusion_proof_input, build_status_non_inclusion_proof_input,
    compute_status_epoch_id, parse_signed_status_epoch, parse_status_proof_input,
    status_epoch_envelope_sha256, verify_signed_status_epoch, verify_status_proof_input,
    FindingAuthorityKeyPolicy, FindingStatusEpoch, FindingStatusFreshnessPolicy,
    FindingStatusOperatorAuthorization, FindingStatusOperatorRole, FindingStatusProofInput,
    FINDING_STATUS_EPOCH_SCHEMA_V1, FINDING_STATUS_SIGNATURE_DOMAIN,
};
use chio_revocation_oracle::{
    finding_status_empty_leaf_hash, FindingStatusSparseMap, FINDING_STATUS_BRANCH_DOMAIN,
    FINDING_STATUS_EMPTY_LEAF_DOMAIN, FINDING_STATUS_HASH_ALGORITHM,
    FINDING_STATUS_KEY_DOMAIN_NONCE, FINDING_STATUS_KEY_HASH_DOMAIN, FINDING_STATUS_MAP_VERSION,
    FINDING_STATUS_OCCUPIED_LEAF_DOMAIN, FINDING_STATUS_PROOF_SEMANTICS,
    FINDING_STATUS_SPARSE_DEPTH,
};
use serde_json::Value;

type TestResult = Result<(), Box<dyn Error>>;

const FINDING_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FINDING_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const INTENT_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const ROOT_GENERATED_AT: u64 = 1_700_000_100;
const PROOF_CHECKED_AT: u64 = 1_700_000_110;

fn operator() -> Keypair {
    Keypair::from_seed(&[42_u8; 32])
}

fn authorization(keypair: &Keypair) -> FindingStatusOperatorAuthorization {
    FindingStatusOperatorAuthorization {
        role: FindingStatusOperatorRole::FindingStatusOperator,
        feed_id: "venue-status-feed".to_string(),
        operator: FindingAuthorityKeyPolicy {
            authority_id: "venue-status-operator".to_string(),
            key: keypair.public_key(),
            key_epoch: 7,
            valid_from: 1_700_000_000,
            valid_until: 1_800_000_000,
            rotation_policy_ref: "rotation/status-feed-v1".to_string(),
            revocation_status_ref: "revocations/status-feed".to_string(),
        },
        revoked_from: None,
    }
}

fn signed_epoch(
    keypair: &Keypair,
    root: chio_revocation_oracle::FindingStatusSparseRoot,
) -> Result<chio_finding::SignedFindingStatusEpoch, chio_finding::FindingError> {
    let mut body = FindingStatusEpoch {
        schema: FINDING_STATUS_EPOCH_SCHEMA_V1.to_string(),
        status_epoch_id: String::new(),
        signature_domain: FINDING_STATUS_SIGNATURE_DOMAIN.to_string(),
        status_map_version: FINDING_STATUS_MAP_VERSION.to_string(),
        proof_semantics: FINDING_STATUS_PROOF_SEMANTICS.to_string(),
        feed_id: "venue-status-feed".to_string(),
        key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
        map_epoch: root.map_epoch,
        operator_id: "venue-status-operator".to_string(),
        operator_key: keypair.public_key(),
        operator_key_epoch: 7,
        root_hash: hex::encode(root.root_hash),
        tree_depth: FINDING_STATUS_SPARSE_DEPTH as u16,
        hash_algorithm: FINDING_STATUS_HASH_ALGORITHM.to_string(),
        key_hash_domain: FINDING_STATUS_KEY_HASH_DOMAIN.to_string(),
        empty_leaf_domain: FINDING_STATUS_EMPTY_LEAF_DOMAIN.to_string(),
        occupied_leaf_domain: FINDING_STATUS_OCCUPIED_LEAF_DOMAIN.to_string(),
        branch_domain: FINDING_STATUS_BRANCH_DOMAIN.to_string(),
        empty_leaf_hash: hex::encode(finding_status_empty_leaf_hash()),
        anchor_refs: vec!["anchor/status-feed/1".to_string()],
        generated_at: ROOT_GENERATED_AT,
        valid_from: 1_700_000_000,
        valid_until: 1_700_000_300,
    };
    body.status_epoch_id = compute_status_epoch_id(&body)?;
    SignedExportEnvelope::sign(body, keypair).map_err(|_| chio_finding::FindingError::Signing)
}

fn inclusion_fixture() -> Result<
    (
        FindingStatusProofInput,
        FindingStatusOperatorAuthorization,
        chio_finding::SignedFindingStatusEpoch,
    ),
    chio_finding::FindingError,
> {
    let keypair = operator();
    let authorization = authorization(&keypair);
    let mut map = FindingStatusSparseMap::new();
    let root = map
        .insert(FINDING_A, INTENT_A)
        .map_err(|_| chio_finding::FindingError::InvalidField("test.root"))?;
    let sparse = map
        .proof(FINDING_A)
        .map_err(|_| chio_finding::FindingError::InvalidField("test.proof"))?;
    let signed = signed_epoch(&keypair, root)?;
    let proof = build_status_inclusion_proof_input(
        &signed,
        FINDING_A,
        INTENT_A,
        &sparse,
        PROOF_CHECKED_AT,
    )?;
    Ok((proof, authorization, signed))
}

fn non_inclusion_fixture() -> Result<
    (
        FindingStatusProofInput,
        FindingStatusOperatorAuthorization,
        chio_finding::SignedFindingStatusEpoch,
    ),
    chio_finding::FindingError,
> {
    let keypair = operator();
    let authorization = authorization(&keypair);
    let mut map = FindingStatusSparseMap::new();
    let root = map
        .insert(FINDING_A, INTENT_A)
        .map_err(|_| chio_finding::FindingError::InvalidField("test.root"))?;
    let sparse = map
        .proof(FINDING_B)
        .map_err(|_| chio_finding::FindingError::InvalidField("test.proof"))?;
    let signed = signed_epoch(&keypair, root)?;
    let proof =
        build_status_non_inclusion_proof_input(&signed, FINDING_B, &sparse, PROOF_CHECKED_AT)?;
    Ok((proof, authorization, signed))
}

fn freshness() -> FindingStatusFreshnessPolicy {
    FindingStatusFreshnessPolicy {
        now: PROOF_CHECKED_AT,
        max_epoch_age_secs: 60,
    }
}

fn status_schema_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-finding/v1")
        .join(format!("{name}.schema.json"))
}

fn validate_schema(name: &str, value: &Value) -> Result<(), chio_spec_validate::ValidateError> {
    let path = status_schema_path(name);
    let schema = chio_spec_validate::load_json(&path)?;
    chio_spec_validate::validate_value(&path, &schema, &path, value)
}

#[test]
fn signed_epoch_and_both_portable_branches_verify() -> TestResult {
    let (inclusion, auth, signed) = inclusion_fixture()?;
    verify_signed_status_epoch(&signed, &auth)?;
    let canonical = chio_core_types::canonical_json_bytes(&signed)?;
    assert_eq!(parse_signed_status_epoch(&canonical)?, signed);
    assert_eq!(
        verify_status_proof_input(&inclusion, &auth, freshness())?,
        signed
    );

    let (non_inclusion, auth, signed) = non_inclusion_fixture()?;
    assert_eq!(
        verify_status_proof_input(&non_inclusion, &auth, freshness())?,
        signed
    );
    Ok(())
}

#[test]
fn status_epoch_numeric_identifiers_are_nonzero_i_json_integers() -> TestResult {
    let (_, _, signed) = inclusion_fixture()?;

    let mut zero_epoch = signed.body.clone();
    zero_epoch.map_epoch = 0;
    assert!(zero_epoch.validate().is_err());

    let mut oversized_key_epoch = signed.body;
    oversized_key_epoch.operator_key_epoch = 1_u64 << 53;
    assert!(oversized_key_epoch.validate().is_err());
    Ok(())
}

#[test]
fn status_epoch_schema_accepts_zero_valid_from_like_the_runtime() -> TestResult {
    let (_, mut auth, signed) = inclusion_fixture()?;
    let keypair = operator();
    let mut body = signed.body;
    body.valid_from = 0;
    body.status_epoch_id = compute_status_epoch_id(&body)?;
    let genesis_epoch = SignedExportEnvelope::sign(body, &keypair)?;
    auth.operator.valid_from = 0;

    verify_signed_status_epoch(&genesis_epoch, &auth)?;
    validate_schema("status-epoch", &serde_json::to_value(genesis_epoch)?)?;
    Ok(())
}

#[test]
fn exact_canonical_proof_bytes_round_trip() -> TestResult {
    let (proof, _, _) = inclusion_fixture()?;
    let canonical = chio_core_types::canonical_json_bytes(&proof)?;
    assert_eq!(parse_status_proof_input(&canonical)?, proof);

    let pretty = serde_json::to_string_pretty(&proof)?;
    assert!(parse_status_proof_input(pretty.as_bytes()).is_err());

    let canonical_text = String::from_utf8(canonical)?;
    let duplicate = canonical_text.replacen(
        "\"feed_id\":\"venue-status-feed\"",
        "\"feed_id\":\"venue-status-feed\",\"feed_id\":\"venue-status-feed\"",
        1,
    );
    assert!(parse_status_proof_input(duplicate.as_bytes()).is_err());
    Ok(())
}

#[test]
fn epoch_version_domain_and_ordinary_root_substitution_reject() -> TestResult {
    let (_, auth, signed) = inclusion_fixture()?;
    let keypair = operator();
    for field in ["schema", "domain", "map", "proof", "hash", "empty"] {
        let mut body = signed.body.clone();
        match field {
            "schema" => body.schema = "chio.revocation.epoch-root.v1".to_string(),
            "domain" => body.signature_domain = "chio-revocation-oracle:v1".to_string(),
            "map" => body.status_map_version = "append_only_v1".to_string(),
            "proof" => body.proof_semantics = "ordinary_merkle_v1".to_string(),
            "hash" => body.branch_domain = "chio.revocation.branch".to_string(),
            "empty" => body.empty_leaf_hash = "00".repeat(32),
            _ => return Err(std::io::Error::other("unknown mutation").into()),
        }
        body.status_epoch_id = compute_status_epoch_id(&body)?;
        let altered = SignedExportEnvelope::sign(body, &keypair)?;
        assert!(
            verify_signed_status_epoch(&altered, &auth).is_err(),
            "mutation must reject: {field}"
        );
    }
    Ok(())
}

#[test]
fn operator_role_key_epoch_validity_and_revocation_are_pinned() -> TestResult {
    let (_, auth, signed) = inclusion_fixture()?;

    let mut wrong_feed = auth.clone();
    wrong_feed.feed_id = "other-feed".to_string();
    assert!(verify_signed_status_epoch(&signed, &wrong_feed).is_err());

    let mut wrong_key = auth.clone();
    wrong_key.operator.key = Keypair::from_seed(&[9_u8; 32]).public_key();
    assert!(verify_signed_status_epoch(&signed, &wrong_key).is_err());

    let mut wrong_epoch = auth.clone();
    wrong_epoch.operator.key_epoch += 1;
    assert!(verify_signed_status_epoch(&signed, &wrong_epoch).is_err());

    let mut expired = auth.clone();
    expired.operator.valid_until = ROOT_GENERATED_AT;
    assert!(verify_signed_status_epoch(&signed, &expired).is_err());

    let mut revoked = auth;
    revoked.revoked_from = Some(ROOT_GENERATED_AT);
    assert!(verify_signed_status_epoch(&signed, &revoked).is_err());
    Ok(())
}

#[test]
fn every_portable_cross_binding_and_freshness_mutation_rejects() -> TestResult {
    let (proof, auth, _) = inclusion_fixture()?;
    let mut cases = Vec::new();

    let mut changed = proof.clone();
    if let FindingStatusProofInput::Inclusion(value) = &mut changed {
        value.feed_id = "other-feed".to_string();
    }
    cases.push(changed);

    let mut changed = proof.clone();
    if let FindingStatusProofInput::Inclusion(value) = &mut changed {
        value.key_domain_nonce -= 1;
    }
    cases.push(changed);

    let mut changed = proof.clone();
    if let FindingStatusProofInput::Inclusion(value) = &mut changed {
        value.map_epoch += 1;
    }
    cases.push(changed);

    let mut changed = proof.clone();
    if let FindingStatusProofInput::Inclusion(value) = &mut changed {
        value.finding_id = FINDING_B.to_string();
    }
    cases.push(changed);

    let mut changed = proof.clone();
    if let FindingStatusProofInput::Inclusion(value) = &mut changed {
        value.status_epoch_id = "22".repeat(32);
    }
    cases.push(changed);

    let mut changed = proof.clone();
    if let FindingStatusProofInput::Inclusion(value) = &mut changed {
        value.status_epoch_sha256 = "33".repeat(32);
    }
    cases.push(changed);

    let mut changed = proof.clone();
    if let FindingStatusProofInput::Inclusion(value) = &mut changed {
        value.root_hash = "44".repeat(32);
    }
    cases.push(changed);

    let mut changed = proof.clone();
    if let FindingStatusProofInput::Inclusion(value) = &mut changed {
        value.siblings[100] = "55".repeat(32);
    }
    cases.push(changed);

    let mut changed = proof.clone();
    if let FindingStatusProofInput::Inclusion(value) = &mut changed {
        value.retraction_intent_sha256 = "66".repeat(32);
    }
    cases.push(changed);

    let mut changed = proof;
    if let FindingStatusProofInput::Inclusion(value) = &mut changed {
        value.checked_at = ROOT_GENERATED_AT - 1;
    }
    cases.push(changed);

    for (index, changed) in cases.iter().enumerate() {
        assert!(
            verify_status_proof_input(changed, &auth, freshness()).is_err(),
            "cross-binding mutation {index} must reject"
        );
    }
    Ok(())
}

#[test]
fn exact_epoch_bytes_and_signature_cannot_be_substituted() -> TestResult {
    let (mut proof, auth, signed) = inclusion_fixture()?;
    let pretty = serde_json::to_string_pretty(&signed)?;
    if let FindingStatusProofInput::Inclusion(value) = &mut proof {
        value.signed_status_epoch_b64 = STANDARD.encode(pretty.as_bytes());
    }
    assert!(verify_status_proof_input(&proof, &auth, freshness()).is_err());

    let (mut proof, auth, signed) = inclusion_fixture()?;
    let wrong_signed = SignedExportEnvelope::sign(signed.body, &Keypair::from_seed(&[8_u8; 32]))?;
    if let FindingStatusProofInput::Inclusion(value) = &mut proof {
        let raw = chio_core_types::canonical_json_bytes(&wrong_signed)?;
        value.signed_status_epoch_b64 = STANDARD.encode(raw);
        value.status_epoch_sha256 = status_epoch_envelope_sha256(&wrong_signed)?;
    }
    assert!(verify_status_proof_input(&proof, &auth, freshness()).is_err());
    Ok(())
}

#[test]
fn stale_future_and_revoked_at_verification_time_reject() -> TestResult {
    let (proof, auth, _) = inclusion_fixture()?;
    assert!(verify_status_proof_input(
        &proof,
        &auth,
        FindingStatusFreshnessPolicy {
            now: PROOF_CHECKED_AT + 120,
            max_epoch_age_secs: 60,
        },
    )
    .is_err());
    assert!(verify_status_proof_input(
        &proof,
        &auth,
        FindingStatusFreshnessPolicy {
            now: PROOF_CHECKED_AT - 1,
            max_epoch_age_secs: 60,
        },
    )
    .is_err());

    let mut revoked = auth;
    revoked.revoked_from = Some(PROOF_CHECKED_AT);
    assert!(verify_status_proof_input(&proof, &revoked, freshness()).is_err());
    Ok(())
}

#[test]
fn schemas_accept_both_branches_and_reject_cross_branch_fields() -> TestResult {
    let (inclusion, _, signed) = inclusion_fixture()?;
    let (non_inclusion, _, _) = non_inclusion_fixture()?;
    validate_schema("status-epoch", &serde_json::to_value(signed)?)?;
    validate_schema("status-proof-input", &serde_json::to_value(&inclusion)?)?;
    validate_schema("status-proof-input", &serde_json::to_value(&non_inclusion)?)?;

    let mut invalid = serde_json::to_value(non_inclusion)?;
    let object = invalid
        .as_object_mut()
        .ok_or_else(|| std::io::Error::other("proof fixture must be an object"))?;
    object.insert("status".to_string(), Value::String("retracted".to_string()));
    object.insert(
        "retraction_intent_sha256".to_string(),
        Value::String(INTENT_A.to_string()),
    );
    assert!(validate_schema("status-proof-input", &invalid).is_err());

    let canonical = chio_core_types::canonical_json_bytes(&invalid)?;
    assert!(parse_status_proof_input(&canonical).is_err());
    Ok(())
}

#[test]
fn deterministic_hash_and_artifact_goldens_are_stable() -> TestResult {
    let (proof, _, signed) = inclusion_fixture()?;
    let mut map = FindingStatusSparseMap::new();
    let root = map.insert(FINDING_A, INTENT_A)?;

    assert_eq!(
        hex::encode(finding_status_empty_leaf_hash()),
        "80a7fe55f5efd9a02893aca68310d8ebd7f0ed7b8dd36686abda7704755a6755"
    );
    assert_eq!(
        hex::encode(root.root_hash),
        "3e32c22164772a7ffbba979dcf5e18dd13406f2bd278780dbcd4a4d76a4463a3"
    );
    assert_eq!(
        signed.body.status_epoch_id,
        "eca2a86d5aca4b0c979a2f2a46ed0461992906e79a2973f5fac76fbc3d450813"
    );
    assert_eq!(
        status_epoch_envelope_sha256(&signed)?,
        "2819276f1c2685967126990479a11cd750607cde326980f7d82e7caa655d5fe0"
    );
    assert_eq!(
        proof.canonical_sha256()?,
        "4d72c95deb875662cc81e1916295eb9318677ce585b7be1296d606e8e11fae75"
    );
    Ok(())
}
