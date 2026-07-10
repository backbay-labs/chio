#![cfg(feature = "bbs")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::{
    body::ChioReceiptBody, decision::Decision, decision::ToolCallAction, kinds::TrustLevel,
    signing::ReceiptSigningHandle,
};
use chio_selective_disclosure::{
    derive_selective_disclosure_proof, derive_selective_disclosure_proof_from_receipt,
    generate_bbs_keypair, project_receipt_body, project_step_record, project_workflow_receipt_body,
    receipt_signed_projection, sign_chio_receipt_with_bbs, sign_projection,
    verify_bbs_projection_manifest, verify_selective_disclosure_proof,
    verify_selective_disclosure_with_context, verify_signed_projection, BbsKeyPair,
    BbsProjectionHiddenPredicate, CryptoVerificationContext, DisclosureContextVerdict,
    DisclosureKeyState, DisclosureRevocationSnapshot, DisclosureSet,
    DisclosureVerifierPrivacyProfile, HolderBindingStatus, InMemoryIssuerRegistry, KeyStateStatus,
    NonceReplayStatus, RevocationSnapshotStatus, SelectiveDisclosureError,
    SelectiveDisclosureProof, TransparencyState, BBS_CIPHERSUITE_SHA256,
    PROJECTION_VERSION_RECEIPT_V1, PROJECTION_VERSION_STEP_V1, PROJECTION_VERSION_WORKFLOW_V1,
    SELECTIVE_DISCLOSURE_PROOF_SCHEMA_V1,
};
use chio_workflow::receipt::{
    StepOutcome, StepRecord, WorkflowOutcome, WorkflowReceiptBody, WORKFLOW_RECEIPT_SCHEMA,
};
use serde_json::Value;
use std::{fs, path::PathBuf};

fn receipt_fixture(kp: &Keypair) -> ChioReceiptBody {
    ChioReceiptBody {
        id: "rcpt-chio-bbs".to_string(),
        timestamp: 1_766_000_000,
        capability_id: "cap-chio-receipt".to_string(),
        tool_server: "vendor-a.files".to_string(),
        tool_name: "read_refund_case".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({
            "path": "/cases/refund-250.json"
        }))
        .expect("fixture action is valid"),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: sha256_hex(b"{\"refund_minor\":25000}"),
        policy_hash: sha256_hex(b"chio-policy"),
        evidence: Vec::new(),
        metadata: Some(serde_json::json!({"workflow_id": "wf-chio-refund-001"})),
        trust_level: TrustLevel::Mediated,
        tenant_id: Some("buyer-tenant".to_string()),
        kernel_key: kp.public_key(),
        bbs_projection_version: None,
    }
}

fn workflow_fixture(kp: &Keypair) -> WorkflowReceiptBody {
    WorkflowReceiptBody {
        id: "wf-chio-refund-001".to_string(),
        schema: WORKFLOW_RECEIPT_SCHEMA.to_string(),
        started_at: 1_766_000_000,
        completed_at: 1_766_000_042,
        skill_id: "refund-underwriting".to_string(),
        skill_version: "0.1.0".to_string(),
        agent_id: "buyer-agent".to_string(),
        session_id: Some("sess-chio-refund".to_string()),
        capability_id: "cap-chio-workflow".to_string(),
        outcome: WorkflowOutcome::Completed,
        steps: vec![
            StepRecord {
                step_index: 0,
                server_id: "vendor-a.files".to_string(),
                tool_name: "read_refund_case".to_string(),
                allowed: true,
                tool_receipt_id: Some("rcpt-a".to_string()),
                outcome: StepOutcome::Success,
                duration_ms: 12,
                cost: Some(MonetaryAmount {
                    units: 100,
                    currency: "USD".to_string(),
                }),
                output_hash: Some(sha256_hex(b"vendor-a-output")),
                bilateral_dsse_sha256: None,
                governance_receipt_id: None,
                parent_receipt_sha256: None,
                consistency_anchor: None,
                destructive: None,
            },
            StepRecord {
                step_index: 1,
                server_id: "vendor-b.kyc".to_string(),
                tool_name: "verify_customer".to_string(),
                allowed: true,
                tool_receipt_id: Some("rcpt-b".to_string()),
                outcome: StepOutcome::Success,
                duration_ms: 18,
                cost: Some(MonetaryAmount {
                    units: 200,
                    currency: "USD".to_string(),
                }),
                output_hash: Some(sha256_hex(b"vendor-b-output")),
                bilateral_dsse_sha256: None,
                governance_receipt_id: None,
                parent_receipt_sha256: None,
                consistency_anchor: None,
                destructive: None,
            },
            StepRecord {
                step_index: 2,
                server_id: "vendor-c.payments".to_string(),
                tool_name: "stage_refund".to_string(),
                allowed: true,
                tool_receipt_id: Some("rcpt-c".to_string()),
                outcome: StepOutcome::Success,
                duration_ms: 12,
                cost: Some(MonetaryAmount {
                    units: 250,
                    currency: "USD".to_string(),
                }),
                output_hash: Some(sha256_hex(b"vendor-c-output")),
                bilateral_dsse_sha256: None,
                governance_receipt_id: None,
                parent_receipt_sha256: None,
                consistency_anchor: None,
                destructive: None,
            },
        ],
        total_cost: Some(MonetaryAmount {
            units: 550,
            currency: "USD".to_string(),
        }),
        duration_ms: 42,
        kernel_key: kp.public_key(),
    }
}

fn registry_for_key(keypair: &chio_selective_disclosure::BbsKeyPair) -> InMemoryIssuerRegistry {
    let mut registry = InMemoryIssuerRegistry::default();
    registry.insert(
        keypair.issuer_fingerprint.clone(),
        keypair.public_key_hex.clone(),
    );
    registry
}

fn contextual_bbs_fixture() -> (SelectiveDisclosureProof, InMemoryIssuerRegistry, BbsKeyPair) {
    let ed25519 = Keypair::generate();
    let receipt = receipt_fixture(&ed25519);
    let projection = project_receipt_body(&receipt).expect("receipt projection succeeds");
    let keypair = generate_bbs_keypair(b"chio-bbs-context-key-material-0001", b"chio").unwrap();
    let signed = sign_projection(&projection, &keypair).expect("signing succeeds");
    let proof = derive_selective_disclosure_proof(
        &signed,
        &projection,
        &keypair,
        &DisclosureSet(vec![1, 5, 11]),
        b"auditor-session-nonce",
    )
    .expect("proof generation succeeds");
    let registry = registry_for_key(&keypair);
    (proof, registry, keypair)
}

fn context_profile(keypair: &BbsKeyPair) -> DisclosureVerifierPrivacyProfile {
    DisclosureVerifierPrivacyProfile {
        schema: "chio.disclosure.verifier-privacy-profile.v1".to_string(),
        profile_id: "profile-buyer-auditor-context".to_string(),
        allowed_proof_mechanisms: vec!["bbs".to_string()],
        required_holder_binding: Some("holder:buyer-agent".to_string()),
        transaction_passport_ref: "passport-bbs-context-valid".to_string(),
        leakage_budget: chio_selective_disclosure::DisclosureProfileLeakageBudget {
            max_disclosed_fields: 3,
            max_hidden_predicates: 1,
        },
        sensitivity_classes: vec![chio_selective_disclosure::DisclosureSensitivityClass {
            class_id: "operational".to_string(),
            fields: vec![
                "capability_id".to_string(),
                "tool_name".to_string(),
                "decision".to_string(),
            ],
        }],
        allowed_issuer_keys: vec![keypair.issuer_fingerprint.clone()],
        required_key_epoch_min: 7,
        forbidden_key_epochs: vec![9],
        required_status_freshness_seconds: 300,
        required_audience: "https://auditor.example/chio".to_string(),
        nonce_policy: "no_replay".to_string(),
        allowed_algorithms: vec!["bbs-bls12381-sha256".to_string()],
        forbidden_algorithms: vec!["rsa-pkcs1v15-sha1".to_string()],
        required_transparency_state: TransparencyState::Anchored,
        max_presentation_age_seconds: 600,
        allowed_disclosed_fields: vec![
            "capability_id".to_string(),
            "tool_name".to_string(),
            "decision".to_string(),
        ],
        forbidden_disclosed_fields: vec!["customer_email".to_string()],
        allowed_hidden_predicates: vec!["amount_lte_100".to_string()],
        forbidden_hidden_predicates: vec!["raw_amount".to_string()],
    }
}

fn crypto_context(
    proof: &SelectiveDisclosureProof,
    _keypair: &BbsKeyPair,
) -> CryptoVerificationContext {
    CryptoVerificationContext {
        schema: "chio.crypto.verification-context.v1".to_string(),
        context_id: "crypto-context-buyer-auditor".to_string(),
        artifact_ref: proof.subject_sha256_hex.clone(),
        proof_mechanism: "bbs".to_string(),
        issuer: "did:chio:issuer-bbs".to_string(),
        issuer_key_ref: proof.issuer_fingerprint.clone(),
        key_state: DisclosureKeyState {
            schema: "chio.trust.key-state.v1".to_string(),
            key_ref: proof.issuer_fingerprint.clone(),
            status: KeyStateStatus::Active,
            epoch: 7,
            valid_from: 1_766_000_000,
            valid_until: 1_766_000_900,
        },
        algorithm: "bbs-bls12381-sha256".to_string(),
        suite: BBS_CIPHERSUITE_SHA256.to_string(),
        hash_algorithm: "sha-256".to_string(),
        canonicalization: "jcs".to_string(),
        signature_ref: "bbs-proof".to_string(),
        verification_time: 1_766_000_100,
        revocation_snapshot: Some(DisclosureRevocationSnapshot {
            schema: "chio.trust.revocation-snapshot.v1".to_string(),
            snapshot_ref: "revocation-snapshot-buyer-auditor".to_string(),
            status: RevocationSnapshotStatus::Fresh,
            issued_at: 1_766_000_050,
            expires_at: 1_766_000_350,
        }),
        audience: "https://auditor.example/chio".to_string(),
        nonce_hex: proof.proof_nonce_hex.clone(),
        nonce_replay_status: NonceReplayStatus::Fresh,
        holder_binding_ref: Some("holder:buyer-agent".to_string()),
        holder_binding_status: HolderBindingStatus::Bound,
        transparency_state: TransparencyState::Anchored,
        presentation_created_at: 1_766_000_080,
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repo root")
}

fn schema_path(relative_path: &str) -> PathBuf {
    repo_root().join("spec/schemas").join(relative_path)
}

fn assert_attest_schema_accepts(relative_path: &str, instance: &Value) {
    assert_schema_accepts(&format!("chio-attest/v1/{relative_path}"), instance);
}

fn assert_schema_accepts(relative_path: &str, instance: &Value) {
    let schema_path = schema_path(relative_path);
    let contents = fs::read_to_string(&schema_path).expect("schema file exists");
    let schema: Value = serde_json::from_str(&contents).expect("schema parses as json");
    let base_uri = schema_path
        .parent()
        .expect("schema parent exists")
        .canonicalize()
        .expect("schema parent canonicalizes")
        .to_string_lossy()
        .replace('\\', "/");
    let base_uri = if base_uri.ends_with('/') {
        format!("file://{base_uri}")
    } else {
        format!("file://{base_uri}/")
    };
    let validator = jsonschema::options()
        .with_base_uri(base_uri)
        .build(&schema)
        .expect("schema compiles");
    if let Err(error) = validator.validate(instance) {
        let mut details = vec![error.to_string()];
        details.extend(
            validator
                .iter_errors(instance)
                .skip(1)
                .map(|entry| entry.to_string()),
        );
        panic!(
            "schema `{relative_path}` rejected instance:\ninstance={}\nerrors={}",
            serde_json::to_string_pretty(instance).expect("instance pretty prints"),
            details.join(" | ")
        );
    }
}

#[test]
fn receipt_projection_signs_and_proves_disclosed_fields_with_bbs_selective_disclosure() {
    let ed25519 = Keypair::generate();
    let receipt = receipt_fixture(&ed25519);
    let projection = project_receipt_body(&receipt).expect("receipt projection succeeds");
    assert_eq!(projection.version, PROJECTION_VERSION_RECEIPT_V1);

    let keypair = generate_bbs_keypair(b"chio-bbs-signing-key-material-0001", b"chio").unwrap();
    let signed = sign_projection(&projection, &keypair).expect("signing succeeds");
    assert!(
        verify_signed_projection(&signed, &projection).expect("signature verification runs"),
        "full projection signature should verify before a disclosure proof is derived"
    );

    let proof = derive_selective_disclosure_proof(
        &signed,
        &projection,
        &keypair,
        &DisclosureSet(vec![1, 5, 11]),
        b"auditor-session-nonce",
    )
    .expect("proof generation succeeds");
    assert_eq!(proof.schema, SELECTIVE_DISCLOSURE_PROOF_SCHEMA_V1);
    assert_eq!(proof.disclosed_indices, vec![1, 5, 11]);
    assert_eq!(
        proof
            .disclosed
            .iter()
            .map(|message| message.field.as_str())
            .collect::<Vec<_>>(),
        vec!["capability_id", "id", "tool_name"]
    );

    let verified = verify_selective_disclosure_proof(&proof, &registry_for_key(&keypair)).unwrap();
    assert_eq!(verified.subject_sha256_hex, projection.subject_sha256_hex);
    assert_eq!(verified.disclosed.len(), 3);
}

/// Exact byte preimage the receipt fixture's `content_hash` is defined over.
/// The WYSIWYS handle MUST be built over these bytes for signing to proceed.
const RECEIPT_FIXTURE_CONTENT_PREIMAGE: &[u8] = b"{\"refund_minor\":25000}";

#[test]
fn receipt_bound_bbs_signature_drives_selective_disclosure_proofs() {
    let ed25519 = Keypair::generate();
    let bbs_keypair = generate_bbs_keypair(b"chio-bbs-signing-key-material-0007", b"chio").unwrap();
    // Handle bound to the exact content the body's content_hash claims.
    let handle =
        ReceiptSigningHandle::from_content_preimage(RECEIPT_FIXTURE_CONTENT_PREIMAGE.to_vec());
    let receipt =
        sign_chio_receipt_with_bbs(receipt_fixture(&ed25519), &ed25519, &bbs_keypair, handle)
            .unwrap();
    assert!(receipt.verify_signature().unwrap());
    assert_eq!(
        receipt.body().bbs_projection_version.as_deref(),
        Some(PROJECTION_VERSION_RECEIPT_V1)
    );
    assert!(receipt.bbs_signature.is_some());

    let projection = project_receipt_body(&receipt.body()).expect("receipt projection succeeds");
    let signed = receipt_signed_projection(&receipt).expect("receipt BBS material is bound");
    assert_eq!(signed.projection_version, PROJECTION_VERSION_RECEIPT_V1);
    assert_eq!(signed.subject_sha256_hex, projection.subject_sha256_hex);
    assert!(
        verify_signed_projection(&signed, &projection).expect("receipt-bound signature verifies")
    );

    let proof = derive_selective_disclosure_proof_from_receipt(
        &receipt,
        &bbs_keypair,
        &DisclosureSet(vec![1, 5, 11]),
        b"auditor-session-nonce",
    )
    .expect("receipt-bound proof generation succeeds");
    let verified = verify_selective_disclosure_proof(&proof, &registry_for_key(&bbs_keypair))
        .expect("receipt-bound proof verifies");
    assert_eq!(verified.subject_sha256_hex, projection.subject_sha256_hex);
}

#[test]
fn bbs_signing_rejects_render_a_sign_b() {
    // Regression: the BBS / selective-disclosure signing path must enforce the
    // same WYSIWYS gate as the classical and backend signers. A body whose
    // content_hash claims the hash of content B while the producer renders
    // content A (the handle's bound content) MUST be refused before any BBS
    // material is produced.
    let ed25519 = Keypair::generate();
    let bbs_keypair = generate_bbs_keypair(b"chio-bbs-signing-key-material-0007", b"chio").unwrap();

    let content_a = b"{\"shown\":\"to-the-human\"}";
    let content_b = b"{\"secretly\":\"signed-instead\"}";

    // Body claims the hash of B; the handle is bound to A.
    let mut body = receipt_fixture(&ed25519);
    body.content_hash = sha256_hex(content_b);
    let handle = ReceiptSigningHandle::from_content_preimage(content_a.to_vec());

    let result = sign_chio_receipt_with_bbs(body, &ed25519, &bbs_keypair, handle);
    assert!(
        matches!(
            result,
            Err(SelectiveDisclosureError::ContentHashMismatch(_))
        ),
        "render-A/sign-B must be refused at the BBS signing boundary, got {result:?}"
    );
}

#[test]
fn bbs_signing_accepts_matching_content_hash() {
    // Positive counterpart: a body whose content_hash matches the handle's
    // bound canonical content is accepted and verifies.
    let ed25519 = Keypair::generate();
    let bbs_keypair = generate_bbs_keypair(b"chio-bbs-signing-key-material-0007", b"chio").unwrap();

    let content = b"{\"shown\":\"to-the-human\"}";
    let mut body = receipt_fixture(&ed25519);
    body.content_hash = sha256_hex(content);
    let handle = ReceiptSigningHandle::from_content_preimage(content.to_vec());

    let receipt = sign_chio_receipt_with_bbs(body, &ed25519, &bbs_keypair, handle)
        .expect("matching content+hash is accepted");
    assert!(receipt.verify_signature().unwrap());
    assert_eq!(receipt.content_hash, sha256_hex(content));
}

#[test]
fn projection_rejects_uppercase_sha256_digest_fields() {
    let ed25519 = Keypair::generate();
    let mut receipt = receipt_fixture(&ed25519);
    receipt.content_hash = receipt.content_hash.to_uppercase();

    assert!(matches!(
        project_receipt_body(&receipt),
        Err(SelectiveDisclosureError::MalformedHexField { field, .. }) if field == "content_hash"
    ));
}

#[test]
fn workflow_and_step_projections_have_stable_versions() {
    let ed25519 = Keypair::generate();
    let workflow = workflow_fixture(&ed25519);
    let workflow_projection =
        project_workflow_receipt_body(&workflow).expect("workflow projection succeeds");
    assert_eq!(workflow_projection.version, PROJECTION_VERSION_WORKFLOW_V1);
    assert!(workflow_projection
        .messages
        .iter()
        .any(|message| message.field == "steps" && message.wholesale_only));

    let step_projection = project_step_record("wf-chio-refund-001", &workflow.steps[2])
        .expect("step projection succeeds");
    assert_eq!(step_projection.version, PROJECTION_VERSION_STEP_V1);
    assert!(step_projection
        .messages
        .iter()
        .any(|message| message.field == "tool_name" && !message.wholesale_only));
}

#[test]
fn step_record_proof_validates_against_attest_schema() {
    let ed25519 = Keypair::generate();
    let workflow = workflow_fixture(&ed25519);
    let projection =
        project_step_record("wf-chio-refund-001", &workflow.steps[2]).expect("step projection");
    assert_eq!(projection.version, PROJECTION_VERSION_STEP_V1);

    let keypair = generate_bbs_keypair(b"chio-bbs-signing-key-material-step", b"chio").unwrap();
    let signed = sign_projection(&projection, &keypair).expect("step signing succeeds");
    assert!(verify_signed_projection(&signed, &projection).expect("step signature verifies"));

    let proof = derive_selective_disclosure_proof(
        &signed,
        &projection,
        &keypair,
        &DisclosureSet(vec![0, 2, 4, 7]),
        b"step-record-proof-schema-nonce",
    )
    .expect("step proof generation succeeds");
    assert_eq!(proof.schema, SELECTIVE_DISCLOSURE_PROOF_SCHEMA_V1);
    assert_eq!(proof.projection_version, PROJECTION_VERSION_STEP_V1);
    verify_selective_disclosure_proof(&proof, &registry_for_key(&keypair))
        .expect("step proof verifies");
    assert_attest_schema_accepts(
        "selective-disclosure-proof.schema.json",
        &serde_json::to_value(&proof).expect("proof serializes"),
    );
}

#[test]
fn projection_manifest_uses_v2_slot_class_and_sensitivity() {
    let ed25519 = Keypair::generate();
    let receipt = receipt_fixture(&ed25519);
    let projection = project_receipt_body(&receipt).expect("receipt projection succeeds");
    let manifest = chio_selective_disclosure::bbs_projection_manifest_from_projection(&projection);
    let manifest_json = serde_json::to_value(&manifest).expect("serialize projection manifest");

    assert_eq!(
        manifest_json["schema"], "chio.bbs-projection.manifest.v2",
        "launch BBS projection manifests must be v2"
    );
    for slot in manifest_json["message_slots"]
        .as_array()
        .expect("message slots")
    {
        assert!(
            slot["message_class"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "each slot carries a typed message class"
        );
        assert!(
            slot["sensitivity_class"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "each slot carries a sensitivity class"
        );
    }
}

#[test]
fn projection_manifest_accepts_declared_hidden_predicates() {
    let ed25519 = Keypair::generate();
    let workflow = workflow_fixture(&ed25519);
    let projection =
        project_workflow_receipt_body(&workflow).expect("workflow projection succeeds");
    let keypair = generate_bbs_keypair(b"chio-bbs-signing-key-material-predicate", b"chio")
        .expect("BBS keypair succeeds");
    let signed = sign_projection(&projection, &keypair).expect("projection signing succeeds");
    let mut manifest =
        chio_selective_disclosure::bbs_projection_manifest_from_projection(&projection);
    let disclosed_slots = manifest
        .message_slots
        .iter()
        .filter(|slot| {
            slot.disclosure == chio_selective_disclosure::BbsProjectionDisclosure::Disclosed
        })
        .map(|slot| slot.slot)
        .collect();
    let proof = derive_selective_disclosure_proof(
        &signed,
        &projection,
        &keypair,
        &DisclosureSet(disclosed_slots),
        b"hidden-predicate-manifest-nonce",
    )
    .expect("selective disclosure proof succeeds");
    manifest
        .hidden_predicates
        .push(BbsProjectionHiddenPredicate {
            predicate_id: "amount_lte_100".to_string(),
            field: "amount".to_string(),
            operator: "<=".to_string(),
            value_sha256: Some(sha256_hex(b"100")),
        });

    verify_bbs_projection_manifest(&proof, &manifest)
        .expect("declared hidden predicate metadata is accepted");

    manifest
        .hidden_predicates
        .push(BbsProjectionHiddenPredicate {
            predicate_id: "amount_lte_100".to_string(),
            field: "amount".to_string(),
            operator: "<=".to_string(),
            value_sha256: Some(sha256_hex(b"100")),
        });
    let error = verify_bbs_projection_manifest(&proof, &manifest)
        .expect_err("duplicate hidden predicates are rejected");

    assert!(matches!(
        error,
        SelectiveDisclosureError::ProjectionManifestInvalid(message)
            if message.contains("duplicate hidden predicate amount_lte_100")
    ));
}

#[test]
fn proof_rejects_stub_schema_and_tampering() {
    let ed25519 = Keypair::generate();
    let workflow = workflow_fixture(&ed25519);
    let projection = project_workflow_receipt_body(&workflow).unwrap();
    let keypair = generate_bbs_keypair(b"chio-bbs-signing-key-material-0002", b"chio").unwrap();
    let signed = sign_projection(&projection, &keypair).unwrap();
    let mut proof = derive_selective_disclosure_proof(
        &signed,
        &projection,
        &keypair,
        &DisclosureSet(vec![4, 9, 10]),
        b"auditor-session-nonce",
    )
    .unwrap();
    let registry = registry_for_key(&keypair);

    proof.schema = "chio.federation-bbs-audit-view.v1.stub".to_string();
    assert!(matches!(
        verify_selective_disclosure_proof(&proof, &registry),
        Err(SelectiveDisclosureError::SchemaMismatch(_))
    ));

    proof.schema = SELECTIVE_DISCLOSURE_PROOF_SCHEMA_V1.to_string();
    proof.subject_sha256_hex = sha256_hex(b"forged-subject");
    assert!(matches!(
        verify_selective_disclosure_proof(&proof, &registry),
        Err(SelectiveDisclosureError::ProofVerificationFailed)
    ));
}

#[test]
fn proof_rejects_wrong_issuer_key() {
    let ed25519 = Keypair::generate();
    let receipt = receipt_fixture(&ed25519);
    let projection = project_receipt_body(&receipt).unwrap();
    let keypair = generate_bbs_keypair(b"chio-bbs-signing-key-material-0003", b"chio").unwrap();
    let signed = sign_projection(&projection, &keypair).unwrap();
    let proof = derive_selective_disclosure_proof(
        &signed,
        &projection,
        &keypair,
        &DisclosureSet(vec![5]),
        b"auditor-session-nonce",
    )
    .unwrap();

    let wrong_keypair =
        generate_bbs_keypair(b"chio-bbs-signing-key-material-0004", b"chio").unwrap();
    let mut registry = InMemoryIssuerRegistry::default();
    registry.insert(
        proof.issuer_fingerprint.clone(),
        wrong_keypair.public_key_hex,
    );
    assert!(matches!(
        verify_selective_disclosure_proof(&proof, &registry),
        Err(SelectiveDisclosureError::IssuerKeyMismatch)
    ));
}

#[test]
fn proof_rejects_message_count_inflation_before_bbs_verification() {
    let ed25519 = Keypair::generate();
    let workflow = workflow_fixture(&ed25519);
    let projection = project_workflow_receipt_body(&workflow).unwrap();
    let keypair = generate_bbs_keypair(b"chio-bbs-signing-key-material-0005", b"chio").unwrap();
    let signed = sign_projection(&projection, &keypair).unwrap();
    let mut proof = derive_selective_disclosure_proof(
        &signed,
        &projection,
        &keypair,
        &DisclosureSet(vec![4, 9]),
        b"auditor-session-nonce",
    )
    .unwrap();

    let mut registry = InMemoryIssuerRegistry::default();
    registry.insert(
        keypair.issuer_fingerprint.clone(),
        keypair.public_key_hex.clone(),
    );

    proof.message_count = proof.message_count.saturating_add(1_000);
    proof.disclosed_indices.push(999);
    let mut forged = proof.disclosed[0].clone();
    forged.index = 999;
    forged.field = "forged".to_string();
    proof.disclosed.push(forged);

    assert!(matches!(
        verify_selective_disclosure_proof(&proof, &registry),
        Err(SelectiveDisclosureError::ProofVerificationFailed)
    ));
}

#[test]
fn proof_rejects_uppercase_disclosed_message_hex() {
    let ed25519 = Keypair::generate();
    let receipt = receipt_fixture(&ed25519);
    let projection = project_receipt_body(&receipt).unwrap();
    let keypair = generate_bbs_keypair(b"chio-bbs-signing-key-material-0006", b"chio").unwrap();
    let signed = sign_projection(&projection, &keypair).unwrap();
    let mut proof = derive_selective_disclosure_proof(
        &signed,
        &projection,
        &keypair,
        &DisclosureSet(vec![5]),
        b"auditor-session-nonce",
    )
    .unwrap();
    proof.disclosed[0].bytes_hex = proof.disclosed[0].bytes_hex.to_uppercase();

    assert!(matches!(
        verify_selective_disclosure_proof(&proof, &registry_for_key(&keypair)),
        Err(SelectiveDisclosureError::MalformedHexField { field, .. }) if field == "id"
    ));
}

fn assert_context_rejection(
    mut context: CryptoVerificationContext,
    profile: DisclosureVerifierPrivacyProfile,
    expected_code: &str,
) {
    let (proof, registry, _keypair) = contextual_bbs_fixture();
    context.artifact_ref = proof.subject_sha256_hex.clone();
    context.nonce_hex = proof.proof_nonce_hex.clone();
    assert!(
        verify_selective_disclosure_proof(&proof, &registry).is_ok(),
        "BBS proof must verify before context policy rejection is evaluated"
    );

    let report =
        verify_selective_disclosure_with_context(&proof, &registry, &context, &profile).unwrap();
    assert_eq!(report.verdict, DisclosureContextVerdict::Rejected);
    assert!(report
        .rejected_checks
        .iter()
        .any(|check| check.code == expected_code));
}

#[test]
fn contextual_disclosure_accepts_valid_crypto_context() {
    let (proof, registry, keypair) = contextual_bbs_fixture();
    let profile = context_profile(&keypair);
    let context = crypto_context(&proof, &keypair);

    let report =
        verify_selective_disclosure_with_context(&proof, &registry, &context, &profile).unwrap();

    assert_eq!(report.schema, "chio.disclosure.crypto-context-report.v1");
    assert_eq!(report.verdict, DisclosureContextVerdict::Verified);
    assert!(report.cryptographic_proof_verified);
    assert_eq!(report.evidence_class, "verifier_context");
    assert!(report
        .verified_claims
        .iter()
        .any(|claim| { claim == "claim.disclosure.crypto_context_bound" }));
    assert_eq!(
        report.disclosed_fields,
        vec!["capability_id", "id", "tool_name"]
    );
}

#[test]
fn crypto_context_artifacts_validate_against_registered_schemas() {
    let (proof, registry, keypair) = contextual_bbs_fixture();
    let profile = context_profile(&keypair);
    let context = crypto_context(&proof, &keypair);

    let report =
        verify_selective_disclosure_with_context(&proof, &registry, &context, &profile).unwrap();

    assert_schema_accepts(
        "chio-crypto/v1/verification-context.schema.json",
        &serde_json::to_value(&context).expect("context serializes"),
    );
    assert_schema_accepts(
        "chio-trust/v1/key-state.schema.json",
        &serde_json::to_value(&context.key_state).expect("key state serializes"),
    );
    assert_schema_accepts(
        "chio-trust/v1/revocation-snapshot.schema.json",
        &serde_json::to_value(
            context
                .revocation_snapshot
                .as_ref()
                .expect("fixture has revocation snapshot"),
        )
        .expect("revocation snapshot serializes"),
    );
    assert_schema_accepts(
        "chio-disclosure/v1/verifier-privacy-profile.schema.json",
        &serde_json::to_value(&profile).expect("profile serializes"),
    );
    assert_schema_accepts(
        "chio-disclosure/v1/crypto-context-report.schema.json",
        &serde_json::to_value(&report).expect("report serializes"),
    );
}

#[test]
fn contextual_disclosure_rejects_wrong_audience_after_bbs_verifies() {
    let (proof, _registry, keypair) = contextual_bbs_fixture();
    let mut context = crypto_context(&proof, &keypair);
    context.audience = "https://attacker.example/chio".to_string();

    assert_context_rejection(
        context,
        context_profile(&keypair),
        "disclosure_context_audience_mismatch",
    );
}

#[test]
fn contextual_disclosure_rejects_replayed_nonce_after_bbs_verifies() {
    let (proof, _registry, keypair) = contextual_bbs_fixture();
    let mut context = crypto_context(&proof, &keypair);
    context.nonce_replay_status = NonceReplayStatus::Replayed;

    assert_context_rejection(
        context,
        context_profile(&keypair),
        "disclosure_context_nonce_replayed",
    );
}

#[test]
fn contextual_disclosure_rejects_stale_key_state_after_bbs_verifies() {
    let (proof, _registry, keypair) = contextual_bbs_fixture();
    let mut context = crypto_context(&proof, &keypair);
    context.key_state.status = KeyStateStatus::Stale;

    assert_context_rejection(
        context,
        context_profile(&keypair),
        "disclosure_context_key_not_active",
    );
}

#[test]
fn contextual_disclosure_rejects_forbidden_algorithm_after_bbs_verifies() {
    let (proof, _registry, keypair) = contextual_bbs_fixture();
    let mut profile = context_profile(&keypair);
    profile
        .forbidden_algorithms
        .push("bbs-bls12381-sha256".to_string());

    assert_context_rejection(
        crypto_context(&proof, &keypair),
        profile,
        "disclosure_context_algorithm_forbidden",
    );
}

#[test]
fn contextual_disclosure_rejects_missing_revocation_snapshot_after_bbs_verifies() {
    let (proof, _registry, keypair) = contextual_bbs_fixture();
    let mut context = crypto_context(&proof, &keypair);
    context.revocation_snapshot = None;

    assert_context_rejection(
        context,
        context_profile(&keypair),
        "disclosure_context_revocation_snapshot_missing",
    );
}

#[test]
fn contextual_disclosure_rejects_missing_holder_binding_after_bbs_verifies() {
    let (proof, _registry, keypair) = contextual_bbs_fixture();
    let mut context = crypto_context(&proof, &keypair);
    context.holder_binding_ref = None;
    context.holder_binding_status = HolderBindingStatus::Missing;

    assert_context_rejection(
        context,
        context_profile(&keypair),
        "disclosure_context_holder_binding_missing",
    );
}

#[test]
fn contextual_disclosure_rejects_preview_transparency_when_anchored_required() {
    let (proof, _registry, keypair) = contextual_bbs_fixture();
    let mut context = crypto_context(&proof, &keypair);
    context.transparency_state = TransparencyState::Preview;

    assert_context_rejection(
        context,
        context_profile(&keypair),
        "disclosure_context_transparency_state_insufficient",
    );
}
