#![cfg(feature = "bbs")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core_types::capability::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::{ChioReceiptBody, Decision, ToolCallAction, TrustLevel};
use chio_selective_disclosure::{
    derive_selective_disclosure_proof, generate_bbs_keypair, project_receipt_body,
    project_step_record, project_workflow_receipt_body, sign_projection,
    verify_selective_disclosure_proof, verify_signed_projection, DisclosureSet,
    InMemoryIssuerRegistry, SelectiveDisclosureError, PROJECTION_VERSION_RECEIPT_V1,
    PROJECTION_VERSION_STEP_V1, PROJECTION_VERSION_WORKFLOW_V1,
    SELECTIVE_DISCLOSURE_PROOF_SCHEMA_V1,
};
use chio_workflow::receipt::{
    StepOutcome, StepRecord, WorkflowOutcome, WorkflowReceiptBody, WORKFLOW_RECEIPT_SCHEMA,
};

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
