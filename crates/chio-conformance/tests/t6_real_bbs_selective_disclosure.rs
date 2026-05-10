#![cfg(feature = "t6-bbs")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::capability::MonetaryAmount;
use chio_core::crypto::{sha256_hex, Keypair};
use chio_selective_disclosure::{
    derive_selective_disclosure_proof, generate_bbs_keypair, project_workflow_receipt_body,
    sign_projection, verify_selective_disclosure_proof, DisclosureSet, InMemoryIssuerRegistry,
    SelectiveDisclosureError, SelectiveDisclosureProof, SELECTIVE_DISCLOSURE_PROOF_SCHEMA_V1,
};
use chio_workflow::receipt::{
    StepOutcome, StepRecord, WorkflowOutcome, WorkflowReceiptBody, WORKFLOW_RECEIPT_SCHEMA,
};

fn three_vendor_workflow(kp: &Keypair) -> WorkflowReceiptBody {
    WorkflowReceiptBody {
        id: "wf-t6-3vendor".to_string(),
        schema: WORKFLOW_RECEIPT_SCHEMA.to_string(),
        started_at: 1_766_000_000,
        completed_at: 1_766_000_042,
        skill_id: "refund-underwriting".to_string(),
        skill_version: "0.1.0".to_string(),
        agent_id: "buyer-agent".to_string(),
        session_id: Some("sess-t6".to_string()),
        capability_id: "cap-t6-workflow".to_string(),
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

#[test]
fn three_vendor_workflow_fixture_verifies_real_bbs_disclosure() {
    let ed25519 = Keypair::generate();
    let workflow = three_vendor_workflow(&ed25519);
    let projection = project_workflow_receipt_body(&workflow).unwrap();
    let keypair = generate_bbs_keypair(b"t6-conformance-bbs-key-material-0001", b"t6").unwrap();
    let signed = sign_projection(&projection, &keypair).unwrap();
    let proof = derive_selective_disclosure_proof(
        &signed,
        &projection,
        &keypair,
        &DisclosureSet(vec![4, 8, 9, 10]),
        b"buyer-auditor-proof-package",
    )
    .unwrap();

    assert_eq!(proof.schema, SELECTIVE_DISCLOSURE_PROOF_SCHEMA_V1);
    assert!(
        !proof.schema.ends_with(".stub"),
        "T6 conformance must not accept the old stub schema"
    );

    let mut registry = InMemoryIssuerRegistry::default();
    registry.insert(
        keypair.issuer_fingerprint.clone(),
        keypair.public_key_hex.clone(),
    );
    let verified = verify_selective_disclosure_proof(&proof, &registry).unwrap();
    assert_eq!(verified.disclosed.len(), 4);
    assert!(verified
        .disclosed
        .iter()
        .any(|message| message.field == "skill_id"));
}

#[test]
fn three_vendor_workflow_fixture_rejects_negative_mutations() {
    let ed25519 = Keypair::generate();
    let workflow = three_vendor_workflow(&ed25519);
    let projection = project_workflow_receipt_body(&workflow).unwrap();
    let keypair = generate_bbs_keypair(b"t6-conformance-bbs-key-material-0002", b"t6").unwrap();
    let signed = sign_projection(&projection, &keypair).unwrap();
    let mut proof = derive_selective_disclosure_proof(
        &signed,
        &projection,
        &keypair,
        &DisclosureSet(vec![4, 9]),
        b"buyer-auditor-proof-package",
    )
    .unwrap();

    let mut registry = InMemoryIssuerRegistry::default();
    registry.insert(
        keypair.issuer_fingerprint.clone(),
        keypair.public_key_hex.clone(),
    );

    proof.disclosed[0].bytes_hex = hex::encode(b"wf-t6-forged");
    assert!(matches!(
        verify_selective_disclosure_proof(&proof, &registry),
        Err(SelectiveDisclosureError::ProofVerificationFailed)
    ));
}

#[test]
fn committed_three_vendor_proof_fixture_verifies() {
    let fixture = include_str!("../../../examples/chiodos-3vendor/fixtures/t6-real-bbs-proof.json");
    let proof: SelectiveDisclosureProof = serde_json::from_str(fixture).unwrap();
    assert_eq!(proof.schema, SELECTIVE_DISCLOSURE_PROOF_SCHEMA_V1);
    assert!(!proof.schema.ends_with(".stub"));

    let mut registry = InMemoryIssuerRegistry::default();
    registry.insert(
        proof.issuer_fingerprint.clone(),
        proof.issuer_public_key_hex.clone(),
    );
    let verified = verify_selective_disclosure_proof(&proof, &registry).unwrap();
    assert_eq!(verified.disclosed.len(), 4);
    assert!(verified
        .disclosed
        .iter()
        .any(|message| message.field == "skill_id"));
}
