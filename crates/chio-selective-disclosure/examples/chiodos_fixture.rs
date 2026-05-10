use chio_core_types::capability::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_selective_disclosure::{
    derive_selective_disclosure_proof, generate_bbs_keypair, project_workflow_receipt_body,
    sign_projection, DisclosureSet,
};
use chio_workflow::receipt::{
    StepOutcome, StepRecord, WorkflowOutcome, WorkflowReceiptBody, WORKFLOW_RECEIPT_SCHEMA,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ed25519 = Keypair::generate();
    let workflow = WorkflowReceiptBody {
        id: "wf-chiodos-refund-001".to_string(),
        schema: WORKFLOW_RECEIPT_SCHEMA.to_string(),
        started_at: 1_766_000_000,
        completed_at: 1_766_000_042,
        skill_id: "refund-underwriting".to_string(),
        skill_version: "0.1.0".to_string(),
        agent_id: "buyer-agent".to_string(),
        session_id: Some("sess-chiodos-refund".to_string()),
        capability_id: "cap-chiodos-workflow".to_string(),
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
        kernel_key: ed25519.public_key(),
    };
    let projection = project_workflow_receipt_body(&workflow)?;
    let keypair = generate_bbs_keypair(b"chiodos-committed-bbs-key-material-0001", b"chiodos")?;
    let signed = sign_projection(&projection, &keypair)?;
    let proof = derive_selective_disclosure_proof(
        &signed,
        &projection,
        &keypair,
        &DisclosureSet(vec![4, 8, 9, 10]),
        b"buyer-auditor-proof-package",
    )?;
    println!("{}", serde_json::to_string_pretty(&proof)?);
    Ok(())
}
