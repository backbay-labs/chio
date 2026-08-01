//! Strict verification of a treaty-bound bilateral DSSE envelope.

use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair};
use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core_types::receipt::decision::{Decision, ToolCallAction};
use chio_core_types::receipt::kinds::TrustLevel;
use chio_federation::bilateral_dsse::{
    sign_chio_bilateral_dsse_envelope, verify_chio_bilateral_dsse_envelope,
    BilateralPredicateExtensions, CapabilityLeaseRef, GovernanceReceiptRef, HashRecord,
    PolicyEvaluationSummary, PolicyVerdict, TreatyBindingRef,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn receipt_metadata() -> serde_json::Value {
    let package: serde_json::Value = match serde_json::from_str(include_str!(
        "../../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
    )) {
        Ok(package) => package,
        Err(error) => panic!("failed to parse buyer-closure proof package fixture: {error}"),
    };
    match package
        .get("toolReceipts")
        .and_then(serde_json::Value::as_array)
        .and_then(|receipts| receipts.first())
        .and_then(|receipt| receipt.get("metadata"))
    {
        Some(metadata) => metadata.clone(),
        None => panic!("buyer-closure proof package fixture has no receipt metadata"),
    }
}

fn signed_receipt(keypair: &Keypair) -> ChioReceipt {
    let action = match ToolCallAction::from_parameters(serde_json::json!({
        "caseRef": "refund-250",
        "tool": "read_refund_case",
        "workflowId": "wf-chio-refund-001"
    })) {
        Ok(action) => action,
        Err(error) => panic!("failed to construct bilateral benchmark action: {error}"),
    };
    let body = ChioReceiptBody {
        id: "receipt-bilateral-benchmark".to_string(),
        timestamp: 1_766_000_001,
        capability_id: "lease-vendor-a-read".to_string(),
        tool_server: "vendor-a.files".to_string(),
        tool_name: "read_refund_case".to_string(),
        action,
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: sha256_hex(br#"{"accepted":true}"#),
        policy_hash: "3".repeat(64),
        evidence: Vec::new(),
        metadata: Some(receipt_metadata()),
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    };
    match ChioReceipt::sign(body, keypair) {
        Ok(receipt) => receipt,
        Err(error) => panic!("failed to sign bilateral benchmark receipt: {error}"),
    }
}

fn extensions(receipt: &ChioReceipt) -> BilateralPredicateExtensions {
    let remote_receipt_sha256 = match canonical_json_bytes(receipt) {
        Ok(bytes) => sha256_hex(&bytes),
        Err(error) => panic!("failed to canonicalize bilateral benchmark receipt: {error}"),
    };
    BilateralPredicateExtensions {
        capability_lease_ref: Some(CapabilityLeaseRef {
            lease_id: "lease-vendor-a-read".to_string(),
            issuer: "did:chio:buyer-kernel".to_string(),
            expires_at_unix_ms: 1_900_000_000_000,
            scope_digest: None,
        }),
        policy_evaluation_summary: Some(PolicyEvaluationSummary {
            server_a_verdict: PolicyVerdict {
                verdict: "allow".to_string(),
                policy_id: "buyer-policy".to_string(),
                policy_version: "v1".to_string(),
                rationale_code: None,
            },
            server_b_verdict: PolicyVerdict {
                verdict: "allow".to_string(),
                policy_id: "vendor-policy".to_string(),
                policy_version: "v1".to_string(),
                rationale_code: None,
            },
            joint_disposition: Some("allow".to_string()),
        }),
        governance_receipt_ref: Some(GovernanceReceiptRef {
            receipt_id: "governance-receipt-1".to_string(),
            kernel_id: "did:chio:buyer-kernel".to_string(),
            digest: HashRecord {
                alg: "sha256".to_string(),
                value: "d".repeat(64),
            },
        }),
        consistency_anchor: Some("anchor-bilateral-benchmark".to_string()),
        consistency_model: Some("totally-ordered".to_string()),
        cross_org_visibility: Some("treaty_only".to_string()),
        treaty_binding_ref: Some(TreatyBindingRef {
            treaty_id: "treaty-buyer-vendor".to_string(),
            treaty_scope_sha256: "1".repeat(64),
            ladder_intersection_sha256: "2".repeat(64),
            admission_report_sha256: "3".repeat(64),
            continuation_sha256: "4".repeat(64),
            lineage_bundle_sha256: "5".repeat(64),
            action_class_id: "workflow.cross_kernel.read_refund_case".to_string(),
            consistency_model: "totally-ordered".to_string(),
            request_sha256: receipt.action.parameter_hash.clone(),
            outcome_sha256: receipt.content_hash.clone(),
            local_receipt_sha256: "8".repeat(64),
            remote_receipt_sha256,
            lease_refs: vec!["lease-vendor-a-read".to_string()],
            governance_refs: vec!["governance-receipt-1".to_string()],
            signer_kernel_ids: vec![
                "did:chio:buyer-kernel".to_string(),
                "did:chio:vendor-a".to_string(),
            ],
        }),
    }
}

pub fn bench(c: &mut Criterion) {
    let buyer_key = Keypair::from_seed(&[11_u8; 32]);
    let vendor_key = Keypair::from_seed(&[12_u8; 32]);
    let receipt = signed_receipt(&vendor_key);
    let envelope = match sign_chio_bilateral_dsse_envelope(
        &receipt,
        &buyer_key,
        &vendor_key,
        "did:chio:buyer-kernel",
        "did:chio:vendor-a",
        "read_refund_case",
        1_766_000_001_000,
        extensions(&receipt),
    ) {
        Ok(envelope) => envelope,
        Err(error) => panic!("failed to sign bilateral benchmark envelope: {error}"),
    };
    let buyer_public = buyer_key.public_key();
    let vendor_public = vendor_key.public_key();
    if verify_chio_bilateral_dsse_envelope(&envelope, &buyer_public, &vendor_public).is_err() {
        panic!("bilateral benchmark fixture did not verify");
    }

    c.bench_function("strict_bilateral_dsse_verify", |b| {
        b.iter(|| {
            if black_box(verify_chio_bilateral_dsse_envelope(
                black_box(&envelope),
                black_box(&buyer_public),
                black_box(&vendor_public),
            ))
            .is_err()
            {
                panic!("strict bilateral verification benchmark rejected its fixture");
            }
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
