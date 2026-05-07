#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::capability::{
    compute_attenuation_witness, scope_hash, AttenuationProof, CapabilityToken,
    CapabilityTokenBody, CapabilityTokenV2Body, Caveat, CaveatKind, ChioScope, Operation,
    ToolGrant,
};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::receipt::{
    verify_receipt_v2_dag, ChioReceiptBody, ChioReceiptV2, Decision, GuardEvidence,
    ReceiptHybridLogicalClock, ReceiptV2BodyHashInput, ReceiptV2ReplaySet, ToolCallAction,
    TrustLevel,
};

fn grant(operations: Vec<Operation>) -> ToolGrant {
    ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool".to_string(),
        operations,
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn receipt_body(kp: &Keypair) -> ChioReceiptBody {
    ChioReceiptBody {
        id: "rcpt-v1-alias".to_string(),
        timestamp: 1710000000,
        capability_id: "cap-1".to_string(),
        tool_server: "srv".to_string(),
        tool_name: "tool".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"ok": true})).unwrap(),
        decision: Decision::Deny {
            reason: "missing capability".to_string(),
            guard: "CapabilityGuard".to_string(),
        },
        content_hash: sha256_hex(b"content"),
        policy_hash: sha256_hex(b"policy"),
        evidence: vec![GuardEvidence {
            guard_name: "CapabilityGuard".to_string(),
            verdict: false,
            details: Some("missing tool invoke".to_string()),
        }],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: kp.public_key(),
    }
}

#[test]
fn capability_v2_unknown_schema_rejected() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let parent = ChioScope {
        grants: vec![grant(vec![Operation::Invoke, Operation::Delegate])],
        ..ChioScope::default()
    };
    let child = ChioScope {
        grants: vec![grant(vec![Operation::Invoke])],
        ..ChioScope::default()
    };
    let witness = compute_attenuation_witness(&parent, &child).unwrap();
    let token = CapabilityToken::sign_v2(
        CapabilityTokenV2Body {
            body: CapabilityTokenBody {
                id: "cap-v2".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: child,
                issued_at: 1,
                expires_at: 2,
                delegation_chain: vec![],
            },
            caveats: vec![Caveat {
                kind: CaveatKind::RestrictTool,
                predicate: "srv/tool".to_string(),
                sig: None,
            }],
            scope_attenuations: vec![],
            attenuation_proof: AttenuationProof {
                parent_scope_hash: scope_hash(&parent).unwrap(),
                child_scope_hash: scope_hash(&ChioScope {
                    grants: vec![grant(vec![Operation::Invoke])],
                    ..ChioScope::default()
                })
                .unwrap(),
                normalized_subset_proof: witness,
            },
            budget_share_bps: Some(10_000),
        },
        &issuer,
    )
    .unwrap();

    let mut bad = token;
    bad.schema = "chio.capability.v999".to_string();
    assert!(bad.verify_signature().is_err());
}

#[test]
fn forged_attenuation_proof_rejected() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let parent = ChioScope {
        grants: vec![grant(vec![Operation::Invoke, Operation::Delegate])],
        ..ChioScope::default()
    };
    let child = ChioScope {
        grants: vec![grant(vec![Operation::Invoke])],
        ..ChioScope::default()
    };
    let witness = compute_attenuation_witness(&parent, &child).unwrap();
    let result = CapabilityToken::sign_v2(
        CapabilityTokenV2Body {
            body: CapabilityTokenBody {
                id: "cap-v2".to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: child,
                issued_at: 1,
                expires_at: 2,
                delegation_chain: vec![],
            },
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: AttenuationProof {
                parent_scope_hash: "00".repeat(32),
                child_scope_hash: scope_hash(&ChioScope {
                    grants: vec![grant(vec![Operation::Invoke])],
                    ..ChioScope::default()
                })
                .unwrap(),
                normalized_subset_proof: witness,
            },
            budget_share_bps: None,
        },
        &issuer,
    );
    assert!(result.is_err());
}

#[test]
fn receipt_v2_negative_conformance_cases() {
    let kp = Keypair::generate();
    let body = ReceiptV2BodyHashInput::from_v1_body(
        receipt_body(&kp),
        "chain-1",
        vec![],
        0,
        ReceiptHybridLogicalClock {
            wall_seconds: 1710000000,
            logical: 0,
            kernel_id: "kernel-a".to_string(),
        },
    );
    let receipt = ChioReceiptV2::sign("rcpt-alias", body, &kp).unwrap();

    let mut mismatched_hash = receipt.clone();
    mismatched_hash.body_hash = "00".repeat(32);
    assert!(!mismatched_hash.verify_signature().unwrap());

    let mut wrong_field_set = receipt.clone();
    wrong_field_set.body_hash = sha256_hex(
        serde_json::to_string(&serde_json::json!({
            "body_hash": receipt.body_hash,
            "signature": receipt.signature.to_hex()
        }))
        .unwrap()
        .as_bytes(),
    );
    assert!(!wrong_field_set.verify_signature().unwrap());

    let mut alias_tampered = receipt.clone();
    alias_tampered.receipt_id = "rcpt-tampered".to_string();
    assert!(alias_tampered.verify_signature().unwrap());
    let mut replay = ReceiptV2ReplaySet::default();
    assert!(replay.insert(&receipt).unwrap());
    assert!(!replay.insert(&alias_tampered).unwrap());
}

#[test]
fn receipt_v2_dag_cycle_shape_rejected() {
    let kp = Keypair::generate();
    let parent_body = ReceiptV2BodyHashInput::from_v1_body(
        receipt_body(&kp),
        "chain-1",
        vec![],
        4,
        ReceiptHybridLogicalClock {
            wall_seconds: 1710000000,
            logical: 0,
            kernel_id: "kernel-a".to_string(),
        },
    );
    let parent = ChioReceiptV2::sign("rcpt-parent", parent_body, &kp).unwrap();
    let child_body = ReceiptV2BodyHashInput::from_v1_body(
        receipt_body(&kp),
        "chain-1",
        vec![parent.body_hash.clone()],
        4,
        ReceiptHybridLogicalClock {
            wall_seconds: 1710000001,
            logical: 0,
            kernel_id: "kernel-b".to_string(),
        },
    );
    let child = ChioReceiptV2::sign("rcpt-child", child_body, &kp).unwrap();
    assert!(verify_receipt_v2_dag(&child, &[parent]).is_err());
}
