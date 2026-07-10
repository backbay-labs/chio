use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::ChioReceiptBody,
    decision::{Decision, ToolCallAction},
    kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
};
use chio_kernel::{receipt_body_fields_coupled, ReceiptCouplingExpectation};
use proptest::prelude::*;

use chio_test_support::prelude::*;

fn fixture() -> (ChioReceiptBody, ToolCallAction, Decision, String, String) {
    let action = ToolCallAction::from_parameters(serde_json::json!({"key": "value"})).test_unwrap();
    let decision = Decision::Allow;
    let content_hash = "content-hash".to_string();
    let policy_hash = "policy-hash".to_string();
    let body = ChioReceiptBody {
        id: "receipt".to_string(),
        timestamp: 1,
        capability_id: "cap".to_string(),
        tool_server: "server".to_string(),
        tool_name: "tool".to_string(),
        action: action.clone(),
        decision: Some(decision.clone()),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: Vec::new(),
        content_hash: content_hash.clone(),
        policy_hash: policy_hash.clone(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: Keypair::from_seed(&[7; 32]).public_key(),
        bbs_projection_version: None,
    };
    (body, action, decision, content_hash, policy_hash)
}

proptest! {
    #[test]
    fn production_receipt_projection_matches_all_field_classes(
        capability_matches in any::<bool>(),
        request_matches in any::<bool>(),
        verdict_matches in any::<bool>(),
        policy_hash_matches in any::<bool>(),
        evidence_class_matches in any::<bool>(),
    ) {
        let (mut body, action, decision, content_hash, policy_hash) = fixture();
        if !capability_matches {
            body.capability_id = "other-cap".to_string();
        }
        if !request_matches {
            body.tool_name = "other-tool".to_string();
        }
        if !verdict_matches {
            body.decision = Some(Decision::Deny {
                reason: "denied".to_string(),
                guard: "guard".to_string(),
            });
        }
        if !policy_hash_matches {
            body.policy_hash = "other-policy".to_string();
        }
        if !evidence_class_matches {
            body.boundary_class = BoundaryClass::AdvisoryOnly;
        }
        let expected = ReceiptCouplingExpectation {
            capability_id: "cap",
            server_id: "server",
            tool_name: "tool",
            action: &action,
            decision: &decision,
            content_hash: &content_hash,
            policy_hash: &policy_hash,
            trust_level: TrustLevel::Mediated,
        };

        prop_assert_eq!(
            receipt_body_fields_coupled(&body, &expected),
            capability_matches
                && request_matches
                && verdict_matches
                && policy_hash_matches
                && evidence_class_matches,
        );
    }
}
