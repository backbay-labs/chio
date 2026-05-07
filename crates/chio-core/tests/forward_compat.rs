// Forward-compatibility integration tests for chio-core serialized types.
//
// These tests prove that chio-core types tolerate unknown fields during
// deserialization (i.e., a v1.0 kernel can deserialize a v2.0 token that
// contains fields it does not yet know about, and vice versa).
//
// Strategy for each test: (1) create a valid instance, (2) serialize to
// serde_json::Value, (3) inject unknown fields, (4) re-serialize to string,
// (5) deserialize to the target type, (6) assert known fields survived and
// that signature verification still works.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::crypto::sha256_hex;
use chio_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
use chio_core::{
    CapabilityToken, CapabilityTokenBody, ChildRequestReceipt, ChildRequestReceiptBody,
    ChioReceipt, ChioReceiptBody, ChioScope, Decision, DelegationLink, DelegationLinkBody,
    GuardEvidence, Keypair, Operation, ToolAnnotations, ToolCallAction, ToolDefinition, ToolGrant,
    ToolManifest, ToolManifestBody,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_token_body(issuer_kp: &Keypair) -> CapabilityTokenBody {
    let subject_kp = Keypair::generate();
    CapabilityTokenBody {
        id: "cap-fwd-001".to_string(),
        issuer: issuer_kp.public_key(),
        subject: subject_kp.public_key(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv-files".to_string(),
                tool_name: "file_read".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: Some(10),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: vec![],
            prompt_grants: vec![],
        },
        issued_at: 1_000_000,
        expires_at: 2_000_000,
        delegation_chain: vec![],
    }
}

fn make_receipt_body(kp: &Keypair) -> ChioReceiptBody {
    let action = ToolCallAction::from_parameters(serde_json::json!({
        "path": "/app/src/main.rs"
    }))
    .unwrap();
    ChioReceiptBody {
        id: "rcpt-fwd-001".to_string(),
        timestamp: 1_710_000_000,
        capability_id: "cap-fwd-001".to_string(),
        tool_server: "srv-files".to_string(),
        tool_name: "file_read".to_string(),
        action,
        decision: Decision::Allow,
        content_hash: sha256_hex(br#"{"ok":true}"#),
        policy_hash: "deadbeefdeadbeef".to_string(),
        evidence: vec![GuardEvidence {
            guard_name: "ForbiddenPathGuard".to_string(),
            verdict: true,
            details: None,
        }],
        metadata: None,
        trust_level: chio_core::TrustLevel::default(),
        tenant_id: None,
        kernel_key: kp.public_key(),
    }
}

fn make_manifest_body(kp: &Keypair) -> ToolManifestBody {
    ToolManifestBody {
        server_id: "srv-files".to_string(),
        server_key: kp.public_key(),
        tools: vec![ToolDefinition {
            name: "file_read".to_string(),
            description: "Read a file".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" }
                },
                "required": ["path"]
            }),
            output_schema: None,
            pricing: None,
            annotations: ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: true,
                requires_approval: false,
                estimated_duration_ms: Some(50),
            },
        }],
        required_capabilities: vec!["fs_read".to_string()],
    }
}

fn make_delegation_link(delegator_kp: &Keypair, delegatee_kp: &Keypair) -> DelegationLink {
    let body = DelegationLinkBody {
        capability_id: "cap-fwd-001".to_string(),
        delegator: delegator_kp.public_key(),
        delegatee: delegatee_kp.public_key(),
        attenuations: vec![],
        timestamp: 1_000_100,
        scope_hash: None,
    };
    DelegationLink::sign(body, delegator_kp).unwrap()
}

fn make_child_receipt_body(kp: &Keypair) -> ChildRequestReceiptBody {
    ChildRequestReceiptBody {
        id: "child-fwd-001".to_string(),
        timestamp: 1_710_000_001,
        session_id: SessionId::new("sess-fwd-001"),
        parent_request_id: RequestId::new("parent-fwd-001"),
        request_id: RequestId::new("child-req-001"),
        operation_kind: OperationKind::CreateMessage,
        terminal_state: OperationTerminalState::Completed,
        outcome_hash: sha256_hex(br#"{"message":"sampled"}"#),
        policy_hash: "aabbccddaabbccdd".to_string(),
        metadata: None,
        kernel_key: kp.public_key(),
    }
}

// ---------------------------------------------------------------------------
// Test 1: v1_token_accepted_by_v2
// Proves basic round-trip still works with no unknown fields injected.
// ---------------------------------------------------------------------------
#[test]
fn v1_token_accepted_by_v2() {
    let kp = Keypair::generate();
    let body = make_token_body(&kp);
    let token = CapabilityToken::sign(body, &kp).unwrap();

    let json = serde_json::to_string(&token).unwrap();
    let restored: CapabilityToken = serde_json::from_str(&json).unwrap();

    assert_eq!(token.id, restored.id);
    assert_eq!(token.issuer, restored.issuer);
    assert_eq!(token.issued_at, restored.issued_at);
    assert_eq!(token.expires_at, restored.expires_at);
    assert_eq!(token.signature.to_hex(), restored.signature.to_hex());
    assert!(restored.verify_signature().unwrap());
}

// ---------------------------------------------------------------------------
// Test 2: v2_token_with_unknown_fields_accepted
// Proves unknown fields injected at the top level and inside ToolGrant are
// silently ignored during deserialization.
// ---------------------------------------------------------------------------
#[test]
fn v2_token_with_unknown_fields_accepted() {
    let kp = Keypair::generate();
    let body = make_token_body(&kp);
    let original_id = body.id.clone();
    let token = CapabilityToken::sign(body, &kp).unwrap();

    // Serialize to Value, inject unknown fields at multiple levels.
    let mut value: serde_json::Value = serde_json::to_value(&token).unwrap();

    // Inject at the top level (simulates v2.0 adding a new root field)
    value["future_field"] = serde_json::Value::String("some_future_value".to_string());
    value["v3_data"] = serde_json::json!({"nested_key": true, "count": 42});

    // Inject inside scope.grants[0] (simulates future v3.0 unknown fields)
    if let Some(grant) = value["scope"]["grants"].get_mut(0) {
        grant["v3_billing_ref"] = serde_json::json!("billing-acct-001");
        grant["v3_priority"] = serde_json::Value::Number(serde_json::Number::from(5));
    }

    let json_with_unknowns = serde_json::to_string(&value).unwrap();

    // Must deserialize without error
    let restored: CapabilityToken = serde_json::from_str(&json_with_unknowns)
        .expect("CapabilityToken must accept unknown fields");

    // Known fields must survive intact
    assert_eq!(original_id, restored.id);
    assert_eq!(token.issuer, restored.issuer);
    assert_eq!(token.issued_at, restored.issued_at);
    assert_eq!(token.expires_at, restored.expires_at);
    assert_eq!(token.signature.to_hex(), restored.signature.to_hex());

    // Signature verification must still succeed using the body (which does not
    // include the unknown fields injected in the raw JSON input).
    assert!(
        restored.verify_signature().unwrap(),
        "signature verification must pass after round-trip with unknown fields"
    );
}

// ---------------------------------------------------------------------------
// Test 3: v2_receipt_with_unknown_fields_accepted
// Proves receipts tolerate unknown fields at multiple nesting levels.
// ---------------------------------------------------------------------------
#[test]
fn v2_receipt_with_unknown_fields_accepted() {
    let kp = Keypair::generate();
    let body = make_receipt_body(&kp);
    let original_id = body.id.clone();
    let receipt = ChioReceipt::sign(body, &kp).unwrap();

    let mut value: serde_json::Value = serde_json::to_value(&receipt).unwrap();

    // Inject at top level
    value["billing_ref"] = serde_json::Value::String("inv-2026-0001".to_string());
    value["v3_trace_id"] = serde_json::json!("trace-abc123");

    // Inject inside evidence[0]
    if let Some(ev) = value["evidence"].get_mut(0) {
        ev["confidence_score"] = serde_json::json!(0.98);
        ev["v3_rule_version"] = serde_json::json!("1.2.0");
    }

    // Inject inside action
    value["action"]["execution_time_ms"] = serde_json::json!(12);

    let json_with_unknowns = serde_json::to_string(&value).unwrap();

    let restored: ChioReceipt =
        serde_json::from_str(&json_with_unknowns).expect("ChioReceipt must accept unknown fields");

    assert_eq!(original_id, restored.id);
    assert_eq!(receipt.capability_id, restored.capability_id);
    assert_eq!(receipt.tool_name, restored.tool_name);
    assert_eq!(receipt.content_hash, restored.content_hash);
    assert_eq!(receipt.signature.to_hex(), restored.signature.to_hex());
    assert!(restored.verify_signature().unwrap());
}

// ---------------------------------------------------------------------------
// Test 4: v2_manifest_with_unknown_fields_accepted
// Proves manifests tolerate unknown fields in all manifest type layers.
// ---------------------------------------------------------------------------
#[test]
fn v2_manifest_with_unknown_fields_accepted() {
    let kp = Keypair::generate();
    let body = make_manifest_body(&kp);
    let original_server_id = body.server_id.clone();
    let manifest = ToolManifest::sign(body, &kp).unwrap();

    let mut value: serde_json::Value = serde_json::to_value(&manifest).unwrap();

    // Inject at the ToolManifest level
    value["schema_version"] = serde_json::json!("2.0");
    value["v3_billing_account"] = serde_json::json!("acct-xyz");

    // Inject inside tools[0] (ToolDefinition)
    if let Some(tool) = value["tools"].get_mut(0) {
        tool["rate_limit"] = serde_json::json!({"per_minute": 60});
        tool["v3_cost_per_call"] = serde_json::json!({"amount": 1, "currency": "Chio"});

        // Inject inside annotations (ToolAnnotations)
        tool["annotations"]["sandboxed"] = serde_json::json!(true);
        tool["annotations"]["v3_energy_class"] = serde_json::json!("A");
    }

    let json_with_unknowns = serde_json::to_string(&value).unwrap();

    let restored: ToolManifest =
        serde_json::from_str(&json_with_unknowns).expect("ToolManifest must accept unknown fields");

    assert_eq!(original_server_id, restored.server_id);
    assert_eq!(manifest.server_key, restored.server_key);
    assert_eq!(manifest.tools.len(), restored.tools.len());
    assert_eq!(manifest.tools[0].name, restored.tools[0].name);
    assert_eq!(manifest.signature.to_hex(), restored.signature.to_hex());
    assert!(restored.verify_signature().unwrap());
}

// ---------------------------------------------------------------------------
// Test 5: unknown_fields_not_preserved_on_reserialize
// Proves that unknown fields absorbed during deserialization are NOT present
// in the re-serialized output (no data leakage, no ghost fields).
// ---------------------------------------------------------------------------
#[test]
fn unknown_fields_not_preserved_on_reserialize() {
    let kp = Keypair::generate();
    let body = make_token_body(&kp);
    let token = CapabilityToken::sign(body, &kp).unwrap();

    let mut value: serde_json::Value = serde_json::to_value(&token).unwrap();
    value["ghost_field"] = serde_json::Value::String("should_disappear".to_string());

    let json_with_ghost = serde_json::to_string(&value).unwrap();
    let restored: CapabilityToken = serde_json::from_str(&json_with_ghost).unwrap();

    // Re-serialize the restored struct
    let reserialzied = serde_json::to_string(&restored).unwrap();
    let output_value: serde_json::Value = serde_json::from_str(&reserialzied).unwrap();

    // Unknown field must NOT be present in the output
    assert!(
        output_value.get("ghost_field").is_none(),
        "ghost_field should not be present after round-trip through struct"
    );

    // Known fields must still be present
    assert!(output_value.get("id").is_some());
    assert!(output_value.get("signature").is_some());
}

// ---------------------------------------------------------------------------
// Test 6: delegation_link_with_unknown_fields
// Proves delegation chain links tolerate unknown fields.
// ---------------------------------------------------------------------------
#[test]
fn delegation_link_with_unknown_fields() {
    let delegator_kp = Keypair::generate();
    let delegatee_kp = Keypair::generate();
    let link = make_delegation_link(&delegator_kp, &delegatee_kp);

    let mut value: serde_json::Value = serde_json::to_value(&link).unwrap();

    // Inject unknown fields that a v2.0 delegation protocol might add
    value["expiry_override"] = serde_json::json!(1_999_999);
    value["v3_reason"] = serde_json::json!("sub-agent spawn");
    value["v3_audit_id"] = serde_json::json!("aud-00123");

    let json_with_unknowns = serde_json::to_string(&value).unwrap();

    let restored: DelegationLink = serde_json::from_str(&json_with_unknowns)
        .expect("DelegationLink must accept unknown fields");

    assert_eq!(link.capability_id, restored.capability_id);
    assert_eq!(link.delegator, restored.delegator);
    assert_eq!(link.delegatee, restored.delegatee);
    assert_eq!(link.timestamp, restored.timestamp);
    assert_eq!(link.signature.to_hex(), restored.signature.to_hex());
    assert!(restored.verify_signature().unwrap());
}

// ---------------------------------------------------------------------------
// Test 7: child_receipt_with_unknown_fields
// Proves child request receipts tolerate unknown fields.
// ---------------------------------------------------------------------------
#[test]
fn child_receipt_with_unknown_fields() {
    let kp = Keypair::generate();
    let body = make_child_receipt_body(&kp);
    let original_id = body.id.clone();
    let receipt = ChildRequestReceipt::sign(body, &kp).unwrap();

    let mut value: serde_json::Value = serde_json::to_value(&receipt).unwrap();

    // Inject unknown fields simulating v2.0 child receipt extensions
    value["sampling_cost"] = serde_json::json!({"tokens": 512, "model": "claude-3"});
    value["v3_trace_parent"] = serde_json::json!("00-abc123-xyz456-01");

    let json_with_unknowns = serde_json::to_string(&value).unwrap();

    let restored: ChildRequestReceipt = serde_json::from_str(&json_with_unknowns)
        .expect("ChildRequestReceipt must accept unknown fields");

    assert_eq!(original_id, restored.id);
    assert_eq!(receipt.session_id, restored.session_id);
    assert_eq!(receipt.parent_request_id, restored.parent_request_id);
    assert_eq!(receipt.request_id, restored.request_id);
    assert_eq!(receipt.outcome_hash, restored.outcome_hash);
    assert_eq!(receipt.signature.to_hex(), restored.signature.to_hex());
    assert!(restored.verify_signature().unwrap());
}
