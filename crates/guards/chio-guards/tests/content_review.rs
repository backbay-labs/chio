//! Integration tests for ContentReviewGuard.
//!
//! Verify that:
//!
//! * a Slack message with PII in the body is denied;
//! * a Stripe charge above `RequireApprovalAbove` triggers
//!   `Verdict::PendingApproval`;
//! * benign outbound content is allowed.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::capability::{
    governance::GovernedTransactionIntent,
    scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_guards::{ContentReviewConfig, ContentReviewGuard};
use chio_kernel::{Guard, GuardContext, ToolCallRequest, Verdict};

fn signed_cap(kp: &Keypair, scope: &ChioScope) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: "cap-content-review".to_string(),
        issuer: kp.public_key(),
        subject: kp.public_key(),
        scope: scope.clone(),
        issued_at: 0,
        expires_at: u64::MAX,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, kp).expect("sign cap")
}

fn make_request_with_scope(
    tool: &str,
    args: serde_json::Value,
    scope: ChioScope,
    intent: Option<GovernedTransactionIntent>,
) -> (ToolCallRequest, ChioScope, String, String) {
    let kp = Keypair::generate();
    let agent_id = kp.public_key().to_hex();
    let server_id = "srv-content".to_string();
    let req = ToolCallRequest {
        request_id: "req-content".to_string(),
        capability: signed_cap(&kp, &scope),
        tool_name: tool.to_string(),
        server_id: server_id.clone(),
        agent_id: agent_id.clone(),
        arguments: args,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: intent,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    (req, scope, agent_id, server_id)
}

fn eval_with<G: Guard>(
    guard: &G,
    tool: &str,
    args: serde_json::Value,
    scope: ChioScope,
    intent: Option<GovernedTransactionIntent>,
    matched_grant_index: Option<usize>,
) -> Verdict {
    let (request, scope, agent_id, server_id) = make_request_with_scope(tool, args, scope, intent);
    let ctx = GuardContext {
        request: &request,
        scope: &scope,
        agent_id: &agent_id,
        server_id: &server_id,
        session_filesystem_roots: None,
        matched_grant_index,
    };
    guard.evaluate(&ctx).expect("guard evaluate").verdict
}

fn eval_simple<G: Guard>(guard: &G, tool: &str, args: serde_json::Value) -> Verdict {
    eval_with(guard, tool, args, ChioScope::default(), None, None)
}

#[test]
fn slack_message_with_pii_denied() {
    let guard = ContentReviewGuard::new();
    let v = eval_simple(
        &guard,
        "slack_send_message",
        serde_json::json!({
            "endpoint": "chat.postMessage",
            "text": "My SSN is 123-45-6789 and email test@example.com"
        }),
    );
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");
}

#[test]
fn benign_slack_message_allowed() {
    let guard = ContentReviewGuard::new();
    let v = eval_simple(
        &guard,
        "slack_send_message",
        serde_json::json!({
            "endpoint": "chat.postMessage",
            "text": "the deploy finished successfully"
        }),
    );
    assert!(matches!(v, Verdict::Allow), "expected Allow, got {v:?}");
}

#[test]
fn stripe_charge_above_threshold_triggers_pending_approval() {
    let guard = ContentReviewGuard::new();
    let grant = ToolGrant {
        server_id: "srv-content".to_string(),
        tool_name: "stripe_create_charge".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![Constraint::RequireApprovalAbove {
            threshold_units: 10_000, // 100 USD in cents
        }],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    let scope = ChioScope {
        grants: vec![grant],
        ..ChioScope::default()
    };
    // Amount field exceeds threshold.
    let v = eval_with(
        &guard,
        "stripe_create_charge",
        serde_json::json!({
            "endpoint": "charges.create",
            "amount": 50_000u64,
            "currency": "usd",
            "description": "pay out supplier"
        }),
        scope,
        None,
        Some(0),
    );
    assert!(
        matches!(v, Verdict::PendingApproval),
        "expected PendingApproval, got {v:?}"
    );
}

#[test]
fn stripe_charge_via_governed_intent_also_triggers_pending_approval() {
    let guard = ContentReviewGuard::new();
    let grant = ToolGrant {
        server_id: "srv-content".to_string(),
        tool_name: "stripe_create_charge".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![Constraint::RequireApprovalAbove {
            threshold_units: 10_000,
        }],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    let scope = ChioScope {
        grants: vec![grant],
        ..ChioScope::default()
    };
    let intent = GovernedTransactionIntent {
        id: "intent-1".to_string(),
        server_id: "srv-content".to_string(),
        tool_name: "stripe_create_charge".to_string(),
        purpose: "vendor invoice".to_string(),
        max_amount: Some(MonetaryAmount {
            units: 25_000,
            currency: "USD".to_string(),
        }),
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    };
    let v = eval_with(
        &guard,
        "stripe_create_charge",
        serde_json::json!({
            "endpoint": "charges.create",
            "description": "pay vendor"
        }),
        scope,
        Some(intent),
        Some(0),
    );
    assert!(
        matches!(v, Verdict::PendingApproval),
        "expected PendingApproval, got {v:?}"
    );
}

#[test]
fn stripe_charge_below_threshold_allowed() {
    let guard = ContentReviewGuard::new();
    let grant = ToolGrant {
        server_id: "srv-content".to_string(),
        tool_name: "stripe_create_charge".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![Constraint::RequireApprovalAbove {
            threshold_units: 10_000,
        }],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    let scope = ChioScope {
        grants: vec![grant],
        ..ChioScope::default()
    };
    let v = eval_with(
        &guard,
        "stripe_create_charge",
        serde_json::json!({
            "endpoint": "charges.create",
            "amount": 500u64,
            "currency": "usd",
            "description": "small charge"
        }),
        scope,
        None,
        Some(0),
    );
    assert!(matches!(v, Verdict::Allow), "expected Allow, got {v:?}");
}

#[test]
fn profanity_banned_word_denies() {
    let mut config = ContentReviewConfig::default();
    config.default_rules.banned_words = vec!["badword".to_string()];
    let guard = ContentReviewGuard::with_config(config).expect("build guard");
    let v = eval_simple(
        &guard,
        "slack_send_message",
        serde_json::json!({
            "endpoint": "chat.postMessage",
            "text": "hey team, this is a BadWord for sure"
        }),
    );
    assert!(matches!(v, Verdict::Deny));
}

#[test]
fn non_external_api_actions_pass_through() {
    let guard = ContentReviewGuard::new();
    let v = eval_simple(&guard, "read_file", serde_json::json!({"path": "/tmp/x"}));
    assert!(matches!(v, Verdict::Allow));
}

#[test]
fn invalid_regex_pattern_fails_initialization() {
    let mut config = ContentReviewConfig::default();
    config.default_rules.extra_patterns = vec!["(unclosed".to_string()];
    let result = ContentReviewGuard::with_config(config);
    assert!(result.is_err(), "expected InvalidPattern error");
}

#[test]
fn extra_pattern_count_limit_fails_initialization() {
    let mut config = ContentReviewConfig::default();
    config.default_rules.extra_patterns = (0..65).map(|idx| format!("pattern-{idx}")).collect();
    let result = ContentReviewGuard::with_config(config);
    let Err(error) = result else {
        panic!("too many extra patterns should fail closed");
    };
    assert!(error.to_string().contains("allows at most 64 patterns"));
}

#[test]
fn extra_pattern_length_limit_fails_initialization() {
    let mut config = ContentReviewConfig::default();
    config.default_rules.extra_patterns = vec!["a".repeat(513)];
    let result = ContentReviewGuard::with_config(config);
    let Err(error) = result else {
        panic!("overlong extra pattern should fail closed");
    };
    assert!(error.to_string().contains("must be at most 512 characters"));
}

#[test]
fn extra_pattern_complexity_limit_fails_initialization() {
    let mut config = ContentReviewConfig::default();
    config.default_rules.extra_patterns =
        vec!["(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+".into()];
    let result = ContentReviewGuard::with_config(config);
    let Err(error) = result else {
        panic!("over-complex extra pattern should fail closed");
    };
    assert!(error.to_string().contains("complexity at most"));
}

#[test]
fn slack_blocks_api_pii_detected_in_nested_text() {
    let guard = ContentReviewGuard::new();
    let v = eval_simple(
        &guard,
        "slack_send_message",
        serde_json::json!({
            "endpoint": "chat.postMessage",
            "blocks": [
                {"text": {"text": "please email me at test@example.com"}}
            ]
        }),
    );
    assert!(matches!(v, Verdict::Deny));
}
