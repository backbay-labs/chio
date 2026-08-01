//! Integration tests for BrowserAutomationGuard.
//!
//! Verify that:
//!
//! * navigation to a domain outside the allowlist is denied;
//! * a read-only browser session (navigate + screenshot only) denies
//!   click and type actions;
//! * credential patterns in Type action text trigger Deny.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::capability::{
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_guards::{BrowserAutomationConfig, BrowserAutomationGuard};
use chio_kernel::{Guard, GuardContext, ToolCallRequest, Verdict};

fn signed_cap(kp: &Keypair, scope: &ChioScope) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: "cap-browser-auto".to_string(),
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

fn make_request(
    tool: &str,
    args: serde_json::Value,
) -> (ToolCallRequest, ChioScope, String, String) {
    let kp = Keypair::generate();
    let scope = ChioScope::default();
    let agent_id = kp.public_key().to_hex();
    let server_id = "srv-browser".to_string();
    let req = ToolCallRequest {
        request_id: "req-browser".to_string(),
        capability: signed_cap(&kp, &scope),
        tool_name: tool.to_string(),
        server_id: server_id.clone(),
        agent_id: agent_id.clone(),
        arguments: args,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    (req, scope, agent_id, server_id)
}

fn eval<G: Guard>(guard: &G, tool: &str, args: serde_json::Value) -> Verdict {
    let (request, scope, agent_id, server_id) = make_request(tool, args);
    let ctx = GuardContext {
        request: &request,
        scope: &scope,
        agent_id: &agent_id,
        server_id: &server_id,
        session_filesystem_roots: None,
        matched_grant_index: None,
    };
    guard.evaluate(&ctx).expect("guard evaluate").verdict
}

#[test]
fn navigation_outside_allowlist_denied() {
    let guard = BrowserAutomationGuard::with_config(BrowserAutomationConfig {
        allowed_domains: vec!["example.com".to_string(), "*.docs.rs".to_string()],
        ..BrowserAutomationConfig::default()
    })
    .expect("build guard");

    // Outside allowlist → Deny
    let v = eval(
        &guard,
        "navigate",
        serde_json::json!({"url": "https://evil.com/login"}),
    );
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");

    // Inside allowlist → Allow
    let v = eval(
        &guard,
        "navigate",
        serde_json::json!({"url": "https://example.com/x"}),
    );
    assert!(matches!(v, Verdict::Allow), "expected Allow, got {v:?}");

    // Wildcard subdomain → Allow
    let v = eval(
        &guard,
        "navigate",
        serde_json::json!({"url": "https://tokio.docs.rs/tokio"}),
    );
    assert!(matches!(v, Verdict::Allow), "expected Allow, got {v:?}");
}

#[test]
fn read_only_session_denies_type_and_click() {
    // navigate + screenshot only.
    let guard = BrowserAutomationGuard::with_config(BrowserAutomationConfig {
        allowed_verbs: vec!["navigate".to_string(), "screenshot".to_string()],
        ..BrowserAutomationConfig::default()
    })
    .expect("build guard");

    let v = eval(
        &guard,
        "browser",
        serde_json::json!({"action": "click", "selector": "#submit"}),
    );
    assert!(matches!(v, Verdict::Deny), "click must Deny, got {v:?}");

    let v = eval(
        &guard,
        "browser",
        serde_json::json!({"action": "type", "text": "hello"}),
    );
    assert!(matches!(v, Verdict::Deny), "type must Deny, got {v:?}");

    // navigate + screenshot still allowed.
    let v = eval(
        &guard,
        "navigate",
        serde_json::json!({"url": "https://example.com"}),
    );
    assert!(
        matches!(v, Verdict::Allow),
        "navigate must Allow, got {v:?}"
    );
    let v = eval(&guard, "screenshot", serde_json::json!({}));
    assert!(
        matches!(v, Verdict::Allow),
        "screenshot must Allow, got {v:?}"
    );
}

#[test]
fn type_with_credential_shaped_value_denied() {
    // Empty allowed_verbs means "any verb"; we isolate the credential
    // detector so it actually runs on Type actions.
    let guard = BrowserAutomationGuard::with_config(BrowserAutomationConfig {
        allowed_verbs: vec![],
        ..BrowserAutomationConfig::default()
    })
    .expect("build guard");

    // AWS access key in a Type action.
    let v = eval(
        &guard,
        "browser",
        serde_json::json!({
            "action": "type",
            "text": "AKIAABCDEFGHIJKLMNOP"
        }),
    );
    assert!(matches!(v, Verdict::Deny), "AWS key must Deny, got {v:?}");

    // password=... shape.
    let v = eval(
        &guard,
        "browser",
        serde_json::json!({
            "action": "type",
            "value": "password = hunter21234"
        }),
    );
    assert!(
        matches!(v, Verdict::Deny),
        "password shape must Deny, got {v:?}"
    );

    // Benign text allowed.
    let v = eval(
        &guard,
        "browser",
        serde_json::json!({
            "action": "type",
            "text": "hello world"
        }),
    );
    assert!(
        matches!(v, Verdict::Allow),
        "benign text must Allow, got {v:?}"
    );
}

#[test]
fn blocked_domain_takes_precedence() {
    let guard = BrowserAutomationGuard::with_config(BrowserAutomationConfig {
        allowed_domains: vec!["*.example.com".to_string()],
        blocked_domains: vec!["bad.example.com".to_string()],
        ..BrowserAutomationConfig::default()
    })
    .expect("build guard");

    let v = eval(
        &guard,
        "navigate",
        serde_json::json!({"url": "https://bad.example.com/path"}),
    );
    assert!(
        matches!(v, Verdict::Deny),
        "blocked domain must Deny, got {v:?}"
    );
}

#[test]
fn non_browser_actions_pass_through() {
    let guard = BrowserAutomationGuard::new();
    let v = eval(&guard, "read_file", serde_json::json!({"path": "/tmp/x"}));
    assert!(matches!(v, Verdict::Allow));
}

#[test]
fn credential_detection_disabled_allows_secrets() {
    let guard = BrowserAutomationGuard::with_config(BrowserAutomationConfig {
        credential_detection: false,
        allowed_verbs: vec![], // any verb
        ..BrowserAutomationConfig::default()
    })
    .expect("build guard");

    let v = eval(
        &guard,
        "browser",
        serde_json::json!({
            "action": "type",
            "text": "AKIAABCDEFGHIJKLMNOP"
        }),
    );
    assert!(matches!(v, Verdict::Allow));
}

#[test]
fn disabled_guard_allows_all() {
    let guard = BrowserAutomationGuard::with_config(BrowserAutomationConfig {
        enabled: false,
        allowed_domains: vec!["example.com".to_string()],
        ..BrowserAutomationConfig::default()
    })
    .expect("build guard");

    let v = eval(
        &guard,
        "navigate",
        serde_json::json!({"url": "https://evil.com"}),
    );
    assert!(matches!(v, Verdict::Allow));
}
