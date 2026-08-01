//! Integration tests for CodeExecutionGuard.
//!
//! Verify that:
//!
//! * language outside the allowlist is denied;
//! * `import subprocess` (dangerous module) is denied;
//! * `network_access = false` denies when the call requests network.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::capability::{
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_guards::{CodeExecutionConfig, CodeExecutionGuard};
use chio_kernel::{Guard, GuardContext, ToolCallRequest, Verdict};

fn signed_cap(kp: &Keypair, scope: &ChioScope) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: "cap-code-exec".to_string(),
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
    let server_id = "srv-code".to_string();
    let req = ToolCallRequest {
        request_id: "req-code".to_string(),
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
fn bash_language_denied_when_allowlist_is_python() {
    let guard = CodeExecutionGuard::with_config(CodeExecutionConfig {
        language_allowlist: vec!["python".to_string()],
        ..CodeExecutionConfig::default()
    })
    .expect("build guard");

    // Explicit language=bash on an eval-style tool.
    let v = eval(
        &guard,
        "eval",
        serde_json::json!({"language": "bash", "code": "echo hi"}),
    );
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");
}

#[test]
fn python_language_allowed_when_allowlist_is_python() {
    let guard = CodeExecutionGuard::with_config(CodeExecutionConfig {
        language_allowlist: vec!["python".to_string()],
        module_denylist: vec![], // empty so we can verify language-only pass
        network_access: true,
        ..CodeExecutionConfig::default()
    })
    .expect("build guard");

    let v = eval(
        &guard,
        "python",
        serde_json::json!({"code": "print('hello')"}),
    );
    assert!(matches!(v, Verdict::Allow), "expected Allow, got {v:?}");
}

#[test]
fn import_subprocess_denied_by_dangerous_module_detection() {
    // Allow python language + network so only the module gate fires.
    let guard = CodeExecutionGuard::with_config(CodeExecutionConfig {
        language_allowlist: vec!["python".to_string()],
        network_access: true,
        ..CodeExecutionConfig::default()
    })
    .expect("build guard");

    let v = eval(
        &guard,
        "python",
        serde_json::json!({"code": "import subprocess\nsubprocess.run(['ls'])"}),
    );
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");
}

#[test]
fn network_access_false_denies_network_request_flag() {
    let guard = CodeExecutionGuard::with_config(CodeExecutionConfig {
        language_allowlist: vec!["python".to_string()],
        module_denylist: vec![], // isolate the network gate
        network_access: false,
        ..CodeExecutionConfig::default()
    })
    .expect("build guard");

    let v = eval(
        &guard,
        "python",
        serde_json::json!({
            "code": "print(1)",
            "network_access": true
        }),
    );
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");
}

#[test]
fn network_access_false_denies_network_module_import() {
    let guard = CodeExecutionGuard::with_config(CodeExecutionConfig {
        language_allowlist: vec!["python".to_string()],
        module_denylist: vec![],
        network_access: false,
        ..CodeExecutionConfig::default()
    })
    .expect("build guard");

    let v = eval(
        &guard,
        "python",
        serde_json::json!({"code": "import requests\nrequests.get('https://x')"}),
    );
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");
}

#[test]
fn execution_time_bound_denies_over_limit() {
    let guard = CodeExecutionGuard::with_config(CodeExecutionConfig {
        language_allowlist: vec!["python".to_string()],
        module_denylist: vec![],
        network_access: true,
        max_execution_time_ms: Some(1_000),
        ..CodeExecutionConfig::default()
    })
    .expect("build guard");

    let v = eval(
        &guard,
        "python",
        serde_json::json!({"code": "print(1)", "timeout_ms": 5_000}),
    );
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");
}

#[test]
fn execution_time_bound_allows_exact_limit() {
    let guard = CodeExecutionGuard::with_config(CodeExecutionConfig {
        language_allowlist: vec!["python".to_string()],
        module_denylist: vec![],
        network_access: true,
        max_execution_time_ms: Some(1_000),
        ..CodeExecutionConfig::default()
    })
    .expect("build guard");

    let v = eval(
        &guard,
        "python",
        serde_json::json!({"code": "print(1)", "timeout_ms": 1_000}),
    );
    assert!(matches!(v, Verdict::Allow), "expected Allow, got {v:?}");
}

#[test]
fn non_code_execution_actions_pass_through() {
    let guard = CodeExecutionGuard::new();
    let v = eval(&guard, "read_file", serde_json::json!({"path": "/tmp/x"}));
    assert!(matches!(v, Verdict::Allow), "expected Allow, got {v:?}");
}

#[test]
fn disabled_guard_allows_everything() {
    let guard = CodeExecutionGuard::with_config(CodeExecutionConfig {
        enabled: false,
        ..CodeExecutionConfig::default()
    })
    .expect("build guard");

    let v = eval(
        &guard,
        "eval",
        serde_json::json!({"language": "bash", "code": "echo hi"}),
    );
    assert!(matches!(v, Verdict::Allow));
}

#[test]
fn payload_exceeding_max_scan_bytes_is_denied_failclosed() {
    // Set a deliberately tiny scan budget to force the padding-bypass
    // path: the dangerous module ("subprocess") sits past the configured
    // bound, so the truncated prefix does not contain the import. A scan
    // that gives up past its budget must deny rather than allow.
    let guard = CodeExecutionGuard::with_config(CodeExecutionConfig {
        language_allowlist: vec!["python".to_string()],
        network_access: true,
        max_scan_bytes: 64,
        ..CodeExecutionConfig::default()
    })
    .expect("build guard");

    let mut padded = String::with_capacity(256);
    padded.push_str("# safe prefix; ");
    padded.push_str(&"a".repeat(128));
    padded.push_str("\nimport subprocess\nsubprocess.run(['ls'])");

    let v = eval(&guard, "python", serde_json::json!({"code": padded}));
    assert!(
        matches!(v, Verdict::Deny),
        "oversized payload must fail-closed, got {v:?}"
    );
}

#[test]
fn payload_at_max_scan_bytes_is_allowed() {
    let guard = CodeExecutionGuard::with_config(CodeExecutionConfig {
        language_allowlist: vec!["python".to_string()],
        network_access: true,
        max_scan_bytes: 64,
        ..CodeExecutionConfig::default()
    })
    .expect("build guard");

    let code = "a".repeat(64);
    assert_eq!(code.len(), 64);

    let v = eval(&guard, "python", serde_json::json!({"code": code}));
    assert!(
        matches!(v, Verdict::Allow),
        "payload exactly at max_scan_bytes should be allowed, got {v:?}"
    );
}
