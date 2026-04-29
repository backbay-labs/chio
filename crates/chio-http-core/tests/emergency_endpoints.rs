//! Phase 1.4 HTTP-surface tests for the emergency kill switch.
//!
//! `chio-http-core` is protocol-agnostic and does not embed an HTTP
//! server, so these tests exercise the substrate-independent handler
//! functions directly. Each test pairs the handler with a real
//! `ChioKernel` so the full "endpoint flips the kernel, subsequent
//! evaluate denies" path is covered end-to-end without spinning up
//! a framework server.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use chio_core_types::capability::{CapabilityToken, ChioScope, Operation, ToolGrant};
use chio_core_types::crypto::Keypair;
use chio_http_core::emergency::EmergencyHandlerError;
use chio_http_core::{
    handle_emergency_resume, handle_emergency_status, handle_emergency_stop, EmergencyAdmin,
    EmergencyStatusResponse, EMERGENCY_ADMIN_TOKEN_HEADER, EMERGENCY_RESUME_PATH,
    EMERGENCY_STATUS_PATH, EMERGENCY_STOP_PATH,
};
use chio_kernel::Verdict as KernelVerdict;
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ServerId, ToolCallRequest,
    ToolServerConnection, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES, EMERGENCY_STOP_DENY_REASON,
};

const ADMIN_TOKEN: &str = "unit-test-admin-token";

struct EchoServer {
    id: ServerId,
    tool: String,
}

impl ToolServerConnection for EchoServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![self.tool.clone()]
    }

    fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        if tool_name != self.tool {
            return Err(KernelError::Internal(format!(
                "unexpected tool {tool_name}"
            )));
        }
        Ok(arguments)
    }
}

fn build_kernel() -> ChioKernel {
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 4,
        policy_hash: "http-emergency-test-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    });
    kernel.register_tool_server(Box::new(EchoServer {
        id: "srv-a".to_string(),
        tool: "read_file".to_string(),
    }));
    kernel
}

fn admin(kernel: ChioKernel) -> EmergencyAdmin {
    EmergencyAdmin::new(Arc::new(kernel), ADMIN_TOKEN.to_string())
}

fn issue_capability(admin: &EmergencyAdmin, agent: &Keypair) -> CapabilityToken {
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };
    admin
        .kernel()
        .issue_capability(&agent.public_key(), scope, 300)
        .expect("issue capability")
}

fn make_request(id: &str, cap: &CapabilityToken) -> ToolCallRequest {
    ToolCallRequest {
        request_id: id.to_string(),
        capability: cap.clone(),
        tool_name: "read_file".to_string(),
        server_id: "srv-a".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: serde_json::json!({"path": "/tmp/hello"}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

#[test]
fn route_constants_match_spec() {
    assert_eq!(EMERGENCY_STOP_PATH, "/emergency-stop");
    assert_eq!(EMERGENCY_RESUME_PATH, "/emergency-resume");
    assert_eq!(EMERGENCY_STATUS_PATH, "/emergency-status");
    assert_eq!(EMERGENCY_ADMIN_TOKEN_HEADER, "X-Admin-Token");
}

#[tokio::test]
async fn stop_then_evaluate_returns_deny() {
    let admin = admin(build_kernel());
    let agent = Keypair::generate();
    let cap = issue_capability(&admin, &agent);

    // Baseline allow.
    let allow_response = admin
        .kernel()
        .evaluate_tool_call(&make_request("baseline", &cap))
        .await
        .expect("baseline evaluate");
    assert_eq!(allow_response.verdict, KernelVerdict::Allow);

    // POST /emergency-stop with a valid body engages the switch.
    let body = serde_json::to_vec(&serde_json::json!({"reason": "drill"})).unwrap();
    let response =
        handle_emergency_stop(&admin, Some(ADMIN_TOKEN), &body).expect("stop should succeed");
    assert!(response.stopped);

    // Now every evaluate must deny with the emergency reason.
    let denied = admin
        .kernel()
        .evaluate_tool_call(&make_request("after-stop", &cap))
        .await
        .expect("post-stop evaluate");
    assert_eq!(denied.verdict, KernelVerdict::Deny);
    assert_eq!(denied.reason.as_deref(), Some(EMERGENCY_STOP_DENY_REASON));
}

#[tokio::test]
async fn resume_restores_normal_operation() {
    let admin = admin(build_kernel());
    let agent = Keypair::generate();
    let cap = issue_capability(&admin, &agent);

    let body = serde_json::to_vec(&serde_json::json!({"reason": "drill"})).unwrap();
    handle_emergency_stop(&admin, Some(ADMIN_TOKEN), &body).expect("stop");
    let denied = admin
        .kernel()
        .evaluate_tool_call(&make_request("req-stopped", &cap))
        .await
        .expect("evaluate while stopped");
    assert_eq!(denied.verdict, KernelVerdict::Deny);

    let resume =
        handle_emergency_resume(&admin, Some(ADMIN_TOKEN), b"").expect("resume should succeed");
    assert!(!resume.stopped);

    let allow = admin
        .kernel()
        .evaluate_tool_call(&make_request("req-resumed", &cap))
        .await
        .expect("evaluate after resume");
    assert_eq!(allow.verdict, KernelVerdict::Allow);
}

#[test]
fn missing_admin_token_returns_unauthorized() {
    let admin = admin(build_kernel());

    let body = serde_json::to_vec(&serde_json::json!({"reason": "x"})).unwrap();
    let error = handle_emergency_stop(&admin, None, &body).expect_err("missing token must fail");
    assert_eq!(error.status(), 401);
    assert_eq!(error, EmergencyHandlerError::Unauthorized);

    // The kernel MUST still be running: unauthorized callers cannot
    // trip the kill switch.
    assert!(!admin.kernel().is_emergency_stopped());

    let wrong =
        handle_emergency_resume(&admin, Some("wrong"), b"").expect_err("wrong token must fail");
    assert_eq!(wrong.status(), 401);

    let status_unauth =
        handle_emergency_status(&admin, None).expect_err("status requires auth too");
    assert_eq!(status_unauth.status(), 401);
}

#[test]
fn bad_request_body_returns_400_and_does_not_flip_kernel() {
    let admin = admin(build_kernel());

    let error = handle_emergency_stop(&admin, Some(ADMIN_TOKEN), b"not-json")
        .expect_err("garbled body must fail");
    assert_eq!(error.status(), 400);
    assert!(matches!(error, EmergencyHandlerError::BadRequest(_)));
    // Fail-closed invariant for bad requests: kernel stays in its
    // previous state. Parsing errors out BEFORE we touch the kernel,
    // so the switch remains disengaged.
    assert!(!admin.kernel().is_emergency_stopped());
}

#[test]
fn status_reports_stopped_state_and_reason() {
    let admin = admin(build_kernel());

    // Before any stop the status is minimal.
    let status: EmergencyStatusResponse =
        handle_emergency_status(&admin, Some(ADMIN_TOKEN)).expect("status pre-stop");
    assert!(!status.stopped);
    assert!(status.since.is_none());
    assert!(status.reason.is_none());

    // Engage the switch with a specific reason.
    let body = serde_json::to_vec(&serde_json::json!({
        "reason": "compromised agent detected in production"
    }))
    .unwrap();
    handle_emergency_stop(&admin, Some(ADMIN_TOKEN), &body).expect("stop");

    let status = handle_emergency_status(&admin, Some(ADMIN_TOKEN)).expect("status post-stop");
    assert!(status.stopped);
    assert_eq!(
        status.reason.as_deref(),
        Some("compromised agent detected in production")
    );
    let since = status.since.expect("since timestamp present when stopped");
    // Should parse as a RFC 3339 timestamp with a timezone suffix.
    assert!(
        since.ends_with("+00:00") || since.ends_with('Z'),
        "since should be a UTC RFC 3339 timestamp, got {since}"
    );

    // After resume, status clears.
    handle_emergency_resume(&admin, Some(ADMIN_TOKEN), b"").expect("resume");
    let status = handle_emergency_status(&admin, Some(ADMIN_TOKEN)).expect("status post-resume");
    assert!(!status.stopped);
    assert!(status.since.is_none());
    assert!(status.reason.is_none());
}

#[test]
fn resume_ignores_body_bytes() {
    let admin = admin(build_kernel());

    // Stop first so resume has something to do.
    let body = serde_json::to_vec(&serde_json::json!({"reason": "x"})).unwrap();
    handle_emergency_stop(&admin, Some(ADMIN_TOKEN), &body).expect("stop");

    // Any body should work for resume, including JSON noise.
    let resume = handle_emergency_resume(
        &admin,
        Some(ADMIN_TOKEN),
        br#"{"this":"is","ignored":true}"#,
    )
    .expect("resume with body");
    assert!(!resume.stopped);
    assert!(!admin.kernel().is_emergency_stopped());
}

#[test]
fn error_body_is_stable_json_shape() {
    let admin = admin(build_kernel());

    let unauth = handle_emergency_status(&admin, Some("wrong-token")).expect_err("wrong token");
    let payload = unauth.body();
    assert_eq!(payload["error"], "unauthorized");
    assert!(payload["message"].as_str().is_some_and(|m| !m.is_empty()));

    let bad_body = handle_emergency_stop(&admin, Some(ADMIN_TOKEN), b"x").expect_err("bad body");
    let payload = bad_body.body();
    assert_eq!(payload["error"], "bad_request");
}
