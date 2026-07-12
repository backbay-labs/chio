//! HTTP-surface tests for `POST /evaluate-plan`.
//!
//! `chio-http-core` does not embed an HTTP server, so these tests
//! exercise the substrate-independent `handle_evaluate_plan` function
//! directly. Each test pairs the handler with a real `ChioKernel` so
//! the "HTTP body in -> kernel evaluates -> JSON response out" flow is
//! covered end-to-end without spinning up a framework server.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use chio_core_types::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::CapabilityToken,
};
use chio_core_types::crypto::Keypair;
use chio_core_types::{
    PlanEvaluationRequest, PlanEvaluationResponse, PlanVerdict, PlannedToolCall, StepVerdictKind,
};
use chio_http_core::{handle_evaluate_plan, PlanHandlerError, EVALUATE_PLAN_PATH};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ServerId, ToolServerConnection,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};

struct EchoServer {
    id: ServerId,
    tools: Vec<String>,
}

#[async_trait::async_trait]
impl ToolServerConnection for EchoServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        if !self.tools.iter().any(|t| t == tool_name) {
            return Err(KernelError::Internal(format!(
                "unexpected tool {tool_name}"
            )));
        }
        Ok(arguments)
    }
}

fn build_kernel(tools: &[&str]) -> Arc<ChioKernel> {
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 4,
        policy_hash: "http-plan-test-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    });
    kernel.register_tool_server(Box::new(EchoServer {
        id: "srv-a".to_string(),
        tools: tools.iter().map(|t| (*t).to_string()).collect(),
    }));
    Arc::new(kernel)
}

fn issue_capability(kernel: &Arc<ChioKernel>, agent: &Keypair, tools: &[&str]) -> CapabilityToken {
    let grants: Vec<ToolGrant> = tools
        .iter()
        .map(|tool| ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: (*tool).to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        })
        .collect();
    let scope = ChioScope {
        grants,
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };
    kernel
        .issue_capability(&agent.public_key(), scope, 300)
        .expect("issue capability")
}

fn planned_call(request_id: &str, tool: &str, params: serde_json::Value) -> PlannedToolCall {
    PlannedToolCall {
        request_id: request_id.to_string(),
        server_id: "srv-a".to_string(),
        tool_name: tool.to_string(),
        action: None,
        parameters: params,
        model_metadata: None,
        dependencies: Vec::new(),
    }
}

#[test]
fn route_path_is_stable() {
    assert_eq!(EVALUATE_PLAN_PATH, "/evaluate-plan");
}

/// A 3-step plan where step 3 is out-of-scope returns
/// `plan_verdict: PartiallyDenied` with step 3 flagged, before any tool
/// executes.
#[test]
fn three_step_plan_with_step_three_out_of_scope_returns_partially_denied() {
    let kernel = build_kernel(&["read_file", "write_file", "delete_file"]);
    let agent = Keypair::generate();
    // Grant only read_file + write_file; delete_file is intentionally
    // missing so step 3 must be denied.
    let cap = issue_capability(&kernel, &agent, &["read_file", "write_file"]);

    let request = PlanEvaluationRequest {
        plan_id: "plan-acceptance".to_string(),
        planner_capability_id: cap.id.clone(),
        planner_capability: cap.clone(),
        agent_id: cap.subject.to_hex(),
        steps: vec![
            planned_call("step-1", "read_file", serde_json::json!({"path": "/tmp/a"})),
            planned_call(
                "step-2",
                "write_file",
                serde_json::json!({"path": "/tmp/b", "contents": "hi"}),
            ),
            planned_call(
                "step-3",
                "delete_file",
                serde_json::json!({"path": "/tmp/c"}),
            ),
        ],
    };

    let body = serde_json::to_vec(&request).expect("serialize plan request");
    let response = handle_evaluate_plan(&kernel, &body).expect("handler returns Ok");

    assert_eq!(response.plan_id, "plan-acceptance");
    assert_eq!(response.plan_verdict, PlanVerdict::PartiallyDenied);
    assert_eq!(response.step_verdicts.len(), 3);

    assert_eq!(response.step_verdicts[0].step_index, 0);
    assert_eq!(response.step_verdicts[0].verdict, StepVerdictKind::Allowed);

    assert_eq!(response.step_verdicts[1].step_index, 1);
    assert_eq!(response.step_verdicts[1].verdict, StepVerdictKind::Allowed);

    // Step 3 (the third step, index 2) must be flagged denied with a
    // scope-related reason.
    assert_eq!(response.step_verdicts[2].step_index, 2);
    assert_eq!(response.step_verdicts[2].verdict, StepVerdictKind::Denied);
    let step3_reason = response.step_verdicts[2]
        .reason
        .as_deref()
        .unwrap_or_default();
    assert!(
        step3_reason.contains("not in capability scope"),
        "step 3 should cite scope; got {step3_reason:?}",
    );
}

#[test]
fn full_allow_plan_round_trips_through_serde() {
    let kernel = build_kernel(&["read_file", "write_file"]);
    let agent = Keypair::generate();
    let cap = issue_capability(&kernel, &agent, &["read_file", "write_file"]);

    let request = PlanEvaluationRequest {
        plan_id: "plan-happy".to_string(),
        planner_capability_id: cap.id.clone(),
        planner_capability: cap.clone(),
        agent_id: cap.subject.to_hex(),
        steps: vec![
            planned_call("a", "read_file", serde_json::json!({"path": "/tmp/a"})),
            planned_call(
                "b",
                "write_file",
                serde_json::json!({"path": "/tmp/b", "contents": "x"}),
            ),
        ],
    };

    let body = serde_json::to_vec(&request).expect("serialize");
    let response = handle_evaluate_plan(&kernel, &body).expect("ok");

    // Re-serialize / deserialize to ensure the response wire shape is
    // stable and the enum variants round-trip.
    let json = serde_json::to_value(&response).expect("serialize response");
    assert_eq!(json["plan_id"], "plan-happy");
    assert_eq!(json["plan_verdict"], "allowed");
    let steps = json["step_verdicts"]
        .as_array()
        .expect("step_verdicts array");
    assert_eq!(steps.len(), 2);
    for step in steps {
        assert_eq!(step["verdict"], "allowed");
        // `reason` and `guard` are omitted on allow (`skip_serializing_if`).
        assert!(step.get("reason").is_none());
        assert!(step.get("guard").is_none());
    }

    // A full round-trip back into the Rust type should preserve shape.
    let decoded: PlanEvaluationResponse =
        serde_json::from_value(json).expect("deserialize response");
    assert_eq!(decoded.plan_verdict, PlanVerdict::Allowed);
}

#[test]
fn malformed_body_returns_bad_request() {
    let kernel = build_kernel(&["read_file"]);

    let error = handle_evaluate_plan(&kernel, b"not-json").expect_err("garbled body must fail");
    assert_eq!(error.status(), 400);
    assert!(matches!(error, PlanHandlerError::BadRequest(_)));

    let body = error.body();
    assert_eq!(body["error"], "bad_request");
    assert!(body["message"].as_str().is_some_and(|m| !m.is_empty()));
}

#[test]
fn empty_plan_is_allowed_with_no_step_verdicts() {
    let kernel = build_kernel(&["read_file"]);
    let agent = Keypair::generate();
    let cap = issue_capability(&kernel, &agent, &["read_file"]);

    let request = PlanEvaluationRequest {
        plan_id: "plan-empty".to_string(),
        planner_capability_id: cap.id.clone(),
        planner_capability: cap.clone(),
        agent_id: cap.subject.to_hex(),
        steps: Vec::new(),
    };

    let body = serde_json::to_vec(&request).expect("serialize");
    let response = handle_evaluate_plan(&kernel, &body).expect("ok");
    assert_eq!(response.plan_verdict, PlanVerdict::Allowed);
    assert!(response.step_verdicts.is_empty());
}

#[test]
fn endpoint_returns_ok_even_when_every_step_is_denied() {
    let kernel = build_kernel(&["read_file"]);
    let agent = Keypair::generate();
    // Issue a capability that does NOT grant the tool referenced by the
    // plan; every step will be denied. The handler must still return
    // Ok (200) with the denial expressed in the JSON.
    let cap = issue_capability(&kernel, &agent, &["read_file"]);

    let request = PlanEvaluationRequest {
        plan_id: "plan-all-denied".to_string(),
        planner_capability_id: cap.id.clone(),
        planner_capability: cap.clone(),
        agent_id: cap.subject.to_hex(),
        steps: vec![
            planned_call("x", "delete_file", serde_json::json!({"path": "/tmp/x"})),
            planned_call("y", "delete_file", serde_json::json!({"path": "/tmp/y"})),
        ],
    };

    let body = serde_json::to_vec(&request).expect("serialize");
    let response = handle_evaluate_plan(&kernel, &body).expect("ok");
    assert_eq!(response.plan_verdict, PlanVerdict::FullyDenied);
    assert_eq!(response.step_verdicts.len(), 2);
    for step in &response.step_verdicts {
        assert_eq!(step.verdict, StepVerdictKind::Denied);
    }
}
