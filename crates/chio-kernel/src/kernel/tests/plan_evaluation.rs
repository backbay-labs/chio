// Phase 2.4 plan-level evaluation tests.
//
// Included by `src/kernel/tests.rs`. Inherits `super::*` plus the
// helpers defined at the top of `tests/all.rs` (`make_config`,
// `make_keypair`, `make_capability`, `make_scope`, `make_grant`,
// `EchoServer`, etc.).

use chio_core_types::capability::ModelSafetyTier;
use chio_core_types::{
    PlanEvaluationRequest, PlanVerdict, PlannedToolCall, StepVerdictKind,
};

fn planned_call(
    request_id: &str,
    server: &str,
    tool: &str,
    params: serde_json::Value,
) -> PlannedToolCall {
    PlannedToolCall {
        request_id: request_id.to_string(),
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        action: None,
        parameters: params,
        model_metadata: None,
        dependencies: Vec::new(),
    }
}

/// All three steps resolve to grants in the capability scope and pass
/// the guard pipeline: the aggregate verdict is `Allowed` and every
/// step is reported allowed individually.
#[test]
fn plan_evaluation_all_steps_allowed() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-a",
        vec!["read_file", "write_file", "list_dir"],
    )));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![
        make_grant("srv-a", "read_file"),
        make_grant("srv-a", "write_file"),
        make_grant("srv-a", "list_dir"),
    ]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let request = PlanEvaluationRequest {
        plan_id: "plan-happy".to_string(),
        planner_capability_id: cap.id.clone(),
        planner_capability: cap.clone(),
        agent_id: cap.subject.to_hex(),
        steps: vec![
            planned_call(
                "step-1",
                "srv-a",
                "read_file",
                serde_json::json!({"path": "/tmp/a"}),
            ),
            planned_call(
                "step-2",
                "srv-a",
                "write_file",
                serde_json::json!({"path": "/tmp/b", "contents": "hi"}),
            ),
            planned_call(
                "step-3",
                "srv-a",
                "list_dir",
                serde_json::json!({"path": "/tmp"}),
            ),
        ],
    };

    let response = kernel.evaluate_plan_blocking(&request);
    assert_eq!(response.plan_id, "plan-happy");
    assert_eq!(response.plan_verdict, PlanVerdict::Allowed);
    assert_eq!(response.step_verdicts.len(), 3);
    for (index, verdict) in response.step_verdicts.iter().enumerate() {
        assert_eq!(verdict.step_index, index);
        assert_eq!(
            verdict.verdict,
            StepVerdictKind::Allowed,
            "step {index} should be allowed, got reason: {:?}",
            verdict.reason,
        );
        assert!(verdict.reason.is_none());
        assert!(verdict.guard.is_none());
    }
}

/// Middle step targets a tool not in the capability scope. The plan
/// returns `PartiallyDenied` with the middle step flagged denied and
/// the other two allowed.
///
/// This is the roadmap acceptance test, shifted to `step 2` (index 1)
/// rather than `step 3` so both preceding and succeeding steps are
/// exercised; the HTTP end-to-end test covers the literal step-3 case.
#[test]
fn plan_evaluation_middle_step_out_of_scope() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-a",
        vec!["read_file", "write_file"],
    )));

    let agent_kp = make_keypair();
    // Grant read_file and list_dir only; write_file is out of scope.
    let scope = make_scope(vec![
        make_grant("srv-a", "read_file"),
        make_grant("srv-a", "list_dir"),
    ]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let request = PlanEvaluationRequest {
        plan_id: "plan-middle-deny".to_string(),
        planner_capability_id: cap.id.clone(),
        planner_capability: cap.clone(),
        agent_id: cap.subject.to_hex(),
        steps: vec![
            planned_call(
                "step-1",
                "srv-a",
                "read_file",
                serde_json::json!({"path": "/tmp/a"}),
            ),
            planned_call(
                "step-2",
                "srv-a",
                "write_file",
                serde_json::json!({"path": "/tmp/b", "contents": "hi"}),
            ),
            planned_call(
                "step-3",
                "srv-a",
                "list_dir",
                serde_json::json!({"path": "/tmp"}),
            ),
        ],
    };

    let response = kernel.evaluate_plan_blocking(&request);
    assert_eq!(response.plan_verdict, PlanVerdict::PartiallyDenied);
    assert_eq!(response.step_verdicts.len(), 3);
    assert_eq!(response.step_verdicts[0].verdict, StepVerdictKind::Allowed);
    assert_eq!(response.step_verdicts[1].verdict, StepVerdictKind::Denied);
    assert!(
        response.step_verdicts[1]
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("not in capability scope"),
        "unexpected deny reason: {:?}",
        response.step_verdicts[1].reason,
    );
    assert_eq!(response.step_verdicts[2].verdict, StepVerdictKind::Allowed);
}

/// First step is out of scope; subsequent steps are still evaluated
/// INDEPENDENTLY -- the kernel does not short-circuit downstream steps
/// based on earlier failures. An out-of-scope first step returns a
/// per-step deny with its own reason and the other two steps return
/// their own independent verdicts.
#[test]
fn plan_evaluation_first_step_denied_does_not_short_circuit() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-a",
        vec!["read_file", "write_file"],
    )));

    let agent_kp = make_keypair();
    // Only write_file is granted; step 1 (read_file) is denied, but
    // steps 2 and 3 (write_file, write_file) should be allowed.
    let scope = make_scope(vec![make_grant("srv-a", "write_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let request = PlanEvaluationRequest {
        plan_id: "plan-first-deny".to_string(),
        planner_capability_id: cap.id.clone(),
        planner_capability: cap.clone(),
        agent_id: cap.subject.to_hex(),
        steps: vec![
            planned_call(
                "step-1",
                "srv-a",
                "read_file",
                serde_json::json!({"path": "/tmp/a"}),
            ),
            planned_call(
                "step-2",
                "srv-a",
                "write_file",
                serde_json::json!({"path": "/tmp/b", "contents": "hi"}),
            ),
            planned_call(
                "step-3",
                "srv-a",
                "write_file",
                serde_json::json!({"path": "/tmp/c", "contents": "bye"}),
            ),
        ],
    };

    let response = kernel.evaluate_plan_blocking(&request);
    assert_eq!(response.plan_verdict, PlanVerdict::PartiallyDenied);
    assert_eq!(response.step_verdicts[0].verdict, StepVerdictKind::Denied);
    assert!(
        response.step_verdicts[0]
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("not in capability scope"),
        "step 1 deny reason should cite scope: {:?}",
        response.step_verdicts[0].reason,
    );
    assert_eq!(response.step_verdicts[1].verdict, StepVerdictKind::Allowed);
    assert_eq!(response.step_verdicts[2].verdict, StepVerdictKind::Allowed);
}

/// Each step carries its own model metadata and each grant has its own
/// ModelConstraint. Plan evaluation scopes the model metadata per-step
/// (not per-plan), so a plan that mixes a permitted model and a
/// disallowed model returns a partial denial keyed to the specific
/// step that submitted the wrong model.
#[test]
fn plan_evaluation_model_metadata_scoped_per_step() {
    use chio_core::capability::{
        ChioScope, Constraint, ModelMetadata, Operation, ToolGrant,
    };

    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-a",
        vec!["sensitive_read", "casual_read"],
    )));

    let agent_kp = make_keypair();

    let restricted_grant = ToolGrant {
        server_id: "srv-a".to_string(),
        tool_name: "sensitive_read".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![Constraint::ModelConstraint {
            allowed_model_ids: vec![],
            min_safety_tier: Some(ModelSafetyTier::High),
        }],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    let permissive_grant = ToolGrant {
        server_id: "srv-a".to_string(),
        tool_name: "casual_read".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    let scope = ChioScope {
        grants: vec![restricted_grant, permissive_grant],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    // Step 1: sensitive_read called under a high-tier model => allowed.
    // Step 2: sensitive_read called under a low-tier model => denied.
    // Step 3: casual_read called with no model metadata and no model
    //         constraint => allowed.
    let high_tier = ModelMetadata {
        model_id: "claude-opus-4".to_string(),
        safety_tier: Some(ModelSafetyTier::High),
        provider: Some("anthropic".to_string()),
        provenance_class: chio_core::capability::ProvenanceEvidenceClass::Asserted,
    };
    let low_tier = ModelMetadata {
        model_id: "small-uncensored".to_string(),
        safety_tier: Some(ModelSafetyTier::Low),
        provider: None,
        provenance_class: chio_core::capability::ProvenanceEvidenceClass::Asserted,
    };

    let steps = vec![
        PlannedToolCall {
            request_id: "step-1".to_string(),
            server_id: "srv-a".to_string(),
            tool_name: "sensitive_read".to_string(),
            action: Some("read".to_string()),
            parameters: serde_json::json!({"path": "/secret"}),
            model_metadata: Some(high_tier),
            dependencies: Vec::new(),
        },
        PlannedToolCall {
            request_id: "step-2".to_string(),
            server_id: "srv-a".to_string(),
            tool_name: "sensitive_read".to_string(),
            action: Some("read".to_string()),
            parameters: serde_json::json!({"path": "/secret"}),
            model_metadata: Some(low_tier),
            dependencies: Vec::new(),
        },
        PlannedToolCall {
            request_id: "step-3".to_string(),
            server_id: "srv-a".to_string(),
            tool_name: "casual_read".to_string(),
            action: None,
            parameters: serde_json::json!({"path": "/public"}),
            model_metadata: None,
            dependencies: Vec::new(),
        },
    ];

    let request = PlanEvaluationRequest {
        plan_id: "plan-model-mix".to_string(),
        planner_capability_id: cap.id.clone(),
        planner_capability: cap.clone(),
        agent_id: cap.subject.to_hex(),
        steps,
    };

    let response = kernel.evaluate_plan_blocking(&request);
    assert_eq!(response.plan_verdict, PlanVerdict::PartiallyDenied);
    assert_eq!(
        response.step_verdicts[0].verdict,
        StepVerdictKind::Allowed,
        "high-tier model should satisfy ModelConstraint",
    );
    assert_eq!(
        response.step_verdicts[1].verdict,
        StepVerdictKind::Denied,
        "low-tier model should fail ModelConstraint",
    );
    assert_eq!(
        response.step_verdicts[2].verdict,
        StepVerdictKind::Allowed,
        "unconstrained tool with no metadata should still be allowed",
    );
}

/// Mismatch between `planner_capability_id` and the embedded token's id
/// is a fatal pre-check: every step is flagged denied with the same
/// mismatch reason.
#[test]
fn plan_evaluation_capability_id_mismatch_denies_every_step() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let request = PlanEvaluationRequest {
        plan_id: "plan-mismatch".to_string(),
        planner_capability_id: "not-the-real-id".to_string(),
        planner_capability: cap.clone(),
        agent_id: cap.subject.to_hex(),
        steps: vec![planned_call(
            "step-1",
            "srv-a",
            "read_file",
            serde_json::json!({"path": "/tmp/a"}),
        )],
    };

    let response = kernel.evaluate_plan_blocking(&request);
    assert_eq!(response.plan_verdict, PlanVerdict::FullyDenied);
    assert_eq!(response.step_verdicts.len(), 1);
    assert_eq!(response.step_verdicts[0].verdict, StepVerdictKind::Denied);
    assert!(
        response.step_verdicts[0]
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("does not match embedded token id"),
        "unexpected deny reason: {:?}",
        response.step_verdicts[0].reason,
    );
}

/// When the kernel is in emergency stop, every step denies with the
/// canonical stop reason regardless of scope.
#[test]
fn plan_evaluation_denies_all_steps_when_kernel_stopped() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    kernel.emergency_stop("drill").unwrap();

    let request = PlanEvaluationRequest {
        plan_id: "plan-during-stop".to_string(),
        planner_capability_id: cap.id.clone(),
        planner_capability: cap.clone(),
        agent_id: cap.subject.to_hex(),
        steps: vec![
            planned_call(
                "step-1",
                "srv-a",
                "read_file",
                serde_json::json!({"path": "/tmp/a"}),
            ),
            planned_call(
                "step-2",
                "srv-a",
                "read_file",
                serde_json::json!({"path": "/tmp/b"}),
            ),
        ],
    };

    let response = kernel.evaluate_plan_blocking(&request);
    assert_eq!(response.plan_verdict, PlanVerdict::FullyDenied);
    assert_eq!(response.step_verdicts.len(), 2);
    for verdict in &response.step_verdicts {
        assert_eq!(verdict.verdict, StepVerdictKind::Denied);
        assert_eq!(verdict.reason.as_deref(), Some(EMERGENCY_STOP_DENY_REASON));
    }
}
