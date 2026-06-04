//! The test runs the production emission path on each edge (not just a
//! constant reference) and then scrapes the per-edge Prometheus body to
//! assert (a) the registry-keyed metric name is present and (b) the
//! production-exercised sample count is non-zero. A registry constant
//! referenced in source code but never emitted at runtime would fail the
//! count check, which is exactly the gap T1.5 left open.

use std::collections::HashMap;
use std::error::Error;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::{
    CapabilityToken, CapabilityTokenBody, ChioScope, Operation, ToolGrant,
};
use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, GuardEvidence, ToolCallAction};
use chio_core::session::OperationTerminalState;
use chio_core::{sha256_hex, Hash, Keypair};
use chio_manifest::{ToolDefinition, ToolManifest};
use chio_metrics_spec::{
    is_registered_metric, CHIO_ANCHOR_ROUND_LATENCY_SECONDS, CHIO_FEDERATION_HOP_LATENCY_SECONDS,
    CHIO_FEDERATION_HOP_TOTAL, CHIO_GUARD_EVALUATIONS_TOTAL, CHIO_KERNEL_DECISION_LATENCY_SECONDS,
    CHIO_RECEIPT_WRITE_TOTAL,
};
use chio_wasm_guards::{
    register_guard_pool_metric_families, GuardRequest, WasmGuardAbi, GUARD_POOL_METRIC_FAMILIES,
    METRIC_CHIO_GUARD_POOL_CHECKOUT_TOTAL, METRIC_CHIO_GUARD_POOL_EVICT_TOTAL,
    METRIC_CHIO_GUARD_POOL_WARM_SIZE,
};
use serde_json::{json, Value};

static RECEIPT_METRICS_TEST_LOCK: Mutex<()> = Mutex::new(());

struct MetricsToolServer;

#[async_trait::async_trait]
impl chio_kernel::ToolServerConnection for MetricsToolServer {
    fn server_id(&self) -> &str {
        "metrics-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["echo".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, chio_kernel::KernelError> {
        Ok(json!({
            "result": "ok",
            "arguments": arguments,
        }))
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn metrics_kernel_with_web3_evidence(
    require_web3_evidence: bool,
) -> (chio_kernel::ChioKernel, Keypair) {
    let keypair = Keypair::generate();
    let config = chio_kernel::KernelConfig {
        ca_public_keys: vec![keypair.public_key()],
        keypair: keypair.clone(),
        max_delegation_depth: 8,
        policy_hash: "metrics-registry-test-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        allow_ephemeral_receipt_log: true,
    };
    let mut kernel = chio_kernel::ChioKernel::new(config);
    kernel.register_tool_server(Box::new(MetricsToolServer));
    (kernel, keypair)
}

fn metrics_kernel() -> (chio_kernel::ChioKernel, Keypair) {
    metrics_kernel_with_web3_evidence(false)
}

fn metrics_manifest() -> ToolManifest {
    metrics_manifest_with_schema(json!({"type": "object"}))
}

fn mcp_target_metrics_manifest() -> ToolManifest {
    metrics_manifest_with_schema(json!({
        "type": "object",
        "x-chio-target-protocol": "mcp"
    }))
}

fn metrics_manifest_with_schema(input_schema: Value) -> ToolManifest {
    ToolManifest {
        schema: "chio.manifest.v1".to_string(),
        server_id: "metrics-srv".to_string(),
        name: "Metrics Test Server".to_string(),
        description: Some("Metrics conformance fixture".to_string()),
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "echo".to_string(),
            description: "Echo input".to_string(),
            input_schema,
            output_schema: None,
            pricing: None,
            has_side_effects: false,
            latency_hint: None,
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: Keypair::from_seed(&[42u8; 32]).public_key().to_hex(),
    }
}

fn receipt_metrics_test_guard() -> Result<MutexGuard<'static, ()>, Box<dyn Error>> {
    RECEIPT_METRICS_TEST_LOCK
        .lock()
        .map_err(|_| "receipt metrics test lock poisoned".into())
}

fn prometheus_counter_sample(
    body: &str,
    metric_name: &str,
    outcome: &str,
) -> Result<u64, Box<dyn Error>> {
    let prefix = format!("{metric_name}{{outcome=\"{outcome}\"}} ");
    for line in body.lines() {
        if let Some(value) = line.strip_prefix(&prefix) {
            return value.trim().parse::<u64>().map_err(|error| {
                format!("invalid Prometheus sample for {prefix}: {error}").into()
            });
        }
    }
    Err(format!("missing Prometheus sample for {prefix}").into())
}

fn assert_prometheus_counter_sample(
    body: &str,
    outcome: &str,
    expected: u64,
) -> Result<(), Box<dyn Error>> {
    let sample = prometheus_counter_sample(body, CHIO_RECEIPT_WRITE_TOTAL, outcome)?;
    assert_eq!(
        sample, expected,
        "Prometheus sample for outcome {outcome} must match the in-process counter"
    );
    assert!(
        sample > 0,
        "Prometheus sample for outcome {outcome} must be non-zero after synthetic load"
    );
    Ok(())
}

fn capability_for_tool(
    issuer: &Keypair,
    subject: &Keypair,
) -> Result<CapabilityToken, chio_core::Error> {
    let now = unix_now();
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-metrics-srv-echo".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "metrics-srv".to_string(),
                    tool_name: "echo".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            issued_at: now.saturating_sub(30),
            expires_at: now + 300,
            delegation_chain: Vec::new(),
        },
        issuer,
    )
}

fn sample_receipt(keypair: &Keypair) -> Result<ChioReceipt, chio_core::Error> {
    let body = ChioReceiptBody {
        id: "rcpt-metrics-federation".to_string(),
        timestamp: unix_now(),
        capability_id: "cap-metrics-srv-echo".to_string(),
        tool_server: "metrics-srv".to_string(),
        tool_name: "echo".to_string(),
        action: ToolCallAction::from_parameters(json!({"message": "hello"}))?,
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: sha256_hex(br#"{"result":"ok"}"#),
        policy_hash: "metrics-registry-test-policy".to_string(),
        evidence: vec![GuardEvidence {
            guard_name: "MetricsConformanceGuard".to_string(),
            verdict: true,
            details: None,
        }],
        metadata: None,
        trust_level: Default::default(),
        tenant_id: None,
        kernel_key: keypair.public_key(),
    };
    ChioReceipt::sign(body, keypair)
}

fn guard_request(agent_id: &str) -> GuardRequest {
    GuardRequest {
        tool_name: "echo".to_string(),
        server_id: "metrics-srv".to_string(),
        agent_id: agent_id.to_string(),
        arguments: json!({"message": "hello"}),
        scopes: vec!["metrics-srv:echo".to_string()],
        action_type: None,
        extracted_path: None,
        extracted_target: None,
        filesystem_roots: Vec::new(),
        matched_grant_index: None,
    }
}

#[test]
fn registry_constants_are_registered_in_spec() {
    for name in [
        CHIO_RECEIPT_WRITE_TOTAL,
        CHIO_GUARD_EVALUATIONS_TOTAL,
        CHIO_KERNEL_DECISION_LATENCY_SECONDS,
        CHIO_ANCHOR_ROUND_LATENCY_SECONDS,
        CHIO_FEDERATION_HOP_TOTAL,
        CHIO_FEDERATION_HOP_LATENCY_SECONDS,
        METRIC_CHIO_GUARD_POOL_CHECKOUT_TOTAL,
        METRIC_CHIO_GUARD_POOL_WARM_SIZE,
        METRIC_CHIO_GUARD_POOL_EVICT_TOTAL,
    ] {
        assert!(
            is_registered_metric(name),
            "expected {name} to live in the chio-metrics-spec registry"
        );
    }
}

#[test]
fn mcp_edge_emits_chio_receipt_write_total() -> Result<(), Box<dyn Error>> {
    let _metrics_guard = receipt_metrics_test_guard()?;
    let (kernel, issuer) = metrics_kernel();
    let agent = Keypair::generate();
    let before = chio_mcp_edge::receipt_write_total(chio_mcp_edge::RECEIPT_WRITE_OUTCOME_ALLOW);

    let bridge = chio_mcp_edge::execute_bridge_mcp_tool_call(
        &kernel,
        chio_mcp_edge::BridgeMcpToolCallRequest {
            request_id: "metrics-mcp-1".to_string(),
            capability: capability_for_tool(&issuer, &agent)?,
            server_id: "metrics-srv".to_string(),
            tool_name: "echo".to_string(),
            arguments: json!({"message": "hello"}),
            agent_id: agent.public_key().to_hex(),
            model_metadata: None,
            route_selection_metadata: None,
            peer_supports_chio_tool_streaming: false,
        },
    )?;

    assert!(matches!(
        bridge.response.verdict,
        chio_kernel::Verdict::Allow
    ));
    let after = chio_mcp_edge::receipt_write_total(chio_mcp_edge::RECEIPT_WRITE_OUTCOME_ALLOW);
    assert!(
        after > before,
        "mcp edge counter must advance through execute_bridge_mcp_tool_call"
    );

    let before_pending =
        chio_mcp_edge::receipt_write_total(chio_mcp_edge::RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL);
    let mut pending_response = bridge.response;
    pending_response.verdict = chio_kernel::Verdict::PendingApproval;
    pending_response.output = None;
    pending_response.reason = Some("approval required".to_string());
    pending_response.terminal_state = OperationTerminalState::Incomplete {
        reason: "approval required".to_string(),
    };
    let pending_projection = chio_mcp_edge::BridgeMcpToolCall::from_kernel_response(
        pending_response,
        "metrics-mcp-pending-1",
        false,
    )?;
    assert!(matches!(
        pending_projection.response.verdict,
        chio_kernel::Verdict::PendingApproval
    ));
    assert!(
        chio_mcp_edge::receipt_write_total(chio_mcp_edge::RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL)
            > before_pending,
        "mcp edge pending approval counter must advance as a distinct normal outcome"
    );

    let (error_kernel, error_issuer) = metrics_kernel_with_web3_evidence(true);
    let error_agent = Keypair::generate();
    let before_error =
        chio_mcp_edge::receipt_write_total(chio_mcp_edge::RECEIPT_WRITE_OUTCOME_ERROR);
    let error_result = chio_mcp_edge::execute_bridge_mcp_tool_call(
        &error_kernel,
        chio_mcp_edge::BridgeMcpToolCallRequest {
            request_id: "metrics-mcp-error-1".to_string(),
            capability: capability_for_tool(&error_issuer, &error_agent)?,
            server_id: "metrics-srv".to_string(),
            tool_name: "echo".to_string(),
            arguments: json!({"message": "hello"}),
            agent_id: error_agent.public_key().to_hex(),
            model_metadata: None,
            route_selection_metadata: None,
            peer_supports_chio_tool_streaming: false,
        },
    );
    assert!(error_result.is_err());
    assert!(
        chio_mcp_edge::receipt_write_total(chio_mcp_edge::RECEIPT_WRITE_OUTCOME_ERROR)
            > before_error,
        "mcp edge kernel error path must advance receipt write error"
    );

    let body = chio_mcp_edge::render_mcp_edge_metrics_prometheus();
    assert!(body.contains(CHIO_RECEIPT_WRITE_TOTAL));
    assert!(body.contains("outcome=\"allow\""));
    assert!(body.contains("outcome=\"pending_approval\""));
    assert!(body.contains("outcome=\"error\""));
    assert_prometheus_counter_sample(
        &body,
        chio_mcp_edge::RECEIPT_WRITE_OUTCOME_ALLOW,
        chio_mcp_edge::receipt_write_total(chio_mcp_edge::RECEIPT_WRITE_OUTCOME_ALLOW),
    )?;
    assert_prometheus_counter_sample(
        &body,
        chio_mcp_edge::RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL,
        chio_mcp_edge::receipt_write_total(chio_mcp_edge::RECEIPT_WRITE_OUTCOME_PENDING_APPROVAL),
    )?;
    assert_prometheus_counter_sample(
        &body,
        chio_mcp_edge::RECEIPT_WRITE_OUTCOME_ERROR,
        chio_mcp_edge::receipt_write_total(chio_mcp_edge::RECEIPT_WRITE_OUTCOME_ERROR),
    )?;
    Ok(())
}

#[test]
fn acp_edge_emits_chio_receipt_write_total() -> Result<(), Box<dyn Error>> {
    let _metrics_guard = receipt_metrics_test_guard()?;
    let (kernel, issuer) = metrics_kernel();
    let agent = Keypair::generate();
    let edge = chio_acp_edge::ChioAcpEdge::new(
        chio_acp_edge::AcpEdgeConfig::default(),
        vec![metrics_manifest()],
    )?;
    let before = chio_acp_edge::receipt_write_total(chio_acp_edge::RECEIPT_WRITE_OUTCOME_ALLOW);
    let execution = chio_acp_edge::AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &agent)?,
        agent_id: agent.public_key().to_hex(),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
    };

    let result = edge.invoke("echo", json!({"message": "hello"}), &kernel, &execution)?;

    assert!(result.success);
    let after = chio_acp_edge::receipt_write_total(chio_acp_edge::RECEIPT_WRITE_OUTCOME_ALLOW);
    assert!(
        after > before,
        "acp edge counter must advance through kernel orchestration"
    );

    let mcp_before_target =
        chio_mcp_edge::receipt_write_total(chio_mcp_edge::RECEIPT_WRITE_OUTCOME_ALLOW);
    let acp_before_target =
        chio_acp_edge::receipt_write_total(chio_acp_edge::RECEIPT_WRITE_OUTCOME_ALLOW);
    let mcp_target_edge = chio_acp_edge::ChioAcpEdge::new(
        chio_acp_edge::AcpEdgeConfig::default(),
        vec![mcp_target_metrics_manifest()],
    )?;
    let mcp_target_result = mcp_target_edge.invoke(
        "echo",
        json!({"message": "mcp target"}),
        &kernel,
        &execution,
    )?;
    assert!(mcp_target_result.success);
    assert_eq!(
        chio_acp_edge::receipt_write_total(chio_acp_edge::RECEIPT_WRITE_OUTCOME_ALLOW),
        acp_before_target + 1,
        "acp to mcp target path must record exactly one source receipt write"
    );
    assert_eq!(
        chio_mcp_edge::receipt_write_total(chio_mcp_edge::RECEIPT_WRITE_OUTCOME_ALLOW),
        mcp_before_target,
        "acp to mcp target projection must not record an MCP receipt write"
    );

    let (error_kernel, error_issuer) = metrics_kernel_with_web3_evidence(true);
    let error_agent = Keypair::generate();
    let before_error =
        chio_acp_edge::receipt_write_total(chio_acp_edge::RECEIPT_WRITE_OUTCOME_ERROR);
    let error_result = edge.invoke(
        "echo",
        json!({"message": "hello"}),
        &error_kernel,
        &chio_acp_edge::AcpKernelExecutionContext {
            capability: capability_for_tool(&error_issuer, &error_agent)?,
            agent_id: error_agent.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        },
    );
    assert!(error_result.is_err());
    assert!(
        chio_acp_edge::receipt_write_total(chio_acp_edge::RECEIPT_WRITE_OUTCOME_ERROR)
            > before_error,
        "acp edge orchestrator error path must advance receipt write error"
    );

    let body = chio_acp_edge::render_acp_edge_metrics_prometheus();
    assert!(body.contains(CHIO_RECEIPT_WRITE_TOTAL));
    assert!(body.contains("outcome=\"allow\""));
    assert!(body.contains("outcome=\"pending_approval\""));
    assert!(body.contains("outcome=\"error\""));
    assert_prometheus_counter_sample(
        &body,
        chio_acp_edge::RECEIPT_WRITE_OUTCOME_ALLOW,
        chio_acp_edge::receipt_write_total(chio_acp_edge::RECEIPT_WRITE_OUTCOME_ALLOW),
    )?;
    assert_prometheus_counter_sample(
        &body,
        chio_acp_edge::RECEIPT_WRITE_OUTCOME_ERROR,
        chio_acp_edge::receipt_write_total(chio_acp_edge::RECEIPT_WRITE_OUTCOME_ERROR),
    )?;
    Ok(())
}

#[test]
fn a2a_edge_emits_chio_receipt_write_total() -> Result<(), Box<dyn Error>> {
    let _metrics_guard = receipt_metrics_test_guard()?;
    let (kernel, issuer) = metrics_kernel();
    let agent = Keypair::generate();
    let mut edge = chio_a2a_edge::ChioA2aEdge::new(
        chio_a2a_edge::A2aEdgeConfig::default(),
        vec![metrics_manifest()],
    )?;
    let request = chio_a2a_edge::SendMessageRequest {
        message: chio_a2a_edge::A2aMessage {
            role: "user".to_string(),
            parts: vec![chio_a2a_edge::A2aPart::Data {
                data: json!({"message": "hello"}),
            }],
            metadata: None,
        },
        metadata: None,
    };
    let before = chio_a2a_edge::receipt_write_total(chio_a2a_edge::RECEIPT_WRITE_OUTCOME_ALLOW);
    let execution = chio_a2a_edge::A2aKernelExecutionContext {
        capability: capability_for_tool(&issuer, &agent)?,
        agent_id: agent.public_key().to_hex(),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
    };

    let response = edge.handle_send_message("echo", &request, &kernel, &execution)?;

    assert_eq!(response.status, chio_a2a_edge::TaskStatus::Completed);
    let after = chio_a2a_edge::receipt_write_total(chio_a2a_edge::RECEIPT_WRITE_OUTCOME_ALLOW);
    assert!(
        after > before,
        "a2a edge counter must advance through kernel orchestration"
    );

    let mcp_before_target =
        chio_mcp_edge::receipt_write_total(chio_mcp_edge::RECEIPT_WRITE_OUTCOME_ALLOW);
    let a2a_before_target =
        chio_a2a_edge::receipt_write_total(chio_a2a_edge::RECEIPT_WRITE_OUTCOME_ALLOW);
    let mut mcp_target_edge = chio_a2a_edge::ChioA2aEdge::new(
        chio_a2a_edge::A2aEdgeConfig::default(),
        vec![mcp_target_metrics_manifest()],
    )?;
    let mcp_target_response =
        mcp_target_edge.handle_send_message("echo", &request, &kernel, &execution)?;
    assert_eq!(
        mcp_target_response.status,
        chio_a2a_edge::TaskStatus::Completed
    );
    assert_eq!(
        chio_a2a_edge::receipt_write_total(chio_a2a_edge::RECEIPT_WRITE_OUTCOME_ALLOW),
        a2a_before_target + 1,
        "a2a to mcp target path must record exactly one source receipt write"
    );
    assert_eq!(
        chio_mcp_edge::receipt_write_total(chio_mcp_edge::RECEIPT_WRITE_OUTCOME_ALLOW),
        mcp_before_target,
        "a2a to mcp target projection must not record an MCP receipt write"
    );

    let (error_kernel, error_issuer) = metrics_kernel_with_web3_evidence(true);
    let error_agent = Keypair::generate();
    let before_error =
        chio_a2a_edge::receipt_write_total(chio_a2a_edge::RECEIPT_WRITE_OUTCOME_ERROR);
    let error_result = edge.handle_send_message(
        "echo",
        &request,
        &error_kernel,
        &chio_a2a_edge::A2aKernelExecutionContext {
            capability: capability_for_tool(&error_issuer, &error_agent)?,
            agent_id: error_agent.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        },
    );
    assert!(error_result.is_err());
    assert!(
        chio_a2a_edge::receipt_write_total(chio_a2a_edge::RECEIPT_WRITE_OUTCOME_ERROR)
            > before_error,
        "a2a edge orchestrator error path must advance receipt write error"
    );

    let body = chio_a2a_edge::render_a2a_edge_metrics_prometheus();
    assert!(body.contains(CHIO_RECEIPT_WRITE_TOTAL));
    assert!(body.contains("outcome=\"allow\""));
    assert!(body.contains("outcome=\"pending_approval\""));
    assert!(body.contains("outcome=\"error\""));
    assert_prometheus_counter_sample(
        &body,
        chio_a2a_edge::RECEIPT_WRITE_OUTCOME_ALLOW,
        chio_a2a_edge::receipt_write_total(chio_a2a_edge::RECEIPT_WRITE_OUTCOME_ALLOW),
    )?;
    assert_prometheus_counter_sample(
        &body,
        chio_a2a_edge::RECEIPT_WRITE_OUTCOME_ERROR,
        chio_a2a_edge::receipt_write_total(chio_a2a_edge::RECEIPT_WRITE_OUTCOME_ERROR),
    )?;
    Ok(())
}

#[test]
fn http_core_emits_kernel_decision_latency_and_guard_evaluations() -> Result<(), Box<dyn Error>> {
    let before_count = chio_http_core::decision_latency_count();
    let before_allow = chio_http_core::guard_evaluations_total(chio_http_core::GUARD_OUTCOME_ALLOW);
    let authority = chio_http_core::HttpAuthority::new(
        Keypair::generate(),
        "metrics-registry-test-policy".to_string(),
    );
    let query = HashMap::new();

    let evaluation = authority.evaluate(chio_http_core::HttpAuthorityInput {
        request_id: "metrics-http-1".to_string(),
        method: chio_http_core::HttpMethod::Get,
        route_pattern: "/metrics".to_string(),
        path: "/metrics",
        query: &query,
        caller: chio_http_core::CallerIdentity {
            subject: "metrics-test".to_string(),
            auth_method: chio_http_core::AuthMethod::Anonymous,
            verified: false,
            tenant: None,
            agent_id: None,
        },
        body_hash: None,
        body_length: 0,
        session_id: None,
        capability_id_hint: None,
        presented_capability: None,
        requested_tool_server: None,
        requested_tool_name: None,
        requested_arguments: None,
        model_metadata: None,
        policy: chio_http_core::HttpAuthorityPolicy::SessionAllow,
    })?;

    assert!(evaluation.verdict.is_allowed());

    let after_count = chio_http_core::decision_latency_count();
    let after_allow = chio_http_core::guard_evaluations_total(chio_http_core::GUARD_OUTCOME_ALLOW);
    assert!(
        after_count > before_count,
        "http-core decision-latency count must advance through HttpAuthority::evaluate"
    );
    assert!(
        after_allow > before_allow,
        "http-core guard-evaluations counter must advance through HttpAuthority::evaluate"
    );

    let body = chio_http_core::render_http_core_metrics_prometheus();
    assert!(body.contains(CHIO_GUARD_EVALUATIONS_TOTAL));
    assert!(body.contains(CHIO_KERNEL_DECISION_LATENCY_SECONDS));
    assert!(body.contains("chio_kernel_decision_latency_seconds_bucket"));
    assert!(body.contains("chio_kernel_decision_latency_seconds_sum"));
    assert!(body.contains("chio_kernel_decision_latency_seconds_count"));
    assert!(body.contains("le=\"+Inf\""));
    assert!(body.contains("guard=\"http_authority\""));
    Ok(())
}

#[test]
fn receipt_write_recording_rules_only_count_infrastructure_errors() {
    let rules = include_str!("../../../deploy/prometheus/chio-recording-rules.yml");
    assert!(
        rules.contains("chio_receipt_write_total{outcome=\"error\"}"),
        "receipt-write burn-rate rules must count only infrastructure errors"
    );
    assert!(
        !rules.contains("chio_receipt_write_total{outcome!=\"success\"}"),
        "receipt-write allow or deny outcomes must not be counted as write errors"
    );
    assert!(
        !rules.contains("pending_approval"),
        "pending approval is a distinct normal-flow outcome and must not appear in the error numerator"
    );
    assert!(
        !rules.contains("chio_receipt_write_latency_seconds_bucket"),
        "receipt-write latency has no emitted histogram family yet"
    );
    for expected in [
        "sum by (surface, outcome, le) (rate(chio_kernel_decision_latency_seconds_bucket[5m]))",
        "sum by (witness, outcome, le) (rate(chio_anchor_round_latency_seconds_bucket[5m]))",
        "sum by (result, le) (rate(chio_federation_hop_latency_seconds_bucket[5m]))",
        "sum by (guard_id, verdict, le) (rate(chio_guard_eval_duration_seconds_bucket[5m]))",
        "sum by (route, outcome, le) (rate(chio_alert_dispatch_latency_seconds_bucket[5m]))",
    ] {
        assert!(
            rules.contains(expected),
            "histogram recording rules must preserve SRE routing labels: {expected}"
        );
    }
}

#[test]
fn anchor_emits_chio_anchor_round_latency_seconds() -> Result<(), Box<dyn Error>> {
    let keypair = Keypair::generate();
    let witness = chio_anchor::AnchorBatchWitness {
        kind: chio_anchor::AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:metrics-test".to_string(),
        root: Hash::zero(),
        observed_at: Some(unix_now()),
    };
    let before = chio_anchor::anchor_round_count(chio_anchor::ANCHOR_OUTCOME_SUCCESS);

    let batch = chio_anchor::build_anchor_batch(
        vec![
            "checkpoint-a".to_string(),
            "checkpoint-b".to_string(),
            "checkpoint-c".to_string(),
        ],
        witness,
        unix_now(),
        &keypair,
    )?;

    assert!(batch.verify_signature()?);
    let after = chio_anchor::anchor_round_count(chio_anchor::ANCHOR_OUTCOME_SUCCESS);
    assert!(
        after > before,
        "anchor success counter must advance through build_anchor_batch"
    );
    let body = chio_anchor::render_anchor_metrics_prometheus();
    assert!(body.contains(CHIO_ANCHOR_ROUND_LATENCY_SECONDS));
    assert!(body.contains("chio_anchor_round_latency_seconds_bucket"));
    assert!(body.contains("chio_anchor_round_latency_seconds_sum"));
    assert!(body.contains("_count"));
    Ok(())
}

#[test]
fn federation_emits_chio_federation_hop_total_and_latency() -> Result<(), Box<dyn Error>> {
    let origin = Keypair::generate();
    let tool_host = Keypair::generate();
    let cosigner = chio_federation::InProcessCoSigner::new(
        "origin-kernel",
        origin.clone(),
        tool_host.public_key(),
    );
    let receipt = sample_receipt(&tool_host)?;
    let before = chio_federation::federation_hop_total(chio_federation::HOP_RESULT_OK);
    let before_latency = chio_federation::federation_hop_latency_count();

    let dual = chio_federation::co_sign_with_origin(
        "origin-kernel",
        &origin.public_key(),
        "tool-host-kernel",
        &tool_host,
        receipt,
        &cosigner,
    )?;

    dual.verify(&origin.public_key(), &tool_host.public_key())?;
    let after = chio_federation::federation_hop_total(chio_federation::HOP_RESULT_OK);
    let after_latency = chio_federation::federation_hop_latency_count();
    assert!(
        after > before,
        "federation hop counter must advance through co_sign_with_origin"
    );
    assert!(
        after_latency > before_latency,
        "federation hop latency must advance through co_sign_with_origin"
    );
    let body = chio_federation::render_federation_metrics_prometheus();
    assert!(body.contains(CHIO_FEDERATION_HOP_TOTAL));
    assert!(body.contains(CHIO_FEDERATION_HOP_LATENCY_SECONDS));
    assert!(body.contains("result=\"ok\""));
    assert!(body.contains("chio_federation_hop_latency_seconds_bucket"));
    assert!(body.contains("chio_federation_hop_latency_seconds_sum"));
    assert!(body.contains("_count"));
    Ok(())
}

#[test]
fn wasm_guards_exports_and_consumes_pool_metric_constants() {
    let registry = register_guard_pool_metric_families();
    assert_eq!(registry.families(), GUARD_POOL_METRIC_FAMILIES);

    let names = registry
        .families()
        .iter()
        .map(|family| family.name)
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            METRIC_CHIO_GUARD_POOL_CHECKOUT_TOTAL,
            METRIC_CHIO_GUARD_POOL_WARM_SIZE,
            METRIC_CHIO_GUARD_POOL_EVICT_TOTAL,
        ]
    );

    for name in names {
        assert!(
            is_registered_metric(name),
            "expected {name} to resolve through chio-wasm-guards and be registered in chio-metrics-spec"
        );
    }
}

#[test]
fn wasm_guards_runtime_emits_pool_metrics() -> Result<(), Box<dyn Error>> {
    let wasm = wat::parse_str(
        r#"
            (module
                (import "chio" "log" (func $log (param i32 i32 i32)))
                (import "chio" "get_config" (func $get_config (param i32 i32 i32 i32) (result i32)))
                (import "chio" "get_time_unix_secs" (func $get_time (result i64)))
                (memory (export "memory") 2)
                (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                    (i32.const 0)
                )
            )
        "#,
    )?;
    let mut backend = chio_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend::new()?
        .with_warm_instance_capacity(1);
    backend.load_module(&wasm, 1_000_000)?;

    let tenant_id = "metrics-tenant-a";
    let before_checkout = backend
        .pool_metrics_snapshot(tenant_id)
        .map_or(0, |snapshot| snapshot.checkout_total);

    let verdict = backend.evaluate(&guard_request(tenant_id))?;
    assert!(verdict.is_allow());

    let Some(snapshot) = backend.pool_metrics_snapshot(tenant_id) else {
        panic!("wasm guard pool metrics snapshot should exist after evaluation");
    };
    assert!(
        snapshot.checkout_total > before_checkout,
        "wasm guard pool checkout metric must advance through WasmtimeBackend::evaluate"
    );
    assert!(
        snapshot.warm_size > 0,
        "wasm guard pool warm size must be reported after evaluation"
    );
    Ok(())
}
