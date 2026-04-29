//! Phase 1.1 HTTP-surface execution-nonce tests.
//!
//! `chio-http-core` is protocol-agnostic (no embedded HTTP server). The
//! test exercises the wire shape that every HTTP adapter inherits:
//!
//!   1. `EvaluateResponse` serializes the signed nonce on allow.
//!   2. The serialized payload round-trips through serde cleanly.
//!   3. A kernel-issued nonce lifted out of a live `evaluate_tool_call`
//!      verifies against the kernel's replay store, and a replay
//!      attempt fails.
//!
//! The tests stand in for a full HTTP integration test without spinning
//! up axum; the adapter crate (`chio-api-protect`) already exercises the
//! `/evaluate` route and inherits the serialization contract.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core_types::capability::{CapabilityToken, ChioScope, Operation, ToolGrant};
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::{
    ChioReceipt, ChioReceiptBody, Decision, ToolCallAction, TrustLevel,
};
// `ChioReceipt` is kept because one test still asserts against
// `response.receipt.action.parameter_hash` on the kernel path below.
use chio_http_core::{
    EvaluateResponse, ExecutionNonceConfig, HttpMethod, HttpReceipt, HttpReceiptBody,
    InMemoryExecutionNonceStore, NonceBinding, SignedExecutionNonce, Verdict,
};
use chio_kernel::{
    mint_execution_nonce, verify_execution_nonce, ChioKernel, KernelConfig, KernelError,
    NestedFlowBridge, ServerId, ToolCallRequest, ToolServerConnection,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};

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

fn make_kernel_with_nonce() -> ChioKernel {
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 4,
        policy_hash: "http-nonce-test-policy".to_string(),
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
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: false,
    };
    let store = Box::new(InMemoryExecutionNonceStore::from_config(&cfg));
    kernel.set_execution_nonce_store(cfg, store);
    kernel
}

fn issue_capability(kernel: &ChioKernel, subject: &Keypair) -> CapabilityToken {
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
    kernel
        .issue_capability(&subject.public_key(), scope, 300)
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

fn http_receipt(signer: &Keypair, id: &str) -> HttpReceipt {
    // Hand-build a minimal HTTP receipt so the `EvaluateResponse`
    // round-trips through JSON. The serde surface is what we care about
    // here; the conversion between ChioReceipt and HttpReceipt is
    // exercised elsewhere.
    let body = HttpReceiptBody {
        id: id.to_string(),
        request_id: "req-test".to_string(),
        route_pattern: "/evaluate".to_string(),
        method: HttpMethod::Post,
        caller_identity_hash: "0".repeat(64),
        session_id: None,
        verdict: Verdict::Allow,
        evidence: vec![],
        response_status: 200,
        timestamp: 1_000_000,
        content_hash: "0".repeat(64),
        policy_hash: "test-policy".to_string(),
        capability_id: None,
        metadata: None,
        kernel_key: signer.public_key(),
    };
    HttpReceipt::sign(body, signer).expect("sign http receipt")
}

#[test]
fn evaluate_response_serializes_execution_nonce_field() {
    // Stand up an ChioReceipt + HttpReceipt so the body type-checks.
    let kp = Keypair::generate();
    let chio_body = ChioReceiptBody {
        id: "rcpt-1".to_string(),
        timestamp: 1_000_000,
        capability_id: "cap-1".to_string(),
        tool_server: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"path": "/x"})).unwrap(),
        decision: Decision::Allow,
        content_hash: "0".repeat(64),
        policy_hash: "policy".to_string(),
        evidence: vec![],
        metadata: None,
        trust_level: TrustLevel::default(),
        kernel_key: kp.public_key(),
        tenant_id: None,
    };
    let chio_receipt = ChioReceipt::sign(chio_body, &kp).unwrap();
    let http_rcpt = http_receipt(&kp, "http-rcpt-nonce");

    let binding = NonceBinding {
        subject_id: "subject-1".to_string(),
        capability_id: "cap-1".to_string(),
        tool_server: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        parameter_hash: chio_receipt.action.parameter_hash.clone(),
    };
    let cfg = ExecutionNonceConfig::default();
    let signed = mint_execution_nonce(&kp, binding, &cfg, 1_000_000).unwrap();

    let response = EvaluateResponse {
        verdict: Verdict::Allow,
        receipt: http_rcpt,
        evidence: vec![],
        execution_nonce: Some(signed.clone()),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("execution_nonce"));
    assert!(json.contains("chio.execution_nonce.v1"));

    let back: EvaluateResponse = serde_json::from_str(&json).unwrap();
    let recovered = back.execution_nonce.expect("nonce round-trips");
    assert_eq!(recovered.nonce.nonce_id, signed.nonce.nonce_id);
    assert_eq!(recovered.nonce.expires_at, signed.nonce.expires_at);
}

#[test]
fn evaluate_response_omits_nonce_when_absent() {
    // Backward compatibility: a kernel without nonce support serializes
    // the response without an `execution_nonce` field so older clients
    // can parse it.
    let kp = Keypair::generate();
    let http_rcpt = http_receipt(&kp, "http-rcpt-absent");
    let response = EvaluateResponse {
        verdict: Verdict::Allow,
        receipt: http_rcpt,
        evidence: vec![],
        execution_nonce: None,
    };
    let json = serde_json::to_string(&response).unwrap();
    assert!(
        !json.contains("execution_nonce"),
        "unexpected execution_nonce field: {json}"
    );
}

#[tokio::test]
async fn kernel_issued_nonce_verifies_and_replay_fails_end_to_end() {
    // End-to-end: evaluate() -> lift nonce -> re-present -> verify OK.
    // Second re-presentation (replay) must be rejected.
    let kernel = make_kernel_with_nonce();
    let agent = Keypair::generate();
    let cap = issue_capability(&kernel, &agent);
    let req = make_request("http-e2e", &cap);

    let response = kernel
        .evaluate_tool_call(&req)
        .await
        .expect("evaluate allow");
    let signed: SignedExecutionNonce = *response
        .execution_nonce
        .expect("allow response carries a nonce");

    let binding = NonceBinding {
        subject_id: cap.subject.to_hex(),
        capability_id: cap.id.clone(),
        tool_server: req.server_id.clone(),
        tool_name: req.tool_name.clone(),
        parameter_hash: response.receipt.action.parameter_hash.clone(),
    };

    kernel
        .verify_presented_execution_nonce(&signed, &binding)
        .expect("first presentation verifies");

    // Replay: same nonce, same kernel, same store -> Replayed error.
    let err = kernel
        .verify_presented_execution_nonce(&signed, &binding)
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("consumed") || msg.contains("Replayed"),
        "{msg}"
    );
}

#[test]
fn stale_nonce_is_rejected_against_local_clock() {
    // Exercise the free-standing verify path with an explicit future
    // clock so the >30s TTL is observable without sleeping.
    let kp = Keypair::generate();
    let store = InMemoryExecutionNonceStore::default();
    let cfg = ExecutionNonceConfig::default();
    let binding = NonceBinding {
        subject_id: "s".into(),
        capability_id: "c".into(),
        tool_server: "t".into(),
        tool_name: "n".into(),
        parameter_hash: "h".into(),
    };
    let now = 1_000_000;
    let signed = mint_execution_nonce(&kp, binding.clone(), &cfg, now).unwrap();
    let err = verify_execution_nonce(
        &signed,
        &kp.public_key(),
        &binding,
        now + cfg.nonce_ttl_secs as i64 + 1,
        &store,
    )
    .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("expired"), "{msg}");
}
