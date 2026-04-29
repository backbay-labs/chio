//! End-to-end integration tests for the Chio runtime stack.
//!
//! Each test exercises the full pipeline: kernel + guards + capability
//! validation + receipt signing, all in-process with no I/O.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::capability::{
    CapabilityToken, CapabilityTokenBody, ChioScope, DelegationLink, DelegationLinkBody, Operation,
    ToolGrant,
};
use chio_core::crypto::Keypair;
use chio_core::receipt::{ChildRequestReceipt, ChioReceipt};
use chio_guards::{ForbiddenPathGuard, GuardPipeline, ShellCommandGuard};
use chio_kernel::{
    CapabilitySnapshot, ChioKernel, Guard, GuardContext, KernelConfig, KernelError, ReceiptStore,
    ReceiptStoreError, ToolCallOutput, ToolCallRequest, ToolServerConnection, Verdict,
};
use std::collections::HashMap;
use std::sync::Mutex;

struct InMemoryReceiptStore {
    snapshots: Mutex<HashMap<String, CapabilitySnapshot>>,
}

impl InMemoryReceiptStore {
    fn new() -> Self {
        Self {
            snapshots: Mutex::new(HashMap::new()),
        }
    }
}

impl ReceiptStore for InMemoryReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn record_capability_snapshot(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        let snapshot = CapabilitySnapshot {
            capability_id: token.id.clone(),
            subject_key: token.subject.to_hex(),
            issuer_key: token.issuer.to_hex(),
            issued_at: token.issued_at,
            expires_at: token.expires_at,
            grants_json: serde_json::to_string(&token.scope)?,
            delegation_depth: token.delegation_chain.len() as u64,
            parent_capability_id: parent_capability_id.map(ToOwned::to_owned),
        };
        self.snapshots
            .lock()
            .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?
            .insert(snapshot.capability_id.clone(), snapshot);
        Ok(())
    }

    fn get_capability_snapshot(
        &self,
        capability_id: &str,
    ) -> Result<Option<CapabilitySnapshot>, ReceiptStoreError> {
        Ok(self
            .snapshots
            .lock()
            .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?
            .get(capability_id)
            .cloned())
    }
}

// Test helpers
/// Create a kernel with the default guard pipeline (forbidden_path +
/// shell_command + egress_allowlist) and an echo tool server on "srv".
fn make_kernel_with_guards() -> (ChioKernel, Keypair) {
    let kp = Keypair::generate();
    let config = KernelConfig {
        keypair: kp.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "e2e-test-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    };
    let mut kernel = ChioKernel::new(config);
    kernel.set_receipt_store(Box::new(InMemoryReceiptStore::new()));
    kernel.register_tool_server(Box::new(EchoServer("srv")));
    kernel.add_guard(Box::new(GuardPipeline::default_pipeline()));
    (kernel, kp)
}

/// Create a bare kernel (no guards) with an echo tool server on "srv".
fn make_kernel_bare() -> (ChioKernel, Keypair) {
    let kp = Keypair::generate();
    let config = KernelConfig {
        keypair: kp.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "e2e-test-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    };
    let mut kernel = ChioKernel::new(config);
    kernel.set_receipt_store(Box::new(InMemoryReceiptStore::new()));
    kernel.register_tool_server(Box::new(EchoServer("srv")));
    (kernel, kp)
}

/// Issue a capability from the kernel granting wildcard access on "srv".
fn issue_wildcard_cap(kernel: &ChioKernel, agent_pk: &chio_core::PublicKey) -> CapabilityToken {
    kernel
        .issue_capability(
            agent_pk,
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "srv".to_string(),
                    tool_name: "*".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            300,
        )
        .expect("issue wildcard cap")
}

/// Issue a capability scoped to a single tool on "srv".
fn issue_tool_cap(
    kernel: &ChioKernel,
    agent_pk: &chio_core::PublicKey,
    tool: &str,
    ttl: u64,
) -> CapabilityToken {
    kernel
        .issue_capability(
            agent_pk,
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "srv".to_string(),
                    tool_name: tool.to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            ttl,
        )
        .expect("issue tool cap")
}

/// Build a ToolCallRequest.
fn make_request(
    id: &str,
    cap: &CapabilityToken,
    tool: &str,
    args: serde_json::Value,
) -> ToolCallRequest {
    ToolCallRequest {
        request_id: id.to_string(),
        capability: cap.clone(),
        tool_name: tool.to_string(),
        server_id: "srv".to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: args,
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

// Mock tool server
/// A tool server that echoes its inputs back as the result.
struct EchoServer(&'static str);

impl ToolServerConnection for EchoServer {
    fn server_id(&self) -> &str {
        self.0
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["*".to_string()]
    }
    fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({
            "tool": tool_name,
            "echo": arguments,
        }))
    }
}

// Test: Happy path -- allowed tool call
#[tokio::test]
async fn full_flow_allowed_tool_call() {
    let (kernel, _ca_kp) = make_kernel_with_guards();
    let agent_kp = Keypair::generate();
    let cap = issue_tool_cap(&kernel, &agent_kp.public_key(), "echo", 300);

    let req = make_request(
        "req-happy",
        &cap,
        "echo",
        serde_json::json!({"message": "hello chio"}),
    );

    let resp = kernel.evaluate_tool_call(&req).await.unwrap();

    // The call should be allowed.
    assert_eq!(resp.verdict, Verdict::Allow);
    assert!(resp.output.is_some(), "allowed call should have a result");
    assert!(resp.reason.is_none(), "allowed call should have no reason");

    // The result should echo back the arguments.
    match resp.output.unwrap() {
        ToolCallOutput::Value(result) => {
            assert_eq!(result["tool"], "echo");
            assert_eq!(result["echo"]["message"], "hello chio");
        }
        other => panic!("unexpected tool output: {other:?}"),
    }

    // The receipt should be Allow and its signature should verify.
    assert!(resp.receipt.is_allowed());
    assert!(
        resp.receipt.verify_signature().unwrap(),
        "receipt signature must verify"
    );
    assert_eq!(resp.receipt.capability_id, cap.id);
}

// Test: Denied by guard -- forbidden path
#[tokio::test]
async fn full_flow_denied_by_forbidden_path() {
    let (kernel, _ca_kp) = make_kernel_with_guards();
    let agent_kp = Keypair::generate();
    let cap = issue_wildcard_cap(&kernel, &agent_kp.public_key());

    let req = make_request(
        "req-forbidden",
        &cap,
        "read_file",
        serde_json::json!({"path": "/etc/shadow"}),
    );

    let resp = kernel.evaluate_tool_call(&req).await.unwrap();

    assert_eq!(resp.verdict, Verdict::Deny);
    assert!(resp.output.is_none());
    let reason = resp.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("forbidden") || reason.contains("denied"),
        "expected denial by forbidden_path guard, got: {reason}"
    );

    // The receipt should be Deny and its signature should still verify.
    assert!(resp.receipt.is_denied());
    assert!(
        resp.receipt.verify_signature().unwrap(),
        "deny receipt signature must verify"
    );
}

// Test: Denied by guard -- dangerous shell command
#[tokio::test]
async fn full_flow_denied_shell_command() {
    let (kernel, _ca_kp) = make_kernel_with_guards();
    let agent_kp = Keypair::generate();
    let cap = issue_wildcard_cap(&kernel, &agent_kp.public_key());

    let req = make_request(
        "req-shell",
        &cap,
        "bash",
        serde_json::json!({"command": "rm -rf /"}),
    );

    let resp = kernel.evaluate_tool_call(&req).await.unwrap();

    assert_eq!(resp.verdict, Verdict::Deny);
    let reason = resp.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("shell") || reason.contains("denied"),
        "expected denial by shell_command guard, got: {reason}"
    );
    assert!(resp.receipt.is_denied());
    assert!(resp.receipt.verify_signature().unwrap());
}

// Test: Denied by capability -- wrong tool
#[tokio::test]
async fn full_flow_denied_wrong_tool() {
    let (kernel, _ca_kp) = make_kernel_bare();
    let agent_kp = Keypair::generate();

    // Capability grants "echo" only.
    let cap = issue_tool_cap(&kernel, &agent_kp.public_key(), "echo", 300);

    // Try to call "filesystem" instead.
    let req = make_request(
        "req-wrong-tool",
        &cap,
        "filesystem",
        serde_json::json!({"path": "/tmp/test"}),
    );

    let resp = kernel.evaluate_tool_call(&req).await.unwrap();

    assert_eq!(resp.verdict, Verdict::Deny);
    let reason = resp.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("not in capability scope"),
        "expected out-of-scope denial, got: {reason}"
    );
    assert!(resp.receipt.is_denied());
    assert!(resp.receipt.verify_signature().unwrap());
}

// Test: Denied by capability -- expired
#[tokio::test]
async fn full_flow_denied_expired_capability() {
    let (kernel, _ca_kp) = make_kernel_bare();
    let agent_kp = Keypair::generate();

    // TTL=0 means the capability expires at the same second it was issued.
    let cap = issue_tool_cap(&kernel, &agent_kp.public_key(), "echo", 0);

    let req = make_request(
        "req-expired",
        &cap,
        "echo",
        serde_json::json!({"message": "too late"}),
    );

    let resp = kernel.evaluate_tool_call(&req).await.unwrap();

    assert_eq!(resp.verdict, Verdict::Deny);
    let reason = resp.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("expired"),
        "expected expiration denial, got: {reason}"
    );
    assert!(resp.receipt.is_denied());
    assert!(resp.receipt.verify_signature().unwrap());
}

// Test: Revocation cascade
#[tokio::test]
async fn full_flow_revocation_cascade() {
    let (kernel, ca_kp) = make_kernel_bare();
    let agent_a_kp = Keypair::generate();
    let agent_b_kp = Keypair::generate();

    // Issue capability A to agent_a.
    // Issue cap A so the kernel has seen agent_a as a valid subject.
    // We don't use cap_a directly -- the point is to revoke its capability ID
    // and see the cascade affect cap_b's delegation chain.
    let cap_a = kernel
        .issue_capability(
            &agent_a_kp.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "srv".to_string(),
                    tool_name: "*".to_string(),
                    operations: vec![Operation::Invoke, Operation::Delegate],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            300,
        )
        .expect("issue delegable cap");

    // Build a delegated capability B: issued by the CA (kernel) to agent_b,
    // but with a delegation chain showing that agent_a delegated to agent_b.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let link_body = DelegationLinkBody {
        capability_id: cap_a.id.clone(),
        delegator: agent_a_kp.public_key(),
        delegatee: agent_b_kp.public_key(),
        attenuations: vec![],
        timestamp: now,
    };
    let link = DelegationLink::sign(link_body, &agent_a_kp).expect("sign delegation link");

    let cap_b_body = CapabilityTokenBody {
        id: format!("cap-delegated-{now}"),
        issuer: ca_kp.public_key(),
        subject: agent_b_kp.public_key(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "*".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        },
        issued_at: now,
        expires_at: now + 300,
        delegation_chain: vec![link],
    };
    let cap_b = CapabilityToken::sign(cap_b_body, &ca_kp).expect("sign delegated cap");

    // Before revocation, B should work.
    let req_ok = ToolCallRequest {
        request_id: "req-cascade-ok".to_string(),
        capability: cap_b.clone(),
        tool_name: "echo".to_string(),
        server_id: "srv".to_string(),
        agent_id: agent_b_kp.public_key().to_hex(),
        model_metadata: None,
        federated_origin_kernel_id: None,
        arguments: serde_json::json!({"msg": "before revocation"}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
    };
    let resp_ok = kernel.evaluate_tool_call(&req_ok).await.unwrap();
    assert_eq!(
        resp_ok.verdict,
        Verdict::Allow,
        "B should work before A is revoked"
    );

    // Revoke A's capability ID; descendants should now fail via the chain entry.
    kernel.revoke_capability(&cap_a.id).unwrap();

    // Now B should be denied because its delegation chain ancestor is revoked.
    let req_revoked = ToolCallRequest {
        request_id: "req-cascade-revoked".to_string(),
        capability: cap_b,
        tool_name: "echo".to_string(),
        server_id: "srv".to_string(),
        agent_id: agent_b_kp.public_key().to_hex(),
        model_metadata: None,
        federated_origin_kernel_id: None,
        arguments: serde_json::json!({"msg": "after revocation"}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
    };
    let resp_revoked = kernel.evaluate_tool_call(&req_revoked).await.unwrap();

    assert_eq!(resp_revoked.verdict, Verdict::Deny);
    let reason = resp_revoked.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("revoked"),
        "expected delegation chain revocation, got: {reason}"
    );
    assert!(resp_revoked.receipt.is_denied());
    assert!(resp_revoked.receipt.verify_signature().unwrap());
}

// Test: Receipt chain integrity
#[tokio::test]
async fn full_flow_receipt_chain() {
    let (kernel, _ca_kp) = make_kernel_bare();
    let agent_kp = Keypair::generate();
    let cap = issue_wildcard_cap(&kernel, &agent_kp.public_key());

    // Make 3 sequential tool calls.
    for i in 0..3 {
        let req = make_request(
            &format!("req-chain-{i}"),
            &cap,
            "echo",
            serde_json::json!({"seq": i}),
        );
        let resp = kernel.evaluate_tool_call(&req).await.unwrap();
        assert_eq!(resp.verdict, Verdict::Allow, "call {i} should succeed");
    }

    // Collect all 3 receipts from the kernel's receipt log.
    let log = kernel.receipt_log();
    let receipts = log.receipts();
    assert_eq!(receipts.len(), 3, "should have exactly 3 receipts");

    // Verify each receipt.
    for (i, receipt) in receipts.iter().enumerate() {
        // Signature must verify.
        assert!(
            receipt.verify_signature().unwrap(),
            "receipt {i} signature must verify"
        );

        // Each receipt references the correct capability.
        assert_eq!(
            receipt.capability_id, cap.id,
            "receipt {i} must reference the issued capability"
        );
    }

    // Timestamps must be monotonically non-decreasing.
    for i in 1..receipts.len() {
        assert!(
            receipts[i].timestamp >= receipts[i - 1].timestamp,
            "receipt {} timestamp ({}) must be >= receipt {} timestamp ({})",
            i,
            receipts[i].timestamp,
            i - 1,
            receipts[i - 1].timestamp,
        );
    }
}

// Test: Guard pipeline fail-closed
#[tokio::test]
async fn full_flow_guard_error_fails_closed() {
    let (mut kernel, _ca_kp) = make_kernel_bare();

    // Register a guard that always returns an error.
    struct BrokenGuard;
    impl Guard for BrokenGuard {
        fn name(&self) -> &str {
            "broken-guard"
        }
        fn evaluate(&self, _ctx: &GuardContext) -> Result<Verdict, KernelError> {
            Err(KernelError::Internal("simulated guard failure".to_string()))
        }
    }
    kernel.add_guard(Box::new(BrokenGuard));

    let agent_kp = Keypair::generate();
    let cap = issue_wildcard_cap(&kernel, &agent_kp.public_key());

    let req = make_request(
        "req-broken",
        &cap,
        "echo",
        serde_json::json!({"message": "should be denied"}),
    );

    let resp = kernel.evaluate_tool_call(&req).await.unwrap();

    // The guard errored, so the kernel must deny (fail-closed).
    assert_eq!(resp.verdict, Verdict::Deny);
    let reason = resp.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("fail-closed"),
        "expected fail-closed denial, got: {reason}"
    );
    assert!(resp.receipt.is_denied());
    assert!(resp.receipt.verify_signature().unwrap());
}

// Test: Multiple guard types in pipeline
#[tokio::test]
async fn full_flow_guard_pipeline_mixed_verdicts() {
    let kp = Keypair::generate();
    let config = KernelConfig {
        keypair: kp.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "e2e-test-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    };
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(EchoServer("srv")));

    // Add only the forbidden-path and shell-command guards.
    let mut pipeline = GuardPipeline::new();
    pipeline.add(Box::new(ForbiddenPathGuard::new()));
    pipeline.add(Box::new(ShellCommandGuard::new()));
    kernel.add_guard(Box::new(pipeline));

    let agent_kp = Keypair::generate();
    let cap = issue_wildcard_cap(&kernel, &agent_kp.public_key());

    // A benign echo call should pass both guards.
    let req_ok = make_request(
        "req-mixed-ok",
        &cap,
        "echo",
        serde_json::json!({"data": "safe"}),
    );
    let resp_ok = kernel.evaluate_tool_call(&req_ok).await.unwrap();
    assert_eq!(resp_ok.verdict, Verdict::Allow);
    assert!(resp_ok.receipt.verify_signature().unwrap());

    // A call with a forbidden path should be denied.
    let req_bad = make_request(
        "req-mixed-bad",
        &cap,
        "read_file",
        serde_json::json!({"path": "/etc/passwd"}),
    );
    let resp_bad = kernel.evaluate_tool_call(&req_bad).await.unwrap();
    assert_eq!(resp_bad.verdict, Verdict::Deny);
    assert!(resp_bad.receipt.is_denied());
    assert!(resp_bad.receipt.verify_signature().unwrap());
}

// Test: Receipt signature verified against kernel public key
#[tokio::test]
async fn full_flow_receipt_verified_against_kernel_pk() {
    let (kernel, ca_kp) = make_kernel_bare();
    let agent_kp = Keypair::generate();
    let cap = issue_tool_cap(&kernel, &agent_kp.public_key(), "echo", 300);

    let req = make_request("req-pk-check", &cap, "echo", serde_json::json!({"x": 1}));
    let resp = kernel.evaluate_tool_call(&req).await.unwrap();

    // The receipt's embedded kernel_key must match the CA keypair's public key.
    assert_eq!(resp.receipt.kernel_key, ca_kp.public_key());

    // And verify_signature checks against that embedded key.
    assert!(resp.receipt.verify_signature().unwrap());
}

// Test: Invocation budget exhaustion
#[tokio::test]
async fn full_flow_budget_exhaustion() {
    let (kernel, _ca_kp) = make_kernel_bare();
    let agent_kp = Keypair::generate();

    // Issue a capability with max_invocations = 2.
    let cap = kernel
        .issue_capability(
            &agent_kp.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "srv".to_string(),
                    tool_name: "echo".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: Some(2),
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            300,
        )
        .expect("issue budgeted cap");

    // First two calls succeed.
    for i in 0..2 {
        let req = make_request(
            &format!("req-budget-{i}"),
            &cap,
            "echo",
            serde_json::json!({"i": i}),
        );
        let resp = kernel.evaluate_tool_call(&req).await.unwrap();
        assert_eq!(resp.verdict, Verdict::Allow, "call {i} should succeed");
        assert!(resp.receipt.verify_signature().unwrap());
    }

    // Third call should be denied due to budget exhaustion.
    let req = make_request("req-budget-2", &cap, "echo", serde_json::json!({"i": 2}));
    let resp = kernel.evaluate_tool_call(&req).await.unwrap();
    assert_eq!(resp.verdict, Verdict::Deny);
    let reason = resp.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("budget"),
        "expected budget exhaustion, got: {reason}"
    );
    assert!(resp.receipt.is_denied());
    assert!(resp.receipt.verify_signature().unwrap());
}

// Test: Direct capability revocation
#[tokio::test]
async fn full_flow_direct_revocation() {
    let (kernel, _ca_kp) = make_kernel_bare();
    let agent_kp = Keypair::generate();
    let cap = issue_tool_cap(&kernel, &agent_kp.public_key(), "echo", 300);

    // First call succeeds.
    let req1 = make_request(
        "req-rev-1",
        &cap,
        "echo",
        serde_json::json!({"msg": "before"}),
    );
    let resp1 = kernel.evaluate_tool_call(&req1).await.unwrap();
    assert_eq!(resp1.verdict, Verdict::Allow);

    // Revoke the capability.
    kernel.revoke_capability(&cap.id).unwrap();

    // Second call should be denied.
    let req2 = make_request(
        "req-rev-2",
        &cap,
        "echo",
        serde_json::json!({"msg": "after"}),
    );
    let resp2 = kernel.evaluate_tool_call(&req2).await.unwrap();
    assert_eq!(resp2.verdict, Verdict::Deny);
    let reason = resp2.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("revoked"),
        "expected revocation denial, got: {reason}"
    );
    assert!(resp2.receipt.verify_signature().unwrap());
}

// Test: Untrusted issuer rejected
#[tokio::test]
async fn full_flow_untrusted_issuer() {
    let (kernel, _ca_kp) = make_kernel_bare();
    let rogue_kp = Keypair::generate();
    let agent_kp = Keypair::generate();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Forge a capability signed by a rogue key (not trusted by the kernel).
    let body = CapabilityTokenBody {
        id: "cap-rogue".to_string(),
        issuer: rogue_kp.public_key(),
        subject: agent_kp.public_key(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "*".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        },
        issued_at: now,
        expires_at: now + 300,
        delegation_chain: vec![],
    };
    let forged_cap = CapabilityToken::sign(body, &rogue_kp).expect("sign forged cap");

    let req = ToolCallRequest {
        request_id: "req-rogue".to_string(),
        capability: forged_cap,
        tool_name: "echo".to_string(),
        server_id: "srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        model_metadata: None,
        federated_origin_kernel_id: None,
        arguments: serde_json::json!({}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
    };

    let resp = kernel.evaluate_tool_call(&req).await.unwrap();
    assert_eq!(resp.verdict, Verdict::Deny);
    let reason = resp.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("not found among trusted"),
        "expected untrusted issuer denial, got: {reason}"
    );
    assert!(resp.receipt.verify_signature().unwrap());
}
