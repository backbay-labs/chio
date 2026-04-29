//! Integration tests: guards wired into the Chio kernel.
//!
//! These tests verify that guards registered on the kernel correctly block
//! or allow tool call requests.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::capability::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_core::session::{
    OperationContext, RequestId, RootDefinition, SessionOperation, ToolCallOperation,
};
use chio_guards::{
    EgressAllowlistGuard, ForbiddenPathGuard, GuardPipeline, PathAllowlistGuard, ShellCommandGuard,
};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, SessionOperationResponse, ToolCallRequest,
    ToolServerConnection, Verdict,
};

// Test helpers
fn make_keypair() -> Keypair {
    Keypair::generate()
}

fn make_kernel() -> (ChioKernel, Keypair) {
    let kp = make_keypair();
    let config = KernelConfig {
        keypair: kp.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "test-policy".to_string(),
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
    kernel.register_tool_server(Box::new(EchoServer));
    (kernel, kp)
}

fn make_request(
    kernel: &ChioKernel,
    agent_kp: &Keypair,
    tool: &str,
    args: serde_json::Value,
) -> ToolCallRequest {
    let scope = ChioScope {
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
    };
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), scope, 300)
        .expect("issue cap");

    ToolCallRequest {
        request_id: "req-1".to_string(),
        capability: cap,
        tool_name: tool.to_string(),
        server_id: "srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: args,
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

struct EchoServer;

impl ToolServerConnection for EchoServer {
    fn server_id(&self) -> &str {
        "srv"
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
        Ok(serde_json::json!({ "tool": tool_name, "echo": arguments }))
    }
}

#[tokio::test]
async fn forbidden_path_blocks_etc_shadow() {
    let (mut kernel, _kp) = make_kernel();
    kernel.add_guard(Box::new(ForbiddenPathGuard::new()));

    let agent_kp = make_keypair();
    let req = make_request(
        &kernel,
        &agent_kp,
        "read_file",
        serde_json::json!({"path": "/etc/shadow"}),
    );

    let resp = kernel.evaluate_tool_call(&req).await.unwrap();
    assert_eq!(resp.verdict, Verdict::Deny);
}

#[tokio::test]
async fn forbidden_path_allows_normal_file() {
    let (mut kernel, _kp) = make_kernel();
    kernel.add_guard(Box::new(ForbiddenPathGuard::new()));

    let agent_kp = make_keypair();
    let req = make_request(
        &kernel,
        &agent_kp,
        "read_file",
        serde_json::json!({"path": "/home/user/project/src/main.rs"}),
    );

    let resp = kernel.evaluate_tool_call(&req).await.unwrap();
    assert_eq!(resp.verdict, Verdict::Allow);
}

#[tokio::test]
async fn shell_command_blocks_rm_rf() {
    let (mut kernel, _kp) = make_kernel();
    kernel.add_guard(Box::new(ShellCommandGuard::new()));

    let agent_kp = make_keypair();
    let req = make_request(
        &kernel,
        &agent_kp,
        "bash",
        serde_json::json!({"command": "rm -rf /"}),
    );

    let resp = kernel.evaluate_tool_call(&req).await.unwrap();
    assert_eq!(resp.verdict, Verdict::Deny);
}

#[tokio::test]
async fn shell_command_allows_git_status() {
    let (mut kernel, _kp) = make_kernel();
    kernel.add_guard(Box::new(ShellCommandGuard::new()));

    let agent_kp = make_keypair();
    let req = make_request(
        &kernel,
        &agent_kp,
        "bash",
        serde_json::json!({"command": "git status"}),
    );

    let resp = kernel.evaluate_tool_call(&req).await.unwrap();
    assert_eq!(resp.verdict, Verdict::Allow);
}

#[tokio::test]
async fn egress_allowlist_blocks_evil_com() {
    let (mut kernel, _kp) = make_kernel();
    kernel.add_guard(Box::new(EgressAllowlistGuard::new()));

    let agent_kp = make_keypair();
    let req = make_request(
        &kernel,
        &agent_kp,
        "http_request",
        serde_json::json!({"url": "https://evil.com/steal"}),
    );

    let resp = kernel.evaluate_tool_call(&req).await.unwrap();
    assert_eq!(resp.verdict, Verdict::Deny);
}

#[tokio::test]
async fn egress_allowlist_allows_github_api() {
    let (mut kernel, _kp) = make_kernel();
    kernel.add_guard(Box::new(EgressAllowlistGuard::new()));

    let agent_kp = make_keypair();
    let req = make_request(
        &kernel,
        &agent_kp,
        "http_request",
        serde_json::json!({"url": "https://api.github.com/repos"}),
    );

    let resp = kernel.evaluate_tool_call(&req).await.unwrap();
    assert_eq!(resp.verdict, Verdict::Allow);
}

#[tokio::test]
async fn pipeline_one_deny_means_overall_deny() {
    let (mut kernel, _kp) = make_kernel();

    let mut pipeline = GuardPipeline::new();
    pipeline.add(Box::new(ForbiddenPathGuard::new()));
    pipeline.add(Box::new(ShellCommandGuard::new()));
    pipeline.add(Box::new(EgressAllowlistGuard::new()));
    kernel.add_guard(Box::new(pipeline));

    let agent_kp = make_keypair();
    // This request touches a forbidden path.
    let req = make_request(
        &kernel,
        &agent_kp,
        "read_file",
        serde_json::json!({"path": "/home/user/.ssh/id_rsa"}),
    );

    let resp = kernel.evaluate_tool_call(&req).await.unwrap();
    assert_eq!(resp.verdict, Verdict::Deny);
}

#[tokio::test]
async fn pipeline_all_allow_means_overall_allow() {
    let (mut kernel, _kp) = make_kernel();

    let mut pipeline = GuardPipeline::new();
    pipeline.add(Box::new(ForbiddenPathGuard::new()));
    pipeline.add(Box::new(ShellCommandGuard::new()));
    pipeline.add(Box::new(EgressAllowlistGuard::new()));
    kernel.add_guard(Box::new(pipeline));

    let agent_kp = make_keypair();
    // A benign file read -- no guard should block it.
    let req = make_request(
        &kernel,
        &agent_kp,
        "read_file",
        serde_json::json!({"path": "/home/user/project/src/main.rs"}),
    );

    let resp = kernel.evaluate_tool_call(&req).await.unwrap();
    assert_eq!(resp.verdict, Verdict::Allow);
}

// Regression: `chio check --tool filesystem --params '{"path": "/etc/shadow"}'`
// previously returned ALLOW because "filesystem" was not recognized as a file
// tool, so the action fell through to McpTool and the ForbiddenPathGuard
// did not fire.
#[tokio::test]
async fn filesystem_tool_blocks_etc_shadow() {
    let (mut kernel, _kp) = make_kernel();
    kernel.add_guard(Box::new(ForbiddenPathGuard::new()));

    let agent_kp = make_keypair();
    let req = make_request(
        &kernel,
        &agent_kp,
        "filesystem",
        serde_json::json!({"path": "/etc/shadow"}),
    );

    let resp = kernel.evaluate_tool_call(&req).await.unwrap();
    assert_eq!(resp.verdict, Verdict::Deny);
}

#[tokio::test]
async fn filesystem_tool_allows_normal_path() {
    let (mut kernel, _kp) = make_kernel();
    kernel.add_guard(Box::new(ForbiddenPathGuard::new()));

    let agent_kp = make_keypair();
    let req = make_request(
        &kernel,
        &agent_kp,
        "filesystem",
        serde_json::json!({"path": "/home/user/project/src/main.rs"}),
    );

    let resp = kernel.evaluate_tool_call(&req).await.unwrap();
    assert_eq!(resp.verdict, Verdict::Allow);
}

#[tokio::test]
async fn filesystem_tool_with_action_read_blocks_forbidden() {
    let (mut kernel, _kp) = make_kernel();
    kernel.add_guard(Box::new(ForbiddenPathGuard::new()));

    let agent_kp = make_keypair();
    let req = make_request(
        &kernel,
        &agent_kp,
        "filesystem",
        serde_json::json!({"path": "/etc/shadow", "action": "read"}),
    );

    let resp = kernel.evaluate_tool_call(&req).await.unwrap();
    assert_eq!(resp.verdict, Verdict::Deny);
}

#[tokio::test]
async fn filesystem_tool_session_roots_allow_in_root_path() {
    let (mut kernel, _kp) = make_kernel();
    kernel.add_guard(Box::new(PathAllowlistGuard::new()));

    let agent_kp = make_keypair();
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
    kernel.activate_session(&session_id).unwrap();
    kernel
        .replace_session_roots(
            &session_id,
            vec![RootDefinition {
                uri: "file:///workspace/project".to_string(),
                name: Some("Project".to_string()),
            }],
        )
        .unwrap();

    let scope = ChioScope {
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
    };
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), scope, 300)
        .expect("issue cap");
    let context = OperationContext {
        session_id: session_id.clone(),
        request_id: RequestId::new("sess-tool-allow"),
        agent_id: agent_kp.public_key().to_hex(),
        parent_request_id: None,
        progress_token: None,
    };
    let operation = SessionOperation::ToolCall(ToolCallOperation {
        capability: cap,
        server_id: "srv".to_string(),
        tool_name: "filesystem".to_string(),
        arguments: serde_json::json!({"path": "/workspace/project/src/main.rs"}),
        model_metadata: None,
    });

    let response = kernel
        .evaluate_session_operation(&context, &operation)
        .unwrap();
    match response {
        SessionOperationResponse::ToolCall(result) => assert_eq!(result.verdict, Verdict::Allow),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn filesystem_tool_session_roots_deny_out_of_root_path() {
    let (mut kernel, _kp) = make_kernel();
    kernel.add_guard(Box::new(PathAllowlistGuard::new()));

    let agent_kp = make_keypair();
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
    kernel.activate_session(&session_id).unwrap();
    kernel
        .replace_session_roots(
            &session_id,
            vec![RootDefinition {
                uri: "file:///workspace/project".to_string(),
                name: Some("Project".to_string()),
            }],
        )
        .unwrap();

    let scope = ChioScope {
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
    };
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), scope, 300)
        .expect("issue cap");
    let context = OperationContext {
        session_id: session_id.clone(),
        request_id: RequestId::new("sess-tool-deny"),
        agent_id: agent_kp.public_key().to_hex(),
        parent_request_id: None,
        progress_token: None,
    };
    let operation = SessionOperation::ToolCall(ToolCallOperation {
        capability: cap,
        server_id: "srv".to_string(),
        tool_name: "filesystem".to_string(),
        arguments: serde_json::json!({"path": "/etc/passwd"}),
        model_metadata: None,
    });

    let response = kernel
        .evaluate_session_operation(&context, &operation)
        .unwrap();
    match response {
        SessionOperationResponse::ToolCall(result) => assert_eq!(result.verdict, Verdict::Deny),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn filesystem_tool_session_roots_fail_closed_when_missing() {
    let (mut kernel, _kp) = make_kernel();
    kernel.add_guard(Box::new(PathAllowlistGuard::new()));

    let agent_kp = make_keypair();
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
    kernel.activate_session(&session_id).unwrap();

    let scope = ChioScope {
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
    };
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), scope, 300)
        .expect("issue cap");
    let context = OperationContext {
        session_id: session_id.clone(),
        request_id: RequestId::new("sess-tool-missing-roots"),
        agent_id: agent_kp.public_key().to_hex(),
        parent_request_id: None,
        progress_token: None,
    };
    let operation = SessionOperation::ToolCall(ToolCallOperation {
        capability: cap,
        server_id: "srv".to_string(),
        tool_name: "filesystem".to_string(),
        arguments: serde_json::json!({"path": "/workspace/project/src/main.rs"}),
        model_metadata: None,
    });

    let response = kernel
        .evaluate_session_operation(&context, &operation)
        .unwrap();
    match response {
        SessionOperationResponse::ToolCall(result) => assert_eq!(result.verdict, Verdict::Deny),
        other => panic!("unexpected response: {other:?}"),
    }
}
