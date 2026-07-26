use chio_core::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::CapabilityTokenBody,
};
use chio_core::crypto::Keypair;
use chio_kernel::{
    ChioKernel, InMemoryExecutionNonceStore, KernelConfig, KernelError, NestedFlowBridge,
    ToolServerConnection, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_manifest::{ToolDefinition, ToolManifest};
use chio_test_support::prelude::*;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

use super::tests::{
    capability_for_tool as shared_capability_for_tool, test_kernel_config as shared_kernel_config,
    test_manifest as shared_manifest, threshold_artifacts,
};
use super::*;

struct MockToolServer;

#[async_trait::async_trait]
impl ToolServerConnection for MockToolServer {
    fn server_id(&self) -> &str {
        "test-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["read_file".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Ok(json!({"result": "ok"}))
    }
}

fn test_kernel_config() -> KernelConfig {
    let keypair = Keypair::generate();
    KernelConfig {
        ca_public_keys: vec![keypair.public_key()],
        keypair,
        max_delegation_depth: 8,
        policy_hash: "policy-acp-nonce-preflight-test".to_string(),
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
    }
}

fn test_manifest() -> ToolManifest {
    ToolManifest {
        schema: "chio.manifest.v1".to_string(),
        server_id: "test-srv".to_string(),
        name: "Test Server".to_string(),
        description: Some("Test".to_string()),
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "read_file".to_string(),
            description: "Read a file".to_string(),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            pricing: None,
            has_side_effects: false,
            latency_hint: None,
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: Keypair::from_seed(&[1; 32]).public_key().to_hex(),
    }
}

fn capability_for_tool(
    issuer: &Keypair,
    subject: &Keypair,
) -> chio_core::capability::token::CapabilityToken {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_expect("system time should be after unix epoch")
        .as_secs();
    chio_core::capability::token::CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-test-srv-read_file".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "test-srv".to_string(),
                    tool_name: "read_file".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            issued_at: now.saturating_sub(30),
            expires_at: now + 300,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        issuer,
    )
    .test_expect("capability should sign")
}

#[test]
fn generated_request_id_rejects_threshold_approvals() {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let capability = shared_capability_for_tool(&issuer, &subject, "srv", "run");
    let (approvals, proposal) = threshold_artifacts(&subject, "acp-auth-set");
    let execution = AcpKernelExecutionContext {
        capability,
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: approvals,
        threshold_approval_proposal: Some(proposal),
        supplemental_authorization: None,
        model_metadata: None,
    };
    let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![shared_manifest()])
        .test_expect("ACP edge should construct");
    let kernel = ChioKernel::new(shared_kernel_config());

    let error = edge
        .invoke("run", serde_json::json!({}), &kernel, &execution)
        .test_expect_err("generated request IDs must reject threshold approvals");

    assert!(error.to_string().contains("invoke_with_request_id"));
}

#[test]
fn strict_nonce_retries_require_and_accept_stable_request_ids() {
    let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    let nonce_config = chio_kernel::ExecutionNonceConfig {
        require_nonce: true,
        ..Default::default()
    };
    kernel.set_execution_nonce_store(
        nonce_config.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&nonce_config)),
    );
    kernel.register_tool_server(Box::new(MockToolServer));

    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };

    let request_id = "acp-strict-nonce-retry";
    let arguments = json!({"path": "/tmp"});
    let result = edge
        .invoke_with_request_id(
            request_id,
            "read_file",
            arguments.clone(),
            &kernel,
            &execution,
        )
        .test_unwrap();

    assert!(!result.success);
    assert!(result
        .error
        .as_deref()
        .test_expect("preflight should explain retry requirement")
        .contains("execution nonce preflight"));
    let metadata = result
        .metadata
        .test_expect("strict preflight should attach metadata");
    assert_eq!(metadata["chio"]["decision"].as_str(), Some("allow"));
    assert_eq!(
        metadata["chio"]["terminalState"]["state"].as_str(),
        Some("incomplete")
    );
    assert!(metadata["chio"]["executionNonce"]["nonce"]["nonce_id"]
        .as_str()
        .is_some());
    let execution_nonce = serde_json::from_value(metadata["chio"]["executionNonce"].clone())
        .test_expect("preflight metadata should contain a signed execution nonce");
    let retry_execution = AcpKernelExecutionContext {
        execution_nonce: Some(execution_nonce),
        ..execution.clone()
    };

    let generated_error = edge
        .invoke("read_file", arguments.clone(), &kernel, &retry_execution)
        .test_expect_err("generated invoke IDs must reject execution nonces");
    assert!(generated_error
        .to_string()
        .contains("invoke_with_request_id"));
    let mcp_error = edge
        .invoke_with_mcp_target("read_file", arguments.clone(), &kernel, &retry_execution)
        .test_expect_err("generated MCP-target IDs must reject execution nonces");
    assert!(mcp_error.to_string().contains("invoke_with_request_id"));

    edge.start_stream_with_request_id(request_id, "read_file", arguments.clone(), &retry_execution)
        .test_expect("stable stream IDs should accept execution nonces");
    let retry = edge
        .invoke_with_request_id(
            request_id,
            "read_file",
            arguments,
            &kernel,
            &retry_execution,
        )
        .test_expect("stable invoke retry should execute");
    assert!(retry.success, "{:?}", retry.error);
}
