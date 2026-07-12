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

use super::*;

struct MockToolServer;

#[async_trait::async_trait]
impl ToolServerConnection for MockToolServer {
    fn server_id(&self) -> &str {
        "test-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["echo".to_string()]
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
        policy_hash: "policy-a2a-nonce-preflight-test".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
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
            name: "echo".to_string(),
            description: "Echo input".to_string(),
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
            id: "cap-test-srv-echo".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "test-srv".to_string(),
                    tool_name: "echo".to_string(),
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
        },
        issuer,
    )
    .test_expect("capability should sign")
}

fn text_message(text: &str) -> SendMessageRequest {
    SendMessageRequest {
        message: A2aMessage {
            role: "user".to_string(),
            parts: vec![A2aPart::Text {
                text: text.to_string(),
            }],
            metadata: None,
        },
        metadata: None,
    }
}

#[test]
fn send_message_strict_nonce_preflight_returns_working_retry_metadata() {
    let mut edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let kernel_issuer = config.keypair.clone();
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
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&kernel_issuer, &subject),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
    };

    let response = edge
        .handle_send_message("echo", &text_message("hello"), &kernel, &execution)
        .test_unwrap();

    assert_eq!(response.status, TaskStatus::Working);
    assert!(response.message.is_none());
    assert!(response
        .status_message
        .as_deref()
        .test_expect("preflight should explain retry requirement")
        .contains("execution nonce preflight"));
    let metadata = response
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
}
