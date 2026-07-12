use std::sync::Arc;

use chio_arena::{KernelMultiplexer, MultiplexError};
use chio_core::{
    capability::scope::{ChioScope, Operation, ToolGrant},
    Keypair,
};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallRequest, ToolServerConnection,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use serde_json::json;

#[tokio::test]
async fn multiplexer_routes_per_agent() -> Result<(), Box<dyn std::error::Error>> {
    let kernel_a = build_kernel("filesystem-a", "echo-a")?;
    let kernel_b = build_kernel("filesystem-b", "echo-b")?;

    let mut mux = KernelMultiplexer::new();
    mux.register("agent-a", Arc::new(kernel_a))?;
    mux.register("agent-b", Arc::new(kernel_b))?;

    assert_eq!(mux.len(), 2);
    assert!(!mux.is_empty());

    let kernel_a_handle = mux.kernel("agent-a")?;
    let kernel_b_handle = mux.kernel("agent-b")?;
    let request_a = build_request(kernel_a_handle.as_ref(), "filesystem-a")?;
    let request_b = build_request(kernel_b_handle.as_ref(), "filesystem-b")?;

    let response_a = mux.route("agent-a", &request_a).await?;
    let response_b = mux.route("agent-b", &request_b).await?;
    assert_eq!(response_a.receipt.tool_server, "filesystem-a");
    assert_eq!(response_b.receipt.tool_server, "filesystem-b");
    Ok(())
}

#[tokio::test]
async fn duplicate_registration_fails() -> Result<(), Box<dyn std::error::Error>> {
    let kernel = Arc::new(build_kernel("filesystem", "echo")?);
    let mut mux = KernelMultiplexer::new();
    mux.register("agent-a", kernel.clone())?;
    let result = mux.register("agent-a", kernel.clone());
    assert!(matches!(result, Err(MultiplexError::DuplicateAgent(_))));
    Ok(())
}

#[tokio::test]
async fn unknown_agent_lookup_fails() -> Result<(), Box<dyn std::error::Error>> {
    let mux = KernelMultiplexer::new();
    let result = mux.kernel("agent-z");
    assert!(matches!(result, Err(MultiplexError::UnknownAgent(_))));
    Ok(())
}

#[tokio::test]
async fn arc_clones_share_state() -> Result<(), Box<dyn std::error::Error>> {
    // Two agents bound to the same Arc<ChioKernel> see the same kernel state;
    // this confirms the multiplexer holds Arc clones, not exclusive
    // references.
    let kernel = Arc::new(build_kernel("filesystem", "echo")?);
    let mut mux = KernelMultiplexer::new();
    mux.register("agent-a", kernel.clone())?;
    mux.register("agent-b", kernel.clone())?;

    let request = build_request(&kernel, "filesystem")?;
    let _ = mux.route("agent-a", &request).await?;
    let _ = mux.route("agent-b", &request).await?;
    Ok(())
}

fn build_kernel(server_id: &str, _label: &str) -> Result<ChioKernel, Box<dyn std::error::Error>> {
    let mut kernel = ChioKernel::new(kernel_config());
    kernel.register_tool_server(Box::new(EchoServer {
        id: server_id.to_string(),
    }));
    Ok(kernel)
}

fn build_request(
    kernel: &ChioKernel,
    server_id: &str,
) -> Result<ToolCallRequest, Box<dyn std::error::Error>> {
    let subject = Keypair::generate();
    let capability = kernel.issue_capability(
        &subject.public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: server_id.to_string(),
                tool_name: "read_file".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        },
        60,
    )?;
    Ok(ToolCallRequest {
        request_id: format!("arena-{server_id}"),
        capability: capability.clone(),
        tool_name: "read_file".to_string(),
        server_id: server_id.to_string(),
        agent_id: capability.subject.to_hex(),
        arguments: json!({ "path": "/tmp/multiplex.txt" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    })
}

struct EchoServer {
    id: String,
}

#[async_trait::async_trait]
impl ToolServerConnection for EchoServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["read_file".to_string()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(json!({
            "tool": tool_name,
            "echo": arguments,
        }))
    }
}

fn kernel_config() -> KernelConfig {
    KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "arena-test-policy".to_string(),
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
