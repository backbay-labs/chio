#![allow(clippy::expect_used, clippy::unwrap_used)]

use crate::McpTargetExecutor;
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_cross_protocol::capability_bridge::{
    CrossProtocolCapabilityEnvelope, CrossProtocolCapabilityRef,
};
use chio_cross_protocol::discovery::DiscoveryProtocol;
use chio_cross_protocol::execution::{
    CrossProtocolExecutionRequest, CrossProtocolTargetRequest, TargetProtocolExecutor,
};
use chio_cross_protocol::routing::{
    RouteCandidateEvidence, RouteSelectionDecision, RouteSelectionEvidence,
};
use chio_kernel::{ChioKernel, KernelConfig, KernelError, ToolServerConnection};
use serde_json::{json, Value};

struct EchoServer;

#[async_trait::async_trait]
impl ToolServerConnection for EchoServer {
    fn server_id(&self) -> &str {
        "srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["read_file".to_string()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Ok(json!({
            "tool": tool_name,
            "arguments": arguments,
        }))
    }
}

#[test]
fn mcp_target_executor_carries_source_receipt_context_into_kernel_receipt_metadata() {
    let mut kernel = make_kernel();
    kernel.register_tool_server(Box::new(EchoServer));
    let agent = Keypair::generate();
    let capability = kernel
        .issue_capability(
            &agent.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "srv".to_string(),
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
            300,
        )
        .unwrap();
    let execution = CrossProtocolExecutionRequest {
        origin_request_id: "acp-source-1".to_string(),
        kernel_request_id: "mcp-target-source-context".to_string(),
        target_protocol: DiscoveryProtocol::Mcp,
        target_server_id: "srv".to_string(),
        target_tool_name: "read_file".to_string(),
        agent_id: agent.public_key().to_hex(),
        arguments: json!({"path": "/tmp/demo.txt"}),
        capability: capability.clone(),
        source_envelope: json!({
            "receipt_context": {
                "sourceReceiptId": "source-receipt-1",
                "sourceProtocol": "acp"
            }
        }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
    };
    let capability_ref = CrossProtocolCapabilityRef {
        chio_capability_id: capability.id.clone(),
        origin_protocol: DiscoveryProtocol::Acp,
        protocol_context: None,
        parent_capability_hash: "parent-hash".to_string(),
    };
    let capability_envelope = CrossProtocolCapabilityEnvelope {
        schema: "test.capability-envelope".to_string(),
        capability_ref: capability_ref.clone(),
        target_protocol: DiscoveryProtocol::Mcp,
        attenuated_scope: execution.capability.scope.clone(),
        bridged_at: 1,
        bridge_id: "bridge-test".to_string(),
    };
    let route_selection = RouteSelectionEvidence {
        route_selection_id: "route-source-context".to_string(),
        decision: RouteSelectionDecision::Select,
        source_protocol: DiscoveryProtocol::Acp,
        requested_target_protocol: DiscoveryProtocol::Mcp,
        selected_route_id: Some("acp-mcp-native".to_string()),
        selected_target_protocol: Some(DiscoveryProtocol::Mcp),
        selected_protocols: vec![DiscoveryProtocol::Acp, DiscoveryProtocol::Mcp],
        reason: None,
        governed_intent_id: None,
        candidates: vec![RouteCandidateEvidence {
            route_id: "acp-mcp-native".to_string(),
            target_protocol: DiscoveryProtocol::Mcp,
            selected_protocols: vec![DiscoveryProtocol::Acp, DiscoveryProtocol::Mcp],
            available: true,
            availability_reason: None,
        }],
    };
    let projected_request = json!({"jsonrpc": "2.0"});
    let executor = McpTargetExecutor {
        peer_supports_chio_tool_streaming: false,
    };

    let result = executor
        .execute(CrossProtocolTargetRequest {
            kernel: &kernel,
            execution: &execution,
            source_protocol: DiscoveryProtocol::Acp,
            bridge_id: "bridge-test",
            capability_ref: &capability_ref,
            capability_envelope: &capability_envelope,
            route_selection: &route_selection,
            projected_request: &projected_request,
        })
        .unwrap();
    let metadata = result.response.receipt.metadata.as_ref().unwrap();
    assert_eq!(
        metadata["receipt_context"]["sourceReceiptId"],
        "source-receipt-1"
    );
    assert_eq!(metadata["receipt_context"]["sourceProtocol"], "acp");
}

fn make_kernel() -> ChioKernel {
    ChioKernel::new(KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "edge-policy".to_string(),
        allow_sampling: true,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    })
}
