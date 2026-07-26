use std::sync::Arc;

use chio_arena::{parse_scenario_str, ArenaRuntime, KernelStepRequest, ScenarioVerdict};
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

fn scenario_toml() -> &'static str {
    r#"
schema_version = "chio.arena.scenario/v1"
id = "walking_skeleton"
title = "Single-agent walking skeleton"
rng_seed = 42
virtual_clock_start = "2026-04-30T00:00:00.000Z"

[determinism]
rng_seed = 42
virtual_clock_start = "2026-04-30T00:00:00.000Z"
scheduler = "single-agent-v1"
locale = "C"

[[agents]]
id = "agent-a"
role = "operator"
model = "recorded:test-agent"
seed_prompt_ref = "prompts/walking-skeleton.txt"

[[steps]]
id = "step-1"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/chio-arena.txt" }
expect_verdict = "allow"
"#
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

#[tokio::test]
async fn runs_single_agent_scenario_and_collects_signed_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(scenario_toml())?;
    let subject = Keypair::generate();
    let mut kernel = ChioKernel::new(kernel_config());
    kernel.register_tool_server(Box::new(EchoServer {
        id: "filesystem".to_string(),
    }));
    let capability = kernel.issue_capability(
        &subject.public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "filesystem".to_string(),
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
    let request = ToolCallRequest {
        request_id: "arena-request-1".to_string(),
        capability: capability.clone(),
        tool_name: "read_file".to_string(),
        server_id: "filesystem".to_string(),
        agent_id: capability.subject.to_hex(),
        arguments: json!({ "path": "/tmp/chio-arena.txt" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    let runtime = ArenaRuntime::new(Arc::new(kernel));
    let run = runtime
        .run(
            &scenario,
            vec![KernelStepRequest {
                step_id: "step-1".to_string(),
                request,
            }],
        )
        .await?;

    assert_eq!(run.scenario_id, "walking_skeleton");
    assert_eq!(run.receipts.len(), 1);
    let receipt = &run.receipts[0];
    assert_eq!(receipt.step_id, "step-1");
    assert_eq!(receipt.request_id, "arena-request-1");
    assert_eq!(receipt.verdict, ScenarioVerdict::Allow);
    assert_eq!(receipt.receipt.tool_server, "filesystem");
    assert_eq!(receipt.receipt.tool_name, "read_file");
    assert!(!receipt.receipt.id.is_empty());
    Ok(())
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
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    }
}
