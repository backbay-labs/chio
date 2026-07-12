//! End-to-end multi-agent reference scenarios.
//!
//! Drives the two-agent and three-agent scenarios under the deterministic
//! scheduler and asserts the runtime produces a receipt per scenario step in
//! schedule order.

use std::path::Path;
use std::sync::Arc;

use chio_arena::{
    load_scenario, shared_kernel_bindings, ArenaRuntime, KernelStepRequest, ScenarioVerdict,
};
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

const TWO_AGENT_PATH: &str = "../../../arena/scenarios/multi/two_agent_tool_exchange.toml";
const THREE_AGENT_PATH: &str =
    "../../../arena/scenarios/multi/three_agent_triangular_delegation.toml";

#[tokio::test]
async fn two_agent_scenario_runs_under_multi_agent_runtime(
) -> Result<(), Box<dyn std::error::Error>> {
    run_reference_scenario(TWO_AGENT_PATH, 4).await
}

#[tokio::test]
async fn three_agent_scenario_runs_under_multi_agent_runtime(
) -> Result<(), Box<dyn std::error::Error>> {
    run_reference_scenario(THREE_AGENT_PATH, 6).await
}

async fn run_reference_scenario(
    relative_path: &str,
    expected_step_count: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let scenario_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    let scenario = load_scenario(&scenario_path)?;
    assert_eq!(scenario.steps.len(), expected_step_count);

    let kernel = Arc::new(build_kernel()?);
    let bindings = shared_kernel_bindings(&scenario, kernel.clone());

    let mut requests = Vec::with_capacity(scenario.steps.len());
    for step in &scenario.steps {
        let capability = kernel.issue_capability(
            &Keypair::generate().public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: step.server.clone(),
                    tool_name: step.tool.clone(),
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
            request_id: format!("arena-{}", step.id),
            capability: capability.clone(),
            tool_name: step.tool.clone(),
            server_id: step.server.clone(),
            agent_id: capability.subject.to_hex(),
            arguments: step.arguments.clone(),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        requests.push(KernelStepRequest {
            step_id: step.id.clone(),
            request,
        });
    }

    let run = ArenaRuntime::run_multi_agent(&scenario, bindings, requests).await?;
    assert_eq!(run.scenario_id, scenario.id);
    assert_eq!(run.receipts.len(), expected_step_count);
    for receipt in &run.receipts {
        assert_eq!(receipt.verdict, ScenarioVerdict::Allow);
    }

    // Receipt order must match scenario step order (the deterministic
    // scheduler preserves declaration order in the absence of multi-step
    // tiebreaks). Use byte equality on serialised step ids.
    let observed_ids: Vec<String> = run
        .receipts
        .iter()
        .map(|receipt| receipt.step_id.clone())
        .collect();
    let expected_ids: Vec<String> = scenario.steps.iter().map(|step| step.id.clone()).collect();
    assert_eq!(observed_ids, expected_ids);
    Ok(())
}

fn build_kernel() -> Result<ChioKernel, Box<dyn std::error::Error>> {
    let mut kernel = ChioKernel::new(kernel_config());
    kernel.register_tool_server(Box::new(EchoServer {
        id: "filesystem".to_string(),
    }));
    Ok(kernel)
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
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    }
}
