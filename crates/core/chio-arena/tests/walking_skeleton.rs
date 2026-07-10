use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use chio_arena::{
    load_scenario, write_arena_bundle, ArenaRuntime, KernelStepRequest, ScenarioVerdict,
    ARENA_MANIFEST_FILENAME,
};
use chio_core::crypto::sha256_hex;
use chio_core::{
    capability::scope::{ChioScope, Operation, ToolGrant},
    Keypair,
};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallRequest, ToolServerConnection,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_replay_corpus::{CHECKPOINT_FILENAME, RECEIPTS_FILENAME, ROOT_FILENAME};
use serde_json::json;

#[tokio::test]
async fn walking_skeleton_loads_runs_and_writes_fixture_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let scenario_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("arena/scenarios/walking_skeleton.toml");
    let scenario = load_scenario(scenario_path)?;
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
        arguments: scenario.steps[0].arguments.clone(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
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
    assert_eq!(run.receipts.len(), 1);
    assert_eq!(run.receipts[0].verdict, ScenarioVerdict::Allow);

    let tmp = tempfile::TempDir::new()?;
    let fixture_dir = tmp.path().join("arena").join(&scenario.id);
    let summary = write_arena_bundle(&fixture_dir, &scenario, &run)?;

    assert_eq!(summary.receipt_count, 1);
    let file_names = fs::read_dir(&fixture_dir)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<Result<BTreeSet<_>, std::io::Error>>()?;
    assert_eq!(
        file_names,
        BTreeSet::from([
            ARENA_MANIFEST_FILENAME.to_string(),
            CHECKPOINT_FILENAME.to_string(),
            RECEIPTS_FILENAME.to_string(),
            ROOT_FILENAME.to_string(),
        ])
    );
    let root_hex = fs::read_to_string(fixture_dir.join(ROOT_FILENAME))?;
    assert_eq!(root_hex, summary.root_hex);
    assert_eq!(recompute_root_hex(&fixture_dir)?, summary.root_hex);
    Ok(())
}

fn recompute_root_hex(dir: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut receipts = fs::read(dir.join(RECEIPTS_FILENAME))?;
    if receipts.last() == Some(&b'\n') {
        receipts.pop();
    }
    let checkpoint = fs::read(dir.join(CHECKPOINT_FILENAME))?;
    let mut payload = Vec::with_capacity(receipts.len().saturating_add(checkpoint.len()));
    payload.extend_from_slice(&receipts);
    payload.extend_from_slice(&checkpoint);
    Ok(sha256_hex(&payload))
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
    }
}
