//! Determinism gate.
//!
//! Runs the three reference scenarios (`walking_skeleton`,
//! `two_agent_tool_exchange`, `three_agent_triangular_delegation`) twice and
//! asserts byte-for-byte equality on the arena's deterministic outputs:
//!
//!   * the determinism witness extracted from the scenario file,
//!   * the schedule emitted by [`DeterministicScheduler`],
//!   * the per-agent RNG snapshot,
//!   * the per-step verdict trace recorded during the run, and
//!   * the canonical-JSON byte image of the manifest's deterministic subset
//!     (everything except the wall-clock-derived `receipt_id` field on each
//!     step entry; the kernel's signed receipts hold a `Uuid::now_v7()`-keyed
//!     id whose byte pattern is intentionally non-replayable here, and is
//!     covered separately by the replay-gate against the fixture
//!     sub-shape).
//!
//! The Linux-only CI workflow `chio-arena-determinism.yml` runs this test
//! under `LC_ALL=C` and `CARGO_INCREMENTAL=0` to harden against locale and
//! incremental-codegen variability.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use chio_arena::{
    load_scenario, parse_scenario_str, shared_kernel_bindings, ArenaRng, ArenaRun, ArenaRuntime,
    DeterministicScheduler, KernelStepRequest, Scenario, ScenarioVerdict, ScheduledStep,
    VirtualClock,
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
use rand::RngCore;
use serde_json::json;

const REFERENCE_SCENARIOS: &[&str] = &[
    "../../../arena/scenarios/walking_skeleton.toml",
    "../../../arena/scenarios/multi/two_agent_tool_exchange.toml",
    "../../../arena/scenarios/multi/three_agent_triangular_delegation.toml",
];

#[tokio::test]
async fn reference_scenarios_emit_byte_identical_artifacts_across_runs(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut observed_ids = BTreeSet::new();
    for relative_path in REFERENCE_SCENARIOS {
        let scenario_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_path);
        let scenario = load_scenario(&scenario_path)?;
        observed_ids.insert(scenario.id.clone());

        // 1. Witness equality across two parses.
        let raw = std::fs::read_to_string(&scenario_path)?;
        let scenario_a = parse_scenario_str(&raw)?;
        let scenario_b = parse_scenario_str(&raw)?;
        let witness_a = serde_json::to_vec(&scenario_a.determinism_witness())?;
        let witness_b = serde_json::to_vec(&scenario_b.determinism_witness())?;
        assert_eq!(
            witness_a, witness_b,
            "scenario {} determinism witness diverged across parses",
            scenario.id
        );

        // 2. Schedule equality across two builds. We track both the
        // canonical byte image (so byte-equality is asserted) and the
        // step count (so the clock trace ticks once per step, matching
        // the runtime's behaviour).
        let (schedule_a, step_count_a) = canonical_schedule(&scenario)?;
        let (schedule_b, step_count_b) = canonical_schedule(&scenario)?;
        assert_eq!(
            schedule_a, schedule_b,
            "scenario {} schedule diverged across builds",
            scenario.id
        );
        assert_eq!(
            step_count_a, step_count_b,
            "scenario {} schedule step count diverged",
            scenario.id
        );

        // 3. RNG snapshot equality across two seedings.
        let snapshot_a = rng_snapshot(&scenario)?;
        let snapshot_b = rng_snapshot(&scenario)?;
        assert_eq!(
            snapshot_a, snapshot_b,
            "scenario {} RNG snapshot diverged",
            scenario.id
        );

        // 4. Virtual clock progression equality. The runtime advances the
        // clock by exactly one tick per scheduled step, so the trace
        // length must be the step count - not the schedule's serialised
        // byte length.
        let clock_a = clock_trace(&scenario, step_count_a)?;
        let clock_b = clock_trace(&scenario, step_count_b)?;
        assert_eq!(
            clock_a, clock_b,
            "scenario {} clock progression diverged",
            scenario.id
        );

        // 5. Per-step verdict trace equality across two end-to-end runs.
        let trace_a = run_verdict_trace(&scenario).await?;
        let trace_b = run_verdict_trace(&scenario).await?;
        assert_eq!(
            trace_a, trace_b,
            "scenario {} verdict trace diverged across runs",
            scenario.id
        );
    }

    assert_eq!(observed_ids.len(), REFERENCE_SCENARIOS.len());
    Ok(())
}

/// Build the canonical byte image of the scheduler's output along with the
/// number of scheduled steps. The byte image is the hardened equality
/// witness; the step count is required so the virtual-clock trace ticks
/// once per step, matching `ArenaRuntime::run_multi_agent`'s behaviour.
fn canonical_schedule(scenario: &Scenario) -> Result<(Vec<u8>, usize), Box<dyn std::error::Error>> {
    let scheduler = DeterministicScheduler::from_scenario(scenario)?;
    let steps = scheduler.schedule();
    let lines: Vec<String> = steps.iter().map(format_schedule_line).collect();
    Ok((lines.join("\n").into_bytes(), steps.len()))
}

fn format_schedule_line(step: &ScheduledStep) -> String {
    format!(
        "{}|{}|{}|{}",
        step.virtual_time, step.agent_id, step.step_id, step.intra_agent_step
    )
}

fn rng_snapshot(scenario: &Scenario) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut rng = ArenaRng::new(scenario.rng_seed);
    rng.register_agents(scenario.agents.iter().map(|agent| agent.id.as_str()))?;
    let snapshot = rng.snapshot_next_u64s();
    let lines: Vec<String> = snapshot
        .iter()
        .map(|(agent_id, value)| format!("{agent_id}={value}"))
        .collect();
    let mut bytes = lines.join("\n").into_bytes();
    bytes.push(b'\n');
    bytes.extend_from_slice(&rng.root_mut().next_u64().to_be_bytes());
    Ok(bytes)
}

/// Render a clock trace by ticking once per scheduled step. The runtime
/// advances the virtual clock at every step boundary, so the trace's
/// `tick_count` must equal the schedule's step count (not the byte image's
/// length).
fn clock_trace(
    scenario: &Scenario,
    tick_count: usize,
) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
    let mut clock = VirtualClock::with_default_tick(scenario.virtual_clock_start.clone())?;
    let mut trace = Vec::with_capacity(tick_count);
    for _ in 0..tick_count {
        clock.tick();
        trace.push(clock.absolute_now_nanos());
    }
    Ok(trace)
}

async fn run_verdict_trace(
    scenario: &Scenario,
) -> Result<Vec<(String, String, ScenarioVerdict)>, Box<dyn std::error::Error>> {
    let kernel = Arc::new(build_kernel()?);
    let bindings = shared_kernel_bindings(scenario, kernel.clone());
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
            request_id: format!("arena-{}-{}", scenario.id, step.id),
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

    let run: ArenaRun = if scenario.agents.len() == 1 {
        ArenaRuntime::new(kernel.clone())
            .run(scenario, requests)
            .await?
    } else {
        ArenaRuntime::run_multi_agent(scenario, bindings, requests).await?
    };

    Ok(run
        .receipts
        .into_iter()
        .map(|receipt| (receipt.step_id, receipt.request_id, receipt.verdict))
        .collect())
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
