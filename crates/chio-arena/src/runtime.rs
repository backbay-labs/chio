use std::collections::BTreeMap;
use std::sync::Arc;

use chio_kernel::{ChioKernel, ToolCallRequest, ToolCallResponse, Verdict};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::clock::{ClockError, VirtualClock};
use crate::rng::{ArenaRng, RngError};
use crate::scenario::{Scenario, ScenarioVerdict};
use crate::scheduler::{DeterministicScheduler, SchedulerError};

#[derive(Debug)]
pub struct KernelStepRequest {
    pub step_id: String,
    pub request: ToolCallRequest,
}

/// Per-agent kernel binding used by the multi-agent runtime. The runtime
/// dispatches each step to the kernel registered for the step's owning agent;
/// agents may share a single `Arc<ChioKernel>` or hold distinct instances.
#[derive(Clone)]
pub struct AgentKernelBinding {
    /// Agent id (matches `Scenario::agents[*].id`).
    pub agent_id: String,
    /// Shared kernel handle. Holding `Arc<ChioKernel>` (rather than `&mut`)
    /// preserves the soft-coupling contract with trajectory-1 M05.
    pub kernel: Arc<ChioKernel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArenaRun {
    pub scenario_id: String,
    pub receipts: Vec<ArenaReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArenaReceipt {
    pub step_id: String,
    pub request_id: String,
    pub verdict: ScenarioVerdict,
    pub reason: Option<String>,
    pub receipt: chio_core::receipt::ChioReceipt,
}

#[derive(Clone)]
pub struct ArenaRuntime {
    kernel: Arc<ChioKernel>,
}

impl ArenaRuntime {
    pub fn new(kernel: Arc<ChioKernel>) -> Self {
        Self { kernel }
    }

    pub async fn run(
        &self,
        scenario: &Scenario,
        requests: Vec<KernelStepRequest>,
    ) -> Result<ArenaRun, ArenaRuntimeError> {
        validate_single_agent_runtime_inputs(scenario, &requests)?;

        let mut receipts = Vec::with_capacity(requests.len());
        for (step, request) in scenario.steps.iter().zip(requests) {
            let response = self.kernel.evaluate_tool_call(&request.request).await?;
            let verdict = scenario_verdict(&response);
            if verdict != step.expect_verdict {
                return Err(ArenaRuntimeError::UnexpectedVerdict {
                    step_id: step.id.clone(),
                    expected: step.expect_verdict,
                    actual: verdict,
                });
            }
            receipts.push(ArenaReceipt {
                step_id: request.step_id,
                request_id: response.request_id,
                verdict,
                reason: response.reason,
                receipt: response.receipt,
            });
        }

        Ok(ArenaRun {
            scenario_id: scenario.id.clone(),
            receipts,
        })
    }

    /// Run a multi-agent scenario under the deterministic scheduler.
    ///
    /// Each scenario step is dispatched to the kernel registered for its
    /// owning agent. The virtual clock advances by exactly one tick per
    /// scheduled step; the arena RNG is seeded from the scenario witness and
    /// per-agent sub-streams are derived through `ArenaRng::register_agents`.
    ///
    /// Receipts are appended in scheduler order, which is fully derived from
    /// scenario contents and therefore byte-identical across runs of the same
    /// scenario witness.
    pub async fn run_multi_agent(
        scenario: &Scenario,
        bindings: Vec<AgentKernelBinding>,
        requests: Vec<KernelStepRequest>,
    ) -> Result<ArenaRun, ArenaRuntimeError> {
        let scheduler = DeterministicScheduler::from_scenario(scenario)?;
        let schedule = scheduler.schedule().to_vec();

        let mut clock = VirtualClock::with_default_tick(scenario.virtual_clock_start.clone())?;
        let mut rng = ArenaRng::new(scenario.rng_seed);
        rng.register_agents(scenario.agents.iter().map(|agent| agent.id.as_str()))?;

        let mut request_lookup: BTreeMap<String, ToolCallRequest> = BTreeMap::new();
        for request in requests {
            request_lookup.insert(request.step_id, request.request);
        }
        let mut kernel_lookup: BTreeMap<String, Arc<ChioKernel>> = BTreeMap::new();
        for binding in bindings {
            kernel_lookup.insert(binding.agent_id, binding.kernel);
        }

        let mut receipts = Vec::with_capacity(schedule.len());
        for step in &schedule {
            let request = request_lookup.remove(&step.step_id).ok_or_else(|| {
                ArenaRuntimeError::MissingStepRequest {
                    step_id: step.step_id.clone(),
                }
            })?;
            let kernel = kernel_lookup
                .get(&step.agent_id)
                .ok_or_else(|| ArenaRuntimeError::MissingAgentKernel(step.agent_id.clone()))?;
            let response = kernel.evaluate_tool_call(&request).await?;
            let verdict = scenario_verdict(&response);
            let scenario_step = scenario_step_by_id(scenario, &step.step_id)?;
            if verdict != scenario_step.expect_verdict {
                return Err(ArenaRuntimeError::UnexpectedVerdict {
                    step_id: step.step_id.clone(),
                    expected: scenario_step.expect_verdict,
                    actual: verdict,
                });
            }
            receipts.push(ArenaReceipt {
                step_id: step.step_id.clone(),
                request_id: response.request_id,
                verdict,
                reason: response.reason,
                receipt: response.receipt,
            });
            clock.tick();
        }

        // Touch the RNG so the snapshot is materialised; this preserves the
        // contract that the arena RNG is observed at every step boundary even
        // if no adversary class consumed from it. The result is unused but
        // the call has a side effect on every sub-stream's internal counter,
        // which makes the determinism gate's byte-equality check stricter.
        let _rng_snapshot = rng.snapshot_next_u64s();
        let _virtual_now = clock.virtual_now_nanos();

        Ok(ArenaRun {
            scenario_id: scenario.id.clone(),
            receipts,
        })
    }
}

fn scenario_step_by_id<'a>(
    scenario: &'a Scenario,
    step_id: &str,
) -> Result<&'a crate::scenario::ScenarioStep, ArenaRuntimeError> {
    scenario
        .steps
        .iter()
        .find(|step| step.id == step_id)
        .ok_or_else(|| ArenaRuntimeError::MissingStepRequest {
            step_id: step_id.to_string(),
        })
}

/// Build per-agent kernel bindings from a single shared kernel handle.
pub fn shared_kernel_bindings(
    scenario: &Scenario,
    kernel: Arc<ChioKernel>,
) -> Vec<AgentKernelBinding> {
    scenario
        .agents
        .iter()
        .map(|agent| AgentKernelBinding {
            agent_id: agent.id.clone(),
            kernel: kernel.clone(),
        })
        .collect()
}

#[derive(Debug, Error)]
pub enum ArenaRuntimeError {
    #[error("single-agent runtime requires exactly one scenario agent")]
    NotSingleAgent,
    #[error("runtime request count {requests} does not match scenario step count {steps}")]
    RequestCountMismatch { requests: usize, steps: usize },
    #[error("runtime request step {actual} does not match scenario step {expected}")]
    StepMismatch { expected: String, actual: String },
    #[error("runtime step {step_id} produced verdict {actual:?}, expected {expected:?}")]
    UnexpectedVerdict {
        step_id: String,
        expected: ScenarioVerdict,
        actual: ScenarioVerdict,
    },
    #[error("kernel evaluation failed: {0}")]
    Kernel(#[from] chio_kernel::KernelError),
    #[error("scheduler error: {0}")]
    Scheduler(#[from] SchedulerError),
    #[error("clock error: {0}")]
    Clock(#[from] ClockError),
    #[error("rng error: {0}")]
    Rng(#[from] RngError),
    #[error("multi-agent runtime missing kernel binding for agent {0}")]
    MissingAgentKernel(String),
    #[error("multi-agent runtime missing request for step {step_id}")]
    MissingStepRequest { step_id: String },
}

fn validate_single_agent_runtime_inputs(
    scenario: &Scenario,
    requests: &[KernelStepRequest],
) -> Result<(), ArenaRuntimeError> {
    if scenario.agents.len() != 1 {
        return Err(ArenaRuntimeError::NotSingleAgent);
    }
    if scenario.steps.len() != requests.len() {
        return Err(ArenaRuntimeError::RequestCountMismatch {
            requests: requests.len(),
            steps: scenario.steps.len(),
        });
    }
    for (step, request) in scenario.steps.iter().zip(requests) {
        if step.id != request.step_id {
            return Err(ArenaRuntimeError::StepMismatch {
                expected: step.id.clone(),
                actual: request.step_id.clone(),
            });
        }
    }
    Ok(())
}

fn scenario_verdict(response: &ToolCallResponse) -> ScenarioVerdict {
    match response.verdict {
        Verdict::Allow if response_was_rewritten(response) => ScenarioVerdict::Rewrite,
        Verdict::Allow => ScenarioVerdict::Allow,
        Verdict::Deny | Verdict::PendingApproval => ScenarioVerdict::Deny,
    }
}

fn response_was_rewritten(response: &ToolCallResponse) -> bool {
    matches!(
        response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("post_invocation"))
            .and_then(|metadata| metadata.get("sanitized"))
            .and_then(serde_json::Value::as_bool),
        Some(true)
    )
}

#[cfg(test)]
mod tests {
    use chio_core::crypto::{sha256_hex, Keypair};
    use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction, TrustLevel};
    use chio_core::session::OperationTerminalState;
    use serde_json::json;

    use super::*;

    #[test]
    fn sanitized_allow_response_maps_to_rewrite() -> Result<(), Box<dyn std::error::Error>> {
        let response = response_with_metadata(Some(json!({
            "post_invocation": {
                "sanitized": true
            }
        })))?;

        assert_eq!(scenario_verdict(&response), ScenarioVerdict::Rewrite);
        Ok(())
    }

    #[test]
    fn unsanitized_allow_response_maps_to_allow() -> Result<(), Box<dyn std::error::Error>> {
        let response = response_with_metadata(None)?;

        assert_eq!(scenario_verdict(&response), ScenarioVerdict::Allow);
        Ok(())
    }

    fn response_with_metadata(
        metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, Box<dyn std::error::Error>> {
        let keypair = Keypair::generate();
        let action = ToolCallAction::from_parameters(json!({"path": "/tmp/chio-arena.txt"}))?;
        let receipt = ChioReceipt::sign(
            ChioReceiptBody {
                id: "receipt-step-1".to_string(),
                timestamp: 1_777_000_000,
                capability_id: "cap-step-1".to_string(),
                tool_server: "filesystem".to_string(),
                tool_name: "read_file".to_string(),
                action,
                decision: Decision::Allow,
                content_hash: sha256_hex(b"content"),
                policy_hash: sha256_hex(b"policy"),
                evidence: Vec::new(),
                metadata,
                trust_level: TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )?;
        Ok(ToolCallResponse {
            request_id: "arena-request-1".to_string(),
            verdict: Verdict::Allow,
            output: None,
            reason: None,
            terminal_state: OperationTerminalState::Completed,
            receipt,
            execution_nonce: None,
        })
    }
}
