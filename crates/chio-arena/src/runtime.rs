use std::sync::Arc;

use chio_kernel::{ChioKernel, ToolCallRequest, Verdict};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::scenario::{Scenario, ScenarioVerdict};

#[derive(Debug)]
pub struct KernelStepRequest {
    pub step_id: String,
    pub request: ToolCallRequest,
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
        for request in requests {
            let response = self.kernel.evaluate_tool_call(&request.request).await?;
            receipts.push(ArenaReceipt {
                step_id: request.step_id,
                request_id: response.request_id,
                verdict: scenario_verdict(response.verdict),
                reason: response.reason,
                receipt: response.receipt,
            });
        }

        Ok(ArenaRun {
            scenario_id: scenario.id.clone(),
            receipts,
        })
    }
}

#[derive(Debug, Error)]
pub enum ArenaRuntimeError {
    #[error("single-agent runtime requires exactly one scenario agent")]
    NotSingleAgent,
    #[error("runtime request count {requests} does not match scenario step count {steps}")]
    RequestCountMismatch { requests: usize, steps: usize },
    #[error("runtime request step {actual} does not match scenario step {expected}")]
    StepMismatch { expected: String, actual: String },
    #[error("kernel evaluation failed: {0}")]
    Kernel(#[from] chio_kernel::KernelError),
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

fn scenario_verdict(verdict: Verdict) -> ScenarioVerdict {
    match verdict {
        Verdict::Allow => ScenarioVerdict::Allow,
        Verdict::Deny | Verdict::PendingApproval => ScenarioVerdict::Deny,
    }
}
