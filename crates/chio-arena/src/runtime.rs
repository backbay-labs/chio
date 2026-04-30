use std::sync::Arc;

use chio_kernel::{ChioKernel, ToolCallRequest, ToolCallResponse, Verdict};
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
