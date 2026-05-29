//! Plan-level evaluation DTOs for pre-flight tool-call assessment.
//!
//! An agent planner can submit an ordered list of planned tool calls to
//! the kernel for a pre-flight evaluation. The kernel evaluates every
//! step independently against the planner's capability and the
//! pre-invocation portion of the guard pipeline, then returns per-step
//! verdicts so the caller can replan or abort early BEFORE any tool has
//! actually executed.
//!
//! Plan evaluation is intentionally stateless and pure: the kernel
//! performs no receipt emission, no budget mutation, no capability
//! revocation, and no tool-server dispatch. Dependencies between steps
//! are advisory metadata only in v1; the kernel does not topologically
//! sort the graph, refuse on cycles, or short-circuit downstream steps
//! when an earlier step is denied.
//!
//! Wire shapes below are the canonical JSON representations served by
//! `POST /evaluate-plan`. The endpoint returns `200 OK` with a
//! `PlanEvaluationResponse` regardless of the aggregate verdict:
//! denials are conveyed in the JSON, not as HTTP status codes.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::capability::{CapabilityToken, ModelMetadata};
use crate::{AgentId, CapabilityId, ServerId};

/// Stable identifier for a planned tool call within a plan.
///
/// Used both as the step's own `request_id` and to populate other
/// steps' `dependencies` lists. The kernel does not require this to be
/// globally unique; uniqueness within a plan is sufficient.
pub type PlannedToolCallId = String;

/// One step in a submitted plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedToolCall {
    /// Planner-assigned identifier for this step. Reused as the
    /// request identifier when the step is synthesised into a full
    /// `ToolCallRequest` for capability and guard evaluation.
    pub request_id: PlannedToolCallId,
    /// Target tool-server id.
    pub server_id: ServerId,
    /// Name of the tool to invoke.
    pub tool_name: String,
    /// Free-form tag describing the action the planner is modelling
    /// (e.g. `"read"`, `"write"`, `"transfer"`). The kernel does not
    /// interpret this field in v1; it is recorded for telemetry and
    /// future pre-invocation guards that want to discriminate on intent
    /// without inspecting parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Arguments the planner intends to pass to the tool server.
    pub parameters: serde_json::Value,
    /// Optional metadata describing the model executing the planner.
    ///
    /// Scoped per step (not per plan) so an orchestrator that routes
    /// individual steps across different models can declare each step's
    /// model independently. Consumed by `Constraint::ModelConstraint`
    /// enforcement in the same way as runtime `ToolCallRequest`s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_metadata: Option<ModelMetadata>,
    /// Other planned step ids this step conceptually depends on.
    ///
    /// Advisory only in v1: the kernel records the edges for downstream
    /// audit but does not topo-sort the plan, reject cycles, or suppress
    /// evaluation of dependent steps when a predecessor is denied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<PlannedToolCallId>,
}

/// Request body for `POST /evaluate-plan`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanEvaluationRequest {
    /// Caller-assigned identifier for this plan. Echoed in the response
    /// so the caller can correlate asynchronous evaluations.
    pub plan_id: String,
    /// Identifier of the capability under which every step is evaluated.
    /// Surfaced in the response for audit correlation; the kernel
    /// cross-checks this against the embedded token's `id` to reject
    /// mismatched submissions.
    pub planner_capability_id: CapabilityId,
    /// Full capability token authorising the plan. The kernel must have
    /// the signed token in hand to verify signature, delegation, and
    /// scope; it does not maintain a capability registry that could be
    /// indexed by id alone.
    pub planner_capability: CapabilityToken,
    /// Agent submitting the plan. Checked against the capability's
    /// `subject` binding in the same way as runtime tool calls.
    pub agent_id: AgentId,
    /// Ordered list of steps in the plan. Evaluated in submission order
    /// but each step evaluated independently.
    pub steps: Vec<PlannedToolCall>,
}

/// Aggregate verdict across every step in the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanVerdict {
    /// Every step is allowed under the planner's capability.
    Allowed,
    /// At least one but not all steps were denied.
    PartiallyDenied,
    /// Every step was denied.
    FullyDenied,
}

/// Verdict for a single step in a submitted plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepVerdict {
    /// Zero-based index of the step in the original submission order.
    pub step_index: usize,
    /// Per-step allow/deny verdict.
    pub verdict: StepVerdictKind,
    /// Human-readable reason, populated on deny and omitted on allow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Name of the guard that denied the step, when denial came from
    /// the pre-invocation guard pipeline. `None` for allows and for
    /// denials stemming from capability/scope checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard: Option<String>,
}

/// Allow/deny decision for a single step.
///
/// Distinct from `PlanVerdict` because an individual step is always
/// either allowed or denied; only the aggregate can be partial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepVerdictKind {
    /// The step would be allowed if submitted as a real tool call.
    Allowed,
    /// The step would be denied.
    Denied,
}

/// Response body for `POST /evaluate-plan`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanEvaluationResponse {
    /// Echoed plan identifier.
    pub plan_id: String,
    /// Aggregate verdict across every step.
    pub plan_verdict: PlanVerdict,
    /// Per-step verdicts in original submission order.
    pub step_verdicts: Vec<StepVerdict>,
}

impl PlanEvaluationResponse {
    /// Compute the aggregate verdict from a per-step verdict list.
    ///
    /// Returns `Allowed` when every step is allowed, `FullyDenied` when
    /// every step is denied, and `PartiallyDenied` otherwise. An empty
    /// plan is treated as `Allowed` by convention: the caller has
    /// declared no work, so nothing can be forbidden.
    #[must_use]
    pub fn aggregate(step_verdicts: &[StepVerdict]) -> PlanVerdict {
        if step_verdicts.is_empty() {
            return PlanVerdict::Allowed;
        }
        let any_allowed = step_verdicts
            .iter()
            .any(|v| matches!(v.verdict, StepVerdictKind::Allowed));
        let any_denied = step_verdicts
            .iter()
            .any(|v| matches!(v.verdict, StepVerdictKind::Denied));
        match (any_allowed, any_denied) {
            (true, false) => PlanVerdict::Allowed,
            (false, true) => PlanVerdict::FullyDenied,
            (true, true) => PlanVerdict::PartiallyDenied,
            // Unreachable: an empty slice was handled above.
            (false, false) => PlanVerdict::Allowed,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn allowed(index: usize) -> StepVerdict {
        StepVerdict {
            step_index: index,
            verdict: StepVerdictKind::Allowed,
            reason: None,
            guard: None,
        }
    }

    fn denied(index: usize, reason: &str) -> StepVerdict {
        StepVerdict {
            step_index: index,
            verdict: StepVerdictKind::Denied,
            reason: Some(reason.to_string()),
            guard: None,
        }
    }

    #[test]
    fn aggregate_empty_plan_is_allowed() {
        assert_eq!(PlanEvaluationResponse::aggregate(&[]), PlanVerdict::Allowed);
    }

    #[test]
    fn aggregate_all_allowed() {
        let steps = vec![allowed(0), allowed(1), allowed(2)];
        assert_eq!(
            PlanEvaluationResponse::aggregate(&steps),
            PlanVerdict::Allowed
        );
    }

    #[test]
    fn aggregate_all_denied() {
        let steps = vec![denied(0, "a"), denied(1, "b")];
        assert_eq!(
            PlanEvaluationResponse::aggregate(&steps),
            PlanVerdict::FullyDenied
        );
    }

    #[test]
    fn aggregate_partially_denied() {
        let steps = vec![allowed(0), allowed(1), denied(2, "out of scope")];
        assert_eq!(
            PlanEvaluationResponse::aggregate(&steps),
            PlanVerdict::PartiallyDenied
        );
    }

    #[test]
    fn planned_call_roundtrips_through_serde() {
        let call = PlannedToolCall {
            request_id: "step-1".to_string(),
            server_id: "srv-a".to_string(),
            tool_name: "read_file".to_string(),
            action: Some("read".to_string()),
            parameters: serde_json::json!({"path": "/tmp/hello"}),
            model_metadata: None,
            dependencies: vec!["step-0".to_string()],
        };
        let encoded = serde_json::to_string(&call).expect("serialize");
        let decoded: PlannedToolCall = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded.request_id, call.request_id);
        assert_eq!(decoded.dependencies, call.dependencies);
        assert_eq!(decoded.action.as_deref(), Some("read"));
    }
}
