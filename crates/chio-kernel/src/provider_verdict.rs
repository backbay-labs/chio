//! Provider-fabric verdict shim.
//!
//! Wires the provider-agnostic [`chio_tool_call_fabric`] crate into the kernel
//! via a thin conversion layer. Lifts a [`ToolInvocation`] into a kernel
//! [`ToolCallRequest`] (when paired with the surrounding capability context)
//! and lowers a kernel [`ToolCallResponse`] into a fabric [`VerdictResult`].
//! The shim is a single conversion point so the fabric vocabulary never leaks
//! into the kernel's internals.

use chio_core::canonical::canonical_json_bytes;
use chio_tool_call_fabric::{DenyReason, ProviderId, ReceiptId, ToolInvocation, VerdictResult};

use crate::runtime::{ToolCallRequest, ToolCallResponse, Verdict};
use crate::{AgentId, ServerId};
use chio_core::capability::CapabilityToken;

/// Errors surfaced when adapting fabric types into the kernel's MCP path.
///
/// The shim is conversion-only; the underlying MCP pipeline still owns its
/// own [`crate::KernelError`] surface. This enum is scoped to the bytes-to-
/// JSON translation step that bridges the fabric's canonical-JSON argument
/// payload into [`serde_json::Value`].
#[derive(Debug, thiserror::Error)]
pub enum ProviderVerdictError {
    /// The fabric arguments payload was not valid JSON. Fabric promises
    /// canonical-JSON bytes (RFC 8785); a parse failure here is a contract
    /// violation by the upstream adapter.
    #[error("fabric arguments payload is not valid JSON: {0}")]
    InvalidArguments(#[source] serde_json::Error),
}

/// Build a [`ToolCallRequest`] from a fabric [`ToolInvocation`] plus the
/// surrounding kernel context (capability token, calling agent, target tool
/// server). All policy decisions remain with `evaluate_tool_call*`; this
/// helper only translates the wire shape.
///
/// `request_id` defaults to `invocation.provenance.request_id` so the
/// upstream provider's request id flows into the kernel verdict and into the
/// resulting receipt without a second round of bookkeeping.
pub fn build_tool_call_request(
    invocation: &ToolInvocation,
    capability: CapabilityToken,
    agent_id: AgentId,
    server_id: ServerId,
) -> Result<ToolCallRequest, ProviderVerdictError> {
    let arguments = if invocation.arguments.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&invocation.arguments)
            .map_err(ProviderVerdictError::InvalidArguments)?
    };

    Ok(ToolCallRequest {
        request_id: invocation.provenance.request_id.clone(),
        capability,
        tool_name: invocation.tool_name.clone(),
        server_id,
        agent_id,
        arguments,
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    })
}

/// Lower a kernel [`ToolCallResponse`] into a fabric [`VerdictResult`].
///
/// The mapping is structural and lossless within the fabric's vocabulary:
///
/// - `Verdict::Allow` -> `VerdictResult::Allow { redactions: [], receipt_id }`
/// - `Verdict::Deny` (and the non-allow terminal variants) ->
///   `VerdictResult::Deny { reason, receipt_id }`
/// - `Verdict::PendingApproval` -> `VerdictResult::Deny { reason, receipt_id }`
///   so callers fail-closed if they ignore the approval channel; phases that
///   plumb HITL across the fabric will replace this branch.
///
/// Redactions are always empty; data-guard redaction lists are not yet wired.
#[must_use]
pub fn verdict_result_from_response(
    invocation: &ToolInvocation,
    response: &ToolCallResponse,
) -> VerdictResult {
    let receipt_id = ReceiptId(response.receipt.id.clone());
    match response.verdict {
        Verdict::Allow => VerdictResult::Allow {
            redactions: Vec::new(),
            receipt_id,
        },
        Verdict::Deny => VerdictResult::Deny {
            reason: classify_deny_reason(invocation, response),
            receipt_id,
        },
        Verdict::PendingApproval => VerdictResult::Deny {
            reason: DenyReason::PolicyDeny {
                rule_id: "kernel.pending_approval".to_string(),
            },
            receipt_id,
        },
    }
}

/// Pick a [`DenyReason`] variant from the kernel response.
///
/// The kernel's deny pathway encodes its rationale as a free-form
/// [`ToolCallResponse::reason`] string. We surface this as
/// [`DenyReason::PolicyDeny`] with the kernel's reason as the `rule_id`,
/// preserving information for auditors without inventing a richer mapping.
/// Specialized variants (`CapabilityExpired`, `BudgetExceeded`, etc.) require
/// kernel-side classification work; the structured taxonomy is not yet wired.
fn classify_deny_reason(_invocation: &ToolInvocation, response: &ToolCallResponse) -> DenyReason {
    let detail = response
        .reason
        .clone()
        .unwrap_or_else(|| "kernel.deny".to_string());
    DenyReason::PolicyDeny { rule_id: detail }
}

/// Stable canonical-JSON byte form of a [`ToolInvocation`].
///
/// Adapters frequently need a stable hash of the invocation for telemetry
/// and replay correlation. The kernel exposes its canonical-JSON helper
/// already; this is a typed wrapper so callers do not import the helper
/// directly. The wrapped helper returns the workspace's own
/// [`chio_core::error::Error`]; callers that already work in that error
/// space can map straight through `?`.
pub fn canonical_invocation_bytes(
    invocation: &ToolInvocation,
) -> chio_core::error::Result<Vec<u8>> {
    canonical_json_bytes(invocation)
}

/// Marker constant tying the shim to the fabric crate version it was built
/// against. Used by the workspace's drift checks to flag when the fabric
/// trait surface evolves without the kernel shim being revisited.
pub const FABRIC_SHIM_PROVIDER_LANES: &[ProviderId] = &[
    ProviderId::OpenAi,
    ProviderId::Anthropic,
    ProviderId::Bedrock,
];

impl crate::ChioKernel {
    /// Compute a fabric [`VerdictResult`] for a provider-native tool
    /// invocation by routing through the existing MCP verdict path.
    ///
    /// The shim builds a [`ToolCallRequest`] from the supplied invocation
    /// plus the surrounding capability context, calls
    /// [`crate::ChioKernel::evaluate_tool_call_blocking`], and lowers the
    /// kernel response into a fabric verdict via
    /// [`verdict_result_from_response`].
    ///
    /// The kernel-side fabric integration point. Adapters call this method
    /// with an invocation already lifted from the upstream wire format and a
    /// capability token resolved from their authentication path.
    pub fn verdict_for_provider_invocation(
        &self,
        invocation: &ToolInvocation,
        capability: CapabilityToken,
        agent_id: AgentId,
        server_id: ServerId,
    ) -> Result<VerdictResult, crate::KernelError> {
        let request = build_tool_call_request(invocation, capability, agent_id, server_id)
            .map_err(|e| {
                crate::KernelError::Internal(format!(
                    "fabric arguments could not be lowered into kernel JSON: {e}"
                ))
            })?;
        let response = self.evaluate_tool_call_blocking(&request)?;
        Ok(verdict_result_from_response(invocation, &response))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_core::receipt::{ChioReceipt, Decision, ToolCallAction};
    use chio_core::session::OperationTerminalState;
    use chio_tool_call_fabric::{Principal, ProvenanceStamp};
    use std::time::{Duration, SystemTime};

    fn sample_invocation() -> ToolInvocation {
        ToolInvocation {
            provider: ProviderId::OpenAi,
            tool_name: "search_web".to_string(),
            arguments: br#"{"query":"chio"}"#.to_vec(),
            provenance: ProvenanceStamp {
                provider: ProviderId::OpenAi,
                request_id: "call_abc123".to_string(),
                api_version: "responses.2026-04-25".to_string(),
                principal: Principal::OpenAiOrg {
                    org_id: "org_123".to_string(),
                },
                received_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            },
        }
    }

    fn synthetic_receipt(id: &str, decision: Decision) -> ChioReceipt {
        // Build a minimal unsigned receipt for the conversion tests. These
        // tests only exercise the structural mapping from kernel verdict
        // to fabric verdict; signature verification is covered by the
        // kernel's own receipt tests.
        let body = chio_core::receipt::ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_000,
            capability_id: "cap-test".to_string(),
            tool_server: "srv-test".to_string(),
            tool_name: "search_web".to_string(),
            action: ToolCallAction {
                parameters: serde_json::json!({"query": "chio"}),
                parameter_hash: "0".repeat(64),
            },
            decision,
            content_hash: "0".repeat(64),
            policy_hash: "0".repeat(64),
            evidence: Vec::new(),
            metadata: None,
            trust_level: Default::default(),
            tenant_id: None,
            kernel_key: chio_core::crypto::Keypair::generate().public_key(),
        };
        let kp = chio_core::crypto::Keypair::generate();
        ChioReceipt::sign(body, &kp).unwrap()
    }

    fn allow_response() -> ToolCallResponse {
        ToolCallResponse {
            request_id: "call_abc123".to_string(),
            verdict: Verdict::Allow,
            output: None,
            reason: None,
            terminal_state: OperationTerminalState::Completed,
            receipt: synthetic_receipt("rcpt_allow", Decision::Allow),
            execution_nonce: None,
        }
    }

    fn deny_response(reason: &str) -> ToolCallResponse {
        let dec = Decision::Deny {
            reason: reason.to_string(),
            guard: "policy.deny".to_string(),
        };
        ToolCallResponse {
            request_id: "call_abc123".to_string(),
            verdict: Verdict::Deny,
            output: None,
            reason: Some(reason.to_string()),
            terminal_state: OperationTerminalState::Completed,
            receipt: synthetic_receipt("rcpt_deny", dec),
            execution_nonce: None,
        }
    }

    fn pending_response() -> ToolCallResponse {
        ToolCallResponse {
            request_id: "call_abc123".to_string(),
            verdict: Verdict::PendingApproval,
            output: None,
            reason: Some("approval pending".to_string()),
            terminal_state: OperationTerminalState::Incomplete {
                reason: "approval pending".to_string(),
            },
            receipt: synthetic_receipt("rcpt_pending", Decision::Allow),
            execution_nonce: None,
        }
    }

    #[test]
    fn provider_verdict_allow_maps_to_fabric_allow() {
        let inv = sample_invocation();
        let resp = allow_response();
        let v = verdict_result_from_response(&inv, &resp);
        match v {
            VerdictResult::Allow {
                redactions,
                receipt_id,
            } => {
                assert!(redactions.is_empty());
                assert_eq!(receipt_id, ReceiptId("rcpt_allow".to_string()));
            }
            other => panic!("expected allow, got {other:?}"),
        }
    }

    #[test]
    fn provider_verdict_deny_carries_kernel_reason_as_rule_id() {
        let inv = sample_invocation();
        let resp = deny_response("budget exhausted");
        let v = verdict_result_from_response(&inv, &resp);
        match v {
            VerdictResult::Deny { reason, receipt_id } => {
                assert_eq!(receipt_id, ReceiptId("rcpt_deny".to_string()));
                match reason {
                    DenyReason::PolicyDeny { rule_id } => {
                        assert_eq!(rule_id, "budget exhausted");
                    }
                    other => panic!("expected policy_deny, got {other:?}"),
                }
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn provider_verdict_deny_falls_back_to_default_rule_id_when_reason_missing() {
        let inv = sample_invocation();
        let mut resp = deny_response("unused");
        resp.reason = None;
        let v = verdict_result_from_response(&inv, &resp);
        let VerdictResult::Deny { reason, .. } = v else {
            panic!("expected deny");
        };
        let DenyReason::PolicyDeny { rule_id } = reason else {
            panic!("expected policy_deny");
        };
        assert_eq!(rule_id, "kernel.deny");
    }

    #[test]
    fn provider_verdict_pending_approval_fails_closed() {
        let inv = sample_invocation();
        let resp = pending_response();
        let v = verdict_result_from_response(&inv, &resp);
        match v {
            VerdictResult::Deny { reason, .. } => match reason {
                DenyReason::PolicyDeny { rule_id } => {
                    assert_eq!(rule_id, "kernel.pending_approval");
                }
                other => panic!("expected policy_deny for pending, got {other:?}"),
            },
            other => panic!("expected deny for pending approval, got {other:?}"),
        }
    }

    #[test]
    fn provider_verdict_receipt_id_round_trips() {
        let inv = sample_invocation();
        let resp = allow_response();
        let v = verdict_result_from_response(&inv, &resp);
        let json = serde_json::to_string(&v).unwrap();
        let back: VerdictResult = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn provider_verdict_canonical_invocation_bytes_are_stable() {
        let inv = sample_invocation();
        let a = canonical_invocation_bytes(&inv).unwrap();
        let b = canonical_invocation_bytes(&inv).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn provider_verdict_known_provider_lanes_are_three() {
        // Sanity check that the provider-id constant tracks the fabric.
        assert_eq!(FABRIC_SHIM_PROVIDER_LANES.len(), 3);
    }
}
