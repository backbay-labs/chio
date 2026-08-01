//! Protocol messages between Agent and Kernel.
//!
//! All messages are serialized as length-prefixed canonical JSON (RFC 8785).
//! The Agent sends `AgentMessage` variants; the Kernel responds with
//! `KernelMessage` variants.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json_bytes;
use crate::capability::governance::{
    GovernedApprovalToken, GovernedTransactionIntent, ThresholdApprovalProposal,
};
use crate::capability::supplemental_authorization::OpaqueSupplementalAuthorization;
use crate::capability::token::CapabilityToken;
use crate::crypto::{PublicKey, Signature};
use crate::receipt::body::ChioReceipt;

/// Fields that bind an execution nonce to one tool invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceBinding {
    pub subject_id: String,
    #[serde(default)]
    pub request_id: String,
    pub capability_id: String,
    pub tool_server: String,
    pub tool_name: String,
    pub parameter_hash: String,
}

/// Signable body of a kernel-issued execution nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionNonce {
    pub schema: String,
    pub nonce_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub bound_to: NonceBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved_hold_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserving_request_id: Option<String>,
}

/// Kernel-signed execution nonce carried across agent/kernel transports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedExecutionNonce {
    pub nonce: ExecutionNonce,
    pub signature: Signature,
}

impl SignedExecutionNonce {
    #[must_use]
    pub fn nonce_id(&self) -> &str {
        &self.nonce.nonce_id
    }

    #[must_use]
    pub fn expires_at(&self) -> i64 {
        self.nonce.expires_at
    }

    #[must_use]
    pub fn reserved_hold_id(&self) -> Option<&str> {
        self.nonce.reserved_hold_id.as_deref()
    }

    #[must_use]
    pub fn reserving_request_id(&self) -> Option<&str> {
        self.nonce.reserving_request_id.as_deref()
    }
}

impl crate::receipt::authoritative_spend::PresentedNonceView for SignedExecutionNonce {
    fn nonce_id(&self) -> &str {
        &self.nonce.nonce_id
    }

    fn bound_capability_id(&self) -> &str {
        &self.nonce.bound_to.capability_id
    }

    fn bound_tool_server(&self) -> &str {
        &self.nonce.bound_to.tool_server
    }

    fn bound_tool_name(&self) -> &str {
        &self.nonce.bound_to.tool_name
    }

    fn bound_parameter_hash(&self) -> &str {
        &self.nonce.bound_to.parameter_hash
    }

    fn bound_reserved_hold_id(&self) -> Option<&str> {
        self.nonce.reserved_hold_id.as_deref()
    }

    fn verify_signed_by(&self, key: &PublicKey) -> bool {
        canonical_json_bytes(&self.nonce).is_ok_and(|bytes| key.verify(&bytes, &self.signature))
    }
}

/// Messages sent from the Agent to the Kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentMessage {
    /// Request to invoke a tool, presenting a capability token as authority.
    ToolCallRequest {
        /// Correlation ID (UUIDv7 recommended).
        id: String,
        /// The signed capability token authorizing this call.
        capability_token: Box<CapabilityToken>,
        /// Target tool server for this invocation.
        server_id: String,
        /// Name of the tool to invoke (must be in the token's scope).
        tool: String,
        /// Tool input parameters.
        params: Box<serde_json::Value>,
        /// Governed transaction the agent is asking the kernel to authorize.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        governed_intent: Option<Box<GovernedTransactionIntent>>,
        /// Single approval covering the governed intent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approval_token: Option<Box<GovernedApprovalToken>>,
        /// Approvals collected for a threshold proposal.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        approval_tokens: Vec<GovernedApprovalToken>,
        /// Threshold policy the collected approvals are counted against.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        threshold_approval_proposal: Option<Box<ThresholdApprovalProposal>>,
        /// Opaque authorization extension carried through to the kernel.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        supplemental_authorization: Option<Box<OpaqueSupplementalAuthorization>>,
        /// Kernel-issued nonce from a strict execution preflight for this request.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        execution_nonce: Option<Box<SignedExecutionNonce>>,
    },
    /// Request a listing of the agent's current capabilities.
    ListCapabilities,
    /// Liveness probe.
    Heartbeat,
}

impl AgentMessage {
    /// Reports why the message's authorization fields cannot be honoured together,
    /// or `None` when the combination is admissible.
    ///
    /// The wire schema states these rules, but a peer that ignores the schema must
    /// still be refused rather than evaluated against a partial authorization set.
    #[must_use]
    pub fn authorization_conflict(&self) -> Option<&'static str> {
        let Self::ToolCallRequest {
            approval_token,
            approval_tokens,
            threshold_approval_proposal,
            ..
        } = self
        else {
            return None;
        };
        if approval_token.is_some() && !approval_tokens.is_empty() {
            return Some("approval_token and approval_tokens are mutually exclusive");
        }
        if threshold_approval_proposal.is_some() && approval_tokens.is_empty() {
            return Some("threshold_approval_proposal requires at least one approval token");
        }
        if !approval_tokens.is_empty() && threshold_approval_proposal.is_none() {
            return Some("approval_tokens require a threshold_approval_proposal");
        }
        None
    }
}

/// Messages sent from the Kernel to the Agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KernelMessage {
    /// Streaming chunk emitted before the final tool response.
    ToolCallChunk {
        /// Correlation ID matching the parent request.
        id: String,
        /// Zero-based chunk index in arrival order.
        chunk_index: u64,
        /// Chunk payload forwarded to the agent.
        data: serde_json::Value,
    },
    /// Response to a tool call request (success or policy-denied).
    ToolCallResponse {
        /// Correlation ID matching the request.
        id: String,
        /// Tool execution result, or an error.
        result: ToolCallResult,
        /// Signed receipt attesting to the decision.
        receipt: Box<ChioReceipt>,
        /// Kernel-issued nonce that must be presented on the exact retry.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        execution_nonce: Option<Box<SignedExecutionNonce>>,
    },
    /// Response to a ListCapabilities request.
    CapabilityList {
        /// The agent's currently valid capabilities.
        capabilities: Vec<CapabilityToken>,
    },
    /// Notification that a capability has been revoked.
    CapabilityRevoked {
        /// ID of the revoked capability.
        id: String,
    },
    /// Liveness probe response.
    Heartbeat,
}

/// The outcome of a tool call: either a successful result value or an error.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ToolCallResult {
    /// The tool call succeeded.
    Ok {
        /// The tool's return value.
        value: serde_json::Value,
    },
    /// The tool call produced streamed output and completed successfully.
    StreamComplete {
        /// Number of chunks that were emitted before completion.
        total_chunks: u64,
    },
    /// The tool call was explicitly cancelled.
    Cancelled {
        /// Human-readable cancellation reason.
        reason: String,
        /// Number of stream chunks emitted before cancellation.
        chunks_received: u64,
    },
    /// The tool call did not reach a complete terminal result.
    Incomplete {
        /// Human-readable interruption reason.
        reason: String,
        /// Number of stream chunks emitted before interruption.
        chunks_received: u64,
    },
    /// The tool call was denied or failed.
    Err {
        /// Structured error.
        error: ToolCallError,
    },
}

/// Errors that can occur during tool call processing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "code", content = "detail", rename_all = "snake_case")]
pub enum ToolCallError {
    /// The capability token was rejected (invalid signature, wrong subject, etc.).
    CapabilityDenied(String),
    /// The capability token has expired.
    CapabilityExpired,
    /// The capability token has been revoked.
    CapabilityRevoked,
    /// A policy guard denied the action.
    PolicyDenied {
        /// Which guard denied the action.
        guard: String,
        /// Human-readable reason.
        reason: String,
    },
    /// The tool server returned an error.
    ToolServerError(String),
    /// An internal error in the Kernel.
    InternalError(String),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::capability::{
        scope::{ChioScope, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    };
    use crate::crypto::Keypair;
    use crate::receipt::{
        body::{ChioReceipt, ChioReceiptBody},
        decision::{Decision, ToolCallAction},
        kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
        metadata::GuardEvidence,
    };

    fn make_token(kp: &Keypair) -> CapabilityToken {
        let body = CapabilityTokenBody {
            id: "cap-msg-001".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "srv".to_string(),
                    tool_name: "echo".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            issued_at: 1000,
            expires_at: 2000,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        };
        CapabilityToken::sign(body, kp).unwrap()
    }

    fn make_receipt(kp: &Keypair) -> ChioReceipt {
        let body = ChioReceiptBody {
            id: "rcpt-msg-001".to_string(),
            timestamp: 1500,
            capability_id: "cap-msg-001".to_string(),
            tool_server: "srv".to_string(),
            tool_name: "echo".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"text": "hello"})).unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: crate::sha256_hex(br#"{"output":"world"}"#),
            policy_hash: "deadbeef".to_string(),
            evidence: vec![GuardEvidence {
                guard_name: "ShellCommandGuard".to_string(),
                verdict: true,
                details: None,
            }],
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp.public_key(),
            bbs_projection_version: None,
        };
        ChioReceipt::sign(body, kp).unwrap()
    }

    fn make_approval(kp: &Keypair) -> GovernedApprovalToken {
        use crate::capability::governance::{GovernedApprovalDecision, GovernedApprovalTokenBody};

        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "approval-msg-001".to_string(),
                approver: kp.public_key(),
                subject: kp.public_key(),
                governed_intent_hash: crate::sha256_hex(b"intent"),
                request_id: "req-001".to_string(),
                threshold_proposal_hash: None,
                issued_at: 1000,
                expires_at: 2000,
                decision: GovernedApprovalDecision::Approved,
            },
            kp,
        )
        .unwrap()
    }

    fn governed_request(
        kp: &Keypair,
        approval_token: Option<Box<GovernedApprovalToken>>,
        approval_tokens: Vec<GovernedApprovalToken>,
        threshold_approval_proposal: Option<Box<ThresholdApprovalProposal>>,
    ) -> AgentMessage {
        AgentMessage::ToolCallRequest {
            id: "req-001".to_string(),
            capability_token: Box::new(make_token(kp)),
            server_id: "srv".to_string(),
            tool: "echo".to_string(),
            params: Box::new(serde_json::json!({"text": "hello"})),
            governed_intent: None,
            approval_token,
            approval_tokens,
            threshold_approval_proposal,
            supplemental_authorization: None,
            execution_nonce: None,
        }
    }

    #[test]
    fn authorization_conflict_rejects_incompatible_approval_sets() {
        let kp = Keypair::generate();

        assert!(governed_request(&kp, None, Vec::new(), None)
            .authorization_conflict()
            .is_none());
        assert!(
            governed_request(&kp, Some(Box::new(make_approval(&kp))), Vec::new(), None)
                .authorization_conflict()
                .is_none()
        );
        assert!(governed_request(
            &kp,
            Some(Box::new(make_approval(&kp))),
            vec![make_approval(&kp)],
            None,
        )
        .authorization_conflict()
        .is_some());
        assert!(governed_request(&kp, None, vec![make_approval(&kp)], None)
            .authorization_conflict()
            .is_some());
        assert!(AgentMessage::Heartbeat.authorization_conflict().is_none());
    }

    #[test]
    fn agent_message_tool_call_authorization_fields_are_optional_on_the_wire() {
        let kp = Keypair::generate();
        let legacy = serde_json::json!({
            "type": "tool_call_request",
            "id": "req-001",
            "capability_token": make_token(&kp),
            "server_id": "srv",
            "tool": "echo",
            "params": {"text": "hello"},
        });
        let restored: AgentMessage = serde_json::from_value(legacy).unwrap();
        match &restored {
            AgentMessage::ToolCallRequest {
                approval_tokens,
                approval_token,
                ..
            } => {
                assert!(approval_token.is_none());
                assert!(approval_tokens.is_empty());
            }
            _ => panic!("wrong variant"),
        }
        assert!(restored.authorization_conflict().is_none());

        let reencoded = serde_json::to_value(&restored).unwrap();
        assert!(reencoded.get("approval_tokens").is_none());
        assert!(reencoded.get("governed_intent").is_none());
    }

    #[test]
    fn agent_message_tool_call_serde_roundtrip() {
        let kp = Keypair::generate();
        let msg = AgentMessage::ToolCallRequest {
            id: "req-001".to_string(),
            capability_token: Box::new(make_token(&kp)),
            server_id: "srv".to_string(),
            tool: "echo".to_string(),
            params: Box::new(serde_json::json!({"text": "hello"})),
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
        };

        let json = serde_json::to_string_pretty(&msg).unwrap();
        let restored: AgentMessage = serde_json::from_str(&json).unwrap();

        match restored {
            AgentMessage::ToolCallRequest {
                id,
                server_id,
                tool,
                ..
            } => {
                assert_eq!(id, "req-001");
                assert_eq!(server_id, "srv");
                assert_eq!(tool, "echo");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn agent_message_heartbeat_serde_roundtrip() {
        let msg = AgentMessage::Heartbeat;
        let json = serde_json::to_string(&msg).unwrap();
        let restored: AgentMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(restored, AgentMessage::Heartbeat));
    }

    #[test]
    fn agent_message_list_capabilities_serde_roundtrip() {
        let msg = AgentMessage::ListCapabilities;
        let json = serde_json::to_string(&msg).unwrap();
        let restored: AgentMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(restored, AgentMessage::ListCapabilities));
    }

    #[test]
    fn kernel_message_tool_response_serde_roundtrip() {
        let kp = Keypair::generate();
        let msg = KernelMessage::ToolCallResponse {
            id: "req-001".to_string(),
            result: ToolCallResult::Ok {
                value: serde_json::json!({"output": "world"}),
            },
            receipt: Box::new(make_receipt(&kp)),
            execution_nonce: None,
        };

        let json = serde_json::to_string_pretty(&msg).unwrap();
        let restored: KernelMessage = serde_json::from_str(&json).unwrap();

        match restored {
            KernelMessage::ToolCallResponse {
                id,
                result,
                receipt,
                execution_nonce,
            } => {
                assert_eq!(id, "req-001");
                assert!(matches!(result, ToolCallResult::Ok { .. }));
                assert!(receipt.verify_signature().unwrap());
                assert!(execution_nonce.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn kernel_message_tool_chunk_serde_roundtrip() {
        let msg = KernelMessage::ToolCallChunk {
            id: "req-001".to_string(),
            chunk_index: 2,
            data: serde_json::json!({"delta": "world"}),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let restored: KernelMessage = serde_json::from_str(&json).unwrap();

        match restored {
            KernelMessage::ToolCallChunk {
                id,
                chunk_index,
                data,
            } => {
                assert_eq!(id, "req-001");
                assert_eq!(chunk_index, 2);
                assert_eq!(data["delta"], "world");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn kernel_message_capability_revoked_serde_roundtrip() {
        let msg = KernelMessage::CapabilityRevoked {
            id: "cap-revoked-001".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let restored: KernelMessage = serde_json::from_str(&json).unwrap();
        match restored {
            KernelMessage::CapabilityRevoked { id } => assert_eq!(id, "cap-revoked-001"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn tool_call_error_serde_roundtrip() {
        let errors = vec![
            ToolCallError::CapabilityDenied("bad signature".to_string()),
            ToolCallError::CapabilityExpired,
            ToolCallError::CapabilityRevoked,
            ToolCallError::PolicyDenied {
                guard: "ForbiddenPathGuard".to_string(),
                reason: "/etc/shadow is forbidden".to_string(),
            },
            ToolCallError::ToolServerError("connection refused".to_string()),
            ToolCallError::InternalError("out of memory".to_string()),
        ];

        for error in &errors {
            let json = serde_json::to_string(error).unwrap();
            let restored: ToolCallError = serde_json::from_str(&json).unwrap();
            assert_eq!(error, &restored);
        }
    }

    #[test]
    fn tool_call_result_ok_serde_roundtrip() {
        let result = ToolCallResult::Ok {
            value: serde_json::json!({"data": [1, 2, 3]}),
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: ToolCallResult = serde_json::from_str(&json).unwrap();
        assert!(matches!(restored, ToolCallResult::Ok { .. }));
    }

    #[test]
    fn tool_call_result_stream_complete_serde_roundtrip() {
        let result = ToolCallResult::StreamComplete { total_chunks: 3 };
        let json = serde_json::to_string(&result).unwrap();
        let restored: ToolCallResult = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            restored,
            ToolCallResult::StreamComplete { total_chunks: 3 }
        ));
    }

    #[test]
    fn tool_call_result_cancelled_serde_roundtrip() {
        let result = ToolCallResult::Cancelled {
            reason: "cancelled by client".to_string(),
            chunks_received: 2,
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: ToolCallResult = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            restored,
            ToolCallResult::Cancelled {
                chunks_received: 2,
                ..
            }
        ));
    }

    #[test]
    fn tool_call_result_incomplete_serde_roundtrip() {
        let result = ToolCallResult::Incomplete {
            reason: "stream ended early".to_string(),
            chunks_received: 4,
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: ToolCallResult = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            restored,
            ToolCallResult::Incomplete {
                chunks_received: 4,
                ..
            }
        ));
    }

    #[test]
    fn tool_call_result_err_serde_roundtrip() {
        let result = ToolCallResult::Err {
            error: ToolCallError::CapabilityExpired,
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: ToolCallResult = serde_json::from_str(&json).unwrap();
        match restored {
            ToolCallResult::Err { error } => {
                assert_eq!(error, ToolCallError::CapabilityExpired);
            }
            _ => panic!("wrong variant"),
        }
    }
}
