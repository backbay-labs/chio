//! Chio tool-call fabric: provider-agnostic types and traits for LLM tool-call dispatch.
//!
//! This crate is the load-bearing contract between Chio and its three native
//! provider adapters (OpenAI Responses, Anthropic Messages, Bedrock Converse).
//! Each adapter lifts its native tool-call shape into [`ToolInvocation`] and
//! lowers the kernel's [`VerdictResult`] back into provider-native bytes via
//! the [`ProviderAdapter`] trait below.
//!
//! Phase 1 of M07 establishes:
//!
//! - The verbatim trait surface ([`ProviderId`], [`Principal`],
//!   [`ProvenanceStamp`], [`ToolInvocation`], [`VerdictResult`],
//!   [`DenyReason`], [`ProviderError`], [`ProviderAdapter`]).
//! - A [`provenance::sign_provenance`] helper that produces a stand-alone
//!   [`provenance::SignedProvenance`] so downstream auditors can attest to a
//!   stamp's identity without pulling the surrounding receipt.
//!
//! Later Phase-1 tickets layer the streaming state machine
//! (`crates/chio-tool-call-fabric/src/stream.rs`), the kernel verdict shim,
//! and the lift/lower fixture set on top of this surface.

#![forbid(unsafe_code)]

pub mod provenance;
pub mod stream;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use thiserror::Error;

pub use provenance::{sign_provenance, verify_signed_provenance, SignedProvenance};
pub use stream::{BlockKind, BufferedBlock, StreamError, StreamEvent, StreamPhase};

/// Compatibility marker. The wire-level `provider` field uses the snake-case
/// serde rendering of [`ProviderId`]; this constant exists so build systems
/// that wish to stamp a fabric-version tag into their telemetry have a stable
/// string to read.
pub const FABRIC_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProviderId {
    OpenAi,
    Anthropic,
    Bedrock,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Principal {
    OpenAiOrg {
        org_id: String,
    },
    AnthropicWorkspace {
        workspace_id: String,
    },
    BedrockIam {
        caller_arn: String,
        account_id: String,
        assumed_role_session_arn: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceStamp {
    pub provider: ProviderId,
    pub request_id: String,
    pub api_version: String,
    pub principal: Principal,
    pub received_at: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolInvocation {
    pub provider: ProviderId,
    pub tool_name: String,
    /// Canonical-JSON bytes (RFC 8785). Stored as raw bytes so the kernel can
    /// hash without re-serializing.
    pub arguments: Vec<u8>,
    pub provenance: ProvenanceStamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Redaction {
    pub path: String,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DenyReason {
    PolicyDeny { rule_id: String },
    GuardDeny { guard_id: String, detail: String },
    CapabilityExpired,
    PrincipalUnknown,
    BudgetExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum VerdictResult {
    Allow {
        redactions: Vec<Redaction>,
        receipt_id: ReceiptId,
    },
    Deny {
        reason: DenyReason,
        receipt_id: ReceiptId,
    },
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("rate limited by upstream: retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },
    #[error("upstream content policy denied request: {0}")]
    ContentPolicy(String),
    #[error("tool arguments failed schema validation: {0}")]
    BadToolArgs(String),
    #[error("upstream 5xx ({status}): {body}")]
    Upstream5xx { status: u16, body: String },
    #[error("transport timeout after {ms}ms")]
    TransportTimeout { ms: u64 },
    #[error("verdict latency budget exceeded ({observed_ms}ms > {budget_ms}ms); fail-closed")]
    VerdictBudgetExceeded { observed_ms: u64, budget_ms: u64 },
    #[error("malformed upstream payload: {0}")]
    Malformed(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Raw upstream request payload bytes.
///
/// Adapters wrap whatever the native SDK or HTTP client surfaced for an
/// outgoing request. The fabric never inspects these bytes; they exist purely
/// as opaque material that adapters lift into [`ToolInvocation`].
pub struct ProviderRequest(pub Vec<u8>);

/// Raw upstream response payload bytes.
///
/// Lower returns these so the caller can hand the bytes back to the upstream
/// transport without the fabric mediating wire-format details.
pub struct ProviderResponse(pub Vec<u8>);

/// Canonical-JSON tool output bytes (RFC 8785).
///
/// Tool execution results are passed back through [`ProviderAdapter::lower`]
/// in canonical form so downstream auditors see byte-identical material
/// regardless of which provider produced or consumed the call.
pub struct ToolResult(pub Vec<u8>);

/// Provider-agnostic adapter contract.
///
/// Each native adapter (OpenAI, Anthropic, Bedrock) implements this trait
/// to lift an upstream request into a normalized [`ToolInvocation`] and to
/// lower a kernel [`VerdictResult`] plus tool result back into the wire
/// format the upstream expects.
///
/// The trait is intentionally minimal so it stays dyn-compatible and so the
/// streaming state machine in `stream.rs` (Phase 1 task 3) can wrap any
/// implementer uniformly.
#[async_trait]
pub trait ProviderAdapter: Send + Sync {
    fn provider(&self) -> ProviderId;
    fn api_version(&self) -> &str;
    async fn lift(&self, raw: ProviderRequest) -> Result<ToolInvocation, ProviderError>;
    async fn lower(
        &self,
        verdict: VerdictResult,
        result: ToolResult,
    ) -> Result<ProviderResponse, ProviderError>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sample_stamp() -> ProvenanceStamp {
        ProvenanceStamp {
            provider: ProviderId::OpenAi,
            request_id: "call_abc123".to_string(),
            api_version: "responses.2026-04-25".to_string(),
            principal: Principal::OpenAiOrg {
                org_id: "org_123".to_string(),
            },
            received_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        }
    }

    #[test]
    fn provider_id_serializes_snake_case() {
        let json = serde_json::to_string(&ProviderId::OpenAi).unwrap();
        assert_eq!(json, "\"open_ai\"");
        let json = serde_json::to_string(&ProviderId::Anthropic).unwrap();
        assert_eq!(json, "\"anthropic\"");
        let json = serde_json::to_string(&ProviderId::Bedrock).unwrap();
        assert_eq!(json, "\"bedrock\"");
    }

    #[test]
    fn principal_round_trips_all_variants() {
        let cases = vec![
            Principal::OpenAiOrg {
                org_id: "org_abc".to_string(),
            },
            Principal::AnthropicWorkspace {
                workspace_id: "wks_xyz".to_string(),
            },
            Principal::BedrockIam {
                caller_arn: "arn:aws:iam::123456789012:role/ChioAgentRole".to_string(),
                account_id: "123456789012".to_string(),
                assumed_role_session_arn: None,
            },
            Principal::BedrockIam {
                caller_arn: "arn:aws:iam::123456789012:role/ChioAgentRole".to_string(),
                account_id: "123456789012".to_string(),
                assumed_role_session_arn: Some(
                    "arn:aws:sts::123456789012:assumed-role/ChioAgentRole/session-1".to_string(),
                ),
            },
        ];
        for p in cases {
            let json = serde_json::to_string(&p).unwrap();
            let back: Principal = serde_json::from_str(&json).unwrap();
            assert_eq!(p, back);
        }
    }

    #[test]
    fn provenance_stamp_round_trips() {
        let stamp = sample_stamp();
        let json = serde_json::to_string(&stamp).unwrap();
        let back: ProvenanceStamp = serde_json::from_str(&json).unwrap();
        assert_eq!(stamp, back);
    }

    #[test]
    fn tool_invocation_round_trips() {
        let invocation = ToolInvocation {
            provider: ProviderId::Anthropic,
            tool_name: "search_web".to_string(),
            arguments: br#"{"query":"chio"}"#.to_vec(),
            provenance: sample_stamp(),
        };
        let json = serde_json::to_string(&invocation).unwrap();
        let back: ToolInvocation = serde_json::from_str(&json).unwrap();
        assert_eq!(invocation, back);
    }

    #[test]
    fn verdict_result_tags_with_verdict_field() {
        let allow = VerdictResult::Allow {
            redactions: vec![],
            receipt_id: ReceiptId("rcpt_1".to_string()),
        };
        let json = serde_json::to_string(&allow).unwrap();
        assert!(json.contains("\"verdict\":\"allow\""));
        let deny = VerdictResult::Deny {
            reason: DenyReason::PolicyDeny {
                rule_id: "rule_1".to_string(),
            },
            receipt_id: ReceiptId("rcpt_2".to_string()),
        };
        let json = serde_json::to_string(&deny).unwrap();
        assert!(json.contains("\"verdict\":\"deny\""));
        assert!(json.contains("\"kind\":\"policy_deny\""));
    }

    #[test]
    fn deny_reason_round_trips() {
        let cases = vec![
            DenyReason::PolicyDeny {
                rule_id: "r1".to_string(),
            },
            DenyReason::GuardDeny {
                guard_id: "g1".to_string(),
                detail: "matched secret pattern".to_string(),
            },
            DenyReason::CapabilityExpired,
            DenyReason::PrincipalUnknown,
            DenyReason::BudgetExceeded,
        ];
        for r in cases {
            let json = serde_json::to_string(&r).unwrap();
            let back: DenyReason = serde_json::from_str(&json).unwrap();
            assert_eq!(r, back);
        }
    }

    #[test]
    fn provider_error_display_is_em_dash_free() {
        // House rule: no em dashes (U+2014) in any rendered Display output.
        let cases = vec![
            ProviderError::RateLimited {
                retry_after_ms: 200,
            },
            ProviderError::ContentPolicy("blocked".to_string()),
            ProviderError::BadToolArgs("missing field".to_string()),
            ProviderError::Upstream5xx {
                status: 502,
                body: "bad gateway".to_string(),
            },
            ProviderError::TransportTimeout { ms: 30_000 },
            ProviderError::VerdictBudgetExceeded {
                observed_ms: 300,
                budget_ms: 250,
            },
            ProviderError::Malformed("nope".to_string()),
        ];
        for err in cases {
            let s = err.to_string();
            assert!(!s.contains('\u{2014}'), "em dash in {s}");
        }
    }

    #[async_trait]
    trait _AdapterIsObjectSafe: ProviderAdapter {}

    fn _assert_adapter_object_safe(_x: &dyn ProviderAdapter) {}
}
