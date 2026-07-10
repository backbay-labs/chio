//! Chio tool-call fabric: provider-agnostic types and traits for LLM tool-call dispatch.
//!
//! This crate is the load-bearing contract between Chio and its native
//! provider adapters.
//! Each adapter lifts its native tool-call shape into [`ToolInvocation`] and
//! lowers the kernel's [`VerdictResult`] back into provider-native bytes via
//! the [`ProviderAdapter`] trait below.
//!
//! The crate establishes:
//!
//! - The verbatim trait surface ([`ProviderId`], [`Principal`],
//!   [`ProvenanceStamp`], [`ToolInvocation`], [`VerdictResult`],
//!   [`DenyReason`], [`ProviderError`], [`ProviderAdapter`]).
//! - A [`provenance::sign_provenance`] helper that produces a stand-alone
//!   [`provenance::SignedProvenance`] so downstream auditors can attest to a
//!   stamp's identity without pulling the surrounding receipt.
//! - The streaming state machine ([`stream`]) that gates buffered tool-call
//!   blocks against a kernel verdict before they are forwarded.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod error;
pub mod provenance;
pub mod stream;
pub mod types;

pub use adapter::{ProviderAdapter, ProviderRequest, ProviderResponse, ToolResult};
pub use error::ProviderError;
pub use provenance::{sign_provenance, verify_signed_provenance, SignedProvenance};
pub use stream::{
    BlockKind, BufferedBlock, StreamError, StreamEvent, StreamPhase,
    DEFAULT_MAX_BUFFERED_BLOCK_BYTES, DEFAULT_MAX_BUFFERED_RAW_FRAMES,
};
pub use types::{
    DenyReason, Principal, ProvenanceStamp, ProviderId, ReceiptId, Redaction, ToolInvocation,
    ToolInvocationValidationError, VerdictResult,
};

/// Compatibility marker. The wire-level `provider` field uses the snake-case
/// serde rendering of [`ProviderId`]; this constant exists so build systems
/// that wish to stamp a fabric-version tag into their telemetry have a stable
/// string to read.
pub const FABRIC_VERSION: &str = "0.1.0";

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::time::{Duration, SystemTime};

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
        let json = serde_json::to_string(&ProviderId::Gemini).unwrap();
        assert_eq!(json, "\"gemini\"");
        let json = serde_json::to_string(&ProviderId::Mistral).unwrap();
        assert_eq!(json, "\"mistral\"");
        let json = serde_json::to_string(&ProviderId::Groq).unwrap();
        assert_eq!(json, "\"groq\"");
        let json = serde_json::to_string(&ProviderId::Ollama).unwrap();
        assert_eq!(json, "\"ollama\"");
        let json = serde_json::to_string(&ProviderId::Cohere).unwrap();
        assert_eq!(json, "\"cohere\"");
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
            Principal::GeminiProject {
                project_id: "proj_chio_demo".to_string(),
            },
            Principal::GroqProject {
                project_id: "proj_chio_demo".to_string(),
            },
            Principal::MistralProject {
                project_id: "proj_chio_demo".to_string(),
            },
            Principal::CohereOrg {
                org_id: "org_chio_demo".to_string(),
            },
            Principal::OllamaHost {
                host: "http://localhost:11434".to_string(),
            },
        ];
        for p in cases {
            let json = serde_json::to_string(&p).unwrap();
            let back: Principal = serde_json::from_str(&json).unwrap();
            assert_eq!(p, back);
        }
    }

    #[test]
    fn principal_kind_tags_render_per_provider() {
        let cases = [
            (
                Principal::GeminiProject {
                    project_id: "proj".to_string(),
                },
                "gemini_project",
            ),
            (
                Principal::GroqProject {
                    project_id: "proj".to_string(),
                },
                "groq_project",
            ),
            (
                Principal::MistralProject {
                    project_id: "proj".to_string(),
                },
                "mistral_project",
            ),
            (
                Principal::CohereOrg {
                    org_id: "org".to_string(),
                },
                "cohere_org",
            ),
            (
                Principal::OllamaHost {
                    host: "host".to_string(),
                },
                "ollama_host",
            ),
        ];
        for (principal, expected_kind) in cases {
            let json = serde_json::to_string(&principal).unwrap();
            assert!(
                json.contains(&format!("\"kind\":\"{expected_kind}\"")),
                "{json} did not carry kind tag {expected_kind}"
            );
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

    #[async_trait]
    trait _AdapterIsObjectSafe: ProviderAdapter {}

    fn _assert_adapter_object_safe(_x: &dyn ProviderAdapter) {}
}
