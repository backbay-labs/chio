#![forbid(unsafe_code)]

pub mod http;
mod response;
mod sse;
mod streaming;

use chio_core::LoadedWeightsUnavailable;
use chio_tool_call_fabric::{DenyReason, ProviderError, ProviderId, ToolInvocation, VerdictResult};
pub use response::{nested_response_body, openai_tool_call_to_function_call, response_body};
pub use sse::{parse_sse_frames, SseFrame, SseParseOptions, UnknownSseFieldPolicy};
pub use streaming::{gate_openai_sse_tool_calls, DecodedToolCall};

/// Common adapter identity surface shared across provider adapters.
pub trait Provider {
    fn provider_id(&self) -> ProviderId;

    fn api_version(&self) -> &str;
}

/// Result of fail-closed stream gating for providers that forward byte streams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatedStream {
    /// Bytes that are safe to forward downstream.
    pub bytes: Vec<u8>,
    /// Tool invocations evaluated in stream order.
    pub invocations: Vec<ToolInvocation>,
    /// Verdicts returned for each invocation in stream order.
    pub verdicts: Vec<VerdictResult>,
}

impl GatedStream {
    pub fn new(
        bytes: Vec<u8>,
        invocations: Vec<ToolInvocation>,
        verdicts: Vec<VerdictResult>,
    ) -> Self {
        Self {
            bytes,
            invocations,
            verdicts,
        }
    }
}

pub fn loaded_weights_unavailable(
    provider_name: &'static str,
    reason: &'static str,
) -> LoadedWeightsUnavailable {
    LoadedWeightsUnavailable::new(provider_name, reason)
}

#[macro_export]
macro_rules! impl_unavailable_loaded_weights {
    ($adapter:ty, $provider_name:expr, $reason:expr) => {
        impl chio_core::LoadedWeights for $adapter {
            fn provider_name(&self) -> &'static str {
                $provider_name
            }

            fn loaded_weights_bytes(
                &self,
            ) -> Result<std::borrow::Cow<'_, [u8]>, chio_core::LoadedWeightsUnavailable> {
                Err($crate::loaded_weights_unavailable($provider_name, $reason))
            }
        }
    };
}

pub fn ensure_streaming_allow_no_redactions(
    provider_label: &str,
    call_kind: &str,
    call_id: &str,
    deny_phase: Option<&str>,
    verdict: &VerdictResult,
) -> Result<(), ProviderError> {
    match verdict {
        VerdictResult::Allow { redactions, .. } if redactions.is_empty() => Ok(()),
        VerdictResult::Allow { .. } => Err(ProviderError::Malformed(format!(
            "{provider_label} streaming {call_kind} `{call_id}` allow verdict requested redactions; fail-closed"
        ))),
        VerdictResult::Deny { reason, receipt_id } => {
            let phase = deny_phase
                .map(|phase| format!(" at {phase}"))
                .unwrap_or_default();
            Err(ProviderError::Malformed(format!(
                "{provider_label} streaming {call_kind} `{call_id}` denied{phase}: {} (receipt {})",
                deny_reason_text(reason),
                receipt_id.0
            )))
        }
    }
}

pub fn deny_reason_text(reason: &DenyReason) -> String {
    match reason {
        DenyReason::PolicyDeny { rule_id } => format!("policy_deny:{rule_id}"),
        DenyReason::GuardDeny { guard_id, detail } => {
            format!("guard_deny:{guard_id}:{detail}")
        }
        DenyReason::CapabilityExpired => "capability_expired".to_string(),
        DenyReason::PrincipalUnknown => "principal_unknown".to_string(),
        DenyReason::BudgetExceeded => "budget_exceeded".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn sse_parser_ignores_unknown_fields_when_configured() {
        let raw = b": keep-alive\ntrace-id: abc-123\ndata: {\"ok\":true}\nbare-line\n\n";
        let frames = parse_sse_frames(raw, SseParseOptions::ignoring_unknown("Test"))
            .unwrap_or_else(|error| panic!("parse should tolerate unknown fields: {error}"));
        assert_eq!(frames.len(), 1);
        assert_eq!(
            frames[0].data.as_ref().and_then(|data| data.get("ok")),
            Some(&Value::Bool(true))
        );
    }

    #[test]
    fn sse_parser_rejects_unknown_fields_when_configured() -> Result<(), Box<dyn std::error::Error>>
    {
        let raw = b"trace-id: abc-123\ndata: {\"ok\":true}\n\n";
        let error = match parse_sse_frames(raw, SseParseOptions::rejecting_unknown("Test")) {
            Ok(_) => {
                return Err(
                    std::io::Error::other("unknown fields should fail in rejecting mode").into(),
                );
            }
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("Test SSE field `trace-id` is not supported"));
        Ok(())
    }

    #[test]
    fn sse_parser_marks_done_sentinel_frame() {
        let raw = b"event: response.completed\ndata: {\"type\":\"response.completed\"}\n\ndata: [DONE]\n\n";
        let options = SseParseOptions::ignoring_unknown("OpenAI")
            .with_done_sentinel("[DONE]")
            .with_event_type_cross_check();
        let frames = parse_sse_frames(raw, options)
            .unwrap_or_else(|error| panic!("done sentinel should parse: {error}"));
        assert_eq!(frames.len(), 2);
        assert!(!frames[0].done);
        assert_eq!(frames[0].event.as_deref(), Some("response.completed"));
        assert!(frames[1].done);
        assert!(frames[1].data.is_none());
        // The terminator bytes are still retained verbatim for forwarding.
        assert!(frames[1].raw.windows(6).any(|w| w == b"[DONE]"));
    }

    #[test]
    fn sse_parser_retains_original_crlf_frame_bytes() {
        let raw = b"event: response.completed\r\ndata: {\"type\":\"response.completed\"}\r\n\r\ndata: [DONE]\r\n\r\n";
        let options = SseParseOptions::ignoring_unknown("OpenAI")
            .with_done_sentinel("[DONE]")
            .with_event_type_cross_check();
        let frames = parse_sse_frames(raw, options)
            .unwrap_or_else(|error| panic!("CRLF frames should parse: {error}"));

        assert_eq!(
            frames[0].raw,
            b"event: response.completed\r\ndata: {\"type\":\"response.completed\"}\r\n\r\n"
        );
        assert_eq!(frames[1].raw, b"data: [DONE]\r\n\r\n");
    }

    #[test]
    fn sse_parser_infers_event_from_type_when_cross_checking() {
        let raw = b"data: {\"type\":\"response.output_item.added\"}\n\n";
        let options = SseParseOptions::ignoring_unknown("OpenAI").with_event_type_cross_check();
        let frames = parse_sse_frames(raw, options)
            .unwrap_or_else(|error| panic!("inference should succeed: {error}"));
        assert_eq!(frames.len(), 1);
        assert_eq!(
            frames[0].event.as_deref(),
            Some("response.output_item.added")
        );
    }

    #[test]
    fn sse_parser_rejects_event_type_mismatch() {
        let raw = b"event: response.completed\ndata: {\"type\":\"response.failed\"}\n\n";
        let options = SseParseOptions::ignoring_unknown("OpenAI").with_event_type_cross_check();
        let error = match parse_sse_frames(raw, options) {
            Ok(_) => panic!("mismatched event/type must fail-closed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("did not match data type"));
    }

    #[test]
    fn sse_parser_rejects_data_frame_without_event_name() {
        let raw = b"data: {\"delta\":\"x\"}\n\n";
        let options = SseParseOptions::ignoring_unknown("OpenAI").with_event_type_cross_check();
        let error = match parse_sse_frames(raw, options) {
            Ok(_) => panic!("a typeless data frame must fail-closed under cross-check"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("missing event name"));
    }

    #[test]
    fn sse_parser_without_cross_check_keeps_explicit_event() {
        // Default behavior is unchanged: no inference, no terminator handling.
        let raw = b"event: ping\ndata: {\"type\":\"other\"}\n\n";
        let frames = parse_sse_frames(raw, SseParseOptions::ignoring_unknown("Test"))
            .unwrap_or_else(|error| panic!("default mode should not cross-check: {error}"));
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event.as_deref(), Some("ping"));
        assert!(!frames[0].done);
    }
}
