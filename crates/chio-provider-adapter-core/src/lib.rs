#![forbid(unsafe_code)]

pub mod http;

use chio_core::LoadedWeightsUnavailable;
use chio_tool_call_fabric::{DenyReason, ProviderError, ProviderId, ToolInvocation, VerdictResult};
use serde_json::Value;

/// Common adapter identity surface used by conformance and refactor helpers.
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

/// Parsed SSE frame with original bytes retained for exact forwarding.
///
/// `done` is set when the frame's `data` payload equals the stream terminator
/// configured through [`SseParseOptions::with_done_sentinel`] (for example the
/// OpenAI `[DONE]` marker). Terminator frames carry `data: None` so callers do
/// not attempt to parse the sentinel string as JSON, while `raw` still holds the
/// original bytes for byte-exact forwarding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseFrame {
    pub event: Option<String>,
    pub data: Option<Value>,
    pub raw: Vec<u8>,
    pub done: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownSseFieldPolicy {
    Ignore,
    Reject,
}

/// Parser configuration shared by every SSE-forwarding adapter.
///
/// The two boolean knobs cover the provider-specific SSE behaviors:
///
/// - `done_sentinel`: when set, a `data` payload equal to this string yields a
///   frame with `done = true` and `data = None` instead of being parsed as JSON.
/// - `cross_check_event_type`: when true, a frame that carries both an explicit
///   `event:` name and a JSON `type` field requires the two to agree, infers a
///   missing `event:` name from the `type` field, and rejects a data frame that
///   resolves to no event name at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SseParseOptions {
    pub provider_label: &'static str,
    pub unknown_field_policy: UnknownSseFieldPolicy,
    pub done_sentinel: Option<&'static str>,
    pub cross_check_event_type: bool,
}

impl SseParseOptions {
    pub const fn ignoring_unknown(provider_label: &'static str) -> Self {
        Self {
            provider_label,
            unknown_field_policy: UnknownSseFieldPolicy::Ignore,
            done_sentinel: None,
            cross_check_event_type: false,
        }
    }

    pub const fn rejecting_unknown(provider_label: &'static str) -> Self {
        Self {
            provider_label,
            unknown_field_policy: UnknownSseFieldPolicy::Reject,
            done_sentinel: None,
            cross_check_event_type: false,
        }
    }

    /// Treat a `data` payload equal to `sentinel` as a stream terminator.
    pub const fn with_done_sentinel(mut self, sentinel: &'static str) -> Self {
        self.done_sentinel = Some(sentinel);
        self
    }

    /// Require an explicit `event:` name to match the JSON `type` field, infer a
    /// missing name from `type`, and reject data frames that resolve to no name.
    pub const fn with_event_type_cross_check(mut self) -> Self {
        self.cross_check_event_type = true;
        self
    }
}

pub fn parse_sse_frames(
    raw: &[u8],
    options: SseParseOptions,
) -> Result<Vec<SseFrame>, ProviderError> {
    let text = std::str::from_utf8(raw).map_err(|error| {
        ProviderError::Malformed(format!(
            "{} SSE bytes were not UTF-8: {error}",
            options.provider_label
        ))
    })?;
    let mut frames = Vec::new();
    let mut lines: Vec<String> = Vec::new();

    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            if !lines.is_empty() {
                frames.push(parse_sse_frame(&lines, options)?);
                lines.clear();
            }
        } else {
            lines.push(line.to_string());
        }
    }
    if !lines.is_empty() {
        frames.push(parse_sse_frame(&lines, options)?);
    }
    Ok(frames)
}

fn parse_sse_frame(lines: &[String], options: SseParseOptions) -> Result<SseFrame, ProviderError> {
    let mut data_lines: Vec<String> = Vec::new();
    let mut event: Option<String> = None;
    let mut raw: Vec<u8> = Vec::new();

    for line in lines {
        raw.extend_from_slice(line.as_bytes());
        raw.push(b'\n');

        if line.starts_with(':') {
            continue;
        }
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value),
            None => match options.unknown_field_policy {
                UnknownSseFieldPolicy::Ignore => (line.as_str(), ""),
                UnknownSseFieldPolicy::Reject => {
                    return Err(ProviderError::Malformed(format!(
                        "{} SSE line `{line}` was missing `:`",
                        options.provider_label
                    )));
                }
            },
        };
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "data" => data_lines.push(value.to_string()),
            "event" => event = Some(value.to_string()),
            "id" | "retry" => {}
            _ => match options.unknown_field_policy {
                UnknownSseFieldPolicy::Ignore => {}
                UnknownSseFieldPolicy::Reject => {
                    return Err(ProviderError::Malformed(format!(
                        "{} SSE field `{field}` is not supported",
                        options.provider_label
                    )));
                }
            },
        }
    }
    raw.push(b'\n');

    let data_text = data_lines.join("\n");
    if let Some(sentinel) = options.done_sentinel {
        if data_text == sentinel {
            return Ok(SseFrame {
                event,
                data: None,
                raw,
                done: true,
            });
        }
    }

    let data = if data_lines.is_empty() {
        None
    } else {
        Some(serde_json::from_str::<Value>(&data_text).map_err(|error| {
            ProviderError::Malformed(format!(
                "{} SSE data was not JSON: {error}",
                options.provider_label
            ))
        })?)
    };

    if options.cross_check_event_type {
        let inferred_event = data
            .as_ref()
            .and_then(|data| data.get("type"))
            .and_then(Value::as_str);
        if let (Some(existing), Some(data_type)) = (event.as_deref(), inferred_event) {
            if existing != data_type {
                return Err(ProviderError::Malformed(format!(
                    "{} SSE event `{existing}` did not match data type `{data_type}`",
                    options.provider_label
                )));
            }
        }
        if event.is_none() {
            event = inferred_event.map(ToString::to_string);
        }
        if data.is_some() && event.is_none() {
            return Err(ProviderError::Malformed(format!(
                "{} SSE data frame was missing event name",
                options.provider_label
            )));
        }
    }

    Ok(SseFrame {
        event,
        data,
        raw,
        done: false,
    })
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
