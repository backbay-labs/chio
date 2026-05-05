#![forbid(unsafe_code)]

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseFrame {
    pub event: Option<String>,
    pub data: Option<Value>,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownSseFieldPolicy {
    Ignore,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SseParseOptions {
    pub provider_label: &'static str,
    pub unknown_field_policy: UnknownSseFieldPolicy,
}

impl SseParseOptions {
    pub const fn ignoring_unknown(provider_label: &'static str) -> Self {
        Self {
            provider_label,
            unknown_field_policy: UnknownSseFieldPolicy::Ignore,
        }
    }

    pub const fn rejecting_unknown(provider_label: &'static str) -> Self {
        Self {
            provider_label,
            unknown_field_policy: UnknownSseFieldPolicy::Reject,
        }
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

    let data = if data_lines.is_empty() {
        None
    } else {
        let text = data_lines.join("\n");
        Some(serde_json::from_str::<Value>(&text).map_err(|error| {
            ProviderError::Malformed(format!(
                "{} SSE data was not JSON: {error}",
                options.provider_label
            ))
        })?)
    };

    Ok(SseFrame { event, data, raw })
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
    fn sse_parser_rejects_unknown_fields_when_configured() {
        let raw = b"trace-id: abc-123\ndata: {\"ok\":true}\n\n";
        let error = parse_sse_frames(raw, SseParseOptions::rejecting_unknown("Test"))
            .expect_err("unknown fields should fail in rejecting mode");
        assert!(error
            .to_string()
            .contains("Test SSE field `trace-id` is not supported"));
    }
}
