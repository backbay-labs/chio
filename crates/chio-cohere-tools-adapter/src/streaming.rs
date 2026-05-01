//! Cohere SSE gating for `/v2/chat` stream payloads.
//!
//! Cohere v2 streams tool calls as a sequence of `tool-call-start`,
//! `tool-call-delta`, and `tool-call-end` SSE events. The conformance
//! corpus uses deterministic fixtures where every `tool-call-end` event
//! carries the fully-assembled `tool_call` block; the adapter buffers on
//! `tool-call-end` and gates the emission on a kernel verdict before
//! forwarding bytes downstream.

use chio_tool_call_fabric::{DenyReason, ProviderError, ToolInvocation, VerdictResult};
use serde_json::Value;

use crate::{native::ToolCallBlock, CohereAdapter};

/// Result of gating one Cohere SSE stream payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatedSseStream {
    /// SSE bytes that are safe to forward downstream.
    pub bytes: Vec<u8>,
    /// Tool invocations evaluated when each `tool_call` block finalised.
    pub invocations: Vec<ToolInvocation>,
    /// Verdicts returned for each invocation in stream order.
    pub verdicts: Vec<VerdictResult>,
}

impl CohereAdapter {
    /// Gate a deterministic Cohere v2 SSE payload.
    pub fn gate_sse_stream<F>(
        &self,
        raw: &[u8],
        mut evaluate: F,
    ) -> Result<GatedSseStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        let frames = parse_sse_frames(raw)?;
        let mut output: Vec<u8> = Vec::new();
        let mut invocations = Vec::new();
        let mut verdicts = Vec::new();

        for frame in frames {
            if let (Some(event), Some(data)) = (frame.event.as_deref(), frame.data.as_ref()) {
                if event == "tool-call-end" {
                    if let Some(block) = tool_call_from_data(data)? {
                        let invocation = self.invocation_from_tool_call(&block)?;
                        let verdict = evaluate(&invocation)?;
                        ensure_streaming_allow(&block, &verdict)?;
                        invocations.push(invocation);
                        verdicts.push(verdict);
                    }
                }
            }
            output.extend_from_slice(&frame.raw);
        }

        Ok(GatedSseStream {
            bytes: output,
            invocations,
            verdicts,
        })
    }
}

#[derive(Debug, Clone)]
struct SseFrame {
    event: Option<String>,
    data: Option<Value>,
    raw: Vec<u8>,
}

fn parse_sse_frames(raw: &[u8]) -> Result<Vec<SseFrame>, ProviderError> {
    let text = std::str::from_utf8(raw).map_err(|error| {
        ProviderError::Malformed(format!("Cohere SSE bytes were not UTF-8: {error}"))
    })?;
    let mut frames = Vec::new();
    let mut lines: Vec<String> = Vec::new();

    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            if !lines.is_empty() {
                frames.push(parse_sse_frame(&lines)?);
                lines.clear();
            }
        } else {
            lines.push(line.to_string());
        }
    }
    if !lines.is_empty() {
        frames.push(parse_sse_frame(&lines)?);
    }
    Ok(frames)
}

fn parse_sse_frame(lines: &[String]) -> Result<SseFrame, ProviderError> {
    let mut data_lines: Vec<String> = Vec::new();
    let mut event: Option<String> = None;
    let mut raw: Vec<u8> = Vec::new();

    for line in lines {
        raw.extend_from_slice(line.as_bytes());
        raw.push(b'\n');

        if line.starts_with(':') {
            continue;
        }
        // Per the WHATWG EventStream spec, lines without a colon are
        // treated as a field with an empty value, and unknown field names
        // are silently ignored. Avoid hard-failing on metadata fields that
        // Cohere may add later (tracing headers, custom extensions).
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v),
            None => (line.as_str(), ""),
        };
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "data" => data_lines.push(value.to_string()),
            "event" => event = Some(value.to_string()),
            // `id`, `retry`, and any other unknown fields are silently
            // ignored per the EventStream spec.
            _ => {}
        }
    }
    raw.push(b'\n');

    let data = if data_lines.is_empty() {
        None
    } else {
        let text = data_lines.join("\n");
        Some(serde_json::from_str::<Value>(&text).map_err(|error| {
            ProviderError::Malformed(format!("Cohere SSE data was not JSON: {error}"))
        })?)
    };

    Ok(SseFrame { event, data, raw })
}

fn tool_call_from_data(data: &Value) -> Result<Option<ToolCallBlock>, ProviderError> {
    let block = data
        .get("tool_call")
        .or_else(|| data.get("delta").and_then(|d| d.get("tool_call")));
    let Some(block) = block else {
        return Ok(None);
    };
    let parsed: ToolCallBlock = serde_json::from_value(block.clone()).map_err(|error| {
        ProviderError::Malformed(format!("Cohere tool_call block was malformed: {error}"))
    })?;
    Ok(Some(parsed))
}

fn ensure_streaming_allow(
    block: &ToolCallBlock,
    verdict: &VerdictResult,
) -> Result<(), ProviderError> {
    match verdict {
        VerdictResult::Allow { redactions, .. } if redactions.is_empty() => Ok(()),
        VerdictResult::Allow { .. } => Err(ProviderError::Malformed(format!(
            "Cohere streaming tool_call `{}` allow verdict requested redactions; fail-closed",
            block.function.name
        ))),
        VerdictResult::Deny { reason, receipt_id } => Err(ProviderError::Malformed(format!(
            "Cohere streaming tool_call `{}` denied: {} (receipt {})",
            block.function.name,
            deny_reason_text(reason),
            receipt_id.0
        ))),
    }
}

fn deny_reason_text(reason: &DenyReason) -> String {
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

    fn require_ok<T, E>(result: Result<T, E>, context: &'static str) -> T
    where
        E: std::fmt::Debug,
    {
        result.unwrap_or_else(|error| panic!("{context}: {error:?}"))
    }

    fn require_some<T>(value: Option<T>, context: &'static str) -> T {
        value.unwrap_or_else(|| panic!("{context}"))
    }

    #[test]
    fn parse_sse_frames_ignores_unknown_fields() {
        // Unknown SSE fields (the spec says these MUST be silently ignored)
        // and bare `:` comment lines and lines without a colon must not
        // cause a hard parse failure.
        let raw = b": cohere keep-alive\n\
                  trace-id: abc-123\n\
                  custom-extension: hello\n\
                  data: {\"event_type\":\"text-delta\",\"text\":\"hi\"}\n\
                  bare-line-no-colon\n\
                  \n";
        let frames = require_ok(
            parse_sse_frames(raw),
            "unknown SSE fields must be tolerated",
        );
        assert_eq!(frames.len(), 1);
        let frame = &frames[0];
        let data = require_some(frame.data.as_ref(), "frame has data");
        assert_eq!(
            data.get("event_type").and_then(serde_json::Value::as_str),
            Some("text-delta")
        );
    }
}
