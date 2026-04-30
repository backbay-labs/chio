//! Groq SSE gating for `chat/completions stream` payloads.
//!
//! Groq streams as JSON-array chunks framed in SSE-style `data:` events.
//! Each chunk carries a partial `Candidate` with content parts. We buffer
//! `tool_calls` parts (which arrive whole on Groq's wire) and gate the
//! emission on a kernel verdict before forwarding bytes downstream.

use chio_tool_call_fabric::{
    DenyReason, ProviderError, ToolInvocation, VerdictResult,
};
use serde_json::Value;

use crate::{native::FunctionCallPart, GroqAdapter};

/// Result of gating one Groq stream payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatedSseStream {
    /// SSE bytes that are safe to forward downstream.
    pub bytes: Vec<u8>,
    /// Tool invocations evaluated when each `tool_calls` part finalised.
    pub invocations: Vec<ToolInvocation>,
    /// Verdicts returned for each invocation in stream order.
    pub verdicts: Vec<VerdictResult>,
}

impl GroqAdapter {
    /// Gate a deterministic Groq SSE payload.
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
            let Some(data) = frame.data.as_ref() else {
                output.extend_from_slice(&frame.raw);
                continue;
            };

            // Walk candidates[].content.parts[] looking for functionCall parts.
            let parts = candidate_parts(data);
            for part in parts {
                if let Some(call) = function_call_from_part(part)? {
                    let invocation = self.invocation_from_function_call(&call)?;
                    let verdict = evaluate(&invocation)?;
                    ensure_streaming_allow(&call, &verdict)?;
                    invocations.push(invocation);
                    verdicts.push(verdict);
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
    data: Option<Value>,
    raw: Vec<u8>,
}

fn parse_sse_frames(raw: &[u8]) -> Result<Vec<SseFrame>, ProviderError> {
    let text = std::str::from_utf8(raw).map_err(|error| {
        ProviderError::Malformed(format!("Groq SSE bytes were not UTF-8: {error}"))
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
    let mut raw: Vec<u8> = Vec::new();

    for line in lines {
        raw.extend_from_slice(line.as_bytes());
        raw.push(b'\n');

        if line.starts_with(':') {
            continue;
        }
        let (field, value) = line.split_once(':').ok_or_else(|| {
            ProviderError::Malformed(format!("Groq SSE line `{line}` was missing `:`"))
        })?;
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "data" => data_lines.push(value.to_string()),
            "event" | "id" | "retry" => {}
            other => {
                return Err(ProviderError::Malformed(format!(
                    "Groq SSE field `{other}` is not supported"
                )));
            }
        }
    }
    raw.push(b'\n');

    let data = if data_lines.is_empty() {
        None
    } else {
        let text = data_lines.join("\n");
        Some(serde_json::from_str::<Value>(&text).map_err(|error| {
            ProviderError::Malformed(format!("Groq SSE data was not JSON: {error}"))
        })?)
    };

    Ok(SseFrame { data, raw })
}

fn candidate_parts(data: &Value) -> Vec<&Value> {
    let mut out = Vec::new();
    let Some(candidates) = data.get("candidates").and_then(Value::as_array) else {
        return out;
    };
    for candidate in candidates {
        let Some(parts) = candidate
            .get("content")
            .and_then(|c| c.get("parts"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for part in parts {
            out.push(part);
        }
    }
    out
}

fn function_call_from_part(part: &Value) -> Result<Option<FunctionCallPart>, ProviderError> {
    let Some(call) = part.get("functionCall") else {
        return Ok(None);
    };
    let parsed: FunctionCallPart = serde_json::from_value(call.clone()).map_err(|error| {
        ProviderError::Malformed(format!("Groq functionCall part was malformed: {error}"))
    })?;
    Ok(Some(parsed))
}

fn ensure_streaming_allow(
    call: &FunctionCallPart,
    verdict: &VerdictResult,
) -> Result<(), ProviderError> {
    match verdict {
        VerdictResult::Allow { redactions, .. } if redactions.is_empty() => Ok(()),
        VerdictResult::Allow { .. } => Err(ProviderError::Malformed(format!(
            "Groq streaming functionCall `{}` allow verdict requested redactions; fail-closed",
            call.name
        ))),
        VerdictResult::Deny { reason, receipt_id } => Err(ProviderError::Malformed(format!(
            "Groq streaming functionCall `{}` denied: {} (receipt {})",
            call.name,
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
