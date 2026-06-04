//! Gemini SSE gating for `streamGenerateContent` payloads.
//!
//! Gemini streams as JSON-array chunks framed in SSE-style `data:` events.
//! Each chunk carries a partial `Candidate` with content parts. We buffer
//! `functionCall` parts (which arrive whole on Gemini's wire) and gate the
//! emission on a kernel verdict before forwarding bytes downstream.

use chio_provider_adapter_core::{
    ensure_streaming_allow_no_redactions, parse_sse_frames, GatedStream, SseParseOptions,
};
use chio_tool_call_fabric::{ProviderError, ToolInvocation, VerdictResult};
use serde_json::Value;

use crate::{native::FunctionCallPart, GeminiAdapter};

pub type GatedSseStream = GatedStream;

impl GeminiAdapter {
    /// Gate a deterministic Gemini SSE payload.
    pub fn gate_sse_stream<F>(
        &self,
        raw: &[u8],
        mut evaluate: F,
    ) -> Result<GatedSseStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        self.ensure_supported_api_version()?;
        let frames = parse_sse_frames(raw, SseParseOptions::rejecting_unknown("Gemini"))?;
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
                    ensure_streaming_allow_no_redactions(
                        "Gemini",
                        "functionCall",
                        &call.name,
                        None,
                        &verdict,
                    )?;
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
        ProviderError::Malformed(format!("Gemini functionCall part was malformed: {error}"))
    })?;
    Ok(Some(parsed))
}
