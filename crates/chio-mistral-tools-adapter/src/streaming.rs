//! Mistral SSE gating for `chat/completions stream` payloads.
//!
//! Mistral streams as JSON-array chunks framed in SSE-style `data:` events.
//! Each chunk carries a partial `Candidate` with content parts. We buffer
//! `tool_calls` parts (which arrive whole on Mistral's wire) and gate the
//! emission on a kernel verdict before forwarding bytes downstream.

use chio_provider_adapter_core::{
    ensure_streaming_allow_no_redactions, parse_sse_frames, GatedStream, SseParseOptions,
};
use chio_tool_call_fabric::{ProviderError, ToolInvocation, VerdictResult};
use serde_json::Value;

use crate::{native::FunctionCallPart, openai_tool_call_to_function_call, MistralAdapter};

pub type GatedSseStream = GatedStream;

impl MistralAdapter {
    /// Gate a deterministic Mistral SSE payload.
    pub fn gate_sse_stream<F>(
        &self,
        raw: &[u8],
        mut evaluate: F,
    ) -> Result<GatedSseStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        let frames = parse_sse_frames(raw, SseParseOptions::ignoring_unknown("Mistral"))?;
        let mut output: Vec<u8> = Vec::new();
        let mut invocations = Vec::new();
        let mut verdicts = Vec::new();

        for frame in frames {
            let Some(data) = frame.data.as_ref() else {
                output.extend_from_slice(&frame.raw);
                continue;
            };

            // Walk OpenAI-shaped choices[].{delta,message}.tool_calls[]
            // first; fall back to Gemini-shaped candidates[].content.parts[]
            // for legacy fixtures.
            for call in extract_stream_function_calls(data)? {
                let invocation = self.invocation_from_function_call(&call)?;
                let verdict = evaluate(&invocation)?;
                ensure_streaming_allow_no_redactions(
                    "Mistral",
                    "functionCall",
                    &call.name,
                    None,
                    &verdict,
                )?;
                invocations.push(invocation);
                verdicts.push(verdict);
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

fn extract_stream_function_calls(data: &Value) -> Result<Vec<FunctionCallPart>, ProviderError> {
    let mut out = Vec::new();
    if let Some(choices) = data.get("choices").and_then(Value::as_array) {
        for choice in choices {
            for source in ["delta", "message"] {
                let Some(tool_calls) = choice
                    .get(source)
                    .and_then(|m| m.get("tool_calls"))
                    .and_then(Value::as_array)
                else {
                    continue;
                };
                for entry in tool_calls {
                    if let Some(part) = openai_tool_call_to_function_call(entry, "Mistral")? {
                        out.push(part);
                    }
                }
            }
        }
    }

    if !out.is_empty() {
        return Ok(out);
    }

    if let Some(candidates) = data.get("candidates").and_then(Value::as_array) {
        for candidate in candidates {
            let Some(parts) = candidate
                .get("content")
                .and_then(|c| c.get("parts"))
                .and_then(Value::as_array)
            else {
                continue;
            };
            for part in parts {
                if let Some(call) = part.get("functionCall") {
                    let parsed: FunctionCallPart =
                        serde_json::from_value(call.clone()).map_err(|error| {
                            ProviderError::Malformed(format!(
                                "Mistral functionCall part was malformed: {error}"
                            ))
                        })?;
                    out.push(parsed);
                }
            }
        }
    }
    Ok(out)
}
