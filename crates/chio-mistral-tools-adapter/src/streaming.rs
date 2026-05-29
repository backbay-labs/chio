//! Mistral SSE gating for `chat/completions` streaming payloads.
//!
//! Mistral is OpenAI-compatible: it streams `chat.completion.chunk` objects
//! framed as SSE `data:` events. Each chunk carries
//! `choices[].delta.tool_calls[]` (or `choices[].message.tool_calls[]` on
//! aggregated chunks). We buffer the tool calls and gate emission on a kernel
//! verdict before forwarding bytes downstream.

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

            // Walk OpenAI-shaped choices[].{delta,message}.tool_calls[].
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
            // Streaming deltas live at choices[].delta.tool_calls[], while
            // batched / aggregated chunks reuse choices[].message.tool_calls[].
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
    Ok(out)
}
