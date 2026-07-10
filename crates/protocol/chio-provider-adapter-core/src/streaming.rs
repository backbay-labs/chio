//! Shared OpenAI-compatible SSE tool-call gate.
//!
//! Providers that speak the OpenAI `chat/completions` streaming shape frame
//! `chat.completion.chunk` objects as SSE `data:` events carrying
//! `choices[].delta.tool_calls[]` (or `choices[].message.tool_calls[]` on
//! aggregated chunks). This gate buffers each decoded tool call and gates
//! emission on a kernel verdict before forwarding bytes downstream. The only
//! per-provider differences are the label used in errors and SSE parsing, the
//! optional `[DONE]` done-sentinel, and how a decoded call is lifted into a
//! provider-stamped [`ToolInvocation`]; those are supplied by the caller.

use chio_tool_call_fabric::{ProviderError, ToolInvocation, VerdictResult};
use serde_json::Value;

use crate::{
    ensure_streaming_allow_no_redactions, openai_tool_call_to_function_call, parse_sse_frames,
    GatedStream, SseParseOptions,
};

/// A decoded OpenAI-compatible `tool_calls[]` entry lifted from an SSE frame.
///
/// Adapters turn this into their own native call struct inside the `invoke`
/// closure supplied to [`gate_openai_sse_tool_calls`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedToolCall {
    /// Provider-native `tool_calls[].id`.
    pub id: String,
    /// Tool name from `tool_calls[].function.name`.
    pub name: String,
    /// Decoded `tool_calls[].function.arguments`.
    pub args: Value,
}

/// Gate a deterministic OpenAI-compatible SSE `chat/completions` payload.
///
/// `provider_label` labels SSE parsing and gate errors, `done_sentinel` is the
/// optional stream terminator (for example `[DONE]`), `invoke` lifts each
/// decoded call into a provider-stamped [`ToolInvocation`], and `evaluate`
/// returns the kernel verdict for that invocation. Each tool call must resolve
/// to an allow verdict with no redactions or the whole stream fails closed.
pub fn gate_openai_sse_tool_calls<Invoke, Eval>(
    raw: &[u8],
    provider_label: &'static str,
    done_sentinel: Option<&'static str>,
    mut invoke: Invoke,
    mut evaluate: Eval,
) -> Result<GatedStream, ProviderError>
where
    Invoke: FnMut(&DecodedToolCall) -> Result<ToolInvocation, ProviderError>,
    Eval: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
{
    let mut options = SseParseOptions::ignoring_unknown(provider_label);
    if let Some(sentinel) = done_sentinel {
        options = options.with_done_sentinel(sentinel);
    }
    let frames = parse_sse_frames(raw, options)?;
    let mut output: Vec<u8> = Vec::new();
    let mut invocations = Vec::new();
    let mut verdicts = Vec::new();

    for frame in frames {
        let Some(data) = frame.data.as_ref() else {
            output.extend_from_slice(&frame.raw);
            continue;
        };

        // Walk OpenAI-shaped choices[].{delta,message}.tool_calls[].
        for call in extract_stream_tool_calls(data, provider_label)? {
            let invocation = invoke(&call)?;
            let verdict = evaluate(&invocation)?;
            ensure_streaming_allow_no_redactions(
                provider_label,
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

    Ok(GatedStream::new(output, invocations, verdicts))
}

fn extract_stream_tool_calls(
    data: &Value,
    provider_label: &str,
) -> Result<Vec<DecodedToolCall>, ProviderError> {
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
                    if let Some(call) = openai_tool_call_to_function_call(
                        entry,
                        provider_label,
                        |id, name, args| DecodedToolCall { id, name, args },
                    )? {
                        out.push(call);
                    }
                }
            }
        }
    }
    Ok(out)
}
