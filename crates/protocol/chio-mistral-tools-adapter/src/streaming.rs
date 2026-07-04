//! Mistral SSE gating for `chat/completions` streaming payloads.
//!
//! Mistral is OpenAI-compatible: it streams `chat.completion.chunk` objects
//! framed as SSE `data:` events. Each chunk carries
//! `choices[].delta.tool_calls[]` (or `choices[].message.tool_calls[]` on
//! aggregated chunks). We buffer the tool calls and gate emission on a kernel
//! verdict before forwarding bytes downstream. The OpenAI-compatible gating
//! logic lives in the shared [`gate_openai_sse_tool_calls`] core primitive.

use chio_provider_adapter_core::{gate_openai_sse_tool_calls, GatedStream};
use chio_tool_call_fabric::{ProviderError, ToolInvocation, VerdictResult};

use crate::{native::FunctionCallPart, MistralAdapter};

pub type GatedSseStream = GatedStream;

impl MistralAdapter {
    /// Gate a deterministic Mistral SSE payload.
    pub fn gate_sse_stream<F>(
        &self,
        raw: &[u8],
        evaluate: F,
    ) -> Result<GatedSseStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        self.ensure_supported_api_version()?;
        gate_openai_sse_tool_calls(
            raw,
            "Mistral",
            None,
            |call| {
                self.invocation_from_function_call(&FunctionCallPart::new(
                    call.id.clone(),
                    call.name.clone(),
                    call.args.clone(),
                ))
            },
            evaluate,
        )
    }
}
