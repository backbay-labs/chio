//! Ollama NDJSON gating for `/api/chat` stream payloads.
//!
//! Ollama streams `/api/chat` as one JSON object per line (NDJSON). Each
//! object carries a partial `message` with optional `tool_calls`. The adapter
//! buffers tool-call entries (which Ollama emits whole on the line that has
//! `done: true` for the assistant message) and gates emission on a kernel
//! verdict before forwarding bytes downstream.

use chio_provider_adapter_core::ensure_streaming_allow_no_redactions;
use chio_tool_call_fabric::{ProviderError, ToolInvocation, VerdictResult};
use serde_json::Value;

use crate::{native::ToolCallPart, OllamaAdapter};

/// Result of gating one Ollama NDJSON stream payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatedNdjsonStream {
    /// NDJSON bytes that are safe to forward downstream.
    pub bytes: Vec<u8>,
    /// Tool invocations evaluated when each `tool_calls` entry finalised.
    pub invocations: Vec<ToolInvocation>,
    /// Verdicts returned for each invocation in stream order.
    pub verdicts: Vec<VerdictResult>,
}

impl OllamaAdapter {
    /// Gate a deterministic Ollama NDJSON `/api/chat` stream payload.
    pub fn gate_sse_stream<F>(
        &self,
        raw: &[u8],
        mut evaluate: F,
    ) -> Result<GatedNdjsonStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        let text = std::str::from_utf8(raw).map_err(|error| {
            ProviderError::Malformed(format!("Ollama NDJSON stream was not UTF-8: {error}"))
        })?;
        let mut output: Vec<u8> = Vec::with_capacity(raw.len());
        let mut invocations = Vec::new();
        let mut verdicts = Vec::new();
        let mut tool_index: usize = 0;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let frame: Value = serde_json::from_str(trimmed).map_err(|error| {
                ProviderError::Malformed(format!("Ollama NDJSON line was not JSON: {error}"))
            })?;

            if let Some(array) = frame
                .get("message")
                .and_then(|message| message.get("tool_calls"))
                .and_then(Value::as_array)
            {
                for entry in array {
                    let parsed: ToolCallPart =
                        serde_json::from_value(entry.clone()).map_err(|error| {
                            ProviderError::Malformed(format!(
                                "Ollama tool_call entry was malformed: {error}"
                            ))
                        })?;
                    let invocation = self.invocation_from_tool_call(tool_index, &parsed)?;
                    let verdict = evaluate(&invocation)?;
                    ensure_streaming_allow_no_redactions(
                        "Ollama",
                        "tool_call",
                        &parsed.function.name,
                        None,
                        &verdict,
                    )?;
                    invocations.push(invocation);
                    verdicts.push(verdict);
                    tool_index += 1;
                }
            }

            output.extend_from_slice(line.as_bytes());
            output.push(b'\n');
        }

        Ok(GatedNdjsonStream {
            bytes: output,
            invocations,
            verdicts,
        })
    }
}
