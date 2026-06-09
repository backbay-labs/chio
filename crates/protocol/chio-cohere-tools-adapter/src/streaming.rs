//! Cohere SSE gating for `/v2/chat` stream payloads.
//!
//! Cohere v2 streams tool calls as a sequence of `tool-call-start`,
//! `tool-call-delta`, and `tool-call-end` SSE events. The conformance
//! corpus uses deterministic fixtures where every `tool-call-end` event
//! carries the fully-assembled `tool_call` block; the adapter buffers on
//! `tool-call-end` and gates the emission on a kernel verdict before
//! forwarding bytes downstream.

use chio_provider_adapter_core::{
    ensure_streaming_allow_no_redactions, parse_sse_frames, GatedStream, SseParseOptions,
};
use chio_tool_call_fabric::{ProviderError, ToolInvocation, VerdictResult};
use serde_json::Value;

use crate::{native::ToolCallBlock, CohereAdapter};

pub type GatedSseStream = GatedStream;

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
        self.ensure_supported_api_version()?;
        let frames = parse_sse_frames(raw, SseParseOptions::ignoring_unknown("Cohere"))?;
        let mut output: Vec<u8> = Vec::new();
        let mut invocations = Vec::new();
        let mut verdicts = Vec::new();

        for frame in frames {
            if let (Some(event), Some(data)) = (frame.event.as_deref(), frame.data.as_ref()) {
                if event == "tool-call-end" {
                    let block = tool_call_from_data(data)?;
                    let invocation = self.invocation_from_tool_call(&block)?;
                    let verdict = evaluate(&invocation)?;
                    ensure_streaming_allow_no_redactions(
                        "Cohere",
                        "tool_call",
                        &block.function.name,
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

fn tool_call_from_data(data: &Value) -> Result<ToolCallBlock, ProviderError> {
    let block = data
        .get("tool_call")
        .or_else(|| data.get("delta").and_then(|d| d.get("tool_call")));
    let Some(block) = block else {
        return Err(ProviderError::Malformed(
            "Cohere tool-call-end frame was missing tool_call".to_string(),
        ));
    };
    let parsed: ToolCallBlock = serde_json::from_value(block.clone()).map_err(|error| {
        ProviderError::Malformed(format!("Cohere tool_call block was malformed: {error}"))
    })?;
    Ok(parsed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::cell::Cell;
    use std::sync::Arc;

    use chio_tool_call_fabric::{ProviderError, ReceiptId, VerdictResult};

    use crate::{transport, CohereAdapter, CohereAdapterConfig};

    fn adapter() -> CohereAdapter {
        CohereAdapter::new(
            CohereAdapterConfig::new(
                "cohere-stream",
                "Cohere stream",
                "0.1.0",
                "deadbeef",
                "org_chio_stream",
            ),
            Arc::new(transport::MockTransport::new()),
        )
    }

    #[test]
    fn tool_call_end_without_tool_call_fails_closed() {
        let adapter = adapter();
        let evaluated = Cell::new(false);
        let err = adapter
            .gate_sse_stream(
                b"event: tool-call-end\ndata: {\"delta\":{}}\n\n",
                |_invocation| {
                    evaluated.set(true);
                    Ok(VerdictResult::Allow {
                        redactions: vec![],
                        receipt_id: ReceiptId("rcpt_stream_allow".to_string()),
                    })
                },
            )
            .expect_err("terminal Cohere tool-call frame without a tool_call must fail closed");

        assert!(!evaluated.get(), "malformed frame must not reach evaluator");
        assert!(matches!(err, ProviderError::Malformed(_)));
        assert!(err.to_string().contains("missing tool_call"));
    }
}
