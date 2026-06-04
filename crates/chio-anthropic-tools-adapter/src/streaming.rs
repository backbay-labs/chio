//! Anthropic Messages SSE gating.
//!
//! The adapter buffers Anthropic `tool_use` blocks until
//! `content_block_stop`, reconstructs the completed input JSON, evaluates
//! Chio's verdict, then releases the buffered start and `input_json_delta`
//! frames only when the verdict allows. A deny verdict or malformed tool-use
//! frame fails closed and returns no forwarded stream bytes for the block.

use chio_provider_adapter_core::{
    ensure_streaming_allow_no_redactions, parse_sse_frames as parse_shared_sse_frames, SseFrame,
    SseParseOptions,
};
use chio_tool_call_fabric::{
    BlockKind, ProviderError, StreamEvent, StreamPhase, ToolInvocation, VerdictResult,
    DEFAULT_MAX_BUFFERED_BLOCK_BYTES, DEFAULT_MAX_BUFFERED_RAW_FRAMES,
};
use serde_json::Value;

use crate::{AnthropicAdapter, ToolUseBlock};

const ANTHROPIC_SSE_LABEL: &str = "Anthropic";
const ANTHROPIC_SSE_OPTIONS: SseParseOptions =
    SseParseOptions::rejecting_unknown(ANTHROPIC_SSE_LABEL);

/// Result of gating one Anthropic event-stream payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatedSseStream {
    /// SSE bytes that are safe to forward downstream.
    pub bytes: Vec<u8>,
    /// Tool invocations evaluated at `content_block_stop`.
    pub invocations: Vec<ToolInvocation>,
    /// Verdicts returned for each invocation, in stream order.
    pub verdicts: Vec<VerdictResult>,
}

impl AnthropicAdapter {
    /// Gate a deterministic Anthropic SSE payload.
    ///
    /// `evaluate` is called once the full `tool_use` input JSON has arrived.
    /// Returning a deny verdict fails closed before any bytes for that block
    /// are released.
    pub fn gate_sse_stream<F>(
        &self,
        raw: &[u8],
        mut evaluate: F,
    ) -> Result<GatedSseStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        let frames = parse_anthropic_sse_frames(raw)?;
        let mut gate = StreamGate::new(self);

        for frame in frames {
            gate.accept(frame, &mut evaluate)?;
        }

        gate.finish()
    }
}

struct StreamGate<'a> {
    adapter: &'a AnthropicAdapter,
    output: Vec<u8>,
    phase: StreamPhase,
    active: Option<ActiveBlock>,
    invocations: Vec<ToolInvocation>,
    verdicts: Vec<VerdictResult>,
}

impl<'a> StreamGate<'a> {
    fn new(adapter: &'a AnthropicAdapter) -> Self {
        Self {
            adapter,
            output: Vec::new(),
            phase: StreamPhase::Idle,
            active: None,
            invocations: Vec::new(),
            verdicts: Vec::new(),
        }
    }

    fn accept<F>(&mut self, frame: SseFrame, evaluate: &mut F) -> Result<(), ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        let Some(event) = frame.event.as_deref() else {
            return self.forward_or_buffer(frame);
        };

        match event {
            "content_block_start" => self.start_content_block(frame),
            "content_block_delta" => self.delta_content_block(frame),
            "content_block_stop" => self.stop_content_block(frame, evaluate),
            "message_stop" => self.stop_message(frame),
            "error" => Err(ProviderError::Malformed(format!(
                "Anthropic SSE error event: {}",
                data_text(&frame)
            ))),
            _ => self.forward_or_buffer(frame),
        }
    }

    fn start_content_block(&mut self, frame: SseFrame) -> Result<(), ProviderError> {
        if let Some(active) = &self.active {
            return Err(ProviderError::Malformed(format!(
                "Anthropic SSE started content block {} before stopping block {}",
                frame_index(&frame, "content_block_start")?,
                active.index
            )));
        }

        let data = required_data(&frame, "content_block_start")?;
        let index = required_index(data, "content_block_start")?;
        let content_block = data.get("content_block").ok_or_else(|| {
            ProviderError::Malformed(
                "Anthropic content_block_start was missing content_block".to_string(),
            )
        })?;
        let kind = block_kind(content_block);

        if kind != BlockKind::ToolCall {
            self.output.extend_from_slice(&frame.raw);
            self.active = Some(ActiveBlock::plain(index, kind));
            return Ok(());
        }

        let block = tool_use_from_content_block(content_block)?;
        self.phase = transition(
            &self.phase,
            StreamEvent::StartBlock {
                block_id: block.id.clone(),
                kind,
            },
        )?;
        self.active = Some(ActiveBlock::tool(index, frame, block)?);
        Ok(())
    }

    fn delta_content_block(&mut self, frame: SseFrame) -> Result<(), ProviderError> {
        let index = frame_index(&frame, "content_block_delta")?;
        let active = self.active.as_mut().ok_or_else(|| {
            ProviderError::Malformed(
                "Anthropic content_block_delta arrived without an active content block".to_string(),
            )
        })?;
        active.ensure_index(index, "content_block_delta")?;

        if active.kind != BlockKind::ToolCall {
            self.output.extend_from_slice(&frame.raw);
            return Ok(());
        }

        let partial_json = input_json_delta(&frame)?;
        self.phase = transition(
            &self.phase,
            StreamEvent::AppendBytes {
                chunk: partial_json.as_bytes().to_vec(),
            },
        )?;
        active.input_json.push_str(partial_json);
        active.push_frame(frame)?;
        Ok(())
    }

    fn stop_content_block<F>(
        &mut self,
        frame: SseFrame,
        evaluate: &mut F,
    ) -> Result<(), ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        let index = frame_index(&frame, "content_block_stop")?;
        let active = self.active.take().ok_or_else(|| {
            ProviderError::Malformed(
                "Anthropic content_block_stop arrived without an active content block".to_string(),
            )
        })?;
        active.ensure_index(index, "content_block_stop")?;

        if active.kind != BlockKind::ToolCall {
            self.output.extend_from_slice(&frame.raw);
            return Ok(());
        }

        let block = active.completed_tool_use()?;
        let invocation = self.adapter.invocation_from_tool_use(&block)?;
        let verdict = evaluate(&invocation)?;
        ensure_streaming_allow(&block, &verdict)?;
        self.phase = transition(&self.phase, StreamEvent::FinishBlock)?;
        self.invocations.push(invocation);
        self.verdicts.push(verdict);
        for frame in active.frames {
            self.output.extend_from_slice(&frame.raw);
        }
        self.output.extend_from_slice(&frame.raw);
        Ok(())
    }

    fn stop_message(&mut self, frame: SseFrame) -> Result<(), ProviderError> {
        if let Some(active) = &self.active {
            return Err(ProviderError::Malformed(format!(
                "Anthropic message_stop arrived before content block {} stopped",
                active.index
            )));
        }
        self.phase = transition(&self.phase, StreamEvent::Close)?;
        self.output.extend_from_slice(&frame.raw);
        Ok(())
    }

    fn forward_or_buffer(&mut self, frame: SseFrame) -> Result<(), ProviderError> {
        if let Some(active) = self.active.as_mut() {
            if active.kind == BlockKind::ToolCall {
                active.push_frame(frame)?;
                return Ok(());
            }
        }
        self.output.extend_from_slice(&frame.raw);
        Ok(())
    }

    fn finish(self) -> Result<GatedSseStream, ProviderError> {
        if let Some(active) = self.active {
            return Err(ProviderError::Malformed(format!(
                "Anthropic SSE ended before content block {} stopped",
                active.index
            )));
        }

        Ok(GatedSseStream {
            bytes: self.output,
            invocations: self.invocations,
            verdicts: self.verdicts,
        })
    }
}

#[derive(Debug)]
struct ActiveBlock {
    index: u64,
    kind: BlockKind,
    frames: Vec<SseFrame>,
    raw_frame_count: usize,
    raw_frame_bytes: usize,
    tool_use: Option<ToolUseBlock>,
    input_json: String,
}

impl ActiveBlock {
    fn plain(index: u64, kind: BlockKind) -> Self {
        Self {
            index,
            kind,
            frames: Vec::new(),
            raw_frame_count: 0,
            raw_frame_bytes: 0,
            tool_use: None,
            input_json: String::new(),
        }
    }

    fn tool(index: u64, frame: SseFrame, block: ToolUseBlock) -> Result<Self, ProviderError> {
        let mut active = Self {
            index,
            kind: BlockKind::ToolCall,
            frames: Vec::new(),
            raw_frame_count: 0,
            raw_frame_bytes: 0,
            tool_use: Some(block),
            input_json: String::new(),
        };
        active.push_frame(frame)?;
        Ok(active)
    }

    fn push_frame(&mut self, frame: SseFrame) -> Result<(), ProviderError> {
        let next_count = self.raw_frame_count.saturating_add(1);
        if next_count > DEFAULT_MAX_BUFFERED_RAW_FRAMES {
            return Err(ProviderError::Malformed(format!(
                "Anthropic content block {} raw frame count {next_count} exceeded limit {}",
                self.index, DEFAULT_MAX_BUFFERED_RAW_FRAMES
            )));
        }
        let frame_bytes = frame.raw.len();
        let projected = self.raw_frame_bytes.saturating_add(frame_bytes);
        if projected > DEFAULT_MAX_BUFFERED_BLOCK_BYTES {
            return Err(ProviderError::Malformed(format!(
                "Anthropic content block {} raw frame bytes would grow from {} to {projected}, exceeding limit {}",
                self.index, self.raw_frame_bytes, DEFAULT_MAX_BUFFERED_BLOCK_BYTES
            )));
        }
        self.raw_frame_count = next_count;
        self.raw_frame_bytes = projected;
        self.frames.push(frame);
        Ok(())
    }

    fn ensure_index(&self, index: u64, event: &str) -> Result<(), ProviderError> {
        if self.index != index {
            return Err(ProviderError::Malformed(format!(
                "Anthropic {event} index {index} did not match active content block {}",
                self.index
            )));
        }
        Ok(())
    }

    fn completed_tool_use(&self) -> Result<ToolUseBlock, ProviderError> {
        let mut block = self.tool_use.clone().ok_or_else(|| {
            ProviderError::Malformed(
                "Anthropic active tool block lost its tool_use start".to_string(),
            )
        })?;
        if self.input_json.is_empty() {
            return Ok(block);
        }
        if !block
            .input
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
        {
            return Err(ProviderError::BadToolArgs(format!(
                "Anthropic tool_use `{}` mixed non-empty start input with input_json_delta frames",
                block.id
            )));
        }

        let input: Value = serde_json::from_str(&self.input_json).map_err(|error| {
            ProviderError::BadToolArgs(format!(
                "Anthropic tool_use `{}` completed input_json_delta was not valid JSON: {error}",
                block.id
            ))
        })?;
        if !input.is_object() {
            return Err(ProviderError::BadToolArgs(format!(
                "Anthropic tool_use `{}` completed input_json_delta was not a JSON object",
                block.id
            )));
        }
        block.input = input;
        Ok(block)
    }
}

fn parse_anthropic_sse_frames(raw: &[u8]) -> Result<Vec<SseFrame>, ProviderError> {
    let frames = parse_shared_sse_frames(raw, ANTHROPIC_SSE_OPTIONS)?;
    for frame in &frames {
        validate_anthropic_sse_frame(frame)?;
    }
    Ok(frames)
}

fn validate_anthropic_sse_frame(frame: &SseFrame) -> Result<(), ProviderError> {
    if frame.data.is_some() && frame.event.is_none() {
        return Err(ProviderError::Malformed(
            "Anthropic SSE data frame was missing event name".to_string(),
        ));
    }
    if let (Some(event), Some(data)) = (frame.event.as_deref(), frame.data.as_ref()) {
        if let Some(data_type) = data.get("type").and_then(Value::as_str) {
            if data_type != event {
                return Err(ProviderError::Malformed(format!(
                    "Anthropic SSE event `{event}` did not match data type `{data_type}`"
                )));
            }
        }
    }
    Ok(())
}

fn required_data<'a>(frame: &'a SseFrame, event: &str) -> Result<&'a Value, ProviderError> {
    frame.data.as_ref().ok_or_else(|| {
        ProviderError::Malformed(format!("Anthropic {event} SSE frame was missing data"))
    })
}

fn data_text(frame: &SseFrame) -> String {
    frame
        .data
        .as_ref()
        .map(Value::to_string)
        .unwrap_or_else(|| "<missing data>".to_string())
}

fn frame_index(frame: &SseFrame, event: &str) -> Result<u64, ProviderError> {
    required_index(required_data(frame, event)?, event)
}

fn required_index(data: &Value, event: &str) -> Result<u64, ProviderError> {
    data.get("index")
        .and_then(Value::as_u64)
        .ok_or_else(|| ProviderError::Malformed(format!("Anthropic {event} was missing index")))
}

fn block_kind(content_block: &Value) -> BlockKind {
    match content_block.get("type").and_then(Value::as_str) {
        Some("tool_use") => BlockKind::ToolCall,
        Some("tool_result") => BlockKind::ToolResult,
        Some("text") => BlockKind::Text,
        _ => BlockKind::Other,
    }
}

fn tool_use_from_content_block(content_block: &Value) -> Result<ToolUseBlock, ProviderError> {
    if block_kind(content_block) != BlockKind::ToolCall {
        return Err(ProviderError::Malformed(
            "Anthropic content block was not tool_use".to_string(),
        ));
    }
    super::parse_tool_use_block(content_block)
}

fn input_json_delta(frame: &SseFrame) -> Result<&str, ProviderError> {
    let data = required_data(frame, "content_block_delta")?;
    let delta = data.get("delta").ok_or_else(|| {
        ProviderError::Malformed("Anthropic content_block_delta was missing delta".to_string())
    })?;
    let delta_type = delta.get("type").and_then(Value::as_str).ok_or_else(|| {
        ProviderError::Malformed("Anthropic content_block_delta was missing delta.type".to_string())
    })?;
    if delta_type != "input_json_delta" {
        return Err(ProviderError::Malformed(format!(
            "Anthropic tool_use delta type `{delta_type}` was not input_json_delta"
        )));
    }
    delta
        .get("partial_json")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::Malformed(
                "Anthropic input_json_delta was missing partial_json".to_string(),
            )
        })
}

fn ensure_streaming_allow(
    block: &ToolUseBlock,
    verdict: &VerdictResult,
) -> Result<(), ProviderError> {
    ensure_streaming_allow_no_redactions(
        "Anthropic",
        "tool_use",
        &block.id,
        Some("content_block_stop"),
        verdict,
    )
}

fn transition(phase: &StreamPhase, event: StreamEvent) -> Result<StreamPhase, ProviderError> {
    phase
        .transition(event)
        .map_err(|error| ProviderError::Malformed(format!("Anthropic SSE state error: {error}")))
}
