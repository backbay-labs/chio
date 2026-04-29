//! Anthropic Messages SSE gating.
//!
//! The adapter buffers Anthropic `tool_use` blocks until
//! `content_block_stop`, reconstructs the completed input JSON, evaluates
//! Chio's verdict, then releases the buffered start and `input_json_delta`
//! frames only when the verdict allows. A deny verdict or malformed tool-use
//! frame fails closed and returns no forwarded stream bytes for the block.

use chio_tool_call_fabric::{
    BlockKind, DenyReason, ProviderError, StreamEvent, StreamPhase, ToolInvocation, VerdictResult,
};
use serde_json::Value;

use crate::{AnthropicAdapter, ToolUseBlock};

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
        let frames = parse_sse_frames(raw)?;
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
            self.forward_or_buffer(frame);
            return Ok(());
        };

        match event {
            "content_block_start" => self.start_content_block(frame),
            "content_block_delta" => self.delta_content_block(frame),
            "content_block_stop" => self.stop_content_block(frame, evaluate),
            "message_stop" => self.stop_message(frame),
            "error" => Err(ProviderError::Malformed(format!(
                "Anthropic SSE error event: {}",
                frame.data_text()
            ))),
            _ => {
                self.forward_or_buffer(frame);
                Ok(())
            }
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

        let data = frame.required_data("content_block_start")?;
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
        self.active = Some(ActiveBlock::tool(index, frame, block));
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
        active.frames.push(frame);
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
        let mut active = self.active.take().ok_or_else(|| {
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
        active.frames.push(frame);
        for frame in active.frames {
            self.output.extend_from_slice(&frame.raw);
        }
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

    fn forward_or_buffer(&mut self, frame: SseFrame) {
        if let Some(active) = self.active.as_mut() {
            if active.kind == BlockKind::ToolCall {
                active.frames.push(frame);
                return;
            }
        }
        self.output.extend_from_slice(&frame.raw);
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
    tool_use: Option<ToolUseBlock>,
    input_json: String,
}

impl ActiveBlock {
    fn plain(index: u64, kind: BlockKind) -> Self {
        Self {
            index,
            kind,
            frames: Vec::new(),
            tool_use: None,
            input_json: String::new(),
        }
    }

    fn tool(index: u64, frame: SseFrame, block: ToolUseBlock) -> Self {
        Self {
            index,
            kind: BlockKind::ToolCall,
            frames: vec![frame],
            tool_use: Some(block),
            input_json: String::new(),
        }
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

#[derive(Debug, Clone)]
struct SseFrame {
    event: Option<String>,
    data: Option<Value>,
    raw: Vec<u8>,
}

impl SseFrame {
    fn required_data(&self, event: &str) -> Result<&Value, ProviderError> {
        self.data.as_ref().ok_or_else(|| {
            ProviderError::Malformed(format!("Anthropic {event} SSE frame was missing data"))
        })
    }

    fn data_text(&self) -> String {
        self.data
            .as_ref()
            .map(Value::to_string)
            .unwrap_or_else(|| "<missing data>".to_string())
    }
}

fn parse_sse_frames(raw: &[u8]) -> Result<Vec<SseFrame>, ProviderError> {
    let text = std::str::from_utf8(raw).map_err(|error| {
        ProviderError::Malformed(format!("Anthropic SSE bytes were not UTF-8: {error}"))
    })?;
    let mut frames = Vec::new();
    let mut lines = Vec::new();

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
    let mut event = None;
    let mut data_lines = Vec::new();
    let mut raw = Vec::new();

    for line in lines {
        raw.extend_from_slice(line.as_bytes());
        raw.push(b'\n');

        if line.starts_with(':') {
            continue;
        }

        let (field, value) = line.split_once(':').ok_or_else(|| {
            ProviderError::Malformed(format!("Anthropic SSE line `{line}` was missing `:`"))
        })?;
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => event = Some(value.to_string()),
            "data" => data_lines.push(value.to_string()),
            "id" | "retry" => {}
            other => {
                return Err(ProviderError::Malformed(format!(
                    "Anthropic SSE field `{other}` is not supported"
                )));
            }
        }
    }
    raw.push(b'\n');

    let data = if data_lines.is_empty() {
        None
    } else {
        let data_text = data_lines.join("\n");
        Some(serde_json::from_str::<Value>(&data_text).map_err(|error| {
            ProviderError::Malformed(format!("Anthropic SSE data was not JSON: {error}"))
        })?)
    };

    if data.is_some() && event.is_none() {
        return Err(ProviderError::Malformed(
            "Anthropic SSE data frame was missing event name".to_string(),
        ));
    }
    if let (Some(event), Some(data)) = (event.as_deref(), data.as_ref()) {
        if let Some(data_type) = data.get("type").and_then(Value::as_str) {
            if data_type != event {
                return Err(ProviderError::Malformed(format!(
                    "Anthropic SSE event `{event}` did not match data type `{data_type}`"
                )));
            }
        }
    }

    Ok(SseFrame { event, data, raw })
}

fn frame_index(frame: &SseFrame, event: &str) -> Result<u64, ProviderError> {
    required_index(frame.required_data(event)?, event)
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
    let data = frame.required_data("content_block_delta")?;
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
    match verdict {
        VerdictResult::Allow { redactions, .. } if redactions.is_empty() => Ok(()),
        VerdictResult::Allow { .. } => Err(ProviderError::Malformed(format!(
            "Anthropic streaming tool_use `{}` allow verdict requested redactions; fail-closed",
            block.id
        ))),
        VerdictResult::Deny { reason, receipt_id } => Err(ProviderError::Malformed(format!(
            "Anthropic streaming tool_use `{}` denied at content_block_stop: {} (receipt {})",
            block.id,
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

fn transition(phase: &StreamPhase, event: StreamEvent) -> Result<StreamPhase, ProviderError> {
    phase
        .transition(event)
        .map_err(|error| ProviderError::Malformed(format!("Anthropic SSE state error: {error}")))
}
