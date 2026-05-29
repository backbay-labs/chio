//! OpenAI Responses SSE gating.
//!
//! Tool-call start and argument-delta frames are held behind the shared fabric
//! `StreamPhase` until the final argument frames have been checked, the adapter
//! lifts `response.output_item.done` into a canonical invocation, and the
//! verdict allows the block.

use chio_provider_adapter_core::{
    ensure_streaming_allow_no_redactions, parse_sse_frames, SseFrame, SseParseOptions,
};
use chio_tool_call_fabric::{
    BlockKind, BufferedBlock, ProviderError, ProviderRequest, StreamEvent, StreamPhase,
    ToolInvocation, VerdictResult, DEFAULT_MAX_BUFFERED_BLOCK_BYTES,
    DEFAULT_MAX_BUFFERED_RAW_FRAMES,
};
use serde_json::{json, Value};

use crate::adapter::OpenAiAdapter;

/// SSE provider label used in error messages and parser configuration.
const OPENAI_SSE_LABEL: &str = "OpenAI";

/// OpenAI Responses SSE parser options: the canonical parser plus the OpenAI
/// `[DONE]` terminator and the `event`/data-`type` cross-check.
const OPENAI_SSE_OPTIONS: SseParseOptions = SseParseOptions::rejecting_unknown(OPENAI_SSE_LABEL)
    .with_done_sentinel("[DONE]")
    .with_event_type_cross_check();

/// Borrow a frame's parsed JSON data or fail closed when it is absent.
fn required_data<'a>(frame: &'a SseFrame, event: &str) -> Result<&'a Value, ProviderError> {
    frame.data.as_ref().ok_or_else(|| {
        ProviderError::Malformed(format!("OpenAI {event} SSE frame was missing data"))
    })
}

/// Render a frame's data for error context, tolerating a missing payload.
fn data_text(frame: &SseFrame) -> String {
    frame
        .data
        .as_ref()
        .map(Value::to_string)
        .unwrap_or_else(|| "<missing data>".to_string())
}

/// Result of gating one deterministic OpenAI Responses SSE payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatedSseStream {
    /// SSE bytes that are safe to forward downstream.
    pub bytes: Vec<u8>,
    /// Tool invocations evaluated at `response.output_item.done`.
    pub invocations: Vec<ToolInvocation>,
    /// Verdicts returned for each invocation, in stream order.
    pub verdicts: Vec<VerdictResult>,
    /// Per-tool-call argument buffers accumulated from delta frames.
    pub buffered_blocks: Vec<BufferedBlock>,
}

/// Deterministic OpenAI SSE transport used by tests and replay.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpenAiSseTransport;

impl OpenAiSseTransport {
    /// Gate a Responses API SSE payload through the supplied adapter.
    pub fn gate_response_stream<F>(
        &self,
        adapter: &OpenAiAdapter,
        raw: &[u8],
        mut evaluate: F,
    ) -> Result<GatedSseStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        let frames = parse_sse_frames(raw, OPENAI_SSE_OPTIONS)?;
        let mut gate = StreamGate::new(adapter);

        for frame in frames {
            gate.accept(frame, &mut evaluate)?;
        }

        gate.finish()
    }
}

impl OpenAiAdapter {
    /// Gate a deterministic OpenAI Responses SSE payload.
    ///
    /// `evaluate` is called exactly when `response.output_item.done` carries a
    /// completed tool-call output item. The start frame, argument deltas, and
    /// argument-done frame remain buffered until the verdict allows the block.
    pub fn gate_sse_stream<F>(
        &self,
        raw: &[u8],
        evaluate: F,
    ) -> Result<GatedSseStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        OpenAiSseTransport.gate_response_stream(self, raw, evaluate)
    }
}

struct StreamGate<'a> {
    adapter: &'a OpenAiAdapter,
    output: Vec<u8>,
    phase: StreamPhase,
    active: Option<ActiveToolBlock>,
    invocations: Vec<ToolInvocation>,
    verdicts: Vec<VerdictResult>,
    buffered_blocks: Vec<BufferedBlock>,
}

impl<'a> StreamGate<'a> {
    fn new(adapter: &'a OpenAiAdapter) -> Self {
        Self {
            adapter,
            output: Vec::new(),
            phase: StreamPhase::Idle,
            active: None,
            invocations: Vec::new(),
            verdicts: Vec::new(),
            buffered_blocks: Vec::new(),
        }
    }

    fn accept<F>(&mut self, frame: SseFrame, evaluate: &mut F) -> Result<(), ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        if frame.done {
            self.close_stream(frame)?;
            return Ok(());
        }

        let Some(event) = frame.event.as_deref() else {
            return self.forward_or_buffer(frame);
        };

        match event {
            "response.output_item.added" => self.start_output_item(frame),
            "response.function_call_arguments.delta" => self.argument_delta(frame),
            "response.function_call_arguments.done" => self.argument_done(frame),
            "response.output_item.done" => self.finish_output_item(frame, evaluate),
            "response.completed" => self.close_stream(frame),
            "error" | "response.error" => Err(ProviderError::Malformed(format!(
                "OpenAI SSE error event: {}",
                data_text(&frame)
            ))),
            _ => self.forward_or_buffer(frame),
        }
    }

    fn start_output_item(&mut self, frame: SseFrame) -> Result<(), ProviderError> {
        if let Some(active) = &self.active {
            return Err(ProviderError::Malformed(format!(
                "OpenAI output_item.added arrived before tool call {} completed",
                active.call_id
            )));
        }

        let data = required_data(&frame, "response.output_item.added")?;
        let item = data.get("item").ok_or_else(|| {
            ProviderError::Malformed("OpenAI output_item.added was missing item".to_string())
        })?;

        if !is_tool_call_item(item) {
            self.output.extend_from_slice(&frame.raw);
            return Ok(());
        }

        let call = response_tool_call_start_from_item(item)?;
        self.phase = transition(
            &self.phase,
            StreamEvent::StartBlock {
                block_id: call.call_id.clone(),
                kind: BlockKind::ToolCall,
            },
        )?;
        self.active = Some(ActiveToolBlock::new(
            frame_output_index(data),
            call.item_id,
            call.call_id,
            call.name,
            call.arguments,
            frame,
        )?);
        Ok(())
    }

    fn argument_delta(&mut self, frame: SseFrame) -> Result<(), ProviderError> {
        let Some(active) = self.active.as_mut() else {
            return Err(ProviderError::Malformed(
                "OpenAI function_call_arguments.delta arrived without an active tool call"
                    .to_string(),
            ));
        };
        active.ensure_match(&frame, "response.function_call_arguments.delta")?;

        let delta = argument_delta_text(&frame)?;
        active.record_argument_delta()?;
        self.phase = transition(
            &self.phase,
            StreamEvent::AppendBytes {
                chunk: delta.as_bytes().to_vec(),
            },
        )?;
        active.push_frame(frame)?;
        Ok(())
    }

    fn argument_done(&mut self, frame: SseFrame) -> Result<(), ProviderError> {
        let buffered = self.phase.buffered().cloned();
        let Some(active) = self.active.as_mut() else {
            return Err(ProviderError::Malformed(
                "OpenAI function_call_arguments.done arrived without an active tool call"
                    .to_string(),
            ));
        };
        active.ensure_match(&frame, "response.function_call_arguments.done")?;

        let arguments = argument_done_text(&frame)?;
        active.record_argument_done(arguments, buffered.as_ref())?;
        active.push_frame(frame)?;
        Ok(())
    }

    fn finish_output_item<F>(
        &mut self,
        frame: SseFrame,
        evaluate: &mut F,
    ) -> Result<(), ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        let data = required_data(&frame, "response.output_item.done")?;
        let item = data.get("item");

        let Some(active) = self.active.take() else {
            if item.is_some_and(is_tool_call_item) {
                return Err(ProviderError::Malformed(
                    "OpenAI output_item.done tool call arrived without an active tool call"
                        .to_string(),
                ));
            }
            self.output.extend_from_slice(&frame.raw);
            return Ok(());
        };
        active.ensure_match(&frame, "response.output_item.done")?;
        let item = item.ok_or_else(|| {
            ProviderError::Malformed(
                "OpenAI output_item.done for active tool call was missing item".to_string(),
            )
        })?;
        if !is_tool_call_item(item) {
            return Err(ProviderError::Malformed(format!(
                "OpenAI output_item.done for active tool call {} was not a tool item",
                active.call_id
            )));
        }

        let buffered = self.phase.buffered().cloned().ok_or_else(|| {
            ProviderError::Malformed(
                "OpenAI SSE state lost the active tool-call buffer".to_string(),
            )
        })?;
        let call = response_tool_call_from_item(item)?;
        active.ensure_completed_call_matches(&call)?;
        ensure_streamed_arguments_match(&call, &buffered)?;

        let invocation = self.invocation_from_call(&call)?;
        let verdict = evaluate(&invocation).inspect_err(|_error| {
            let _ = self.close_buffering_phase();
        })?;
        if let Err(error) = ensure_streaming_allow(&call.call_id, &verdict) {
            let _ = self.close_buffering_phase();
            return Err(error);
        }

        self.phase = transition(&self.phase, StreamEvent::FinishBlock)?;
        self.invocations.push(invocation);
        self.verdicts.push(verdict);
        self.buffered_blocks.push(buffered);
        for frame in active.frames {
            self.output.extend_from_slice(&frame.raw);
        }
        self.output.extend_from_slice(&frame.raw);
        Ok(())
    }

    fn close_stream(&mut self, frame: SseFrame) -> Result<(), ProviderError> {
        if let Some(active) = &self.active {
            return Err(ProviderError::Malformed(format!(
                "OpenAI stream closed before tool call {} completed",
                active.call_id
            )));
        }
        if self.phase.is_closed() {
            self.output.extend_from_slice(&frame.raw);
            return Ok(());
        }
        self.phase = transition(&self.phase, StreamEvent::Close)?;
        self.output.extend_from_slice(&frame.raw);
        Ok(())
    }

    fn forward_or_buffer(&mut self, frame: SseFrame) -> Result<(), ProviderError> {
        if let Some(active) = self.active.as_mut() {
            active.push_frame(frame)?;
            return Ok(());
        }
        self.output.extend_from_slice(&frame.raw);
        Ok(())
    }

    fn invocation_from_call(
        &self,
        call: &ResponseToolCall,
    ) -> Result<ToolInvocation, ProviderError> {
        self.adapter
            .lift_batch(ProviderRequest(
                serde_json::to_vec(&json!({ "output": [call.payload.clone()] })).map_err(
                    |error| {
                        ProviderError::Malformed(format!(
                            "OpenAI SSE tool-call payload failed JSON encoding: {error}"
                        ))
                    },
                )?,
            ))?
            .into_iter()
            .next()
            .ok_or_else(|| {
                ProviderError::Malformed(
                    "OpenAI SSE tool-call item did not lift into an invocation".to_string(),
                )
            })
    }

    fn close_buffering_phase(&mut self) -> Result<(), ProviderError> {
        self.phase = transition(&self.phase, StreamEvent::Close)?;
        Ok(())
    }

    fn finish(self) -> Result<GatedSseStream, ProviderError> {
        if let Some(active) = self.active {
            return Err(ProviderError::Malformed(format!(
                "OpenAI SSE ended before tool call {} completed",
                active.call_id
            )));
        }

        Ok(GatedSseStream {
            bytes: self.output,
            invocations: self.invocations,
            verdicts: self.verdicts,
            buffered_blocks: self.buffered_blocks,
        })
    }
}

#[derive(Debug)]
struct ActiveToolBlock {
    output_index: Option<u64>,
    item_id: Option<String>,
    call_id: String,
    name: Option<String>,
    start_arguments: Option<String>,
    saw_argument_delta: bool,
    done_arguments: Option<String>,
    raw_frame_count: usize,
    raw_frame_bytes: usize,
    frames: Vec<SseFrame>,
}

impl ActiveToolBlock {
    fn new(
        output_index: Option<u64>,
        item_id: Option<String>,
        call_id: String,
        name: Option<String>,
        start_arguments: Option<String>,
        first: SseFrame,
    ) -> Result<Self, ProviderError> {
        let mut block = Self {
            output_index,
            item_id,
            call_id,
            name,
            start_arguments,
            saw_argument_delta: false,
            done_arguments: None,
            raw_frame_count: 0,
            raw_frame_bytes: 0,
            frames: Vec::new(),
        };
        block.push_frame(first)?;
        Ok(block)
    }

    fn push_frame(&mut self, frame: SseFrame) -> Result<(), ProviderError> {
        let next_count = self.raw_frame_count.saturating_add(1);
        if next_count > DEFAULT_MAX_BUFFERED_RAW_FRAMES {
            return Err(ProviderError::Malformed(format!(
                "OpenAI tool call `{}` raw frame count {next_count} exceeded limit {}",
                self.call_id, DEFAULT_MAX_BUFFERED_RAW_FRAMES
            )));
        }
        let frame_bytes = frame.raw.len();
        let projected = self.raw_frame_bytes.saturating_add(frame_bytes);
        if projected > DEFAULT_MAX_BUFFERED_BLOCK_BYTES {
            return Err(ProviderError::Malformed(format!(
                "OpenAI tool call `{}` raw frame bytes would grow from {} to {projected}, exceeding limit {}",
                self.call_id, self.raw_frame_bytes, DEFAULT_MAX_BUFFERED_BLOCK_BYTES
            )));
        }
        self.raw_frame_count = next_count;
        self.raw_frame_bytes = projected;
        self.frames.push(frame);
        Ok(())
    }

    fn record_argument_delta(&mut self) -> Result<(), ProviderError> {
        self.saw_argument_delta = true;
        if self
            .start_arguments
            .as_deref()
            .is_some_and(|arguments| !arguments.is_empty())
        {
            return Err(ProviderError::BadToolArgs(format!(
                "OpenAI tool call `{}` mixed non-empty output_item.added arguments with argument delta frames",
                self.call_id
            )));
        }
        Ok(())
    }

    fn record_argument_done(
        &mut self,
        arguments: String,
        buffered: Option<&BufferedBlock>,
    ) -> Result<(), ProviderError> {
        if self.done_arguments.is_some() {
            return Err(ProviderError::Malformed(format!(
                "OpenAI function_call_arguments.done repeated for tool call `{}`",
                self.call_id
            )));
        }
        if self.saw_argument_delta {
            let buffered = buffered.ok_or_else(|| {
                ProviderError::Malformed(format!(
                    "OpenAI SSE state lost streamed arguments for tool call `{}`",
                    self.call_id
                ))
            })?;
            ensure_streamed_arguments_match_text(&self.call_id, &arguments, buffered)?;
        }
        self.done_arguments = Some(arguments);
        Ok(())
    }

    fn ensure_match(&self, frame: &SseFrame, event: &str) -> Result<(), ProviderError> {
        let data = required_data(frame, event)?;
        if let (Some(expected), Some(actual)) = (self.output_index, frame_output_index(data)) {
            if expected != actual {
                return Err(ProviderError::Malformed(format!(
                    "OpenAI {event} output_index {actual} did not match active output_index {expected}"
                )));
            }
        }
        if let (Some(expected), Some(actual)) = (&self.item_id, frame_item_id(data)) {
            if expected != &actual {
                return Err(ProviderError::Malformed(format!(
                    "OpenAI {event} item_id {actual} did not match active item_id {expected}"
                )));
            }
        }
        if let Some(actual) = frame_call_id(data) {
            if actual != self.call_id {
                return Err(ProviderError::Malformed(format!(
                    "OpenAI {event} call_id {actual} did not match active call_id {}",
                    self.call_id
                )));
            }
        }
        Ok(())
    }

    fn ensure_completed_call_matches(&self, call: &ResponseToolCall) -> Result<(), ProviderError> {
        if let (Some(expected), Some(actual)) = (&self.item_id, &call.item_id) {
            if expected != actual {
                return Err(ProviderError::Malformed(format!(
                    "OpenAI output_item.done item_id {actual} did not match active item_id {expected}"
                )));
            }
        }
        if call.call_id != self.call_id {
            return Err(ProviderError::Malformed(format!(
                "OpenAI output_item.done call_id {} did not match active call_id {}",
                call.call_id, self.call_id
            )));
        }
        if let Some(name) = &self.name {
            if call.name != *name {
                return Err(ProviderError::Malformed(format!(
                    "OpenAI output_item.done name {} did not match active name {}",
                    call.name, name
                )));
            }
        }
        if let Some(start_arguments) = &self.start_arguments {
            if !start_arguments.is_empty()
                && !self.saw_argument_delta
                && start_arguments.as_bytes() != call.arguments.as_bytes()
            {
                return Err(ProviderError::Malformed(format!(
                    "OpenAI output_item.done arguments for tool call `{}` did not match non-empty output_item.added arguments",
                    self.call_id
                )));
            }
        }
        if self.saw_argument_delta && self.done_arguments.is_none() {
            return Err(ProviderError::Malformed(format!(
                "OpenAI tool call `{}` streamed argument deltas without response.function_call_arguments.done",
                self.call_id
            )));
        }
        if let Some(done_arguments) = &self.done_arguments {
            if done_arguments.as_bytes() != call.arguments.as_bytes() {
                return Err(ProviderError::Malformed(format!(
                    "OpenAI function_call_arguments.done arguments for tool call `{}` did not match output_item.done arguments",
                    self.call_id
                )));
            }
        }
        Ok(())
    }
}

struct ResponseToolCallStart {
    item_id: Option<String>,
    call_id: String,
    name: Option<String>,
    arguments: Option<String>,
}

struct ResponseToolCall {
    item_id: Option<String>,
    call_id: String,
    name: String,
    arguments: String,
    payload: Value,
}

fn response_tool_call_start_from_item(
    item: &Value,
) -> Result<ResponseToolCallStart, ProviderError> {
    Ok(ResponseToolCallStart {
        item_id: tool_call_item_id(item),
        call_id: tool_call_id(item)?,
        name: tool_call_name(item),
        arguments: item
            .get("arguments")
            .or_else(|| {
                item.get("function")
                    .and_then(|function| function.get("arguments"))
            })
            .map(start_arguments_string)
            .transpose()?,
    })
}

fn response_tool_call_from_item(item: &Value) -> Result<ResponseToolCall, ProviderError> {
    let item_id = tool_call_item_id(item);
    let call_id = tool_call_id(item)?;
    let name = tool_call_name(item).ok_or_else(|| {
        ProviderError::Malformed("OpenAI SSE tool-call item was missing non-empty name".to_string())
    })?;
    let arguments = item
        .get("arguments")
        .or_else(|| {
            item.get("function")
                .and_then(|function| function.get("arguments"))
        })
        .ok_or_else(|| {
            ProviderError::Malformed("OpenAI SSE tool-call item was missing arguments".to_string())
        })?;
    let arguments = arguments_string(arguments)?;

    Ok(ResponseToolCall {
        item_id,
        call_id: call_id.clone(),
        name: name.clone(),
        arguments: arguments.clone(),
        payload: json!({
            "arguments": arguments,
            "call_id": call_id,
            "name": name,
            "type": "function_call",
        }),
    })
}

fn tool_call_item_id(item: &Value) -> Option<String> {
    item.get("id").and_then(Value::as_str).and_then(non_empty)
}

fn tool_call_id(item: &Value) -> Result<String, ProviderError> {
    item.get("call_id")
        .and_then(Value::as_str)
        .and_then(non_empty)
        .ok_or_else(|| {
            ProviderError::Malformed(
                "OpenAI SSE tool-call item was missing non-empty call_id".to_string(),
            )
        })
}

fn tool_call_name(item: &Value) -> Option<String> {
    item.get("name")
        .or_else(|| {
            item.get("function")
                .and_then(|function| function.get("name"))
        })
        .and_then(Value::as_str)
        .and_then(non_empty)
}

fn arguments_string(value: &Value) -> Result<String, ProviderError> {
    match value {
        Value::String(text) => {
            serde_json::from_str::<Value>(text).map_err(|error| {
                ProviderError::BadToolArgs(format!(
                    "OpenAI SSE tool-call arguments were not valid JSON: {error}"
                ))
            })?;
            Ok(text.to_string())
        }
        Value::Object(_) => serde_json::to_string(value).map_err(|error| {
            ProviderError::Malformed(format!(
                "OpenAI SSE tool-call arguments failed JSON encoding: {error}"
            ))
        }),
        _ => Err(ProviderError::BadToolArgs(
            "OpenAI SSE tool-call arguments must be a JSON object or JSON string".to_string(),
        )),
    }
}

fn start_arguments_string(value: &Value) -> Result<String, ProviderError> {
    if value.as_str() == Some("") {
        return Ok(String::new());
    }
    arguments_string(value)
}

fn is_tool_call_item(item: &Value) -> bool {
    item.get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind == "function_call" || kind == "tool_call")
}

fn frame_output_index(data: &Value) -> Option<u64> {
    data.get("output_index")
        .or_else(|| data.get("item").and_then(|item| item.get("output_index")))
        .and_then(Value::as_u64)
}

fn frame_item_id(data: &Value) -> Option<String> {
    data.get("item_id")
        .or_else(|| data.get("item").and_then(|item| item.get("id")))
        .and_then(Value::as_str)
        .and_then(non_empty)
}

fn frame_call_id(data: &Value) -> Option<String> {
    data.get("call_id")
        .or_else(|| data.get("item").and_then(|item| item.get("call_id")))
        .and_then(Value::as_str)
        .and_then(non_empty)
}

fn argument_delta_text(frame: &SseFrame) -> Result<&str, ProviderError> {
    let data = required_data(frame, "response.function_call_arguments.delta")?;
    data.get("delta")
        .or_else(|| data.get("arguments_delta"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::Malformed(
                "OpenAI function_call_arguments.delta was missing delta".to_string(),
            )
        })
}

fn argument_done_text(frame: &SseFrame) -> Result<String, ProviderError> {
    let data = required_data(frame, "response.function_call_arguments.done")?;
    let arguments = data.get("arguments").ok_or_else(|| {
        ProviderError::Malformed(
            "OpenAI function_call_arguments.done was missing arguments".to_string(),
        )
    })?;
    arguments_string(arguments)
}

fn ensure_streamed_arguments_match(
    call: &ResponseToolCall,
    buffered: &BufferedBlock,
) -> Result<(), ProviderError> {
    ensure_streamed_arguments_match_text(&call.call_id, &call.arguments, buffered)
}

fn ensure_streamed_arguments_match_text(
    call_id: &str,
    arguments: &str,
    buffered: &BufferedBlock,
) -> Result<(), ProviderError> {
    if buffered.bytes.is_empty() || buffered.bytes == arguments.as_bytes() {
        return Ok(());
    }

    Err(ProviderError::Malformed(format!(
        "OpenAI streamed argument deltas for tool call `{call_id}` did not match final arguments"
    )))
}

fn ensure_streaming_allow(call_id: &str, verdict: &VerdictResult) -> Result<(), ProviderError> {
    ensure_streaming_allow_no_redactions(
        OPENAI_SSE_LABEL,
        "tool call",
        call_id,
        Some("output_item.done"),
        verdict,
    )
}

fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn transition(phase: &StreamPhase, event: StreamEvent) -> Result<StreamPhase, ProviderError> {
    phase
        .transition(event)
        .map_err(|error| ProviderError::Malformed(format!("OpenAI SSE state error: {error}")))
}
