//! Bedrock ConverseStream event gating.
//!
//! Bedrock Runtime streams `ConverseStream` over HTTP/2 event messages. This
//! module uses deterministic JSON event-message fixtures for tests and replay:
//! each event is represented as an object with one top-level Bedrock event
//! key such as `contentBlockStart`, `contentBlockDelta`, or `messageStop`.
//! The adapter buffers `toolUse` starts and later `contentBlockDelta` input
//! fragments until `contentBlockStop`, reconstructs the completed JSON,
//! evaluates Chio's verdict, then releases buffered frames only when the
//! verdict allows. Malformed events, evaluator errors, redaction-bearing
//! allows, and denied tool uses all fail closed before any bytes for the
//! tool-use block are released.

use chio_tool_call_fabric::{
    BlockKind, DenyReason, ProviderError, StreamEvent, StreamPhase, ToolInvocation, VerdictResult,
};
use serde_json::{json, Value};

use crate::{BedrockAdapter, BedrockOperation, ToolUseBlock};

/// Result of gating one deterministic Bedrock ConverseStream payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatedConverseStream {
    /// JSON bytes for the event messages that are safe to forward.
    pub bytes: Vec<u8>,
    /// Forwarded event messages in stream order.
    pub events: Vec<Value>,
    /// Tool invocations evaluated at `contentBlockStop`.
    pub invocations: Vec<ToolInvocation>,
    /// Verdicts returned for each invocation, in stream order.
    pub verdicts: Vec<VerdictResult>,
}

impl BedrockAdapter {
    /// Gate a deterministic Bedrock ConverseStream payload.
    ///
    /// `evaluate` is called once the full `toolUse` input JSON has arrived.
    /// Returning a deny verdict fails closed before any bytes for that block
    /// are released.
    pub fn gate_converse_stream<F>(
        &self,
        raw: &[u8],
        mut evaluate: F,
    ) -> Result<GatedConverseStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        self.transport()
            .validate_operation(BedrockOperation::ConverseStream)
            .map_err(|error| {
                ProviderError::Malformed(format!(
                    "Bedrock ConverseStream transport gate failed: {error}"
                ))
            })?;

        let events = parse_event_messages(raw)?;
        let mut gate = StreamGate::new(self);

        for event in events {
            gate.accept(event, &mut evaluate)?;
        }

        gate.finish()
    }
}

struct StreamGate<'a> {
    adapter: &'a BedrockAdapter,
    output: Vec<Value>,
    phase: StreamPhase,
    active: Option<ActiveToolBlock>,
    invocations: Vec<ToolInvocation>,
    verdicts: Vec<VerdictResult>,
}

impl<'a> StreamGate<'a> {
    fn new(adapter: &'a BedrockAdapter) -> Self {
        Self {
            adapter,
            output: Vec::new(),
            phase: StreamPhase::Idle,
            active: None,
            invocations: Vec::new(),
            verdicts: Vec::new(),
        }
    }

    fn accept<F>(
        &mut self,
        event: ConverseStreamEvent,
        evaluate: &mut F,
    ) -> Result<(), ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        match event.kind {
            EventKind::MessageStart | EventKind::Metadata => {
                self.forward(event);
                Ok(())
            }
            EventKind::ContentBlockStart => self.start_content_block(event),
            EventKind::ContentBlockDelta => self.delta_content_block(event),
            EventKind::ContentBlockStop => self.stop_content_block(event, evaluate),
            EventKind::MessageStop => self.stop_message(event),
            EventKind::Error => Err(ProviderError::Malformed(format!(
                "Bedrock ConverseStream error event `{}`: {}",
                event.name, event.payload
            ))),
            EventKind::Unknown => Err(ProviderError::Malformed(format!(
                "Bedrock ConverseStream event `{}` is not supported",
                event.name
            ))),
        }
    }

    fn start_content_block(&mut self, event: ConverseStreamEvent) -> Result<(), ProviderError> {
        if let Some(active) = &self.active {
            return Err(ProviderError::Malformed(format!(
                "Bedrock contentBlockStart arrived before content block {} stopped",
                active.index
            )));
        }

        let index = content_block_index(&event.payload, "contentBlockStart")?;
        let start = event.payload.get("start").ok_or_else(|| {
            ProviderError::Malformed("Bedrock contentBlockStart was missing start".to_string())
        })?;
        let Some(block) = tool_use_from_start(start)? else {
            self.forward(event);
            return Ok(());
        };

        self.phase = transition(
            &self.phase,
            StreamEvent::StartBlock {
                block_id: block.tool_use_id.clone(),
                kind: BlockKind::ToolCall,
            },
        )?;
        self.active = Some(ActiveToolBlock::new(index, block, event.raw));
        Ok(())
    }

    fn delta_content_block(&mut self, event: ConverseStreamEvent) -> Result<(), ProviderError> {
        let index = content_block_index(&event.payload, "contentBlockDelta")?;
        let Some(active) = self.active.as_mut() else {
            if has_tool_use_delta(&event.payload) {
                return Err(ProviderError::Malformed(
                    "Bedrock contentBlockDelta toolUse arrived without an active contentBlockStart"
                        .to_string(),
                ));
            }
            self.forward(event);
            return Ok(());
        };
        active.ensure_index(index, "contentBlockDelta")?;

        let input = tool_use_delta_input(&event.payload)?;
        self.phase = transition(
            &self.phase,
            StreamEvent::AppendBytes {
                chunk: input.as_bytes().to_vec(),
            },
        )?;
        active.input_json.push_str(input);
        active.frames.push(event.raw);
        Ok(())
    }

    fn stop_content_block<F>(
        &mut self,
        event: ConverseStreamEvent,
        evaluate: &mut F,
    ) -> Result<(), ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        let index = content_block_index(&event.payload, "contentBlockStop")?;
        let Some(mut active) = self.active.take() else {
            self.forward(event);
            return Ok(());
        };
        active.ensure_index(index, "contentBlockStop")?;

        let block = active.completed_tool_use()?;
        let invocation = self.adapter.invocation_from_tool_use(block.clone())?;
        let verdict = evaluate(&invocation)?;
        ensure_streaming_allow(&block, &verdict)?;
        self.phase = transition(&self.phase, StreamEvent::FinishBlock)?;
        self.invocations.push(invocation);
        self.verdicts.push(verdict);
        active.frames.push(event.raw);
        self.output.extend(active.frames);
        Ok(())
    }

    fn stop_message(&mut self, event: ConverseStreamEvent) -> Result<(), ProviderError> {
        if let Some(active) = &self.active {
            return Err(ProviderError::Malformed(format!(
                "Bedrock messageStop arrived before content block {} stopped",
                active.index
            )));
        }
        self.phase = transition(&self.phase, StreamEvent::Close)?;
        self.forward(event);
        Ok(())
    }

    fn forward(&mut self, event: ConverseStreamEvent) {
        self.output.push(event.raw);
    }

    fn finish(self) -> Result<GatedConverseStream, ProviderError> {
        if let Some(active) = self.active {
            return Err(ProviderError::Malformed(format!(
                "Bedrock ConverseStream ended before content block {} stopped",
                active.index
            )));
        }

        let bytes = serde_json::to_vec(&self.output).map_err(|error| {
            ProviderError::Malformed(format!(
                "Bedrock ConverseStream forwarded events failed JSON encoding: {error}"
            ))
        })?;
        Ok(GatedConverseStream {
            bytes,
            events: self.output,
            invocations: self.invocations,
            verdicts: self.verdicts,
        })
    }
}

#[derive(Debug)]
struct ActiveToolBlock {
    index: u64,
    block: ToolUseBlock,
    input_json: String,
    frames: Vec<Value>,
}

impl ActiveToolBlock {
    fn new(index: u64, block: ToolUseBlock, first: Value) -> Self {
        Self {
            index,
            block,
            input_json: String::new(),
            frames: vec![first],
        }
    }

    fn ensure_index(&self, index: u64, event: &str) -> Result<(), ProviderError> {
        if self.index != index {
            return Err(ProviderError::Malformed(format!(
                "Bedrock {event} contentBlockIndex {index} did not match active content block {}",
                self.index
            )));
        }
        Ok(())
    }

    fn completed_tool_use(&self) -> Result<ToolUseBlock, ProviderError> {
        let mut block = self.block.clone();
        if self.input_json.is_empty() {
            if !block.input.is_object() {
                return Err(ProviderError::BadToolArgs(format!(
                    "Bedrock toolUse `{}` input must be a JSON object",
                    block.tool_use_id
                )));
            }
            return Ok(block);
        }
        if !block
            .input
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
        {
            return Err(ProviderError::BadToolArgs(format!(
                "Bedrock toolUse `{}` mixed non-empty start input with delta.toolUse.input frames",
                block.tool_use_id
            )));
        }

        let input: Value = serde_json::from_str(&self.input_json).map_err(|error| {
            ProviderError::BadToolArgs(format!(
                "Bedrock toolUse `{}` completed delta.toolUse.input was not valid JSON: {error}",
                block.tool_use_id
            ))
        })?;
        if !input.is_object() {
            return Err(ProviderError::BadToolArgs(format!(
                "Bedrock toolUse `{}` completed delta.toolUse.input was not a JSON object",
                block.tool_use_id
            )));
        }
        block.input = input;
        Ok(block)
    }
}

#[derive(Debug, Clone)]
struct ConverseStreamEvent {
    kind: EventKind,
    name: String,
    payload: Value,
    raw: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventKind {
    MessageStart,
    ContentBlockStart,
    ContentBlockDelta,
    ContentBlockStop,
    MessageStop,
    Metadata,
    Error,
    Unknown,
}

fn parse_event_messages(raw: &[u8]) -> Result<Vec<ConverseStreamEvent>, ProviderError> {
    let value: Value = serde_json::from_slice(raw).map_err(|error| {
        ProviderError::Malformed(format!(
            "Bedrock ConverseStream event payload was not JSON: {error}"
        ))
    })?;

    let values = match value {
        Value::Array(values) => values,
        Value::Object(mut map) => {
            if let Some(Value::Array(values)) = map.remove("events") {
                values
            } else if let Some(Value::Array(values)) = map.remove("eventStream") {
                values
            } else {
                vec![Value::Object(map)]
            }
        }
        _ => {
            return Err(ProviderError::Malformed(
                "Bedrock ConverseStream payload must be an event array or envelope".to_string(),
            ))
        }
    };

    values.into_iter().map(parse_event_message).collect()
}

fn parse_event_message(value: Value) -> Result<ConverseStreamEvent, ProviderError> {
    let map = value.as_object().ok_or_else(|| {
        ProviderError::Malformed(
            "Bedrock ConverseStream event message was not an object".to_string(),
        )
    })?;
    if map.len() != 1 {
        return Err(ProviderError::Malformed(
            "Bedrock ConverseStream event message must have exactly one event key".to_string(),
        ));
    }
    let Some((name, payload)) = map.iter().next() else {
        return Err(ProviderError::Malformed(
            "Bedrock ConverseStream event message was empty".to_string(),
        ));
    };
    if !payload.is_object() {
        return Err(ProviderError::Malformed(format!(
            "Bedrock ConverseStream event `{name}` payload was not an object"
        )));
    }

    Ok(ConverseStreamEvent {
        kind: event_kind(name),
        name: name.clone(),
        payload: payload.clone(),
        raw: value,
    })
}

fn event_kind(name: &str) -> EventKind {
    match name {
        "messageStart" => EventKind::MessageStart,
        "contentBlockStart" => EventKind::ContentBlockStart,
        "contentBlockDelta" => EventKind::ContentBlockDelta,
        "contentBlockStop" => EventKind::ContentBlockStop,
        "messageStop" => EventKind::MessageStop,
        "metadata" => EventKind::Metadata,
        "internalServerException"
        | "modelStreamErrorException"
        | "serviceUnavailableException"
        | "throttlingException"
        | "validationException" => EventKind::Error,
        other if other.ends_with("Exception") => EventKind::Error,
        _ => EventKind::Unknown,
    }
}

fn content_block_index(payload: &Value, event: &str) -> Result<u64, ProviderError> {
    payload
        .get("contentBlockIndex")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            ProviderError::Malformed(format!("Bedrock {event} was missing contentBlockIndex"))
        })
}

fn tool_use_from_start(start: &Value) -> Result<Option<ToolUseBlock>, ProviderError> {
    let Some(tool_use) = start.get("toolUse") else {
        return Ok(None);
    };
    let tool_use_id = required_non_empty_string(
        tool_use,
        "toolUseId",
        "contentBlockStart.start.toolUse.toolUseId",
    )?;
    let name = required_non_empty_string(tool_use, "name", "contentBlockStart.start.toolUse.name")?;
    let input = tool_use.get("input").cloned().unwrap_or_else(|| json!({}));

    Ok(Some(ToolUseBlock {
        tool_use_id,
        name,
        input,
    }))
}

fn required_non_empty_string(
    value: &Value,
    field: &str,
    display: &str,
) -> Result<String, ProviderError> {
    let raw = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ProviderError::Malformed(format!("Bedrock {display} was missing")))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Err(ProviderError::Malformed(format!(
            "Bedrock {display} must not be empty"
        )))
    } else {
        Ok(trimmed.to_string())
    }
}

fn has_tool_use_delta(payload: &Value) -> bool {
    payload
        .get("delta")
        .and_then(|delta| delta.get("toolUse"))
        .is_some()
}

fn tool_use_delta_input(payload: &Value) -> Result<&str, ProviderError> {
    let delta = payload.get("delta").ok_or_else(|| {
        ProviderError::Malformed("Bedrock contentBlockDelta was missing delta".to_string())
    })?;
    let tool_use = delta.get("toolUse").ok_or_else(|| {
        ProviderError::Malformed(
            "Bedrock toolUse contentBlockDelta was missing delta.toolUse".to_string(),
        )
    })?;
    tool_use
        .get("input")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::Malformed(
                "Bedrock toolUse contentBlockDelta was missing string input".to_string(),
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
            "Bedrock streaming toolUse `{}` allow verdict requested redactions; fail-closed",
            block.tool_use_id
        ))),
        VerdictResult::Deny { reason, receipt_id } => Err(ProviderError::Malformed(format!(
            "Bedrock streaming toolUse `{}` denied at contentBlockStop: {} (receipt {})",
            block.tool_use_id,
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
    phase.transition(event).map_err(|error| {
        ProviderError::Malformed(format!("Bedrock ConverseStream state error: {error}"))
    })
}
