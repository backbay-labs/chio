//! Batch lift/lower support for Bedrock Runtime Converse tool blocks.
//!
//! The implementation stays offline and fixture-backed: it parses raw
//! Converse JSON envelopes, lifts `toolUse` content blocks into the shared
//! Chio fabric shape, and lowers verdicts back into Bedrock `toolResult`
//! content blocks. Transport dispatch remains outside this module.

#[path = "streaming.rs"]
pub mod streaming;

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::time::SystemTime;

use chio_core::canonical::canonical_json_bytes;
use chio_tool_call_fabric::{
    DenyReason, ProvenanceStamp, ProviderAdapter, ProviderError, ProviderId, ProviderRequest,
    ProviderResponse, ReceiptId, Redaction, ToolInvocation, ToolResult, VerdictResult,
};
use serde_json::{json, Value};

use crate::{BedrockAdapter, ToolResultBlock, ToolResultStatus, ToolUseBlock};

const TOOL_CONFIG_FIELD: &str = "toolConfig";
const TOOL_USE_FIELD: &str = "toolUse";
const TOOL_RESULT_FIELD: &str = "toolResult";
const TOOL_USE_ID_FIELD: &str = "toolUseId";
const CONTENT_FIELD: &str = "content";

impl BedrockAdapter {
    /// Lift every `toolUse` block in a non-streaming Bedrock Converse
    /// response payload.
    ///
    /// Accepted fixture forms:
    /// - a full Converse response envelope with `output.message.content`
    /// - a message object with a `content` array
    /// - an array of content blocks
    /// - a single `{"toolUse": ...}` content block
    ///
    /// If `toolConfig` is present, any lifted tool name must be declared in
    /// that config. This keeps fixture-backed tests honest without requiring
    /// a network call or AWS SDK client construction.
    pub fn lift_batch(&self, raw: ProviderRequest) -> Result<Vec<ToolInvocation>, ProviderError> {
        let payload = parse_json_payload(raw)?;
        let declared_tools = declared_tool_names(&payload)?;
        let blocks = content_blocks(&payload);

        let mut invocations = Vec::new();
        for block in blocks {
            if let Some(tool_use) = tool_use_from_block(&block)? {
                if !declared_tools.is_empty() && !declared_tools.contains(&tool_use.name) {
                    return Err(ProviderError::Malformed(format!(
                        "bedrock toolUse `{}` was not declared in toolConfig",
                        tool_use.name
                    )));
                }
                invocations.push(self.invocation_from_tool_use(tool_use)?);
            }
        }

        if invocations.is_empty() {
            return Err(ProviderError::Malformed(
                "bedrock Converse payload did not contain toolUse content blocks".to_string(),
            ));
        }

        Ok(invocations)
    }

    /// Lower one kernel verdict and tool output into a Bedrock `toolResult`
    /// content block.
    ///
    /// `result` is canonical JSON tool output bytes on the allow path. The
    /// value is wrapped as Bedrock JSON content unless it already looks like
    /// Bedrock content. The deny path ignores tool output and emits a
    /// structured Chio denial payload with `status: "error"`.
    pub fn lower_tool_result(
        &self,
        tool_use_id: &str,
        verdict: VerdictResult,
        result: ToolResult,
    ) -> Result<ProviderResponse, ProviderError> {
        let tool_use_id = non_empty_str(tool_use_id, TOOL_USE_ID_FIELD)?;
        let block = match verdict {
            VerdictResult::Allow { redactions, .. } => {
                let content = bedrock_content_from_tool_result(result, &redactions)?;
                ToolResultBlock {
                    tool_use_id: tool_use_id.to_string(),
                    content,
                    status: ToolResultStatus::Success,
                }
            }
            VerdictResult::Deny { reason, receipt_id } => ToolResultBlock {
                tool_use_id: tool_use_id.to_string(),
                content: deny_content(&reason, &receipt_id)?,
                status: ToolResultStatus::Error,
            },
        };

        provider_response_from_tool_result(block)
    }

    fn lift_one(&self, raw: ProviderRequest) -> Result<ToolInvocation, ProviderError> {
        let mut invocations = self.lift_batch(raw)?;
        if invocations.len() != 1 {
            return Err(ProviderError::Malformed(format!(
                "ProviderAdapter::lift expected exactly one bedrock toolUse block, found {}",
                invocations.len()
            )));
        }

        invocations.pop().ok_or_else(|| {
            ProviderError::Malformed(
                "ProviderAdapter::lift lost the extracted bedrock toolUse block".to_string(),
            )
        })
    }

    fn lower_with_tool_use_id(
        &self,
        verdict: VerdictResult,
        result: ToolResult,
    ) -> Result<ProviderResponse, ProviderError> {
        let payload: Value = serde_json::from_slice(&result.0).map_err(|error| {
            ProviderError::BadToolArgs(format!(
                "bedrock ToolResult payload was not valid JSON: {error}"
            ))
        })?;
        let tool_use_id = payload
            .get(TOOL_USE_ID_FIELD)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProviderError::Malformed(
                    "bedrock ProviderAdapter::lower requires ToolResult JSON with toolUseId"
                        .to_string(),
                )
            })?
            .to_string();
        let content = payload
            .get(CONTENT_FIELD)
            .cloned()
            .unwrap_or_else(|| strip_tool_use_id(payload));

        self.lower_tool_result(
            &tool_use_id,
            verdict,
            ToolResult(json_bytes(&content, "bedrock ToolResult content")?),
        )
    }

    fn invocation_from_tool_use(
        &self,
        tool_use: ToolUseBlock,
    ) -> Result<ToolInvocation, ProviderError> {
        let arguments = canonical_json_bytes(&tool_use.input).map_err(|error| {
            ProviderError::BadToolArgs(format!(
                "bedrock toolUse `{}` input failed canonical JSON encoding: {error}",
                tool_use.tool_use_id
            ))
        })?;

        Ok(ToolInvocation {
            provider: ProviderId::Bedrock,
            tool_name: tool_use.name,
            arguments,
            provenance: ProvenanceStamp {
                provider: ProviderId::Bedrock,
                request_id: tool_use.tool_use_id,
                api_version: self.api_version().to_string(),
                principal: self.config().principal(),
                received_at: SystemTime::now(),
            },
        })
    }
}

impl ProviderAdapter for BedrockAdapter {
    fn provider(&self) -> ProviderId {
        BedrockAdapter::provider(self)
    }

    fn api_version(&self) -> &str {
        BedrockAdapter::api_version(self)
    }

    fn lift<'life0, 'async_trait>(
        &'life0 self,
        raw: ProviderRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ToolInvocation, ProviderError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.lift_one(raw) })
    }

    fn lower<'life0, 'async_trait>(
        &'life0 self,
        verdict: VerdictResult,
        result: ToolResult,
    ) -> Pin<Box<dyn Future<Output = Result<ProviderResponse, ProviderError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.lower_with_tool_use_id(verdict, result) })
    }
}

fn parse_json_payload(raw: ProviderRequest) -> Result<Value, ProviderError> {
    let value: Value = serde_json::from_slice(&raw.0).map_err(|error| {
        ProviderError::Malformed(format!("bedrock Converse payload was not JSON: {error}"))
    })?;
    unwrap_envelope(value)
}

fn unwrap_envelope(value: Value) -> Result<Value, ProviderError> {
    for field in ["body", "response", "payload"] {
        if let Some(nested) = value.get(field) {
            return match nested {
                Value::Object(_) | Value::Array(_) => Ok(nested.clone()),
                Value::String(body) => serde_json::from_str(body).map_err(|error| {
                    ProviderError::Malformed(format!(
                        "bedrock Converse envelope field `{field}` was not JSON: {error}"
                    ))
                }),
                _ => Err(ProviderError::Malformed(format!(
                    "bedrock Converse envelope field `{field}` was not an object, array, or string body"
                ))),
            };
        }
    }
    Ok(value)
}

fn declared_tool_names(payload: &Value) -> Result<BTreeSet<String>, ProviderError> {
    let mut names = BTreeSet::new();
    if let Some(tool_config) = payload.get(TOOL_CONFIG_FIELD) {
        parse_tool_config(tool_config, &mut names)?;
    }
    Ok(names)
}

fn parse_tool_config(value: &Value, names: &mut BTreeSet<String>) -> Result<(), ProviderError> {
    let tools = value
        .get("tools")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ProviderError::Malformed("bedrock toolConfig.tools must be an array".to_string())
        })?;

    for tool in tools {
        let spec = tool.get("toolSpec").unwrap_or(tool);
        let name = spec.get("name").and_then(Value::as_str).ok_or_else(|| {
            ProviderError::Malformed("bedrock toolConfig tool is missing name".to_string())
        })?;
        let name = non_empty_str(name, "toolConfig.tools[].name")?;
        if spec.get("inputSchema").is_none() {
            return Err(ProviderError::Malformed(format!(
                "bedrock toolConfig tool `{name}` is missing inputSchema"
            )));
        }
        names.insert(name.to_string());
    }

    Ok(())
}

fn content_blocks(value: &Value) -> Vec<Value> {
    match value {
        Value::Array(values) => values.clone(),
        Value::Object(map) if map.contains_key(TOOL_USE_FIELD) => vec![value.clone()],
        Value::Object(map) if map.contains_key(TOOL_RESULT_FIELD) => vec![value.clone()],
        Value::Object(map) => {
            if let Some(content) = map.get(CONTENT_FIELD).and_then(Value::as_array) {
                return content.clone();
            }
            if let Some(content) = map
                .get("output")
                .and_then(|output| output.get("message"))
                .and_then(|message| message.get(CONTENT_FIELD))
                .and_then(Value::as_array)
            {
                return content.clone();
            }
            if let Some(content) = map
                .get("message")
                .and_then(|message| message.get(CONTENT_FIELD))
                .and_then(Value::as_array)
            {
                return content.clone();
            }
            Vec::new()
        }
        _ => Vec::new(),
    }
}

fn tool_use_from_block(block: &Value) -> Result<Option<ToolUseBlock>, ProviderError> {
    let Some(value) = block.get(TOOL_USE_FIELD).or_else(|| {
        if block.get(TOOL_USE_ID_FIELD).is_some() && block.get("name").is_some() {
            Some(block)
        } else {
            None
        }
    }) else {
        return Ok(None);
    };

    let tool_use: ToolUseBlock = serde_json::from_value(value.clone()).map_err(|error| {
        ProviderError::Malformed(format!("bedrock toolUse block was malformed: {error}"))
    })?;

    validate_tool_use(tool_use).map(Some)
}

fn validate_tool_use(tool_use: ToolUseBlock) -> Result<ToolUseBlock, ProviderError> {
    non_empty_str(&tool_use.tool_use_id, TOOL_USE_ID_FIELD)?;
    non_empty_str(&tool_use.name, "toolUse.name")?;
    if !tool_use.input.is_object() {
        return Err(ProviderError::BadToolArgs(format!(
            "bedrock toolUse `{}` input must be a JSON object",
            tool_use.tool_use_id
        )));
    }
    Ok(tool_use)
}

fn bedrock_content_from_tool_result(
    result: ToolResult,
    redactions: &[Redaction],
) -> Result<Value, ProviderError> {
    let value: Value = serde_json::from_slice(&result.0).map_err(|error| {
        ProviderError::BadToolArgs(format!("bedrock tool result was not valid JSON: {error}"))
    })?;
    let value = apply_redactions(value, redactions, "Bedrock toolResult content")?;

    if looks_like_bedrock_content(&value) {
        Ok(value)
    } else {
        Ok(json!([{ "json": value }]))
    }
}

fn apply_redactions(
    mut value: Value,
    redactions: &[Redaction],
    context: &str,
) -> Result<Value, ProviderError> {
    for redaction in redactions {
        apply_redaction(&mut value, redaction, context)?;
    }
    Ok(value)
}

fn apply_redaction(
    value: &mut Value,
    redaction: &Redaction,
    context: &str,
) -> Result<(), ProviderError> {
    if redaction.path.is_empty() {
        *value = Value::String(redaction.replacement.clone());
        return Ok(());
    }
    if !redaction.path.starts_with('/') {
        return Err(ProviderError::Malformed(format!(
            "{context} allow verdict requested redaction path `{}`; only JSON Pointer paths are supported",
            redaction.path
        )));
    }
    let target = value.pointer_mut(&redaction.path).ok_or_else(|| {
        ProviderError::Malformed(format!(
            "{context} allow verdict requested redaction path `{}` that did not resolve",
            redaction.path
        ))
    })?;
    *target = Value::String(redaction.replacement.clone());
    Ok(())
}

fn looks_like_bedrock_content(value: &Value) -> bool {
    value.as_array().is_some_and(|items| {
        items.iter().all(|item| {
            item.as_object().is_some_and(|map| {
                map.contains_key("json")
                    || map.contains_key("text")
                    || map.contains_key("image")
                    || map.contains_key("document")
            })
        })
    })
}

fn deny_content(reason: &DenyReason, receipt_id: &ReceiptId) -> Result<Value, ProviderError> {
    let reason = serde_json::to_value(reason).map_err(|error| {
        ProviderError::Malformed(format!("bedrock deny reason was not serializable: {error}"))
    })?;
    Ok(json!([
        {
            "json": {
                "chio": {
                    "verdict": "deny",
                    "receiptId": receipt_id.0,
                    "reason": reason
                }
            }
        }
    ]))
}

fn provider_response_from_tool_result(
    block: ToolResultBlock,
) -> Result<ProviderResponse, ProviderError> {
    let value = json!({ TOOL_RESULT_FIELD: block });
    Ok(ProviderResponse(json_bytes(
        &value,
        "bedrock toolResult content block",
    )?))
}

fn strip_tool_use_id(mut value: Value) -> Value {
    if let Value::Object(ref mut map) = value {
        map.remove(TOOL_USE_ID_FIELD);
    }
    value
}

fn non_empty_str<'a>(value: &'a str, field: &str) -> Result<&'a str, ProviderError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(ProviderError::Malformed(format!(
            "bedrock {field} must not be empty"
        )))
    } else {
        Ok(trimmed)
    }
}

fn json_bytes(value: &Value, context: &str) -> Result<Vec<u8>, ProviderError> {
    serde_json::to_vec(value).map_err(|error| {
        ProviderError::Malformed(format!("failed to serialize {context}: {error}"))
    })
}
