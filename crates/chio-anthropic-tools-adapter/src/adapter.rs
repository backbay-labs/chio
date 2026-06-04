//! ProviderAdapter implementation for Anthropic Messages batch payloads.
//!
//! This module lifts non-streaming `messages.create` `tool_use` content
//! blocks into Chio's shared [`chio_tool_call_fabric::ToolInvocation`] shape
//! and lowers kernel verdicts back into Anthropic `tool_result` blocks for
//! the next user message.

#[path = "streaming.rs"]
pub mod streaming;

use std::future::Future;
use std::pin::Pin;
use std::time::SystemTime;

use chio_core::canonical::canonical_json_bytes;
use chio_manifest::ServerTool;
use chio_tool_call_fabric::{
    DenyReason, Principal, ProvenanceStamp, ProviderAdapter, ProviderError, ProviderId,
    ProviderRequest, ProviderResponse, Redaction, ToolInvocation, ToolResult, VerdictResult,
};
use serde_json::{json, Value};

use crate::{AnthropicAdapter, ToolResultBlock, ToolUseBlock};

impl AnthropicAdapter {
    /// Lift every Anthropic `tool_use` content block in a non-streaming
    /// `messages.create` response payload.
    ///
    /// Accepted payload forms:
    /// - a plain Anthropic Message object with a `content` array
    /// - an envelope with `body`, `response`, `payload`, or `message`
    /// - a single `tool_use` content block
    pub fn lift_batch(&self, raw: ProviderRequest) -> Result<Vec<ToolInvocation>, ProviderError> {
        let blocks = tool_use_blocks(raw)?;
        if blocks.is_empty() {
            return Err(ProviderError::Malformed(
                "messages.create payload did not contain Anthropic tool_use content blocks"
                    .to_string(),
            ));
        }

        let invocations = blocks
            .iter()
            .map(|block| self.invocation_from_tool_use(block))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(invocations)
    }

    fn lift_one(&self, raw: ProviderRequest) -> Result<ToolInvocation, ProviderError> {
        let blocks = tool_use_blocks(raw)?;
        if blocks.len() != 1 {
            return Err(ProviderError::Malformed(format!(
                "ProviderAdapter::lift expected exactly one Anthropic tool_use block, found {}",
                blocks.len()
            )));
        }

        let block = blocks.into_iter().next().ok_or_else(|| {
            ProviderError::Malformed(
                "ProviderAdapter::lift lost the extracted Anthropic tool_use block".to_string(),
            )
        })?;
        let invocation = self.invocation_from_tool_use(&block)?;
        Ok(invocation)
    }

    fn invocation_from_tool_use(
        &self,
        block: &ToolUseBlock,
    ) -> Result<ToolInvocation, ProviderError> {
        validate_tool_use_block(block)?;
        ensure_server_tool_feature(&block.name)?;
        self.server_tool_gate().ensure_tool_allowed(&block.name)?;
        let arguments = canonical_json_bytes(&block.input).map_err(|error| {
            ProviderError::BadToolArgs(format!(
                "Anthropic tool_use input failed canonical JSON encoding: {error}"
            ))
        })?;

        Ok(ToolInvocation {
            provider: ProviderId::Anthropic,
            tool_name: block.name.clone(),
            arguments,
            provenance: ProvenanceStamp {
                provider: ProviderId::Anthropic,
                request_id: block.id.clone(),
                api_version: self.config().api_version.clone(),
                principal: Principal::AnthropicWorkspace {
                    workspace_id: self.config().workspace_id.clone(),
                },
                received_at: SystemTime::now(),
            },
        })
    }

    /// Lower a kernel verdict and canonical tool result into an Anthropic
    /// `tool_result` content block.
    pub fn lower_tool_result_block(
        &self,
        tool_use_id: &str,
        verdict: VerdictResult,
        result: ToolResult,
    ) -> Result<ToolResultBlock, ProviderError> {
        let tool_use_id = non_empty_str(tool_use_id, "tool_use_id")?;
        match verdict {
            VerdictResult::Allow { redactions, .. } => {
                let content = parse_tool_result_content(result)?;
                lower_allow_tool_result(tool_use_id, content, &redactions)
            }
            VerdictResult::Deny { reason, .. } => Ok(lower_deny_tool_result(tool_use_id, &reason)),
        }
    }

    fn lower_pending_tool_result(
        &self,
        pending: PendingToolResult,
        verdict: VerdictResult,
    ) -> Result<ToolResultBlock, ProviderError> {
        let tool_use_id = non_empty_str(&pending.tool_use_id, "tool_use_id")?;
        match verdict {
            VerdictResult::Allow { redactions, .. } => {
                let content = pending.content.ok_or_else(|| {
                    ProviderError::Malformed(
                        "Anthropic ProviderAdapter::lower allow path requires ToolResult content"
                            .to_string(),
                    )
                })?;
                lower_allow_tool_result(tool_use_id, content, &redactions)
            }
            VerdictResult::Deny { reason, .. } => Ok(lower_deny_tool_result(tool_use_id, &reason)),
        }
    }
}

impl ProviderAdapter for AnthropicAdapter {
    fn provider(&self) -> ProviderId {
        ProviderId::Anthropic
    }

    fn api_version(&self) -> &str {
        self.api_version()
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
        Box::pin(async move {
            let pending = parse_tool_result_envelope(result)?;
            let block = self.lower_pending_tool_result(pending, verdict)?;
            serde_json::to_vec(&block)
                .map(ProviderResponse)
                .map_err(|error| {
                    ProviderError::Malformed(format!(
                        "Anthropic tool_result block failed JSON encoding: {error}"
                    ))
                })
        })
    }
}

fn tool_use_blocks(raw: ProviderRequest) -> Result<Vec<ToolUseBlock>, ProviderError> {
    let value: Value = serde_json::from_slice(&raw.0).map_err(|error| {
        ProviderError::Malformed(format!("messages.create payload was not JSON: {error}"))
    })?;
    let body = message_body(value)?;
    extract_tool_use_blocks(&body)
}

fn message_body(value: Value) -> Result<Value, ProviderError> {
    for field in ["body", "response", "payload", "message"] {
        if let Some(nested) = value.get(field) {
            return nested_message_body(nested).ok_or_else(|| {
                ProviderError::Malformed(format!(
                    "messages.create envelope field `{field}` was not a JSON object or string body"
                ))
            });
        }
    }

    Ok(value)
}

fn nested_message_body(value: &Value) -> Option<Value> {
    match value {
        Value::Object(_) => Some(value.clone()),
        Value::String(body) => serde_json::from_str(body).ok(),
        _ => None,
    }
}

fn extract_tool_use_blocks(body: &Value) -> Result<Vec<ToolUseBlock>, ProviderError> {
    if is_tool_use_block(body) {
        return parse_tool_use_block(body).map(|block| vec![block]);
    }

    let content = body.get("content").ok_or_else(|| {
        ProviderError::Malformed(
            "messages.create payload did not contain an Anthropic content array".to_string(),
        )
    })?;
    let content = content.as_array().ok_or_else(|| {
        ProviderError::Malformed("Anthropic message `content` field was not an array".to_string())
    })?;

    content
        .iter()
        .filter(|block| is_tool_use_block(block))
        .map(parse_tool_use_block)
        .collect()
}

fn is_tool_use_block(value: &Value) -> bool {
    value
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|block_type| block_type == "tool_use")
}

fn parse_tool_use_block(value: &Value) -> Result<ToolUseBlock, ProviderError> {
    serde_json::from_value(value.clone()).map_err(|error| {
        ProviderError::Malformed(format!("Anthropic tool_use block was malformed: {error}"))
    })
}

fn validate_tool_use_block(block: &ToolUseBlock) -> Result<(), ProviderError> {
    if block.block_type != "tool_use" {
        return Err(ProviderError::Malformed(format!(
            "Anthropic content block type `{}` was not tool_use",
            block.block_type
        )));
    }
    validate_provider_identifier(&block.id, "tool_use id")?;
    validate_provider_identifier(&block.name, "tool_use name")?;
    if !block.input.is_object() {
        return Err(ProviderError::BadToolArgs(format!(
            "Anthropic tool_use `{}` input was not a JSON object",
            block.id
        )));
    }
    Ok(())
}

fn validate_provider_identifier(value: &str, field: &str) -> Result<(), ProviderError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ProviderError::Malformed(format!(
            "Anthropic {field} was empty"
        )));
    }
    if trimmed != value {
        return Err(ProviderError::Malformed(format!(
            "Anthropic {field} must not contain surrounding whitespace"
        )));
    }
    Ok(())
}

fn ensure_server_tool_feature(name: &str) -> Result<(), ProviderError> {
    if ServerTool::from_anthropic_wire_name(name).is_some() && !cfg!(feature = "computer-use") {
        return Err(ProviderError::Malformed(format!(
            "Anthropic server tool `{name}` requires the `computer-use` cargo feature"
        )));
    }
    Ok(())
}

struct PendingToolResult {
    tool_use_id: String,
    content: Option<Value>,
}

fn parse_tool_result_envelope(result: ToolResult) -> Result<PendingToolResult, ProviderError> {
    let value: Value = serde_json::from_slice(&result.0).map_err(|error| {
        ProviderError::Malformed(format!("tool result was not JSON bytes: {error}"))
    })?;
    let object = value.as_object().ok_or_else(|| {
        ProviderError::Malformed(
            "Anthropic ProviderAdapter::lower requires ToolResult JSON with tool_use_id"
                .to_string(),
        )
    })?;
    let tool_use_id = object
        .get("tool_use_id")
        .or_else(|| object.get("toolUseId"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::Malformed(
                "Anthropic ProviderAdapter::lower requires ToolResult JSON with tool_use_id"
                    .to_string(),
            )
        })?;
    let tool_use_id = non_empty_str(tool_use_id, "tool_use_id")?.to_string();
    let content = object.get("content").cloned();

    Ok(PendingToolResult {
        tool_use_id,
        content,
    })
}

fn parse_tool_result_content(result: ToolResult) -> Result<Value, ProviderError> {
    serde_json::from_slice(&result.0).map_err(|error| {
        ProviderError::Malformed(format!("tool result was not JSON bytes: {error}"))
    })
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

fn non_empty_str<'a>(value: &'a str, field: &str) -> Result<&'a str, ProviderError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(ProviderError::Malformed(format!(
            "Anthropic {field} must not be empty"
        )))
    } else if trimmed != value {
        Err(ProviderError::Malformed(format!(
            "Anthropic {field} must not contain surrounding whitespace"
        )))
    } else {
        Ok(value)
    }
}

fn lower_allow_tool_result(
    tool_use_id: &str,
    content: Value,
    redactions: &[Redaction],
) -> Result<ToolResultBlock, ProviderError> {
    let content = apply_redactions(content, redactions, "Anthropic tool_result")?;
    Ok(ToolResultBlock::allow(tool_use_id, content))
}

fn lower_deny_tool_result(tool_use_id: &str, reason: &DenyReason) -> ToolResultBlock {
    ToolResultBlock::deny(tool_use_id, deny_content(reason))
}

fn deny_content(reason: &DenyReason) -> Value {
    let text = match reason {
        DenyReason::PolicyDeny { rule_id } => format!("policy_deny: {rule_id}"),
        DenyReason::GuardDeny { guard_id, detail } => {
            format!("guard_deny: {guard_id}: {detail}")
        }
        DenyReason::CapabilityExpired => "capability_expired".to_string(),
        DenyReason::PrincipalUnknown => "principal_unknown".to_string(),
        DenyReason::BudgetExceeded => "budget_exceeded".to_string(),
    };
    json!([{ "type": "text", "text": text }])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use chio_tool_call_fabric::{ReceiptId, Redaction};
    use serde_json::json;

    use super::*;
    use crate::transport::MockTransport;
    use crate::AnthropicAdapterConfig;

    fn adapter() -> AnthropicAdapter {
        let config = AnthropicAdapterConfig::new(
            "anthropic-1",
            "Anthropic Messages",
            "0.1.0",
            "deadbeef",
            "wks_chio_demo",
        );
        AnthropicAdapter::new(config, Arc::new(MockTransport::new()))
    }

    #[test]
    fn lower_pending_tool_result_applies_allow_redactions() {
        let adapter = adapter();
        let pending = PendingToolResult {
            tool_use_id: "toolu_weather_1".to_string(),
            content: Some(json!([{ "type": "text", "text": "secret" }])),
        };
        let verdict = VerdictResult::Allow {
            redactions: vec![Redaction {
                path: "/0/text".to_string(),
                replacement: "[redacted]".to_string(),
            }],
            receipt_id: ReceiptId("rcpt_allow_redacted".to_string()),
        };

        let block = adapter.lower_pending_tool_result(pending, verdict).unwrap();

        assert_eq!(block.tool_use_id, "toolu_weather_1");
        assert!(!block.is_error);
        assert_eq!(block.content[0]["text"], "[redacted]");
    }

    #[test]
    fn lower_pending_tool_result_requires_content_on_allow() {
        let adapter = adapter();
        let pending = PendingToolResult {
            tool_use_id: "toolu_weather_1".to_string(),
            content: None,
        };
        let verdict = VerdictResult::Allow {
            redactions: vec![],
            receipt_id: ReceiptId("rcpt_allow_missing_content".to_string()),
        };

        let error = adapter
            .lower_pending_tool_result(pending, verdict)
            .expect_err("allow lowering without content must fail closed");

        assert!(error
            .to_string()
            .contains("allow path requires ToolResult content"));
    }

    #[test]
    fn lift_rejects_tool_use_name_with_surrounding_whitespace() {
        let adapter = adapter();
        let raw = ProviderRequest(
            serde_json::to_vec(&json!({
                "content": [{
                    "type": "tool_use",
                    "id": "toolu_server_tool",
                    "name": " bash_20241022 ",
                    "input": {}
                }]
            }))
            .unwrap(),
        );

        let error = adapter
            .lift_batch(raw)
            .expect_err("whitespace-padded tool name must fail closed");

        assert!(error
            .to_string()
            .contains("tool_use name must not contain surrounding whitespace"));
    }
}
