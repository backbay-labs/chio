//! ProviderAdapter implementation for OpenAI Responses API batch payloads.
//!
//! Compiled only with the `provider-adapter` feature. Lifts non-streaming
//! `responses.create` function-call items into the shared Chio
//! [`chio_tool_call_fabric::ToolInvocation`] shape.

use std::future::Future;
use std::pin::Pin;
use std::time::SystemTime;

use chio_core::canonical::canonical_json_bytes;
use chio_tool_call_fabric::{
    DenyReason, Principal, ProvenanceStamp, ProviderAdapter, ProviderError, ProviderId,
    ProviderRequest, ProviderResponse, Redaction, ToolInvocation, ToolResult, VerdictResult,
};
use serde_json::{json, Value};

use crate::{ChioOpenAiAdapter, OpenAiToolCall};

/// Pinned OpenAI Responses API snapshot exposed through the fabric adapter.
pub const OPENAI_RESPONSES_API_VERSION: &str = "responses.2026-04-25";

const OPENAI_ORGANIZATION_HEADER: &str = "openai-organization";
const OPENAI_ORG_ID_HEADER: &str = "openai-org-id";
const X_OPENAI_ORGANIZATION_HEADER: &str = "x-openai-organization";

/// Configuration for the provider-native OpenAI adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiAdapterConfig {
    /// OpenAI organization id captured from the `OpenAI-Organization` header.
    ///
    /// If the raw payload passed to [`OpenAiAdapter::lift_batch`] contains a
    /// header envelope, that header value wins. This field is the fail-closed
    /// fallback for transports that already stripped headers before handing
    /// the body to the adapter.
    pub org_id: String,
    /// Pinned OpenAI Responses API version.
    pub api_version: String,
}

impl OpenAiAdapterConfig {
    /// Construct a config pinned to the current OpenAI Responses API snapshot.
    pub fn new(org_id: impl Into<String>) -> Self {
        Self {
            org_id: org_id.into(),
            api_version: OPENAI_RESPONSES_API_VERSION.to_string(),
        }
    }
}

impl From<&str> for OpenAiAdapterConfig {
    fn from(org_id: &str) -> Self {
        Self::new(org_id)
    }
}

impl From<String> for OpenAiAdapterConfig {
    fn from(org_id: String) -> Self {
        Self::new(org_id)
    }
}

/// OpenAI Responses provider adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiAdapter {
    config: OpenAiAdapterConfig,
}

impl OpenAiAdapter {
    /// Build a new adapter from a config or organization id.
    pub fn new(config: impl Into<OpenAiAdapterConfig>) -> Self {
        Self {
            config: config.into(),
        }
    }

    /// Borrow the adapter configuration.
    pub fn config(&self) -> &OpenAiAdapterConfig {
        &self.config
    }

    /// Lift every function-call item in a non-streaming `responses.create`
    /// payload.
    ///
    /// Accepted payload forms:
    /// - a plain Responses API response object with an `output` array
    /// - an envelope with `headers` plus `body`, `response`, or `payload`
    /// - a single Responses API `function_call` output item
    ///
    /// The actual tool-call extraction delegates to the existing
    /// [`ChioOpenAiAdapter::extract_responses_api_calls`] helper so the
    /// legacy Responses API behavior remains the source of truth.
    pub fn lift_batch(&self, raw: ProviderRequest) -> Result<Vec<ToolInvocation>, ProviderError> {
        let parsed = parse_payload(raw)?;
        let org_id = self.org_id_for_payload(parsed.org_id_from_header.as_deref())?;
        let calls = ChioOpenAiAdapter::extract_responses_api_calls(&parsed.body)
            .map_err(|e| ProviderError::Malformed(e.to_string()))?;

        if calls.is_empty() {
            return Err(ProviderError::Malformed(
                "responses.create payload did not contain function_call output items".to_string(),
            ));
        }

        calls
            .iter()
            .map(|call| self.invocation_from_call(call, &org_id))
            .collect()
    }

    fn lift_one(&self, raw: ProviderRequest) -> Result<ToolInvocation, ProviderError> {
        let mut invocations = self.lift_batch(raw)?;
        if invocations.len() != 1 {
            return Err(ProviderError::Malformed(format!(
                "ProviderAdapter::lift expected exactly one function_call item, found {}",
                invocations.len()
            )));
        }

        invocations.pop().ok_or_else(|| {
            ProviderError::Malformed(
                "ProviderAdapter::lift lost the extracted function_call item".to_string(),
            )
        })
    }

    fn org_id_for_payload(&self, header_org_id: Option<&str>) -> Result<String, ProviderError> {
        let candidate = header_org_id.unwrap_or(&self.config.org_id).trim();
        if candidate.is_empty() {
            return Err(ProviderError::Malformed(
                "missing OpenAI organization id for provenance".to_string(),
            ));
        }
        Ok(candidate.to_string())
    }

    fn invocation_from_call(
        &self,
        call: &OpenAiToolCall,
        org_id: &str,
    ) -> Result<ToolInvocation, ProviderError> {
        let arguments: Value = serde_json::from_str(&call.function.arguments).map_err(|error| {
            ProviderError::BadToolArgs(format!(
                "function_call `{}` arguments were not valid JSON: {error}",
                call.id
            ))
        })?;
        let arguments = canonical_json_bytes(&arguments).map_err(|error| {
            ProviderError::BadToolArgs(format!(
                "function_call `{}` arguments failed canonical JSON encoding: {error}",
                call.id
            ))
        })?;

        Ok(ToolInvocation {
            provider: ProviderId::OpenAi,
            tool_name: call.function.name.clone(),
            arguments,
            provenance: ProvenanceStamp {
                provider: ProviderId::OpenAi,
                request_id: call.id.clone(),
                api_version: self.config.api_version.clone(),
                principal: Principal::OpenAiOrg {
                    org_id: org_id.to_string(),
                },
                received_at: SystemTime::now(),
            },
        })
    }
}

impl ProviderAdapter for OpenAiAdapter {
    fn provider(&self) -> ProviderId {
        ProviderId::OpenAi
    }

    fn api_version(&self) -> &str {
        &self.config.api_version
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
        Box::pin(async move { lower_tool_outputs(verdict, result) })
    }
}

struct PendingToolOutput {
    call_id: String,
    output: Option<Value>,
}

fn lower_tool_outputs(
    verdict: VerdictResult,
    result: ToolResult,
) -> Result<ProviderResponse, ProviderError> {
    let pending = parse_tool_result(result)?;
    let tool_outputs = pending
        .iter()
        .map(|entry| lower_output_entry(&verdict, entry))
        .collect::<Result<Vec<_>, _>>()?;
    let response =
        canonical_json_bytes(&json!({ "tool_outputs": tool_outputs })).map_err(|error| {
            ProviderError::Malformed(format!(
                "OpenAI tool_outputs failed canonical JSON encoding: {error}"
            ))
        })?;
    Ok(ProviderResponse(response))
}

fn parse_tool_result(result: ToolResult) -> Result<Vec<PendingToolOutput>, ProviderError> {
    let value: Value = serde_json::from_slice(&result.0).map_err(|error| {
        ProviderError::Malformed(format!("OpenAI ToolResult was not JSON: {error}"))
    })?;

    let entries = match &value {
        Value::Array(values) => values
            .iter()
            .map(parse_tool_result_entry)
            .collect::<Result<Vec<_>, _>>()?,
        Value::Object(_) => {
            if let Some(values) = tool_outputs_array(&value) {
                values
                    .iter()
                    .map(parse_tool_result_entry)
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                vec![parse_tool_result_entry(&value)?]
            }
        }
        _ => {
            return Err(ProviderError::Malformed(
                "OpenAI ToolResult must be an object, array, or tool_outputs envelope".to_string(),
            ));
        }
    };

    if entries.is_empty() {
        return Err(ProviderError::Malformed(
            "OpenAI ToolResult did not contain any tool outputs".to_string(),
        ));
    }
    if entries.len() != 1 {
        return Err(ProviderError::Malformed(format!(
            "OpenAI ToolResult lower expects exactly one tool output per verdict, found {}",
            entries.len()
        )));
    }

    Ok(entries)
}

fn tool_outputs_array(value: &Value) -> Option<&Vec<Value>> {
    value
        .get("tool_outputs")
        .or_else(|| value.get("outputs"))
        .and_then(Value::as_array)
}

fn parse_tool_result_entry(value: &Value) -> Result<PendingToolOutput, ProviderError> {
    let call_id = value
        .get("call_id")
        .or_else(|| value.get("tool_call_id"))
        .and_then(Value::as_str)
        .and_then(non_empty)
        .ok_or_else(|| {
            ProviderError::Malformed(
                "OpenAI ToolResult entry was missing non-empty call_id".to_string(),
            )
        })?;

    Ok(PendingToolOutput {
        call_id,
        output: value.get("output").cloned(),
    })
}

fn lower_output_entry(
    verdict: &VerdictResult,
    entry: &PendingToolOutput,
) -> Result<Value, ProviderError> {
    match verdict {
        VerdictResult::Allow { redactions, .. } => allow_tool_output(entry, redactions),
        VerdictResult::Deny { reason, receipt_id } => {
            deny_tool_output(entry, reason, &receipt_id.0)
        }
    }
}

fn allow_tool_output(
    entry: &PendingToolOutput,
    redactions: &[Redaction],
) -> Result<Value, ProviderError> {
    let output = entry.output.as_ref().ok_or_else(|| {
        ProviderError::Malformed(format!(
            "OpenAI ToolResult entry `{}` was missing output for allow verdict",
            entry.call_id
        ))
    })?;
    let output = apply_redactions(
        output.clone(),
        redactions,
        &format!("OpenAI ToolResult entry `{}` output", entry.call_id),
    )?;

    Ok(json!({
        "type": "function_call_output",
        "call_id": entry.call_id,
        "output": output_string(&output)?,
    }))
}

fn deny_tool_output(
    entry: &PendingToolOutput,
    reason: &DenyReason,
    receipt_id: &str,
) -> Result<Value, ProviderError> {
    let deny_payload = json!({
        "error": "chio_denied_tool_call",
        "reason": reason,
        "receipt_id": receipt_id,
        "synthetic": true,
        "verdict": "deny",
    });

    Ok(json!({
        "type": "function_call_output",
        "call_id": entry.call_id,
        "output": output_string(&deny_payload)?,
    }))
}

fn output_string(value: &Value) -> Result<String, ProviderError> {
    if let Some(text) = value.as_str() {
        return Ok(text.to_string());
    }

    let bytes = canonical_json_bytes(value).map_err(|error| {
        ProviderError::Malformed(format!(
            "OpenAI tool output failed canonical JSON encoding: {error}"
        ))
    })?;
    String::from_utf8(bytes).map_err(|error| {
        ProviderError::Malformed(format!("OpenAI tool output was not UTF-8: {error}"))
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

struct ParsedPayload {
    body: Value,
    org_id_from_header: Option<String>,
}

fn parse_payload(raw: ProviderRequest) -> Result<ParsedPayload, ProviderError> {
    let value: Value = serde_json::from_slice(&raw.0).map_err(|error| {
        ProviderError::Malformed(format!("responses.create payload was not JSON: {error}"))
    })?;
    let org_id_from_header = value.get("headers").and_then(extract_org_id_header);
    let body = response_body(value)?;
    Ok(ParsedPayload {
        body,
        org_id_from_header,
    })
}

fn response_body(value: Value) -> Result<Value, ProviderError> {
    for field in ["body", "response", "payload"] {
        if let Some(nested) = value.get(field) {
            return nested_response_body(nested).ok_or_else(|| {
                ProviderError::Malformed(format!(
                    "responses.create envelope field `{field}` was not a JSON object or string body"
                ))
            });
        }
    }

    if is_responses_output_item(&value) {
        return Ok(json!({ "output": [value] }));
    }

    Ok(value)
}

fn nested_response_body(value: &Value) -> Option<Value> {
    match value {
        Value::Object(_) => Some(value.clone()),
        Value::String(body) => serde_json::from_str(body).ok(),
        _ => None,
    }
}

fn is_responses_output_item(value: &Value) -> bool {
    value
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|item_type| item_type == "function_call")
}

fn extract_org_id_header(headers: &Value) -> Option<String> {
    let headers = headers.as_object()?;
    headers.iter().find_map(|(key, value)| {
        if is_org_header_name(key) {
            header_value(value)
        } else {
            None
        }
    })
}

fn is_org_header_name(key: &str) -> bool {
    key.eq_ignore_ascii_case(OPENAI_ORGANIZATION_HEADER)
        || key.eq_ignore_ascii_case(OPENAI_ORG_ID_HEADER)
        || key.eq_ignore_ascii_case(X_OPENAI_ORGANIZATION_HEADER)
}

fn header_value(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => non_empty(value),
        Value::Array(values) => values.iter().find_map(header_value),
        _ => None,
    }
}

fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}
