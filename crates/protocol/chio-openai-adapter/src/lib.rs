//! # chio-openai
//!
//! Adapter that intercepts OpenAI-style tool_use / function-calling requests
//! and routes them through the Chio kernel for capability validation and
//! receipt signing.
//!
//! Supports both:
//! - **Chat Completions API** format (function_call / tool_calls)
//! - **Responses API** format (tool invocations)
//!
//! Every function call produces a signed receipt. Guards fail closed by default.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use chio_core::capability::{
    governance::{GovernedApprovalToken, GovernedTransactionIntent, ThresholdApprovalProposal},
    scope::ModelMetadata,
    token::CapabilityToken,
};
use chio_core::receipt::body::ChioReceipt;
use chio_core::session::OperationTerminalState;
use chio_cross_protocol::discovery::{DiscoveryProtocol, TargetProtocolRegistry};
use chio_cross_protocol::routing::{plan_authoritative_route, route_selection_metadata};
use chio_kernel::{
    dpop, ChioKernel, SignedExecutionNonce, ToolCallOutput, ToolCallRequest, ToolCallResponse,
    Verdict as KernelVerdict,
};
use chio_manifest::{ToolDefinition, ToolManifest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[cfg(feature = "provider-adapter")]
pub mod adapter;

#[cfg(feature = "provider-adapter")]
pub use adapter::{
    OpenAiAdapter, OpenAiAdapterConfig as OpenAiProviderAdapterConfig, OPENAI_RESPONSES_API_VERSION,
};

#[cfg(feature = "provider-adapter")]
pub mod streaming;

#[cfg(feature = "provider-adapter")]
pub mod transport;

#[cfg(feature = "provider-adapter")]
pub use transport::{
    ChatCompletionsOutcome, OpenAiTransport, OPENAI_API_BASE_URL, OPENAI_API_KEY_ENV,
    OPENAI_CHAT_COMPLETIONS_PATH, OPENAI_RESPONSES_PATH,
};

/// Errors produced by the OpenAI adapter.
#[derive(Debug, thiserror::Error)]
pub enum OpenAiAdapterError {
    /// A tool/function was not found.
    #[error("function not found: {0}")]
    FunctionNotFound(String),

    /// The request was malformed.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// The kernel denied the request.
    #[error("kernel error: {0}")]
    Kernel(String),

    /// Manifest error.
    #[error("manifest error: {0}")]
    Manifest(#[from] chio_manifest::ManifestError),
}

/// An OpenAI function definition (for Chat Completions tools parameter).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiFunctionDef {
    /// Function name.
    pub name: String,
    /// Function description.
    pub description: String,
    /// JSON Schema for parameters.
    pub parameters: Value,
}

/// An OpenAI tool definition (wraps a function def).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiToolDef {
    /// Always "function".
    #[serde(rename = "type")]
    pub tool_type: String,
    /// The function definition.
    pub function: OpenAiFunctionDef,
}

/// An OpenAI tool call from a Chat Completions response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiToolCall {
    /// The tool call ID.
    pub id: String,
    /// Always "function".
    #[serde(rename = "type")]
    pub call_type: String,
    /// The function call details.
    pub function: OpenAiFunctionCall,
}

/// An OpenAI function call (name + arguments).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiFunctionCall {
    /// Function name.
    pub name: String,
    /// JSON-encoded arguments.
    pub arguments: String,
}

/// Result of executing a tool call through the adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallResult {
    /// The tool call ID (matches the request).
    pub tool_call_id: String,
    /// The function name.
    pub name: String,
    /// The result content.
    pub content: String,
    /// Whether the call was denied by the kernel.
    pub denied: bool,
    /// Whether this result is a nonce preflight instead of executed tool output.
    #[serde(default)]
    pub preflight: bool,
    /// Signed nonce to present on the retry path when `preflight` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_nonce: Option<SignedExecutionNonce>,
    /// Receipt reference (if generated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_ref: Option<String>,
    /// Signed receipt returned by the kernel (if generated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ChioReceipt>,
}

/// A Responses API function call output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsesApiOutput {
    /// Always "function_call_output".
    #[serde(rename = "type")]
    pub output_type: String,
    /// The call ID.
    pub call_id: String,
    /// The output content.
    pub output: String,
}

/// Configuration for the OpenAI adapter.
#[derive(Debug, Clone)]
pub struct OpenAiAdapterConfig {
    /// Server ID for manifest generation.
    pub server_id: String,
    /// Server name.
    pub server_name: String,
    /// Server version.
    pub server_version: String,
    /// Public key.
    pub public_key: String,
}

/// Execution context required to route OpenAI tool calls through the kernel.
#[derive(Debug, Clone)]
pub struct OpenAiExecutionContext {
    /// Capability token authorizing the requested tools.
    pub capability: CapabilityToken,
    /// Hex-encoded public key or stable agent identifier for subject binding.
    pub agent_id: String,
    /// Optional DPoP proof bound to this invocation.
    pub dpop_proof: Option<dpop::DpopProof>,
    /// Optional execution nonces for strict kernel dispatch, keyed by OpenAI
    /// tool-call ID. Execution nonces are single-use and bound to one retry,
    /// so batch execution must not reuse one nonce across all tool calls.
    pub execution_nonces: BTreeMap<String, SignedExecutionNonce>,
    /// Optional governed transaction intent.
    pub governed_intent: Option<GovernedTransactionIntent>,
    /// Optional governed approval token.
    pub approval_token: Option<GovernedApprovalToken>,
    /// Optional threshold approval tokens.
    pub approval_tokens: Vec<GovernedApprovalToken>,
    /// Signed threshold proposal binding `approval_tokens`.
    pub threshold_approval_proposal: Option<ThresholdApprovalProposal>,
    /// Opaque authenticated extension forwarded without interpretation.
    pub supplemental_authorization:
        Option<chio_core::capability::supplemental_authorization::OpaqueSupplementalAuthorization>,
    /// Optional originating model metadata for model-constrained grants.
    pub model_metadata: Option<ModelMetadata>,
}

/// The OpenAI adapter.
///
/// Wraps Chio tool manifests and processes OpenAI-style function calls
/// through the kernel guard pipeline.
#[derive(Debug)]
pub struct ChioOpenAiAdapter {
    manifest: ToolManifest,
    /// Maps function name to (server_id, tool_name).
    function_bindings: BTreeMap<String, (String, String)>,
}

impl ChioOpenAiAdapter {
    /// Create a new adapter from Chio tool manifests.
    pub fn new(
        config: OpenAiAdapterConfig,
        manifests: Vec<ToolManifest>,
    ) -> Result<Self, OpenAiAdapterError> {
        let mut all_tools = Vec::new();
        let mut function_bindings = BTreeMap::new();

        for manifest in &manifests {
            for tool in &manifest.tools {
                let func_name = tool.name.clone();
                if function_bindings.contains_key(&func_name) {
                    continue;
                }
                function_bindings
                    .insert(func_name, (manifest.server_id.clone(), tool.name.clone()));
                all_tools.push(tool.clone());
            }
        }

        if all_tools.is_empty() {
            return Err(OpenAiAdapterError::InvalidRequest(
                "no tools to expose".to_string(),
            ));
        }

        let manifest = ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: config.server_id.clone(),
            name: config.server_name.clone(),
            description: Some("Chio tools exposed via OpenAI function calling".to_string()),
            version: config.server_version.clone(),
            tools: all_tools,
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: config.public_key.clone(),
        };

        chio_manifest::validate_manifest(&manifest)?;

        Ok(Self {
            manifest,
            function_bindings,
        })
    }

    /// Get the manifest.
    pub fn manifest(&self) -> &ToolManifest {
        &self.manifest
    }

    /// Generate OpenAI tools array for the Chat Completions API.
    pub fn openai_tools(&self) -> Vec<OpenAiToolDef> {
        self.manifest
            .tools
            .iter()
            .map(|tool| OpenAiToolDef {
                tool_type: "function".to_string(),
                function: OpenAiFunctionDef {
                    name: tool.name.clone(),
                    description: tool.description.clone(),
                    parameters: tool.input_schema.clone(),
                },
            })
            .collect()
    }

    /// Generate OpenAI tools as a JSON Value (for embedding in requests).
    pub fn openai_tools_json(&self) -> Value {
        serde_json::to_value(self.openai_tools()).unwrap_or(Value::Array(vec![]))
    }

    /// List all function names.
    pub fn function_names(&self) -> Vec<String> {
        self.manifest.tools.iter().map(|t| t.name.clone()).collect()
    }

    /// Get a tool definition by function name.
    pub fn function_def(&self, name: &str) -> Option<&ToolDefinition> {
        self.manifest.tools.iter().find(|t| t.name == name)
    }

    /// Execute an OpenAI tool call through the Chio kernel.
    ///
    /// This is the core interception point. Every function call produces
    /// a signed receipt via the kernel guard pipeline.
    pub fn execute_tool_call(
        &self,
        tool_call: &OpenAiToolCall,
        kernel: &ChioKernel,
        execution: &OpenAiExecutionContext,
    ) -> ToolCallResult {
        if execution.approval_token.is_some() && !execution.approval_tokens.is_empty() {
            return denied_tool_call_result(
                tool_call,
                "Error: singular and threshold approval tokens must not be mixed".to_string(),
            );
        }
        if execution.approval_tokens.len()
            > chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS
        {
            return denied_tool_call_result(
                tool_call,
                format!(
                    "Error: threshold approval set exceeds {} tokens",
                    chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS
                ),
            );
        }
        if execution.approval_tokens.is_empty() != execution.threshold_approval_proposal.is_none() {
            return denied_tool_call_result(
                tool_call,
                "Error: threshold approval tokens and proposal must be supplied together"
                    .to_string(),
            );
        }
        let (server_id, tool_name) = {
            let binding = self.function_bindings.get(&tool_call.function.name);
            match binding {
                Some((server_id, name)) => (server_id.clone(), name.clone()),
                None => {
                    return denied_tool_call_result(
                        tool_call,
                        format!("Error: function '{}' not found", tool_call.function.name),
                    );
                }
            }
        };

        let arguments = match serde_json::from_str::<Value>(&tool_call.function.arguments) {
            Ok(args) => args,
            Err(e) => {
                return denied_tool_call_result(
                    tool_call,
                    format!("Error: failed to parse arguments: {e}"),
                );
            }
        };

        let request = ToolCallRequest {
            request_id: format!("openai-{}", tool_call.id),
            capability: execution.capability.clone(),
            tool_name,
            server_id,
            agent_id: execution.agent_id.clone(),
            arguments,
            dpop_proof: execution.dpop_proof.clone(),
            execution_nonce: execution.execution_nonces.get(&tool_call.id).cloned(),
            governed_intent: execution.governed_intent.clone(),
            approval_token: execution.approval_token.clone(),
            approval_tokens: execution.approval_tokens.clone(),
            threshold_approval_proposal: execution.threshold_approval_proposal.clone(),
            supplemental_authorization: execution.supplemental_authorization.clone(),
            model_metadata: execution.model_metadata.clone(),
            federated_origin_kernel_id: None,
        };

        let route_plan = match plan_authoritative_route(
            &request.request_id,
            DiscoveryProtocol::OpenAi,
            DiscoveryProtocol::Native,
            execution.governed_intent.as_ref(),
            &TargetProtocolRegistry::new(DiscoveryProtocol::Native),
            &BTreeMap::new(),
        ) {
            Ok(plan) => plan,
            Err(error) => {
                return denied_tool_call_result(
                    tool_call,
                    format!("Error: failed to plan authoritative route: {error}"),
                );
            }
        };
        let route_metadata = match route_selection_metadata(&route_plan.evidence) {
            Ok(metadata) => metadata,
            Err(error) => {
                return denied_tool_call_result(
                    tool_call,
                    format!("Error: failed to serialize route selection: {error}"),
                );
            }
        };

        match kernel.evaluate_tool_call_blocking_with_metadata(&request, Some(route_metadata)) {
            Ok(response) => {
                let preflight_reason = execution_nonce_preflight_reason(&response);
                let preflight = preflight_reason.is_some();
                let execution_nonce = response.execution_nonce.as_deref().cloned();
                let denied = !matches!(response.verdict, KernelVerdict::Allow) || preflight;
                let content = preflight_reason.unwrap_or_else(|| {
                    render_response_content(&response.output, response.reason.as_deref())
                });
                let receipt_ref = Some(response.receipt.id.clone());
                ToolCallResult {
                    tool_call_id: tool_call.id.clone(),
                    name: tool_call.function.name.clone(),
                    content,
                    denied,
                    preflight,
                    execution_nonce,
                    receipt_ref,
                    receipt: Some(response.receipt),
                }
            }
            Err(error) => denied_tool_call_result(tool_call, format!("Error: {error}")),
        }
    }

    /// Execute multiple tool calls (batch processing).
    pub fn execute_tool_calls(
        &self,
        tool_calls: &[OpenAiToolCall],
        kernel: &ChioKernel,
        execution: &OpenAiExecutionContext,
    ) -> Vec<ToolCallResult> {
        if tool_calls.len() > 1
            && (execution.approval_token.is_some()
                || !execution.approval_tokens.is_empty()
                || execution.threshold_approval_proposal.is_some()
                || execution.supplemental_authorization.is_some())
        {
            return tool_calls
                .iter()
                .map(|tool_call| {
                    denied_tool_call_result(
                        tool_call,
                        "Error: request-bound authorization artifacts require a single OpenAI tool call"
                            .to_string(),
                    )
                })
                .collect();
        }
        tool_calls
            .iter()
            .map(|tc| self.execute_tool_call(tc, kernel, execution))
            .collect()
    }

    /// Convert tool call results to Chat Completions message format.
    ///
    /// Returns tool role messages suitable for the next Chat Completions request.
    pub fn results_to_messages(results: &[ToolCallResult]) -> Vec<Value> {
        results
            .iter()
            .filter(|result| !result.preflight)
            .map(|r| {
                json!({
                    "role": "tool",
                    "tool_call_id": r.tool_call_id,
                    "content": r.content,
                })
            })
            .collect()
    }

    /// Convert tool call results to Responses API format.
    pub fn results_to_responses_api(results: &[ToolCallResult]) -> Vec<ResponsesApiOutput> {
        results
            .iter()
            .filter(|result| !result.preflight)
            .map(|r| ResponsesApiOutput {
                output_type: "function_call_output".to_string(),
                call_id: r.tool_call_id.clone(),
                output: r.content.clone(),
            })
            .collect()
    }

    /// Extract tool calls from a Chat Completions response message.
    pub fn extract_tool_calls(message: &Value) -> Result<Vec<OpenAiToolCall>, OpenAiAdapterError> {
        let Some(tool_calls) = message.get("tool_calls") else {
            return Ok(Vec::new());
        };
        let calls = tool_calls.as_array().ok_or_else(|| {
            OpenAiAdapterError::InvalidRequest("tool_calls must be an array".to_string())
        })?;

        calls
            .iter()
            .enumerate()
            .map(|(index, call)| {
                let parsed =
                    serde_json::from_value::<OpenAiToolCall>(call.clone()).map_err(|e| {
                        OpenAiAdapterError::InvalidRequest(format!(
                            "tool_calls[{index}] is malformed: {e}"
                        ))
                    })?;
                validate_tool_call(parsed, &format!("tool_calls[{index}]"))
            })
            .collect()
    }

    /// Extract tool calls from a Responses API output.
    pub fn extract_responses_api_calls(
        output: &Value,
    ) -> Result<Vec<OpenAiToolCall>, OpenAiAdapterError> {
        // Responses API uses a different format with "output" array
        let Some(output_items) = output.get("output") else {
            return Ok(Vec::new());
        };
        let items = output_items.as_array().ok_or_else(|| {
            OpenAiAdapterError::InvalidRequest("output must be an array".to_string())
        })?;

        items
            .iter()
            .enumerate()
            .filter_map(|(index, item)| {
                let item_type = item.get("type").and_then(Value::as_str)?;
                if item_type == "function_call" {
                    Some((index, item))
                } else {
                    None
                }
            })
            .map(|(index, item)| {
                let context = format!("output[{index}] function_call");
                let name = required_string_field(item, "name", &context)?;
                let arguments = required_string_field(item, "arguments", &context)?;
                let call_id = required_string_field(item, "call_id", &context)?;
                validate_tool_call(
                    OpenAiToolCall {
                        id: call_id,
                        call_type: "function".to_string(),
                        function: OpenAiFunctionCall { name, arguments },
                    },
                    &context,
                )
            })
            .collect()
    }
}

fn required_string_field(
    value: &Value,
    field: &str,
    context: &str,
) -> Result<String, OpenAiAdapterError> {
    let Some(value) = value.get(field).and_then(Value::as_str) else {
        return Err(OpenAiAdapterError::InvalidRequest(format!(
            "{context} missing non-empty {field}"
        )));
    };
    if value.trim().is_empty() {
        return Err(OpenAiAdapterError::InvalidRequest(format!(
            "{context} missing non-empty {field}"
        )));
    }
    Ok(value.to_string())
}

fn validate_tool_call(
    call: OpenAiToolCall,
    context: &str,
) -> Result<OpenAiToolCall, OpenAiAdapterError> {
    if call.id.trim().is_empty() {
        return Err(OpenAiAdapterError::InvalidRequest(format!(
            "{context} missing non-empty call_id"
        )));
    }
    if call.id.trim() != call.id {
        return Err(OpenAiAdapterError::InvalidRequest(format!(
            "{context} call_id must not contain surrounding whitespace"
        )));
    }
    if call.call_type != "function" {
        return Err(OpenAiAdapterError::InvalidRequest(format!(
            "{context} has unsupported type `{}`",
            call.call_type
        )));
    }
    if call.function.name.trim().is_empty() {
        return Err(OpenAiAdapterError::InvalidRequest(format!(
            "{context} missing non-empty function.name"
        )));
    }
    if call.function.name.trim() != call.function.name {
        return Err(OpenAiAdapterError::InvalidRequest(format!(
            "{context} function.name must not contain surrounding whitespace"
        )));
    }
    if call.function.arguments.trim().is_empty() {
        return Err(OpenAiAdapterError::InvalidRequest(format!(
            "{context} missing non-empty function.arguments"
        )));
    }
    Ok(call)
}

fn denied_tool_call_result(
    tool_call: &OpenAiToolCall,
    content: impl Into<String>,
) -> ToolCallResult {
    ToolCallResult {
        tool_call_id: tool_call.id.clone(),
        name: tool_call.function.name.clone(),
        content: content.into(),
        denied: true,
        preflight: false,
        execution_nonce: None,
        receipt_ref: None,
        receipt: None,
    }
}

fn render_response_content(output: &Option<ToolCallOutput>, reason: Option<&str>) -> String {
    match output {
        Some(ToolCallOutput::Value(result)) => {
            if let Some(text) = result.as_str() {
                text.to_string()
            } else {
                serde_json::to_string(result).unwrap_or_else(|_| "{}".to_string())
            }
        }
        Some(ToolCallOutput::Stream(stream)) => {
            let chunks = stream
                .chunks
                .iter()
                .map(|chunk| chunk.data.clone())
                .collect::<Vec<_>>();
            serde_json::to_string(&chunks).unwrap_or_else(|_| "[]".to_string())
        }
        None => reason
            .map(|message| format!("Error: {message}"))
            .unwrap_or_else(|| "{}".to_string()),
    }
}

fn execution_nonce_preflight_reason(response: &ToolCallResponse) -> Option<String> {
    if !matches!(response.verdict, KernelVerdict::Allow) {
        return None;
    }
    let OperationTerminalState::Incomplete { reason } = &response.terminal_state else {
        return None;
    };
    Some(format!(
        "Error: execution nonce preflight did not execute the tool; retry through a nonce-aware path ({reason})"
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
