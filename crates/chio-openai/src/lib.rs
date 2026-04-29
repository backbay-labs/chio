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

use std::collections::BTreeMap;

use chio_core::capability::{
    CapabilityToken, GovernedApprovalToken, GovernedTransactionIntent, ModelMetadata,
};
use chio_core::receipt::ChioReceipt;
use chio_cross_protocol::{
    plan_authoritative_route, route_selection_metadata, DiscoveryProtocol, TargetProtocolRegistry,
};
use chio_kernel::{dpop, ChioKernel, ToolCallOutput, ToolCallRequest, Verdict as KernelVerdict};
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
    /// Optional governed transaction intent.
    pub governed_intent: Option<GovernedTransactionIntent>,
    /// Optional governed approval token.
    pub approval_token: Option<GovernedApprovalToken>,
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
        let (server_id, tool_name) = {
            let binding = self.function_bindings.get(&tool_call.function.name);
            match binding {
                Some((server_id, name)) => (server_id.clone(), name.clone()),
                None => {
                    return ToolCallResult {
                        tool_call_id: tool_call.id.clone(),
                        name: tool_call.function.name.clone(),
                        content: format!("Error: function '{}' not found", tool_call.function.name),
                        denied: true,
                        receipt_ref: None,
                        receipt: None,
                    };
                }
            }
        };

        let arguments = match serde_json::from_str::<Value>(&tool_call.function.arguments) {
            Ok(args) => args,
            Err(e) => {
                return ToolCallResult {
                    tool_call_id: tool_call.id.clone(),
                    name: tool_call.function.name.clone(),
                    content: format!("Error: failed to parse arguments: {e}"),
                    denied: true,
                    receipt_ref: None,
                    receipt: None,
                };
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
            governed_intent: execution.governed_intent.clone(),
            approval_token: execution.approval_token.clone(),
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
                return ToolCallResult {
                    tool_call_id: tool_call.id.clone(),
                    name: tool_call.function.name.clone(),
                    content: format!("Error: failed to plan authoritative route: {error}"),
                    denied: true,
                    receipt_ref: None,
                    receipt: None,
                };
            }
        };
        let route_metadata = match route_selection_metadata(&route_plan.evidence) {
            Ok(metadata) => metadata,
            Err(error) => {
                return ToolCallResult {
                    tool_call_id: tool_call.id.clone(),
                    name: tool_call.function.name.clone(),
                    content: format!("Error: failed to serialize route selection: {error}"),
                    denied: true,
                    receipt_ref: None,
                    receipt: None,
                };
            }
        };

        match kernel.evaluate_tool_call_blocking_with_metadata(&request, Some(route_metadata)) {
            Ok(response) => {
                let denied = !matches!(response.verdict, KernelVerdict::Allow);
                let content = render_response_content(&response.output, response.reason.as_deref());
                let receipt_ref = Some(response.receipt.id.clone());
                ToolCallResult {
                    tool_call_id: tool_call.id.clone(),
                    name: tool_call.function.name.clone(),
                    content,
                    denied,
                    receipt_ref,
                    receipt: Some(response.receipt),
                }
            }
            Err(error) => ToolCallResult {
                tool_call_id: tool_call.id.clone(),
                name: tool_call.function.name.clone(),
                content: format!("Error: {error}"),
                denied: true,
                receipt_ref: None,
                receipt: None,
            },
        }
    }

    /// Execute multiple tool calls (batch processing).
    pub fn execute_tool_calls(
        &self,
        tool_calls: &[OpenAiToolCall],
        kernel: &ChioKernel,
        execution: &OpenAiExecutionContext,
    ) -> Vec<ToolCallResult> {
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
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            OpenAiAdapterError::InvalidRequest(format!("{context} missing non-empty {field}"))
        })
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
    if call.function.arguments.trim().is_empty() {
        return Err(OpenAiAdapterError::InvalidRequest(format!(
            "{context} missing non-empty function.arguments"
        )));
    }
    Ok(call)
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_core::capability::{
        ChioScope, Constraint, GovernedTransactionIntent, ModelSafetyTier, MonetaryAmount,
        Operation, ToolGrant,
    };
    use chio_core::crypto::Keypair;
    use chio_kernel::{
        ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolServerConnection,
        DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
        DEFAULT_MAX_STREAM_TOTAL_BYTES,
    };

    struct MockToolServer {
        response: Value,
    }

    impl ToolServerConnection for MockToolServer {
        fn server_id(&self) -> &str {
            "test-srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["get_weather".to_string(), "search".to_string()]
        }

        fn invoke(
            &self,
            _tool_name: &str,
            _arguments: Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Value, KernelError> {
            Ok(self.response.clone())
        }
    }

    struct FailingServer;

    impl ToolServerConnection for FailingServer {
        fn server_id(&self) -> &str {
            "fail-srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["fail".to_string()]
        }

        fn invoke(
            &self,
            _tool_name: &str,
            _arguments: Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Value, KernelError> {
            Err(KernelError::ToolServerError("simulated failure".into()))
        }
    }

    fn test_manifest() -> ToolManifest {
        ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "test-srv".to_string(),
            name: "Test".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![
                ToolDefinition {
                    name: "get_weather".to_string(),
                    description: "Get the weather for a location".to_string(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "location": {"type": "string"}
                        },
                        "required": ["location"]
                    }),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: false,
                    latency_hint: None,
                },
                ToolDefinition {
                    name: "search".to_string(),
                    description: "Search the web".to_string(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"}
                        },
                        "required": ["query"]
                    }),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: false,
                    latency_hint: None,
                },
            ],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "aabbccdd".to_string(),
        }
    }

    fn test_config() -> OpenAiAdapterConfig {
        OpenAiAdapterConfig {
            server_id: "openai-test".to_string(),
            server_name: "OpenAI Test".to_string(),
            server_version: "1.0.0".to_string(),
            public_key: "aabbccdd".to_string(),
        }
    }

    fn test_server() -> MockToolServer {
        MockToolServer {
            response: json!({"temperature": 72, "conditions": "sunny"}),
        }
    }

    fn weather_tool_call() -> OpenAiToolCall {
        OpenAiToolCall {
            id: "call_abc123".to_string(),
            call_type: "function".to_string(),
            function: OpenAiFunctionCall {
                name: "get_weather".to_string(),
                arguments: r#"{"location": "San Francisco"}"#.to_string(),
            },
        }
    }

    fn test_kernel_config() -> KernelConfig {
        KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: Vec::new(),
            max_delegation_depth: 8,
            policy_hash: "test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        }
    }

    fn test_execution_context(
        kernel: &ChioKernel,
        agent_kp: &Keypair,
        server_id: &str,
        tool_name: &str,
    ) -> OpenAiExecutionContext {
        let capability = kernel
            .issue_capability(
                &agent_kp.public_key(),
                ChioScope {
                    grants: vec![ToolGrant {
                        server_id: server_id.to_string(),
                        tool_name: tool_name.to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: Vec::new(),
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: Vec::new(),
                    prompt_grants: Vec::new(),
                },
                3600,
            )
            .expect("capability should issue");
        OpenAiExecutionContext {
            capability,
            agent_id: agent_kp.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        }
    }

    // ---- Adapter creation tests ----

    #[test]
    fn adapter_creates_from_manifest() {
        let adapter = ChioOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        assert_eq!(adapter.manifest().server_id, "openai-test");
    }

    #[test]
    fn adapter_empty_manifests_errors() {
        let empty_manifest = ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "empty".to_string(),
            name: "Empty".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "aabb".to_string(),
        };
        let err = ChioOpenAiAdapter::new(test_config(), vec![empty_manifest]).unwrap_err();
        assert!(matches!(err, OpenAiAdapterError::InvalidRequest(_)));
    }

    #[test]
    fn adapter_function_names() {
        let adapter = ChioOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let names = adapter.function_names();
        assert!(names.contains(&"get_weather".to_string()));
        assert!(names.contains(&"search".to_string()));
    }

    #[test]
    fn adapter_function_def_lookup() {
        let adapter = ChioOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let def = adapter.function_def("get_weather").unwrap();
        assert_eq!(def.description, "Get the weather for a location");
    }

    #[test]
    fn adapter_unknown_function_def_returns_none() {
        let adapter = ChioOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        assert!(adapter.function_def("nonexistent").is_none());
    }

    // ---- OpenAI tools generation tests ----

    #[test]
    fn openai_tools_format() {
        let adapter = ChioOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let tools = adapter.openai_tools();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].tool_type, "function");
        assert_eq!(tools[0].function.name, "get_weather");
    }

    #[test]
    fn openai_tools_json_is_valid() {
        let adapter = ChioOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let json = adapter.openai_tools_json();
        assert!(json.is_array());
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["type"], "function");
    }

    #[test]
    fn openai_tool_has_parameters_schema() {
        let adapter = ChioOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let tools = adapter.openai_tools();
        let weather = &tools[0];
        assert!(weather.function.parameters.get("properties").is_some());
    }

    // ---- Tool call execution tests ----

    #[test]
    fn execute_tool_call_success() {
        let adapter = ChioOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let mut kernel = ChioKernel::new(test_kernel_config());
        kernel.register_tool_server(Box::new(test_server()));
        let agent_kp = Keypair::generate();
        let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "get_weather");
        let result = adapter.execute_tool_call(&weather_tool_call(), &kernel, &execution);
        assert!(!result.denied);
        assert_eq!(result.tool_call_id, "call_abc123");
        assert!(result.content.contains("72"));
        assert!(result.receipt_ref.is_some());
        assert!(result.receipt.is_some());
        let route_selection = result
            .receipt
            .as_ref()
            .and_then(|receipt| receipt.metadata.as_ref())
            .and_then(|metadata| metadata.get("route_selection"));
        assert_eq!(
            route_selection
                .and_then(|value| value.get("selectedTargetProtocol"))
                .and_then(Value::as_str),
            Some("native")
        );
        assert_eq!(
            route_selection
                .and_then(|value| value.get("decision"))
                .and_then(Value::as_str),
            Some("select")
        );
    }

    #[test]
    fn execute_tool_call_preserves_model_metadata_for_model_constrained_grant() {
        let adapter = ChioOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let mut kernel = ChioKernel::new(test_kernel_config());
        kernel.register_tool_server(Box::new(test_server()));
        let agent_kp = Keypair::generate();
        let capability = kernel
            .issue_capability(
                &agent_kp.public_key(),
                ChioScope {
                    grants: vec![ToolGrant {
                        server_id: "test-srv".to_string(),
                        tool_name: "get_weather".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![Constraint::ModelConstraint {
                            allowed_model_ids: vec!["gpt-5".to_string()],
                            min_safety_tier: Some(ModelSafetyTier::High),
                        }],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: Vec::new(),
                    prompt_grants: Vec::new(),
                },
                3600,
            )
            .expect("capability should issue");
        let execution = OpenAiExecutionContext {
            capability,
            agent_id: agent_kp.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: Some(ModelMetadata {
                model_id: "gpt-5".to_string(),
                safety_tier: Some(ModelSafetyTier::High),
                provider: Some("openai".to_string()),
                provenance_class: chio_core::capability::ProvenanceEvidenceClass::Asserted,
            }),
        };

        let result = adapter.execute_tool_call(&weather_tool_call(), &kernel, &execution);
        assert!(!result.denied);
        assert!(result.receipt.is_some());
    }

    #[test]
    fn execute_tool_call_treats_pending_approval_as_denied() {
        let adapter = ChioOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let mut kernel = ChioKernel::new(test_kernel_config());
        kernel.register_tool_server(Box::new(test_server()));
        let agent_kp = Keypair::generate();
        let capability = kernel
            .issue_capability(
                &agent_kp.public_key(),
                ChioScope {
                    grants: vec![ToolGrant {
                        server_id: "test-srv".to_string(),
                        tool_name: "get_weather".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![Constraint::RequireApprovalAbove {
                            threshold_units: 50,
                        }],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: Vec::new(),
                    prompt_grants: Vec::new(),
                },
                3600,
            )
            .expect("capability should issue");
        let execution = OpenAiExecutionContext {
            capability,
            agent_id: agent_kp.public_key().to_hex(),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-openai-approval-1".to_string(),
                server_id: "test-srv".to_string(),
                tool_name: "get_weather".to_string(),
                purpose: "require human approval".to_string(),
                max_amount: Some(MonetaryAmount {
                    units: 100,
                    currency: "USD".to_string(),
                }),
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: None,
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
        };

        let result = adapter.execute_tool_call(&weather_tool_call(), &kernel, &execution);
        assert!(result.denied);
        assert!(result.content.contains("approval"));
        assert!(result.receipt.is_some());
        assert!(result.receipt_ref.is_some());
    }

    #[test]
    fn execute_tool_call_unknown_function() {
        let adapter = ChioOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let mut kernel = ChioKernel::new(test_kernel_config());
        kernel.register_tool_server(Box::new(test_server()));
        let agent_kp = Keypair::generate();
        let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "get_weather");
        let call = OpenAiToolCall {
            id: "call_unknown".to_string(),
            call_type: "function".to_string(),
            function: OpenAiFunctionCall {
                name: "nonexistent".to_string(),
                arguments: "{}".to_string(),
            },
        };
        let result = adapter.execute_tool_call(&call, &kernel, &execution);
        assert!(result.denied);
        assert!(result.content.contains("not found"));
        assert!(result.receipt.is_none());
    }

    #[test]
    fn execute_tool_call_invalid_arguments() {
        let adapter = ChioOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let mut kernel = ChioKernel::new(test_kernel_config());
        kernel.register_tool_server(Box::new(test_server()));
        let agent_kp = Keypair::generate();
        let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "get_weather");
        let call = OpenAiToolCall {
            id: "call_bad".to_string(),
            call_type: "function".to_string(),
            function: OpenAiFunctionCall {
                name: "get_weather".to_string(),
                arguments: "not valid json".to_string(),
            },
        };
        let result = adapter.execute_tool_call(&call, &kernel, &execution);
        assert!(result.denied);
        assert!(result.content.contains("parse arguments"));
        assert!(result.receipt.is_none());
    }

    #[test]
    fn execute_tool_call_server_error() {
        let manifest = ToolManifest {
            schema: "chio.manifest.v1".to_string(),
            server_id: "fail-srv".to_string(),
            name: "Fail".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "fail".to_string(),
                description: "Fails".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "aabb".to_string(),
        };
        let adapter = ChioOpenAiAdapter::new(test_config(), vec![manifest]).unwrap();
        let mut kernel = ChioKernel::new(test_kernel_config());
        kernel.register_tool_server(Box::new(FailingServer));
        let agent_kp = Keypair::generate();
        let execution = test_execution_context(&kernel, &agent_kp, "fail-srv", "fail");
        let call = OpenAiToolCall {
            id: "call_fail".to_string(),
            call_type: "function".to_string(),
            function: OpenAiFunctionCall {
                name: "fail".to_string(),
                arguments: "{}".to_string(),
            },
        };
        let result = adapter.execute_tool_call(&call, &kernel, &execution);
        assert!(result.denied);
        assert!(result.receipt_ref.is_some());
        assert!(result.receipt.is_some());
    }

    #[test]
    fn execute_tool_call_generates_unique_receipts() {
        let adapter = ChioOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let mut kernel = ChioKernel::new(test_kernel_config());
        kernel.register_tool_server(Box::new(test_server()));
        let agent_kp = Keypair::generate();
        let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "get_weather");
        let r1 = adapter.execute_tool_call(&weather_tool_call(), &kernel, &execution);
        let r2 = adapter.execute_tool_call(&weather_tool_call(), &kernel, &execution);
        assert_ne!(r1.receipt_ref, r2.receipt_ref);
    }

    // ---- Batch execution tests ----

    #[test]
    fn execute_tool_calls_batch() {
        let adapter = ChioOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let mut kernel = ChioKernel::new(test_kernel_config());
        kernel.register_tool_server(Box::new(test_server()));
        let agent_kp = Keypair::generate();
        let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "*");
        let calls = vec![
            weather_tool_call(),
            OpenAiToolCall {
                id: "call_search".to_string(),
                call_type: "function".to_string(),
                function: OpenAiFunctionCall {
                    name: "search".to_string(),
                    arguments: r#"{"query": "test"}"#.to_string(),
                },
            },
        ];
        let results = adapter.execute_tool_calls(&calls, &kernel, &execution);
        assert_eq!(results.len(), 2);
        assert!(!results[0].denied);
        assert!(!results[1].denied);
    }

    // ---- Message conversion tests ----

    #[test]
    fn results_to_messages_format() {
        let results = vec![ToolCallResult {
            tool_call_id: "call_123".to_string(),
            name: "get_weather".to_string(),
            content: "sunny".to_string(),
            denied: false,
            receipt_ref: Some("receipt-1".to_string()),
            receipt: None,
        }];
        let messages = ChioOpenAiAdapter::results_to_messages(&results);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], "tool");
        assert_eq!(messages[0]["tool_call_id"], "call_123");
        assert_eq!(messages[0]["content"], "sunny");
    }

    #[test]
    fn results_to_messages_multiple() {
        let results = vec![
            ToolCallResult {
                tool_call_id: "c1".to_string(),
                name: "a".to_string(),
                content: "r1".to_string(),
                denied: false,
                receipt_ref: None,
                receipt: None,
            },
            ToolCallResult {
                tool_call_id: "c2".to_string(),
                name: "b".to_string(),
                content: "r2".to_string(),
                denied: false,
                receipt_ref: None,
                receipt: None,
            },
        ];
        let messages = ChioOpenAiAdapter::results_to_messages(&results);
        assert_eq!(messages.len(), 2);
    }

    // ---- Responses API conversion tests ----

    #[test]
    fn results_to_responses_api_format() {
        let results = vec![ToolCallResult {
            tool_call_id: "call_123".to_string(),
            name: "get_weather".to_string(),
            content: "sunny".to_string(),
            denied: false,
            receipt_ref: Some("receipt-1".to_string()),
            receipt: None,
        }];
        let outputs = ChioOpenAiAdapter::results_to_responses_api(&results);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].output_type, "function_call_output");
        assert_eq!(outputs[0].call_id, "call_123");
        assert_eq!(outputs[0].output, "sunny");
    }

    // ---- Extract tool calls tests ----

    #[test]
    fn extract_tool_calls_from_chat_completions() {
        let message = json!({
            "role": "assistant",
            "tool_calls": [{
                "id": "call_abc",
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "arguments": "{\"location\": \"NYC\"}"
                }
            }]
        });
        let calls = ChioOpenAiAdapter::extract_tool_calls(&message).unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "get_weather");
        assert_eq!(calls[0].id, "call_abc");
    }

    #[test]
    fn extract_tool_calls_empty_when_no_calls() {
        let message = json!({"role": "assistant", "content": "hello"});
        let calls = ChioOpenAiAdapter::extract_tool_calls(&message).unwrap();
        assert!(calls.is_empty());
    }

    #[test]
    fn extract_tool_calls_multiple() {
        let message = json!({
            "role": "assistant",
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "arguments": "{}"
                    }
                },
                {
                    "id": "call_2",
                    "type": "function",
                    "function": {
                        "name": "search",
                        "arguments": "{\"query\": \"test\"}"
                    }
                }
            ]
        });
        let calls = ChioOpenAiAdapter::extract_tool_calls(&message).unwrap();
        assert_eq!(calls.len(), 2);
    }

    // ---- Responses API extraction tests ----

    #[test]
    fn extract_responses_api_calls() {
        let output = json!({
            "output": [
                {
                    "type": "function_call",
                    "call_id": "fc_123",
                    "name": "get_weather",
                    "arguments": "{\"location\": \"LA\"}"
                }
            ]
        });
        let calls = ChioOpenAiAdapter::extract_responses_api_calls(&output).unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "get_weather");
        assert_eq!(calls[0].id, "fc_123");
    }

    #[test]
    fn extract_responses_api_filters_non_function_calls() {
        let output = json!({
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": "hello"}]
                },
                {
                    "type": "function_call",
                    "call_id": "fc_1",
                    "name": "search",
                    "arguments": "{}"
                }
            ]
        });
        let calls = ChioOpenAiAdapter::extract_responses_api_calls(&output).unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "search");
    }

    #[test]
    fn extract_responses_api_empty_output() {
        let output = json!({"output": []});
        let calls = ChioOpenAiAdapter::extract_responses_api_calls(&output).unwrap();
        assert!(calls.is_empty());
    }

    #[test]
    fn extract_responses_api_rejects_missing_call_id() {
        let output = json!({
            "output": [
                {
                    "type": "function_call",
                    "name": "search",
                    "arguments": "{}"
                }
            ]
        });

        let err = ChioOpenAiAdapter::extract_responses_api_calls(&output).unwrap_err();
        assert!(err.to_string().contains("missing non-empty call_id"));
    }

    #[test]
    fn extract_responses_api_rejects_malformed_function_call_in_mixed_output() {
        let output = json!({
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": "hello"}]
                },
                {
                    "type": "function_call",
                    "call_id": "fc_valid",
                    "name": "search",
                    "arguments": "{}"
                },
                {
                    "type": "function_call",
                    "call_id": "fc_bad",
                    "name": "",
                    "arguments": "{}"
                }
            ]
        });

        let err = ChioOpenAiAdapter::extract_responses_api_calls(&output).unwrap_err();
        assert!(err.to_string().contains("missing non-empty name"));
    }

    // ---- Deduplication tests ----

    #[test]
    fn duplicate_tools_across_manifests_deduplicated() {
        let m1 = test_manifest();
        let m2 = test_manifest();
        let adapter = ChioOpenAiAdapter::new(test_config(), vec![m1, m2]).unwrap();
        assert_eq!(adapter.function_names().len(), 2);
    }

    // ---- Error display tests ----

    #[test]
    fn error_display_function_not_found() {
        let err = OpenAiAdapterError::FunctionNotFound("x".into());
        assert!(format!("{err}").contains("x"));
    }

    #[test]
    fn error_display_invalid_request() {
        let err = OpenAiAdapterError::InvalidRequest("bad".into());
        assert!(format!("{err}").contains("bad"));
    }

    #[test]
    fn error_display_kernel() {
        let err = OpenAiAdapterError::Kernel("denied".into());
        assert!(format!("{err}").contains("denied"));
    }

    // ---- Serde tests ----

    #[test]
    fn tool_call_result_serializes() {
        let result = ToolCallResult {
            tool_call_id: "call_1".to_string(),
            name: "test".to_string(),
            content: "ok".to_string(),
            denied: false,
            receipt_ref: Some("receipt-1".to_string()),
            receipt: None,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["tool_call_id"], "call_1");
        assert_eq!(json["denied"], false);
    }

    #[test]
    fn tool_call_result_omits_receipt_ref_when_none() {
        let result = ToolCallResult {
            tool_call_id: "call_1".to_string(),
            name: "test".to_string(),
            content: "ok".to_string(),
            denied: false,
            receipt_ref: None,
            receipt: None,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json.get("receipt_ref").is_none());
    }

    #[test]
    fn openai_tool_def_roundtrips() {
        let def = OpenAiToolDef {
            tool_type: "function".to_string(),
            function: OpenAiFunctionDef {
                name: "test".to_string(),
                description: "A test function".to_string(),
                parameters: json!({"type": "object"}),
            },
        };
        let json = serde_json::to_value(&def).unwrap();
        let roundtripped: OpenAiToolDef = serde_json::from_value(json).unwrap();
        assert_eq!(roundtripped.function.name, "test");
    }

    #[test]
    fn openai_function_call_roundtrips() {
        let call = OpenAiFunctionCall {
            name: "get_weather".to_string(),
            arguments: r#"{"location":"NYC"}"#.to_string(),
        };
        let json = serde_json::to_value(&call).unwrap();
        let roundtripped: OpenAiFunctionCall = serde_json::from_value(json).unwrap();
        assert_eq!(roundtripped.name, "get_weather");
    }

    // ---- String result handling ----

    #[test]
    fn execute_tool_call_with_string_result() {
        let server = MockToolServer {
            response: json!("hello world"),
        };
        let adapter = ChioOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let mut kernel = ChioKernel::new(test_kernel_config());
        kernel.register_tool_server(Box::new(server));
        let agent_kp = Keypair::generate();
        let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "get_weather");
        let result = adapter.execute_tool_call(&weather_tool_call(), &kernel, &execution);
        assert_eq!(result.content, "hello world");
    }

    #[test]
    fn execute_tool_call_with_object_result() {
        let server = MockToolServer {
            response: json!({"temp": 72}),
        };
        let adapter = ChioOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let mut kernel = ChioKernel::new(test_kernel_config());
        kernel.register_tool_server(Box::new(server));
        let agent_kp = Keypair::generate();
        let execution = test_execution_context(&kernel, &agent_kp, "test-srv", "get_weather");
        let result = adapter.execute_tool_call(&weather_tool_call(), &kernel, &execution);
        assert!(result.content.contains("72"));
    }
}
