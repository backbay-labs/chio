#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;
use chio_core::capability::{
    ChioScope, Constraint, ModelMetadata, ModelSafetyTier, Operation, PromptGrant,
    ProvenanceEvidenceClass, ResourceGrant, ToolGrant,
};
use chio_core::crypto::Keypair;
use chio_core::{
    CompletionResult, PromptArgument, PromptDefinition, PromptMessage, PromptResult,
    ResourceContent, ResourceDefinition, ResourceTemplateDefinition, SamplingMessage, SamplingTool,
    SamplingToolChoice,
};
use chio_kernel::{
    KernelConfig, KernelError, PromptProvider, ResourceProvider, ToolCallChunk, ToolCallStream,
    ToolServerConnection, ToolServerEvent, ToolServerStreamResult,
};
use std::io::Cursor;
use std::sync::{Arc, Mutex};

struct EchoServer;
struct StreamingEchoServer;
struct UrlRequiredServer;
#[derive(Default)]
struct AsyncEventServer {
    events: Mutex<Vec<ToolServerEvent>>,
}
struct AsyncEventServerConnection(Arc<AsyncEventServer>);
struct DocsResourceProvider;
struct ExamplePromptProvider;

impl ToolServerConnection for EchoServer {
    fn server_id(&self) -> &str {
        "srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec![
            "read_file".to_string(),
            "write_file".to_string(),
            "echo_json".to_string(),
        ]
    }

    fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        match tool_name {
            "echo_json" => Ok(json!({
                "temperature": 22.5,
                "conditions": "Partly cloudy",
            })),
            _ => Ok(json!({
                "tool": tool_name,
                "arguments": arguments,
            })),
        }
    }
}

impl ToolServerConnection for StreamingEchoServer {
    fn server_id(&self) -> &str {
        "stream-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec![
            "stream_file".to_string(),
            "stream_file_incomplete".to_string(),
        ]
    }

    fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Ok(json!({
            "tool": tool_name,
            "arguments": arguments,
            "fallback": true,
        }))
    }

    fn invoke_stream(
        &self,
        tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        let stream = ToolCallStream {
            chunks: vec![
                ToolCallChunk {
                    data: json!({"type": "text", "text": "chunk one"}),
                },
                ToolCallChunk {
                    data: json!({"type": "text", "text": "chunk two"}),
                },
            ],
        };

        let result = match tool_name {
            "stream_file" => ToolServerStreamResult::Complete(stream),
            "stream_file_incomplete" => ToolServerStreamResult::Incomplete {
                stream,
                reason: "upstream stream interrupted".to_string(),
            },
            _ => return Ok(None),
        };

        Ok(Some(result))
    }
}

impl ToolServerConnection for UrlRequiredServer {
    fn server_id(&self) -> &str {
        "url-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["authorize".to_string()]
    }

    fn invoke(
        &self,
        _tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Err(KernelError::UrlElicitationsRequired {
            message: "URL elicitation is required for this operation".to_string(),
            elicitations: vec![CreateElicitationOperation::Url {
                meta: None,
                message: "Complete authorization in your browser".to_string(),
                url: "https://example.com/authorize".to_string(),
                elicitation_id: "elicit-auth".to_string(),
            }],
        })
    }
}

impl AsyncEventServer {
    fn push_event(&self, event: ToolServerEvent) {
        self.events.lock().unwrap().push(event);
    }
}

impl ToolServerConnection for AsyncEventServerConnection {
    fn server_id(&self) -> &str {
        "srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec![
            "read_file".to_string(),
            "write_file".to_string(),
            "echo_json".to_string(),
        ]
    }

    fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Ok(json!({
            "tool": tool_name,
            "arguments": arguments,
        }))
    }

    fn drain_events(&self) -> Result<Vec<ToolServerEvent>, KernelError> {
        let mut events = self.0.events.lock().unwrap();
        Ok(std::mem::take(&mut *events))
    }
}

impl ResourceProvider for DocsResourceProvider {
    fn list_resources(&self) -> Vec<ResourceDefinition> {
        vec![
            ResourceDefinition {
                uri: "repo://docs/roadmap".to_string(),
                name: "Roadmap".to_string(),
                title: Some("Roadmap".to_string()),
                description: Some("Project roadmap".to_string()),
                mime_type: Some("text/markdown".to_string()),
                size: Some(128),
                annotations: Some(json!({"audience": "engineering"})),
                icons: None,
            },
            ResourceDefinition {
                uri: "repo://secret/ops".to_string(),
                name: "Ops Secret".to_string(),
                title: None,
                description: Some("Should be filtered".to_string()),
                mime_type: Some("text/plain".to_string()),
                size: None,
                annotations: None,
                icons: None,
            },
        ]
    }

    fn list_resource_templates(&self) -> Vec<ResourceTemplateDefinition> {
        vec![ResourceTemplateDefinition {
            uri_template: "repo://docs/{slug}".to_string(),
            name: "Doc Template".to_string(),
            title: None,
            description: Some("Parameterized docs resource".to_string()),
            mime_type: Some("text/markdown".to_string()),
            annotations: None,
            icons: None,
        }]
    }

    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError> {
        match uri {
            "repo://docs/roadmap" => Ok(Some(vec![ResourceContent {
                uri: uri.to_string(),
                mime_type: Some("text/markdown".to_string()),
                text: Some("# Roadmap".to_string()),
                blob: None,
                annotations: None,
            }])),
            _ => Ok(None),
        }
    }

    fn complete_resource_argument(
        &self,
        uri: &str,
        argument_name: &str,
        value: &str,
        _context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, KernelError> {
        if uri == "repo://docs/{slug}" && argument_name == "slug" {
            let values = ["roadmap", "architecture", "api"]
                .into_iter()
                .filter(|candidate| candidate.starts_with(value))
                .map(str::to_string)
                .collect::<Vec<_>>();
            return Ok(Some(CompletionResult {
                total: Some(values.len() as u32),
                has_more: false,
                values,
            }));
        }

        Ok(None)
    }
}

struct FilesystemResourceProvider;

impl ResourceProvider for FilesystemResourceProvider {
    fn list_resources(&self) -> Vec<ResourceDefinition> {
        vec![
            ResourceDefinition {
                uri: "file:///workspace/project/docs/roadmap.md".to_string(),
                name: "Filesystem Roadmap".to_string(),
                title: Some("Filesystem Roadmap".to_string()),
                description: Some("In-root file-backed resource".to_string()),
                mime_type: Some("text/markdown".to_string()),
                size: Some(64),
                annotations: None,
                icons: None,
            },
            ResourceDefinition {
                uri: "file:///workspace/private/ops.md".to_string(),
                name: "Filesystem Ops".to_string(),
                title: None,
                description: Some("Out-of-root file-backed resource".to_string()),
                mime_type: Some("text/plain".to_string()),
                size: Some(32),
                annotations: None,
                icons: None,
            },
        ]
    }

    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError> {
        match uri {
            "file:///workspace/project/docs/roadmap.md" => Ok(Some(vec![ResourceContent {
                uri: uri.to_string(),
                mime_type: Some("text/markdown".to_string()),
                text: Some("# Filesystem Roadmap".to_string()),
                blob: None,
                annotations: None,
            }])),
            "file:///workspace/private/ops.md" => Ok(Some(vec![ResourceContent {
                uri: uri.to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some("ops".to_string()),
                blob: None,
                annotations: None,
            }])),
            _ => Ok(None),
        }
    }
}

impl PromptProvider for ExamplePromptProvider {
    fn list_prompts(&self) -> Vec<PromptDefinition> {
        vec![
            PromptDefinition {
                name: "summarize_docs".to_string(),
                title: Some("Summarize Docs".to_string()),
                description: Some("Summarize a documentation resource".to_string()),
                arguments: vec![PromptArgument {
                    name: "topic".to_string(),
                    title: None,
                    description: Some("Topic to summarize".to_string()),
                    required: Some(true),
                }],
                icons: None,
            },
            PromptDefinition {
                name: "ops_secret".to_string(),
                title: None,
                description: Some("Should be filtered".to_string()),
                arguments: vec![],
                icons: None,
            },
        ]
    }

    fn get_prompt(
        &self,
        name: &str,
        arguments: Value,
    ) -> Result<Option<PromptResult>, KernelError> {
        match name {
            "summarize_docs" => Ok(Some(PromptResult {
                description: Some("Summarize docs".to_string()),
                messages: vec![PromptMessage {
                    role: "user".to_string(),
                    content: json!({
                        "type": "text",
                        "text": format!(
                            "Summarize {}",
                            arguments["topic"].as_str().unwrap_or("the docs")
                        ),
                    }),
                }],
            })),
            _ => Ok(None),
        }
    }

    fn complete_prompt_argument(
        &self,
        name: &str,
        argument_name: &str,
        value: &str,
        _context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, KernelError> {
        if name == "summarize_docs" && argument_name == "topic" {
            let values = ["roadmap", "architecture", "release-plan"]
                .into_iter()
                .filter(|candidate| candidate.starts_with(value))
                .map(str::to_string)
                .collect::<Vec<_>>();
            return Ok(Some(CompletionResult {
                total: Some(values.len() as u32),
                has_more: false,
                values,
            }));
        }

        Ok(None)
    }
}

fn make_kernel() -> (ChioKernel, Keypair) {
    let keypair = Keypair::generate();
    let config = KernelConfig {
        keypair: keypair.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "edge-policy".to_string(),
        allow_sampling: true,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    };
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(EchoServer));
    kernel.register_resource_provider(Box::new(DocsResourceProvider));
    kernel.register_resource_provider(Box::new(FilesystemResourceProvider));
    kernel.register_prompt_provider(Box::new(ExamplePromptProvider));
    (kernel, keypair)
}

fn make_streaming_kernel() -> (ChioKernel, Keypair) {
    let (mut kernel, keypair) = make_kernel();
    kernel.register_tool_server(Box::new(StreamingEchoServer));
    (kernel, keypair)
}

fn issue_capabilities(kernel: &ChioKernel, agent: &Keypair) -> Vec<CapabilityToken> {
    issue_capabilities_with_resource_operations(kernel, agent, vec![Operation::Read])
}

fn issue_streaming_capabilities(kernel: &ChioKernel, agent: &Keypair) -> Vec<CapabilityToken> {
    let mut capabilities = issue_capabilities(kernel, agent);
    capabilities.push(
        kernel
            .issue_capability(
                &agent.public_key(),
                ChioScope {
                    grants: vec![
                        ToolGrant {
                            server_id: "stream-srv".to_string(),
                            tool_name: "stream_file".to_string(),
                            operations: vec![Operation::Invoke],
                            constraints: vec![],
                            max_invocations: None,
                            max_cost_per_invocation: None,
                            max_total_cost: None,
                            dpop_required: None,
                        },
                        ToolGrant {
                            server_id: "stream-srv".to_string(),
                            tool_name: "stream_file_incomplete".to_string(),
                            operations: vec![Operation::Invoke],
                            constraints: vec![],
                            max_invocations: None,
                            max_cost_per_invocation: None,
                            max_total_cost: None,
                            dpop_required: None,
                        },
                    ],
                    resource_grants: vec![],
                    prompt_grants: vec![],
                },
                300,
            )
            .unwrap(),
    );
    capabilities
}

fn issue_capabilities_with_resource_operations(
    kernel: &ChioKernel,
    agent: &Keypair,
    resource_operations: Vec<Operation>,
) -> Vec<CapabilityToken> {
    issue_capabilities_with_resource_grants(
        kernel,
        agent,
        vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: resource_operations,
        }],
    )
}

fn issue_capabilities_with_resource_grants(
    kernel: &ChioKernel,
    agent: &Keypair,
    resource_grants: Vec<ResourceGrant>,
) -> Vec<CapabilityToken> {
    vec![kernel
        .issue_capability(
            &agent.public_key(),
            ChioScope {
                grants: vec![
                    ToolGrant {
                        server_id: "srv".to_string(),
                        tool_name: "read_file".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    },
                    ToolGrant {
                        server_id: "srv".to_string(),
                        tool_name: "echo_json".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    },
                ],
                resource_grants,
                prompt_grants: vec![PromptGrant {
                    prompt_name: "summarize_*".to_string(),
                    operations: vec![Operation::Get],
                }],
            },
            300,
        )
        .unwrap()]
}

fn issue_model_constrained_capability(kernel: &ChioKernel, agent: &Keypair) -> CapabilityToken {
    kernel
        .issue_capability(
            &agent.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "srv".to_string(),
                    tool_name: "read_file".to_string(),
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
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            300,
        )
        .unwrap()
}

fn sample_manifest() -> ToolManifest {
    ToolManifest {
        schema: "chio.manifest.v1".into(),
        server_id: "srv".into(),
        name: "Test Server".into(),
        description: Some("test".into()),
        version: "0.1.0".into(),
        tools: vec![
            ToolDefinition {
                name: "read_file".into(),
                description: "Read a file".into(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: Some(LatencyHint::Fast),
            },
            ToolDefinition {
                name: "echo_json".into(),
                description: "Return a JSON object".into(),
                input_schema: json!({"type": "object"}),
                output_schema: Some(json!({
                    "type": "object",
                    "properties": {
                        "temperature": { "type": "number" },
                        "conditions": { "type": "string" }
                    }
                })),
                pricing: None,
                has_side_effects: false,
                latency_hint: Some(LatencyHint::Moderate),
            },
            ToolDefinition {
                name: "write_file".into(),
                description: "Write a file".into(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: true,
                latency_hint: Some(LatencyHint::Slow),
            },
        ],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: "abcd".into(),
    }
}

fn streaming_manifest() -> ToolManifest {
    ToolManifest {
        schema: "chio.manifest.v1".into(),
        server_id: "stream-srv".into(),
        name: "Streaming Test Server".into(),
        description: Some("streaming test".into()),
        version: "0.1.0".into(),
        tools: vec![
            ToolDefinition {
                name: "stream_file".into(),
                description: "Return streamed chunks".into(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: Some(LatencyHint::Moderate),
            },
            ToolDefinition {
                name: "stream_file_incomplete".into(),
                description: "Return streamed chunks then terminate incomplete".into(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: Some(LatencyHint::Slow),
            },
        ],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: "stream-abcd".into(),
    }
}

fn make_edge(page_size: usize) -> ChioMcpEdge {
    make_edge_with_config(page_size, false)
}

fn make_model_constrained_edge(page_size: usize) -> ChioMcpEdge {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = vec![issue_model_constrained_capability(&kernel, &agent)];
    ChioMcpEdge::new(
        McpEdgeConfig {
            server_name: "Chio MCP Edge".to_string(),
            server_version: "0.1.0".to_string(),
            page_size,
            tools_list_changed: false,
            completion_enabled: None,
            resources_subscribe: false,
            resources_list_changed: false,
            prompts_list_changed: false,
            logging_enabled: false,
        },
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap()
}

fn run_stdio_session(edge: &mut ChioMcpEdge, messages: &[Value]) -> Vec<Value> {
    let mut input = String::new();
    for message in messages {
        input.push_str(&serde_json::to_string(message).unwrap());
        input.push('\n');
    }
    let mut output = Vec::new();
    edge.serve_stdio(Cursor::new(input.into_bytes()), &mut output)
        .unwrap();
    String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect()
}

fn run_channel_session(edge: &mut ChioMcpEdge, messages: &[Value]) -> Vec<Value> {
    let (tx, rx) = std::sync::mpsc::channel();
    for message in messages {
        tx.send(message.clone()).unwrap();
    }
    drop(tx);

    let mut output = Vec::new();
    edge.serve_message_channels(rx, &mut output).unwrap();
    String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect()
}

fn normalize_transport_output(messages: &mut [Value]) {
    for message in messages {
        normalize_dynamic_transport_fields(message);
    }
}

fn normalize_dynamic_transport_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(owner_session_id) = map.get_mut("ownerSessionId") {
                *owner_session_id = json!("$session");
            }
            // The two transports capture wall-clock timestamps independently;
            // a tick across a second boundary between the stdio and channel
            // runs causes assert_eq! to flake. The shape comparison is what
            // matters, so collapse the captured instants to a sentinel.
            for field in ["createdAt", "lastUpdatedAt"] {
                if let Some(ts) = map.get_mut(field) {
                    *ts = json!("$timestamp");
                }
            }
            for child in map.values_mut() {
                normalize_dynamic_transport_fields(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                normalize_dynamic_transport_fields(child);
            }
        }
        _ => {}
    }
}

fn make_edge_with_config(page_size: usize, logging_enabled: bool) -> ChioMcpEdge {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_capabilities(&kernel, &agent);
    ChioMcpEdge::new(
        McpEdgeConfig {
            server_name: "Chio MCP Edge".to_string(),
            server_version: "0.1.0".to_string(),
            page_size,
            tools_list_changed: false,
            completion_enabled: None,
            resources_subscribe: false,
            resources_list_changed: false,
            prompts_list_changed: false,
            logging_enabled,
        },
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap()
}

#[test]
fn execute_bridge_mcp_tool_call_preserves_model_metadata() {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capability = issue_model_constrained_capability(&kernel, &agent);

    let bridge = execute_bridge_mcp_tool_call(
        &kernel,
        BridgeMcpToolCallRequest {
            request_id: "mcp-model-1".to_string(),
            capability,
            server_id: "srv".to_string(),
            tool_name: "read_file".to_string(),
            arguments: json!({"path":"/tmp/demo.txt"}),
            agent_id: agent.public_key().to_hex(),
            model_metadata: Some(ModelMetadata {
                model_id: "gpt-5".to_string(),
                safety_tier: Some(ModelSafetyTier::High),
                provider: Some("openai".to_string()),
                provenance_class: ProvenanceEvidenceClass::Asserted,
            }),
            route_selection_metadata: None,
            peer_supports_chio_tool_streaming: false,
        },
    )
    .unwrap();

    assert!(matches!(bridge.response.verdict, Verdict::Allow));
}

#[tokio::test]
async fn execute_bridge_mcp_tool_call_async_preserves_model_metadata() {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capability = issue_model_constrained_capability(&kernel, &agent);

    let bridge = execute_bridge_mcp_tool_call_async(
        &kernel,
        BridgeMcpToolCallRequest {
            request_id: "mcp-model-async-1".to_string(),
            capability,
            server_id: "srv".to_string(),
            tool_name: "read_file".to_string(),
            arguments: json!({"path":"/tmp/demo.txt"}),
            agent_id: agent.public_key().to_hex(),
            model_metadata: Some(ModelMetadata {
                model_id: "gpt-5".to_string(),
                safety_tier: Some(ModelSafetyTier::High),
                provider: Some("openai".to_string()),
                provenance_class: ProvenanceEvidenceClass::Asserted,
            }),
            route_selection_metadata: None,
            peer_supports_chio_tool_streaming: false,
        },
    )
    .await
    .unwrap();

    assert!(matches!(bridge.response.verdict, Verdict::Allow));
}

#[test]
fn tools_call_uses_meta_model_metadata_and_records_asserted_provenance() {
    let mut edge = make_model_constrained_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let denied = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": "/tmp/demo.txt" }
            }
        }))
        .unwrap();
    assert_eq!(denied["result"]["isError"], true);

    let allowed = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": "/tmp/demo.txt" },
                "_meta": {
                    "modelMetadata": {
                        "model_id": "gpt-5",
                        "safety_tier": "high",
                        "provider": "openai",
                        "provenance_class": "verified"
                    }
                }
            }
        }))
        .unwrap();
    assert_eq!(allowed["result"]["isError"], false);

    let receipt_log = edge.kernel.receipt_log();
    let receipt = receipt_log.receipts().last().expect("tool call receipt");
    let metadata = receipt.metadata.as_ref().expect("receipt metadata");
    assert_eq!(metadata["model_metadata"]["model_id"], "gpt-5");
    assert_eq!(metadata["model_metadata"]["provenance_class"], "asserted");
}

fn make_streaming_edge(page_size: usize) -> ChioMcpEdge {
    let (kernel, _) = make_streaming_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_streaming_capabilities(&kernel, &agent);
    ChioMcpEdge::new(
        McpEdgeConfig {
            server_name: "Chio MCP Edge".to_string(),
            server_version: "0.1.0".to_string(),
            page_size,
            tools_list_changed: false,
            completion_enabled: None,
            resources_subscribe: false,
            resources_list_changed: false,
            prompts_list_changed: false,
            logging_enabled: false,
        },
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest(), streaming_manifest()],
    )
    .unwrap()
}

fn make_url_required_edge() -> ChioMcpEdge {
    let keypair = Keypair::generate();
    let config = KernelConfig {
        keypair: keypair.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "edge-policy".to_string(),
        allow_sampling: true,
        allow_sampling_tool_use: false,
        allow_elicitation: true,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    };
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(UrlRequiredServer));
    let agent = Keypair::generate();
    let capabilities = vec![kernel
        .issue_capability(
            &agent.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "url-srv".to_string(),
                    tool_name: "authorize".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            300,
        )
        .unwrap()];

    ChioMcpEdge::new(
        McpEdgeConfig::default(),
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![ToolManifest {
            schema: "chio.manifest.v1".into(),
            server_id: "url-srv".into(),
            name: "URL Required Server".into(),
            description: Some("url required test".into()),
            version: "0.1.0".into(),
            tools: vec![ToolDefinition {
                name: "authorize".into(),
                description: "Requires URL elicitation".into(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: Some(LatencyHint::Moderate),
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: "url-abcd".into(),
        }],
    )
    .unwrap()
}

fn make_event_edge(server: Arc<AsyncEventServer>) -> ChioMcpEdge {
    let keypair = Keypair::generate();
    let config = KernelConfig {
        keypair: keypair.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "edge-policy".to_string(),
        allow_sampling: true,
        allow_sampling_tool_use: false,
        allow_elicitation: true,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    };
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(AsyncEventServerConnection(server)));
    kernel.register_resource_provider(Box::new(DocsResourceProvider));
    kernel.register_prompt_provider(Box::new(ExamplePromptProvider));
    let agent = Keypair::generate();
    let capabilities = issue_capabilities_with_resource_operations(
        &kernel,
        &agent,
        vec![Operation::Read, Operation::Subscribe],
    );

    ChioMcpEdge::new(
        McpEdgeConfig {
            tools_list_changed: true,
            resources_subscribe: true,
            resources_list_changed: true,
            prompts_list_changed: true,
            ..McpEdgeConfig::default()
        },
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap()
}

fn ready_session_id(edge: &ChioMcpEdge) -> SessionId {
    match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        other => panic!("expected ready session, got {other:?}"),
    }
}

fn register_pending_url_elicitation(
    edge: &mut ChioMcpEdge,
    elicitation_id: &str,
    related_task_id: Option<&str>,
) {
    let session_id = ready_session_id(edge);
    edge.kernel
        .register_session_pending_url_elicitation(
            &session_id,
            elicitation_id.to_string(),
            related_task_id.map(ToString::to_string),
        )
        .unwrap();
}

#[test]
fn initialize_then_initialized_enters_ready_state() {
    let mut edge = make_edge(10);

    let initialize = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }))
        .unwrap();

    assert_eq!(
        initialize["result"]["protocolVersion"],
        MCP_PROTOCOL_VERSION
    );
    assert_eq!(
        initialize["result"]["capabilities"]["tools"]["listChanged"],
        false
    );
    assert_eq!(
        initialize["result"]["capabilities"]["resources"]["subscribe"],
        false
    );
    assert_eq!(
        initialize["result"]["capabilities"]["prompts"]["listChanged"],
        false
    );
    assert_eq!(
        initialize["result"]["capabilities"]["completions"],
        json!({})
    );
    assert_eq!(
        initialize["result"]["capabilities"]["experimental"][CHIO_TOOL_STREAMING_CAPABILITY_KEY]
            ["toolCallChunkNotifications"],
        true
    );
    assert_eq!(
        initialize["result"]["capabilities"]["experimental"][CHIO_PROTOCOL_CAPABILITY_KEY]
            ["supportedProtocolVersions"],
        json!([MCP_PROTOCOL_VERSION])
    );
    assert_eq!(
        initialize["result"]["capabilities"]["experimental"][CHIO_PROTOCOL_CAPABILITY_KEY]
            ["selectedProtocolVersion"],
        MCP_PROTOCOL_VERSION
    );
    assert_eq!(
        initialize["result"]["capabilities"]["experimental"][CHIO_PROTOCOL_CAPABILITY_KEY]
            ["compatibility"],
        "exact_match"
    );
    assert_eq!(
        initialize["result"]["capabilities"]["experimental"][CHIO_PROTOCOL_CAPABILITY_KEY]
            ["downgradeBehavior"],
        "reject"
    );
    assert_eq!(
        initialize["result"]["capabilities"]["tasks"]["list"],
        json!({})
    );
    assert_eq!(
        initialize["result"]["capabilities"]["tasks"]["cancel"],
        json!({})
    );
    assert_eq!(
        initialize["result"]["capabilities"]["tasks"]["requests"]["tools"]["call"],
        json!({})
    );
    assert!(initialize["result"]["capabilities"]
        .get("logging")
        .is_none());

    let initialized = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));
    assert!(initialized.is_none());
    assert!(matches!(edge.state, EdgeState::Ready { .. }));
}

#[test]
fn initialize_unsupported_protocol_version_rejected() {
    let mut edge = make_edge(10);

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-01-01"
            }
        }))
        .unwrap();

    assert_eq!(response["error"]["code"], JSONRPC_INVALID_REQUEST);
    assert_eq!(response["error"]["message"], "unsupported protocolVersion");
    assert_eq!(
        response["error"]["data"]["chioError"]["code"],
        CHIO_ERROR_PROTOCOL_VERSION_UNSUPPORTED
    );
    assert_eq!(
        response["error"]["data"]["chioError"]["name"],
        "protocol_version_unsupported"
    );
    assert_eq!(
        response["error"]["data"]["chioError"]["category"],
        "protocol"
    );
    assert_eq!(response["error"]["data"]["chioError"]["transient"], false);
    assert_eq!(
        response["error"]["data"]["chioError"]["retry"]["strategy"],
        "do_not_retry_until_version_change"
    );
    assert_eq!(
        response["error"]["data"]["requestedProtocolVersion"],
        "2024-01-01"
    );
    assert_eq!(
        response["error"]["data"]["supportedProtocolVersions"],
        json!([MCP_PROTOCOL_VERSION])
    );
    assert!(matches!(edge.state, EdgeState::Uninitialized));
}

#[test]
fn tools_list_is_paginated() {
    let mut edge = make_edge(2);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let first_page = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }))
        .unwrap();
    assert_eq!(first_page["result"]["tools"].as_array().unwrap().len(), 2);
    assert!(first_page["result"]["nextCursor"].is_null());
    assert!(
        first_page["result"]["tools"][0]["annotations"]["readOnlyHint"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        first_page["result"]["tools"][0]["execution"]["taskSupport"],
        "optional"
    );
    assert_eq!(
        first_page["result"]["tools"][1]["outputSchema"]["type"],
        "object"
    );

    let second_page = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": { "cursor": "2" }
        }))
        .unwrap();
    assert_eq!(second_page["result"]["tools"].as_array().unwrap().len(), 0);
    assert!(second_page["result"]["nextCursor"].is_null());
}

#[test]
fn tools_call_requires_initialized_session() {
    let mut edge = make_edge(10);
    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "read_file", "arguments": { "path": "/tmp/x" } }
        }))
        .unwrap();

    assert_eq!(response["error"]["code"], JSONRPC_SERVER_NOT_INITIALIZED);
}

#[test]
fn parse_peer_capabilities_treats_empty_elicitation_as_form_support() {
    let capabilities = parse_peer_capabilities(&json!({
        "capabilities": {
            "elicitation": {},
        }
    }));

    assert!(capabilities.supports_elicitation);
    assert!(capabilities.elicitation_form);
    assert!(!capabilities.elicitation_url);

    let capabilities = parse_peer_capabilities(&json!({
        "capabilities": {
            "elicitation": {
                "form": {},
                "url": {}
            }
        }
    }));

    assert!(capabilities.supports_elicitation);
    assert!(capabilities.elicitation_form);
    assert!(capabilities.elicitation_url);
}

#[test]
fn parse_peer_capabilities_honors_object_valued_sampling_subcapabilities() {
    let capabilities = parse_peer_capabilities(&json!({
        "capabilities": {
            "sampling": {
                "context": {},
                "tools": {}
            }
        }
    }));

    assert!(capabilities.supports_sampling);
    assert!(capabilities.sampling_context);
    assert!(capabilities.sampling_tools);

    let malformed = parse_peer_capabilities(&json!({
        "capabilities": {
            "sampling": {
                "includeContext": true,
                "tools": true
            }
        }
    }));

    assert!(malformed.supports_sampling);
    assert!(!malformed.sampling_context);
    assert!(!malformed.sampling_tools);
}

#[test]
fn parse_peer_capabilities_tracks_resource_subscription_support_when_present() {
    let capabilities = parse_peer_capabilities(&json!({
        "capabilities": {
            "resources": {
                "subscribe": true
            }
        }
    }));

    assert!(capabilities.supports_subscriptions);

    let capabilities = parse_peer_capabilities(&json!({
        "capabilities": {
            "resources": {
                "subscribe": false
            }
        }
    }));

    assert!(!capabilities.supports_subscriptions);
}

#[test]
fn wrapped_elicitation_completion_notifications_only_emit_for_known_ids() {
    let mut edge = make_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "elicitation": {
                    "form": {},
                    "url": {}
                }
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    register_pending_url_elicitation(&mut edge, "elicit-123", Some("task-7"));

    edge.handle_upstream_transport_notification(json!({
        "jsonrpc": "2.0",
        "method": "notifications/elicitation/complete",
        "params": {
            "elicitationId": "elicit-123"
        }
    }));
    edge.handle_upstream_transport_notification(json!({
        "jsonrpc": "2.0",
        "method": "notifications/elicitation/complete",
        "params": {
            "elicitationId": "unknown-id"
        }
    }));

    let notifications = edge.take_pending_notifications();
    assert_eq!(notifications.len(), 1);
    assert_eq!(
        notifications[0]["method"],
        "notifications/elicitation/complete"
    );
    assert_eq!(notifications[0]["params"]["elicitationId"], "elicit-123");
    assert_eq!(
        notifications[0]["params"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
        "task-7"
    );
}

#[test]
fn direct_tool_server_url_required_errors_are_brokered_as_jsonrpc_errors() {
    let mut edge = make_url_required_edge();
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "elicitation": {
                    "url": {}
                }
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "authorize",
                "arguments": {}
            }
        }))
        .unwrap();

    assert_eq!(response["error"]["code"], JSONRPC_URL_ELICITATION_REQUIRED);
    assert_eq!(response["error"]["data"]["elicitations"][0]["mode"], "url");
    assert_eq!(
        response["error"]["data"]["elicitations"][0]["elicitationId"],
        "elicit-auth"
    );

    edge.notify_elicitation_completed("elicit-auth");
    let notifications = edge.take_pending_notifications();
    assert_eq!(notifications.len(), 1);
    assert_eq!(
        notifications[0]["method"],
        "notifications/elicitation/complete"
    );
    assert_eq!(notifications[0]["params"]["elicitationId"], "elicit-auth");
}

#[test]
fn direct_tool_server_events_are_forwarded_through_the_edge() {
    let server = Arc::new(AsyncEventServer::default());
    let mut edge = make_event_edge(Arc::clone(&server));
    edge.set_session_auth_context(SessionAuthContext::in_process_anonymous());
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "elicitation": {
                    "url": {}
                }
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));
    let subscribe = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/subscribe",
            "params": {
                "uri": "repo://docs/roadmap"
            }
        }))
        .unwrap();
    assert!(subscribe.get("result").is_some());

    register_pending_url_elicitation(&mut edge, "elicit-async", None);
    server.push_event(ToolServerEvent::ElicitationCompleted {
        elicitation_id: "elicit-async".to_string(),
    });
    server.push_event(ToolServerEvent::ResourceUpdated {
        uri: "repo://docs/roadmap".to_string(),
    });
    server.push_event(ToolServerEvent::ResourcesListChanged);
    server.push_event(ToolServerEvent::ToolsListChanged);
    server.push_event(ToolServerEvent::PromptsListChanged);

    let notifications = edge.drain_runtime_notifications().unwrap();
    let methods = notifications
        .iter()
        .map(|notification| notification["method"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    assert!(methods.contains(&"notifications/elicitation/complete"));
    assert!(methods.contains(&"notifications/resources/updated"));
    assert!(methods.contains(&"notifications/resources/list_changed"));
    assert!(methods.contains(&"notifications/tools/list_changed"));
    assert!(methods.contains(&"notifications/prompts/list_changed"));
}

#[test]
fn in_process_runtime_drain_flushes_late_async_events_without_request_bridge() {
    let server = Arc::new(AsyncEventServer::default());
    let mut edge = make_event_edge(Arc::clone(&server));
    edge.set_session_auth_context(SessionAuthContext::in_process_anonymous());
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "elicitation": {
                    "url": {}
                }
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));
    register_pending_url_elicitation(&mut edge, "elicit-late", Some("task-7"));

    server.push_event(ToolServerEvent::ElicitationCompleted {
        elicitation_id: "elicit-late".to_string(),
    });

    let notifications = edge.drain_runtime_notifications().unwrap();

    assert_eq!(notifications.len(), 1);
    assert_eq!(
        notifications[0]["method"],
        "notifications/elicitation/complete"
    );
    assert_eq!(notifications[0]["params"]["elicitationId"], "elicit-late");
    assert_eq!(
        notifications[0]["params"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
        "task-7"
    );
    assert!(edge.drain_runtime_notifications().unwrap().is_empty());
}

#[test]
fn in_process_runtime_drain_completes_task_after_tools_call_returns_task() {
    let mut edge = make_edge(10);
    edge.set_session_auth_context(SessionAuthContext::in_process_anonymous());
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let create = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": {},
                "task": {}
            }
        }))
        .unwrap();
    let task_id = create["result"]["task"]["taskId"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(create["result"]["task"]["status"], "working");

    let notifications = edge.drain_runtime_notifications().unwrap();
    assert_eq!(notifications.len(), 1);
    assert_eq!(notifications[0]["method"], "notifications/tasks/status");
    assert_eq!(notifications[0]["params"]["taskId"], task_id);
    assert_eq!(notifications[0]["params"]["status"], "completed");

    let get_completed = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tasks/get",
            "params": { "taskId": task_id.clone() }
        }))
        .unwrap();
    assert_eq!(get_completed["result"]["status"], "completed");

    let result = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tasks/result",
            "params": { "taskId": task_id.clone() }
        }))
        .unwrap();
    assert_eq!(
        result["result"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
        task_id
    );
    assert_eq!(result["result"]["structuredContent"]["temperature"], 22.5);
    assert!(edge.drain_runtime_notifications().unwrap().is_empty());
}

#[test]
fn tools_call_returns_structured_content_for_object_results() {
    let mut edge = make_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "echo_json", "arguments": {} }
        }))
        .unwrap();

    assert_eq!(response["result"]["isError"], false);
    assert_eq!(response["result"]["structuredContent"]["temperature"], 22.5);
    assert!(response["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("temperature"));
}

#[test]
fn tools_call_denied_by_capabilities_returns_tool_error() {
    let mut edge = make_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "write_file", "arguments": { "path": "/tmp/x", "content": "hi" } }
        }))
        .unwrap();

    assert_eq!(response["result"]["isError"], true);
    assert!(response["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("not authorized"));
}

#[test]
fn tools_call_streams_chunks_via_experimental_notifications_when_negotiated() {
    let mut edge = make_streaming_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "experimental": {
                    "chioToolStreaming": {
                        "toolCallChunkNotifications": true
                    }
                }
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "stream_file", "arguments": {} }
        }))
        .unwrap();

    assert_eq!(response["result"]["isError"], false);
    assert_eq!(
        response["result"]["structuredContent"][CHIO_TOOL_STREAM_KEY]["mode"],
        "notification_stream"
    );
    assert_eq!(
        response["result"]["structuredContent"][CHIO_TOOL_STREAM_KEY]["notificationMethod"],
        CHIO_TOOL_STREAMING_NOTIFICATION_METHOD
    );
    assert_eq!(
        response["result"]["structuredContent"][CHIO_TOOL_STREAM_KEY]["totalChunks"],
        2
    );
    let notifications = edge.take_pending_notifications();
    assert_eq!(notifications.len(), 2);
    assert_eq!(
        notifications[0]["method"],
        CHIO_TOOL_STREAMING_NOTIFICATION_METHOD
    );
    assert_eq!(notifications[0]["params"]["requestId"], json!(2));
    assert_eq!(notifications[0]["params"]["chunkIndex"], 0);
    assert_eq!(notifications[0]["params"]["totalChunks"], 2);
    assert_eq!(notifications[0]["params"]["chunk"]["text"], "chunk one");
    assert_eq!(notifications[1]["params"]["chunkIndex"], 1);
    assert_eq!(notifications[1]["params"]["chunk"]["text"], "chunk two");
}

#[test]
fn tools_call_streams_collapse_when_peer_does_not_negotiate_extension() {
    let mut edge = make_streaming_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "stream_file", "arguments": {} }
        }))
        .unwrap();

    assert_eq!(response["result"]["isError"], false);
    assert_eq!(
        response["result"]["structuredContent"][CHIO_TOOL_STREAM_KEY]["mode"],
        "collapsed_result"
    );
    assert_eq!(
        response["result"]["structuredContent"][CHIO_TOOL_STREAM_KEY]["chunks"][0]["text"],
        "chunk one"
    );
    assert!(edge.take_pending_notifications().is_empty());
}

#[test]
fn incomplete_streamed_tools_call_preserves_chunks_and_terminal_state() {
    let mut edge = make_streaming_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "experimental": {
                    "chioToolStreaming": {
                        "toolCallChunkNotifications": true
                    }
                }
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "stream_file_incomplete", "arguments": {} }
        }))
        .unwrap();

    assert_eq!(response["result"]["isError"], true);
    assert_eq!(
        response["result"]["structuredContent"][CHIO_TOOL_STREAM_KEY]["terminalState"],
        "incomplete"
    );
    assert_eq!(
        response["result"]["structuredContent"][CHIO_TOOL_STREAM_KEY]["reason"],
        "upstream stream interrupted"
    );

    let notifications = edge.take_pending_notifications();
    assert_eq!(notifications.len(), 2);
    assert_eq!(
        notifications[0]["method"],
        CHIO_TOOL_STREAMING_NOTIFICATION_METHOD
    );
}

#[test]
fn task_augmented_tool_call_completes_via_tasks_result_and_tracks_status() {
    let mut edge = make_streaming_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "experimental": {
                    "chioToolStreaming": {
                        "toolCallChunkNotifications": true
                    }
                }
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let create = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "stream_file",
                "arguments": {},
                "task": { "ttl": 60000 }
            }
        }))
        .unwrap();
    let task_id = create["result"]["task"]["taskId"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(create["result"]["task"]["status"], "working");
    assert_eq!(create["result"]["task"]["ttl"], 60000);
    assert_eq!(
        create["result"]["task"]["pollInterval"],
        TASK_POLL_INTERVAL_MILLIS
    );
    assert_eq!(create["result"]["task"]["ownership"]["workOwner"], "task");
    assert_eq!(
        create["result"]["task"]["ownership"]["resultStreamOwner"],
        "request_stream"
    );
    assert_eq!(
        create["result"]["task"]["ownership"]["statusNotificationOwner"],
        "session_notification_stream"
    );
    assert_eq!(
        create["result"]["task"]["ownership"]["terminalStateOwner"],
        "task"
    );
    assert!(create["result"]["task"]["ownerSessionId"]
        .as_str()
        .unwrap()
        .starts_with("sess-"));
    assert!(create["result"]["task"]["ownerRequestId"]
        .as_str()
        .unwrap()
        .starts_with("mcp-edge-req-"));
    assert!(create["result"]["task"]["parentRequestId"].is_null());

    let get_working = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tasks/get",
            "params": { "taskId": task_id.clone() }
        }))
        .unwrap();
    assert_eq!(get_working["result"]["status"], "working");
    assert_eq!(get_working["result"]["ownership"]["workOwner"], "task");

    let result = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tasks/result",
            "params": { "taskId": task_id.clone() }
        }))
        .unwrap();
    assert_eq!(
        result["result"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
        task_id
    );
    assert!(
        result["result"]["_meta"][RELATED_TASK_META_KEY]["ownerSessionId"]
            .as_str()
            .unwrap()
            .starts_with("sess-")
    );
    assert!(
        result["result"]["_meta"][RELATED_TASK_META_KEY]["ownerRequestId"]
            .as_str()
            .unwrap()
            .starts_with("mcp-edge-req-")
    );
    assert!(result["result"]["_meta"][RELATED_TASK_META_KEY]["parentRequestId"].is_null());
    assert_eq!(
        result["result"]["structuredContent"]["chioToolStream"]["mode"],
        "notification_stream"
    );

    let notifications = edge.take_pending_notifications();
    assert_eq!(notifications.len(), 3);
    assert_eq!(
        notifications[0]["params"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
        task_id
    );
    assert!(notifications.iter().any(|notification| {
        notification["method"] == "notifications/tasks/status"
            && notification["params"]["taskId"] == task_id
            && notification["params"]["status"] == "completed"
    }));

    let get_completed = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tasks/get",
            "params": { "taskId": task_id.clone() }
        }))
        .unwrap();
    assert_eq!(get_completed["result"]["status"], "completed");
    assert_eq!(
        get_completed["result"]["ownership"]["terminalStateOwner"],
        "task"
    );
}

#[test]
fn tasks_cancel_marks_working_task_cancelled_and_result_returns_error_payload() {
    let mut edge = make_streaming_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let create = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "stream_file",
                "arguments": {},
                "task": {}
            }
        }))
        .unwrap();
    let task_id = create["result"]["task"]["taskId"]
        .as_str()
        .unwrap()
        .to_string();

    let cancelled = edge
        .handle_jsonrpc(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tasks/cancel",
                "params": { "taskId": task_id.clone() }
        }))
        .unwrap();
    assert_eq!(cancelled["result"]["status"], "cancelled");
    let notifications = edge.take_pending_notifications();
    assert_eq!(notifications.len(), 1);
    assert_eq!(notifications[0]["method"], "notifications/tasks/status");
    assert_eq!(notifications[0]["params"]["taskId"], task_id);
    assert!(notifications[0]["params"].get("_meta").is_none());

    let result = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tasks/result",
            "params": { "taskId": task_id.clone() }
        }))
        .unwrap();
    assert_eq!(result["result"]["isError"], true);
    assert_eq!(
        result["result"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
        task_id
    );
}

#[test]
fn request_cancelled_errors_record_cancelled_task_terminal_state() {
    let mut edge = make_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let (session_id, context, operation) = edge
        .prepare_tool_call_request(
            &json!(2),
            &json!({
                "name": "read_file",
                "arguments": { "path": "/tmp/race" },
                "task": {}
            }),
        )
        .unwrap();
    let task_id = "mcp-edge-task-cancelled".to_string();
    let mut task = EdgeTask::new(task_id.clone(), session_id, context, operation, None, 0);

    let outcome = edge.tool_call_error_outcome(
        &task.session_id,
        KernelError::RequestCancelled {
            request_id: chio_core::session::RequestId::new("cancelled-request"),
            reason: "cancelled by client: user aborted sample".to_string(),
        },
        Some(task_id.as_str()),
    );
    task.record_outcome(outcome);

    assert_eq!(task.status, EdgeTaskStatus::Cancelled);
    assert_eq!(
        task.status_message.as_deref(),
        Some("cancelled by client: user aborted sample")
    );

    let result = task_outcome_to_jsonrpc(Some(task.clone()), &json!(3), &task_id);
    assert_eq!(result["result"]["isError"], true);
    assert_eq!(
        result["result"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
        task_id
    );
    assert_eq!(
        result["result"]["_meta"][RELATED_TASK_META_KEY]["ownerSessionId"],
        task.owner_session_id
    );
    assert_eq!(
        result["result"]["_meta"][RELATED_TASK_META_KEY]["ownerRequestId"],
        task.owner_request_id
    );
    assert_eq!(
        result["result"]["_meta"][RELATED_TASK_META_KEY]["parentRequestId"].as_str(),
        task.parent_request_id.as_deref()
    );
    assert!(result["result"]["content"][0]["text"]
        .as_str()
        .expect("cancelled task result text")
        .contains("cancelled by client: user aborted sample"));
}

#[test]
fn serve_stdio_handles_initialize_and_tools_list_roundtrip() {
    let mut edge = make_edge(10);
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n"
    );

    let mut output = Vec::new();
    edge.serve_stdio(Cursor::new(input.as_bytes()), &mut output)
        .unwrap();

    let lines = String::from_utf8(output).unwrap();
    let responses = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(responses.len(), 2);
    assert_eq!(
        responses[0]["result"]["protocolVersion"],
        MCP_PROTOCOL_VERSION
    );
    let tools = responses[1]["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 2);
    assert!(tools.iter().all(|tool| tool["name"] != "write_file"));
}

#[test]
fn serve_stdio_emits_stream_chunk_notifications_before_final_tool_response() {
    let mut edge = make_streaming_edge(10);
    let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"capabilities\":{\"experimental\":{\"chioToolStreaming\":{\"toolCallChunkNotifications\":true}}}}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"stream_file\",\"arguments\":{}}}\n"
        );

    let mut output = Vec::new();
    edge.serve_stdio(Cursor::new(input.as_bytes()), &mut output)
        .unwrap();

    let lines = String::from_utf8(output).unwrap();
    let responses = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(responses.len(), 4);
    assert_eq!(
        responses[0]["result"]["protocolVersion"],
        MCP_PROTOCOL_VERSION
    );
    assert_eq!(
        responses[1]["method"],
        CHIO_TOOL_STREAMING_NOTIFICATION_METHOD
    );
    assert_eq!(responses[1]["params"]["chunkIndex"], 0);
    assert_eq!(
        responses[2]["method"],
        CHIO_TOOL_STREAMING_NOTIFICATION_METHOD
    );
    assert_eq!(responses[2]["params"]["chunkIndex"], 1);
    assert_eq!(responses[3]["id"], 2);
    assert_eq!(
        responses[3]["result"]["structuredContent"][CHIO_TOOL_STREAM_KEY]["mode"],
        "notification_stream"
    );
}

#[test]
fn serve_stdio_tasks_result_emits_stream_chunk_notifications_before_result() {
    let mut edge = make_streaming_edge(10);
    let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"capabilities\":{\"experimental\":{\"chioToolStreaming\":{\"toolCallChunkNotifications\":true}}}}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"stream_file\",\"arguments\":{},\"task\":{}}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tasks/result\",\"params\":{\"taskId\":\"mcp-edge-task-1\"}}\n"
        );

    let mut output = Vec::new();
    edge.serve_stdio(Cursor::new(input.as_bytes()), &mut output)
        .unwrap();

    let lines = String::from_utf8(output).unwrap();
    let responses = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(responses.len(), 6);
    assert_eq!(
        responses[0]["result"]["protocolVersion"],
        MCP_PROTOCOL_VERSION
    );
    assert_eq!(responses[1]["result"]["task"]["status"], "working");
    assert_eq!(
        responses[2]["method"],
        CHIO_TOOL_STREAMING_NOTIFICATION_METHOD
    );
    assert_eq!(
        responses[3]["method"],
        CHIO_TOOL_STREAMING_NOTIFICATION_METHOD
    );
    assert_eq!(responses[4]["method"], "notifications/tasks/status");
    assert_eq!(responses[4]["params"]["status"], "completed");
    assert_eq!(responses[5]["id"], 3);
    assert_eq!(
        responses[5]["result"]["_meta"][RELATED_TASK_META_KEY]["taskId"],
        "mcp-edge-task-1"
    );
}

#[test]
fn serve_message_channels_matches_stdio_for_streaming_tasks_result_flow() {
    let messages = vec![
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "capabilities": {
                    "experimental": {
                        "chioToolStreaming": {
                            "toolCallChunkNotifications": true
                        }
                    }
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "stream_file",
                "arguments": {},
                "task": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tasks/result",
            "params": {
                "taskId": "mcp-edge-task-1"
            }
        }),
    ];

    let mut stdio_edge = make_streaming_edge(10);
    let mut stdio = run_stdio_session(&mut stdio_edge, &messages);
    let mut channel_edge = make_streaming_edge(10);
    let mut channel = run_channel_session(&mut channel_edge, &messages);

    normalize_transport_output(&mut stdio);
    normalize_transport_output(&mut channel);

    assert_eq!(channel, stdio);
}

#[test]
fn serve_message_channels_matches_stdio_for_task_cancellation_flow() {
    let messages = vec![
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }),
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "stream_file",
                "arguments": {},
                "task": {}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tasks/cancel",
            "params": {
                "taskId": "mcp-edge-task-1"
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tasks/result",
            "params": {
                "taskId": "mcp-edge-task-1"
            }
        }),
    ];

    let mut stdio_edge = make_streaming_edge(10);
    let mut stdio = run_stdio_session(&mut stdio_edge, &messages);
    let mut channel_edge = make_streaming_edge(10);
    let mut channel = run_channel_session(&mut channel_edge, &messages);

    normalize_transport_output(&mut stdio);
    normalize_transport_output(&mut channel);

    assert_eq!(channel, stdio);
}

#[test]
fn resources_list_is_filtered_by_capabilities() {
    let mut edge = make_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/list",
            "params": {}
        }))
        .unwrap();

    let resources = response["result"]["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["uri"], "repo://docs/roadmap");
}

#[test]
fn resources_read_returns_contents() {
    let mut edge = make_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": { "uri": "repo://docs/roadmap" }
        }))
        .unwrap();

    assert_eq!(response["result"]["contents"][0]["text"], "# Roadmap");
}

#[test]
fn resources_read_allows_in_root_filesystem_resources() {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_capabilities_with_resource_grants(
        &kernel,
        &agent,
        vec![ResourceGrant {
            uri_pattern: "file:///workspace/*".to_string(),
            operations: vec![Operation::Read],
        }],
    );
    let mut edge = ChioMcpEdge::new(
        McpEdgeConfig::default(),
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap();

    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };
    edge.kernel
        .replace_session_roots(
            &session_id,
            vec![RootDefinition {
                uri: "file:///workspace/project".to_string(),
                name: Some("Project".to_string()),
            }],
        )
        .unwrap();

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": { "uri": "file:///workspace/project/docs/roadmap.md" }
        }))
        .unwrap();

    assert_eq!(
        response["result"]["contents"][0]["text"],
        "# Filesystem Roadmap"
    );
}

#[test]
fn resources_read_denies_out_of_root_filesystem_resources() {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_capabilities_with_resource_grants(
        &kernel,
        &agent,
        vec![ResourceGrant {
            uri_pattern: "file:///workspace/*".to_string(),
            operations: vec![Operation::Read],
        }],
    );
    let mut edge = ChioMcpEdge::new(
        McpEdgeConfig::default(),
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap();

    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };
    edge.kernel
        .replace_session_roots(
            &session_id,
            vec![RootDefinition {
                uri: "file:///workspace/project".to_string(),
                name: Some("Project".to_string()),
            }],
        )
        .unwrap();

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": { "uri": "file:///workspace/private/ops.md" }
        }))
        .unwrap();

    assert_eq!(response["error"]["code"], JSONRPC_INVALID_PARAMS);
    assert_eq!(
            response["error"]["message"],
            "resource read denied: filesystem-backed resource path /workspace/private/ops.md is outside the negotiated roots"
        );
    let receipt = &response["error"]["data"]["receipt"];
    assert_eq!(receipt["tool_name"], "resources/read");
    assert_eq!(receipt["tool_server"], "session");
    assert_eq!(receipt["decision"]["verdict"], "deny");
    assert_eq!(receipt["decision"]["guard"], "session_roots");
    assert_eq!(
        receipt["decision"]["reason"],
        "filesystem-backed resource path /workspace/private/ops.md is outside the negotiated roots"
    );
    assert!(receipt["signature"].is_string());
}

#[test]
fn resources_read_denies_filesystem_resources_when_roots_are_missing() {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_capabilities_with_resource_grants(
        &kernel,
        &agent,
        vec![ResourceGrant {
            uri_pattern: "file:///workspace/*".to_string(),
            operations: vec![Operation::Read],
        }],
    );
    let mut edge = ChioMcpEdge::new(
        McpEdgeConfig::default(),
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap();

    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": { "uri": "file:///workspace/project/docs/roadmap.md" }
        }))
        .unwrap();

    assert_eq!(response["error"]["code"], JSONRPC_INVALID_PARAMS);
    assert_eq!(
        response["error"]["message"],
        "resource read denied: no enforceable filesystem roots are available for this session"
    );
    let receipt = &response["error"]["data"]["receipt"];
    assert_eq!(receipt["tool_name"], "resources/read");
    assert_eq!(receipt["tool_server"], "session");
    assert_eq!(receipt["decision"]["verdict"], "deny");
    assert_eq!(receipt["decision"]["guard"], "session_roots");
    assert_eq!(
        receipt["decision"]["reason"],
        "no enforceable filesystem roots are available for this session"
    );
    assert!(receipt["signature"].is_string());
}

#[test]
fn resources_subscribe_tracks_session_state() {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_capabilities_with_resource_operations(
        &kernel,
        &agent,
        vec![Operation::Read, Operation::Subscribe],
    );
    let mut edge = ChioMcpEdge::new(
        McpEdgeConfig {
            resources_subscribe: true,
            ..McpEdgeConfig::default()
        },
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap();

    let initialize = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }))
        .unwrap();
    assert_eq!(
        initialize["result"]["capabilities"]["resources"]["subscribe"],
        true
    );
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/subscribe",
            "params": { "uri": "repo://docs/roadmap" }
        }))
        .unwrap();

    assert_eq!(response["result"], json!({}));
    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };
    assert!(edge
        .kernel
        .session_has_resource_subscription(&session_id, "repo://docs/roadmap")
        .unwrap());
}

#[test]
fn resources_unsubscribe_clears_session_state() {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_capabilities_with_resource_operations(
        &kernel,
        &agent,
        vec![Operation::Read, Operation::Subscribe],
    );
    let mut edge = ChioMcpEdge::new(
        McpEdgeConfig {
            resources_subscribe: true,
            ..McpEdgeConfig::default()
        },
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap();

    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "resources/subscribe",
        "params": { "uri": "repo://docs/roadmap" }
    }));
    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/unsubscribe",
            "params": { "uri": "repo://docs/roadmap" }
        }))
        .unwrap();

    assert_eq!(response["result"], json!({}));
    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };
    assert!(!edge
        .kernel
        .session_has_resource_subscription(&session_id, "repo://docs/roadmap")
        .unwrap());
}

#[test]
fn resource_update_notifications_only_emit_for_subscribed_uris() {
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_capabilities_with_resource_operations(
        &kernel,
        &agent,
        vec![Operation::Read, Operation::Subscribe],
    );
    let mut edge = ChioMcpEdge::new(
        McpEdgeConfig {
            resources_subscribe: true,
            ..McpEdgeConfig::default()
        },
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap();

    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "resources/subscribe",
        "params": { "uri": "repo://docs/roadmap" }
    }));

    edge.notify_resource_updated("repo://secret/ops");
    assert!(edge.take_pending_notifications().is_empty());

    edge.notify_resource_updated("repo://docs/roadmap");
    let notifications = edge.take_pending_notifications();
    assert_eq!(notifications.len(), 1);
    assert_eq!(
        notifications[0]["method"],
        "notifications/resources/updated"
    );
    assert_eq!(notifications[0]["params"]["uri"], "repo://docs/roadmap");
}

#[test]
fn resources_list_changed_notification_emits_when_enabled() {
    let mut edge = make_edge(10);
    edge.config.resources_list_changed = true;

    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    edge.notify_resources_list_changed();
    let notifications = edge.take_pending_notifications();

    assert_eq!(notifications.len(), 1);
    assert_eq!(
        notifications[0]["method"],
        "notifications/resources/list_changed"
    );
    assert!(notifications[0].get("params").is_none());
}

#[test]
fn prompts_list_and_get_are_filtered_by_capabilities() {
    let mut edge = make_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let list_response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "prompts/list",
            "params": {}
        }))
        .unwrap();

    let prompts = list_response["result"]["prompts"].as_array().unwrap();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0]["name"], "summarize_docs");

    let get_response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "prompts/get",
            "params": { "name": "summarize_docs", "arguments": { "topic": "roadmap" } }
        }))
        .unwrap();

    assert_eq!(
        get_response["result"]["messages"][0]["content"]["text"],
        "Summarize roadmap"
    );
}

#[test]
fn completion_complete_returns_candidates_for_prompt_and_resource_refs() {
    let mut edge = make_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let prompt_response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "completion/complete",
            "params": {
                "ref": { "type": "ref/prompt", "name": "summarize_docs" },
                "argument": { "name": "topic", "value": "r" },
                "context": { "arguments": {} }
            }
        }))
        .unwrap();
    assert_eq!(prompt_response["result"]["completion"]["total"], 2);
    assert_eq!(
        prompt_response["result"]["completion"]["values"],
        json!(["roadmap", "release-plan"])
    );

    let resource_response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "completion/complete",
            "params": {
                "ref": { "type": "ref/resource", "uri": "repo://docs/{slug}" },
                "argument": { "name": "slug", "value": "a" },
                "context": { "arguments": {} }
            }
        }))
        .unwrap();
    assert_eq!(
        resource_response["result"]["completion"]["values"],
        json!(["architecture", "api"])
    );
}

#[test]
fn logging_set_level_enables_warning_notifications_for_denied_calls() {
    let mut edge = make_edge_with_config(10, true);
    let initialize = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }))
        .unwrap();
    assert_eq!(initialize["result"]["capabilities"]["logging"], json!({}));

    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let set_level = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "logging/setLevel",
            "params": { "level": "warning" }
        }))
        .unwrap();
    assert_eq!(set_level["result"], json!({}));
    assert!(edge.take_pending_notifications().is_empty());

    let denied = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {}
            }
        }))
        .unwrap();
    assert_eq!(denied["result"]["isError"], true);

    let notifications = edge.take_pending_notifications();
    assert_eq!(notifications.len(), 1);
    assert_eq!(notifications[0]["method"], "notifications/message");
    assert_eq!(notifications[0]["params"]["level"], "warning");
    assert_eq!(notifications[0]["params"]["logger"], "chio.mcp.tools");
    assert_eq!(notifications[0]["params"]["data"]["event"], "tool_denied");
}

#[test]
fn initialize_persists_configured_session_auth_context() {
    let mut edge = make_edge(10);
    let auth_context = SessionAuthContext::streamable_http_static_bearer(
        "static-bearer:abcd1234",
        "cafebabe",
        Some("http://localhost:3000".to_string()),
    );
    edge.set_session_auth_context(auth_context.clone());

    let initialize = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }))
        .unwrap();
    assert_eq!(
        initialize["result"]["protocolVersion"],
        MCP_PROTOCOL_VERSION
    );

    let session_id = match &edge.state {
        EdgeState::WaitingForInitialized { session_id } => session_id.clone(),
        other => panic!("expected waiting-for-initialized state, got {other:?}"),
    };

    let session = edge.kernel.session(&session_id).expect("session exists");
    assert_eq!(session.auth_context(), auth_context);
}

#[test]
fn create_message_roundtrips_through_client_with_child_lineage() {
    let mut edge = make_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "sampling": {
                    "context": {}
                }
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };
    let parent_context = OperationContext::new(
        session_id.clone(),
        RequestId::new("tool-parent"),
        edge.agent_id.clone(),
    );
    edge.kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();

    let operation = CreateMessageOperation {
        messages: vec![SamplingMessage {
            role: "user".to_string(),
            content: json!({
                "type": "text",
                "text": "Summarize the latest diff"
            }),
            meta: None,
        }],
        model_preferences: None,
        system_prompt: Some("Be concise.".to_string()),
        include_context: Some("thisServer".to_string()),
        temperature: Some(0.1),
        max_tokens: 256,
        stop_sequences: vec![],
        metadata: None,
        tools: vec![],
        tool_choice: None,
    };

    let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":\"edge-client-1\",\"result\":",
            "{\"role\":\"assistant\",\"content\":{\"type\":\"text\",\"text\":\"Summary ready.\"},\"model\":\"gpt-5.4\",\"stopReason\":\"endTurn\"}}\n"
        );
    let mut output = Vec::new();
    let result = edge
        .create_message(
            &parent_context,
            operation,
            &mut Cursor::new(input.as_bytes()),
            &mut output,
        )
        .unwrap();

    assert_eq!(result.model, "gpt-5.4");
    assert_eq!(result.content["text"], "Summary ready.");

    let lines = String::from_utf8(output).unwrap();
    let messages = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["method"], "sampling/createMessage");
    assert_eq!(messages[0]["params"]["includeContext"], "thisServer");
    assert_eq!(
        messages[0]["params"]["messages"][0]["content"]["text"],
        "Summarize the latest diff"
    );

    let session = edge.kernel.session(&session_id).unwrap();
    assert!(session
        .inflight()
        .get(&RequestId::new("tool-parent"))
        .is_some());
    assert!(session
        .inflight()
        .get(&RequestId::new("mcp-edge-req-1"))
        .is_none());
}

#[test]
fn create_message_denies_tool_use_when_not_negotiated() {
    let mut edge = make_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "sampling": {}
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };
    let parent_context = OperationContext::new(
        session_id.clone(),
        RequestId::new("tool-parent"),
        edge.agent_id.clone(),
    );
    edge.kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();

    let operation = CreateMessageOperation {
        messages: vec![SamplingMessage {
            role: "user".to_string(),
            content: json!({
                "type": "text",
                "text": "Search the docs first"
            }),
            meta: None,
        }],
        model_preferences: None,
        system_prompt: None,
        include_context: None,
        temperature: None,
        max_tokens: 128,
        stop_sequences: vec![],
        metadata: None,
        tools: vec![SamplingTool {
            name: "search_docs".to_string(),
            description: Some("Search docs".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        }],
        tool_choice: Some(SamplingToolChoice {
            mode: "auto".to_string(),
        }),
    };

    let mut output = Vec::new();
    let error = edge
        .create_message(
            &parent_context,
            operation,
            &mut Cursor::new(b""),
            &mut output,
        )
        .unwrap_err();
    match error {
        AdapterError::NestedFlowDenied(message) => {
            assert!(message.contains("tool use"));
        }
        other => panic!("unexpected error: {other}"),
    }
    assert!(output.is_empty());
    assert!(edge
        .kernel
        .session(&session_id)
        .unwrap()
        .inflight()
        .get(&RequestId::new("mcp-edge-req-1"))
        .is_none());
}

#[test]
fn serve_stdio_requests_roots_after_initialized_and_updates_session() {
    let mut edge = make_edge(10);
    let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"capabilities\":{\"roots\":{\"listChanged\":true}}}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"edge-client-1\",\"result\":{\"roots\":[{\"uri\":\"file:///workspace/project\",\"name\":\"Project\"}]}}\n"
        );

    let mut output = Vec::new();
    edge.serve_stdio(Cursor::new(input.as_bytes()), &mut output)
        .unwrap();

    let lines = String::from_utf8(output).unwrap();
    let messages = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(messages.len(), 2);
    assert_eq!(
        messages[0]["result"]["protocolVersion"],
        MCP_PROTOCOL_VERSION
    );
    assert_eq!(messages[1]["method"], "roots/list");

    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };
    let session = edge.kernel.session(&session_id).unwrap();
    assert!(session.peer_capabilities().supports_roots);
    assert!(session.peer_capabilities().roots_list_changed);
    assert_eq!(session.roots().len(), 1);
    assert_eq!(session.roots()[0].uri, "file:///workspace/project");
}

#[test]
fn restore_ready_session_requests_roots_and_updates_session() {
    let mut edge = make_edge(10);
    let session_id = SessionId::new("sess-restored-roots");
    edge.restore_ready_session(
        session_id.clone(),
        PeerCapabilities {
            supports_roots: true,
            roots_list_changed: false,
            ..PeerCapabilities::default()
        },
    )
    .unwrap();

    let (client_tx, client_rx) = mpsc::channel();
    client_tx
        .send(ClientInbound::Message(json!({
            "jsonrpc": "2.0",
            "id": "edge-client-1",
            "result": {
                "roots": [{
                    "uri": "file:///workspace/restored",
                    "name": "Restored"
                }]
            }
        })))
        .unwrap();
    drop(client_tx);

    let mut output = Vec::new();
    edge.process_pending_actions_with_channel(&client_rx, &mut output)
        .unwrap();

    let lines = String::from_utf8(output).unwrap();
    let messages = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["method"], "roots/list");

    let session = edge.kernel.session(&session_id).unwrap();
    assert_eq!(session.roots().len(), 1);
    assert_eq!(session.roots()[0].uri, "file:///workspace/restored");
    assert_eq!(session.roots()[0].name.as_deref(), Some("Restored"));
}

#[test]
fn serve_stdio_refreshes_roots_after_list_changed_notification() {
    let mut edge = make_edge(10);
    let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"capabilities\":{\"roots\":{\"listChanged\":true}}}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"edge-client-1\",\"result\":{\"roots\":[{\"uri\":\"file:///workspace/project-a\",\"name\":\"Project A\"}]}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/roots/list_changed\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"edge-client-2\",\"result\":{\"roots\":[{\"uri\":\"file:///workspace/project-b\",\"name\":\"Project B\"}]}}\n"
        );

    let mut output = Vec::new();
    edge.serve_stdio(Cursor::new(input.as_bytes()), &mut output)
        .unwrap();

    let lines = String::from_utf8(output).unwrap();
    let messages = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(messages.len(), 3);
    assert_eq!(messages[1]["method"], "roots/list");
    assert_eq!(messages[2]["method"], "roots/list");

    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };
    let session = edge.kernel.session(&session_id).unwrap();
    assert_eq!(session.roots().len(), 1);
    assert_eq!(session.roots()[0].uri, "file:///workspace/project-b");
    assert_eq!(session.roots()[0].name.as_deref(), Some("Project B"));
}

#[test]
fn refresh_roots_with_channel_defers_unrelated_requests() {
    let mut edge = make_edge(10);
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "capabilities": {
                "roots": {
                    "listChanged": true
                }
            }
        }
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let session_id = match &edge.state {
        EdgeState::Ready { session_id } => session_id.clone(),
        _ => panic!("expected ready state"),
    };

    let (client_tx, client_rx) = mpsc::channel();
    client_tx
        .send(ClientInbound::Message(json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {
                    "path": "/tmp/example.txt"
                }
            }
        })))
        .unwrap();
    client_tx
        .send(ClientInbound::Message(json!({
            "jsonrpc": "2.0",
            "id": "edge-client-1",
            "result": {
                "roots": [{
                    "uri": "file:///workspace/project",
                    "name": "Project"
                }]
            }
        })))
        .unwrap();
    drop(client_tx);

    let mut output = Vec::new();
    edge.refresh_roots_from_client_with_channel(&session_id, &client_rx, &mut output)
        .unwrap();

    let lines = String::from_utf8(output).unwrap();
    let messages = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["method"], "roots/list");

    assert_eq!(edge.deferred_client_messages.len(), 1);
    assert_eq!(edge.deferred_client_messages[0]["method"], "tools/call");

    let session = edge.kernel.session(&session_id).unwrap();
    assert_eq!(session.roots().len(), 1);
    assert_eq!(session.roots()[0].uri, "file:///workspace/project");
    assert_eq!(session.roots()[0].name.as_deref(), Some("Project"));
}
