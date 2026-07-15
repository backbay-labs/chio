use crate::adapter::*;
use crate::edge::*;
use crate::errors::*;
use crate::manifest::infer_has_side_effects;
use crate::result_mapping::*;
use crate::server::*;
use crate::url_elicitation::*;
use chio_core::session::CreateElicitationOperation;
use chio_core::{
    CompletionResult, ResourceContent, ResourceDefinition, ResourceTemplateDefinition,
};
use chio_kernel::{KernelError, PromptProvider, ResourceProvider, ToolServerConnection};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex as StdMutex};

use chio_test_support::prelude::*;

fn valid_test_public_key() -> String {
    chio_core::Keypair::from_seed(&[13u8; 32])
        .public_key()
        .to_hex()
}

#[derive(Clone)]
enum MockCallBehavior {
    Success(McpToolResult),
    UrlRequired {
        message: String,
        data: serde_json::Value,
    },
    McpError {
        code: i64,
        message: String,
    },
    ConnectionFailed(String),
}

struct MockTransport {
    tools: Vec<McpToolInfo>,
    call_behavior: MockCallBehavior,
    call_count: std::sync::Arc<AtomicUsize>,
    resources: Vec<ResourceDefinition>,
    resource_templates: Vec<ResourceTemplateDefinition>,
    prompts: Vec<chio_core::PromptDefinition>,
    capabilities: McpServerCapabilities,
}

impl MockTransport {
    fn simple(tools: Vec<McpToolInfo>, call_behavior: MockCallBehavior) -> Self {
        Self {
            tools,
            call_behavior,
            call_count: std::sync::Arc::new(AtomicUsize::new(0)),
            resources: vec![],
            resource_templates: vec![],
            prompts: vec![],
            capabilities: McpServerCapabilities::default(),
        }
    }

    fn with_capabilities(mut self, capabilities: McpServerCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    fn with_resources(mut self, resources: Vec<ResourceDefinition>) -> Self {
        self.resources = resources;
        self
    }

    fn with_resource_templates(mut self, templates: Vec<ResourceTemplateDefinition>) -> Self {
        self.resource_templates = templates;
        self
    }

    fn with_prompts(mut self, prompts: Vec<chio_core::PromptDefinition>) -> Self {
        self.prompts = prompts;
        self
    }

    fn call_count_handle(&self) -> std::sync::Arc<AtomicUsize> {
        self.call_count.clone()
    }
}

impl McpTransport for MockTransport {
    fn capabilities(&self) -> McpServerCapabilities {
        self.capabilities.clone()
    }

    fn list_tools(&self) -> Result<Vec<McpToolInfo>, AdapterError> {
        Ok(self.tools.clone())
    }

    fn call_tool(
        &self,
        tool_name: &str,
        _arguments: serde_json::Value,
    ) -> Result<McpToolResult, AdapterError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let _ = tool_name;
        match &self.call_behavior {
            MockCallBehavior::Success(result) => Ok(result.clone()),
            MockCallBehavior::UrlRequired { message, data } => Err(AdapterError::McpError {
                code: -32042,
                message: message.clone(),
                data: Some(data.clone()),
            }),
            MockCallBehavior::McpError { code, message } => Err(AdapterError::McpError {
                code: *code,
                message: message.clone(),
                data: None,
            }),
            MockCallBehavior::ConnectionFailed(msg) => {
                Err(AdapterError::ConnectionFailed(msg.clone()))
            }
        }
    }

    fn list_resources(&self) -> Result<Vec<ResourceDefinition>, AdapterError> {
        Ok(self.resources.clone())
    }

    fn list_resource_templates(&self) -> Result<Vec<ResourceTemplateDefinition>, AdapterError> {
        Ok(self.resource_templates.clone())
    }

    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, AdapterError> {
        for resource in &self.resources {
            if resource.uri == uri {
                return Ok(Some(vec![ResourceContent {
                    uri: uri.to_string(),
                    mime_type: resource.mime_type.clone(),
                    text: Some(format!("content of {uri}")),
                    blob: None,
                    annotations: None,
                }]));
            }
        }
        Ok(None)
    }

    fn list_prompts(&self) -> Result<Vec<chio_core::PromptDefinition>, AdapterError> {
        Ok(self.prompts.clone())
    }

    fn get_prompt(
        &self,
        name: &str,
        _arguments: serde_json::Value,
    ) -> Result<Option<chio_core::PromptResult>, AdapterError> {
        if self.prompts.iter().any(|p| p.name == name) {
            Ok(Some(chio_core::PromptResult {
                description: Some(format!("Prompt: {name}")),
                messages: vec![chio_core::PromptMessage {
                    role: "user".to_string(),
                    content: serde_json::json!({"type": "text", "text": format!("prompt {name}")}),
                }],
            }))
        } else {
            Ok(None)
        }
    }

    fn complete_prompt_argument(
        &self,
        _name: &str,
        _argument_name: &str,
        value: &str,
        _context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, AdapterError> {
        Ok(Some(CompletionResult {
            total: Some(1),
            has_more: false,
            values: vec![format!("{value}-completed")],
        }))
    }

    fn complete_resource_argument(
        &self,
        _uri: &str,
        _argument_name: &str,
        value: &str,
        _context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, AdapterError> {
        Ok(Some(CompletionResult {
            total: Some(1),
            has_more: false,
            values: vec![format!("{value}-res-completed")],
        }))
    }
}

struct BlockingDrainProbeTransport {
    entered_call_tx: StdMutex<Option<std::sync::mpsc::Sender<()>>>,
    release: (StdMutex<bool>, Condvar),
}

impl BlockingDrainProbeTransport {
    fn new(entered_call_tx: std::sync::mpsc::Sender<()>) -> Self {
        Self {
            entered_call_tx: StdMutex::new(Some(entered_call_tx)),
            release: (StdMutex::new(false), Condvar::new()),
        }
    }

    fn release_call(&self) {
        let (released, cvar) = &self.release;
        let mut released = released
            .lock()
            .unwrap_or_else(|error| panic!("release mutex poisoned: {error}"));
        *released = true;
        cvar.notify_all();
    }
}

impl McpTransport for BlockingDrainProbeTransport {
    fn list_tools(&self) -> Result<Vec<McpToolInfo>, AdapterError> {
        Ok(vec![])
    }

    fn call_tool(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
    ) -> Result<McpToolResult, AdapterError> {
        if let Some(tx) = self
            .entered_call_tx
            .lock()
            .unwrap_or_else(|error| panic!("entered-call mutex poisoned: {error}"))
            .take()
        {
            let _ = tx.send(());
        }

        let (released, cvar) = &self.release;
        let released = released
            .lock()
            .unwrap_or_else(|error| panic!("release mutex poisoned: {error}"));
        let _released = cvar
            .wait_while(released, |released| !*released)
            .unwrap_or_else(|error| panic!("release condvar poisoned: {error}"));
        Ok(success_result("released"))
    }

    fn drain_notifications(&self) -> Vec<serde_json::Value> {
        vec![serde_json::json!({
            "method": "notifications/probe"
        })]
    }
}

fn default_config() -> McpAdapterConfig {
    McpAdapterConfig {
        server_id: "mcp-test".into(),
        server_name: "Test".into(),
        server_version: "0.1.0".into(),
        public_key: valid_test_public_key(),
    }
}

fn text_tool_info(name: &str) -> McpToolInfo {
    McpToolInfo {
        name: name.into(),
        title: None,
        description: Some(format!("Tool {name}")),
        input_schema: serde_json::json!({"type": "object"}),
        output_schema: None,
        annotations: None,
        execution: None,
    }
}

fn success_result(text: &str) -> McpToolResult {
    McpToolResult {
        content: vec![serde_json::json!({"type": "text", "text": text})],
        structured_content: None,
        is_error: Some(false),
    }
}

#[test]
fn mcp_tool_result_to_chio_value_preserves_content_and_optional_fields() {
    let result = McpToolResult {
        content: vec![serde_json::json!({"type": "text", "text": "hello"})],
        structured_content: Some(serde_json::json!({"answer": 42})),
        is_error: Some(true),
    };

    let output = mcp_tool_result_to_chio_value(result);

    assert_eq!(output["content"][0]["text"], "hello");
    assert_eq!(output["structuredContent"]["answer"], 42);
    assert_eq!(output["isError"], true);
}

#[test]
fn mcp_tool_result_to_chio_value_defaults_absent_is_error_to_false() {
    let output = mcp_tool_result_to_chio_value(success_result("ok"));

    assert_eq!(output["content"][0]["text"], "ok");
    assert!(output.get("structuredContent").is_none());
    assert_eq!(output["isError"], false);

    let output = mcp_tool_result_to_chio_value(McpToolResult {
        content: vec![],
        structured_content: None,
        is_error: None,
    });
    assert_eq!(output["isError"], false);
    assert!(output.get("structuredContent").is_none());
}

// ---- Manifest generation tests ----

#[test]
fn generate_manifest_from_mcp() {
    let transport = MockTransport::simple(
        vec![McpToolInfo {
            name: "read_file".into(),
            title: Some("Read File".into()),
            description: Some("Read a file".into()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: Some(serde_json::json!({"type": "string"})),
            annotations: Some(serde_json::json!({"readOnlyHint": true})),
            execution: None,
        }],
        MockCallBehavior::Success(success_result("called read_file")),
    );

    let config = McpAdapterConfig {
        server_id: "mcp-fs".into(),
        server_name: "Filesystem MCP".into(),
        server_version: "1.0.0".into(),
        public_key: valid_test_public_key(),
    };

    let adapter = McpAdapter::new(config, Box::new(transport));
    let manifest = adapter
        .generate_manifest()
        .unwrap_or_else(|e| panic!("manifest: {e}"));

    assert_eq!(manifest.tools.len(), 1);
    assert_eq!(manifest.tools[0].name, "read_file");
    assert_eq!(manifest.tools[0].description, "Read File\n\nRead a file");
    assert_eq!(
        manifest.tools[0].output_schema,
        Some(serde_json::json!({"type": "string"}))
    );
    assert!(!manifest.tools[0].has_side_effects);
}

#[test]
fn manifest_uses_mcp_title_when_description_is_absent() {
    let transport = MockTransport::simple(
        vec![McpToolInfo {
            name: "search_docs".into(),
            title: Some("Search Docs".into()),
            description: None,
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            annotations: None,
            execution: None,
        }],
        MockCallBehavior::Success(success_result("ok")),
    );
    let adapter = McpAdapter::new(default_config(), Box::new(transport));

    let manifest = adapter.generate_manifest().test_unwrap();

    assert_eq!(manifest.tools[0].description, "Search Docs");
}

#[test]
fn manifest_description_only_tools_remain_unchanged() {
    let transport = MockTransport::simple(
        vec![McpToolInfo {
            name: "describe".into(),
            title: None,
            description: Some("Existing description".into()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            annotations: None,
            execution: None,
        }],
        MockCallBehavior::Success(success_result("ok")),
    );
    let adapter = McpAdapter::new(default_config(), Box::new(transport));

    let manifest = adapter.generate_manifest().test_unwrap();

    assert_eq!(manifest.tools[0].description, "Existing description");
}

#[test]
fn manifest_multiple_tools_preserves_order() {
    let tools = vec![
        text_tool_info("alpha"),
        text_tool_info("beta"),
        text_tool_info("gamma"),
    ];
    let transport = MockTransport::simple(tools, MockCallBehavior::Success(success_result("ok")));
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let manifest = adapter
        .generate_manifest()
        .unwrap_or_else(|e| panic!("{e}"));
    let names: Vec<&str> = manifest.tools.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, vec!["alpha", "beta", "gamma"]);
}

#[test]
fn adapted_server_reports_read_only_from_manifest_hints() {
    let transport = MockTransport::simple(
        vec![
            McpToolInfo {
                name: "read_file".into(),
                title: None,
                description: Some("Read a file".into()),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                annotations: Some(serde_json::json!({"readOnlyHint": true})),
                execution: None,
            },
            text_tool_info("write_file"),
        ],
        MockCallBehavior::Success(success_result("ok")),
    );
    let server =
        AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport))).test_unwrap();

    // The readOnlyHint-annotated tool is exempt from side-effect handling;
    // an unannotated tool and an unknown name stay side-effecting.
    assert!(server.tool_is_read_only("read_file"));
    assert!(!server.tool_is_read_only("write_file"));
    assert!(!server.tool_is_read_only("missing_tool"));
}

#[test]
fn manifest_infers_side_effects_from_annotations() {
    let tool_readonly = McpToolInfo {
        name: "safe".into(),
        title: None,
        description: Some("Safe".into()),
        input_schema: serde_json::json!({"type": "object"}),
        output_schema: None,
        annotations: Some(serde_json::json!({"readOnlyHint": true})),
        execution: None,
    };
    let tool_write = McpToolInfo {
        name: "danger".into(),
        title: None,
        description: Some("Danger".into()),
        input_schema: serde_json::json!({"type": "object"}),
        output_schema: None,
        annotations: Some(serde_json::json!({"readOnlyHint": false})),
        execution: None,
    };
    let tool_none = McpToolInfo {
        name: "unknown".into(),
        title: None,
        description: Some("Unknown".into()),
        input_schema: serde_json::json!({"type": "object"}),
        output_schema: None,
        annotations: None,
        execution: None,
    };
    let transport = MockTransport::simple(
        vec![tool_readonly, tool_write, tool_none],
        MockCallBehavior::Success(success_result("ok")),
    );
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let manifest = adapter
        .generate_manifest()
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !manifest.tools[0].has_side_effects,
        "readOnly=true should be no side effects"
    );
    assert!(
        manifest.tools[1].has_side_effects,
        "readOnly=false should have side effects"
    );
    assert!(
        manifest.tools[2].has_side_effects,
        "missing annotations defaults to side effects (fail-closed)"
    );
}

#[test]
fn manifest_conflicting_readonly_and_destructive_annotations_fail_closed() {
    let tool_conflicting = McpToolInfo {
        name: "conflicting".into(),
        title: None,
        description: Some("Conflicting safety hints".into()),
        input_schema: serde_json::json!({"type": "object"}),
        output_schema: None,
        annotations: Some(serde_json::json!({
            "readOnlyHint": true,
            "destructiveHint": true,
        })),
        execution: None,
    };
    let transport = MockTransport::simple(
        vec![tool_conflicting],
        MockCallBehavior::Success(success_result("ok")),
    );
    let adapter = McpAdapter::new(default_config(), Box::new(transport));

    let manifest = adapter.generate_manifest().test_unwrap();

    assert!(
        manifest.tools[0].has_side_effects,
        "destructiveHint=true must override readOnlyHint=true"
    );
}

#[test]
fn manifest_empty_tools_list_rejected() {
    let transport = MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")));
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let err = adapter.generate_manifest().test_unwrap_err();
    assert!(matches!(err, AdapterError::ManifestError(_)));
}

#[test]
fn manifest_rejects_non_object_mcp_input_schema() {
    let transport = MockTransport::simple(
        vec![McpToolInfo {
            name: "bad_schema".into(),
            title: None,
            description: Some("Bad schema".into()),
            input_schema: serde_json::json!(["not", "an", "object"]),
            output_schema: None,
            annotations: None,
            execution: None,
        }],
        MockCallBehavior::Success(success_result("ok")),
    );
    let adapter = McpAdapter::new(default_config(), Box::new(transport));

    let err = adapter.generate_manifest().test_unwrap_err();

    assert!(matches!(err, AdapterError::ParseError(_)));
    assert!(err.to_string().contains("inputSchema"));
}

#[test]
fn manifest_rejects_non_object_mcp_output_schema() {
    let transport = MockTransport::simple(
        vec![McpToolInfo {
            name: "bad_output".into(),
            title: None,
            description: Some("Bad output schema".into()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: Some(serde_json::json!("not an object")),
            annotations: None,
            execution: None,
        }],
        MockCallBehavior::Success(success_result("ok")),
    );
    let adapter = McpAdapter::new(default_config(), Box::new(transport));

    let err = adapter.generate_manifest().test_unwrap_err();

    assert!(matches!(err, AdapterError::ParseError(_)));
    assert!(err.to_string().contains("outputSchema"));
}

#[test]
fn manifest_schema_is_correct() {
    let transport = MockTransport::simple(
        vec![text_tool_info("t")],
        MockCallBehavior::Success(success_result("ok")),
    );
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let manifest = adapter
        .generate_manifest()
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(manifest.schema, "chio.manifest.v1");
}

#[test]
fn manifest_carries_server_metadata() {
    let public_key = valid_test_public_key();
    let config = McpAdapterConfig {
        server_id: "my-server".into(),
        server_name: "My Server".into(),
        server_version: "2.0.0".into(),
        public_key: public_key.clone(),
    };
    let transport = MockTransport::simple(
        vec![text_tool_info("t")],
        MockCallBehavior::Success(success_result("ok")),
    );
    let adapter = McpAdapter::new(config, Box::new(transport));
    let manifest = adapter
        .generate_manifest()
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(manifest.server_id, "my-server");
    assert_eq!(manifest.name, "My Server");
    assert_eq!(manifest.version, "2.0.0");
    assert_eq!(manifest.public_key, public_key);
}

// ---- Invocation tests ----

#[test]
fn invoke_tool_via_adapter() {
    let transport = MockTransport::simple(
        vec![],
        MockCallBehavior::Success(success_result("called some_tool")),
    );
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let result = adapter
        .invoke("some_tool", serde_json::json!({}))
        .unwrap_or_else(|e| panic!("invoke: {e}"));

    let content = result["content"]
        .as_array()
        .unwrap_or_else(|| panic!("expected content array"));
    assert_eq!(content.len(), 1);
    assert_eq!(content[0]["text"], "called some_tool");
}

#[test]
fn invoke_returns_structured_content_when_present() {
    let result = McpToolResult {
        content: vec![serde_json::json!({"type": "text", "text": "hello"})],
        structured_content: Some(serde_json::json!({"weather": "sunny"})),
        is_error: None,
    };
    let transport = MockTransport::simple(vec![], MockCallBehavior::Success(result));
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let output = adapter
        .invoke("t", serde_json::json!({}))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(output["structuredContent"]["weather"], "sunny");
}

#[test]
fn invoke_returns_is_error_flag() {
    let result = McpToolResult {
        content: vec![serde_json::json!({"type": "text", "text": "fail"})],
        structured_content: None,
        is_error: Some(true),
    };
    let transport = MockTransport::simple(vec![], MockCallBehavior::Success(result));
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let output = adapter
        .invoke("t", serde_json::json!({}))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(output["isError"], true);
}

#[test]
fn invoke_defaults_missing_is_error_to_false() {
    let result = McpToolResult {
        content: vec![serde_json::json!({"type": "text", "text": "ok"})],
        structured_content: None,
        is_error: None,
    };
    let transport = MockTransport::simple(vec![], MockCallBehavior::Success(result));
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let output = adapter
        .invoke("t", serde_json::json!({}))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(output["isError"], false);
}

#[test]
fn invoke_multiple_content_chunks() {
    let result = McpToolResult {
        content: vec![
            serde_json::json!({"type": "text", "text": "chunk1"}),
            serde_json::json!({"type": "text", "text": "chunk2"}),
            serde_json::json!({"type": "text", "text": "chunk3"}),
        ],
        structured_content: None,
        is_error: Some(false),
    };
    let transport = MockTransport::simple(vec![], MockCallBehavior::Success(result));
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let output = adapter
        .invoke("t", serde_json::json!({}))
        .unwrap_or_else(|e| panic!("{e}"));
    let content = output["content"]
        .as_array()
        .unwrap_or_else(|| panic!("content"));
    assert_eq!(content.len(), 3);
    assert_eq!(content[2]["text"], "chunk3");
}

// ---- Error path tests ----

#[test]
fn invoke_connection_failed_produces_adapter_error() {
    let transport = MockTransport::simple(
        vec![],
        MockCallBehavior::ConnectionFailed("pipe broken".to_string()),
    );
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let err = adapter.invoke("t", serde_json::json!({})).test_unwrap_err();
    assert!(matches!(err, AdapterError::ConnectionFailed(_)));
}

#[test]
fn invoke_mcp_error_non_url_code_surfaces_as_mcp_error() {
    let transport = MockTransport::simple(
        vec![],
        MockCallBehavior::McpError {
            code: -32601,
            message: "method not found".to_string(),
        },
    );
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let err = adapter.invoke("t", serde_json::json!({})).test_unwrap_err();
    match err {
        AdapterError::McpError { code, message, .. } => {
            assert_eq!(code, -32601);
            assert_eq!(message, "method not found");
        }
        other => panic!("unexpected: {other}"),
    }
}

#[test]
fn map_tool_invocation_error_connection_failed_becomes_request_incomplete() {
    let err = map_tool_invocation_error(AdapterError::ConnectionFailed("oops".into()));
    assert!(matches!(err, KernelError::RequestIncomplete(_)));
}

#[test]
fn map_tool_invocation_error_parse_error_becomes_request_incomplete() {
    let err = map_tool_invocation_error(AdapterError::ParseError("bad json".into()));
    assert!(matches!(err, KernelError::RequestIncomplete(_)));
}

#[test]
fn map_tool_invocation_error_request_cancelled_preserved() {
    let request_id = chio_core::session::RequestId::from("req-123".to_string());
    let err = map_tool_invocation_error(AdapterError::RequestCancelled {
        request_id: request_id.clone(),
        reason: "user cancelled".into(),
    });
    match err {
        KernelError::RequestCancelled {
            request_id: id,
            reason,
        } => {
            assert_eq!(id, request_id);
            assert_eq!(reason, "user cancelled");
        }
        other => panic!("unexpected: {other}"),
    }
}

#[test]
fn map_tool_invocation_error_generic_mcp_error_becomes_tool_server_error() {
    let err = map_tool_invocation_error(AdapterError::McpError {
        code: -32000,
        message: "custom error".into(),
        data: None,
    });
    assert!(matches!(err, KernelError::ToolServerError(_)));
}

// ---- URL elicitation error mapping ----

#[test]
fn adapted_server_exposes_manifest_tool_names() {
    let transport = MockTransport::simple(
        vec![text_tool_info("read_file"), text_tool_info("write_file")],
        MockCallBehavior::Success(success_result("called read_file")),
    );
    let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
        .unwrap_or_else(|e| panic!("adapted server: {e}"));
    assert_eq!(adapted.server_id(), "mcp-test");
    assert_eq!(
        adapted.tool_names(),
        vec!["read_file".to_string(), "write_file".to_string()]
    );
}

#[tokio::test]
async fn adapted_server_rejects_manifest_unknown_tool_without_contacting_upstream() {
    let transport = MockTransport::simple(
        vec![text_tool_info("known_tool")],
        MockCallBehavior::Success(success_result("unexpected")),
    );
    let call_count = transport.call_count_handle();
    let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
        .unwrap_or_else(|e| panic!("adapted server: {e}"));

    let error = adapted
        .invoke("unlisted_tool", serde_json::json!({}), None)
        .await
        .test_unwrap_err();

    assert!(matches!(
        error,
        KernelError::ToolNotRegistered(ref tool) if tool == "unlisted_tool"
    ));
    assert_eq!(call_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn adapted_server_maps_url_required_errors_into_kernel_errors() {
    let transport = MockTransport::simple(
        vec![McpToolInfo {
            name: "authorize".into(),
            title: None,
            description: Some("Requires URL elicitation".into()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            annotations: None,
            execution: None,
        }],
        MockCallBehavior::UrlRequired {
            message: "URL elicitation is required for this operation".to_string(),
            data: serde_json::json!({
                "elicitations": [{
                    "mode": "url",
                    "message": "Complete authorization in your browser",
                    "url": "https://example.com/authorize",
                    "elicitationId": "elicit-auth"
                }]
            }),
        },
    );

    let config = McpAdapterConfig {
        server_id: "mcp-auth".into(),
        server_name: "Auth".into(),
        server_version: "0.1.0".into(),
        public_key: valid_test_public_key(),
    };

    let adapted = AdaptedMcpServer::new(McpAdapter::new(config, Box::new(transport)))
        .unwrap_or_else(|e| panic!("adapted server: {e}"));
    let error = adapted
        .invoke("authorize", serde_json::json!({}), None)
        .await
        .test_unwrap_err();

    match error {
        KernelError::UrlElicitationsRequired {
            message,
            elicitations,
        } => {
            assert_eq!(message, "URL elicitation is required for this operation");
            assert_eq!(elicitations.len(), 1);
            assert!(matches!(
                &elicitations[0],
                CreateElicitationOperation::Url { elicitation_id, .. }
                if elicitation_id == "elicit-auth"
            ));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn url_elicitation_error_missing_data_falls_back_to_tool_server_error() {
    let err = parse_url_elicitation_required_error("missing data".into(), None);
    assert!(err.is_err());
}

#[test]
fn url_elicitation_error_missing_elicitations_key_falls_back() {
    let err = parse_url_elicitation_required_error(
        "bad shape".into(),
        Some(serde_json::json!({"other": 1})),
    );
    assert!(err.is_err());
}

#[test]
fn url_elicitation_error_empty_elicitations_falls_back() {
    let err = parse_url_elicitation_required_error(
        "empty".into(),
        Some(serde_json::json!({"elicitations": []})),
    );
    assert!(err.is_err());
}

#[test]
fn url_elicitation_error_rejects_malformed_url_elicitations() {
    let cases = [
        (
            serde_json::json!({
                "elicitations": [{
                    "mode": "url",
                    "message": "Authorize",
                    "url": "https://example.com/authorize",
                    "elicitationId": " elicit-auth "
                }]
            }),
            "data.elicitations[0].elicitationId must not include leading or trailing whitespace",
        ),
        (
            serde_json::json!({
                "elicitations": [{
                    "mode": "url",
                    "message": "Authorize",
                    "url": "javascript:alert(1)",
                    "elicitationId": "elicit-auth"
                }]
            }),
            "data.elicitations[0].url must use http or https",
        ),
        (
            serde_json::json!({
                "elicitations": [{
                    "mode": "url",
                    "message": "Authorize",
                    "url": "https://user:secret@example.com/authorize",
                    "elicitationId": "elicit-auth"
                }]
            }),
            "data.elicitations[0].url must not include userinfo",
        ),
    ];

    for (data, expected) in cases {
        let err = parse_url_elicitation_required_error("bad URL elicitation".into(), Some(data))
            .test_unwrap_err();
        assert!(
            err.contains(expected),
            "expected error containing {expected:?}, got {err:?}"
        );
    }
}

// ---- AdaptedMcpServer ToolServerConnection ----

#[tokio::test]
async fn adapted_server_invoke_delegates_to_adapter() {
    let transport = MockTransport::simple(
        vec![text_tool_info("echo")],
        MockCallBehavior::Success(success_result("echoed")),
    );
    let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
        .unwrap_or_else(|e| panic!("{e}"));
    let result = adapted
        .invoke("echo", serde_json::json!({}), None)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(result["content"][0]["text"], "echoed");
}

#[test]
fn adapted_server_manifest_clone() {
    let transport = MockTransport::simple(
        vec![text_tool_info("t1")],
        MockCallBehavior::Success(success_result("ok")),
    );
    let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
        .unwrap_or_else(|e| panic!("{e}"));
    let clone = adapted.manifest_clone();
    assert_eq!(clone.server_id, adapted.manifest().server_id);
    assert_eq!(clone.tools.len(), adapted.manifest().tools.len());
}

// ---- Resource provider tests ----

#[test]
fn resource_provider_only_created_when_supported() {
    let transport = MockTransport::simple(
        vec![text_tool_info("t")],
        MockCallBehavior::Success(success_result("ok")),
    );
    let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(adapted.resource_provider().is_none());
}

#[test]
fn resource_provider_created_when_supported() {
    let transport = MockTransport::simple(
        vec![text_tool_info("t")],
        MockCallBehavior::Success(success_result("ok")),
    )
    .with_capabilities(McpServerCapabilities {
        resources_supported: true,
        ..Default::default()
    })
    .with_resources(vec![ResourceDefinition {
        uri: "test://doc".into(),
        name: "Doc".into(),
        title: None,
        description: None,
        mime_type: Some("text/plain".into()),
        size: None,
        annotations: None,
        icons: None,
    }]);
    let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
        .unwrap_or_else(|e| panic!("{e}"));
    let provider = adapted.resource_provider();
    assert!(provider.is_some());
    let provider = provider.unwrap_or_else(|| panic!("expected provider"));
    let resources = provider.list_resources();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].uri, "test://doc");
}

#[test]
fn resource_provider_read_resource() {
    let transport = MockTransport::simple(
        vec![text_tool_info("t")],
        MockCallBehavior::Success(success_result("ok")),
    )
    .with_capabilities(McpServerCapabilities {
        resources_supported: true,
        ..Default::default()
    })
    .with_resources(vec![ResourceDefinition {
        uri: "test://readme".into(),
        name: "Readme".into(),
        title: None,
        description: None,
        mime_type: Some("text/markdown".into()),
        size: None,
        annotations: None,
        icons: None,
    }]);
    let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
        .unwrap_or_else(|e| panic!("{e}"));
    let provider = adapted
        .resource_provider()
        .unwrap_or_else(|| panic!("provider"));
    let content = provider
        .read_resource("test://readme")
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("expected content"));
    assert_eq!(content.len(), 1);
    assert!(content[0]
        .text
        .as_deref()
        .unwrap_or("")
        .contains("test://readme"));
}

#[test]
fn resource_provider_templates_list() {
    let transport = MockTransport::simple(
        vec![text_tool_info("t")],
        MockCallBehavior::Success(success_result("ok")),
    )
    .with_capabilities(McpServerCapabilities {
        resources_supported: true,
        ..Default::default()
    })
    .with_resource_templates(vec![ResourceTemplateDefinition {
        uri_template: "test://docs/{slug}".into(),
        name: "Doc Template".into(),
        title: None,
        description: Some("Parameterized doc".into()),
        mime_type: Some("text/markdown".into()),
        annotations: None,
        icons: None,
    }]);
    let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
        .unwrap_or_else(|e| panic!("{e}"));
    let provider = adapted
        .resource_provider()
        .unwrap_or_else(|| panic!("provider"));
    let templates = provider.list_resource_templates();
    assert_eq!(templates.len(), 1);
    assert_eq!(templates[0].uri_template, "test://docs/{slug}");
}

#[test]
fn resource_provider_complete_resource_argument() {
    let transport = MockTransport::simple(
        vec![text_tool_info("t")],
        MockCallBehavior::Success(success_result("ok")),
    )
    .with_capabilities(McpServerCapabilities {
        resources_supported: true,
        ..Default::default()
    });
    let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
        .unwrap_or_else(|e| panic!("{e}"));
    let provider = adapted
        .resource_provider()
        .unwrap_or_else(|| panic!("provider"));
    let result = provider
        .complete_resource_argument("test://docs/{slug}", "slug", "read", &serde_json::json!({}))
        .unwrap_or_else(|e| panic!("{e}"));
    let result = result.unwrap_or_else(|| panic!("expected completion"));
    assert_eq!(result.values, vec!["read-res-completed".to_string()]);
}

// ---- Prompt provider tests ----

#[test]
fn prompt_provider_only_created_when_supported() {
    let transport = MockTransport::simple(
        vec![text_tool_info("t")],
        MockCallBehavior::Success(success_result("ok")),
    );
    let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(adapted.prompt_provider().is_none());
}

#[test]
fn prompt_provider_created_when_supported() {
    let transport = MockTransport::simple(
        vec![text_tool_info("t")],
        MockCallBehavior::Success(success_result("ok")),
    )
    .with_capabilities(McpServerCapabilities {
        prompts_supported: true,
        ..Default::default()
    })
    .with_prompts(vec![chio_core::PromptDefinition {
        name: "greet".into(),
        title: None,
        description: Some("Greeting".into()),
        arguments: vec![],
        icons: None,
    }]);
    let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
        .unwrap_or_else(|e| panic!("{e}"));
    let provider = adapted
        .prompt_provider()
        .unwrap_or_else(|| panic!("prompt provider"));
    let prompts = provider.list_prompts();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].name, "greet");
}

#[test]
fn prompt_provider_get_prompt() {
    let transport = MockTransport::simple(
        vec![text_tool_info("t")],
        MockCallBehavior::Success(success_result("ok")),
    )
    .with_capabilities(McpServerCapabilities {
        prompts_supported: true,
        ..Default::default()
    })
    .with_prompts(vec![chio_core::PromptDefinition {
        name: "greet".into(),
        title: None,
        description: Some("Greeting".into()),
        arguments: vec![],
        icons: None,
    }]);
    let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
        .unwrap_or_else(|e| panic!("{e}"));
    let provider = adapted
        .prompt_provider()
        .unwrap_or_else(|| panic!("prompt provider"));
    let result = provider
        .get_prompt("greet", serde_json::json!({}))
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("expected prompt"));
    assert_eq!(result.messages.len(), 1);
}

#[test]
fn prompt_provider_get_unknown_prompt_returns_none() {
    let transport = MockTransport::simple(
        vec![text_tool_info("t")],
        MockCallBehavior::Success(success_result("ok")),
    )
    .with_capabilities(McpServerCapabilities {
        prompts_supported: true,
        ..Default::default()
    });
    let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
        .unwrap_or_else(|e| panic!("{e}"));
    let provider = adapted
        .prompt_provider()
        .unwrap_or_else(|| panic!("prompt provider"));
    let result = provider
        .get_prompt("nonexistent", serde_json::json!({}))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(result.is_none());
}

#[test]
fn prompt_provider_complete_argument() {
    let transport = MockTransport::simple(
        vec![text_tool_info("t")],
        MockCallBehavior::Success(success_result("ok")),
    )
    .with_capabilities(McpServerCapabilities {
        prompts_supported: true,
        ..Default::default()
    });
    let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
        .unwrap_or_else(|e| panic!("{e}"));
    let provider = adapted
        .prompt_provider()
        .unwrap_or_else(|| panic!("prompt provider"));
    let result = provider
        .complete_prompt_argument("greet", "name", "Al", &serde_json::json!({}))
        .unwrap_or_else(|e| panic!("{e}"));
    let result = result.unwrap_or_else(|| panic!("expected completion"));
    assert_eq!(result.values, vec!["Al-completed".to_string()]);
}

// ---- SerializedMcpTransport tests ----

#[test]
fn serialized_transport_delegates_list_tools() {
    let inner = MockTransport::simple(
        vec![text_tool_info("a"), text_tool_info("b")],
        MockCallBehavior::Success(success_result("ok")),
    );
    let serialized = SerializedMcpTransport::from_arc(Arc::new(inner));
    let tools = serialized.list_tools().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(tools.len(), 2);
}

#[test]
fn serialized_transport_delegates_call_tool() {
    let inner = MockTransport::simple(
        vec![],
        MockCallBehavior::Success(success_result("serialized call")),
    );
    let serialized = SerializedMcpTransport::from_arc(Arc::new(inner));
    let result = serialized
        .call_tool("t", serde_json::json!({}))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(result.content[0]["text"], "serialized call");
}

#[test]
fn serialized_transport_delegates_capabilities() {
    let inner = MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")))
        .with_capabilities(McpServerCapabilities {
            prompts_supported: true,
            resources_supported: true,
            ..Default::default()
        });
    let serialized = SerializedMcpTransport::from_arc(Arc::new(inner));
    let caps = serialized.capabilities();
    assert!(caps.prompts_supported);
    assert!(caps.resources_supported);
}

#[test]
fn serialized_transport_delegates_list_resources() {
    let inner = MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")))
        .with_resources(vec![ResourceDefinition {
            uri: "test://r".into(),
            name: "R".into(),
            title: None,
            description: None,
            mime_type: None,
            size: None,
            annotations: None,
            icons: None,
        }]);
    let serialized = SerializedMcpTransport::from_arc(Arc::new(inner));
    let resources = serialized
        .list_resources()
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(resources.len(), 1);
}

#[test]
fn serialized_transport_delegates_list_prompts() {
    let inner = MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")))
        .with_prompts(vec![chio_core::PromptDefinition {
            name: "p".into(),
            title: None,
            description: None,
            arguments: vec![],
            icons: None,
        }]);
    let serialized = SerializedMcpTransport::from_arc(Arc::new(inner));
    let prompts = serialized.list_prompts().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(prompts.len(), 1);
}

#[test]
fn serialized_transport_serializes_notification_drain_with_active_request() {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let inner = Arc::new(BlockingDrainProbeTransport::new(entered_tx));
    let serialized = Arc::new(SerializedMcpTransport::from_arc(inner.clone()));

    let call_serialized = serialized.clone();
    let call_thread =
        std::thread::spawn(move || call_serialized.call_tool("t", serde_json::json!({})));
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("serialized call did not enter transport: {error}"));

    let (drained_tx, drained_rx) = std::sync::mpsc::channel();
    let drain_serialized = serialized.clone();
    let drain_thread = std::thread::spawn(move || {
        let notifications = drain_serialized.drain_notifications();
        let _ = drained_tx.send(notifications);
    });

    assert!(
        drained_rx
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err(),
        "notification drain bypassed the active request gate"
    );

    inner.release_call();
    let call_result = call_thread
        .join()
        .unwrap_or_else(|_| panic!("call thread panicked"));
    call_result.unwrap_or_else(|error| panic!("call_tool failed: {error}"));
    let notifications = drained_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap_or_else(|error| panic!("drain did not complete after release: {error}"));
    assert_eq!(notifications.len(), 1);
    assert_eq!(notifications[0]["method"], "notifications/probe");
    drain_thread
        .join()
        .unwrap_or_else(|_| panic!("drain thread panicked"));
}

// ---- Chunked output tests ----

#[test]
fn chunked_output_each_chunk_in_content_array() {
    let result = McpToolResult {
        content: vec![
            serde_json::json!({"type": "text", "text": "part-1"}),
            serde_json::json!({"type": "text", "text": "part-2"}),
            serde_json::json!({"type": "text", "text": "part-3"}),
            serde_json::json!({"type": "text", "text": "part-4"}),
            serde_json::json!({"type": "text", "text": "part-5"}),
        ],
        structured_content: None,
        is_error: Some(false),
    };
    let transport = MockTransport::simple(vec![], MockCallBehavior::Success(result));
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let output = adapter
        .invoke("chunked_tool", serde_json::json!({}))
        .unwrap_or_else(|e| panic!("{e}"));
    let content = output["content"]
        .as_array()
        .unwrap_or_else(|| panic!("expected content array"));
    assert_eq!(content.len(), 5);
    for (i, chunk) in content.iter().enumerate() {
        assert_eq!(chunk["text"], format!("part-{}", i + 1));
    }
}

#[test]
fn chunked_output_mixed_types() {
    let result = McpToolResult {
        content: vec![
            serde_json::json!({"type": "text", "text": "hello"}),
            serde_json::json!({"type": "image", "data": "base64data", "mimeType": "image/png"}),
        ],
        structured_content: None,
        is_error: Some(false),
    };
    let transport = MockTransport::simple(vec![], MockCallBehavior::Success(result));
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let output = adapter
        .invoke("mixed", serde_json::json!({}))
        .unwrap_or_else(|e| panic!("{e}"));
    let content = output["content"]
        .as_array()
        .unwrap_or_else(|| panic!("expected content array"));
    assert_eq!(content.len(), 2);
    assert_eq!(content[0]["type"], "text");
    assert_eq!(content[1]["type"], "image");
}

// ---- Denial receipt / structured error tests ----

#[test]
fn error_path_mcp_error_has_structured_code_and_message() {
    let transport = MockTransport::simple(
        vec![],
        MockCallBehavior::McpError {
            code: -32600,
            message: "invalid request shape".to_string(),
        },
    );
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let err = adapter.invoke("t", serde_json::json!({})).test_unwrap_err();
    let display = format!("{err}");
    assert!(
        display.contains("-32600"),
        "error display should contain code"
    );
    assert!(
        display.contains("invalid request shape"),
        "error display should contain message"
    );
}

#[tokio::test]
async fn adapted_server_mcp_error_maps_to_tool_server_error() {
    let transport = MockTransport::simple(
        vec![text_tool_info("t")],
        MockCallBehavior::McpError {
            code: -32001,
            message: "internal MCP error".to_string(),
        },
    );
    let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
        .unwrap_or_else(|e| panic!("{e}"));
    let err = adapted
        .invoke("t", serde_json::json!({}), None)
        .await
        .test_unwrap_err();
    assert!(matches!(err, KernelError::ToolServerError(_)));
}

#[tokio::test]
async fn adapted_server_connection_error_maps_to_request_incomplete() {
    let transport = MockTransport::simple(
        vec![text_tool_info("t")],
        MockCallBehavior::ConnectionFailed("network down".to_string()),
    );
    let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
        .unwrap_or_else(|e| panic!("{e}"));
    let err = adapted
        .invoke("t", serde_json::json!({}), None)
        .await
        .test_unwrap_err();
    assert!(matches!(err, KernelError::RequestIncomplete(_)));
}

// ---- AdapterError display tests ----

#[test]
fn adapter_error_display_includes_structured_details() {
    let err = AdapterError::McpError {
        code: -32042,
        message: "url elicitation required".into(),
        data: Some(serde_json::json!({"key": "value"})),
    };
    let display = format!("{err}");
    assert!(display.contains("-32042"));
    assert!(display.contains("url elicitation required"));
}

#[test]
fn adapter_error_tool_not_found() {
    let err = AdapterError::ToolNotFound("missing_tool".into());
    let display = format!("{err}");
    assert!(display.contains("missing_tool"));
}

#[test]
fn adapter_error_nested_flow_denied() {
    let err = AdapterError::NestedFlowDenied("no bridge".into());
    let display = format!("{err}");
    assert!(display.contains("no bridge"));
}

// ---- Capabilities tests ----

#[test]
fn adapter_capabilities_exposed() {
    let caps = McpServerCapabilities {
        tools_list_changed: true,
        resources_supported: true,
        prompts_supported: true,
        logging_supported: true,
        completions_supported: true,
        resources_subscribe: true,
        resources_list_changed: true,
        prompts_list_changed: true,
    };
    let transport = MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")))
        .with_capabilities(caps.clone());
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let result = adapter.capabilities();
    assert_eq!(result, caps);
}

#[test]
fn upstream_capabilities_exposed_through_adapted_server() {
    let caps = McpServerCapabilities {
        resources_supported: true,
        prompts_supported: true,
        ..Default::default()
    };
    let transport = MockTransport::simple(
        vec![text_tool_info("t")],
        MockCallBehavior::Success(success_result("ok")),
    )
    .with_capabilities(caps);
    let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
        .unwrap_or_else(|e| panic!("{e}"));
    let upstream = adapted.upstream_capabilities();
    assert!(upstream.resources_supported);
    assert!(upstream.prompts_supported);
}

// ---- Notification source tests ----

#[test]
fn notification_source_returns_chio_transport() {
    let transport = MockTransport::simple(
        vec![text_tool_info("t")],
        MockCallBehavior::Success(success_result("ok")),
    );
    let adapted = AdaptedMcpServer::new(McpAdapter::new(default_config(), Box::new(transport)))
        .unwrap_or_else(|e| panic!("{e}"));
    let source = adapted.notification_source();
    let notifications = source.drain_notifications();
    assert!(notifications.is_empty());
}

// ---- infer_has_side_effects tests ----

#[test]
fn infer_side_effects_no_annotations_defaults_true() {
    assert!(infer_has_side_effects(None));
}

#[test]
fn infer_side_effects_empty_object_defaults_true() {
    let ann = serde_json::json!({});
    assert!(infer_has_side_effects(Some(&ann)));
}

#[test]
fn infer_side_effects_readonly_true_returns_false() {
    let ann = serde_json::json!({"readOnlyHint": true});
    assert!(!infer_has_side_effects(Some(&ann)));
}

#[test]
fn infer_side_effects_readonly_false_returns_true() {
    let ann = serde_json::json!({"readOnlyHint": false});
    assert!(infer_has_side_effects(Some(&ann)));
}

#[test]
fn infer_side_effects_readonly_non_bool_defaults_true() {
    let ann = serde_json::json!({"readOnlyHint": "yes"});
    assert!(infer_has_side_effects(Some(&ann)));
}

#[test]
fn infer_side_effects_destructive_true_overrides_readonly_true() {
    let ann = serde_json::json!({
        "readOnlyHint": true,
        "destructiveHint": true,
    });
    assert!(infer_has_side_effects(Some(&ann)));
}

#[test]
fn infer_side_effects_malformed_destructive_hint_fails_closed() {
    let ann = serde_json::json!({
        "readOnlyHint": true,
        "destructiveHint": "no",
    });
    assert!(infer_has_side_effects(Some(&ann)));
}

// ---- Direct adapter delegation tests ----

#[test]
fn adapter_list_resources_delegates() {
    let transport = MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")))
        .with_resources(vec![ResourceDefinition {
            uri: "test://r1".into(),
            name: "R1".into(),
            title: None,
            description: None,
            mime_type: None,
            size: None,
            annotations: None,
            icons: None,
        }]);
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let resources = adapter.list_resources().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(resources.len(), 1);
}

#[test]
fn adapter_list_resource_templates_delegates() {
    let transport = MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")))
        .with_resource_templates(vec![ResourceTemplateDefinition {
            uri_template: "test://{id}".into(),
            name: "T".into(),
            title: None,
            description: None,
            mime_type: None,
            annotations: None,
            icons: None,
        }]);
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let templates = adapter
        .list_resource_templates()
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(templates.len(), 1);
}

#[test]
fn adapter_read_resource_delegates() {
    let transport = MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")))
        .with_resources(vec![ResourceDefinition {
            uri: "test://doc".into(),
            name: "Doc".into(),
            title: None,
            description: None,
            mime_type: Some("text/plain".into()),
            size: None,
            annotations: None,
            icons: None,
        }]);
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let content = adapter
        .read_resource("test://doc")
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("expected content"));
    assert_eq!(content.len(), 1);
}

#[test]
fn adapter_list_prompts_delegates() {
    let transport = MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")))
        .with_prompts(vec![chio_core::PromptDefinition {
            name: "p1".into(),
            title: None,
            description: None,
            arguments: vec![],
            icons: None,
        }]);
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let prompts = adapter.list_prompts().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(prompts.len(), 1);
}

#[test]
fn adapter_get_prompt_delegates() {
    let transport = MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")))
        .with_prompts(vec![chio_core::PromptDefinition {
            name: "p1".into(),
            title: None,
            description: None,
            arguments: vec![],
            icons: None,
        }]);
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let result = adapter
        .get_prompt("p1", serde_json::json!({}))
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("expected prompt"));
    assert_eq!(result.messages.len(), 1);
}

#[test]
fn adapter_complete_prompt_argument_delegates() {
    let transport = MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")));
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let result = adapter
        .complete_prompt_argument("p", "arg", "val", &serde_json::json!({}))
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("expected completion"));
    assert_eq!(result.values, vec!["val-completed"]);
}

#[test]
fn adapter_complete_resource_argument_delegates() {
    let transport = MockTransport::simple(vec![], MockCallBehavior::Success(success_result("ok")));
    let adapter = McpAdapter::new(default_config(), Box::new(transport));
    let result = adapter
        .complete_resource_argument("u", "arg", "val", &serde_json::json!({}))
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("expected completion"));
    assert_eq!(result.values, vec!["val-res-completed"]);
}

// ---- McpServerCapabilities tests ----

#[test]
fn capabilities_from_initialize_result_parses_all_fields() {
    let result = serde_json::json!({
        "capabilities": {
            "tools": {"listChanged": true},
            "resources": {"subscribe": true, "listChanged": true},
            "prompts": {"listChanged": true},
            "completions": {},
            "logging": {}
        }
    });
    let caps = McpServerCapabilities::from_initialize_result(&result);
    assert!(caps.tools_list_changed);
    assert!(caps.resources_supported);
    assert!(caps.resources_subscribe);
    assert!(caps.resources_list_changed);
    assert!(caps.prompts_supported);
    assert!(caps.prompts_list_changed);
    assert!(caps.completions_supported);
    assert!(caps.logging_supported);
}

#[test]
fn capabilities_from_empty_result_all_false() {
    let result = serde_json::json!({});
    let caps = McpServerCapabilities::from_initialize_result(&result);
    assert!(!caps.tools_list_changed);
    assert!(!caps.resources_supported);
    assert!(!caps.prompts_supported);
    assert!(!caps.completions_supported);
    assert!(!caps.logging_supported);
}

#[test]
fn capabilities_partial_tools_only() {
    let result = serde_json::json!({
        "capabilities": {
            "tools": {}
        }
    });
    let caps = McpServerCapabilities::from_initialize_result(&result);
    assert!(!caps.tools_list_changed);
    assert!(!caps.resources_supported);
}
