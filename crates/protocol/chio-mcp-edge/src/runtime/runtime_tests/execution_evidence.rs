use super::*;
use chio_core::receipt::body::ChioReceipt;
use std::sync::atomic::{AtomicUsize, Ordering};

struct ObservedServer {
    calls: Arc<AtomicUsize>,
    output: Value,
}

#[async_trait::async_trait]
impl ToolServerConnection for ObservedServer {
    fn server_id(&self) -> &str {
        "srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["read_file".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.output.clone())
    }
}

fn evidence_call(edge: &mut ChioMcpEdge) -> Value {
    edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "/workspace/example.txt"},
            "_meta": {"chioRequestId": "host-operation-7"},
        },
    }))
    .unwrap()
}

#[test]
fn execution_evidence_is_advertised_and_binds_real_kernel_result() {
    let (kernel, signer) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_capabilities(&kernel, &agent);
    let capability_id = capabilities[0].id.clone();
    let mut edge = ChioMcpEdge::new(
        McpEdgeConfig::default(),
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap();
    let initialized = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {},
        }))
        .unwrap();
    assert_eq!(
        initialized["result"]["capabilities"]["experimental"]["io.chio/execution-evidence"]
            ["version"],
        "1"
    );
    edge.handle_jsonrpc(json!({"jsonrpc":"2.0", "method":"notifications/initialized"}));

    let response = evidence_call(&mut edge);
    let evidence = &response["result"]["_meta"]["chioEvidence"];
    let receipt: ChioReceipt = serde_json::from_value(evidence["receipt"].clone()).unwrap();
    assert_eq!(evidence["schema"], "chio.mcp.execution-evidence.v1");
    assert_eq!(evidence["requestId"], "host-operation-7");
    assert_eq!(evidence["outputKind"], "value");
    assert_eq!(evidence["terminalState"], "completed");
    assert_eq!(receipt.kernel_key, signer.public_key());
    assert!(receipt.verify_signature().unwrap());
    assert_eq!(receipt.capability_id, capability_id);
    assert_eq!(receipt.tool_server, "srv");
    assert_eq!(receipt.tool_name, "read_file");
    assert_eq!(receipt.decision, Some(Decision::Allow));
    assert_eq!(
        receipt.metadata.as_ref().unwrap()["receipt_context"]["request_id"],
        "host-operation-7"
    );
    assert_eq!(
        receipt.metadata.as_ref().unwrap()["attribution"]["subject_key"],
        agent.public_key().to_hex()
    );
    assert_eq!(
        receipt.action.parameter_hash,
        sha256_hex(&canonical_json_bytes(&json!({"path": "/workspace/example.txt"})).unwrap())
    );
    assert_eq!(
        receipt.content_hash,
        sha256_hex(&canonical_json_bytes(&evidence["output"]).unwrap())
    );
    assert_ne!(
        receipt.content_hash,
        sha256_hex(&canonical_json_bytes(&json!({"forged": true})).unwrap())
    );
    assert_ne!(receipt.kernel_key, Keypair::generate().public_key());

    let mut substituted = receipt.clone();
    substituted.metadata.as_mut().unwrap()["receipt_context"]["request_id"] =
        json!("another-request");
    assert!(!substituted.verify_signature().unwrap());
}

#[test]
fn execution_evidence_overwrites_upstream_metadata_and_preserves_hash_preimage() {
    for upstream_meta in [
        json!({"chioEvidence": {"receipt": "forged"}}),
        json!("malformed"),
    ] {
        let mut edge = make_edge(10);
        let calls = Arc::new(AtomicUsize::new(0));
        let output = json!({"content": [{"type": "text", "text": "observed output"}], "_meta": upstream_meta});
        edge.kernel.register_tool_server(Box::new(ObservedServer {
            calls: calls.clone(),
            output: output.clone(),
        }));
        initialize_edge(&mut edge);
        let response = evidence_call(&mut edge);
        let evidence = &response["result"]["_meta"]["chioEvidence"];
        let receipt: ChioReceipt = serde_json::from_value(evidence["receipt"].clone()).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(evidence["output"], output);
        assert!(receipt.verify_signature().unwrap());
        assert_eq!(
            receipt.content_hash,
            sha256_hex(&canonical_json_bytes(&output).unwrap())
        );
    }
}

#[test]
fn execution_evidence_reports_kernel_denial_without_invoking_or_exposing_output() {
    let (mut kernel, signer) = make_kernel();
    let caller = Keypair::generate();
    let wrong_subject = Keypair::generate();
    let capabilities = issue_capabilities(&kernel, &wrong_subject);
    let calls = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(ObservedServer {
        calls: calls.clone(),
        output: json!({"secret": "must not be read"}),
    }));
    let mut edge = ChioMcpEdge::new(
        McpEdgeConfig::default(),
        kernel,
        caller.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap();
    initialize_edge(&mut edge);
    let response = evidence_call(&mut edge);
    let evidence = &response["result"]["_meta"]["chioEvidence"];
    let receipt: ChioReceipt = serde_json::from_value(evidence["receipt"].clone()).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(evidence["outputKind"], "none");
    assert!(evidence["output"].is_null());
    assert_eq!(receipt.kernel_key, signer.public_key());
    assert!(receipt.verify_signature().unwrap());
    assert!(matches!(receipt.decision, Some(Decision::Deny { .. })));
    assert!(!response.to_string().contains("must not be read"));
}

#[test]
fn execution_evidence_does_not_project_streams_as_verified_values() {
    let mut edge = make_streaming_edge(10);
    initialize_edge(&mut edge);
    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": "stream_file", "arguments": {},
                "_meta": {"chioRequestId": "stream-operation-9"}},
        }))
        .unwrap();
    let evidence = &response["result"]["_meta"]["chioEvidence"];
    let receipt: ChioReceipt = serde_json::from_value(evidence["receipt"].clone()).unwrap();
    assert_eq!(evidence["outputKind"], "stream");
    assert!(evidence["output"].is_null());
    assert!(receipt.verify_signature().unwrap());
    assert_ne!(receipt.content_hash, sha256_hex(b"null"));
}

#[test]
fn execution_context_reports_only_the_ready_session_authority() {
    let mut edge = make_edge(10);
    let before = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0", "id": 1, "method": "chio/execution-context", "params": {},
        }))
        .unwrap();
    assert!(before.get("error").is_some());
    initialize_edge(&mut edge);
    let context = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0", "id": 2, "method": "chio/execution-context", "params": {},
        }))
        .unwrap();
    assert_eq!(context["result"]["schema"], "chio.mcp.execution-context.v1");
    assert_eq!(context["result"]["subjectKey"], edge.agent_id);
    assert_eq!(context["result"]["serverId"], "srv");
    assert_eq!(context["result"]["serverIds"], json!(["srv"]));
    assert_eq!(
        context["result"]["capabilityIds"],
        json!(edge
            .capabilities
            .iter()
            .map(|cap| &cap.id)
            .collect::<Vec<_>>())
    );
    assert!(!context.to_string().contains("private"));
}

#[test]
fn execution_context_does_not_select_one_owner_from_an_ambiguous_inventory() {
    let mut edge = make_edge(10);
    initialize_edge(&mut edge);
    let mut other = edge.tools[0].clone();
    other.server_id = "other-resource-owner".to_string();
    edge.tools.push(other);
    let context = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0", "id": 2, "method": "chio/execution-context", "params": {},
        }))
        .unwrap();
    assert!(context["result"]["serverId"].is_null());
    assert_eq!(
        context["result"]["serverIds"],
        json!(["other-resource-owner", "srv"])
    );
}

#[test]
fn execution_nonce_retry_uses_the_nonce_bound_request_identity() {
    let session_id = SessionId::new("nonce-retry-session");
    let preflight = build_operation_context(
        &json!(7),
        session_id.clone(),
        "agent",
        "tools/call",
        &json!({ "name": "read_file", "arguments": { "path": "/tmp/demo.txt" } }),
    )
    .unwrap();
    let retry = build_operation_context_for_retry(
        &json!(7),
        session_id.clone(),
        "agent",
        "tools/call",
        &json!({
            "name": "read_file",
            "arguments": { "path": "/tmp/demo.txt" },
            "_meta": { "chioExecutionNonce": { "nonce": "opaque" } }
        }),
        Some(preflight.request_id.as_str()),
    )
    .unwrap();

    assert_eq!(preflight.request_id, retry.request_id);
}
