fn agent_connection_fixture() -> (AcpAgentConnection, ChioKernel, AcpKernelExecutionContext) {
    let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let connection = AcpAgentConnection::new(edge, "read_file".into(), "path".into()).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let subject = Keypair::generate();
    let execution = AcpKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "test-srv", "read_file"),
        agent_id: subject.public_key().to_hex(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
    };
    (connection, kernel, execution)
}

fn acp_request(method: &str, params: Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})
}

fn initialized_session(
    connection: &mut AcpAgentConnection,
    kernel: &ChioKernel,
    execution: &AcpKernelExecutionContext,
) -> String {
    assert_eq!(
        connection.handle_jsonrpc(
            acp_request("initialize", json!({"protocolVersion":1})),
            kernel,
            execution
        )[0]["result"]["protocolVersion"],
        1
    );
    connection.handle_jsonrpc(
        acp_request("session/new", json!({"cwd":"/tmp","mcpServers":[]})),
        kernel,
        execution,
    )[0]["result"]["sessionId"]
        .as_str()
        .test_unwrap()
        .to_owned()
}

#[test]
fn agent_connection_returns_bound_updates_and_handles_reused_rpc_ids_as_new_prompts() {
    let (mut connection, kernel, execution) = agent_connection_fixture();
    let session_id = initialized_session(&mut connection, &kernel, &execution);
    let request = acp_request(
        "session/prompt",
        json!({"sessionId":session_id,"prompt":[{"type":"text","text":"README.md"}]}),
    );
    let first = connection.handle_jsonrpc(request.clone(), &kernel, &execution);
    let second = connection.handle_jsonrpc(request, &kernel, &execution);
    assert_eq!(first.len(), 3);
    assert_eq!(first[0]["method"], "session/update");
    assert_eq!(first[0]["params"]["update"]["status"], "completed");
    assert_eq!(first[2]["result"]["stopReason"], "end_turn");
    let receipt = &first[2]["result"]["_meta"]["chio"]["receipt"];
    assert_eq!(receipt["action"]["parameters"], json!({"path":"README.md"}));
    assert_eq!(
        first[0]["params"]["update"]["toolCallId"],
        receipt["metadata"]["receipt_context"]["request_id"]
    );
    assert_eq!(
        first[0]["params"]["update"]["_meta"],
        first[2]["result"]["_meta"]
    );
    assert_ne!(
        first[0]["params"]["update"]["toolCallId"],
        second[0]["params"]["update"]["toolCallId"]
    );
    assert_eq!(kernel.receipt_log().receipts().len(), 2);
}

#[test]
fn agent_connection_rejects_invalid_or_other_caller_sessions_before_dispatch() {
    let (mut connection, kernel, mut execution) = agent_connection_fixture();
    let uninitialized = connection.handle_jsonrpc(
        acp_request("session/new", json!({"cwd":"/tmp","mcpServers":[]})),
        &kernel,
        &execution,
    );
    assert!(!uninitialized[0]["error"].is_null());
    let session_id = initialized_session(&mut connection, &kernel, &execution);
    for prompt in [
        json!([]),
        json!([{"type":"image","data":"image"}]),
        json!([{"type":"text","text":"x".repeat(65_537)}]),
        json!([{"type":"text","text":"x".repeat(65_536)},{"type":"text","text":""}]),
    ] {
        assert!(!connection.handle_jsonrpc(
            acp_request(
                "session/prompt",
                json!({"sessionId":session_id,"prompt":prompt})
            ),
            &kernel,
            &execution
        )[0]["error"]
            .is_null());
    }
    assert!(!connection.handle_jsonrpc(
        acp_request(
            "session/new",
            json!({"cwd":"/tmp","mcpServers":[{"name":"unconfigured"}]})
        ),
        &kernel,
        &execution
    )[0]["error"]
        .is_null());
    execution.agent_id = Keypair::generate().public_key().to_hex();
    assert!(!connection.handle_jsonrpc(
        acp_request(
            "session/prompt",
            json!({"sessionId":session_id,"prompt":[{"type":"text","text":"README.md"}]})
        ),
        &kernel,
        &execution
    )[0]["error"]
        .is_null());
    assert!(kernel.receipt_log().receipts().is_empty());
}
