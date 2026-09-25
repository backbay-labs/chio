fn v1_fixture() -> (ChioA2aEdge, ChioKernel, A2aKernelExecutionContext) {
    let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let config = test_kernel_config();
    let issuer = config.keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(test_server()));
    let subject = Keypair::generate();
    let execution = A2aKernelExecutionContext {
        capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
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
    (edge, kernel, execution)
}

fn v1_message(message_id: &str, skill: &str) -> Value {
    json!({"jsonrpc":"2.0","id":"transport-id","method":"SendMessage",
        "params":{"message":{"messageId":message_id,"role":"ROLE_USER",
            "parts":[{"data":{"text":"Count this exact input"}}]},
            "metadata":{"chio":{"targetSkillId":skill}}}})
}

#[test]
fn v1_task_lookup_and_identical_retry_keep_the_original_receipt() {
    let (mut edge, kernel, execution) = v1_fixture();
    let request = v1_message("first-message", "echo");
    let first = edge.handle_jsonrpc(request.clone(), &kernel, &execution);
    let task = first["result"]["task"].clone();
    assert_eq!(task["status"]["state"], "TASK_STATE_COMPLETED");
    assert_eq!(
        task["artifacts"][0]["parts"][0]["data"],
        json!({"result":"ok"})
    );
    let receipt = &task["metadata"]["chio"]["receipt"];
    assert_eq!(
        receipt["action"]["parameters"],
        json!({"text":"Count this exact input"})
    );
    assert!(!receipt["signature"].is_null());
    assert_eq!(
        task["metadata"]["chio"]["retainedOutput"],
        json!({"kind":"value","value":{"result":"ok"}})
    );
    assert_eq!(
        receipt["content_hash"],
        chio_core::sha256_hex(br#"{"result":"ok"}"#)
    );
    let retry = edge.handle_jsonrpc(request.clone(), &kernel, &execution);
    assert_eq!(retry["result"]["task"], task);
    let lookup = edge.handle_jsonrpc(
        json!({"jsonrpc":"2.0","id":2,"method":"GetTask",
        "params":{"id":task["id"]}}),
        &kernel,
        &execution,
    );
    assert_eq!(lookup["result"], task);
    let mut different = request;
    different["params"]["message"]["parts"][0]["data"]["text"] = json!("Substituted input");
    assert_eq!(
        edge.handle_jsonrpc(different, &kernel, &execution)["error"]["code"],
        -32602
    );
    assert_eq!(kernel.receipt_log().receipts().len(), 1);
    let mut other = execution;
    other.agent_id = Keypair::generate().public_key().to_hex();
    for method in ["GetTask", "CancelTask"] {
        assert_eq!(
            edge.handle_jsonrpc(
                json!({"jsonrpc":"2.0","id":3,"method":method,
            "params":{"id":task["id"]}}),
                &kernel,
                &other
            )["error"]["code"],
            -32001
        );
    }
}

#[test]
fn v1_scope_refusal_is_a_failed_task_with_a_signed_denial() {
    let (mut edge, kernel, execution) = v1_fixture();
    let response = edge.handle_jsonrpc(v1_message("refused-message", "write"), &kernel, &execution);
    assert_eq!(
        response["result"]["task"]["status"]["state"],
        "TASK_STATE_FAILED"
    );
    assert_eq!(
        response["result"]["task"]["metadata"]["chio"]["receipt"]["decision"]["verdict"],
        "deny"
    );
    assert!(response["result"]["task"]["artifacts"].is_null());
}

#[test]
fn v1_malformed_requests_and_notifications_never_dispatch() {
    let (mut edge, kernel, execution) = v1_fixture();
    for case in ["missing-id", "role", "part", "task", "stream", "push"] {
        let mut request = v1_message(case, "echo");
        match case {
            "missing-id" => request["params"]["message"]["messageId"] = json!(""),
            "role" => request["params"]["message"]["role"] = json!("ROLE_AGENT"),
            "part" => {
                request["params"]["message"]["parts"][0]["url"] = json!("https://example.invalid")
            }
            "task" => request["params"]["message"]["taskId"] = json!("existing-task"),
            "stream" => request["params"]["configuration"] = json!({"returnImmediately":true}),
            "push" => request["params"]["configuration"] = json!({"taskPushNotificationConfig":{}}),
            _ => unreachable!(),
        }
        assert!(
            !edge.handle_jsonrpc(request, &kernel, &execution)["error"].is_null(),
            "{case}"
        );
    }
    let mut notification = v1_message("no-response", "echo");
    notification.as_object_mut().test_unwrap().remove("id");
    assert!(edge
        .handle_jsonrpc(notification, &kernel, &execution)
        .is_notification());
    assert!(kernel.receipt_log().receipts().is_empty());
    let card = edge.agent_card_v1();
    assert_eq!(card["supportedInterfaces"][0]["protocolVersion"], "1.0");
    assert_eq!(card["capabilities"]["streaming"], false);
    assert!(card["skills"][0].get("bridgeFidelity").is_none());
}
