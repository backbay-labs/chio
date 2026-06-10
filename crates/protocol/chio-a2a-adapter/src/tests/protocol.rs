#[tokio::test]
async fn a2a_contract_resolver_rejects_loopback_answers() {
    let mut contract = HttpEgressContract::permissive_for_tests("127.0.0.1:80");
    contract.deny_loopback = true;
    let resolver = A2aContractResolver { contract };

    let error = ureq::Resolver::resolve(&resolver, "127.0.0.1:80")
        .expect_err("loopback DNS answers are rejected at resolver time");

    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        error.to_string().contains("loopback"),
        "unexpected resolver error: {error}"
    );
}

#[test]
fn jsonrpc_result_decoder_preserves_fail_closed_error_precedence() {
    let version_error = decode_jsonrpc_result(
        A2aJsonRpcResponse::<Value> {
            jsonrpc: "1.0".to_string(),
            result: None,
            error: Some(A2aJsonRpcError {
                code: -32000,
                message: "remote denied".to_string(),
            }),
        },
        "GetTask",
    )
    .expect_err("unexpected protocol version should fail before remote error");
    assert!(
        version_error
            .to_string()
            .contains("unexpected JSON-RPC version 1.0"),
        "unexpected version error: {version_error}"
    );

    let remote_error = decode_jsonrpc_result(
        A2aJsonRpcResponse::<Value> {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(A2aJsonRpcError {
                code: -32001,
                message: "remote denied".to_string(),
            }),
        },
        "GetTask",
    )
    .expect_err("remote JSON-RPC error should fail before missing result");
    assert!(
        remote_error
            .to_string()
            .contains("A2A JSON-RPC error -32001: remote denied"),
        "unexpected remote error: {remote_error}"
    );

    let missing_result = decode_jsonrpc_result(
        A2aJsonRpcResponse::<Value> {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: None,
        },
        "GetTask",
    )
    .expect_err("missing result should fail closed");
    assert!(
        missing_result
            .to_string()
            .contains("A2A JSON-RPC GetTask response omitted `result`"),
        "unexpected missing-result error: {missing_result}"
    );

    let missing_unlabeled_result = decode_jsonrpc_result(
        A2aJsonRpcResponse::<Value> {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: None,
        },
        "",
    )
    .expect_err("unlabeled response without result should fail closed");
    assert!(
        missing_unlabeled_result
            .to_string()
            .contains("A2A JSON-RPC response omitted `result`"),
        "unexpected unlabeled missing-result error: {missing_unlabeled_result}"
    );
}

#[test]
fn jsonrpc_result_decoder_returns_present_result() {
    let value = decode_jsonrpc_result(
        A2aJsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(json!({ "ok": true })),
            error: None,
        },
        "GetTask",
    )
    .expect("present result should decode");

    assert_eq!(value, json!({ "ok": true }));
}

#[test]
fn parse_tool_input_rejects_unknown_top_level_fields() {
    let error = parse_tool_input(json!({
        "message": "hello",
        "typoed_field": true
    }))
    .expect_err("unknown top-level tool input fields must fail closed");

    let message = error.to_string();
    assert!(
        message.contains("unknown field") && message.contains("typoed_field"),
        "unexpected unknown-field error: {message}"
    );
}

#[test]
fn parse_tool_input_rejects_unknown_follow_up_fields() {
    let error = parse_tool_input(json!({
        "get_task": {
            "id": "task-1",
            "extra": true
        }
    }))
    .expect_err("unknown follow-up fields must fail closed");

    let message = error.to_string();
    assert!(
        message.contains("unknown field") && message.contains("extra"),
        "unexpected unknown-field error: {message}"
    );
}

#[test]
fn parse_tool_input_rejects_unknown_push_authentication_fields() {
    let error = parse_tool_input(json!({
        "create_push_notification_config": {
            "task_id": "task-1",
            "url": "https://callback.example/hook",
            "authentication": {
                "scheme": "bearer",
                "extra": true
            }
        }
    }))
    .expect_err("unknown nested push authentication fields must fail closed");

    let message = error.to_string();
    assert!(
        message.contains("unknown field") && message.contains("extra"),
        "unexpected unknown-field error: {message}"
    );
}

#[test]
fn send_message_schema_requirement_rejects_empty_surface() {
    let mut one_of = Vec::new();
    let error = append_send_message_schema_requirement(
        &mut one_of,
        A2aSkillInputSurface {
            accepts_text: false,
            accepts_json: false,
        },
    )
    .expect_err("empty send surface must not emit an empty anyOf schema");

    assert!(
        error.to_string().contains("SendMessage schema requires"),
        "unexpected schema invariant error: {error}"
    );
    assert!(one_of.is_empty());
}

#[tokio::test]
async fn validate_send_message_response_rejects_task_without_status_state() {
    let error = validate_send_message_response(A2aSendMessageResponse {
        task: Some(json!({
            "id": "task-1"
        })),
        message: None,
    })
    .expect_err("task without status.state should fail");
    assert!(error.to_string().contains("status.state"));
}

#[tokio::test]
async fn validate_stream_response_rejects_status_update_without_task_id() {
    let error = validate_stream_response(json!({
        "statusUpdate": {
            "status": { "state": "TASK_STATE_COMPLETED" }
        }
    }))
    .expect_err("statusUpdate without taskId should fail");
    assert!(error.to_string().contains("taskId"));
}

#[tokio::test]
async fn validate_stream_response_rejects_artifact_update_without_task_id() {
    let error = validate_stream_response(json!({
        "artifactUpdate": {
            "artifact": {
                "artifactId": "artifact-1"
            }
        }
    }))
    .expect_err("artifactUpdate without taskId should fail");
    assert!(error.to_string().contains("taskId"));
}

#[tokio::test]
async fn build_get_task_url_appends_tenant_and_history_length() {
    let url = build_get_task_url(
        "http://localhost:9000",
        "task-1",
        Some("tenant-alpha"),
        Some(2),
    )
    .expect("build get task URL");

    assert_eq!(
        url.as_str(),
        "http://localhost:9000/tenant-alpha/tasks/task-1?historyLength=2"
    );
}

#[tokio::test]
async fn build_send_message_url_appends_tenant_path_segment() {
    let send_url =
        build_send_message_url("http://localhost:9000/api", Some("tenant-alpha"), false)
            .expect("build send message URL");
    let stream_url =
        build_send_message_url("http://localhost:9000/api", Some("tenant-alpha"), true)
            .expect("build stream message URL");

    assert_eq!(
        send_url.as_str(),
        "http://localhost:9000/api/tenant-alpha/message:send"
    );
    assert_eq!(
        stream_url.as_str(),
        "http://localhost:9000/api/tenant-alpha/message:stream"
    );
}

#[tokio::test]
async fn build_cancel_task_url_appends_tenant_path_segment() {
    let url =
        build_cancel_task_url("http://localhost:9000/api", "task-1", Some("tenant-alpha"))
            .expect("build cancel task URL");

    assert_eq!(
        url.as_str(),
        "http://localhost:9000/api/tenant-alpha/tasks/task-1:cancel"
    );
}

#[tokio::test]
async fn build_push_notification_urls_append_tenant_path_segment() {
    let collection_url = build_push_notification_configs_url(
        "http://localhost:9000/api",
        "task-1",
        Some("tenant-alpha"),
    )
    .expect("build push notification configs URL");
    let config_url = build_push_notification_config_url(
        "http://localhost:9000/api",
        "task-1",
        "config-1",
        Some("tenant-alpha"),
    )
    .expect("build push notification config URL");
    let list_url = build_list_push_notification_configs_url(
        "http://localhost:9000/api",
        "task-1",
        Some("tenant-alpha"),
        Some(25),
        Some("page-2"),
    )
    .expect("build list push notification configs URL");

    assert_eq!(
        collection_url.as_str(),
        "http://localhost:9000/api/tenant-alpha/tasks/task-1/pushNotificationConfigs"
    );
    assert_eq!(
        config_url.as_str(),
        "http://localhost:9000/api/tenant-alpha/tasks/task-1/pushNotificationConfigs/config-1"
    );
    assert_eq!(
        list_url.as_str(),
        "http://localhost:9000/api/tenant-alpha/tasks/task-1/pushNotificationConfigs?pageSize=25&pageToken=page-2"
    );
}

#[tokio::test]
async fn sse_parser_stops_after_terminal_task_state() {
    let terminal = json!({
        "task": task_payload("TASK_STATE_COMPLETED", true)
    });
    let body = format!(
        "data: {}\n\ndata: {{not-json}}\n\n",
        serde_json::to_string(&terminal).unwrap()
    );

    let parsed = parse_sse_stream(body.as_bytes(), Ok).unwrap();

    let ToolServerStreamResult::Complete(stream) = parsed else {
        panic!("expected terminal stream to complete");
    };
    assert_eq!(stream.chunk_count(), 1);
}

#[tokio::test]
async fn sse_parser_rejects_oversized_line() {
    let huge_text = "a".repeat(20_000);
    let event = json!({
        "message": {
            "messageId": "msg-huge",
            "role": "agent",
            "parts": [{ "text": huge_text }]
        }
    });
    let body = format!("data: {}\n\n", serde_json::to_string(&event).unwrap());

    let error = parse_sse_stream(body.as_bytes(), Ok).unwrap_err();

    assert!(error.to_string().contains("line"));
}

#[tokio::test]
async fn sse_parser_rejects_oversized_delimiterless_line() {
    let body = format!("data: {}", "x".repeat(MAX_SSE_LINE_BYTES + 1));

    let error = parse_sse_stream(body.as_bytes(), Ok).unwrap_err();

    assert!(error.to_string().contains("line"));
}

#[tokio::test]
async fn sse_parser_charges_oversized_line_against_response_limit() {
    let body = format!("data: {}\n", "x".repeat(MAX_SSE_LINE_BYTES + 1));

    let error = parse_sse_stream_with_limit(body.as_bytes(), 8, Ok).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("response bytes"));
    assert!(!message.contains("line"));
}

#[tokio::test]
async fn sse_parser_charges_delimiterless_line_against_response_limit() {
    let body = format!("data: {}", "x".repeat(MAX_SSE_LINE_BYTES + 1));

    let error = parse_sse_stream_with_limit(body.as_bytes(), 8, Ok).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("response bytes"));
    assert!(!message.contains("line"));
}

#[tokio::test]
async fn sse_line_reader_consumes_chunk_on_response_limit_error() {
    let body = b"data: overflow\nnext: event\n";
    let mut reader = BufReader::new(body.as_slice());
    let mut line = String::new();
    let mut total_bytes = 0;

    let error = read_sse_line(&mut reader, &mut line, &mut total_bytes, 8).unwrap_err();

    assert!(error.to_string().contains("response bytes"));
    assert!(line.is_empty());
    assert_eq!(total_bytes, "data: overflow\n".len() as u64);
    assert_eq!(reader.fill_buf().unwrap(), b"next: event\n");
}

#[tokio::test]
async fn sse_line_reader_consumes_chunk_on_byte_counter_overflow_error() {
    let body = b"data: overflow\nnext: event\n";
    let mut reader = BufReader::new(body.as_slice());
    let mut line = String::new();
    let mut total_bytes = u64::MAX;

    let error =
        read_sse_line(&mut reader, &mut line, &mut total_bytes, u64::MAX).unwrap_err();

    assert!(error.to_string().contains("byte counter overflowed"));
    assert!(line.is_empty());
    assert_eq!(total_bytes, u64::MAX);
    assert_eq!(reader.fill_buf().unwrap(), b"next: event\n");
}

#[tokio::test]
async fn sse_parser_preserves_utf8_split_across_reads() {
    struct OneByteReader {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl Read for OneByteReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.offset >= self.bytes.len() || output.is_empty() {
                return Ok(0);
            }
            output[0] = self.bytes[self.offset];
            self.offset += 1;
            Ok(1)
        }
    }

    let text = "caf\u{00e9}";
    let terminal = json!({
        "message": {
            "messageId": "msg-utf8",
            "role": "agent",
            "parts": [{ "text": text }]
        }
    });
    let body = format!("data: {}\n\n", serde_json::to_string(&terminal).unwrap());

    let parsed = parse_sse_stream(
        OneByteReader {
            bytes: body.into_bytes(),
            offset: 0,
        },
        Ok,
    )
    .unwrap();

    let ToolServerStreamResult::Complete(stream) = parsed else {
        panic!("expected terminal stream to complete");
    };
    assert_eq!(stream.chunks[0].data["message"]["parts"][0]["text"], text);
}

#[tokio::test]
async fn sse_parser_enforces_contract_response_limit() {
    let working = json!({
        "task": task_payload("TASK_STATE_WORKING", false)
    });
    let body = format!("data: {}\n\n", serde_json::to_string(&working).unwrap());

    let error = parse_sse_stream_with_limit(body.as_bytes(), 8, Ok).unwrap_err();

    assert!(error.to_string().contains("response bytes"));
}

#[tokio::test]
async fn sse_parser_rejects_too_many_chunks() {
    let working = json!({
        "task": task_payload("TASK_STATE_WORKING", false)
    });
    let mut body = String::new();
    for _ in 0..1_100 {
        body.push_str("data: ");
        body.push_str(&serde_json::to_string(&working).unwrap());
        body.push_str("\n\n");
    }

    let error = parse_sse_stream(body.as_bytes(), Ok).unwrap_err();

    assert!(error.to_string().contains("chunk"));
}
