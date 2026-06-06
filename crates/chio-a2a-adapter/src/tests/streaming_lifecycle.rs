#[tokio::test]
async fn adapter_invoke_stream_returns_none_without_stream_flag() {
    let Some(server) = FakeA2aServer::spawn_jsonrpc() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover JSONRPC adapter");

    let stream = adapter
        .invoke_stream(
            "research",
            json!({
                "message": "Do not stream this"
            }),
            None,
        )
        .await
        .expect("invoke_stream should not fail");
    assert!(stream.is_none());
    let _ = adapter
        .invoke(
            "research",
            json!({
                "message": "finish request log"
            }),
            None,
        )
        .await
        .expect("invoke blocking request");
    server.join();
}

#[tokio::test]
async fn adapter_jsonrpc_streaming_invocation_returns_complete_stream() {
    let Some(server) = FakeA2aServer::spawn_jsonrpc_streaming_complete() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover JSONRPC adapter");

    let stream = adapter
        .invoke_stream(
            "research",
            json!({
                "message": "Stream the answer",
                "stream": true
            }),
            None,
        )
        .await
        .expect("invoke stream")
        .expect("stream result");

    let ToolServerStreamResult::Complete(stream) = stream else {
        panic!("expected complete stream");
    };
    assert_eq!(stream.chunk_count(), 3);
    assert_eq!(
        stream.chunks[0].data["task"]["status"]["state"],
        "TASK_STATE_WORKING"
    );
    assert_eq!(
        stream.chunks[1].data["artifactUpdate"]["artifact"]["parts"][0]["text"],
        "partial research result"
    );
    assert_eq!(
        stream.chunks[2].data["statusUpdate"]["status"]["state"],
        "TASK_STATE_COMPLETED"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains("\"method\":\"SendStreamingMessage\""));
    assert!(requests[1].contains("Accept: text/event-stream"));
    server.join();
}

#[tokio::test]
async fn adapter_blocking_registry_conflict_rejects_rebound_task_response() {
    let registry_path = unique_path("chio-a2a-http-blocking-conflict", ".json");
    let Some(server) = FakeA2aServer::spawn_http_json() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_task_registry_file(&registry_path)
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover HTTP+JSON adapter");
    seed_a2a_task(&adapter, "clinical_search", "task-1");

    let error = adapter
        .invoke(
            "research",
            json!({
                "data": { "query": "hypertension staging guidelines" },
                "return_immediately": true
            }),
            None,
        )
        .await
        .expect_err("registry conflict should fail the blocking response");
    server.join();

    assert!(error.to_string().contains("attempted to rebind"));
    assert!(
        adapter
            .validate_task_binding("research", "task-1", "test_follow_up")
            .is_err(),
        "conflicting registry binding must still deny future follow-up"
    );

    let _ = fs::remove_file(registry_path);
}

#[tokio::test]
async fn adapter_streaming_registry_conflict_rejects_rebound_stream() {
    let registry_path = unique_path("chio-a2a-jsonrpc-stream-conflict", ".json");
    let Some(server) = FakeA2aServer::spawn_jsonrpc_streaming_complete() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_task_registry_file(&registry_path)
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover JSONRPC adapter");
    seed_a2a_task(&adapter, "clinical_search", "task-1");

    let error = adapter
        .invoke_stream(
            "research",
            json!({
                "message": "Stream the answer",
                "stream": true
            }),
            None,
        )
        .await
        .expect_err("registry conflict should fail the stream response");
    server.join();

    assert!(error.to_string().contains("attempted to rebind"));
    assert!(
        adapter
            .validate_task_binding("research", "task-1", "test_follow_up")
            .is_err(),
        "conflicting registry binding must still deny future follow-up"
    );

    let _ = fs::remove_file(registry_path);
}

#[tokio::test]
async fn adapter_streaming_registry_corruption_fails_closed() {
    let registry_path = unique_path("chio-a2a-jsonrpc-stream-corrupt", ".json");
    let Some(server) = FakeA2aServer::spawn_jsonrpc_streaming_complete() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_task_registry_file(&registry_path)
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover JSONRPC adapter");
    fs::write(&registry_path, b"{not-json").expect("corrupt task registry");

    let stream_result = adapter
        .invoke_stream(
            "research",
            json!({
                "message": "Stream the answer",
                "stream": true
            }),
            None,
        )
        .await;
    server.join();

    let error = stream_result.expect_err("corrupt stream registry should fail closed");
    assert!(
        error
            .to_string()
            .contains("failed to parse A2A task registry"),
        "unexpected stream error: {error}"
    );

    let _ = fs::remove_file(registry_path);
}

#[tokio::test]
async fn adapter_streaming_registry_corruption_with_rebind_phrase_fails_closed() {
    let registry_path = unique_path(
        "chio-a2a-jsonrpc-stream-attempted to rebind-corrupt",
        ".json",
    );
    let Some(server) = FakeA2aServer::spawn_jsonrpc_streaming_complete() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_task_registry_file(&registry_path)
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover JSONRPC adapter");
    fs::write(&registry_path, b"{not-json").expect("corrupt task registry");

    let stream_result = adapter
        .invoke_stream(
            "research",
            json!({
                "message": "Stream the answer",
                "stream": true
            }),
            None,
        )
        .await;
    server.join();

    let error = stream_result
        .expect_err("corrupt stream registry path text must not bypass fail-closed handling");
    assert!(
        error
            .to_string()
            .contains("failed to parse A2A task registry"),
        "unexpected stream error: {error}"
    );

    let _ = fs::remove_file(registry_path);
}

#[tokio::test]
async fn adapter_http_json_streaming_invocation_returns_complete_stream() {
    let Some(server) = FakeA2aServer::spawn_http_json_streaming_complete() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover HTTP+JSON adapter");

    let stream = adapter
        .invoke_stream(
            "research",
            json!({
                "message": "Stream the answer",
                "stream": true
            }),
            None,
        )
        .await
        .expect("invoke stream")
        .expect("stream result");

    let ToolServerStreamResult::Complete(stream) = stream else {
        panic!("expected complete stream");
    };
    assert_eq!(stream.chunk_count(), 3);
    assert_eq!(
        stream.chunks[2].data["statusUpdate"]["status"]["state"],
        "TASK_STATE_COMPLETED"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains("POST /message:stream HTTP/1.1"));
    assert!(requests[1].contains("Accept: text/event-stream"));
    server.join();
}

#[tokio::test]
async fn adapter_streaming_closure_without_terminal_state_is_incomplete() {
    let Some(server) = FakeA2aServer::spawn_jsonrpc_streaming_incomplete() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover JSONRPC adapter");

    let stream = adapter
        .invoke_stream(
            "research",
            json!({
                "message": "Stream the answer",
                "stream": true
            }),
            None,
        )
        .await
        .expect("invoke stream")
        .expect("stream result");

    let ToolServerStreamResult::Incomplete { stream, reason } = stream else {
        panic!("expected incomplete stream");
    };
    assert_eq!(stream.chunk_count(), 2);
    assert!(reason.contains("terminal or interrupted"));
    server.join();
}

#[tokio::test]
async fn adapter_jsonrpc_subscribe_task_returns_complete_stream() {
    let registry_path = unique_path("chio-a2a-jsonrpc-subscribe", ".json");
    let Some(server) = FakeA2aServer::spawn_jsonrpc_subscribe_complete() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_task_registry_file(&registry_path)
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover JSONRPC adapter");
    seed_a2a_task(&adapter, "research", "task-1");

    let stream = adapter
        .invoke_stream(
            "research",
            json!({
                "subscribe_task": { "id": "task-1" }
            }),
            None,
        )
        .await
        .expect("invoke subscribe stream")
        .expect("stream result");

    let ToolServerStreamResult::Complete(stream) = stream else {
        panic!("expected complete stream");
    };
    assert_eq!(stream.chunk_count(), 3);
    assert_eq!(
        stream.chunks[2].data["statusUpdate"]["status"]["state"],
        "TASK_STATE_COMPLETED"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains("\"method\":\"SubscribeToTask\""));
    assert!(requests[1].contains("Accept: text/event-stream"));
    server.join();
}

#[tokio::test]
async fn adapter_http_json_subscribe_task_returns_complete_stream() {
    let registry_path = unique_path("chio-a2a-http-subscribe", ".json");
    let Some(server) = FakeA2aServer::spawn_http_json_subscribe_complete() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_task_registry_file(&registry_path)
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover HTTP+JSON adapter");
    seed_a2a_task(&adapter, "research", "task-1");

    let stream = adapter
        .invoke_stream(
            "research",
            json!({
                "subscribe_task": { "id": "task-1" }
            }),
            None,
        )
        .await
        .expect("invoke subscribe stream")
        .expect("stream result");

    let ToolServerStreamResult::Complete(stream) = stream else {
        panic!("expected complete stream");
    };
    assert_eq!(stream.chunk_count(), 3);
    assert_eq!(
        stream.chunks[2].data["statusUpdate"]["status"]["state"],
        "TASK_STATE_COMPLETED"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].starts_with("GET /tasks/task-1:subscribe HTTP/1.1"));
    assert!(requests[1].contains("Accept: text/event-stream"));
    server.join();
}

#[tokio::test]
async fn adapter_subscribe_task_closure_without_terminal_state_is_incomplete() {
    let registry_path = unique_path("chio-a2a-jsonrpc-subscribe-incomplete", ".json");
    let Some(server) = FakeA2aServer::spawn_jsonrpc_subscribe_incomplete() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_task_registry_file(&registry_path)
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover JSONRPC adapter");
    seed_a2a_task(&adapter, "research", "task-1");

    let stream = adapter
        .invoke_stream(
            "research",
            json!({
                "subscribe_task": { "id": "task-1" }
            }),
            None,
        )
        .await
        .expect("invoke subscribe stream")
        .expect("stream result");

    let ToolServerStreamResult::Incomplete { stream, reason } = stream else {
        panic!("expected incomplete stream");
    };
    assert_eq!(stream.chunk_count(), 2);
    assert!(reason.contains("terminal or interrupted"));
    server.join();
}

#[tokio::test]
async fn adapter_jsonrpc_cancel_task_returns_cancelled_task() {
    let registry_path = unique_path("chio-a2a-jsonrpc-cancel", ".json");
    let Some(server) = FakeA2aServer::spawn_jsonrpc_cancel_task() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_task_registry_file(&registry_path)
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover JSONRPC adapter");
    seed_a2a_task(&adapter, "research", "task-1");

    let result = adapter
        .invoke(
            "research",
            json!({
                "cancel_task": {
                    "id": "task-1",
                    "metadata": { "reason": "user-request" }
                }
            }),
            None,
        )
        .await
        .expect("cancel task");

    assert_eq!(result["task"]["id"], "task-1");
    assert_eq!(result["task"]["status"]["state"], "TASK_STATE_CANCELED");

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains("\"method\":\"CancelTask\""));
    assert!(requests[1].contains("\"reason\":\"user-request\""));
    server.join();
}

#[tokio::test]
async fn adapter_http_json_cancel_task_returns_cancelled_task() {
    let registry_path = unique_path("chio-a2a-http-cancel", ".json");
    let Some(server) = FakeA2aServer::spawn_http_json_cancel_task() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_task_registry_file(&registry_path)
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover HTTP+JSON adapter");
    seed_a2a_task(&adapter, "research", "task-1");

    let result = adapter
        .invoke(
            "research",
            json!({
                "cancel_task": {
                    "id": "task-1",
                    "metadata": { "reason": "user-request" }
                }
            }),
            None,
        )
        .await
        .expect("cancel task");

    assert_eq!(result["task"]["id"], "task-1");
    assert_eq!(result["task"]["status"]["state"], "TASK_STATE_CANCELED");

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].starts_with("POST /tasks/task-1:cancel HTTP/1.1"));
    assert!(requests[1].contains("\"reason\":\"user-request\""));
    server.join();
}

#[tokio::test]
async fn adapter_jsonrpc_push_notification_config_crud_roundtrip() {
    let registry_path = unique_path("chio-a2a-jsonrpc-push", ".json");
    let Some(server) = FakeA2aServer::spawn_jsonrpc_push_notification_crud() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_task_registry_file(&registry_path)
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover JSONRPC adapter");
    seed_a2a_task(&adapter, "research", "task-1");

    let created = adapter
        .invoke(
            "research",
            json!({
                "create_push_notification_config": {
                    "task_id": "task-1",
                    "url": "https://callbacks.example.com/chio",
                    "token": "notify-token",
                    "authentication": {
                        "scheme": "bearer",
                        "credentials": "callback-secret"
                    }
                }
            }),
            None,
        )
        .await
        .expect("create push notification config");
    assert_eq!(
        created["push_notification_config"]["id"],
        Value::String("config-1".to_string())
    );

    let fetched = adapter
        .invoke(
            "research",
            json!({
                "get_push_notification_config": {
                    "task_id": "task-1",
                    "id": "config-1"
                }
            }),
            None,
        )
        .await
        .expect("get push notification config");
    assert_eq!(
        fetched["push_notification_config"]["url"],
        "https://callbacks.example.com/chio"
    );

    let listed = adapter
        .invoke(
            "research",
            json!({
                "list_push_notification_configs": {
                    "task_id": "task-1",
                    "page_size": 25,
                    "page_token": "page-2"
                }
            }),
            None,
        )
        .await
        .expect("list push notification configs");
    assert_eq!(
        listed["push_notification_configs"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(listed["next_page_token"], "next-page");

    let deleted = adapter
        .invoke(
            "research",
            json!({
                "delete_push_notification_config": {
                    "task_id": "task-1",
                    "id": "config-1"
                }
            }),
            None,
        )
        .await
        .expect("delete push notification config");
    assert_eq!(deleted["deleted"], Value::Bool(true));

    let requests = server.requests();
    assert_eq!(requests.len(), 5);
    assert!(requests[1].contains("\"method\":\"CreateTaskPushNotificationConfig\""));
    assert!(requests[2].contains("\"method\":\"GetTaskPushNotificationConfig\""));
    assert!(requests[3].contains("\"method\":\"ListTaskPushNotificationConfigs\""));
    assert!(requests[4].contains("\"method\":\"DeleteTaskPushNotificationConfig\""));
    server.join();
}

#[tokio::test]
async fn adapter_http_json_push_notification_config_crud_roundtrip() {
    let registry_path = unique_path("chio-a2a-http-push", ".json");
    let Some(server) = FakeA2aServer::spawn_http_json_push_notification_crud() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_task_registry_file(&registry_path)
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover HTTP+JSON adapter");
    seed_a2a_task(&adapter, "research", "task-1");

    let created = adapter
        .invoke(
            "research",
            json!({
                "create_push_notification_config": {
                    "task_id": "task-1",
                    "url": "https://callbacks.example.com/chio",
                    "token": "notify-token",
                    "authentication": {
                        "scheme": "bearer",
                        "credentials": "callback-secret"
                    }
                }
            }),
            None,
        )
        .await
        .expect("create push notification config");
    assert_eq!(
        created["push_notification_config"]["authentication"]["scheme"],
        "bearer"
    );

    let fetched = adapter
        .invoke(
            "research",
            json!({
                "get_push_notification_config": {
                    "task_id": "task-1",
                    "id": "config-1"
                }
            }),
            None,
        )
        .await
        .expect("get push notification config");
    assert_eq!(
        fetched["push_notification_config"]["id"],
        Value::String("config-1".to_string())
    );

    let listed = adapter
        .invoke(
            "research",
            json!({
                "list_push_notification_configs": {
                    "task_id": "task-1",
                    "page_size": 25,
                    "page_token": "page-2"
                }
            }),
            None,
        )
        .await
        .expect("list push notification configs");
    assert_eq!(
        listed["push_notification_configs"][0]["authentication"]["credentials"],
        "callback-secret"
    );

    let deleted = adapter
        .invoke(
            "research",
            json!({
                "delete_push_notification_config": {
                    "task_id": "task-1",
                    "id": "config-1"
                }
            }),
            None,
        )
        .await
        .expect("delete push notification config");
    assert_eq!(deleted["deleted"], Value::Bool(true));

    let requests = server.requests();
    assert_eq!(requests.len(), 5);
    assert!(requests[1].starts_with("POST /tasks/task-1/pushNotificationConfigs HTTP/1.1"));
    assert!(
        requests[2].starts_with("GET /tasks/task-1/pushNotificationConfigs/config-1 HTTP/1.1")
    );
    assert!(requests[3].starts_with(
        "GET /tasks/task-1/pushNotificationConfigs?pageSize=25&pageToken=page-2 HTTP/1.1"
    ));
    assert!(requests[4]
        .starts_with("DELETE /tasks/task-1/pushNotificationConfigs/config-1 HTTP/1.1"));
    server.join();
}

#[tokio::test]
async fn adapter_rejects_insecure_push_notification_callback_url() {
    let registry_path = unique_path("chio-a2a-insecure-push", ".json");
    let Some(server) = FakeA2aServer::spawn_jsonrpc_push_notification_capability_only() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_task_registry_file(&registry_path)
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover JSONRPC adapter");
    seed_a2a_task(&adapter, "research", "task-1");

    let error = adapter
        .invoke(
            "research",
            json!({
                "create_push_notification_config": {
                    "task_id": "task-1",
                    "url": "http://example.com/callback"
                }
            }),
            None,
        )
        .await
        .expect_err("insecure callback URL should fail closed");
    assert!(error
        .to_string()
        .contains("push notification URL must use https"));
    assert_eq!(server.requests().len(), 1);
    server.join();
}

#[tokio::test]
async fn adapter_rejects_push_notification_callback_url_userinfo_before_dispatch() {
    let registry_path = unique_path("chio-a2a-userinfo-push", ".json");
    let Some(server) = FakeA2aServer::spawn_jsonrpc_push_notification_capability_only() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_task_registry_file(&registry_path)
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover JSONRPC adapter");
    seed_a2a_task(&adapter, "research", "task-1");

    let error = adapter
        .invoke(
            "research",
            json!({
                "create_push_notification_config": {
                    "task_id": "task-1",
                    "url": "https://user:secret@callbacks.example.com/chio"
                }
            }),
            None,
        )
        .await
        .expect_err("callback URL userinfo should fail closed");
    assert!(error
        .to_string()
        .contains("push notification URL must not include userinfo"));
    assert_eq!(server.requests().len(), 1);
    server.join();
}

#[tokio::test]
async fn adapter_rejects_push_notification_callback_url_fragment_before_dispatch() {
    let registry_path = unique_path("chio-a2a-fragment-push", ".json");
    let Some(server) = FakeA2aServer::spawn_jsonrpc_push_notification_capability_only() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_task_registry_file(&registry_path)
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover JSONRPC adapter");
    seed_a2a_task(&adapter, "research", "task-1");

    let error = adapter
        .invoke(
            "research",
            json!({
                "create_push_notification_config": {
                    "task_id": "task-1",
                    "url": "https://callbacks.example.com/chio#secret"
                }
            }),
            None,
        )
        .await
        .expect_err("callback URL fragment should fail closed");
    assert!(error
        .to_string()
        .contains("push notification URL must not include a fragment"));
    assert_eq!(server.requests().len(), 1);
    server.join();
}

#[tokio::test]
async fn adapter_rejects_malformed_push_notification_auth_material_before_dispatch() {
    let registry_path = unique_path("chio-a2a-push-auth-material", ".json");
    let Some(server) = FakeA2aServer::spawn_jsonrpc_push_notification_capability_only() else {
        return;
    };
    let manifest_key = Keypair::generate();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), manifest_key.public_key().to_hex())
            .with_task_registry_file(&registry_path)
            .with_timeout(Duration::from_secs(2)),
    )
    .expect("discover JSONRPC adapter");
    seed_a2a_task(&adapter, "research", "task-1");

    for (input, expected_error) in [
        (
            json!({
                "task_id": "task-1",
                "url": "https://callbacks.example.com/chio",
                "token": " "
            }),
            "`create_push_notification_config.token` must be a non-empty unpadded string without control characters",
        ),
        (
            json!({
                "task_id": "task-1",
                "url": "https://callbacks.example.com/chio",
                "authentication": {
                    "scheme": "bearer\n",
                    "credentials": "callback-secret"
                }
            }),
            "`authentication.scheme` must be a non-empty HTTP token",
        ),
        (
            json!({
                "task_id": "task-1",
                "url": "https://callbacks.example.com/chio",
                "authentication": {
                    "scheme": "bearer",
                    "credentials": " callback-secret "
                }
            }),
            "`authentication.credentials` must be a non-empty unpadded string without control characters",
        ),
    ] {
        let error = adapter
            .invoke(
                "research",
                json!({ "create_push_notification_config": input }),
                None,
            )
            .await
            .expect_err("malformed push notification auth material should fail closed");
        assert!(
            error.to_string().contains(expected_error),
            "unexpected push auth material error: {error}"
        );
        assert_eq!(server.requests().len(), 1);
    }
    server.join();
}
