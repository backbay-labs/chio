use super::*;

#[test]
fn mcp_serve_progresses_wrapped_sampling_tasks_while_upstream_keeps_talking() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let policy_path = write_nested_flow_policy(&dir);
    let script_path = write_mock_server_script(&dir);

    let mut child = chio_command_with_session_db(&dir)
        .args([
            "mcp",
            "serve",
            "--policy",
            policy_path.to_str().expect("policy path"),
            "--server-id",
            "wrapped-mock",
            "--server-name",
            "Wrapped Mock",
            "--",
            "python3",
            script_path.to_str().expect("script path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio mcp serve");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "sampling": {
                        "context": {},
                        "tools": {}
                    }
                },
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );
    let (initialize, initialize_notifications) = read_response(&mut stdout, 1);
    assert!(initialize_notifications.is_empty());
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    );

    send_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "sampled_echo_tasked_noisy",
                "arguments": {"message": "sample this without waiting for idle"}
            }
        }),
    );
    let (sampled, sampled_notifications, sampled_requests) =
        read_response_with_nested_flow_support(&mut stdout, &mut stdin, 2);
    assert_eq!(sampled_requests.len(), 1);
    assert_eq!(sampled_requests[0]["method"], "sampling/createMessage");
    assert_eq!(sampled["result"]["isError"], false);
    assert_eq!(
        sampled["result"]["structuredContent"]["taskStatusBeforeResult"],
        "completed"
    );
    assert_eq!(sampled["result"]["structuredContent"]["noiseCount"], 8);
    assert!(
        sampled["result"]["structuredContent"]["taskStatusNotifications"]
            .as_u64()
            .expect("task status notification count")
            >= 1
    );
    assert_eq!(
        sampled["result"]["structuredContent"]["sampled"]["content"]["text"],
        "sampled by client"
    );
    assert!(sampled_notifications
        .iter()
        .all(|notification| notification["method"] != "notifications/tasks/status"));

    drop(stdin);

    let status = child.wait().expect("wait for chio process");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(status.success(), "chio stderr:\n{stderr}");

    let _ = fs::remove_file(policy_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_dir(dir);
}
