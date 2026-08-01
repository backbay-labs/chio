use super::*;

#[test]
fn mcp_serve_http_rejects_initialize_with_session_header_without_issuing_session() {
    skip_when_loopback_denied!(
        mcp_serve_http_rejects_initialize_with_session_header_without_issuing_session
    );
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let response = post_raw(
        &client,
        &base_url,
        Some(token),
        Some("bogus-session"),
        "application/json, text/event-stream",
        "application/json",
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(response.headers().get("MCP-Session-Id").is_none());
}

#[test]
fn mcp_serve_http_rejects_initialize_without_request_id() {
    skip_when_loopback_denied!(mcp_serve_http_rejects_initialize_without_request_id);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let response = post_raw(
        &client,
        &base_url,
        Some(token),
        None,
        "application/json, text/event-stream",
        "application/json",
        &json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "0.1.0"
                }
            }
        }),
    );

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(response.headers().get("MCP-Session-Id").is_none());
}

#[test]
fn mcp_serve_http_rejects_malformed_jsonrpc_body() {
    skip_when_loopback_denied!(mcp_serve_http_rejects_malformed_jsonrpc_body);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let response = post_bytes(
        &client,
        &base_url,
        Some(token),
        None,
        "application/json, text/event-stream",
        "application/json",
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25""#,
    );
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = response.json().expect("parse malformed request response");
    assert_eq!(body["error"]["code"], -32700);
    assert!(body["error"]["message"]
        .as_str()
        .expect("parse error message")
        .contains("invalid JSON"));
}
