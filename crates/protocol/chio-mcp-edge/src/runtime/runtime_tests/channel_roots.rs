use super::*;

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
