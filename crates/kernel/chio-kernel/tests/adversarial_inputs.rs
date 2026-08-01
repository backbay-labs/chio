#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Cursor;

use chio_core::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_kernel::transport::{read_frame, ChioTransport, TransportError};

fn encode_frame(body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

fn make_capability_token() -> CapabilityToken {
    let kp = Keypair::generate();
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-adversarial-001".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "srv".to_string(),
                    tool_name: "echo".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            issued_at: 1_000,
            expires_at: 2_000,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &kp,
    )
    .expect("capability token should sign")
}

fn valid_tool_call_json() -> serde_json::Value {
    serde_json::json!({
        "type": "tool_call_request",
        "id": "req-adversarial-001",
        "capability_token": serde_json::to_value(make_capability_token()).expect("token should serialize"),
        "server_id": "srv",
        "tool": "echo",
        "params": {
            "text": "hello"
        }
    })
}

#[test]
fn malformed_json_body_returns_deserialize_error() {
    let frame = encode_frame(br#"{"type":"tool_call_request","id":"req-1""#);
    let mut transport = ChioTransport::new(Cursor::new(frame), Vec::new());

    let err = transport.recv().unwrap_err();
    assert!(matches!(err, TransportError::Deserialize(_)));
}

#[test]
fn zero_length_body_returns_deserialize_error() {
    let mut transport = ChioTransport::new(Cursor::new(0_u32.to_be_bytes().to_vec()), Vec::new());

    let err = transport.recv().unwrap_err();
    assert!(matches!(err, TransportError::Deserialize(_)));
}

#[test]
fn truncated_frame_body_returns_connection_closed() {
    let full_body = serde_json::to_vec(&valid_tool_call_json()).expect("body should serialize");
    let truncated_len = full_body.len() + 8;
    let mut frame = Vec::with_capacity(4 + full_body.len());
    frame.extend_from_slice(&(truncated_len as u32).to_be_bytes());
    frame.extend_from_slice(&full_body[..full_body.len() / 2]);

    let err = read_frame(&mut Cursor::new(frame)).unwrap_err();
    assert!(matches!(err, TransportError::ConnectionClosed));
}

#[test]
fn missing_required_id_field_returns_deserialize_error() {
    let mut payload = valid_tool_call_json();
    payload
        .as_object_mut()
        .expect("payload should be an object")
        .remove("id");

    let body = serde_json::to_vec(&payload).expect("payload should serialize");
    let mut transport = ChioTransport::new(Cursor::new(encode_frame(&body)), Vec::new());

    let err = transport.recv().unwrap_err();
    assert!(matches!(err, TransportError::Deserialize(_)));
}

#[test]
fn wrong_type_fields_return_deserialize_error() {
    let payload = serde_json::json!({
        "type": "tool_call_request",
        "id": 123,
        "capability_token": serde_json::to_value(make_capability_token()).expect("token should serialize"),
        "server_id": ["srv"],
        "tool": false,
        "params": null
    });
    let body = serde_json::to_vec(&payload).expect("payload should serialize");
    let mut transport = ChioTransport::new(Cursor::new(encode_frame(&body)), Vec::new());

    let err = transport.recv().unwrap_err();
    assert!(matches!(err, TransportError::Deserialize(_)));
}
