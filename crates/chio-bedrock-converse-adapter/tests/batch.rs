#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::SystemTime;

use chio_bedrock_converse_adapter::{
    transport, BedrockAdapter, BedrockAdapterConfig, BEDROCK_CONVERSE_API_VERSION,
};
use chio_tool_call_fabric::{
    DenyReason, Principal, ProviderAdapter, ProviderError, ProviderId, ProviderRequest, ReceiptId,
    Redaction, ToolResult, VerdictResult,
};
use serde_json::{json, Value};

struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(NoopWaker));
    let mut cx = Context::from_waker(&waker);
    let mut future = Box::pin(future);

    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn adapter() -> BedrockAdapter {
    let cfg = BedrockAdapterConfig::new(
        "bedrock-1",
        "Bedrock Converse",
        "0.1.0",
        "deadbeef",
        "arn:aws:iam::123456789012:role/ChioAgentRole",
        "123456789012",
    )
    .with_assumed_role_session_arn(
        "arn:aws:sts::123456789012:assumed-role/ChioAgentRole/session-1",
    );
    BedrockAdapter::new(cfg, Arc::new(transport::MockTransport::new())).unwrap()
}

fn raw(value: Value) -> ProviderRequest {
    ProviderRequest(serde_json::to_vec(&value).unwrap())
}

fn tool_result(value: Value) -> ToolResult {
    ToolResult(serde_json::to_vec(&value).unwrap())
}

fn converse_fixture() -> Value {
    json!({
        "toolConfig": {
            "tools": [
                {
                    "toolSpec": {
                        "name": "get_weather",
                        "description": "Get weather",
                        "inputSchema": {
                            "json": {
                                "type": "object",
                                "properties": {
                                    "location": {"type": "string"},
                                    "unit": {"type": "string"}
                                },
                                "required": ["location"]
                            }
                        }
                    }
                },
                {
                    "toolSpec": {
                        "name": "search_docs",
                        "description": "Search docs",
                        "inputSchema": {
                            "json": {
                                "type": "object",
                                "properties": {"query": {"type": "string"}}
                            }
                        }
                    }
                }
            ]
        },
        "output": {
            "message": {
                "role": "assistant",
                "content": [
                    {"text": "checking"},
                    {
                        "toolUse": {
                            "toolUseId": "tooluse_weather_1",
                            "name": "get_weather",
                            "input": {
                                "unit": "celsius",
                                "location": "Boston"
                            }
                        }
                    },
                    {
                        "toolUse": {
                            "toolUseId": "tooluse_docs_1",
                            "name": "search_docs",
                            "input": {
                                "query": "Bedrock Converse toolUse"
                            }
                        }
                    }
                ]
            }
        }
    })
}

#[test]
fn adapter_reports_bedrock_provider_and_converse_pin() {
    let adapter = adapter();

    assert_eq!(adapter.provider(), ProviderId::Bedrock);
    assert_eq!(adapter.api_version(), BEDROCK_CONVERSE_API_VERSION);
    assert_eq!(adapter.api_version(), "bedrock.converse.v1");
    assert_eq!(adapter.region(), "us-east-1");
}

#[test]
fn lift_batch_converse_response_lifts_each_tool_use_block() {
    let adapter = adapter();

    let invocations = adapter.lift_batch(raw(converse_fixture())).unwrap();

    assert_eq!(invocations.len(), 2);
    assert_eq!(invocations[0].provider, ProviderId::Bedrock);
    assert_eq!(invocations[0].tool_name, "get_weather");
    assert_eq!(
        invocations[0].arguments,
        br#"{"location":"Boston","unit":"celsius"}"#.to_vec()
    );
    assert_eq!(invocations[0].provenance.provider, ProviderId::Bedrock);
    assert_eq!(invocations[0].provenance.request_id, "tooluse_weather_1");
    assert_eq!(
        invocations[0].provenance.api_version,
        BEDROCK_CONVERSE_API_VERSION
    );
    assert_eq!(
        invocations[0].provenance.principal,
        Principal::BedrockIam {
            caller_arn: "arn:aws:iam::123456789012:role/ChioAgentRole".to_string(),
            account_id: "123456789012".to_string(),
            assumed_role_session_arn: Some(
                "arn:aws:sts::123456789012:assumed-role/ChioAgentRole/session-1".to_string()
            ),
        }
    );

    assert_eq!(invocations[1].tool_name, "search_docs");
    assert_eq!(invocations[1].provenance.request_id, "tooluse_docs_1");
    assert_eq!(
        invocations[1].arguments,
        br#"{"query":"Bedrock Converse toolUse"}"#.to_vec()
    );
}

#[test]
fn lift_accepts_single_tool_use_content_block() {
    let adapter = adapter();
    let invocation = block_on(adapter.lift(raw(json!({
        "toolUse": {
            "toolUseId": "tooluse_direct_1",
            "name": "lookup_customer",
            "input": {"customer_id": "cust_8675309"}
        }
    }))))
    .unwrap();

    assert_eq!(invocation.tool_name, "lookup_customer");
    assert_eq!(invocation.provenance.request_id, "tooluse_direct_1");
    assert_eq!(
        invocation.arguments,
        br#"{"customer_id":"cust_8675309"}"#.to_vec()
    );
}

#[test]
fn trait_lift_fails_closed_for_parallel_tool_uses() {
    let adapter = adapter();
    let err = block_on(adapter.lift(raw(converse_fixture())))
        .expect_err("parallel tool uses should use lift_batch");

    assert!(err.to_string().contains("expected exactly one"));
}

#[test]
fn lower_allow_builds_bedrock_tool_result_content_block() {
    let adapter = adapter();
    let response = adapter
        .lower_tool_result(
            "tooluse_weather_1",
            VerdictResult::Allow {
                redactions: vec![],
                receipt_id: ReceiptId("rcpt_allow_1".to_string()),
            },
            tool_result(json!({"temperature": 64, "unit": "fahrenheit"})),
        )
        .unwrap();
    let value: Value = serde_json::from_slice(&response.0).unwrap();

    assert!(value.get("metadata").is_none());
    assert_eq!(value["toolResult"]["toolUseId"], "tooluse_weather_1");
    assert_eq!(value["toolResult"]["status"], "success");
    assert_eq!(
        value["toolResult"]["content"],
        json!([{"json": {"temperature": 64, "unit": "fahrenheit"}}])
    );
}

#[test]
fn lower_allow_applies_redactions_before_provider_serialization() {
    let adapter = adapter();
    let response = adapter
        .lower_tool_result(
            "tooluse_weather_1",
            VerdictResult::Allow {
                redactions: vec![Redaction {
                    path: "/token".to_string(),
                    replacement: "[redacted]".to_string(),
                }],
                receipt_id: ReceiptId("rcpt_allow_redacted".to_string()),
            },
            tool_result(json!({"token": "secret", "ok": true})),
        )
        .unwrap();
    let value: Value = serde_json::from_slice(&response.0).unwrap();

    assert_eq!(
        value["toolResult"]["content"],
        json!([{"json": {"token": "[redacted]", "ok": true}}])
    );
}

#[test]
fn lift_batch_provider_metadata_uses_receive_time() {
    let adapter = adapter();
    let before = SystemTime::now();

    let invocations = adapter.lift_batch(raw(converse_fixture())).unwrap();
    let after = SystemTime::now();

    assert_eq!(
        invocations[0].provenance.request_id,
        "tooluse_weather_1".to_string()
    );
    assert!(invocations[0].provenance.received_at >= before);
    assert!(invocations[0].provenance.received_at <= after);
    assert!(invocations[1].provenance.received_at >= before);
    assert!(invocations[1].provenance.received_at <= after);
}

#[test]
fn trait_lower_accepts_tool_use_id_envelope() {
    let adapter = adapter();
    let response = block_on(adapter.lower(
        VerdictResult::Allow {
            redactions: vec![],
            receipt_id: ReceiptId("rcpt_allow_2".to_string()),
        },
        tool_result(json!({
            "toolUseId": "tooluse_docs_1",
            "content": [{"json": {"matches": 3}}]
        })),
    ))
    .unwrap();
    let value: Value = serde_json::from_slice(&response.0).unwrap();

    assert_eq!(value["toolResult"]["toolUseId"], "tooluse_docs_1");
    assert_eq!(value["toolResult"]["status"], "success");
    assert_eq!(
        value["toolResult"]["content"],
        json!([{"json": {"matches": 3}}])
    );
}

#[test]
fn lower_deny_builds_error_tool_result_with_deterministic_reason() {
    let adapter = adapter();
    let response = block_on(adapter.lower(
        VerdictResult::Deny {
            reason: DenyReason::GuardDeny {
                guard_id: "bedrock_guard".to_string(),
                detail: "blocked pii".to_string(),
            },
            receipt_id: ReceiptId("rcpt_deny_1".to_string()),
        },
        tool_result(json!({
            "toolUseId": "tooluse_weather_1",
            "content": [{"json": {"ignored": true}}]
        })),
    ))
    .unwrap();
    let value: Value = serde_json::from_slice(&response.0).unwrap();

    assert_eq!(value["toolResult"]["toolUseId"], "tooluse_weather_1");
    assert_eq!(value["toolResult"]["status"], "error");
    assert_eq!(
        value["toolResult"]["content"],
        json!([
            {
                "json": {
                    "chio": {
                        "verdict": "deny",
                        "receiptId": "rcpt_deny_1",
                        "reason": {
                            "kind": "guard_deny",
                            "guard_id": "bedrock_guard",
                            "detail": "blocked pii"
                        }
                    }
                }
            }
        ])
    );
}

#[test]
fn lift_fails_closed_for_malformed_tool_use_shapes() {
    let adapter = adapter();
    let bad_json = ProviderRequest(b"{not json".to_vec());
    assert!(matches!(
        adapter.lift_batch(bad_json),
        Err(ProviderError::Malformed(_))
    ));

    let no_tool_use = adapter.lift_batch(raw(json!({
        "output": {"message": {"content": [{"text": "no tools"}]}}
    })));
    assert!(matches!(no_tool_use, Err(ProviderError::Malformed(_))));

    let scalar_input = adapter.lift_batch(raw(json!({
        "toolUse": {
            "toolUseId": "tooluse_bad_1",
            "name": "get_weather",
            "input": "not an object"
        }
    })));
    assert!(matches!(scalar_input, Err(ProviderError::BadToolArgs(_))));
}

#[test]
fn lift_fails_closed_when_tool_use_is_not_declared_in_tool_config() {
    let adapter = adapter();
    let err = adapter
        .lift_batch(raw(json!({
            "toolConfig": {
                "tools": [
                    {
                        "toolSpec": {
                            "name": "declared_tool",
                            "inputSchema": {"json": {"type": "object"}}
                        }
                    }
                ]
            },
            "output": {
                "message": {
                    "content": [
                        {
                            "toolUse": {
                                "toolUseId": "tooluse_bad_2",
                                "name": "undeclared_tool",
                                "input": {}
                            }
                        }
                    ]
                }
            }
        })))
        .expect_err("undeclared tool use should fail closed");

    assert!(err.to_string().contains("not declared in toolConfig"));
}

#[test]
fn lower_fails_closed_when_trait_result_lacks_tool_use_id() -> Result<(), String> {
    let adapter = adapter();
    let result = block_on(adapter.lower(
        VerdictResult::Allow {
            redactions: vec![],
            receipt_id: ReceiptId("rcpt_allow_missing_id".to_string()),
        },
        tool_result(json!({"ok": true})),
    ));

    let err = match result {
        Ok(_) => return Err("trait lower must preserve toolUseId".to_string()),
        Err(err) => err,
    };

    assert!(err
        .to_string()
        .contains("requires ToolResult JSON with toolUseId"));
    Ok(())
}
