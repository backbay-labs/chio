#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use chio_anthropic_tools_adapter::transport::MockTransport;
use chio_anthropic_tools_adapter::{AnthropicAdapter, AnthropicAdapterConfig, ANTHROPIC_VERSION};
use chio_tool_call_fabric::{
    DenyReason, Principal, ProviderAdapter, ProviderId, ProviderRequest, ReceiptId, Redaction,
    ToolResult, VerdictResult,
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

fn adapter() -> AnthropicAdapter {
    let config = AnthropicAdapterConfig::new(
        "anthropic-1",
        "Anthropic Messages",
        "0.1.0",
        "deadbeef",
        "wks_chio_demo",
    );
    AnthropicAdapter::new(config, Arc::new(MockTransport::new()))
}

fn raw(value: Value) -> ProviderRequest {
    ProviderRequest(serde_json::to_vec(&value).unwrap())
}

fn allow_verdict() -> VerdictResult {
    VerdictResult::Allow {
        redactions: vec![],
        receipt_id: ReceiptId("rcpt_allow_1".to_string()),
    }
}

fn deny_verdict() -> VerdictResult {
    VerdictResult::Deny {
        reason: DenyReason::PolicyDeny {
            rule_id: "rule_no_network".to_string(),
        },
        receipt_id: ReceiptId("rcpt_deny_1".to_string()),
    }
}

#[test]
fn adapter_reports_anthropic_provider_and_snapshot_pin() {
    let adapter = adapter();

    assert_eq!(adapter.provider(), ProviderId::Anthropic);
    assert_eq!(adapter.api_version(), ANTHROPIC_VERSION);
    assert_eq!(adapter.api_version(), "2023-06-01");
}

#[test]
fn lift_single_message_response_builds_tool_invocation() {
    let adapter = adapter();
    let payload = raw(json!({
        "id": "msg_01single",
        "type": "message",
        "role": "assistant",
        "content": [
            { "type": "text", "text": "checking" },
            {
                "type": "tool_use",
                "id": "toolu_weather_1",
                "name": "get_weather",
                "input": {
                    "unit": "celsius",
                    "location": "San Francisco, CA"
                }
            }
        ]
    }));

    let invocation = block_on(adapter.lift(payload)).unwrap();

    assert_eq!(invocation.provider, ProviderId::Anthropic);
    assert_eq!(invocation.tool_name, "get_weather");
    assert_eq!(
        String::from_utf8(invocation.arguments).unwrap(),
        "{\"location\":\"San Francisco, CA\",\"unit\":\"celsius\"}"
    );
    assert_eq!(invocation.provenance.provider, ProviderId::Anthropic);
    assert_eq!(invocation.provenance.request_id, "toolu_weather_1");
    assert_eq!(invocation.provenance.api_version, "2023-06-01");
    assert_eq!(
        invocation.provenance.principal,
        Principal::AnthropicWorkspace {
            workspace_id: "wks_chio_demo".to_string()
        }
    );
}

#[test]
fn lift_accepts_envelope_with_string_body() {
    let adapter = adapter();
    let body = serde_json::to_string(&json!({
        "content": [
            {
                "type": "tool_use",
                "id": "toolu_translate_1",
                "name": "translate_text",
                "input": {
                    "text": "Chio mediates tools.",
                    "target_lang": "es"
                }
            }
        ]
    }))
    .unwrap();
    let payload = raw(json!({ "body": body }));

    let invocation = block_on(adapter.lift(payload)).unwrap();

    assert_eq!(invocation.tool_name, "translate_text");
    assert_eq!(invocation.provenance.request_id, "toolu_translate_1");
}

#[test]
fn lift_batch_parallel_response_lifts_each_tool_use() {
    let adapter = adapter();
    let invocations = adapter
        .lift_batch(raw(json!({
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_weather_1",
                    "name": "get_weather",
                    "input": { "location": "LA" }
                },
                {
                    "type": "tool_use",
                    "id": "toolu_search_1",
                    "name": "search_web",
                    "input": { "query": "Anthropic Messages" }
                }
            ]
        })))
        .unwrap();

    assert_eq!(invocations.len(), 2);
    assert_eq!(invocations[0].tool_name, "get_weather");
    assert_eq!(invocations[0].provenance.request_id, "toolu_weather_1");
    assert_eq!(
        String::from_utf8(invocations[0].arguments.clone()).unwrap(),
        "{\"location\":\"LA\"}"
    );
    assert_eq!(invocations[1].tool_name, "search_web");
    assert_eq!(invocations[1].provenance.request_id, "toolu_search_1");
    assert_eq!(
        String::from_utf8(invocations[1].arguments.clone()).unwrap(),
        "{\"query\":\"Anthropic Messages\"}"
    );
}

#[test]
fn trait_lift_fails_closed_for_parallel_response() {
    let adapter = adapter();
    let err = block_on(adapter.lift(raw(json!({
        "content": [
            {
                "type": "tool_use",
                "id": "toolu_1",
                "name": "first",
                "input": {}
            },
            {
                "type": "tool_use",
                "id": "toolu_2",
                "name": "second",
                "input": {}
            }
        ]
    }))))
    .expect_err("parallel response should use lift_batch");

    assert!(err.to_string().contains("expected exactly one"));
}

#[test]
fn lift_fails_closed_for_non_object_input() {
    let adapter = adapter();
    let err = block_on(adapter.lift(raw(json!({
        "content": [
            {
                "type": "tool_use",
                "id": "toolu_bad_input",
                "name": "get_weather",
                "input": "not an object"
            }
        ]
    }))))
    .expect_err("non-object input should deny lift");

    assert!(err
        .to_string()
        .contains("tool arguments failed schema validation"));
}

#[cfg(not(feature = "computer-use"))]
#[test]
fn lift_fails_closed_for_server_tool_without_feature() {
    let adapter = adapter();
    let err = block_on(adapter.lift(raw(json!({
        "content": [
            {
                "type": "tool_use",
                "id": "toolu_server_tool",
                "name": "computer_use_20241022",
                "input": { "action": "screenshot" }
            }
        ]
    }))))
    .expect_err("server tools require feature flag");

    assert!(err.to_string().contains("computer-use"));
}

#[test]
fn lower_allow_emits_tool_result_with_executed_content() {
    let adapter = adapter();
    let invocations = adapter
        .lift_batch(raw(json!({
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_weather_1",
                    "name": "get_weather",
                    "input": { "location": "LA" }
                }
            ]
        })))
        .unwrap();
    assert_eq!(invocations.len(), 1);

    let response = block_on(
        adapter.lower(
            allow_verdict(),
            ToolResult(
                br#"{"tool_use_id":"toolu_weather_1","content":[{"type":"text","text":"72F"}]}"#
                    .to_vec(),
            ),
        ),
    )
    .unwrap();
    let block: Value = serde_json::from_slice(&response.0).unwrap();

    assert_eq!(block["type"], "tool_result");
    assert_eq!(block["tool_use_id"], "toolu_weather_1");
    assert_eq!(block["is_error"], false);
    assert_eq!(block["content"][0]["text"], "72F");
}

#[test]
fn lower_deny_emits_error_tool_result_with_reason() {
    let adapter = adapter();
    let invocation = block_on(adapter.lift(raw(json!({
        "content": [
            {
                "type": "tool_use",
                "id": "toolu_search_1",
                "name": "search_web",
                "input": { "query": "blocked" }
            }
        ]
    }))))
    .unwrap();
    assert_eq!(invocation.provenance.request_id, "toolu_search_1");

    let response = block_on(adapter.lower(
        deny_verdict(),
        ToolResult(br#"{"tool_use_id":"toolu_search_1"}"#.to_vec()),
    ))
    .unwrap();
    let block: Value = serde_json::from_slice(&response.0).unwrap();

    assert_eq!(block["type"], "tool_result");
    assert_eq!(block["tool_use_id"], "toolu_search_1");
    assert_eq!(block["is_error"], true);
    assert_eq!(block["content"][0]["text"], "policy_deny: rule_no_network");
}

#[test]
fn lower_without_pending_tool_use_fails_closed() {
    let adapter = adapter();
    let result = block_on(adapter.lower(allow_verdict(), ToolResult(b"{}".to_vec())));
    assert!(result.is_err(), "lower needs an explicit tool_use id");
    let err = result.err().unwrap();

    assert!(err
        .to_string()
        .contains("requires ToolResult JSON with tool_use_id"));
}

#[test]
fn lower_allow_applies_redactions_before_provider_serialization() {
    let adapter = adapter();
    let response = block_on(
        adapter.lower(
            VerdictResult::Allow {
                redactions: vec![Redaction {
                    path: "/0/text".to_string(),
                    replacement: "[redacted]".to_string(),
                }],
                receipt_id: ReceiptId("rcpt_allow_redacted".to_string()),
            },
            ToolResult(
                br#"{"tool_use_id":"toolu_weather_1","content":[{"type":"text","text":"secret"}]}"#
                    .to_vec(),
            ),
        ),
    )
    .unwrap();
    let block: Value = serde_json::from_slice(&response.0).unwrap();

    assert_eq!(block["tool_use_id"], "toolu_weather_1");
    assert_eq!(block["content"][0]["text"], "[redacted]");
}
