#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use chio_anthropic_tools_adapter::transport::MockTransport;
use chio_anthropic_tools_adapter::{AnthropicAdapter, AnthropicAdapterConfig};
use chio_tool_call_fabric::{
    DenyReason, ProviderAdapter, ProviderError, ProviderId, ProviderRequest, ReceiptId, Redaction,
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

fn allow_verdict() -> VerdictResult {
    VerdictResult::Allow {
        redactions: vec![],
        receipt_id: ReceiptId("rcpt_stream_allow".to_string()),
    }
}

fn deny_verdict() -> VerdictResult {
    VerdictResult::Deny {
        reason: DenyReason::PolicyDeny {
            rule_id: "rule_no_network".to_string(),
        },
        receipt_id: ReceiptId("rcpt_stream_deny".to_string()),
    }
}

fn raw(value: Value) -> ProviderRequest {
    ProviderRequest(serde_json::to_vec(&value).unwrap())
}

fn tool_use_stream() -> Vec<u8> {
    br#"event: message_start
data: {"type":"message_start","message":{"id":"msg_stream_1","type":"message","role":"assistant","content":[]}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_weather_1","name":"get_weather","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"location\":\"LA\""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":",\"unit\":\"f\"}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_stop
data: {"type":"message_stop"}

"#
    .to_vec()
}

#[test]
fn gates_tool_use_at_content_block_start_and_forwards_after_allow() {
    let adapter = adapter();
    let mut calls = 0;
    let gated = adapter
        .gate_sse_stream(&tool_use_stream(), |invocation| {
            calls += 1;
            assert_eq!(invocation.provider, ProviderId::Anthropic);
            assert_eq!(invocation.tool_name, "get_weather");
            assert_eq!(invocation.provenance.request_id, "toolu_weather_1");
            assert_eq!(
                String::from_utf8(invocation.arguments.clone()).unwrap(),
                "{\"location\":\"LA\",\"unit\":\"f\"}"
            );
            Ok(allow_verdict())
        })
        .unwrap();

    assert_eq!(calls, 1);
    assert_eq!(gated.invocations.len(), 1);
    assert_eq!(gated.verdicts, vec![allow_verdict()]);
    let forwarded = String::from_utf8(gated.bytes).unwrap();
    assert!(forwarded.contains("event: content_block_start"));
    assert!(forwarded.contains("toolu_weather_1"));
    assert!(forwarded.contains("input_json_delta"));
    assert!(forwarded.contains("event: message_stop"));

    let lowered = block_on(
        adapter.lower(
            allow_verdict(),
            ToolResult(
                br#"{"tool_use_id":"toolu_weather_1","content":[{"type":"text","text":"72F"}]}"#
                    .to_vec(),
            ),
        ),
    )
    .unwrap();
    let lowered: Value = serde_json::from_slice(&lowered.0).unwrap();
    assert_eq!(lowered["tool_use_id"], "toolu_weather_1");
    assert_eq!(lowered["is_error"], false);
}

#[test]
fn denied_tool_use_start_fails_closed() {
    let adapter = adapter();
    let err = adapter
        .gate_sse_stream(&tool_use_stream(), |_invocation| Ok(deny_verdict()))
        .expect_err("deny verdict should close the stream");

    assert!(err.to_string().contains("denied at content_block_stop"));

    let lower = block_on(adapter.lower(allow_verdict(), ToolResult(b"{}".to_vec())));
    assert!(lower.is_err());
    let lower_error = lower.err().unwrap();
    assert!(lower_error
        .to_string()
        .contains("requires ToolResult JSON with tool_use_id"));
}

#[test]
fn forbidden_late_input_json_delta_fails_closed_before_forwarding() {
    let adapter = adapter();
    let err = adapter
        .gate_sse_stream(&tool_use_stream(), |invocation| {
            let args = String::from_utf8(invocation.arguments.clone()).unwrap();
            if args.contains("\"unit\":\"f\"") {
                Ok(deny_verdict())
            } else {
                Ok(allow_verdict())
            }
        })
        .expect_err("late forbidden args should deny after reconstruction");

    assert!(err.to_string().contains("denied at content_block_stop"));
}

#[test]
fn non_empty_start_input_with_delta_fails_closed() {
    let adapter = adapter();
    let stream = br#"event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_split_1","name":"get_weather","input":{"secret":"forbidden"}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"location\":\"LA\"}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

"#;
    let mut calls = 0;
    let err = adapter
        .gate_sse_stream(stream, |_invocation| {
            calls += 1;
            Ok(allow_verdict())
        })
        .expect_err("mixed start and delta args should fail closed");

    assert_eq!(calls, 0);
    assert!(err.to_string().contains("mixed non-empty start input"));
}

#[test]
fn malformed_json_event_fails_closed() {
    let adapter = adapter();
    let stream = br#"event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":

"#;
    let err = adapter
        .gate_sse_stream(stream, |_invocation| Ok(allow_verdict()))
        .expect_err("invalid event JSON should fail closed");

    assert!(err.to_string().contains("SSE data was not JSON"));
}

#[test]
fn input_json_delta_without_active_tool_fails_closed() {
    let adapter = adapter();
    let stream = br#"event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}

"#;
    let err = adapter
        .gate_sse_stream(stream, |_invocation| Ok(allow_verdict()))
        .expect_err("delta outside a content block should fail closed");

    assert!(err.to_string().contains("without an active content block"));
}

#[test]
fn text_content_stream_passes_without_verdict() {
    let adapter = adapter();
    let stream = br#"event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_stop
data: {"type":"message_stop"}

"#;
    let mut calls = 0;
    let gated = adapter
        .gate_sse_stream(stream, |_invocation| {
            calls += 1;
            Ok(allow_verdict())
        })
        .unwrap();

    assert_eq!(calls, 0);
    assert!(gated.invocations.is_empty());
    assert_eq!(gated.bytes, stream);
}

#[test]
fn batch_lift_lower_behavior_still_round_trips() {
    let adapter = adapter();
    let invocations = adapter
        .lift_batch(raw(json!({
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_batch_1",
                    "name": "get_weather",
                    "input": { "location": "Boston", "unit": "celsius" }
                }
            ]
        })))
        .unwrap();

    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].tool_name, "get_weather");
    assert_eq!(
        String::from_utf8(invocations[0].arguments.clone()).unwrap(),
        "{\"location\":\"Boston\",\"unit\":\"celsius\"}"
    );

    let lowered = block_on(adapter.lower(
        allow_verdict(),
        ToolResult(
            br#"{"tool_use_id":"toolu_batch_1","content":[{"type":"text","text":"5C"}]}"#.to_vec(),
        ),
    ))
    .unwrap();
    let lowered: Value = serde_json::from_slice(&lowered.0).unwrap();

    assert_eq!(lowered["tool_use_id"], "toolu_batch_1");
    assert_eq!(lowered["content"][0]["text"], "5C");
}

#[test]
fn lower_allow_applies_redactions_before_serialization() {
    let adapter = adapter();
    let verdict = VerdictResult::Allow {
        redactions: vec![Redaction {
            path: "/0/text".to_string(),
            replacement: "[redacted]".to_string(),
        }],
        receipt_id: ReceiptId("rcpt_allow_redacted".to_string()),
    };

    let block = adapter
        .lower_tool_result_block(
            "toolu_weather_1",
            verdict,
            ToolResult(br#"[{"type":"text","text":"secret"}]"#.to_vec()),
        )
        .unwrap();

    assert_eq!(block.tool_use_id, "toolu_weather_1");
    assert_eq!(block.content[0]["text"], "[redacted]");
}

#[test]
fn evaluator_errors_fail_closed() {
    let adapter = adapter();
    let err = adapter
        .gate_sse_stream(&tool_use_stream(), |_invocation| {
            Err(ProviderError::VerdictBudgetExceeded {
                observed_ms: 300,
                budget_ms: 250,
            })
        })
        .expect_err("verdict evaluator errors should fail closed");

    assert!(err.to_string().contains("verdict latency budget exceeded"));
}
