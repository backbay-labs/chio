#![cfg(feature = "provider-adapter")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use chio_core::canonical::canonical_json_bytes;
use chio_openai::adapter::OpenAiAdapter;
use chio_tool_call_fabric::{
    DenyReason, ProviderAdapter, ProviderError, ProviderRequest, ReceiptId, Redaction, ToolResult,
    VerdictResult,
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

fn tool_result(value: Value) -> ToolResult {
    ToolResult(canonical_json_bytes(&value).unwrap())
}

fn response_json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

#[test]
fn lower_allow_single_output_into_openai_tool_outputs() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let result = tool_result(json!({
        "call_id": "call_weather_1",
        "output": {
            "forecast": "sunny",
            "temperature_c": 21
        }
    }));
    let verdict = VerdictResult::Allow {
        redactions: vec![],
        receipt_id: ReceiptId("rcpt_allow_1".to_string()),
    };

    let response = block_on(adapter.lower(verdict, result)).unwrap();
    let payload = response_json(&response.0);
    let outputs = payload["tool_outputs"].as_array().unwrap();

    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0]["type"], "function_call_output");
    assert_eq!(outputs[0]["call_id"], "call_weather_1");
    assert_eq!(
        outputs[0]["output"],
        "{\"forecast\":\"sunny\",\"temperature_c\":21}"
    );
}

#[test]
fn lower_rejects_multiple_outputs_for_single_verdict() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let result = tool_result(json!([
        {
            "call_id": "call_weather_1",
            "output": {"forecast": "sunny"}
        },
        {
            "tool_call_id": "call_search_1",
            "output": "top result"
        }
    ]));
    let verdict = VerdictResult::Allow {
        redactions: vec![],
        receipt_id: ReceiptId("rcpt_allow_1".to_string()),
    };

    let err = match block_on(adapter.lower(verdict, result)) {
        Ok(_) => panic!("multiple outputs for one verdict must fail"),
        Err(err) => err,
    };

    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err
        .to_string()
        .contains("expects exactly one tool output per verdict"));
}

#[test]
fn lower_deny_emits_synthetic_tool_output_with_reason() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let result = tool_result(json!({
        "call_id": "call_sensitive_1"
    }));
    let verdict = VerdictResult::Deny {
        reason: DenyReason::PolicyDeny {
            rule_id: "deny_pii".to_string(),
        },
        receipt_id: ReceiptId("rcpt_deny_1".to_string()),
    };

    let response = block_on(adapter.lower(verdict, result)).unwrap();
    let payload = response_json(&response.0);
    let outputs = payload["tool_outputs"].as_array().unwrap();
    let deny_payload: Value = serde_json::from_str(outputs[0]["output"].as_str().unwrap()).unwrap();

    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0]["type"], "function_call_output");
    assert_eq!(outputs[0]["call_id"], "call_sensitive_1");
    assert_eq!(deny_payload["verdict"], "deny");
    assert_eq!(deny_payload["synthetic"], true);
    assert_eq!(deny_payload["error"], "chio_denied_tool_call");
    assert_eq!(deny_payload["receipt_id"], "rcpt_deny_1");
    assert_eq!(deny_payload["reason"]["kind"], "policy_deny");
    assert_eq!(deny_payload["reason"]["rule_id"], "deny_pii");
}

#[test]
fn lower_allow_applies_redactions_before_provider_serialization() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let result = tool_result(json!({
        "call_id": "call_weather_1",
        "output": {
            "forecast": "sunny",
            "secret": "abc123"
        }
    }));
    let verdict = VerdictResult::Allow {
        redactions: vec![Redaction {
            path: "/secret".to_string(),
            replacement: "[redacted]".to_string(),
        }],
        receipt_id: ReceiptId("rcpt_allow_redacted".to_string()),
    };

    let response = block_on(adapter.lower(verdict, result)).unwrap();
    let payload = response_json(&response.0);
    let outputs = payload["tool_outputs"].as_array().unwrap();
    let output: Value = serde_json::from_str(outputs[0]["output"].as_str().unwrap()).unwrap();

    assert_eq!(output["forecast"], "sunny");
    assert_eq!(output["secret"], "[redacted]");
}

#[test]
fn lower_fails_closed_when_call_id_is_missing() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let result = tool_result(json!({
        "output": "orphaned result"
    }));
    let verdict = VerdictResult::Allow {
        redactions: vec![],
        receipt_id: ReceiptId("rcpt_allow_1".to_string()),
    };

    let err = match block_on(adapter.lower(verdict, result)) {
        Ok(_) => panic!("missing call_id must fail"),
        Err(err) => err,
    };

    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err.to_string().contains("missing non-empty call_id"));
}

#[test]
fn lower_fails_closed_when_allow_output_is_missing() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let result = tool_result(json!({
        "call_id": "call_empty_1"
    }));
    let verdict = VerdictResult::Allow {
        redactions: vec![],
        receipt_id: ReceiptId("rcpt_allow_1".to_string()),
    };

    let err = match block_on(adapter.lower(verdict, result)) {
        Ok(_) => panic!("missing output must fail"),
        Err(err) => err,
    };

    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err.to_string().contains("missing output for allow verdict"));
}

#[test]
fn lift_batch_fails_closed_on_missing_response_call_id() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let payload = json!({
        "output": [
            {
                "type": "function_call",
                "name": "search",
                "arguments": "{}"
            }
        ]
    });

    let err = adapter
        .lift_batch(ProviderRequest(serde_json::to_vec(&payload).unwrap()))
        .unwrap_err();

    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err.to_string().contains("missing non-empty call_id"));
}

#[test]
fn lift_batch_fails_closed_on_malformed_mixed_response_output() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let payload = json!({
        "output": [
            {
                "type": "message",
                "content": [{"type": "output_text", "text": "hello"}]
            },
            {
                "type": "function_call",
                "call_id": "fc_valid",
                "name": "search",
                "arguments": "{}"
            },
            {
                "type": "function_call",
                "call_id": "fc_bad",
                "name": "leaky_tool",
                "arguments": ""
            }
        ]
    });

    let err = adapter
        .lift_batch(ProviderRequest(serde_json::to_vec(&payload).unwrap()))
        .unwrap_err();

    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err.to_string().contains("missing non-empty arguments"));
}
