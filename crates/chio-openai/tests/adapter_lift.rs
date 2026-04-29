#![cfg(feature = "provider-adapter")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use chio_core::canonical::canonical_json_bytes;
use chio_openai::adapter::{OpenAiAdapter, OpenAiAdapterConfig, OPENAI_RESPONSES_API_VERSION};
use chio_tool_call_fabric::{Principal, ProviderAdapter, ProviderId, ProviderRequest};
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

fn raw(value: Value) -> ProviderRequest {
    ProviderRequest(serde_json::to_vec(&value).unwrap())
}

#[test]
fn adapter_reports_openai_provider_and_snapshot_pin() {
    let adapter = OpenAiAdapter::new(OpenAiAdapterConfig::new("org_config"));

    assert_eq!(adapter.provider(), ProviderId::OpenAi);
    assert_eq!(adapter.api_version(), OPENAI_RESPONSES_API_VERSION);
    assert_eq!(adapter.api_version(), "responses.2026-04-25");
}

#[test]
fn lift_single_batch_response_builds_tool_invocation() {
    let adapter = OpenAiAdapter::new(OpenAiAdapterConfig::new("org_chio_demo"));
    let payload = raw(json!({
        "id": "resp_123",
        "object": "response",
        "output": [
            {
                "type": "message",
                "content": [{"type": "output_text", "text": "checking"}]
            },
            {
                "type": "function_call",
                "call_id": "call_weather_1",
                "name": "get_weather",
                "arguments": "{\"unit\":\"celsius\",\"location\":\"San Francisco, CA\"}"
            }
        ]
    }));

    let invocation = block_on(adapter.lift(payload)).unwrap();

    assert_eq!(invocation.provider, ProviderId::OpenAi);
    assert_eq!(invocation.tool_name, "get_weather");
    assert_eq!(
        invocation.arguments,
        canonical_json_bytes(&json!({
            "location": "San Francisco, CA",
            "unit": "celsius"
        }))
        .unwrap()
    );
    assert_eq!(invocation.provenance.provider, ProviderId::OpenAi);
    assert_eq!(invocation.provenance.request_id, "call_weather_1");
    assert_eq!(
        invocation.provenance.api_version,
        OPENAI_RESPONSES_API_VERSION
    );
    assert_eq!(
        invocation.provenance.principal,
        Principal::OpenAiOrg {
            org_id: "org_chio_demo".to_string()
        }
    );
}

#[test]
fn lift_reads_org_id_from_header_envelope() {
    let adapter = OpenAiAdapter::new(OpenAiAdapterConfig::new("org_config"));
    let payload = raw(json!({
        "headers": {
            "OpenAI-Organization": "org_from_header"
        },
        "body": {
            "output": [
                {
                    "type": "function_call",
                    "call_id": "call_search_1",
                    "name": "search_web",
                    "arguments": "{\"query\":\"chio\"}"
                }
            ]
        }
    }));

    let invocation = block_on(adapter.lift(payload)).unwrap();

    assert_eq!(
        invocation.provenance.principal,
        Principal::OpenAiOrg {
            org_id: "org_from_header".to_string()
        }
    );
}

#[test]
fn lift_accepts_single_function_call_item_payload() {
    let adapter = OpenAiAdapter::new("org_direct_item");
    let payload = raw(json!({
        "type": "function_call",
        "call_id": "call_direct_1",
        "name": "lookup_account",
        "arguments": "{\"account_id\":\"acct_123\"}"
    }));

    let invocation = block_on(adapter.lift(payload)).unwrap();

    assert_eq!(invocation.tool_name, "lookup_account");
    assert_eq!(invocation.provenance.request_id, "call_direct_1");
    assert_eq!(
        invocation.provenance.principal,
        Principal::OpenAiOrg {
            org_id: "org_direct_item".to_string()
        }
    );
}

#[test]
fn lift_batch_parallel_response_lifts_each_call() {
    let adapter = OpenAiAdapter::new("org_parallel");
    let invocations = adapter
        .lift_batch(raw(json!({
            "output": [
                {
                    "type": "function_call",
                    "call_id": "call_weather_1",
                    "name": "get_weather",
                    "arguments": "{\"location\":\"LA\"}"
                },
                {
                    "type": "function_call",
                    "call_id": "call_search_1",
                    "name": "search_web",
                    "arguments": "{\"query\":\"OpenAI Responses\"}"
                }
            ]
        })))
        .unwrap();

    assert_eq!(invocations.len(), 2);
    assert_eq!(invocations[0].tool_name, "get_weather");
    assert_eq!(invocations[0].provenance.request_id, "call_weather_1");
    assert_eq!(
        invocations[0].arguments,
        canonical_json_bytes(&json!({"location": "LA"})).unwrap()
    );
    assert_eq!(invocations[1].tool_name, "search_web");
    assert_eq!(invocations[1].provenance.request_id, "call_search_1");
    assert_eq!(
        invocations[1].arguments,
        canonical_json_bytes(&json!({"query": "OpenAI Responses"})).unwrap()
    );
}

#[test]
fn trait_lift_fails_closed_for_parallel_response() {
    let adapter = OpenAiAdapter::new("org_parallel");
    let err = block_on(adapter.lift(raw(json!({
        "output": [
            {
                "type": "function_call",
                "call_id": "call_1",
                "name": "first",
                "arguments": "{}"
            },
            {
                "type": "function_call",
                "call_id": "call_2",
                "name": "second",
                "arguments": "{}"
            }
        ]
    }))))
    .expect_err("parallel response should use lift_batch");

    assert!(err.to_string().contains("expected exactly one"));
}

#[test]
fn lift_fails_closed_for_malformed_arguments() {
    let adapter = OpenAiAdapter::new("org_config");
    let err = block_on(adapter.lift(raw(json!({
        "output": [
            {
                "type": "function_call",
                "call_id": "call_bad_args",
                "name": "get_weather",
                "arguments": "{not json"
            }
        ]
    }))))
    .expect_err("malformed arguments should deny lift");

    assert!(err
        .to_string()
        .contains("tool arguments failed schema validation"));
}
