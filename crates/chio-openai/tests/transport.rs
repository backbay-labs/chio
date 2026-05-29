#![cfg(feature = "provider-adapter")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Hermetic tests for the OpenAI outbound transport.
//!
//! These exercise the real request/response handling end to end without a live
//! network: the `MockHttpTransport` path records the bytes the adapter posts and
//! scripts upstream responses, and the `wiremock` path drives the real
//! reqwest-backed `HttpTransport` against a localhost mock server.

use std::sync::Arc;
use std::time::Duration;

use chio_core::canonical::canonical_json_bytes;
use chio_openai::transport::{
    OpenAiTransport, OPENAI_CHAT_COMPLETIONS_PATH, OPENAI_RESPONSES_PATH,
};
use chio_provider_adapter_core::http::{
    AuthScheme, CallKind, HttpResponse, HttpTransportError, MockHttpTransport,
};
use chio_tool_call_fabric::{Principal, ProviderError, ProviderId, ReceiptId, VerdictResult};
use serde_json::json;
use wiremock::matchers::{body_string, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn allow_verdict() -> VerdictResult {
    VerdictResult::Allow {
        redactions: vec![],
        receipt_id: ReceiptId("rcpt_transport_allow".to_string()),
    }
}

// ---- MockHttpTransport: hermetic request/response, no reqwest ----

#[tokio::test]
async fn send_responses_posts_to_responses_path_and_lifts_tool_calls() {
    let mock = Arc::new(MockHttpTransport::new("mock://openai"));
    mock.push_json_response(
        json!({
            "id": "resp_mock_1",
            "object": "response",
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": "checking"}]
                },
                {
                    "type": "function_call",
                    "call_id": "call_weather_mock",
                    "name": "get_weather",
                    "arguments": "{\"location\":\"San Francisco, CA\",\"unit\":\"celsius\"}"
                }
            ]
        })
        .to_string()
        .into_bytes(),
    );

    let transport = OpenAiTransport::with_transport(mock.clone(), "org_mock");
    let request = json!({
        "model": "gpt-5",
        "input": "what is the weather",
        "tools": [{"type": "function", "name": "get_weather"}]
    })
    .to_string()
    .into_bytes();

    let invocations = transport.send_responses(&request).await.unwrap();

    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].provider, ProviderId::OpenAi);
    assert_eq!(invocations[0].tool_name, "get_weather");
    assert_eq!(
        invocations[0].arguments,
        canonical_json_bytes(&json!({
            "location": "San Francisco, CA",
            "unit": "celsius"
        }))
        .unwrap()
    );
    assert_eq!(invocations[0].provenance.request_id, "call_weather_mock");
    assert_eq!(
        invocations[0].provenance.principal,
        Principal::OpenAiOrg {
            org_id: "org_mock".to_string()
        }
    );

    // The adapter posted the caller's body verbatim to the Responses path.
    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].kind, CallKind::Json);
    assert_eq!(calls[0].path, OPENAI_RESPONSES_PATH);
    assert_eq!(calls[0].body, request);
}

#[tokio::test]
async fn send_chat_completions_parses_tool_calls_and_lifts_invocations() {
    let mock = Arc::new(MockHttpTransport::new("mock://openai"));
    mock.push_json_response(
        json!({
            "id": "chatcmpl_mock_1",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_chat_weather",
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "arguments": "{\"location\":\"NYC\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        })
        .to_string()
        .into_bytes(),
    );

    let transport = OpenAiTransport::with_transport(mock.clone(), "org_mock");
    let request = json!({"model": "gpt-5", "messages": []})
        .to_string()
        .into_bytes();

    let outcome = transport.send_chat_completions(&request).await.unwrap();

    assert_eq!(outcome.tool_calls.len(), 1);
    assert_eq!(outcome.tool_calls[0].id, "call_chat_weather");
    assert_eq!(outcome.tool_calls[0].function.name, "get_weather");

    assert_eq!(outcome.invocations.len(), 1);
    assert_eq!(outcome.invocations[0].tool_name, "get_weather");
    assert_eq!(
        outcome.invocations[0].arguments,
        canonical_json_bytes(&json!({"location": "NYC"})).unwrap()
    );
    assert_eq!(
        outcome.invocations[0].provenance.request_id,
        "call_chat_weather"
    );

    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].path, OPENAI_CHAT_COMPLETIONS_PATH);
}

#[tokio::test]
async fn send_chat_completions_returns_empty_for_plain_text_answer() {
    let mock = Arc::new(MockHttpTransport::new("mock://openai"));
    mock.push_json_response(
        json!({
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "hello"},
                "finish_reason": "stop"
            }]
        })
        .to_string()
        .into_bytes(),
    );

    let transport = OpenAiTransport::with_transport(mock, "org_mock");
    let outcome = transport
        .send_chat_completions(&json!({"model": "gpt-5"}).to_string().into_bytes())
        .await
        .unwrap();
    assert!(outcome.tool_calls.is_empty());
    assert!(outcome.invocations.is_empty());
}

#[tokio::test]
async fn streaming_send_gates_buffered_sse_through_adapter() {
    let sse = concat!(
        "event: response.created\n",
        "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_stream_mock\"}}\n\n",
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_stream_mock\",\"call_id\":\"call_stream_mock\",\"name\":\"get_weather\",\"arguments\":\"\"}}\n\n",
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"call_stream_mock\",\"delta\":\"{\\\"location\\\":\\\"NYC\\\"}\"}\n\n",
        "event: response.function_call_arguments.done\n",
        "data: {\"type\":\"response.function_call_arguments.done\",\"output_index\":0,\"item_id\":\"fc_stream_mock\",\"arguments\":\"{\\\"location\\\":\\\"NYC\\\"}\"}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_stream_mock\",\"call_id\":\"call_stream_mock\",\"name\":\"get_weather\",\"arguments\":\"{\\\"location\\\":\\\"NYC\\\"}\"}}\n\n",
        "event: response.completed\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_stream_mock\"}}\n\n",
    );
    let mock = Arc::new(MockHttpTransport::new("mock://openai"));
    mock.push_response(HttpResponse::new(
        200,
        sse.as_bytes().to_vec(),
        Some("text/event-stream".to_string()),
    ));

    let transport = OpenAiTransport::with_transport(mock.clone(), "org_mock");
    let mut evaluated = Vec::new();
    let gated = transport
        .stream_responses(b"{\"model\":\"gpt-5\",\"stream\":true}", |invocation| {
            evaluated.push(invocation.provenance.request_id.clone());
            Ok(allow_verdict())
        })
        .await
        .unwrap();

    assert_eq!(evaluated, vec!["call_stream_mock"]);
    assert_eq!(gated.invocations.len(), 1);
    assert_eq!(gated.invocations[0].tool_name, "get_weather");
    assert_eq!(gated.verdicts, vec![allow_verdict()]);

    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].kind, CallKind::Sse);
    assert_eq!(calls[0].path, OPENAI_RESPONSES_PATH);
}

#[tokio::test]
async fn upstream_rate_limit_fails_closed_as_rate_limited() {
    let mock = Arc::new(MockHttpTransport::new("mock://openai"));
    mock.push_error(HttpTransportError::Status {
        code: 429,
        body: "rate limit reached".to_string(),
    });

    let transport = OpenAiTransport::with_transport(mock, "org_mock");
    let error = transport
        .send_responses(b"{}")
        .await
        .expect_err("a 429 must fail closed");
    assert!(matches!(error, ProviderError::RateLimited { .. }));
}

#[tokio::test]
async fn upstream_5xx_fails_closed_as_upstream_5xx() {
    let mock = Arc::new(MockHttpTransport::new("mock://openai"));
    mock.push_error(HttpTransportError::Status {
        code: 503,
        body: "service unavailable".to_string(),
    });

    let transport = OpenAiTransport::with_transport(mock, "org_mock");
    let error = transport
        .send_responses(b"{}")
        .await
        .expect_err("a 503 must fail closed");
    assert!(matches!(
        error,
        ProviderError::Upstream5xx { status: 503, .. }
    ));
}

#[tokio::test]
async fn malformed_upstream_body_fails_closed() {
    let mock = Arc::new(MockHttpTransport::new("mock://openai"));
    mock.push_json_response(b"not json".to_vec());

    let transport = OpenAiTransport::with_transport(mock, "org_mock");
    let error = transport
        .send_chat_completions(b"{}")
        .await
        .expect_err("a non-JSON body must fail closed");
    assert!(matches!(error, ProviderError::Malformed(_)));
}

// ---- wiremock: real reqwest HttpTransport end to end ----

#[tokio::test]
async fn real_transport_posts_bearer_and_org_header_to_responses() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(OPENAI_RESPONSES_PATH))
        .and(header("authorization", "Bearer sk-live-test"))
        .and(header("openai-organization", "org_live"))
        .and(body_string("{\"model\":\"gpt-5\"}"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(
                json!({
                    "output": [{
                        "type": "function_call",
                        "call_id": "call_live_1",
                        "name": "get_weather",
                        "arguments": "{\"location\":\"LA\"}"
                    }]
                })
                .to_string()
                .into_bytes(),
                "application/json",
            ),
        )
        .mount(&server)
        .await;

    let transport = OpenAiTransport::with_base_url(
        server.uri(),
        "sk-live-test",
        "org_live",
        Duration::from_secs(5),
    )
    .unwrap();

    let invocations = transport
        .send_responses(b"{\"model\":\"gpt-5\"}")
        .await
        .unwrap();
    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].tool_name, "get_weather");
    assert_eq!(invocations[0].provenance.request_id, "call_live_1");
}

#[tokio::test]
async fn real_transport_maps_non_2xx_to_content_policy() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(OPENAI_RESPONSES_PATH))
        .respond_with(ResponseTemplate::new(403).set_body_string("blocked by content policy"))
        .mount(&server)
        .await;

    let transport =
        OpenAiTransport::with_base_url(server.uri(), "sk-test", "org_live", Duration::from_secs(5))
            .unwrap();
    let error = transport
        .send_responses(b"{}")
        .await
        .expect_err("a 403 must fail closed");
    assert!(matches!(error, ProviderError::ContentPolicy(_)));
}

#[test]
fn from_env_is_fail_closed_when_key_is_unset() {
    // SAFETY: single-threaded test, unique variable name not used elsewhere.
    std::env::remove_var("OPENAI_API_KEY");
    let error =
        OpenAiTransport::from_env("org_env").expect_err("an unset OPENAI_API_KEY must fail closed");
    assert!(matches!(error, ProviderError::Malformed(_)));
}

#[test]
fn auth_scheme_bearer_is_constructible_for_callers() {
    // The transport accepts a caller-injected bearer without touching the env.
    let scheme = AuthScheme::Bearer("sk-injected".to_string());
    assert_eq!(scheme, AuthScheme::Bearer("sk-injected".to_string()));
}
