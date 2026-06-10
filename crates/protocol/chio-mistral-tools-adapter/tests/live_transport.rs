//! Hermetic exercise of the real `MistralHttpTransport` against a local mock
//! HTTP server. No live network: `wiremock` binds an ephemeral localhost port
//! and we point the transport at it through `HttpTransportConfig`. This proves
//! the real reqwest request/response path (bearer auth, JSON POST to
//! `/v1/chat/completions`, response parse into the adapter's invocation type).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use chio_mistral_tools_adapter::transport::{
    MistralHttpTransport, MISTRAL_API_VERSION, MISTRAL_CHAT_COMPLETIONS_PATH,
};
use chio_mistral_tools_adapter::{MistralAdapter, MistralAdapterConfig, MistralChatRequest};
use chio_provider_adapter_core::http::{AuthScheme, HttpTransportConfig};
use chio_tool_call_fabric::ProviderId;
use serde_json::{json, Value};
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config() -> MistralAdapterConfig {
    MistralAdapterConfig::new(
        "mistral-live",
        "Mistral Live",
        "0.1.0",
        "deadbeef",
        "proj_chio_live",
    )
}

fn chat_request() -> MistralChatRequest {
    MistralChatRequest::new(
        "mistral-large-latest",
        vec![json!({"role": "user", "content": "What is the weather in Paris?"})],
        vec![json!({
            "type": "function",
            "function": {
                "name": "get_weather",
                "parameters": {
                    "type": "object",
                    "properties": {"city": {"type": "string"}},
                    "required": ["city"]
                }
            }
        })],
    )
}

#[tokio::test]
async fn real_transport_posts_with_bearer_and_lifts_tool_calls() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(MISTRAL_CHAT_COMPLETIONS_PATH))
        .and(header("authorization", "Bearer sk-mistral-test"))
        .and(header("x-mistral-api-version", MISTRAL_API_VERSION))
        .and(body_partial_json(json!({"model": "mistral-large-latest"})))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(
                serde_json::to_vec(&json!({
                    "id": "chatcmpl_live",
                    "object": "chat.completion",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "tool_calls": [{
                                "id": "call_live_1",
                                "type": "function",
                                "function": {
                                    "name": "get_weather",
                                    "arguments": "{\"city\":\"Paris\"}"
                                }
                            }]
                        },
                        "finish_reason": "tool_calls"
                    }]
                }))
                .unwrap(),
                "application/json",
            ),
        )
        .mount(&server)
        .await;

    // Point the real transport at the local mock server instead of the pinned
    // production host.
    let http_config = HttpTransportConfig::new(server.uri())
        .with_auth(AuthScheme::Bearer("sk-mistral-test".to_string()))
        .with_header("x-mistral-api-version", MISTRAL_API_VERSION);
    let transport = MistralHttpTransport::from_config(http_config).unwrap();
    let adapter = MistralAdapter::new(config(), Arc::new(transport));

    let invocations = adapter
        .send_chat_completion(&chat_request())
        .await
        .expect("the real transport path must lift tool calls");
    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].tool_name, "get_weather");
    assert_eq!(invocations[0].provider, ProviderId::Mistral);
    let args: Value = serde_json::from_slice(&invocations[0].arguments).unwrap();
    assert_eq!(args["city"], "Paris");
}

#[tokio::test]
async fn real_transport_maps_upstream_429_to_rate_limited() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(MISTRAL_CHAT_COMPLETIONS_PATH))
        .respond_with(ResponseTemplate::new(429).set_body_string("rate limited"))
        .mount(&server)
        .await;

    let http_config = HttpTransportConfig::new(server.uri())
        .with_auth(AuthScheme::Bearer("sk-mistral-test".to_string()));
    let transport = MistralHttpTransport::from_config(http_config).unwrap();
    let adapter = MistralAdapter::new(config(), Arc::new(transport));

    let error = adapter
        .send_chat_completion(&chat_request())
        .await
        .expect_err("a 429 must fail closed");
    assert!(matches!(
        error,
        chio_tool_call_fabric::ProviderError::RateLimited { .. }
    ));
}

#[tokio::test]
async fn real_transport_streams_and_gates_tool_calls() {
    let server = MockServer::start().await;
    let chunk = json!({
        "id": "chatcmpl_live_stream",
        "object": "chat.completion.chunk",
        "choices": [{
            "index": 0,
            "delta": {
                "tool_calls": [{
                    "id": "call_live_stream_1",
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "arguments": "{\"city\":\"Paris\"}"
                    }
                }]
            }
        }]
    });
    let mut sse = b"data: ".to_vec();
    sse.extend_from_slice(&serde_json::to_vec(&chunk).unwrap());
    sse.extend_from_slice(b"\n\n");

    Mock::given(method("POST"))
        .and(path(MISTRAL_CHAT_COMPLETIONS_PATH))
        .and(body_partial_json(json!({"stream": true})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_raw(sse, "text/event-stream"),
        )
        .mount(&server)
        .await;

    let http_config = HttpTransportConfig::new(server.uri())
        .with_auth(AuthScheme::Bearer("sk-mistral-test".to_string()));
    let transport = MistralHttpTransport::from_config(http_config).unwrap();
    let adapter = MistralAdapter::new(config(), Arc::new(transport));

    let verdict = chio_tool_call_fabric::VerdictResult::Allow {
        redactions: vec![],
        receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_live_stream".into()),
    };
    let gated = adapter
        .send_chat_completion_stream(&chat_request(), |_invocation| Ok(verdict.clone()))
        .await
        .expect("the streaming transport path must gate tool calls");
    assert_eq!(gated.invocations.len(), 1);
    assert_eq!(gated.invocations[0].tool_name, "get_weather");
}
