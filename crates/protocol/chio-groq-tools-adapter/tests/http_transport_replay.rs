//! Hermetic end-to-end test of the real reqwest-backed Groq transport.
//!
//! These tests stand up a local `wiremock` server and drive the adapter's real
//! [`HttpTransport`] against it, proving the full outbound path (Bearer auth,
//! the OpenAI-compatible chat/completions request body, and the tool-call
//! response parse) without any live network access.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use chio_groq_tools_adapter::transport::{groq_transport_config, AuthScheme, HttpTransport};
use chio_groq_tools_adapter::{GroqAdapter, GroqAdapterConfig, GROQ_CHAT_COMPLETIONS_PATH};
use chio_tool_call_fabric::ProviderError;
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn adapter(server_uri: &str) -> GroqAdapter {
    // Point the real transport at the wiremock base URL while keeping the
    // production Bearer auth scheme and pinned version header.
    let mut config = groq_transport_config(AuthScheme::Bearer("sk-groq-test".to_string()));
    config.base_url = server_uri.to_string();
    let transport = HttpTransport::new(config).expect("transport builds");

    let cfg = GroqAdapterConfig::new(
        "groq-http",
        "Groq HTTP",
        "0.1.0",
        "deadbeef",
        "org_chio_demo",
    );
    GroqAdapter::new(cfg, Arc::new(transport))
}

fn request_body() -> serde_json::Value {
    json!({
        "model": "llama-3.3-70b-versatile",
        "messages": [{"role": "user", "content": "What is the weather in San Francisco?"}],
        "tools": [{
            "type": "function",
            "function": {
                "name": "get_weather",
                "parameters": {"type": "object", "properties": {"location": {"type": "string"}}}
            }
        }]
    })
}

#[tokio::test]
async fn real_transport_posts_bearer_and_lifts_tool_calls() {
    let server = MockServer::start().await;
    let response = json!({
        "id": "chatcmpl_groq_http",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "tool_calls": [{
                    "id": "call_weather_1",
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "arguments": "{\"location\":\"San Francisco, CA\"}"
                    }
                }]
            },
            "finish_reason": "tool_calls"
        }]
    });
    Mock::given(method("POST"))
        .and(path(GROQ_CHAT_COMPLETIONS_PATH))
        .and(header("authorization", "Bearer sk-groq-test"))
        .and(header("x-groq-api-version", "2025-04"))
        .and(body_json(request_body()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(serde_json::to_vec(&response).unwrap(), "application/json"),
        )
        .mount(&server)
        .await;

    let adapter = adapter(&server.uri());
    let body = serde_json::to_vec(&request_body()).unwrap();
    let invocations = adapter.send_chat_completion(&body).await.unwrap();

    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].tool_name, "get_weather");
    // Arguments were canonicalized from the JSON-string `arguments` slot.
    let args: serde_json::Value = serde_json::from_slice(&invocations[0].arguments).unwrap();
    assert_eq!(args, json!({"location": "San Francisco, CA"}));
}

#[tokio::test]
async fn real_transport_maps_upstream_5xx_fail_closed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(GROQ_CHAT_COMPLETIONS_PATH))
        .respond_with(ResponseTemplate::new(503).set_body_string("overloaded"))
        .mount(&server)
        .await;

    let adapter = adapter(&server.uri());
    let body = serde_json::to_vec(&request_body()).unwrap();
    let error = adapter
        .send_chat_completion(&body)
        .await
        .expect_err("a 503 must fail closed");
    assert!(matches!(
        error,
        ProviderError::Upstream5xx { status: 503, .. }
    ));
}
