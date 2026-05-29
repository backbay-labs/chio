//! Hermetic tests for the real `CohereTransport` `/v2/chat` path.
//!
//! These drive the adapter's real `reqwest`-backed transport against a local
//! `wiremock` server, so the outbound POST, bearer auth header, path, and the
//! response-to-`ToolInvocation` lift are all exercised without touching the
//! network.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use chio_cohere_tools_adapter::{CohereAdapter, CohereAdapterConfig, CohereTransport};
use chio_tool_call_fabric::{ProviderError, ProviderId, ReceiptId, VerdictResult};
use serde_json::json;
use wiremock::matchers::{body_string, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config() -> CohereAdapterConfig {
    CohereAdapterConfig::new(
        "cohere-live",
        "Cohere v2 chat",
        "0.1.0",
        "deadbeef",
        "org_chio_live",
    )
}

#[tokio::test]
async fn chat_posts_to_v2_chat_with_bearer_and_lifts_tool_calls() {
    let server = MockServer::start().await;
    let request_body = "{\"model\":\"command-r\",\"messages\":[]}";
    let response_body = json!({
        "message": {
            "role": "assistant",
            "tool_plan": "I will look up the weather",
            "tool_calls": [
                {
                    "id": "call_live_1",
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "arguments": "{\"city\":\"Paris\"}"
                    }
                }
            ]
        }
    });

    Mock::given(method("POST"))
        .and(path("/v2/chat"))
        .and(header("authorization", "Bearer live-key"))
        .and(body_string(request_body))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            serde_json::to_vec(&response_body).unwrap(),
            "application/json",
        ))
        .mount(&server)
        .await;

    let transport = CohereTransport::with_base_url(server.uri(), "live-key").unwrap();
    let adapter = CohereAdapter::new(config(), Arc::new(transport));

    let invocations = adapter.chat(request_body.as_bytes()).await.unwrap();
    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].tool_name, "get_weather");
    assert_eq!(invocations[0].provider, ProviderId::Cohere);
    assert_eq!(invocations[0].provenance.request_id, "call_live_1");
}

#[tokio::test]
async fn chat_maps_upstream_429_to_rate_limited() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/chat"))
        .respond_with(ResponseTemplate::new(429).set_body_string("rate limit exceeded"))
        .mount(&server)
        .await;

    let transport = CohereTransport::with_base_url(server.uri(), "live-key").unwrap();
    let adapter = CohereAdapter::new(config(), Arc::new(transport));

    let error = adapter
        .chat(b"{}")
        .await
        .expect_err("a 429 upstream status must fail closed");
    assert!(matches!(error, ProviderError::RateLimited { .. }));
}

#[tokio::test]
async fn chat_stream_gates_sse_response() {
    let server = MockServer::start().await;
    let sse = "event: tool-call-end\ndata: {\"tool_call\":{\"id\":\"call_live_2\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"{\\\"city\\\":\\\"Paris\\\"}\"}}}\n\n";
    Mock::given(method("POST"))
        .and(path("/v2/chat"))
        .and(header("authorization", "Bearer live-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .mount(&server)
        .await;

    let transport = CohereTransport::with_base_url(server.uri(), "live-key").unwrap();
    let adapter = CohereAdapter::new(config(), Arc::new(transport));

    let gated = adapter
        .chat_stream(b"{\"stream\":true}", |_invocation| {
            Ok(VerdictResult::Allow {
                redactions: vec![],
                receipt_id: ReceiptId("rcpt_live_allow".to_string()),
            })
        })
        .await
        .unwrap();
    assert_eq!(gated.invocations.len(), 1);
    assert_eq!(gated.invocations[0].tool_name, "get_weather");
    assert_eq!(gated.bytes, sse.as_bytes());
}
