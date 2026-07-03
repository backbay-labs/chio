#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use serde_json::json;

fn config() -> GroqAdapterConfig {
    GroqAdapterConfig::new(
        "groq-1",
        "Groq generateContent",
        "0.1.0",
        "deadbeef",
        "org_chio_demo",
    )
}

fn config_with_api_version(api_version: &str) -> GroqAdapterConfig {
    let mut cfg = config();
    cfg.api_version = api_version.to_string();
    cfg
}

fn tool_call_payload() -> Value {
    json!({
        "id": "chatcmpl_api_pin",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "tool_calls": [{
                    "id": "call_api_pin",
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "arguments": "{\"city\":\"Paris\"}"
                    }
                }]
            },
            "finish_reason": "tool_calls"
        }]
    })
}

fn tool_call_stream() -> Vec<u8> {
    let chunk = json!({
        "id": "chatcmpl_api_pin_stream",
        "object": "chat.completion.chunk",
        "choices": [{
            "index": 0,
            "delta": {
                "tool_calls": [{
                    "id": "call_api_pin_stream",
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "arguments": "{\"city\":\"Paris\"}"
                    }
                }]
            }
        }]
    });
    let mut sse = Vec::new();
    sse.extend_from_slice(b"data: ");
    sse.extend_from_slice(&serde_json::to_vec(&chunk).unwrap());
    sse.extend_from_slice(b"\n\n");
    sse
}

fn raw_payload(value: Value) -> ProviderRequest {
    ProviderRequest(serde_json::to_vec(&value).unwrap())
}

fn assert_api_version_drift(error: ProviderError) {
    match error {
        ProviderError::Malformed(message) => {
            assert!(message.contains("Groq adapter supports only API version 2025-04"));
            assert!(message.contains("configured 2024-12"));
        }
        other => panic!("expected Malformed API version drift, got {other:?}"),
    }
}

#[test]
fn config_pins_api_version() {
    let cfg = config();
    assert_eq!(cfg.api_version, GROQ_API_VERSION);
    assert_eq!(cfg.api_version, "2025-04");
}

#[test]
fn adapter_reports_provider_and_pin() {
    let cfg = config();
    let transport = transport::MockTransport::new();
    let adapter = GroqAdapter::new(cfg, Arc::new(transport));
    assert_eq!(adapter.provider(), ProviderId::Groq);
    assert_eq!(adapter.api_version(), "2025-04");
}

#[tokio::test]
async fn send_chat_completion_rejects_api_version_drift_before_transport_call() {
    let mock = Arc::new(transport::MockTransport::new());
    mock.push_json_response(serde_json::to_vec(&tool_call_payload()).unwrap());
    let adapter = GroqAdapter::new(config_with_api_version("2024-12"), mock.clone());

    let err = adapter
        .send_chat_completion(&chat_request_body())
        .await
        .expect_err("drifted Groq API version must fail before transport");

    assert_api_version_drift(err);
    assert!(mock.calls().is_empty());
}

#[tokio::test]
async fn send_chat_completion_rejects_invalid_request_body_before_transport_call() {
    let cases = [
        (
            "not-json",
            b"not-json".to_vec(),
            "Groq chat/completions request body was not JSON",
        ),
        (
            "not-object",
            b"[]".to_vec(),
            "Groq chat/completions request body must be a JSON object",
        ),
        (
            "padded-model",
            br#"{"model":" llama-3.3-70b-versatile ","messages":[{"role":"user","content":"hello"}]}"#
                .to_vec(),
            "Groq chat/completions request model must not contain surrounding whitespace",
        ),
        (
            "empty-messages",
            br#"{"model":"llama-3.3-70b-versatile","messages":[]}"#.to_vec(),
            "Groq chat/completions request must include at least one message",
        ),
    ];

    for (name, request, expected) in cases {
        let mock = Arc::new(transport::MockTransport::new());
        mock.push_json_response(tool_call_response());
        let adapter = GroqAdapter::new(config(), mock.clone());

        let err = adapter
            .send_chat_completion(&request)
            .await
            .expect_err("invalid Groq request must fail before transport");

        assert!(
            err.to_string().contains(expected),
            "{name} error `{err}` did not contain `{expected}`"
        );
        assert!(mock.calls().is_empty(), "{name} reached transport");
    }
}

#[tokio::test]
async fn send_chat_completion_stream_rejects_api_version_drift_before_transport_call() {
    let mock = Arc::new(transport::MockTransport::new());
    mock.push_response(transport::HttpResponse::new(
        200,
        tool_call_stream(),
        Some("text/event-stream".to_string()),
    ));
    let adapter = GroqAdapter::new(config_with_api_version("2024-12"), mock.clone());

    let err = adapter
        .send_chat_completion_stream(&chat_request_body(), |_invocation| {
            Ok(VerdictResult::Allow {
                redactions: vec![],
                receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_pin".into()),
            })
        })
        .await
        .expect_err("drifted Groq API version must fail before stream transport");

    assert_api_version_drift(err);
    assert!(mock.calls().is_empty());
}

#[tokio::test]
async fn send_chat_completion_stream_rejects_invalid_request_body_before_transport_call() {
    let mock = Arc::new(transport::MockTransport::new());
    mock.push_response(transport::HttpResponse::new(
        200,
        tool_call_stream(),
        Some("text/event-stream".to_string()),
    ));
    let adapter = GroqAdapter::new(config(), mock.clone());

    let err = adapter
        .send_chat_completion_stream(
            br#"{"model":"","messages":[{"role":"user","content":"hello"}]}"#,
            |_invocation| {
                Ok(VerdictResult::Allow {
                    redactions: vec![],
                    receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_pin".into()),
                })
            },
        )
        .await
        .expect_err("invalid Groq stream request must fail before transport");

    assert!(err
        .to_string()
        .contains("Groq chat/completions request model must not be empty"));
    assert!(mock.calls().is_empty());
}

#[test]
fn lift_batch_rejects_api_version_drift_before_provenance_stamp() {
    let adapter = GroqAdapter::new(
        config_with_api_version("2024-12"),
        Arc::new(transport::MockTransport::new()),
    );

    let err = adapter
        .lift_batch(raw_payload(tool_call_payload()))
        .expect_err("drifted Groq API version must fail before provenance stamping");

    assert_api_version_drift(err);
}

#[test]
fn gate_sse_stream_rejects_api_version_drift_before_evaluator() {
    let adapter = GroqAdapter::new(
        config_with_api_version("2024-12"),
        Arc::new(transport::MockTransport::new()),
    );
    let evaluated = std::cell::Cell::new(false);

    let err = adapter
        .gate_sse_stream(&tool_call_stream(), |_invocation| {
            evaluated.set(true);
            Ok(VerdictResult::Allow {
                redactions: vec![],
                receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_pin".into()),
            })
        })
        .expect_err("drifted Groq API version must fail before stream evaluation");

    assert_api_version_drift(err);
    assert!(!evaluated.get());
}

#[test]
fn lower_function_response_rejects_api_version_drift() {
    let adapter = GroqAdapter::new(
        config_with_api_version("2024-12"),
        Arc::new(transport::MockTransport::new()),
    );
    let verdict = VerdictResult::Allow {
        redactions: vec![],
        receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_pin".into()),
    };
    let result = ToolResult(b"{\"temp\":18}".to_vec());

    let err = adapter
        .lower_function_response("call_weather_1", verdict, result)
        .expect_err("drifted Groq API version must fail before lowering");

    assert_api_version_drift(err);
}

#[test]
fn lift_batch_extracts_openai_tool_calls() {
    // Wire shape matches the captured Groq fixture
    // crates/chio-provider-conformance/fixtures/groq/groq_basic_single_tool_call.ndjson:
    // choices[].message.tool_calls[] with `function.arguments` as a
    // JSON-encoded string.
    let cfg = config();
    let adapter = GroqAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
    let payload = json!({
        "id": "chatcmpl_test",
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
                        "arguments": "{\"city\":\"Paris\"}"
                    }
                }]
            },
            "finish_reason": "tool_calls"
        }]
    });
    let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
    let invocations = adapter.lift_batch(raw).unwrap();
    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].tool_name, "get_weather");
    assert_eq!(invocations[0].provenance.request_id, "call_weather_1");
}

#[test]
fn lift_batch_extracts_parallel_tool_calls() {
    // Multiple OpenAI-compatible tool_calls[] entries lift in order.
    let cfg = config();
    let adapter = GroqAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
    let payload = json!({
        "id": "chatcmpl_parallel",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "call_weather_1",
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "arguments": "{\"city\":\"Paris\"}"
                        }
                    },
                    {
                        "id": "call_time_1",
                        "type": "function",
                        "function": {
                            "name": "get_time",
                            "arguments": "{\"tz\":\"UTC\"}"
                        }
                    }
                ]
            },
            "finish_reason": "tool_calls"
        }]
    });
    let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
    let invocations = adapter.lift_batch(raw).unwrap();
    assert_eq!(invocations.len(), 2);
    assert_eq!(invocations[0].tool_name, "get_weather");
    assert_eq!(invocations[0].provenance.request_id, "call_weather_1");
    assert_eq!(invocations[1].tool_name, "get_time");
    assert_eq!(invocations[1].provenance.request_id, "call_time_1");
    assert!(matches!(
        invocations[0].provenance.principal,
        Principal::GroqProject { .. }
    ));
}

#[test]
fn lift_batch_rejects_function_tool_call_missing_function_object() {
    let cfg = config();
    let adapter = GroqAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
    let payload = json!({
        "id": "chatcmpl_malformed_tool",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "call_weather_1",
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "arguments": "{\"city\":\"Paris\"}"
                        }
                    },
                    {
                        "id": "call_missing_function",
                        "type": "function"
                    }
                ]
            },
            "finish_reason": "tool_calls"
        }]
    });
    let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
    let err = adapter.lift_batch(raw).unwrap_err();

    assert!(
        matches!(err, ProviderError::Malformed(message) if message.contains("tool_calls[].function was missing"))
    );
}

#[test]
fn lift_batch_rejects_malformed_envelope_before_outer_tool_calls() {
    let cfg = config();
    let adapter = GroqAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
    let payload = json!({
        "body": 42,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "tool_calls": [{
                    "id": "call_outer",
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "arguments": "{\"city\":\"Paris\"}"
                    }
                }]
            },
            "finish_reason": "tool_calls"
        }]
    });
    let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
    let err = adapter.lift_batch(raw).unwrap_err();

    assert!(err.to_string().contains("envelope field `body`"));
}

#[test]
fn lift_batch_maps_safety_block_to_content_policy() {
    let cfg = config();
    let adapter = GroqAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
    let payload = json!({
        "stop_reason": "refusal",
        "promptFeedback": {
            "blockReason": "SAFETY"
        }
    });
    let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
    let err = adapter
        .lift_batch(raw)
        .expect_err("Groq safety block must fail closed as content policy");

    assert!(matches!(err, ProviderError::ContentPolicy(_)));
    assert!(err.to_string().contains("SAFETY"));
}

#[test]
fn lift_batch_maps_content_filter_finish_reason_to_content_policy() {
    let cfg = config();
    let adapter = GroqAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
    let payload = json!({
        "choices": [{
            "message": { "role": "assistant", "content": "" },
            "finish_reason": "content_filter"
        }]
    });
    let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
    let err = adapter
        .lift_batch(raw)
        .expect_err("Groq content_filter finish reason must fail closed");

    assert!(matches!(err, ProviderError::ContentPolicy(_)));
    assert!(err.to_string().contains("content_filter"));
}

#[test]
fn lift_batch_rejects_function_call_name_with_surrounding_whitespace() {
    let cfg = config();
    let adapter = GroqAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
    let payload = json!({
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "tool_calls": [{
                    "id": "call_padded_name",
                    "type": "function",
                    "function": {
                        "name": " get_weather ",
                        "arguments": "{}"
                    }
                }]
            },
            "finish_reason": "tool_calls"
        }]
    });
    let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
    let err = adapter
        .lift_batch(raw)
        .expect_err("whitespace-padded function name must fail closed");

    assert!(err
        .to_string()
        .contains("functionCall name must not contain surrounding whitespace"));
}

#[test]
fn lower_function_response_allow() {
    let cfg = config();
    let adapter = GroqAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
    let verdict = VerdictResult::Allow {
        redactions: vec![],
        receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_demo".into()),
    };
    let result = ToolResult(b"{\"temp\":18}".to_vec());
    let part = adapter
        .lower_function_response("call_weather_1", verdict, result)
        .unwrap();
    assert_eq!(part.tool_call_id, "call_weather_1");
}

#[test]
fn lower_allow_function_response_helper_applies_redactions() {
    let part = lower_allow_function_response(
        "call_weather_1",
        ToolResult(br#"{"token":"secret","ok":true}"#.to_vec()),
        &[Redaction {
            path: "/token".to_string(),
            replacement: "[redacted]".to_string(),
        }],
    )
    .unwrap();

    assert_eq!(part.tool_call_id, "call_weather_1");
    assert_eq!(part.response, json!({"token": "[redacted]", "ok": true}));
}
fn chat_request_body() -> Vec<u8> {
    let request = json!({
        "model": "llama-3.3-70b-versatile",
        "messages": [{"role": "user", "content": "What is the weather in Paris?"}],
        "tools": [{
            "type": "function",
            "function": {
                "name": "get_weather",
                "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}
            }
        }]
    });
    serde_json::to_vec(&request).unwrap()
}

fn tool_call_response() -> Vec<u8> {
    let response = json!({
        "id": "chatcmpl_test",
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
                        "arguments": "{\"city\":\"Paris\"}"
                    }
                }]
            },
            "finish_reason": "tool_calls"
        }]
    });
    serde_json::to_vec(&response).unwrap()
}

#[tokio::test]
async fn send_chat_completion_posts_and_lifts() {
    let mock = Arc::new(transport::MockTransport::new());
    mock.push_json_response(tool_call_response());
    let adapter = GroqAdapter::new(config(), mock.clone());

    let request = chat_request_body();
    let invocations = adapter.send_chat_completion(&request).await.unwrap();

    // The lifted invocation came back from the real outbound parse path.
    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].tool_name, "get_weather");
    assert_eq!(invocations[0].provenance.request_id, "call_weather_1");

    // The adapter posted the request body to the chat/completions path.
    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].path, GROQ_CHAT_COMPLETIONS_PATH);
    assert_eq!(calls[0].body, request);
}

#[tokio::test]
async fn send_chat_completion_maps_upstream_status() {
    let mock = Arc::new(transport::MockTransport::new());
    mock.push_error(transport::HttpTransportError::Status {
        code: 429,
        body: "rate limited".to_string(),
    });
    let adapter = GroqAdapter::new(config(), mock);

    let error = adapter
        .send_chat_completion(&chat_request_body())
        .await
        .expect_err("a 429 must fail closed");
    assert!(matches!(error, ProviderError::RateLimited { .. }));
}

#[tokio::test]
async fn send_chat_completion_timeout_fails_closed() {
    let mock = Arc::new(transport::MockTransport::new());
    mock.push_error(transport::HttpTransportError::Timeout {
        url: "https://api.groq.com/openai/v1/chat/completions".to_string(),
        timeout_ms: 60_000,
    });
    let adapter = GroqAdapter::new(config(), mock);

    let error = adapter
        .send_chat_completion(&chat_request_body())
        .await
        .expect_err("a timeout must fail closed");
    assert!(matches!(
        error,
        ProviderError::TransportTimeout { ms: 60_000 }
    ));
}

#[tokio::test]
async fn send_chat_completion_stream_gates_buffered_sse() {
    let chunk = json!({
        "id": "chatcmpl_stream",
        "object": "chat.completion.chunk",
        "choices": [{
            "index": 0,
            "delta": {
                "tool_calls": [{
                    "id": "call_weather_1",
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "arguments": "{\"city\":\"Paris\"}"
                    }
                }]
            }
        }]
    });
    let mut sse = Vec::new();
    sse.extend_from_slice(b"data: ");
    sse.extend_from_slice(&serde_json::to_vec(&chunk).unwrap());
    sse.extend_from_slice(b"\n\ndata: [DONE]\n\n");

    let mock = Arc::new(transport::MockTransport::new());
    mock.push_response(transport::HttpResponse::new(
        200,
        sse,
        Some("text/event-stream".to_string()),
    ));
    let adapter = GroqAdapter::new(config(), mock.clone());

    let gated = adapter
        .send_chat_completion_stream(&chat_request_body(), |_invocation| {
            Ok(VerdictResult::Allow {
                redactions: vec![],
                receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_stream".into()),
            })
        })
        .await
        .unwrap();
    assert_eq!(gated.invocations.len(), 1);
    assert_eq!(gated.invocations[0].tool_name, "get_weather");
    assert_eq!(gated.invocations[0].provenance.request_id, "call_weather_1");

    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].kind,
        chio_provider_adapter_core::http::CallKind::Sse
    );
}
