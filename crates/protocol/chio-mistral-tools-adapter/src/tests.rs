#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::json;

fn config() -> MistralAdapterConfig {
    MistralAdapterConfig::new(
        "mistral-1",
        "Mistral chat/completions",
        "0.1.0",
        "deadbeef",
        "org_chio_demo",
    )
}

fn config_with_api_version(api_version: &str) -> MistralAdapterConfig {
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

struct DriftedTransport {
    called: Arc<AtomicBool>,
}

impl DriftedTransport {
    fn new(called: Arc<AtomicBool>) -> Self {
        Self { called }
    }
}

#[async_trait::async_trait]
impl transport::Transport for DriftedTransport {
    fn api_version(&self) -> &str {
        "2024-12"
    }

    async fn chat_completion(&self, _body: &[u8]) -> Result<Vec<u8>, transport::TransportError> {
        self.called.store(true, Ordering::SeqCst);
        Ok(serde_json::to_vec(&tool_call_payload()).unwrap())
    }

    async fn chat_completion_stream(
        &self,
        _body: &[u8],
    ) -> Result<Vec<u8>, transport::TransportError> {
        self.called.store(true, Ordering::SeqCst);
        Ok(tool_call_stream())
    }
}

fn assert_api_version_drift(error: ProviderError) {
    match error {
        ProviderError::Malformed(message) => {
            assert!(message.contains("Mistral adapter supports only API version 2025-04"));
            assert!(message.contains("2024-12"));
        }
        other => panic!("expected Malformed API version drift, got {other:?}"),
    }
}

#[test]
fn config_pins_api_version() {
    let cfg = config();
    assert_eq!(cfg.api_version, MISTRAL_API_VERSION);
    assert_eq!(cfg.api_version, "2025-04");
}

#[test]
fn adapter_reports_provider_and_pin() {
    let cfg = config();
    let transport = transport::MockTransport::new();
    let adapter = MistralAdapter::new(cfg, Arc::new(transport));
    assert_eq!(adapter.provider(), ProviderId::Mistral);
    assert_eq!(adapter.api_version(), "2025-04");
}

#[tokio::test]
async fn send_chat_completion_rejects_api_version_drift_before_transport_call() {
    let mock = transport::MockTransport::new();
    mock.push_response(serde_json::to_vec(&tool_call_payload()).unwrap());
    let mock = Arc::new(mock);
    let adapter = MistralAdapter::new(config_with_api_version("2024-12"), mock.clone());

    let err = adapter
        .send_chat_completion(&chat_request())
        .await
        .expect_err("drifted Mistral API version must fail before transport");

    assert_api_version_drift(err);
    assert!(mock.calls().is_empty());
}

#[tokio::test]
async fn send_chat_completion_rejects_transport_api_version_drift_before_send() {
    let called = Arc::new(AtomicBool::new(false));
    let transport = Arc::new(DriftedTransport::new(called.clone()));
    let adapter = MistralAdapter::new(config(), transport);

    let err = adapter
        .send_chat_completion(&chat_request())
        .await
        .expect_err("drifted Mistral transport API version must fail before send");

    assert_api_version_drift(err);
    assert!(!called.load(Ordering::SeqCst));
}

#[tokio::test]
async fn send_chat_completion_stream_rejects_api_version_drift_before_transport_call() {
    let mock = transport::MockTransport::new();
    mock.push_response(tool_call_stream());
    let mock = Arc::new(mock);
    let adapter = MistralAdapter::new(config_with_api_version("2024-12"), mock.clone());

    let err = adapter
        .send_chat_completion_stream(&chat_request(), |_invocation| {
            Ok(VerdictResult::Allow {
                redactions: vec![],
                receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_pin".into()),
            })
        })
        .await
        .expect_err("drifted Mistral API version must fail before stream transport");

    assert_api_version_drift(err);
    assert!(mock.calls().is_empty());
}

#[tokio::test]
async fn send_chat_completion_stream_rejects_transport_api_version_drift_before_send() {
    let called = Arc::new(AtomicBool::new(false));
    let transport = Arc::new(DriftedTransport::new(called.clone()));
    let adapter = MistralAdapter::new(config(), transport);

    let err = adapter
        .send_chat_completion_stream(&chat_request(), |_invocation| {
            Ok(VerdictResult::Allow {
                redactions: vec![],
                receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_pin".into()),
            })
        })
        .await
        .expect_err("drifted Mistral stream transport API version must fail before send");

    assert_api_version_drift(err);
    assert!(!called.load(Ordering::SeqCst));
}

#[test]
fn lift_batch_rejects_api_version_drift_before_provenance_stamp() {
    let adapter = MistralAdapter::new(
        config_with_api_version("2024-12"),
        Arc::new(transport::MockTransport::new()),
    );

    let err = adapter
        .lift_batch(raw_payload(tool_call_payload()))
        .expect_err("drifted Mistral API version must fail before provenance stamping");

    assert_api_version_drift(err);
}

#[test]
fn gate_sse_stream_rejects_api_version_drift_before_evaluator() {
    let adapter = MistralAdapter::new(
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
        .expect_err("drifted Mistral API version must fail before stream evaluation");

    assert_api_version_drift(err);
    assert!(!evaluated.get());
}

#[test]
fn lower_function_response_rejects_api_version_drift() {
    let adapter = MistralAdapter::new(
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
        .expect_err("drifted Mistral API version must fail before lowering");

    assert_api_version_drift(err);
}

#[test]
fn lift_batch_extracts_openai_tool_calls() {
    // Wire shape matches the captured Mistral fixture
    // crates/chio-provider-conformance/fixtures/mistral/mistral_basic_single_tool_call.ndjson:
    // choices[].message.tool_calls[] with `function.arguments` as a
    // JSON-encoded string.
    let cfg = config();
    let adapter = MistralAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
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
    let adapter = MistralAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
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
        Principal::MistralProject { .. }
    ));
}

#[test]
fn lift_batch_rejects_function_tool_call_missing_function_object() {
    let cfg = config();
    let adapter = MistralAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
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
fn lift_batch_classifies_content_filter_finish_reason() {
    let cfg = config();
    let adapter = MistralAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
    let payload = json!({
        "id": "chatcmpl_safety",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null
            },
            "finish_reason": "content_filter"
        }]
    });
    let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
    let err = adapter.lift_batch(raw).unwrap_err();

    assert!(matches!(err, ProviderError::ContentPolicy(_)));
}

#[test]
fn lift_batch_rejects_malformed_envelope_before_outer_tool_calls() {
    let cfg = config();
    let adapter = MistralAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
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
fn lift_batch_rejects_function_call_name_with_surrounding_whitespace() {
    let cfg = config();
    let adapter = MistralAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
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
                        "name": " get_weather ",
                        "arguments": "{\"city\":\"Paris\"}"
                    }
                }]
            },
            "finish_reason": "tool_calls"
        }]
    });
    let raw = ProviderRequest(serde_json::to_vec(&payload).unwrap());
    let err = adapter.lift_batch(raw).unwrap_err();

    assert!(err.to_string().contains("surrounding whitespace"));
}

#[test]
fn lower_function_response_allow() {
    let cfg = config();
    let adapter = MistralAdapter::new(cfg, Arc::new(transport::MockTransport::new()));
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

#[test]
fn chat_request_serializes_expected_shape() {
    let body = chat_request().to_json_bytes().unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["model"], "mistral-large-latest");
    assert!(value["messages"].is_array());
    assert!(value["tools"].is_array());
    // A non-streaming request omits the `stream` flag entirely.
    assert!(value.get("stream").is_none());
}

#[test]
fn chat_request_fails_closed_on_empty_model() {
    let request = MistralChatRequest::new("", vec![json!({"role": "user"})], vec![]);
    let error = request
        .to_json_bytes()
        .expect_err("an empty model must fail closed");
    assert!(matches!(error, ProviderError::BadToolArgs(_)));
}

#[tokio::test]
async fn send_chat_completion_posts_and_lifts_tool_calls() {
    let mock = transport::MockTransport::new();
    // Wire shape mirrors the captured Mistral conformance fixture.
    mock.push_response(
        serde_json::to_vec(&json!({
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
        }))
        .unwrap(),
    );
    let mock = Arc::new(mock);
    let adapter = MistralAdapter::new(config(), mock.clone());

    let invocations = adapter.send_chat_completion(&chat_request()).await.unwrap();
    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].tool_name, "get_weather");
    assert_eq!(invocations[0].provenance.request_id, "call_weather_1");
    assert_eq!(invocations[0].provider, ProviderId::Mistral);

    // The adapter posted the encoded request body to the chat endpoint.
    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, MISTRAL_CHAT_COMPLETIONS_PATH);
    let sent: Value = serde_json::from_slice(&calls[0].1).unwrap();
    assert_eq!(sent["model"], "mistral-large-latest");
}

#[tokio::test]
async fn send_chat_completion_fails_closed_when_transport_empty() {
    let adapter = MistralAdapter::new(config(), Arc::new(transport::MockTransport::new()));
    let error = adapter
        .send_chat_completion(&chat_request())
        .await
        .expect_err("an exhausted transport must fail closed");
    assert!(matches!(error, ProviderError::Malformed(_)));
}

#[tokio::test]
async fn send_chat_completion_stream_gates_tool_calls() {
    let mock = transport::MockTransport::new();
    let chunk = json!({
        "id": "chatcmpl_stream",
        "object": "chat.completion.chunk",
        "choices": [{
            "index": 0,
            "delta": {
                "tool_calls": [{
                    "id": "call_stream_1",
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
    mock.push_response(sse);
    let adapter = MistralAdapter::new(config(), Arc::new(mock));

    let verdict = VerdictResult::Allow {
        redactions: vec![],
        receipt_id: chio_tool_call_fabric::ReceiptId("rcpt_stream".into()),
    };
    let gated = adapter
        .send_chat_completion_stream(&chat_request(), |_invocation| Ok(verdict.clone()))
        .await
        .unwrap();
    assert_eq!(gated.invocations.len(), 1);
    assert_eq!(gated.invocations[0].tool_name, "get_weather");
    assert_eq!(gated.invocations[0].provenance.request_id, "call_stream_1");
}
