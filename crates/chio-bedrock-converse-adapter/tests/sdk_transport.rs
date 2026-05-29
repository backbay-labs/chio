//! Hermetic coverage for the live AWS SDK Converse transport.
//!
//! These tests drive [`AwsSdkTransport`] end to end through the real
//! `aws-sdk-bedrockruntime` client. A `StaticReplayClient` is injected as the
//! SDK HTTP client so the Converse request is serialized, "sent", and the
//! canned Bedrock Converse JSON response is deserialized by the SDK exactly as
//! it would be against the live service, with no network access.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use aws_sdk_bedrockruntime::config::retry::RetryConfig;
use aws_sdk_bedrockruntime::config::{
    BehaviorVersion, Credentials, Region, SharedCredentialsProvider,
};
use aws_sdk_bedrockruntime::{Client, Config};
use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
use aws_smithy_types::body::SdkBody;
use chio_bedrock_converse_adapter::{
    AwsSdkTransport, BedrockAdapter, BedrockAdapterConfig, ConverseRequest, ToolConfig, ToolSpec,
    BEDROCK_CONVERSE_API_VERSION,
};
use chio_tool_call_fabric::{Principal, ProviderError, ProviderId};
use serde_json::{json, Value};

const MODEL_ID: &str = "anthropic.claude-3-sonnet-20240229-v1:0";

fn adapter_with_replay(client: StaticReplayClient) -> BedrockAdapter {
    let config = Config::builder()
        .behavior_version(BehaviorVersion::v2026_01_12())
        .retry_config(RetryConfig::disabled())
        .region(Region::new("us-east-1"))
        .credentials_provider(SharedCredentialsProvider::new(Credentials::new(
            "AKIDEXAMPLE",
            "secret",
            None,
            None,
            "chio-test",
        )))
        .http_client(client)
        .build();
    let transport = AwsSdkTransport::from_client(Client::from_conf(config));

    let cfg = BedrockAdapterConfig::new(
        "bedrock-1",
        "Bedrock Converse",
        "0.1.0",
        "deadbeef",
        "arn:aws:iam::123456789012:role/ChioAgentRole",
        "123456789012",
    )
    .with_assumed_role_session_arn(
        "arn:aws:sts::123456789012:assumed-role/ChioAgentRole/session-1",
    );
    BedrockAdapter::new(cfg, Arc::new(transport)).expect("adapter builds")
}

fn converse_response_body() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "output": {
            "message": {
                "role": "assistant",
                "content": [
                    {"text": "checking the weather"},
                    {
                        "toolUse": {
                            "toolUseId": "tooluse_weather_1",
                            "name": "get_weather",
                            "input": {"location": "Boston", "unit": "celsius"}
                        }
                    }
                ]
            }
        },
        "stopReason": "tool_use",
        "usage": {"inputTokens": 12, "outputTokens": 7, "totalTokens": 19}
    }))
    .unwrap()
}

fn replay_client(status: u16, body: Vec<u8>) -> StaticReplayClient {
    let request = http::Request::builder()
        .method("POST")
        .uri("https://bedrock-runtime.us-east-1.amazonaws.com/placeholder")
        .body(SdkBody::empty())
        .unwrap();
    let response = http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(SdkBody::from(body))
        .unwrap();
    StaticReplayClient::new(vec![ReplayEvent::new(request, response)])
}

fn weather_request() -> ConverseRequest {
    ConverseRequest::new(
        MODEL_ID,
        vec![json!({
            "role": "user",
            "content": [{"text": "What is the weather in Boston?"}]
        })],
    )
    .with_tool_config(ToolConfig::new(vec![ToolSpec::new(
        "get_weather",
        Some("Get the weather".to_string()),
        json!({"json": {"type": "object", "properties": {"location": {"type": "string"}}}}),
    )]))
}

#[tokio::test]
async fn converse_lifts_tool_use_from_real_sdk_response() {
    let client = replay_client(200, converse_response_body());
    let recorded = client.clone();
    let adapter = adapter_with_replay(client);

    let invocations = adapter
        .converse(weather_request())
        .await
        .expect("converse succeeds");

    assert_eq!(invocations.len(), 1);
    let invocation = &invocations[0];
    assert_eq!(invocation.provider, ProviderId::Bedrock);
    assert_eq!(invocation.tool_name, "get_weather");
    assert_eq!(invocation.provenance.request_id, "tooluse_weather_1");
    assert_eq!(
        invocation.provenance.api_version,
        BEDROCK_CONVERSE_API_VERSION
    );
    assert_eq!(
        String::from_utf8(invocation.arguments.clone()).unwrap(),
        r#"{"location":"Boston","unit":"celsius"}"#
    );
    assert_eq!(
        invocation.provenance.principal,
        Principal::BedrockIam {
            caller_arn: "arn:aws:iam::123456789012:role/ChioAgentRole".to_string(),
            account_id: "123456789012".to_string(),
            assumed_role_session_arn: Some(
                "arn:aws:sts::123456789012:assumed-role/ChioAgentRole/session-1".to_string()
            ),
        }
    );

    // The SDK actually serialized and dispatched the Converse request.
    let requests: Vec<_> = recorded.actual_requests().collect();
    assert_eq!(requests.len(), 1);
    let sent = &requests[0];
    assert_eq!(sent.method(), "POST");
    assert!(
        sent.uri().contains("/converse"),
        "expected Converse path, got {}",
        sent.uri()
    );
    let sent_body: Value = serde_json::from_slice(sent.body().bytes().unwrap()).unwrap();
    assert!(sent_body.get("messages").is_some());
    assert!(sent_body.get("toolConfig").is_some());
}

#[tokio::test]
async fn converse_maps_throttling_to_rate_limited() {
    let error_body = serde_json::to_vec(&json!({"message": "Rate exceeded"})).unwrap();
    let request = http::Request::builder()
        .method("POST")
        .uri("https://bedrock-runtime.us-east-1.amazonaws.com/placeholder")
        .body(SdkBody::empty())
        .unwrap();
    let response = http::Response::builder()
        .status(429)
        .header("content-type", "application/json")
        .header("x-amzn-errortype", "ThrottlingException")
        .body(SdkBody::from(error_body))
        .unwrap();
    let client = StaticReplayClient::new(vec![ReplayEvent::new(request, response)]);
    let adapter = adapter_with_replay(client);

    let err = adapter
        .converse(weather_request())
        .await
        .expect_err("throttling should fail closed");
    assert!(
        matches!(err, ProviderError::RateLimited { .. }),
        "expected RateLimited, got {err:?}"
    );
}

#[tokio::test]
async fn converse_maps_validation_error_to_malformed() {
    let error_body = serde_json::to_vec(&json!({"message": "model id is invalid"})).unwrap();
    let request = http::Request::builder()
        .method("POST")
        .uri("https://bedrock-runtime.us-east-1.amazonaws.com/placeholder")
        .body(SdkBody::empty())
        .unwrap();
    let response = http::Response::builder()
        .status(400)
        .header("content-type", "application/json")
        .header("x-amzn-errortype", "ValidationException")
        .body(SdkBody::from(error_body))
        .unwrap();
    let client = StaticReplayClient::new(vec![ReplayEvent::new(request, response)]);
    let adapter = adapter_with_replay(client);

    let err = adapter
        .converse(weather_request())
        .await
        .expect_err("validation error should fail closed");
    assert!(
        matches!(err, ProviderError::Malformed(_)),
        "expected Malformed, got {err:?}"
    );
}
