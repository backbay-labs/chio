#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use chio_bedrock_converse_adapter::{
    transport, BedrockAdapter, BedrockAdapterConfig, BEDROCK_CONVERSE_API_VERSION,
};
use chio_tool_call_fabric::{
    DenyReason, ProviderError, ProviderId, ProviderRequest, ReceiptId, Redaction, ToolResult,
    VerdictResult,
};
use serde_json::{json, Value};

fn adapter() -> BedrockAdapter {
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
    BedrockAdapter::new(cfg, Arc::new(transport::MockTransport::new())).unwrap()
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

fn tool_result(value: Value) -> ToolResult {
    ToolResult(serde_json::to_vec(&value).unwrap())
}

fn stream_bytes(events: Value) -> Vec<u8> {
    serde_json::to_vec(&events).unwrap()
}

fn converse_stream_fixture() -> Value {
    json!([
        {"messageStart": {"role": "assistant"}},
        {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": "checking "}}},
        {"contentBlockStop": {"contentBlockIndex": 0}},
        {
            "contentBlockStart": {
                "contentBlockIndex": 1,
                "start": {
                    "toolUse": {
                        "toolUseId": "tooluse_weather_1",
                        "name": "get_weather"
                    }
                }
            }
        },
        {
            "contentBlockDelta": {
                "contentBlockIndex": 1,
                "delta": {
                    "toolUse": {
                        "input": "{\"location\":\"LA\""
                    }
                }
            }
        },
        {
            "contentBlockDelta": {
                "contentBlockIndex": 1,
                "delta": {
                    "toolUse": {
                        "input": ",\"unit\":\"f\"}"
                    }
                }
            }
        },
        {"contentBlockStop": {"contentBlockIndex": 1}},
        {"messageStop": {"stopReason": "tool_use"}}
    ])
}

fn converse_batch_fixture() -> Value {
    json!({
        "toolConfig": {
            "tools": [
                {
                    "toolSpec": {
                        "name": "get_weather",
                        "description": "Get weather",
                        "inputSchema": {
                            "json": {
                                "type": "object",
                                "properties": {
                                    "location": {"type": "string"},
                                    "unit": {"type": "string"}
                                }
                            }
                        }
                    }
                }
            ]
        },
        "output": {
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "toolUse": {
                            "toolUseId": "tooluse_weather_1",
                            "name": "get_weather",
                            "input": {
                                "unit": "celsius",
                                "location": "Boston"
                            }
                        }
                    }
                ]
            }
        }
    })
}

#[test]
fn gates_tool_use_at_content_block_start_and_forwards_after_allow() {
    let adapter = adapter();
    let events = converse_stream_fixture();
    let mut calls = 0;
    let gated = adapter
        .gate_converse_stream(&stream_bytes(events.clone()), |invocation| {
            calls += 1;
            assert_eq!(invocation.provider, ProviderId::Bedrock);
            assert_eq!(invocation.tool_name, "get_weather");
            assert_eq!(invocation.provenance.request_id, "tooluse_weather_1");
            assert_eq!(
                invocation.provenance.api_version,
                BEDROCK_CONVERSE_API_VERSION
            );
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
    assert_eq!(gated.events, events.as_array().unwrap().clone());

    let forwarded: Value = serde_json::from_slice(&gated.bytes).unwrap();
    assert_eq!(forwarded, events);
}

#[test]
fn denied_tool_use_start_fails_closed() {
    let adapter = adapter();
    let err = adapter
        .gate_converse_stream(&stream_bytes(converse_stream_fixture()), |_invocation| {
            Ok(deny_verdict())
        })
        .expect_err("deny verdict should close the stream");

    assert!(err.to_string().contains("denied at contentBlockStop"));
}

#[test]
fn forbidden_late_tool_use_delta_fails_closed_before_forwarding() {
    let adapter = adapter();
    let err = adapter
        .gate_converse_stream(&stream_bytes(converse_stream_fixture()), |invocation| {
            let args = String::from_utf8(invocation.arguments.clone()).unwrap();
            if args.contains("\"unit\":\"f\"") {
                Ok(deny_verdict())
            } else {
                Ok(allow_verdict())
            }
        })
        .expect_err("late forbidden args should deny after reconstruction");

    assert!(err.to_string().contains("denied at contentBlockStop"));
}

#[test]
fn non_empty_start_input_with_delta_fails_closed() {
    let adapter = adapter();
    let stream = json!([
        {
            "contentBlockStart": {
                "contentBlockIndex": 0,
                "start": {
                    "toolUse": {
                        "toolUseId": "tooluse_split_1",
                        "name": "get_weather",
                        "input": {"secret": "forbidden"}
                    }
                }
            }
        },
        {
            "contentBlockDelta": {
                "contentBlockIndex": 0,
                "delta": {
                    "toolUse": {
                        "input": "{\"location\":\"LA\"}"
                    }
                }
            }
        },
        {"contentBlockStop": {"contentBlockIndex": 0}}
    ]);
    let mut calls = 0;
    let err = adapter
        .gate_converse_stream(&stream_bytes(stream), |_invocation| {
            calls += 1;
            Ok(allow_verdict())
        })
        .expect_err("mixed start and delta args should fail closed");

    assert_eq!(calls, 0);
    assert!(err.to_string().contains("mixed non-empty start input"));
}

#[test]
fn scalar_start_only_input_fails_closed_before_verdict() {
    let adapter = adapter();
    let stream = json!([
        {
            "contentBlockStart": {
                "contentBlockIndex": 0,
                "start": {
                    "toolUse": {
                        "toolUseId": "tooluse_scalar_1",
                        "name": "get_weather",
                        "input": "forbidden"
                    }
                }
            }
        },
        {"contentBlockStop": {"contentBlockIndex": 0}}
    ]);
    let mut calls = 0;
    let err = adapter
        .gate_converse_stream(&stream_bytes(stream), |_invocation| {
            calls += 1;
            Ok(allow_verdict())
        })
        .expect_err("start-only scalar args should fail closed");

    assert_eq!(calls, 0);
    assert!(matches!(err, ProviderError::BadToolArgs(_)));
    assert!(err.to_string().contains("input must be a JSON object"));
}

#[test]
fn malformed_json_event_fails_closed() {
    let adapter = adapter();
    let err = adapter
        .gate_converse_stream(br#"[{"contentBlockStart":"#, |_invocation| {
            Ok(allow_verdict())
        })
        .expect_err("invalid stream JSON should fail closed");

    assert!(err.to_string().contains("event payload was not JSON"));
}

#[test]
fn tool_use_delta_without_active_start_fails_closed() {
    let adapter = adapter();
    let stream = json!([
        {
            "contentBlockDelta": {
                "contentBlockIndex": 0,
                "delta": {
                    "toolUse": {
                        "input": "{\"location\":\"LA\"}"
                    }
                }
            }
        }
    ]);
    let err = adapter
        .gate_converse_stream(&stream_bytes(stream), |_invocation| Ok(allow_verdict()))
        .expect_err("toolUse delta outside a content block should fail closed");

    assert!(err
        .to_string()
        .contains("without an active contentBlockStart"));
}

#[test]
fn mismatched_tool_use_block_index_fails_closed() {
    let adapter = adapter();
    let stream = json!([
        {
            "contentBlockStart": {
                "contentBlockIndex": 1,
                "start": {
                    "toolUse": {
                        "toolUseId": "tooluse_weather_1",
                        "name": "get_weather"
                    }
                }
            }
        },
        {
            "contentBlockDelta": {
                "contentBlockIndex": 2,
                "delta": {
                    "toolUse": {
                        "input": "{}"
                    }
                }
            }
        }
    ]);
    let err = adapter
        .gate_converse_stream(&stream_bytes(stream), |_invocation| Ok(allow_verdict()))
        .expect_err("mismatched toolUse block index should fail closed");

    assert!(err
        .to_string()
        .contains("did not match active content block"));
}

#[test]
fn text_stream_passes_without_verdict() {
    let adapter = adapter();
    let stream = json!([
        {"messageStart": {"role": "assistant"}},
        {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": "hello"}}},
        {"contentBlockStop": {"contentBlockIndex": 0}},
        {"metadata": {"usage": {"inputTokens": 3, "outputTokens": 1}}},
        {"messageStop": {"stopReason": "end_turn"}}
    ]);
    let mut calls = 0;
    let gated = adapter
        .gate_converse_stream(&stream_bytes(stream.clone()), |_invocation| {
            calls += 1;
            Ok(allow_verdict())
        })
        .unwrap();

    assert_eq!(calls, 0);
    assert!(gated.invocations.is_empty());
    assert_eq!(gated.events, stream.as_array().unwrap().clone());
}

#[test]
fn batch_lift_lower_behavior_still_round_trips() {
    let adapter = adapter();
    let invocations = adapter.lift_batch(raw(converse_batch_fixture())).unwrap();

    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].tool_name, "get_weather");
    assert_eq!(
        String::from_utf8(invocations[0].arguments.clone()).unwrap(),
        "{\"location\":\"Boston\",\"unit\":\"celsius\"}"
    );

    let lowered = adapter
        .lower_tool_result(
            "tooluse_weather_1",
            allow_verdict(),
            tool_result(json!({"temperature": 5, "unit": "celsius"})),
        )
        .unwrap();
    let lowered: Value = serde_json::from_slice(&lowered.0).unwrap();

    assert_eq!(lowered["toolResult"]["toolUseId"], "tooluse_weather_1");
    assert_eq!(lowered["toolResult"]["status"], "success");
    assert_eq!(
        lowered["toolResult"]["content"],
        json!([{"json": {"temperature": 5, "unit": "celsius"}}])
    );
}

#[test]
fn lower_allow_applies_redactions_before_serialization() {
    let adapter = adapter();
    let lowered = adapter
        .lower_tool_result(
            "tooluse_weather_1",
            VerdictResult::Allow {
                redactions: vec![Redaction {
                    path: "/secret".to_string(),
                    replacement: "[redacted]".to_string(),
                }],
                receipt_id: ReceiptId("rcpt_allow_redacted".to_string()),
            },
            tool_result(json!({"secret": "abc123", "status": "ok"})),
        )
        .unwrap();
    let lowered: Value = serde_json::from_slice(&lowered.0).unwrap();

    assert_eq!(
        lowered["toolResult"]["content"],
        json!([{"json": {"secret": "[redacted]", "status": "ok"}}])
    );
}

#[test]
fn evaluator_errors_fail_closed() {
    let adapter = adapter();
    let err = adapter
        .gate_converse_stream(&stream_bytes(converse_stream_fixture()), |_invocation| {
            Err(ProviderError::VerdictBudgetExceeded {
                observed_ms: 300,
                budget_ms: 250,
            })
        })
        .expect_err("verdict evaluator errors should fail closed");

    assert!(err.to_string().contains("verdict latency budget exceeded"));
}
