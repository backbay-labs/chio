#![cfg(feature = "provider-adapter")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::canonical::canonical_json_bytes;
use chio_openai::adapter::OpenAiAdapter;
use chio_tool_call_fabric::{DenyReason, ProviderError, ProviderId, ReceiptId, VerdictResult};
use serde_json::json;

fn allow_verdict() -> VerdictResult {
    VerdictResult::Allow {
        redactions: vec![],
        receipt_id: ReceiptId("rcpt_allow_stream_1".to_string()),
    }
}

fn policy_deny_verdict() -> VerdictResult {
    VerdictResult::Deny {
        reason: DenyReason::PolicyDeny {
            rule_id: "deny_calendar".to_string(),
        },
        receipt_id: ReceiptId("rcpt_deny_stream_1".to_string()),
    }
}

fn tool_call_stream() -> &'static str {
    concat!(
        "event: response.created\n",
        "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_stream_1\"}}\n\n",
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_calendar_1\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"\"}}\n\n",
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"call_calendar_1\",\"delta\":\"{\\\"title\\\":\"}\n\n",
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"call_calendar_1\",\"delta\":\"\\\"Chio sync\\\",\\\"duration_minutes\\\":30}\"}\n\n",
        "event: response.function_call_arguments.done\n",
        "data: {\"type\":\"response.function_call_arguments.done\",\"output_index\":0,\"item_id\":\"fc_calendar_1\",\"arguments\":\"{\\\"title\\\":\\\"Chio sync\\\",\\\"duration_minutes\\\":30}\"}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_calendar_1\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"{\\\"title\\\":\\\"Chio sync\\\",\\\"duration_minutes\\\":30}\"}}\n\n",
        "event: response.completed\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_stream_1\"}}\n\n",
    )
}

#[test]
fn buffers_function_call_argument_deltas_until_done_verdict_allows() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let mut evaluated = Vec::new();
    let gated = adapter
        .gate_sse_stream(tool_call_stream().as_bytes(), |invocation| {
            evaluated.push(invocation.provenance.request_id.clone());
            Ok(allow_verdict())
        })
        .unwrap();

    assert_eq!(evaluated, vec!["call_calendar_1"]);
    assert_eq!(gated.invocations.len(), 1);
    assert_eq!(gated.invocations[0].provider, ProviderId::OpenAi);
    assert_eq!(gated.invocations[0].tool_name, "create_calendar_event");
    assert_eq!(
        gated.invocations[0].arguments,
        canonical_json_bytes(&json!({
            "duration_minutes": 30,
            "title": "Chio sync"
        }))
        .unwrap()
    );
    assert_eq!(gated.verdicts, vec![allow_verdict()]);
    assert_eq!(gated.buffered_blocks.len(), 1);
    assert_eq!(gated.buffered_blocks[0].block_id, "call_calendar_1");
    assert_eq!(
        String::from_utf8(gated.buffered_blocks[0].bytes.clone()).unwrap(),
        "{\"title\":\"Chio sync\",\"duration_minutes\":30}"
    );

    let forwarded = String::from_utf8(gated.bytes).unwrap();
    assert!(forwarded.contains("response.created"));
    assert!(forwarded.contains("response.output_item.added"));
    assert!(forwarded.contains("response.function_call_arguments.delta"));
    assert!(forwarded.contains("response.function_call_arguments.done"));
    assert!(forwarded.contains("response.output_item.done"));
    assert!(forwarded.contains("response.completed"));
}

#[test]
fn done_sentinel_after_completed_is_idempotent() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let raw = format!("{}data: [DONE]\n\n", tool_call_stream());

    let gated = adapter
        .gate_sse_stream(raw.as_bytes(), |_| Ok(allow_verdict()))
        .unwrap();

    let forwarded = String::from_utf8(gated.bytes).unwrap();
    assert!(forwarded.contains("response.completed"));
    assert!(forwarded.ends_with("data: [DONE]\n\n"));
}

#[test]
fn deny_verdict_fails_closed_before_tool_frames_are_released() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let mut calls = 0;
    let err = adapter
        .gate_sse_stream(tool_call_stream().as_bytes(), |_| {
            calls += 1;
            Ok(policy_deny_verdict())
        })
        .expect_err("deny verdict should fail closed");

    assert_eq!(calls, 1);
    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err.to_string().contains("denied at output_item.done"));
    assert!(err.to_string().contains("deny_calendar"));
}

#[test]
fn mismatched_done_arguments_fail_closed_before_verdict() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let raw = concat!(
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"\"}}\n\n",
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"call_calendar_1\",\"delta\":\"{\\\"title\\\":\\\"queued\\\"}\"}\n\n",
        "event: response.function_call_arguments.done\n",
        "data: {\"type\":\"response.function_call_arguments.done\",\"output_index\":0,\"arguments\":\"{\\\"title\\\":\\\"queued\\\"}\"}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"{\\\"title\\\":\\\"different\\\"}\"}}\n\n",
    );

    let mut calls = 0;
    let err = adapter
        .gate_sse_stream(raw.as_bytes(), |_| {
            calls += 1;
            Ok(allow_verdict())
        })
        .expect_err("mismatched streamed arguments should fail closed");

    assert_eq!(calls, 0);
    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err.to_string().contains("did not match"));
}

#[test]
fn missing_function_arguments_done_fails_closed_before_verdict() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let raw = concat!(
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_calendar_1\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"\"}}\n\n",
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"call_calendar_1\",\"delta\":\"{\\\"title\\\":\\\"queued\\\"}\"}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_calendar_1\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"{\\\"title\\\":\\\"queued\\\"}\"}}\n\n",
    );

    let mut calls = 0;
    let err = adapter
        .gate_sse_stream(raw.as_bytes(), |_| {
            calls += 1;
            Ok(allow_verdict())
        })
        .expect_err("missing argument done should fail closed");

    assert_eq!(calls, 0);
    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err
        .to_string()
        .contains("without response.function_call_arguments.done"));
}

#[test]
fn mismatched_function_arguments_done_fails_closed_before_verdict() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let raw = concat!(
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_calendar_1\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"\"}}\n\n",
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"call_calendar_1\",\"delta\":\"{\\\"title\\\":\\\"queued\\\"}\"}\n\n",
        "event: response.function_call_arguments.done\n",
        "data: {\"type\":\"response.function_call_arguments.done\",\"output_index\":0,\"item_id\":\"fc_calendar_1\",\"arguments\":\"{\\\"title\\\":\\\"forbidden\\\"}\"}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_calendar_1\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"{\\\"title\\\":\\\"queued\\\"}\"}}\n\n",
    );

    let mut calls = 0;
    let err = adapter
        .gate_sse_stream(raw.as_bytes(), |_| {
            calls += 1;
            Ok(allow_verdict())
        })
        .expect_err("argument done mismatch should fail closed");

    assert_eq!(calls, 0);
    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err.to_string().contains("did not match final arguments"));
}

#[test]
fn function_arguments_done_must_match_output_item_done_before_verdict() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let raw = concat!(
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_calendar_1\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"\"}}\n\n",
        "event: response.function_call_arguments.done\n",
        "data: {\"type\":\"response.function_call_arguments.done\",\"output_index\":0,\"item_id\":\"fc_calendar_1\",\"arguments\":\"{\\\"title\\\":\\\"forbidden\\\"}\"}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_calendar_1\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"{\\\"title\\\":\\\"safe\\\"}\"}}\n\n",
    );

    let mut calls = 0;
    let err = adapter
        .gate_sse_stream(raw.as_bytes(), |_| {
            calls += 1;
            Ok(allow_verdict())
        })
        .expect_err("argument done and item done mismatch should fail closed");

    assert_eq!(calls, 0);
    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err.to_string().contains("arguments for tool call"));
}

#[test]
fn non_empty_start_arguments_with_delta_fail_closed_before_verdict() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let raw = concat!(
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"{\\\"secret\\\":\\\"forbidden\\\"}\"}}\n\n",
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"call_calendar_1\",\"delta\":\"{\\\"title\\\":\\\"safe\\\"}\"}\n\n",
        "event: response.function_call_arguments.done\n",
        "data: {\"type\":\"response.function_call_arguments.done\",\"output_index\":0,\"arguments\":\"{\\\"title\\\":\\\"safe\\\"}\"}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"call_id\":\"call_calendar_1\",\"name\":\"create_calendar_event\",\"arguments\":\"{\\\"title\\\":\\\"safe\\\"}\"}}\n\n",
    );

    let mut calls = 0;
    let err = adapter
        .gate_sse_stream(raw.as_bytes(), |_| {
            calls += 1;
            Ok(allow_verdict())
        })
        .expect_err("non-empty start args plus deltas should fail closed");

    assert_eq!(calls, 0);
    assert!(matches!(err, ProviderError::BadToolArgs(_)));
    assert!(err.to_string().contains("mixed non-empty"));
}

#[test]
fn id_only_function_call_fails_closed_before_verdict() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let raw = concat!(
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"item_fc_1\",\"name\":\"create_calendar_event\",\"arguments\":\"\"}}\n\n",
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"item_fc_1\",\"delta\":\"{}\"}\n\n",
        "event: response.function_call_arguments.done\n",
        "data: {\"type\":\"response.function_call_arguments.done\",\"output_index\":0,\"item_id\":\"item_fc_1\",\"arguments\":\"{}\"}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"item_fc_1\",\"name\":\"create_calendar_event\",\"arguments\":\"{}\"}}\n\n",
    );

    let mut calls = 0;
    let err = adapter
        .gate_sse_stream(raw.as_bytes(), |_| {
            calls += 1;
            Ok(allow_verdict())
        })
        .expect_err("id-only function call must fail closed");

    assert_eq!(calls, 0);
    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err.to_string().contains("missing non-empty call_id"));
}

#[test]
fn verdict_timeout_terminates_before_tool_frames_are_released() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let err = adapter
        .gate_sse_stream(tool_call_stream().as_bytes(), |_| {
            Err(ProviderError::VerdictBudgetExceeded {
                observed_ms: 300,
                budget_ms: 250,
            })
        })
        .expect_err("timeout should fail closed");

    assert!(matches!(err, ProviderError::VerdictBudgetExceeded { .. }));
    assert!(err.to_string().contains("verdict latency budget exceeded"));
}

#[test]
fn malformed_delta_without_active_tool_call_fails_closed() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let raw = concat!(
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"call_orphan\",\"delta\":\"{}\"}\n\n",
    );

    let err = adapter
        .gate_sse_stream(raw.as_bytes(), |_| Ok(allow_verdict()))
        .expect_err("orphaned delta should fail closed");

    assert!(matches!(err, ProviderError::Malformed(_)));
    assert!(err.to_string().contains("without an active tool call"));
}

#[test]
fn malformed_done_tool_call_arguments_fail_closed() {
    let adapter = OpenAiAdapter::new("org_chio_demo");
    let raw = concat!(
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"call_id\":\"call_bad_args\",\"name\":\"create_calendar_event\",\"arguments\":\"\"}}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"call_id\":\"call_bad_args\",\"name\":\"create_calendar_event\",\"arguments\":\"{not json\"}}\n\n",
    );

    let err = adapter
        .gate_sse_stream(raw.as_bytes(), |_| Ok(allow_verdict()))
        .expect_err("invalid done arguments should fail closed");

    assert!(matches!(err, ProviderError::BadToolArgs(_)));
    assert!(err.to_string().contains("arguments"));
}
