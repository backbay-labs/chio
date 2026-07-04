use super::*;

pub(super) fn assert_replayed_invocations(
    fixture: &ProviderCaptureFixture,
    captured: &[CapturedVerdict],
    invocations: &[ToolInvocation],
) -> Result<(), ReplayError> {
    let mut expected = captured
        .iter()
        .map(|entry| (entry.invocation_id.clone(), entry.invocation.clone()))
        .collect::<BTreeMap<_, _>>();

    for invocation in invocations {
        let request_id = invocation.provenance.request_id.as_str();
        let expected_invocation = expected.remove(request_id).ok_or_else(|| {
            invalid_fixture(
                &fixture.path,
                format!("adapter produced unexpected invocation {request_id}"),
            )
        })?;
        let actual = comparable_invocation(
            &fixture.path,
            invocation,
            expected_invocation.provenance.received_at.clone(),
        )?;
        assert_canonical_json_eq(
            format!("{} invocation {request_id}", fixture.fixture_id),
            &expected_invocation,
            &actual,
        )?;
    }

    if let Some((request_id, _)) = expected.into_iter().next() {
        return Err(invalid_fixture(
            &fixture.path,
            format!("adapter did not replay expected invocation {request_id}"),
        ));
    }

    Ok(())
}

pub(super) fn assert_replayed_verdicts(
    fixture: &ProviderCaptureFixture,
    captured: &[CapturedVerdict],
    verdicts: &[VerdictResult],
) -> Result<(), ReplayError> {
    if captured.len() != verdicts.len() {
        return Err(invalid_fixture(
            &fixture.path,
            format!(
                "captured {} verdicts but replay produced {}",
                captured.len(),
                verdicts.len()
            ),
        ));
    }

    for (captured, actual) in captured.iter().zip(verdicts) {
        assert_verdict_eq(
            format!("{} verdict {}", fixture.fixture_id, captured.invocation_id),
            &captured.verdict,
            actual,
        )?;
    }

    Ok(())
}

#[cfg(any(
    feature = "fixtures-openai",
    feature = "fixtures-anthropic",
    feature = "fixtures-bedrock"
))]
pub(super) fn captured_verdict_by_invocation_id(
    path: &Path,
    captured: &[CapturedVerdict],
    invocation_id: &str,
) -> Result<VerdictResult, ReplayError> {
    captured
        .iter()
        .find(|entry| entry.invocation_id == invocation_id)
        .map(|entry| entry.verdict.clone())
        .ok_or_else(|| {
            invalid_fixture(
                path,
                format!("lowered tool output {invocation_id} had no captured verdict"),
            )
        })
}

#[cfg(feature = "fixtures-openai")]
pub(super) fn assert_openai_lowered_responses(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_openai::OpenAiAdapter,
    captured: &[CapturedVerdict],
) -> Result<usize, ReplayError> {
    use chio_tool_call_fabric::ProviderAdapter;

    let mut lowered = 0;

    for record in fixture.lowered_tool_output_requests() {
        let expected_body = record.payload.get("body").ok_or_else(|| {
            invalid_fixture(
                &fixture.path,
                "lowered upstream_request payload was missing body",
            )
        })?;
        let expected_outputs = expected_body
            .get("tool_outputs")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                invalid_fixture(
                    &fixture.path,
                    "OpenAI lowered body was missing tool_outputs",
                )
            })?;
        let mut actual_outputs = Vec::with_capacity(expected_outputs.len());
        for expected_output in expected_outputs {
            let call_id = expected_output
                .get("call_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    invalid_fixture(&fixture.path, "OpenAI lowered output was missing call_id")
                })?;
            let verdict = captured_verdict_by_invocation_id(&fixture.path, captured, call_id)?;
            let single_output_body = serde_json::json!({
                "tool_outputs": [expected_output.clone()],
            });
            let result = ToolResult(canonical_json_bytes_for(
                format!("{} captured tool result {call_id}", fixture.fixture_id),
                &single_output_body,
            )?);
            let response = futures_lite_block_on(adapter.lower(verdict, result))?;
            let actual_body = serde_json::from_slice::<Value>(&response.0)?;
            let mut outputs = actual_body
                .get("tool_outputs")
                .and_then(Value::as_array)
                .cloned()
                .ok_or_else(|| {
                    invalid_fixture(
                        &fixture.path,
                        "OpenAI adapter lower response was missing tool_outputs",
                    )
                })?;
            if outputs.len() != 1 {
                return Err(invalid_fixture(
                    &fixture.path,
                    "OpenAI adapter lower response must contain one tool output",
                ));
            }
            actual_outputs.push(outputs.remove(0));
        }
        let actual_body = serde_json::json!({ "tool_outputs": actual_outputs });

        assert_canonical_json_eq(
            format!("{} lowered OpenAI tool_outputs", fixture.fixture_id),
            expected_body,
            &actual_body,
        )?;
        lowered += 1;
    }

    Ok(lowered)
}

#[cfg(feature = "fixtures-anthropic")]
pub(super) fn assert_anthropic_lowered_responses(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_anthropic_tools_adapter::AnthropicAdapter,
    captured: &[CapturedVerdict],
) -> Result<usize, ReplayError> {
    use chio_tool_call_fabric::ProviderAdapter;

    let mut lowered = 0;

    for record in fixture.lowered_anthropic_tool_result_requests() {
        let expected_body = record.payload.get("body").ok_or_else(|| {
            invalid_fixture(
                &fixture.path,
                "lowered upstream_request payload was missing body",
            )
        })?;
        let tool_use_id = expected_body
            .get("tool_use_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                invalid_fixture(
                    &fixture.path,
                    "Anthropic lowered tool_result was missing tool_use_id",
                )
            })?;
        let verdict = captured_verdict_by_invocation_id(&fixture.path, captured, tool_use_id)?;
        let result = ToolResult(anthropic_tool_result_payload(&fixture.path, expected_body)?);
        let response = futures_lite_block_on(adapter.lower(verdict, result))?;
        let actual_body = serde_json::from_slice::<Value>(&response.0)?;

        assert_canonical_json_eq(
            format!("{} lowered Anthropic tool_result", fixture.fixture_id),
            expected_body,
            &actual_body,
        )?;
        lowered += 1;
    }

    Ok(lowered)
}

#[cfg(feature = "fixtures-bedrock")]
pub(super) fn assert_bedrock_lowered_responses(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_bedrock_converse_adapter::BedrockAdapter,
    captured: &[CapturedVerdict],
) -> Result<usize, ReplayError> {
    use chio_tool_call_fabric::ProviderAdapter;

    let mut lowered = 0;

    for record in fixture.lowered_bedrock_tool_result_requests() {
        let expected_body = record.payload.get("body").ok_or_else(|| {
            invalid_fixture(
                &fixture.path,
                "lowered upstream_request payload was missing body",
            )
        })?;
        let tool_use_id = expected_body
            .get("toolResult")
            .and_then(|tool_result| tool_result.get("toolUseId"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                invalid_fixture(
                    &fixture.path,
                    "Bedrock lowered toolResult was missing toolUseId",
                )
            })?;
        let verdict = captured_verdict_by_invocation_id(&fixture.path, captured, tool_use_id)?;
        let result = ToolResult(bedrock_tool_result_payload(&fixture.path, expected_body)?);
        let response = futures_lite_block_on(adapter.lower(verdict, result))?;
        let actual_body = serde_json::from_slice::<Value>(&response.0)?;

        assert_canonical_json_eq(
            format!("{} lowered Bedrock toolResult", fixture.fixture_id),
            expected_body,
            &actual_body,
        )?;
        lowered += 1;
    }

    Ok(lowered)
}

pub(super) fn comparable_invocation(
    path: &Path,
    invocation: &ToolInvocation,
    received_at: Value,
) -> Result<ComparableInvocation, ReplayError> {
    invocation.validate().map_err(|error| {
        invalid_fixture(
            path,
            format!("adapter produced invalid fabric invocation: {error}"),
        )
    })?;
    Ok(ComparableInvocation {
        provider: invocation.provider,
        tool_name: invocation.tool_name.clone(),
        arguments: serde_json::from_slice(&invocation.arguments)?,
        provenance: ComparableProvenance {
            provider: invocation.provenance.provider,
            request_id: invocation.provenance.request_id.clone(),
            api_version: invocation.provenance.api_version.clone(),
            principal: invocation.provenance.principal.clone(),
            received_at,
        },
    })
}

pub(super) fn captured_redactions(payload: &Value) -> Result<Vec<Redaction>, ReplayError> {
    let Some(redactions) = payload.get("redactions") else {
        return Ok(Vec::new());
    };
    serde_json::from_value(redactions.clone()).map_err(ReplayError::from)
}

pub(super) fn captured_deny_reason(
    path: &Path,
    payload: &Value,
) -> Result<DenyReason, ReplayError> {
    let reason = payload
        .get("reason")
        .ok_or_else(|| invalid_fixture(path, "deny kernel_verdict payload was missing reason"))?;
    serde_json::from_value(reason.clone()).map_err(ReplayError::from)
}

#[cfg(any(
    feature = "fixtures-openai",
    feature = "fixtures-anthropic",
    feature = "fixtures-bedrock"
))]
pub(super) fn futures_lite_block_on<F>(future: F) -> F::Output
where
    F: std::future::Future,
{
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    let waker = Waker::from(Arc::new(NoopWaker));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);

    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}
