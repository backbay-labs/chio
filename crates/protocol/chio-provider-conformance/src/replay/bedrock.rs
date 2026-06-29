use super::*;

/// Replay a Bedrock fixture through the Bedrock Converse provider adapter.
#[cfg(feature = "fixtures-bedrock")]
pub fn replay_bedrock_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let fixture = load_fixture(path)?;
    fixture.ensure_bedrock()?;
    let captured = fixture.captured_verdicts()?;
    let principal = fixture.bedrock_principal()?;
    let adapter = bedrock_adapter(principal)?;

    let (mode, invocations, verdicts) = if fixture.has_bedrock_stream_tool_events() {
        let (invocations, verdicts) = replay_bedrock_stream(&fixture, &adapter, &captured)?;
        (ReplayMode::Stream, invocations, verdicts)
    } else {
        let invocations = replay_bedrock_batch(&fixture, &adapter)?;
        if captured.is_empty() && invocations.is_empty() {
            (ReplayMode::NoToolCall, Vec::new(), Vec::new())
        } else {
            let verdicts = captured.iter().map(|entry| entry.verdict.clone()).collect();
            (ReplayMode::Batch, invocations, verdicts)
        }
    };

    assert_replayed_invocations(&fixture, &captured, &invocations)?;
    assert_replayed_verdicts(&fixture, &captured, &verdicts)?;
    let lowered_responses = assert_bedrock_lowered_responses(&fixture, &adapter, &captured)?;

    Ok(ReplayOutcome {
        fixture_id: fixture.fixture_id,
        path: fixture.path,
        mode,
        records: fixture.records.len(),
        invocations: invocations.len(),
        verdicts: verdicts.len(),
        lowered_responses,
    })
}

/// Feature-disabled entrypoint that explains which feature is needed for Bedrock replay.
#[cfg(not(feature = "fixtures-bedrock"))]
pub fn replay_bedrock_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let path = path.as_ref();
    Err(invalid_fixture(
        path,
        "Bedrock replay requires the fixtures-bedrock feature",
    ))
}

#[cfg(feature = "fixtures-bedrock")]
fn replay_bedrock_batch(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_bedrock_converse_adapter::BedrockAdapter,
) -> Result<Vec<ToolInvocation>, ReplayError> {
    let mut invocations = Vec::new();
    for record in fixture.upstream_responses() {
        if bedrock_response_has_no_tool_uses(&record.payload) {
            continue;
        }

        let bytes = serde_json::to_vec(&record.payload)?;
        invocations.extend(adapter.lift_batch(ProviderRequest(bytes))?);
    }
    Ok(invocations)
}

#[cfg(feature = "fixtures-bedrock")]
fn replay_bedrock_stream(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_bedrock_converse_adapter::BedrockAdapter,
    captured: &[CapturedVerdict],
) -> Result<(Vec<ToolInvocation>, Vec<VerdictResult>), ReplayError> {
    fixture.ensure_bedrock_stream_verdict_chronology()?;
    let mut verdicts_by_id = captured
        .iter()
        .map(|entry| (entry.invocation_id.clone(), entry.verdict.clone()))
        .collect::<BTreeMap<_, _>>();
    let stream = fixture_bedrock_stream_bytes(fixture)?;
    let gated = adapter.gate_converse_stream(&stream, |invocation| {
        let request_id = invocation.provenance.request_id.as_str();
        verdicts_by_id.remove(request_id).ok_or_else(|| {
            ProviderError::Malformed(format!(
                "Bedrock stream replay produced unexpected invocation {request_id}"
            ))
        })
    })?;

    if let Some((request_id, _)) = verdicts_by_id.into_iter().next() {
        return Err(invalid_fixture(
            &fixture.path,
            format!("Bedrock stream replay did not produce invocation {request_id}"),
        ));
    }

    Ok((gated.invocations, gated.verdicts))
}

#[cfg(feature = "fixtures-bedrock")]
#[derive(Debug, Clone)]
pub(super) struct BedrockFixturePrincipal {
    pub(super) caller_arn: String,
    pub(super) account_id: String,
    pub(super) assumed_role_session_arn: Option<String>,
}

#[cfg(feature = "fixtures-bedrock")]
fn bedrock_adapter(
    principal: BedrockFixturePrincipal,
) -> Result<chio_bedrock_converse_adapter::BedrockAdapter, ReplayError> {
    use std::sync::Arc;

    use chio_bedrock_converse_adapter::transport::MockTransport;
    use chio_bedrock_converse_adapter::{BedrockAdapter, BedrockAdapterConfig};

    let mut config = BedrockAdapterConfig::new(
        "bedrock-1",
        "Bedrock Converse",
        "0.1.0",
        "deadbeef",
        principal.caller_arn,
        principal.account_id,
    );
    if let Some(session_arn) = principal.assumed_role_session_arn {
        config = config.with_assumed_role_session_arn(session_arn);
    }

    BedrockAdapter::new(config, Arc::new(MockTransport::new())).map_err(|error| {
        invalid_fixture(
            Path::new("fixtures/bedrock"),
            format!("Bedrock conformance adapter failed validation: {error}"),
        )
    })
}

#[cfg(feature = "fixtures-bedrock")]
pub(super) fn bedrock_tool_result_payload(
    path: &Path,
    expected_body: &Value,
) -> Result<Vec<u8>, ReplayError> {
    let tool_result = expected_body
        .get("toolResult")
        .ok_or_else(|| invalid_fixture(path, "Bedrock lowered body was missing toolResult"))?;
    canonical_json_bytes_for("captured Bedrock toolResult", tool_result).map_err(ReplayError::from)
}
