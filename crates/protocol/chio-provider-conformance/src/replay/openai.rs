use super::*;

/// Replay an OpenAI fixture through the OpenAI provider adapter.
#[cfg(feature = "fixtures-openai")]
pub fn replay_openai_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    use chio_openai::OpenAiAdapter;

    let fixture = load_fixture(path)?;
    fixture.ensure_openai()?;
    let captured = fixture.captured_verdicts()?;
    let org_id = fixture.openai_org_id()?;
    let adapter = OpenAiAdapter::new(org_id);

    let (mode, invocations, verdicts) = if fixture.has_stream_tool_events() {
        let (invocations, verdicts) = replay_openai_stream(&fixture, &adapter, &captured)?;
        (ReplayMode::Stream, invocations, verdicts)
    } else {
        let invocations = replay_openai_batch(&fixture, &adapter)?;
        if captured.is_empty() && invocations.is_empty() {
            (ReplayMode::NoToolCall, Vec::new(), Vec::new())
        } else {
            let verdicts = captured.iter().map(|entry| entry.verdict.clone()).collect();
            (ReplayMode::Batch, invocations, verdicts)
        }
    };

    assert_replayed_invocations(&fixture, &captured, &invocations)?;
    assert_replayed_verdicts(&fixture, &captured, &verdicts)?;
    let lowered_responses = assert_openai_lowered_responses(&fixture, &adapter, &captured)?;

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

/// Feature-disabled entrypoint that explains which feature is needed for OpenAI replay.
#[cfg(not(feature = "fixtures-openai"))]
pub fn replay_openai_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let path = path.as_ref();
    Err(invalid_fixture(
        path,
        "OpenAI replay requires the fixtures-openai feature",
    ))
}

#[cfg(feature = "fixtures-openai")]
fn replay_openai_batch(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_openai::OpenAiAdapter,
) -> Result<Vec<ToolInvocation>, ReplayError> {
    let mut invocations = Vec::new();
    for record in fixture.upstream_responses() {
        if response_has_no_tool_calls(&record.payload) {
            continue;
        }

        let bytes = serde_json::to_vec(&record.payload)?;
        invocations.extend(adapter.lift_batch(ProviderRequest(bytes))?);
    }
    Ok(invocations)
}

#[cfg(feature = "fixtures-openai")]
fn replay_openai_stream(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_openai::OpenAiAdapter,
    captured: &[CapturedVerdict],
) -> Result<(Vec<ToolInvocation>, Vec<VerdictResult>), ReplayError> {
    fixture.ensure_openai_stream_verdict_chronology()?;
    let mut verdicts_by_id = captured
        .iter()
        .map(|entry| (entry.invocation_id.clone(), entry.verdict.clone()))
        .collect::<BTreeMap<_, _>>();
    let sse = fixture_sse_bytes(fixture)?;
    let gated = adapter.gate_sse_stream(&sse, |invocation| {
        let request_id = invocation.provenance.request_id.as_str();
        verdicts_by_id.remove(request_id).ok_or_else(|| {
            ProviderError::Malformed(format!(
                "OpenAI stream replay produced unexpected invocation {request_id}"
            ))
        })
    })?;

    if let Some((request_id, _)) = verdicts_by_id.into_iter().next() {
        return Err(invalid_fixture(
            &fixture.path,
            format!("OpenAI stream replay did not produce invocation {request_id}"),
        ));
    }

    Ok((gated.invocations, gated.verdicts))
}
