use super::*;

/// Replay a Gemini fixture through the Gemini provider adapter.
#[cfg(feature = "fixtures-gemini")]
pub fn replay_gemini_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let fixture = load_fixture(path)?;
    fixture.ensure_gemini()?;
    let captured = fixture.captured_verdicts()?;
    let project_id = fixture.gemini_project_id()?;
    let adapter = gemini_adapter(project_id);
    let invocations = replay_gemini_batch(&fixture, &adapter)?;
    let (mode, verdicts) = replay_mode_and_captured_verdicts(&captured, invocations.is_empty());

    assert_replayed_invocations(&fixture, &captured, &invocations)?;
    assert_replayed_verdicts(&fixture, &captured, &verdicts)?;
    let lowered_responses = assert_gemini_lowered_responses(&fixture, &adapter, &captured)?;

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

/// Replay a Mistral fixture through the Mistral provider adapter.
#[cfg(feature = "fixtures-mistral")]
pub fn replay_mistral_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let fixture = load_fixture(path)?;
    fixture.ensure_mistral()?;
    let captured = fixture.captured_verdicts()?;
    let project_id = fixture.mistral_project_id()?;
    let adapter = mistral_adapter(project_id);
    let invocations = replay_mistral_batch(&fixture, &adapter)?;
    let (mode, verdicts) = replay_mode_and_captured_verdicts(&captured, invocations.is_empty());

    assert_replayed_invocations(&fixture, &captured, &invocations)?;
    assert_replayed_verdicts(&fixture, &captured, &verdicts)?;
    let lowered_responses = assert_mistral_lowered_responses(&fixture, &adapter, &captured)?;

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

/// Replay a Groq fixture through the Groq provider adapter.
#[cfg(feature = "fixtures-groq")]
pub fn replay_groq_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let fixture = load_fixture(path)?;
    fixture.ensure_groq()?;
    let captured = fixture.captured_verdicts()?;
    let project_id = fixture.groq_project_id()?;
    let adapter = groq_adapter(project_id);
    let invocations = replay_groq_batch(&fixture, &adapter)?;
    let (mode, verdicts) = replay_mode_and_captured_verdicts(&captured, invocations.is_empty());

    assert_replayed_invocations(&fixture, &captured, &invocations)?;
    assert_replayed_verdicts(&fixture, &captured, &verdicts)?;
    let lowered_responses = assert_groq_lowered_responses(&fixture, &adapter, &captured)?;

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

/// Replay an Ollama fixture through the Ollama provider adapter.
#[cfg(feature = "fixtures-ollama")]
pub fn replay_ollama_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let fixture = load_fixture(path)?;
    fixture.ensure_ollama()?;
    let captured = fixture.captured_verdicts()?;
    let host = fixture.ollama_host()?;
    let adapter = ollama_adapter(host);

    let (mode, invocations, verdicts) = if fixture.has_ollama_stream_tool_events() {
        let (invocations, verdicts) = replay_ollama_stream(&fixture, &adapter, &captured)?;
        (ReplayMode::Stream, invocations, verdicts)
    } else {
        let invocations = replay_ollama_batch(&fixture, &adapter)?;
        if captured.is_empty() && invocations.is_empty() {
            (ReplayMode::NoToolCall, Vec::new(), Vec::new())
        } else {
            let verdicts = captured.iter().map(|entry| entry.verdict.clone()).collect();
            (ReplayMode::Batch, invocations, verdicts)
        }
    };

    assert_replayed_invocations(&fixture, &captured, &invocations)?;
    assert_replayed_verdicts(&fixture, &captured, &verdicts)?;
    let lowered_responses = assert_ollama_lowered_responses(&fixture, &adapter, &captured)?;

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

/// Replay a Cohere fixture through the Cohere provider adapter.
#[cfg(feature = "fixtures-cohere")]
pub fn replay_cohere_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let fixture = load_fixture(path)?;
    fixture.ensure_cohere()?;
    let captured = fixture.captured_verdicts()?;
    let org_id = fixture.cohere_org_id()?;
    let adapter = cohere_adapter(org_id);

    let (mode, invocations, verdicts) = if fixture.has_cohere_stream_tool_events() {
        let (invocations, verdicts) = replay_cohere_stream(&fixture, &adapter, &captured)?;
        (ReplayMode::Stream, invocations, verdicts)
    } else {
        let invocations = replay_cohere_batch(&fixture, &adapter)?;
        if captured.is_empty() && invocations.is_empty() {
            (ReplayMode::NoToolCall, Vec::new(), Vec::new())
        } else {
            let verdicts = captured.iter().map(|entry| entry.verdict.clone()).collect();
            (ReplayMode::Batch, invocations, verdicts)
        }
    };

    assert_replayed_invocations(&fixture, &captured, &invocations)?;
    assert_replayed_verdicts(&fixture, &captured, &verdicts)?;
    let lowered_responses = assert_cohere_lowered_responses(&fixture, &adapter, &captured)?;

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

#[cfg(any(
    feature = "fixtures-gemini",
    feature = "fixtures-mistral",
    feature = "fixtures-groq"
))]
fn replay_mode_and_captured_verdicts(
    captured: &[CapturedVerdict],
    invocations_empty: bool,
) -> (ReplayMode, Vec<VerdictResult>) {
    if captured.is_empty() && invocations_empty {
        (ReplayMode::NoToolCall, Vec::new())
    } else {
        let verdicts = captured.iter().map(|entry| entry.verdict.clone()).collect();
        (ReplayMode::Batch, verdicts)
    }
}

#[cfg(feature = "fixtures-gemini")]
fn assert_gemini_lowered_responses(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_gemini_tools_adapter::GeminiAdapter,
    captured: &[CapturedVerdict],
) -> Result<usize, ReplayError> {
    let mut lowered = 0;
    let mut records = lowered_response_records_by_invocation_id(fixture)?;
    for entry in captured {
        let record = take_lowered_response_record(fixture, &mut records, entry)?;
        let part = adapter.lower_function_response(
            &entry.invocation.tool_name,
            entry.verdict.clone(),
            replay_tool_result(fixture, entry, record)?,
        )?;
        let actual = serde_json::to_value(part)?;
        assert_captured_lowered_response(fixture, entry, record, "Gemini", &actual)?;
        lowered += 1;
    }
    ensure_no_unconsumed_lowered_records(fixture, records)?;
    Ok(lowered)
}

#[cfg(feature = "fixtures-mistral")]
fn assert_mistral_lowered_responses(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_mistral_tools_adapter::MistralAdapter,
    captured: &[CapturedVerdict],
) -> Result<usize, ReplayError> {
    let mut lowered = 0;
    let mut records = lowered_response_records_by_invocation_id(fixture)?;
    for entry in captured {
        let record = take_lowered_response_record(fixture, &mut records, entry)?;
        let part = adapter.lower_function_response(
            &entry.invocation_id,
            entry.verdict.clone(),
            replay_tool_result(fixture, entry, record)?,
        )?;
        let actual = openai_compatible_tool_message(&part.tool_call_id, &part.response)?;
        assert_captured_lowered_response(fixture, entry, record, "Mistral", &actual)?;
        lowered += 1;
    }
    ensure_no_unconsumed_lowered_records(fixture, records)?;
    Ok(lowered)
}

#[cfg(feature = "fixtures-groq")]
fn assert_groq_lowered_responses(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_groq_tools_adapter::GroqAdapter,
    captured: &[CapturedVerdict],
) -> Result<usize, ReplayError> {
    let mut lowered = 0;
    let mut records = lowered_response_records_by_invocation_id(fixture)?;
    for entry in captured {
        let record = take_lowered_response_record(fixture, &mut records, entry)?;
        let part = adapter.lower_function_response(
            &entry.invocation_id,
            entry.verdict.clone(),
            replay_tool_result(fixture, entry, record)?,
        )?;
        let actual = openai_compatible_tool_message(&part.tool_call_id, &part.response)?;
        assert_captured_lowered_response(fixture, entry, record, "Groq", &actual)?;
        lowered += 1;
    }
    ensure_no_unconsumed_lowered_records(fixture, records)?;
    Ok(lowered)
}

#[cfg(feature = "fixtures-ollama")]
fn assert_ollama_lowered_responses(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_ollama_tools_adapter::OllamaAdapter,
    captured: &[CapturedVerdict],
) -> Result<usize, ReplayError> {
    let mut lowered = 0;
    let mut records = lowered_response_records_by_invocation_id(fixture)?;
    for entry in captured {
        let record = take_lowered_response_record(fixture, &mut records, entry)?;
        let message = adapter.lower_tool_message(
            &entry.invocation.tool_name,
            entry.verdict.clone(),
            replay_tool_result(fixture, entry, record)?,
        )?;
        let actual = serde_json::to_value(message)?;
        assert_captured_lowered_response(fixture, entry, record, "Ollama", &actual)?;
        lowered += 1;
    }
    ensure_no_unconsumed_lowered_records(fixture, records)?;
    Ok(lowered)
}

#[cfg(feature = "fixtures-cohere")]
fn assert_cohere_lowered_responses(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_cohere_tools_adapter::CohereAdapter,
    captured: &[CapturedVerdict],
) -> Result<usize, ReplayError> {
    let mut lowered = 0;
    let mut records = lowered_response_records_by_invocation_id(fixture)?;
    for entry in captured {
        let record = take_lowered_response_record(fixture, &mut records, entry)?;
        let message = adapter.lower_tool_message(
            &entry.invocation_id,
            entry.verdict.clone(),
            replay_tool_result(fixture, entry, record)?,
        )?;
        let actual = serde_json::to_value(message)?;
        assert_captured_lowered_response(fixture, entry, record, "Cohere", &actual)?;
        lowered += 1;
    }
    ensure_no_unconsumed_lowered_records(fixture, records)?;
    Ok(lowered)
}

#[cfg(any(
    feature = "fixtures-gemini",
    feature = "fixtures-mistral",
    feature = "fixtures-groq",
    feature = "fixtures-ollama",
    feature = "fixtures-cohere"
))]
fn replay_tool_result(
    fixture: &ProviderCaptureFixture,
    entry: &CapturedVerdict,
    record: &CaptureRecord,
) -> Result<ToolResult, ReplayError> {
    let tool_result = record.payload.get("tool_result").ok_or_else(|| {
        invalid_fixture(
            &fixture.path,
            format!(
                "lowered tool result {} was missing tool_result",
                entry.invocation_id
            ),
        )
    })?;
    Ok(ToolResult(canonical_json_bytes_for(
        format!(
            "{} captured tool result {}",
            fixture.fixture_id, entry.invocation_id
        ),
        tool_result,
    )?))
}

#[cfg(any(feature = "fixtures-mistral", feature = "fixtures-groq"))]
fn openai_compatible_tool_message(
    tool_call_id: &str,
    response: &Value,
) -> Result<Value, ReplayError> {
    Ok(serde_json::json!({
        "role": "tool",
        "tool_call_id": tool_call_id,
        "content": serde_json::to_string(response)?,
    }))
}

#[cfg(any(
    feature = "fixtures-gemini",
    feature = "fixtures-mistral",
    feature = "fixtures-groq",
    feature = "fixtures-ollama",
    feature = "fixtures-cohere"
))]
fn lowered_response_records_by_invocation_id(
    fixture: &ProviderCaptureFixture,
) -> Result<BTreeMap<String, &CaptureRecord>, ReplayError> {
    let mut records = BTreeMap::new();
    for record in &fixture.records {
        if record.direction != CaptureDirection::UpstreamRequest {
            continue;
        }
        if record.payload.get("stage").and_then(Value::as_str) != Some("lowered_tool_result") {
            continue;
        }
        let invocation_id = record
            .payload
            .get("invocation_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                invalid_fixture(
                    &fixture.path,
                    "lowered tool result record was missing invocation_id",
                )
            })?;
        if records.insert(invocation_id.to_string(), record).is_some() {
            return Err(invalid_fixture(
                &fixture.path,
                format!("duplicate lowered tool result record for {invocation_id}"),
            ));
        }
    }
    Ok(records)
}

#[cfg(any(
    feature = "fixtures-gemini",
    feature = "fixtures-mistral",
    feature = "fixtures-groq",
    feature = "fixtures-ollama",
    feature = "fixtures-cohere"
))]
fn take_lowered_response_record<'a>(
    fixture: &ProviderCaptureFixture,
    records: &mut BTreeMap<String, &'a CaptureRecord>,
    entry: &CapturedVerdict,
) -> Result<&'a CaptureRecord, ReplayError> {
    records.remove(&entry.invocation_id).ok_or_else(|| {
        invalid_fixture(
            &fixture.path,
            format!(
                "captured verdict {} had no lowered tool result record",
                entry.invocation_id
            ),
        )
    })
}

#[cfg(any(
    feature = "fixtures-gemini",
    feature = "fixtures-mistral",
    feature = "fixtures-groq",
    feature = "fixtures-ollama",
    feature = "fixtures-cohere"
))]
fn assert_captured_lowered_response(
    fixture: &ProviderCaptureFixture,
    entry: &CapturedVerdict,
    record: &CaptureRecord,
    provider_label: &str,
    actual: &Value,
) -> Result<(), ReplayError> {
    let expected = record.payload.get("body").ok_or_else(|| {
        invalid_fixture(
            &fixture.path,
            format!(
                "lowered tool result {} was missing body",
                entry.invocation_id
            ),
        )
    })?;

    assert_canonical_json_eq(
        format!(
            "{} lowered {provider_label} {}",
            fixture.fixture_id, entry.invocation_id
        ),
        expected,
        actual,
    )?;
    Ok(())
}

#[cfg(any(
    feature = "fixtures-gemini",
    feature = "fixtures-mistral",
    feature = "fixtures-groq",
    feature = "fixtures-ollama",
    feature = "fixtures-cohere"
))]
fn ensure_no_unconsumed_lowered_records(
    fixture: &ProviderCaptureFixture,
    records: BTreeMap<String, &CaptureRecord>,
) -> Result<(), ReplayError> {
    if let Some(invocation_id) = records.keys().next() {
        return Err(invalid_fixture(
            &fixture.path,
            format!("lowered tool result {invocation_id} had no captured verdict"),
        ));
    }
    Ok(())
}

/// Feature-disabled entrypoint that explains which feature is needed for Gemini replay.
#[cfg(not(feature = "fixtures-gemini"))]
pub fn replay_gemini_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let path = path.as_ref();
    Err(invalid_fixture(
        path,
        "Gemini replay requires the fixtures-gemini feature",
    ))
}

/// Feature-disabled entrypoint that explains which feature is needed for Mistral replay.
#[cfg(not(feature = "fixtures-mistral"))]
pub fn replay_mistral_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let path = path.as_ref();
    Err(invalid_fixture(
        path,
        "Mistral replay requires the fixtures-mistral feature",
    ))
}

/// Feature-disabled entrypoint that explains which feature is needed for Groq replay.
#[cfg(not(feature = "fixtures-groq"))]
pub fn replay_groq_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let path = path.as_ref();
    Err(invalid_fixture(
        path,
        "Groq replay requires the fixtures-groq feature",
    ))
}

/// Feature-disabled entrypoint that explains which feature is needed for Ollama replay.
#[cfg(not(feature = "fixtures-ollama"))]
pub fn replay_ollama_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let path = path.as_ref();
    Err(invalid_fixture(
        path,
        "Ollama replay requires the fixtures-ollama feature",
    ))
}

/// Feature-disabled entrypoint that explains which feature is needed for Cohere replay.
#[cfg(not(feature = "fixtures-cohere"))]
pub fn replay_cohere_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let path = path.as_ref();
    Err(invalid_fixture(
        path,
        "Cohere replay requires the fixtures-cohere feature",
    ))
}

#[cfg(feature = "fixtures-gemini")]
fn replay_gemini_batch(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_gemini_tools_adapter::GeminiAdapter,
) -> Result<Vec<ToolInvocation>, ReplayError> {
    let mut invocations = Vec::new();
    for record in fixture.upstream_responses() {
        if gemini_response_has_no_function_calls(&record.payload) {
            continue;
        }

        let bytes = serde_json::to_vec(&record.payload)?;
        invocations.extend(adapter.lift_batch(ProviderRequest(bytes))?);
    }
    Ok(invocations)
}

#[cfg(feature = "fixtures-mistral")]
fn replay_mistral_batch(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_mistral_tools_adapter::MistralAdapter,
) -> Result<Vec<ToolInvocation>, ReplayError> {
    let mut invocations = Vec::new();
    for record in fixture.upstream_responses() {
        if openai_compatible_response_has_no_tool_calls(&record.payload) {
            continue;
        }

        let bytes = serde_json::to_vec(&record.payload)?;
        invocations.extend(adapter.lift_batch(ProviderRequest(bytes))?);
    }
    Ok(invocations)
}

#[cfg(feature = "fixtures-groq")]
fn replay_groq_batch(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_groq_tools_adapter::GroqAdapter,
) -> Result<Vec<ToolInvocation>, ReplayError> {
    let mut invocations = Vec::new();
    for record in fixture.upstream_responses() {
        if openai_compatible_response_has_no_tool_calls(&record.payload) {
            continue;
        }

        let bytes = serde_json::to_vec(&record.payload)?;
        invocations.extend(adapter.lift_batch(ProviderRequest(bytes))?);
    }
    Ok(invocations)
}

#[cfg(feature = "fixtures-ollama")]
fn replay_ollama_batch(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_ollama_tools_adapter::OllamaAdapter,
) -> Result<Vec<ToolInvocation>, ReplayError> {
    let mut invocations = Vec::new();
    for record in fixture.upstream_responses() {
        if ollama_response_has_no_tool_calls(&record.payload) {
            continue;
        }

        let bytes = serde_json::to_vec(&record.payload)?;
        invocations.extend(adapter.lift_batch(ProviderRequest(bytes))?);
    }
    Ok(invocations)
}

#[cfg(feature = "fixtures-cohere")]
fn replay_cohere_batch(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_cohere_tools_adapter::CohereAdapter,
) -> Result<Vec<ToolInvocation>, ReplayError> {
    let mut invocations = Vec::new();
    for record in fixture.upstream_responses() {
        if cohere_response_has_no_tool_calls(&record.payload) {
            continue;
        }

        let bytes = serde_json::to_vec(&record.payload)?;
        invocations.extend(adapter.lift_batch(ProviderRequest(bytes))?);
    }
    Ok(invocations)
}

#[cfg(feature = "fixtures-ollama")]
fn replay_ollama_stream(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_ollama_tools_adapter::OllamaAdapter,
    captured: &[CapturedVerdict],
) -> Result<(Vec<ToolInvocation>, Vec<VerdictResult>), ReplayError> {
    let mut verdicts_by_id = captured
        .iter()
        .map(|entry| (entry.invocation_id.clone(), entry.verdict.clone()))
        .collect::<BTreeMap<_, _>>();
    let ndjson = fixture_ollama_ndjson_bytes(fixture)?;
    let gated = adapter.gate_sse_stream(&ndjson, |invocation| {
        let request_id = invocation.provenance.request_id.as_str();
        verdicts_by_id.remove(request_id).ok_or_else(|| {
            ProviderError::Malformed(format!(
                "Ollama stream replay produced unexpected invocation {request_id}"
            ))
        })
    })?;

    if let Some((request_id, _)) = verdicts_by_id.into_iter().next() {
        return Err(invalid_fixture(
            &fixture.path,
            format!("Ollama stream replay did not produce invocation {request_id}"),
        ));
    }

    Ok((gated.invocations, gated.verdicts))
}

#[cfg(feature = "fixtures-cohere")]
fn replay_cohere_stream(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_cohere_tools_adapter::CohereAdapter,
    captured: &[CapturedVerdict],
) -> Result<(Vec<ToolInvocation>, Vec<VerdictResult>), ReplayError> {
    let mut verdicts_by_id = captured
        .iter()
        .map(|entry| (entry.invocation_id.clone(), entry.verdict.clone()))
        .collect::<BTreeMap<_, _>>();
    let sse = fixture_sse_bytes(fixture)?;
    let gated = adapter.gate_sse_stream(&sse, |invocation| {
        let request_id = invocation.provenance.request_id.as_str();
        verdicts_by_id.remove(request_id).ok_or_else(|| {
            ProviderError::Malformed(format!(
                "Cohere stream replay produced unexpected invocation {request_id}"
            ))
        })
    })?;

    if let Some((request_id, _)) = verdicts_by_id.into_iter().next() {
        return Err(invalid_fixture(
            &fixture.path,
            format!("Cohere stream replay did not produce invocation {request_id}"),
        ));
    }

    Ok((gated.invocations, gated.verdicts))
}

#[cfg(feature = "fixtures-gemini")]
fn gemini_adapter(project_id: String) -> chio_gemini_tools_adapter::GeminiAdapter {
    use std::sync::Arc;

    use chio_gemini_tools_adapter::transport::MockTransport;
    use chio_gemini_tools_adapter::{GeminiAdapter, GeminiAdapterConfig};

    GeminiAdapter::new(
        GeminiAdapterConfig::new(
            "gemini-1",
            "Gemini GenerateContent",
            "0.1.0",
            "deadbeef",
            project_id,
        ),
        Arc::new(MockTransport::new()),
    )
}

#[cfg(feature = "fixtures-mistral")]
fn mistral_adapter(project_id: String) -> chio_mistral_tools_adapter::MistralAdapter {
    use std::sync::Arc;

    use chio_mistral_tools_adapter::transport::MockTransport;
    use chio_mistral_tools_adapter::{MistralAdapter, MistralAdapterConfig};

    MistralAdapter::new(
        MistralAdapterConfig::new(
            "mistral-1",
            "Mistral Chat Completions",
            "0.1.0",
            "deadbeef",
            project_id,
        ),
        Arc::new(MockTransport::new()),
    )
}

#[cfg(feature = "fixtures-groq")]
fn groq_adapter(project_id: String) -> chio_groq_tools_adapter::GroqAdapter {
    use std::sync::Arc;

    use chio_groq_tools_adapter::{GroqAdapter, GroqAdapterConfig, MockTransport};

    GroqAdapter::new(
        GroqAdapterConfig::new(
            "groq-1",
            "Groq Chat Completions",
            "0.1.0",
            "deadbeef",
            project_id,
        ),
        Arc::new(MockTransport::new()),
    )
}

#[cfg(feature = "fixtures-ollama")]
fn ollama_adapter(host: String) -> chio_ollama_tools_adapter::OllamaAdapter {
    use std::sync::Arc;

    use chio_ollama_tools_adapter::transport::MockTransport;
    use chio_ollama_tools_adapter::{OllamaAdapter, OllamaAdapterConfig};

    OllamaAdapter::new(
        OllamaAdapterConfig::new("ollama-1", "Ollama Chat", "0.1.0", "deadbeef", host),
        Arc::new(MockTransport::new("mock://ollama")),
    )
}

#[cfg(feature = "fixtures-cohere")]
fn cohere_adapter(org_id: String) -> chio_cohere_tools_adapter::CohereAdapter {
    use std::sync::Arc;

    use chio_cohere_tools_adapter::{CohereAdapter, CohereAdapterConfig, MockTransport};

    CohereAdapter::new(
        CohereAdapterConfig::new("cohere-1", "Cohere Chat", "0.1.0", "deadbeef", org_id),
        Arc::new(MockTransport::new()),
    )
}

#[cfg(feature = "fixtures-gemini")]
fn gemini_response_has_no_function_calls(payload: &Value) -> bool {
    !payload_has_gemini_function_call(gemini_response_body(payload))
}

#[cfg(feature = "fixtures-gemini")]
fn gemini_response_body(payload: &Value) -> &Value {
    ["body", "response", "payload"]
        .iter()
        .find_map(|field| payload.get(field).filter(|value| value.is_object()))
        .unwrap_or(payload)
}

#[cfg(feature = "fixtures-gemini")]
fn payload_has_gemini_function_call(value: &Value) -> bool {
    if value.get("functionCall").is_some() {
        return true;
    }

    value
        .get("candidates")
        .and_then(Value::as_array)
        .is_some_and(|candidates| {
            candidates.iter().any(|candidate| {
                candidate
                    .get("content")
                    .and_then(|content| content.get("parts"))
                    .and_then(Value::as_array)
                    .is_some_and(|parts| {
                        parts.iter().any(|part| part.get("functionCall").is_some())
                    })
            })
        })
}

#[cfg(any(feature = "fixtures-mistral", feature = "fixtures-groq"))]
fn openai_compatible_response_has_no_tool_calls(payload: &Value) -> bool {
    let body = openai_compatible_response_body(payload);
    !body
        .get("choices")
        .and_then(Value::as_array)
        .is_some_and(|choices| {
            choices.iter().any(|choice| {
                choice
                    .get("message")
                    .and_then(|message| message.get("tool_calls"))
                    .and_then(Value::as_array)
                    .is_some_and(|calls| !calls.is_empty())
            })
        })
}

#[cfg(any(feature = "fixtures-mistral", feature = "fixtures-groq"))]
fn openai_compatible_response_body(payload: &Value) -> &Value {
    ["body", "response", "payload"]
        .iter()
        .find_map(|field| payload.get(field).filter(|value| value.is_object()))
        .unwrap_or(payload)
}

#[cfg(feature = "fixtures-ollama")]
fn ollama_response_has_no_tool_calls(payload: &Value) -> bool {
    let body = ollama_response_body(payload);
    body.get("message")
        .and_then(|message| message.get("tool_calls"))
        .and_then(Value::as_array)
        .is_none_or(|calls| calls.is_empty())
}

#[cfg(feature = "fixtures-ollama")]
fn ollama_response_body(payload: &Value) -> &Value {
    ["body", "response", "payload"]
        .iter()
        .find_map(|field| payload.get(field).filter(|value| value.is_object()))
        .unwrap_or(payload)
}

#[cfg(feature = "fixtures-cohere")]
fn cohere_response_has_no_tool_calls(payload: &Value) -> bool {
    let body = cohere_response_body(payload);
    body.get("message")
        .and_then(|message| message.get("tool_calls"))
        .and_then(Value::as_array)
        .is_none_or(|calls| calls.is_empty())
}

#[cfg(feature = "fixtures-cohere")]
fn cohere_response_body(payload: &Value) -> &Value {
    ["body", "response", "payload"]
        .iter()
        .find_map(|field| payload.get(field).filter(|value| value.is_object()))
        .unwrap_or(payload)
}
