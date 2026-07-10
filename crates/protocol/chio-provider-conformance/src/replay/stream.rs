use super::*;

#[cfg(any(
    feature = "fixtures-openai",
    feature = "fixtures-anthropic",
    feature = "fixtures-cohere"
))]
pub(super) fn fixture_sse_bytes(fixture: &ProviderCaptureFixture) -> Result<Vec<u8>, ReplayError> {
    let mut bytes = Vec::new();

    for record in &fixture.records {
        if record.direction != CaptureDirection::UpstreamEvent {
            continue;
        }

        let event = event_name(&record.payload).ok_or_else(|| {
            invalid_fixture(&fixture.path, "upstream_event payload was missing event")
        })?;
        let data = record.payload.get("data").ok_or_else(|| {
            invalid_fixture(&fixture.path, "upstream_event payload was missing data")
        })?;
        bytes.extend_from_slice(b"event: ");
        bytes.extend_from_slice(event.as_bytes());
        bytes.extend_from_slice(b"\n");
        bytes.extend_from_slice(b"data: ");
        bytes.extend_from_slice(serde_json::to_string(data)?.as_bytes());
        bytes.extend_from_slice(b"\n\n");
    }

    Ok(bytes)
}

#[cfg(any(
    feature = "fixtures-openai",
    feature = "fixtures-anthropic",
    feature = "fixtures-cohere"
))]
pub(super) fn event_name(payload: &Value) -> Option<&str> {
    payload.get("event").and_then(Value::as_str)
}

#[cfg(feature = "fixtures-openai")]
pub(super) fn stream_event_item(payload: &Value) -> Option<&Value> {
    payload
        .get("data")
        .and_then(|data| data.get("item"))
        .or_else(|| payload.get("data").and_then(|data| data.get("output_item")))
}

#[cfg(feature = "fixtures-bedrock")]
pub(super) fn fixture_bedrock_stream_bytes(
    fixture: &ProviderCaptureFixture,
) -> Result<Vec<u8>, ReplayError> {
    let events = fixture
        .records
        .iter()
        .filter(|record| record.direction == CaptureDirection::UpstreamEvent)
        .map(|record| record.payload.clone())
        .collect::<Vec<_>>();

    serde_json::to_vec(&events).map_err(ReplayError::from)
}

#[cfg(feature = "fixtures-ollama")]
pub(super) fn fixture_ollama_ndjson_bytes(
    fixture: &ProviderCaptureFixture,
) -> Result<Vec<u8>, ReplayError> {
    let mut bytes = Vec::new();

    for record in &fixture.records {
        if record.direction != CaptureDirection::UpstreamEvent {
            continue;
        }

        let data = record.payload.get("data").ok_or_else(|| {
            invalid_fixture(&fixture.path, "upstream_event payload was missing data")
        })?;
        bytes.extend_from_slice(serde_json::to_string(data)?.as_bytes());
        bytes.push(b'\n');
    }

    Ok(bytes)
}
