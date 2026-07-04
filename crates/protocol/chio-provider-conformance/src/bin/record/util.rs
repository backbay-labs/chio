use std::path::Path;

use chio_provider_conformance::{CaptureDirection, CaptureRecord};
use chrono::{SecondsFormat, Utc};
use serde_json::{json, Value};

use crate::cli::ScenarioSeed;
use crate::record::capture_record;
use crate::RecordError;

pub(crate) fn required_json_str<'a>(
    value: &'a Value,
    field: &str,
    path: &Path,
) -> Result<&'a str, RecordError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid_fixture(path, format!("captured tool call was missing {field}")))
}

pub(crate) fn seed_family(seed: &ScenarioSeed) -> Option<String> {
    seed.records.iter().find_map(|record| record.family.clone())
}

pub(crate) fn seed_api_snapshot(seed: &ScenarioSeed) -> Option<String> {
    seed.records
        .iter()
        .find_map(|record| record.api_snapshot.clone())
}

pub(crate) fn sse_records(
    seed: &ScenarioSeed,
    text: &str,
) -> Result<Vec<CaptureRecord>, RecordError> {
    parse_sse_payloads(text)?
        .into_iter()
        .map(|payload| {
            Ok(capture_record(
                seed,
                CaptureDirection::UpstreamEvent,
                payload,
            ))
        })
        .collect()
}

fn parse_sse_payloads(text: &str) -> Result<Vec<Value>, RecordError> {
    let mut payloads = Vec::new();
    let mut event: Option<String> = None;
    let mut data_lines: Vec<String> = Vec::new();

    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            push_sse_payload(&mut payloads, &mut event, &mut data_lines)?;
            continue;
        }
        if let Some(rest) = line.strip_prefix("event:") {
            event = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("data:") {
            data_lines.push(rest.trim_start().to_string());
        }
    }
    push_sse_payload(&mut payloads, &mut event, &mut data_lines)?;
    Ok(payloads)
}

fn push_sse_payload(
    payloads: &mut Vec<Value>,
    event: &mut Option<String>,
    data_lines: &mut Vec<String>,
) -> Result<(), RecordError> {
    if data_lines.is_empty() {
        *event = None;
        return Ok(());
    }
    let data_text = data_lines.join("\n");
    data_lines.clear();
    if data_text.trim() == "[DONE]" {
        *event = None;
        return Ok(());
    }
    let data = serde_json::from_str::<Value>(&data_text)?;
    let event_name = event.take().unwrap_or_else(|| {
        data.get("type")
            .and_then(Value::as_str)
            .unwrap_or("message")
            .to_string()
    });
    payloads.push(json!({ "event": event_name, "data": data }));
    Ok(())
}

pub(crate) fn now_ts() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub(crate) fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

pub(crate) fn invalid_fixture(path: impl AsRef<Path>, message: impl Into<String>) -> RecordError {
    RecordError::InvalidFixture {
        path: path.as_ref().to_path_buf(),
        message: message.into(),
    }
}
