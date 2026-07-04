use std::path::{Path, PathBuf};

use chio_provider_conformance::{CaptureDirection, CaptureRecord, CAPTURE_SCHEMA};
use serde_json::{Map, Value};

use crate::bedrock::BEDROCK_REGION;
use crate::cli::ScenarioSeed;
use crate::util::{invalid_fixture, now_ts, seed_api_snapshot, seed_family};
use crate::RecordError;

pub(crate) fn live_request_record(seed: &ScenarioSeed) -> CaptureRecord {
    let mut record = seed.initial_request.clone();
    record.ts = Some(now_ts());
    record.schema = CAPTURE_SCHEMA.to_string();
    record.fixture_id = seed.scenario.clone();
    record.family = seed_family(seed);
    record.api_snapshot = seed_api_snapshot(seed);
    if let Some(object) = record.payload.as_object_mut() {
        object.insert(
            "capture_mode".to_string(),
            Value::String("live_record".to_string()),
        );
    }
    record
}

pub(crate) fn capture_record(
    seed: &ScenarioSeed,
    direction: CaptureDirection,
    payload: Value,
) -> CaptureRecord {
    CaptureRecord {
        ts: Some(now_ts()),
        schema: CAPTURE_SCHEMA.to_string(),
        fixture_id: seed.scenario.clone(),
        family: seed_family(seed),
        api_snapshot: seed_api_snapshot(seed),
        direction,
        provider: seed.provider.fixture_provider().to_string(),
        invocation_id: None,
        verdict: None,
        receipt_id: None,
        payload,
    }
}

pub(crate) fn stamp_openai_headers(
    record: &mut CaptureRecord,
    org_id: &str,
) -> Result<(), RecordError> {
    let headers = headers_mut(&mut record.payload)?;
    headers.insert(
        "OpenAI-Organization".to_string(),
        Value::String(org_id.to_string()),
    );
    Ok(())
}

pub(crate) fn stamp_anthropic_headers(
    record: &mut CaptureRecord,
    workspace_id: &str,
) -> Result<(), RecordError> {
    let headers = headers_mut(&mut record.payload)?;
    headers.insert(
        "x-chio-anthropic-workspace-id".to_string(),
        Value::String(workspace_id.to_string()),
    );
    Ok(())
}

pub(crate) fn stamp_bedrock_headers(
    record: &mut CaptureRecord,
    caller_arn: &str,
    account_id: &str,
    assumed_role_session_arn: Option<&str>,
) -> Result<(), RecordError> {
    let headers = headers_mut(&mut record.payload)?;
    headers.insert(
        "x-chio-bedrock-region".to_string(),
        Value::String(BEDROCK_REGION.to_string()),
    );
    headers.insert(
        "x-chio-bedrock-caller-arn".to_string(),
        Value::String(caller_arn.to_string()),
    );
    headers.insert(
        "x-chio-bedrock-account-id".to_string(),
        Value::String(account_id.to_string()),
    );
    if let Some(session_arn) = assumed_role_session_arn {
        headers.insert(
            "x-chio-bedrock-assumed-role-session-arn".to_string(),
            Value::String(session_arn.to_string()),
        );
    }
    Ok(())
}

fn headers_mut(payload: &mut Value) -> Result<&mut Map<String, Value>, RecordError> {
    let object = payload
        .as_object_mut()
        .ok_or_else(|| RecordError::InvalidFixture {
            path: PathBuf::from("capture"),
            message: "request payload was not a JSON object".to_string(),
        })?;
    let headers = object
        .entry("headers".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if !headers.is_object() {
        *headers = Value::Object(Map::new());
    }
    headers
        .as_object_mut()
        .ok_or_else(|| RecordError::InvalidFixture {
            path: PathBuf::from("capture"),
            message: "request headers were not a JSON object".to_string(),
        })
}

pub(crate) fn request_body(record: &CaptureRecord) -> Result<Value, RecordError> {
    record
        .payload
        .get("body")
        .cloned()
        .ok_or_else(|| invalid_fixture(Path::new("capture"), "request payload was missing body"))
}

pub(crate) fn anthropic_version(record: &CaptureRecord) -> Result<String, RecordError> {
    let headers = record
        .payload
        .get("headers")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            invalid_fixture(Path::new("capture"), "request payload was missing headers")
        })?;
    headers
        .iter()
        .find_map(|(key, value)| {
            if key.eq_ignore_ascii_case("anthropic-version") {
                value.as_str().map(ToString::to_string)
            } else {
                None
            }
        })
        .ok_or_else(|| {
            invalid_fixture(
                Path::new("capture"),
                "request headers were missing anthropic-version",
            )
        })
}

pub(crate) fn insert_payload_field(
    payload: &mut Value,
    key: &str,
    value: Value,
) -> Result<(), RecordError> {
    let object = payload.as_object_mut().ok_or_else(|| {
        invalid_fixture(
            Path::new("capture"),
            format!("payload for field `{key}` was not a JSON object"),
        )
    })?;
    object.insert(key.to_string(), value);
    Ok(())
}
