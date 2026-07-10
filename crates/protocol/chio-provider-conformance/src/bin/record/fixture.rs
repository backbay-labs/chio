use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use chio_provider_conformance::{
    CaptureDirection, CaptureRecord, CapturedVerdictKind, CAPTURE_SCHEMA,
};
use chio_tool_call_fabric::VerdictResult;
use serde_json::{json, Value};

use crate::cli::{ProviderArg, ScenarioSeed};
use crate::invoke::CapturedInvocation;
use crate::record::insert_payload_field;
use crate::util::{invalid_fixture, now_ts, seed_api_snapshot, seed_family};
use crate::RecordError;

#[derive(Debug)]
pub(crate) struct RecordPlan {
    pub(crate) seed: ScenarioSeed,
    pub(crate) request_record: CaptureRecord,
    pub(crate) response_records: Vec<CaptureRecord>,
    pub(crate) invocations: Vec<CapturedInvocation>,
}

#[derive(Debug)]
pub(crate) struct RecordedFixture {
    pub(crate) path: PathBuf,
    pub(crate) records: Vec<CaptureRecord>,
}

pub(crate) fn assemble_records(plan: RecordPlan) -> Result<RecordedFixture, RecordError> {
    let mut records = Vec::new();
    records.push(plan.request_record);
    records.extend(plan.response_records);
    for invocation in &plan.invocations {
        records.push(kernel_verdict_record(&plan.seed, invocation)?);
    }
    records.extend(lowered_records(&plan.seed, &plan.invocations)?);

    Ok(RecordedFixture {
        path: plan.seed.path,
        records,
    })
}

fn kernel_verdict_record(
    seed: &ScenarioSeed,
    captured: &CapturedInvocation,
) -> Result<CaptureRecord, RecordError> {
    let arguments = serde_json::from_slice::<Value>(&captured.invocation.arguments)?;
    let invocation = json!({
        "provider": captured.invocation.provider,
        "tool_name": captured.invocation.tool_name,
        "arguments": arguments,
        "provenance": {
            "provider": captured.invocation.provenance.provider,
            "request_id": captured.invocation.provenance.request_id,
            "api_version": captured.invocation.provenance.api_version,
            "principal": captured.invocation.provenance.principal,
            "received_at": captured.received_at,
        }
    });
    let payload = match &captured.verdict {
        VerdictResult::Allow { redactions, .. } if redactions.is_empty() => {
            json!({ "invocation": invocation })
        }
        VerdictResult::Allow { redactions, .. } => {
            json!({ "invocation": invocation, "redactions": redactions })
        }
        VerdictResult::Deny { reason, .. } => {
            json!({ "invocation": invocation, "reason": reason })
        }
    };

    Ok(CaptureRecord {
        ts: Some(captured.received_at.clone()),
        schema: CAPTURE_SCHEMA.to_string(),
        fixture_id: seed.scenario.clone(),
        family: seed_family(seed),
        api_snapshot: seed_api_snapshot(seed),
        direction: CaptureDirection::KernelVerdict,
        provider: seed.provider.fixture_provider().to_string(),
        invocation_id: Some(captured.invocation.provenance.request_id.clone()),
        verdict: Some(match captured.verdict {
            VerdictResult::Allow { .. } => CapturedVerdictKind::Allow,
            VerdictResult::Deny { .. } => CapturedVerdictKind::Deny,
        }),
        receipt_id: Some(captured.receipt_id.clone()),
        payload,
    })
}

fn lowered_records(
    seed: &ScenarioSeed,
    invocations: &[CapturedInvocation],
) -> Result<Vec<CaptureRecord>, RecordError> {
    if invocations.is_empty() || seed.lowered_templates.is_empty() {
        return Ok(Vec::new());
    }

    match seed.provider {
        ProviderArg::OpenAi => lowered_openai_records(seed, invocations),
        ProviderArg::Anthropic => lowered_sequential_records(seed, invocations, "tool_use_id"),
        ProviderArg::Bedrock => lowered_bedrock_records(seed, invocations),
    }
}

fn lowered_openai_records(
    seed: &ScenarioSeed,
    invocations: &[CapturedInvocation],
) -> Result<Vec<CaptureRecord>, RecordError> {
    let Some(template) = seed.lowered_templates.first() else {
        return Ok(Vec::new());
    };
    let mut body =
        template.payload.get("body").cloned().ok_or_else(|| {
            invalid_fixture(&seed.path, "OpenAI lowered template was missing body")
        })?;
    let outputs = body
        .get_mut("tool_outputs")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            invalid_fixture(
                &seed.path,
                "OpenAI lowered template was missing tool_outputs",
            )
        })?;
    if outputs.is_empty() {
        return Err(invalid_fixture(
            &seed.path,
            "OpenAI lowered template had no tool_outputs",
        ));
    }
    let templates = outputs.clone();
    outputs.clear();
    for (index, invocation) in invocations.iter().enumerate() {
        let source = templates
            .get(index)
            .or_else(|| templates.last())
            .cloned()
            .ok_or_else(|| {
                invalid_fixture(&seed.path, "OpenAI lowered template lost tool_outputs")
            })?;
        let mut output = source;
        insert_payload_field(
            &mut output,
            "call_id",
            Value::String(invocation.invocation.provenance.request_id.clone()),
        )?;
        outputs.push(output);
    }

    Ok(vec![lowered_record_from_body(seed, template, body)])
}

fn lowered_sequential_records(
    seed: &ScenarioSeed,
    invocations: &[CapturedInvocation],
    id_field: &str,
) -> Result<Vec<CaptureRecord>, RecordError> {
    let mut records = Vec::new();
    for (index, invocation) in invocations.iter().enumerate() {
        let template = seed
            .lowered_templates
            .get(index)
            .or_else(|| seed.lowered_templates.last())
            .ok_or_else(|| invalid_fixture(&seed.path, "lowered template was missing"))?;
        let mut body = template
            .payload
            .get("body")
            .cloned()
            .ok_or_else(|| invalid_fixture(&seed.path, "lowered template was missing body"))?;
        insert_payload_field(
            &mut body,
            id_field,
            Value::String(invocation.invocation.provenance.request_id.clone()),
        )?;
        records.push(lowered_record_from_body(seed, template, body));
    }
    Ok(records)
}

fn lowered_bedrock_records(
    seed: &ScenarioSeed,
    invocations: &[CapturedInvocation],
) -> Result<Vec<CaptureRecord>, RecordError> {
    let mut records = Vec::new();
    for (index, invocation) in invocations.iter().enumerate() {
        let template = seed
            .lowered_templates
            .get(index)
            .or_else(|| seed.lowered_templates.last())
            .ok_or_else(|| invalid_fixture(&seed.path, "Bedrock lowered template was missing"))?;
        let mut body = template.payload.get("body").cloned().ok_or_else(|| {
            invalid_fixture(&seed.path, "Bedrock lowered template was missing body")
        })?;
        let tool_result = body.get_mut("toolResult").ok_or_else(|| {
            invalid_fixture(
                &seed.path,
                "Bedrock lowered template was missing toolResult",
            )
        })?;
        insert_payload_field(
            tool_result,
            "toolUseId",
            Value::String(invocation.invocation.provenance.request_id.clone()),
        )?;
        records.push(lowered_record_from_body(seed, template, body));
    }
    Ok(records)
}

fn lowered_record_from_body(
    seed: &ScenarioSeed,
    template: &CaptureRecord,
    body: Value,
) -> CaptureRecord {
    let mut record = template.clone();
    record.ts = Some(now_ts());
    record.schema = CAPTURE_SCHEMA.to_string();
    record.fixture_id = seed.scenario.clone();
    record.provider = seed.provider.fixture_provider().to_string();
    record.payload = json!({ "body": body });
    record
}

pub(crate) fn write_records_atomic(fixture: &RecordedFixture) -> Result<(), RecordError> {
    let parent = fixture.path.parent().ok_or_else(|| {
        invalid_fixture(
            &fixture.path,
            "fixture path did not have a parent directory",
        )
    })?;
    fs::create_dir_all(parent).map_err(|source| RecordError::CreateFixtureDir {
        path: parent.to_path_buf(),
        source,
    })?;
    let tmp_path = fixture.path.with_extension("ndjson.tmp");
    {
        let file = File::create(&tmp_path).map_err(|source| RecordError::WriteFixture {
            path: tmp_path.clone(),
            source,
        })?;
        let mut writer = BufWriter::new(file);
        for record in &fixture.records {
            serde_json::to_writer(&mut writer, record)?;
            writer
                .write_all(b"\n")
                .map_err(|source| RecordError::WriteFixture {
                    path: tmp_path.clone(),
                    source,
                })?;
        }
        writer.flush().map_err(|source| RecordError::WriteFixture {
            path: tmp_path.clone(),
            source,
        })?;
    }
    fs::rename(&tmp_path, &fixture.path).map_err(|source| RecordError::ReplaceFixture {
        path: fixture.path.clone(),
        source,
    })
}
