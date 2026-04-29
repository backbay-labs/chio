//! Replay OpenAI provider captures through the native adapter surface.

#![cfg_attr(
    not(any(
        feature = "fixtures-openai",
        feature = "fixtures-anthropic",
        feature = "fixtures-bedrock"
    )),
    allow(dead_code, unused_imports)
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use chio_tool_call_fabric::{
    DenyReason, Principal, ProviderError, ProviderId, ProviderRequest, ReceiptId, Redaction,
    ToolInvocation, ToolResult, VerdictResult,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::assertions::{
    assert_canonical_json_eq, assert_verdict_eq, canonical_json_bytes_for, AssertionError,
};
use crate::capture::{CaptureDirection, CaptureRecord, CapturedVerdictKind, CAPTURE_SCHEMA};

/// Replay error with fixture path context.
#[derive(Debug, Error)]
pub enum ReplayError {
    /// A fixture file could not be read.
    #[error("read fixture {path:?}: {source}")]
    ReadFixture {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// A fixture directory could not be read.
    #[error("read fixture directory {path:?}: {source}")]
    ReadFixtureDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// A fixture line was not valid JSON.
    #[error("parse fixture {path:?} line {line}: {source}")]
    ParseLine {
        path: PathBuf,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    /// A capture field had an unsupported value.
    #[error("invalid fixture {path:?}: {message}")]
    InvalidFixture { path: PathBuf, message: String },
    /// Canonical JSON or equality assertion failed.
    #[error(transparent)]
    Assertion(#[from] AssertionError),
    /// Provider adapter replay failed.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// JSON encoding or decoding failed while reconstructing replay inputs.
    #[error("JSON error during replay: {0}")]
    Json(#[from] serde_json::Error),
}

/// Loaded provider capture fixture.
#[derive(Debug, Clone)]
pub struct ProviderCaptureFixture {
    /// Fixture id embedded in every capture record.
    pub fixture_id: String,
    /// Source file path.
    pub path: PathBuf,
    records: Vec<CaptureRecord>,
}

/// Replay mode selected from the capture shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayMode {
    /// Batch `upstream_response` payloads were lifted.
    Batch,
    /// Streaming `upstream_event` payloads were replayed as SSE.
    Stream,
    /// No tool call crossed the adapter boundary.
    NoToolCall,
}

/// Summary returned after a fixture replay completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayOutcome {
    /// Fixture id.
    pub fixture_id: String,
    /// Source fixture path.
    pub path: PathBuf,
    /// Replay mode used for this fixture.
    pub mode: ReplayMode,
    /// Number of NDJSON records loaded.
    pub records: usize,
    /// Number of adapter invocations reconstructed.
    pub invocations: usize,
    /// Number of kernel verdict records asserted.
    pub verdicts: usize,
    /// Number of lowered provider responses asserted.
    pub lowered_responses: usize,
}

/// Captured verdict record normalized into the fabric verdict type.
#[derive(Debug, Clone, PartialEq)]
pub struct CapturedVerdict {
    /// Invocation id from the capture record.
    pub invocation_id: String,
    /// Fabric verdict reconstructed from the capture.
    pub verdict: VerdictResult,
    /// Captured invocation body used for canonical JSON byte assertions.
    pub invocation: ComparableInvocation,
}

/// Tool invocation representation used for stable capture comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComparableInvocation {
    pub provider: ProviderId,
    pub tool_name: String,
    pub arguments: Value,
    pub provenance: ComparableProvenance,
}

/// Provenance representation used for stable capture comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComparableProvenance {
    pub provider: ProviderId,
    pub request_id: String,
    pub api_version: String,
    pub principal: Principal,
    pub received_at: Value,
}

/// Return the OpenAI fixture corpus path.
pub fn openai_fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/openai")
}

/// Return all OpenAI NDJSON fixture paths in deterministic order.
pub fn openai_fixture_paths() -> Result<Vec<PathBuf>, ReplayError> {
    let root = openai_fixture_dir();
    let entries = fs::read_dir(&root).map_err(|source| ReplayError::ReadFixtureDir {
        path: root.clone(),
        source,
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| ReplayError::ReadFixtureDir {
            path: root.clone(),
            source,
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("ndjson") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

/// Return the Anthropic fixture corpus path.
pub fn anthropic_fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/anthropic")
}

/// Return all Anthropic NDJSON fixture paths in deterministic order.
pub fn anthropic_fixture_paths() -> Result<Vec<PathBuf>, ReplayError> {
    let root = anthropic_fixture_dir();
    let entries = fs::read_dir(&root).map_err(|source| ReplayError::ReadFixtureDir {
        path: root.clone(),
        source,
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| ReplayError::ReadFixtureDir {
            path: root.clone(),
            source,
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("ndjson") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

/// Return the Bedrock fixture corpus path.
pub fn bedrock_fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/bedrock")
}

/// Return all Bedrock NDJSON fixture paths in deterministic order.
pub fn bedrock_fixture_paths() -> Result<Vec<PathBuf>, ReplayError> {
    let root = bedrock_fixture_dir();
    let entries = fs::read_dir(&root).map_err(|source| ReplayError::ReadFixtureDir {
        path: root.clone(),
        source,
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| ReplayError::ReadFixtureDir {
            path: root.clone(),
            source,
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("ndjson") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

/// Load an NDJSON fixture from disk.
pub fn load_fixture(path: impl AsRef<Path>) -> Result<ProviderCaptureFixture, ReplayError> {
    let path = path.as_ref().to_path_buf();
    let body = fs::read_to_string(&path).map_err(|source| ReplayError::ReadFixture {
        path: path.clone(),
        source,
    })?;
    let mut records = Vec::new();

    for (line_index, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let record = serde_json::from_str::<CaptureRecord>(line).map_err(|source| {
            ReplayError::ParseLine {
                path: path.clone(),
                line: line_index + 1,
                source,
            }
        })?;
        validate_record(&path, &record)?;
        records.push(record);
    }

    let Some(first) = records.first() else {
        return Err(invalid_fixture(
            &path,
            "fixture did not contain any records",
        ));
    };
    let fixture_id = first.fixture_id.clone();
    if records
        .iter()
        .any(|record| record.fixture_id.as_str() != fixture_id.as_str())
    {
        return Err(invalid_fixture(
            &path,
            "fixture_id changed within one NDJSON file",
        ));
    }

    Ok(ProviderCaptureFixture {
        fixture_id,
        path,
        records,
    })
}

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

/// Replay an Anthropic fixture through the Anthropic provider adapter.
#[cfg(feature = "fixtures-anthropic")]
pub fn replay_anthropic_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let fixture = load_fixture(path)?;
    fixture.ensure_anthropic()?;
    let captured = fixture.captured_verdicts()?;
    let workspace_id = fixture.anthropic_workspace_id()?;
    let adapter = anthropic_adapter(&fixture.path, workspace_id)?;

    let (mode, invocations, verdicts) = if fixture.has_anthropic_stream_tool_events() {
        let (invocations, verdicts) = replay_anthropic_stream(&fixture, &adapter, &captured)?;
        (ReplayMode::Stream, invocations, verdicts)
    } else {
        let invocations = replay_anthropic_batch(&fixture, &adapter)?;
        if captured.is_empty() && invocations.is_empty() {
            (ReplayMode::NoToolCall, Vec::new(), Vec::new())
        } else {
            let verdicts = captured.iter().map(|entry| entry.verdict.clone()).collect();
            (ReplayMode::Batch, invocations, verdicts)
        }
    };

    assert_replayed_invocations(&fixture, &captured, &invocations)?;
    assert_replayed_verdicts(&fixture, &captured, &verdicts)?;
    let lowered_responses = assert_anthropic_lowered_responses(&fixture, &adapter, &captured)?;

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

/// Stub that explains which feature is needed for Bedrock replay.
#[cfg(not(feature = "fixtures-bedrock"))]
pub fn replay_bedrock_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let path = path.as_ref();
    Err(invalid_fixture(
        path,
        "Bedrock replay requires the fixtures-bedrock feature",
    ))
}

/// Stub that explains which feature is needed for Anthropic replay.
#[cfg(not(feature = "fixtures-anthropic"))]
pub fn replay_anthropic_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let path = path.as_ref();
    Err(invalid_fixture(
        path,
        "Anthropic replay requires the fixtures-anthropic feature",
    ))
}

/// Stub that explains which feature is needed for OpenAI replay.
#[cfg(not(feature = "fixtures-openai"))]
pub fn replay_openai_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let path = path.as_ref();
    Err(invalid_fixture(
        path,
        "OpenAI replay requires the fixtures-openai feature",
    ))
}

impl ProviderCaptureFixture {
    #[cfg(feature = "fixtures-openai")]
    fn ensure_openai(&self) -> Result<(), ReplayError> {
        if self
            .records
            .iter()
            .all(|record| record.provider == "openai")
        {
            return Ok(());
        }

        Err(invalid_fixture(
            &self.path,
            "OpenAI replay received a non-openai provider record",
        ))
    }

    #[cfg(feature = "fixtures-anthropic")]
    fn ensure_anthropic(&self) -> Result<(), ReplayError> {
        if self
            .records
            .iter()
            .all(|record| record.provider == "anthropic")
        {
            return Ok(());
        }

        Err(invalid_fixture(
            &self.path,
            "Anthropic replay received a non-anthropic provider record",
        ))
    }

    #[cfg(feature = "fixtures-bedrock")]
    fn ensure_bedrock(&self) -> Result<(), ReplayError> {
        if self
            .records
            .iter()
            .all(|record| record.provider == "bedrock")
        {
            return Ok(());
        }

        Err(invalid_fixture(
            &self.path,
            "Bedrock replay received a non-bedrock provider record",
        ))
    }

    fn captured_verdicts(&self) -> Result<Vec<CapturedVerdict>, ReplayError> {
        self.records
            .iter()
            .filter(|record| record.direction == CaptureDirection::KernelVerdict)
            .map(|record| self.captured_verdict(record))
            .collect()
    }

    fn captured_verdict(&self, record: &CaptureRecord) -> Result<CapturedVerdict, ReplayError> {
        let invocation_id =
            required_field(&self.path, record.invocation_id.as_deref(), "invocation_id")?;
        let receipt_id = required_field(&self.path, record.receipt_id.as_deref(), "receipt_id")?;
        let kind = record.verdict.ok_or_else(|| {
            invalid_fixture(&self.path, "kernel_verdict record was missing verdict")
        })?;
        let invocation_value = record.payload.get("invocation").ok_or_else(|| {
            invalid_fixture(&self.path, "kernel_verdict payload was missing invocation")
        })?;
        let invocation = serde_json::from_value::<ComparableInvocation>(invocation_value.clone())?;

        if invocation.provenance.request_id != invocation_id {
            return Err(invalid_fixture(
                &self.path,
                "kernel_verdict invocation_id did not match provenance.request_id",
            ));
        }

        let verdict = match kind {
            CapturedVerdictKind::Allow => VerdictResult::Allow {
                redactions: captured_redactions(&record.payload)?,
                receipt_id: ReceiptId(receipt_id.to_string()),
            },
            CapturedVerdictKind::Deny => VerdictResult::Deny {
                reason: captured_deny_reason(&self.path, &record.payload)?,
                receipt_id: ReceiptId(receipt_id.to_string()),
            },
        };

        Ok(CapturedVerdict {
            invocation_id: invocation_id.to_string(),
            verdict,
            invocation,
        })
    }

    #[cfg(feature = "fixtures-openai")]
    fn openai_org_id(&self) -> Result<String, ReplayError> {
        self.records
            .iter()
            .filter(|record| record.direction == CaptureDirection::UpstreamRequest)
            .find_map(|record| org_id_from_payload(&record.payload))
            .ok_or_else(|| {
                invalid_fixture(
                    &self.path,
                    "OpenAI fixture did not include an organization header",
                )
            })
    }

    #[cfg(feature = "fixtures-anthropic")]
    fn anthropic_workspace_id(&self) -> Result<String, ReplayError> {
        self.records
            .iter()
            .filter(|record| record.direction == CaptureDirection::UpstreamRequest)
            .find_map(|record| anthropic_workspace_id_from_payload(&record.payload))
            .ok_or_else(|| {
                invalid_fixture(
                    &self.path,
                    "Anthropic fixture did not include a deterministic workspace header",
                )
            })
    }

    #[cfg(feature = "fixtures-bedrock")]
    fn bedrock_principal(&self) -> Result<BedrockFixturePrincipal, ReplayError> {
        self.records
            .iter()
            .filter(|record| record.direction == CaptureDirection::UpstreamRequest)
            .find_map(|record| bedrock_principal_from_payload(&record.payload))
            .ok_or_else(|| {
                invalid_fixture(
                    &self.path,
                    "Bedrock fixture did not include deterministic IAM principal headers",
                )
            })
    }

    #[cfg(feature = "fixtures-openai")]
    fn has_stream_tool_events(&self) -> bool {
        self.records.iter().any(|record| {
            if record.direction != CaptureDirection::UpstreamEvent {
                return false;
            }

            event_name(&record.payload).is_some_and(|event| {
                event == "response.function_call_arguments.delta"
                    || stream_event_item(&record.payload)
                        .and_then(|item| item.get("type"))
                        .and_then(Value::as_str)
                        == Some("function_call")
            })
        })
    }

    #[cfg(feature = "fixtures-openai")]
    fn ensure_openai_stream_verdict_chronology(&self) -> Result<(), ReplayError> {
        let mut completed_calls = BTreeSet::<String>::new();

        for record in &self.records {
            match record.direction {
                CaptureDirection::UpstreamEvent => {
                    if event_name(&record.payload) != Some("response.output_item.done") {
                        continue;
                    }
                    if let Some(call_id) = record
                        .payload
                        .get("data")
                        .and_then(|data| data.get("item"))
                        .and_then(|item| {
                            (item.get("type").and_then(Value::as_str) == Some("function_call"))
                                .then_some(item)
                        })
                        .and_then(|item| item.get("call_id"))
                        .and_then(Value::as_str)
                    {
                        completed_calls.insert(call_id.to_string());
                    }
                }
                CaptureDirection::KernelVerdict => {
                    let invocation_id = required_field(
                        &self.path,
                        record.invocation_id.as_deref(),
                        "invocation_id",
                    )?;
                    if !completed_calls.contains(invocation_id) {
                        return Err(invalid_fixture(
                            &self.path,
                            format!(
                                "OpenAI stream kernel_verdict for {invocation_id} appeared before response.output_item.done"
                            ),
                        ));
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    #[cfg(feature = "fixtures-anthropic")]
    fn has_anthropic_stream_tool_events(&self) -> bool {
        self.records.iter().any(|record| {
            if record.direction != CaptureDirection::UpstreamEvent {
                return false;
            }

            event_name(&record.payload) == Some("content_block_start")
                && record
                    .payload
                    .get("data")
                    .and_then(|data| data.get("content_block"))
                    .and_then(|block| block.get("type"))
                    .and_then(Value::as_str)
                    == Some("tool_use")
        })
    }

    #[cfg(feature = "fixtures-anthropic")]
    fn ensure_anthropic_stream_verdict_chronology(&self) -> Result<(), ReplayError> {
        let mut block_to_tool = BTreeMap::<u64, String>::new();
        let mut completed_tools = BTreeSet::<String>::new();

        for record in &self.records {
            match record.direction {
                CaptureDirection::UpstreamEvent => match event_name(&record.payload) {
                    Some("content_block_start") => {
                        let Some(index) = record
                            .payload
                            .get("data")
                            .and_then(|data| data.get("index"))
                            .and_then(Value::as_u64)
                        else {
                            continue;
                        };
                        if let Some(tool_use_id) = record
                            .payload
                            .get("data")
                            .and_then(|data| data.get("content_block"))
                            .and_then(|block| {
                                (block.get("type").and_then(Value::as_str) == Some("tool_use"))
                                    .then_some(block)
                            })
                            .and_then(|block| block.get("id"))
                            .and_then(Value::as_str)
                        {
                            block_to_tool.insert(index, tool_use_id.to_string());
                        }
                    }
                    Some("content_block_stop") => {
                        let Some(index) = record
                            .payload
                            .get("data")
                            .and_then(|data| data.get("index"))
                            .and_then(Value::as_u64)
                        else {
                            continue;
                        };
                        if let Some(tool_use_id) = block_to_tool.get(&index) {
                            completed_tools.insert(tool_use_id.clone());
                        }
                    }
                    _ => {}
                },
                CaptureDirection::KernelVerdict => {
                    let invocation_id = required_field(
                        &self.path,
                        record.invocation_id.as_deref(),
                        "invocation_id",
                    )?;
                    if !completed_tools.contains(invocation_id) {
                        return Err(invalid_fixture(
                            &self.path,
                            format!(
                                "Anthropic stream kernel_verdict for {invocation_id} appeared before content_block_stop"
                            ),
                        ));
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    #[cfg(feature = "fixtures-bedrock")]
    fn has_bedrock_stream_tool_events(&self) -> bool {
        self.records.iter().any(|record| {
            if record.direction != CaptureDirection::UpstreamEvent {
                return false;
            }

            record
                .payload
                .get("contentBlockStart")
                .and_then(|start| start.get("start"))
                .and_then(|start| start.get("toolUse"))
                .is_some()
        })
    }

    #[cfg(feature = "fixtures-bedrock")]
    fn ensure_bedrock_stream_verdict_chronology(&self) -> Result<(), ReplayError> {
        let mut block_to_tool = BTreeMap::<u64, String>::new();
        let mut completed_tools = BTreeSet::<String>::new();

        for record in &self.records {
            match record.direction {
                CaptureDirection::UpstreamEvent => {
                    if let Some(start) = record.payload.get("contentBlockStart") {
                        let Some(index) = start.get("contentBlockIndex").and_then(Value::as_u64)
                        else {
                            continue;
                        };
                        if let Some(tool_use_id) = start
                            .get("start")
                            .and_then(|start| start.get("toolUse"))
                            .and_then(|tool| tool.get("toolUseId"))
                            .and_then(Value::as_str)
                        {
                            block_to_tool.insert(index, tool_use_id.to_string());
                        }
                    }

                    if let Some(stop) = record.payload.get("contentBlockStop") {
                        let Some(index) = stop.get("contentBlockIndex").and_then(Value::as_u64)
                        else {
                            continue;
                        };
                        if let Some(tool_use_id) = block_to_tool.get(&index) {
                            completed_tools.insert(tool_use_id.clone());
                        }
                    }
                }
                CaptureDirection::KernelVerdict => {
                    let invocation_id = required_field(
                        &self.path,
                        record.invocation_id.as_deref(),
                        "invocation_id",
                    )?;
                    if !completed_tools.contains(invocation_id) {
                        return Err(invalid_fixture(
                            &self.path,
                            format!(
                                "Bedrock stream kernel_verdict for {invocation_id} appeared before contentBlockStop"
                            ),
                        ));
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn upstream_responses(&self) -> impl Iterator<Item = &CaptureRecord> {
        self.records
            .iter()
            .filter(|record| record.direction == CaptureDirection::UpstreamResponse)
    }

    #[cfg(feature = "fixtures-openai")]
    fn lowered_tool_output_requests(&self) -> Vec<&CaptureRecord> {
        self.records
            .iter()
            .filter(|record| {
                record.direction == CaptureDirection::UpstreamRequest
                    && record
                        .payload
                        .get("body")
                        .and_then(|body| body.get("tool_outputs"))
                        .is_some()
            })
            .collect()
    }

    #[cfg(feature = "fixtures-anthropic")]
    fn lowered_anthropic_tool_result_requests(&self) -> Vec<&CaptureRecord> {
        self.records
            .iter()
            .filter(|record| {
                record.direction == CaptureDirection::UpstreamRequest
                    && record
                        .payload
                        .get("body")
                        .and_then(|body| body.get("type"))
                        .and_then(Value::as_str)
                        == Some("tool_result")
            })
            .collect()
    }

    #[cfg(feature = "fixtures-bedrock")]
    fn lowered_bedrock_tool_result_requests(&self) -> Vec<&CaptureRecord> {
        self.records
            .iter()
            .filter(|record| {
                record.direction == CaptureDirection::UpstreamRequest
                    && record
                        .payload
                        .get("body")
                        .and_then(|body| body.get("toolResult"))
                        .is_some()
            })
            .collect()
    }
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

#[cfg(feature = "fixtures-anthropic")]
fn replay_anthropic_batch(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_anthropic_tools_adapter::AnthropicAdapter,
) -> Result<Vec<ToolInvocation>, ReplayError> {
    let mut invocations = Vec::new();
    for record in fixture.upstream_responses() {
        if anthropic_response_has_no_tool_uses(&record.payload) {
            continue;
        }

        let bytes = serde_json::to_vec(&record.payload)?;
        invocations.extend(adapter.lift_batch(ProviderRequest(bytes))?);
    }
    Ok(invocations)
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

#[cfg(feature = "fixtures-anthropic")]
fn replay_anthropic_stream(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_anthropic_tools_adapter::AnthropicAdapter,
    captured: &[CapturedVerdict],
) -> Result<(Vec<ToolInvocation>, Vec<VerdictResult>), ReplayError> {
    fixture.ensure_anthropic_stream_verdict_chronology()?;
    let mut verdicts_by_id = captured
        .iter()
        .map(|entry| (entry.invocation_id.clone(), entry.verdict.clone()))
        .collect::<BTreeMap<_, _>>();
    let sse = fixture_sse_bytes(fixture)?;
    let gated = adapter.gate_sse_stream(&sse, |invocation| {
        let request_id = invocation.provenance.request_id.as_str();
        verdicts_by_id.remove(request_id).ok_or_else(|| {
            ProviderError::Malformed(format!(
                "Anthropic stream replay produced unexpected invocation {request_id}"
            ))
        })
    })?;

    if let Some((request_id, _)) = verdicts_by_id.into_iter().next() {
        return Err(invalid_fixture(
            &fixture.path,
            format!("Anthropic stream replay did not produce invocation {request_id}"),
        ));
    }

    Ok((gated.invocations, gated.verdicts))
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

fn assert_replayed_invocations(
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

fn assert_replayed_verdicts(
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

fn captured_verdict_by_invocation_id(
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
fn assert_openai_lowered_responses(
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
fn assert_anthropic_lowered_responses(
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
fn assert_bedrock_lowered_responses(
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

#[cfg(feature = "fixtures-anthropic")]
fn anthropic_adapter(
    path: &Path,
    workspace_id: String,
) -> Result<chio_anthropic_tools_adapter::AnthropicAdapter, ReplayError> {
    use std::sync::Arc;

    use chio_anthropic_tools_adapter::transport::MockTransport;
    use chio_anthropic_tools_adapter::{AnthropicAdapter, AnthropicAdapterConfig};

    let config = AnthropicAdapterConfig::new(
        "anthropic-1",
        "Anthropic Messages",
        "0.1.0",
        "deadbeef",
        workspace_id,
    );
    AnthropicAdapter::new_with_manifest(
        config,
        Arc::new(MockTransport::new()),
        &anthropic_server_tool_manifest(),
    )
    .map_err(|error| {
        invalid_fixture(
            path,
            format!("Anthropic conformance manifest failed validation: {error}"),
        )
    })
}

#[cfg(feature = "fixtures-anthropic")]
fn anthropic_server_tool_manifest() -> chio_manifest::ToolManifest {
    use chio_manifest::{
        LatencyHint, ServerTool, ToolDefinition, ToolManifest, TOOL_MANIFEST_SCHEMA,
    };

    ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "anthropic-1".into(),
        name: "Anthropic Messages".to_string(),
        description: Some("Anthropic conformance replay manifest".to_string()),
        version: "0.1.0".to_string(),
        tools: vec![ToolDefinition {
            name: "regular_tool".to_string(),
            description: "Regular client-hosted conformance tool".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: Some(serde_json::json!({"type": "object"})),
            pricing: None,
            has_side_effects: false,
            latency_hint: Some(LatencyHint::Fast),
        }],
        server_tools: vec![
            ServerTool::ComputerUse,
            ServerTool::Bash,
            ServerTool::TextEditor,
        ],
        required_permissions: None,
        public_key: "deadbeef".to_string(),
    }
}

#[cfg(feature = "fixtures-anthropic")]
fn anthropic_tool_result_payload(
    path: &Path,
    expected_body: &Value,
) -> Result<Vec<u8>, ReplayError> {
    if expected_body.get("tool_use_id").is_none() {
        return Err(invalid_fixture(
            path,
            "Anthropic lowered tool_result was missing tool_use_id",
        ));
    }
    canonical_json_bytes_for("captured Anthropic tool_result envelope", expected_body)
        .map_err(ReplayError::from)
}

#[cfg(feature = "fixtures-bedrock")]
#[derive(Debug, Clone)]
struct BedrockFixturePrincipal {
    caller_arn: String,
    account_id: String,
    assumed_role_session_arn: Option<String>,
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
fn bedrock_tool_result_payload(path: &Path, expected_body: &Value) -> Result<Vec<u8>, ReplayError> {
    let tool_result = expected_body
        .get("toolResult")
        .ok_or_else(|| invalid_fixture(path, "Bedrock lowered body was missing toolResult"))?;
    canonical_json_bytes_for("captured Bedrock toolResult", tool_result).map_err(ReplayError::from)
}

fn validate_record(path: &Path, record: &CaptureRecord) -> Result<(), ReplayError> {
    if record.schema != CAPTURE_SCHEMA {
        return Err(invalid_fixture(
            path,
            format!("unsupported capture schema {}", record.schema),
        ));
    }

    if record.provider.is_empty() {
        return Err(invalid_fixture(path, "provider was empty"));
    }

    Ok(())
}

fn comparable_invocation(
    invocation: &ToolInvocation,
    received_at: Value,
) -> Result<ComparableInvocation, ReplayError> {
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

fn captured_redactions(payload: &Value) -> Result<Vec<Redaction>, ReplayError> {
    let Some(redactions) = payload.get("redactions") else {
        return Ok(Vec::new());
    };
    serde_json::from_value(redactions.clone()).map_err(ReplayError::from)
}

fn captured_deny_reason(path: &Path, payload: &Value) -> Result<DenyReason, ReplayError> {
    let reason = payload
        .get("reason")
        .ok_or_else(|| invalid_fixture(path, "deny kernel_verdict payload was missing reason"))?;
    serde_json::from_value(reason.clone()).map_err(ReplayError::from)
}

#[cfg(feature = "fixtures-bedrock")]
fn bedrock_response_has_no_tool_uses(payload: &Value) -> bool {
    !bedrock_content_blocks(payload).iter().any(|block| {
        block
            .get("toolUse")
            .or_else(|| {
                if block.get("toolUseId").is_some() && block.get("name").is_some() {
                    Some(block)
                } else {
                    None
                }
            })
            .is_some()
    })
}

#[cfg(feature = "fixtures-bedrock")]
fn bedrock_content_blocks(value: &Value) -> Vec<&Value> {
    if let Some(values) = value.as_array() {
        return values.iter().collect();
    }
    let Some(map) = value.as_object() else {
        return Vec::new();
    };
    if map.contains_key("toolUse") {
        return vec![value];
    }
    if let Some(content) = map.get("content").and_then(Value::as_array) {
        return content.iter().collect();
    }
    if let Some(content) = map
        .get("output")
        .and_then(|output| output.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(Value::as_array)
    {
        return content.iter().collect();
    }
    if let Some(content) = map
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(Value::as_array)
    {
        return content.iter().collect();
    }
    Vec::new()
}

#[cfg(feature = "fixtures-openai")]
fn response_has_no_tool_calls(payload: &Value) -> bool {
    let output = payload.get("output").and_then(Value::as_array);
    let Some(output) = output else {
        return true;
    };

    !output.iter().any(|item| {
        item.get("type")
            .and_then(Value::as_str)
            .is_some_and(|value| value == "function_call")
    })
}

#[cfg(feature = "fixtures-anthropic")]
fn anthropic_response_has_no_tool_uses(payload: &Value) -> bool {
    let body = anthropic_message_body(payload);
    let content = body.get("content").and_then(Value::as_array);
    let Some(content) = content else {
        return true;
    };

    !content.iter().any(|item| {
        item.get("type")
            .and_then(Value::as_str)
            .is_some_and(|value| value == "tool_use")
    })
}

#[cfg(feature = "fixtures-anthropic")]
fn anthropic_message_body(payload: &Value) -> &Value {
    ["body", "response", "payload", "message"]
        .iter()
        .find_map(|field| payload.get(field).filter(|value| value.is_object()))
        .unwrap_or(payload)
}

#[cfg(any(feature = "fixtures-openai", feature = "fixtures-anthropic"))]
fn fixture_sse_bytes(fixture: &ProviderCaptureFixture) -> Result<Vec<u8>, ReplayError> {
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

#[cfg(any(feature = "fixtures-openai", feature = "fixtures-anthropic"))]
fn event_name(payload: &Value) -> Option<&str> {
    payload.get("event").and_then(Value::as_str)
}

#[cfg(feature = "fixtures-openai")]
fn stream_event_item(payload: &Value) -> Option<&Value> {
    payload
        .get("data")
        .and_then(|data| data.get("item"))
        .or_else(|| payload.get("data").and_then(|data| data.get("output_item")))
}

#[cfg(feature = "fixtures-openai")]
fn org_id_from_payload(payload: &Value) -> Option<String> {
    let headers = payload.get("headers")?.as_object()?;
    headers.iter().find_map(|(key, value)| {
        if is_openai_org_header(key) {
            header_value(value)
        } else {
            None
        }
    })
}

#[cfg(feature = "fixtures-anthropic")]
fn anthropic_workspace_id_from_payload(payload: &Value) -> Option<String> {
    let headers = payload.get("headers")?.as_object()?;
    headers.iter().find_map(|(key, value)| {
        if is_anthropic_workspace_header(key) {
            header_value(value)
        } else {
            None
        }
    })
}

#[cfg(feature = "fixtures-bedrock")]
fn bedrock_principal_from_payload(payload: &Value) -> Option<BedrockFixturePrincipal> {
    let headers = payload.get("headers")?.as_object()?;
    let caller_arn = headers.iter().find_map(|(key, value)| {
        if key.eq_ignore_ascii_case("x-chio-bedrock-caller-arn") {
            header_value(value)
        } else {
            None
        }
    })?;
    let account_id = headers.iter().find_map(|(key, value)| {
        if key.eq_ignore_ascii_case("x-chio-bedrock-account-id") {
            header_value(value)
        } else {
            None
        }
    })?;
    let assumed_role_session_arn = headers.iter().find_map(|(key, value)| {
        if key.eq_ignore_ascii_case("x-chio-bedrock-assumed-role-session-arn") {
            header_value(value)
        } else {
            None
        }
    });

    Some(BedrockFixturePrincipal {
        caller_arn,
        account_id,
        assumed_role_session_arn,
    })
}

#[cfg(feature = "fixtures-anthropic")]
fn is_anthropic_workspace_header(key: &str) -> bool {
    key.eq_ignore_ascii_case("x-chio-anthropic-workspace-id")
        || key.eq_ignore_ascii_case("anthropic-workspace-id")
}

#[cfg(feature = "fixtures-openai")]
fn is_openai_org_header(key: &str) -> bool {
    key.eq_ignore_ascii_case("openai-organization")
        || key.eq_ignore_ascii_case("openai-org-id")
        || key.eq_ignore_ascii_case("x-openai-organization")
}

#[cfg(any(
    feature = "fixtures-openai",
    feature = "fixtures-anthropic",
    feature = "fixtures-bedrock"
))]
fn header_value(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => non_empty(value),
        Value::Array(values) => values.iter().find_map(header_value),
        _ => None,
    }
}

#[cfg(any(
    feature = "fixtures-openai",
    feature = "fixtures-anthropic",
    feature = "fixtures-bedrock"
))]
fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(feature = "fixtures-bedrock")]
fn fixture_bedrock_stream_bytes(fixture: &ProviderCaptureFixture) -> Result<Vec<u8>, ReplayError> {
    let events = fixture
        .records
        .iter()
        .filter(|record| record.direction == CaptureDirection::UpstreamEvent)
        .map(|record| record.payload.clone())
        .collect::<Vec<_>>();

    serde_json::to_vec(&events).map_err(ReplayError::from)
}

fn required_field<'a>(
    path: &Path,
    value: Option<&'a str>,
    field: &str,
) -> Result<&'a str, ReplayError> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_fixture(path, format!("record was missing {field}")))
}

fn invalid_fixture(path: impl AsRef<Path>, message: impl Into<String>) -> ReplayError {
    ReplayError::InvalidFixture {
        path: path.as_ref().to_path_buf(),
        message: message.into(),
    }
}

fn futures_lite_block_on<F>(future: F) -> F::Output
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
