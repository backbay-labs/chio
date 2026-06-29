use super::*;

#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("read fixture {path:?}: {source}")]
    ReadFixture {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("read fixture directory {path:?}: {source}")]
    ReadFixtureDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse fixture {path:?} line {line}: {source}")]
    ParseLine {
        path: PathBuf,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid fixture {path:?}: {message}")]
    InvalidFixture { path: PathBuf, message: String },
    #[error(transparent)]
    Assertion(#[from] AssertionError),
    #[error(transparent)]
    Provider(#[from] ProviderError),
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
    pub(super) records: Vec<CaptureRecord>,
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
    fixture_paths_for_dir(openai_fixture_dir())
}

/// Return the Anthropic fixture corpus path.
pub fn anthropic_fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/anthropic")
}

/// Return all Anthropic NDJSON fixture paths in deterministic order.
pub fn anthropic_fixture_paths() -> Result<Vec<PathBuf>, ReplayError> {
    fixture_paths_for_dir(anthropic_fixture_dir())
}

/// Return the Bedrock fixture corpus path.
pub fn bedrock_fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/bedrock")
}

/// Return all Bedrock NDJSON fixture paths in deterministic order.
pub fn bedrock_fixture_paths() -> Result<Vec<PathBuf>, ReplayError> {
    fixture_paths_for_dir(bedrock_fixture_dir())
}

/// Return the Gemini fixture corpus path.
pub fn gemini_fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/gemini")
}

/// Return all Gemini NDJSON fixture paths in deterministic order.
pub fn gemini_fixture_paths() -> Result<Vec<PathBuf>, ReplayError> {
    fixture_paths_for_dir(gemini_fixture_dir())
}

/// Return the Mistral fixture corpus path.
pub fn mistral_fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/mistral")
}

/// Return all Mistral NDJSON fixture paths in deterministic order.
pub fn mistral_fixture_paths() -> Result<Vec<PathBuf>, ReplayError> {
    fixture_paths_for_dir(mistral_fixture_dir())
}

/// Return the Groq fixture corpus path.
pub fn groq_fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/groq")
}

/// Return all Groq NDJSON fixture paths in deterministic order.
pub fn groq_fixture_paths() -> Result<Vec<PathBuf>, ReplayError> {
    fixture_paths_for_dir(groq_fixture_dir())
}

/// Return the Ollama fixture corpus path.
pub fn ollama_fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/ollama")
}

/// Return all Ollama NDJSON fixture paths in deterministic order.
pub fn ollama_fixture_paths() -> Result<Vec<PathBuf>, ReplayError> {
    fixture_paths_for_dir(ollama_fixture_dir())
}

/// Return the Cohere fixture corpus path.
pub fn cohere_fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/cohere")
}

/// Return all Cohere NDJSON fixture paths in deterministic order.
pub fn cohere_fixture_paths() -> Result<Vec<PathBuf>, ReplayError> {
    fixture_paths_for_dir(cohere_fixture_dir())
}

pub(super) fn fixture_paths_for_dir(root: PathBuf) -> Result<Vec<PathBuf>, ReplayError> {
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
    validate_fixture_id_matches_filename(&path, &fixture_id)?;

    let provider = first.provider.clone();
    if records
        .iter()
        .any(|record| record.provider.as_str() != provider.as_str())
    {
        return Err(invalid_fixture(
            &path,
            "provider changed within one NDJSON file",
        ));
    }

    Ok(ProviderCaptureFixture {
        fixture_id,
        path,
        records,
    })
}

impl ProviderCaptureFixture {
    #[cfg(feature = "fixtures-openai")]
    pub(super) fn ensure_openai(&self) -> Result<(), ReplayError> {
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
    pub(super) fn ensure_anthropic(&self) -> Result<(), ReplayError> {
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
    pub(super) fn ensure_bedrock(&self) -> Result<(), ReplayError> {
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

    #[cfg(feature = "fixtures-gemini")]
    pub(super) fn ensure_gemini(&self) -> Result<(), ReplayError> {
        if self
            .records
            .iter()
            .all(|record| record.provider == "gemini")
        {
            return Ok(());
        }

        Err(invalid_fixture(
            &self.path,
            "Gemini replay received a non-gemini provider record",
        ))
    }

    #[cfg(feature = "fixtures-mistral")]
    pub(super) fn ensure_mistral(&self) -> Result<(), ReplayError> {
        if self
            .records
            .iter()
            .all(|record| record.provider == "mistral")
        {
            return Ok(());
        }

        Err(invalid_fixture(
            &self.path,
            "Mistral replay received a non-mistral provider record",
        ))
    }

    #[cfg(feature = "fixtures-groq")]
    pub(super) fn ensure_groq(&self) -> Result<(), ReplayError> {
        if self.records.iter().all(|record| record.provider == "groq") {
            return Ok(());
        }

        Err(invalid_fixture(
            &self.path,
            "Groq replay received a non-groq provider record",
        ))
    }

    #[cfg(feature = "fixtures-ollama")]
    pub(super) fn ensure_ollama(&self) -> Result<(), ReplayError> {
        if self
            .records
            .iter()
            .all(|record| record.provider == "ollama")
        {
            return Ok(());
        }

        Err(invalid_fixture(
            &self.path,
            "Ollama replay received a non-ollama provider record",
        ))
    }

    #[cfg(feature = "fixtures-cohere")]
    pub(super) fn ensure_cohere(&self) -> Result<(), ReplayError> {
        if self
            .records
            .iter()
            .all(|record| record.provider == "cohere")
        {
            return Ok(());
        }

        Err(invalid_fixture(
            &self.path,
            "Cohere replay received a non-cohere provider record",
        ))
    }

    pub(super) fn captured_verdicts(&self) -> Result<Vec<CapturedVerdict>, ReplayError> {
        self.records
            .iter()
            .filter(|record| record.direction == CaptureDirection::KernelVerdict)
            .map(|record| self.captured_verdict(record))
            .collect()
    }

    pub(super) fn captured_verdict(
        &self,
        record: &CaptureRecord,
    ) -> Result<CapturedVerdict, ReplayError> {
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
    pub(super) fn openai_org_id(&self) -> Result<String, ReplayError> {
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
    pub(super) fn anthropic_workspace_id(&self) -> Result<String, ReplayError> {
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
    pub(super) fn bedrock_principal(&self) -> Result<BedrockFixturePrincipal, ReplayError> {
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

    #[cfg(feature = "fixtures-gemini")]
    pub(super) fn gemini_project_id(&self) -> Result<String, ReplayError> {
        self.header_from_upstream_request("x-chio-gemini-project-id")
            .ok_or_else(|| {
                invalid_fixture(
                    &self.path,
                    "Gemini fixture did not include a deterministic project header",
                )
            })
    }

    #[cfg(feature = "fixtures-mistral")]
    pub(super) fn mistral_project_id(&self) -> Result<String, ReplayError> {
        self.header_from_upstream_request("x-chio-mistral-org-id")
            .ok_or_else(|| {
                invalid_fixture(
                    &self.path,
                    "Mistral fixture did not include a deterministic project header",
                )
            })
    }

    #[cfg(feature = "fixtures-groq")]
    pub(super) fn groq_project_id(&self) -> Result<String, ReplayError> {
        self.header_from_upstream_request("x-chio-groq-org-id")
            .ok_or_else(|| {
                invalid_fixture(
                    &self.path,
                    "Groq fixture did not include a deterministic project header",
                )
            })
    }

    #[cfg(feature = "fixtures-ollama")]
    pub(super) fn ollama_host(&self) -> Result<String, ReplayError> {
        self.header_from_upstream_request("x-chio-ollama-org-id")
            .ok_or_else(|| {
                invalid_fixture(
                    &self.path,
                    "Ollama fixture did not include a deterministic host header",
                )
            })
    }

    #[cfg(feature = "fixtures-cohere")]
    pub(super) fn cohere_org_id(&self) -> Result<String, ReplayError> {
        self.header_from_upstream_request("x-chio-cohere-org-id")
            .ok_or_else(|| {
                invalid_fixture(
                    &self.path,
                    "Cohere fixture did not include a deterministic organization header",
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
    pub(super) fn header_from_upstream_request(&self, header_name: &str) -> Option<String> {
        self.records
            .iter()
            .filter(|record| record.direction == CaptureDirection::UpstreamRequest)
            .find_map(|record| header_from_payload(&record.payload, header_name))
    }

    #[cfg(feature = "fixtures-openai")]
    pub(super) fn has_stream_tool_events(&self) -> bool {
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
    pub(super) fn ensure_openai_stream_verdict_chronology(&self) -> Result<(), ReplayError> {
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
    pub(super) fn has_anthropic_stream_tool_events(&self) -> bool {
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
    pub(super) fn ensure_anthropic_stream_verdict_chronology(&self) -> Result<(), ReplayError> {
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
    pub(super) fn has_bedrock_stream_tool_events(&self) -> bool {
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
    pub(super) fn ensure_bedrock_stream_verdict_chronology(&self) -> Result<(), ReplayError> {
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

    #[cfg(feature = "fixtures-ollama")]
    pub(super) fn has_ollama_stream_tool_events(&self) -> bool {
        self.records.iter().any(|record| {
            if record.direction != CaptureDirection::UpstreamEvent {
                return false;
            }

            record
                .payload
                .get("data")
                .and_then(|data| data.get("message"))
                .and_then(|message| message.get("tool_calls"))
                .and_then(Value::as_array)
                .is_some_and(|calls| !calls.is_empty())
        })
    }

    #[cfg(feature = "fixtures-cohere")]
    pub(super) fn has_cohere_stream_tool_events(&self) -> bool {
        self.records.iter().any(|record| {
            if record.direction != CaptureDirection::UpstreamEvent {
                return false;
            }

            event_name(&record.payload) == Some("tool-call-end")
        })
    }

    pub(super) fn upstream_responses(&self) -> impl Iterator<Item = &CaptureRecord> {
        self.records
            .iter()
            .filter(|record| record.direction == CaptureDirection::UpstreamResponse)
    }

    #[cfg(feature = "fixtures-openai")]
    pub(super) fn lowered_tool_output_requests(&self) -> Vec<&CaptureRecord> {
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
    pub(super) fn lowered_anthropic_tool_result_requests(&self) -> Vec<&CaptureRecord> {
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
    pub(super) fn lowered_bedrock_tool_result_requests(&self) -> Vec<&CaptureRecord> {
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

fn validate_record(path: &Path, record: &CaptureRecord) -> Result<(), ReplayError> {
    if record.schema != CAPTURE_SCHEMA {
        return Err(invalid_fixture(
            path,
            format!("unsupported capture schema {}", record.schema),
        ));
    }

    validate_record_identifier(path, &record.provider, "provider")?;
    validate_record_identifier(path, &record.fixture_id, "fixture_id")?;

    Ok(())
}

fn validate_fixture_id_matches_filename(path: &Path, fixture_id: &str) -> Result<(), ReplayError> {
    let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return Err(invalid_fixture(
            path,
            "fixture filename was not valid UTF-8",
        ));
    };
    if fixture_id != stem {
        return Err(invalid_fixture(path, "fixture_id did not match filename"));
    }
    Ok(())
}

fn validate_record_identifier(path: &Path, value: &str, field: &str) -> Result<(), ReplayError> {
    if value.trim().is_empty() {
        return Err(invalid_fixture(path, format!("{field} was empty")));
    }
    if value.trim() != value {
        return Err(invalid_fixture(
            path,
            format!("{field} had surrounding whitespace"),
        ));
    }
    Ok(())
}

pub(super) fn required_field<'a>(
    path: &Path,
    value: Option<&'a str>,
    field: &str,
) -> Result<&'a str, ReplayError> {
    let value =
        value.ok_or_else(|| invalid_fixture(path, format!("record was missing {field}")))?;
    if value.trim().is_empty() {
        return Err(invalid_fixture(path, format!("record was missing {field}")));
    }
    if value.trim() != value {
        return Err(invalid_fixture(
            path,
            format!("{field} had surrounding whitespace"),
        ));
    }
    Ok(value)
}

pub(super) fn invalid_fixture(path: impl AsRef<Path>, message: impl Into<String>) -> ReplayError {
    ReplayError::InvalidFixture {
        path: path.as_ref().to_path_buf(),
        message: message.into(),
    }
}
