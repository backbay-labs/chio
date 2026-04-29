use std::env;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use chio_provider_conformance::{
    canonical_json_bytes_for, provider_fixture_path, CaptureDirection, CaptureRecord,
    CapturedVerdictKind, CAPTURE_SCHEMA,
};
use chio_tool_call_fabric::{
    Principal, ProvenanceStamp, ProviderId, ReceiptId, ToolInvocation, VerdictResult,
};
use chrono::{SecondsFormat, Utc};
use clap::{Parser, ValueEnum};
use serde_json::{json, Map, Value};
use thiserror::Error;

const OPENAI_RESPONSES_URL: &str = "https://api.openai.com/v1/responses";
const ANTHROPIC_MESSAGES_URL: &str = "https://api.anthropic.com/v1/messages";
const BEDROCK_REGION: &str = "us-east-1";

#[derive(Debug, Parser)]
#[command(
    name = "record",
    about = "Re-record Chio provider conformance fixtures"
)]
struct Cli {
    /// Provider fixture corpus to re-record.
    #[arg(long, value_enum)]
    provider: ProviderArg,

    /// Scenario id, without the `.ndjson` suffix.
    #[arg(long)]
    scenario: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ProviderArg {
    #[value(name = "openai")]
    OpenAi,
    Anthropic,
    Bedrock,
}

impl ProviderArg {
    fn fixture_provider(self) -> &'static str {
        match self {
            ProviderArg::OpenAi => "openai",
            ProviderArg::Anthropic => "anthropic",
            ProviderArg::Bedrock => "bedrock",
        }
    }
}

#[derive(Debug)]
struct ScenarioSeed {
    provider: ProviderArg,
    scenario: String,
    path: PathBuf,
    records: Vec<CaptureRecord>,
    initial_request: CaptureRecord,
    lowered_templates: Vec<CaptureRecord>,
    expected_invocations: usize,
}

#[derive(Debug)]
struct CapturedInvocation {
    invocation: ToolInvocation,
    verdict: VerdictResult,
    receipt_id: String,
    received_at: String,
}

#[derive(Debug)]
struct RecordPlan {
    seed: ScenarioSeed,
    request_record: CaptureRecord,
    response_records: Vec<CaptureRecord>,
    invocations: Vec<CapturedInvocation>,
}

#[derive(Debug)]
enum Credentials {
    OpenAi {
        api_key: String,
        org_id: String,
    },
    Anthropic {
        api_key: String,
        workspace_id: String,
    },
    Bedrock {
        profile: Option<String>,
        caller_arn: String,
        account_id: String,
        assumed_role_session_arn: Option<String>,
    },
}

#[derive(Debug, Error)]
enum RecordError {
    #[error("invalid scenario id `{0}`: use the fixture id without path separators")]
    InvalidScenario(String),
    #[error("scenario fixture does not exist: {path}")]
    ScenarioNotFound { path: PathBuf },
    #[error("read fixture {path}: {source}")]
    ReadFixture {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("create fixture directory {path}: {source}")]
    CreateFixtureDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("write fixture {path}: {source}")]
    WriteFixture {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("replace fixture {path}: {source}")]
    ReplaceFixture {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse fixture {path} line {line}: {source}")]
    ParseFixtureLine {
        path: PathBuf,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid fixture {path}: {message}")]
    InvalidFixture { path: PathBuf, message: String },
    #[error("missing environment for {provider}: set {vars}")]
    MissingEnv {
        provider: &'static str,
        vars: &'static str,
    },
    #[error("{provider} curl request failed: {message}")]
    Curl {
        provider: &'static str,
        message: String,
    },
    #[error("{provider} captured payload did not contain expected tool invocations: {message}")]
    CaptureShape {
        provider: &'static str,
        message: String,
    },
    #[error("JSON error while recording fixture: {0}")]
    Json(#[from] serde_json::Error),
    #[error("bedrock AWS CLI command failed: {message}")]
    AwsCli { message: String },
    #[error("bedrock streaming re-record requires a Bedrock SDK event-stream capture path; use a non-streaming scenario for this CLI revision")]
    BedrockStreamUnsupported,
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), RecordError> {
    let seed = load_seed(cli.provider, &cli.scenario)?;
    let credentials = credentials_for(cli.provider)?;
    let plan = match (&credentials, cli.provider) {
        (Credentials::OpenAi { api_key, org_id }, ProviderArg::OpenAi) => {
            record_openai(seed, api_key, org_id)?
        }
        (
            Credentials::Anthropic {
                api_key,
                workspace_id,
            },
            ProviderArg::Anthropic,
        ) => record_anthropic(seed, api_key, workspace_id)?,
        (
            Credentials::Bedrock {
                profile,
                caller_arn,
                account_id,
                assumed_role_session_arn,
            },
            ProviderArg::Bedrock,
        ) => record_bedrock(
            seed,
            profile.as_deref(),
            caller_arn,
            account_id,
            assumed_role_session_arn.as_deref(),
        )?,
        _ => {
            return Err(RecordError::InvalidFixture {
                path: seed.path,
                message: "provider credentials did not match requested provider".to_string(),
            });
        }
    };

    let records = assemble_records(plan)?;
    write_records_atomic(&records)?;
    println!(
        "recorded {} records to {}",
        records.records.len(),
        records.path.display()
    );
    Ok(())
}

fn load_seed(provider: ProviderArg, scenario: &str) -> Result<ScenarioSeed, RecordError> {
    validate_scenario_id(scenario)?;
    let path = provider_fixture_path(provider.fixture_provider(), scenario);
    if !path.exists() {
        return Err(RecordError::ScenarioNotFound { path });
    }

    let body = fs::read_to_string(&path).map_err(|source| RecordError::ReadFixture {
        path: path.clone(),
        source,
    })?;
    let mut records = Vec::new();
    for (line_index, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record = serde_json::from_str::<CaptureRecord>(line).map_err(|source| {
            RecordError::ParseFixtureLine {
                path: path.clone(),
                line: line_index + 1,
                source,
            }
        })?;
        validate_record(&path, provider, scenario, &record)?;
        records.push(record);
    }
    if records.is_empty() {
        return Err(invalid_fixture(
            &path,
            "fixture did not contain any records",
        ));
    }

    let initial_request = records
        .iter()
        .find(|record| {
            record.direction == CaptureDirection::UpstreamRequest
                && record
                    .payload
                    .get("capture_mode")
                    .and_then(Value::as_str)
                    .is_some()
        })
        .cloned()
        .ok_or_else(|| {
            invalid_fixture(&path, "fixture did not include an initial upstream request")
        })?;

    let lowered_templates = records
        .iter()
        .filter(|record| {
            record.direction == CaptureDirection::UpstreamRequest
                && record
                    .payload
                    .get("capture_mode")
                    .and_then(Value::as_str)
                    .is_none()
        })
        .cloned()
        .collect::<Vec<_>>();
    let expected_invocations = records
        .iter()
        .filter(|record| record.direction == CaptureDirection::KernelVerdict)
        .count();

    Ok(ScenarioSeed {
        provider,
        scenario: scenario.to_string(),
        path,
        records,
        initial_request,
        lowered_templates,
        expected_invocations,
    })
}

fn validate_scenario_id(scenario: &str) -> Result<(), RecordError> {
    let valid = !scenario.is_empty()
        && scenario
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-');
    if valid {
        Ok(())
    } else {
        Err(RecordError::InvalidScenario(scenario.to_string()))
    }
}

fn validate_record(
    path: &Path,
    provider: ProviderArg,
    scenario: &str,
    record: &CaptureRecord,
) -> Result<(), RecordError> {
    if record.schema != CAPTURE_SCHEMA {
        return Err(invalid_fixture(
            path,
            format!("unsupported capture schema {}", record.schema),
        ));
    }
    if record.provider != provider.fixture_provider() {
        return Err(invalid_fixture(
            path,
            format!(
                "record provider `{}` did not match `{}`",
                record.provider,
                provider.fixture_provider()
            ),
        ));
    }
    if record.fixture_id != scenario {
        return Err(invalid_fixture(
            path,
            format!(
                "record fixture_id `{}` did not match `{scenario}`",
                record.fixture_id
            ),
        ));
    }
    Ok(())
}

fn credentials_for(provider: ProviderArg) -> Result<Credentials, RecordError> {
    match provider {
        ProviderArg::OpenAi => {
            let api_key = required_env("OPENAI_API_KEY").ok_or(RecordError::MissingEnv {
                provider: "openai",
                vars: "OPENAI_API_KEY and OPENAI_ORGANIZATION",
            })?;
            let org_id = required_env("OPENAI_ORGANIZATION").ok_or(RecordError::MissingEnv {
                provider: "openai",
                vars: "OPENAI_API_KEY and OPENAI_ORGANIZATION",
            })?;
            Ok(Credentials::OpenAi { api_key, org_id })
        }
        ProviderArg::Anthropic => {
            let api_key = required_env("ANTHROPIC_API_KEY").ok_or(RecordError::MissingEnv {
                provider: "anthropic",
                vars: "ANTHROPIC_API_KEY and CHIO_ANTHROPIC_WORKSPACE_ID",
            })?;
            let workspace_id =
                required_env("CHIO_ANTHROPIC_WORKSPACE_ID").ok_or(RecordError::MissingEnv {
                    provider: "anthropic",
                    vars: "ANTHROPIC_API_KEY and CHIO_ANTHROPIC_WORKSPACE_ID",
                })?;
            Ok(Credentials::Anthropic {
                api_key,
                workspace_id,
            })
        }
        ProviderArg::Bedrock => {
            let profile = required_env("AWS_PROFILE");
            let has_static_credentials = required_env("AWS_ACCESS_KEY_ID").is_some()
                && required_env("AWS_SECRET_ACCESS_KEY").is_some();
            if profile.is_none() && !has_static_credentials {
                return Err(RecordError::MissingEnv {
                    provider: "bedrock",
                    vars: "AWS_PROFILE or AWS_ACCESS_KEY_ID plus AWS_SECRET_ACCESS_KEY",
                });
            }
            let identity = bedrock_caller_identity(profile.as_deref())?;
            Ok(Credentials::Bedrock {
                profile,
                caller_arn: identity.caller_arn,
                account_id: identity.account_id,
                assumed_role_session_arn: identity.assumed_role_session_arn,
            })
        }
    }
}

fn required_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn curl_json_post(
    provider: &'static str,
    url: &str,
    headers: &[(&str, String)],
    body: &Value,
) -> Result<String, RecordError> {
    let input_path =
        env::temp_dir().join(format!("chio-{provider}-{}.json", sanitize_id(&now_ts())));
    fs::write(&input_path, serde_json::to_vec(body)?).map_err(|source| {
        RecordError::WriteFixture {
            path: input_path.clone(),
            source,
        }
    })?;

    let mut command = Command::new("curl");
    command.args([
        "--silent",
        "--show-error",
        "--fail-with-body",
        "--location",
        "--request",
        "POST",
        "--header",
        "Content-Type: application/json",
    ]);
    for (name, value) in headers {
        command.args(["--header", &format!("{name}: {value}")]);
    }
    command.args(["--data-binary", &format!("@{}", input_path.display()), url]);

    let output = command.output().map_err(|source| RecordError::Curl {
        provider,
        message: format!("failed to run curl: {source}"),
    })?;
    let _ = fs::remove_file(&input_path);
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let message = if stdout.is_empty() {
            stderr
        } else if stderr.is_empty() {
            stdout
        } else {
            format!("{stderr}\n{stdout}")
        };
        return Err(RecordError::Curl { provider, message });
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn record_openai(
    seed: ScenarioSeed,
    api_key: &str,
    org_id: &str,
) -> Result<RecordPlan, RecordError> {
    let mut request_record = live_request_record(&seed);
    stamp_openai_headers(&mut request_record, org_id)?;
    let request_body = request_body(&request_record)?;
    let stream = request_body
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let response_text = curl_json_post(
        "openai",
        OPENAI_RESPONSES_URL,
        &[
            ("Authorization", format!("Bearer {api_key}")),
            ("OpenAI-Organization", org_id.to_string()),
        ],
        &request_body,
    )?;
    if stream {
        let response_records = sse_records(&seed, &response_text)?;
        let invocations = openai_stream_invocations(&seed, org_id, &response_records)?;
        Ok(RecordPlan {
            seed,
            request_record,
            response_records,
            invocations,
        })
    } else {
        let response_payload = serde_json::from_str::<Value>(&response_text)?;
        let response_record =
            capture_record(&seed, CaptureDirection::UpstreamResponse, response_payload);
        let invocations = openai_batch_invocations(&seed, org_id, &response_record.payload)?;
        Ok(RecordPlan {
            seed,
            request_record,
            response_records: vec![response_record],
            invocations,
        })
    }
}

fn record_anthropic(
    seed: ScenarioSeed,
    api_key: &str,
    workspace_id: &str,
) -> Result<RecordPlan, RecordError> {
    let mut request_record = live_request_record(&seed);
    stamp_anthropic_headers(&mut request_record, workspace_id)?;
    let request_body = request_body(&request_record)?;
    let stream = request_body
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let response_text = curl_json_post(
        "anthropic",
        ANTHROPIC_MESSAGES_URL,
        &[
            ("x-api-key", api_key.to_string()),
            ("anthropic-version", anthropic_version(&request_record)?),
        ],
        &request_body,
    )?;
    if stream {
        let response_records = sse_records(&seed, &response_text)?;
        let invocations = anthropic_stream_invocations(&seed, workspace_id, &response_records)?;
        Ok(RecordPlan {
            seed,
            request_record,
            response_records,
            invocations,
        })
    } else {
        let response_payload = serde_json::from_str::<Value>(&response_text)?;
        let response_record =
            capture_record(&seed, CaptureDirection::UpstreamResponse, response_payload);
        let invocations =
            anthropic_batch_invocations(&seed, workspace_id, &response_record.payload)?;
        Ok(RecordPlan {
            seed,
            request_record,
            response_records: vec![response_record],
            invocations,
        })
    }
}

fn record_bedrock(
    seed: ScenarioSeed,
    profile: Option<&str>,
    caller_arn: &str,
    account_id: &str,
    assumed_role_session_arn: Option<&str>,
) -> Result<RecordPlan, RecordError> {
    let mut request_record = live_request_record(&seed);
    stamp_bedrock_headers(
        &mut request_record,
        caller_arn,
        account_id,
        assumed_role_session_arn,
    )?;
    let request_body = request_body(&request_record)?;
    let stream = request_record
        .payload
        .get("method")
        .and_then(Value::as_str)
        .is_some_and(|method| method == "ConverseStream")
        || request_body
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    if stream {
        return Err(RecordError::BedrockStreamUnsupported);
    }

    let response_payload = bedrock_converse(profile, &request_body)?;
    let mut response_record =
        capture_record(&seed, CaptureDirection::UpstreamResponse, response_payload);
    if let Some(tool_config) = request_body.get("toolConfig") {
        insert_payload_field(
            &mut response_record.payload,
            "toolConfig",
            tool_config.clone(),
        )?;
    }

    let invocations = bedrock_batch_invocations(
        &seed,
        caller_arn,
        account_id,
        assumed_role_session_arn,
        &response_record.payload,
    )?;
    Ok(RecordPlan {
        seed,
        request_record,
        response_records: vec![response_record],
        invocations,
    })
}

fn openai_batch_invocations(
    seed: &ScenarioSeed,
    org_id: &str,
    payload: &Value,
) -> Result<Vec<CapturedInvocation>, RecordError> {
    let invocations = extract_openai_invocations(seed, org_id, payload)?;
    if invocations.is_empty() && seed.expected_invocations > 0 {
        return Err(RecordError::CaptureShape {
            provider: "openai",
            message: "response did not include function_call outputs".to_string(),
        });
    }
    Ok(captured_invocations(seed, invocations))
}

fn openai_stream_invocations(
    seed: &ScenarioSeed,
    org_id: &str,
    records: &[CaptureRecord],
) -> Result<Vec<CapturedInvocation>, RecordError> {
    let mut invocations = Vec::new();
    for record in records {
        if let Some(invocation) = openai_invocation_from_stream_record(seed, org_id, record)? {
            invocations.push(invocation);
        }
    }
    if invocations.is_empty() && seed.expected_invocations > 0 {
        return Err(RecordError::CaptureShape {
            provider: "openai",
            message: "stream did not include completed function_call items".to_string(),
        });
    }
    Ok(captured_invocations(seed, invocations))
}

fn anthropic_batch_invocations(
    seed: &ScenarioSeed,
    workspace_id: &str,
    payload: &Value,
) -> Result<Vec<CapturedInvocation>, RecordError> {
    let invocations = extract_anthropic_invocations(seed, workspace_id, payload)?;
    if invocations.is_empty() && seed.expected_invocations > 0 {
        return Err(RecordError::CaptureShape {
            provider: "anthropic",
            message: "response did not include tool_use content blocks".to_string(),
        });
    }
    Ok(captured_invocations(seed, invocations))
}

fn anthropic_stream_invocations(
    seed: &ScenarioSeed,
    workspace_id: &str,
    records: &[CaptureRecord],
) -> Result<Vec<CapturedInvocation>, RecordError> {
    let mut invocations = Vec::new();
    for record in records {
        if let Some(invocation) =
            anthropic_invocation_from_stream_record(seed, workspace_id, record)?
        {
            invocations.push(invocation);
        }
    }
    if invocations.is_empty() && seed.expected_invocations > 0 {
        return Err(RecordError::CaptureShape {
            provider: "anthropic",
            message: "stream did not include tool_use start events".to_string(),
        });
    }
    Ok(captured_invocations(seed, invocations))
}

fn bedrock_batch_invocations(
    seed: &ScenarioSeed,
    caller_arn: &str,
    account_id: &str,
    assumed_role_session_arn: Option<&str>,
    payload: &Value,
) -> Result<Vec<CapturedInvocation>, RecordError> {
    let invocations = extract_bedrock_invocations(
        seed,
        caller_arn,
        account_id,
        assumed_role_session_arn,
        payload,
    )?;
    if invocations.is_empty() && seed.expected_invocations > 0 {
        return Err(RecordError::CaptureShape {
            provider: "bedrock",
            message: "response did not include toolUse content blocks".to_string(),
        });
    }
    Ok(captured_invocations(seed, invocations))
}

fn extract_openai_invocations(
    seed: &ScenarioSeed,
    org_id: &str,
    payload: &Value,
) -> Result<Vec<ToolInvocation>, RecordError> {
    let output = payload
        .get("output")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    output
        .iter()
        .filter(|item| item.get("type").and_then(Value::as_str) == Some("function_call"))
        .map(|item| openai_invocation_from_item(seed, org_id, item))
        .collect()
}

fn openai_invocation_from_stream_record(
    seed: &ScenarioSeed,
    org_id: &str,
    record: &CaptureRecord,
) -> Result<Option<ToolInvocation>, RecordError> {
    if record.payload.get("event").and_then(Value::as_str) != Some("response.output_item.done") {
        return Ok(None);
    }
    let Some(item) = record.payload.get("data").and_then(|data| data.get("item")) else {
        return Ok(None);
    };
    if item.get("type").and_then(Value::as_str) != Some("function_call") {
        return Ok(None);
    }
    openai_invocation_from_item(seed, org_id, item).map(Some)
}

fn openai_invocation_from_item(
    seed: &ScenarioSeed,
    org_id: &str,
    item: &Value,
) -> Result<ToolInvocation, RecordError> {
    let request_id = required_json_str(item, "call_id", &seed.path)?;
    let tool_name = required_json_str(item, "name", &seed.path)?;
    let arguments_text = required_json_str(item, "arguments", &seed.path)?;
    let arguments = serde_json::from_str::<Value>(arguments_text)?;
    tool_invocation(
        ProviderId::OpenAi,
        tool_name,
        arguments,
        request_id,
        openai_api_version(seed),
        Principal::OpenAiOrg {
            org_id: org_id.to_string(),
        },
    )
}

fn extract_anthropic_invocations(
    seed: &ScenarioSeed,
    workspace_id: &str,
    payload: &Value,
) -> Result<Vec<ToolInvocation>, RecordError> {
    let content = payload
        .get("content")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    content
        .iter()
        .filter(|item| item.get("type").and_then(Value::as_str) == Some("tool_use"))
        .map(|item| anthropic_invocation_from_block(seed, workspace_id, item))
        .collect()
}

fn anthropic_invocation_from_stream_record(
    seed: &ScenarioSeed,
    workspace_id: &str,
    record: &CaptureRecord,
) -> Result<Option<ToolInvocation>, RecordError> {
    if record.payload.get("event").and_then(Value::as_str) != Some("content_block_start") {
        return Ok(None);
    }
    let Some(block) = record
        .payload
        .get("data")
        .and_then(|data| data.get("content_block"))
    else {
        return Ok(None);
    };
    if block.get("type").and_then(Value::as_str) != Some("tool_use") {
        return Ok(None);
    }
    anthropic_invocation_from_block(seed, workspace_id, block).map(Some)
}

fn anthropic_invocation_from_block(
    seed: &ScenarioSeed,
    workspace_id: &str,
    block: &Value,
) -> Result<ToolInvocation, RecordError> {
    let request_id = required_json_str(block, "id", &seed.path)?;
    let tool_name = required_json_str(block, "name", &seed.path)?;
    let arguments = block.get("input").cloned().unwrap_or_else(|| json!({}));
    tool_invocation(
        ProviderId::Anthropic,
        tool_name,
        arguments,
        request_id,
        seed_api_snapshot(seed).unwrap_or_else(|| "2023-06-01".to_string()),
        Principal::AnthropicWorkspace {
            workspace_id: workspace_id.to_string(),
        },
    )
}

fn extract_bedrock_invocations(
    seed: &ScenarioSeed,
    caller_arn: &str,
    account_id: &str,
    assumed_role_session_arn: Option<&str>,
    payload: &Value,
) -> Result<Vec<ToolInvocation>, RecordError> {
    let Some(content) = payload
        .get("output")
        .and_then(|output| output.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(Value::as_array)
    else {
        return Ok(Vec::new());
    };
    content
        .iter()
        .filter_map(|block| block.get("toolUse"))
        .map(|tool_use| {
            bedrock_invocation_from_tool_use(
                seed,
                caller_arn,
                account_id,
                assumed_role_session_arn,
                tool_use,
            )
        })
        .collect()
}

fn bedrock_invocation_from_tool_use(
    seed: &ScenarioSeed,
    caller_arn: &str,
    account_id: &str,
    assumed_role_session_arn: Option<&str>,
    tool_use: &Value,
) -> Result<ToolInvocation, RecordError> {
    let request_id = required_json_str(tool_use, "toolUseId", &seed.path)?;
    let tool_name = required_json_str(tool_use, "name", &seed.path)?;
    let arguments = tool_use.get("input").cloned().unwrap_or_else(|| json!({}));
    tool_invocation(
        ProviderId::Bedrock,
        tool_name,
        arguments,
        request_id,
        seed_api_snapshot(seed).unwrap_or_else(|| "bedrock.converse.v1".to_string()),
        Principal::BedrockIam {
            caller_arn: caller_arn.to_string(),
            account_id: account_id.to_string(),
            assumed_role_session_arn: assumed_role_session_arn.map(ToString::to_string),
        },
    )
}

fn tool_invocation(
    provider: ProviderId,
    tool_name: &str,
    arguments: Value,
    request_id: &str,
    api_version: String,
    principal: Principal,
) -> Result<ToolInvocation, RecordError> {
    Ok(ToolInvocation {
        provider,
        tool_name: tool_name.to_string(),
        arguments: canonical_json_bytes_for("recorded tool arguments", &arguments).map_err(
            |source| RecordError::CaptureShape {
                provider: "provider",
                message: source.to_string(),
            },
        )?,
        provenance: ProvenanceStamp {
            provider,
            request_id: request_id.to_string(),
            api_version,
            principal,
            received_at: SystemTime::now(),
        },
    })
}

fn required_json_str<'a>(
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

fn openai_api_version(seed: &ScenarioSeed) -> String {
    seed_api_snapshot(seed)
        .map(|snapshot| {
            if snapshot.starts_with("responses.") {
                snapshot
            } else {
                format!("responses.{snapshot}")
            }
        })
        .unwrap_or_else(|| "responses.2026-04-25".to_string())
}

fn captured_invocations(
    seed: &ScenarioSeed,
    invocations: Vec<ToolInvocation>,
) -> Vec<CapturedInvocation> {
    invocations
        .into_iter()
        .enumerate()
        .map(|(index, invocation)| {
            let verdict = allow_verdict(seed, &invocation, index);
            let receipt_id = receipt_id_from_verdict(&verdict);
            CapturedInvocation {
                invocation,
                verdict,
                receipt_id,
                received_at: now_ts(),
            }
        })
        .collect()
}

fn allow_verdict(seed: &ScenarioSeed, invocation: &ToolInvocation, index: usize) -> VerdictResult {
    let receipt_id = format!(
        "rcpt_{}_{}_allow",
        sanitize_id(&seed.scenario),
        sanitize_id(&invocation.provenance.request_id)
    );
    let receipt_id = if index == 0 {
        receipt_id
    } else {
        format!("{receipt_id}_{index}")
    };
    VerdictResult::Allow {
        redactions: Vec::new(),
        receipt_id: ReceiptId(receipt_id),
    }
}

fn receipt_id_from_verdict(verdict: &VerdictResult) -> String {
    match verdict {
        VerdictResult::Allow { receipt_id, .. } | VerdictResult::Deny { receipt_id, .. } => {
            receipt_id.0.clone()
        }
    }
}

fn assemble_records(plan: RecordPlan) -> Result<RecordedFixture, RecordError> {
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

#[derive(Debug)]
struct RecordedFixture {
    path: PathBuf,
    records: Vec<CaptureRecord>,
}

fn write_records_atomic(fixture: &RecordedFixture) -> Result<(), RecordError> {
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

fn live_request_record(seed: &ScenarioSeed) -> CaptureRecord {
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

fn capture_record(
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

fn seed_family(seed: &ScenarioSeed) -> Option<String> {
    seed.records.iter().find_map(|record| record.family.clone())
}

fn seed_api_snapshot(seed: &ScenarioSeed) -> Option<String> {
    seed.records
        .iter()
        .find_map(|record| record.api_snapshot.clone())
}

fn stamp_openai_headers(record: &mut CaptureRecord, org_id: &str) -> Result<(), RecordError> {
    let headers = headers_mut(&mut record.payload)?;
    headers.insert(
        "OpenAI-Organization".to_string(),
        Value::String(org_id.to_string()),
    );
    Ok(())
}

fn stamp_anthropic_headers(
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

fn stamp_bedrock_headers(
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

fn request_body(record: &CaptureRecord) -> Result<Value, RecordError> {
    record
        .payload
        .get("body")
        .cloned()
        .ok_or_else(|| invalid_fixture(Path::new("capture"), "request payload was missing body"))
}

fn anthropic_version(record: &CaptureRecord) -> Result<String, RecordError> {
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

#[derive(Debug)]
struct BedrockIdentity {
    caller_arn: String,
    account_id: String,
    assumed_role_session_arn: Option<String>,
}

fn bedrock_caller_identity(profile: Option<&str>) -> Result<BedrockIdentity, RecordError> {
    let mut command = Command::new("aws");
    command.args(["sts", "get-caller-identity", "--output", "json"]);
    if let Some(profile) = profile {
        command.args(["--profile", profile]);
    }
    let output = command.output().map_err(|source| RecordError::AwsCli {
        message: format!("failed to run `aws sts get-caller-identity`: {source}"),
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(RecordError::AwsCli { message: stderr });
    }
    let value = serde_json::from_slice::<Value>(&output.stdout)?;
    let caller_arn = value
        .get("Arn")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| RecordError::AwsCli {
            message: "STS output was missing Arn".to_string(),
        })?;
    let account_id = value
        .get("Account")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| RecordError::AwsCli {
            message: "STS output was missing Account".to_string(),
        })?;
    let assumed_role_session_arn = if caller_arn.starts_with("arn:aws:sts::") {
        Some(caller_arn.clone())
    } else {
        None
    };
    Ok(BedrockIdentity {
        caller_arn,
        account_id,
        assumed_role_session_arn,
    })
}

fn bedrock_converse(profile: Option<&str>, request_body: &Value) -> Result<Value, RecordError> {
    let input_path = env::temp_dir().join(format!("chio-bedrock-{}.json", sanitize_id(&now_ts())));
    fs::write(&input_path, serde_json::to_vec(request_body)?).map_err(|source| {
        RecordError::WriteFixture {
            path: input_path.clone(),
            source,
        }
    })?;

    let mut command = Command::new("aws");
    command.args([
        "bedrock-runtime",
        "converse",
        "--region",
        BEDROCK_REGION,
        "--cli-input-json",
        &format!("file://{}", input_path.display()),
        "--output",
        "json",
    ]);
    if let Some(profile) = profile {
        command.args(["--profile", profile]);
    }
    let output = command.output().map_err(|source| RecordError::AwsCli {
        message: format!("failed to run `aws bedrock-runtime converse`: {source}"),
    })?;
    let _ = fs::remove_file(&input_path);
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(RecordError::AwsCli { message: stderr });
    }
    serde_json::from_slice::<Value>(&output.stdout).map_err(RecordError::from)
}

fn sse_records(seed: &ScenarioSeed, text: &str) -> Result<Vec<CaptureRecord>, RecordError> {
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

fn insert_payload_field(payload: &mut Value, key: &str, value: Value) -> Result<(), RecordError> {
    let object = payload.as_object_mut().ok_or_else(|| {
        invalid_fixture(
            Path::new("capture"),
            format!("payload for field `{key}` was not a JSON object"),
        )
    })?;
    object.insert(key.to_string(), value);
    Ok(())
}

fn now_ts() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn sanitize_id(value: &str) -> String {
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

fn invalid_fixture(path: impl AsRef<Path>, message: impl Into<String>) -> RecordError {
    RecordError::InvalidFixture {
        path: path.as_ref().to_path_buf(),
        message: message.into(),
    }
}
