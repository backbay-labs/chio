use std::fs;
use std::path::{Path, PathBuf};

use chio_provider_conformance::{
    provider_fixture_path, CaptureDirection, CaptureRecord, CAPTURE_SCHEMA,
};
use clap::{Parser, ValueEnum};
use serde_json::Value;

use crate::anthropic::record_anthropic;
use crate::bedrock::record_bedrock;
use crate::credentials::{credentials_for, Credentials};
use crate::fixture::{assemble_records, write_records_atomic};
use crate::openai::record_openai;
use crate::util::invalid_fixture;
use crate::RecordError;

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
pub(crate) enum ProviderArg {
    #[value(name = "openai")]
    OpenAi,
    Anthropic,
    Bedrock,
}

impl ProviderArg {
    pub(crate) fn fixture_provider(self) -> &'static str {
        match self {
            ProviderArg::OpenAi => "openai",
            ProviderArg::Anthropic => "anthropic",
            ProviderArg::Bedrock => "bedrock",
        }
    }
}

#[derive(Debug)]
pub(crate) struct ScenarioSeed {
    pub(crate) provider: ProviderArg,
    pub(crate) scenario: String,
    pub(crate) path: PathBuf,
    pub(crate) records: Vec<CaptureRecord>,
    pub(crate) initial_request: CaptureRecord,
    pub(crate) lowered_templates: Vec<CaptureRecord>,
    pub(crate) expected_invocations: usize,
}

pub(crate) fn main() {
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
