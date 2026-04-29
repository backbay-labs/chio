use std::fs;
use std::path::{Path, PathBuf};

use chio_provider_conformance::replay::ComparableProvenance;
use chio_provider_conformance::{
    assertions::assert_canonical_bytes_eq, canonical_json_bytes_for, provider_fixture_path,
    replay_anthropic_fixture, replay_bedrock_fixture, replay_openai_fixture, CaptureDirection,
    CaptureRecord, CapturedVerdictKind, ComparableInvocation, ReplayError, ReplayOutcome,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(about = "Dry-run cross-provider Chio policy equality demo")]
struct Args {
    #[arg(long)]
    dry_run: bool,

    #[arg(long, value_name = "PATH")]
    policy: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct DemoPolicy {
    name: String,
    rules: DemoRules,
}

#[derive(Debug, Deserialize)]
struct DemoRules {
    tool_access: ToolAccessRule,
    fixture_contract: FixtureContract,
}

#[derive(Debug, Deserialize)]
struct ToolAccessRule {
    enabled: bool,
    allow: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FixtureContract {
    scenario_id: String,
    required_tool: String,
    required_arguments: Value,
    expected_verdict: CapturedVerdictKind,
}

#[derive(Debug, Clone, Serialize)]
struct DemoReceipt {
    receipt_id: String,
    body: ReceiptBody,
}

#[derive(Debug, Clone, Serialize)]
struct ReceiptBody {
    policy_id: String,
    scenario_id: String,
    tool_name: String,
    arguments: Value,
    verdict: VerdictView,
    provenance: ComparableProvenance,
}

#[derive(Debug, Clone, Serialize)]
struct ReceiptBodyWithoutProvenance {
    policy_id: String,
    scenario_id: String,
    tool_name: String,
    arguments: Value,
    verdict: VerdictView,
}

#[derive(Debug, Clone, Serialize)]
struct VerdictView {
    verdict: CapturedVerdictKind,
    reason: Option<Value>,
    redactions: Vec<Value>,
}

#[derive(Debug, Clone, Copy)]
struct ProviderCase {
    provider: &'static str,
    fixture_id: &'static str,
    kind: ProviderKind,
}

#[derive(Debug, Clone, Copy)]
enum ProviderKind {
    OpenAi,
    Anthropic,
    Bedrock,
}

#[derive(Debug, Error)]
enum DemoError {
    #[error("--dry-run is required; this example never calls live provider APIs")]
    DryRunRequired,
    #[error("read policy {path:?}: {source}")]
    ReadPolicy {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse policy {path:?}: {source}")]
    ParsePolicy {
        path: PathBuf,
        #[source]
        source: serde_yml::Error,
    },
    #[error("policy {policy_id} does not allow required tool {tool}")]
    ToolNotAllowed { policy_id: String, tool: String },
    #[error("policy fixture contract is disabled")]
    DisabledContract,
    #[error("read fixture {path:?}: {source}")]
    ReadFixture {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse fixture {path:?} line {line}: {source}")]
    ParseFixtureLine {
        path: PathBuf,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("fixture {path:?} had {count} kernel verdict records; expected exactly one")]
    KernelVerdictCount { path: PathBuf, count: usize },
    #[error("fixture {path:?} verdict record was missing {field}")]
    MissingVerdictField { path: PathBuf, field: &'static str },
    #[error("fixture {fixture_id} replay produced {actual} verdicts; expected one")]
    ReplayVerdictCount { fixture_id: String, actual: usize },
    #[error("fixture {fixture_id} tool {actual} did not match policy tool {expected}")]
    ToolMismatch {
        fixture_id: String,
        expected: String,
        actual: String,
    },
    #[error("fixture {fixture_id} arguments did not match policy contract")]
    ArgumentsMismatch { fixture_id: String },
    #[error("fixture {fixture_id} verdict {actual:?} did not match policy verdict {expected:?}")]
    VerdictMismatch {
        fixture_id: String,
        expected: CapturedVerdictKind,
        actual: CapturedVerdictKind,
    },
    #[error("canonical JSON assertion failed: {0}")]
    Assertion(#[from] chio_provider_conformance::AssertionError),
    #[error("replay failed: {0}")]
    Replay(#[from] ReplayError),
    #[error("render receipt JSON: {0}")]
    Render(#[from] serde_json::Error),
}

fn main() -> Result<(), DemoError> {
    let args = Args::parse();
    if !args.dry_run {
        return Err(DemoError::DryRunRequired);
    }

    let policy_path = args
        .policy
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("policy.yaml"));
    let policy = load_policy(&policy_path)?;
    validate_policy(&policy)?;

    let receipts = provider_cases()
        .iter()
        .map(|case| run_case(case, &policy))
        .collect::<Result<Vec<_>, _>>()?;

    assert_receipt_equivalence(&receipts)?;

    for receipt in &receipts {
        println!("{}", serde_json::to_string_pretty(receipt)?);
    }
    println!(
        "cross-provider verdict equality: {} receipts validated for policy {}",
        receipts.len(),
        policy.name
    );

    Ok(())
}

fn provider_cases() -> [ProviderCase; 3] {
    [
        ProviderCase {
            provider: "openai",
            fixture_id: "openai_basic_single_tool_call",
            kind: ProviderKind::OpenAi,
        },
        ProviderCase {
            provider: "anthropic",
            fixture_id: "anthropic_basic_single_tool_use",
            kind: ProviderKind::Anthropic,
        },
        ProviderCase {
            provider: "bedrock",
            fixture_id: "bedrock_basic_single_tool_use",
            kind: ProviderKind::Bedrock,
        },
    ]
}

fn load_policy(path: &Path) -> Result<DemoPolicy, DemoError> {
    let text = fs::read_to_string(path).map_err(|source| DemoError::ReadPolicy {
        path: path.to_path_buf(),
        source,
    })?;
    serde_yml::from_str(&text).map_err(|source| DemoError::ParsePolicy {
        path: path.to_path_buf(),
        source,
    })
}

fn validate_policy(policy: &DemoPolicy) -> Result<(), DemoError> {
    if !policy.rules.tool_access.enabled {
        return Err(DemoError::DisabledContract);
    }

    let required_tool = &policy.rules.fixture_contract.required_tool;
    if policy
        .rules
        .tool_access
        .allow
        .iter()
        .any(|tool| tool == required_tool)
    {
        return Ok(());
    }

    Err(DemoError::ToolNotAllowed {
        policy_id: policy.name.clone(),
        tool: required_tool.clone(),
    })
}

fn run_case(case: &ProviderCase, policy: &DemoPolicy) -> Result<DemoReceipt, DemoError> {
    let path = provider_fixture_path(case.provider, case.fixture_id);
    let outcome = replay_case(case.kind, &path)?;
    if outcome.verdicts != 1 {
        return Err(DemoError::ReplayVerdictCount {
            fixture_id: outcome.fixture_id,
            actual: outcome.verdicts,
        });
    }

    let receipt = read_receipt(&path, policy)?;
    enforce_policy(policy, &receipt)?;
    Ok(receipt)
}

fn replay_case(kind: ProviderKind, path: &Path) -> Result<ReplayOutcome, ReplayError> {
    match kind {
        ProviderKind::OpenAi => replay_openai_fixture(path),
        ProviderKind::Anthropic => replay_anthropic_fixture(path),
        ProviderKind::Bedrock => replay_bedrock_fixture(path),
    }
}

fn read_receipt(path: &Path, policy: &DemoPolicy) -> Result<DemoReceipt, DemoError> {
    let text = fs::read_to_string(path).map_err(|source| DemoError::ReadFixture {
        path: path.to_path_buf(),
        source,
    })?;

    let mut verdict_records = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record = serde_json::from_str::<CaptureRecord>(line).map_err(|source| {
            DemoError::ParseFixtureLine {
                path: path.to_path_buf(),
                line: line_index + 1,
                source,
            }
        })?;
        if record.direction == CaptureDirection::KernelVerdict {
            verdict_records.push(record);
        }
    }

    if verdict_records.len() != 1 {
        return Err(DemoError::KernelVerdictCount {
            path: path.to_path_buf(),
            count: verdict_records.len(),
        });
    }

    let Some(record) = verdict_records.into_iter().next() else {
        return Err(DemoError::KernelVerdictCount {
            path: path.to_path_buf(),
            count: 0,
        });
    };
    let invocation = record
        .payload
        .get("invocation")
        .cloned()
        .ok_or_else(|| DemoError::MissingVerdictField {
            path: path.to_path_buf(),
            field: "payload.invocation",
        })
        .and_then(|value| {
            serde_json::from_value::<ComparableInvocation>(value).map_err(|source| {
                DemoError::ParseFixtureLine {
                    path: path.to_path_buf(),
                    line: 0,
                    source,
                }
            })
        })?;
    let verdict = record
        .verdict
        .ok_or_else(|| DemoError::MissingVerdictField {
            path: path.to_path_buf(),
            field: "verdict",
        })?;
    let receipt_id = record
        .receipt_id
        .ok_or_else(|| DemoError::MissingVerdictField {
            path: path.to_path_buf(),
            field: "receipt_id",
        })?;

    Ok(DemoReceipt {
        receipt_id,
        body: ReceiptBody {
            policy_id: policy.name.clone(),
            scenario_id: policy.rules.fixture_contract.scenario_id.clone(),
            tool_name: invocation.tool_name,
            arguments: invocation.arguments,
            verdict: VerdictView {
                verdict,
                reason: record.payload.get("reason").cloned(),
                redactions: record
                    .payload
                    .get("redactions")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default(),
            },
            provenance: invocation.provenance,
        },
    })
}

fn enforce_policy(policy: &DemoPolicy, receipt: &DemoReceipt) -> Result<(), DemoError> {
    let contract = &policy.rules.fixture_contract;
    if receipt.body.tool_name != contract.required_tool {
        return Err(DemoError::ToolMismatch {
            fixture_id: receipt.receipt_id.clone(),
            expected: contract.required_tool.clone(),
            actual: receipt.body.tool_name.clone(),
        });
    }
    if receipt.body.arguments != contract.required_arguments {
        return Err(DemoError::ArgumentsMismatch {
            fixture_id: receipt.receipt_id.clone(),
        });
    }
    if receipt.body.verdict.verdict != contract.expected_verdict {
        return Err(DemoError::VerdictMismatch {
            fixture_id: receipt.receipt_id.clone(),
            expected: contract.expected_verdict,
            actual: receipt.body.verdict.verdict,
        });
    }
    Ok(())
}

fn assert_receipt_equivalence(receipts: &[DemoReceipt]) -> Result<(), DemoError> {
    let Some(first) = receipts.first() else {
        return Ok(());
    };

    let first_body = body_without_provenance(&first.body);
    let first_body_bytes = canonical_json_bytes_for("first receipt body", &first_body)?;
    let first_verdict_bytes =
        canonical_json_bytes_for("first normalized verdict", &first.body.verdict)?;

    for receipt in receipts.iter().skip(1) {
        let body = body_without_provenance(&receipt.body);
        let body_bytes = canonical_json_bytes_for("normalized receipt body", &body)?;
        assert_canonical_bytes_eq(
            "receipt body excluding provenance",
            &first_body_bytes,
            &body_bytes,
        )?;

        let verdict_bytes = canonical_json_bytes_for("normalized verdict", &receipt.body.verdict)?;
        assert_canonical_bytes_eq("normalized verdict", &first_verdict_bytes, &verdict_bytes)?;
    }

    Ok(())
}

fn body_without_provenance(body: &ReceiptBody) -> ReceiptBodyWithoutProvenance {
    ReceiptBodyWithoutProvenance {
        policy_id: body.policy_id.clone(),
        scenario_id: body.scenario_id.clone(),
        tool_name: body.tool_name.clone(),
        arguments: body.arguments.clone(),
        verdict: body.verdict.clone(),
    }
}
