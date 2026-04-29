#![cfg(all(
    feature = "fixtures-openai",
    feature = "fixtures-anthropic",
    feature = "fixtures-bedrock"
))]

use std::fs;
use std::path::Path;

use chio_provider_conformance::{
    assertions::assert_canonical_bytes_eq, canonical_json_bytes_for, provider_fixture_path,
    replay_anthropic_fixture, replay_bedrock_fixture, replay_openai_fixture, CaptureDirection,
    CaptureRecord, CapturedVerdictKind, ComparableInvocation,
};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone)]
struct ProviderFixture {
    provider: &'static str,
    fixture_id: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct NormalizedInvocation {
    tool_name: String,
    arguments: Value,
}

#[derive(Debug, Clone, Serialize)]
struct NormalizedVerdict {
    verdict: CapturedVerdictKind,
    reason: Option<Value>,
    redactions: Vec<Value>,
}

#[derive(Debug, Clone, Serialize)]
struct NormalizedReceiptBody {
    policy_id: &'static str,
    scenario_id: &'static str,
    invocation: NormalizedInvocation,
    verdict: NormalizedVerdict,
}

#[derive(Debug, Clone)]
struct CapturedKernelVerdict {
    fixture_id: String,
    invocation: ComparableInvocation,
    verdict: NormalizedVerdict,
}

#[test]
fn weather_tool_policy_verdicts_match_across_all_providers() {
    let cases = [
        ProviderFixture {
            provider: "openai",
            fixture_id: "openai_basic_single_tool_call",
        },
        ProviderFixture {
            provider: "anthropic",
            fixture_id: "anthropic_basic_single_tool_use",
        },
        ProviderFixture {
            provider: "bedrock",
            fixture_id: "bedrock_basic_single_tool_use",
        },
    ];

    let mut captured = Vec::new();
    for case in cases {
        let path = provider_fixture_path(case.provider, case.fixture_id);
        replay_fixture(case.provider, &path);
        captured.push(load_single_verdict(&path));
    }

    assert_eq!(captured.len(), 3);
    assert_byte_equal_normalized_receipts("weather_lookup_allow", &captured);
}

fn replay_fixture(provider: &str, path: &Path) {
    let outcome = match provider {
        "openai" => replay_openai_fixture(path),
        "anthropic" => replay_anthropic_fixture(path),
        "bedrock" => replay_bedrock_fixture(path),
        other => panic!("unsupported provider {other}"),
    };
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => panic!("replay {}: {error}", path.display()),
    };
    assert_eq!(
        outcome.verdicts, 1,
        "{} should emit one kernel verdict",
        outcome.fixture_id
    );
}

fn load_single_verdict(path: &Path) -> CapturedKernelVerdict {
    let body = match fs::read_to_string(path) {
        Ok(body) => body,
        Err(error) => panic!("read {}: {error}", path.display()),
    };

    let mut records = Vec::new();
    for (line_index, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let record = match serde_json::from_str::<CaptureRecord>(line) {
            Ok(record) => record,
            Err(error) => panic!("parse {} line {}: {error}", path.display(), line_index + 1),
        };
        if record.direction == CaptureDirection::KernelVerdict {
            records.push(record);
        }
    }

    assert_eq!(
        records.len(),
        1,
        "{} should contain one kernel verdict record",
        path.display()
    );
    let Some(record) = records.into_iter().next() else {
        panic!(
            "{} missing kernel verdict after count check",
            path.display()
        );
    };

    let invocation = match record.payload.get("invocation").cloned() {
        Some(value) => match serde_json::from_value::<ComparableInvocation>(value) {
            Ok(invocation) => invocation,
            Err(error) => panic!("parse {} invocation: {error}", path.display()),
        },
        None => panic!("{} verdict missing invocation payload", path.display()),
    };
    let Some(verdict) = record.verdict else {
        panic!("{} verdict missing verdict kind", path.display());
    };

    CapturedKernelVerdict {
        fixture_id: record.fixture_id,
        invocation,
        verdict: NormalizedVerdict {
            verdict,
            reason: record.payload.get("reason").cloned(),
            redactions: record
                .payload
                .get("redactions")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        },
    }
}

fn assert_byte_equal_normalized_receipts(
    scenario_id: &'static str,
    captured: &[CapturedKernelVerdict],
) {
    let Some(first) = captured.first() else {
        panic!("no captured verdicts supplied");
    };
    let first_body = normalized_receipt_body(scenario_id, first);
    let first_body_bytes = match canonical_json_bytes_for("first normalized receipt", &first_body) {
        Ok(bytes) => bytes,
        Err(error) => panic!("canonicalize first normalized receipt: {error}"),
    };
    let first_verdict_bytes =
        match canonical_json_bytes_for("first normalized verdict", &first.verdict) {
            Ok(bytes) => bytes,
            Err(error) => panic!("canonicalize first normalized verdict: {error}"),
        };

    for entry in captured.iter().skip(1) {
        let body = normalized_receipt_body(scenario_id, entry);
        let body_bytes = match canonical_json_bytes_for("normalized receipt", &body) {
            Ok(bytes) => bytes,
            Err(error) => panic!("canonicalize {}: {error}", entry.fixture_id),
        };
        if let Err(error) = assert_canonical_bytes_eq(
            "cross-provider normalized receipt",
            &first_body_bytes,
            &body_bytes,
        ) {
            panic!("{} normalized receipt mismatch: {error}", entry.fixture_id);
        }

        let verdict_bytes = match canonical_json_bytes_for("normalized verdict", &entry.verdict) {
            Ok(bytes) => bytes,
            Err(error) => panic!("canonicalize {} verdict: {error}", entry.fixture_id),
        };
        if let Err(error) = assert_canonical_bytes_eq(
            "cross-provider verdict",
            &first_verdict_bytes,
            &verdict_bytes,
        ) {
            panic!("{} verdict mismatch: {error}", entry.fixture_id);
        }
    }
}

fn normalized_receipt_body(
    scenario_id: &'static str,
    entry: &CapturedKernelVerdict,
) -> NormalizedReceiptBody {
    NormalizedReceiptBody {
        policy_id: "cross-provider-policy-demo",
        scenario_id,
        invocation: NormalizedInvocation {
            tool_name: entry.invocation.tool_name.clone(),
            arguments: entry.invocation.arguments.clone(),
        },
        verdict: entry.verdict.clone(),
    }
}
