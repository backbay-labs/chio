//! Auto-promotion to fixtures via the existing CHIO_BLESS gate
//! (BLESS_REASON=arena:<scenario-id>).

use std::collections::HashMap;

use chio_arena::{
    parse_scenario_str, promote_to_fixtures, ArenaReceipt, ArenaRun, BlessEnv, PromoteError,
    ScenarioVerdict, ARENA_PROMOTE_CAP_DEFAULT,
};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction, TrustLevel};
use serde_json::{json, Value};

#[derive(Default)]
struct StubEnv {
    inner: HashMap<String, String>,
}

impl StubEnv {
    fn with(mut self, key: &str, value: &str) -> Self {
        self.inner.insert(key.to_string(), value.to_string());
        self
    }
}

impl BlessEnv for StubEnv {
    fn var(&self, name: &str) -> Option<String> {
        self.inner.get(name).cloned()
    }
}

fn scenario_toml() -> &'static str {
    r#"
schema_version = "chio.arena.scenario/v1"
id = "promote_demo"
title = "Promotion demo"
rng_seed = 7
virtual_clock_start = "2026-04-30T00:00:00.000Z"

[determinism]
rng_seed = 7
virtual_clock_start = "2026-04-30T00:00:00.000Z"
scheduler = "single-agent-v1"
locale = "C"

[[agents]]
id = "agent-a"
role = "operator"
model = "recorded:test-agent"
seed_prompt_ref = "prompts/promote.txt"

[[steps]]
id = "step-1"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/p5.txt" }
expect_verdict = "deny"

[[steps]]
id = "step-2"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/allowed.txt" }
expect_verdict = "allow"
"#
}

fn arena_receipt(
    step_id: &str,
    verdict: ScenarioVerdict,
    reason: Option<&str>,
) -> Result<ArenaReceipt, Box<dyn std::error::Error>> {
    let keypair = Keypair::generate();
    let action = ToolCallAction::from_parameters(json!({"path": format!("/tmp/{}.txt", step_id)}))?;
    let decision = match verdict {
        ScenarioVerdict::Allow | ScenarioVerdict::Rewrite => Decision::Allow,
        ScenarioVerdict::Deny => Decision::Deny {
            reason: reason.unwrap_or("policy:denied").to_string(),
            guard: "test-guard".to_string(),
        },
    };
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: format!("receipt-{step_id}"),
            timestamp: 1_777_000_000,
            capability_id: format!("cap-{step_id}"),
            tool_server: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            action,
            decision: Some(decision),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: sha256_hex(b"content"),
            policy_hash: sha256_hex(b"policy"),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )?;
    Ok(ArenaReceipt {
        step_id: step_id.to_string(),
        request_id: format!("req-{step_id}"),
        verdict,
        reason: reason.map(str::to_string),
        receipt,
    })
}

fn run_with_one_deny() -> Result<ArenaRun, Box<dyn std::error::Error>> {
    Ok(ArenaRun {
        scenario_id: "promote_demo".to_string(),
        receipts: vec![
            arena_receipt("step-1", ScenarioVerdict::Deny, Some("policy:denied"))?,
            arena_receipt("step-2", ScenarioVerdict::Allow, None)?,
        ],
    })
}

#[test]
fn writes_fixture_under_arena_class_namespace() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(scenario_toml())?;
    let run = run_with_one_deny()?;
    let tmp = tempfile::tempdir()?;
    let fixtures_root = tmp.path();
    let env = StubEnv::default()
        .with("CHIO_BLESS", "1")
        .with("BLESS_REASON", "arena:promote_demo");

    let summary = promote_to_fixtures(
        &scenario,
        &run,
        fixtures_root,
        "prompt-injection",
        ARENA_PROMOTE_CAP_DEFAULT,
        &env,
    )?;

    assert_eq!(summary.fixtures.len(), 1);
    assert_eq!(summary.bless_reason, "arena:promote_demo");
    assert_eq!(summary.family, "prompt-injection");
    assert_eq!(summary.receipts_scanned, 2);
    assert_eq!(summary.receipts_skipped_cap, 0);

    let fixture_path = &summary.fixtures[0];
    assert!(fixture_path.starts_with(fixtures_root.join("arena").join("prompt-injection")));
    let bytes = std::fs::read(fixture_path)?;
    let parsed: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        parsed["schema_version"],
        Value::String("chio.arena.fixture/v1".to_string())
    );
    assert_eq!(parsed["bless_reason"], "arena:promote_demo");
    assert_eq!(parsed["expected_verdict"], "deny");
    assert_eq!(parsed["arena"]["scenario_id"], "promote_demo");
    Ok(())
}

#[test]
fn refuses_without_chio_bless() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(scenario_toml())?;
    let run = run_with_one_deny()?;
    let tmp = tempfile::tempdir()?;
    let env = StubEnv::default().with("BLESS_REASON", "arena:promote_demo");

    let result = promote_to_fixtures(&scenario, &run, tmp.path(), "prompt-injection", 5, &env);
    match result {
        Err(PromoteError::BlessGate { clause }) => {
            assert!(clause.contains("CHIO_BLESS"), "got {clause}");
        }
        other => panic!("expected BlessGate refusal, got {other:?}"),
    }
    Ok(())
}

#[test]
fn refuses_when_ci_is_truthy() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(scenario_toml())?;
    let run = run_with_one_deny()?;
    let tmp = tempfile::tempdir()?;
    let env = StubEnv::default()
        .with("CHIO_BLESS", "1")
        .with("BLESS_REASON", "arena:promote_demo")
        .with("CI", "true");

    let result = promote_to_fixtures(&scenario, &run, tmp.path(), "prompt-injection", 5, &env);
    match result {
        Err(PromoteError::BlessGate { clause }) => {
            assert!(clause.contains("CI"), "got {clause}");
        }
        other => panic!("expected CI refusal, got {other:?}"),
    }
    Ok(())
}

#[test]
fn refuses_when_bless_reason_does_not_match_scenario_id() -> Result<(), Box<dyn std::error::Error>>
{
    let scenario = parse_scenario_str(scenario_toml())?;
    let run = run_with_one_deny()?;
    let tmp = tempfile::tempdir()?;
    let env = StubEnv::default()
        .with("CHIO_BLESS", "1")
        .with("BLESS_REASON", "arena:other_scenario");

    let result = promote_to_fixtures(&scenario, &run, tmp.path(), "prompt-injection", 5, &env);
    match result {
        Err(PromoteError::BlessGate { clause }) => {
            assert!(clause.contains("scenario-id"), "got {clause}");
        }
        other => panic!("expected scenario-id refusal, got {other:?}"),
    }
    Ok(())
}

#[test]
fn enforces_per_run_cap() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(scenario_toml_with_many_denies())?;
    let mut receipts = Vec::new();
    for idx in 1..=10 {
        receipts.push(arena_receipt(
            &format!("step-{idx}"),
            ScenarioVerdict::Deny,
            Some("policy:denied"),
        )?);
    }
    let run = ArenaRun {
        scenario_id: "promote_capped".to_string(),
        receipts,
    };
    let tmp = tempfile::tempdir()?;
    let env = StubEnv::default()
        .with("CHIO_BLESS", "1")
        .with("BLESS_REASON", "arena:promote_capped");

    let summary = promote_to_fixtures(
        &scenario,
        &run,
        tmp.path(),
        "prompt-injection",
        ARENA_PROMOTE_CAP_DEFAULT,
        &env,
    )?;

    assert_eq!(summary.fixtures.len(), ARENA_PROMOTE_CAP_DEFAULT);
    assert_eq!(summary.receipts_skipped_cap, 10 - ARENA_PROMOTE_CAP_DEFAULT);
    Ok(())
}

fn scenario_toml_with_many_denies() -> &'static str {
    r#"
schema_version = "chio.arena.scenario/v1"
id = "promote_capped"
title = "Promotion cap demo"
rng_seed = 7
virtual_clock_start = "2026-04-30T00:00:00.000Z"

[determinism]
rng_seed = 7
virtual_clock_start = "2026-04-30T00:00:00.000Z"
scheduler = "single-agent-v1"
locale = "C"

[[agents]]
id = "agent-a"
role = "operator"
model = "recorded:test-agent"
seed_prompt_ref = "prompts/cap.txt"

[[steps]]
id = "step-1"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/1.txt" }
expect_verdict = "deny"

[[steps]]
id = "step-2"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/2.txt" }
expect_verdict = "deny"

[[steps]]
id = "step-3"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/3.txt" }
expect_verdict = "deny"

[[steps]]
id = "step-4"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/4.txt" }
expect_verdict = "deny"

[[steps]]
id = "step-5"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/5.txt" }
expect_verdict = "deny"

[[steps]]
id = "step-6"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/6.txt" }
expect_verdict = "deny"

[[steps]]
id = "step-7"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/7.txt" }
expect_verdict = "deny"

[[steps]]
id = "step-8"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/8.txt" }
expect_verdict = "deny"

[[steps]]
id = "step-9"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/9.txt" }
expect_verdict = "deny"

[[steps]]
id = "step-10"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/10.txt" }
expect_verdict = "deny"
"#
}
