//! End-to-end smoke test composing the auto-promotion building blocks:
//! a failing arena scenario auto-promotes to both corpora, the receipt
//! bundle is replayable bit-exact via the fixture layout, and the
//! leaderboard is rendered with the stable schema.

use std::collections::BTreeMap;
use std::collections::HashMap;

use chio_arena::coevolve::{FitnessReport, FitnessSample};
use chio_arena::{
    parse_scenario_str, promote_to_adversarial_suite, promote_to_fixtures, render_leaderboard,
    write_arena_bundle, AdversaryClass, ArenaReceipt, ArenaRun, BlessEnv, Leaderboard,
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
id = "smoke_e2e"
title = "End-to-end smoke"
rng_seed = 42
virtual_clock_start = "2026-04-30T00:00:00.000Z"

[determinism]
rng_seed = 42
virtual_clock_start = "2026-04-30T00:00:00.000Z"
scheduler = "single-agent-v1"
locale = "C"

[[agents]]
id = "agent-a"
role = "operator"
model = "recorded:test-agent"
seed_prompt_ref = "prompts/smoke.txt"

[[steps]]
id = "step-deny"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/smoke-deny.txt" }
expect_verdict = "deny"
"#
}

fn deny_receipt() -> Result<ArenaReceipt, Box<dyn std::error::Error>> {
    let keypair = Keypair::generate();
    let action = ToolCallAction::from_parameters(json!({"path": "/tmp/smoke-deny.txt"}))?;
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "receipt-step-deny".to_string(),
            timestamp: 1_777_000_000,
            capability_id: "cap-step-deny".to_string(),
            tool_server: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            action,
            decision: Some(Decision::Deny {
                reason: "policy:denied".to_string(),
                guard: "test-guard".to_string(),
            }),
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
        step_id: "step-deny".to_string(),
        request_id: "req-step-deny".to_string(),
        verdict: ScenarioVerdict::Deny,
        reason: Some("policy:denied".to_string()),
        receipt,
    })
}

#[test]
fn end_to_end_smoke() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(scenario_toml())?;
    let run = ArenaRun {
        scenario_id: "smoke_e2e".to_string(),
        receipts: vec![deny_receipt()?],
    };
    let workspace = tempfile::tempdir()?;

    // Step 1: write the byte-compatible bundle under target/arena/.
    let bundle_dir = workspace
        .path()
        .join("target")
        .join("arena")
        .join(&scenario.id);
    let bundle = write_arena_bundle(&bundle_dir, &scenario, &run)?;
    assert!(bundle_dir.join("receipts.ndjson").is_file());
    assert!(bundle_dir.join("checkpoint.json").is_file());
    assert!(bundle_dir.join("root.hex").is_file());
    assert!(bundle_dir.join("arena.json").is_file());
    assert_eq!(bundle.scenario_id, "smoke_e2e");

    // Step 2: auto-promote to the fixture corpus.
    let fixtures_root = workspace
        .path()
        .join("tests")
        .join("replay")
        .join("fixtures");
    let env = StubEnv::default()
        .with("CHIO_BLESS", "1")
        .with("BLESS_REASON", "arena:smoke_e2e");
    let fixture = promote_to_fixtures(
        &scenario,
        &run,
        &fixtures_root,
        "prompt-injection",
        ARENA_PROMOTE_CAP_DEFAULT,
        &env,
    )?;
    assert_eq!(fixture.fixtures.len(), 1);
    let fixture_bytes = std::fs::read(&fixture.fixtures[0])?;
    let fixture_parsed: Value = serde_json::from_slice(&fixture_bytes)?;
    assert_eq!(fixture_parsed["bless_reason"], "arena:smoke_e2e");
    assert_eq!(fixture_parsed["expected_failure_class"], "prompt-injection");

    // Step 3: auto-promote to the adversarial suite (falls back to
    // promote-pending/ since the adversarial-suite scaffold is not present).
    let suite =
        promote_to_adversarial_suite(&scenario, &run, workspace.path(), "prompt-injection")?;
    assert!(!suite.live_target);
    assert_eq!(suite.cases.len(), 1);

    // Step 4: render a leaderboard for the run.
    let mut samples = BTreeMap::new();
    samples.insert(
        "alpha".to_string(),
        FitnessSample {
            class: AdversaryClass::PromptInjection,
            population: "alpha".to_string(),
            step_ids: vec!["step-deny".to_string()],
            tuples: Vec::new(),
            survivals: 0,
            defeats: 1,
        },
    );
    let report = FitnessReport { samples };
    let leaderboard = Leaderboard::from_fitness_report(&report, &scenario.id, 0);
    let leaderboard_dir = workspace.path().join("target").join("arena");
    let artifacts = render_leaderboard(&leaderboard_dir, &leaderboard)?;
    assert!(artifacts.json_path.is_file());
    assert!(artifacts.markdown_path.is_file());

    Ok(())
}
