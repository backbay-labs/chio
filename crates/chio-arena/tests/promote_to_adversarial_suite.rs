//! Auto-promotion to the chio-adversarial-suite per-class JSON files.
//! Until the suite lands, the writer falls back to a
//! `target/arena/promote-pending/` holding directory.

use chio_arena::{
    parse_scenario_str, promote_to_adversarial_suite, ArenaReceipt, ArenaRun, ScenarioVerdict,
};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::TrustLevel,
};
use serde_json::{json, Value};

fn scenario_toml() -> &'static str {
    r#"
schema_version = "chio.arena.scenario/v1"
id = "suite_demo"
title = "Adversarial suite promotion demo"
rng_seed = 11
virtual_clock_start = "2026-04-30T00:00:00.000Z"

[determinism]
rng_seed = 11
virtual_clock_start = "2026-04-30T00:00:00.000Z"
scheduler = "single-agent-v1"
locale = "C"

[[agents]]
id = "agent-a"
role = "operator"
model = "recorded:test-agent"
seed_prompt_ref = "prompts/suite.txt"

[[steps]]
id = "step-1"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/suite-1.txt" }
expect_verdict = "deny"
"#
}

fn arena_receipt() -> Result<ArenaReceipt, Box<dyn std::error::Error>> {
    let keypair = Keypair::generate();
    let action = ToolCallAction::from_parameters(json!({"path": "/tmp/suite-1.txt"}))?;
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "receipt-step-1".to_string(),
            timestamp: 1_777_000_000,
            capability_id: "cap-step-1".to_string(),
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
            bbs_projection_version: None,
        },
        &keypair,
    )?;
    Ok(ArenaReceipt {
        step_id: "step-1".to_string(),
        request_id: "req-step-1".to_string(),
        verdict: ScenarioVerdict::Deny,
        reason: Some("policy:denied".to_string()),
        receipt,
    })
}

#[test]
fn falls_back_to_promote_pending_when_suite_absent() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(scenario_toml())?;
    let run = ArenaRun {
        scenario_id: "suite_demo".to_string(),
        receipts: vec![arena_receipt()?],
    };
    let tmp = tempfile::tempdir()?;

    let summary = promote_to_adversarial_suite(&scenario, &run, tmp.path(), "prompt-injection")?;

    assert!(!summary.live_target);
    assert!(summary.root.starts_with(
        tmp.path()
            .join("target")
            .join("arena")
            .join("promote-pending")
    ));
    assert_eq!(summary.cases.len(), 1);
    let case_bytes = std::fs::read(&summary.cases[0])?;
    let parsed: Value = serde_json::from_slice(&case_bytes)?;
    assert_eq!(parsed["schema_version"], "chio.arena.adversarial-case/v1");
    assert_eq!(parsed["class"], "prompt-injection");
    assert_eq!(parsed["scenario_id"], "suite_demo");
    Ok(())
}

#[test]
fn writes_to_live_suite_when_present() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(scenario_toml())?;
    let run = ArenaRun {
        scenario_id: "suite_demo".to_string(),
        receipts: vec![arena_receipt()?],
    };
    let tmp = tempfile::tempdir()?;
    // Pre-create the suite scaffold.
    let suite_root = tmp
        .path()
        .join("crates")
        .join("chio-adversarial-suite")
        .join("cases");
    std::fs::create_dir_all(&suite_root)?;

    let summary =
        promote_to_adversarial_suite(&scenario, &run, tmp.path(), "capability-overrequest")?;

    assert!(summary.live_target);
    assert!(summary.root.starts_with(&suite_root));
    assert_eq!(summary.cases.len(), 1);
    Ok(())
}

#[test]
fn skips_allow_receipts() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(scenario_toml())?;
    let allowed = arena_receipt_allow()?;
    let run = ArenaRun {
        scenario_id: "suite_demo".to_string(),
        receipts: vec![allowed],
    };
    let tmp = tempfile::tempdir()?;

    let summary = promote_to_adversarial_suite(&scenario, &run, tmp.path(), "prompt-injection")?;
    assert!(summary.cases.is_empty());
    Ok(())
}

fn arena_receipt_allow() -> Result<ArenaReceipt, Box<dyn std::error::Error>> {
    let keypair = Keypair::generate();
    let action = ToolCallAction::from_parameters(json!({"path": "/tmp/ok.txt"}))?;
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "receipt-allow-1".to_string(),
            timestamp: 1_777_000_000,
            capability_id: "cap-allow".to_string(),
            tool_server: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            action,
            decision: Some(Decision::Allow),
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
            bbs_projection_version: None,
        },
        &keypair,
    )?;
    Ok(ArenaReceipt {
        step_id: "step-1".to_string(),
        request_id: "req-step-1".to_string(),
        verdict: ScenarioVerdict::Allow,
        reason: None,
        receipt,
    })
}
