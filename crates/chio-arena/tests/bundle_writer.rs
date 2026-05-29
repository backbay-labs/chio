use chio_arena::{parse_scenario_str, write_arena_bundle, ArenaReceipt, ArenaRun, ScenarioVerdict};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction, TrustLevel};
use serde_json::json;

fn scenario_toml() -> &'static str {
    r#"
schema_version = "chio.arena.scenario/v1"
id = "walking_skeleton"
title = "Single-agent walking skeleton"
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
seed_prompt_ref = "prompts/walking-skeleton.txt"

[[steps]]
id = "step-1"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/chio-arena.txt" }
expect_verdict = "allow"
"#
}

#[test]
fn writes_bundle_and_arena_manifest() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(scenario_toml())?;
    let run = ArenaRun {
        scenario_id: scenario.id.clone(),
        receipts: vec![arena_receipt()?],
    };
    let tmp = tempfile::tempdir()?;
    let bundle_dir = tmp.path().join("arena").join("walking_skeleton");

    let summary = write_arena_bundle(&bundle_dir, &scenario, &run)?;

    assert_eq!(summary.scenario_id, "walking_skeleton");
    assert_eq!(summary.receipt_count, 1);
    assert!(bundle_dir.join("receipts.ndjson").is_file());
    assert!(bundle_dir.join("checkpoint.json").is_file());
    assert!(bundle_dir.join("root.hex").is_file());
    assert!(bundle_dir.join("arena.json").is_file());
    assert_eq!(summary.manifest_path, bundle_dir.join("arena.json"));

    Ok(())
}

fn arena_receipt() -> Result<ArenaReceipt, Box<dyn std::error::Error>> {
    let keypair = Keypair::generate();
    let action = ToolCallAction::from_parameters(json!({"path": "/tmp/chio-arena.txt"}))?;
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "receipt-step-1".to_string(),
            timestamp: 1_777_000_000,
            capability_id: "cap-step-1".to_string(),
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
        },
        &keypair,
    )?;
    Ok(ArenaReceipt {
        step_id: "step-1".to_string(),
        request_id: "arena-request-1".to_string(),
        verdict: ScenarioVerdict::Allow,
        reason: None,
        receipt,
    })
}
