//! Capability-overrequest adversary class tests (`M08.P3.T3`).

use chio_arena::adversary::capability_overrequest::{default_variants, REASON};
use chio_arena::{
    evaluate_against_guards, parse_scenario_str, population_from_block, AdversaryClass,
    CapabilityOverrequestAdversary, IssuedScope, ScenarioVerdict,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn scenario_str() -> &'static str {
    r#"
schema_version = "chio.arena.scenario/v1"
id = "capability_overrequest_unit"
title = "Capability overrequest unit"
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
seed_prompt_ref = "prompts/seed.txt"

[[steps]]
id = "step-1"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/x.txt" }
expect_verdict = "allow"

[[adversaries]]
class = "capability-overrequest"
population = "default"
seed_ref = "scope-monotone"
"#
}

#[test]
fn every_variant_denied_by_guard() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(scenario_str())?;
    let mut population = population_from_block(&scenario.adversaries[0])?;
    assert_eq!(population.class(), AdversaryClass::CapabilityOverrequest);
    assert_eq!(population.len(), default_variants().len());

    let issued = IssuedScope::allow("filesystem", "read_file");
    let base_step = scenario.steps[0].clone();
    let mut rng = ChaCha20Rng::seed_from_u64(scenario.rng_seed);
    for _ in 0..population.len() {
        let action = population.next_action(&base_step, &mut rng);
        assert_eq!(action.expected_verdict, ScenarioVerdict::Deny);
        // Mutated step always escapes the issued scope.
        assert!(
            action.mutated_step.server != issued.server || action.mutated_step.tool != issued.tool
        );
        let evaluation = evaluate_against_guards(&action, &issued);
        assert_eq!(evaluation.verdict, ScenarioVerdict::Deny);
        assert_eq!(evaluation.reason, REASON);
    }
    Ok(())
}

#[test]
fn matching_scope_allowed() -> Result<(), Box<dyn std::error::Error>> {
    // Build a CapabilityOverrequestAdversary whose target equals the issued
    // scope; the evaluator should NOT trip fail-closed in that case. This
    // proves the adversary is exercising the scope-subset check, not a
    // hardcoded deny.
    let adversary = CapabilityOverrequestAdversary::new(
        "noop",
        chio_arena::adversary::capability_overrequest::OverrequestVariant {
            label: "match".to_string(),
            target_server: "filesystem".to_string(),
            target_tool: "read_file".to_string(),
        },
    );
    use chio_arena::Adversary;
    let issued = IssuedScope::allow("filesystem", "read_file");
    let base_step = chio_arena::ScenarioStep {
        id: "step-1".to_string(),
        agent: "agent-a".to_string(),
        server: "filesystem".to_string(),
        tool: "read_file".to_string(),
        arguments: serde_json::json!({"path": "/tmp/x.txt"}),
        expect_verdict: ScenarioVerdict::Allow,
    };
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let action = adversary.act(&base_step, &mut rng);
    let evaluation = evaluate_against_guards(&action, &issued);
    assert_eq!(evaluation.verdict, ScenarioVerdict::Allow);
    assert_eq!(evaluation.reason, "scope-subset");
    Ok(())
}
