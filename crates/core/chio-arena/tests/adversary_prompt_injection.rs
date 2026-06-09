//! Prompt-injection adversary class tests.

use chio_arena::adversary::prompt_injection::{INJECTION_MARKER, INJECTION_PATTERNS, REASON};
use chio_arena::{
    evaluate_against_guards, parse_scenario_str, population_from_block, Adversary, AdversaryClass,
    IssuedScope, PromptInjectionAdversary, ScenarioVerdict,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::json;

fn base_scenario() -> &'static str {
    r#"
schema_version = "chio.arena.scenario/v1"
id = "prompt_injection_unit"
title = "Prompt injection unit"
rng_seed = 1
virtual_clock_start = "2026-04-30T00:00:00.000Z"

[determinism]
rng_seed = 1
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
class = "prompt-injection"
population = "default"
seed_ref = "fuzz/artifacts"
"#
}

#[test]
fn each_pattern_triggers_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(base_scenario())?;
    let mut population = population_from_block(&scenario.adversaries[0])?;
    assert_eq!(population.class(), AdversaryClass::PromptInjection);
    assert_eq!(population.len(), INJECTION_PATTERNS.len());

    let issued = IssuedScope::allow("filesystem", "read_file");
    let base_step = scenario.steps[0].clone();
    let mut rng = ChaCha20Rng::seed_from_u64(scenario.rng_seed);
    for _ in 0..INJECTION_PATTERNS.len() {
        let action = population.next_action(&base_step, &mut rng);
        let evaluation = evaluate_against_guards(&action, &issued);
        assert_eq!(action.expected_verdict, ScenarioVerdict::Deny);
        assert_eq!(evaluation.verdict, ScenarioVerdict::Deny);
        assert_eq!(evaluation.reason, REASON);
        let arguments = action.mutated_step.arguments.to_string();
        assert!(arguments.contains(INJECTION_MARKER));
    }
    Ok(())
}

#[test]
fn deterministic_across_runs() -> Result<(), Box<dyn std::error::Error>> {
    let adversary = PromptInjectionAdversary::new("det", "ignore-previous-instructions")?;
    let base_step = chio_arena::ScenarioStep {
        id: "step-1".to_string(),
        agent: "agent-a".to_string(),
        server: "filesystem".to_string(),
        tool: "read_file".to_string(),
        arguments: json!({"path": "/tmp/x.txt"}),
        expect_verdict: ScenarioVerdict::Allow,
    };
    let mut rng_a = ChaCha20Rng::seed_from_u64(123);
    let mut rng_b = ChaCha20Rng::seed_from_u64(123);
    let action_a = adversary.act(&base_step, &mut rng_a);
    let action_b = adversary.act(&base_step, &mut rng_b);
    assert_eq!(
        action_a.mutated_step.arguments,
        action_b.mutated_step.arguments
    );
    assert_eq!(action_a.mutated_step.id, action_b.mutated_step.id);
    Ok(())
}

#[test]
fn unknown_pattern_rejected() {
    let err = PromptInjectionAdversary::new("default", "not-a-pattern").err();
    assert!(err.is_some(), "expected unknown pattern to fail");
}
