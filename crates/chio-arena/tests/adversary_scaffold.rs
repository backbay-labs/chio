//! Scaffolding tests for the adversary surface.
//!
//! These tests focus on the trait and population machinery rather than
//! per-class behaviour: they exercise the [`AdversaryClass`] round-trip,
//! the [`AdversaryPopulation`] constructor invariants, and the DSL
//! `[[adversaries]]` block parser plus its `params` extension.

use chio_arena::{
    parse_scenario_str, population_from_block, Adversary, AdversaryClass, AdversaryError,
    AdversaryPopulation, PromptInjectionAdversary,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const SCENARIO_WITH_ADVERSARY_BLOCK: &str = r#"
schema_version = "chio.arena.scenario/v1"
id = "scaffold_adversary"
title = "Scaffold adversary scenario"
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
seed_prompt_ref = "prompts/scaffold.txt"

[[steps]]
id = "step-1"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/scaffold.txt" }
expect_verdict = "allow"

[[adversaries]]
class = "prompt-injection"
population = "scaffold-injection"
seed_ref = "fuzz/artifacts"

[adversaries.params]
patterns = ["ignore-previous-instructions"]
"#;

#[test]
fn class_string_round_trips() -> Result<(), AdversaryError> {
    for class in [
        AdversaryClass::PromptInjection,
        AdversaryClass::CapabilityOverrequest,
        AdversaryClass::ReplayAttempt,
        AdversaryClass::ScopeEscape,
    ] {
        let parsed = AdversaryClass::parse(class.as_str())?;
        assert_eq!(parsed, class);
    }
    Ok(())
}

#[test]
fn empty_population_rejected() {
    let err = AdversaryPopulation::new("empty", Vec::new()).err();
    assert!(matches!(err, Some(AdversaryError::EmptyPopulation(_))));
}

#[test]
fn mixed_class_population_rejected() -> Result<(), AdversaryError> {
    let injection: Box<dyn Adversary + Send + Sync> = Box::new(PromptInjectionAdversary::new(
        "mixed",
        "ignore-previous-instructions",
    )?);
    let escape: Box<dyn Adversary + Send + Sync> = Box::new(chio_arena::ScopeEscapeAdversary::new(
        "mixed",
        chio_arena::adversary::scope_escape::ScopeEscalation {
            label: "broaden-tool".to_string(),
            server: "filesystem".to_string(),
            tool: "write_file".to_string(),
        },
    ));
    let err = AdversaryPopulation::new("mixed", vec![injection, escape]).err();
    assert!(matches!(
        err,
        Some(AdversaryError::MixedClassPopulation { .. })
    ));
    Ok(())
}

#[test]
fn population_round_robins_members() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(SCENARIO_WITH_ADVERSARY_BLOCK)?;
    assert_eq!(scenario.adversaries.len(), 1);
    let block = &scenario.adversaries[0];
    let mut population = population_from_block(block)?;
    assert_eq!(population.class(), AdversaryClass::PromptInjection);
    assert_eq!(population.name(), "scaffold-injection");
    assert_eq!(population.len(), 1);

    let base_step = scenario.steps[0].clone();
    let mut rng = ChaCha20Rng::seed_from_u64(scenario.rng_seed);
    let action_a = population.next_action(&base_step, &mut rng);
    let action_b = population.next_action(&base_step, &mut rng);
    // With one member the cursor wraps; the actions differ because the RNG
    // sub-stream advanced between calls.
    assert_eq!(action_a.class, AdversaryClass::PromptInjection);
    assert_eq!(action_b.class, AdversaryClass::PromptInjection);
    assert_ne!(
        action_a.mutated_step.arguments, action_b.mutated_step.arguments,
        "RNG sub-stream must advance between adversary actions"
    );
    Ok(())
}

#[test]
fn dsl_block_parses_with_params_table() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(SCENARIO_WITH_ADVERSARY_BLOCK)?;
    let block = &scenario.adversaries[0];
    assert_eq!(block.class, "prompt-injection");
    assert_eq!(block.population, "scaffold-injection");
    let patterns = block
        .params
        .get("patterns")
        .and_then(|value| value.as_array())
        .ok_or("patterns array missing")?;
    assert_eq!(patterns.len(), 1);
    Ok(())
}

#[test]
fn dsl_block_rejects_inline_secret_in_params() {
    let scenario_str = SCENARIO_WITH_ADVERSARY_BLOCK.replace(
        "patterns = [\"ignore-previous-instructions\"]",
        "api_key = \"sk-test\"",
    );
    let err = parse_scenario_str(&scenario_str).err();
    assert!(
        matches!(err, Some(chio_arena::ScenarioError::InlineSecret { .. })),
        "expected InlineSecret error, got {err:?}"
    );
}
