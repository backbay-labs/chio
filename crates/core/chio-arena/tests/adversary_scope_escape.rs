//! Scope-superset escape adversary class tests.
//!
//! Triggers the capability algebra scope-monotonicity property: a
//! delegated scope must be a subset of the delegating capability's
//! scope. The toy guard evaluator denies any action whose
//! `delegated_scope` array references a (server, tool) pair outside the
//! issued scope, mirroring the kernel's authority surface.

use chio_arena::adversary::scope_escape::{
    default_escalations, ScopeEscalation, DELEGATED_SCOPE_KEY, REASON,
};
use chio_arena::{
    evaluate_against_guards, parse_scenario_str, population_from_block, Adversary, AdversaryClass,
    IssuedScope, ScenarioVerdict, ScopeEscapeAdversary,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::json;

fn scenario_str() -> &'static str {
    r#"
schema_version = "chio.arena.scenario/v1"
id = "scope_escape_unit"
title = "Scope escape unit"
rng_seed = 23
virtual_clock_start = "2026-04-30T00:00:00.000Z"

[determinism]
rng_seed = 23
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
class = "scope-escape"
population = "default"
seed_ref = "scope-monotone"
"#
}

#[test]
fn every_escalation_denied() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(scenario_str())?;
    let mut population = population_from_block(&scenario.adversaries[0])?;
    assert_eq!(population.class(), AdversaryClass::ScopeEscape);
    assert_eq!(population.len(), default_escalations().len());

    let issued = IssuedScope::allow("filesystem", "read_file");
    let base_step = scenario.steps[0].clone();
    let mut rng = ChaCha20Rng::seed_from_u64(scenario.rng_seed);
    for _ in 0..population.len() {
        let action = population.next_action(&base_step, &mut rng);
        let evaluation = evaluate_against_guards(&action, &issued);
        assert_eq!(action.expected_verdict, ScenarioVerdict::Deny);
        assert_eq!(evaluation.verdict, ScenarioVerdict::Deny);
        assert_eq!(evaluation.reason, REASON);
        // Every action carries a delegated_scope array that escapes the
        // issued scope; the scope-monotone property is what makes it
        // fail-closed.
        let delegated = action
            .mutated_step
            .arguments
            .get(DELEGATED_SCOPE_KEY)
            .and_then(|value| value.as_array());
        let delegated = match delegated {
            Some(array) => array,
            None => panic!("delegated scope array missing"),
        };
        assert!(!delegated.is_empty());
    }
    Ok(())
}

#[test]
fn scope_subset_does_not_trigger_deny() -> Result<(), Box<dyn std::error::Error>> {
    // A "no-op" escalation that delegates exactly the issued scope must NOT
    // trip fail-closed; that proves the adversary class is exercising the
    // monotonicity property, not a hardcoded Deny.
    let adversary = ScopeEscapeAdversary::new(
        "noop",
        ScopeEscalation {
            label: "identity".to_string(),
            server: "filesystem".to_string(),
            tool: "read_file".to_string(),
        },
    );
    let issued = IssuedScope::allow("filesystem", "read_file");
    let base_step = chio_arena::ScenarioStep {
        id: "step-1".to_string(),
        agent: "agent-a".to_string(),
        server: "filesystem".to_string(),
        tool: "read_file".to_string(),
        arguments: json!({"path": "/tmp/x.txt"}),
        expect_verdict: ScenarioVerdict::Allow,
    };
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let action = adversary.act(&base_step, &mut rng);
    let evaluation = evaluate_against_guards(&action, &issued);
    assert_eq!(evaluation.verdict, ScenarioVerdict::Allow);
    Ok(())
}
