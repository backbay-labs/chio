//! Replay-attempt adversary class tests (`M08.P3.T4`).
//!
//! Crosses into trajectory-1 M04's `replay_attack` fixture family. The
//! arena adversary class consumes the same nonce-reuse pattern names the
//! family encodes (`immediate-reuse`, `delayed-reuse`, `stale-nonce`,
//! `concurrent-reuse`) and asserts fail-closed via the toy guard
//! evaluator. The unit test does not reread the M04 JSON fixtures; the M04
//! `chio replay` engine remains the source of truth for those bytes.

use chio_arena::adversary::replay_attempt::{REASON, REPLAYED_NONCE_KEY, REPLAY_PATTERNS};
use chio_arena::{
    evaluate_against_guards, parse_scenario_str, population_from_block, AdversaryClass,
    IssuedScope, ScenarioVerdict,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;

const CAPTURED_NONCE: &str = "nonce-feed-cafe";

fn scenario_str() -> String {
    format!(
        r#"
schema_version = "chio.arena.scenario/v1"
id = "replay_attempt_unit"
title = "Replay attempt unit"
rng_seed = 17
virtual_clock_start = "2026-04-30T00:00:00.000Z"

[determinism]
rng_seed = 17
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
arguments = {{ path = "/tmp/x.txt" }}
expect_verdict = "allow"

[[adversaries]]
class = "replay-attempt"
population = "default"
seed_ref = "tests/replay/fixtures/replay_attack"

[adversaries.params]
nonce = "{CAPTURED_NONCE}"
"#
    )
}

#[test]
fn each_pattern_denied_when_nonce_seen() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(&scenario_str())?;
    let mut population = population_from_block(&scenario.adversaries[0])?;
    assert_eq!(population.class(), AdversaryClass::ReplayAttempt);
    assert_eq!(population.len(), REPLAY_PATTERNS.len());

    let mut seen = BTreeMap::new();
    seen.insert(CAPTURED_NONCE.to_string(), ());
    let issued = IssuedScope {
        server: "filesystem".to_string(),
        tool: "read_file".to_string(),
        seen_nonces: seen,
        revoked: false,
    };

    let base_step = scenario.steps[0].clone();
    let mut rng = ChaCha20Rng::seed_from_u64(scenario.rng_seed);
    for _ in 0..population.len() {
        let action = population.next_action(&base_step, &mut rng);
        let evaluation = evaluate_against_guards(&action, &issued);
        assert_eq!(action.expected_verdict, ScenarioVerdict::Deny);
        assert_eq!(evaluation.verdict, ScenarioVerdict::Deny);
        assert_eq!(evaluation.reason, REASON);
        let nonce = action
            .mutated_step
            .arguments
            .get(REPLAYED_NONCE_KEY)
            .and_then(|value| value.as_str());
        assert_eq!(nonce, Some(CAPTURED_NONCE));
    }
    Ok(())
}

#[test]
fn revoked_capability_triggers_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(&scenario_str())?;
    let mut population = population_from_block(&scenario.adversaries[0])?;
    let issued = IssuedScope {
        server: "filesystem".to_string(),
        tool: "read_file".to_string(),
        seen_nonces: BTreeMap::new(),
        revoked: true,
    };
    let base_step = scenario.steps[0].clone();
    let mut rng = ChaCha20Rng::seed_from_u64(99);
    let action = population.next_action(&base_step, &mut rng);
    let evaluation = evaluate_against_guards(&action, &issued);
    assert_eq!(evaluation.verdict, ScenarioVerdict::Deny);
    assert_eq!(evaluation.reason, REASON);
    Ok(())
}

#[test]
fn fresh_nonce_against_clean_kernel_is_allowed() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(&scenario_str())?;
    let mut population = population_from_block(&scenario.adversaries[0])?;
    // The kernel has no record of the captured nonce yet; the toy
    // evaluator returns Allow. This confirms the adversary triggers the
    // replay property, not a hardcoded Deny.
    let issued = IssuedScope::allow("filesystem", "read_file");
    let base_step = scenario.steps[0].clone();
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let action = population.next_action(&base_step, &mut rng);
    let evaluation = evaluate_against_guards(&action, &issued);
    assert_eq!(evaluation.verdict, ScenarioVerdict::Allow);
    Ok(())
}

#[test]
fn missing_nonce_param_rejected() {
    let mut bad_scenario = scenario_str();
    bad_scenario = bad_scenario.replace(
        "[adversaries.params]",
        "[adversaries.params]\n# nonce missing",
    );
    bad_scenario = bad_scenario.replace(&format!("nonce = \"{CAPTURED_NONCE}\""), "");
    // parse succeeds (params optional in DSL); population_from_block fails
    let scenario = match chio_arena::parse_scenario_str(&bad_scenario) {
        Ok(scenario) => scenario,
        Err(error) => panic!("scenario should parse without nonce param: {error}"),
    };
    let err = population_from_block(&scenario.adversaries[0]).err();
    assert!(
        matches!(
            err,
            Some(chio_arena::AdversaryError::MissingParameter {
                parameter: "nonce",
                ..
            })
        ),
        "expected MissingParameter(nonce), got {err:?}"
    );
}
