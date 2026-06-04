use chio_arena::{parse_scenario_str, ScenarioError, ScenarioVerdict};

fn valid_scenario() -> &'static str {
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

[[budgets]]
agent = "agent-a"
server = "filesystem"
tool = "read_file"
max_invocations = 1

[[guards]]
id = "native-allowlist"
mode = "enforce"
config_ref = "guards/native-allowlist.toml"

[[steps]]
id = "step-1"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/chio-arena.txt" }
expect_verdict = "allow"

[[adversaries]]
class = "walking-skeleton"
population = "none"
seed_ref = "none"

[ext]
owner = "m08"
"#
}

#[test]
fn parses_valid_scenario_and_extracts_witness() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(valid_scenario())?;
    assert_eq!(scenario.id, "walking_skeleton");
    assert_eq!(scenario.steps[0].expect_verdict, ScenarioVerdict::Allow);

    let witness = scenario.determinism_witness();
    assert_eq!(witness.rng_seed, 42);
    assert_eq!(witness.virtual_clock_start, "2026-04-30T00:00:00.000Z");
    assert_eq!(witness.agents, vec!["agent-a"]);
    assert_eq!(witness.steps, vec!["step-1"]);
    Ok(())
}

#[test]
fn rejects_unknown_top_level_fields() {
    let input = valid_scenario().replace("[ext]", "unexpected = true\n\n[ext]");
    let err = parse_scenario_str(&input).err();
    assert!(matches!(err, Some(ScenarioError::Toml(_))));
}

#[test]
fn rejects_unknown_major_schema_version() {
    let input = valid_scenario().replace("chio.arena.scenario/v1", "chio.arena.scenario/v2");
    let err = parse_scenario_str(&input).err();
    assert!(matches!(
        err,
        Some(ScenarioError::UnsupportedSchemaVersion(_))
    ));
}

#[test]
fn rejects_missing_rng_seed() {
    let input = valid_scenario().replace("rng_seed = 42\n", "");
    let err = parse_scenario_str(&input).err();
    assert!(matches!(err, Some(ScenarioError::Toml(_))));
}

#[test]
fn rejects_witness_mismatch() {
    let input = valid_scenario().replacen("rng_seed = 42", "rng_seed = 41", 1);
    let err = parse_scenario_str(&input).err();
    assert!(matches!(
        err,
        Some(ScenarioError::WitnessMismatch { field: "rng_seed" })
    ));
}

#[test]
fn rejects_unknown_budget_agent() {
    // Replacing every `agent = "agent-a"` flips both the [[budgets]] and
    // [[steps]] entries; budget validation runs first so the surfaced error
    // is UnknownBudgetAgent. This guards the budget-side path.
    let input = valid_scenario().replace("agent = \"agent-a\"", "agent = \"agent-b\"");
    let err = parse_scenario_str(&input).err();
    assert!(matches!(
        err,
        Some(ScenarioError::UnknownBudgetAgent { .. })
    ));
}

#[test]
fn rejects_unknown_step_agent() {
    // Only flip the agent inside [[steps]] so budgets remain valid. Without
    // this scoping the step-level validation never fires because
    // UnknownBudgetAgent would mask it, leaving UnknownStepAgent uncovered.
    let mut input = valid_scenario().to_owned();
    let steps_marker = "[[steps]]\nid = \"step-1\"\nagent = \"agent-a\"";
    let replacement = "[[steps]]\nid = \"step-1\"\nagent = \"agent-b\"";
    let Some(position) = input.find(steps_marker) else {
        panic!("valid_scenario must contain the [[steps]] marker");
    };
    input.replace_range(position..position + steps_marker.len(), replacement);
    let err = parse_scenario_str(&input).err();
    assert!(
        matches!(err, Some(ScenarioError::UnknownStepAgent { .. })),
        "expected UnknownStepAgent, got {err:?}",
    );
}

#[test]
fn rejects_duplicate_guard_ids() {
    let input = valid_scenario().replace(
        "[[steps]]",
        "[[guards]]\nid = \"native-allowlist\"\nmode = \"observe\"\nconfig_ref = \"guards/duplicate.toml\"\n\n[[steps]]",
    );
    let err = parse_scenario_str(&input).err();
    assert!(
        matches!(err, Some(ScenarioError::DuplicateGuard(_))),
        "expected DuplicateGuard, got {err:?}",
    );
}

#[test]
fn rejects_inline_secret_marker() {
    let input = valid_scenario().replace(
        "arguments = { path = \"/tmp/chio-arena.txt\" }",
        "arguments = { api_key = \"sk-test\" }",
    );
    let err = parse_scenario_str(&input).err();
    assert!(matches!(err, Some(ScenarioError::InlineSecret { .. })));
}

#[test]
fn rejects_provider_dependency_marker() {
    let input = valid_scenario().replace("recorded:test-agent", "chio-openai::client");
    let err = parse_scenario_str(&input).err();
    assert!(matches!(
        err,
        Some(ScenarioError::ProviderDependency { .. })
    ));
}
