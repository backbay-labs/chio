use chio_arena::{parse_scenario_str, DeterministicScheduler};

fn three_agent_scenario_toml() -> &'static str {
    r#"
schema_version = "chio.arena.scenario/v1"
id = "three_agent_triangle"
title = "Three agents triangular delegation"
rng_seed = 7
virtual_clock_start = "2026-04-30T00:00:00.000Z"

[determinism]
rng_seed = 7
virtual_clock_start = "2026-04-30T00:00:00.000Z"
scheduler = "deterministic-multi-v1"
locale = "C"

[[agents]]
id = "agent-a"
role = "operator"
model = "recorded:test-agent"
seed_prompt_ref = "prompts/a.txt"

[[agents]]
id = "agent-b"
role = "operator"
model = "recorded:test-agent"
seed_prompt_ref = "prompts/b.txt"

[[agents]]
id = "agent-c"
role = "operator"
model = "recorded:test-agent"
seed_prompt_ref = "prompts/c.txt"

[[steps]]
id = "step-1"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/a-1.txt" }
expect_verdict = "allow"

[[steps]]
id = "step-2"
agent = "agent-b"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/b-1.txt" }
expect_verdict = "allow"

[[steps]]
id = "step-3"
agent = "agent-c"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/c-1.txt" }
expect_verdict = "allow"

[[steps]]
id = "step-4"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/a-2.txt" }
expect_verdict = "allow"

[[steps]]
id = "step-5"
agent = "agent-b"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/b-2.txt" }
expect_verdict = "allow"
"#
}

#[test]
fn schedule_is_byte_identical_between_runs() -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(three_agent_scenario_toml())?;
    let first = DeterministicScheduler::from_scenario(&scenario)?;
    let second = DeterministicScheduler::from_scenario(&scenario)?;
    assert_eq!(first.schedule(), second.schedule());
    Ok(())
}

#[test]
fn schedule_orders_by_virtual_time_then_agent_then_intra_step(
) -> Result<(), Box<dyn std::error::Error>> {
    let scenario = parse_scenario_str(three_agent_scenario_toml())?;
    let scheduler = DeterministicScheduler::from_scenario(&scenario)?;
    let schedule = scheduler.schedule();
    assert_eq!(schedule.len(), 5);

    let agent_intra_counts: Vec<(String, u64)> = schedule
        .iter()
        .map(|step| (step.agent_id.clone(), step.intra_agent_step))
        .collect();
    assert_eq!(
        agent_intra_counts,
        vec![
            ("agent-a".to_string(), 0),
            ("agent-b".to_string(), 0),
            ("agent-c".to_string(), 0),
            ("agent-a".to_string(), 1),
            ("agent-b".to_string(), 1),
        ]
    );

    // Virtual time must be strictly monotonic.
    for window in schedule.windows(2) {
        assert!(window[0].virtual_time < window[1].virtual_time);
    }
    Ok(())
}

#[test]
fn schedule_byte_serialization_is_canonical() -> Result<(), Box<dyn std::error::Error>> {
    // Exercise byte-level equality on a string formatted from the schedule.
    let scenario = parse_scenario_str(three_agent_scenario_toml())?;
    let a = DeterministicScheduler::from_scenario(&scenario)?;
    let b = DeterministicScheduler::from_scenario(&scenario)?;
    let render_a: Vec<String> = a
        .schedule()
        .iter()
        .map(|step| {
            format!(
                "{}:{}:{}",
                step.virtual_time, step.agent_id, step.intra_agent_step
            )
        })
        .collect();
    let render_b: Vec<String> = b
        .schedule()
        .iter()
        .map(|step| {
            format!(
                "{}:{}:{}",
                step.virtual_time, step.agent_id, step.intra_agent_step
            )
        })
        .collect();
    assert_eq!(render_a, render_b);
    Ok(())
}
