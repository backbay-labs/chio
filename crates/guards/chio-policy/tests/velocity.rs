//! `rules.velocity` first-class variant tests.
//!
//! `Rules::velocity` carries a dedicated `VelocityRule` struct that compiles
//! to `VelocityGuard` + `AgentVelocityGuard`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_policy::models::{HumanInLoopTimeoutAction, Rules, VelocityRule};
use chio_policy::{compile_policy, compile_policy_with_memory_budget, HushSpec};

fn rule(yaml: &str) -> HushSpec {
    HushSpec::parse(yaml).expect("parse hushspec")
}

#[test]
fn velocity_rule_parses_full_shape() {
    let spec = rule(
        r#"
hushspec: "0.1.0"
rules:
  velocity:
    enabled: true
    max_invocations_per_window: 40
    max_spend_per_window: 50000
    max_requests_per_agent: 30
    max_requests_per_session: 10
    window_secs: 3600
    burst_factor: 1.25
"#,
    );
    let velocity = spec
        .rules
        .as_ref()
        .and_then(|r| r.velocity.as_ref())
        .expect("velocity rule");
    assert!(velocity.enabled);
    assert_eq!(velocity.max_invocations_per_window, Some(40));
    assert_eq!(velocity.max_spend_per_window, Some(50000));
    assert_eq!(velocity.max_requests_per_agent, Some(30));
    assert_eq!(velocity.max_requests_per_session, Some(10));
    assert_eq!(velocity.window_secs, 3600);
    assert!((velocity.burst_factor - 1.25).abs() < f64::EPSILON);
}

#[test]
fn velocity_rule_defaults() {
    let spec = rule(
        r#"
hushspec: "0.1.0"
rules:
  velocity:
    max_invocations_per_window: 60
"#,
    );
    let velocity = spec
        .rules
        .as_ref()
        .and_then(|r| r.velocity.as_ref())
        .expect("velocity rule");
    assert!(velocity.enabled, "enabled defaults to true");
    assert_eq!(velocity.window_secs, 60, "default window_secs is 60");
    assert!(
        (velocity.burst_factor - 1.0).abs() < f64::EPSILON,
        "default burst_factor is 1.0"
    );
}

#[test]
fn velocity_rule_rejects_unknown_fields() {
    let parsed = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  velocity:
    max_calls_per_min: 60
"#,
    );
    let err = parsed.expect_err("unknown velocity field should fail");
    assert!(
        err.to_string().contains("max_calls_per_min") || err.to_string().contains("unknown field"),
        "unexpected error: {err}"
    );
}

#[test]
fn velocity_compile_emits_velocity_and_agent_guards() {
    let spec = rule(
        r#"
hushspec: "0.1.0"
rules:
  velocity:
    max_invocations_per_window: 40
    max_spend_per_window: 50000
    max_requests_per_agent: 20
    window_secs: 3600
"#,
    );
    let compiled = compile_policy(&spec).expect("compile should succeed");
    assert!(
        compiled.guard_names.contains(&"velocity".to_string()),
        "expected velocity guard, got {:?}",
        compiled.guard_names
    );
    assert!(
        compiled.guard_names.contains(&"agent-velocity".to_string()),
        "expected agent-velocity guard, got {:?}",
        compiled.guard_names
    );
}

#[test]
fn velocity_compile_only_invocation_limit() {
    let spec = rule(
        r#"
hushspec: "0.1.0"
rules:
  velocity:
    max_invocations_per_window: 40
    window_secs: 60
"#,
    );
    let compiled = compile_policy(&spec).expect("compile should succeed");
    assert!(compiled.guard_names.contains(&"velocity".to_string()));
    assert!(!compiled.guard_names.contains(&"agent-velocity".to_string()));
}

#[test]
fn velocity_compile_only_agent_limit() {
    let spec = rule(
        r#"
hushspec: "0.1.0"
rules:
  velocity:
    max_requests_per_agent: 25
    window_secs: 60
"#,
    );
    let compiled = compile_policy(&spec).expect("compile should succeed");
    assert!(compiled.guard_names.contains(&"agent-velocity".to_string()));
    assert!(!compiled.guard_names.contains(&"velocity".to_string()));
}

#[test]
fn velocity_disabled_emits_no_guards() {
    let spec = rule(
        r#"
hushspec: "0.1.0"
rules:
  velocity:
    enabled: false
    max_invocations_per_window: 40
"#,
    );
    let compiled = compile_policy(&spec).expect("compile should succeed");
    assert!(!compiled.guard_names.contains(&"velocity".to_string()));
    assert!(!compiled.guard_names.contains(&"agent-velocity".to_string()));
}

#[test]
fn velocity_empty_rule_emits_no_guards() {
    // A `velocity:` block without any limit fields must not wedge an
    // unlimited guard onto the pipeline.
    let spec = rule(
        r#"
hushspec: "0.1.0"
rules:
  velocity: {}
"#,
    );
    let compiled = compile_policy(&spec).expect("compile should succeed");
    assert!(!compiled.guard_names.contains(&"velocity".to_string()));
    assert!(!compiled.guard_names.contains(&"agent-velocity".to_string()));
}

#[test]
fn velocity_guard_precedes_shell_guard() {
    // Insertion point: VelocityGuard + AgentVelocityGuard sit
    // between ForbiddenPathGuard and ShellCommandGuard.
    let spec = rule(
        r#"
hushspec: "0.1.0"
rules:
  forbidden_paths:
    enabled: true
    patterns: ["**/.ssh/**"]
  velocity:
    max_invocations_per_window: 10
    max_requests_per_agent: 5
  shell_commands:
    enabled: true
"#,
    );
    let compiled = compile_policy(&spec).expect("compile should succeed");
    let names: Vec<&str> = compiled.guard_names.iter().map(String::as_str).collect();

    let fp_pos = names
        .iter()
        .position(|n| *n == "forbidden-path")
        .expect("forbidden-path in pipeline");
    let vel_pos = names
        .iter()
        .position(|n| *n == "velocity")
        .expect("velocity in pipeline");
    let agent_pos = names
        .iter()
        .position(|n| *n == "agent-velocity")
        .expect("agent-velocity in pipeline");
    let shell_pos = names
        .iter()
        .position(|n| *n == "shell-command")
        .expect("shell-command in pipeline");

    assert!(fp_pos < vel_pos, "velocity should follow forbidden-path");
    assert!(vel_pos < shell_pos, "velocity should precede shell-command");
    assert!(
        agent_pos < shell_pos,
        "agent-velocity should precede shell-command"
    );
}

#[test]
fn velocity_compile_threads_configured_memory_budget() {
    // The policy-compiled velocity guard must honor the CONFIGURED process memory
    // budget's `velocity_bucket_cap`, not the compiled-in default.
    // `compile_policy_with_memory_budget` threads a lowered budget into
    // `VelocityGuard::from_memory_budget`; here we assert that entry point compiles
    // and still emits the velocity guard with a tightened budget. The
    // cap-is-honored behavior itself is pinned by the guard-level test
    // `from_memory_budget_honors_lowered_velocity_bucket_cap`.
    let spec = rule(
        r#"
hushspec: "0.1.0"
rules:
  velocity:
    max_invocations_per_window: 40
    window_secs: 60
"#,
    );
    let budget = chio_kernel::MemoryBudgetConfig {
        velocity_bucket_cap: 4,
        ..chio_kernel::MemoryBudgetConfig::defaults()
    };
    let compiled = compile_policy_with_memory_budget(&spec, None, &budget)
        .expect("compile with memory budget should succeed");
    assert!(
        compiled.guard_names.contains(&"velocity".to_string()),
        "expected velocity guard, got {:?}",
        compiled.guard_names
    );
}

#[test]
fn velocity_rule_struct_literal_round_trips() {
    // Struct construction sanity: default helpers wire through.
    let rules = Rules {
        velocity: Some(VelocityRule {
            enabled: true,
            max_invocations_per_window: Some(60),
            max_spend_per_window: None,
            max_requests_per_agent: None,
            max_requests_per_session: None,
            window_secs: 60,
            burst_factor: 1.0,
        }),
        ..Rules::default()
    };
    assert!(rules.velocity.is_some());
    // HumanInLoopTimeoutAction::Deny is the default; confirm it exists.
    let _ = HumanInLoopTimeoutAction::default();
}
