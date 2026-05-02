#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use chio_core::capability::Constraint;
use chio_policy::{compile_policy, HushSpec};

fn compile(yaml: &str) -> chio_policy::CompiledPolicy {
    let spec = match HushSpec::parse(yaml) {
        Ok(spec) => spec,
        Err(error) => panic!("test policy should parse: {error}"),
    };
    match compile_policy(&spec) {
        Ok(compiled) => compiled,
        Err(error) => panic!("test policy should compile: {error}"),
    }
}

fn approval_thresholds(compiled: &chio_policy::CompiledPolicy) -> Vec<u64> {
    compiled
        .default_scope
        .grants
        .iter()
        .flat_map(|grant| grant.constraints.iter())
        .filter_map(|constraint| match constraint {
            Constraint::RequireApprovalAbove { threshold_units } => Some(*threshold_units),
            _ => None,
        })
        .collect()
}

#[test]
fn tool_access_confirmation_glob_overlap_forces_zero_approval_threshold() {
    let compiled = compile(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: ["payments.*"]
    require_confirmation: ["payments.charge"]
    default: block
"#,
    );

    assert_eq!(approval_thresholds(&compiled), vec![0]);
}

#[test]
fn human_in_loop_approval_threshold_applies_when_confirmation_globs_do_not_overlap() {
    let compiled = compile(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: ["calendar.read"]
    default: block
  human_in_loop:
    enabled: true
    require_confirmation: ["payments.*"]
    approve_above: 15000
"#,
    );

    assert_eq!(approval_thresholds(&compiled), vec![15000]);
}

#[test]
fn default_allow_with_security_constraints_fails_closed_to_empty_scope() {
    let compiled = compile(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    default: allow
    max_args_size: 4096
"#,
    );

    assert!(
        compiled.default_scope.grants.is_empty(),
        "default-allow plus security constraints must not widen to wildcard scope"
    );
}
