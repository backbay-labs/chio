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
fn default_allow_with_representable_security_constraints_emits_constrained_wildcard_scope() {
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

    assert_eq!(compiled.default_scope.grants.len(), 1);
    let grant = &compiled.default_scope.grants[0];
    assert_eq!(grant.server_id, "*");
    assert_eq!(grant.tool_name, "*");
    assert_eq!(grant.constraints, vec![Constraint::MaxArgsSize(4096)]);
}

#[test]
fn default_block_with_overlapping_allow_and_block_list_fails_closed_to_empty_scope() {
    let compiled = compile(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: ["payments.*"]
    block: ["payments.refund"]
    default: block
"#,
    );

    assert!(
        compiled.default_scope.grants.is_empty(),
        "block-list semantics cannot be represented by positive-only default scope grants"
    );
}

#[test]
fn default_block_with_disjoint_allow_and_block_list_preserves_allow_scope() {
    let compiled = compile(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: ["read_file", "build"]
    block: ["deploy_production"]
    default: block
"#,
    );

    let grants: Vec<&str> = compiled
        .default_scope
        .grants
        .iter()
        .map(|grant| grant.tool_name.as_str())
        .collect();
    assert_eq!(grants, vec!["read_file", "build"]);
}

#[test]
fn default_allow_with_human_in_loop_approval_emits_constrained_wildcard_scope() {
    let compiled = compile(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    default: allow
  human_in_loop:
    enabled: true
    approve_above: 15000
"#,
    );

    assert_eq!(compiled.default_scope.grants.len(), 1);
    assert_eq!(compiled.default_scope.grants[0].tool_name, "*");
    assert_eq!(approval_thresholds(&compiled), vec![15000]);
}

#[test]
fn default_allow_with_selective_human_in_loop_confirmation_fails_closed() {
    let compiled = compile(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    default: allow
  human_in_loop:
    enabled: true
    require_confirmation: ["shell_*"]
"#,
    );

    assert!(compiled.default_scope.grants.is_empty());
    assert_eq!(approval_thresholds(&compiled), Vec::<u64>::new());
}

#[test]
fn default_allow_with_global_human_in_loop_confirmation_emits_zero_threshold_wildcard_scope() {
    let compiled = compile(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    default: allow
  human_in_loop:
    enabled: true
    require_confirmation: ["*"]
"#,
    );

    assert_eq!(compiled.default_scope.grants.len(), 1);
    assert_eq!(compiled.default_scope.grants[0].tool_name, "*");
    assert_eq!(approval_thresholds(&compiled), vec![0]);
}
