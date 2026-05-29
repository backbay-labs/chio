//! `rules.human_in_loop` first-class variant tests.
//!
//! `Rules::human_in_loop` compiles to
//! `Constraint::RequireApprovalAbove { threshold_units }` on tool grants.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::capability::Constraint;
use chio_policy::models::HumanInLoopTimeoutAction;
use chio_policy::{compile_policy, HushSpec};

fn rule(yaml: &str) -> HushSpec {
    HushSpec::parse(yaml).expect("parse hushspec")
}

#[test]
fn human_in_loop_parses_full_shape() {
    let spec = rule(
        r#"
hushspec: "0.1.0"
rules:
  human_in_loop:
    enabled: true
    require_confirmation:
      - "write_*"
      - "shell_*"
    approve_above: 15000
    approve_above_currency: "USD"
    timeout_seconds: 900
    on_timeout: deny
"#,
    );
    let hil = spec
        .rules
        .as_ref()
        .and_then(|r| r.human_in_loop.as_ref())
        .expect("human_in_loop rule");
    assert!(hil.enabled);
    assert_eq!(hil.require_confirmation, vec!["write_*", "shell_*"]);
    assert_eq!(hil.approve_above, Some(15000));
    assert_eq!(hil.approve_above_currency.as_deref(), Some("USD"));
    assert_eq!(hil.timeout_seconds, Some(900));
    assert_eq!(hil.on_timeout, HumanInLoopTimeoutAction::Deny);
}

#[test]
fn human_in_loop_defaults() {
    let spec = rule(
        r#"
hushspec: "0.1.0"
rules:
  human_in_loop:
    approve_above: 10000
"#,
    );
    let hil = spec
        .rules
        .as_ref()
        .and_then(|r| r.human_in_loop.as_ref())
        .expect("human_in_loop rule");
    assert!(hil.enabled, "enabled defaults to true");
    assert_eq!(hil.on_timeout, HumanInLoopTimeoutAction::Deny);
    assert!(hil.require_confirmation.is_empty());
}

#[test]
fn human_in_loop_defer_timeout_parses() {
    let spec = rule(
        r#"
hushspec: "0.1.0"
rules:
  human_in_loop:
    approve_above: 100
    on_timeout: defer
"#,
    );
    let hil = spec
        .rules
        .as_ref()
        .and_then(|r| r.human_in_loop.as_ref())
        .expect("human_in_loop rule");
    assert_eq!(hil.on_timeout, HumanInLoopTimeoutAction::Defer);
}

#[test]
fn human_in_loop_rejects_unknown_fields() {
    let parsed = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  human_in_loop:
    approve_above_usd: 150
"#,
    );
    let err = parsed.expect_err("unknown human_in_loop field should fail");
    assert!(
        err.to_string().contains("approve_above_usd") || err.to_string().contains("unknown field"),
        "unexpected error: {err}"
    );
}

#[test]
fn human_in_loop_approve_above_emits_require_approval_above() {
    let spec = rule(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: ["payments.charge"]
    default: block
  human_in_loop:
    enabled: true
    approve_above: 15000
    approve_above_currency: "USD"
"#,
    );
    let compiled = compile_policy(&spec).expect("compile should succeed");
    assert_eq!(compiled.default_scope.grants.len(), 1);
    let grant = &compiled.default_scope.grants[0];
    assert!(
        grant.constraints.iter().any(|c| matches!(
            c,
            Constraint::RequireApprovalAbove {
                threshold_units: 15000
            }
        )),
        "expected RequireApprovalAbove {{ threshold_units: 15000 }}, got {:?}",
        grant.constraints
    );
}

#[test]
fn human_in_loop_require_confirmation_forces_threshold_zero() {
    let spec = rule(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: ["shell_exec"]
    default: block
  human_in_loop:
    enabled: true
    require_confirmation: ["shell_*"]
    approve_above: 50000
"#,
    );
    let compiled = compile_policy(&spec).expect("compile should succeed");
    let grant = &compiled.default_scope.grants[0];
    assert!(
        grant
            .constraints
            .iter()
            .any(|c| matches!(c, Constraint::RequireApprovalAbove { threshold_units: 0 })),
        "require_confirmation glob match should override approve_above to 0; got {:?}",
        grant.constraints
    );
}

#[test]
fn human_in_loop_disabled_emits_no_constraint() {
    let spec = rule(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: ["payments.charge"]
    default: block
  human_in_loop:
    enabled: false
    approve_above: 15000
"#,
    );
    let compiled = compile_policy(&spec).expect("compile should succeed");
    let grant = &compiled.default_scope.grants[0];
    assert!(
        !grant
            .constraints
            .iter()
            .any(|c| matches!(c, Constraint::RequireApprovalAbove { .. })),
        "disabled human_in_loop should not emit approval constraints; got {:?}",
        grant.constraints
    );
}

#[test]
fn human_in_loop_without_thresholds_emits_no_constraint() {
    let spec = rule(
        r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: ["read_file"]
    default: block
  human_in_loop:
    enabled: true
"#,
    );
    let compiled = compile_policy(&spec).expect("compile should succeed");
    let grant = &compiled.default_scope.grants[0];
    assert!(
        !grant
            .constraints
            .iter()
            .any(|c| matches!(c, Constraint::RequireApprovalAbove { .. })),
        "bare human_in_loop with no thresholds should not emit constraints; got {:?}",
        grant.constraints
    );
}
