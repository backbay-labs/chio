//! `extensions.chio` tests.
//!
//! The `chio` slot on `Extensions` carries chio-specific semantics (market
//! hours, signing, k8s namespaces, rollback, expression-based approval) that
//! the Chio kernel does not interpret directly. The kernel accepts the block
//! as passthrough; chio-bridge interprets it.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_policy::{compile_policy, merge, HushSpec};

fn parse(yaml: &str) -> HushSpec {
    HushSpec::parse(yaml).expect("parse hushspec")
}

#[test]
fn chio_extension_market_hours_round_trip() {
    let spec = parse(
        r#"
hushspec: "0.1.0"
extensions:
  chio:
    market_hours:
      tz: "America/New_York"
      open: "09:30"
      close: "16:00"
      days: ["mon", "tue", "wed", "thu", "fri"]
"#,
    );
    let chio = spec
        .extensions
        .as_ref()
        .and_then(|e| e.chio.as_ref())
        .expect("chio extension");
    let market = chio.market_hours.as_ref().expect("market_hours");
    assert_eq!(market.tz, "America/New_York");
    assert_eq!(market.open, "09:30");
    assert_eq!(market.close, "16:00");
    assert_eq!(market.days.len(), 5);
}

#[test]
fn chio_extension_signing_round_trip() {
    let spec = parse(
        r#"
hushspec: "0.1.0"
extensions:
  chio:
    signing:
      algo: "Ed25519"
      required: true
      key_ref: "chio://keys/trader"
"#,
    );
    let chio = spec.extensions.and_then(|e| e.chio).expect("chio");
    let signing = chio.signing.expect("signing");
    assert_eq!(signing.algo, "Ed25519");
    assert!(signing.required);
    assert_eq!(signing.key_ref.as_deref(), Some("chio://keys/trader"));
}

#[test]
fn chio_extension_k8s_namespaces_round_trip() {
    let spec = parse(
        r#"
hushspec: "0.1.0"
extensions:
  chio:
    k8s_namespaces:
      allow: ["dev", "staging"]
      human_in_loop: ["prod-canary"]
      deny: ["prod"]
"#,
    );
    let chio = spec.extensions.and_then(|e| e.chio).expect("chio");
    let ns = chio.k8s_namespaces.expect("k8s_namespaces");
    assert_eq!(ns.allow, vec!["dev", "staging"]);
    assert_eq!(ns.human_in_loop, vec!["prod-canary"]);
    assert_eq!(ns.deny, vec!["prod"]);
}

#[test]
fn chio_extension_rollback_round_trip() {
    let spec = parse(
        r#"
hushspec: "0.1.0"
extensions:
  chio:
    rollback:
      on_guard_fail: true
      on_timeout: false
      strategy: "reverse-diff"
"#,
    );
    let chio = spec.extensions.and_then(|e| e.chio).expect("chio");
    let rb = chio.rollback.expect("rollback");
    assert!(rb.on_guard_fail);
    assert!(!rb.on_timeout);
    assert_eq!(rb.strategy.as_deref(), Some("reverse-diff"));
}

#[test]
fn chio_extension_human_in_loop_advanced_round_trip() {
    let spec = parse(
        r#"
hushspec: "0.1.0"
extensions:
  chio:
    human_in_loop:
      approve_when:
        - "tool == 'ticket.refund' and amount > 10000"
      approvers:
        n: 2
        of: ["alice", "bob", "carol"]
        timeout_seconds: 1800
"#,
    );
    let chio = spec.extensions.and_then(|e| e.chio).expect("chio");
    let hil = chio.human_in_loop.expect("chio hil");
    assert_eq!(hil.approve_when.len(), 1);
    let approvers = hil.approvers.expect("approvers");
    assert_eq!(approvers.n, 2);
    assert_eq!(approvers.of.len(), 3);
    assert_eq!(approvers.timeout_seconds, Some(1800));
}

#[test]
fn chio_extension_rejects_unknown_fields() {
    let parsed = HushSpec::parse(
        r#"
hushspec: "0.1.0"
extensions:
  chio:
    unknown_thing: true
"#,
    );
    let err = parsed.expect_err("unknown chio field should fail");
    assert!(
        err.to_string().contains("unknown_thing") || err.to_string().contains("unknown field"),
        "unexpected error: {err}"
    );
}

#[test]
fn chio_extension_is_passthrough_not_compiled() {
    // The Chio kernel does not interpret `extensions.chio`; compilation
    // must still succeed without producing extra guards.
    let spec = parse(
        r#"
hushspec: "0.1.0"
extensions:
  chio:
    market_hours:
      tz: "UTC"
      open: "00:00"
      close: "23:59"
      days: ["mon","tue","wed","thu","fri","sat","sun"]
    signing:
      algo: "Ed25519"
      required: true
"#,
    );
    let compiled = compile_policy(&spec).expect("compile");
    assert!(
        compiled.guards.is_empty(),
        "chio extension should not emit guards; got {:?}",
        compiled.guard_names
    );
}

#[test]
fn chio_extension_merge_preserves_base_fields_when_child_adds_signing() {
    let base = parse(
        r#"
hushspec: "0.1.0"
extensions:
  chio:
    market_hours:
      tz: "America/New_York"
      open: "09:30"
      close: "16:00"
      days: ["mon", "tue", "wed", "thu", "fri"]
    rollback:
      on_guard_fail: true
      on_timeout: false
      strategy: "reverse-diff"
"#,
    );
    let child = parse(
        r#"
hushspec: "0.1.0"
extensions:
  chio:
    signing:
      algo: "Ed25519"
      required: true
      key_ref: "chio://keys/trader"
"#,
    );

    let merged = merge(&base, &child);
    let Some(chio) = merged
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.chio.as_ref())
    else {
        unreachable!("merged policy should contain chio extension");
    };

    assert_eq!(
        chio.market_hours
            .as_ref()
            .map(|market| market.open.as_str()),
        Some("09:30")
    );
    assert_eq!(
        chio.rollback
            .as_ref()
            .and_then(|rollback| rollback.strategy.as_deref()),
        Some("reverse-diff")
    );
    assert_eq!(
        chio.signing.as_ref().map(|signing| signing.algo.as_str()),
        Some("Ed25519")
    );
}
