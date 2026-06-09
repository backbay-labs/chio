#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_policy::models::{DefaultAction, Rules, ToolAccessRule};
use chio_policy::{evaluate, is_hushspec_format, validate, Decision, EvaluationAction, HushSpec};

fn tool_access_spec(
    default: DefaultAction,
    allow: &[&str],
    block: &[&str],
    max_args_size: Option<usize>,
) -> HushSpec {
    HushSpec {
        hushspec: "0.1.0".to_string(),
        name: Some("integration-smoke".to_string()),
        description: Some("integration smoke coverage".to_string()),
        extends: None,
        merge_strategy: None,
        rules: Some(Rules {
            tool_access: Some(ToolAccessRule {
                enabled: true,
                allow: allow.iter().map(|value| (*value).to_string()).collect(),
                block: block.iter().map(|value| (*value).to_string()).collect(),
                require_confirmation: Vec::new(),
                default,
                max_args_size,
                require_runtime_assurance_tier: None,
                prefer_runtime_assurance_tier: None,
                require_workload_identity: None,
                prefer_workload_identity: None,
            }),
            ..Rules::default()
        }),
        extensions: None,
        metadata: None,
    }
}

#[test]
fn hushspec_allows_listed_tool_call_after_yaml_round_trip() {
    let spec = tool_access_spec(DefaultAction::Block, &["research.lookup"], &[], None);
    let yaml = spec.to_yaml().expect("serialize hushspec");
    assert!(is_hushspec_format(&yaml));

    let parsed = HushSpec::parse(&yaml).expect("parse hushspec");
    let validation = validate(&parsed);
    assert!(validation.is_valid());

    let result = evaluate(
        &parsed,
        &EvaluationAction {
            action_type: "tool_call".to_string(),
            target: Some("research.lookup".to_string()),
            ..EvaluationAction::default()
        },
    );

    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn hushspec_denies_blocked_tool_call() {
    let spec = tool_access_spec(
        DefaultAction::Allow,
        &["research.lookup"],
        &["admin.delete"],
        None,
    );

    let result = evaluate(
        &spec,
        &EvaluationAction {
            action_type: "tool_call".to_string(),
            target: Some("admin.delete".to_string()),
            ..EvaluationAction::default()
        },
    );

    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(
        result.matched_rule.as_deref(),
        Some("rules.tool_access.block")
    );
}

#[test]
fn validation_rejects_zero_max_args_size_edge_case() {
    let spec = tool_access_spec(DefaultAction::Allow, &["research.lookup"], &[], Some(0));
    let validation = validate(&spec);

    assert!(!validation.is_valid());
    assert!(validation
        .errors
        .iter()
        .any(|error| error.to_string().contains("max_args_size")));
}
