use std::time::{Duration, Instant};

use crate::evaluate::{evaluate, glob_matches, Decision, EvaluationAction};
use crate::models::{HushSpec, RULE_BLOCK_NAMES};

use super::*;

fn parse(yaml: &str) -> HushSpec {
    HushSpec::parse(yaml).unwrap_or_else(|error| panic!("fixture must parse: {error}"))
}

fn tool_policy(allow: &[&str], block: &[&str], default: &str) -> HushSpec {
    let list = |values: &[&str]| {
        if values.is_empty() {
            "[]".to_string()
        } else {
            format!(
                "\n{}",
                values
                    .iter()
                    .map(|pattern| format!("      - {pattern:?}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        }
    };
    let allow = list(allow);
    let block = list(block);
    parse(&format!(
        "hushspec: '0.1.0'\nrules:\n  tool_access:\n    enabled: true\n    allow: {allow}\n    block: {block}\n    default: {default}\n"
    ))
}

#[test]
fn lowering_inventory_stays_in_lockstep_with_every_rule_block() {
    let policy = parse(
        "hushspec: '0.1.0'\nrules:\n  secret_patterns:\n    patterns:\n      - name: token\n        pattern: token-[0-9]+\n        severity: error\n",
    );
    let lowered = lower_policy(&policy);
    assert_eq!(lowered.blocks.len(), RULE_BLOCK_NAMES.len());
    assert_eq!(
        lowered
            .blocks
            .iter()
            .map(|block| block.name.as_str())
            .collect::<Vec<_>>(),
        RULE_BLOCK_NAMES
    );
    assert_eq!(lowered.not_analyzed().len(), 1);
    assert_eq!(lowered.not_analyzed()[0].block, "secret_patterns");
}

#[test]
fn configured_tool_preferences_are_reported_as_not_analyzed() {
    let policy = parse(
        "hushspec: '0.1.0'\nrules:\n  tool_access:\n    enabled: true\n    prefer_runtime_assurance_tier: attested\n    prefer_workload_identity:\n      scheme: spiffe\n      trust_domain: prod.chio\n      path_prefixes: ['/payments']\n",
    );
    let report = analyze(&policy, AnalysisOptions::default()).expect("analyze preferences");
    let fields = report
        .not_analyzed
        .iter()
        .map(|notice| notice.field.as_str())
        .collect::<Vec<_>>();
    assert!(fields.contains(&"prefer_runtime_assurance_tier"));
    assert!(fields.contains(&"prefer_workload_identity"));
}

#[test]
fn explicit_universe_makes_a_different_default_contradictory() {
    let bool_atom = |value, effect, field: &str| RuleAtom {
        block: "synthetic".to_string(),
        domain: "flag".to_string(),
        effect,
        matcher: AtomMatcher::BoolFlag { value },
        provenance: RuleRef {
            field: field.to_string(),
            index: 0,
            pattern: value.to_string(),
        },
    };
    let block = LoweredBlock {
        name: "synthetic".to_string(),
        state: BlockState::Active,
        atoms: vec![
            bool_atom(false, AtomEffect::Deny, "deny_false"),
            bool_atom(true, AtomEffect::Deny, "deny_true"),
            RuleAtom {
                block: "synthetic".to_string(),
                domain: "flag".to_string(),
                effect: AtomEffect::Allow,
                matcher: AtomMatcher::Default,
                provenance: RuleRef {
                    field: "default".to_string(),
                    index: 0,
                    pattern: "allow".to_string(),
                },
            },
        ],
    };
    let options = AnalysisOptions::default();
    let mut report = AnalysisReport::new("0".repeat(64));
    let mut counters = std::collections::BTreeMap::new();
    let mut budget = AnalysisBudget::new(options);
    analyze_block(&block, &mut report, &mut counters, options, &mut budget)
        .expect("analyze dead default");
    assert!(report.findings.iter().any(|finding| {
        finding.kind == FindingKind::Contradiction && finding.rule_ref.field == "default"
    }));
}

#[test]
fn glob_default_remains_reachable_for_the_reference_newline_domain() {
    let report = analyze(
        &tool_policy(&["**"], &[], "block"),
        AnalysisOptions::default(),
    )
    .expect("analyze newline-sensitive default");
    assert!(!report.findings.iter().any(|finding| {
        finding.kind == FindingKind::Contradiction && finding.rule_ref.field == "default"
    }));
}

#[test]
fn glob_relations_preserve_reference_matcher_semantics() {
    let options = AnalysisOptions::default();
    assert_eq!(
        glob_relation("mail.send", "mail.*", options).expect("relation"),
        GlobRelation::SubsetOf
    );
    assert_eq!(
        glob_relation("mail.*", "mail.send", options).expect("relation"),
        GlobRelation::SupersetOf
    );
    assert_eq!(
        glob_relation("alpha", "beta", options).expect("relation"),
        GlobRelation::Disjoint
    );
    assert_eq!(
        glob_relation("**", "*", options).expect("relation"),
        GlobRelation::Overlapping
    );

    let patterns = ["", "a", "?", "*", "**", "a/*", "a/**", "*/b"];
    let samples = ["", "a", "b", "/", "\n", "aa", "a/", "a/b", "/b", "a\n"];
    for left in patterns {
        for right in patterns {
            let relation = glob_relation(left, right, options).expect("bounded relation");
            if matches!(relation, GlobRelation::Equal | GlobRelation::SubsetOf) {
                for sample in samples {
                    if glob_matches(left, sample).expect("reference matcher") {
                        assert!(
                            glob_matches(right, sample).expect("reference matcher"),
                            "{left:?} was classified as a subset of {right:?}, but {sample:?} distinguishes them"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn analyzer_detects_duplicate_contradictory_and_shadowed_rules() {
    let duplicate_and_contradictory =
        tool_policy(&["mail.*", "mail.send"], &["mail.send"], "block");
    let report =
        analyze(&duplicate_and_contradictory, AnalysisOptions::default()).expect("analyze policy");
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.kind == FindingKind::UnreachableRule));
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.kind == FindingKind::Contradiction));

    let shadowed = tool_policy(&["mail.send"], &["mail.**"], "block");
    let report = analyze(&shadowed, AnalysisOptions::default()).expect("analyze policy");
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.kind == FindingKind::ShadowedRule));
}

#[test]
fn widening_refinement_carries_an_engine_confirmed_witness() {
    let old = tool_policy(&["repo.read"], &[], "block");
    let new = tool_policy(&["repo.read", "repo.write"], &[], "block");
    let report =
        analyze_against(&new, &old, AnalysisOptions::default()).expect("analyze refinement");
    assert_eq!(
        report.refinement.as_ref().map(|result| result.status),
        Some(RefinementStatus::DoesNotRefine)
    );
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == FindingKind::RefinementFailure)
        .expect("refinement finding");
    let witness = finding.witness.as_ref().expect("refinement witness");
    let action = EvaluationAction {
        action_type: witness.action_type.clone(),
        target: Some(witness.target.clone()),
        content: witness.content.clone(),
        origin: None,
        posture: None,
        args_size: witness.args_size,
        runtime_attestation: None,
    };
    assert_ne!(evaluate(&new, &action).decision, Decision::Deny);
    assert_eq!(evaluate(&old, &action).decision, Decision::Deny);
}

#[test]
fn numeric_widening_uses_a_boundary_witness() {
    let old = parse(
        "hushspec: '0.1.0'\nrules:\n  tool_access:\n    allow: ['repo.*']\n    block: []\n    default: block\n    max_args_size: 10\n",
    );
    let new = parse(
        "hushspec: '0.1.0'\nrules:\n  tool_access:\n    allow: ['repo.*']\n    block: []\n    default: block\n    max_args_size: 20\n",
    );
    let report =
        analyze_against(&new, &old, AnalysisOptions::default()).expect("analyze numeric widening");
    let witness = report
        .findings
        .iter()
        .find_map(|finding| finding.witness.as_ref())
        .expect("numeric witness");
    assert_eq!(witness.args_size, Some(11));
}

#[test]
fn runtime_requirements_make_masked_numeric_widening_inconclusive() {
    let old = parse(
        "hushspec: '0.1.0'\nrules:\n  tool_access:\n    allow: ['repo.*']\n    block: []\n    default: block\n    max_args_size: 10\n    require_runtime_assurance_tier: attested\n",
    );
    let new = parse(
        "hushspec: '0.1.0'\nrules:\n  tool_access:\n    allow: ['repo.*']\n    block: []\n    default: block\n    max_args_size: 20\n    require_runtime_assurance_tier: attested\n",
    );
    let report = analyze_against(&new, &old, AnalysisOptions::default())
        .expect("analyze masked numeric widening");
    assert_eq!(
        report.refinement.as_ref().map(|result| result.status),
        Some(RefinementStatus::Inconclusive)
    );
}

#[test]
fn finite_action_refinement_uses_a_fresh_unlisted_witness() {
    let listed = "['chio.analysis.other', 'remote.clipboard', 'remote.file_transfer', 'remote.audio', 'remote.drive_mapping']";
    let old = parse(&format!(
        "hushspec: '0.1.0'\nrules:\n  computer_use:\n    enabled: true\n    mode: fail_closed\n    allowed_actions: {listed}\n"
    ));
    let new = parse(&format!(
        "hushspec: '0.1.0'\nrules:\n  computer_use:\n    enabled: true\n    mode: observe\n    allowed_actions: {listed}\n"
    ));
    let report = analyze_against(&new, &old, AnalysisOptions::default())
        .expect("analyze finite action widening");
    assert_eq!(
        report.refinement.as_ref().map(|result| result.status),
        Some(RefinementStatus::DoesNotRefine)
    );
    let witness = report
        .findings
        .iter()
        .find_map(|finding| finding.witness.as_ref())
        .expect("finite action witness");
    assert_eq!(witness.action_type, "computer_use");
    assert!(!listed.contains(&witness.target));
}

#[test]
fn removed_forbidden_path_reports_forbidden_path_provenance() {
    let old = parse(
        "hushspec: '0.1.0'\nrules:\n  forbidden_paths:\n    patterns: ['/secret/**']\n    exceptions: []\n",
    );
    let new = parse("hushspec: '0.1.0'\n");
    let report = analyze_against(&new, &old, AnalysisOptions::default())
        .expect("analyze removed forbidden path");
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == FindingKind::RefinementFailure)
        .expect("path refinement finding");
    assert_eq!(finding.block, "forbidden_paths");
}

#[test]
fn metadata_only_change_with_identical_extensions_still_refines() {
    let old = parse("hushspec: '0.1.0'\nname: old\nextensions: {}\n");
    let new = parse("hushspec: '0.1.0'\nname: new\nextensions: {}\n");
    let report = analyze_against(&new, &old, AnalysisOptions::default())
        .expect("analyze metadata-only change");
    assert_eq!(
        report.refinement.as_ref().map(|result| result.status),
        Some(RefinementStatus::Refines)
    );
}

#[test]
fn narrowing_refinement_is_accepted_and_opaque_changes_are_inconclusive() {
    let broad = tool_policy(&["repo.*"], &[], "block");
    let narrow = tool_policy(&["repo.read"], &[], "block");
    let report =
        analyze_against(&narrow, &broad, AnalysisOptions::default()).expect("analyze narrowing");
    assert_eq!(
        report.refinement.as_ref().map(|result| result.status),
        Some(RefinementStatus::Refines)
    );

    let old =
        parse("hushspec: '0.1.0'\nrules:\n  shell_commands:\n    forbidden_patterns: ['rm -rf']\n");
    let new = parse(
        "hushspec: '0.1.0'\nrules:\n  shell_commands:\n    forbidden_patterns: ['rm -rf', 'curl']\n",
    );
    let report = analyze_against(&new, &old, AnalysisOptions::default())
        .expect("analyze unsupported change");
    assert_eq!(
        report.refinement.as_ref().map(|result| result.status),
        Some(RefinementStatus::Inconclusive)
    );
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.kind == FindingKind::AnalysisIncomplete));
}

#[test]
fn analyzer_limits_fail_closed() {
    let policy = tool_policy(&["one", "two"], &[], "block");
    let error = analyze(
        &policy,
        AnalysisOptions {
            max_atoms: 1,
            ..AnalysisOptions::default()
        },
    )
    .expect_err("atom limit");
    assert!(matches!(error, AnalysisError::AtomLimit { .. }));

    let error = glob_relation(
        "oversized",
        "*",
        AnalysisOptions {
            max_pattern_chars: 3,
            ..AnalysisOptions::default()
        },
    )
    .expect_err("pattern limit");
    assert!(matches!(error, AnalysisError::PatternLimit { .. }));

    let error = analyze(
        &tool_policy(&["oversized"], &[], "block"),
        AnalysisOptions {
            max_pattern_chars: 3,
            ..AnalysisOptions::default()
        },
    )
    .expect_err("authored pattern limit");
    assert!(matches!(error, AnalysisError::PatternLimit { .. }));

    let error = glob_relation(
        "a*",
        "b*",
        AnalysisOptions {
            max_automaton_transitions: 1,
            ..AnalysisOptions::default()
        },
    )
    .expect_err("transition limit");
    assert!(matches!(
        error,
        AnalysisError::AutomatonTransitionLimit { .. }
    ));

    let error = glob_relation(
        "a*",
        "b*",
        AnalysisOptions {
            max_automaton_states: 1,
            ..AnalysisOptions::default()
        },
    )
    .expect_err("aggregate state limit");
    assert!(matches!(error, AnalysisError::AutomatonLimit { .. }));

    let old = tool_policy(&["repo.read"], &[], "block");
    let new = tool_policy(&["repo.read", "repo.write"], &[], "block");
    let error = analyze_against(
        &new,
        &old,
        AnalysisOptions {
            max_automaton_states: 2,
            ..AnalysisOptions::default()
        },
    )
    .expect_err("combined state limit");
    assert!(matches!(error, AnalysisError::AutomatonLimit { .. }));
}

#[test]
fn ten_thousand_finite_actions_avoid_quadratic_evaluator_scans() {
    let actions = (0..10_000)
        .map(|index| format!("      - action-{index}"))
        .collect::<Vec<_>>()
        .join("\n");
    let old = parse(&format!(
        "hushspec: '0.1.0'\nrules:\n  computer_use:\n    enabled: true\n    mode: guardrail\n    allowed_actions:\n{actions}\n"
    ));
    let new = parse(
        "hushspec: '0.1.0'\nrules:\n  computer_use:\n    enabled: true\n    mode: observe\n    allowed_actions: []\n",
    );
    let started = Instant::now();
    let report = analyze_against(
        &new,
        &old,
        AnalysisOptions {
            max_atoms: 10_001,
            ..AnalysisOptions::default()
        },
    )
    .expect("analyze finite action sets");
    assert_eq!(
        report.refinement.as_ref().map(|result| result.status),
        Some(RefinementStatus::Refines)
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "10,000 finite actions took {:?}",
        started.elapsed()
    );
}

#[test]
fn thousand_literal_atoms_complete_within_the_product_envelope() {
    let allow = (0..1_000)
        .map(|index| format!("      - tool-{index}"))
        .collect::<Vec<_>>()
        .join("\n");
    let policy = parse(&format!(
        "hushspec: '0.1.0'\nrules:\n  tool_access:\n    enabled: true\n    allow:\n{allow}\n    block: []\n    default: block\n"
    ));
    let started = Instant::now();
    let report = analyze(&policy, AnalysisOptions::default()).expect("analyze 1,000 atoms");
    assert_eq!(report.summary.errors, 0);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "1,000 literal atoms took {:?}",
        started.elapsed()
    );
}

#[test]
fn mixed_wildcard_findings_fail_closed_before_report_expansion() {
    let block = (0..255)
        .map(|_| "      - repo.*")
        .collect::<Vec<_>>()
        .join("\n");
    let policy = parse(&format!(
        "hushspec: '0.1.0'\nrules:\n  tool_access:\n    enabled: true\n    allow: ['repo.*']\n    block:\n{block}\n    default: block\n"
    ));
    let options = AnalysisOptions {
        max_atoms: 256,
        ..AnalysisOptions::default()
    };
    let started = Instant::now();
    let error = analyze(&policy, options).expect_err("finding budget must fail closed");
    assert!(matches!(error, AnalysisError::FindingLimit { .. }));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "mixed wildcard budget took {:?}",
        started.elapsed()
    );
}

#[test]
fn large_mixed_literal_policy_hits_the_aggregate_comparison_budget() {
    let list = |prefix: &str| {
        (0..250)
            .map(|index| format!("      - {prefix}-{index}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let allow = list("allow");
    let block = list("block");
    let policy = parse(&format!(
        "hushspec: '0.1.0'\nrules:\n  tool_access:\n    enabled: true\n    allow:\n{allow}\n    block:\n{block}\n    default: block\n"
    ));
    let options = AnalysisOptions {
        max_atoms: 500,
        ..AnalysisOptions::default()
    };
    let started = Instant::now();
    let error = analyze(&policy, options).expect_err("comparison budget must fail closed");
    assert!(matches!(
        error,
        AnalysisError::MatcherComparisonLimit { .. }
    ));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "mixed literal budget took {:?}",
        started.elapsed()
    );
}

#[test]
fn report_schema_and_thresholds_are_stable() {
    let policy =
        parse("hushspec: '0.1.0'\nrules:\n  shell_commands:\n    forbidden_patterns: ['rm']\n");
    let report = analyze(&policy, AnalysisOptions::default()).expect("analyze policy");
    let value = serde_json::to_value(&report).expect("serialize report");
    assert_eq!(value["schema"], ANALYSIS_SCHEMA);
    assert!(report.has_at_or_above(AnalysisSeverity::Notice));
    assert!(!report.has_at_or_above(AnalysisSeverity::Warning));
}
