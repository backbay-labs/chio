#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use chio_policy::{
    analyze_against, evaluate, AnalysisOptions, Decision, EvaluationAction, FindingKind, HushSpec,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 32 * 1024;
const PAIR_SEPARATOR: &str = "\n---CHIO-POLICY-PAIR---\n";

#[derive(Arbitrary, Debug)]
struct PolicyPair {
    old_pattern: u8,
    new_pattern: u8,
    old_default_allow: bool,
    new_default_allow: bool,
    old_block: bool,
    new_block: bool,
}

fn selected_pattern(selector: u8) -> &'static str {
    const PATTERNS: &[&str] = &[
        "repo.read",
        "repo.write",
        "repo.*",
        "repo.**",
        "admin.?",
        "*",
        "**",
    ];
    PATTERNS[usize::from(selector) % PATTERNS.len()]
}

fn policy_yaml(pattern: &str, default_allow: bool, block: bool) -> String {
    let default = if default_allow { "allow" } else { "block" };
    let (allow, block) = if block {
        ("[]".to_string(), format!("['{pattern}']"))
    } else {
        (format!("['{pattern}']"), "[]".to_string())
    };
    format!(
        "hushspec: '0.1.0'\nrules:\n  tool_access:\n    enabled: true\n    allow: {allow}\n    block: {block}\n    default: {default}\n"
    )
}

fn confirm_witness(new: &HushSpec, old: &HushSpec, report: &chio_policy::AnalysisReport) {
    for finding in &report.findings {
        if finding.kind != FindingKind::RefinementFailure {
            continue;
        }
        let Some(witness) = &finding.witness else {
            panic!("refinement failure must carry a witness");
        };
        let action = EvaluationAction {
            action_type: witness.action_type.clone(),
            target: Some(witness.target.clone()),
            content: witness.content.clone(),
            origin: None,
            posture: None,
            args_size: witness.args_size,
            runtime_attestation: None,
        };
        assert_ne!(evaluate(new, &action).decision, Decision::Deny);
        assert_eq!(evaluate(old, &action).decision, Decision::Deny);
    }
}

fn exercise(old_yaml: &str, new_yaml: &str) {
    let (Ok(old), Ok(new)) = (HushSpec::parse(old_yaml), HushSpec::parse(new_yaml)) else {
        return;
    };
    let options = AnalysisOptions {
        max_atoms: 256,
        max_pattern_chars: 256,
        max_automaton_states: 4_096,
        max_automaton_transitions: 16_384,
    };
    if let Ok(report) = analyze_against(&new, &old, options) {
        confirm_witness(&new, &old, &report);
    }
}

fn exercise_raw(data: &[u8]) {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Some((old, new)) = text.split_once(PAIR_SEPARATOR) {
        exercise(old, new);
    }
}

fuzz_target!(|data: &[u8]| {
    exercise_raw(data);

    let mut unstructured = Unstructured::new(data);
    if let Ok(pair) = PolicyPair::arbitrary(&mut unstructured) {
        let old = policy_yaml(
            selected_pattern(pair.old_pattern),
            pair.old_default_allow,
            pair.old_block,
        );
        let new = policy_yaml(
            selected_pattern(pair.new_pattern),
            pair.new_default_allow,
            pair.new_block,
        );
        exercise(&old, &new);
    }
});
