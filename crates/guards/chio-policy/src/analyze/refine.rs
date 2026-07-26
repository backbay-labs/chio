use std::collections::{BTreeMap, BTreeSet};

use crate::evaluate::{evaluate, Decision, EvaluationAction};
use crate::models::{
    ComputerUseMode, DefaultAction, HushSpec, InputInjectionRule, RemoteDesktopChannelsRule, Rules,
};

use super::glob::{find_combined_witness, GlobAutomaton};
use super::report::{RefinementSummary, RuleRef, Witness};
use super::{
    push_finding, AnalysisBudget, AnalysisError, AnalysisOptions, AnalysisReport, AnalysisSeverity,
    FindingDraft, FindingKind, RefinementStatus,
};

#[derive(Default)]
struct PatternCollector {
    patterns: Vec<String>,
}

impl PatternCollector {
    fn add(&mut self, patterns: &[String]) -> Vec<usize> {
        let start = self.patterns.len();
        self.patterns.extend(patterns.iter().cloned());
        (start..self.patterns.len()).collect()
    }

    fn compile(&self, options: AnalysisOptions) -> Result<Vec<GlobAutomaton>, AnalysisError> {
        self.patterns
            .iter()
            .map(|pattern| GlobAutomaton::compile(pattern, options.max_pattern_chars))
            .collect()
    }
}

#[derive(Default)]
struct ListDecision {
    active: bool,
    allow: Vec<usize>,
    block: Vec<usize>,
    default_allow: bool,
}

impl ListDecision {
    fn admits(&self, matches: &[bool]) -> bool {
        if !self.active {
            return true;
        }
        if self.block.iter().any(|&index| matches[index]) {
            return false;
        }
        if self.allow.iter().any(|&index| matches[index]) {
            return true;
        }
        self.default_allow
    }
}

#[derive(Default)]
struct PathDecision {
    forbidden_active: bool,
    forbidden: Vec<usize>,
    exceptions: Vec<usize>,
    allowlist_active: bool,
    allowed: Vec<usize>,
}

impl PathDecision {
    fn admits(&self, matches: &[bool]) -> bool {
        let exception = self.exceptions.iter().any(|&index| matches[index]);
        if self.forbidden_active && !exception && self.forbidden.iter().any(|&index| matches[index])
        {
            return false;
        }
        !self.allowlist_active || self.allowed.iter().any(|&index| matches[index])
    }
}

#[derive(Clone, Copy)]
enum ListDomain {
    Tool,
    Egress,
}

impl ListDomain {
    fn decision(self, rules: Option<&Rules>, collector: &mut PatternCollector) -> ListDecision {
        match self {
            Self::Tool => {
                let Some(rule) = rules.and_then(|rules| rules.tool_access.as_ref()) else {
                    return ListDecision::default();
                };
                ListDecision {
                    active: rule.enabled,
                    allow: collector.add(&rule.allow),
                    block: collector.add(&rule.block),
                    default_allow: rule.default == DefaultAction::Allow,
                }
            }
            Self::Egress => {
                let Some(rule) = rules.and_then(|rules| rules.egress.as_ref()) else {
                    return ListDecision::default();
                };
                ListDecision {
                    active: rule.enabled,
                    allow: collector.add(&rule.allow),
                    block: collector.add(&rule.block),
                    default_allow: rule.default == DefaultAction::Allow,
                }
            }
        }
    }

    const fn action_type(self) -> &'static str {
        match self {
            Self::Tool => "tool_call",
            Self::Egress => "egress",
        }
    }

    const fn block(self) -> &'static str {
        match self {
            Self::Tool => "tool_access",
            Self::Egress => "egress",
        }
    }
}

#[derive(Clone, Copy)]
enum PathOperation {
    Read,
    Write,
    Patch,
}

fn path_decision(
    rules: Option<&Rules>,
    operation: PathOperation,
    collector: &mut PatternCollector,
) -> PathDecision {
    let Some(rules) = rules else {
        return PathDecision::default();
    };
    let mut decision = PathDecision::default();
    if let Some(rule) = &rules.forbidden_paths {
        decision.forbidden_active = rule.enabled;
        decision.forbidden = collector.add(&rule.patterns);
        decision.exceptions = collector.add(&rule.exceptions);
    }
    if let Some(rule) = &rules.path_allowlist {
        decision.allowlist_active = rule.enabled;
        let patterns = match operation {
            PathOperation::Read => &rule.read,
            PathOperation::Write => &rule.write,
            PathOperation::Patch if rule.patch.is_empty() => &rule.write,
            PathOperation::Patch => &rule.patch,
        };
        decision.allowed = collector.add(patterns);
    }
    decision
}

fn action(witness: &Witness) -> EvaluationAction {
    EvaluationAction {
        action_type: witness.action_type.clone(),
        target: Some(witness.target.clone()),
        content: witness.content.clone(),
        origin: None,
        posture: None,
        args_size: witness.args_size,
        runtime_attestation: None,
    }
}

fn forbidden_path_matches(policy: &HushSpec, target: &str) -> (bool, bool) {
    let Some(rule) = policy
        .rules
        .as_ref()
        .and_then(|rules| rules.forbidden_paths.as_ref())
        .filter(|rule| rule.enabled)
    else {
        return (false, false);
    };
    let pattern = rule
        .patterns
        .iter()
        .any(|pattern| crate::evaluate::glob_matches(pattern, target).unwrap_or(false));
    let exception = rule
        .exceptions
        .iter()
        .any(|pattern| crate::evaluate::glob_matches(pattern, target).unwrap_or(false));
    (pattern, exception)
}

fn confirms(
    policy: &HushSpec,
    against: &HushSpec,
    witness: &Witness,
    budget: &mut AnalysisBudget,
) -> Result<bool, AnalysisError> {
    budget.consume_evaluator_confirmation()?;
    Ok(
        evaluate(policy, &action(witness)).decision != Decision::Deny
            && evaluate(against, &action(witness)).decision == Decision::Deny,
    )
}

fn search_list_witness(
    policy: &HushSpec,
    against: &HushSpec,
    options: AnalysisOptions,
    domain: ListDomain,
    args_size: Option<usize>,
    compare_pattern_admission: bool,
    budget: &mut AnalysisBudget,
) -> Result<Option<(String, Witness)>, AnalysisError> {
    let mut collector = PatternCollector::default();
    let new = domain.decision(policy.rules.as_ref(), &mut collector);
    let old = domain.decision(against.rules.as_ref(), &mut collector);
    let automata = collector.compile(options)?;
    let witness = find_combined_witness(&automata, budget, |matches, target, budget| {
        if !new.admits(matches) || (compare_pattern_admission && old.admits(matches)) {
            return Ok(false);
        }
        let witness = Witness {
            action_type: domain.action_type().to_string(),
            target: target.to_string(),
            args_size,
            content: None,
        };
        confirms(policy, against, &witness, budget)
    })?;
    Ok(witness.map(|target| {
        (
            domain.block().to_string(),
            Witness {
                action_type: domain.action_type().to_string(),
                target,
                args_size,
                content: None,
            },
        )
    }))
}

fn search_path_witness(
    policy: &HushSpec,
    against: &HushSpec,
    options: AnalysisOptions,
    operation: PathOperation,
    budget: &mut AnalysisBudget,
) -> Result<Option<(String, Witness)>, AnalysisError> {
    let action_type = match operation {
        PathOperation::Read => "file_read",
        PathOperation::Write => "file_write",
        PathOperation::Patch => "patch_apply",
    };
    let mut collector = PatternCollector::default();
    let new = path_decision(policy.rules.as_ref(), operation, &mut collector);
    let old = path_decision(against.rules.as_ref(), operation, &mut collector);
    let automata = collector.compile(options)?;
    let witness = find_combined_witness(&automata, budget, |matches, target, budget| {
        if !new.admits(matches) || old.admits(matches) {
            return Ok(false);
        }
        let witness = Witness {
            action_type: action_type.to_string(),
            target: target.to_string(),
            args_size: None,
            content: match operation {
                PathOperation::Write | PathOperation::Patch => {
                    Some("chio policy analysis witness".to_string())
                }
                PathOperation::Read => None,
            },
        };
        confirms(policy, against, &witness, budget)
    })?;
    Ok(witness.map(|target| {
        let (new_forbidden, new_exception) = forbidden_path_matches(policy, &target);
        let (old_forbidden, old_exception) = forbidden_path_matches(against, &target);
        let forbidden_rule_changed_admission =
            (old_forbidden && !old_exception) || (new_forbidden && new_exception);
        let block = if forbidden_rule_changed_admission {
            "forbidden_paths"
        } else {
            "path_allowlist"
        };
        (
            block.to_string(),
            Witness {
                action_type: action_type.to_string(),
                target,
                args_size: None,
                content: match operation {
                    PathOperation::Write | PathOperation::Patch => {
                        Some("chio policy analysis witness".to_string())
                    }
                    PathOperation::Read => None,
                },
            },
        )
    }))
}

fn tool_arg_witness(
    policy: &HushSpec,
    against: &HushSpec,
    options: AnalysisOptions,
    budget: &mut AnalysisBudget,
) -> Result<Option<(String, Witness)>, AnalysisError> {
    let new_limit = policy
        .rules
        .as_ref()
        .and_then(|rules| rules.tool_access.as_ref())
        .filter(|rule| rule.enabled)
        .and_then(|rule| rule.max_args_size);
    let old_limit = against
        .rules
        .as_ref()
        .and_then(|rules| rules.tool_access.as_ref())
        .filter(|rule| rule.enabled)
        .and_then(|rule| rule.max_args_size);
    let widening_value = match (new_limit, old_limit) {
        (None, Some(old)) => old.checked_add(1),
        (Some(new), Some(old)) if new > old => old.checked_add(1),
        _ => None,
    };
    let Some(args_size) = widening_value else {
        return Ok(None);
    };
    search_list_witness(
        policy,
        against,
        options,
        ListDomain::Tool,
        Some(args_size),
        false,
        budget,
    )
}

struct FiniteDecision<'a> {
    computer_enabled: bool,
    computer_mode: ComputerUseMode,
    computer_allowed: BTreeSet<&'a str>,
    remote: Option<&'a RemoteDesktopChannelsRule>,
    input: Option<&'a InputInjectionRule>,
    input_allowed: BTreeSet<&'a str>,
}

impl<'a> FiniteDecision<'a> {
    fn from_policy(policy: &'a HushSpec) -> Self {
        let rules = policy.rules.as_ref();
        let computer = rules.and_then(|rules| rules.computer_use.as_ref());
        let input = rules.and_then(|rules| rules.input_injection.as_ref());
        Self {
            computer_enabled: computer.is_some_and(|rule| rule.enabled),
            computer_mode: computer.map_or(ComputerUseMode::Observe, |rule| rule.mode),
            computer_allowed: computer
                .into_iter()
                .flat_map(|rule| &rule.allowed_actions)
                .map(String::as_str)
                .collect(),
            remote: rules.and_then(|rules| rules.remote_desktop_channels.as_ref()),
            input,
            input_allowed: input
                .into_iter()
                .flat_map(|rule| &rule.allowed_types)
                .map(String::as_str)
                .collect(),
        }
    }

    fn admits_computer(&self, target: &str) -> bool {
        let computer_admits = !self.computer_enabled
            || self.computer_allowed.contains(target)
            || self.computer_mode != ComputerUseMode::FailClosed;
        let remote_admits = self.remote.is_none_or(|rule| {
            !rule.enabled
                || match target {
                    "remote.clipboard" => rule.clipboard,
                    "remote.file_transfer" => rule.file_transfer,
                    "remote.audio" => rule.audio,
                    "remote.drive_mapping" => rule.drive_mapping,
                    _ => true,
                }
        });
        computer_admits && remote_admits
    }

    fn admits_input(&self, target: &str) -> bool {
        self.input
            .is_none_or(|rule| !rule.enabled || self.input_allowed.contains(target))
    }
}

fn finite_action_witnesses(
    policy: &HushSpec,
    against: &HushSpec,
    budget: &mut AnalysisBudget,
) -> Result<Option<(String, Witness)>, AnalysisError> {
    let mut candidates = BTreeSet::new();
    for rules in [policy.rules.as_ref(), against.rules.as_ref()]
        .into_iter()
        .flatten()
    {
        if let Some(rule) = &rules.computer_use {
            candidates.extend(rule.allowed_actions.iter().cloned());
        }
        if let Some(rule) = &rules.input_injection {
            candidates.extend(rule.allowed_types.iter().cloned());
        }
    }
    for channel in [
        "remote.clipboard",
        "remote.file_transfer",
        "remote.audio",
        "remote.drive_mapping",
    ] {
        candidates.insert(channel.to_string());
    }
    for index in 0usize.. {
        if candidates.insert(format!("chio.analysis.other.{index}")) {
            break;
        }
    }

    let new = FiniteDecision::from_policy(policy);
    let old = FiniteDecision::from_policy(against);
    for action_type in ["computer_use", "input_inject"] {
        for target in &candidates {
            let (new_admits, old_admits) = if action_type == "computer_use" {
                (new.admits_computer(target), old.admits_computer(target))
            } else {
                (new.admits_input(target), old.admits_input(target))
            };
            if !new_admits || old_admits {
                continue;
            }
            let witness = Witness {
                action_type: action_type.to_string(),
                target: target.clone(),
                args_size: None,
                content: None,
            };
            if confirms(policy, against, &witness, budget)? {
                let block = if action_type == "computer_use" {
                    "computer_use"
                } else {
                    "input_injection"
                };
                return Ok(Some((block.to_string(), witness)));
            }
            return Err(AnalysisError::WitnessValidation(format!(
                "{} target {:?}",
                witness.action_type, witness.target
            )));
        }
    }
    Ok(None)
}

fn changed_unsupported_surface(policy: &HushSpec, against: &HushSpec) -> bool {
    if policy.extensions != against.extensions
        || (policy.extensions.is_some() && policy.rules != against.rules)
    {
        return true;
    }
    let empty = Rules::default();
    let new = policy.rules.as_ref().unwrap_or(&empty);
    let old = against.rules.as_ref().unwrap_or(&empty);
    let path_changed =
        new.forbidden_paths != old.forbidden_paths || new.path_allowlist != old.path_allowlist;
    if path_changed && (new.secret_patterns.is_some() || old.secret_patterns.is_some()) {
        return true;
    }
    if path_changed && (new.patch_integrity.is_some() || old.patch_integrity.is_some()) {
        return true;
    }
    if new.secret_patterns != old.secret_patterns
        || new.patch_integrity != old.patch_integrity
        || new.shell_commands != old.shell_commands
        || new.browser_automation != old.browser_automation
        || new.code_execution != old.code_execution
        || new.velocity != old.velocity
        || new.human_in_loop != old.human_in_loop
    {
        return true;
    }

    match (&new.tool_access, &old.tool_access) {
        (Some(new), Some(old)) => {
            let admission_surface_changed = new.enabled != old.enabled
                || new.allow != old.allow
                || new.block != old.block
                || new.default != old.default
                || new.max_args_size != old.max_args_size;
            if admission_surface_changed
                && (new.require_runtime_assurance_tier.is_some()
                    || old.require_runtime_assurance_tier.is_some()
                    || new.require_workload_identity.is_some()
                    || old.require_workload_identity.is_some())
            {
                return true;
            }
            if new.require_confirmation != old.require_confirmation
                || new.require_runtime_assurance_tier != old.require_runtime_assurance_tier
                || new.prefer_runtime_assurance_tier != old.prefer_runtime_assurance_tier
                || new.require_workload_identity != old.require_workload_identity
                || new.prefer_workload_identity != old.prefer_workload_identity
            {
                return true;
            }
        }
        (Some(new), None) | (None, Some(new)) => {
            if !new.require_confirmation.is_empty()
                || new.require_runtime_assurance_tier.is_some()
                || new.prefer_runtime_assurance_tier.is_some()
                || new.require_workload_identity.is_some()
                || new.prefer_workload_identity.is_some()
            {
                return true;
            }
        }
        (None, None) => {}
    }

    match (&new.input_injection, &old.input_injection) {
        (Some(new), Some(old)) => {
            new.require_postcondition_probe != old.require_postcondition_probe
        }
        (Some(rule), None) | (None, Some(rule)) => rule.require_postcondition_probe,
        (None, None) => false,
    }
}

fn witness_rule_ref(policy: &HushSpec, block: &str, witness: &Witness) -> RuleRef {
    let rules = policy.rules.as_ref();
    let candidates: Option<(&str, &[String])> = match block {
        "tool_access" => rules
            .and_then(|rules| rules.tool_access.as_ref())
            .map(|rule| ("allow", rule.allow.as_slice())),
        "egress" => rules
            .and_then(|rules| rules.egress.as_ref())
            .map(|rule| ("allow", rule.allow.as_slice())),
        "path_allowlist" => rules
            .and_then(|rules| rules.path_allowlist.as_ref())
            .map(|rule| {
                let values = match witness.action_type.as_str() {
                    "file_read" => rule.read.as_slice(),
                    "file_write" => rule.write.as_slice(),
                    "patch_apply" if rule.patch.is_empty() => rule.write.as_slice(),
                    "patch_apply" => rule.patch.as_slice(),
                    _ => &[],
                };
                ("allow", values)
            }),
        "forbidden_paths" => rules
            .and_then(|rules| rules.forbidden_paths.as_ref())
            .map(|rule| ("exceptions", rule.exceptions.as_slice())),
        _ => None,
    };
    if let Some((field, patterns)) = candidates {
        for (index, pattern) in patterns.iter().enumerate() {
            if crate::evaluate::glob_matches(pattern, &witness.target).unwrap_or(false) {
                return RuleRef {
                    field: field.to_string(),
                    index,
                    pattern: pattern.clone(),
                };
            }
        }
    }
    RuleRef {
        field: "default".to_string(),
        index: 0,
        pattern: "admitted by effective policy".to_string(),
    }
}

pub(crate) fn analyze_refinement(
    policy: &HushSpec,
    against: &HushSpec,
    options: AnalysisOptions,
    report: &mut AnalysisReport,
    budget: &mut AnalysisBudget,
) -> Result<(), AnalysisError> {
    let mut counters = BTreeMap::new();
    let mut widening = None;
    if policy != against {
        widening = search_list_witness(
            policy,
            against,
            options,
            ListDomain::Tool,
            None,
            true,
            budget,
        )?;
        if widening.is_none() {
            widening = tool_arg_witness(policy, against, options, budget)?;
        }
        if widening.is_none() {
            widening = search_list_witness(
                policy,
                against,
                options,
                ListDomain::Egress,
                None,
                true,
                budget,
            )?;
        }
        for operation in [
            PathOperation::Read,
            PathOperation::Write,
            PathOperation::Patch,
        ] {
            if widening.is_none() {
                widening = search_path_witness(policy, against, options, operation, budget)?;
            }
        }
        if widening.is_none() {
            widening = finite_action_witnesses(policy, against, budget)?;
        }
    }

    let status = if let Some((block, witness)) = widening {
        if !confirms(policy, against, &witness, budget)? {
            return Err(AnalysisError::WitnessValidation(format!(
                "{} target {:?}",
                witness.action_type, witness.target
            )));
        }
        push_finding(
            report,
            &mut counters,
            budget,
            FindingDraft {
                kind: FindingKind::RefinementFailure,
                severity: AnalysisSeverity::Error,
                block: block.clone(),
                rule_ref: witness_rule_ref(policy, &block, &witness),
                message: "new policy admits an input denied by the comparison policy".to_string(),
                witness: Some(witness),
            },
        )?;
        RefinementStatus::DoesNotRefine
    } else if policy != against && changed_unsupported_surface(policy, against) {
        push_finding(
            report,
            &mut counters,
            budget,
            FindingDraft {
                kind: FindingKind::AnalysisIncomplete,
                severity: AnalysisSeverity::Error,
                block: "policy".to_string(),
                rule_ref: RuleRef {
                    field: "unsupported_fragment".to_string(),
                    index: 0,
                    pattern: "changed".to_string(),
                },
                message: "changed policy fields include semantics outside the bounded analyzer"
                    .to_string(),
                witness: None,
            },
        )?;
        RefinementStatus::Inconclusive
    } else {
        RefinementStatus::Refines
    };
    report.refinement = Some(RefinementSummary { status });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_confirmation_budget_fails_closed() {
        let policy = HushSpec::parse("hushspec: '0.1.0'\n").expect("parse policy");
        let witness = Witness {
            action_type: "tool_call".to_string(),
            target: "repo.read".to_string(),
            args_size: None,
            content: None,
        };
        let mut budget = AnalysisBudget::new(AnalysisOptions {
            max_atoms: 1,
            ..AnalysisOptions::default()
        });
        for _ in 0..super::super::EVALUATOR_CONFIRMATIONS_PER_ATOM {
            let _ = confirms(&policy, &policy, &witness, &mut budget)
                .expect("confirmation within budget");
        }
        let error = confirms(&policy, &policy, &witness, &mut budget)
            .expect_err("confirmation budget exhaustion");
        assert!(matches!(
            error,
            AnalysisError::EvaluatorConfirmationLimit { .. }
        ));
    }
}
