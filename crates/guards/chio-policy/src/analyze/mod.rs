mod glob;
mod ir;
mod refine;
mod report;

use std::collections::BTreeMap;

use thiserror::Error;

use crate::models::HushSpec;
use crate::receipt::compute_policy_hash;
use crate::validate;

pub use glob::GlobRelation;
pub use ir::{
    lower_policy, AtomEffect, AtomMatcher, BlockState, LoweredBlock, LoweredPolicy, RuleAtom,
};
pub use report::{
    AnalysisReport, AnalysisSeverity, AnalysisSummary, Finding, FindingKind, NotAnalyzed,
    RefinementStatus, RefinementSummary, RuleRef, Witness, ANALYSIS_SCHEMA,
};

use glob::{relation as glob_relation_inner, GlobAutomaton};

// Bound quadratic relation and report surfaces independently of CLI atom overrides.
const MATCHER_COMPARISONS_PER_ATOM: usize = 100;
const MAX_MATCHER_COMPARISONS: usize = 1_000_000;
const MAX_FINDINGS: usize = 10_000;
const EVALUATOR_CONFIRMATIONS_PER_ATOM: usize = 10;
const MAX_EVALUATOR_CONFIRMATIONS: usize = 100_000;
const MAX_ALPHABET_WORK: usize = 100_000;

pub(crate) struct AnalysisBudget {
    matcher_comparisons: usize,
    max_matcher_comparisons: usize,
    findings: usize,
    max_findings: usize,
    automaton_states: usize,
    max_automaton_states: usize,
    automaton_transitions: usize,
    max_automaton_transitions: usize,
    alphabet_work: usize,
    max_alphabet_work: usize,
    evaluator_confirmations: usize,
    max_evaluator_confirmations: usize,
}

impl AnalysisBudget {
    fn new(options: AnalysisOptions) -> Self {
        Self {
            matcher_comparisons: 0,
            max_matcher_comparisons: options
                .max_atoms
                .saturating_mul(MATCHER_COMPARISONS_PER_ATOM)
                .min(MAX_MATCHER_COMPARISONS),
            findings: 0,
            max_findings: options.max_atoms.min(MAX_FINDINGS),
            automaton_states: 0,
            max_automaton_states: options.max_automaton_states,
            automaton_transitions: 0,
            max_automaton_transitions: options.max_automaton_transitions,
            alphabet_work: 0,
            max_alphabet_work: MAX_ALPHABET_WORK,
            evaluator_confirmations: 0,
            max_evaluator_confirmations: options
                .max_atoms
                .saturating_mul(EVALUATOR_CONFIRMATIONS_PER_ATOM)
                .min(MAX_EVALUATOR_CONFIRMATIONS),
        }
    }

    fn consume_matcher_comparison(&mut self) -> Result<(), AnalysisError> {
        self.matcher_comparisons = self.matcher_comparisons.saturating_add(1);
        if self.matcher_comparisons > self.max_matcher_comparisons {
            return Err(AnalysisError::MatcherComparisonLimit {
                maximum: self.max_matcher_comparisons,
            });
        }
        Ok(())
    }

    fn reserve_finding(&mut self) -> Result<(), AnalysisError> {
        if self.findings >= self.max_findings {
            return Err(AnalysisError::FindingLimit {
                maximum: self.max_findings,
            });
        }
        self.findings += 1;
        Ok(())
    }

    pub(crate) fn consume_automaton_states(&mut self, count: usize) -> Result<(), AnalysisError> {
        self.automaton_states = self.automaton_states.saturating_add(count);
        if self.automaton_states > self.max_automaton_states {
            return Err(AnalysisError::AutomatonLimit {
                maximum: self.max_automaton_states,
            });
        }
        Ok(())
    }

    pub(crate) fn consume_automaton_transition(&mut self) -> Result<(), AnalysisError> {
        self.automaton_transitions = self.automaton_transitions.saturating_add(1);
        if self.automaton_transitions > self.max_automaton_transitions {
            return Err(AnalysisError::AutomatonTransitionLimit {
                maximum: self.max_automaton_transitions,
            });
        }
        Ok(())
    }

    pub(crate) fn consume_alphabet_work(&mut self) -> Result<(), AnalysisError> {
        self.alphabet_work = self.alphabet_work.saturating_add(1);
        if self.alphabet_work > self.max_alphabet_work {
            return Err(AnalysisError::AlphabetWorkLimit {
                maximum: self.max_alphabet_work,
            });
        }
        Ok(())
    }

    pub(crate) fn consume_evaluator_confirmation(&mut self) -> Result<(), AnalysisError> {
        self.evaluator_confirmations = self.evaluator_confirmations.saturating_add(1);
        if self.evaluator_confirmations > self.max_evaluator_confirmations {
            return Err(AnalysisError::EvaluatorConfirmationLimit {
                maximum: self.max_evaluator_confirmations,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnalysisOptions {
    pub max_atoms: usize,
    pub max_pattern_chars: usize,
    pub max_automaton_states: usize,
    pub max_automaton_transitions: usize,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            max_atoms: 10_000,
            max_pattern_chars: 4_096,
            max_automaton_states: 1_000_000,
            max_automaton_transitions: 10_000_000,
        }
    }
}

impl AnalysisOptions {
    fn validate(self) -> Result<Self, AnalysisError> {
        if self.max_atoms == 0 {
            return Err(AnalysisError::InvalidLimit("max_atoms must be positive"));
        }
        if self.max_pattern_chars == 0 {
            return Err(AnalysisError::InvalidLimit(
                "max_pattern_chars must be positive",
            ));
        }
        if self.max_automaton_states == 0 {
            return Err(AnalysisError::InvalidLimit(
                "max_automaton_states must be positive",
            ));
        }
        if self.max_automaton_transitions == 0 {
            return Err(AnalysisError::InvalidLimit(
                "max_automaton_transitions must be positive",
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error("invalid analyzer limit: {0}")]
    InvalidLimit(&'static str),
    #[error("policy validation failed: {0}")]
    InvalidPolicy(String),
    #[error(
        "policy contains {count} analyzable atoms, exceeding the configured maximum {maximum}"
    )]
    AtomLimit { count: usize, maximum: usize },
    #[error("analysis exceeded the aggregate maximum of {maximum} matcher comparisons")]
    MatcherComparisonLimit { maximum: usize },
    #[error("analysis exceeded the aggregate maximum of {maximum} findings")]
    FindingLimit { maximum: usize },
    #[error("glob contains {length} characters, exceeding the configured maximum {maximum}")]
    PatternLimit { length: usize, maximum: usize },
    #[error("glob analysis exceeded the aggregate maximum of {maximum} states")]
    AutomatonLimit { maximum: usize },
    #[error("glob analysis exceeded the aggregate maximum of {maximum} transitions")]
    AutomatonTransitionLimit { maximum: usize },
    #[error("glob analysis exceeded the aggregate maximum of {maximum} alphabet work units")]
    AlphabetWorkLimit { maximum: usize },
    #[error(
        "analysis exceeded the aggregate maximum of {maximum} production evaluator confirmations"
    )]
    EvaluatorConfirmationLimit { maximum: usize },
    #[error("refinement witness failed production evaluator confirmation: {0}")]
    WitnessValidation(String),
}

fn validate_policy(policy: &HushSpec) -> Result<(), AnalysisError> {
    let result = validate(policy);
    if result.errors.is_empty() {
        return Ok(());
    }
    Err(AnalysisError::InvalidPolicy(
        result
            .errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; "),
    ))
}

fn enforce_atom_limit(
    lowered: &LoweredPolicy,
    options: AnalysisOptions,
) -> Result<(), AnalysisError> {
    let count = lowered.authored_atom_count();
    if count > options.max_atoms {
        return Err(AnalysisError::AtomLimit {
            count,
            maximum: options.max_atoms,
        });
    }
    for atom in lowered.blocks.iter().flat_map(|block| &block.atoms) {
        let AtomMatcher::Glob { pattern } = &atom.matcher else {
            continue;
        };
        let length = pattern.chars().count();
        if length > options.max_pattern_chars {
            return Err(AnalysisError::PatternLimit {
                length,
                maximum: options.max_pattern_chars,
            });
        }
    }
    Ok(())
}

pub fn glob_relation(
    left: &str,
    right: &str,
    options: AnalysisOptions,
) -> Result<GlobRelation, AnalysisError> {
    let options = options.validate()?;
    let mut budget = AnalysisBudget::new(options);
    glob_relation_with_budget(left, right, options, &mut budget)
}

fn glob_relation_with_budget(
    left: &str,
    right: &str,
    options: AnalysisOptions,
    budget: &mut AnalysisBudget,
) -> Result<GlobRelation, AnalysisError> {
    let left_chars = left.chars().count();
    let right_chars = right.chars().count();
    if left_chars > options.max_pattern_chars {
        return Err(AnalysisError::PatternLimit {
            length: left_chars,
            maximum: options.max_pattern_chars,
        });
    }
    if right_chars > options.max_pattern_chars {
        return Err(AnalysisError::PatternLimit {
            length: right_chars,
            maximum: options.max_pattern_chars,
        });
    }
    let has_meta = |value: &str| value.contains(['*', '?']);
    if !has_meta(left) && !has_meta(right) {
        return Ok(if left == right {
            GlobRelation::Equal
        } else {
            GlobRelation::Disjoint
        });
    }
    let left = GlobAutomaton::compile(left, options.max_pattern_chars)?;
    let right = GlobAutomaton::compile(right, options.max_pattern_chars)?;
    glob_relation_inner(&left, &right, budget)
}

fn range_relation(
    left_lo: Option<u64>,
    left_hi: Option<u64>,
    right_lo: Option<u64>,
    right_hi: Option<u64>,
) -> GlobRelation {
    let left_lo = left_lo.unwrap_or(0);
    let right_lo = right_lo.unwrap_or(0);
    let left_hi = left_hi.unwrap_or(u64::MAX);
    let right_hi = right_hi.unwrap_or(u64::MAX);
    if left_hi < right_lo || right_hi < left_lo {
        GlobRelation::Disjoint
    } else if left_lo == right_lo && left_hi == right_hi {
        GlobRelation::Equal
    } else if left_lo >= right_lo && left_hi <= right_hi {
        GlobRelation::SubsetOf
    } else if right_lo >= left_lo && right_hi <= left_hi {
        GlobRelation::SupersetOf
    } else {
        GlobRelation::Overlapping
    }
}

fn matcher_relation(
    left: &AtomMatcher,
    right: &AtomMatcher,
    options: AnalysisOptions,
    budget: &mut AnalysisBudget,
) -> Result<Option<GlobRelation>, AnalysisError> {
    budget.consume_matcher_comparison()?;
    let relation = match (left, right) {
        (AtomMatcher::Glob { pattern: left }, AtomMatcher::Glob { pattern: right }) => {
            glob_relation_with_budget(left, right, options, budget)?
        }
        (
            AtomMatcher::NumericRange {
                lo: left_lo,
                hi: left_hi,
            },
            AtomMatcher::NumericRange {
                lo: right_lo,
                hi: right_hi,
            },
        ) => range_relation(*left_lo, *left_hi, *right_lo, *right_hi),
        (AtomMatcher::BoolFlag { value: left }, AtomMatcher::BoolFlag { value: right }) => {
            if left == right {
                GlobRelation::Equal
            } else {
                GlobRelation::Disjoint
            }
        }
        (AtomMatcher::SetMember { values: left }, AtomMatcher::SetMember { values: right }) => {
            if left == right {
                GlobRelation::Equal
            } else if left.is_subset(right) {
                GlobRelation::SubsetOf
            } else if right.is_subset(left) {
                GlobRelation::SupersetOf
            } else if left.is_disjoint(right) {
                GlobRelation::Disjoint
            } else {
                GlobRelation::Overlapping
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(relation))
}

fn is_subset_or_equal(relation: GlobRelation) -> bool {
    matches!(relation, GlobRelation::Equal | GlobRelation::SubsetOf)
}

fn dominant_effect(block: &str) -> Option<AtomEffect> {
    match block {
        "forbidden_paths" => Some(AtomEffect::Allow),
        "egress" | "tool_access" => Some(AtomEffect::Deny),
        _ => None,
    }
}

fn matcher_union_covers_universe(
    atoms: &[&RuleAtom],
    options: AnalysisOptions,
    budget: &mut AnalysisBudget,
) -> Result<bool, AnalysisError> {
    let Some(first) = atoms.first() else {
        return Ok(false);
    };
    match &first.matcher {
        AtomMatcher::Glob { .. } => {
            let mut patterns = Vec::with_capacity(atoms.len());
            let mut matches_empty = false;
            for atom in atoms {
                budget.consume_matcher_comparison()?;
                let AtomMatcher::Glob { pattern } = &atom.matcher else {
                    return Ok(false);
                };
                matches_empty |= glob::pattern_matches_empty(pattern);
                patterns.push(pattern);
            }
            if !matches_empty {
                return Ok(false);
            }
            let automata = patterns
                .into_iter()
                .map(|pattern| GlobAutomaton::compile(pattern, options.max_pattern_chars))
                .collect::<Result<Vec<_>, _>>()?;
            let uncovered = glob::find_combined_witness(&automata, budget, |matches, _, _| {
                Ok(matches.iter().all(|matched| !matched))
            })?;
            Ok(uncovered.is_none())
        }
        AtomMatcher::NumericRange { .. } => {
            let mut ranges = Vec::with_capacity(atoms.len());
            for atom in atoms {
                budget.consume_matcher_comparison()?;
                let AtomMatcher::NumericRange { lo, hi } = &atom.matcher else {
                    return Ok(false);
                };
                ranges.push((lo.unwrap_or(0), hi.unwrap_or(u64::MAX)));
            }
            ranges.sort_unstable_by_key(|range| range.0);
            let mut next = 0u64;
            for (lo, hi) in ranges {
                if lo > next {
                    return Ok(false);
                }
                if hi == u64::MAX {
                    return Ok(true);
                }
                next = next.max(hi.saturating_add(1));
            }
            Ok(false)
        }
        AtomMatcher::BoolFlag { .. } => {
            let mut seen_false = false;
            let mut seen_true = false;
            for atom in atoms {
                budget.consume_matcher_comparison()?;
                let AtomMatcher::BoolFlag { value } = &atom.matcher else {
                    return Ok(false);
                };
                if *value {
                    seen_true = true;
                } else {
                    seen_false = true;
                }
            }
            Ok(seen_false && seen_true)
        }
        AtomMatcher::SetMember { .. } | AtomMatcher::Default | AtomMatcher::Opaque { .. } => {
            Ok(false)
        }
    }
}

fn analyze_dead_defaults(
    block: &LoweredBlock,
    report: &mut AnalysisReport,
    counters: &mut BTreeMap<&'static str, usize>,
    options: AnalysisOptions,
    budget: &mut AnalysisBudget,
) -> Result<(), AnalysisError> {
    for default in block
        .atoms
        .iter()
        .filter(|atom| matches!(atom.matcher, AtomMatcher::Default))
    {
        let explicit: Vec<&RuleAtom> = block
            .atoms
            .iter()
            .filter(|atom| {
                atom.domain == default.domain
                    && !matches!(
                        atom.matcher,
                        AtomMatcher::Default | AtomMatcher::Opaque { .. }
                    )
            })
            .collect();
        if !explicit.iter().any(|atom| atom.effect != default.effect)
            || !matcher_union_covers_universe(&explicit, options, budget)?
        {
            continue;
        }
        push_finding(
            report,
            counters,
            budget,
            FindingDraft {
                kind: FindingKind::Contradiction,
                severity: AnalysisSeverity::Error,
                block: block.name.clone(),
                rule_ref: default.provenance.clone(),
                message: "default can never be selected because explicit entries cover the matcher domain"
                    .to_string(),
                witness: None,
            },
        )?;
    }
    Ok(())
}

fn finding_prefix(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::ShadowedRule => "SHADOW",
        FindingKind::UnreachableRule => "UNREACH",
        FindingKind::Contradiction => "CONTRA",
        FindingKind::AmbiguousOverlap => "OVERLAP",
        FindingKind::RefinementFailure => "REFINE",
        FindingKind::AnalysisIncomplete => "INCOMPLETE",
    }
}

pub(crate) struct FindingDraft {
    pub kind: FindingKind,
    pub severity: AnalysisSeverity,
    pub block: String,
    pub rule_ref: RuleRef,
    pub message: String,
    pub witness: Option<Witness>,
}

pub(crate) fn push_finding(
    report: &mut AnalysisReport,
    counters: &mut BTreeMap<&'static str, usize>,
    budget: &mut AnalysisBudget,
    draft: FindingDraft,
) -> Result<(), AnalysisError> {
    budget.reserve_finding()?;
    let prefix = finding_prefix(draft.kind);
    let count = counters.entry(prefix).or_default();
    *count += 1;
    report.findings.push(Finding {
        id: format!("{prefix}-{count:04}"),
        kind: draft.kind,
        severity: draft.severity,
        block: draft.block,
        rule_ref: draft.rule_ref,
        message: draft.message,
        witness: draft.witness,
    });
    Ok(())
}

fn analyze_block(
    block: &LoweredBlock,
    report: &mut AnalysisReport,
    counters: &mut BTreeMap<&'static str, usize>,
    options: AnalysisOptions,
    budget: &mut AnalysisBudget,
) -> Result<(), AnalysisError> {
    if block.state != BlockState::Active {
        return Ok(());
    }
    let atoms: Vec<&RuleAtom> = block
        .atoms
        .iter()
        .filter(|atom| {
            !matches!(
                atom.matcher,
                AtomMatcher::Default | AtomMatcher::Opaque { .. }
            )
        })
        .collect();
    analyze_dead_defaults(block, report, counters, options, budget)?;

    let literal_only_same_effect = atoms
        .first()
        .map(|first| {
            atoms.iter().all(|atom| {
                atom.effect == first.effect
                    && matches!(
                        &atom.matcher,
                        AtomMatcher::Glob { pattern }
                            if !pattern.contains(['*', '?'])
                    )
            })
        })
        .unwrap_or(false);
    if literal_only_same_effect {
        let mut seen = BTreeMap::new();
        for atom in atoms {
            let AtomMatcher::Glob { pattern } = &atom.matcher else {
                continue;
            };
            let key = (
                atom.domain.as_str(),
                atom.provenance.field.as_str(),
                pattern.as_str(),
            );
            if let Some((field, index)) = seen.get(&key) {
                push_finding(
                    report,
                    counters,
                    budget,
                    FindingDraft {
                        kind: FindingKind::UnreachableRule,
                        severity: AnalysisSeverity::Warning,
                        block: block.name.clone(),
                        rule_ref: atom.provenance.clone(),
                        message: format!(
                            "never changes the decision because earlier {field} entry {index} covers it"
                        ),
                        witness: None,
                    },
                )?;
            } else {
                seen.insert(key, (atom.provenance.field.as_str(), atom.provenance.index));
            }
        }
        return Ok(());
    }

    for (left_index, left) in atoms.iter().enumerate() {
        for right in atoms.iter().skip(left_index + 1) {
            if left.domain != right.domain {
                continue;
            }
            let Some(relation) = matcher_relation(&left.matcher, &right.matcher, options, budget)?
            else {
                continue;
            };

            if left.effect == right.effect {
                if left.provenance.field == right.provenance.field
                    && is_subset_or_equal(match relation {
                        GlobRelation::SubsetOf => GlobRelation::SupersetOf,
                        GlobRelation::SupersetOf => GlobRelation::SubsetOf,
                        other => other,
                    })
                {
                    push_finding(
                        report,
                        counters,
                        budget,
                        FindingDraft {
                            kind: FindingKind::UnreachableRule,
                            severity: AnalysisSeverity::Warning,
                            block: block.name.clone(),
                            rule_ref: right.provenance.clone(),
                            message: format!(
                                "never changes the decision because earlier {} entry {} covers it",
                                left.provenance.field, left.provenance.index
                            ),
                            witness: None,
                        },
                    )?;
                }
                continue;
            }

            if relation == GlobRelation::Equal {
                push_finding(
                    report,
                    counters,
                    budget,
                    FindingDraft {
                        kind: FindingKind::Contradiction,
                        severity: AnalysisSeverity::Error,
                        block: block.name.clone(),
                        rule_ref: right.provenance.clone(),
                        message: format!(
                            "conflicts exactly with {} entry {}",
                            left.provenance.field, left.provenance.index
                        ),
                        witness: None,
                    },
                )?;
                continue;
            }

            let dominant = dominant_effect(&block.name).unwrap_or(left.effect);
            let (dominant_atom, other_atom, other_subset) = if left.effect == dominant {
                (left, right, matches!(relation, GlobRelation::SupersetOf))
            } else {
                (right, left, matches!(relation, GlobRelation::SubsetOf))
            };
            if other_subset {
                push_finding(
                    report,
                    counters,
                    budget,
                    FindingDraft {
                        kind: FindingKind::ShadowedRule,
                        severity: AnalysisSeverity::Warning,
                        block: block.name.clone(),
                        rule_ref: other_atom.provenance.clone(),
                        message: format!(
                            "never takes effect because {} entry {} dominates it",
                            dominant_atom.provenance.field, dominant_atom.provenance.index
                        ),
                        witness: None,
                    },
                )?;
            } else if relation == GlobRelation::Overlapping {
                push_finding(
                    report,
                    counters,
                    budget,
                    FindingDraft {
                        kind: FindingKind::AmbiguousOverlap,
                        severity: AnalysisSeverity::Notice,
                        block: block.name.clone(),
                        rule_ref: right.provenance.clone(),
                        message: format!(
                            "overlaps {} entry {} with a different effect",
                            left.provenance.field, left.provenance.index
                        ),
                        witness: None,
                    },
                )?;
            }
        }
    }
    Ok(())
}

fn analyze_lowered(
    policy: &HushSpec,
    lowered: &LoweredPolicy,
    options: AnalysisOptions,
    budget: &mut AnalysisBudget,
) -> Result<AnalysisReport, AnalysisError> {
    let mut report = AnalysisReport::new(compute_policy_hash(policy));
    report.not_analyzed = lowered.not_analyzed();
    if policy.extensions.is_some() {
        report.not_analyzed.push(NotAnalyzed {
            block: "extensions".to_string(),
            field: "*".to_string(),
            reason: "contextual and stateful extension semantics".to_string(),
        });
    }
    let mut counters = BTreeMap::new();
    for block in &lowered.blocks {
        analyze_block(block, &mut report, &mut counters, options, budget)?;
    }
    report.finalize();
    Ok(report)
}

pub fn analyze(
    policy: &HushSpec,
    options: AnalysisOptions,
) -> Result<AnalysisReport, AnalysisError> {
    let options = options.validate()?;
    validate_policy(policy)?;
    let lowered = lower_policy(policy);
    enforce_atom_limit(&lowered, options)?;
    let mut budget = AnalysisBudget::new(options);
    analyze_lowered(policy, &lowered, options, &mut budget)
}

pub fn analyze_against(
    policy: &HushSpec,
    against: &HushSpec,
    options: AnalysisOptions,
) -> Result<AnalysisReport, AnalysisError> {
    let options = options.validate()?;
    validate_policy(policy)?;
    validate_policy(against)?;
    let lowered = lower_policy(policy);
    let against_lowered = lower_policy(against);
    enforce_atom_limit(&lowered, options)?;
    enforce_atom_limit(&against_lowered, options)?;
    let mut budget = AnalysisBudget::new(options);
    let mut report = analyze_lowered(policy, &lowered, options, &mut budget)?;
    report.against_sha256 = Some(compute_policy_hash(against));
    refine::analyze_refinement(policy, against, options, &mut report, &mut budget)?;
    report.finalize();
    Ok(report)
}

#[cfg(test)]
mod tests;
