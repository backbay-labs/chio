use serde::{Deserialize, Serialize};

pub const ANALYSIS_SCHEMA: &str = "chio.policy-analysis.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisSeverity {
    Notice,
    Warning,
    Error,
}

impl AnalysisSeverity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    ShadowedRule,
    UnreachableRule,
    Contradiction,
    AmbiguousOverlap,
    RefinementFailure,
    AnalysisIncomplete,
}

impl FindingKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ShadowedRule => "shadowed_rule",
            Self::UnreachableRule => "unreachable_rule",
            Self::Contradiction => "contradiction",
            Self::AmbiguousOverlap => "ambiguous_overlap",
            Self::RefinementFailure => "refinement_failure",
            Self::AnalysisIncomplete => "analysis_incomplete",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRef {
    pub field: String,
    pub index: usize,
    pub pattern: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Witness {
    pub action_type: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub kind: FindingKind,
    pub severity: AnalysisSeverity,
    pub block: String,
    pub rule_ref: RuleRef,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness: Option<Witness>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotAnalyzed {
    pub block: String,
    pub field: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefinementStatus {
    Refines,
    DoesNotRefine,
    Inconclusive,
}

impl RefinementStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Refines => "refines",
            Self::DoesNotRefine => "does_not_refine",
            Self::Inconclusive => "inconclusive",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefinementSummary {
    pub status: RefinementStatus,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub errors: usize,
    pub warnings: usize,
    pub notices: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub schema: String,
    pub policy_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub against_sha256: Option<String>,
    pub findings: Vec<Finding>,
    pub not_analyzed: Vec<NotAnalyzed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refinement: Option<RefinementSummary>,
    pub summary: AnalysisSummary,
}

impl AnalysisReport {
    pub(crate) fn new(policy_sha256: String) -> Self {
        Self {
            schema: ANALYSIS_SCHEMA.to_string(),
            policy_sha256,
            against_sha256: None,
            findings: Vec::new(),
            not_analyzed: Vec::new(),
            refinement: None,
            summary: AnalysisSummary::default(),
        }
    }

    pub(crate) fn finalize(&mut self) {
        let mut summary = AnalysisSummary::default();
        for finding in &self.findings {
            match finding.severity {
                AnalysisSeverity::Notice => summary.notices += 1,
                AnalysisSeverity::Warning => summary.warnings += 1,
                AnalysisSeverity::Error => summary.errors += 1,
            }
        }
        summary.notices += self.not_analyzed.len();
        self.summary = summary;
    }

    #[must_use]
    pub fn has_at_or_above(&self, threshold: AnalysisSeverity) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity >= threshold)
            || (threshold == AnalysisSeverity::Notice && !self.not_analyzed.is_empty())
    }
}
