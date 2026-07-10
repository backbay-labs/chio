use chio_reputation::{
    ImportedReputationSignal, ImportedTrustPolicy, LocalReputationScorecard, ReputationConfig,
};
use serde::{Deserialize, Serialize};

use crate::policy::TierScopeCeiling;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReputationScoringSource {
    Default,
    IssuancePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProbationaryStatus {
    pub below_receipt_target: bool,
    pub below_day_target: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LocalReputationTierView {
    pub name: String,
    pub score_range: [f64; 2],
    pub max_scope: TierScopeCeiling,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LocalReputationInspection {
    pub subject_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    pub scoring_source: ReputationScoringSource,
    pub scoring: ReputationConfig,
    pub probationary_receipt_count: u64,
    pub probationary_min_days: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probationary_score_ceiling: Option<f64>,
    pub probationary: bool,
    pub probationary_status: ProbationaryStatus,
    pub effective_score: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_tier: Option<LocalReputationTierView>,
    pub scorecard: LocalReputationScorecard,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported_trust: Option<ImportedTrustReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImportedTrustReport {
    pub policy: ImportedTrustPolicy,
    pub signal_count: usize,
    pub accepted_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<ImportedReputationSignal>,
}
