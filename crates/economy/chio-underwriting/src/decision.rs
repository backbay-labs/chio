use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json_bytes;
use crate::capability::{runtime_attestation::RuntimeAssuranceTier, scope::MonetaryAmount};
use crate::crypto::sha256_hex;
use crate::receipt::lineage::SignedExportEnvelope;
use crate::{
    bounded_underwriting_limit, UnderwritingAppealStatus, UnderwritingEvidenceKind,
    UnderwritingEvidenceReference, UnderwritingPolicyInput, UnderwritingPolicyInputQuery,
    UnderwritingReasonCode, UnderwritingRiskClass, UnderwritingRuntimeAssuranceEvidence,
    UnderwritingSignal, MAX_UNDERWRITING_DECISION_LIMIT, UNDERWRITING_DECISION_ARTIFACT_SCHEMA,
    UNDERWRITING_DECISION_POLICY_SCHEMA, UNDERWRITING_DECISION_POLICY_VERSION,
    UNDERWRITING_DECISION_REPORT_SCHEMA,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum UnderwritingDecisionOutcome {
    Approve,
    ReduceCeiling,
    StepUp,
    Deny,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnderwritingDecisionReasonCode {
    PolicySignal,
    ComplianceScoreRequired,
    InsufficientReceiptHistory,
    StaleReceiptHistory,
    ReputationBelowApproveThreshold,
    ReputationBelowDenyThreshold,
    RuntimeAssuranceBelowApproveTier,
    RuntimeAssuranceBelowStepUpTier,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnderwritingRemediation {
    GatherMoreReceiptHistory,
    RefreshReceiptEvidence,
    StrongerRuntimeAssurance,
    ActiveCertification,
    SettlementResolution,
    MeteredBillingReconciliation,
    ManualReview,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingDecisionPolicy {
    pub schema: String,
    pub version: String,
    pub minimum_receipt_history: u64,
    pub maximum_receipt_age_seconds: u64,
    pub minimum_approve_reputation_score: f64,
    pub deny_reputation_score_below: f64,
    pub minimum_step_up_runtime_assurance_tier: RuntimeAssuranceTier,
    pub minimum_approve_runtime_assurance_tier: RuntimeAssuranceTier,
    pub require_active_tool_certification: bool,
    pub require_compliance_score_reference: bool,
    pub reduce_ceiling_factor: f64,
}

impl Default for UnderwritingDecisionPolicy {
    fn default() -> Self {
        Self {
            schema: UNDERWRITING_DECISION_POLICY_SCHEMA.to_string(),
            version: UNDERWRITING_DECISION_POLICY_VERSION.to_string(),
            minimum_receipt_history: 1,
            maximum_receipt_age_seconds: 60 * 60 * 24 * 30,
            minimum_approve_reputation_score: 0.6,
            deny_reputation_score_below: 0.25,
            minimum_step_up_runtime_assurance_tier: RuntimeAssuranceTier::Attested,
            minimum_approve_runtime_assurance_tier: RuntimeAssuranceTier::Verified,
            require_active_tool_certification: true,
            require_compliance_score_reference: false,
            reduce_ceiling_factor: 0.5,
        }
    }
}

impl UnderwritingDecisionPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.minimum_receipt_history == 0 {
            return Err(
                "underwriting decision policy minimum_receipt_history must be greater than zero"
                    .to_string(),
            );
        }
        if self.maximum_receipt_age_seconds == 0 {
            return Err(
                "underwriting decision policy maximum_receipt_age_seconds must be greater than zero"
                    .to_string(),
            );
        }
        if !(0.0..=1.0).contains(&self.minimum_approve_reputation_score) {
            return Err(
                "underwriting decision policy minimum_approve_reputation_score must be between 0.0 and 1.0"
                    .to_string(),
            );
        }
        if !(0.0..=1.0).contains(&self.deny_reputation_score_below) {
            return Err(
                "underwriting decision policy deny_reputation_score_below must be between 0.0 and 1.0"
                    .to_string(),
            );
        }
        if self.deny_reputation_score_below >= self.minimum_approve_reputation_score {
            return Err(
                "underwriting decision policy deny_reputation_score_below must be less than minimum_approve_reputation_score"
                    .to_string(),
            );
        }
        if self.minimum_step_up_runtime_assurance_tier > self.minimum_approve_runtime_assurance_tier
        {
            return Err(
                "underwriting decision policy minimum_step_up_runtime_assurance_tier must not exceed minimum_approve_runtime_assurance_tier"
                    .to_string(),
            );
        }
        if !(0.0..1.0).contains(&self.reduce_ceiling_factor) {
            return Err(
                "underwriting decision policy reduce_ceiling_factor must be greater than 0.0 and less than 1.0"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingDecisionFinding {
    pub class: UnderwritingRiskClass,
    pub outcome: UnderwritingDecisionOutcome,
    pub reason: UnderwritingDecisionReasonCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal_reason: Option<UnderwritingReasonCode>,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<UnderwritingRemediation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<UnderwritingEvidenceReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingDecisionReport {
    pub schema: String,
    pub generated_at: u64,
    pub policy: UnderwritingDecisionPolicy,
    pub outcome: UnderwritingDecisionOutcome,
    pub risk_class: UnderwritingRiskClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_ceiling_factor: Option<f64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<UnderwritingDecisionFinding>,
    pub input: UnderwritingPolicyInput,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnderwritingDecisionLifecycleState {
    Active,
    Superseded,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnderwritingReviewState {
    Approved,
    ManualReviewRequired,
    Denied,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnderwritingBudgetAction {
    Preserve,
    Reduce,
    Hold,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingBudgetRecommendation {
    pub action: UnderwritingBudgetAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ceiling_factor: Option<f64>,
    pub rationale: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnderwritingPremiumState {
    Quoted,
    Withheld,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingPremiumQuote {
    pub state: UnderwritingPremiumState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis_points: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quoted_amount: Option<MonetaryAmount>,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingDecisionArtifact {
    pub schema: String,
    pub decision_id: String,
    pub issued_at: u64,
    pub evaluation: UnderwritingDecisionReport,
    pub lifecycle_state: UnderwritingDecisionLifecycleState,
    pub review_state: UnderwritingReviewState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_decision_id: Option<String>,
    pub budget: UnderwritingBudgetRecommendation,
    pub premium: UnderwritingPremiumQuote,
}

pub type SignedUnderwritingDecision = SignedExportEnvelope<UnderwritingDecisionArtifact>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingDecisionQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<UnderwritingDecisionOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<UnderwritingDecisionLifecycleState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appeal_status: Option<UnderwritingAppealStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl Default for UnderwritingDecisionQuery {
    fn default() -> Self {
        Self {
            decision_id: None,
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            outcome: None,
            lifecycle_state: None,
            appeal_status: None,
            limit: Some(50),
        }
    }
}

impl UnderwritingDecisionQuery {
    #[must_use]
    pub fn limit_or_default(&self) -> usize {
        bounded_underwriting_limit(self.limit, 50, MAX_UNDERWRITING_DECISION_LIMIT)
    }

    #[must_use]
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.limit = Some(self.limit_or_default());
        normalized
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingDecisionSummary {
    pub matching_decisions: u64,
    pub returned_decisions: u64,
    pub active_decisions: u64,
    pub superseded_decisions: u64,
    pub open_appeals: u64,
    pub accepted_appeals: u64,
    pub rejected_appeals: u64,
    pub total_quoted_premium_units: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_quoted_premium_currency: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub quoted_premium_totals_by_currency: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingDecisionRow {
    pub decision: SignedUnderwritingDecision,
    pub lifecycle_state: UnderwritingDecisionLifecycleState,
    pub open_appeal_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_appeal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_appeal_status: Option<UnderwritingAppealStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingDecisionListReport {
    pub generated_at: u64,
    pub filters: UnderwritingDecisionQuery,
    pub summary: UnderwritingDecisionSummary,
    pub decisions: Vec<UnderwritingDecisionRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingSimulationRequest {
    pub query: UnderwritingPolicyInputQuery,
    pub policy: UnderwritingDecisionPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingSimulationDelta {
    pub outcome_changed: bool,
    pub risk_class_changed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_ceiling_factor: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulated_ceiling_factor: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingSimulationReport {
    pub schema: String,
    pub generated_at: u64,
    pub input: UnderwritingPolicyInput,
    pub default_evaluation: UnderwritingDecisionReport,
    pub simulated_evaluation: UnderwritingDecisionReport,
    pub delta: UnderwritingSimulationDelta,
}

pub fn evaluate_underwriting_policy_input(
    input: UnderwritingPolicyInput,
    policy: &UnderwritingDecisionPolicy,
) -> Result<UnderwritingDecisionReport, String> {
    policy.validate()?;

    let mut findings = Vec::new();
    let latest_receipt_ref = input
        .receipts
        .receipt_refs
        .iter()
        .max_by_key(|reference| reference.observed_at.unwrap_or(0))
        .cloned();

    if input.receipts.matching_receipts < policy.minimum_receipt_history {
        findings.push(UnderwritingDecisionFinding {
            class: UnderwritingRiskClass::Elevated,
            outcome: UnderwritingDecisionOutcome::StepUp,
            reason: UnderwritingDecisionReasonCode::InsufficientReceiptHistory,
            signal_reason: None,
            description: format!(
                "only {} receipt(s) matched; policy requires at least {}",
                input.receipts.matching_receipts, policy.minimum_receipt_history
            ),
            remediation: Some(UnderwritingRemediation::GatherMoreReceiptHistory),
            evidence_refs: latest_receipt_ref.clone().into_iter().collect(),
        });
    }

    if let Some(latest_receipt_ref) = latest_receipt_ref.as_ref() {
        if let Some(observed_at) = latest_receipt_ref.observed_at {
            if observed_at > input.generated_at {
                findings.push(UnderwritingDecisionFinding {
                    class: UnderwritingRiskClass::Elevated,
                    outcome: UnderwritingDecisionOutcome::StepUp,
                    reason: UnderwritingDecisionReasonCode::StaleReceiptHistory,
                    signal_reason: None,
                    description: format!(
                        "latest receipt evidence was observed {}s after the underwriting input was generated",
                        observed_at - input.generated_at
                    ),
                    remediation: Some(UnderwritingRemediation::RefreshReceiptEvidence),
                    evidence_refs: vec![latest_receipt_ref.clone()],
                });
            } else if input.generated_at - observed_at > policy.maximum_receipt_age_seconds {
                findings.push(UnderwritingDecisionFinding {
                    class: UnderwritingRiskClass::Elevated,
                    outcome: UnderwritingDecisionOutcome::StepUp,
                    reason: UnderwritingDecisionReasonCode::StaleReceiptHistory,
                    signal_reason: None,
                    description: format!(
                        "latest receipt evidence is {}s old, exceeding the {}s freshness window",
                        input.generated_at - observed_at,
                        policy.maximum_receipt_age_seconds
                    ),
                    remediation: Some(UnderwritingRemediation::RefreshReceiptEvidence),
                    evidence_refs: vec![latest_receipt_ref.clone()],
                });
            }
        }
    }

    if policy.require_compliance_score_reference && input.compliance_score.is_none() {
        findings.push(UnderwritingDecisionFinding {
            class: UnderwritingRiskClass::Elevated,
            outcome: UnderwritingDecisionOutcome::StepUp,
            reason: UnderwritingDecisionReasonCode::ComplianceScoreRequired,
            signal_reason: None,
            description:
                "policy requires a compliance-score reference, but no signed score evidence was included in the underwriting input"
                    .to_string(),
            remediation: Some(UnderwritingRemediation::ManualReview),
            evidence_refs: Vec::new(),
        });
    }

    if let Some(reputation) = input.reputation.as_ref() {
        let evidence_refs = input_signal(
            input.signals.as_slice(),
            UnderwritingReasonCode::LowReputation,
        )
        .map_or_else(Vec::new, |signal| signal.evidence_refs.clone());
        if reputation.effective_score < policy.deny_reputation_score_below {
            findings.push(UnderwritingDecisionFinding {
                class: UnderwritingRiskClass::Critical,
                outcome: UnderwritingDecisionOutcome::Deny,
                reason: UnderwritingDecisionReasonCode::ReputationBelowDenyThreshold,
                signal_reason: Some(UnderwritingReasonCode::LowReputation),
                description: format!(
                    "effective reputation score {:.4} is below the deny threshold {:.4}",
                    reputation.effective_score, policy.deny_reputation_score_below
                ),
                remediation: Some(UnderwritingRemediation::ManualReview),
                evidence_refs,
            });
        } else if reputation.effective_score < policy.minimum_approve_reputation_score {
            findings.push(UnderwritingDecisionFinding {
                class: UnderwritingRiskClass::Elevated,
                outcome: UnderwritingDecisionOutcome::ReduceCeiling,
                reason: UnderwritingDecisionReasonCode::ReputationBelowApproveThreshold,
                signal_reason: Some(UnderwritingReasonCode::LowReputation),
                description: format!(
                    "effective reputation score {:.4} is below the approval threshold {:.4}",
                    reputation.effective_score, policy.minimum_approve_reputation_score
                ),
                remediation: None,
                evidence_refs,
            });
        }
    }

    if input.receipts.governed_receipts > 0 {
        let runtime_evidence_refs = runtime_assurance_evidence_refs(
            input.runtime_assurance.as_ref(),
            input.signals.as_slice(),
        );
        let highest_tier = input
            .runtime_assurance
            .as_ref()
            .and_then(|runtime_assurance| runtime_assurance.highest_tier);
        match highest_tier {
            Some(tier) if tier < policy.minimum_step_up_runtime_assurance_tier => {
                findings.push(UnderwritingDecisionFinding {
                    class: UnderwritingRiskClass::Elevated,
                    outcome: UnderwritingDecisionOutcome::StepUp,
                    reason: UnderwritingDecisionReasonCode::RuntimeAssuranceBelowStepUpTier,
                    signal_reason: input_signal(
                        input.signals.as_slice(),
                        UnderwritingReasonCode::MissingRuntimeAssurance,
                    )
                    .map(|signal| signal.reason)
                    .or_else(|| {
                        input_signal(
                            input.signals.as_slice(),
                            UnderwritingReasonCode::WeakRuntimeAssurance,
                        )
                        .map(|signal| signal.reason)
                    }),
                    description: format!(
                        "highest runtime assurance tier `{tier:?}` is below the step-up floor `{}`",
                        format!("{:?}", policy.minimum_step_up_runtime_assurance_tier)
                            .to_lowercase()
                    ),
                    remediation: Some(UnderwritingRemediation::StrongerRuntimeAssurance),
                    evidence_refs: runtime_evidence_refs,
                });
            }
            Some(tier) if tier < policy.minimum_approve_runtime_assurance_tier => {
                findings.push(UnderwritingDecisionFinding {
                    class: UnderwritingRiskClass::Guarded,
                    outcome: UnderwritingDecisionOutcome::ReduceCeiling,
                    reason: UnderwritingDecisionReasonCode::RuntimeAssuranceBelowApproveTier,
                    signal_reason: input_signal(
                        input.signals.as_slice(),
                        UnderwritingReasonCode::WeakRuntimeAssurance,
                    )
                    .map(|signal| signal.reason),
                    description: format!(
                        "highest runtime assurance tier `{tier:?}` is below the approval target `{}`",
                        format!("{:?}", policy.minimum_approve_runtime_assurance_tier)
                            .to_lowercase()
                    ),
                    remediation: None,
                    evidence_refs: runtime_evidence_refs,
                });
            }
            None => {
                findings.push(UnderwritingDecisionFinding {
                    class: UnderwritingRiskClass::Elevated,
                    outcome: UnderwritingDecisionOutcome::StepUp,
                    reason: UnderwritingDecisionReasonCode::RuntimeAssuranceBelowStepUpTier,
                    signal_reason: input_signal(
                        input.signals.as_slice(),
                        UnderwritingReasonCode::MissingRuntimeAssurance,
                    )
                    .map(|signal| signal.reason),
                    description:
                        "governed receipt history is present but no runtime assurance evidence was observed"
                            .to_string(),
                    remediation: Some(UnderwritingRemediation::StrongerRuntimeAssurance),
                    evidence_refs: runtime_evidence_refs,
                });
            }
            Some(_) => {}
        }
    }

    for signal in &input.signals {
        match signal.reason {
            UnderwritingReasonCode::RevokedCertification
            | UnderwritingReasonCode::FailedCertification
            | UnderwritingReasonCode::FailedSettlementExposure => {
                findings.push(UnderwritingDecisionFinding {
                    class: signal.class,
                    outcome: UnderwritingDecisionOutcome::Deny,
                    reason: UnderwritingDecisionReasonCode::PolicySignal,
                    signal_reason: Some(signal.reason),
                    description: signal.description.clone(),
                    remediation: remediation_for_signal(signal.reason),
                    evidence_refs: signal.evidence_refs.clone(),
                })
            }
            UnderwritingReasonCode::MissingCertification
                if policy.require_active_tool_certification
                    && input.filters.tool_server.is_some() =>
            {
                findings.push(UnderwritingDecisionFinding {
                    class: UnderwritingRiskClass::Elevated,
                    outcome: UnderwritingDecisionOutcome::StepUp,
                    reason: UnderwritingDecisionReasonCode::PolicySignal,
                    signal_reason: Some(signal.reason),
                    description: signal.description.clone(),
                    remediation: Some(UnderwritingRemediation::ActiveCertification),
                    evidence_refs: signal.evidence_refs.clone(),
                });
            }
            UnderwritingReasonCode::ProbationaryHistory
            | UnderwritingReasonCode::ImportedTrustDependency
            | UnderwritingReasonCode::PendingSettlementExposure
            | UnderwritingReasonCode::MeteredBillingMismatch
            | UnderwritingReasonCode::DelegatedCallChain
            | UnderwritingReasonCode::SharedEvidenceProofRequired => {
                findings.push(UnderwritingDecisionFinding {
                    class: signal.class,
                    outcome: UnderwritingDecisionOutcome::ReduceCeiling,
                    reason: UnderwritingDecisionReasonCode::PolicySignal,
                    signal_reason: Some(signal.reason),
                    description: signal.description.clone(),
                    remediation: remediation_for_signal(signal.reason),
                    evidence_refs: signal.evidence_refs.clone(),
                })
            }
            UnderwritingReasonCode::LowReputation
            | UnderwritingReasonCode::MissingRuntimeAssurance
            | UnderwritingReasonCode::WeakRuntimeAssurance
            | UnderwritingReasonCode::MissingCertification => {}
        }
    }

    dedupe_findings(&mut findings);

    let outcome = findings
        .iter()
        .map(|finding| finding.outcome)
        .max()
        .unwrap_or(UnderwritingDecisionOutcome::Approve);
    let risk_class = findings
        .iter()
        .map(|finding| finding.class)
        .max()
        .unwrap_or(UnderwritingRiskClass::Baseline);
    let suggested_ceiling_factor = (outcome == UnderwritingDecisionOutcome::ReduceCeiling)
        .then_some(policy.reduce_ceiling_factor);

    Ok(UnderwritingDecisionReport {
        schema: UNDERWRITING_DECISION_REPORT_SCHEMA.to_string(),
        generated_at: input.generated_at,
        policy: policy.clone(),
        outcome,
        risk_class,
        suggested_ceiling_factor,
        findings,
        input,
    })
}

pub fn build_underwriting_decision_artifact(
    evaluation: UnderwritingDecisionReport,
    issued_at: u64,
    supersedes_decision_id: Option<String>,
    quoted_exposure: Option<MonetaryAmount>,
) -> Result<UnderwritingDecisionArtifact, String> {
    let review_state = match evaluation.outcome {
        UnderwritingDecisionOutcome::Approve | UnderwritingDecisionOutcome::ReduceCeiling => {
            UnderwritingReviewState::Approved
        }
        UnderwritingDecisionOutcome::StepUp => UnderwritingReviewState::ManualReviewRequired,
        UnderwritingDecisionOutcome::Deny => UnderwritingReviewState::Denied,
    };
    let budget =
        budget_recommendation_for_outcome(evaluation.outcome, evaluation.suggested_ceiling_factor);
    let premium =
        premium_quote_for_outcome(evaluation.outcome, evaluation.risk_class, quoted_exposure);
    let decision_id_input = canonical_json_bytes(&(
        UNDERWRITING_DECISION_ARTIFACT_SCHEMA,
        issued_at,
        &evaluation,
        &supersedes_decision_id,
        &budget,
        &premium,
    ))
    .map_err(|error| error.to_string())?;
    let decision_id = format!("uwd-{}", sha256_hex(&decision_id_input));

    Ok(UnderwritingDecisionArtifact {
        schema: UNDERWRITING_DECISION_ARTIFACT_SCHEMA.to_string(),
        decision_id,
        issued_at,
        evaluation,
        lifecycle_state: UnderwritingDecisionLifecycleState::Active,
        review_state,
        supersedes_decision_id,
        budget,
        premium,
    })
}

fn budget_recommendation_for_outcome(
    outcome: UnderwritingDecisionOutcome,
    ceiling_factor: Option<f64>,
) -> UnderwritingBudgetRecommendation {
    match outcome {
        UnderwritingDecisionOutcome::Approve => UnderwritingBudgetRecommendation {
            action: UnderwritingBudgetAction::Preserve,
            ceiling_factor: None,
            rationale: "bounded underwriting approved the existing ceiling".to_string(),
        },
        UnderwritingDecisionOutcome::ReduceCeiling => UnderwritingBudgetRecommendation {
            action: UnderwritingBudgetAction::Reduce,
            ceiling_factor,
            rationale: "risk findings require a narrower economic ceiling".to_string(),
        },
        UnderwritingDecisionOutcome::StepUp => UnderwritingBudgetRecommendation {
            action: UnderwritingBudgetAction::Hold,
            ceiling_factor: None,
            rationale: "manual review or stronger evidence is required before granting the ceiling"
                .to_string(),
        },
        UnderwritingDecisionOutcome::Deny => UnderwritingBudgetRecommendation {
            action: UnderwritingBudgetAction::Deny,
            ceiling_factor: None,
            rationale: "bounded underwriting denied the requested economic authority".to_string(),
        },
    }
}

fn premium_quote_for_outcome(
    outcome: UnderwritingDecisionOutcome,
    risk_class: UnderwritingRiskClass,
    quoted_exposure: Option<MonetaryAmount>,
) -> UnderwritingPremiumQuote {
    let basis_points = match outcome {
        UnderwritingDecisionOutcome::Approve => Some(match risk_class {
            UnderwritingRiskClass::Baseline => 100,
            UnderwritingRiskClass::Guarded => 150,
            UnderwritingRiskClass::Elevated => 200,
            UnderwritingRiskClass::Critical => 300,
        }),
        UnderwritingDecisionOutcome::ReduceCeiling => Some(match risk_class {
            UnderwritingRiskClass::Baseline => 150,
            UnderwritingRiskClass::Guarded => 250,
            UnderwritingRiskClass::Elevated => 400,
            UnderwritingRiskClass::Critical => 600,
        }),
        UnderwritingDecisionOutcome::StepUp | UnderwritingDecisionOutcome::Deny => None,
    };

    match outcome {
        UnderwritingDecisionOutcome::Approve | UnderwritingDecisionOutcome::ReduceCeiling => {
            UnderwritingPremiumQuote {
                state: UnderwritingPremiumState::Quoted,
                basis_points,
                quoted_amount: quoted_exposure
                    .as_ref()
                    .zip(basis_points)
                    .map(|(amount, bps)| quote_premium_amount(amount, bps)),
                rationale: "premium output is derived from the bounded decision schedule"
                    .to_string(),
            }
        }
        UnderwritingDecisionOutcome::StepUp => UnderwritingPremiumQuote {
            state: UnderwritingPremiumState::Withheld,
            basis_points: None,
            quoted_amount: None,
            rationale: "premium is withheld until manual review or stronger evidence completes"
                .to_string(),
        },
        UnderwritingDecisionOutcome::Deny => UnderwritingPremiumQuote {
            state: UnderwritingPremiumState::NotApplicable,
            basis_points: None,
            quoted_amount: None,
            rationale: "premium is not quoted for denied underwriting decisions".to_string(),
        },
    }
}

fn quote_premium_amount(exposure: &MonetaryAmount, basis_points: u32) -> MonetaryAmount {
    // u128 keeps the intermediate multiplication exact for any u64 exposure
    // and any u32 basis_points. The conversion back to u64 saturates so a
    // future caller passing basis_points >= 10_000 cannot truncate silently;
    // an overflow here surfaces as the largest representable premium and is
    // preferred over wrap-around.
    let units = (u128::from(exposure.units) * u128::from(basis_points)).div_ceil(10_000_u128);
    let saturated_units = u64::try_from(units).unwrap_or(u64::MAX);
    MonetaryAmount {
        units: saturated_units,
        currency: exposure.currency.clone(),
    }
}

fn remediation_for_signal(reason: UnderwritingReasonCode) -> Option<UnderwritingRemediation> {
    match reason {
        UnderwritingReasonCode::FailedSettlementExposure
        | UnderwritingReasonCode::PendingSettlementExposure => {
            Some(UnderwritingRemediation::SettlementResolution)
        }
        UnderwritingReasonCode::MeteredBillingMismatch => {
            Some(UnderwritingRemediation::MeteredBillingReconciliation)
        }
        UnderwritingReasonCode::RevokedCertification
        | UnderwritingReasonCode::FailedCertification
        | UnderwritingReasonCode::MissingCertification => {
            Some(UnderwritingRemediation::ActiveCertification)
        }
        _ => None,
    }
}

fn runtime_assurance_evidence_refs(
    runtime_assurance: Option<&UnderwritingRuntimeAssuranceEvidence>,
    signals: &[UnderwritingSignal],
) -> Vec<UnderwritingEvidenceReference> {
    if let Some(signal) = input_signal(signals, UnderwritingReasonCode::MissingRuntimeAssurance) {
        return signal.evidence_refs.clone();
    }
    if let Some(signal) = input_signal(signals, UnderwritingReasonCode::WeakRuntimeAssurance) {
        return signal.evidence_refs.clone();
    }
    runtime_assurance
        .and_then(|runtime_assurance| {
            runtime_assurance
                .latest_evidence_sha256
                .as_ref()
                .map(|evidence_sha256| UnderwritingEvidenceReference {
                    kind: UnderwritingEvidenceKind::RuntimeAssuranceEvidence,
                    reference_id: evidence_sha256.clone(),
                    observed_at: None,
                    digest_sha256: Some(evidence_sha256.clone()),
                    locator: runtime_assurance
                        .latest_verifier
                        .as_ref()
                        .map(|verifier| format!("runtime-assurance:{verifier}")),
                })
        })
        .into_iter()
        .collect()
}

fn input_signal(
    signals: &[UnderwritingSignal],
    reason: UnderwritingReasonCode,
) -> Option<&UnderwritingSignal> {
    signals.iter().find(|signal| signal.reason == reason)
}

fn dedupe_findings(findings: &mut Vec<UnderwritingDecisionFinding>) {
    let mut deduped = Vec::with_capacity(findings.len());
    for finding in findings.drain(..) {
        let duplicate = deduped
            .iter()
            .any(|existing: &UnderwritingDecisionFinding| {
                existing.outcome == finding.outcome
                    && existing.reason == finding.reason
                    && existing.signal_reason == finding.signal_reason
            });
        if !duplicate {
            deduped.push(finding);
        }
    }
    *findings = deduped;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::*;

    #[test]
    fn quote_premium_amount_saturates_when_basis_points_force_overflow() {
        // Regression: a basis_points value that forces the u128
        // intermediate above u64::MAX must saturate rather than truncate.
        let exposure = MonetaryAmount {
            units: u64::MAX,
            currency: "USD".to_string(),
        };
        // 20_000 bps = 2x the exposure; (u64::MAX * 20000 / 10000) > u64::MAX.
        let quoted = quote_premium_amount(&exposure, 20_000);
        assert_eq!(quoted.units, u64::MAX);
        assert_eq!(quoted.currency, "USD");
    }

    #[test]
    fn quote_premium_amount_uses_ceil_for_partial_basis_points() {
        // Ensure the div_ceil behavior is preserved: 1 unit at 1 bp must
        // round up to 1 minor unit so a charged premium is never zero-priced
        // when bps is non-zero.
        let exposure = MonetaryAmount {
            units: 1,
            currency: "USD".to_string(),
        };
        let quoted = quote_premium_amount(&exposure, 1);
        assert_eq!(quoted.units, 1);
    }

    #[test]
    fn bounded_underwriting_limit_clamps_default_and_edges() {
        assert_eq!(bounded_underwriting_limit(None, 100, 200), 100);
        assert_eq!(bounded_underwriting_limit(Some(0), 100, 200), 1);
        assert_eq!(bounded_underwriting_limit(Some(250), 100, 200), 200);
        assert_eq!(bounded_underwriting_limit(Some(75), 100, 200), 75);
    }

    #[test]
    fn underwriting_query_requires_anchor() {
        let query = UnderwritingPolicyInputQuery::default();
        let error = query.validate().unwrap_err();
        assert!(error.contains("at least one anchor"));
    }

    #[test]
    fn underwriting_query_requires_tool_server_when_tool_name_is_set() {
        let query = UnderwritingPolicyInputQuery {
            tool_name: Some("bash".to_string()),
            ..UnderwritingPolicyInputQuery::default()
        };
        let error = query.validate().unwrap_err();
        assert!(error.contains("--tool-server"));
    }

    #[test]
    fn underwriting_query_clamps_limit_and_validates_window() {
        let query = UnderwritingPolicyInputQuery {
            agent_subject: Some("subject-1".to_string()),
            since: Some(20),
            until: Some(10),
            receipt_limit: Some(5_000),
            ..UnderwritingPolicyInputQuery::default()
        };
        assert_eq!(
            query.receipt_limit_or_default(),
            MAX_UNDERWRITING_RECEIPT_LIMIT
        );
        assert_eq!(
            query.normalized().receipt_limit,
            Some(MAX_UNDERWRITING_RECEIPT_LIMIT)
        );
        let error = query.validate().unwrap_err();
        assert!(error.contains("since > until"));
    }

    #[test]
    fn underwriting_query_rejects_blank_or_padded_filters() {
        let query = UnderwritingPolicyInputQuery {
            agent_subject: Some(" ".to_string()),
            ..UnderwritingPolicyInputQuery::default()
        };
        let error = query.validate().unwrap_err();
        assert!(error.contains("agent_subject"));

        let query = UnderwritingPolicyInputQuery {
            tool_server: Some("tool-server ".to_string()),
            ..UnderwritingPolicyInputQuery::default()
        };
        let error = query.validate().unwrap_err();
        assert!(error.contains("tool_server"));
    }

    #[test]
    fn underwriting_taxonomy_v1_lists_all_supported_classes_and_reasons() {
        let taxonomy = UnderwritingRiskTaxonomy::default();
        assert_eq!(taxonomy.version, UNDERWRITING_RISK_TAXONOMY_VERSION);
        assert!(taxonomy
            .supported_classes
            .contains(&UnderwritingRiskClass::Critical));
        assert!(taxonomy
            .supported_reasons
            .contains(&UnderwritingReasonCode::MeteredBillingMismatch));
    }

    fn sample_underwriting_input(generated_at: u64) -> UnderwritingPolicyInput {
        UnderwritingPolicyInput {
            schema: UNDERWRITING_POLICY_INPUT_SCHEMA.to_string(),
            generated_at,
            filters: UnderwritingPolicyInputQuery {
                agent_subject: Some("subject-1".to_string()),
                receipt_limit: Some(10),
                ..UnderwritingPolicyInputQuery::default()
            },
            taxonomy: UnderwritingRiskTaxonomy::default(),
            receipts: UnderwritingReceiptEvidence {
                matching_receipts: 2,
                returned_receipts: 2,
                allow_count: 2,
                deny_count: 0,
                cancelled_count: 0,
                incomplete_count: 0,
                governed_receipts: 2,
                approval_receipts: 2,
                approved_receipts: 2,
                call_chain_receipts: 0,
                runtime_assurance_receipts: 2,
                pending_settlement_receipts: 0,
                failed_settlement_receipts: 0,
                actionable_settlement_receipts: 0,
                metered_receipts: 0,
                actionable_metered_receipts: 0,
                shared_evidence_reference_count: 0,
                shared_evidence_proof_required_count: 0,
                receipt_refs: vec![
                    UnderwritingEvidenceReference {
                        kind: UnderwritingEvidenceKind::Receipt,
                        reference_id: "rcpt-1".to_string(),
                        observed_at: Some(generated_at - 120),
                        digest_sha256: None,
                        locator: Some("receipt:rcpt-1".to_string()),
                    },
                    UnderwritingEvidenceReference {
                        kind: UnderwritingEvidenceKind::Receipt,
                        reference_id: "rcpt-2".to_string(),
                        observed_at: Some(generated_at - 30),
                        digest_sha256: None,
                        locator: Some("receipt:rcpt-2".to_string()),
                    },
                ],
            },
            reputation: Some(UnderwritingReputationEvidence {
                subject_key: "subject-1".to_string(),
                effective_score: 0.93,
                probationary: false,
                resolved_tier: Some("trusted".to_string()),
                imported_signal_count: 0,
                accepted_imported_signal_count: 0,
            }),
            certification: None,
            runtime_assurance: Some(UnderwritingRuntimeAssuranceEvidence {
                governed_receipts: 2,
                runtime_assurance_receipts: 2,
                highest_tier: Some(RuntimeAssuranceTier::Verified),
                latest_schema: Some("chio.runtime-attestation.azure-maa.jwt.v1".to_string()),
                latest_verifier_family: Some(AttestationVerifierFamily::AzureMaa),
                latest_verifier: Some("verifier.chio".to_string()),
                latest_evidence_sha256: Some("sha256-runtime".to_string()),
                observed_verifier_families: vec![AttestationVerifierFamily::AzureMaa],
            }),
            compliance_score: None,
            signals: Vec::new(),
        }
    }

    #[test]
    fn underwriting_decision_policy_rejects_invalid_thresholds() {
        let policy = UnderwritingDecisionPolicy {
            deny_reputation_score_below: 0.8,
            minimum_approve_reputation_score: 0.5,
            reduce_ceiling_factor: 1.2,
            ..UnderwritingDecisionPolicy::default()
        };
        let error = policy.validate().unwrap_err();
        assert!(error.contains("deny_reputation_score_below"));
    }

    #[test]
    fn underwriting_evaluator_approves_recent_high_assurance_history() {
        let report = evaluate_underwriting_policy_input(
            sample_underwriting_input(1_000_000),
            &UnderwritingDecisionPolicy::default(),
        )
        .unwrap();
        assert_eq!(report.schema, UNDERWRITING_DECISION_REPORT_SCHEMA);
        assert_eq!(report.outcome, UnderwritingDecisionOutcome::Approve);
        assert_eq!(report.risk_class, UnderwritingRiskClass::Baseline);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn underwriting_evaluator_reduces_ceiling_for_guarded_signals() {
        let mut input = sample_underwriting_input(1_000_000);
        input.reputation.as_mut().unwrap().probationary = true;
        input.signals.push(UnderwritingSignal {
            class: UnderwritingRiskClass::Guarded,
            reason: UnderwritingReasonCode::ProbationaryHistory,
            description: "local reputation is still probationary".to_string(),
            evidence_refs: vec![UnderwritingEvidenceReference {
                kind: UnderwritingEvidenceKind::ReputationInspection,
                reference_id: "subject-1".to_string(),
                observed_at: None,
                digest_sha256: None,
                locator: Some("reputation:subject-1".to_string()),
            }],
        });

        let report =
            evaluate_underwriting_policy_input(input, &UnderwritingDecisionPolicy::default())
                .unwrap();
        assert_eq!(report.outcome, UnderwritingDecisionOutcome::ReduceCeiling);
        assert_eq!(report.risk_class, UnderwritingRiskClass::Guarded);
        assert_eq!(report.suggested_ceiling_factor, Some(0.5));
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].signal_reason,
            Some(UnderwritingReasonCode::ProbationaryHistory)
        );
    }

    #[test]
    fn underwriting_evaluator_steps_up_for_stale_history() {
        let mut input = sample_underwriting_input(1_000_000);
        input.receipts.receipt_refs = vec![UnderwritingEvidenceReference {
            kind: UnderwritingEvidenceKind::Receipt,
            reference_id: "rcpt-stale".to_string(),
            observed_at: Some(100),
            digest_sha256: None,
            locator: Some("receipt:rcpt-stale".to_string()),
        }];
        input.receipts.matching_receipts = 1;
        let policy = UnderwritingDecisionPolicy {
            maximum_receipt_age_seconds: 60,
            ..UnderwritingDecisionPolicy::default()
        };

        let report = evaluate_underwriting_policy_input(input, &policy).unwrap();
        assert_eq!(report.outcome, UnderwritingDecisionOutcome::StepUp);
        assert!(report.findings.iter().any(|finding| {
            finding.reason == UnderwritingDecisionReasonCode::StaleReceiptHistory
        }));
    }

    #[test]
    fn underwriting_evaluator_steps_up_for_future_receipt_evidence() {
        let mut input = sample_underwriting_input(1_000_000);
        input.receipts.receipt_refs = vec![UnderwritingEvidenceReference {
            kind: UnderwritingEvidenceKind::Receipt,
            reference_id: "rcpt-future".to_string(),
            observed_at: Some(1_000_001),
            digest_sha256: None,
            locator: Some("receipt:rcpt-future".to_string()),
        }];
        let policy = UnderwritingDecisionPolicy {
            maximum_receipt_age_seconds: 60,
            ..UnderwritingDecisionPolicy::default()
        };

        let report = evaluate_underwriting_policy_input(input, &policy).unwrap();

        assert_eq!(report.outcome, UnderwritingDecisionOutcome::StepUp);
        assert!(report.findings.iter().any(|finding| {
            finding.reason == UnderwritingDecisionReasonCode::StaleReceiptHistory
                && finding.description.contains("after the underwriting input")
        }));
    }

    #[test]
    fn underwriting_evaluator_requires_compliance_reference_when_policy_demands_it() {
        let report = evaluate_underwriting_policy_input(
            sample_underwriting_input(1_000_000),
            &UnderwritingDecisionPolicy {
                require_compliance_score_reference: true,
                ..UnderwritingDecisionPolicy::default()
            },
        )
        .unwrap();

        assert_eq!(report.outcome, UnderwritingDecisionOutcome::StepUp);
        assert!(report.findings.iter().any(|finding| {
            finding.reason == UnderwritingDecisionReasonCode::ComplianceScoreRequired
        }));
    }

    #[test]
    fn underwriting_evaluator_denies_critical_signal_history() {
        let mut input = sample_underwriting_input(1_000_000);
        input.signals.push(UnderwritingSignal {
            class: UnderwritingRiskClass::Critical,
            reason: UnderwritingReasonCode::FailedSettlementExposure,
            description: "one governed receipt remains in failed settlement".to_string(),
            evidence_refs: vec![UnderwritingEvidenceReference {
                kind: UnderwritingEvidenceKind::SettlementReconciliation,
                reference_id: "rcpt-2".to_string(),
                observed_at: Some(999_990),
                digest_sha256: None,
                locator: Some("settlement:rcpt-2".to_string()),
            }],
        });

        let report =
            evaluate_underwriting_policy_input(input, &UnderwritingDecisionPolicy::default())
                .unwrap();
        assert_eq!(report.outcome, UnderwritingDecisionOutcome::Deny);
        assert_eq!(report.risk_class, UnderwritingRiskClass::Critical);
        assert!(report.findings.iter().any(|finding| {
            finding.signal_reason == Some(UnderwritingReasonCode::FailedSettlementExposure)
        }));
    }

    #[test]
    fn underwriting_decision_artifact_builds_budget_and_premium_outputs() {
        let evaluation = evaluate_underwriting_policy_input(
            sample_underwriting_input(1_000_000),
            &UnderwritingDecisionPolicy::default(),
        )
        .unwrap();
        let artifact = build_underwriting_decision_artifact(
            evaluation,
            1_000_100,
            None,
            Some(MonetaryAmount {
                units: 4_200,
                currency: "USD".to_string(),
            }),
        )
        .unwrap();
        assert_eq!(artifact.schema, UNDERWRITING_DECISION_ARTIFACT_SCHEMA);
        assert_eq!(artifact.review_state, UnderwritingReviewState::Approved);
        assert_eq!(artifact.budget.action, UnderwritingBudgetAction::Preserve);
        assert_eq!(artifact.premium.state, UnderwritingPremiumState::Quoted);
        assert_eq!(
            artifact.premium.quoted_amount,
            Some(MonetaryAmount {
                units: 42,
                currency: "USD".to_string(),
            })
        );
    }

    #[test]
    fn signed_underwriting_decision_verifies() {
        let evaluation = evaluate_underwriting_policy_input(
            sample_underwriting_input(1_000_000),
            &UnderwritingDecisionPolicy::default(),
        )
        .unwrap();
        let artifact =
            build_underwriting_decision_artifact(evaluation, 1_000_100, None, None).unwrap();
        let keypair = crate::crypto::Keypair::generate();
        let signed = SignedUnderwritingDecision::sign(artifact, &keypair).unwrap();
        assert!(signed.verify_signature().unwrap());
    }
}
