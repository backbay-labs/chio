use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedPrivacyBoundary {
    pub matching_receipts: u64,
    pub returned_receipts: u64,
    pub direct_evidence_export_supported: bool,
    pub child_receipt_scope: EvidenceChildReceiptScope,
    pub proofs_complete: bool,
    pub export_query: EvidenceExportQuery,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_scope_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedDecisionSummary {
    pub allow_count: u64,
    pub deny_count: u64,
    pub cancelled_count: u64,
    pub incomplete_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedSettlementSummary {
    pub pending_receipts: u64,
    pub settled_receipts: u64,
    pub failed_receipts: u64,
    pub not_applicable_receipts: u64,
    pub actionable_receipts: u64,
    pub reconciled_receipts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedGovernedActionSummary {
    pub governed_receipts: u64,
    pub approval_receipts: u64,
    pub approved_receipts: u64,
    pub commerce_receipts: u64,
    pub max_amount_receipts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedMeteredBillingSummary {
    pub metered_receipts: u64,
    pub evidence_attached_receipts: u64,
    pub missing_evidence_receipts: u64,
    pub over_quoted_units_receipts: u64,
    pub over_max_billed_units_receipts: u64,
    pub over_quoted_cost_receipts: u64,
    pub financial_mismatch_receipts: u64,
    pub actionable_receipts: u64,
    pub reconciled_receipts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedReputationSummary {
    pub subject_key: String,
    pub effective_score: f64,
    pub probationary: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_tier: Option<String>,
    pub imported_signal_count: usize,
    pub accepted_imported_signal_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedReceiptRow {
    pub receipt_id: String,
    pub timestamp: u64,
    pub capability_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_key: Option<String>,
    pub tool_server: String,
    pub tool_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    #[serde(default)]
    pub authorized: bool,
    pub settlement_status: SettlementStatus,
    pub reconciliation_state: SettlementReconciliationState,
    pub action_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_charged: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempted_cost: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_authority: Option<FinancialBudgetAuthorityReceiptMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed: Option<GovernedTransactionReceiptMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_transaction_diagnostics: Option<GovernedTransactionDiagnostics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metered_reconciliation: Option<BehavioralFeedMeteredBillingRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedMeteredBillingRow {
    pub reconciliation_state: MeteredBillingReconciliationState,
    pub action_required: bool,
    pub evidence_missing: bool,
    pub exceeds_quoted_units: bool,
    pub exceeds_max_billed_units: bool,
    pub exceeds_quoted_cost: bool,
    pub financial_mismatch: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<MeteredBillingEvidenceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedReceiptSelection {
    pub matching_receipts: u64,
    pub receipts: Vec<BehavioralFeedReceiptRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralFeedReport {
    pub schema: String,
    pub generated_at: u64,
    pub filters: BehavioralFeedQuery,
    pub privacy: BehavioralFeedPrivacyBoundary,
    pub decisions: BehavioralFeedDecisionSummary,
    pub settlements: BehavioralFeedSettlementSummary,
    pub governed_actions: BehavioralFeedGovernedActionSummary,
    pub metered_billing: BehavioralFeedMeteredBillingSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reputation: Option<BehavioralFeedReputationSummary>,
    pub shared_evidence: SharedEvidenceReferenceSummary,
    pub receipts: Vec<BehavioralFeedReceiptRow>,
}

pub type SignedBehavioralFeed = SignedExportEnvelope<BehavioralFeedReport>;

// ===========================================================================
// Scoring and advisory signals over ComplianceReport and BehavioralFeedReport.
// ===========================================================================

/// EMA (exponentially-weighted moving average) baseline state for a
/// single (agent, metric) pair. Used by behavioral profiling to detect
/// z-score anomalies without storing every historical sample.
///
/// The baseline uses Welford-style incremental tracking of mean and
/// variance so callers can compute a z-score for any new sample
/// without re-reading history.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EmaBaselineState {
    /// Number of samples folded into the baseline.
    pub sample_count: u64,
    /// Exponentially-weighted mean.
    pub ema_mean: f64,
    /// Exponentially-weighted variance.
    pub ema_variance: f64,
    /// Last update timestamp (unix seconds).
    pub last_update: u64,
}

impl EmaBaselineState {
    /// Fold a new sample into the baseline with the provided smoothing
    /// factor `alpha` (0.0..=1.0). Higher alpha weighs recent samples
    /// more heavily.
    ///
    /// `alpha` is clamped to `(0.0, 1.0]`. `now` is recorded as
    /// `last_update`.
    pub fn update(&mut self, sample: f64, alpha: f64, now: u64) {
        let alpha = alpha.clamp(f64::MIN_POSITIVE, 1.0);
        if self.sample_count == 0 {
            self.ema_mean = sample;
            self.ema_variance = 0.0;
        } else {
            let prev_mean = self.ema_mean;
            self.ema_mean = prev_mean + alpha * (sample - prev_mean);
            // Incremental EWMA variance, following West (1979) / Welford.
            let diff = sample - prev_mean;
            self.ema_variance = (1.0 - alpha) * (self.ema_variance + alpha * diff * diff);
        }
        self.sample_count = self.sample_count.saturating_add(1);
        self.last_update = now;
    }

    /// Standard deviation (sqrt of EWMA variance).
    #[must_use]
    pub fn stddev(&self) -> f64 {
        self.ema_variance.max(0.0).sqrt()
    }

    /// Z-score for a new sample. Returns `None` when the baseline has
    /// fewer than two samples or zero variance (no meaningful signal).
    #[must_use]
    pub fn z_score(&self, sample: f64) -> Option<f64> {
        if self.sample_count < 2 {
            return None;
        }
        let stddev = self.stddev();
        if stddev <= f64::EPSILON {
            return None;
        }
        Some((sample - self.ema_mean) / stddev)
    }
}

/// Summary of behavioral-anomaly signals derived from receipts over a
/// window. Used by `BehavioralProfileGuard` and surfaced in operator
/// UIs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralAnomalyScore {
    /// Agent subject this anomaly score applies to.
    pub agent_id: String,
    /// Baseline statistic the z-score is computed against.
    pub baseline: EmaBaselineState,
    /// Current-window sample value (e.g. call count per window).
    pub current_sample: f64,
    /// Computed z-score, or `None` when baseline is too small.
    pub z_score: Option<f64>,
    /// Threshold above which an advisory signal is raised.
    pub sigma_threshold: f64,
    /// Whether the current sample crossed the threshold.
    pub anomaly: bool,
    /// Unix timestamp (seconds) at which the score was computed.
    pub generated_at: u64,
}

/// Compute a behavioral-anomaly score from a pre-existing baseline plus
/// a current-window sample. Exposes the same math the guard uses so
/// callers can surface anomaly scores in dashboards without rerunning
/// the guard.
#[must_use]
pub fn behavioral_anomaly_score(
    agent_id: &str,
    baseline: &EmaBaselineState,
    current_sample: f64,
    sigma_threshold: f64,
    now: u64,
) -> BehavioralAnomalyScore {
    let z_score = baseline.z_score(current_sample);
    let anomaly = z_score.is_some_and(|z| z.abs() > sigma_threshold);
    BehavioralAnomalyScore {
        agent_id: agent_id.to_string(),
        baseline: baseline.clone(),
        current_sample,
        z_score,
        sigma_threshold,
        anomaly,
        generated_at: now,
    }
}
