//! Compliance scoring built on top of `ComplianceReport`.
//!
//! Productizes the existing [`crate::operator_report::ComplianceReport`]
//! into a user-facing 0..=1000 score with weighted factors:
//!
//! | Factor                   | Max points | Signal                                   |
//! |--------------------------|-----------:|------------------------------------------|
//! | Deny rate                |        300 | denies / total_observed                  |
//! | Revocation rate          |        300 | revoked_caps / observed_caps (or flag)   |
//! | Velocity anomaly rate    |        150 | anomaly_windows / total_windows          |
//! | Policy coverage          |        150 | lineage + checkpoint rates (averaged)    |
//! | Attestation freshness    |        100 | age of latest attestation vs. staleness  |
//!
//! Weights sum to 1000. Each factor produces a 0..=max deduction; the
//! final score is `1000 - total_deductions`, clamped to `[0, 1000]`.
//!
//! This module is additive: it consumes a [`ComplianceReport`] without
//! modifying its fields. Callers who already materialize a compliance
//! report reuse its figures verbatim.

use serde::{Deserialize, Serialize};

use chio_core::underwriting::{
    UnderwritingComplianceEvidence, UNDERWRITING_COMPLIANCE_EVIDENCE_SCHEMA,
};

use crate::operator_report::ComplianceReport;

/// Maximum possible compliance score.
pub const COMPLIANCE_SCORE_MAX: u32 = 1000;

/// Weight (maximum-deducted points) for the deny-rate factor.
pub const WEIGHT_DENY_RATE: u32 = 300;
/// Weight for the revocation factor.
pub const WEIGHT_REVOCATION: u32 = 300;
/// Weight for the velocity-anomaly factor.
pub const WEIGHT_VELOCITY_ANOMALY: u32 = 150;
/// Weight for the policy-coverage factor.
pub const WEIGHT_POLICY_COVERAGE: u32 = 150;
/// Weight for the attestation-freshness factor.
pub const WEIGHT_ATTESTATION_FRESHNESS: u32 = 100;

/// Default staleness threshold (seconds) beyond which the attestation
/// freshness factor is fully deducted. Ninety days mirrors the default
/// receipt-retention window in [`crate::receipt_store::RetentionConfig`].
pub const DEFAULT_ATTESTATION_STALENESS_SECS: u64 = 7_776_000;

/// Observed compliance inputs that are not carried by `ComplianceReport`.
///
/// The raw `ComplianceReport` tracks lineage and checkpoint coverage
/// but does not carry deny counts, revocation state, or velocity
/// anomaly counts. `ComplianceScoreInputs` is the additive surface that
/// callers populate from adjacent stores (receipt analytics,
/// revocation store, velocity guard telemetry).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceScoreInputs {
    /// Total receipts observed in the scoring window.
    pub total_receipts: u64,
    /// Receipts with a deny decision in the scoring window.
    pub deny_receipts: u64,
    /// Number of capabilities exercised (or observed) in the window.
    pub observed_capabilities: u64,
    /// Number of those capabilities that are currently revoked.
    pub revoked_capabilities: u64,
    /// Whether any capability exercised by this agent is currently revoked.
    /// Fast-path fallback when per-capability counts aren't available.
    pub any_revoked: bool,
    /// Number of velocity windows evaluated.
    pub velocity_windows: u64,
    /// Windows flagged as anomalous by velocity / behavioral guards.
    pub anomalous_velocity_windows: u64,
    /// Age (in seconds) of the most recent kernel-signed attestation
    /// (checkpoint, receipt, or dpop nonce) at scoring time. When
    /// `None`, freshness is treated as maximally stale.
    pub attestation_age_secs: Option<u64>,
}

impl ComplianceScoreInputs {
    /// Build an inputs struct from a `ComplianceReport` plus the
    /// ambient inputs the report does not track.
    ///
    /// This helper keeps callers from duplicating the "zero checkpoint
    /// coverage still counts" logic when no receipts are observed.
    #[must_use]
    pub fn new(
        total_receipts: u64,
        deny_receipts: u64,
        observed_capabilities: u64,
        revoked_capabilities: u64,
        velocity_windows: u64,
        anomalous_velocity_windows: u64,
        attestation_age_secs: Option<u64>,
    ) -> Self {
        let any_revoked = revoked_capabilities > 0;
        Self {
            total_receipts,
            deny_receipts,
            observed_capabilities,
            revoked_capabilities,
            any_revoked,
            velocity_windows,
            anomalous_velocity_windows,
            attestation_age_secs,
        }
    }
}

/// Per-factor deduction detail (0..=max points).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceFactor {
    /// Human-readable factor name.
    pub name: String,
    /// Weight (maximum deduction) assigned to this factor.
    pub weight: u32,
    /// Deduction applied (0..=weight).
    pub deduction: u32,
    /// Points awarded (weight - deduction).
    pub points: u32,
    /// Raw rate / ratio that drove the deduction (0.0..=1.0).
    pub rate: f64,
}

impl ComplianceFactor {
    fn from_rate(name: &str, weight: u32, rate: f64) -> Self {
        let clamped = rate.clamp(0.0, 1.0);
        // Round half-away-from-zero is not necessary; floor is enough
        // because all weights are small integers.
        let raw = (clamped * f64::from(weight)).round();
        let deduction = raw.clamp(0.0, f64::from(weight)) as u32;
        let points = weight.saturating_sub(deduction);
        Self {
            name: name.to_string(),
            weight,
            deduction,
            points,
            rate: clamped,
        }
    }
}

/// Full factor breakdown for a compliance score.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceFactorBreakdown {
    pub deny_rate: ComplianceFactor,
    pub revocation: ComplianceFactor,
    pub velocity_anomaly: ComplianceFactor,
    pub policy_coverage: ComplianceFactor,
    pub attestation_freshness: ComplianceFactor,
}

impl ComplianceFactorBreakdown {
    #[must_use]
    pub fn total_deductions(&self) -> u32 {
        self.deny_rate.deduction
            + self.revocation.deduction
            + self.velocity_anomaly.deduction
            + self.policy_coverage.deduction
            + self.attestation_freshness.deduction
    }

    #[must_use]
    pub fn total_points(&self) -> u32 {
        self.deny_rate.points
            + self.revocation.points
            + self.velocity_anomaly.points
            + self.policy_coverage.points
            + self.attestation_freshness.points
    }
}

/// Final compliance score for an agent over a window.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceScore {
    /// Agent subject the score applies to.
    pub agent_id: String,
    /// 0..=1000 score (1000 = perfect).
    pub score: u32,
    /// Factor-by-factor breakdown.
    pub factor_breakdown: ComplianceFactorBreakdown,
    /// Unix timestamp (seconds) at which the score was computed.
    pub generated_at: u64,
    /// Snapshot of the inputs used to compute the score.
    pub inputs: ComplianceScoreInputs,
}

impl ComplianceScore {
    #[must_use]
    pub fn as_underwriting_evidence(&self) -> UnderwritingComplianceEvidence {
        UnderwritingComplianceEvidence {
            schema: UNDERWRITING_COMPLIANCE_EVIDENCE_SCHEMA.to_string(),
            agent_id: self.agent_id.clone(),
            score: self.score,
            generated_at: self.generated_at,
            total_receipts: self.inputs.total_receipts,
            deny_receipts: self.inputs.deny_receipts,
            observed_capabilities: self.inputs.observed_capabilities,
            revoked_capabilities: self.inputs.revoked_capabilities,
            attestation_age_secs: self.inputs.attestation_age_secs,
        }
    }
}

/// Options controlling scoring thresholds. Defaults match the
/// roadmap's 19.1 acceptance targets (zero denies in 1000 calls -> >900;
/// any revoked cap -> <500).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceScoreConfig {
    /// Attestation age (seconds) at which freshness is fully deducted.
    pub attestation_staleness_secs: u64,
    /// When `true`, a single `any_revoked == true` flag fully deducts
    /// the revocation factor even if `observed_capabilities` is zero.
    pub treat_any_revocation_as_full: bool,
    /// Ceiling (exclusive) on the final score when any observed
    /// capability is revoked. Defaults to 500 so that the roadmap's
    /// 19.1 acceptance target ("revoked capability -> score <500")
    /// holds regardless of the raw factor math.
    pub revocation_ceiling: u32,
}

impl Default for ComplianceScoreConfig {
    fn default() -> Self {
        Self {
            attestation_staleness_secs: DEFAULT_ATTESTATION_STALENESS_SECS,
            treat_any_revocation_as_full: true,
            revocation_ceiling: 499,
        }
    }
}

/// Compute the weighted compliance score for an agent.
///
/// * `report` -- previously-materialized compliance report (for
///   lineage and checkpoint coverage).
/// * `inputs` -- ambient inputs the report does not carry (deny rate,
///   revocations, velocity anomalies, attestation age).
/// * `config` -- scoring thresholds.
/// * `agent_id` -- scored agent (echoed into the output).
/// * `now` -- Unix timestamp to stamp on the score.
#[must_use]
pub fn compliance_score(
    report: &ComplianceReport,
    inputs: &ComplianceScoreInputs,
    config: &ComplianceScoreConfig,
    agent_id: &str,
    now: u64,
) -> ComplianceScore {
    let breakdown = compliance_factor_breakdown(report, inputs, config);
    let raw_score = COMPLIANCE_SCORE_MAX.saturating_sub(breakdown.total_deductions());
    // Revocation ceiling: once the regulatory system has revoked any
    // capability exercised by this agent, the score is capped below
    // `revocation_ceiling` regardless of the raw factor math. This
    // ensures the 19.1 acceptance target ("revoked -> <500") holds
    // even when other factors look healthy.
    let score = if inputs.any_revoked || inputs.revoked_capabilities > 0 {
        raw_score.min(config.revocation_ceiling)
    } else {
        raw_score
    };

    ComplianceScore {
        agent_id: agent_id.to_string(),
        score,
        factor_breakdown: breakdown,
        generated_at: now,
        inputs: inputs.clone(),
    }
}

/// Build the per-factor breakdown without wrapping it in a score.
///
/// Exposed for callers that want to surface individual factor deltas
/// (dashboards) without collapsing to a single number.
#[must_use]
pub fn compliance_factor_breakdown(
    report: &ComplianceReport,
    inputs: &ComplianceScoreInputs,
    config: &ComplianceScoreConfig,
) -> ComplianceFactorBreakdown {
    // --- Deny rate ----------------------------------------------------
    let deny_rate = if inputs.total_receipts == 0 {
        0.0
    } else {
        inputs.deny_receipts as f64 / inputs.total_receipts as f64
    };

    // --- Revocation ---------------------------------------------------
    let revocation_rate = if inputs.observed_capabilities == 0 {
        if config.treat_any_revocation_as_full && inputs.any_revoked {
            1.0
        } else {
            0.0
        }
    } else {
        let raw = inputs.revoked_capabilities as f64 / inputs.observed_capabilities as f64;
        // If `any_revoked` is set the agent has *at least one* revoked
        // capability: floor the rate so that acceptance (any revocation
        // deducts below 500) is met even when the denominator is large.
        if config.treat_any_revocation_as_full && inputs.any_revoked {
            raw.max(1.0)
        } else {
            raw
        }
    };

    // --- Velocity anomaly --------------------------------------------
    let velocity_rate = if inputs.velocity_windows == 0 {
        0.0
    } else {
        inputs.anomalous_velocity_windows as f64 / inputs.velocity_windows as f64
    };

    // --- Policy coverage --------------------------------------------
    //
    // Deduct when coverage is *missing*. We average the checkpoint
    // coverage and lineage coverage gap, then clamp to [0, 1]. If the
    // report has no receipts, coverage is treated as "unknown good" (no
    // deduction) so that a brand-new agent with no activity still
    // scores perfectly on this factor.
    let policy_coverage_gap = if report.matching_receipts == 0 {
        0.0
    } else {
        let checkpoint_coverage = report.checkpoint_coverage_rate.unwrap_or_else(|| {
            if report.matching_receipts == 0 {
                1.0
            } else {
                report.evidence_ready_receipts as f64 / report.matching_receipts as f64
            }
        });
        let lineage_coverage = report.lineage_coverage_rate.unwrap_or_else(|| {
            if report.matching_receipts == 0 {
                1.0
            } else {
                report.lineage_covered_receipts as f64 / report.matching_receipts as f64
            }
        });
        let avg_coverage = ((checkpoint_coverage + lineage_coverage) / 2.0).clamp(0.0, 1.0);
        1.0 - avg_coverage
    };

    // --- Attestation freshness ---------------------------------------
    let freshness_rate = match inputs.attestation_age_secs {
        None => 1.0,
        Some(age) => {
            if config.attestation_staleness_secs == 0 {
                0.0
            } else {
                (age as f64 / config.attestation_staleness_secs as f64).clamp(0.0, 1.0)
            }
        }
    };

    ComplianceFactorBreakdown {
        deny_rate: ComplianceFactor::from_rate("deny_rate", WEIGHT_DENY_RATE, deny_rate),
        revocation: ComplianceFactor::from_rate("revocation", WEIGHT_REVOCATION, revocation_rate),
        velocity_anomaly: ComplianceFactor::from_rate(
            "velocity_anomaly",
            WEIGHT_VELOCITY_ANOMALY,
            velocity_rate,
        ),
        policy_coverage: ComplianceFactor::from_rate(
            "policy_coverage",
            WEIGHT_POLICY_COVERAGE,
            policy_coverage_gap,
        ),
        attestation_freshness: ComplianceFactor::from_rate(
            "attestation_freshness",
            WEIGHT_ATTESTATION_FRESHNESS,
            freshness_rate,
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::evidence_export::{EvidenceChildReceiptScope, EvidenceExportQuery};

    fn perfect_report() -> ComplianceReport {
        ComplianceReport {
            matching_receipts: 1000,
            evidence_ready_receipts: 1000,
            uncheckpointed_receipts: 0,
            checkpoint_coverage_rate: Some(1.0),
            lineage_covered_receipts: 1000,
            lineage_gap_receipts: 0,
            lineage_coverage_rate: Some(1.0),
            pending_settlement_receipts: 0,
            failed_settlement_receipts: 0,
            direct_evidence_export_supported: true,
            child_receipt_scope: EvidenceChildReceiptScope::FullQueryWindow,
            proofs_complete: true,
            export_query: EvidenceExportQuery::default(),
            export_scope_note: None,
        }
    }

    #[test]
    fn clean_agent_scores_above_900() {
        let inputs = ComplianceScoreInputs::new(1000, 0, 1, 0, 0, 0, Some(0));
        let score = compliance_score(
            &perfect_report(),
            &inputs,
            &ComplianceScoreConfig::default(),
            "agent-1",
            0,
        );
        assert!(
            score.score > 900,
            "clean agent should score >900, got {}",
            score.score
        );
    }

    #[test]
    fn revocation_flag_drives_score_below_500() {
        let mut inputs = ComplianceScoreInputs::new(1000, 0, 1, 1, 0, 0, Some(0));
        inputs.any_revoked = true;
        let score = compliance_score(
            &perfect_report(),
            &inputs,
            &ComplianceScoreConfig::default(),
            "agent-2",
            0,
        );
        assert!(
            score.score < 500,
            "revoked agent should score <500, got {}",
            score.score
        );
    }

    #[test]
    fn empty_report_scores_perfectly_on_coverage() {
        let report = ComplianceReport {
            matching_receipts: 0,
            evidence_ready_receipts: 0,
            uncheckpointed_receipts: 0,
            checkpoint_coverage_rate: None,
            lineage_covered_receipts: 0,
            lineage_gap_receipts: 0,
            lineage_coverage_rate: None,
            pending_settlement_receipts: 0,
            failed_settlement_receipts: 0,
            direct_evidence_export_supported: true,
            child_receipt_scope: EvidenceChildReceiptScope::FullQueryWindow,
            proofs_complete: true,
            export_query: EvidenceExportQuery::default(),
            export_scope_note: None,
        };
        let inputs = ComplianceScoreInputs::new(0, 0, 0, 0, 0, 0, Some(0));
        let breakdown =
            compliance_factor_breakdown(&report, &inputs, &ComplianceScoreConfig::default());
        assert_eq!(breakdown.policy_coverage.deduction, 0);
        assert_eq!(breakdown.deny_rate.deduction, 0);
    }

    #[test]
    fn stale_attestation_deducts_freshness_factor() {
        let inputs = ComplianceScoreInputs::new(
            100,
            0,
            1,
            0,
            0,
            0,
            Some(DEFAULT_ATTESTATION_STALENESS_SECS),
        );
        let breakdown = compliance_factor_breakdown(
            &perfect_report(),
            &inputs,
            &ComplianceScoreConfig::default(),
        );
        assert_eq!(
            breakdown.attestation_freshness.deduction, WEIGHT_ATTESTATION_FRESHNESS,
            "fully stale attestation should deduct the full weight"
        );
    }

    #[test]
    fn weights_sum_to_maximum() {
        assert_eq!(
            WEIGHT_DENY_RATE
                + WEIGHT_REVOCATION
                + WEIGHT_VELOCITY_ANOMALY
                + WEIGHT_POLICY_COVERAGE
                + WEIGHT_ATTESTATION_FRESHNESS,
            COMPLIANCE_SCORE_MAX
        );
    }
}
