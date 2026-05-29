// Compliance-score acceptance tests.
//
// Included by `src/kernel/tests.rs`, which already pulled in `super::*`
// and helpers from `tests/all.rs`. We only need items that are not in
// scope yet.
//
// Acceptance criteria:
//   * zero denies in 1000 calls -> score > 900
//   * revoked capability        -> score < 500

use crate::compliance_score::{
    compliance_score, ComplianceScoreConfig, ComplianceScoreInputs,
};
use crate::evidence_export::{EvidenceChildReceiptScope, EvidenceExportQuery};
use crate::operator_report::ComplianceReport;

fn clean_report() -> ComplianceReport {
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
fn phase_19_1_zero_denies_in_1000_calls_scores_above_900() {
    let report = clean_report();
    let inputs = ComplianceScoreInputs::new(1000, 0, 1, 0, 1000, 0, Some(0));
    let score = compliance_score(
        &report,
        &inputs,
        &ComplianceScoreConfig::default(),
        "agent-clean",
        1,
    );

    assert!(
        score.score > 900,
        "zero denies in 1000 calls must score >900 (got {})",
        score.score
    );
    assert_eq!(score.agent_id, "agent-clean");
    assert_eq!(score.factor_breakdown.deny_rate.deduction, 0);
}

#[test]
fn phase_19_1_revoked_capability_scores_below_500() {
    let report = clean_report();
    // One observed capability, fully revoked. any_revoked forces the
    // revocation factor to max.
    let mut inputs = ComplianceScoreInputs::new(1000, 0, 1, 1, 1000, 0, Some(0));
    inputs.any_revoked = true;
    let score = compliance_score(
        &report,
        &inputs,
        &ComplianceScoreConfig::default(),
        "agent-revoked",
        1,
    );

    assert!(
        score.score < 500,
        "revoked capability must score <500 (got {})",
        score.score
    );
    assert_eq!(
        score.factor_breakdown.revocation.points, 0,
        "revocation factor should be fully deducted"
    );
}

#[test]
fn phase_19_1_breakdown_surfaces_per_factor_details() {
    let report = clean_report();
    let inputs = ComplianceScoreInputs::new(1000, 100, 5, 0, 500, 50, Some(1_000));
    let score = compliance_score(
        &report,
        &inputs,
        &ComplianceScoreConfig::default(),
        "agent-mixed",
        1,
    );

    // Per-factor fields exist and deductions match their rates.
    assert!(score.factor_breakdown.deny_rate.deduction > 0);
    assert!(score.factor_breakdown.velocity_anomaly.deduction > 0);
    assert_eq!(score.factor_breakdown.revocation.deduction, 0);
    assert!(score.score <= crate::compliance_score::COMPLIANCE_SCORE_MAX);
}
