//! Unified spend/exposure comptroller surface projection.
//!
//! Pure projection over the existing `OperatorReport` (kernel) and
//! `ExposureLedgerReport` (credit) types. This is the single Rust source of
//! truth for the `chio.comptroller.surface-report.v1` schema.

use chio_core_types::CHIO_COMPTROLLER_SURFACE_REPORT_V1_SCHEMA;
use chio_credit::{ExposureLedgerCurrencyPosition, ExposureLedgerReport};
use serde::{Deserialize, Serialize};

use super::{
    BudgetUtilizationSummary, OperatorReport, OperatorReportQuery, SettlementReconciliationSummary,
};

/// Schema id for the comptroller surface projection (re-exported single source of truth).
pub const COMPTROLLER_SURFACE_REPORT_SCHEMA: &str = CHIO_COMPTROLLER_SURFACE_REPORT_V1_SCHEMA;

/// Allow/deny/cancelled/incomplete decision counts projected from the operator activity summary.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComptrollerDecisionSummary {
    pub allow_count: u64,
    pub deny_count: u64,
    pub cancelled_count: u64,
    pub incomplete_count: u64,
}

/// Optional sha256 hash-refs to the composed source artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComptrollerSurfaceSourceRefs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_report_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposure_ledger_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_comptroller_report_ref: Option<String>,
}

/// Unified spend/exposure contract: a projection over OperatorReport + ExposureLedgerReport.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComptrollerSurfaceReport {
    pub schema: String,
    pub generated_at: u64,
    pub filters: OperatorReportQuery,
    pub exposure_positions: Vec<ExposureLedgerCurrencyPosition>,
    pub decision_summary: ComptrollerDecisionSummary,
    pub settlement_reconciliation: SettlementReconciliationSummary,
    pub budget_utilization: BudgetUtilizationSummary,
    pub source_refs: ComptrollerSurfaceSourceRefs,
    /// Reserved for future execution-nonce linkage; omitted until a later schema
    /// revision to avoid a governance-gated schema bump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_nonce_ref: Option<String>,
    /// Reserved for future hold linkage; omitted until a later schema revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_ref: Option<String>,
}

impl ComptrollerSurfaceReport {
    /// Compose the projection from the already-built operator + exposure read models.
    pub fn from_parts(operator: &OperatorReport, exposure: &ExposureLedgerReport) -> Self {
        Self {
            schema: COMPTROLLER_SURFACE_REPORT_SCHEMA.to_string(),
            generated_at: operator.generated_at,
            filters: operator.filters.clone(),
            exposure_positions: exposure.positions.clone(),
            decision_summary: ComptrollerDecisionSummary {
                allow_count: operator.activity.summary.allow_count,
                deny_count: operator.activity.summary.deny_count,
                cancelled_count: operator.activity.summary.cancelled_count,
                incomplete_count: operator.activity.summary.incomplete_count,
            },
            settlement_reconciliation: operator.settlement_reconciliation.summary.clone(),
            budget_utilization: operator.budget_utilization.summary.clone(),
            source_refs: ComptrollerSurfaceSourceRefs::default(),
            execution_nonce_ref: None,
            hold_ref: None,
        }
    }

    /// Fail-closed single-domain invariant over the credit exposure positions.
    ///
    /// Within each currency position, outstanding holds (reserved + pending) must not exceed the
    /// governed exposure ceiling. A ceiling of 0 means "no governed ceiling" and is skipped
    /// (fail-safe). This is a credit-domain-only check; it does NOT cross into kernel budget cost
    /// units, whose unit mapping to exposure units is undefined.
    pub fn validate_consistency(&self) -> Result<(), String> {
        for position in &self.exposure_positions {
            if position.governed_max_exposure_units == 0 {
                continue;
            }
            // Fail-closed: an outstanding sum that overflows u64 must be reported
            // as an inconsistency, not clamped. A saturating add would pin
            // `outstanding` to the u64 ceiling and pass the comparison below even
            // though the true reserved + pending exposure exceeds the governed
            // limit, masking an over-limit position.
            let Some(outstanding) = position.reserved_units.checked_add(position.pending_units)
            else {
                return Err(format!(
                    "exposure position {} outstanding holds overflow u64 (reserved {} + pending {})",
                    position.currency, position.reserved_units, position.pending_units
                ));
            };
            if outstanding > position.governed_max_exposure_units {
                return Err(format!(
                    "exposure position {} outstanding holds {} exceed governed ceiling {}",
                    position.currency, outstanding, position.governed_max_exposure_units
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_credit::ExposureLedgerCurrencyPosition;

    fn position(
        currency: &str,
        governed: u64,
        reserved: u64,
        pending: u64,
    ) -> ExposureLedgerCurrencyPosition {
        ExposureLedgerCurrencyPosition {
            currency: currency.to_string(),
            governed_max_exposure_units: governed,
            reserved_units: reserved,
            settled_units: 0,
            pending_units: pending,
            failed_units: 0,
            provisional_loss_units: 0,
            recovered_units: 0,
            quoted_premium_units: 0,
            active_quoted_premium_units: 0,
        }
    }

    fn sample() -> ComptrollerSurfaceReport {
        ComptrollerSurfaceReport {
            schema: COMPTROLLER_SURFACE_REPORT_SCHEMA.to_string(),
            generated_at: 1_700_000_000,
            filters: OperatorReportQuery::default(),
            exposure_positions: vec![position("USD", 4200, 1000, 200)],
            decision_summary: ComptrollerDecisionSummary {
                allow_count: 1,
                deny_count: 1,
                cancelled_count: 0,
                incomplete_count: 0,
            },
            settlement_reconciliation: SettlementReconciliationSummary::default(),
            budget_utilization: BudgetUtilizationSummary::default(),
            source_refs: ComptrollerSurfaceSourceRefs::default(),
            execution_nonce_ref: None,
            hold_ref: None,
        }
    }

    #[test]
    fn serde_round_trip_is_camel_case() {
        let report = sample();
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("\"schema\":\"chio.comptroller.surface-report.v1\""));
        assert!(json.contains("\"generatedAt\""));
        assert!(json.contains("\"exposurePositions\""));
        assert!(json.contains("\"governedMaxExposureUnits\""));
        assert!(json.contains("\"allowCount\""));
        // Reserved linkage slots are omitted until they are populated.
        assert!(!json.contains("executionNonceRef"));
        assert!(!json.contains("holdRef"));
        let back: ComptrollerSurfaceReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(report, back);
    }

    #[test]
    fn validate_consistency_accepts_coherent_positions() {
        assert!(sample().validate_consistency().is_ok());
    }

    #[test]
    fn validate_consistency_rejects_outstanding_over_governed_ceiling() {
        let mut report = sample();
        report.exposure_positions = vec![position("USD", 4200, 5000, 0)];
        let err = report
            .validate_consistency()
            .expect_err("must reject over-ceiling");
        assert!(err.contains("exceed governed ceiling"));
    }

    #[test]
    fn validate_consistency_treats_zero_ceiling_as_no_ceiling() {
        let mut report = sample();
        report.exposure_positions = vec![position("USD", 0, u64::MAX / 2, u64::MAX / 2)];
        assert!(report.validate_consistency().is_ok());
    }

    #[test]
    fn validate_consistency_rejects_outstanding_overflow_over_ceiling() {
        let mut report = sample();
        // reserved + pending overflows u64, so a saturating clamp would pin
        // outstanding to the u64 ceiling and silently pass a governed limit that
        // the true exposure exceeds. A fail-closed validator must reject it.
        report.exposure_positions = vec![position("USD", u64::MAX, u64::MAX, 1)];
        let err = report
            .validate_consistency()
            .expect_err("overflowing outstanding must fail closed");
        assert!(err.contains("overflow"), "unexpected error: {err}");
    }
}
