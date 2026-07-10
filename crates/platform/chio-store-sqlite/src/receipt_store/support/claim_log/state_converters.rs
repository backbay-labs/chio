use super::*;

pub(crate) fn settlement_reconciliation_state_text(
    state: SettlementReconciliationState,
) -> &'static str {
    match state {
        SettlementReconciliationState::Open => "open",
        SettlementReconciliationState::Reconciled => "reconciled",
        SettlementReconciliationState::Ignored => "ignored",
        SettlementReconciliationState::RetryScheduled => "retry_scheduled",
    }
}

pub(crate) fn parse_settlement_reconciliation_state(
    value: &str,
) -> Result<SettlementReconciliationState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn metered_billing_reconciliation_state_text(
    state: MeteredBillingReconciliationState,
) -> &'static str {
    match state {
        MeteredBillingReconciliationState::Open => "open",
        MeteredBillingReconciliationState::Reconciled => "reconciled",
        MeteredBillingReconciliationState::Ignored => "ignored",
        MeteredBillingReconciliationState::RetryScheduled => "retry_scheduled",
    }
}

pub(crate) fn parse_metered_billing_reconciliation_state(
    value: &str,
) -> Result<MeteredBillingReconciliationState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn underwriting_decision_outcome_label(
    outcome: UnderwritingDecisionOutcome,
) -> &'static str {
    match outcome {
        UnderwritingDecisionOutcome::Approve => "approve",
        UnderwritingDecisionOutcome::ReduceCeiling => "reduce_ceiling",
        UnderwritingDecisionOutcome::StepUp => "step_up",
        UnderwritingDecisionOutcome::Deny => "deny",
    }
}

pub(crate) fn underwriting_lifecycle_state_label(
    state: UnderwritingDecisionLifecycleState,
) -> &'static str {
    match state {
        UnderwritingDecisionLifecycleState::Active => "active",
        UnderwritingDecisionLifecycleState::Superseded => "superseded",
    }
}

pub(crate) fn underwriting_review_state_label(
    state: chio_kernel::UnderwritingReviewState,
) -> &'static str {
    match state {
        chio_kernel::UnderwritingReviewState::Approved => "approved",
        chio_kernel::UnderwritingReviewState::ManualReviewRequired => "manual_review_required",
        chio_kernel::UnderwritingReviewState::Denied => "denied",
    }
}

pub(crate) fn underwriting_risk_class_label(
    class: chio_kernel::UnderwritingRiskClass,
) -> &'static str {
    match class {
        chio_kernel::UnderwritingRiskClass::Baseline => "baseline",
        chio_kernel::UnderwritingRiskClass::Guarded => "guarded",
        chio_kernel::UnderwritingRiskClass::Elevated => "elevated",
        chio_kernel::UnderwritingRiskClass::Critical => "critical",
    }
}

pub(crate) fn underwriting_appeal_status_label(status: UnderwritingAppealStatus) -> &'static str {
    match status {
        UnderwritingAppealStatus::Open => "open",
        UnderwritingAppealStatus::Accepted => "accepted",
        UnderwritingAppealStatus::Rejected => "rejected",
    }
}

pub(crate) fn credit_facility_disposition_label(
    disposition: CreditFacilityDisposition,
) -> &'static str {
    match disposition {
        CreditFacilityDisposition::Grant => "grant",
        CreditFacilityDisposition::ManualReview => "manual_review",
        CreditFacilityDisposition::Deny => "deny",
    }
}

pub(crate) fn credit_facility_lifecycle_state_label(
    state: CreditFacilityLifecycleState,
) -> &'static str {
    match state {
        CreditFacilityLifecycleState::Active => "active",
        CreditFacilityLifecycleState::Superseded => "superseded",
        CreditFacilityLifecycleState::Denied => "denied",
        CreditFacilityLifecycleState::Expired => "expired",
    }
}

pub(crate) fn credit_bond_disposition_label(disposition: CreditBondDisposition) -> &'static str {
    match disposition {
        CreditBondDisposition::Lock => "lock",
        CreditBondDisposition::Hold => "hold",
        CreditBondDisposition::Release => "release",
        CreditBondDisposition::Impair => "impair",
    }
}

pub(crate) fn credit_bond_lifecycle_state_label(state: CreditBondLifecycleState) -> &'static str {
    match state {
        CreditBondLifecycleState::Active => "active",
        CreditBondLifecycleState::Superseded => "superseded",
        CreditBondLifecycleState::Released => "released",
        CreditBondLifecycleState::Impaired => "impaired",
        CreditBondLifecycleState::Expired => "expired",
    }
}

pub(crate) fn liability_provider_lifecycle_state_label(
    state: LiabilityProviderLifecycleState,
) -> &'static str {
    match state {
        LiabilityProviderLifecycleState::Active => "active",
        LiabilityProviderLifecycleState::Suspended => "suspended",
        LiabilityProviderLifecycleState::Superseded => "superseded",
        LiabilityProviderLifecycleState::Retired => "retired",
    }
}

pub(crate) fn credit_loss_lifecycle_event_kind_label(
    kind: CreditLossLifecycleEventKind,
) -> &'static str {
    match kind {
        CreditLossLifecycleEventKind::Delinquency => "delinquency",
        CreditLossLifecycleEventKind::Recovery => "recovery",
        CreditLossLifecycleEventKind::ReserveRelease => "reserve_release",
        CreditLossLifecycleEventKind::ReserveSlash => "reserve_slash",
        CreditLossLifecycleEventKind::WriteOff => "write_off",
    }
}

pub(crate) fn parse_underwriting_lifecycle_state(
    value: &str,
) -> Result<UnderwritingDecisionLifecycleState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn parse_credit_facility_lifecycle_state(
    value: &str,
) -> Result<CreditFacilityLifecycleState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn parse_credit_bond_lifecycle_state(
    value: &str,
) -> Result<CreditBondLifecycleState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn parse_liability_provider_lifecycle_state(
    value: &str,
) -> Result<LiabilityProviderLifecycleState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn liability_quote_disposition_label(
    disposition: &LiabilityQuoteDisposition,
) -> &'static str {
    match disposition {
        LiabilityQuoteDisposition::Quoted => "quoted",
        LiabilityQuoteDisposition::Declined => "declined",
    }
}

pub(crate) fn liability_auto_bind_disposition_label(
    disposition: &LiabilityAutoBindDisposition,
) -> &'static str {
    match disposition {
        LiabilityAutoBindDisposition::AutoBound => "auto_bound",
        LiabilityAutoBindDisposition::ManualReview => "manual_review",
        LiabilityAutoBindDisposition::Denied => "denied",
    }
}
