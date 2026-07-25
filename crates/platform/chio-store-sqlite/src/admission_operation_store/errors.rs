use super::*;

pub(super) fn map_budget_capture_error(error: BudgetStoreError) -> AdmissionCaptureError {
    match error {
        BudgetStoreError::Fenced { .. } => AdmissionCaptureError::Fenced,
        BudgetStoreError::OutcomeUnknown(detail) => AdmissionCaptureError::OutcomeUnknown(detail),
        error => AdmissionCaptureError::Invariant(error.to_string()),
    }
}

pub(super) fn map_payment_operation_error(
    error: AdmissionOperationStoreError,
) -> AdmissionPaymentJournalError {
    match error {
        AdmissionOperationStoreError::Fenced => AdmissionPaymentJournalError::Fenced,
        AdmissionOperationStoreError::OutcomeUnknown(detail) => {
            AdmissionPaymentJournalError::OutcomeUnknown(detail)
        }
        AdmissionOperationStoreError::Unavailable(detail) => {
            AdmissionPaymentJournalError::Unavailable(detail)
        }
        error => AdmissionPaymentJournalError::Invariant(error.to_string()),
    }
}

pub(super) fn map_payment_budget_error(error: BudgetStoreError) -> AdmissionPaymentJournalError {
    match error {
        BudgetStoreError::Fenced { .. } => AdmissionPaymentJournalError::Fenced,
        BudgetStoreError::OutcomeUnknown(detail) => {
            AdmissionPaymentJournalError::OutcomeUnknown(detail)
        }
        BudgetStoreError::Invariant(detail) => AdmissionPaymentJournalError::Conflict(detail),
        error => AdmissionPaymentJournalError::Invariant(error.to_string()),
    }
}

pub(super) fn map_payment_owner_error(
    error: SqliteServingOwnerError,
) -> AdmissionPaymentJournalError {
    match error {
        SqliteServingOwnerError::OutcomeUnknown(detail) => {
            AdmissionPaymentJournalError::OutcomeUnknown(detail)
        }
        error => AdmissionPaymentJournalError::Invariant(error.to_string()),
    }
}
