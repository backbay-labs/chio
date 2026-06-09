use super::*;

pub(super) fn into_receipt_store_error(error: CliError) -> ReceiptStoreError {
    ReceiptStoreError::Io(std::io::Error::other(error.to_string()))
}

pub(super) fn into_revocation_store_error(error: CliError) -> RevocationStoreError {
    RevocationStoreError::Io(std::io::Error::other(error.to_string()))
}

pub(super) fn into_budget_store_error(error: CliError) -> BudgetStoreError {
    BudgetStoreError::Io(std::io::Error::other(error.to_string()))
}
