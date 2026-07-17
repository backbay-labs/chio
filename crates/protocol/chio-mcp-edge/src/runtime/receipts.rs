pub(super) fn record_receipt_write_error() {
    crate::metrics::record_receipt_write(crate::metrics::RECEIPT_WRITE_OUTCOME_ERROR);
}

fn is_receipt_write_error(error: &chio_kernel::KernelError) -> bool {
    !matches!(
        error,
        chio_kernel::KernelError::RequestCancelled { .. }
            | chio_kernel::KernelError::UrlElicitationsRequired { .. }
    )
}

pub(super) fn record_receipt_write_kernel_error(error: &chio_kernel::KernelError) {
    if is_receipt_write_error(error) {
        record_receipt_write_error();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_url_elicitation_is_not_a_receipt_write_error() {
        let error = chio_kernel::KernelError::UrlElicitationsRequired {
            message: "URL elicitation required".to_string(),
            elicitations: Vec::new(),
        };

        assert!(!is_receipt_write_error(&error));
        assert!(is_receipt_write_error(&chio_kernel::KernelError::Internal(
            "receipt sink unavailable".to_string()
        )));
    }
}
