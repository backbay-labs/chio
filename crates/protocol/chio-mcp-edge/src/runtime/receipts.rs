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
    use super::is_receipt_write_error;
    use chio_kernel::KernelError;

    #[test]
    fn receipt_write_error_classifier_excludes_control_flow_errors() {
        let cancelled = KernelError::RequestCancelled {
            request_id: chio_core::session::RequestId::new("cancelled-request"),
            reason: "cancelled by client".to_string(),
        };
        let url_elicitation = KernelError::UrlElicitationsRequired {
            message: "URL elicitation required".to_string(),
            elicitations: Vec::new(),
        };
        let internal = KernelError::Internal("receipt sink unavailable".to_string());

        assert!(!is_receipt_write_error(&cancelled));
        assert!(!is_receipt_write_error(&url_elicitation));
        assert!(is_receipt_write_error(&internal));
    }
}
