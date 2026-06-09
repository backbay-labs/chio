pub(super) fn record_receipt_write_error() {
    crate::metrics::record_receipt_write(crate::metrics::RECEIPT_WRITE_OUTCOME_ERROR);
}

pub(super) fn record_receipt_write_kernel_error(error: &chio_kernel::KernelError) {
    match error {
        chio_kernel::KernelError::RequestCancelled { .. }
        | chio_kernel::KernelError::UrlElicitationsRequired { .. } => {}
        _ => record_receipt_write_error(),
    }
}
