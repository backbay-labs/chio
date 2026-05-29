// Edge error type and receipt-write error accounting helpers.

/// Errors produced by the ACP edge.
#[derive(Debug, thiserror::Error)]
pub enum AcpEdgeError {
    /// A tool was not found.
    #[error("tool not found: {0}")]
    ToolNotFound(String),

    /// The request was malformed.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Access was denied.
    #[error("access denied: {0}")]
    AccessDenied(String),

    /// The kernel reported an error.
    #[error("kernel error: {0}")]
    Kernel(String),

    /// Manifest error.
    #[error("manifest error: {0}")]
    Manifest(#[from] chio_manifest::ManifestError),

    /// Cross-protocol orchestration failed.
    #[error("bridge error: {0}")]
    Bridge(#[from] chio_cross_protocol::BridgeError),
}

fn record_receipt_write_error() {
    crate::metrics::record_receipt_write(crate::metrics::RECEIPT_WRITE_OUTCOME_ERROR);
}

fn record_receipt_write_bridge_error(error: &BridgeError) {
    if matches!(error, BridgeError::Kernel(_)) {
        record_receipt_write_error();
    }
}
