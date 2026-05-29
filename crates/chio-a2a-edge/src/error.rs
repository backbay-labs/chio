// Edge error type and receipt-write error accounting helpers.

/// Errors produced by the A2A edge.
#[derive(Debug, thiserror::Error)]
pub enum A2aEdgeError {
    /// A tool was not found.
    #[error("tool not found: {0}")]
    ToolNotFound(String),

    /// The request was malformed.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// The kernel denied the request.
    #[error("kernel error: {0}")]
    Kernel(String),

    /// Manifest construction failed.
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
