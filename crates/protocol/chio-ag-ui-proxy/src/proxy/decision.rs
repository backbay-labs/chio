/// The proxy's decision for an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyDecision {
    /// Forward the event to the UI.
    Forward,
    /// Block the event with a reason.
    Block { reason: String },
}

/// Errors from the AG-UI proxy.
#[derive(Debug, thiserror::Error)]
pub enum AgUiProxyError {
    #[error("receipt signing failed: {0}")]
    ReceiptSigning(String),

    #[error("invalid event: {0}")]
    InvalidEvent(String),

    #[error("budget registry failed: {0}")]
    BudgetRegistry(String),
}
