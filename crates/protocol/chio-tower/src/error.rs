//! Error types for the Chio tower middleware.

use std::fmt;

/// Error type for Chio tower middleware operations.
#[derive(Debug)]
pub enum ChioTowerError {
    /// Failed to evaluate the request.
    Evaluation(String),
    /// Failed to sign a receipt.
    ReceiptSign(String),
    /// Failed to persist a signed receipt to the configured durable receipt
    /// store. A durable store is attached but its append (or the conversion of
    /// the HTTP receipt into a core receipt) failed, so the request fails closed
    /// rather than completing without a recorded audit trail.
    ReceiptPersist(String),
    /// Failed to extract caller identity.
    IdentityExtraction(String),
    /// Inner service error.
    Inner(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for ChioTowerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evaluation(msg) => write!(f, "Chio evaluation error: {msg}"),
            Self::ReceiptSign(msg) => write!(f, "Chio receipt signing error: {msg}"),
            Self::ReceiptPersist(msg) => write!(f, "Chio receipt persistence error: {msg}"),
            Self::IdentityExtraction(msg) => write!(f, "Chio identity extraction error: {msg}"),
            Self::Inner(err) => write!(f, "inner service error: {err}"),
        }
    }
}

impl std::error::Error for ChioTowerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inner(err) => Some(err.as_ref()),
            _ => None,
        }
    }
}
