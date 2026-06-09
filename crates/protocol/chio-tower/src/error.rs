//! Error types for the Chio tower middleware.

use std::fmt;

/// Error type for Chio tower middleware operations.
#[derive(Debug)]
pub enum ChioTowerError {
    /// Failed to evaluate the request.
    Evaluation(String),
    /// Failed to sign a receipt.
    ReceiptSign(String),
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
