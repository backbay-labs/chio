use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommerceOrderError {
    #[error("unsupported commerce schema for {field}: {schema}")]
    UnsupportedSchema { field: &'static str, schema: String },
    #[error("invalid commerce artifact {field}: {message}")]
    InvalidArtifact {
        field: &'static str,
        message: String,
    },
    #[error("{field} digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch {
        field: String,
        expected: String,
        actual: String,
    },
    #[error("commerce replay failed: {0}")]
    ReplayFailed(String),
    #[error("commerce payment failed: {0}")]
    PaymentFailed(String),
    #[error("commerce mandate failed: {0}")]
    MandateFailed(String),
    #[error("commerce provider trust failed: {0}")]
    ProviderTrustFailed(String),
    #[error("commerce settlement failed: {0}")]
    SettlementFailed(String),
    #[error("commerce coverage failed: {0}")]
    CoverageFailed(String),
}
