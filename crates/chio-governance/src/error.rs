#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum GovernanceAuthorizationError {
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),
    #[error("invalid authorization artifact: {0}")]
    InvalidArtifact(String),
    #[error("authorization signature is invalid")]
    InvalidSignature,
    #[error("capability lease is expired or unknown: {0}")]
    LeaseExpiredOrUnknown(String),
    #[error("capability lease is not yet valid: {0}")]
    LeaseNotYetValid(String),
    #[error("capability lease scope digest mismatch")]
    ScopeDigestMismatch,
    #[error("governance receipt is required for destructive steps")]
    GovernanceReceiptRequired,
    #[error("governance receipt is not yet valid: {0}")]
    GovernanceReceiptNotYetValid(String),
    #[error("governance receipt workflow mismatch")]
    WorkflowMismatch,
    #[error("governance receipt step hash mismatch")]
    StepHashMismatch,
    #[error("governance receipt lease mismatch")]
    LeaseMismatch,
    #[error("canonical signature operation failed: {0}")]
    Crypto(String),
}
