#[derive(Debug, thiserror::Error)]
pub enum ChioPackageError {
    #[error("canonical JSON failed: {0}")]
    Canonical(String),
    #[error("package schema is unsupported: {0}")]
    UnsupportedSchema(String),
    #[error("unsupported proof claim: {0}")]
    UnsupportedClaim(String),
    #[error("workflow verification failed: {0}")]
    Workflow(String),
    #[error("governance verification failed: {0}")]
    Governance(String),
    #[error("federation verification failed: {0}")]
    Federation(String),
    #[error("selective disclosure verification failed: {0}")]
    SelectiveDisclosure(String),
    #[error("trusted issuer registry failed: {0}")]
    TrustedIssuer(String),
    #[error("verifier trust bundle failed: {0}")]
    TrustBundle(String),
    #[error("workflow intersection failed: {0}")]
    WorkflowIntersection(String),
    #[error("lease scope binding failed: {0}")]
    LeaseScopeBinding(String),
    #[error("verification context failed: {0}")]
    VerificationContext(String),
    #[error("package data is inconsistent: {0}")]
    Inconsistent(String),
    #[error("JSON operation failed: {0}")]
    Json(String),
}
