use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransactionPassportError {
    #[error("unsupported transaction passport schema: {0}")]
    UnsupportedSchema(String),
    #[error("invalid transaction passport field {field}: {message}")]
    InvalidPassportField { field: String, message: String },
    #[error("invalid transaction passport timestamp {field}: {value}: {message}")]
    InvalidPassportTimestamp {
        field: String,
        value: String,
        message: String,
    },
    #[error("transaction passport validity window invalid: {0}")]
    InvalidPassportValidityWindow(String),
    #[error("transaction passport not yet valid: not_before {not_before}, now {now}")]
    PassportNotYetValid { not_before: String, now: String },
    #[error("transaction passport expired: expires_at {expires_at}, now {now}")]
    PassportExpired { expires_at: String, now: String },
    #[error("trusted transaction root keys missing")]
    MissingTrustedTransactionRootKeys,
    #[error("transaction passport signer is not trusted")]
    UntrustedTransactionPassportSigner,
    #[error("transaction passport signature invalid: {0}")]
    InvalidPassportSignature(String),
    #[error("invalid evidence graph digest: {0}")]
    InvalidEvidenceGraphDigest(String),
    #[error("invalid claim set digest: {0}")]
    InvalidClaimSetDigest(String),
    #[error("invalid verifier policy digest: {0}")]
    InvalidVerifierPolicyDigest(String),
    #[error("unsafe evidence graph path: {0}")]
    UnsafeEvidenceGraphPath(String),
    #[error("unsafe claim set path: {0}")]
    UnsafeClaimSetPath(String),
    #[error("unsafe verifier policy path: {0}")]
    UnsafeVerifierPolicyPath(String),
    #[error("invalid evidence graph artifact: {0}")]
    InvalidEvidenceGraphArtifact(String),
    #[error("unsupported evidence graph schema: {0}")]
    UnsupportedEvidenceGraphSchema(String),
    #[error("missing evidence graph artifact: {0}")]
    MissingEvidenceGraphArtifact(String),
    #[error(
        "evidence graph artifact digest mismatch for {path}: expected {expected}, got {actual}"
    )]
    EvidenceGraphArtifactDigestMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("invalid verifier policy artifact: {0}")]
    InvalidVerifierPolicyArtifact(String),
    #[error("unsupported verifier policy schema: {0}")]
    UnsupportedVerifierPolicySchema(String),
    #[error("missing execution lease")]
    MissingExecutionLease,
    #[error("missing runtime artifact: {0}")]
    MissingRuntimeArtifact(String),
    #[error("invalid runtime artifact {path}: {message}")]
    InvalidRuntimeArtifact { path: String, message: String },
    #[error("runtime security claim failed: {0}")]
    RuntimeSecurityClaimFailed(String),
    #[error("missing enterprise artifact: {0}")]
    MissingEnterpriseArtifact(String),
    #[error("invalid enterprise artifact {path}: {message}")]
    InvalidEnterpriseArtifact { path: String, message: String },
    #[error("enterprise export claim failed: {0}")]
    EnterpriseExportClaimFailed(String),
    #[error("missing Agent Web artifact: {0}")]
    MissingAgentWebArtifact(String),
    #[error("invalid Agent Web artifact {path}: {message}")]
    InvalidAgentWebArtifact { path: String, message: String },
    #[error("Agent Web claim failed: {0}")]
    AgentWebClaimFailed(String),
    #[error("missing trust-market artifact: {0}")]
    MissingTrustMarketArtifact(String),
    #[error("invalid trust-market artifact {path}: {message}")]
    InvalidTrustMarketArtifact { path: String, message: String },
    #[error("trust-market claim failed: {0}")]
    TrustMarketClaimFailed(String),
    #[error("risk comptroller claim failed: {0}")]
    RiskComptrollerClaimFailed(String),
    #[error("missing cognition-market artifact: {0}")]
    MissingCognitionMarketArtifact(String),
    #[error("invalid cognition-market artifact {path}: {message}")]
    InvalidCognitionMarketArtifact { path: String, message: String },
    #[error("cognition-market claim failed: {0}")]
    CognitionMarketClaimFailed(String),
    #[error("advisory evidence cannot authorize runtime execution")]
    AdvisoryEvidenceCannotAuthorize,
    #[error("evidence graph digest mismatch: expected {expected}, got {actual}")]
    EvidenceGraphDigestMismatch { expected: String, actual: String },
    #[error("verifier policy digest mismatch: expected {expected}, got {actual}")]
    VerifierPolicyDigestMismatch { expected: String, actual: String },
}
