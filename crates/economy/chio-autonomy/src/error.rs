#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AutonomyContractError {
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),

    #[error("missing field: {0}")]
    MissingField(&'static str),

    #[error("duplicate value: {0}")]
    DuplicateValue(String),

    #[error("unknown reference: {0}")]
    UnknownReference(String),

    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),

    #[error("invalid decision: {0}")]
    InvalidDecision(String),

    #[error("invalid optimization: {0}")]
    InvalidOptimization(String),

    #[error("invalid execution: {0}")]
    InvalidExecution(String),

    #[error("invalid drift: {0}")]
    InvalidDrift(String),

    #[error("invalid qualification case: {0}")]
    InvalidQualificationCase(String),
}
