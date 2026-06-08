#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExtensionContractError {
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),

    #[error("missing field: {0}")]
    MissingField(&'static str),

    #[error("duplicate id or value: {0}")]
    DuplicateValue(String),

    #[error("unknown reference: {0}")]
    UnknownReference(String),

    #[error("invalid guardrail: {0}")]
    InvalidGuardrail(String),

    #[error("invalid profile: {0}")]
    InvalidProfile(String),

    #[error("invalid qualification case: {0}")]
    InvalidQualificationCase(String),
}
