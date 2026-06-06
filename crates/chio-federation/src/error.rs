#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FederationContractError {
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(String),

    #[error("missing field: {0}")]
    MissingField(&'static str),

    #[error("duplicate value: {0}")]
    DuplicateValue(String),

    #[error("invalid reference: {0}")]
    InvalidReference(String),

    #[error("invalid exchange: {0}")]
    InvalidExchange(String),

    #[error("invalid quorum: {0}")]
    InvalidQuorum(String),

    #[error("invalid admission: {0}")]
    InvalidAdmission(String),

    #[error("invalid clearing: {0}")]
    InvalidClearing(String),

    #[error("invalid qualification case: {0}")]
    InvalidQualificationCase(String),
}
