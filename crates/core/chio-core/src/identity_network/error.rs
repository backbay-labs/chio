#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentityNetworkContractError {
    #[error("unsupported schema `{0}`")]
    UnsupportedSchema(String),
    #[error("missing required field `{0}`")]
    MissingField(&'static str),
    #[error("duplicate value `{0}`")]
    DuplicateValue(String),
    #[error("invalid reference `{0}`")]
    InvalidReference(String),
    #[error("invalid identity profile `{0}`")]
    InvalidProfile(String),
    #[error("invalid wallet directory entry `{0}`")]
    InvalidDirectoryEntry(String),
    #[error("invalid wallet routing manifest `{0}`")]
    InvalidRouting(String),
    #[error("invalid qualification case `{0}`")]
    InvalidQualificationCase(String),
}
