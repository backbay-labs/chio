//! Mobile attestation verifier errors.

use thiserror::Error;

pub const URN_APP_ATTEST_INVALID_CBOR: &str = "urn:chio:error:custody:app-attest-invalid-cbor";
pub const URN_APP_ATTEST_INVALID_ROOT: &str = "urn:chio:error:custody:app-attest-invalid-root";
pub const URN_APP_ATTEST_APP_MISMATCH: &str = "urn:chio:error:custody:app-attest-app-mismatch";
pub const URN_APP_ATTEST_CHALLENGE_MISMATCH: &str =
    "urn:chio:error:custody:app-attest-challenge-mismatch";
pub const URN_APP_ATTEST_KEY_MISMATCH: &str = "urn:chio:error:custody:app-attest-key-mismatch";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AttestationError {
    #[error("app attest: invalid CBOR: {0}")]
    InvalidCbor(String),
    #[error("app attest: invalid pinned Apple root: {0}")]
    InvalidRoot(String),
    #[error("app attest: app identifier hash mismatch")]
    AppIdentifierMismatch,
    #[error("app attest: challenge hash mismatch")]
    ChallengeMismatch,
    #[error("app attest: key id mismatch")]
    KeyIdMismatch,
    #[error("app attest: missing field {0}")]
    MissingField(&'static str),
    #[error("app attest: unsupported format {0}")]
    UnsupportedFormat(String),
}

impl AttestationError {
    #[must_use]
    pub fn urn(&self) -> &'static str {
        match self {
            Self::InvalidCbor(_) | Self::MissingField(_) | Self::UnsupportedFormat(_) => {
                URN_APP_ATTEST_INVALID_CBOR
            }
            Self::InvalidRoot(_) => URN_APP_ATTEST_INVALID_ROOT,
            Self::AppIdentifierMismatch => URN_APP_ATTEST_APP_MISMATCH,
            Self::ChallengeMismatch => URN_APP_ATTEST_CHALLENGE_MISMATCH,
            Self::KeyIdMismatch => URN_APP_ATTEST_KEY_MISMATCH,
        }
    }
}
