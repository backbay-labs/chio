//! Mobile attestation verifier errors.

use thiserror::Error;

pub const URN_APP_ATTEST_INVALID_CBOR: &str = "urn:chio:error:custody:app-attest-invalid-cbor";
pub const URN_APP_ATTEST_INVALID_ROOT: &str = "urn:chio:error:custody:app-attest-invalid-root";
pub const URN_APP_ATTEST_APP_MISMATCH: &str = "urn:chio:error:custody:app-attest-app-mismatch";
pub const URN_APP_ATTEST_CHALLENGE_MISMATCH: &str =
    "urn:chio:error:custody:app-attest-challenge-mismatch";
pub const URN_APP_ATTEST_KEY_MISMATCH: &str = "urn:chio:error:custody:app-attest-key-mismatch";
pub const URN_APP_ATTEST_CREDENTIAL_KEY_MISMATCH: &str =
    "urn:chio:error:custody:app-attest-credential-key-mismatch";
pub const URN_APP_ATTEST_COUNTER_ROLLBACK: &str =
    "urn:chio:error:custody:app-attest-counter-rollback";
pub const URN_APP_ATTEST_CERT_CHAIN_INVALID: &str =
    "urn:chio:error:custody:app-attest-cert-chain-invalid";
pub const URN_PLAY_INTEGRITY_INVALID_TOKEN: &str =
    "urn:chio:error:custody:play-integrity-invalid-token";
pub const URN_PLAY_INTEGRITY_NONCE_MISMATCH: &str =
    "urn:chio:error:custody:play-integrity-nonce-mismatch";
pub const URN_PLAY_INTEGRITY_APP_REJECTED: &str =
    "urn:chio:error:custody:play-integrity-app-rejected";
pub const URN_PLAY_INTEGRITY_DEVICE_REJECTED: &str =
    "urn:chio:error:custody:play-integrity-device-rejected";

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
    #[error("app attest: attestation leaf public key does not match credential public key")]
    CredentialKeyMismatch,
    #[error("app attest: counter rollback")]
    CounterRollback,
    #[error("app attest: certificate chain invalid: {0}")]
    CertificateChainInvalid(String),
    #[error("app attest: missing field {0}")]
    MissingField(&'static str),
    #[error("app attest: unsupported format {0}")]
    UnsupportedFormat(String),
    #[error("play integrity: invalid token: {0}")]
    PlayIntegrityInvalidToken(String),
    #[error("play integrity: nonce mismatch")]
    PlayIntegrityNonceMismatch,
    #[error("play integrity: app rejected")]
    PlayIntegrityAppRejected,
    #[error("play integrity: device rejected")]
    PlayIntegrityDeviceRejected,
    #[error("play integrity: package mismatch")]
    PlayIntegrityPackageMismatch,
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
            Self::CredentialKeyMismatch => URN_APP_ATTEST_CREDENTIAL_KEY_MISMATCH,
            Self::CounterRollback => URN_APP_ATTEST_COUNTER_ROLLBACK,
            Self::CertificateChainInvalid(_) => URN_APP_ATTEST_CERT_CHAIN_INVALID,
            Self::PlayIntegrityInvalidToken(_) => URN_PLAY_INTEGRITY_INVALID_TOKEN,
            Self::PlayIntegrityNonceMismatch => URN_PLAY_INTEGRITY_NONCE_MISMATCH,
            Self::PlayIntegrityAppRejected | Self::PlayIntegrityPackageMismatch => {
                URN_PLAY_INTEGRITY_APP_REJECTED
            }
            Self::PlayIntegrityDeviceRejected => URN_PLAY_INTEGRITY_DEVICE_REJECTED,
        }
    }
}
