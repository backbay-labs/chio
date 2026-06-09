//! Error types for chio-core.
//!
//! Under the default `std` feature the `Error` enum is a normal
//! [`thiserror::Error`] deriving `std::error::Error`. Under `no_std`, the
//! crate provides equivalent `core::fmt::Display` + `core::error::Error`
//! impls so the enum remains usable in portable consumers (wasm32 edge,
//! embedded kernels). The variants, payload shapes, and serde behaviour
//! are bit-identical on both feature paths.

use alloc::string::String;

/// All errors produced by chio-core.
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[derive(Debug)]
pub enum Error {
    #[cfg_attr(feature = "std", error("invalid public key: {0}"))]
    InvalidPublicKey(String),

    #[cfg_attr(feature = "std", error("invalid hex: {0}"))]
    InvalidHex(String),

    #[cfg_attr(feature = "std", error("invalid signature: {0}"))]
    InvalidSignature(String),

    #[cfg_attr(feature = "std", error("json serialization error: {0}"))]
    Json(#[cfg_attr(feature = "std", from)] serde_json::Error),

    #[cfg_attr(feature = "std", error("canonical JSON error: {0}"))]
    CanonicalJson(String),

    #[cfg_attr(feature = "std", error("capability expired at {expires_at}"))]
    CapabilityExpired { expires_at: u64 },

    #[cfg_attr(
        feature = "std",
        error("capability not yet valid (not_before: {not_before})")
    )]
    CapabilityNotYetValid { not_before: u64 },

    #[cfg_attr(feature = "std", error("capability revoked: {id}"))]
    CapabilityRevoked { id: String },

    #[cfg_attr(feature = "std", error("delegation chain broken: {reason}"))]
    DelegationChainBroken { reason: String },

    #[cfg_attr(feature = "std", error("attenuation violation: {reason}"))]
    AttenuationViolation { reason: String },

    #[cfg_attr(feature = "std", error("scope mismatch: {reason}"))]
    ScopeMismatch { reason: String },

    #[cfg_attr(feature = "std", error("signature verification failed"))]
    SignatureVerificationFailed,

    #[cfg_attr(
        feature = "std",
        error("delegation depth {depth} exceeds maximum {max}")
    )]
    DelegationDepthExceeded { depth: u32, max: u32 },

    #[cfg_attr(
        feature = "std",
        error("invalid hash length: expected {expected}, got {actual}")
    )]
    InvalidHashLength { expected: usize, actual: usize },

    #[cfg_attr(feature = "std", error("merkle proof verification failed"))]
    MerkleProofFailed,

    #[cfg_attr(feature = "std", error("empty tree: cannot compute root"))]
    EmptyTree,

    #[cfg_attr(
        feature = "std",
        error("invalid proof: leaf index {index} out of bounds for tree with {leaves} leaves")
    )]
    InvalidProofIndex { index: usize, leaves: usize },
}

// `From<serde_json::Error>` is emitted by `#[from]` under the `std` feature.
// Provide an equivalent impl for the `no_std` path so callers can still use
// `?` on serde_json results.
#[cfg(not(feature = "std"))]
impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Json(err)
    }
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidPublicKey(m) => write!(f, "invalid public key: {m}"),
            Error::InvalidHex(m) => write!(f, "invalid hex: {m}"),
            Error::InvalidSignature(m) => write!(f, "invalid signature: {m}"),
            Error::Json(m) => write!(f, "json serialization error: {m}"),
            Error::CanonicalJson(m) => write!(f, "canonical JSON error: {m}"),
            Error::CapabilityExpired { expires_at } => {
                write!(f, "capability expired at {expires_at}")
            }
            Error::CapabilityNotYetValid { not_before } => {
                write!(f, "capability not yet valid (not_before: {not_before})")
            }
            Error::CapabilityRevoked { id } => write!(f, "capability revoked: {id}"),
            Error::DelegationChainBroken { reason } => {
                write!(f, "delegation chain broken: {reason}")
            }
            Error::AttenuationViolation { reason } => {
                write!(f, "attenuation violation: {reason}")
            }
            Error::ScopeMismatch { reason } => write!(f, "scope mismatch: {reason}"),
            Error::SignatureVerificationFailed => write!(f, "signature verification failed"),
            Error::DelegationDepthExceeded { depth, max } => {
                write!(f, "delegation depth {depth} exceeds maximum {max}")
            }
            Error::InvalidHashLength { expected, actual } => {
                write!(f, "invalid hash length: expected {expected}, got {actual}")
            }
            Error::MerkleProofFailed => write!(f, "merkle proof verification failed"),
            Error::EmptyTree => write!(f, "empty tree: cannot compute root"),
            Error::InvalidProofIndex { index, leaves } => write!(
                f,
                "invalid proof: leaf index {index} out of bounds for tree with {leaves} leaves"
            ),
        }
    }
}

#[cfg(not(feature = "std"))]
impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Error::Json(err) => Some(err),
            _ => None,
        }
    }
}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, Error>;
