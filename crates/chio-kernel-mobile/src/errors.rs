//! Error surface exposed across the UniFFI boundary.
//!
//! Every variant carries a human-readable `message: String` so the
//! generated Swift / Kotlin code renders a usable error to the host
//! app without a second lookup. Keeping the payload flat (single
//! `String` per variant) also keeps the UDL `[Error]` interface
//! simple.

#![forbid(unsafe_code)]

use core::fmt;

/// Errors raised by the mobile FFI.
///
/// The variant names in this enum match the `[Error]` interface in
/// `chio_kernel_mobile.udl` exactly; UniFFI relies on the name match
/// to produce the right Swift/Kotlin case for each variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChioMobileError {
    /// A JSON argument failed to parse.
    InvalidJson { message: String },
    /// A hex-encoded key or seed failed to decode.
    InvalidHex { message: String },
    /// Capability verification (signature, issuer trust, or time
    /// bounds) failed.
    InvalidCapability { message: String },
    /// Portable-passport envelope verification failed.
    InvalidPassport { message: String },
    /// Mobile attestation verification has not been provisioned for
    /// this platform lane yet.
    AttestationUnavailable { message: String },
    /// Mobile attestation evidence was present but rejected.
    AttestationRejected { message: String },
    /// The receipt body's `kernel_key` did not match the derived
    /// public key of the provided signing seed. Fail-fast so a
    /// receipt is never emitted whose embedded key cannot verify
    /// its own signature.
    KernelKeyMismatch { message: String },
    /// The canonical-JSON signing pipeline reported an error.
    SigningFailed { message: String },
    /// An `evaluate()` call returned a deny verdict. The message
    /// carries the kernel-core `deny_reason()`.
    EvaluationDenied { message: String },
    /// An internal invariant was violated (canonical-JSON failure,
    /// unexpected kernel-core error, etc.). Treat as fail-closed.
    Internal { message: String },
}

impl ChioMobileError {
    /// Shared accessor: every variant stores its message in the same slot.
    pub fn message(&self) -> &str {
        match self {
            ChioMobileError::InvalidJson { message }
            | ChioMobileError::InvalidHex { message }
            | ChioMobileError::InvalidCapability { message }
            | ChioMobileError::InvalidPassport { message }
            | ChioMobileError::AttestationUnavailable { message }
            | ChioMobileError::AttestationRejected { message }
            | ChioMobileError::KernelKeyMismatch { message }
            | ChioMobileError::SigningFailed { message }
            | ChioMobileError::EvaluationDenied { message }
            | ChioMobileError::Internal { message } => message.as_str(),
        }
    }
}

impl fmt::Display for ChioMobileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag = match self {
            ChioMobileError::InvalidJson { .. } => "invalid json",
            ChioMobileError::InvalidHex { .. } => "invalid hex",
            ChioMobileError::InvalidCapability { .. } => "invalid capability",
            ChioMobileError::InvalidPassport { .. } => "invalid passport",
            ChioMobileError::AttestationUnavailable { .. } => "attestation unavailable",
            ChioMobileError::AttestationRejected { .. } => "attestation rejected",
            ChioMobileError::KernelKeyMismatch { .. } => "kernel key mismatch",
            ChioMobileError::SigningFailed { .. } => "signing failed",
            ChioMobileError::EvaluationDenied { .. } => "evaluation denied",
            ChioMobileError::Internal { .. } => "internal",
        };
        write!(f, "{tag}: {}", self.message())
    }
}

impl std::error::Error for ChioMobileError {}
