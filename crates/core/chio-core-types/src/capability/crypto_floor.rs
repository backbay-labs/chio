use serde::{Deserialize, Serialize};

use crate::crypto::SigningAlgorithm;
use crate::error::Error;

/// Minimum cryptographic posture enforced by the capability validator.
///
/// Mirrors the wire form of `chio_policy::CryptoFloor` and the kernel-side
/// `KernelCryptoFloor`. Defined locally in `chio-core-types` so the
/// portable verifier (no_std builds, edge runtimes) can branch on the
/// configured floor without taking a dependency on `chio-policy` or
/// `chio-kernel`. Operators that load a HushSpec policy translate the
/// parsed floor into this enum at the kernel boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityCryptoFloor {
    /// Accept classical-only Ed25519/P-256/P-384 envelopes. Default.
    #[default]
    AllowClassical,
    /// Accept either classical-only or hybrid classical-plus-ML-DSA-65
    /// envelopes.
    AllowHybrid,
    /// Reject classical-only envelopes; require hybrid signing on every
    /// signed capability token.
    PqRequired,
}

impl CapabilityCryptoFloor {
    /// Whether the floor permits hybrid envelopes on the wire.
    #[must_use]
    pub fn allows_hybrid(&self) -> bool {
        matches!(self, Self::AllowHybrid | Self::PqRequired)
    }

    /// Whether the floor permits classical-only envelopes on the wire.
    #[must_use]
    pub fn allows_classical_only(&self) -> bool {
        matches!(self, Self::AllowClassical | Self::AllowHybrid)
    }

    /// Stable wire-format identifier for diagnostics.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AllowClassical => "allow_classical",
            Self::AllowHybrid => "allow_hybrid",
            Self::PqRequired => "pq_required",
        }
    }
}

/// Lowercase wire label for a [`SigningAlgorithm`] used in error messages.
///
/// Equivalent to `SigningAlgorithm::prefix` for the non-Ed25519 variants
/// but returns the explicit `"ed25519"` literal for Ed25519 (the prefix
/// helper returns `""` because Ed25519 keys render bare on the wire).
fn signing_algorithm_label(alg: SigningAlgorithm) -> &'static str {
    match alg {
        SigningAlgorithm::Ed25519 => "ed25519",
        SigningAlgorithm::P256 => "p256",
        SigningAlgorithm::P384 => "p384",
        SigningAlgorithm::Hybrid => "hybrid",
    }
}

/// Errors raised by [`CapabilityToken::verify_signature_with_floor`].
///
/// Distinguishes floor-policy rejections from cryptographic verification
/// failures so the kernel can surface a different audit-log row for each.
/// Threat model row `pq_signature_downgrade` is the surface this guards.
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[derive(Debug)]
pub enum CapabilityFloorVerifyError {
    /// The signature algorithm violates the configured `crypto_floor`.
    /// Fail-closed at the floor boundary BEFORE cryptographic verification
    /// runs. Threat model row `pq_signature_downgrade` is the surface this
    /// guards.
    #[cfg_attr(
        feature = "std",
        error(
            "capability rejected by crypto_floor={}: signature algorithm {} not permitted",
            floor.as_str(),
            signing_algorithm_label(*signature_algorithm)
        )
    )]
    RejectedByCryptoFloor {
        /// The configured floor that rejected the token.
        floor: CapabilityCryptoFloor,
        /// The signature algorithm carried by the token.
        signature_algorithm: SigningAlgorithm,
    },

    /// The optional `CapabilityToken::algorithm` envelope field disagrees
    /// with the algorithm carried by `Signature`. Treated as a downgrade
    /// signal and rejected fail-closed.
    #[cfg_attr(
        feature = "std",
        error(
            "capability algorithm envelope field {} disagrees with signature {}",
            signing_algorithm_label(*declared),
            signing_algorithm_label(*actual)
        )
    )]
    AlgorithmMismatch {
        /// The algorithm declared in the envelope field.
        declared: SigningAlgorithm,
        /// The algorithm carried by the signature material.
        actual: SigningAlgorithm,
    },

    /// Forwarded from the underlying canonical-JSON or signature
    /// verification path.
    #[cfg_attr(
        feature = "std",
        error("capability cryptographic verification failed: {0}")
    )]
    Crypto(#[cfg_attr(feature = "std", source)] Error),
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for CapabilityFloorVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RejectedByCryptoFloor {
                floor,
                signature_algorithm,
            } => write!(
                f,
                "capability rejected by crypto_floor={}: signature algorithm {} not permitted",
                floor.as_str(),
                signing_algorithm_label(*signature_algorithm)
            ),
            Self::AlgorithmMismatch { declared, actual } => write!(
                f,
                "capability algorithm envelope field {} disagrees with signature {}",
                signing_algorithm_label(*declared),
                signing_algorithm_label(*actual)
            ),
            Self::Crypto(err) => write!(f, "capability cryptographic verification failed: {err}"),
        }
    }
}

#[cfg(not(feature = "std"))]
impl core::error::Error for CapabilityFloorVerifyError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Crypto(err) => Some(err),
            _ => None,
        }
    }
}
