use crate::crypto::SigningAlgorithm;
use crate::error::Error;

use serde::{Deserialize, Serialize};

/// Minimum cryptographic posture enforced by receipt validators.
///
/// Mirrors `CapabilityCryptoFloor` and the wire form of
/// `chio_policy::CryptoFloor` without coupling portable receipt verification
/// to kernel or policy crates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptCryptoFloor {
    /// Accept classical-only Ed25519/P-256/P-384 envelopes. Default.
    #[default]
    AllowClassical,
    /// Accept either classical-only or hybrid classical-plus-ML-DSA-65
    /// envelopes.
    AllowHybrid,
    /// Reject classical-only envelopes; require hybrid signing on every
    /// signed receipt.
    PqRequired,
}

impl ReceiptCryptoFloor {
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

/// Lowercase wire label for a [`SigningAlgorithm`] used in receipt floor
/// diagnostics.
pub(crate) fn receipt_signing_algorithm_label(alg: SigningAlgorithm) -> &'static str {
    match alg {
        SigningAlgorithm::Ed25519 => "ed25519",
        SigningAlgorithm::P256 => "p256",
        SigningAlgorithm::P384 => "p384",
        SigningAlgorithm::Hybrid => "hybrid",
    }
}

/// Errors raised by [`ChioReceipt::verify_signature_with_floor`].
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[derive(Debug)]
pub enum ReceiptFloorVerifyError {
    /// The signature algorithm violates the configured `crypto_floor`.
    #[cfg_attr(
        feature = "std",
        error(
            "receipt rejected by crypto_floor={}: signature algorithm {} not permitted",
            floor.as_str(),
            receipt_signing_algorithm_label(*signature_algorithm)
        )
    )]
    RejectedByCryptoFloor {
        /// The configured floor that rejected the receipt.
        floor: ReceiptCryptoFloor,
        /// The signature algorithm carried by the receipt.
        signature_algorithm: SigningAlgorithm,
    },

    /// The optional receipt algorithm envelope field disagrees with the
    /// algorithm carried by the signature material.
    #[cfg_attr(
        feature = "std",
        error(
            "receipt algorithm envelope field {} disagrees with signature {}",
            receipt_signing_algorithm_label(*declared),
            receipt_signing_algorithm_label(*actual)
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
        error("receipt cryptographic verification failed: {0}")
    )]
    Crypto(#[cfg_attr(feature = "std", source)] Error),
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for ReceiptFloorVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RejectedByCryptoFloor {
                floor,
                signature_algorithm,
            } => write!(
                f,
                "receipt rejected by crypto_floor={}: signature algorithm {} not permitted",
                floor.as_str(),
                receipt_signing_algorithm_label(*signature_algorithm)
            ),
            Self::AlgorithmMismatch { declared, actual } => write!(
                f,
                "receipt algorithm envelope field {} disagrees with signature {}",
                receipt_signing_algorithm_label(*declared),
                receipt_signing_algorithm_label(*actual)
            ),
            Self::Crypto(err) => write!(f, "receipt cryptographic verification failed: {err}"),
        }
    }
}

#[cfg(not(feature = "std"))]
impl core::error::Error for ReceiptFloorVerifyError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Crypto(err) => Some(err),
            _ => None,
        }
    }
}

pub(crate) fn ensure_receipt_signature_algorithm_allowed(
    declared_algorithm: Option<SigningAlgorithm>,
    signature_algorithm: SigningAlgorithm,
    floor: ReceiptCryptoFloor,
) -> core::result::Result<(), ReceiptFloorVerifyError> {
    if let Some(declared) = declared_algorithm {
        if declared != signature_algorithm {
            return Err(ReceiptFloorVerifyError::AlgorithmMismatch {
                declared,
                actual: signature_algorithm,
            });
        }
    }

    let is_hybrid = matches!(signature_algorithm, SigningAlgorithm::Hybrid);
    let allowed = if is_hybrid {
        floor.allows_hybrid()
    } else {
        floor.allows_classical_only()
    };
    if !allowed {
        return Err(ReceiptFloorVerifyError::RejectedByCryptoFloor {
            floor,
            signature_algorithm,
        });
    }

    Ok(())
}
