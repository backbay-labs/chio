//! Session compliance certificate issuance with hybrid signing.
//!
//! A `SessionComplianceCertificate` is a kernel-signed envelope that
//! attests a session's receipt log was free of policy violations against
//! a specific `crypto_floor` and `policy_hash`. It is the artifact that
//! external auditors consume when they need a compact, signed summary of
//! a session without re-walking the underlying receipt store.
//!
//! ## Why this module exists
//!
//! `chio-acp-proxy` ships a Sigstore-only compliance certificate that
//! consumes a bare `Keypair` for Ed25519 signing. The kernel needs the
//! same envelope shape signed through an arbitrary `&dyn SigningBackend`
//! so a `HybridBackend` can produce `Signature::Hybrid` envelopes under
//! `crypto_floor=allow_hybrid` or `pq_required`. This module is the
//! kernel-side hybrid path; it wraps a body identical in shape to the
//! acp-proxy form but signs through the `chio-core-types` backend
//! abstraction.
//!
//! Spec reference: `spec/COMPLIANCE-CERTIFICATE.md`.
//!
//! Threat model row `pq_signature_downgrade` is the surface this guards.

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{
    sign_canonical_with_backend, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
use serde::{Deserialize, Serialize};

use crate::receipt_support::KernelCryptoFloor;

/// Body of a session compliance certificate.
///
/// Mirrors the fields the auditor consumes (`session_id`, `policy_hash`,
/// receipt counts, `all_signatures_valid`) and adds a `crypto_floor` field
/// so the verifier can reproduce the floor under which the certificate
/// was issued. Canonical JSON of this body is the byte input to
/// `SigningBackend::sign_bytes`; downstream verifiers reproduce the
/// canonical bytes and call `PublicKey::verify` on the resulting
/// signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionComplianceCertificateBody {
    /// Session this certificate covers.
    pub session_id: String,
    /// SHA-256 hash of the policy applied to every receipt in the
    /// session.
    pub policy_hash: String,
    /// Number of receipts walked while issuing this certificate.
    pub receipt_count: u64,
    /// Whether every receipt's signature re-verified during issuance.
    pub all_signatures_valid: bool,
    /// Crypto floor under which the certificate was issued. The verifier
    /// reproduces this floor when re-verifying receipt-side signatures so
    /// a downgrade attack on receipts is caught at certificate-load time.
    pub crypto_floor: String,
    /// Unix timestamp (seconds) when the certificate was issued.
    pub issued_at: u64,
}

/// A signed session compliance certificate.
///
/// Wraps a [`SessionComplianceCertificateBody`] with the issuing kernel's
/// public key and a signature over canonical JSON of the body. Under
/// `crypto_floor=allow_hybrid` or `pq_required` the signature is
/// [`Signature::Hybrid`] and the public key is [`PublicKey::Hybrid`];
/// otherwise both fields carry classical material (Ed25519 / P-256 /
/// P-384) and remain byte-identical to the classical envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionComplianceCertificate {
    /// Body the signature covers.
    pub body: SessionComplianceCertificateBody,
    /// Public key of the issuing kernel.
    pub signer_key: PublicKey,
    /// Algorithm used for `signature`. Carried so consumers can branch
    /// without parsing the self-describing prefix; informational only
    /// (verification dispatches off the signature material).
    pub algorithm: SigningAlgorithm,
    /// Signature over canonical JSON of `body`.
    pub signature: Signature,
}

/// Errors raised during compliance certificate issuance and verification.
#[derive(Debug, thiserror::Error)]
pub enum ComplianceCertificateError {
    /// The body's `crypto_floor` field disagrees with the floor the
    /// caller threaded into issuance. Fail-closed: a mis-stamped floor
    /// is a downgrade signal.
    #[error(
        "compliance certificate crypto_floor field {body_floor} disagrees with issuance floor {issuance_floor}"
    )]
    CryptoFloorMismatch {
        /// The floor recorded in the body.
        body_floor: String,
        /// The floor the caller threaded into issuance.
        issuance_floor: String,
    },

    /// Canonical JSON serialization or signing failed.
    #[error("compliance certificate signing failed: {0}")]
    SigningFailed(String),

    /// Signature verification rejected the certificate.
    #[error("compliance certificate signature verification failed")]
    SignatureVerificationFailed,

    /// The declared algorithm field was tampered or drifted from the
    /// self-describing signature envelope.
    #[error(
        "compliance certificate algorithm field {declared} disagrees with signature algorithm {actual}"
    )]
    AlgorithmMismatch {
        /// The informational algorithm field carried by the envelope.
        declared: &'static str,
        /// The algorithm parsed from the signature material.
        actual: &'static str,
    },

    /// The certificate's signature algorithm violates the configured
    /// `crypto_floor`. Threat model row `pq_signature_downgrade`.
    #[error(
        "compliance certificate rejected by crypto_floor={floor}: signature algorithm {actual} not permitted"
    )]
    RejectedByCryptoFloor {
        /// The configured floor that rejected the certificate.
        floor: &'static str,
        /// The signature algorithm carried by the certificate.
        actual: &'static str,
    },
}

/// Issue a session compliance certificate signed through `backend`.
///
/// The caller threads the `crypto_floor` separately so the body field is
/// authoritative and tamper-evident: a body with a different floor than
/// the issuance call rejects fail-closed at issuance time, not at first
/// audit. Under `KernelCryptoFloor::AllowClassical` this produces a
/// classical-only envelope byte-identical to the signed form (when
/// the body's `crypto_floor` field agrees with the configured floor).
///
/// # Errors
///
/// Returns [`ComplianceCertificateError::CryptoFloorMismatch`] when the
/// body's `crypto_floor` field disagrees with `floor`.
/// [`ComplianceCertificateError::SigningFailed`] when canonical JSON or
/// signing fails. Threat model row `pq_signature_downgrade` is the
/// surface this guards.
pub fn issue_session_compliance_certificate(
    body: SessionComplianceCertificateBody,
    floor: KernelCryptoFloor,
    backend: &dyn SigningBackend,
) -> Result<SessionComplianceCertificate, ComplianceCertificateError> {
    if body.crypto_floor != floor.as_str() {
        return Err(ComplianceCertificateError::CryptoFloorMismatch {
            body_floor: body.crypto_floor.clone(),
            issuance_floor: floor.as_str().to_string(),
        });
    }

    let (signature, _bytes) = sign_canonical_with_backend(backend, &body)
        .map_err(|error| ComplianceCertificateError::SigningFailed(error.to_string()))?;

    Ok(SessionComplianceCertificate {
        body,
        signer_key: backend.public_key(),
        algorithm: backend.algorithm(),
        signature,
    })
}

/// Verify a session compliance certificate against the configured
/// `crypto_floor`.
///
/// Performs the same dispatch table as
/// `CapabilityToken::verify_signature_with_floor`: floor rejection BEFORE
/// cryptographic verification, fail-closed on a mismatch between the
/// body's `crypto_floor` field and the verification floor, fail-closed on
/// signature failures.
///
/// # Errors
///
/// Returns [`ComplianceCertificateError::RejectedByCryptoFloor`] when the
/// certificate's signature algorithm violates the configured floor.
/// [`ComplianceCertificateError::CryptoFloorMismatch`] when the body's
/// floor field disagrees with the verification floor.
/// [`ComplianceCertificateError::SignatureVerificationFailed`] when the
/// cryptographic check fails.
pub fn verify_session_compliance_certificate(
    cert: &SessionComplianceCertificate,
    floor: KernelCryptoFloor,
) -> Result<(), ComplianceCertificateError> {
    // Step 1: floor enforcement. Reject any algorithm the floor does not
    // permit BEFORE running the cryptographic check.
    let signature_algorithm = cert.signature.algorithm();
    if cert.algorithm != signature_algorithm {
        return Err(ComplianceCertificateError::AlgorithmMismatch {
            declared: signing_algorithm_label(cert.algorithm),
            actual: signing_algorithm_label(signature_algorithm),
        });
    }
    let is_hybrid = matches!(signature_algorithm, SigningAlgorithm::Hybrid);
    let allowed = if is_hybrid {
        floor.allows_hybrid()
    } else {
        floor.allows_classical_only()
    };
    if !allowed {
        return Err(ComplianceCertificateError::RejectedByCryptoFloor {
            floor: floor.as_str(),
            actual: signing_algorithm_label(signature_algorithm),
        });
    }

    // Step 2: body floor field consistency.
    if cert.body.crypto_floor != floor.as_str() {
        return Err(ComplianceCertificateError::CryptoFloorMismatch {
            body_floor: cert.body.crypto_floor.clone(),
            issuance_floor: floor.as_str().to_string(),
        });
    }

    // Step 3: cryptographic verification.
    let bytes = canonical_json_bytes(&cert.body)
        .map_err(|error| ComplianceCertificateError::SigningFailed(error.to_string()))?;
    if !cert.signer_key.verify(&bytes, &cert.signature) {
        return Err(ComplianceCertificateError::SignatureVerificationFailed);
    }

    Ok(())
}

fn signing_algorithm_label(alg: SigningAlgorithm) -> &'static str {
    match alg {
        SigningAlgorithm::Ed25519 => "ed25519",
        SigningAlgorithm::P256 => "p256",
        SigningAlgorithm::P384 => "p384",
        SigningAlgorithm::Hybrid => "hybrid",
    }
}
