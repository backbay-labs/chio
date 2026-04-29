//! Stand-alone signed provenance helper.
//!
//! Today the Chio receipt is signed end-to-end, but the provenance stamp
//! itself is not separately attestable. M07 adds a small helper so downstream
//! auditors can verify the upstream identity (provider, request id, principal)
//! without pulling the surrounding receipt.
//!
//! The construction is intentionally narrow: a [`SignedProvenance`] envelope
//! carries the canonical-JSON bytes of the [`ProvenanceStamp`], the producing
//! [`PublicKey`], and the [`Signature`] over those bytes. Verification is the
//! inverse and never panics.
//!
//! All cryptography is delegated to `chio_core::crypto`, which already powers
//! capability tokens, receipts, and DPoP proofs. The fabric crate does not
//! introduce new key handling or new algorithms.

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{
    sign_canonical_with_backend, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
use chio_core::error::Error as CoreError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ProvenanceStamp;

/// Envelope wrapping a [`ProvenanceStamp`] together with a detached signature
/// over its canonical-JSON bytes.
///
/// The envelope is itself canonical-JSON serializable, so it can be embedded
/// in an audit log line, attached to a receipt, or transmitted as a standalone
/// attestation. Equality is byte-equality on every field including the signed
/// bytes, matching the protocol's general "receipts compare by exact bytes"
/// posture.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedProvenance {
    /// Original stamp. Mirrors the unsigned shape so consumers that only
    /// trust their own canonicalization can re-derive the signed bytes.
    pub stamp: ProvenanceStamp,
    /// RFC 8785 canonical-JSON bytes of `stamp`. Stored explicitly so the
    /// signer's exact byte sequence is reproducible without re-running
    /// canonicalization on the verifier side.
    pub signed_bytes: Vec<u8>,
    /// Algorithm of the [`Signature`]. Matches `signature.algorithm()` and is
    /// retained as a top-level hint so consumers can short-circuit before
    /// touching the signature material.
    pub algorithm: SigningAlgorithm,
    /// Public half of the producing [`SigningBackend`].
    pub public_key: PublicKey,
    /// Detached signature over [`Self::signed_bytes`].
    pub signature: Signature,
}

/// Error returned by [`sign_provenance`] and [`verify_signed_provenance`].
#[derive(Debug, Error)]
pub enum ProvenanceError {
    /// Underlying canonicalization or signing failure surfaced by
    /// `chio_core::crypto`.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// Signature did not verify against the supplied public key and bytes.
    #[error("signature did not verify against the provided public key")]
    SignatureMismatch,
    /// The envelope's `signed_bytes` differ from the canonical-JSON
    /// re-serialization of `stamp`. Surfaces canonicalization drift before a
    /// signature check, since the bytes that were signed must equal the bytes
    /// the verifier independently produces.
    #[error("envelope signed_bytes diverged from canonical re-serialization of stamp")]
    CanonicalDrift,
    /// Algorithm hint disagreed with the [`Signature`]'s algorithm.
    #[error("envelope algorithm hint did not match signature algorithm")]
    AlgorithmMismatch,
}

impl From<CoreError> for ProvenanceError {
    fn from(value: CoreError) -> Self {
        ProvenanceError::Crypto(value.to_string())
    }
}

/// Sign a [`ProvenanceStamp`] with the given backend and return a
/// [`SignedProvenance`] envelope.
///
/// The stamp is serialized to RFC 8785 canonical JSON; the resulting bytes
/// are signed via [`sign_canonical_with_backend`]; both the bytes and the
/// signature are placed in the returned envelope alongside the producing
/// public key.
///
/// This is a thin convenience layer over `chio_core::crypto`; the fabric does
/// not add new cryptographic primitives.
pub fn sign_provenance(
    stamp: &ProvenanceStamp,
    backend: &dyn SigningBackend,
) -> Result<SignedProvenance, ProvenanceError> {
    let (signature, signed_bytes) = sign_canonical_with_backend(backend, stamp)?;
    Ok(SignedProvenance {
        stamp: stamp.clone(),
        signed_bytes,
        algorithm: backend.algorithm(),
        public_key: backend.public_key(),
        signature,
    })
}

/// Verify a [`SignedProvenance`] envelope.
///
/// Three checks run, in order:
///
/// 1. The envelope's `algorithm` field matches the signature algorithm.
/// 2. The envelope's `signed_bytes` re-canonicalize from `stamp` byte-for-byte
///    (so a verifier never trusts unsigned framing decisions).
/// 3. The signature verifies against `public_key` over `signed_bytes`.
///
/// On success returns the public key that signed the stamp so callers can
/// route trust decisions through their identity layer.
pub fn verify_signed_provenance(
    envelope: &SignedProvenance,
) -> Result<&PublicKey, ProvenanceError> {
    if envelope.algorithm != envelope.signature.algorithm() {
        return Err(ProvenanceError::AlgorithmMismatch);
    }
    let recanon = canonical_json_bytes(&envelope.stamp)?;
    if recanon != envelope.signed_bytes {
        return Err(ProvenanceError::CanonicalDrift);
    }
    if !envelope
        .public_key
        .verify(&envelope.signed_bytes, &envelope.signature)
    {
        return Err(ProvenanceError::SignatureMismatch);
    }
    Ok(&envelope.public_key)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{Principal, ProviderId};
    use chio_core::crypto::Ed25519Backend;
    use std::time::{Duration, SystemTime};

    fn sample_stamp() -> ProvenanceStamp {
        ProvenanceStamp {
            provider: ProviderId::Bedrock,
            request_id: "tooluse_42".to_string(),
            api_version: "bedrock-2023-09-30".to_string(),
            principal: Principal::BedrockIam {
                caller_arn: "arn:aws:iam::123456789012:role/ChioAgentRole".to_string(),
                account_id: "123456789012".to_string(),
                assumed_role_session_arn: None,
            },
            received_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        }
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let backend = Ed25519Backend::generate();
        let stamp = sample_stamp();
        let envelope = sign_provenance(&stamp, &backend).unwrap();
        assert_eq!(envelope.stamp, stamp);
        assert_eq!(envelope.algorithm, SigningAlgorithm::Ed25519);
        let pk = verify_signed_provenance(&envelope).unwrap();
        assert_eq!(pk, &backend.public_key());
    }

    #[test]
    fn tampered_stamp_fails_canonical_drift() {
        let backend = Ed25519Backend::generate();
        let stamp = sample_stamp();
        let mut envelope = sign_provenance(&stamp, &backend).unwrap();
        envelope.stamp.request_id = "tooluse_43".to_string();
        let err = verify_signed_provenance(&envelope).unwrap_err();
        matches!(err, ProvenanceError::CanonicalDrift);
    }

    #[test]
    fn tampered_signed_bytes_fail_canonical_drift() {
        let backend = Ed25519Backend::generate();
        let stamp = sample_stamp();
        let mut envelope = sign_provenance(&stamp, &backend).unwrap();
        envelope.signed_bytes.push(b' ');
        let err = verify_signed_provenance(&envelope).unwrap_err();
        matches!(err, ProvenanceError::CanonicalDrift);
    }

    #[test]
    fn wrong_public_key_fails_signature_mismatch() {
        let backend_a = Ed25519Backend::generate();
        let backend_b = Ed25519Backend::generate();
        let stamp = sample_stamp();
        let mut envelope = sign_provenance(&stamp, &backend_a).unwrap();
        envelope.public_key = backend_b.public_key();
        let err = verify_signed_provenance(&envelope).unwrap_err();
        matches!(err, ProvenanceError::SignatureMismatch);
    }

    #[test]
    fn signed_provenance_round_trips_through_canonical_json() {
        let backend = Ed25519Backend::generate();
        let stamp = sample_stamp();
        let envelope = sign_provenance(&stamp, &backend).unwrap();
        let json = serde_json::to_vec(&envelope).unwrap();
        let back: SignedProvenance = serde_json::from_slice(&json).unwrap();
        assert_eq!(envelope, back);
        verify_signed_provenance(&back).unwrap();
    }

    #[test]
    fn provenance_error_display_em_dash_free() {
        let errs = vec![
            ProvenanceError::Crypto("bad seed".to_string()),
            ProvenanceError::SignatureMismatch,
            ProvenanceError::CanonicalDrift,
            ProvenanceError::AlgorithmMismatch,
        ];
        for e in errs {
            assert!(!e.to_string().contains('\u{2014}'));
        }
    }
}
