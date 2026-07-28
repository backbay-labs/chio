//! Shared signed-envelope discipline for the market artifact families in
//! this crate.
//!
//! Every value-moving family in this crate travels as a
//! `SignedExportEnvelope<T>` whose signer must equal an EXTERNALLY pinned
//! authority key. `SignedExportEnvelope::verify_signature` verifies against
//! the envelope's own embedded key with loose Ed25519 semantics; it is
//! never an authority boundary here. These helpers verify strictly against
//! the pinned key, reject weak keys, and require the embedded signer to
//! equal the pinned authority so an envelope cannot advertise one signer
//! while verifying under another.

use chio_core_types::canonical_json_bytes;
use chio_core_types::crypto::{sha256_hex, PublicKey, SigningAlgorithm};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::Serialize;

use crate::validate::FindingError;

/// Canonical digest of the exact signed envelope (body + signer +
/// signature). This is the "exact signed envelope digest" every admission
/// binding references; digest-of-body is a different identity and is never
/// interchangeable with it.
pub fn signed_envelope_sha256<T: Serialize>(
    envelope: &SignedExportEnvelope<T>,
) -> Result<String, FindingError> {
    let bytes = canonical_json_bytes(envelope).map_err(|_| FindingError::Canonicalization)?;
    Ok(sha256_hex(&bytes))
}

/// Verify an envelope against an externally pinned authority key,
/// fail-closed: pinned key must be a non-weak Ed25519 key, the embedded
/// signer must equal the pinned key, and the signature must verify
/// STRICTLY over the canonical body.
pub fn verify_pinned_envelope<T: Serialize>(
    envelope: &SignedExportEnvelope<T>,
    pinned_authority: &PublicKey,
    label: &'static str,
) -> Result<(), FindingError> {
    require_ed25519(pinned_authority, label)?;
    if envelope.signer_key != *pinned_authority {
        return Err(FindingError::AuthorityMismatch(label));
    }
    match pinned_authority.verify_canonical_strict(&envelope.body, &envelope.signature) {
        Ok(true) => Ok(()),
        _ => Err(FindingError::EnvelopeSignatureInvalid(label)),
    }
}

/// Validate a key policy's key material shape: canonical Ed25519, not weak.
pub(crate) fn require_ed25519(key: &PublicKey, label: &'static str) -> Result<(), FindingError> {
    if key.algorithm() != SigningAlgorithm::Ed25519 || key.is_weak_ed25519() {
        return Err(FindingError::InvalidAuthorityKey(label));
    }
    Ok(())
}
