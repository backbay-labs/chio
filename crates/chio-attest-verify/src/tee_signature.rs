use p384::ecdsa::{signature::Verifier as _, Signature as P384Signature, VerifyingKey};
use x509_cert::{der::Decode as _, Certificate};

use crate::AttestError;

/// Verify an ECDSA P-384/SHA-384 signature with the attestation key
/// carried by a quote's leaf certificate.
///
/// Production TEE quotes carry an X.509 leaf certificate. The in-tree
/// deterministic fixture corpus carries the same public key in raw SEC1
/// form so fixture generation does not need a certificate issuer. Both
/// encodings are fail-closed: bytes that are neither X.509 DER nor raw
/// uncompressed P-384 public keys are rejected before signature
/// verification.
pub(crate) fn verify_p384_signature_with_attestation_key(
    attestation_key: &[u8],
    signed_message: &[u8],
    signature: &[u8],
) -> Result<(), AttestError> {
    let verifying_key = p384_verifying_key_from_attestation_key(attestation_key)?;
    let signature = parse_p384_signature(signature)?;
    verifying_key
        .verify(signed_message, &signature)
        .map_err(|_| AttestError::SignatureMismatch)
}

fn p384_verifying_key_from_attestation_key(
    attestation_key: &[u8],
) -> Result<VerifyingKey, AttestError> {
    let sec1_bytes = match Certificate::from_der(attestation_key) {
        Ok(certificate) => certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec(),
        Err(_) => attestation_key.to_vec(),
    };

    VerifyingKey::from_sec1_bytes(&sec1_bytes).map_err(|error| {
        AttestError::Malformed(format!(
            "tee attestation key is not a P-384 public key: {error}"
        ))
    })
}

fn parse_p384_signature(signature: &[u8]) -> Result<P384Signature, AttestError> {
    P384Signature::from_slice(signature)
        .or_else(|_| P384Signature::from_der(signature))
        .map_err(|_| AttestError::SignatureMismatch)
}
