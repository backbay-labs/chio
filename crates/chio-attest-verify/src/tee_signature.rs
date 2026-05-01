use p256::ecdsa::{
    signature::Verifier as _, Signature as P256Signature, VerifyingKey as P256VerifyingKey,
};
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use x509_cert::{der::Decode as _, Certificate};

use crate::AttestError;

const AMD_SEV_SNP_SIGNATURE_LEN: usize = 512;
const AMD_SEV_SNP_SCALAR_LEN: usize = 72;
const AMD_SEV_SNP_P384_SCALAR_BYTES: usize = 48;

/// Verify an ECDSA P-256/SHA-256 signature with the attestation key
/// carried by a quote's leaf certificate.
pub(crate) fn verify_p256_signature_with_attestation_key(
    attestation_key: &[u8],
    signed_message: &[u8],
    signature: &[u8],
) -> Result<(), AttestError> {
    let verifying_key = p256_verifying_key_from_attestation_key(attestation_key)?;
    let signature = parse_p256_signature(signature)?;
    verifying_key
        .verify(signed_message, &signature)
        .map_err(|_| AttestError::SignatureMismatch)
}

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
) -> Result<P384VerifyingKey, AttestError> {
    let sec1_bytes = match Certificate::from_der(attestation_key) {
        Ok(certificate) => certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec(),
        Err(_) => attestation_key.to_vec(),
    };

    P384VerifyingKey::from_sec1_bytes(&sec1_bytes).map_err(|error| {
        AttestError::Malformed(format!(
            "tee attestation key is not a P-384 public key: {error}"
        ))
    })
}

fn p256_verifying_key_from_attestation_key(
    attestation_key: &[u8],
) -> Result<P256VerifyingKey, AttestError> {
    let sec1_bytes = match Certificate::from_der(attestation_key) {
        Ok(certificate) => certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec(),
        Err(_) => attestation_key.to_vec(),
    };

    P256VerifyingKey::from_sec1_bytes(&sec1_bytes).map_err(|error| {
        AttestError::Malformed(format!(
            "tee attestation key is not a P-256 public key: {error}"
        ))
    })
}

fn parse_p384_signature(signature: &[u8]) -> Result<P384Signature, AttestError> {
    if let Ok(parsed) = P384Signature::from_slice(signature) {
        return Ok(parsed);
    }
    if let Ok(parsed) = P384Signature::from_der(signature) {
        return Ok(parsed);
    }
    parse_amd_sev_snp_p384_signature(signature)
}

fn parse_p256_signature(signature: &[u8]) -> Result<P256Signature, AttestError> {
    P256Signature::from_slice(signature)
        .or_else(|_| P256Signature::from_der(signature))
        .map_err(|_| AttestError::SignatureMismatch)
}

fn parse_amd_sev_snp_p384_signature(signature: &[u8]) -> Result<P384Signature, AttestError> {
    if signature.len() != AMD_SEV_SNP_SIGNATURE_LEN {
        return Err(AttestError::SignatureMismatch);
    }
    let r = &signature[..AMD_SEV_SNP_SCALAR_LEN];
    let s = &signature[AMD_SEV_SNP_SCALAR_LEN..AMD_SEV_SNP_SCALAR_LEN * 2];
    let reserved = &signature[AMD_SEV_SNP_SCALAR_LEN * 2..];
    if r[AMD_SEV_SNP_P384_SCALAR_BYTES..]
        .iter()
        .any(|byte| *byte != 0)
        || s[AMD_SEV_SNP_P384_SCALAR_BYTES..]
            .iter()
            .any(|byte| *byte != 0)
        || reserved.iter().any(|byte| *byte != 0)
    {
        return Err(AttestError::SignatureMismatch);
    }

    let mut raw = [0u8; AMD_SEV_SNP_P384_SCALAR_BYTES * 2];
    for index in 0..AMD_SEV_SNP_P384_SCALAR_BYTES {
        raw[index] = r[AMD_SEV_SNP_P384_SCALAR_BYTES - 1 - index];
        raw[AMD_SEV_SNP_P384_SCALAR_BYTES + index] = s[AMD_SEV_SNP_P384_SCALAR_BYTES - 1 - index];
    }
    P384Signature::from_slice(&raw).map_err(|_| AttestError::SignatureMismatch)
}
