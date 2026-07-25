use chio_core_types::sha256_hex;
use frost_ed25519::keys::KeyPackage;
use frost_ed25519::rand_core::{CryptoRng, RngCore};
use frost_ed25519::{round1, round2, SigningPackage};
use zeroize::Zeroizing;

use crate::{FrostCeremonySecret, FrostCeremonySecretKind};

const MAX_SIGNER_SECRET_BYTES: usize = 1024;
const MAX_SIGNING_PACKAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrostSignerError {
    #[error("invalid FROST signer input: {0}")]
    Invalid(&'static str),
    #[error("FROST signer cryptography failed: {0}")]
    Crypto(String),
}

pub struct FrostSignerNonceSecret {
    bytes: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for FrostSignerNonceSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FrostSignerNonceSecret")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl FrostSignerNonceSecret {
    pub fn from_custody_bytes(bytes: Zeroizing<Vec<u8>>) -> Result<Self, FrostSignerError> {
        if bytes.is_empty() || bytes.len() > MAX_SIGNER_SECRET_BYTES {
            return Err(FrostSignerError::Invalid(
                "nonce custody payload length is outside the supported range",
            ));
        }
        round1::SigningNonces::deserialize(&bytes)
            .map_err(|error| FrostSignerError::Crypto(error.to_string()))?;
        Ok(Self { bytes })
    }

    #[must_use]
    pub fn custody_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug)]
pub struct FrostSignerPreparation {
    nonce_secret: FrostSignerNonceSecret,
    signer_identifier_bytes: Vec<u8>,
    verification_share: String,
    commitment_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrostSignerKeyIdentity {
    signer_identifier_bytes: Vec<u8>,
    verification_share: String,
}

impl FrostSignerKeyIdentity {
    #[must_use]
    pub fn signer_identifier_bytes(&self) -> &[u8] {
        &self.signer_identifier_bytes
    }

    #[must_use]
    pub fn verification_share(&self) -> &str {
        &self.verification_share
    }
}

impl FrostSignerPreparation {
    #[must_use]
    pub fn nonce_secret(&self) -> &FrostSignerNonceSecret {
        &self.nonce_secret
    }

    /// Takes ownership of the nonce secret so it can be spent on one signature share.
    #[must_use]
    pub fn into_nonce_secret(self) -> FrostSignerNonceSecret {
        self.nonce_secret
    }

    #[must_use]
    pub fn signer_identifier_bytes(&self) -> &[u8] {
        &self.signer_identifier_bytes
    }

    #[must_use]
    pub fn verification_share(&self) -> &str {
        &self.verification_share
    }

    #[must_use]
    pub fn commitment_bytes(&self) -> &[u8] {
        &self.commitment_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrostSignatureShare {
    share_bytes: Vec<u8>,
}

impl FrostSignatureShare {
    #[must_use]
    pub fn share_bytes(&self) -> &[u8] {
        &self.share_bytes
    }
}

pub fn prepare_frost_signer<R: CryptoRng + RngCore>(
    key_package_secret: &FrostCeremonySecret,
    rng: &mut R,
) -> Result<FrostSignerPreparation, FrostSignerError> {
    let key_package = decode_key_package(key_package_secret)?;
    let (nonces, commitments) = round1::commit(key_package.signing_share(), rng);
    let nonce_bytes = nonces
        .serialize()
        .map_err(|error| FrostSignerError::Crypto(error.to_string()))?;
    let commitment_bytes = commitments
        .serialize()
        .map_err(|error| FrostSignerError::Crypto(error.to_string()))?;
    let verification_share = key_package
        .verifying_share()
        .serialize()
        .map_err(|error| FrostSignerError::Crypto(error.to_string()))?;
    Ok(FrostSignerPreparation {
        nonce_secret: FrostSignerNonceSecret::from_custody_bytes(Zeroizing::new(nonce_bytes))?,
        signer_identifier_bytes: key_package.identifier().serialize(),
        verification_share: hex::encode(verification_share),
        commitment_bytes,
    })
}

pub fn inspect_frost_signer_key(
    key_package_secret: &FrostCeremonySecret,
) -> Result<FrostSignerKeyIdentity, FrostSignerError> {
    let key_package = decode_key_package(key_package_secret)?;
    let verification_share = key_package
        .verifying_share()
        .serialize()
        .map_err(|error| FrostSignerError::Crypto(error.to_string()))?;
    Ok(FrostSignerKeyIdentity {
        signer_identifier_bytes: key_package.identifier().serialize(),
        verification_share: hex::encode(verification_share),
    })
}

/// Produces this signer's share for exactly one authorized message.
///
/// The nonce secret is consumed. A FROST nonce that signs two different messages
/// discloses the signing share, so a retry must obtain a fresh nonce from
/// [`prepare_frost_signer`] rather than replaying this one.
pub fn create_frost_signature_share(
    key_package_secret: &FrostCeremonySecret,
    nonce_secret: FrostSignerNonceSecret,
    signing_package_bytes: &[u8],
    expected_message_digest: &str,
    expected_commitment_bytes: &[u8],
) -> Result<FrostSignatureShare, FrostSignerError> {
    if signing_package_bytes.is_empty() || signing_package_bytes.len() > MAX_SIGNING_PACKAGE_BYTES {
        return Err(FrostSignerError::Invalid(
            "signing package length is outside the supported range",
        ));
    }
    validate_sha256(expected_message_digest)?;
    let key_package = decode_key_package(key_package_secret)?;
    let nonces = round1::SigningNonces::deserialize(nonce_secret.custody_bytes())
        .map_err(|error| FrostSignerError::Crypto(error.to_string()))?;
    let expected_commitment = round1::SigningCommitments::deserialize(expected_commitment_bytes)
        .map_err(|error| FrostSignerError::Crypto(error.to_string()))?;
    let signing_package = SigningPackage::deserialize(signing_package_bytes)
        .map_err(|error| FrostSignerError::Crypto(error.to_string()))?;
    if sha256_hex(signing_package.message()) != expected_message_digest {
        return Err(FrostSignerError::Invalid(
            "signing package message differs from the authorized message",
        ));
    }
    if signing_package.signing_commitment(key_package.identifier()) != Some(expected_commitment) {
        return Err(FrostSignerError::Invalid(
            "signing package commitment differs from the prepared nonce",
        ));
    }
    let share = round2::sign(&signing_package, &nonces, &key_package)
        .map_err(|error| FrostSignerError::Crypto(error.to_string()))?;
    Ok(FrostSignatureShare {
        share_bytes: share.serialize(),
    })
}

fn decode_key_package(secret: &FrostCeremonySecret) -> Result<KeyPackage, FrostSignerError> {
    if secret.kind() != FrostCeremonySecretKind::KeyPackage {
        return Err(FrostSignerError::Invalid(
            "signer requires a completed DKG key package",
        ));
    }
    KeyPackage::deserialize(secret.custody_bytes())
        .map_err(|error| FrostSignerError::Crypto(error.to_string()))
}

fn validate_sha256(value: &str) -> Result<(), FrostSignerError> {
    if value.len() != 64
        || value.bytes().any(|byte| !byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(FrostSignerError::Invalid(
            "message digest must be lowercase SHA-256 hexadecimal",
        ));
    }
    Ok(())
}
