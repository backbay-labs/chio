//! Post-quantum signing helpers.
//!
//! This module is compiled only with the `pq` feature. It provides the
//! ML-DSA-65 half used by hybrid Chio signatures while leaving default builds
//! classical-only.

use alloc::boxed::Box;
use alloc::vec::Vec;

use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use rand_core::OsRng;

use crate::crypto::{
    PublicKey, Signature, SigningAlgorithm, SigningBackend, HYBRID_ED25519_MLDSA65,
    HYBRID_P256_MLDSA65, HYBRID_P384_MLDSA65, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};
use crate::error::{Error, Result};

/// ML-DSA-65 private-key byte length from FIPS 204.
pub const ML_DSA_65_SECRET_KEY_LEN: usize = 4032;

/// ML-DSA-65 signing backend used as the post-quantum half of a hybrid key.
#[derive(Clone)]
pub struct MlDsa65Backend {
    public_key: ml_dsa_65::PublicKey,
    private_key: ml_dsa_65::PrivateKey,
}

impl MlDsa65Backend {
    /// Generate an ML-DSA-65 keypair from OS randomness.
    pub fn generate() -> Result<Self> {
        let (public_key, private_key) = ml_dsa_65::try_keygen_with_rng(&mut OsRng)
            .map_err(|e| Error::InvalidSignature(format!("ML-DSA-65 keygen failed: {e}")))?;
        Ok(Self {
            public_key,
            private_key,
        })
    }

    /// Generate an ML-DSA-65 keypair from a 32-byte FIPS 204 keygen seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let (public_key, private_key) = ml_dsa_65::KG::keygen_from_seed(seed);
        Self {
            public_key,
            private_key,
        }
    }

    /// Import an ML-DSA-65 private key from its encoded FIPS 204 byte form.
    pub fn from_secret_key_bytes(bytes: &[u8]) -> Result<Self> {
        let secret_key_bytes: [u8; ML_DSA_65_SECRET_KEY_LEN] = bytes.try_into().map_err(|_| {
            Error::InvalidSignature(format!(
                "expected {ML_DSA_65_SECRET_KEY_LEN}-byte ML-DSA-65 private key, got {} bytes",
                bytes.len()
            ))
        })?;
        let private_key = ml_dsa_65::PrivateKey::try_from_bytes(secret_key_bytes).map_err(|e| {
            Error::InvalidSignature(format!("ML-DSA-65 private key import failed: {e}"))
        })?;
        let public_key = private_key.get_public_key();
        Ok(Self {
            public_key,
            private_key,
        })
    }

    /// Encoded ML-DSA-65 public-key bytes.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; ML_DSA_65_PUBLIC_KEY_LEN] {
        self.public_key.clone().into_bytes()
    }

    /// Encoded ML-DSA-65 private-key bytes.
    #[must_use]
    pub fn secret_key_bytes(&self) -> [u8; ML_DSA_65_SECRET_KEY_LEN] {
        self.private_key.clone().into_bytes()
    }

    /// Produce a randomized ML-DSA-65 signature over `message`.
    pub fn sign_bytes(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signature = self
            .private_key
            .try_sign_with_rng(&mut OsRng, message, &[])
            .map_err(|e| Error::InvalidSignature(format!("ML-DSA-65 sign failed: {e}")))?;
        Ok(signature.to_vec())
    }

    /// Produce a deterministic ML-DSA-65 signature for KAT replay.
    pub fn sign_bytes_with_seed(&self, message: &[u8], seed: &[u8; 32]) -> Result<Vec<u8>> {
        #[allow(deprecated)]
        let signature = ml_dsa_65::_internal_sign(&self.private_key, message, &[], *seed)
            .map_err(|e| Error::InvalidSignature(format!("ML-DSA-65 KAT sign failed: {e}")))?;
        Ok(signature.to_vec())
    }
}

/// Verify an ML-DSA-65 signature against encoded public-key bytes.
#[must_use]
pub fn verify_mldsa65_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let public_key_bytes: [u8; ML_DSA_65_PUBLIC_KEY_LEN] = match public_key.try_into() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let signature_bytes: [u8; ML_DSA_65_SIGNATURE_LEN] = match signature.try_into() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let public_key = match ml_dsa_65::PublicKey::try_from_bytes(public_key_bytes) {
        Ok(public_key) => public_key,
        Err(_) => return false,
    };
    public_key.verify(message, &signature_bytes, &[])
}

/// Signing backend that produces hybrid classical plus ML-DSA-65 signatures.
pub struct HybridBackend {
    classical: Box<dyn SigningBackend>,
    pq: MlDsa65Backend,
    alg_set: &'static str,
    public_key: PublicKey,
}

impl HybridBackend {
    /// Construct a hybrid backend from a classical backend and an ML-DSA-65
    /// backend.
    pub fn new(classical: Box<dyn SigningBackend>, pq: MlDsa65Backend) -> Result<Self> {
        let alg_set = match classical.algorithm() {
            SigningAlgorithm::Ed25519 => HYBRID_ED25519_MLDSA65,
            SigningAlgorithm::P256 => HYBRID_P256_MLDSA65,
            SigningAlgorithm::P384 => HYBRID_P384_MLDSA65,
            SigningAlgorithm::Hybrid => {
                return Err(Error::InvalidSignature(
                    "hybrid signing backends cannot be nested".to_string(),
                ));
            }
        };
        let pq_public_key = pq.public_key_bytes();
        let public_key =
            PublicKey::from_hybrid_parts(classical.public_key(), &pq_public_key, alg_set)?;
        Ok(Self {
            classical,
            pq,
            alg_set,
            public_key,
        })
    }

    /// Borrow the ML-DSA-65 backend.
    #[must_use]
    pub fn pq_backend(&self) -> &MlDsa65Backend {
        &self.pq
    }
}

impl SigningBackend for HybridBackend {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Hybrid
    }

    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    fn sign_bytes(&self, message: &[u8]) -> Result<Signature> {
        let classical = self.classical.sign_bytes(message)?;
        let pq = self.pq.sign_bytes(message)?;
        Signature::from_hybrid_parts(classical, &pq, self.alg_set)
    }
}
