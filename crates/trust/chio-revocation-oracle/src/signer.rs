//! Authenticity signing and verification for revocation-oracle epoch roots.
//!
//! The oracle publishes a [`crate::EpochRoot`] every epoch tick: a commitment
//! to the current sparse-Merkle root of the revocation set plus the epoch
//! counter, leaf count, and issuance timestamp. A remote kernel or federation
//! peer that did not compute the root needs an authenticity proof before it
//! merges the root (and the inclusion / non-inclusion proofs that bind to it)
//! into its local cache.
//!
//! That proof is an Ed25519 signature over the RFC 8785 (JSON Canonicalization
//! Scheme) bytes of the [`crate::EpochRoot`], prefixed with a fixed
//! domain-separation context string. Signing is performed by
//! [`Ed25519RootSigner`], which holds the private [`Keypair`]. Verification is
//! performed by [`Ed25519RootVerifier`], which holds only the pinned
//! [`PublicKey`] and the expected `signer_id`. The two halves are split across
//! [`EpochRootSigner`] and [`EpochRootVerifier`] so a verify-only peer is
//! type-prevented from ever holding key material that could forge a root.
//!
//! # Signed bytes
//!
//! The exact message fed to Ed25519 is:
//!
//! ```text
//! DOMAIN_SEPARATION_CONTEXT || canonical_json_bytes(EpochRoot)
//! ```
//!
//! where [`DOMAIN_SEPARATION_CONTEXT`] is a constant byte string that scopes the
//! signature to this protocol and version, and `canonical_json_bytes` is the
//! RFC 8785 serialization from `chio-core-types`. Because the canonical form is
//! byte-stable across serde versions, a verifier that re-canonicalizes the same
//! [`crate::EpochRoot`] reconstructs identical bytes, so signatures are
//! reproducible in tests and across peers.
//!
//! # Fail-closed posture
//!
//! Every decode or verification error denies. A [`crate::RootSignature`] whose
//! `signer_id` or `algorithm` does not match the verifier, whose
//! `signature_bytes` are not exactly 64 bytes, or whose Ed25519 check fails,
//! yields [`RevocationOracleError::SignatureVerificationFailed`]. Canonical-JSON
//! serialization failures surface as [`RevocationOracleError::Serialization`].

use chio_core_types::{canonical_json_bytes, Keypair, PublicKey, Signature};

use crate::{EpochRoot, Result, RevocationOracleError, RootSignature};

/// Domain-separation context prepended to the canonical [`EpochRoot`] bytes
/// before signing or verifying. Binds a signature to this protocol and version
/// so a signature produced for a different context can never validate here.
pub const DOMAIN_SEPARATION_CONTEXT: &[u8] = b"chio-revocation-oracle:v1:epoch-root";

/// Wire tag carried in [`RootSignature::algorithm`] for Ed25519 signatures.
pub const ALGORITHM_ED25519: &str = "ed25519";

/// Byte length of a raw Ed25519 signature as carried in
/// [`RootSignature::signature_bytes`].
const ED25519_SIGNATURE_LEN: usize = 64;

/// Produces an authenticity signature over an oracle epoch root.
///
/// Implementations hold private key material. The signing and verifying roles
/// are deliberately separated into distinct traits ([`EpochRootSigner`] and
/// [`EpochRootVerifier`]) so a verify-only deployment never depends on a type
/// that can sign.
pub trait EpochRootSigner {
    /// Stable identity of the signing oracle, mirrored into
    /// [`RootSignature::signer_id`].
    fn signer_id(&self) -> &str;

    /// Sign `root`, returning a detached [`RootSignature`] over the
    /// domain-separated canonical bytes of the root.
    fn sign_epoch_root(&self, root: &EpochRoot) -> Result<RootSignature>;
}

/// Verifies an authenticity signature over an oracle epoch root using only a
/// pinned public key.
///
/// A verifier never holds private key material and therefore cannot forge a
/// root. This is the trust-anchor side consumed by federation receivers that
/// pin a peer oracle's published public key.
pub trait EpochRootVerifier {
    /// Stable identity of the oracle whose signatures this verifier accepts.
    fn signer_id(&self) -> &str;

    /// Verify `signature` over `root`. Returns `Ok(())` only when the signer
    /// identity, algorithm tag, signature length, and cryptographic check all
    /// pass. Any mismatch or decode failure denies fail-closed.
    fn verify_epoch_root(&self, root: &EpochRoot, signature: &RootSignature) -> Result<()>;
}

/// Compute the exact byte sequence signed for `root`: the domain-separation
/// context followed by the RFC 8785 canonical JSON of the root.
fn signing_message(root: &EpochRoot) -> Result<Vec<u8>> {
    let canonical = canonical_json_bytes(root)
        .map_err(|err| RevocationOracleError::Serialization(err.to_string()))?;
    let mut message = Vec::with_capacity(DOMAIN_SEPARATION_CONTEXT.len() + canonical.len());
    message.extend_from_slice(DOMAIN_SEPARATION_CONTEXT);
    message.extend_from_slice(&canonical);
    Ok(message)
}

/// Ed25519 epoch-root signer holding the oracle's private [`Keypair`].
///
/// This is the default production signer for the revocation oracle. It signs
/// the domain-separated canonical JSON of an [`EpochRoot`] and tags the result
/// with [`ALGORITHM_ED25519`] and the configured `signer_id`.
#[derive(Clone)]
pub struct Ed25519RootSigner {
    signer_id: String,
    keypair: Keypair,
}

impl Ed25519RootSigner {
    /// Construct a signer from an existing [`Keypair`] and a stable
    /// `signer_id`.
    #[must_use]
    pub fn new(signer_id: impl Into<String>, keypair: Keypair) -> Self {
        Self {
            signer_id: signer_id.into(),
            keypair,
        }
    }

    /// Construct a signer from the canonical `signing_key` provisioning string.
    ///
    /// The value is either the literal `"generate"`, which mints a fresh random
    /// keypair for development and ephemeral deployments, or a 32-byte Ed25519
    /// seed encoded as hex (with an optional `0x` prefix). This mirrors the
    /// authority-keypair convention used across Chio control-plane components so
    /// the oracle key can be provisioned from the same seed-hex file source.
    ///
    /// A malformed seed (wrong length or non-hex) is rejected fail-closed as
    /// [`RevocationOracleError::SignerRejected`].
    pub fn from_signing_key(signer_id: impl Into<String>, signing_key: &str) -> Result<Self> {
        let keypair = if signing_key == "generate" {
            Keypair::generate()
        } else {
            Keypair::from_seed_hex(signing_key)
                .map_err(|_| RevocationOracleError::SignerRejected)?
        };
        Ok(Self::new(signer_id, keypair))
    }

    /// Public half of this signer's identity, suitable for pinning into a
    /// matching [`Ed25519RootVerifier`] and for out-of-band distribution to
    /// federation peers.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    /// Build the verify-only counterpart that pins this signer's public key and
    /// `signer_id`.
    #[must_use]
    pub fn verifier(&self) -> Ed25519RootVerifier {
        Ed25519RootVerifier::new(self.signer_id.clone(), self.keypair.public_key())
    }
}

impl EpochRootSigner for Ed25519RootSigner {
    fn signer_id(&self) -> &str {
        &self.signer_id
    }

    fn sign_epoch_root(&self, root: &EpochRoot) -> Result<RootSignature> {
        let message = signing_message(root)?;
        let signature = self.keypair.sign(&message);
        Ok(RootSignature {
            signer_id: self.signer_id.clone(),
            algorithm: ALGORITHM_ED25519.to_string(),
            signature_bytes: signature.to_bytes().to_vec(),
        })
    }
}

/// Ed25519 epoch-root verifier holding only the pinned [`PublicKey`].
///
/// Constructed from a federation peer's published public key (or from
/// [`Ed25519RootSigner::verifier`] in-process), this type checks signatures
/// without any ability to produce them.
#[derive(Clone, Debug)]
pub struct Ed25519RootVerifier {
    signer_id: String,
    public_key: PublicKey,
}

impl Ed25519RootVerifier {
    /// Construct a verifier from a pinned `signer_id` and [`PublicKey`].
    #[must_use]
    pub fn new(signer_id: impl Into<String>, public_key: PublicKey) -> Self {
        Self {
            signer_id: signer_id.into(),
            public_key,
        }
    }

    /// Construct a verifier from a pinned `signer_id` and a hex-encoded public
    /// key (the bare lowercase Ed25519 form, with optional `0x` prefix).
    ///
    /// A malformed public key is rejected fail-closed as
    /// [`RevocationOracleError::SignatureVerificationFailed`] so a verifier can
    /// never be built around undecodable trust material.
    pub fn from_public_key_hex(signer_id: impl Into<String>, public_key_hex: &str) -> Result<Self> {
        let public_key = PublicKey::from_hex(public_key_hex)
            .map_err(|_| RevocationOracleError::SignatureVerificationFailed)?;
        Ok(Self::new(signer_id, public_key))
    }

    /// Borrow the pinned public key.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

impl EpochRootVerifier for Ed25519RootVerifier {
    fn signer_id(&self) -> &str {
        &self.signer_id
    }

    fn verify_epoch_root(&self, root: &EpochRoot, signature: &RootSignature) -> Result<()> {
        if signature.signer_id != self.signer_id || signature.algorithm != ALGORITHM_ED25519 {
            return Err(RevocationOracleError::SignatureVerificationFailed);
        }
        let signature_bytes: [u8; ED25519_SIGNATURE_LEN] = signature
            .signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| RevocationOracleError::SignatureVerificationFailed)?;
        let candidate = Signature::from_bytes(&signature_bytes);
        let message = signing_message(root)?;
        if self.public_key.verify(&message, &candidate) {
            Ok(())
        } else {
            Err(RevocationOracleError::SignatureVerificationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    const SEED_A: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const SEED_B: &str = "0202020202020202020202020202020202020202020202020202020202020202";

    fn epoch_root(epoch: u64) -> EpochRoot {
        EpochRoot {
            epoch,
            root_hash: [epoch as u8; 32],
            leaf_count: epoch as usize,
            issued_at_unix_ms: 1_700_000_000_000 + epoch,
        }
    }

    #[test]
    fn sign_verify_round_trip() {
        let signer = Ed25519RootSigner::from_signing_key("oracle-a", SEED_A).test_unwrap();
        let verifier = signer.verifier();
        let root = epoch_root(7);
        let signature = signer.sign_epoch_root(&root).test_unwrap();
        assert_eq!(signature.algorithm, ALGORITHM_ED25519);
        assert_eq!(signature.signer_id, "oracle-a");
        assert_eq!(signature.signature_bytes.len(), ED25519_SIGNATURE_LEN);
        verifier.verify_epoch_root(&root, &signature).test_unwrap();
    }

    #[test]
    fn signatures_are_deterministic_for_a_fixed_seed() {
        let signer_one = Ed25519RootSigner::from_signing_key("oracle-a", SEED_A).test_unwrap();
        let signer_two = Ed25519RootSigner::from_signing_key("oracle-a", SEED_A).test_unwrap();
        let root = epoch_root(3);
        let sig_one = signer_one.sign_epoch_root(&root).test_unwrap();
        let sig_two = signer_two.sign_epoch_root(&root).test_unwrap();
        assert_eq!(sig_one.signature_bytes, sig_two.signature_bytes);
    }

    #[test]
    fn tampered_root_fails() {
        let signer = Ed25519RootSigner::from_signing_key("oracle-a", SEED_A).test_unwrap();
        let verifier = signer.verifier();
        let root = epoch_root(7);
        let signature = signer.sign_epoch_root(&root).test_unwrap();

        let mut tampered = root.clone();
        tampered.root_hash[0] ^= 0x01;
        assert_eq!(
            verifier.verify_epoch_root(&tampered, &signature),
            Err(RevocationOracleError::SignatureVerificationFailed)
        );

        let mut tampered_count = root.clone();
        tampered_count.leaf_count += 1;
        assert_eq!(
            verifier.verify_epoch_root(&tampered_count, &signature),
            Err(RevocationOracleError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn tampered_signature_bytes_fail() {
        let signer = Ed25519RootSigner::from_signing_key("oracle-a", SEED_A).test_unwrap();
        let verifier = signer.verifier();
        let root = epoch_root(7);
        let mut signature = signer.sign_epoch_root(&root).test_unwrap();
        signature.signature_bytes[0] ^= 0x01;
        assert_eq!(
            verifier.verify_epoch_root(&root, &signature),
            Err(RevocationOracleError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let signer = Ed25519RootSigner::from_signing_key("oracle-a", SEED_A).test_unwrap();
        let other = Ed25519RootSigner::from_signing_key("oracle-a", SEED_B).test_unwrap();
        let root = epoch_root(7);
        let signature = signer.sign_epoch_root(&root).test_unwrap();
        // Same signer_id, different key: must fail-closed.
        assert_eq!(
            other.verifier().verify_epoch_root(&root, &signature),
            Err(RevocationOracleError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn wrong_signer_id_is_rejected() {
        let signer = Ed25519RootSigner::from_signing_key("oracle-a", SEED_A).test_unwrap();
        let root = epoch_root(7);
        let signature = signer.sign_epoch_root(&root).test_unwrap();
        let verifier = Ed25519RootVerifier::new("oracle-b", signer.public_key());
        assert_eq!(
            verifier.verify_epoch_root(&root, &signature),
            Err(RevocationOracleError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn wrong_algorithm_tag_is_rejected() {
        let signer = Ed25519RootSigner::from_signing_key("oracle-a", SEED_A).test_unwrap();
        let verifier = signer.verifier();
        let root = epoch_root(7);
        let mut signature = signer.sign_epoch_root(&root).test_unwrap();
        signature.algorithm = "digest-stub-sha256".to_string();
        assert_eq!(
            verifier.verify_epoch_root(&root, &signature),
            Err(RevocationOracleError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn short_signature_bytes_fail_closed() {
        let signer = Ed25519RootSigner::from_signing_key("oracle-a", SEED_A).test_unwrap();
        let verifier = signer.verifier();
        let root = epoch_root(7);
        let mut signature = signer.sign_epoch_root(&root).test_unwrap();
        signature.signature_bytes.truncate(32);
        assert_eq!(
            verifier.verify_epoch_root(&root, &signature),
            Err(RevocationOracleError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn malformed_seed_is_rejected() {
        assert_eq!(
            Ed25519RootSigner::from_signing_key("oracle-a", "not-hex").err(),
            Some(RevocationOracleError::SignerRejected)
        );
        // 16 bytes instead of 32.
        assert_eq!(
            Ed25519RootSigner::from_signing_key("oracle-a", "01010101010101010101010101010101")
                .err(),
            Some(RevocationOracleError::SignerRejected)
        );
    }

    #[test]
    fn verifier_from_public_key_hex_round_trip() {
        let signer = Ed25519RootSigner::from_signing_key("oracle-a", SEED_A).test_unwrap();
        let public_key_hex = signer.public_key().to_hex();
        let verifier =
            Ed25519RootVerifier::from_public_key_hex("oracle-a", &public_key_hex).test_unwrap();
        let root = epoch_root(9);
        let signature = signer.sign_epoch_root(&root).test_unwrap();
        verifier.verify_epoch_root(&root, &signature).test_unwrap();
    }

    #[test]
    fn verifier_from_malformed_public_key_hex_is_rejected() {
        assert_eq!(
            Ed25519RootVerifier::from_public_key_hex("oracle-a", "zz").err(),
            Some(RevocationOracleError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn signing_message_is_domain_separated() {
        let root = epoch_root(1);
        let message = signing_message(&root).test_unwrap();
        assert!(message.starts_with(DOMAIN_SEPARATION_CONTEXT));
        let canonical = canonical_json_bytes(&root).test_unwrap();
        assert_eq!(
            &message[DOMAIN_SEPARATION_CONTEXT.len()..],
            canonical.as_slice()
        );
    }
}
