//! Cryptographic hashing (SHA-256).
//!
//! Provides a typed 32-byte `Hash` value and SHA-256 convenience functions.
//! Ported from hush-core's `hashing` module for use in Merkle trees and
//! receipt log integrity proofs.

use alloc::format;
use alloc::string::{String, ToString};

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::error::{Error, Result};

/// A 32-byte hash value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash {
    #[serde(with = "hash_serde")]
    bytes: [u8; 32],
}

mod hash_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], s: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&alloc::format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D>(d: D) -> core::result::Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = alloc::string::String::deserialize(d)?;
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(&hex_str);
        let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("hash must be 32 bytes"))
    }
}

impl Hash {
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Create from hex string (with or without `0x` prefix).
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

        let bytes = hex::decode(hex_str).map_err(|e| Error::InvalidHex(e.to_string()))?;

        if bytes.len() != 32 {
            return Err(Error::InvalidHashLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_bytes(arr))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    #[must_use]
    pub fn to_hex_prefixed(&self) -> String {
        format!("0x{}", self.to_hex())
    }

    #[must_use]
    pub fn zero() -> Self {
        Self { bytes: [0u8; 32] }
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Display for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{}", self.to_hex())
    }
}

/// Compute SHA-256 hash of data.
#[must_use]
pub fn sha256(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash::from_bytes(bytes)
}

/// Compute SHA-256 hash and return as hex string (no prefix).
///
/// This matches the convention of `crypto::sha256_hex` within chio-core.
/// Use `sha256(data).to_hex_prefixed()` if you need a `0x` prefix.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    sha256(data).to_hex()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello");
        // Known SHA-256 hash of "hello"
        assert_eq!(
            hash.to_hex(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex(b"hello");
        assert_eq!(hash.len(), 64); // 64 hex chars, no prefix
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_hash_from_hex() {
        let original = sha256(b"test");
        let from_hex = Hash::from_hex(&original.to_hex()).unwrap();
        let from_hex_prefixed = Hash::from_hex(&original.to_hex_prefixed()).unwrap();

        assert_eq!(original, from_hex);
        assert_eq!(original, from_hex_prefixed);
    }

    #[test]
    fn test_hash_serde() {
        let hash = sha256(b"test");
        let json = serde_json::to_string(&hash).unwrap();
        let restored: Hash = serde_json::from_str(&json).unwrap();

        assert_eq!(hash, restored);
        assert!(json.contains("0x")); // Should be prefixed in JSON
    }

    #[test]
    fn test_hash_display() {
        let hash = sha256(b"hello");
        let display = format!("{hash}");
        assert!(display.starts_with("0x"));
        assert_eq!(display.len(), 66);
    }

    #[test]
    fn test_zero_hash() {
        let zero = Hash::zero();
        assert_eq!(zero.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_concat_hashes() {
        fn concat_hashes(left: &Hash, right: &Hash) -> Hash {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(left.as_bytes());
            combined[32..].copy_from_slice(right.as_bytes());
            sha256(&combined)
        }

        let h1 = sha256(b"left");
        let h2 = sha256(b"right");
        let combined = concat_hashes(&h1, &h2);

        // Should be deterministic
        let combined2 = concat_hashes(&h1, &h2);
        assert_eq!(combined, combined2);

        // Order matters
        let combined_reversed = concat_hashes(&h2, &h1);
        assert_ne!(combined, combined_reversed);
    }
}
