//! Loaded model-weight digest surface.
//!
//! Providers that can expose the loaded artifact return bytes for a
//! recomputed SHA-256 digest. Hosted APIs and protocol bridges that cannot
//! expose the artifact return [`LoadedWeightsUnavailable`] so kernel bind can
//! fail closed.

use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use sha2::{Digest, Sha256};

/// Typed refusal for providers that cannot expose loaded model bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedWeightsUnavailable {
    provider: String,
    reason: String,
}

impl LoadedWeightsUnavailable {
    /// Construct an unavailable error for a provider or protocol surface.
    #[must_use]
    pub fn new(provider: impl ToString, reason: impl ToString) -> Self {
        Self {
            provider: provider.to_string(),
            reason: reason.to_string(),
        }
    }

    /// Provider or protocol surface that could not expose loaded weights.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Human-readable reason the loaded artifact is not available.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for LoadedWeightsUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "loaded weights unavailable for {}: {}",
            self.provider, self.reason
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LoadedWeightsUnavailable {}

/// Recomputes a loaded-weight digest from provider-owned bytes.
pub trait LoadedWeights {
    /// Provider or fixture name used in unavailable errors and audit output.
    fn provider_name(&self) -> &'static str;

    /// Return the bytes for the loaded model artifact.
    fn loaded_weights_bytes(&self) -> Result<Cow<'_, [u8]>, LoadedWeightsUnavailable>;

    /// Return lowercase hex SHA-256 over the loaded model artifact.
    fn loaded_weights_hash(&self) -> Result<String, LoadedWeightsUnavailable> {
        let bytes = self.loaded_weights_bytes()?;
        Ok(loaded_weights_hash_of(bytes.as_ref()))
    }
}

impl LoadedWeights for [u8] {
    fn provider_name(&self) -> &'static str {
        "test-fixture"
    }

    fn loaded_weights_bytes(&self) -> Result<Cow<'_, [u8]>, LoadedWeightsUnavailable> {
        Ok(Cow::Borrowed(self))
    }
}

impl LoadedWeights for Vec<u8> {
    fn provider_name(&self) -> &'static str {
        "test-fixture"
    }

    fn loaded_weights_bytes(&self) -> Result<Cow<'_, [u8]>, LoadedWeightsUnavailable> {
        Ok(Cow::Borrowed(self.as_slice()))
    }
}

/// Compute a lowercase hex SHA-256 digest from one or more chunks.
#[must_use]
pub fn loaded_weights_hash_of_chunks<I, B>(chunks: I) -> String
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    let mut hasher = Sha256::new();
    for chunk in chunks {
        hasher.update(chunk.as_ref());
    }
    hex::encode(hasher.finalize())
}

/// Compute a lowercase hex SHA-256 digest from one contiguous byte slice.
#[must_use]
pub fn loaded_weights_hash_of(bytes: &[u8]) -> String {
    loaded_weights_hash_of_chunks([bytes])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_digest_matches_single_slice_digest() {
        let single = loaded_weights_hash_of(b"abc123");
        let chunked = loaded_weights_hash_of_chunks([b"abc".as_slice(), b"123".as_slice()]);
        assert_eq!(single, chunked);
    }

    #[test]
    fn digest_matches_sha256_known_vector() {
        assert_eq!(
            loaded_weights_hash_of(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn byte_slice_implements_loaded_weights() {
        let bytes = b"fixture-weights".as_slice();
        let hash = match bytes.loaded_weights_hash() {
            Ok(hash) => hash,
            Err(err) => panic!("fixture bytes should hash: {err}"),
        };
        assert_eq!(hash, loaded_weights_hash_of(b"fixture-weights"));
    }
}
