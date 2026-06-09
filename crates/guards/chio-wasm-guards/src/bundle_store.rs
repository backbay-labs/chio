//! In-process content bundle storage for WASM guard policy context.
//!
//! Deliberately local to `chio-wasm-guards`: the `policy-context::bundle-handle`
//! resource reads from this host-owned store.

use std::collections::HashMap;

/// Storage abstraction for content-addressed policy-context blobs.
pub trait BundleStore: Send + Sync {
    /// Fetch the full blob identified by its SHA-256 digest.
    fn fetch_blob(&self, sha256: &[u8; 32]) -> Result<Vec<u8>, BundleError>;
}

/// Errors returned by content bundle storage.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BundleError {
    /// The supplied digest string is not a valid SHA-256 hex digest.
    #[error("invalid sha256 digest {digest:?}: expected sha256:<64 hex chars> or 64 hex chars")]
    InvalidSha256 { digest: String },
    /// No blob exists for the requested digest.
    #[error("bundle blob not found for sha256:{sha256}")]
    MissingBlob { sha256: String },
}

/// Minimal in-memory bundle store.
#[derive(Debug, Default, Clone)]
pub struct InMemoryBundleStore {
    blobs: HashMap<[u8; 32], Vec<u8>>,
}

impl InMemoryBundleStore {
    /// Create an empty in-memory bundle store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a blob by SHA-256 digest.
    pub fn insert(&mut self, sha256: [u8; 32], blob: impl Into<Vec<u8>>) {
        self.blobs.insert(sha256, blob.into());
    }

    /// Return a new store containing one blob.
    #[must_use]
    pub fn with_blob(mut self, sha256: [u8; 32], blob: impl Into<Vec<u8>>) -> Self {
        self.insert(sha256, blob);
        self
    }
}

impl BundleStore for InMemoryBundleStore {
    fn fetch_blob(&self, sha256: &[u8; 32]) -> Result<Vec<u8>, BundleError> {
        self.blobs
            .get(sha256)
            .cloned()
            .ok_or_else(|| BundleError::MissingBlob {
                sha256: hex::encode(sha256),
            })
    }
}

/// Parse a content-addressed bundle id into a SHA-256 digest.
///
/// Accepted forms are `sha256:<64 hex chars>` and bare `64 hex chars`.
pub fn parse_sha256_digest(id: &str) -> Result<[u8; 32], BundleError> {
    let digest = id.strip_prefix("sha256:").unwrap_or(id);
    if digest.len() != 64 || !digest.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(BundleError::InvalidSha256 {
            digest: id.to_string(),
        });
    }

    let mut out = [0_u8; 32];
    hex::decode_to_slice(digest, &mut out).map_err(|_| BundleError::InvalidSha256 {
        digest: id.to_string(),
    })?;
    Ok(out)
}
