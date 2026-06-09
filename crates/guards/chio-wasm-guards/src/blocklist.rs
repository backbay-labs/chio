//! Persistent digest blocklist for guard reload and pull paths.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Structured error code emitted when a guard digest is blocked.
pub const E_GUARD_DIGEST_BLOCKLISTED: &str = "E_GUARD_DIGEST_BLOCKLISTED";

/// Persistent blocklist rooted at `${XDG_STATE_HOME}/chio/guards/blocklist.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardDigestBlocklist {
    path: PathBuf,
}

impl GuardDigestBlocklist {
    /// Build a blocklist rooted at `${state_home}/chio/guards/blocklist.json`.
    #[must_use]
    pub fn from_state_home(state_home: impl Into<PathBuf>) -> Self {
        Self::from_path(
            state_home
                .into()
                .join("chio")
                .join("guards")
                .join("blocklist.json"),
        )
    }

    /// Build a blocklist from an explicit JSON file path.
    #[must_use]
    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Build a blocklist rooted at `${XDG_STATE_HOME:-~/.local/state}`.
    pub fn from_environment() -> Result<Self, BlocklistError> {
        Ok(Self::from_state_home(default_state_home()?))
    }

    /// Return the concrete blocklist file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Return true when `digest` is present in the persisted blocklist.
    pub fn is_blocklisted(&self, digest: &str) -> Result<bool, BlocklistError> {
        let digest = normalize_digest(digest)?;
        Ok(self.load()?.digests.contains(&digest))
    }

    /// Add `digest` to the persisted blocklist.
    pub fn add_digest(&self, digest: &str) -> Result<bool, BlocklistError> {
        let digest = normalize_digest(digest)?;
        let mut file = self.load()?;
        let inserted = file.digests.insert(digest);
        self.store(&file)?;
        Ok(inserted)
    }

    /// Remove `digest` from the persisted blocklist.
    pub fn remove_digest(&self, digest: &str) -> Result<bool, BlocklistError> {
        let digest = normalize_digest(digest)?;
        let mut file = self.load()?;
        let removed = file.digests.remove(&digest);
        self.store(&file)?;
        Ok(removed)
    }

    fn load(&self) -> Result<BlocklistFile, BlocklistError> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|source| BlocklistError::Json {
                path: self.path.clone(),
                source,
            }),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                Ok(BlocklistFile::default())
            }
            Err(source) => Err(BlocklistError::Io {
                operation: "read",
                path: self.path.clone(),
                source,
            }),
        }
    }

    fn store(&self, file: &BlocklistFile) -> Result<(), BlocklistError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|source| BlocklistError::Io {
                operation: "create",
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let bytes = serde_json::to_vec_pretty(file).map_err(|source| BlocklistError::Json {
            path: self.path.clone(),
            source,
        })?;
        fs::write(&self.path, bytes).map_err(|source| BlocklistError::Io {
            operation: "write",
            path: self.path.clone(),
            source,
        })
    }
}

/// Normalize a digest into `sha256:<64-lower-hex>`.
pub fn normalize_digest(digest: &str) -> Result<String, BlocklistError> {
    let value = digest.trim();
    let hex = value.strip_prefix("sha256:").unwrap_or(value);
    if hex.len() != 64 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(BlocklistError::InvalidDigest {
            digest: digest.to_string(),
        });
    }
    Ok(format!("sha256:{}", hex.to_ascii_lowercase()))
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct BlocklistFile {
    #[serde(default)]
    digests: BTreeSet<String>,
}

/// Blocklist persistence and validation errors.
#[derive(Debug, thiserror::Error)]
pub enum BlocklistError {
    /// Digest does not have a valid sha256 form.
    #[error("guard digest must be sha256:<64-hex> or <64-hex>, got {digest:?}")]
    InvalidDigest {
        /// Rejected digest.
        digest: String,
    },

    /// Blocklist file IO failed.
    #[error("failed to {operation} guard blocklist path {}: {source}", path.display())]
    Io {
        /// Operation name.
        operation: &'static str,
        /// Path being accessed.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },

    /// Blocklist JSON failed to parse or serialize.
    #[error("guard blocklist JSON invalid at {}: {source}", path.display())]
    Json {
        /// Path being accessed.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: serde_json::Error,
    },

    /// No state-home path could be derived.
    #[error("could not derive Chio guard state root from XDG_STATE_HOME or HOME")]
    StateRootUnavailable,
}

fn default_state_home() -> Result<PathBuf, BlocklistError> {
    if let Some(state_home) = env::var_os("XDG_STATE_HOME") {
        if !state_home.as_os_str().is_empty() {
            return Ok(PathBuf::from(state_home));
        }
    }

    let Some(home) = env::var_os("HOME") else {
        return Err(BlocklistError::StateRootUnavailable);
    };
    if home.as_os_str().is_empty() {
        return Err(BlocklistError::StateRootUnavailable);
    }

    Ok(PathBuf::from(home).join(".local").join("state"))
}
