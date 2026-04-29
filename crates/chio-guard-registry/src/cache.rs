//! Content-addressed on-disk cache for pulled Chio guard artifacts.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::oci::{GuardRegistryError, Result, Sha256Digest};

/// OCI image manifest cache file name.
pub const CACHE_MANIFEST_JSON_FILE: &str = "manifest.json";
/// Chio guard config cache file name.
pub const CACHE_CONFIG_JSON_FILE: &str = "config.json";
/// Raw WIT layer cache file name.
pub const CACHE_WIT_BIN_FILE: &str = "wit.bin";
/// Wasm component cache file name.
pub const CACHE_MODULE_WASM_FILE: &str = "module.wasm";
/// Sigstore bundle cache file name.
pub const CACHE_SIGSTORE_BUNDLE_JSON_FILE: &str = "sigstore-bundle.json";

/// Ordered cache file names required for every cached guard artifact.
pub const CACHE_FILE_NAMES: [&str; 5] = [
    CACHE_MANIFEST_JSON_FILE,
    CACHE_CONFIG_JSON_FILE,
    CACHE_WIT_BIN_FILE,
    CACHE_MODULE_WASM_FILE,
    CACHE_SIGSTORE_BUNDLE_JSON_FILE,
];

/// Root directory for the Chio guard artifact cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardCache {
    root: PathBuf,
}

impl GuardCache {
    /// Build a cache rooted at `${cache_home}/chio/guards`.
    pub fn from_cache_home(cache_home: impl Into<PathBuf>) -> Self {
        Self::new(cache_home.into().join("chio").join("guards"))
    }

    /// Build a cache rooted at `${XDG_CACHE_HOME:-~/.cache}/chio/guards`.
    pub fn from_environment() -> Result<Self> {
        Ok(Self::from_cache_home(default_cache_home()?))
    }

    /// Build a cache from an already-derived guard cache root.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Return the guard cache root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Derive the cache layout for a validated sha256 digest.
    pub fn layout(&self, digest: &Sha256Digest) -> GuardCacheLayout {
        GuardCacheLayout::new(self.root.clone(), digest)
    }

    /// Write all cache files for a pulled guard artifact.
    pub fn write_artifact(
        &self,
        digest: &Sha256Digest,
        artifact: GuardCacheArtifact<'_>,
    ) -> Result<CachedGuardArtifact> {
        let layout = self.layout(digest);
        create_dir_all(layout.directory())?;
        write_cache_file(&layout.manifest_json_path(), artifact.manifest_json)?;
        write_cache_file(&layout.config_json_path(), artifact.config_json)?;
        write_cache_file(&layout.wit_bin_path(), artifact.wit)?;
        write_cache_file(&layout.module_wasm_path(), artifact.module)?;
        write_cache_file(
            &layout.sigstore_bundle_json_path(),
            artifact.sigstore_bundle_json,
        )?;

        Ok(CachedGuardArtifact {
            digest: digest.clone(),
            layout,
        })
    }
}

/// File layout for one content-addressed guard artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardCacheLayout {
    directory: PathBuf,
}

impl GuardCacheLayout {
    /// Build a layout rooted at `<cache_root>/<sha256-digest>`.
    pub fn new(cache_root: impl Into<PathBuf>, digest: &Sha256Digest) -> Self {
        Self {
            directory: cache_root.into().join(digest.as_str()),
        }
    }

    /// Directory containing all cached files for the digest.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// OCI image manifest path.
    pub fn manifest_json_path(&self) -> PathBuf {
        self.directory.join(CACHE_MANIFEST_JSON_FILE)
    }

    /// Chio guard config path.
    pub fn config_json_path(&self) -> PathBuf {
        self.directory.join(CACHE_CONFIG_JSON_FILE)
    }

    /// Raw WIT layer path.
    pub fn wit_bin_path(&self) -> PathBuf {
        self.directory.join(CACHE_WIT_BIN_FILE)
    }

    /// Wasm component path.
    pub fn module_wasm_path(&self) -> PathBuf {
        self.directory.join(CACHE_MODULE_WASM_FILE)
    }

    /// Sigstore bundle path.
    pub fn sigstore_bundle_json_path(&self) -> PathBuf {
        self.directory.join(CACHE_SIGSTORE_BUNDLE_JSON_FILE)
    }

    /// Return the complete ordered file path list for the layout.
    pub fn file_paths(&self) -> [PathBuf; 5] {
        [
            self.manifest_json_path(),
            self.config_json_path(),
            self.wit_bin_path(),
            self.module_wasm_path(),
            self.sigstore_bundle_json_path(),
        ]
    }
}

/// Bytes to write into one cache entry.
#[derive(Debug, Clone, Copy)]
pub struct GuardCacheArtifact<'a> {
    /// OCI image manifest bytes.
    pub manifest_json: &'a [u8],
    /// Chio guard config bytes.
    pub config_json: &'a [u8],
    /// Raw WIT layer bytes.
    pub wit: &'a [u8],
    /// Wasm component bytes.
    pub module: &'a [u8],
    /// Sigstore bundle bytes.
    pub sigstore_bundle_json: &'a [u8],
}

/// Cache write result for a pulled guard artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedGuardArtifact {
    /// Validated sha256 digest for this cache entry.
    pub digest: Sha256Digest,
    /// Concrete file layout written to disk.
    pub layout: GuardCacheLayout,
}

fn default_cache_home() -> Result<PathBuf> {
    if let Some(cache_home) = env::var_os("XDG_CACHE_HOME") {
        if !cache_home.as_os_str().is_empty() {
            return Ok(PathBuf::from(cache_home));
        }
    }

    let Some(home) = env::var_os("HOME") else {
        return Err(GuardRegistryError::CacheRootUnavailable);
    };
    if home.as_os_str().is_empty() {
        return Err(GuardRegistryError::CacheRootUnavailable);
    }

    Ok(PathBuf::from(home).join(".cache"))
}

fn create_dir_all(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|source| GuardRegistryError::CacheIo {
        operation: "create",
        path: path.to_path_buf(),
        source,
    })
}

fn write_cache_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).map_err(|source| GuardRegistryError::CacheIo {
        operation: "write",
        path: path.to_path_buf(),
        source,
    })
}
