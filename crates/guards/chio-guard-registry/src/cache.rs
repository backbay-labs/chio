//! Content-addressed on-disk cache for pulled Chio guard artifacts.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::oci::{
    GuardRegistryError, Result, Sha256Digest, GUARD_ARTIFACT_MEDIA_TYPE, GUARD_CONFIG_MEDIA_TYPE,
    GUARD_MANIFEST_LAYER_MEDIA_TYPE, GUARD_MODULE_LAYER_MEDIA_TYPE, GUARD_WIT_LAYER_MEDIA_TYPE,
};
use crate::publish::GUARD_OCI_MANIFEST_MEDIA_TYPE;
use oci_distribution::manifest::{OciDescriptor, OciImageManifest};
use sha2::{Digest, Sha256};

/// OCI image manifest cache file name.
pub const CACHE_MANIFEST_JSON_FILE: &str = "manifest.json";
/// Chio guard config cache file name.
pub const CACHE_CONFIG_JSON_FILE: &str = "config.json";
/// Raw WIT layer cache file name.
pub const CACHE_WIT_BIN_FILE: &str = "wit.bin";
/// Wasm component cache file name.
pub const CACHE_MODULE_WASM_FILE: &str = "module.wasm";
/// Guard manifest layer cache file name.
pub const CACHE_GUARD_MANIFEST_JSON_FILE: &str = "guard-manifest.json";
/// Sigstore bundle cache file name.
pub const CACHE_SIGSTORE_BUNDLE_JSON_FILE: &str = "sigstore-bundle.json";

/// Ordered cache file names required for every cached guard artifact.
pub const CACHE_FILE_NAMES: [&str; 6] = [
    CACHE_MANIFEST_JSON_FILE,
    CACHE_CONFIG_JSON_FILE,
    CACHE_WIT_BIN_FILE,
    CACHE_MODULE_WASM_FILE,
    CACHE_GUARD_MANIFEST_JSON_FILE,
    CACHE_SIGSTORE_BUNDLE_JSON_FILE,
];

/// Ordered cache file names required before any guard artifact can be loaded.
pub const CACHE_ARTIFACT_FILE_NAMES: [&str; 5] = [
    CACHE_MANIFEST_JSON_FILE,
    CACHE_CONFIG_JSON_FILE,
    CACHE_WIT_BIN_FILE,
    CACHE_MODULE_WASM_FILE,
    CACHE_GUARD_MANIFEST_JSON_FILE,
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
        validate_cache_admission(digest, &artifact)?;
        let layout = self.layout(digest);
        create_dir_all(layout.directory())?;
        write_cache_file(&layout.manifest_json_path(), artifact.manifest_json)?;
        write_cache_file(&layout.config_json_path(), artifact.config_json)?;
        write_cache_file(&layout.wit_bin_path(), artifact.wit)?;
        write_cache_file(&layout.module_wasm_path(), artifact.module)?;
        write_cache_file(
            &layout.guard_manifest_json_path(),
            artifact.guard_manifest_json,
        )?;
        if let Some(sigstore_bundle_json) = artifact.sigstore_bundle_json {
            write_cache_file(&layout.sigstore_bundle_json_path(), sigstore_bundle_json)?;
        } else {
            remove_cache_file_if_exists(&layout.sigstore_bundle_json_path())?;
        }

        Ok(CachedGuardArtifact {
            digest: digest.clone(),
            layout,
        })
    }
}

/// Re-read a cache entry and validate that every cached artifact file still
/// matches the pinned OCI manifest digest and descriptor metadata.
pub fn validate_cached_artifact_layout(
    digest: &Sha256Digest,
    layout: &GuardCacheLayout,
) -> Result<()> {
    let manifest_json = read_cache_file(&layout.manifest_json_path())?;
    let config_json = read_cache_file(&layout.config_json_path())?;
    let wit = read_cache_file(&layout.wit_bin_path())?;
    let module = read_cache_file(&layout.module_wasm_path())?;
    let guard_manifest_json = read_cache_file(&layout.guard_manifest_json_path())?;
    validate_cache_admission(
        digest,
        &GuardCacheArtifact {
            manifest_json: &manifest_json,
            config_json: &config_json,
            wit: &wit,
            module: &module,
            guard_manifest_json: &guard_manifest_json,
            sigstore_bundle_json: None,
        },
    )
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

    /// Guard manifest layer path.
    pub fn guard_manifest_json_path(&self) -> PathBuf {
        self.directory.join(CACHE_GUARD_MANIFEST_JSON_FILE)
    }

    /// Sigstore bundle path.
    pub fn sigstore_bundle_json_path(&self) -> PathBuf {
        self.directory.join(CACHE_SIGSTORE_BUNDLE_JSON_FILE)
    }

    /// Return the complete ordered file path list for the layout.
    pub fn file_paths(&self) -> [PathBuf; 6] {
        [
            self.manifest_json_path(),
            self.config_json_path(),
            self.wit_bin_path(),
            self.module_wasm_path(),
            self.guard_manifest_json_path(),
            self.sigstore_bundle_json_path(),
        ]
    }

    /// Return files required for the pulled artifact independent of
    /// verification material.
    pub fn artifact_file_paths(&self) -> [PathBuf; 5] {
        [
            self.manifest_json_path(),
            self.config_json_path(),
            self.wit_bin_path(),
            self.module_wasm_path(),
            self.guard_manifest_json_path(),
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
    /// Guard manifest layer bytes.
    pub guard_manifest_json: &'a [u8],
    /// Optional Sigstore bundle bytes. `None` means the artifact was cached
    /// without Sigstore verification material; Sigstore load modes will deny
    /// until the bundle file is supplied.
    pub sigstore_bundle_json: Option<&'a [u8]>,
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

fn ensure_manifest_digest_matches(digest: &Sha256Digest, manifest_json: &[u8]) -> Result<()> {
    let actual = format!("sha256:{:x}", Sha256::digest(manifest_json));
    if actual != digest.as_str() {
        return Err(GuardRegistryError::ManifestDigestMismatch {
            expected: digest.as_str().to_owned(),
            actual,
        });
    }
    Ok(())
}

fn validate_cache_admission(
    digest: &Sha256Digest,
    artifact: &GuardCacheArtifact<'_>,
) -> Result<()> {
    ensure_manifest_digest_matches(digest, artifact.manifest_json)?;
    let manifest =
        serde_json::from_slice::<OciImageManifest>(artifact.manifest_json).map_err(|err| {
            GuardRegistryError::VerifyFailedClosed {
                message: format!("failed to parse pulled OCI manifest JSON: {err}"),
            }
        })?;
    validate_top_level_manifest_shape(&manifest)?;
    validate_descriptor(
        "config.json",
        &manifest.config,
        GUARD_CONFIG_MEDIA_TYPE,
        artifact.config_json,
    )?;
    if manifest.layers.len() != 3 {
        return Err(GuardRegistryError::LayerCount {
            actual: manifest.layers.len(),
        });
    }
    validate_descriptor(
        "wit.bin",
        descriptor_for_layer(&manifest.layers, "wit.bin", GUARD_WIT_LAYER_MEDIA_TYPE)?,
        GUARD_WIT_LAYER_MEDIA_TYPE,
        artifact.wit,
    )?;
    validate_descriptor(
        "module.wasm",
        descriptor_for_layer(
            &manifest.layers,
            "module.wasm",
            GUARD_MODULE_LAYER_MEDIA_TYPE,
        )?,
        GUARD_MODULE_LAYER_MEDIA_TYPE,
        artifact.module,
    )?;
    validate_descriptor(
        "guard-manifest.json",
        descriptor_for_layer(
            &manifest.layers,
            "guard-manifest.json",
            GUARD_MANIFEST_LAYER_MEDIA_TYPE,
        )?,
        GUARD_MANIFEST_LAYER_MEDIA_TYPE,
        artifact.guard_manifest_json,
    )?;
    Ok(())
}

fn validate_top_level_manifest_shape(manifest: &OciImageManifest) -> Result<()> {
    if manifest.media_type.as_deref() != Some(GUARD_OCI_MANIFEST_MEDIA_TYPE) {
        return Err(GuardRegistryError::DescriptorMediaTypeMismatch {
            artifact: "manifest.json",
            expected: GUARD_OCI_MANIFEST_MEDIA_TYPE,
            actual: manifest
                .media_type
                .clone()
                .unwrap_or_else(|| "<missing>".to_owned()),
        });
    }
    if manifest.artifact_type.as_deref() != Some(GUARD_ARTIFACT_MEDIA_TYPE) {
        return Err(GuardRegistryError::DescriptorMediaTypeMismatch {
            artifact: "manifest.json",
            expected: GUARD_ARTIFACT_MEDIA_TYPE,
            actual: manifest
                .artifact_type
                .clone()
                .unwrap_or_else(|| "<missing>".to_owned()),
        });
    }
    Ok(())
}

fn descriptor_for_layer<'a>(
    layers: &'a [OciDescriptor],
    artifact_name: &'static str,
    expected_media_type: &'static str,
) -> Result<&'a OciDescriptor> {
    let mut matches = layers
        .iter()
        .filter(|layer| layer.media_type == expected_media_type);
    let Some(descriptor) = matches.next() else {
        let actual = layers
            .iter()
            .map(|layer| layer.media_type.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(GuardRegistryError::DescriptorMediaTypeMismatch {
            artifact: artifact_name,
            expected: expected_media_type,
            actual: if actual.is_empty() {
                "<missing>".to_owned()
            } else {
                actual
            },
        });
    };
    if matches.next().is_some() {
        return Err(GuardRegistryError::DescriptorMediaTypeMismatch {
            artifact: artifact_name,
            expected: expected_media_type,
            actual: format!("{expected_media_type} appears multiple times"),
        });
    }

    Ok(descriptor)
}

fn validate_descriptor(
    artifact_name: &'static str,
    descriptor: &OciDescriptor,
    expected_media_type: &'static str,
    bytes: &[u8],
) -> Result<()> {
    if descriptor.media_type != expected_media_type {
        return Err(GuardRegistryError::DescriptorMediaTypeMismatch {
            artifact: artifact_name,
            expected: expected_media_type,
            actual: descriptor.media_type.clone(),
        });
    }
    let actual_digest = format!("sha256:{:x}", Sha256::digest(bytes));
    if descriptor.digest != actual_digest {
        return Err(GuardRegistryError::DescriptorDigestMismatch {
            artifact: artifact_name,
            expected: descriptor.digest.clone(),
            actual: actual_digest,
        });
    }
    let actual_size = i64::try_from(bytes.len()).unwrap_or(i64::MAX);
    if descriptor.size != actual_size {
        return Err(GuardRegistryError::DescriptorSizeMismatch {
            artifact: artifact_name,
            expected: descriptor.size,
            actual: actual_size,
        });
    }
    Ok(())
}

fn write_cache_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).map_err(|source| GuardRegistryError::CacheIo {
        operation: "write",
        path: path.to_path_buf(),
        source,
    })
}

fn read_cache_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|source| GuardRegistryError::CacheIo {
        operation: "read",
        path: path.to_path_buf(),
        source,
    })
}

fn remove_cache_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(GuardRegistryError::CacheIo {
            operation: "remove",
            path: path.to_path_buf(),
            source,
        }),
    }
}
