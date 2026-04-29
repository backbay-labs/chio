//! Fail-closed offline load policy for cached Chio guard artifacts.

use std::path::PathBuf;

use serde::Serialize;

use crate::cache::{GuardCache, GuardCacheLayout};
use crate::oci::{GuardRegistryError, Sha256Digest};
use crate::verify::{
    GuardLoadEvent, GuardLoadEventResult, GuardLoadSource, GuardVerificationKind,
    GuardVerificationReport,
};

/// Result type for offline load policy decisions.
pub type GuardOfflineLoadResult<T> = std::result::Result<T, GuardOfflineLoadError>;

/// Network state visible to the guard load policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuardNetworkState {
    /// Registry/network path is reachable.
    Online,
    /// Registry/network path is unavailable and only cache reads are allowed.
    Offline,
}

impl GuardNetworkState {
    fn load_source(self) -> GuardLoadSource {
        match self {
            Self::Online => GuardLoadSource::Network,
            Self::Offline => GuardLoadSource::OfflineCache,
        }
    }
}

/// Inputs for evaluating a guard load against the offline policy.
#[derive(Debug, Clone, Copy)]
pub struct GuardOfflineLoadRequest<'a> {
    /// Content-addressed local cache.
    pub cache: &'a GuardCache,
    /// Pinned digest being loaded.
    pub digest: &'a Sha256Digest,
    /// Network state for this load attempt.
    pub network: GuardNetworkState,
    /// Verification mode expected for this load attempt.
    pub verification: GuardVerificationKind,
}

/// Successful fail-closed load decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardOfflineLoad {
    /// Pinned digest that was admitted.
    pub digest: Sha256Digest,
    /// Concrete cache layout used by the admitted load.
    pub layout: GuardCacheLayout,
    /// Structured allow event for this load.
    pub event: GuardLoadEvent,
    /// Verification report that allowed the load.
    pub verification: GuardVerificationReport,
}

/// Fail-closed offline load denials.
#[derive(Debug, thiserror::Error)]
pub enum GuardOfflineLoadError {
    /// Offline mode cannot fetch a missing artifact.
    #[error("guard offline load denied: cache entry {digest} is missing")]
    OfflineCacheMiss {
        /// Pinned digest requested by the load.
        digest: String,
        /// Missing cache files.
        missing: Vec<PathBuf>,
        /// Structured deny event for the load.
        event: Box<GuardLoadEvent>,
    },

    /// Online policy path was asked to load from an incomplete cache.
    #[error("guard network load denied: cache entry {digest} is incomplete")]
    OnlineCacheIncomplete {
        /// Pinned digest requested by the load.
        digest: String,
        /// Missing cache files.
        missing: Vec<PathBuf>,
        /// Structured deny event for the load.
        event: Box<GuardLoadEvent>,
    },

    /// Cache metadata could not be inspected and the load is denied.
    #[error("guard load denied: failed to inspect cache path {path}: {source}")]
    CacheStat {
        /// Cache path that could not be inspected.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
        /// Structured deny event for the load.
        event: Box<GuardLoadEvent>,
    },

    /// Network path reached verification but the signature failed.
    #[error("guard network load denied: signature verification failed: {source}")]
    NetworkSignatureDenied {
        /// Verification error returned by the signing mode.
        #[source]
        source: Box<GuardRegistryError>,
        /// Structured deny event for the load.
        event: Box<GuardLoadEvent>,
    },

    /// Offline cache path reached verification but the cached signature failed.
    #[error("guard offline load denied: cached signature verification failed: {source}")]
    CachedSignatureDenied {
        /// Verification error returned by the signing mode.
        #[source]
        source: Box<GuardRegistryError>,
        /// Structured deny event for the load.
        event: Box<GuardLoadEvent>,
    },
}

impl GuardOfflineLoadError {
    /// Structured deny event attached to this fail-closed decision.
    pub fn event(&self) -> &GuardLoadEvent {
        match self {
            Self::OfflineCacheMiss { event, .. }
            | Self::OnlineCacheIncomplete { event, .. }
            | Self::CacheStat { event, .. }
            | Self::NetworkSignatureDenied { event, .. }
            | Self::CachedSignatureDenied { event, .. } => event.as_ref(),
        }
    }
}

/// Load a cached guard only when cache presence and verification both pass.
///
/// This function does not perform network I/O. Online callers should fetch into
/// cache first, then call this policy gate. Offline callers get a deterministic
/// deny when the digest is not already complete in the local cache.
pub fn load_guard_with_policy<VerifyCached>(
    request: GuardOfflineLoadRequest<'_>,
    verify_cached: VerifyCached,
) -> GuardOfflineLoadResult<GuardOfflineLoad>
where
    VerifyCached: FnOnce(&GuardCacheLayout) -> Result<GuardVerificationReport, GuardRegistryError>,
{
    let layout = request.cache.layout(request.digest);
    let digest = request.digest.as_str().to_owned();
    let source = request.network.load_source();
    let missing = missing_cache_files(&layout, request, source)?;
    if !missing.is_empty() {
        let reason = match request.network {
            GuardNetworkState::Online => "online-cache-incomplete",
            GuardNetworkState::Offline => "offline-cache-miss",
        };
        let event = GuardLoadEvent::deny(request.verification, source, digest.clone(), reason);
        return match request.network {
            GuardNetworkState::Online => Err(GuardOfflineLoadError::OnlineCacheIncomplete {
                digest,
                missing,
                event: Box::new(event),
            }),
            GuardNetworkState::Offline => Err(GuardOfflineLoadError::OfflineCacheMiss {
                digest,
                missing,
                event: Box::new(event),
            }),
        };
    }

    match verify_cached(&layout) {
        Ok(report) => {
            let event = GuardLoadEvent::allow(report.kind, source, digest, &report.assertion);
            Ok(GuardOfflineLoad {
                digest: request.digest.clone(),
                layout,
                event,
                verification: report,
            })
        }
        Err(error) => {
            let event = GuardLoadEvent::deny(
                request.verification,
                source,
                digest,
                "signature-verification-failed",
            );
            match request.network {
                GuardNetworkState::Online => Err(GuardOfflineLoadError::NetworkSignatureDenied {
                    source: Box::new(error),
                    event: Box::new(event),
                }),
                GuardNetworkState::Offline => Err(GuardOfflineLoadError::CachedSignatureDenied {
                    source: Box::new(error),
                    event: Box::new(event),
                }),
            }
        }
    }
}

fn missing_cache_files(
    layout: &GuardCacheLayout,
    request: GuardOfflineLoadRequest<'_>,
    source: GuardLoadSource,
) -> GuardOfflineLoadResult<Vec<PathBuf>> {
    let mut missing = Vec::new();
    for path in layout.file_paths() {
        match path.try_exists() {
            Ok(true) => {}
            Ok(false) => missing.push(path),
            Err(source_error) => {
                return Err(GuardOfflineLoadError::CacheStat {
                    path,
                    source: source_error,
                    event: Box::new(GuardLoadEvent {
                        event: crate::verify::CHIO_GUARD_VERIFY_EVENT,
                        result: GuardLoadEventResult::Deny,
                        verification: request.verification,
                        source,
                        digest: request.digest.as_str().to_owned(),
                        subject_digest_sha256: None,
                        identity: None,
                        reason: Some("cache-stat-failed".to_owned()),
                    }),
                });
            }
        }
    }
    Ok(missing)
}
