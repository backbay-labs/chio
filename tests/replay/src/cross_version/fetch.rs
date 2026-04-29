//! Bundle fetch + sha256-pinned cache for tagged release artifacts.
//!
//! The cross-version harness re-verifies receipts produced by historical
//! tagged releases. Bundles named in `release_compat_matrix.toml` are
//! downloaded once over HTTPS, cached on disk under
//! `$CHIO_REPLAY_CACHE_DIR/<tag>/replay-bundle.tgz` (default:
//! `$HOME/.cache/chio/replay-bundles/<tag>/replay-bundle.tgz`), and pinned
//! against the matrix's `bundle_sha256` value.
//!
//! # Fail-closed contract
//!
//! 1. The pin in the matrix is the only sha source the cache trusts. A
//!    cache hit is only honoured if the on-disk bytes hash to exactly the
//!    pinned digest. A mismatched cached file is evicted, and the network
//!    fetch is retried.
//! 2. Network responses are also pinned: a download whose digest does not
//!    match the matrix is rejected with [`FetchError::ShaMismatch`] and
//!    NEVER written to disk. Subsequent calls re-fetch from scratch.
//! 3. HTTP errors (4xx/5xx) surface as [`FetchError::Network`] via
//!    `error_for_status`, so a corrupted CDN response cannot be silently
//!    accepted as the bundle.
//!
//! # Cache root resolution
//!
//! Resolution order, first match wins:
//! 1. `$CHIO_REPLAY_CACHE_DIR` if set (test hook + ops override).
//! 2. `$XDG_CACHE_HOME/chio/replay-bundles` if set.
//! 3. `$HOME/.cache/chio/replay-bundles` if `$HOME` is set.
//! 4. `./.chio-replay-bundles` (last-ditch fallback for headless CI without
//!    a HOME, e.g. some sandboxed runners).
//!
//! The harness deliberately avoids the `dirs` crate to keep `tests/replay`'s
//! transitive surface small.
//!
//! # Network access in tests
//!
//! Live-network tests are gated by `#[ignore]` so the default
//! `cargo test -p chio-replay-gate` run is hermetic. Run them explicitly
//! with:
//!
//! ```bash
//! cargo test -p chio-replay-gate --lib cross_version::fetch::fetch_tests -- --ignored
//! ```

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::CompatEntry;

/// Environment variable that overrides the cache root.
///
/// Honoured by [`cache_root`]. Used by tests (via `tempfile::TempDir`) and by
/// operators who need to redirect the cache to a specific volume.
pub const CACHE_ROOT_ENV: &str = "CHIO_REPLAY_CACHE_DIR";

/// XDG cache home environment variable (consulted after `CACHE_ROOT_ENV`).
const XDG_CACHE_HOME_ENV: &str = "XDG_CACHE_HOME";

/// Per-bundle file name inside `cache_root()/<tag>/`.
///
/// Held to a single name so cache layout is deterministic across releases.
pub const BUNDLE_FILE_NAME: &str = "replay-bundle.tgz";

/// Errors surfaced by [`fetch_or_cache`].
///
/// Underlying errors are flattened to `String` rather than carrying the
/// full `reqwest::Error` / `std::io::Error` types: the cache only ever
/// reports them, never recovers from them, and we want the public surface
/// of this test crate to stay free of transitive type leaks.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// HTTP/transport-level failure (DNS, TLS, non-2xx, body read).
    #[error("network error fetching {url:?}: {detail}")]
    Network {
        /// URL the harness was attempting to fetch.
        url: String,
        /// Stringified underlying error.
        detail: String,
    },
    /// File-system failure (cache mkdir, read, write, evict).
    #[error("io error at {path:?}: {detail}")]
    Io {
        /// Path the harness was attempting to touch.
        path: PathBuf,
        /// Stringified IO error.
        detail: String,
    },
    /// Bundle digest did not equal the matrix pin. Bytes are NOT cached.
    #[error("sha256 mismatch for {tag}: expected {expected}, got {actual}")]
    ShaMismatch {
        /// Release tag being fetched.
        tag: String,
        /// Pinned digest from the matrix file.
        expected: String,
        /// Digest of the bytes the network returned.
        actual: String,
    },
}

/// Result of a successful [`fetch_or_cache`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedBundle {
    /// Release tag the bundle is bound to (e.g. `"v0.1.0"`).
    pub tag: String,
    /// Absolute path to the cached bundle file.
    pub path: PathBuf,
    /// Lowercase-hex sha256 digest of the cached bytes. Always equal to
    /// the matrix pin on a successful return.
    pub sha256: String,
}

/// Resolve the cache root.
///
/// See module-level docs for the resolution order. This function is pure
/// (no I/O); the caller is responsible for `create_dir_all`.
#[must_use]
pub fn cache_root() -> PathBuf {
    if let Ok(p) = std::env::var(CACHE_ROOT_ENV) {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Ok(p) = std::env::var(XDG_CACHE_HOME_ENV) {
        if !p.is_empty() {
            return PathBuf::from(p).join("chio").join("replay-bundles");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home)
                .join(".cache")
                .join("chio")
                .join("replay-bundles");
        }
    }
    PathBuf::from(".chio-replay-bundles")
}

/// Path the bundle for `tag` would live at, under the current cache root.
///
/// Does not touch the file system. Pure helper for tests + diagnostics.
#[must_use]
pub fn bundle_path_for(tag: &str) -> PathBuf {
    cache_root().join(tag).join(BUNDLE_FILE_NAME)
}

/// Return the cached bundle path if it exists and the sha256 matches.
/// Otherwise, fetch over HTTPS and verify before caching.
///
/// # Errors
///
/// - [`FetchError::Io`] if the cache directory cannot be created or a
///   cached file cannot be read/evicted.
/// - [`FetchError::Network`] for any HTTP/transport-level failure.
/// - [`FetchError::ShaMismatch`] if the freshly-downloaded bytes do not
///   match the matrix pin. The bytes are NOT written to disk in this case.
pub fn fetch_or_cache(entry: &CompatEntry) -> Result<FetchedBundle, FetchError> {
    let dir = cache_root().join(&entry.tag);
    std::fs::create_dir_all(&dir).map_err(|e| FetchError::Io {
        path: dir.clone(),
        detail: e.to_string(),
    })?;
    let path = dir.join(BUNDLE_FILE_NAME);

    if path.exists() {
        let actual = sha256_of_file(&path)?;
        if actual == entry.bundle_sha256 {
            return Ok(FetchedBundle {
                tag: entry.tag.clone(),
                path,
                sha256: actual,
            });
        }
        // Cache poisoning or partial write: evict and re-fetch.
        std::fs::remove_file(&path).map_err(|e| FetchError::Io {
            path: path.clone(),
            detail: e.to_string(),
        })?;
    }

    let bytes = http_get(&entry.bundle_url)?;
    let actual = sha256_of_bytes(&bytes);
    if actual != entry.bundle_sha256 {
        return Err(FetchError::ShaMismatch {
            tag: entry.tag.clone(),
            expected: entry.bundle_sha256.clone(),
            actual,
        });
    }
    std::fs::write(&path, &bytes).map_err(|e| FetchError::Io {
        path: path.clone(),
        detail: e.to_string(),
    })?;
    Ok(FetchedBundle {
        tag: entry.tag.clone(),
        path,
        sha256: actual,
    })
}

/// Blocking HTTPS GET that surfaces 4xx/5xx as `FetchError::Network`.
///
/// Kept as a free function (rather than inline) so tests can reason about
/// network calls separately from cache + digest logic.
fn http_get(url: &str) -> Result<Vec<u8>, FetchError> {
    let response = reqwest::blocking::get(url).map_err(|e| FetchError::Network {
        url: url.to_string(),
        detail: e.to_string(),
    })?;
    let response = response
        .error_for_status()
        .map_err(|e| FetchError::Network {
            url: url.to_string(),
            detail: e.to_string(),
        })?;
    let bytes = response.bytes().map_err(|e| FetchError::Network {
        url: url.to_string(),
        detail: e.to_string(),
    })?;
    Ok(bytes.to_vec())
}

/// Hash the contents of `path` and return a lowercase-hex sha256 digest.
fn sha256_of_file(path: &Path) -> Result<String, FetchError> {
    let bytes = std::fs::read(path).map_err(|e| FetchError::Io {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;
    Ok(sha256_of_bytes(&bytes))
}

/// Hash `bytes` and return a lowercase-hex sha256 digest.
#[must_use]
pub fn sha256_of_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

#[cfg(test)]
mod fetch_tests {
    //! Unit tests for the cache layer. `unwrap`/`expect` are allowed in
    //! this module to match the established pattern in `loader_tests`,
    //! `driver::tests`, and `fs_iter::tests`.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::cross_version::CompatLevel;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serialises tests that mutate `CHIO_REPLAY_CACHE_DIR` /
    /// `XDG_CACHE_HOME` / `HOME` so they cannot interleave. `cargo test`
    /// runs tests on multiple threads by default; without this guard the
    /// env-var-dependent tests would flake.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Build a synthetic `CompatEntry` pinned to `sha`. The URL points at
    /// a non-routable test domain so accidental network hits would fail
    /// loudly rather than silently succeeding.
    fn pinned_entry(tag: &str, sha: &str) -> CompatEntry {
        CompatEntry {
            tag: tag.to_string(),
            released_at: "2025-01-01".to_string(),
            bundle_url: format!("https://example.invalid/{tag}.tgz"),
            bundle_sha256: sha.to_string(),
            compat: CompatLevel::Supported,
            supported_until: None,
            notes: String::new(),
        }
    }

    /// Set `CHIO_REPLAY_CACHE_DIR` to `dir` for the duration of the test.
    /// Returns the lock guard so the caller keeps it alive.
    fn lock_and_redirect(dir: &Path) -> std::sync::MutexGuard<'_, ()> {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: env writes are not thread-safe in general; ENV_LOCK
        // serialises this test module, and no other test in the crate
        // touches CHIO_REPLAY_CACHE_DIR.
        std::env::set_var(CACHE_ROOT_ENV, dir);
        guard
    }

    #[test]
    fn sha256_helper_matches_known_vector() {
        // NIST CAVS sha256 known-answer for the ASCII bytes "abc".
        let v = sha256_of_bytes(b"abc");
        assert_eq!(
            v,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_helper_handles_empty_input() {
        let v = sha256_of_bytes(b"");
        assert_eq!(
            v,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn cache_root_honours_env_override() {
        let td = TempDir::new().unwrap();
        let _g = lock_and_redirect(td.path());
        assert_eq!(cache_root(), td.path());
    }

    #[test]
    fn bundle_path_for_uses_tag_subdir() {
        let td = TempDir::new().unwrap();
        let _g = lock_and_redirect(td.path());
        let p = bundle_path_for("v1.2.3");
        assert_eq!(p, td.path().join("v1.2.3").join(BUNDLE_FILE_NAME));
    }

    #[test]
    fn cached_file_with_matching_sha_returns_immediately() {
        let td = TempDir::new().unwrap();
        let _g = lock_and_redirect(td.path());

        // Pre-populate the cache with bytes whose sha is known.
        let bytes = b"hello chio";
        let sha = sha256_of_bytes(bytes);
        let tag = "v0.0.1";
        let dir = td.path().join(tag);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(BUNDLE_FILE_NAME);
        std::fs::write(&path, bytes).unwrap();

        let entry = pinned_entry(tag, &sha);
        let got = fetch_or_cache(&entry).expect("cache hit must succeed");
        assert_eq!(got.tag, tag);
        assert_eq!(got.path, path);
        assert_eq!(got.sha256, sha);
        // File still present (we did not evict on a hit).
        assert!(path.exists());
    }

    #[test]
    fn cached_file_with_wrong_sha_is_evicted_and_network_failure_surfaces() {
        let td = TempDir::new().unwrap();
        let _g = lock_and_redirect(td.path());

        // Cache holds the wrong bytes.
        let cached_bytes = b"stale corruption";
        let tag = "v0.0.2";
        let dir = td.path().join(tag);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(BUNDLE_FILE_NAME);
        std::fs::write(&path, cached_bytes).unwrap();

        // Pin to a different sha so the cache must miss.
        let pinned_sha = sha256_of_bytes(b"the right bytes");
        let entry = pinned_entry(tag, &pinned_sha);

        // The URL is unreachable, so we expect a network error - but
        // critically, the bad cache file MUST have been evicted before
        // the network attempt.
        let err = fetch_or_cache(&entry).expect_err("must fail (cache poison + unreachable URL)");
        assert!(
            matches!(err, FetchError::Network { .. }),
            "expected Network error after eviction, got {err:?}"
        );
        assert!(
            !path.exists(),
            "stale cache file must be evicted before network fetch"
        );
    }

    #[test]
    fn missing_cache_triggers_network_attempt() {
        let td = TempDir::new().unwrap();
        let _g = lock_and_redirect(td.path());

        let entry = pinned_entry(
            "v0.0.3",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        // No prior cache file - call goes straight to network. example.invalid
        // never resolves, so we expect Network.
        let err = fetch_or_cache(&entry).expect_err("unreachable host must fail");
        assert!(
            matches!(err, FetchError::Network { .. }),
            "expected Network error for unreachable host, got {err:?}"
        );
        // Nothing was written.
        let path = td.path().join("v0.0.3").join(BUNDLE_FILE_NAME);
        assert!(
            !path.exists(),
            "no bundle file must be written when fetch fails"
        );
    }

    /// Live-network smoke test against a real HTTPS endpoint with a
    /// well-known sha256. Skipped by default (`#[ignore]`); run via
    /// `cargo test -p chio-replay-gate --lib cross_version::fetch::fetch_tests::live_fetch_against_real_url_is_pinned -- --ignored`.
    ///
    /// Pinned target: <https://www.rfc-editor.org/rfc/rfc8259.txt> (RFC 8259,
    /// the JSON spec). Stable, served over HTTPS, small payload. The pin
    /// will need updating if rfc-editor.org re-publishes the document.
    #[ignore]
    #[test]
    fn live_fetch_against_real_url_is_pinned() {
        let td = TempDir::new().unwrap();
        let _g = lock_and_redirect(td.path());

        // Sentinel pin (zeros). Expect ShaMismatch, which proves the
        // network path actually executed and the digest was checked.
        let entry = CompatEntry {
            tag: "v-live-fetch".to_string(),
            released_at: "2025-01-01".to_string(),
            bundle_url: "https://www.rfc-editor.org/rfc/rfc8259.txt".to_string(),
            bundle_sha256: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            compat: CompatLevel::Supported,
            supported_until: None,
            notes: String::new(),
        };
        let err = fetch_or_cache(&entry).expect_err("sentinel pin must reject");
        assert!(
            matches!(err, FetchError::ShaMismatch { .. }),
            "expected ShaMismatch, got {err:?}"
        );
        // No bytes written on mismatch.
        let path = td.path().join("v-live-fetch").join(BUNDLE_FILE_NAME);
        assert!(!path.exists(), "mismatched bytes must not be cached");
    }
}
