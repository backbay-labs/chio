//! Peer-binary discovery and lockfile parsing.
//!
//! External implementers cannot rely on having Python, Node.js, Go, or C++
//! toolchains available locally to build the conformance peer adapters. The
//! `chio conformance fetch-peers` subcommand downloads pre-built binaries
//! whose URLs and integrity digests are pinned in
//! `crates/chio-conformance/peers.lock.toml`.
//!
//! This module owns the parsing and validation of that lockfile. Actual
//! download / extraction lives in the CLI handler so that this crate stays
//! free of network code paths during unit tests.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Schema identifier for the v1 peers lockfile.
pub const PEERS_LOCK_SCHEMA: &str = "chio.conformance.peers/v1";

/// Filename used for the bundled lockfile when published or installed.
pub const PEERS_LOCK_FILENAME: &str = "peers.lock.toml";

/// Recognised peer-language identifiers. New languages must be added here
/// and to the conformance harness in lock-step.
pub const SUPPORTED_LANGUAGES: &[&str] = &["python", "js", "go", "cpp"];

/// Parsed representation of `peers.lock.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct PeersLock {
    /// Schema discriminator. MUST equal `chio.conformance.peers/v1`.
    pub schema: String,
    /// Pinned peer-binary entries.
    #[serde(default, rename = "peer")]
    pub peers: Vec<PeerEntry>,
}

/// A single pinned peer-binary release artifact.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerEntry {
    /// Language adapter identifier (one of `SUPPORTED_LANGUAGES`).
    pub language: String,
    /// Fully-qualified https URL of the release artifact.
    pub url: String,
    /// 64-character lowercase hex sha256 of the artifact bytes.
    pub sha256: String,
    /// Rust target triple the binary was built for.
    pub target: String,
    /// Executable name inside the archive.
    pub binary: String,
    /// Whether this entry has been published with a real sha256 pin and a
    /// reachable url. Defaults to `true` so historical entries do not need
    /// to be edited; placeholder entries MUST set `published = false`.
    /// `chio conformance fetch-peers` SKIPS entries with
    /// `published = false` rather than failing them with a sha256
    /// mismatch. See cleanup C5 issue D for the gating contract.
    #[serde(default = "default_published")]
    pub published: bool,
}

fn default_published() -> bool {
    true
}

/// Errors surfaced when loading or validating `peers.lock.toml`.
#[derive(Debug, thiserror::Error)]
pub enum PeersLockError {
    /// Filesystem failure reading the lockfile.
    #[error("i/o error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Lockfile bytes are not valid TOML matching the v1 schema.
    #[error("toml parse error in {path}: {source}")]
    Toml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    /// Lockfile parsed but failed schema validation (see `PeersLock::validate`).
    #[error("invalid peers.lock.toml: {0}")]
    Validation(String),
}

impl PeersLock {
    /// Parse `peers.lock.toml` from disk. Does NOT validate; call
    /// `PeersLock::validate` after loading to enforce schema invariants.
    pub fn load(path: &Path) -> Result<Self, PeersLockError> {
        let bytes = fs::read_to_string(path).map_err(|source| PeersLockError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse_str(&bytes).map_err(|source| match source {
            PeersLockError::Toml { source, .. } => PeersLockError::Toml {
                path: path.to_path_buf(),
                source,
            },
            other => other,
        })
    }

    /// Parse `peers.lock.toml` from an in-memory string. Named `parse_str`
    /// rather than `from_str` to avoid colliding with `std::str::FromStr`.
    pub fn parse_str(content: &str) -> Result<Self, PeersLockError> {
        toml::from_str::<PeersLock>(content).map_err(|source| PeersLockError::Toml {
            path: PathBuf::from("<memory>"),
            source,
        })
    }

    /// Validate the parsed lockfile:
    /// - schema MUST equal `chio.conformance.peers/v1`,
    /// - every `url` MUST be https,
    /// - every `sha256` MUST be 64 chars of lowercase hex,
    /// - every `language` MUST appear in `SUPPORTED_LANGUAGES`,
    /// - `target` and `binary` MUST be non-empty.
    pub fn validate(&self) -> Result<(), PeersLockError> {
        if self.schema != PEERS_LOCK_SCHEMA {
            return Err(PeersLockError::Validation(format!(
                "unexpected schema `{}`, expected `{}`",
                self.schema, PEERS_LOCK_SCHEMA
            )));
        }
        if self.peers.is_empty() {
            return Err(PeersLockError::Validation(
                "lockfile has no [[peer]] entries".to_string(),
            ));
        }
        for (idx, entry) in self.peers.iter().enumerate() {
            entry
                .validate()
                .map_err(|message| PeersLockError::Validation(format!("peer[{idx}]: {message}")))?;
        }
        Ok(())
    }

    /// Filter entries by language and target triple. Both filters are
    /// case-sensitive; pass an empty string to skip a filter.
    pub fn entries_for(&self, language: &str, target: &str) -> Vec<&PeerEntry> {
        self.peers
            .iter()
            .filter(|entry| language.is_empty() || entry.language == language)
            .filter(|entry| target.is_empty() || entry.target == target)
            .collect()
    }

    /// Filter entries by language only.
    pub fn entries_for_language(&self, language: &str) -> Vec<&PeerEntry> {
        self.entries_for(language, "")
    }

    /// Partition entries into `(published, skipped)` based on the
    /// `published` flag. Cleanup C5 issue D: placeholder entries with
    /// all-zeros / all-ones sha256 pins must SKIP rather than fail
    /// `fetch-peers`; the partition lets the caller print a friendly
    /// "skipping unpublished entry" line per skipped row.
    pub fn partition_by_published<'a>(
        entries: &[&'a PeerEntry],
    ) -> (Vec<&'a PeerEntry>, Vec<&'a PeerEntry>) {
        let mut published = Vec::new();
        let mut skipped = Vec::new();
        for entry in entries {
            if entry.published {
                published.push(*entry);
            } else {
                skipped.push(*entry);
            }
        }
        (published, skipped)
    }
}

impl PeerEntry {
    fn validate(&self) -> Result<(), String> {
        if !SUPPORTED_LANGUAGES.contains(&self.language.as_str()) {
            return Err(format!(
                "unsupported language `{}`; expected one of {:?}",
                self.language, SUPPORTED_LANGUAGES,
            ));
        }
        if !self.url.starts_with("https://") {
            return Err(format!("url `{}` is not https", self.url));
        }
        if !is_lowercase_hex_64(&self.sha256) {
            return Err(format!(
                "sha256 `{}` is not 64 lowercase hex chars",
                self.sha256
            ));
        }
        if self.target.trim().is_empty() {
            return Err("target must be non-empty".to_string());
        }
        if self.binary.trim().is_empty() {
            return Err("binary must be non-empty".to_string());
        }
        Ok(())
    }
}

fn is_lowercase_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch))
}

/// Resolve the default `peers.lock.toml` path at runtime.
///
/// External consumers obtain `chio` via `cargo install chio-cli` (or build
/// the chio-conformance crate). The compile-time `CARGO_MANIFEST_DIR` of
/// either crate is gone after install, so this helper consults a layered
/// list of candidates so the caller does not have to pass `--lockfile`
/// for the common cases. Order:
///
/// 1. `$CHIO_PEERS_LOCK` (explicit override; honoured first so CI and
///    sandboxes can pin a vendored copy).
/// 2. `$XDG_CONFIG_HOME/chio/peers.lock.toml` (XDG default).
/// 3. `$HOME/.config/chio/peers.lock.toml` (XDG fallback).
/// 4. `<repo-root>/crates/chio-conformance/peers.lock.toml` (in-repo
///    default for `cargo run` from a fresh checkout).
/// 5. `./peers.lock.toml` (cwd-relative; useful for sandboxed CI).
///
/// Returns the first candidate that exists. When none exist this returns
/// the in-repo default (candidate 4) so the error message points users at
/// the canonical path.
#[must_use]
pub fn default_peers_lock_path() -> PathBuf {
    if let Some(path) = std::env::var_os("CHIO_PEERS_LOCK") {
        return PathBuf::from(path);
    }

    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        let candidate = PathBuf::from(xdg).join("chio").join(PEERS_LOCK_FILENAME);
        if candidate.exists() {
            return candidate;
        }
    }

    if let Some(home) = std::env::var_os("HOME") {
        let candidate = PathBuf::from(home)
            .join(".config")
            .join("chio")
            .join(PEERS_LOCK_FILENAME);
        if candidate.exists() {
            return candidate;
        }
    }

    let in_repo = in_repo_default_lock_path();
    if in_repo.exists() {
        return in_repo;
    }

    let cwd = PathBuf::from(PEERS_LOCK_FILENAME);
    if cwd.exists() {
        return cwd;
    }

    in_repo
}

/// In-repo default. Resolved relative to the chio-conformance crate at
/// compile time; only useful when the binary still has the workspace
/// checkout next to it (i.e. `cargo run --bin chio` from the repo).
fn in_repo_default_lock_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PEERS_LOCK_FILENAME)
}

/// Compute the lowercase hex sha256 digest of `bytes`. Used by the CLI
/// download path to verify integrity after fetching a release artifact.
///
/// Thin re-export of [`chio_core::sha256_hex`]; kept here for callers that
/// already imported `chio_conformance::sha256_hex`. Cleanup C5 issue E
/// removed the duplicate implementation.
pub fn sha256_hex(bytes: &[u8]) -> String {
    chio_core::sha256_hex(bytes)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const VALID: &str = r#"
schema = "chio.conformance.peers/v1"

[[peer]]
language = "python"
url = "https://example.com/py.tar.gz"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
target = "x86_64-unknown-linux-gnu"
binary = "chio-py-peer"

[[peer]]
language = "js"
url = "https://example.com/js.tar.gz"
sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
target = "aarch64-apple-darwin"
binary = "chio-js-peer"
"#;

    #[test]
    fn parses_valid_lockfile() {
        let lock = PeersLock::parse_str(VALID).expect("parse valid lockfile");
        assert_eq!(lock.schema, PEERS_LOCK_SCHEMA);
        assert_eq!(lock.peers.len(), 2);
        lock.validate().expect("valid lockfile passes validation");
    }

    #[test]
    fn rejects_wrong_schema() {
        let bad = VALID.replace("chio.conformance.peers/v1", "chio.conformance.peers/v2");
        let lock = PeersLock::parse_str(&bad).expect("still parses");
        let err = lock.validate().expect_err("wrong schema rejected");
        assert!(format!("{err}").contains("unexpected schema"));
    }

    #[test]
    fn rejects_non_https_url() {
        let bad = VALID.replace(
            "https://example.com/py.tar.gz",
            "http://example.com/py.tar.gz",
        );
        let lock = PeersLock::parse_str(&bad).expect("still parses");
        let err = lock.validate().expect_err("http rejected");
        assert!(format!("{err}").contains("not https"));
    }

    #[test]
    fn rejects_short_sha256() {
        let bad = VALID.replace(
            "0000000000000000000000000000000000000000000000000000000000000000",
            "deadbeef",
        );
        let lock = PeersLock::parse_str(&bad).expect("still parses");
        let err = lock.validate().expect_err("short sha256 rejected");
        assert!(format!("{err}").contains("64 lowercase hex"));
    }

    #[test]
    fn rejects_uppercase_sha256() {
        let bad = VALID.replace(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        );
        let lock = PeersLock::parse_str(&bad).expect("still parses");
        let err = lock.validate().expect_err("uppercase sha256 rejected");
        assert!(format!("{err}").contains("64 lowercase hex"));
    }

    #[test]
    fn rejects_unsupported_language() {
        let bad = VALID.replace(r#"language = "python""#, r#"language = "ruby""#);
        let lock = PeersLock::parse_str(&bad).expect("still parses");
        let err = lock.validate().expect_err("ruby rejected");
        assert!(format!("{err}").contains("unsupported language"));
    }

    #[test]
    fn rejects_empty_peer_list() {
        let bad = "schema = \"chio.conformance.peers/v1\"\n";
        let lock = PeersLock::parse_str(bad).expect("still parses");
        let err = lock.validate().expect_err("empty list rejected");
        assert!(format!("{err}").contains("no [[peer]] entries"));
    }

    #[test]
    fn entries_for_filters_by_language_and_target() {
        let lock = PeersLock::parse_str(VALID).expect("parse");
        let py_only = lock.entries_for_language("python");
        assert_eq!(py_only.len(), 1);
        assert_eq!(py_only[0].language, "python");

        let py_linux = lock.entries_for("python", "x86_64-unknown-linux-gnu");
        assert_eq!(py_linux.len(), 1);

        let py_darwin = lock.entries_for("python", "aarch64-apple-darwin");
        assert!(py_darwin.is_empty());

        let all = lock.entries_for("", "");
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn shipped_lockfile_validates() {
        // The lockfile shipped at crates/chio-conformance/peers.lock.toml is
        // the source of truth. This test prevents accidental schema drift.
        let manifest_dir =
            std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set during cargo test");
        let path = Path::new(&manifest_dir).join("peers.lock.toml");
        let lock = PeersLock::load(&path).expect("load shipped peers.lock.toml");
        lock.validate().expect("shipped lockfile validates");
        assert!(!lock.peers.is_empty());
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        // sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
    }

    #[test]
    fn published_defaults_to_true() {
        // Cleanup C5 issue D: omitting `published` keeps the historical
        // behaviour where every entry is treated as published.
        let lock = PeersLock::parse_str(VALID).expect("parse");
        assert!(lock.peers[0].published);
        assert!(lock.peers[1].published);
    }

    #[test]
    fn partition_by_published_separates_skipped_entries() {
        let raw = r#"
schema = "chio.conformance.peers/v1"

[[peer]]
language = "python"
url = "https://example.com/py.tar.gz"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
target = "x86_64-unknown-linux-gnu"
binary = "chio-py-peer"
published = false

[[peer]]
language = "js"
url = "https://example.com/js.tar.gz"
sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
target = "aarch64-apple-darwin"
binary = "chio-js-peer"
published = true
"#;
        let lock = PeersLock::parse_str(raw).expect("parse");
        let all = lock.entries_for("", "");
        let (published, skipped) = PeersLock::partition_by_published(&all);
        assert_eq!(published.len(), 1);
        assert_eq!(skipped.len(), 1);
        assert_eq!(published[0].language, "js");
        assert_eq!(skipped[0].language, "python");
    }

    #[test]
    fn shipped_lockfile_marks_placeholders_as_unpublished() {
        // The shipped lockfile carries placeholder sha256 pins, so every
        // entry MUST be flagged as unpublished until the release pipeline
        // fills in real values.
        let manifest_dir =
            std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set during cargo test");
        let path = Path::new(&manifest_dir).join("peers.lock.toml");
        let lock = PeersLock::load(&path).expect("load shipped peers.lock.toml");
        for (idx, entry) in lock.peers.iter().enumerate() {
            assert!(
                !entry.published,
                "shipped peer[{idx}] ({} / {}) is flagged published but the lockfile carries placeholder pins; flip published=true only when the release pipeline cuts a real binary",
                entry.language,
                entry.target,
            );
        }
    }
}
