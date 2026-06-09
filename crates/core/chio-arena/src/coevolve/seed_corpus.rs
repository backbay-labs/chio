//! Seed-corpus loader.
//!
//! The co-evolution loop seeds its initial population from two sources:
//!
//!   1. Fuzz crash artifacts under `fuzz/artifacts/` (primary). The
//!      directory does not exist on every checkout (libFuzzer only
//!      writes there when it surfaces a crash); the loader returns an
//!      empty list when the directory is absent and records that fact in
//!      [`SeedCorpus::missing_sources`] rather than failing.
//!   2. Replay-attack and tampered-signature fixture families under
//!      `tests/replay/fixtures/replay_attack/` and
//!      `tests/replay/fixtures/tampered_signature/` (secondary). These
//!      are always present on a clean checkout; missing files are
//!      reported the same way as the primary source.
//!
//! Each artifact is recorded as `(path, sha256)` so a rotated corpus
//! surfaces as a manifest hash mismatch in the driver's run record
//! rather than a silent no-op (guarding against adversary-class drift
//! from the fuzz seed corpus).
//!
//! Determinism contract: artifacts are returned sorted lexicographically
//! by path. The loader uses `std::fs::read_dir` and sorts the entries
//! before reading their bytes; the iteration order of the underlying
//! filesystem is therefore irrelevant. SHA-256 is computed via the
//! workspace `chio_core::crypto::sha256_hex` helper for parity with the
//! arena bundle writer.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use chio_core::crypto::sha256_hex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default relative paths for the fuzz artefact source and the
/// replay-attack and tampered-signature families. Callers can override
/// either with [`SeedCorpusSources::with_fuzz_artifacts`] etc.
pub const DEFAULT_FUZZ_ARTIFACTS_DIR: &str = "fuzz/artifacts";
/// Default replay-attack family directory.
pub const DEFAULT_REPLAY_ATTACK_DIR: &str = "tests/replay/fixtures/replay_attack";
/// Default tampered-signature family directory.
pub const DEFAULT_TAMPERED_SIGNATURE_DIR: &str = "tests/replay/fixtures/tampered_signature";

/// Sources searched by the seed corpus loader. Callers (typically the
/// driver) construct the sources with [`SeedCorpusSources::default`] and
/// pass them to [`load_seed_corpus`].
#[derive(Debug, Clone)]
pub struct SeedCorpusSources {
    /// Fuzz crash artifacts (primary source).
    pub fuzz_artifacts: PathBuf,
    /// Replay-attack family.
    pub replay_attack: PathBuf,
    /// Tampered-signature family.
    pub tampered_signature: PathBuf,
}

impl SeedCorpusSources {
    /// Build sources rooted at `root`. The relative paths follow the
    /// canonical defaults documented at the top of this module.
    pub fn rooted_at(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        Self {
            fuzz_artifacts: root.join(DEFAULT_FUZZ_ARTIFACTS_DIR),
            replay_attack: root.join(DEFAULT_REPLAY_ATTACK_DIR),
            tampered_signature: root.join(DEFAULT_TAMPERED_SIGNATURE_DIR),
        }
    }

    /// Override the fuzz-artifacts path.
    pub fn with_fuzz_artifacts(mut self, path: impl AsRef<Path>) -> Self {
        self.fuzz_artifacts = path.as_ref().to_path_buf();
        self
    }

    /// Override the replay-attack path.
    pub fn with_replay_attack(mut self, path: impl AsRef<Path>) -> Self {
        self.replay_attack = path.as_ref().to_path_buf();
        self
    }

    /// Override the tampered-signature path.
    pub fn with_tampered_signature(mut self, path: impl AsRef<Path>) -> Self {
        self.tampered_signature = path.as_ref().to_path_buf();
        self
    }
}

impl Default for SeedCorpusSources {
    fn default() -> Self {
        Self::rooted_at(".")
    }
}

/// One seed-corpus artifact: the originating relative path plus the
/// SHA-256 hash of its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedArtifact {
    /// Path that produced the artifact. Always absolute (or workspace-
    /// relative if the loader was rooted at a relative directory) so the
    /// manifest can be rehydrated later.
    pub path: PathBuf,
    /// Stable identifier for the originating family
    /// (`fuzz_artifacts`, `replay_attack`, `tampered_signature`).
    pub family: String,
    /// SHA-256 of the artifact's raw bytes.
    pub sha256: String,
    /// Size in bytes (informational; helps surface rotated corpora).
    pub size_bytes: u64,
}

/// Result of a seed-corpus load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedCorpus {
    /// All artifacts found, sorted lexicographically by path.
    pub artifacts: Vec<SeedArtifact>,
    /// Sources that were missing on this checkout. Empty when every
    /// source resolved to an existing directory.
    pub missing_sources: Vec<String>,
}

impl SeedCorpus {
    /// Total artifact count across all families.
    pub fn len(&self) -> usize {
        self.artifacts.len()
    }

    /// Whether the corpus is empty.
    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty()
    }

    /// Aggregate SHA-256 of every artifact hash and missing-source label,
    /// in order. Used by the driver to record a single corpus-shape
    /// fingerprint in the run manifest; rotation surfaces as a
    /// fingerprint mismatch (whether the rotation deletes an artifact,
    /// renames one, or marks a previously-present source as missing).
    pub fn fingerprint_hex(&self) -> String {
        let mut buffer = Vec::with_capacity(self.artifacts.len() * 65);
        for artifact in &self.artifacts {
            buffer.extend_from_slice(artifact.sha256.as_bytes());
            buffer.push(b'\n');
        }
        buffer.extend_from_slice(b"--missing--\n");
        for label in &self.missing_sources {
            buffer.extend_from_slice(label.as_bytes());
            buffer.push(b'\n');
        }
        sha256_hex(&buffer)
    }
}

/// Errors raised by the seed-corpus loader.
#[derive(Debug, Error)]
pub enum SeedCorpusError {
    /// I/O failure while reading an artifact.
    #[error("I/O error reading {path}: {source}")]
    Io {
        /// Offending path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
}

/// Load every artifact from the configured sources. Missing source
/// directories are recorded in [`SeedCorpus::missing_sources`] and do not
/// fail the load.
pub fn load_seed_corpus(sources: &SeedCorpusSources) -> Result<SeedCorpus, SeedCorpusError> {
    let mut artifacts = Vec::new();
    let mut missing = Vec::new();

    for (family, path) in [
        ("fuzz_artifacts", sources.fuzz_artifacts.as_path()),
        ("replay_attack", sources.replay_attack.as_path()),
        ("tampered_signature", sources.tampered_signature.as_path()),
    ] {
        if !path.exists() {
            missing.push(family.to_string());
            continue;
        }
        load_directory(family, path, &mut artifacts)?;
    }

    artifacts.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(SeedCorpus {
        artifacts,
        missing_sources: missing,
    })
}

fn load_directory(
    family: &str,
    dir: &Path,
    out: &mut Vec<SeedArtifact>,
) -> Result<(), SeedCorpusError> {
    let read = fs::read_dir(dir).map_err(|source| SeedCorpusError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let mut entries: Vec<PathBuf> = Vec::new();
    for entry in read {
        let entry = entry.map_err(|source| SeedCorpusError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let metadata = entry.metadata().map_err(|source| SeedCorpusError::Io {
            path: path.clone(),
            source,
        })?;
        if !metadata.is_file() {
            continue;
        }
        entries.push(path);
    }
    entries.sort();
    for path in entries {
        let bytes = fs::read(&path).map_err(|source| SeedCorpusError::Io {
            path: path.clone(),
            source,
        })?;
        let size_bytes = bytes.len() as u64;
        let sha256 = sha256_hex(&bytes);
        out.push(SeedArtifact {
            path,
            family: family.to_string(),
            sha256,
            size_bytes,
        });
    }
    Ok(())
}
