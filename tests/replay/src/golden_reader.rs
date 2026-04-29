//! Golden reader for the M04 deterministic-replay gate.
//!
//! This module is the read-side counterpart of
//! [`crate::golden_writer`]. The writer (T3) produces three on-disk
//! artifacts per scenario; this module loads them back as RAW BYTES
//! so the byte-comparison harness in [`crate::byte_compare`] can
//! diff a candidate run against a golden snapshot without ever round-
//! tripping through `serde_json`. A serde round-trip would mask the
//! exact byte-level drift (whitespace, key order, line endings) that
//! T3 was carefully designed to lock down.
//!
//! # Naming
//!
//! T3's writer-side accumulator is also called `GoldenSet`. To avoid
//! a name collision in code that imports both modules, the loaded
//! representation here is named [`GoldenLoaded`]. Mnemonic: the
//! writer assembles a set; the reader hands back a loaded snapshot.
//!
//! # Validated invariants
//!
//! [`GoldenLoaded::load`] enforces every byte-stable contract that
//! [`crate::golden_writer::GoldenSet::commit`] promises, so a corrupt
//! or hand-edited goldens directory fails at load time rather than
//! producing a misleading "byte-identical" comparison later:
//!
//! - The scenario directory exists and contains `receipts.ndjson`,
//!   `checkpoint.json`, and `root.hex`.
//! - `root.hex` is exactly 64 bytes long, all lowercase hex digits,
//!   with no trailing newline. The 32-byte decoded form is also
//!   surfaced as [`GoldenLoaded::root_bytes`] for callers that want
//!   to recompute over raw bytes.
//! - `receipts.ndjson` ends with a single `0x0a` (LF) byte. The
//!   writer terminates every line, including the last; a missing
//!   final LF is a corruption signal.
//! - `checkpoint.json` is non-empty.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::golden_format::{
    CHECKPOINT_FILENAME, RECEIPTS_FILENAME, ROOT_FILENAME, ROOT_HEX_LEN, ROOT_LEN,
};

/// Errors produced while loading a goldens directory.
#[derive(Debug, Error)]
pub enum GoldenReaderError {
    /// An I/O operation against a goldens path failed (read or
    /// metadata). Note that "file not present" is reported as
    /// [`GoldenReaderError::MissingFile`] rather than a generic
    /// [`GoldenReaderError::Io`] so callers can distinguish "the
    /// goldens have not been blessed yet" from "the disk is broken".
    #[error("I/O error at {path}: {source}")]
    Io {
        /// Path that was being operated on.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// One of the expected goldens files (`receipts.ndjson`,
    /// `checkpoint.json`, `root.hex`) was not found.
    #[error("required goldens file is missing: {0}")]
    MissingFile(PathBuf),

    /// `root.hex` did not have the exact byte length the writer
    /// promises. The full file content is included so the operator
    /// can see whether a stray newline crept in (`actual_len == 65`)
    /// or whether the file was hand-edited entirely.
    #[error("root.hex must be exactly {expected_len} bytes, got {actual_len}: {content:?}")]
    RootHexInvalid {
        /// The contractually required length (always 64).
        expected_len: usize,
        /// The actual on-disk length.
        actual_len: usize,
        /// The raw on-disk content for diagnostics.
        content: String,
    },

    /// `root.hex` had the right length but contained non-lowercase
    /// or non-hex characters. The writer always emits lowercase, so
    /// any deviation is corruption.
    #[error("root.hex must be lowercase hex only, got {0:?}")]
    RootHexNotLowercase(String),

    /// `root.hex` failed to decode as 32 raw bytes.
    #[error("root.hex failed to decode as 32 bytes: {0}")]
    RootHexDecode(#[from] hex::FromHexError),

    /// `receipts.ndjson` did not end with exactly one `0x0a` (LF)
    /// terminator. The writer always terminates the final line with
    /// a single LF; an empty file or a file ending with a blank
    /// line (`\n\n`) is corruption.
    #[error("receipts.ndjson must end with a single LF terminator")]
    ReceiptsMissingTerminator,

    /// `checkpoint.json` was empty. The writer never produces a
    /// zero-byte checkpoint.
    #[error("checkpoint.json must not be empty")]
    EmptyCheckpoint,
}

/// A scenario's goldens loaded from disk as raw bytes.
///
/// All three artifacts are kept verbatim, not re-encoded, so the
/// byte-comparison harness can diff candidate output against the
/// stored bytes directly. The decoded `root_bytes` field is offered
/// as a convenience alongside the raw `root_hex`; callers that want
/// to verify "the hex on disk is the bytes I just computed" can use
/// either form.
#[derive(Debug, Clone)]
pub struct GoldenLoaded {
    /// Directory the goldens were loaded from.
    pub dir: PathBuf,
    /// Raw bytes of `receipts.ndjson` (LF-terminated, including the
    /// final line).
    pub receipts: Vec<u8>,
    /// Raw bytes of `checkpoint.json` (canonical JSON, no trailing
    /// whitespace).
    pub checkpoint: Vec<u8>,
    /// Raw lowercase-hex string from `root.hex` (exactly 64 chars,
    /// no trailing newline).
    pub root_hex: String,
    /// Decoded 32-byte Merkle root.
    pub root_bytes: [u8; ROOT_LEN],
}

impl GoldenLoaded {
    /// Load a scenario's goldens from `scenario_dir`.
    ///
    /// All bytes are read verbatim; no JSON parsing happens here.
    /// On any contract violation the function returns an error
    /// without populating the other fields, so callers can rely on
    /// "Ok means every invariant holds".
    pub fn load(scenario_dir: impl AsRef<Path>) -> Result<Self, GoldenReaderError> {
        let dir = scenario_dir.as_ref().to_path_buf();

        let receipts_path = dir.join(RECEIPTS_FILENAME);
        let checkpoint_path = dir.join(CHECKPOINT_FILENAME);
        let root_path = dir.join(ROOT_FILENAME);

        let receipts = read_required(&receipts_path)?;
        let checkpoint = read_required(&checkpoint_path)?;
        let root_raw = read_required(&root_path)?;

        // root.hex contract: exactly 64 bytes, lowercase hex, no
        // trailing newline. Validate length first so the diagnostic
        // captures the actual byte count when (e.g.) someone
        // appended a stray '\n'.
        if root_raw.len() != ROOT_HEX_LEN {
            return Err(GoldenReaderError::RootHexInvalid {
                expected_len: ROOT_HEX_LEN,
                actual_len: root_raw.len(),
                content: String::from_utf8_lossy(&root_raw).into_owned(),
            });
        }
        let root_hex = match String::from_utf8(root_raw.clone()) {
            Ok(s) => s,
            Err(_) => {
                return Err(GoldenReaderError::RootHexInvalid {
                    expected_len: ROOT_HEX_LEN,
                    actual_len: root_raw.len(),
                    content: String::from_utf8_lossy(&root_raw).into_owned(),
                });
            }
        };
        if !root_hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
            return Err(GoldenReaderError::RootHexNotLowercase(root_hex));
        }
        let root_bytes_vec = hex::decode(&root_hex)?;
        if root_bytes_vec.len() != ROOT_LEN {
            // Defensive: hex::decode of a 64-char input always
            // yields 32 bytes, but if that ever drifts we want to
            // fail closed rather than panic on the array conversion.
            return Err(GoldenReaderError::RootHexInvalid {
                expected_len: ROOT_HEX_LEN,
                actual_len: root_raw.len(),
                content: root_hex,
            });
        }
        let mut root_bytes = [0u8; ROOT_LEN];
        root_bytes.copy_from_slice(&root_bytes_vec);

        // receipts.ndjson contract: file must end with EXACTLY one
        // `0x0a` (LF). An empty file fails the check (writer's
        // `EmptyReceipts` invariant), as does a file that ends with a
        // blank line `...\n\n` (corruption). The penultimate-byte
        // check guards against the latter so the reader fails
        // closed when an editor or buggy concatenation appends a
        // stray LF after the final receipt.
        match receipts.last() {
            Some(&b'\n') => {
                if receipts.len() >= 2 && receipts[receipts.len() - 2] == b'\n' {
                    return Err(GoldenReaderError::ReceiptsMissingTerminator);
                }
            }
            _ => return Err(GoldenReaderError::ReceiptsMissingTerminator),
        }

        // checkpoint.json contract: non-empty (writer never produces
        // a zero-byte checkpoint).
        if checkpoint.is_empty() {
            return Err(GoldenReaderError::EmptyCheckpoint);
        }

        Ok(Self {
            dir,
            receipts,
            checkpoint,
            root_hex,
            root_bytes,
        })
    }
}

/// Read a goldens file as raw bytes, mapping "not found" into
/// [`GoldenReaderError::MissingFile`] and any other I/O failure into
/// [`GoldenReaderError::Io`].
fn read_required(path: &Path) -> Result<Vec<u8>, GoldenReaderError> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            Err(GoldenReaderError::MissingFile(path.to_path_buf()))
        }
        Err(source) => Err(GoldenReaderError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the golden reader. The round-trip test drives
    //! the writer end-to-end and then loads the result back; the
    //! negative tests hand-craft on-disk corruption to lock in each
    //! byte-stable contract that the writer promises.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::golden_writer::GoldenSet;
    use serde_json::json;
    use tempfile::TempDir;

    fn make_dir() -> TempDir {
        TempDir::new().expect("tempdir must succeed in tests")
    }

    /// Bless a scenario via the writer and return its directory.
    fn write_scenario(dir: &Path, root: [u8; 32]) {
        let mut set = GoldenSet::new(dir);
        set.append_receipt(&json!({"a": 1, "b": 2}))
            .expect("append must succeed");
        set.append_receipt(&json!({"id": 7, "kind": "allow"}))
            .expect("append must succeed");
        set.set_checkpoint(&json!({"height": 1, "root": "deadbeef"}))
            .expect("set_checkpoint must succeed");
        set.set_root(root);
        set.commit().expect("commit must succeed");
    }

    #[test]
    fn load_round_trips_against_golden_writer() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_round_trip");
        let mut root = [0u8; 32];
        for (i, byte) in root.iter_mut().enumerate() {
            *byte = i as u8;
        }
        write_scenario(&dir, root);

        let loaded = GoldenLoaded::load(&dir).expect("load must succeed");

        assert_eq!(loaded.dir, dir);
        // receipts must round-trip byte-for-byte.
        let on_disk_receipts = fs::read(dir.join(RECEIPTS_FILENAME)).unwrap();
        assert_eq!(loaded.receipts, on_disk_receipts);
        // checkpoint must round-trip byte-for-byte.
        let on_disk_checkpoint = fs::read(dir.join(CHECKPOINT_FILENAME)).unwrap();
        assert_eq!(loaded.checkpoint, on_disk_checkpoint);
        // root.hex must match the writer-known encoding for an
        // identity-byte root (00..1f).
        assert_eq!(
            loaded.root_hex,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
        assert_eq!(loaded.root_bytes, root);
    }

    #[test]
    fn load_rejects_missing_dir() {
        let tmp = make_dir();
        let dir = tmp.path().join("does_not_exist");
        let err = GoldenLoaded::load(&dir).expect_err("load must fail for missing dir");
        // Implementation reports the first missing artifact path
        // (receipts.ndjson) as MissingFile, since `read_required`
        // maps NotFound into MissingFile uniformly.
        match err {
            GoldenReaderError::MissingFile(path) => {
                assert_eq!(path, dir.join(RECEIPTS_FILENAME));
            }
            other => panic!("expected MissingFile, got {other:?}"),
        }
    }

    #[test]
    fn load_rejects_root_hex_with_trailing_newline() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_root_hex_trailing_lf");
        write_scenario(&dir, [0u8; 32]);

        // Re-write root.hex with a stray trailing newline. The
        // writer never produces this, so load must reject it.
        let root_path = dir.join(ROOT_FILENAME);
        let mut bytes = fs::read(&root_path).unwrap();
        bytes.push(b'\n');
        fs::write(&root_path, &bytes).unwrap();
        assert_eq!(bytes.len(), 65);

        let err = GoldenLoaded::load(&dir).expect_err("load must fail with trailing LF");
        match err {
            GoldenReaderError::RootHexInvalid {
                expected_len,
                actual_len,
                ..
            } => {
                assert_eq!(expected_len, 64);
                assert_eq!(actual_len, 65);
            }
            other => panic!("expected RootHexInvalid, got {other:?}"),
        }
    }

    #[test]
    fn load_rejects_uppercase_root_hex() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_root_hex_uppercase");
        write_scenario(&dir, [0xABu8; 32]);

        // Replace root.hex with an all-uppercase version of the
        // same root. Length stays at 64, but lowercase contract is
        // violated.
        let root_path = dir.join(ROOT_FILENAME);
        let body = fs::read_to_string(&root_path).unwrap();
        let upper = body.to_ascii_uppercase();
        assert_eq!(upper.len(), 64);
        fs::write(&root_path, upper.as_bytes()).unwrap();

        let err = GoldenLoaded::load(&dir).expect_err("load must fail for uppercase hex");
        match err {
            GoldenReaderError::RootHexNotLowercase(content) => {
                assert_eq!(content.len(), 64);
                assert!(content
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
            }
            other => panic!("expected RootHexNotLowercase, got {other:?}"),
        }
    }

    #[test]
    fn load_rejects_receipts_with_double_lf_terminator() {
        // The writer terminates each line with a single LF and never
        // emits a trailing blank line. A file ending with `...\n\n`
        // is corruption; the reader must fail-closed instead of
        // silently accepting the malformed golden.
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_receipts_double_lf");
        write_scenario(&dir, [4u8; 32]);

        let receipts_path = dir.join(RECEIPTS_FILENAME);
        let mut bytes = fs::read(&receipts_path).unwrap();
        assert_eq!(*bytes.last().unwrap(), b'\n');
        bytes.push(b'\n'); // produces a trailing blank line.
        fs::write(&receipts_path, &bytes).unwrap();

        let err = GoldenLoaded::load(&dir).expect_err("load must fail with trailing blank line");
        assert!(matches!(err, GoldenReaderError::ReceiptsMissingTerminator));
    }

    #[test]
    fn load_rejects_receipts_without_lf_terminator() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_receipts_no_lf");
        write_scenario(&dir, [1u8; 32]);

        // Strip the trailing LF from receipts.ndjson.
        let receipts_path = dir.join(RECEIPTS_FILENAME);
        let mut bytes = fs::read(&receipts_path).unwrap();
        assert_eq!(*bytes.last().unwrap(), b'\n');
        bytes.pop();
        fs::write(&receipts_path, &bytes).unwrap();

        let err = GoldenLoaded::load(&dir).expect_err("load must fail without LF terminator");
        assert!(matches!(err, GoldenReaderError::ReceiptsMissingTerminator));
    }

    #[test]
    fn load_rejects_empty_checkpoint() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_empty_checkpoint");
        write_scenario(&dir, [2u8; 32]);

        let checkpoint_path = dir.join(CHECKPOINT_FILENAME);
        fs::write(&checkpoint_path, b"").unwrap();

        let err = GoldenLoaded::load(&dir).expect_err("load must fail for empty checkpoint");
        assert!(matches!(err, GoldenReaderError::EmptyCheckpoint));
    }

    #[test]
    fn root_bytes_decoded_matches_root_hex() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_root_decode");
        let mut root = [0u8; 32];
        for (i, byte) in root.iter_mut().enumerate() {
            // Use a non-trivial pattern so a buggy decoder cannot
            // accidentally match identity bytes.
            *byte = (i as u8).wrapping_mul(13).wrapping_add(7);
        }
        write_scenario(&dir, root);

        let loaded = GoldenLoaded::load(&dir).expect("load must succeed");
        assert_eq!(hex::encode(loaded.root_bytes), loaded.root_hex);
        assert_eq!(loaded.root_bytes, root);
    }

    #[test]
    fn load_rejects_missing_receipts_file_only() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_missing_receipts");
        write_scenario(&dir, [3u8; 32]);

        fs::remove_file(dir.join(RECEIPTS_FILENAME)).unwrap();

        let err = GoldenLoaded::load(&dir).expect_err("load must fail when receipts is missing");
        match err {
            GoldenReaderError::MissingFile(path) => {
                assert_eq!(path, dir.join(RECEIPTS_FILENAME));
            }
            other => panic!("expected MissingFile, got {other:?}"),
        }
    }
}
