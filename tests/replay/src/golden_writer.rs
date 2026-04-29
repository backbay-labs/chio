//! Golden writer for the M04 deterministic-replay gate.
//!
//! Each replay-gate scenario produces three on-disk artifacts under
//! `tests/replay/goldens/<family>/<name>/`:
//!
//! - `receipts.ndjson`: one canonical-JSON object per line, newline
//!   (`0x0a`) terminated, including the final line. NDJSON keeps the
//!   M10 tee streams byte-compatible with the goldens.
//! - `checkpoint.json`: a single canonical-JSON object describing the
//!   scenario's anchor checkpoint. No leading or trailing whitespace.
//! - `root.hex`: the 32-byte Merkle root encoded as exactly 64
//!   lowercase hex characters with no trailing newline. Raw hex makes
//!   diffs human-readable while keeping byte-stable behaviour.
//!
//! The output of this writer is the ground-truth golden bytes for the
//! replay gate, so determinism is the load-bearing guarantee. Every
//! JSON object that flows through [`GoldenSet::append_receipt`] or
//! [`GoldenSet::set_checkpoint`] is reshaped through
//! [`chio_core_types::canonical::canonicalize`] (RFC 8785 / JCS:
//! recursively sorts object keys by UTF-16 code unit, preserves array
//! order, emits no insignificant whitespace) before being written to
//! disk. The same canonicaliser is used by the workspace-wide signing
//! surface, so the replay-gate goldens stay byte-stable across
//! `serde_json` upgrades.
//!
//! Writes are staged into `<file>.tmp` siblings, fsynced, then renamed
//! into place on commit. On any per-file failure all already-staged
//! `.tmp` siblings are cleaned up so a half-written goldens directory
//! is never observable. The rename step is the per-file commit point;
//! the multi-file commit is therefore "best effort atomic": each rename
//! is itself atomic on POSIX filesystems but the three renames are not
//! one transaction. The writer documents that and cleans up `.tmp`
//! files on any failure to keep the partial state inspectable but
//! never mistakable for a successful bless.
//!
//! T3 lands the writer only. T4 will add the byte-comparison reader
//! that consumes these files as raw `Vec<u8>` (no serde round-trip),
//! and T5/T6 wire the writer into actual fixture execution.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;
use thiserror::Error;

use crate::golden_format::{
    canonical_json_bytes, CHECKPOINT_FILENAME, RECEIPTS_FILENAME, ROOT_FILENAME, ROOT_HEX_LEN,
    ROOT_LEN, TMP_SUFFIX,
};

/// Errors produced while staging or committing a [`GoldenSet`].
#[derive(Debug, Error)]
pub enum GoldenWriterError {
    /// `serde_json` failed to serialize a canonicalized value. In
    /// practice this only fires for non-string object keys, which the
    /// recursive [`canonicalize`] helper does not produce, but we keep
    /// the variant so any future regression surfaces fail-closed.
    #[error("canonical-JSON serialization failed: {0}")]
    CanonicalJson(#[from] serde_json::Error),

    /// `commit` was called without a prior `set_checkpoint`.
    #[error("cannot commit goldens: checkpoint was not set")]
    MissingCheckpoint,

    /// `commit` was called without a prior `set_root`.
    #[error("cannot commit goldens: root was not set")]
    MissingRoot,

    /// `commit` was called with no receipts appended. A scenario with
    /// zero receipts is a usage bug, not a valid empty corpus.
    #[error("cannot commit goldens: no receipts were appended")]
    EmptyReceipts,

    /// An I/O operation against a goldens path failed.
    #[error("I/O error at {path}: {source}")]
    Io {
        /// Path that was being operated on.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
}

/// Per-file byte sizes recorded after a successful commit. Useful for
/// CI logs and for sanity-checking that a refactor did not change the
/// goldens out from under the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoldenSetByteSizes {
    /// Byte length of `receipts.ndjson`.
    pub receipts: u64,
    /// Byte length of `checkpoint.json`.
    pub checkpoint: u64,
    /// Byte length of `root.hex`.
    pub root: u64,
}

/// Summary returned from a successful [`GoldenSet::commit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoldenSetSummary {
    /// Directory the goldens were written into.
    pub dir: PathBuf,
    /// Number of receipts written to `receipts.ndjson`.
    pub receipt_count: usize,
    /// Lowercase hex of the Merkle root that was written to
    /// `root.hex` (without a trailing newline).
    pub root_hex: String,
    /// Per-file byte sizes of the three goldens.
    pub byte_sizes: GoldenSetByteSizes,
}

/// In-memory accumulator for one scenario's golden artifacts.
///
/// Construct with [`GoldenSet::new`], stage inputs via
/// [`append_receipt`](Self::append_receipt),
/// [`set_checkpoint`](Self::set_checkpoint), and
/// [`set_root`](Self::set_root), then call [`commit`](Self::commit) to
/// flush the staged bytes to disk atomically.
///
/// Buffers are kept as raw `Vec<u8>` (already canonical-JSON encoded)
/// so the writer never re-serializes between staging and commit, which
/// is what makes the byte-equivalence gate possible.
#[derive(Debug)]
pub struct GoldenSet {
    dir: PathBuf,
    receipts_buf: Vec<u8>,
    receipt_count: usize,
    checkpoint: Option<Vec<u8>>,
    root: Option<[u8; ROOT_LEN]>,
}

impl GoldenSet {
    /// Initialize a new `GoldenSet` for the given per-scenario goldens
    /// directory. The directory is not touched until
    /// [`commit`](Self::commit) is called; create-on-commit keeps the
    /// staging surface side-effect free.
    pub fn new(scenario_dir: impl AsRef<Path>) -> Self {
        Self {
            dir: scenario_dir.as_ref().to_path_buf(),
            receipts_buf: Vec::new(),
            receipt_count: 0,
            checkpoint: None,
            root: None,
        }
    }

    /// Append a single receipt to the staged NDJSON buffer.
    ///
    /// The receipt is canonicalized through the workspace-wide RFC
    /// 8785 implementation in
    /// [`chio_core_types::canonical::canonicalize`] (UTF-16 key sort,
    /// no insignificant whitespace) and terminated with a single
    /// `\n`.
    pub fn append_receipt(&mut self, receipt: &Value) -> Result<(), GoldenWriterError> {
        let bytes = canonical_json_bytes(receipt).map_err(|source| GoldenWriterError::Io {
            path: PathBuf::from(RECEIPTS_FILENAME),
            source,
        })?;
        self.receipts_buf.extend_from_slice(&bytes);
        self.receipts_buf.push(b'\n');
        self.receipt_count = self.receipt_count.saturating_add(1);
        Ok(())
    }

    /// Stage the canonical-JSON encoding of `checkpoint` for later
    /// commit. Replaces any previously staged checkpoint (the last
    /// caller wins, matching the natural "rebuild and overwrite"
    /// flow the gate uses on `--bless`).
    pub fn set_checkpoint(&mut self, checkpoint: &Value) -> Result<(), GoldenWriterError> {
        let bytes = canonical_json_bytes(checkpoint).map_err(|source| GoldenWriterError::Io {
            path: PathBuf::from(CHECKPOINT_FILENAME),
            source,
        })?;
        self.checkpoint = Some(bytes);
        Ok(())
    }

    /// Stage the 32-byte Merkle root for later commit. Replaces any
    /// previously staged root.
    pub fn set_root(&mut self, root: [u8; ROOT_LEN]) {
        self.root = Some(root);
    }

    /// Flush the staged goldens to disk.
    ///
    /// Behaviour:
    ///
    /// 1. Validates that at least one receipt has been appended and
    ///    that both a checkpoint and a root have been staged. Missing
    ///    pieces produce [`GoldenWriterError::EmptyReceipts`],
    ///    [`GoldenWriterError::MissingCheckpoint`], and
    ///    [`GoldenWriterError::MissingRoot`] respectively.
    /// 2. Creates the goldens directory (`mkdir -p` semantics).
    /// 3. Writes each artifact to a `<file>.tmp` sibling, fsyncs it,
    ///    then renames it into place. On any per-file failure the
    ///    method removes any `.tmp` siblings it has staged so far so
    ///    a partial-failure scenario does not leak stale temp files
    ///    next to the goldens. The rename step is the per-file
    ///    commit point; the three renames are issued back-to-back so
    ///    a crash between them is the only window in which a
    ///    partially-published goldens directory could be observed,
    ///    which the byte-equivalence reader catches at load time.
    /// 4. Returns a [`GoldenSetSummary`] describing what was written.
    pub fn commit(self) -> Result<GoldenSetSummary, GoldenWriterError> {
        if self.receipt_count == 0 {
            return Err(GoldenWriterError::EmptyReceipts);
        }
        let checkpoint_bytes = match self.checkpoint {
            Some(bytes) => bytes,
            None => return Err(GoldenWriterError::MissingCheckpoint),
        };
        let root_bytes = match self.root {
            Some(bytes) => bytes,
            None => return Err(GoldenWriterError::MissingRoot),
        };

        // mkdir -p the per-scenario goldens directory.
        if let Err(source) = fs::create_dir_all(&self.dir) {
            return Err(GoldenWriterError::Io {
                path: self.dir.clone(),
                source,
            });
        }

        let receipts_path = self.dir.join(RECEIPTS_FILENAME);
        let checkpoint_path = self.dir.join(CHECKPOINT_FILENAME);
        let root_path = self.dir.join(ROOT_FILENAME);

        let root_hex = hex::encode(root_bytes);
        // Defensive: the encoder is documented to produce 2*N lowercase
        // hex chars, but the gate's ground-truth invariant is "exactly
        // 64 lowercase hex chars, no trailing newline". Reject up front
        // if that ever drifts.
        if root_hex.len() != ROOT_HEX_LEN {
            return Err(GoldenWriterError::Io {
                path: root_path.clone(),
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "hex-encoded root has wrong length: expected {ROOT_HEX_LEN}, got {}",
                        root_hex.len()
                    ),
                ),
            });
        }

        // Stage all three artifacts as `<file>.tmp` siblings up front
        // so that if any one stage fails we can clean up the previous
        // siblings before bubbling the error. Renames happen in a
        // separate loop after every stage has succeeded.
        let receipts_tmp = staging_path(&receipts_path);
        let checkpoint_tmp = staging_path(&checkpoint_path);
        let root_tmp = staging_path(&root_path);

        if let Err(err) = stage_file(&receipts_tmp, &self.receipts_buf) {
            cleanup_tmp(&[&receipts_tmp]);
            return Err(err);
        }
        if let Err(err) = stage_file(&checkpoint_tmp, &checkpoint_bytes) {
            cleanup_tmp(&[&receipts_tmp, &checkpoint_tmp]);
            return Err(err);
        }
        if let Err(err) = stage_file(&root_tmp, root_hex.as_bytes()) {
            cleanup_tmp(&[&receipts_tmp, &checkpoint_tmp, &root_tmp]);
            return Err(err);
        }

        // All three files are durably staged; promote them by rename.
        // A failure here is rare (same-directory POSIX rename is
        // atomic) but we still clean up any remaining staged file so
        // the per-scenario directory ends in either a fully-published
        // state or a state where the partial-publish is visible only
        // through whichever renames already succeeded (no stray .tmp
        // files mixed in).
        if let Err(err) = rename_staged(&receipts_tmp, &receipts_path) {
            cleanup_tmp(&[&checkpoint_tmp, &root_tmp]);
            return Err(err);
        }
        if let Err(err) = rename_staged(&checkpoint_tmp, &checkpoint_path) {
            cleanup_tmp(&[&root_tmp]);
            return Err(err);
        }
        rename_staged(&root_tmp, &root_path)?;

        let receipts_size = file_size(&receipts_path)?;
        let checkpoint_size = file_size(&checkpoint_path)?;
        let root_size = file_size(&root_path)?;

        Ok(GoldenSetSummary {
            dir: self.dir,
            receipt_count: self.receipt_count,
            root_hex,
            byte_sizes: GoldenSetByteSizes {
                receipts: receipts_size,
                checkpoint: checkpoint_size,
                root: root_size,
            },
        })
    }
}

/// Construct the staging-path sibling (`<file>.tmp`) for `final_path`.
fn staging_path(final_path: &Path) -> PathBuf {
    let mut staging = final_path.as_os_str().to_owned();
    staging.push(TMP_SUFFIX);
    PathBuf::from(staging)
}

/// Write `bytes` to `staging_path` and fsync it before returning.
///
/// fsync is requested explicitly so the rename step in
/// [`rename_staged`] promotes already-durable bytes; otherwise a
/// crash between rename and fsync could leave the rename visible but
/// the bytes lost. The fsync is best-effort: if the platform does not
/// support `File::sync_all` (e.g. some Windows handles) the underlying
/// I/O error is surfaced to the caller along with the staging path.
fn stage_file(staging_path: &Path, bytes: &[u8]) -> Result<(), GoldenWriterError> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(staging_path)
        .map_err(|source| GoldenWriterError::Io {
            path: staging_path.to_path_buf(),
            source,
        })?;
    file.write_all(bytes)
        .map_err(|source| GoldenWriterError::Io {
            path: staging_path.to_path_buf(),
            source,
        })?;
    file.sync_all().map_err(|source| GoldenWriterError::Io {
        path: staging_path.to_path_buf(),
        source,
    })?;
    Ok(())
}

/// Promote a staged file to its final path via `fs::rename`.
fn rename_staged(staging_path: &Path, final_path: &Path) -> Result<(), GoldenWriterError> {
    fs::rename(staging_path, final_path).map_err(|source| GoldenWriterError::Io {
        path: final_path.to_path_buf(),
        source,
    })
}

/// Best-effort cleanup of staged `.tmp` files after a partial failure.
///
/// Errors are silently ignored: the calling commit has already failed,
/// and the caller's error path will surface the original I/O failure.
/// Removing the staged siblings here keeps the goldens directory free
/// of partial-publish residue that could mislead a follow-on bless.
fn cleanup_tmp(paths: &[&Path]) {
    for path in paths {
        let _ = fs::remove_file(path);
    }
}

/// Returns the byte length of `path`, mapping I/O errors into
/// [`GoldenWriterError::Io`].
fn file_size(path: &Path) -> Result<u64, GoldenWriterError> {
    match fs::metadata(path) {
        Ok(meta) => Ok(meta.len()),
        Err(source) => Err(GoldenWriterError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the golden writer. These drive the canonicalizer
    //! directly and exercise the on-disk write/commit dance through a
    //! temporary directory. The byte-stable invariants asserted here
    //! (key order, NDJSON terminator, root.hex shape) are exactly the
    //! invariants the M04 replay gate diffs against, so a regression
    //! in any one of them surfaces here before the gate ever runs.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn make_dir() -> TempDir {
        TempDir::new().expect("tempdir must succeed in tests")
    }

    fn read_bytes(path: &Path) -> Vec<u8> {
        fs::read(path).expect("read of just-committed goldens must succeed")
    }

    fn read_string(path: &Path) -> String {
        fs::read_to_string(path).expect("read of just-committed goldens must succeed")
    }

    // The previous revision of this module hand-rolled a BTreeMap
    // canonicaliser; the writer now delegates to the workspace-wide
    // `chio_core_types::canonical::canonicalize` (RFC 8785 / JCS) via
    // `crate::golden_format::canonical_json_bytes`. The tests below
    // assert the byte-level invariants the writer relies on (sorted
    // keys, recursion, no whitespace, primitive round-trip,
    // per-element object sort within arrays). If the shared
    // canonicaliser ever drifts in a way that touches the replay
    // corpus, these tests trip before the byte-equivalence gate.

    #[test]
    fn canonicalize_sorts_object_keys() {
        let input = json!({"b": 1, "a": 2});
        let bytes = canonical_json_bytes(&input).expect("canonicalize must succeed");
        assert_eq!(bytes, br#"{"a":2,"b":1}"#);
    }

    #[test]
    fn canonicalize_recurses_into_nested() {
        let input = json!({"x": {"b": 1, "a": 2}});
        let bytes = canonical_json_bytes(&input).expect("canonicalize must succeed");
        assert_eq!(bytes, br#"{"x":{"a":2,"b":1}}"#);
    }

    #[test]
    fn canonicalize_preserves_array_order() {
        let input = json!([3, 1, 2]);
        let bytes = canonical_json_bytes(&input).expect("canonicalize must succeed");
        assert_eq!(bytes, b"[3,1,2]");
    }

    #[test]
    fn canonicalize_handles_primitives() {
        // Numbers, strings, booleans, null round-trip via the shared
        // canonicaliser to the same byte form `serde_json::to_string`
        // would have produced for these ASCII / integer values.
        let cases = [
            (json!(null), "null"),
            (json!(true), "true"),
            (json!(false), "false"),
            (json!(0), "0"),
            (json!(-7), "-7"),
            (json!("hello"), r#""hello""#),
        ];
        for (value, want) in cases {
            let bytes = canonical_json_bytes(&value).expect("canonicalize must succeed");
            assert_eq!(bytes, want.as_bytes(), "case={value:?}");
        }
    }

    #[test]
    fn canonicalize_sorts_array_of_objects_per_element() {
        let input = json!([
            {"b": 1, "a": 2},
            {"d": 3, "c": 4},
        ]);
        let bytes = canonical_json_bytes(&input).expect("canonicalize must succeed");
        assert_eq!(bytes, br#"[{"a":2,"b":1},{"c":4,"d":3}]"#);
    }

    #[test]
    fn append_receipt_then_commit_writes_ndjson() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_a");

        let mut set = GoldenSet::new(&dir);
        set.append_receipt(&json!({"b": 1, "a": 2}))
            .expect("append must succeed");
        set.append_receipt(&json!({"id": 42, "kind": "allow"}))
            .expect("append must succeed");
        set.append_receipt(&json!({"nested": {"z": 1, "y": 2}}))
            .expect("append must succeed");
        set.set_checkpoint(&json!({"root": "deadbeef", "height": 1}))
            .expect("set_checkpoint must succeed");
        set.set_root([0u8; 32]);

        let summary = set.commit().expect("commit must succeed");
        assert_eq!(summary.receipt_count, 3);
        assert_eq!(summary.dir, dir);

        let receipts_path = dir.join(RECEIPTS_FILENAME);
        let body = read_string(&receipts_path);
        let lines: Vec<&str> = body.split_terminator('\n').collect();
        assert_eq!(lines.len(), 3, "exactly three receipts must be written");
        assert_eq!(lines[0], r#"{"a":2,"b":1}"#);
        assert_eq!(lines[1], r#"{"id":42,"kind":"allow"}"#);
        assert_eq!(lines[2], r#"{"nested":{"y":2,"z":1}}"#);
    }

    #[test]
    fn commit_without_root_fails() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_no_root");

        let mut set = GoldenSet::new(&dir);
        set.append_receipt(&json!({"k": "v"}))
            .expect("append must succeed");
        set.set_checkpoint(&json!({"root": "00", "height": 0}))
            .expect("set_checkpoint must succeed");

        let err = set.commit().expect_err("commit must fail without root");
        assert!(matches!(err, GoldenWriterError::MissingRoot));
        // The directory should not have been created either, since the
        // mkdir step runs after validation.
        assert!(
            !dir.exists(),
            "no goldens directory must be created on failure"
        );
    }

    #[test]
    fn commit_without_checkpoint_fails() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_no_checkpoint");

        let mut set = GoldenSet::new(&dir);
        set.append_receipt(&json!({"k": "v"}))
            .expect("append must succeed");
        set.set_root([1u8; 32]);

        let err = set
            .commit()
            .expect_err("commit must fail without checkpoint");
        assert!(matches!(err, GoldenWriterError::MissingCheckpoint));
        assert!(
            !dir.exists(),
            "no goldens directory must be created on failure"
        );
    }

    #[test]
    fn commit_with_empty_receipts_fails() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_empty");

        let mut set = GoldenSet::new(&dir);
        set.set_checkpoint(&json!({"root": "00", "height": 0}))
            .expect("set_checkpoint must succeed");
        set.set_root([2u8; 32]);

        let err = set.commit().expect_err("commit must fail with no receipts");
        assert!(matches!(err, GoldenWriterError::EmptyReceipts));
        assert!(
            !dir.exists(),
            "no goldens directory must be created on failure"
        );
    }

    #[test]
    fn root_hex_is_lowercase_64_chars_no_trailing_newline() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_root_shape");

        let mut set = GoldenSet::new(&dir);
        set.append_receipt(&json!({"only": "one"}))
            .expect("append must succeed");
        set.set_checkpoint(&json!({"root": "ab", "height": 7}))
            .expect("set_checkpoint must succeed");
        // Use a non-trivial root so we can spot-check encoding.
        let mut root = [0u8; 32];
        for (i, byte) in root.iter_mut().enumerate() {
            *byte = i as u8;
        }
        set.set_root(root);

        let summary = set.commit().expect("commit must succeed");
        assert_eq!(summary.root_hex.len(), 64);
        assert_eq!(
            summary.root_hex,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );

        let root_path = dir.join(ROOT_FILENAME);
        let bytes = read_bytes(&root_path);
        assert_eq!(bytes.len(), 64, "root.hex must be exactly 64 bytes on disk");
        let s = String::from_utf8(bytes).expect("root.hex must be valid UTF-8");
        assert_eq!(s.len(), 64, "root.hex must be exactly 64 chars on disk");
        assert!(
            !s.ends_with('\n'),
            "root.hex must not have a trailing newline"
        );
        assert!(
            s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
            "root.hex must be lowercase hex only"
        );
    }

    #[test]
    fn ndjson_terminator_is_lf_only() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_ndjson_terminator");

        let mut set = GoldenSet::new(&dir);
        set.append_receipt(&json!({"i": 0}))
            .expect("append must succeed");
        set.append_receipt(&json!({"i": 1}))
            .expect("append must succeed");
        set.set_checkpoint(&json!({"root": "00", "height": 0}))
            .expect("set_checkpoint must succeed");
        set.set_root([0u8; 32]);

        set.commit().expect("commit must succeed");

        let receipts_path = dir.join(RECEIPTS_FILENAME);
        let bytes = read_bytes(&receipts_path);
        assert!(!bytes.is_empty(), "receipts.ndjson must not be empty");
        assert_eq!(
            *bytes.last().unwrap_or(&0),
            b'\n',
            "receipts.ndjson must end with a single LF after the last line"
        );
        // No CR anywhere.
        for (i, b) in bytes.iter().enumerate() {
            assert_ne!(
                *b, b'\r',
                "receipts.ndjson byte {i} is CR; LF-only required"
            );
        }
        // Exactly two LFs (one per receipt).
        let lf_count = bytes.iter().filter(|b| **b == b'\n').count();
        assert_eq!(lf_count, 2, "expected one LF per receipt for two receipts");
    }

    #[test]
    fn checkpoint_json_is_canonical_with_no_extra_whitespace() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_checkpoint_canonical");

        let mut set = GoldenSet::new(&dir);
        set.append_receipt(&json!({"x": 1}))
            .expect("append must succeed");
        set.set_checkpoint(&json!({"height": 9, "root": "00", "anchored_at": "2026"}))
            .expect("set_checkpoint must succeed");
        set.set_root([3u8; 32]);

        set.commit().expect("commit must succeed");

        let checkpoint_path = dir.join(CHECKPOINT_FILENAME);
        let body = read_string(&checkpoint_path);
        // Keys must be sorted, no spaces, no trailing newline.
        assert_eq!(
            body, r#"{"anchored_at":"2026","height":9,"root":"00"}"#,
            "checkpoint.json must be canonical JSON with sorted keys and no whitespace"
        );
    }

    #[test]
    fn commit_creates_directory_and_reports_byte_sizes() {
        let tmp = make_dir();
        // Use a nested path to verify mkdir -p semantics.
        let dir = tmp.path().join("nested").join("scenario_sizes");

        let mut set = GoldenSet::new(&dir);
        set.append_receipt(&json!({"k": "v"}))
            .expect("append must succeed");
        set.set_checkpoint(&json!({"root": "00", "height": 0}))
            .expect("set_checkpoint must succeed");
        set.set_root([0u8; 32]);

        let summary = set.commit().expect("commit must succeed");
        assert!(dir.is_dir(), "commit must create nested goldens directory");

        let receipts_size = fs::metadata(dir.join(RECEIPTS_FILENAME))
            .expect("receipts metadata")
            .len();
        let checkpoint_size = fs::metadata(dir.join(CHECKPOINT_FILENAME))
            .expect("checkpoint metadata")
            .len();
        let root_size = fs::metadata(dir.join(ROOT_FILENAME))
            .expect("root metadata")
            .len();

        assert_eq!(summary.byte_sizes.receipts, receipts_size);
        assert_eq!(summary.byte_sizes.checkpoint, checkpoint_size);
        assert_eq!(summary.byte_sizes.root, root_size);
        assert_eq!(summary.byte_sizes.root, 64);
    }

    #[test]
    fn no_tmp_files_remain_after_successful_commit() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_no_tmp");

        let mut set = GoldenSet::new(&dir);
        set.append_receipt(&json!({"k": "v"}))
            .expect("append must succeed");
        set.set_checkpoint(&json!({"root": "00", "height": 0}))
            .expect("set_checkpoint must succeed");
        set.set_root([0u8; 32]);

        set.commit().expect("commit must succeed");

        let entries: Vec<PathBuf> = fs::read_dir(&dir)
            .expect("readdir must succeed")
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .collect();
        for entry in &entries {
            let name = entry
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            assert!(
                !name.ends_with(TMP_SUFFIX),
                "no .tmp staging files must remain after commit (found {name})"
            );
        }
    }
}
