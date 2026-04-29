//! Raw byte-comparison harness for the M04 deterministic-replay
//! gate.
//!
//! The replay gate's load-bearing property is BYTE EQUIVALENCE
//! between a candidate run's output and a previously-blessed golden
//! snapshot. To preserve that property the comparison MUST operate
//! on raw `&[u8]` slices on both sides; any detour through
//! `serde_json::Value` would normalize whitespace and key order and
//! mask the exact drift the gate is meant to catch. Nothing in this
//! module deserializes JSON.
//!
//! [`compare_artifacts`] is the primary entry point: given a
//! [`crate::golden_reader::GoldenLoaded`] (the expected snapshot) and
//! the three raw byte buffers from a candidate run, it returns a
//! `Vec<ByteDiff>` with ALL artifacts that differ. The gate caller is
//! responsible for rendering the diff; this module only computes it.
//!
//! # Diff shape
//!
//! On mismatch the returned [`ByteDiff::Different`] variant carries:
//!
//! - `kind`: which artifact differed ([`ArtifactKind::Receipts`],
//!   [`ArtifactKind::Checkpoint`], [`ArtifactKind::RootHex`]).
//! - `expected_len` / `actual_len`: byte lengths of both sides.
//! - `first_diff_offset`: offset of the first differing byte. When
//!   one side is a strict prefix of the other, the offset is the
//!   shorter length (i.e. where the longer side started having
//!   "extra" bytes).
//! - `expected_window` / `actual_window`: a 32-byte window starting
//!   at `first_diff_offset.saturating_sub(8)` into each side, capped
//!   by the available bytes. Gives operators eight bytes of leading
//!   context plus the divergent run.
//!
//! [`compare_byte_slices`] is the same primitive exposed for one
//! artifact at a time, useful in unit tests and ad-hoc diagnostics.

use crate::golden_reader::GoldenLoaded;

/// Byte length of the diff context window emitted on mismatch.
const DIFF_WINDOW_LEN: usize = 32;

/// Bytes of leading context to include before `first_diff_offset` in
/// the emitted window. The window then runs forward until either
/// [`DIFF_WINDOW_LEN`] bytes have been collected or the slice is
/// exhausted.
const DIFF_WINDOW_LEADING: usize = 8;

/// Which on-disk artifact a [`ByteDiff`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    /// `receipts.ndjson`.
    Receipts,
    /// `checkpoint.json`.
    Checkpoint,
    /// `root.hex`.
    RootHex,
}

/// Result of comparing one expected byte slice against one actual
/// byte slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ByteDiff {
    /// The two slices are byte-identical.
    Equal,
    /// The two slices differ. The fields locate the first divergence
    /// and surface enough context to debug it without round-tripping
    /// through a higher-level decoder.
    Different {
        /// Which artifact this diff refers to.
        kind: ArtifactKind,
        /// Length of the expected (golden) slice.
        expected_len: usize,
        /// Length of the actual (candidate) slice.
        actual_len: usize,
        /// Byte offset of the first divergent byte. When one side is
        /// a strict prefix of the other, this is the shorter length.
        first_diff_offset: usize,
        /// Up to [`DIFF_WINDOW_LEN`] bytes of expected content
        /// starting at `first_diff_offset.saturating_sub(8)`.
        expected_window: Vec<u8>,
        /// Up to [`DIFF_WINDOW_LEN`] bytes of actual content
        /// starting at `first_diff_offset.saturating_sub(8)`.
        actual_window: Vec<u8>,
    },
}

/// Pairwise raw byte compare for a single artifact.
///
/// Returns [`ByteDiff::Equal`] when both slices have the same length
/// and the same bytes. Otherwise returns [`ByteDiff::Different`] with
/// the first divergent offset and a 32-byte context window from each
/// side. Lengths longer than the window are intentional: the window
/// is capped, not the length fields, so callers can spot length-only
/// drift even when both sides agree on every common byte.
pub fn compare_byte_slices(kind: ArtifactKind, expected: &[u8], actual: &[u8]) -> ByteDiff {
    if expected == actual {
        return ByteDiff::Equal;
    }

    let common = expected.len().min(actual.len());
    // Walk the shared prefix one byte at a time. If every common
    // byte matches the divergence is at `common` (one side is a
    // strict prefix of the other).
    let mut first_diff_offset = common;
    for i in 0..common {
        if expected[i] != actual[i] {
            first_diff_offset = i;
            break;
        }
    }

    let window_start = first_diff_offset.saturating_sub(DIFF_WINDOW_LEADING);
    let expected_window = window_slice(expected, window_start, DIFF_WINDOW_LEN);
    let actual_window = window_slice(actual, window_start, DIFF_WINDOW_LEN);

    ByteDiff::Different {
        kind,
        expected_len: expected.len(),
        actual_len: actual.len(),
        first_diff_offset,
        expected_window,
        actual_window,
    }
}

/// Compare a candidate run's three raw artifact buffers against the
/// expected goldens. Returns ALL diffs (no short-circuit) in a
/// stable order: receipts, then checkpoint, then root.hex.
pub fn compare_artifacts(
    expected: &GoldenLoaded,
    actual_receipts: &[u8],
    actual_checkpoint: &[u8],
    actual_root_hex: &str,
) -> Vec<ByteDiff> {
    let mut diffs = Vec::new();

    let receipts_diff =
        compare_byte_slices(ArtifactKind::Receipts, &expected.receipts, actual_receipts);
    if !matches!(receipts_diff, ByteDiff::Equal) {
        diffs.push(receipts_diff);
    }

    let checkpoint_diff = compare_byte_slices(
        ArtifactKind::Checkpoint,
        &expected.checkpoint,
        actual_checkpoint,
    );
    if !matches!(checkpoint_diff, ByteDiff::Equal) {
        diffs.push(checkpoint_diff);
    }

    // root_hex is stored as a UTF-8 string for ergonomic logging,
    // but the byte-compare contract still operates on `&[u8]` so
    // there is no string-aware normalization in the diff path.
    let root_diff = compare_byte_slices(
        ArtifactKind::RootHex,
        expected.root_hex.as_bytes(),
        actual_root_hex.as_bytes(),
    );
    if !matches!(root_diff, ByteDiff::Equal) {
        diffs.push(root_diff);
    }

    diffs
}

/// Copy up to `len` bytes from `slice` starting at `start`, clamped
/// to the slice's actual length. Returns an empty `Vec` when `start`
/// is past the end.
fn window_slice(slice: &[u8], start: usize, len: usize) -> Vec<u8> {
    if start >= slice.len() {
        return Vec::new();
    }
    let end = start.saturating_add(len).min(slice.len());
    slice[start..end].to_vec()
}

#[cfg(test)]
mod tests {
    //! Unit tests for the byte-comparison harness. The pairwise
    //! tests exercise [`compare_byte_slices`] across the four
    //! interesting cases (equal, first-byte mismatch, mid-slice
    //! mismatch, prefix-vs-longer in both directions). The
    //! end-to-end tests drive [`compare_artifacts`] through a real
    //! goldens directory written by [`crate::golden_writer`] so the
    //! "no serde round-trip" property is exercised on actual bytes.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::golden_writer::GoldenSet;
    use serde_json::json;
    use std::path::Path;
    use tempfile::TempDir;

    fn make_dir() -> TempDir {
        TempDir::new().expect("tempdir must succeed in tests")
    }

    fn bless_scenario(dir: &Path) {
        let mut set = GoldenSet::new(dir);
        set.append_receipt(&json!({"a": 1, "b": 2}))
            .expect("append must succeed");
        set.append_receipt(&json!({"id": 42, "kind": "allow"}))
            .expect("append must succeed");
        set.set_checkpoint(&json!({"height": 1, "root": "ab"}))
            .expect("set_checkpoint must succeed");
        let mut root = [0u8; 32];
        for (i, byte) in root.iter_mut().enumerate() {
            *byte = i as u8;
        }
        set.set_root(root);
        set.commit().expect("commit must succeed");
    }

    #[test]
    fn compare_byte_slices_equal_returns_equal() {
        let buf = b"abcdef".to_vec();
        let diff = compare_byte_slices(ArtifactKind::Receipts, &buf, &buf);
        assert_eq!(diff, ByteDiff::Equal);
    }

    #[test]
    fn compare_byte_slices_different_first_byte() {
        let expected = b"abc";
        let actual = b"xbc";
        let diff = compare_byte_slices(ArtifactKind::Receipts, expected, actual);
        match diff {
            ByteDiff::Different {
                kind,
                expected_len,
                actual_len,
                first_diff_offset,
                expected_window,
                actual_window,
            } => {
                assert_eq!(kind, ArtifactKind::Receipts);
                assert_eq!(expected_len, 3);
                assert_eq!(actual_len, 3);
                assert_eq!(first_diff_offset, 0);
                assert_eq!(expected_window, b"abc".to_vec());
                assert_eq!(actual_window, b"xbc".to_vec());
            }
            ByteDiff::Equal => panic!("expected Different, got Equal"),
        }
    }

    #[test]
    fn compare_byte_slices_different_middle() {
        let expected = b"abcdef";
        let actual = b"abcXef";
        let diff = compare_byte_slices(ArtifactKind::Checkpoint, expected, actual);
        match diff {
            ByteDiff::Different {
                kind,
                expected_len,
                actual_len,
                first_diff_offset,
                expected_window,
                actual_window,
            } => {
                assert_eq!(kind, ArtifactKind::Checkpoint);
                assert_eq!(expected_len, 6);
                assert_eq!(actual_len, 6);
                assert_eq!(first_diff_offset, 3);
                // Window starts at saturating_sub(8) = 0 for short
                // inputs, so we get the full slice on each side.
                assert_eq!(expected_window, b"abcdef".to_vec());
                assert_eq!(actual_window, b"abcXef".to_vec());
            }
            ByteDiff::Equal => panic!("expected Different, got Equal"),
        }
    }

    #[test]
    fn compare_byte_slices_actual_shorter_prefix() {
        let expected = b"abcdef";
        let actual = b"abc";
        let diff = compare_byte_slices(ArtifactKind::RootHex, expected, actual);
        match diff {
            ByteDiff::Different {
                kind,
                expected_len,
                actual_len,
                first_diff_offset,
                ..
            } => {
                assert_eq!(kind, ArtifactKind::RootHex);
                assert_eq!(expected_len, 6);
                assert_eq!(actual_len, 3);
                // Divergence is at the shorter length: actual ran
                // out of bytes there.
                assert_eq!(first_diff_offset, 3);
            }
            ByteDiff::Equal => panic!("expected Different, got Equal"),
        }
    }

    #[test]
    fn compare_byte_slices_actual_longer_prefix() {
        let expected = b"abc";
        let actual = b"abcdef";
        let diff = compare_byte_slices(ArtifactKind::RootHex, expected, actual);
        match diff {
            ByteDiff::Different {
                kind,
                expected_len,
                actual_len,
                first_diff_offset,
                ..
            } => {
                assert_eq!(kind, ArtifactKind::RootHex);
                assert_eq!(expected_len, 3);
                assert_eq!(actual_len, 6);
                // Symmetric to the actual-shorter case: divergence
                // is at the shorter length (expected here).
                assert_eq!(first_diff_offset, 3);
            }
            ByteDiff::Equal => panic!("expected Different, got Equal"),
        }
    }

    #[test]
    fn compare_artifacts_returns_empty_on_full_match() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_match");
        bless_scenario(&dir);

        let expected = GoldenLoaded::load(&dir).expect("load must succeed");
        // Compare a freshly-loaded snapshot against its own bytes:
        // every artifact must be byte-equal.
        let diffs = compare_artifacts(
            &expected,
            &expected.receipts,
            &expected.checkpoint,
            &expected.root_hex,
        );
        assert!(diffs.is_empty(), "expected no diffs, got {diffs:?}");
    }

    #[test]
    fn compare_artifacts_returns_three_diffs_when_all_differ() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_all_differ");
        bless_scenario(&dir);

        let expected = GoldenLoaded::load(&dir).expect("load must succeed");

        // Mutate every artifact by one byte (or by length for
        // root_hex, since it must be 64 chars on the expected side).
        let mut bad_receipts = expected.receipts.clone();
        bad_receipts[0] ^= 0x01;
        let mut bad_checkpoint = expected.checkpoint.clone();
        bad_checkpoint[0] ^= 0x01;
        // Replace the first hex char with a different lowercase hex
        // char so we still have a 64-char string but a different
        // byte at offset 0.
        let mut bad_root_chars: Vec<char> = expected.root_hex.chars().collect();
        bad_root_chars[0] = if bad_root_chars[0] == 'f' { 'e' } else { 'f' };
        let bad_root: String = bad_root_chars.into_iter().collect();

        let diffs = compare_artifacts(&expected, &bad_receipts, &bad_checkpoint, &bad_root);
        assert_eq!(diffs.len(), 3, "expected three diffs, got {diffs:?}");
        // Order is contractually receipts, checkpoint, root.hex.
        match &diffs[0] {
            ByteDiff::Different { kind, .. } => assert_eq!(*kind, ArtifactKind::Receipts),
            ByteDiff::Equal => panic!("diff[0] must be Different"),
        }
        match &diffs[1] {
            ByteDiff::Different { kind, .. } => assert_eq!(*kind, ArtifactKind::Checkpoint),
            ByteDiff::Equal => panic!("diff[1] must be Different"),
        }
        match &diffs[2] {
            ByteDiff::Different { kind, .. } => assert_eq!(*kind, ArtifactKind::RootHex),
            ByteDiff::Equal => panic!("diff[2] must be Different"),
        }
    }

    #[test]
    fn compare_artifacts_includes_first_diff_window() {
        let tmp = make_dir();
        let dir = tmp.path().join("scenario_window");
        bless_scenario(&dir);

        let expected = GoldenLoaded::load(&dir).expect("load must succeed");

        // Flip a single byte deep enough into receipts that the
        // window cannot start at offset 0; that lets us verify the
        // 8-byte leading-context rule.
        let mut bad_receipts = expected.receipts.clone();
        let flip_at = 20usize.min(bad_receipts.len().saturating_sub(1));
        bad_receipts[flip_at] ^= 0x01;

        let diffs = compare_artifacts(
            &expected,
            &bad_receipts,
            &expected.checkpoint,
            &expected.root_hex,
        );
        assert_eq!(diffs.len(), 1);
        match &diffs[0] {
            ByteDiff::Different {
                kind,
                first_diff_offset,
                expected_window,
                actual_window,
                expected_len,
                actual_len,
            } => {
                assert_eq!(*kind, ArtifactKind::Receipts);
                assert_eq!(*first_diff_offset, flip_at);
                // Both windows must be capped at 32 bytes and
                // start at first_diff_offset.saturating_sub(8).
                assert!(expected_window.len() <= DIFF_WINDOW_LEN);
                assert!(actual_window.len() <= DIFF_WINDOW_LEN);
                let window_start = flip_at.saturating_sub(DIFF_WINDOW_LEADING);
                let expected_end =
                    window_start + DIFF_WINDOW_LEN.min(expected.receipts.len() - window_start);
                assert_eq!(
                    expected_window.as_slice(),
                    &expected.receipts[window_start..expected_end],
                );
                let actual_end =
                    window_start + DIFF_WINDOW_LEN.min(bad_receipts.len() - window_start);
                assert_eq!(
                    actual_window.as_slice(),
                    &bad_receipts[window_start..actual_end],
                );
                // Lengths are unchanged because we flipped one byte
                // in place.
                assert_eq!(*expected_len, expected.receipts.len());
                assert_eq!(*actual_len, bad_receipts.len());
            }
            ByteDiff::Equal => panic!("expected Different, got Equal"),
        }
    }
}
