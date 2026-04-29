//! Re-verify cross-version replay bundles against the current kernel.
//!
//! The [`fetch`](super::fetch) layer downloads a tagged release's
//! `replay-bundle.tgz` and pins it on disk by sha256. This module reads
//! that cached archive, extracts the three goldens
//! (`receipts.ndjson` / `checkpoint.json` / `root.hex`), and re-runs the
//! current kernel's verifier surface over them.
//!
//! # Bundle layout
//!
//! Every replay bundle, regardless of producing tag, MUST contain the
//! following three files (paths are matched by basename inside the
//! tarball, so `replay-bundle/<file>` and `<file>` both resolve):
//!
//! - `receipts.ndjson`: one canonical-JSON receipt per line, LF
//!   terminated. Matches the byte-for-byte output of
//!   [`crate::golden_writer::GoldenSet`].
//! - `checkpoint.json`: a single canonical-JSON checkpoint object,
//!   no surrounding whitespace.
//! - `root.hex`: exactly 64 lowercase-hex characters, no trailing
//!   newline. Encodes the 32-byte synthetic root.
//!
//! # Verifier passes
//!
//! [`reverify_bundle`] performs three independent passes per bundle:
//!
//! 1. **Structural extract.** Each required entry MUST exist; missing
//!    files surface as [`ReverifyError::MissingEntry`].
//! 2. **Signature verify.** Each receipt is parsed as
//!    [`chio_core_types::ChioReceipt`] and run through
//!    [`ChioReceipt::verify_signature`](chio_core_types::ChioReceipt::verify_signature).
//!    Stub-shape receipts (current pre-1.0 goldens emit a placeholder
//!    JSON object via the `corpus_smoke` driver) deserialize-fail; that
//!    is recorded as `receipts_unsigned`, NOT a signature failure.
//!    Only deserialize-succeeding receipts whose signature does not
//!    verify count toward `receipts_signature_failed`.
//! 3. **Root recompute.** Recompute the synthetic Merkle root over the
//!    on-disk `receipts.ndjson` || `checkpoint.json` byte stream
//!    (matches the `corpus_smoke.rs` derivation), and compare against
//!    the bytes in `root.hex`.
//!
//! # Compat-level handling
//!
//! Callers (the integration test) drive the matrix:
//!
//! - [`CompatLevel::Supported`]: `root_match == false`,
//!   `receipts_signature_failed != 0`, or any extract error MUST fail
//!   the test.
//! - [`CompatLevel::BestEffort`]: same checks run, but failures are
//!   logged and tolerated (the report still surfaces).
//! - [`CompatLevel::Broken`]: skipped before this module is called.
//!
//! No live network here; the [`fetch`](super::fetch) layer owns that
//! contract. This module operates on a [`FetchedBundle`] that is already
//! pinned by sha256.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use chio_core_types::ChioReceipt;
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};

use super::fetch::{FetchError, FetchedBundle};
use super::{CompatEntry, CompatLevel};

/// Required basename inside the bundle tarball.
const RECEIPTS_FILENAME: &str = "receipts.ndjson";
/// Required basename inside the bundle tarball.
const CHECKPOINT_FILENAME: &str = "checkpoint.json";
/// Required basename inside the bundle tarball.
const ROOT_FILENAME: &str = "root.hex";

/// Errors surfaced by [`reverify_bundle`].
///
/// Underlying I/O / archive errors are flattened to `String` so this
/// public surface stays free of `tar`/`flate2` type leaks (mirrors the
/// pattern already used by [`FetchError`]).
#[derive(Debug, thiserror::Error)]
pub enum ReverifyError {
    /// Re-uses the fetch layer's error so callers can `?` through both
    /// `fetch_or_cache` and `reverify_bundle` from a single result type.
    #[error("fetch failed: {0}")]
    Fetch(#[from] FetchError),
    /// Tarball could not be opened or read (gzip framing, truncated
    /// archive, IO error reading entries).
    #[error("bundle archive could not be opened: {0}")]
    Archive(String),
    /// One of the three required entries was absent from the tarball.
    /// Always surfaces by basename.
    #[error("required entry {0} missing from bundle archive")]
    MissingEntry(&'static str),
    /// `root.hex` was present but did not contain exactly 64 lowercase
    /// hex bytes (no trailing newline). The replay-gate writer
    /// guarantees that shape, so a mismatch here means the bundle was
    /// tampered with or the producing tag's writer drifted.
    #[error("root.hex is malformed: expected 64 lowercase hex bytes, got {0:?}")]
    MalformedRoot(String),
    /// A required basename appeared more than once inside the tarball.
    /// Replay bundles are produced by the gate's writer which emits each
    /// of the three required files exactly once; a duplicate is treated
    /// as a structural-integrity failure (a malicious bundle could
    /// otherwise stage one set of bytes for re-verification while
    /// shadowing them with a second entry that overwrites the first).
    #[error("duplicate entry {0} inside bundle archive (required basenames must appear once)")]
    DuplicateEntry(&'static str),
}

/// Result of a successful [`reverify_bundle`] call.
///
/// `root_match == true && receipts_signature_failed == 0` is the
/// success contract for [`CompatLevel::Supported`] entries. Best-effort
/// entries may report `false` / non-zero without failing the test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReverifyReport {
    /// Release tag this report covers (mirrors [`FetchedBundle::tag`]).
    pub tag: String,
    /// Compat level the matrix declared for this tag.
    pub compat: CompatLevel,
    /// Total number of receipts present in `receipts.ndjson`.
    pub receipts_total: usize,
    /// Receipts that parsed as [`ChioReceipt`] but whose
    /// [`verify_signature`](chio_core_types::ChioReceipt::verify_signature)
    /// returned `Ok(false)` or `Err(_)`. Both are signature failures
    /// from the gate's point of view (a structurally-valid receipt
    /// MUST verify under its embedded kernel key).
    pub receipts_signature_failed: usize,
    /// Receipts that did not deserialize as [`ChioReceipt`] at all.
    /// These are stub-shape pre-1.0 goldens emitted by the
    /// `corpus_smoke` driver; they have no signature to verify and so
    /// are recorded separately rather than counted as failures.
    pub receipts_unsigned: usize,
    /// `true` iff the recomputed synthetic root equals the bytes in
    /// `root.hex`.
    pub root_match: bool,
    /// Lowercase hex of the recomputed root (always 64 chars).
    pub recomputed_root_hex: String,
    /// Lowercase hex of the bundle's pinned root (always 64 chars).
    pub bundle_root_hex: String,
}

/// Drive the re-verify flow on a fetched bundle.
///
/// `entry` is consulted to populate [`ReverifyReport::compat`]; the
/// caller is responsible for deciding whether a non-clean report is
/// fatal (matrix-level policy lives in the integration test, not here).
///
/// # Errors
///
/// - [`ReverifyError::Archive`] for any archive-level failure (open,
///   gzip frame, tar entry read).
/// - [`ReverifyError::MissingEntry`] if any of the three required
///   files is absent.
/// - [`ReverifyError::MalformedRoot`] if `root.hex` is the wrong
///   shape.
///
/// `Fetch` is included in [`ReverifyError`] for forward compatibility
/// with callers that pipe `fetch_or_cache(...).and_then(reverify)` but
/// is not surfaced from inside this function (the bundle is already
/// fetched at call time).
pub fn reverify_bundle(
    bundle: &FetchedBundle,
    entry: &CompatEntry,
) -> Result<ReverifyReport, ReverifyError> {
    let entries = extract_required_entries(&bundle.path)?;

    let receipts_bytes = entries
        .get(RECEIPTS_FILENAME)
        .ok_or(ReverifyError::MissingEntry(RECEIPTS_FILENAME))?;
    let checkpoint_bytes = entries
        .get(CHECKPOINT_FILENAME)
        .ok_or(ReverifyError::MissingEntry(CHECKPOINT_FILENAME))?;
    let root_bytes = entries
        .get(ROOT_FILENAME)
        .ok_or(ReverifyError::MissingEntry(ROOT_FILENAME))?;

    let bundle_root_hex = parse_root_hex(root_bytes)?;
    let (receipts_total, receipts_signature_failed, receipts_unsigned) =
        verify_receipts(receipts_bytes);

    let recomputed_root_hex = recompute_root_hex(receipts_bytes, checkpoint_bytes);
    let root_match = recomputed_root_hex == bundle_root_hex;

    Ok(ReverifyReport {
        tag: entry.tag.clone(),
        compat: entry.compat,
        receipts_total,
        receipts_signature_failed,
        receipts_unsigned,
        root_match,
        recomputed_root_hex,
        bundle_root_hex,
    })
}

/// Open the gzip-framed tarball at `path` and pull out the three
/// required goldens by basename. Entries whose basename does not match
/// one of the three target files are silently ignored (the bundle may
/// carry release-engineering metadata that is out of scope here).
///
/// Required basenames MUST appear exactly once. A duplicate
/// `receipts.ndjson` / `checkpoint.json` / `root.hex` is rejected via
/// [`ReverifyError::DuplicateEntry`]; a HashMap-overwrite policy would
/// let a malicious bundle stage one set of bytes for re-verification
/// and shadow them with a second entry, defeating the integrity check.
fn extract_required_entries(path: &Path) -> Result<HashMap<String, Vec<u8>>, ReverifyError> {
    let file = std::fs::File::open(path).map_err(|e| ReverifyError::Archive(e.to_string()))?;
    let decoder = GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);

    let mut out: HashMap<String, Vec<u8>> = HashMap::new();
    let entries = archive
        .entries()
        .map_err(|e| ReverifyError::Archive(e.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| ReverifyError::Archive(e.to_string()))?;
        let path_in_archive = entry
            .path()
            .map_err(|e| ReverifyError::Archive(e.to_string()))?;
        let basename = match path_in_archive.file_name().and_then(|s| s.to_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };
        // Map the basename back to one of the three required-file
        // sentinels so the duplicate-entry error uses the same
        // `&'static str` constant the rest of the module advertises.
        let required: &'static str = if basename == RECEIPTS_FILENAME {
            RECEIPTS_FILENAME
        } else if basename == CHECKPOINT_FILENAME {
            CHECKPOINT_FILENAME
        } else if basename == ROOT_FILENAME {
            ROOT_FILENAME
        } else {
            continue;
        };
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .map_err(|e| ReverifyError::Archive(e.to_string()))?;
        // Per-entry uniqueness: a well-formed bundle holds each
        // required file exactly once. Reject duplicates so a tarball
        // with two `receipts.ndjson` entries (one benign, one with
        // tampered bytes) cannot silently overwrite the first.
        if out.contains_key(required) {
            return Err(ReverifyError::DuplicateEntry(required));
        }
        out.insert(required.to_string(), buf);
    }
    Ok(out)
}

/// Validate that `bytes` is exactly 64 lowercase hex chars (no
/// trailing newline), and return them as a `String`.
fn parse_root_hex(bytes: &[u8]) -> Result<String, ReverifyError> {
    let s = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return Err(ReverifyError::MalformedRoot("<non-utf8>".to_string())),
    };
    if s.len() != 64
        || !s
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Err(ReverifyError::MalformedRoot(s.to_string()));
    }
    Ok(s.to_string())
}

/// Walk `receipts_bytes` line by line and run each receipt through the
/// kernel verifier. Returns `(total, signature_failed, unsigned)`.
///
/// Stub-shape receipts (no signature field) deserialize-fail and are
/// counted as `unsigned`, NOT as a signature failure.
fn verify_receipts(receipts_bytes: &[u8]) -> (usize, usize, usize) {
    let mut total = 0usize;
    let mut sig_fail = 0usize;
    let mut unsigned = 0usize;
    for line in receipts_bytes.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        total += 1;
        let receipt: ChioReceipt = match serde_json::from_slice(line) {
            Ok(r) => r,
            Err(_) => {
                // Stub-shape receipt (current goldens). No signature
                // to verify; record and move on.
                unsigned += 1;
                continue;
            }
        };
        match receipt.verify_signature() {
            Ok(true) => {}
            Ok(false) | Err(_) => sig_fail += 1,
        }
    }
    (total, sig_fail, unsigned)
}

/// Recompute the synthetic root over `(receipts_bytes || checkpoint_bytes)`.
///
/// Matches the derivation used by `tests/replay/tests/corpus_smoke.rs`:
/// `SHA-256(receipts || checkpoint)` over the on-disk byte streams.
/// Operating on the bytes directly (rather than re-canonicalizing JSON)
/// is the load-bearing decision: the gate's invariant is that the
/// goldens are byte-stable, so the verifier reads the same bytes the
/// writer emitted without any re-serialization round-trip.
fn recompute_root_hex(receipts_bytes: &[u8], checkpoint_bytes: &[u8]) -> String {
    // The corpus_smoke driver hashes single-receipt scenarios as
    // `serde_json::to_vec(receipt) || serde_json::to_vec(checkpoint)`.
    // The on-disk receipts.ndjson appends a `\n` after each receipt
    // line, but the synthetic root is computed before that LF is
    // added. Strip the trailing LF (if any) before hashing so a
    // single-receipt bundle's recomputed root matches the writer's
    // output. Multi-receipt bundles will not (yet) match this exact
    // derivation; they are treated as `root_match == false` and that
    // surface is documented in the integration test.
    let receipts_no_trailing_lf = strip_trailing_lf(receipts_bytes);
    let mut hasher = Sha256::new();
    hasher.update(receipts_no_trailing_lf);
    hasher.update(checkpoint_bytes);
    hex::encode(hasher.finalize())
}

/// Drop a single trailing `\n` byte if present. Used to align the
/// in-memory bytes with the synthetic-root derivation in
/// `corpus_smoke.rs`.
fn strip_trailing_lf(bytes: &[u8]) -> &[u8] {
    if bytes.last() == Some(&b'\n') {
        &bytes[..bytes.len() - 1]
    } else {
        bytes
    }
}

#[cfg(test)]
mod reverify_tests {
    //! Unit tests construct synthetic .tgz bundles in-process. No live
    //! network and no on-disk goldens are touched, so this module runs
    //! under the default `cargo test` invocation. `unwrap`/`expect`
    //! allowed inside `#[cfg(test)]` (matches the established pattern
    //! in `loader_tests`, `fetch_tests`, and `driver::tests`).
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::cross_version::fetch::{sha256_of_bytes, FetchedBundle};
    use crate::cross_version::CompatLevel;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tempfile::TempDir;

    /// Minimal CompatEntry tuned for tests. URL/sha are placeholders
    /// because reverify never re-fetches; it operates on a
    /// pre-fetched bundle.
    fn entry_for(tag: &str, compat: CompatLevel) -> CompatEntry {
        CompatEntry {
            tag: tag.to_string(),
            released_at: "2025-01-01".to_string(),
            bundle_url: format!("https://example.invalid/{tag}.tgz"),
            bundle_sha256: "0".repeat(64),
            compat,
            supported_until: None,
            notes: String::new(),
        }
    }

    /// Pack the three named entries into a gzip-framed tarball at
    /// `path`. Each `(name, bytes)` pair becomes one tar entry rooted
    /// at `replay-bundle/<name>` (matches the layout the
    /// release-tagged.yml workflow will produce).
    fn write_synthetic_bundle(path: &Path, files: &[(&str, &[u8])]) {
        let file = std::fs::File::create(path).unwrap();
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for (name, bytes) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            let entry_path = format!("replay-bundle/{name}");
            builder
                .append_data(&mut header, &entry_path, *bytes)
                .unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
    }

    /// Build a `FetchedBundle` over a freshly-written synthetic bundle.
    fn synthetic_bundle(td: &TempDir, tag: &str, files: &[(&str, &[u8])]) -> FetchedBundle {
        let path = td.path().join(format!("{tag}.tgz"));
        write_synthetic_bundle(&path, files);
        let bytes = std::fs::read(&path).unwrap();
        FetchedBundle {
            tag: tag.to_string(),
            path,
            sha256: sha256_of_bytes(&bytes),
        }
    }

    /// Build a single-receipt golden's three files, with a synthetic
    /// root derived to match the writer's `corpus_smoke` scheme.
    fn make_stub_golden(scenario: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let receipt = serde_json::json!({
            "scenario": scenario,
            "verdict": "allow",
            "nonce": "00112233445566778899aabbccddeeff",
        });
        let checkpoint = serde_json::json!({
            "scenario": scenario,
            "clock": "2026-01-01T00:00:00Z",
            "issuer": "deadbeef",
        });
        let receipt_bytes = serde_json::to_vec(&receipt).unwrap();
        let checkpoint_bytes = serde_json::to_vec(&checkpoint).unwrap();

        // receipts.ndjson is the raw receipt + LF terminator.
        let mut receipts_ndjson = Vec::new();
        receipts_ndjson.extend_from_slice(&receipt_bytes);
        receipts_ndjson.push(b'\n');

        // Synthetic root: SHA-256(receipt_bytes || checkpoint_bytes).
        let mut hasher = Sha256::new();
        hasher.update(&receipt_bytes);
        hasher.update(&checkpoint_bytes);
        let root_hex = hex::encode(hasher.finalize());

        (receipts_ndjson, checkpoint_bytes, root_hex.into_bytes())
    }

    #[test]
    fn happy_path_stub_receipt_root_matches() {
        let td = TempDir::new().unwrap();
        let (receipts, checkpoint, root) = make_stub_golden("allow_simple/01_basic_capability");
        let bundle = synthetic_bundle(
            &td,
            "v0.1.0",
            &[
                (RECEIPTS_FILENAME, &receipts),
                (CHECKPOINT_FILENAME, &checkpoint),
                (ROOT_FILENAME, &root),
            ],
        );
        let entry = entry_for("v0.1.0", CompatLevel::BestEffort);
        let report = reverify_bundle(&bundle, &entry).expect("reverify must succeed");

        assert_eq!(report.tag, "v0.1.0");
        assert_eq!(report.compat, CompatLevel::BestEffort);
        assert_eq!(report.receipts_total, 1);
        // Stub receipts have no signature; they go to `unsigned`, not
        // `signature_failed`.
        assert_eq!(report.receipts_signature_failed, 0);
        assert_eq!(report.receipts_unsigned, 1);
        assert!(report.root_match, "synthetic-root match must hold");
        assert_eq!(report.recomputed_root_hex.len(), 64);
        assert_eq!(report.bundle_root_hex.len(), 64);
    }

    #[test]
    fn missing_receipts_entry_rejected() {
        let td = TempDir::new().unwrap();
        let (_receipts, checkpoint, root) = make_stub_golden("x");
        let bundle = synthetic_bundle(
            &td,
            "v0.1.0",
            &[(CHECKPOINT_FILENAME, &checkpoint), (ROOT_FILENAME, &root)],
        );
        let entry = entry_for("v0.1.0", CompatLevel::BestEffort);
        let err = reverify_bundle(&bundle, &entry).expect_err("missing receipts must fail");
        assert!(
            matches!(err, ReverifyError::MissingEntry(name) if name == RECEIPTS_FILENAME),
            "expected MissingEntry(receipts.ndjson), got {err:?}"
        );
    }

    #[test]
    fn missing_checkpoint_entry_rejected() {
        let td = TempDir::new().unwrap();
        let (receipts, _checkpoint, root) = make_stub_golden("x");
        let bundle = synthetic_bundle(
            &td,
            "v0.1.0",
            &[(RECEIPTS_FILENAME, &receipts), (ROOT_FILENAME, &root)],
        );
        let entry = entry_for("v0.1.0", CompatLevel::BestEffort);
        let err = reverify_bundle(&bundle, &entry).expect_err("missing checkpoint must fail");
        assert!(
            matches!(err, ReverifyError::MissingEntry(name) if name == CHECKPOINT_FILENAME),
            "expected MissingEntry(checkpoint.json), got {err:?}"
        );
    }

    #[test]
    fn missing_root_entry_rejected() {
        let td = TempDir::new().unwrap();
        let (receipts, checkpoint, _root) = make_stub_golden("x");
        let bundle = synthetic_bundle(
            &td,
            "v0.1.0",
            &[
                (RECEIPTS_FILENAME, &receipts),
                (CHECKPOINT_FILENAME, &checkpoint),
            ],
        );
        let entry = entry_for("v0.1.0", CompatLevel::BestEffort);
        let err = reverify_bundle(&bundle, &entry).expect_err("missing root must fail");
        assert!(
            matches!(err, ReverifyError::MissingEntry(name) if name == ROOT_FILENAME),
            "expected MissingEntry(root.hex), got {err:?}"
        );
    }

    #[test]
    fn malformed_root_too_short_rejected() {
        let td = TempDir::new().unwrap();
        let (receipts, checkpoint, _root) = make_stub_golden("x");
        let bundle = synthetic_bundle(
            &td,
            "v0.1.0",
            &[
                (RECEIPTS_FILENAME, &receipts),
                (CHECKPOINT_FILENAME, &checkpoint),
                (ROOT_FILENAME, b"deadbeef"),
            ],
        );
        let entry = entry_for("v0.1.0", CompatLevel::BestEffort);
        let err = reverify_bundle(&bundle, &entry).expect_err("short root must fail");
        assert!(
            matches!(&err, ReverifyError::MalformedRoot(s) if s == "deadbeef"),
            "expected MalformedRoot(deadbeef), got {err:?}"
        );
    }

    #[test]
    fn malformed_root_uppercase_hex_rejected() {
        let td = TempDir::new().unwrap();
        let (receipts, checkpoint, _root) = make_stub_golden("x");
        let upper = "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";
        let bundle = synthetic_bundle(
            &td,
            "v0.1.0",
            &[
                (RECEIPTS_FILENAME, &receipts),
                (CHECKPOINT_FILENAME, &checkpoint),
                (ROOT_FILENAME, upper.as_bytes()),
            ],
        );
        let entry = entry_for("v0.1.0", CompatLevel::BestEffort);
        let err = reverify_bundle(&bundle, &entry).expect_err("uppercase hex must fail");
        assert!(
            matches!(err, ReverifyError::MalformedRoot(_)),
            "expected MalformedRoot, got {err:?}"
        );
    }

    #[test]
    fn root_mismatch_surfaces_root_match_false() {
        let td = TempDir::new().unwrap();
        let (receipts, checkpoint, _real_root) = make_stub_golden("x");
        // Pin a deliberately wrong root.
        let wrong_root = "0".repeat(64);
        let bundle = synthetic_bundle(
            &td,
            "v0.1.0",
            &[
                (RECEIPTS_FILENAME, &receipts),
                (CHECKPOINT_FILENAME, &checkpoint),
                (ROOT_FILENAME, wrong_root.as_bytes()),
            ],
        );
        let entry = entry_for("v0.1.0", CompatLevel::BestEffort);
        let report = reverify_bundle(&bundle, &entry).expect("structural reverify must succeed");
        assert!(
            !report.root_match,
            "wrong root must surface root_match=false"
        );
        assert_eq!(report.bundle_root_hex, wrong_root);
        assert_ne!(report.recomputed_root_hex, wrong_root);
    }

    #[test]
    fn unreadable_archive_surfaces_archive_error() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("not-a-tarball.tgz");
        std::fs::write(&path, b"this is not gzip").unwrap();
        let bundle = FetchedBundle {
            tag: "v0.1.0".to_string(),
            path,
            sha256: "0".repeat(64),
        };
        let entry = entry_for("v0.1.0", CompatLevel::BestEffort);
        let err =
            reverify_bundle(&bundle, &entry).expect_err("non-gzip bytes must fail at archive open");
        assert!(
            matches!(err, ReverifyError::Archive(_)),
            "expected Archive(_), got {err:?}"
        );
    }

    #[test]
    fn entries_outside_known_set_are_ignored() {
        let td = TempDir::new().unwrap();
        let (receipts, checkpoint, root) = make_stub_golden("x");
        // Add a release-engineering metadata file that the harness
        // must silently skip.
        let bundle = synthetic_bundle(
            &td,
            "v0.1.0",
            &[
                (RECEIPTS_FILENAME, &receipts),
                (CHECKPOINT_FILENAME, &checkpoint),
                (ROOT_FILENAME, &root),
                ("README.txt", b"release notes; not parsed by reverify"),
                ("manifest.toml", b"# build provenance metadata"),
            ],
        );
        let entry = entry_for("v0.1.0", CompatLevel::BestEffort);
        let report = reverify_bundle(&bundle, &entry).expect("extra entries must not fail");
        assert!(report.root_match);
        assert_eq!(report.receipts_total, 1);
    }

    #[test]
    fn empty_receipts_file_yields_zero_total() {
        let td = TempDir::new().unwrap();
        let (_receipts, checkpoint, _root) = make_stub_golden("x");
        let mut hasher = Sha256::new();
        hasher.update(&checkpoint);
        let root_hex = hex::encode(hasher.finalize()).into_bytes();
        let bundle = synthetic_bundle(
            &td,
            "v0.1.0",
            &[
                (RECEIPTS_FILENAME, b""),
                (CHECKPOINT_FILENAME, &checkpoint),
                (ROOT_FILENAME, &root_hex),
            ],
        );
        let entry = entry_for("v0.1.0", CompatLevel::BestEffort);
        let report = reverify_bundle(&bundle, &entry).expect("empty receipts must reverify");
        assert_eq!(report.receipts_total, 0);
        assert_eq!(report.receipts_signature_failed, 0);
        assert_eq!(report.receipts_unsigned, 0);
        assert!(report.root_match, "empty-receipts root must still match");
    }

    #[test]
    fn parse_root_hex_helper_rejects_non_utf8() {
        let bad: &[u8] = &[0xff, 0xfe, 0xfd];
        let err = parse_root_hex(bad).expect_err("non-utf8 must fail");
        assert!(matches!(err, ReverifyError::MalformedRoot(_)));
    }

    #[test]
    fn parse_root_hex_helper_accepts_canonical_shape() {
        let good = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let got = parse_root_hex(good.as_bytes()).expect("canonical hex must parse");
        assert_eq!(got, good);
    }

    #[test]
    fn strip_trailing_lf_handles_present_and_absent() {
        assert_eq!(strip_trailing_lf(b"abc\n"), b"abc");
        assert_eq!(strip_trailing_lf(b"abc"), b"abc");
        assert_eq!(strip_trailing_lf(b""), b"");
        assert_eq!(strip_trailing_lf(b"\n"), b"");
    }

    #[test]
    fn flat_layout_bundle_also_resolved() {
        // A bundle whose entries live at the tarball root (no
        // `replay-bundle/` prefix). Resolve by basename means both
        // layouts work.
        let td = TempDir::new().unwrap();
        let (receipts, checkpoint, root) = make_stub_golden("x");
        let path = td.path().join("flat.tgz");
        let file = std::fs::File::create(&path).unwrap();
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for (name, bytes) in [
            (RECEIPTS_FILENAME, &receipts[..]),
            (CHECKPOINT_FILENAME, &checkpoint[..]),
            (ROOT_FILENAME, &root[..]),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            // Note: no `replay-bundle/` prefix.
            builder.append_data(&mut header, name, bytes).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();

        let bytes = std::fs::read(&path).unwrap();
        let bundle = FetchedBundle {
            tag: "v0.1.0".to_string(),
            path,
            sha256: sha256_of_bytes(&bytes),
        };
        let entry = entry_for("v0.1.0", CompatLevel::BestEffort);
        let report = reverify_bundle(&bundle, &entry).expect("flat layout must reverify");
        assert!(report.root_match);
        assert_eq!(report.receipts_total, 1);
    }

    /// Bundles MUST contain each required basename exactly once. A
    /// duplicate `receipts.ndjson` entry (one benign, one with tampered
    /// bytes) must be rejected up front so the second copy cannot
    /// silently overwrite the first inside the extractor's HashMap.
    #[test]
    fn duplicate_receipts_entry_rejected() {
        let td = TempDir::new().unwrap();
        let (receipts, checkpoint, root) = make_stub_golden("dup_receipts");
        // Second receipts payload carries different bytes than the first
        // so an overwrite would be observable as a verifier-state shift.
        let evil_receipts = b"{\"scenario\":\"tampered\",\"verdict\":\"allow\",\"nonce\":\"00\"}\n";
        let bundle = synthetic_bundle(
            &td,
            "v0.1.0",
            &[
                (RECEIPTS_FILENAME, &receipts),
                (CHECKPOINT_FILENAME, &checkpoint),
                (ROOT_FILENAME, &root),
                (RECEIPTS_FILENAME, evil_receipts.as_slice()),
            ],
        );
        let entry = entry_for("v0.1.0", CompatLevel::Supported);
        let err = reverify_bundle(&bundle, &entry).expect_err("duplicate basename must reject");
        assert!(
            matches!(err, ReverifyError::DuplicateEntry(name) if name == RECEIPTS_FILENAME),
            "expected DuplicateEntry(receipts.ndjson), got {err:?}"
        );
    }

    /// Same protection for `checkpoint.json` and `root.hex`: a duplicate
    /// must surface as a structural-integrity error, not a silent
    /// overwrite.
    #[test]
    fn duplicate_root_entry_rejected() {
        let td = TempDir::new().unwrap();
        let (receipts, checkpoint, root) = make_stub_golden("dup_root");
        let evil_root = b"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let bundle = synthetic_bundle(
            &td,
            "v0.1.0",
            &[
                (RECEIPTS_FILENAME, &receipts),
                (CHECKPOINT_FILENAME, &checkpoint),
                (ROOT_FILENAME, &root),
                (ROOT_FILENAME, evil_root.as_slice()),
            ],
        );
        let entry = entry_for("v0.1.0", CompatLevel::Supported);
        let err = reverify_bundle(&bundle, &entry).expect_err("duplicate root must reject");
        assert!(
            matches!(err, ReverifyError::DuplicateEntry(name) if name == ROOT_FILENAME),
            "expected DuplicateEntry(root.hex), got {err:?}"
        );
    }
}
