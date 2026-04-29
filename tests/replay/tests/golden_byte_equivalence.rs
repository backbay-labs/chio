//! Golden byte-equivalence test for the replay-gate corpus.
//!
//! For each of the 50 scenarios under `tests/replay/fixtures/`, this test
//! reproduces the synthesis flow that the initial bless used (driver +
//! canonical-JSON receipt / checkpoint + SHA-256 synthetic root) in a
//! `TempDir`, then loads those bytes back as raw `Vec<u8>` and diffs them
//! byte-for-byte against the on-disk blessed goldens.
//!
//! The synthesis recipe MUST stay byte-identical with the bless flow. Any
//! change here is a re-bless event: see `docs/replay-compat.md` and the
//! `CHIO_BLESS` rules.
//!
//! # Determinism guarantees this test exercises
//!
//! - `LC_ALL=C` directory-listing order via [`fs_iter::walk_files_sorted`].
//! - Fixed clock + counter-only nonce + Ed25519 deterministic-by-spec
//!   signing via [`ScenarioDriver`].
//! - Canonical-JSON object-key sort and LF-only NDJSON terminator
//!   guaranteed by the writer in [`golden_writer::GoldenSet`].

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use chio_replay_gate::byte_compare::{compare_artifacts, ArtifactKind, ByteDiff};
use chio_replay_gate::driver::ScenarioDriver;
use chio_replay_gate::fs_iter;
use chio_replay_gate::golden_format;
use chio_replay_gate::golden_reader::GoldenLoaded;
use chio_replay_gate::golden_writer::GoldenSet;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

/// Total fixture count expected under `tests/replay/fixtures/` and
/// `tests/replay/goldens/`.
const EXPECTED_FIXTURE_COUNT: usize = 50;

#[test]
fn all_50_goldens_match_byte_for_byte() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let fixtures_root = Path::new(manifest_dir).join("fixtures");
    let goldens_root = Path::new(manifest_dir).join("goldens");

    assert!(
        goldens_root.is_dir(),
        "goldens root {} does not exist; run the bless flow first",
        goldens_root.display(),
    );

    let manifests = enumerate_manifests(&fixtures_root);
    assert_eq!(
        manifests.len(),
        EXPECTED_FIXTURE_COUNT,
        "expected {} manifests, found {}",
        EXPECTED_FIXTURE_COUNT,
        manifests.len(),
    );

    let staging = TempDir::new().expect("tempdir for synthetic candidates must succeed");

    let mut diffs_total: usize = 0;
    let mut scenarios_with_diffs: Vec<String> = Vec::new();

    for manifest_path in &manifests {
        let manifest = load_manifest(manifest_path);
        let family = require_str(&manifest, "family", manifest_path);
        let scenario_name = require_str(&manifest, "name", manifest_path);
        let scenario_leaf = scenario_name
            .rsplit('/')
            .next()
            .unwrap_or(scenario_name.as_str())
            .to_string();

        // Candidate goldens: regenerated into a TempDir, never touching
        // the on-disk corpus.
        let candidate_dir = staging.path().join(&family).join(&scenario_leaf);
        write_synthetic_goldens(&manifest, manifest_path, &candidate_dir);
        let candidate = GoldenLoaded::load(&candidate_dir).unwrap_or_else(|err| {
            panic!(
                "failed to load freshly-synthesized candidate goldens at {}: {err}",
                candidate_dir.display()
            )
        });

        // Expected goldens: loaded straight off disk. Any tampering
        // surfaces as a contract-violation error from `GoldenLoaded::load`
        // (root.hex shape, NDJSON terminator, non-empty checkpoint).
        let expected_dir = goldens_root.join(&family).join(&scenario_leaf);
        let expected = GoldenLoaded::load(&expected_dir).unwrap_or_else(|err| {
            panic!(
                "failed to load blessed goldens at {}: {err}",
                expected_dir.display()
            )
        });

        // Pure raw-byte compare. No serde round-trip, by design.
        let scenario_diffs = compare_artifacts(
            &expected,
            &candidate.receipts,
            &candidate.checkpoint,
            &candidate.root_hex,
        );
        if !scenario_diffs.is_empty() {
            diffs_total = diffs_total.saturating_add(scenario_diffs.len());
            scenarios_with_diffs.push(format!("{}/{}", family, scenario_leaf));
            for diff in &scenario_diffs {
                eprintln!(
                    "DIFF in {}/{}: {}",
                    family,
                    scenario_leaf,
                    render_diff(diff)
                );
            }
        }
    }

    assert!(
        diffs_total == 0,
        "byte-equivalence gate failed: {} diff(s) across {} scenario(s) ({:?})",
        diffs_total,
        scenarios_with_diffs.len(),
        scenarios_with_diffs,
    );

    println!(
        "byte-equivalence: {} scenarios match the blessed goldens byte-for-byte",
        manifests.len(),
    );
}

/// Reproduce the bless-time synthesis recipe into `scenario_dir`.
///
/// MUST stay in sync with the recipe used by the bless flow:
///
/// - `receipt = { scenario, verdict, nonce }` where `nonce` is the
///   first call to `ScenarioDriver::next_nonce()` rendered as lowercase hex.
/// - `checkpoint = { scenario, clock, issuer }` where `issuer` is the
///   verifying-key bytes of the test seed rendered as lowercase hex.
/// - `root = SHA-256(canonical(receipt) || canonical(checkpoint))` via
///   [`golden_format::canonical_json_bytes`].
/// - All manifest fields used by the synthesis (`name`, `expected_verdict`,
///   `clock`) are required-string-typed via [`require_str`].
fn write_synthetic_goldens(manifest: &Value, manifest_path: &Path, scenario_dir: &Path) {
    let mut driver = ScenarioDriver::new().unwrap_or_else(|err| {
        panic!(
            "driver init failed: {err} (manifest {})",
            manifest_path.display()
        )
    });

    let scenario_name = require_str(manifest, "name", manifest_path);
    let expected_verdict = require_str(manifest, "expected_verdict", manifest_path);
    let clock = require_str(manifest, "clock", manifest_path);
    let seed_index = require_u64(manifest, "fixed_nonce_seed_index", manifest_path);

    // Advance the driver's nonce counter so the bless-time nonce for
    // this scenario uniquely tracks the manifest's
    // `fixed_nonce_seed_index`. Each `next_nonce()` call increments the
    // counter by exactly 1 (see `ScenarioDriver::next_nonce`), so
    // calling it `seed_index` times before the load-bearing call lines
    // counter == seed_index for the recorded nonce. This keeps the 50
    // synthetic goldens distinct in the `nonce` field rather than
    // collapsing to counter-zero across all of them.
    for _ in 0..seed_index {
        let _ = driver.next_nonce();
    }

    let nonce = driver.next_nonce();
    let nonce_hex = hex::encode(nonce);
    let issuer_hex = hex::encode(driver.verifying_key().to_bytes());

    let receipt = json!({
        "scenario": scenario_name,
        "verdict": expected_verdict,
        "nonce": nonce_hex,
    });
    let checkpoint = json!({
        "scenario": scenario_name,
        "clock": clock,
        "issuer": issuer_hex,
    });

    // Canonicalize the receipt and checkpoint via the workspace-wide
    // RFC 8785 serializer before hashing. This makes the SHA-256
    // root deterministic under any serde_json key-order policy: the
    // canonicaliser sorts keys itself rather than relying on
    // serde_json's preserve-or-not-preserve insertion order.
    let receipt_bytes =
        golden_format::canonical_json_bytes(&receipt).expect("synthetic receipt must canonicalize");
    let checkpoint_bytes = golden_format::canonical_json_bytes(&checkpoint)
        .expect("synthetic checkpoint must canonicalize");
    let mut hasher = Sha256::new();
    hasher.update(&receipt_bytes);
    hasher.update(&checkpoint_bytes);
    let digest = hasher.finalize();
    let mut root = [0u8; 32];
    root.copy_from_slice(&digest);

    let mut set = GoldenSet::new(scenario_dir);
    set.append_receipt(&receipt)
        .unwrap_or_else(|err| panic!("append_receipt failed: {err}"));
    set.set_checkpoint(&checkpoint)
        .unwrap_or_else(|err| panic!("set_checkpoint failed: {err}"));
    set.set_root(root);
    set.commit()
        .unwrap_or_else(|err| panic!("commit failed: {err}"));
}

/// Recursively enumerate every `.json` manifest under `root`, sorted in
/// `LC_ALL=C` byte order. Delegates to
/// [`fs_iter::walk_files_sorted`] (T7) so this test and any future
/// scenario loader use the same canonicalization. Symlinks and special
/// files are filtered out fail-closed by the walker.
fn enumerate_manifests(root: &Path) -> Vec<PathBuf> {
    fs_iter::walk_files_sorted(root, |p| {
        p.extension()
            .and_then(|s| s.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("json"))
            .unwrap_or(false)
    })
    .unwrap_or_else(|err| {
        panic!(
            "failed to enumerate manifests under {}: {err}",
            root.display()
        )
    })
}

/// Read and parse a manifest as a `serde_json::Value`. Panics with a
/// path-tagged message on any failure.
fn load_manifest(path: &Path) -> Value {
    let bytes = fs::read(path)
        .unwrap_or_else(|err| panic!("read manifest {} failed: {err}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|err| panic!("parse manifest {} failed: {err}", path.display()))
}

/// Pull a required `&str` field out of a manifest, panicking with a
/// path-tagged message if absent or non-string.
fn require_str(manifest: &Value, key: &str, path: &Path) -> String {
    manifest
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!(
                "manifest {} missing required string key {key:?}",
                path.display()
            )
        })
        .to_string()
}

/// Pull a required non-negative integer field out of a manifest.
///
/// Panics with a path-tagged message if absent, non-numeric, or not
/// representable as `u64`. Used by [`write_synthetic_goldens`] to read
/// `fixed_nonce_seed_index`, which must drive the bless-time nonce
/// counter so each of the 50 scenarios records a distinct nonce in its
/// receipt rather than counter-zero across the corpus.
fn require_u64(manifest: &Value, key: &str, path: &Path) -> u64 {
    manifest
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| {
            panic!(
                "manifest {} missing required u64 key {key:?}",
                path.display()
            )
        })
}

/// Pretty-print a [`ByteDiff::Different`] for the failure surface.
fn render_diff(diff: &ByteDiff) -> String {
    match diff {
        ByteDiff::Equal => "Equal".to_string(),
        ByteDiff::Different {
            kind,
            expected_len,
            actual_len,
            first_diff_offset,
            expected_window,
            actual_window,
        } => format!(
            "kind={} expected_len={} actual_len={} first_diff_offset={} \
             expected_window={:?} actual_window={:?}",
            kind_label(*kind),
            expected_len,
            actual_len,
            first_diff_offset,
            String::from_utf8_lossy(expected_window),
            String::from_utf8_lossy(actual_window),
        ),
    }
}

fn kind_label(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::Receipts => "receipts.ndjson",
        ArtifactKind::Checkpoint => "checkpoint.json",
        ArtifactKind::RootHex => "root.hex",
    }
}
