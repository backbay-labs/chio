//! Corpus smoke test: enumerate every fixture manifest, drive it through a
//! no-op scenario runner, and verify each one produces a non-empty goldens
//! tree without panicking.
//!
//! # Invariants asserted here
//!
//! - Exactly 50 `.json` manifests live under `tests/replay/fixtures/`.
//! - Per-family counts match expected numbers.
//! - The `fixed_nonce_seed_index` values across all 50 manifests form
//!   the contiguous set `0..50` (no duplicates, no gaps).
//! - Every manifest exposes the required keys (`schema_version`,
//!   `name`, `family`, `expected_verdict`, `fixed_nonce_seed_index`).
//! - For every manifest, a fresh `ScenarioDriver` plus a synthetic
//!   `GoldenSet` round-trip writes one receipt + checkpoint + 32-byte
//!   root to disk with sizes consistent with the writer's invariants
//!   (root.hex == 64 bytes, checkpoint > 0, receipts > 0).
//!
//! Recursion delegates to [`chio_replay_gate::fs_iter::walk_files_sorted`]
//! so this test and any future Scenario-loader code share a single canonical
//! `LC_ALL=C`-equivalent byte-order enumerator. Symbolic links are filtered
//! out fail-closed during recursion.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use chio_replay_gate::driver::ScenarioDriver;
use chio_replay_gate::fs_iter;
use chio_replay_gate::golden_writer::{GoldenSet, GoldenSetSummary};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

/// Total fixture count expected under `tests/replay/fixtures/`.
const EXPECTED_FIXTURE_COUNT: usize = 50;

/// Per-family fixture counts. Sorted alphabetically by family name to match
/// the on-disk directory listing order.
const EXPECTED_FAMILY_COUNTS: &[(&str, usize)] = &[
    ("allow_metered", 5),
    ("allow_simple", 8),
    ("allow_with_delegation", 6),
    ("deny_expired", 5),
    ("deny_revoked", 4),
    ("deny_scope_mismatch", 6),
    ("guard_rewrite", 6),
    ("replay_attack", 4),
    ("tampered_canonical_json", 3),
    ("tampered_signature", 3),
];

/// Required top-level keys on every manifest. Missing any of these is a
/// hard failure: the M04 gate refuses to run a corpus with an
/// underspecified manifest, and the smoke test enforces the contract.
const REQUIRED_MANIFEST_KEYS: &[&str] = &[
    "schema_version",
    "name",
    "family",
    "expected_verdict",
    "fixed_nonce_seed_index",
];

#[test]
fn all_50_fixtures_load_and_run() {
    let fixtures_root = fixtures_root();
    let manifests = enumerate_manifests(&fixtures_root);

    // 1. Total count.
    assert_eq!(
        manifests.len(),
        EXPECTED_FIXTURE_COUNT,
        "expected {} fixture manifests under {}, got {}",
        EXPECTED_FIXTURE_COUNT,
        fixtures_root.display(),
        manifests.len(),
    );

    // 2. Per-family counts.
    let family_counts = count_by_family(&manifests);
    let expected_map: BTreeMap<&str, usize> = EXPECTED_FAMILY_COUNTS.iter().copied().collect();
    assert_eq!(
        family_counts, expected_map,
        "per-family fixture counts diverge from expected",
    );
    println!("per-family fixture counts: {family_counts:?}");

    // 3. Drive every scenario through the writer round-trip into one
    //    shared TempDir. Track the seed-index set as we go.
    let goldens_root = TempDir::new().expect("tempdir for synthetic goldens must succeed");
    let mut seed_indices: BTreeSet<u64> = BTreeSet::new();

    for manifest_path in &manifests {
        let manifest = load_manifest(manifest_path);

        // Required-key contract.
        for key in REQUIRED_MANIFEST_KEYS {
            assert!(
                manifest.get(*key).is_some(),
                "manifest {} is missing required key {:?}",
                manifest_path.display(),
                key,
            );
        }

        let family = manifest
            .get("family")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                panic!(
                    "manifest {} has non-string `family`",
                    manifest_path.display()
                )
            })
            .to_string();
        let scenario_name = manifest
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("manifest {} has non-string `name`", manifest_path.display()))
            .to_string();
        let seed_index = manifest
            .get("fixed_nonce_seed_index")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| {
                panic!(
                    "manifest {} has non-u64 `fixed_nonce_seed_index`",
                    manifest_path.display()
                )
            });

        // Track for the post-loop uniqueness assertion. Duplicate slots
        // would silently collapse two scenarios onto the same nonce
        // counter origin, so reject up front.
        let inserted = seed_indices.insert(seed_index);
        assert!(
            inserted,
            "manifest {} reuses fixed_nonce_seed_index={} already taken by another fixture",
            manifest_path.display(),
            seed_index,
        );

        // Per-scenario goldens directory (mirrors the on-disk layout
        // the writer expects: <root>/<family>/<scenario_leaf>/).
        let scenario_leaf = scenario_name
            .rsplit('/')
            .next()
            .unwrap_or(scenario_name.as_str());
        let scenario_dir = goldens_root.path().join(&family).join(scenario_leaf);

        let summary = run_scenario(&manifest, manifest_path, &scenario_dir);

        // Writer-output sanity checks. These are not byte-equivalence
        // (Phase 2's job) but they catch any silent regression in the
        // staging / commit dance that would otherwise let a Phase-2
        // gate run with empty or malformed goldens.
        assert!(
            summary.receipt_count >= 1,
            "scenario {} produced no receipts",
            scenario_name,
        );
        assert!(
            summary.byte_sizes.receipts > 0,
            "scenario {} wrote a zero-byte receipts.ndjson",
            scenario_name,
        );
        assert!(
            summary.byte_sizes.checkpoint > 0,
            "scenario {} wrote a zero-byte checkpoint.json",
            scenario_name,
        );
        assert_eq!(
            summary.byte_sizes.root, 64,
            "scenario {} wrote a root.hex with {} bytes (must be exactly 64)",
            scenario_name, summary.byte_sizes.root,
        );
    }

    // 4. The 50 fixed_nonce_seed_index values must form the contiguous
    //    set 0..50.
    let expected: BTreeSet<u64> = (0..EXPECTED_FIXTURE_COUNT as u64).collect();
    assert_eq!(
        seed_indices, expected,
        "fixed_nonce_seed_index values must form the set 0..{}",
        EXPECTED_FIXTURE_COUNT,
    );

    println!(
        "corpus_smoke: enumerated {} manifests across {} families; \
         all per-scenario writer round-trips succeeded; \
         fixed_nonce_seed_index set == 0..{}",
        manifests.len(),
        EXPECTED_FAMILY_COUNTS.len(),
        EXPECTED_FIXTURE_COUNT,
    );
}

/// Run a single scenario through a fresh `ScenarioDriver` plus `GoldenSet`.
/// Synthetic receipts / checkpoint / root only.
fn run_scenario(manifest: &Value, manifest_path: &Path, scenario_dir: &Path) -> GoldenSetSummary {
    let mut driver = ScenarioDriver::new().unwrap_or_else(|err| {
        panic!(
            "ScenarioDriver::new failed while running manifest {}: {err}",
            manifest_path.display()
        )
    });

    let scenario_name = manifest
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let expected_verdict = manifest
        .get("expected_verdict")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let clock = manifest
        .get("clock")
        .and_then(Value::as_str)
        .unwrap_or("unknown");

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

    // Synthetic root: SHA-256 of canonical-JSON(receipt) ||
    // canonical-JSON(checkpoint). Uses serde_json's default (no
    // insignificant whitespace) which matches the writer's on-disk
    // bytes, so the synthetic root is reproducible across runs without
    // having to re-canonicalize here.
    let receipt_bytes = serde_json::to_vec(&receipt).expect("synthetic receipt must serialize");
    let checkpoint_bytes =
        serde_json::to_vec(&checkpoint).expect("synthetic checkpoint must serialize");
    let mut hasher = Sha256::new();
    hasher.update(&receipt_bytes);
    hasher.update(&checkpoint_bytes);
    let digest = hasher.finalize();
    let mut root = [0u8; 32];
    root.copy_from_slice(&digest);

    let mut set = GoldenSet::new(scenario_dir);
    set.append_receipt(&receipt).unwrap_or_else(|err| {
        panic!(
            "append_receipt failed for manifest {}: {err}",
            manifest_path.display()
        )
    });
    set.set_checkpoint(&checkpoint).unwrap_or_else(|err| {
        panic!(
            "set_checkpoint failed for manifest {}: {err}",
            manifest_path.display()
        )
    });
    set.set_root(root);

    set.commit().unwrap_or_else(|err| {
        panic!(
            "commit failed for manifest {}: {err}",
            manifest_path.display()
        )
    })
}

/// Resolves the absolute path to the `tests/replay/fixtures/`
/// directory. `CARGO_MANIFEST_DIR` is `tests/replay/` for this crate,
/// so the corpus lives one directory level down.
fn fixtures_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir).join("fixtures")
}

/// Recursively enumerate every `.json` manifest under `root`, sorted
/// lexicographically by raw byte order. Delegates to
/// [`fs_iter::walk_files_sorted`] (T7) so this test and any future
/// Scenario-loader code use the same canonicalization. Symlinks and
/// special files are filtered out fail-closed by the walker.
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

/// Group manifest paths by their parent directory leaf, which is the
/// fixture family name. Returns a sorted map (BTreeMap) so the
/// assertion comparison is order-stable.
fn count_by_family(manifests: &[PathBuf]) -> BTreeMap<&'static str, usize> {
    // We can't return a BTreeMap<&Path, usize> because the family
    // strings come from the manifest file names. Match against the
    // canonical EXPECTED_FAMILY_COUNTS keys so unexpected directories
    // are surfaced as a missing-key assertion rather than silently
    // counted into a new bucket.
    let mut counts: BTreeMap<&'static str, usize> = EXPECTED_FAMILY_COUNTS
        .iter()
        .map(|(name, _)| (*name, 0usize))
        .collect();

    for path in manifests {
        let family = path
            .parent()
            .and_then(Path::file_name)
            .and_then(|s| s.to_str())
            .unwrap_or_else(|| panic!("manifest {} has no parent directory leaf", path.display()));

        // Find the matching static key so the BTreeMap key has the
        // 'static lifetime the return type needs.
        let key = EXPECTED_FAMILY_COUNTS
            .iter()
            .find(|(name, _)| *name == family)
            .map(|(name, _)| *name)
            .unwrap_or_else(|| {
                panic!(
                    "manifest {} lives under unexpected family directory {:?} \
                     (not listed in EXPECTED_FAMILY_COUNTS)",
                    path.display(),
                    family,
                )
            });

        let entry = counts.entry(key).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    counts
}

/// Read and parse a manifest JSON file from disk. Panics with a
/// useful, manifest-path-tagged message on any failure so a future
/// `--bless` run gets actionable diagnostics.
fn load_manifest(path: &Path) -> Value {
    let bytes = fs::read(path)
        .unwrap_or_else(|err| panic!("failed to read manifest {}: {err}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|err| panic!("failed to parse manifest {} as JSON: {err}", path.display()))
}
