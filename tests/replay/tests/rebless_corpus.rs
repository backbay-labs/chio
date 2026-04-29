//! Manual re-bless helper for the M04 replay corpus.
//!
//! This is an `#[ignore]`-gated test that regenerates the on-disk
//! goldens under `tests/replay/goldens/` from the manifests under
//! `tests/replay/fixtures/`, using the same synthesis recipe the
//! `golden_byte_equivalence` exit test reproduces. It is the only
//! place inside the test crate that writes to the goldens tree
//! directly; the byte-equivalence test always writes into a
//! `TempDir`.
//!
//! Why this exists: the bless wrapper script
//! (`scripts/bless-replay-goldens.sh`) plus the in-process gate
//! (`tests/replay/src/bless.rs`) cover the "operator-on-a-developer-
//! workstation re-bless on a topic branch" flow. When a structural
//! refactor inside the synthesis path itself changes the bytes (for
//! example, advancing the nonce counter per `fixed_nonce_seed_index`
//! so all 50 scenarios record distinct nonces rather than counter-
//! zero), the re-bless that has to happen IS the change - so the
//! mechanical part of the bless ("write the new bytes") and the
//! gate's "guard the inputs" responsibility have to come apart.
//!
//! Invocation:
//!
//! ```text
//! CHIO_REBLESS_GOLDENS=1 cargo test -p chio-replay-gate \
//!     --test rebless_corpus -- --ignored --nocapture
//! ```
//!
//! The env-var requirement (on top of `--ignored`) is a belt-and-
//! braces guard: a stray `cargo test -- --ignored` cannot rewrite
//! the goldens; the operator must explicitly opt in. The follow-up
//! commit message convention is the same as the manual bless flow.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use chio_replay_gate::driver::ScenarioDriver;
use chio_replay_gate::fs_iter;
use chio_replay_gate::golden_format;
use chio_replay_gate::golden_writer::GoldenSet;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Rebless trigger env-var. Must be exactly "1" for the helper to run.
const REBLESS_ENV_VAR: &str = "CHIO_REBLESS_GOLDENS";

/// Total fixture count expected under `tests/replay/fixtures/`. Mirrors
/// the constant in `golden_byte_equivalence.rs` so the two stay aligned.
const EXPECTED_FIXTURE_COUNT: usize = 50;

#[ignore]
#[test]
fn rebless_all_50_goldens() {
    if env::var(REBLESS_ENV_VAR).as_deref() != Ok("1") {
        eprintln!("rebless helper opt-out: set {REBLESS_ENV_VAR}=1 to actually rewrite goldens");
        return;
    }

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let fixtures_root = Path::new(manifest_dir).join("fixtures");
    let goldens_root = Path::new(manifest_dir).join("goldens");

    let manifests = enumerate_manifests(&fixtures_root);
    assert_eq!(
        manifests.len(),
        EXPECTED_FIXTURE_COUNT,
        "expected {EXPECTED_FIXTURE_COUNT} manifests, found {}",
        manifests.len()
    );

    for manifest_path in &manifests {
        let manifest = load_manifest(manifest_path);
        let family = require_str(&manifest, "family", manifest_path);
        let scenario_name = require_str(&manifest, "name", manifest_path);
        let scenario_leaf = scenario_name
            .rsplit('/')
            .next()
            .unwrap_or(scenario_name.as_str())
            .to_string();
        let scenario_dir = goldens_root.join(&family).join(&scenario_leaf);
        if scenario_dir.is_dir() {
            // Wipe so the writer's create-fresh policy holds.
            fs::remove_dir_all(&scenario_dir)
                .unwrap_or_else(|e| panic!("could not clear {}: {e}", scenario_dir.display()));
        }
        write_synthetic_goldens(&manifest, manifest_path, &scenario_dir);
        eprintln!(
            "rebless: wrote {}",
            scenario_dir
                .strip_prefix(manifest_dir)
                .unwrap_or(&scenario_dir)
                .display()
        );
    }

    eprintln!(
        "rebless: 50 scenarios re-blessed under {}",
        goldens_root.display()
    );
    eprintln!(
        "rebless: review the diff and follow the manual bless commit + audit-log + \
         seal-bless-audit.sh dance described in scripts/bless-replay-goldens.sh"
    );
}

/// Reproduce the bless-time synthesis recipe directly into
/// `scenario_dir` (which must not yet exist).
///
/// MUST stay in lockstep with the recipe in
/// `golden_byte_equivalence.rs::write_synthetic_goldens`. If the
/// recipes drift, the byte-equivalence exit test will detect the
/// drift on the very next CI run.
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

fn load_manifest(path: &Path) -> Value {
    let bytes = fs::read(path)
        .unwrap_or_else(|err| panic!("read manifest {} failed: {err}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|err| panic!("parse manifest {} failed: {err}", path.display()))
}

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
