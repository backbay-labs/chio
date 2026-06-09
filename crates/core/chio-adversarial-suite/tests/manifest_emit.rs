//! Integration test for the cross-SDK verdict-matrix manifest producer.
//!
//! The on-disk manifest at `crates/chio-adversarial-suite/manifest.json`
//! is consumed by cross-language verdict differential drivers. This test
//! asserts that:
//!
//! 1. `Manifest::from_bundled()` succeeds against the shipped cases.
//! 2. The on-disk manifest at `manifest.json` is byte-for-byte equal
//!    to the freshly emitted canonical JSON. Drift means a developer
//!    edited a case JSON but forgot to regenerate the manifest, so we
//!    fail the build with a clear hint.
//! 3. Every manifest entry references a real bundled case and pins its
//!    sha256 against the embedded contents.
//! 4. Every attack class shows up at least once so a future case drop
//!    cannot silently shrink cross-SDK coverage.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use chio_adversarial_suite::{
    bundled_cases, AttackClass, ExpectedVerdict, Manifest, ATTACK_CLASSES, BUNDLED_CASES,
    MANIFEST_PRODUCER, MANIFEST_SCHEMA_VERSION,
};

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.json")
}

#[test]
fn manifest_emits_against_bundled_cases() {
    let manifest = match Manifest::from_bundled() {
        Ok(manifest) => manifest,
        Err(err) => panic!("Manifest::from_bundled failed: {err}"),
    };

    assert_eq!(manifest.schema_version, MANIFEST_SCHEMA_VERSION);
    assert_eq!(manifest.producer, MANIFEST_PRODUCER);
    assert!(
        !manifest.cases.is_empty(),
        "manifest must include at least one non-pending case"
    );
    assert_eq!(manifest.case_count, manifest.cases.len());

    // Every entry has a non-empty deny reason and threat id.
    for entry in &manifest.cases {
        assert_eq!(entry.expected_verdict, ExpectedVerdict::Deny);
        assert!(!entry.expected_reason.trim().is_empty());
        assert!(!entry.threat_id.trim().is_empty());
        assert_eq!(entry.content_sha256.len(), 64);
        assert!(entry
            .content_sha256
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        assert!(entry.path.starts_with("cases/"));
    }
}

#[test]
fn manifest_covers_every_attack_class() {
    let manifest = match Manifest::from_bundled() {
        Ok(manifest) => manifest,
        Err(err) => panic!("Manifest::from_bundled failed: {err}"),
    };

    let observed: BTreeSet<AttackClass> = manifest.cases.iter().map(|c| c.class).collect();
    let expected: BTreeSet<AttackClass> = ATTACK_CLASSES.iter().copied().collect();
    assert_eq!(
        observed, expected,
        "manifest must reference every attack class"
    );
}

#[test]
fn manifest_entries_reference_real_bundled_cases() {
    let manifest = match Manifest::from_bundled() {
        Ok(manifest) => manifest,
        Err(err) => panic!("Manifest::from_bundled failed: {err}"),
    };

    let bundled_paths: BTreeSet<&str> = BUNDLED_CASES.iter().map(|c| c.path).collect();
    for entry in &manifest.cases {
        assert!(
            bundled_paths.contains(entry.path.as_str()),
            "manifest entry path {} not in BUNDLED_CASES",
            entry.path
        );
    }

    // Every non-pending bundled case is represented exactly once.
    let cases = match bundled_cases() {
        Ok(cases) => cases,
        Err(err) => panic!("bundled_cases failed: {err}"),
    };
    let expected_ids: BTreeSet<String> = cases
        .into_iter()
        .filter(|c| !c.pending)
        .map(|c| c.id)
        .collect();
    let manifest_ids: BTreeSet<String> = manifest.cases.iter().map(|e| e.id.clone()).collect();
    assert_eq!(expected_ids, manifest_ids);
}

#[test]
fn manifest_json_on_disk_matches_emitter() {
    let manifest = match Manifest::from_bundled() {
        Ok(manifest) => manifest,
        Err(err) => panic!("Manifest::from_bundled failed: {err}"),
    };
    let canonical = match manifest.to_canonical_json() {
        Ok(s) => s,
        Err(err) => panic!("to_canonical_json failed: {err}"),
    };

    let path = manifest_path();
    let on_disk = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(err) => panic!(
            "missing {}: {err}. Regenerate with `cargo test -p chio-adversarial-suite --test manifest_emit -- --ignored regenerate`",
            path.display()
        ),
    };

    if canonical != on_disk {
        panic!(
            "manifest drift detected at {}.\n\
             Regenerate with: cargo test -p chio-adversarial-suite --test manifest_emit -- --ignored regenerate",
            path.display()
        );
    }
}

/// Regenerate `manifest.json` on disk. Marked `#[ignore]` so a normal
/// `cargo test` run never silently rewrites the source file; the
/// drift-detection test above guards against forgotten regenerations.
#[test]
#[ignore = "regenerator: invoke explicitly with `-- --ignored regenerate`"]
fn regenerate() {
    let manifest = match Manifest::from_bundled() {
        Ok(manifest) => manifest,
        Err(err) => panic!("Manifest::from_bundled failed: {err}"),
    };
    let canonical = match manifest.to_canonical_json() {
        Ok(s) => s,
        Err(err) => panic!("to_canonical_json failed: {err}"),
    };
    let path = manifest_path();
    if let Err(err) = fs::write(&path, canonical) {
        panic!("failed to write {}: {err}", path.display());
    }
}
