//! Pinned WebAuthn fixture corpus integration test.
//!
//! The corpus is a set of JSON descriptors that pin the custody
//! failure-mode taxonomy: four positive cases and four negative cases,
//! each negative case bound to a `urn:chio:error:custody:*` code. These
//! tests validate the corpus shape, descriptor id uniqueness, and the
//! negative-case URN coverage the error registry requires. The descriptor
//! schema carries an optional `description` slot so a deployment can pin
//! byte-level `PublicKeyCredential` assertion captures alongside a
//! descriptor without changing this schema.

use serde::Deserialize;
use std::path::{Path, PathBuf};

const POSITIVE_COUNT: usize = 4;
const NEGATIVE_COUNT: usize = 4;

#[derive(Debug, Deserialize)]
struct Descriptor {
    id: String,
    kind: String,
    #[serde(default)]
    failure_mode: Option<String>,
    #[serde(default)]
    expected_urn: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    description: Option<String>,
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/passkey")
}

fn load_dir(dir: &Path) -> Vec<Descriptor> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(err) => panic!("fixture dir {} must exist: {err}", dir.display()),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(err) => panic!("read_dir entry: {err}"),
        };
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(err) => panic!("read {}: {err}", path.display()),
        };
        let desc: Descriptor = match serde_json::from_slice(&bytes) {
            Ok(d) => d,
            Err(err) => panic!("parse {}: {err}", path.display()),
        };
        out.push(desc);
    }
    out
}

#[test]
fn corpus_directories_present() {
    let root = fixtures_root();
    assert!(root.join("positive").is_dir(), "positive/ must exist");
    assert!(root.join("negative").is_dir(), "negative/ must exist");
}

#[test]
fn corpus_carries_four_positive_and_four_negative() {
    let positive = load_dir(&fixtures_root().join("positive"));
    let negative = load_dir(&fixtures_root().join("negative"));
    assert_eq!(
        positive.len(),
        POSITIVE_COUNT,
        "exactly 4 positive fixtures"
    );
    assert_eq!(
        negative.len(),
        NEGATIVE_COUNT,
        "exactly 4 negative fixtures"
    );
}

#[test]
fn positive_descriptors_kind_and_no_urn() {
    for d in load_dir(&fixtures_root().join("positive")) {
        assert_eq!(
            d.kind, "positive",
            "fixture {}: kind must be 'positive'",
            d.id
        );
        assert!(
            d.failure_mode.is_none(),
            "fixture {}: positive must not carry failure_mode",
            d.id
        );
        assert!(
            d.expected_urn.is_none(),
            "fixture {}: positive must not carry expected_urn",
            d.id
        );
    }
}

#[test]
fn negative_descriptors_cover_required_failure_modes() {
    use std::collections::BTreeSet;
    let mut modes: BTreeSet<String> = BTreeSet::new();
    for d in load_dir(&fixtures_root().join("negative")) {
        assert_eq!(
            d.kind, "negative",
            "fixture {}: kind must be 'negative'",
            d.id
        );
        let mode = match d.failure_mode.as_deref() {
            Some(m) => m,
            None => panic!("fixture {}: negative must carry failure_mode", d.id),
        };
        let urn = match d.expected_urn.as_deref() {
            Some(u) => u,
            None => panic!("fixture {}: negative must carry expected_urn", d.id),
        };
        assert!(
            urn.starts_with("urn:chio:error:custody:"),
            "fixture {}: expected_urn must be a custody URN, got {urn}",
            d.id
        );
        modes.insert(mode.to_string());
    }

    let required = [
        "replayed-challenge",
        "mismatched-origin",
        "expired-challenge",
        "malformed-cbor",
    ];
    for r in required {
        assert!(modes.contains(r), "negative corpus must cover {r}");
    }
}

#[test]
fn fixture_ids_are_unique() {
    use std::collections::BTreeSet;
    let mut ids: BTreeSet<String> = BTreeSet::new();
    for d in load_dir(&fixtures_root().join("positive")) {
        assert!(
            ids.insert(format!("positive:{}", d.id)),
            "duplicate positive id {}",
            d.id
        );
    }
    for d in load_dir(&fixtures_root().join("negative")) {
        assert!(
            ids.insert(format!("negative:{}", d.id)),
            "duplicate negative id {}",
            d.id
        );
    }
}
