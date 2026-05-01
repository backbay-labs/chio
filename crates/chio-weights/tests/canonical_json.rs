//! Golden-vector tests for the model-card canonical-JSON encoding.
//!
//! These tests lock the byte-level shape of `ModelCard::to_canonical_json`
//! so that a future change to the serde layout, the canonical-JSON encoder,
//! or the schema is forced to update the byte-pinned vectors. The vectors
//! are committed under `tests/golden/`.
//!
//! Two implementations of the schema (Rust, TypeScript / Python / Go)
//! producing the same logical card MUST produce byte-identical output;
//! cosign signatures are taken over these bytes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_weights::card::{ModelCard, StringSet};
use chrono::{TimeZone, Utc};

const GOLDEN_BYTES: &[u8] = include_bytes!("golden/model_card_minimal_v1.json");

fn fixed_issued_at() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 4, 30, 12, 0, 0).unwrap()
}

fn minimal_card() -> ModelCard {
    let issued = fixed_issued_at();
    let expires = issued + chrono::Duration::days(30);
    ModelCard::new(
        "0000000000000000000000000000000000000000000000000000000000000001",
        StringSet::new(["tool:read", "tool:write"]),
        StringSet::new(["tool:exec"]),
        "public-internet",
        "https://example.com/issuer",
        issued,
        expires,
    )
    .unwrap()
}

#[test]
fn canonical_json_matches_minimal_golden_vector() {
    let card = minimal_card();
    let bytes = card.to_canonical_json().unwrap();
    assert_eq!(
        bytes,
        GOLDEN_BYTES,
        "canonical-json output drifted from golden vector at tests/golden/model_card_minimal_v1.json. \
         If this drift is intentional, regenerate the golden file (it is byte-pinned)."
    );
}

#[test]
fn canonical_json_round_trips_through_decode() {
    let card = minimal_card();
    let bytes = card.to_canonical_json().unwrap();
    let again = ModelCard::from_canonical_json(&bytes).unwrap();
    assert_eq!(card, again, "decode must reconstruct the input card");
    let bytes2 = again.to_canonical_json().unwrap();
    assert_eq!(
        bytes, bytes2,
        "re-encode must produce byte-identical output"
    );
}

#[test]
fn canonical_json_keys_are_sorted_lexicographically() {
    // RFC 8785 sorts object keys by UTF-16 code units. The model-card schema's
    // keys all live in the ASCII subset, so lexicographic sort over codepoints
    // matches UTF-16 sort. Verify the on-disk byte order.
    let card = minimal_card();
    let bytes = card.to_canonical_json().unwrap();
    let s = std::str::from_utf8(&bytes).unwrap();

    let order = [
        "\"allowed_capability_set\":",
        "\"banned_tools\":",
        "\"card_version\":",
        "\"expires_at\":",
        "\"issued_at\":",
        "\"issuer\":",
        "\"training_data_class\":",
        "\"weights_hash\":",
    ];
    let mut last = 0usize;
    for key in order {
        let idx = s
            .find(key)
            .unwrap_or_else(|| panic!("canonical output missing key {key:?}"));
        assert!(
            idx >= last,
            "keys not in sorted order: {key:?} found at byte {idx}, previous boundary was {last}"
        );
        last = idx;
    }
}

#[test]
fn canonical_json_set_arrays_are_sorted_unique() {
    let card = minimal_card();
    let bytes = card.to_canonical_json().unwrap();
    let s = std::str::from_utf8(&bytes).unwrap();

    // allowed_capability_set was constructed with ["tool:read","tool:write"];
    // BTreeSet ordering puts read < write. The sorted JSON array MUST appear
    // exactly once, in that order.
    assert!(
        s.contains("\"allowed_capability_set\":[\"tool:read\",\"tool:write\"]"),
        "canonical-json must encode the scope set as a sorted unique array, got: {s}"
    );
    assert!(
        s.contains("\"banned_tools\":[\"tool:exec\"]"),
        "canonical-json must encode the banned tools as a sorted unique array, got: {s}"
    );
}

#[test]
fn canonical_json_has_no_inter_token_whitespace() {
    let card = minimal_card();
    let bytes = card.to_canonical_json().unwrap();
    let s = std::str::from_utf8(&bytes).unwrap();
    assert!(
        !s.contains("  "),
        "RFC 8785 forbids inter-token whitespace; got {s}"
    );
    assert!(
        !s.contains("\n"),
        "RFC 8785 forbids inter-token whitespace; got {s}"
    );
    assert!(
        !s.contains(": "),
        "RFC 8785 forbids inter-token whitespace; got {s}"
    );
}
