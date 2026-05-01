//! Helper binary that prints the canonical-JSON encoding of the minimal
//! model card used by `tests/canonical_json.rs`. Run via
//! `cargo run -p chio-weights --example dump_minimal_card` and pipe the
//! output into `tests/golden/model_card_minimal_v1.json` to regenerate the
//! pinned vector.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;

use chio_weights::card::{ModelCard, StringSet};
use chrono::{TimeZone, Utc};

fn main() {
    let issued = Utc.with_ymd_and_hms(2026, 4, 30, 12, 0, 0).unwrap();
    let expires = issued + chrono::Duration::days(30);
    let card = ModelCard::new(
        "0000000000000000000000000000000000000000000000000000000000000001",
        StringSet::new(["tool:read", "tool:write"]),
        StringSet::new(["tool:exec"]),
        "public-internet",
        "https://example.com/issuer",
        issued,
        expires,
    )
    .unwrap();
    let bytes = card.to_canonical_json().unwrap();
    std::io::stdout().write_all(&bytes).unwrap();
}
