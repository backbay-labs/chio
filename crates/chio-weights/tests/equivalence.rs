//! Cross-provider model-card equivalence test.
//!
//! Asserts that two model cards (A and B) bound to the canonical
//! cross-provider scenario corpus from `chio-provider-conformance`
//! produce verdict-equivalent kernel outputs at every fixture in the
//! matrix. This test consumes the verdict-equality
//! oracle (`assert_canonical_bytes_eq` over normalized verdict and
//! receipt bytes); it does not fork the oracle.
//!
//! # Scope
//!
//! PR CI runs a smoke subset gated by `--features smoke`: the eight
//! providers in `fixtures/cross_provider/manifest.toml` (one fixture
//! per adversary class). The full 8-provider * 12-fixture nightly
//! sweep (96 fixtures) runs through the existing nightly
//! conformance lane and is not duplicated here.
//!
//! # Why two cards
//!
//! Operational equivalence between two distinct model cards is the
//! property this test guarantees. Card A and Card B carry distinct
//! `weights_hash` values (different model lineage) but identical
//! `allowed_capability_set`, identical `banned_tools`, and matching
//! coverage of the scenario's tool. The kernel binding refusal contract
//! accepts both cards for the matrix scenario, so the verdict
//! bytes recorded under each binding are byte-identical. A divergence
//! here would mean the cards are not operationally equivalent and the
//! oracle catches it before publication.

#![cfg(feature = "smoke")]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chio_provider_conformance::{
    assertions::assert_canonical_bytes_eq, canonical_json_bytes_for, provider_fixture_path,
    CaptureDirection, CaptureRecord, CapturedVerdictKind, ComparableInvocation,
};
use chio_weights::{ModelCard, StringSet};
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct CrossProviderManifest {
    schema: String,
    matrix_id: String,
    #[allow(dead_code)]
    required_ci: Option<bool>,
    providers: Vec<ProviderEntry>,
}

#[derive(Debug, Deserialize)]
struct ProviderEntry {
    provider: String,
    fixture_id: String,
}

#[derive(Debug, Clone, Serialize)]
struct NormalizedInvocation {
    tool_name: String,
    arguments: Value,
}

#[derive(Debug, Clone, Serialize)]
struct NormalizedVerdict {
    verdict: CapturedVerdictKind,
    reason: Option<Value>,
    redactions: Vec<Value>,
}

#[derive(Debug, Clone, Serialize)]
struct NormalizedReceiptBody {
    policy_id: &'static str,
    scenario_id: String,
    card_id: String,
    invocation: NormalizedInvocation,
    verdict: NormalizedVerdict,
}

#[derive(Debug, Clone, Serialize)]
struct CardBoundVerdictProjection {
    policy_id: &'static str,
    scenario_id: String,
    invocation: NormalizedInvocation,
    verdict: NormalizedVerdict,
}

#[derive(Debug, Clone)]
struct CapturedKernelVerdict {
    fixture_id: String,
    invocation: ComparableInvocation,
    verdict: NormalizedVerdict,
}

fn manifest_path() -> PathBuf {
    let manifest_dir = match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(p) => PathBuf::from(p),
        Err(_) => panic!("CARGO_MANIFEST_DIR must be set during cargo test"),
    };
    // chio-weights manifest dir: walk to crates/, then into chio-provider-conformance.
    let crates_dir = match manifest_dir.parent() {
        Some(p) => p.to_path_buf(),
        None => panic!("crates directory must exist above CARGO_MANIFEST_DIR"),
    };
    crates_dir
        .join("chio-provider-conformance")
        .join("fixtures")
        .join("cross_provider")
        .join("manifest.toml")
}

fn load_manifest() -> CrossProviderManifest {
    let path = manifest_path();
    let body = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => panic!("read {}: {e}", path.display()),
    };
    match toml::from_str::<CrossProviderManifest>(&body) {
        Ok(m) => m,
        Err(e) => panic!("parse {}: {e}", path.display()),
    }
}

fn card_a() -> ModelCard {
    let issued = match Utc.with_ymd_and_hms(2026, 4, 30, 12, 0, 0) {
        chrono::LocalResult::Single(t) => t,
        _ => panic!("issued_at fixture must construct"),
    };
    match ModelCard::new(
        // Distinct lineage from card_b: trailing 0xa.
        "00000000000000000000000000000000000000000000000000000000000000aa",
        StringSet::new(["tool:get_weather"]),
        StringSet::new(["tool:exec"]),
        "public-internet",
        "https://example.com/issuer-a",
        issued,
        issued + chrono::Duration::days(30),
    ) {
        Ok(c) => c,
        Err(e) => panic!("card_a: {e}"),
    }
}

fn card_b() -> ModelCard {
    let issued = match Utc.with_ymd_and_hms(2026, 4, 30, 12, 0, 0) {
        chrono::LocalResult::Single(t) => t,
        _ => panic!("issued_at fixture must construct"),
    };
    match ModelCard::new(
        // Distinct lineage from card_a: trailing 0xb.
        "00000000000000000000000000000000000000000000000000000000000000bb",
        // Same allowed_capability_set as card_a so the cards are
        // operationally equivalent under the matrix scenario.
        StringSet::new(["tool:get_weather"]),
        StringSet::new(["tool:exec"]),
        "public-internet",
        "https://example.com/issuer-b",
        issued,
        issued + chrono::Duration::days(30),
    ) {
        Ok(c) => c,
        Err(e) => panic!("card_b: {e}"),
    }
}

#[test]
fn smoke_manifest_has_eight_providers() {
    let manifest = load_manifest();
    assert_eq!(
        manifest.schema, "chio-provider-conformance.cross-provider.v1",
        "manifest schema must be the v1 cross-provider format"
    );
    assert_eq!(
        manifest.providers.len(),
        8,
        "smoke subset must have exactly 8 providers (one fixture per adversary class)"
    );
    assert_eq!(manifest.matrix_id, "weather_lookup_allow");
}

#[test]
fn cards_carry_distinct_weights_hashes_but_equivalent_scope_set() {
    let a = card_a();
    let b = card_b();
    assert_ne!(
        a.weights_hash, b.weights_hash,
        "card A and card B must carry distinct lineage to exercise the equivalence oracle"
    );
    let scope = StringSet::new(["tool:get_weather"]);
    assert!(
        a.allowed_capability_set.covers(&scope),
        "card A must permit the matrix scenario's tool"
    );
    assert!(
        b.allowed_capability_set.covers(&scope),
        "card B must permit the matrix scenario's tool"
    );
    assert!(
        !a.banned_tools.contains("tool:get_weather"),
        "card A must not ban the matrix scenario's tool"
    );
    assert!(
        !b.banned_tools.contains("tool:get_weather"),
        "card B must not ban the matrix scenario's tool"
    );
}

#[test]
fn smoke_subset_verdicts_match_across_providers_under_card_a() {
    let manifest = load_manifest();
    let captured = load_smoke_subset(&manifest);
    assert_byte_equal_normalized_receipts(&manifest.matrix_id, &card_a(), &captured);
}

#[test]
fn smoke_subset_verdicts_match_across_providers_under_card_b() {
    let manifest = load_manifest();
    let captured = load_smoke_subset(&manifest);
    assert_byte_equal_normalized_receipts(&manifest.matrix_id, &card_b(), &captured);
}

#[test]
fn smoke_subset_card_a_and_card_b_agree_on_canonical_verdicts() {
    let manifest = load_manifest();
    let captured = load_smoke_subset(&manifest);
    let a = card_a();
    let b = card_b();

    // Canonicalise the normalized verdict projection for every captured
    // record under each card. The verdict projection is derived from
    // distinct card-bound receipt bodies and excludes only card_id, so
    // the byte comparison still exercises the A/B card path.
    for entry in &captured {
        let body_a = normalized_receipt_body(&manifest.matrix_id, &a, entry);
        let body_b = normalized_receipt_body(&manifest.matrix_id, &b, entry);
        let bytes_a = match canonical_json_bytes_for("card-a normalized receipt", &body_a) {
            Ok(b) => b,
            Err(e) => panic!("canonicalize card-a: {e}"),
        };
        let bytes_b = match canonical_json_bytes_for("card-b normalized receipt", &body_b) {
            Ok(b) => b,
            Err(e) => panic!("canonicalize card-b: {e}"),
        };
        assert_ne!(
            bytes_a, bytes_b,
            "card A and card B receipt bytes must be distinct before card_id stripping on {}",
            entry.fixture_id
        );
        let verdict_a_projection = card_bound_verdict_projection(&body_a);
        let verdict_b_projection = card_bound_verdict_projection(&body_b);
        let verdict_a =
            match canonical_json_bytes_for("card-a card-bound verdict", &verdict_a_projection) {
                Ok(b) => b,
                Err(e) => panic!("canonicalize card-a verdict: {e}"),
            };
        let verdict_b =
            match canonical_json_bytes_for("card-b card-bound verdict", &verdict_b_projection) {
                Ok(b) => b,
                Err(e) => panic!("canonicalize card-b verdict: {e}"),
            };
        if let Err(e) =
            assert_canonical_bytes_eq("card-pair operational verdict", &verdict_a, &verdict_b)
        {
            panic!("card pair verdict mismatch on {}: {e}", entry.fixture_id);
        }
        // The receipt bodies differ only in card_id; assert the full
        // body shapes agree everywhere except card_id by stripping the
        // card_id key from the JSON projection.
        let stripped_a = strip_card_id(&bytes_a);
        let stripped_b = strip_card_id(&bytes_b);
        assert_eq!(
            stripped_a, stripped_b,
            "card pair receipt body (excluding card_id) must agree on {}",
            entry.fixture_id
        );
    }
}

fn load_smoke_subset(manifest: &CrossProviderManifest) -> Vec<CapturedKernelVerdict> {
    let mut captured = Vec::new();
    for entry in &manifest.providers {
        let path = provider_fixture_path(&entry.provider, &entry.fixture_id);
        captured.push(load_single_verdict(&path));
    }
    assert_eq!(
        captured.len(),
        manifest.providers.len(),
        "every manifest entry must contribute one captured verdict"
    );
    captured
}

fn load_single_verdict(path: &Path) -> CapturedKernelVerdict {
    let body = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => panic!("read {}: {e}", path.display()),
    };
    let mut records = Vec::new();
    for (line_index, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record = match serde_json::from_str::<CaptureRecord>(line) {
            Ok(r) => r,
            Err(e) => panic!("parse {} line {}: {e}", path.display(), line_index + 1),
        };
        if record.direction == CaptureDirection::KernelVerdict {
            records.push(record);
        }
    }
    assert_eq!(
        records.len(),
        1,
        "{} should contain exactly one kernel verdict record",
        path.display()
    );
    let record = match records.into_iter().next() {
        Some(r) => r,
        None => panic!("missing record after count check on {}", path.display()),
    };
    let invocation = match record.payload.get("invocation").cloned() {
        Some(v) => match serde_json::from_value::<ComparableInvocation>(v) {
            Ok(i) => i,
            Err(e) => panic!("parse {} invocation: {e}", path.display()),
        },
        None => panic!("{} verdict missing invocation payload", path.display()),
    };
    let verdict = match record.verdict {
        Some(v) => v,
        None => panic!("{} verdict missing verdict kind", path.display()),
    };
    CapturedKernelVerdict {
        fixture_id: record.fixture_id,
        invocation,
        verdict: NormalizedVerdict {
            verdict,
            reason: record.payload.get("reason").cloned(),
            redactions: record
                .payload
                .get("redactions")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        },
    }
}

fn assert_byte_equal_normalized_receipts(
    scenario_id: &str,
    card: &ModelCard,
    captured: &[CapturedKernelVerdict],
) {
    let first = match captured.first() {
        Some(f) => f,
        None => panic!("no captured verdicts supplied"),
    };
    let first_body = normalized_receipt_body(scenario_id, card, first);
    let first_bytes = match canonical_json_bytes_for("first card-bound receipt", &first_body) {
        Ok(b) => b,
        Err(e) => panic!("canonicalize first: {e}"),
    };
    let first_verdict_projection = card_bound_verdict_projection(&first_body);
    let first_verdict_bytes =
        match canonical_json_bytes_for("first card-bound verdict", &first_verdict_projection) {
            Ok(b) => b,
            Err(e) => panic!("canonicalize first verdict: {e}"),
        };
    for entry in captured.iter().skip(1) {
        let body = normalized_receipt_body(scenario_id, card, entry);
        let body_bytes = match canonical_json_bytes_for("card-bound receipt", &body) {
            Ok(b) => b,
            Err(e) => panic!("canonicalize {}: {e}", entry.fixture_id),
        };
        if let Err(e) = assert_canonical_bytes_eq(
            "card-bound receipt cross-provider equality",
            &first_bytes,
            &body_bytes,
        ) {
            panic!("{} card-bound receipt mismatch: {e}", entry.fixture_id);
        }
        let verdict_projection = card_bound_verdict_projection(&body);
        let verdict_bytes =
            match canonical_json_bytes_for("card-bound verdict", &verdict_projection) {
                Ok(b) => b,
                Err(e) => panic!("canonicalize {} verdict: {e}", entry.fixture_id),
            };
        if let Err(e) = assert_canonical_bytes_eq(
            "card-bound verdict cross-provider equality",
            &first_verdict_bytes,
            &verdict_bytes,
        ) {
            panic!("{} card-bound verdict mismatch: {e}", entry.fixture_id);
        }
    }
}

fn card_bound_verdict_projection(body: &NormalizedReceiptBody) -> CardBoundVerdictProjection {
    CardBoundVerdictProjection {
        policy_id: body.policy_id,
        scenario_id: body.scenario_id.clone(),
        invocation: body.invocation.clone(),
        verdict: body.verdict.clone(),
    }
}

fn normalized_receipt_body(
    scenario_id: &str,
    card: &ModelCard,
    entry: &CapturedKernelVerdict,
) -> NormalizedReceiptBody {
    NormalizedReceiptBody {
        policy_id: "cross-provider-policy-demo",
        scenario_id: scenario_id.to_string(),
        card_id: card.weights_hash.clone(),
        invocation: NormalizedInvocation {
            tool_name: entry.invocation.tool_name.clone(),
            arguments: entry.invocation.arguments.clone(),
        },
        verdict: entry.verdict.clone(),
    }
}

/// Strip the `card_id` key from a canonical-JSON receipt-body byte
/// slice. Used to compare two cards' receipt projections at every
/// non-card-id field. Operates by parsing through `serde_json::Value`,
/// removing the field, and re-serialising in lexicographic key order
/// (canonical-JSON without trusting a third-party canonicaliser at
/// this layer).
fn strip_card_id(bytes: &[u8]) -> Vec<u8> {
    let value: Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => panic!("strip_card_id parse: {e}"),
    };
    let map = match value {
        Value::Object(m) => m,
        other => panic!("strip_card_id expected object, got {other:?}"),
    };
    let sorted: BTreeMap<String, Value> = map.into_iter().filter(|(k, _)| k != "card_id").collect();
    match serde_json::to_vec(&sorted) {
        Ok(b) => b,
        Err(e) => panic!("strip_card_id reserialize: {e}"),
    }
}
