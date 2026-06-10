//! Shared helpers for the threat-model coverage tests.
//!
//! Each per-threat test under `tests/threats/<id>.rs` asserts that at
//! least one non-pending DENY-asserted adversarial vector cites the
//! threat ID. This module isolates the corpus-loading boilerplate so
//! the per-threat files stay narrow and threat-specific.
//!
//! The adversarial corpus lives under
//! `crates/chio-adversarial-suite/cases/<class>/<id>.json` and is
//! exposed as `bundled_cases()` from the suite crate. Cases with
//! `pending: true` are auto-promoted from libFuzzer crashes and
//! are excluded from the threat-coverage assertions until a human
//! triages them.

#![allow(dead_code)]

use chio_adversarial_suite::{bundled_cases, AdversarialCase, ExpectedVerdict};

/// Load every non-pending DENY-asserted bundled case that cites
/// `threat_id`.
///
/// The result is sorted by case `id` for deterministic test output.
/// An empty result is an authoring error: every threat ID exercised
/// by these tests must already have at least one corpus case.
pub fn corpus_cases_for(threat_id: &str) -> Vec<AdversarialCase> {
    let all = bundled_cases()
        .unwrap_or_else(|err| panic!("chio-adversarial-suite bundled_cases load failed: {err}"));
    let mut hits: Vec<AdversarialCase> = all
        .into_iter()
        .filter(|case| {
            case.threat_id == threat_id
                && !case.pending
                && case.expected_verdict == ExpectedVerdict::Deny
        })
        .collect();
    hits.sort_by(|a, b| a.id.cmp(&b.id));
    hits
}

/// Assert the threat ID is backed by at least one non-pending DENY
/// case in the bundled corpus, and that every such case carries a
/// non-empty `expected_reason`. The expected-reason check guards
/// against silent regressions where the deny path is rewritten and
/// the corpus is left pointing at a stale reason string.
pub fn assert_threat_covered_by_corpus(threat_id: &str) {
    let cases = corpus_cases_for(threat_id);
    assert!(
        !cases.is_empty(),
        "threat {threat_id:?} has no non-pending DENY cases in chio-adversarial-suite/cases/; \
         add a vector or strip the `pending: true` flag from an existing one"
    );
    for case in &cases {
        assert!(
            !case.expected_reason.trim().is_empty(),
            "threat {threat_id:?} case {:?} has an empty expected_reason",
            case.id
        );
        assert_eq!(
            case.expected_verdict,
            ExpectedVerdict::Deny,
            "threat {threat_id:?} case {:?} must deny-assert",
            case.id
        );
    }
}
