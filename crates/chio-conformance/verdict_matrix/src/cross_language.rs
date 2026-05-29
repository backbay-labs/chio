//! Cross-language verdict-matrix diff oracle.
//!
//! Aggregates per-driver verdict reports across the verdict-matrix drivers
//! declared in manifest.toml (the in-process Rust and WASM-browser kernels
//! plus the language-SDK and deployment-shape drivers) and asserts the
//! (verdict, reason_code, scope_set) tuple equality contract on every
//! scenario where two or more drivers produce a non-unsupported tuple.
//!
//! The diff oracle is fail-closed: any divergence between drivers, or
//! between a driver and the expected tuple, surfaces a
//! `CrossLanguageDivergence` and the orchestrating test fails.
//! Drivers that do not embed kernel evaluation (e.g. the TS node-http
//! transport client without a sidecar, or the Go HTTP SDK that has no
//! local semantic emitter) report scenarios as unsupported and are
//! filtered out of the equality check on those scenarios; the oracle
//! still requires that the manifest's `drivers.required` list (which
//! pins `rust-kernel`) produces tuples for every scenario.
//!
//! The cross-language divergence gate runs this oracle in CI; any
//! divergence in the cross-language tuple set fails the PR check. See
//! `docs/conformance/verdict-matrix.md` for the runbook.

use std::collections::{BTreeMap, BTreeSet};

use super::diff_oracle::{DriverReport, TupleDivergence, VerdictMatrixManifest};
use super::VerdictTuple;

/// Per-driver report keyed by driver id (`rust-kernel`, `python-sdk`,
/// `typescript-node-http`, `wasm-browser`, `go-http-sdk`).
#[derive(Debug, Clone, Default)]
pub struct CrossLanguageReport {
    drivers: BTreeMap<String, DriverReport>,
}

impl CrossLanguageReport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a driver's tuples. If a driver id is registered twice,
    /// the second registration replaces the first (callers should not
    /// rely on this; it exists so retries during driver bring-up cannot
    /// silently stack stale tuples).
    pub fn add_driver(&mut self, report: DriverReport) {
        self.drivers.insert(report.driver.clone(), report);
    }

    pub fn drivers(&self) -> impl Iterator<Item = &DriverReport> {
        self.drivers.values()
    }

    pub fn driver_ids(&self) -> Vec<String> {
        self.drivers.keys().cloned().collect()
    }

    pub fn driver(&self, id: &str) -> Option<&DriverReport> {
        self.drivers.get(id)
    }

    pub fn into_reports(self) -> Vec<DriverReport> {
        self.drivers.into_values().collect()
    }

    pub fn reports(&self) -> Vec<DriverReport> {
        self.drivers.values().cloned().collect()
    }
}

/// Cross-language divergence: a single scenario where two drivers
/// disagree, or where a driver disagrees with the expected tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossLanguageDivergence {
    /// A driver disagrees with the expected tuple from the scenario
    /// definition.
    DriverVsExpected(TupleDivergence),
    /// Two drivers agree on producing a tuple for the same scenario,
    /// but the tuples differ. Both halves are surfaced so the failure
    /// message points at both ends.
    DriverVsDriver {
        scenario_id: String,
        left_driver: String,
        left_tuple: VerdictTuple,
        right_driver: String,
        right_tuple: VerdictTuple,
    },
}

impl CrossLanguageDivergence {
    pub fn scenario_id(&self) -> &str {
        match self {
            Self::DriverVsExpected(divergence) => divergence.scenario_id.as_str(),
            Self::DriverVsDriver { scenario_id, .. } => scenario_id.as_str(),
        }
    }
}

/// Diff an aggregated cross-language report against the manifest +
/// expected tuples. Returns every divergence found. An empty vector is
/// the gate's pass condition.
///
/// Semantics:
///
/// - Required drivers (per `manifest.drivers.required`) MUST emit a
///   tuple for every scenario in `expected`; a missing tuple is a
///   divergence (this catches a regression where the Rust kernel
///   driver silently stopped emitting).
/// - Non-required drivers MAY skip scenarios they cannot emit a tuple
///   for (e.g. the WASM browser kernel skips revocation/replay/
///   redaction because it has no kernel state machine for those
///   classes). Skipped scenarios do NOT register as divergences.
/// - Whenever a driver DOES emit a tuple, it must match the expected
///   tuple AND it must match every other driver that emits a tuple
///   for the same scenario.
pub fn diff_cross_language(
    manifest: &VerdictMatrixManifest,
    expected: &BTreeMap<String, VerdictTuple>,
    report: &CrossLanguageReport,
) -> Vec<CrossLanguageDivergence> {
    let mut divergences = Vec::new();

    // Required-driver gate: missing required drivers surface one
    // divergence per scenario (one of the two ways the gate fails).
    for required_driver in &manifest.drivers.required {
        match report.drivers.get(required_driver) {
            None => {
                for (scenario_id, expected_tuple) in expected {
                    divergences.push(CrossLanguageDivergence::DriverVsExpected(TupleDivergence {
                        scenario_id: scenario_id.clone(),
                        driver: required_driver.clone(),
                        expected: Some(expected_tuple.clone().normalized()),
                        actual: None,
                    }));
                }
            }
            Some(driver_report) => {
                for (scenario_id, expected_tuple) in expected {
                    if !driver_report.tuples.contains_key(scenario_id) {
                        divergences.push(CrossLanguageDivergence::DriverVsExpected(
                            TupleDivergence {
                                scenario_id: scenario_id.clone(),
                                driver: required_driver.clone(),
                                expected: Some(expected_tuple.clone().normalized()),
                                actual: None,
                            },
                        ));
                    }
                }
            }
        }
    }

    divergences.extend(driver_vs_expected_divergences(expected, report));
    divergences.extend(driver_vs_driver_divergences(report));
    divergences
}

/// Diff a cross-language report against a static expected map only,
/// without consulting the manifest's `drivers.required` list. Useful
/// when the test wants to assert tuple equality between the drivers it
/// has on hand without failing for missing required drivers.
pub fn diff_cross_language_against_expected(
    expected: &BTreeMap<String, VerdictTuple>,
    report: &CrossLanguageReport,
) -> Vec<CrossLanguageDivergence> {
    let mut divergences = driver_vs_expected_divergences(expected, report);
    divergences.extend(driver_vs_driver_divergences(report));
    divergences
}

fn driver_vs_expected_divergences(
    expected: &BTreeMap<String, VerdictTuple>,
    report: &CrossLanguageReport,
) -> Vec<CrossLanguageDivergence> {
    let mut divergences = Vec::new();
    for driver_report in report.drivers.values() {
        for (scenario_id, actual_tuple) in &driver_report.tuples {
            let normalized_actual = actual_tuple.clone().normalized();
            match expected.get(scenario_id) {
                Some(expected_tuple) => {
                    let normalized_expected = expected_tuple.clone().normalized();
                    if normalized_actual != normalized_expected {
                        divergences.push(CrossLanguageDivergence::DriverVsExpected(
                            TupleDivergence {
                                scenario_id: scenario_id.clone(),
                                driver: driver_report.driver.clone(),
                                expected: Some(normalized_expected),
                                actual: Some(normalized_actual),
                            },
                        ));
                    }
                }
                None => {
                    // Driver emitted a tuple for a scenario the corpus
                    // does not declare. Always a divergence (catches
                    // stale fixtures).
                    divergences.push(CrossLanguageDivergence::DriverVsExpected(TupleDivergence {
                        scenario_id: scenario_id.clone(),
                        driver: driver_report.driver.clone(),
                        expected: None,
                        actual: Some(normalized_actual),
                    }));
                }
            }
        }
    }
    divergences
}

fn driver_vs_driver_divergences(report: &CrossLanguageReport) -> Vec<CrossLanguageDivergence> {
    let mut divergences = Vec::new();
    let driver_ids: Vec<String> = report.drivers.keys().cloned().collect();
    let mut scenario_ids: BTreeSet<String> = BTreeSet::new();
    for driver_report in report.drivers.values() {
        scenario_ids.extend(driver_report.tuples.keys().cloned());
    }

    for scenario_id in scenario_ids {
        for (left_index, left_id) in driver_ids.iter().enumerate() {
            let Some(left_report) = report.drivers.get(left_id) else {
                continue;
            };
            let Some(left_tuple) = left_report.tuples.get(&scenario_id) else {
                continue;
            };
            let normalized_left = left_tuple.clone().normalized();
            for right_id in driver_ids.iter().skip(left_index + 1) {
                let Some(right_report) = report.drivers.get(right_id) else {
                    continue;
                };
                let Some(right_tuple) = right_report.tuples.get(&scenario_id) else {
                    continue;
                };
                let normalized_right = right_tuple.clone().normalized();
                if normalized_left != normalized_right {
                    divergences.push(CrossLanguageDivergence::DriverVsDriver {
                        scenario_id: scenario_id.clone(),
                        left_driver: left_id.clone(),
                        left_tuple: normalized_left.clone(),
                        right_driver: right_id.clone(),
                        right_tuple: normalized_right,
                    });
                }
            }
        }
    }

    divergences
}

/// Render a divergence list as a human-readable multi-line string.
/// The first line summarises the count; subsequent lines list each
/// divergence in deterministic order.
pub fn divergence_summary(divergences: &[CrossLanguageDivergence]) -> String {
    if divergences.is_empty() {
        return String::from("0 cross-language divergences");
    }
    let mut lines = Vec::with_capacity(divergences.len() + 1);
    lines.push(format!(
        "{} cross-language divergence(s):",
        divergences.len()
    ));
    for divergence in divergences {
        match divergence {
            CrossLanguageDivergence::DriverVsExpected(tuple_divergence) => {
                lines.push(format!(
                    "  - [{}] driver={} expected={:?} actual={:?}",
                    tuple_divergence.scenario_id,
                    tuple_divergence.driver,
                    tuple_divergence.expected,
                    tuple_divergence.actual,
                ));
            }
            CrossLanguageDivergence::DriverVsDriver {
                scenario_id,
                left_driver,
                left_tuple,
                right_driver,
                right_tuple,
            } => {
                lines.push(format!(
                    "  - [{scenario_id}] {left_driver}={left_tuple:?} vs {right_driver}={right_tuple:?}"
                ));
            }
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::super::Verdict;
    use super::*;

    fn make_tuple(verdict: Verdict, reason: &str, scopes: &[&str]) -> VerdictTuple {
        VerdictTuple {
            verdict,
            reason_code: reason.to_string(),
            scope_set: scopes.iter().map(|scope| scope.to_string()).collect(),
        }
        .normalized()
    }

    fn driver_report(driver: &str, tuples: &[(&str, VerdictTuple)]) -> DriverReport {
        let mut map = BTreeMap::new();
        for (scenario_id, tuple) in tuples {
            map.insert(scenario_id.to_string(), tuple.clone());
        }
        DriverReport {
            driver: driver.to_string(),
            tuples: map,
        }
    }

    #[test]
    fn empty_report_yields_no_divergences() {
        let report = CrossLanguageReport::new();
        let expected: BTreeMap<String, VerdictTuple> = BTreeMap::new();
        let divergences = diff_cross_language_against_expected(&expected, &report);
        assert!(divergences.is_empty());
    }

    #[test]
    fn matching_drivers_produce_no_divergence() {
        let allow_read = make_tuple(Verdict::Allow, "urn:chio:error:none", &["tool:read"]);
        let mut report = CrossLanguageReport::new();
        report.add_driver(driver_report(
            "rust-kernel",
            &[("scenario-a", allow_read.clone())],
        ));
        report.add_driver(driver_report(
            "wasm-browser",
            &[("scenario-a", allow_read.clone())],
        ));
        let mut expected = BTreeMap::new();
        expected.insert(String::from("scenario-a"), allow_read.clone());
        let divergences = diff_cross_language_against_expected(&expected, &report);
        assert!(
            divergences.is_empty(),
            "expected no divergences, got {}",
            divergence_summary(&divergences),
        );
    }

    #[test]
    fn driver_vs_driver_disagreement_is_surfaced() {
        let allow = make_tuple(Verdict::Allow, "urn:chio:error:none", &["tool:read"]);
        let deny = make_tuple(
            Verdict::Deny,
            "urn:chio:error:capability:scope-exceeded",
            &["tool:read"],
        );
        let mut report = CrossLanguageReport::new();
        report.add_driver(driver_report(
            "rust-kernel",
            &[("scenario-a", allow.clone())],
        ));
        report.add_driver(driver_report(
            "wasm-browser",
            &[("scenario-a", deny.clone())],
        ));
        let mut expected = BTreeMap::new();
        expected.insert(String::from("scenario-a"), allow.clone());
        let divergences = diff_cross_language_against_expected(&expected, &report);
        // Two divergences: rust-kernel vs wasm-browser, plus wasm-browser vs expected.
        assert_eq!(
            divergences.len(),
            2,
            "summary: {}",
            divergence_summary(&divergences)
        );
        let has_driver_vs_driver = divergences.iter().any(|divergence| {
            matches!(
                divergence,
                CrossLanguageDivergence::DriverVsDriver { left_driver, right_driver, .. }
                    if left_driver == "rust-kernel" && right_driver == "wasm-browser"
            )
        });
        assert!(
            has_driver_vs_driver,
            "expected a DriverVsDriver divergence between rust-kernel and wasm-browser"
        );
    }

    #[test]
    fn missing_tuple_in_one_driver_does_not_trigger_driver_vs_driver() {
        // Unsupported scenarios are filtered out of the cross-driver
        // equality lane: a driver that does not produce a tuple for a
        // scenario must not cause a DriverVsDriver divergence against
        // a driver that does. The expected-side gate still catches
        // missing required tuples.
        let allow = make_tuple(Verdict::Allow, "urn:chio:error:none", &["tool:read"]);
        let mut report = CrossLanguageReport::new();
        report.add_driver(driver_report(
            "rust-kernel",
            &[("scenario-a", allow.clone())],
        ));
        report.add_driver(driver_report("typescript-node-http", &[]));
        let divergences = driver_vs_driver_divergences(&report);
        assert!(
            divergences.is_empty(),
            "missing tuples must not cause driver-vs-driver divergences: {}",
            divergence_summary(&divergences)
        );
    }

    #[test]
    fn divergence_summary_is_deterministic_and_lists_all_entries() {
        let allow = make_tuple(Verdict::Allow, "urn:chio:error:none", &["tool:read"]);
        let deny = make_tuple(
            Verdict::Deny,
            "urn:chio:error:capability:scope-exceeded",
            &["tool:read"],
        );
        let mut report = CrossLanguageReport::new();
        report.add_driver(driver_report(
            "rust-kernel",
            &[("scenario-a", allow.clone()), ("scenario-b", allow.clone())],
        ));
        report.add_driver(driver_report(
            "wasm-browser",
            &[("scenario-a", deny.clone()), ("scenario-b", deny.clone())],
        ));
        let mut expected = BTreeMap::new();
        expected.insert(String::from("scenario-a"), allow.clone());
        expected.insert(String::from("scenario-b"), allow.clone());
        let divergences = diff_cross_language_against_expected(&expected, &report);
        let rendered = divergence_summary(&divergences);
        assert!(
            rendered.starts_with(&format!(
                "{} cross-language divergence(s):",
                divergences.len()
            )),
            "summary should start with a count line: `{rendered}`"
        );
        // scenario-a appears before scenario-b in BTree order.
        let scenario_a_index = match rendered.find("scenario-a") {
            Some(index) => index,
            None => panic!("rendered summary missing scenario-a: {rendered}"),
        };
        let scenario_b_index = match rendered.find("scenario-b") {
            Some(index) => index,
            None => panic!("rendered summary missing scenario-b: {rendered}"),
        };
        assert!(scenario_a_index < scenario_b_index);
    }
}
