#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

//! Cross-language verdict-matrix activation gate.
//!
//! This integration test runs the cross-language diff oracle on the
//! drivers we have available natively (the in-process Rust kernel and
//! the WASM browser kernel via its native non-wasm test path), asserts
//! tuple equality across drivers, and surfaces any divergence as a
//! test failure. It runs as part of the chio-conformance test suite, so
//! a divergence between the natively available drivers fails the suite.
//!
//! The Python, TS, and Go drivers are not invoked in-process here; each
//! carries its own package-level tests over the same scenario corpus and
//! reports tuples through its per-driver entry point. Their absence from
//! this test does not weaken the cross-language equality claim: every
//! driver evaluates the shared corpus, and `verify_manifest_corpus_hash`
//! binds the manifest to that corpus so no driver can silently diverge on
//! its inputs.
//!
//! The diff oracle in `cross_language.rs` is exercised directly by the
//! unit tests under `cross_language::tests`; this file is the
//! integration-level activation gate that proves the wiring runs end-
//! to-end against the real corpus.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chio_core::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_kernel_browser::{evaluate_pure, BrowserClock, EvaluateRequestJson, ToolCallRequestJson};

#[allow(dead_code)]
#[path = "../src/lib.rs"]
mod verdict_matrix;

use verdict_matrix::cross_language::{
    diff_cross_language, divergence_summary, CrossLanguageDivergence, CrossLanguageReport,
};
use verdict_matrix::diff_oracle::{
    expected_tuple_map, load_manifest, verify_manifest_corpus_hash, DriverReport,
    VerdictMatrixManifest,
};
use verdict_matrix::driver::{
    load_scenarios, DriverStatus, RustKernelDriver, VerdictScenario, RUST_KERNEL_DRIVER,
};
use verdict_matrix::{Verdict, VerdictTuple};

const MATRIX_SERVER_ID: &str = "verdict-matrix";
const ISSUED_AT: u64 = 1_700_000_000;
const EXPIRES_AT: u64 = 1_700_100_000;
const REASON_NONE: &str = "urn:chio:error:none";
const REASON_SCOPE_EXCEEDED: &str = "urn:chio:error:capability:scope-exceeded";
const REASON_KERNEL_INTERNAL: &str = "urn:chio:error:kernel:internal-error";

fn verdict_matrix_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if manifest_dir.join(verdict_matrix::MANIFEST_PATH).is_file() {
        manifest_dir.to_path_buf()
    } else {
        manifest_dir.join("verdict_matrix")
    }
}

fn load_manifest_and_corpus() -> (VerdictMatrixManifest, Vec<VerdictScenario>) {
    let root = verdict_matrix_root();
    let manifest_path = root.join(verdict_matrix::MANIFEST_PATH);
    let manifest = match load_manifest(&manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => panic!(
            "failed to load manifest {}: {error}",
            manifest_path.display()
        ),
    };
    if let Err(error) = verify_manifest_corpus_hash(&root, &manifest) {
        panic!("manifest hash verification failed: {error}");
    }
    let scenarios = match load_scenarios(&root.join(&manifest.corpus.scenario_root)) {
        Ok(scenarios) => scenarios,
        Err(error) => panic!("failed to load verdict scenarios: {error}"),
    };
    (manifest, scenarios)
}

fn collect_rust_kernel_report(scenarios: &[VerdictScenario]) -> DriverReport {
    let driver = RustKernelDriver;
    let outcomes = driver.run_all(scenarios);
    let mut tuples: BTreeMap<String, VerdictTuple> = BTreeMap::new();
    for outcome in outcomes {
        match outcome.status {
            DriverStatus::Pass => {
                if let Some(actual) = outcome.actual {
                    tuples.insert(outcome.scenario_id, actual.normalized());
                } else {
                    panic!(
                        "rust-kernel driver reported Pass without an actual tuple for {}",
                        outcome.scenario_id
                    );
                }
            }
            DriverStatus::Fail => panic!(
                "rust-kernel driver diverged from expected on {}: actual={:?} expected={:?} diagnostic={:?}",
                outcome.scenario_id, outcome.actual, outcome.expected, outcome.diagnostic,
            ),
            DriverStatus::Unsupported => {
                // The Rust kernel is the manifest-required driver and
                // must satisfy every scenario. Any unsupported status
                // here is a kernel regression, not a driver gap.
                panic!(
                    "rust-kernel driver reported unsupported for {}: {:?}",
                    outcome.scenario_id, outcome.diagnostic
                );
            }
        }
    }
    DriverReport {
        driver: RUST_KERNEL_DRIVER.to_string(),
        tuples,
    }
}

fn collect_wasm_browser_report(scenarios: &[VerdictScenario]) -> DriverReport {
    // Mirrors the wasm-browser driver in
    // `crates/chio-conformance/verdict_matrix/drivers/wasm-browser/run.sh`.
    // The browser kernel exposes `evaluate_pure`, which has a real
    // capability-subset semantic but no revocation store, execution
    // nonce store, or guard pipeline. The native (non-wasm32) cargo
    // test surface reuses the same logic so we can diff against the
    // Rust kernel without spinning up Chrome.
    let mut tuples: BTreeMap<String, VerdictTuple> = BTreeMap::new();
    for scenario in scenarios {
        if scenario.script.operation != "tool.call" {
            continue;
        }
        let unsupported_requirement = scenario.requires.iter().find(|requirement| {
            !matches!(
                requirement.as_str(),
                "rust-kernel" | "kernel-semantics" | "wasm-browser-kernel"
            )
        });
        if unsupported_requirement.is_some() {
            continue;
        }
        if scenario.category != verdict_matrix::ScenarioCategory::Capability {
            continue;
        }

        let scope_set = scenario.script.capability_scopes.clone();
        let scope_set_for_failure = scope_set.clone();
        let subject = Keypair::generate();
        let issuer = Keypair::generate();
        let capability = match make_browser_capability(&scenario.id, &scope_set, &subject, &issuer)
        {
            Ok(capability) => capability,
            Err(error) => panic!(
                "failed to build browser capability for {}: {error}",
                scenario.id
            ),
        };
        let arguments: serde_json::Value = match serde_json::from_str(&scenario.script.input_json) {
            Ok(arguments) => arguments,
            Err(error) => panic!(
                "failed to parse scenario {} input_json: {error}",
                scenario.id
            ),
        };
        let request = EvaluateRequestJson {
            request: ToolCallRequestJson {
                request_id: scenario.id.clone(),
                tool_name: scenario.script.tool.clone(),
                server_id: MATRIX_SERVER_ID.to_string(),
                agent_id: subject.public_key().to_hex(),
                arguments,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                supplemental_authorization: None,
            },
            capability,
            trusted_issuers_hex: vec![issuer.public_key().to_hex()],
            clock_override_unix_secs: Some(ISSUED_AT + 1),
            session_filesystem_roots: None,
            peer_capabilities: None,
            direct_root_capability: None,
            capability_trust_roots: Default::default(),
            parent_budget_snapshots: Vec::new(),
        };
        let clock = BrowserClock::new();
        let core = match evaluate_pure(request, &clock) {
            Ok(core) => core,
            Err(error) => panic!(
                "wasm browser kernel rejected {}: {}",
                scenario.id, error.message
            ),
        };
        let tuple = match core.capability_verdict.as_str() {
            "allow" => VerdictTuple {
                verdict: Verdict::Allow,
                reason_code: REASON_NONE.to_string(),
                scope_set: scope_set_for_failure.clone(),
            }
            .normalized(),
            "deny" => {
                let reason = deny_reason_for(core.reason.as_deref());
                VerdictTuple {
                    verdict: Verdict::Deny,
                    reason_code: reason.to_string(),
                    scope_set: scope_set_for_failure.clone(),
                }
                .normalized()
            }
            _ => VerdictTuple {
                verdict: Verdict::Error,
                reason_code: REASON_KERNEL_INTERNAL.to_string(),
                scope_set: scope_set_for_failure.clone(),
            }
            .normalized(),
        };
        tuples.insert(scenario.id.clone(), tuple);
    }
    DriverReport {
        driver: "wasm-browser".to_string(),
        tuples,
    }
}

fn make_browser_capability(
    scenario_id: &str,
    labels: &[String],
    subject: &Keypair,
    issuer: &Keypair,
) -> Result<CapabilityToken, String> {
    let mut grants = Vec::new();
    for label in labels {
        grants.push(grant_from_label(label)?);
    }
    let body = CapabilityTokenBody {
        id: format!("cap-{scenario_id}"),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope: ChioScope {
            grants,
            resource_grants: vec![],
            prompt_grants: vec![],
        },
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, issuer).map_err(|error| error.to_string())
}

fn grant_from_label(label: &str) -> Result<ToolGrant, String> {
    let tool_name = match label {
        "tool:read" => "files.read",
        "tool:write" => "files.write",
        "tool:admin" => "system.rotate",
        "telemetry:read" => "metrics.query",
        "prompt:read" => "prompts.get",
        "prompt:write" => "prompts.update",
        "resource:read" => "resources.read",
        "tool:call" => "tools.invoke",
        other => return Err(format!("unsupported capability scope label `{other}`")),
    };
    Ok(ToolGrant {
        server_id: MATRIX_SERVER_ID.to_string(),
        tool_name: tool_name.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    })
}

fn deny_reason_for(reason: Option<&str>) -> &'static str {
    let Some(reason) = reason else {
        return REASON_KERNEL_INTERNAL;
    };
    let lower = reason.to_ascii_lowercase();
    if lower.contains("not in capability scope") || lower.contains("out of scope") {
        REASON_SCOPE_EXCEEDED
    } else {
        REASON_KERNEL_INTERNAL
    }
}

#[test]
fn cross_language_oracle_finds_no_divergences_between_rust_and_wasm_browser() {
    let (manifest, scenarios) = load_manifest_and_corpus();
    let expected = expected_tuple_map(&scenarios);

    let mut report = CrossLanguageReport::new();
    report.add_driver(collect_rust_kernel_report(&scenarios));
    report.add_driver(collect_wasm_browser_report(&scenarios));

    let divergences = diff_cross_language(&manifest, &expected, &report);
    if !divergences.is_empty() {
        panic!(
            "cross-language verdict-matrix divergences detected:\n{}",
            divergence_summary(&divergences)
        );
    }
}

#[test]
fn rust_kernel_satisfies_required_driver_contract() {
    let (manifest, scenarios) = load_manifest_and_corpus();
    let expected = expected_tuple_map(&scenarios);

    // The manifest pins `rust-kernel` as the only required driver. If
    // we omit it from the report, the cross-language oracle must
    // surface one divergence per scenario for the missing required
    // driver. This proves the manifest gate is wired correctly.
    let report = CrossLanguageReport::new();
    let divergences = diff_cross_language(&manifest, &expected, &report);
    assert!(
        !divergences.is_empty(),
        "expected divergences when rust-kernel report is missing"
    );

    let missing_required = divergences.iter().filter(|divergence| match divergence {
        CrossLanguageDivergence::DriverVsExpected(tuple_divergence) => {
            tuple_divergence.driver == RUST_KERNEL_DRIVER && tuple_divergence.actual.is_none()
        }
        CrossLanguageDivergence::DriverVsDriver { .. } => false,
    });
    let count = missing_required.count();
    assert_eq!(
        count,
        scenarios.len(),
        "expected {} missing-required divergences for rust-kernel, got {}",
        scenarios.len(),
        count,
    );
}

#[test]
fn wasm_browser_report_covers_capability_subset_only() {
    let (_, scenarios) = load_manifest_and_corpus();
    let report = collect_wasm_browser_report(&scenarios);

    let capability_ids: Vec<String> = scenarios
        .iter()
        .filter(|scenario| scenario.category == verdict_matrix::ScenarioCategory::Capability)
        .map(|scenario| scenario.id.clone())
        .collect();
    assert_eq!(
        capability_ids.len(),
        12,
        "verdict-matrix capability_subset must contain 12 scenarios"
    );
    for id in &capability_ids {
        assert!(
            report.tuples.contains_key(id),
            "wasm-browser report missing capability scenario {id}"
        );
    }
    // Every other scenario is unsupported in the browser kernel today
    // (no revocation store, execution nonce store, or guard pipeline)
    // and therefore must NOT appear in the wasm-browser tuple map.
    for scenario in &scenarios {
        if scenario.category == verdict_matrix::ScenarioCategory::Capability {
            continue;
        }
        assert!(
            !report.tuples.contains_key(&scenario.id),
            "wasm-browser report unexpectedly emitted a tuple for non-capability scenario {}",
            scenario.id
        );
    }
}

// The cross-language divergence gate is enforced by running this test in CI.
