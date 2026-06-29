use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use chio_conformance::{
    generate_markdown_report, CompatibilityReport, ResultStatus, ScenarioDescriptor, ScenarioResult,
};
use chio_core::{canonical_json_bytes, sha256_hex, Keypair};

use crate::CliError;

use super::helpers::unix_now;
use super::schema::{
    CERTIFICATION_PROVENANCE_MODE_ARTIFACT_SIGNER, CERTIFICATION_SCHEMA,
    CRITERIA_PROFILE_ALL_PASS_V1, EVIDENCE_PROFILE_CONFORMANCE_REPORT_BUNDLE_V1,
    GENERATED_REPORT_MEDIA_TYPE_MARKDOWN,
};
use super::types::{
    CertificationCheckBody, CertificationCriterion, CertificationEvidence, CertificationFinding,
    CertificationSummary, CertificationTarget, CertificationVerdict, CriterionStatus,
    EvaluationArtifacts, SignedCertificationCheck,
};

pub(crate) fn build_certification_body(
    criteria_profile: &str,
    tool_server_id: &str,
    tool_server_name: Option<&str>,
    scenarios_dir: &Path,
    results_dir: &Path,
    report_output: Option<&Path>,
    scenarios: Vec<ScenarioDescriptor>,
    results: Vec<ScenarioResult>,
) -> Result<(CertificationCheckBody, Vec<u8>), CliError> {
    if criteria_profile != CRITERIA_PROFILE_ALL_PASS_V1 {
        return Err(CliError::attest_error(format!(
            "unsupported certification criteria profile: {criteria_profile}"
        )));
    }

    let report = CompatibilityReport {
        scenarios: scenarios.clone(),
        results: results.clone(),
    };
    let report_markdown = generate_markdown_report(&report);
    let report_bytes = report_markdown.as_bytes().to_vec();

    let evaluation = evaluate_all_pass_profile(&scenarios, &results);
    let evidence = CertificationEvidence {
        evidence_profile: EVIDENCE_PROFILE_CONFORMANCE_REPORT_BUNDLE_V1.to_string(),
        scenarios_dir: scenarios_dir.display().to_string(),
        results_dir: results_dir.display().to_string(),
        normalized_scenarios_sha256: sha256_hex(&canonical_json_bytes(&scenarios)?),
        normalized_results_sha256: sha256_hex(&canonical_json_bytes(&results)?),
        generated_report_sha256: sha256_hex(&report_bytes),
        generated_report_bytes: report_bytes.len(),
        generated_report_media_type: GENERATED_REPORT_MEDIA_TYPE_MARKDOWN.to_string(),
        provenance_mode: CERTIFICATION_PROVENANCE_MODE_ARTIFACT_SIGNER.to_string(),
        report_output: report_output.map(|path| path.display().to_string()),
    };

    let body = CertificationCheckBody {
        schema: CERTIFICATION_SCHEMA.to_string(),
        criteria_profile: criteria_profile.to_string(),
        checked_at: unix_now(),
        target: CertificationTarget {
            tool_server_id: tool_server_id.to_string(),
            tool_server_name: tool_server_name.map(ToOwned::to_owned),
        },
        verdict: evaluation.verdict,
        summary: evaluation.summary,
        criteria: evaluation.criteria,
        evidence,
        findings: evaluation.findings,
    };
    Ok((body, report_bytes))
}

pub(crate) fn evaluate_all_pass_profile(
    scenarios: &[ScenarioDescriptor],
    results: &[ScenarioResult],
) -> EvaluationArtifacts {
    let scenario_ids = scenarios
        .iter()
        .map(|scenario| scenario.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut results_by_scenario = BTreeMap::<String, usize>::new();
    let mut findings = Vec::new();

    for result in results {
        if scenario_ids.contains(result.scenario_id.as_str()) {
            *results_by_scenario
                .entry(result.scenario_id.clone())
                .or_insert(0) += 1;
        } else {
            findings.push(CertificationFinding {
                kind: "unknown-scenario-result".to_string(),
                message: format!(
                    "result references unknown scenario `{}`",
                    result.scenario_id
                ),
                scenario_id: Some(result.scenario_id.clone()),
                peer: Some(result.peer.clone()),
                deployment_mode: Some(result.deployment_mode.label().to_string()),
                transport: Some(result.transport.label().to_string()),
                status: Some(result.status),
            });
        }
    }

    for scenario in scenarios {
        if scenario.expected != ResultStatus::Pass {
            findings.push(CertificationFinding {
                kind: "scenario-expectation-not-certifiable".to_string(),
                message: format!(
                    "scenario `{}` has non-pass expected status `{}`",
                    scenario.id,
                    scenario.expected.label()
                ),
                scenario_id: Some(scenario.id.clone()),
                peer: None,
                deployment_mode: None,
                transport: None,
                status: Some(scenario.expected),
            });
        }
        if !results_by_scenario.contains_key(&scenario.id) {
            findings.push(CertificationFinding {
                kind: "missing-scenario-result".to_string(),
                message: format!("scenario `{}` has no result coverage", scenario.id),
                scenario_id: Some(scenario.id.clone()),
                peer: None,
                deployment_mode: None,
                transport: None,
                status: None,
            });
        }
    }

    for result in results {
        if result.status != ResultStatus::Pass {
            findings.push(CertificationFinding {
                kind: "non-pass-result".to_string(),
                message: format!(
                    "scenario `{}` returned `{}`",
                    result.scenario_id,
                    result.status.label()
                ),
                scenario_id: Some(result.scenario_id.clone()),
                peer: Some(result.peer.clone()),
                deployment_mode: Some(result.deployment_mode.label().to_string()),
                transport: Some(result.transport.label().to_string()),
                status: Some(result.status),
            });
        }
    }

    let pass_count = results
        .iter()
        .filter(|result| result.status == ResultStatus::Pass)
        .count();
    let fail_count = results
        .iter()
        .filter(|result| result.status == ResultStatus::Fail)
        .count();
    let unsupported_count = results
        .iter()
        .filter(|result| result.status == ResultStatus::Unsupported)
        .count();
    let skipped_count = results
        .iter()
        .filter(|result| result.status == ResultStatus::Skipped)
        .count();
    let xfail_count = results
        .iter()
        .filter(|result| result.status == ResultStatus::Xfail)
        .count();
    let unknown_results_count = findings
        .iter()
        .filter(|finding| finding.kind == "unknown-scenario-result")
        .count();
    let missing_scenarios_count = findings
        .iter()
        .filter(|finding| finding.kind == "missing-scenario-result")
        .count();
    let unsupported_expectation_count = findings
        .iter()
        .filter(|finding| finding.kind == "scenario-expectation-not-certifiable")
        .count();
    let unique_peers = results
        .iter()
        .map(|result| result.peer.as_str())
        .collect::<BTreeSet<_>>()
        .len();

    let criteria = vec![
        CertificationCriterion {
            id: "non-empty-scenario-corpus".to_string(),
            description: "Certification requires at least one declared scenario.".to_string(),
            status: if scenarios.is_empty() {
                CriterionStatus::Fail
            } else {
                CriterionStatus::Pass
            },
        },
        CertificationCriterion {
            id: "non-empty-result-corpus".to_string(),
            description: "Certification requires at least one observed result.".to_string(),
            status: if results.is_empty() {
                CriterionStatus::Fail
            } else {
                CriterionStatus::Pass
            },
        },
        CertificationCriterion {
            id: "scenario-coverage-complete".to_string(),
            description:
                "Every declared scenario must have at least one result and every result must map to a declared scenario."
                    .to_string(),
            status: if missing_scenarios_count == 0 && unknown_results_count == 0 {
                CriterionStatus::Pass
            } else {
                CriterionStatus::Fail
            },
        },
        CertificationCriterion {
            id: "certification-profile-supported".to_string(),
            description:
                "The alpha certification profile only supports scenario sets whose declared expectation is pass."
                    .to_string(),
            status: if unsupported_expectation_count == 0 {
                CriterionStatus::Pass
            } else {
                CriterionStatus::Fail
            },
        },
        CertificationCriterion {
            id: "all-results-pass".to_string(),
            description:
                "Every observed conformance result must be pass; fail, unsupported, skipped, and xfail block certification."
                    .to_string(),
            status: if fail_count == 0
                && unsupported_count == 0
                && skipped_count == 0
                && xfail_count == 0
                && !results.is_empty()
            {
                CriterionStatus::Pass
            } else {
                CriterionStatus::Fail
            },
        },
    ];

    let verdict = if criteria
        .iter()
        .all(|criterion| criterion.status == CriterionStatus::Pass)
    {
        CertificationVerdict::Pass
    } else {
        CertificationVerdict::Fail
    };

    EvaluationArtifacts {
        verdict,
        criteria,
        findings,
        summary: CertificationSummary {
            scenario_count: scenarios.len(),
            result_count: results.len(),
            evaluated_peer_count: unique_peers,
            pass_count,
            fail_count,
            unsupported_count,
            skipped_count,
            xfail_count,
            missing_scenarios_count,
            unknown_results_count,
        },
    }
}

pub(crate) fn sign_artifact(
    body: CertificationCheckBody,
    keypair: &Keypair,
) -> Result<SignedCertificationCheck, CliError> {
    let (signature, _) = keypair.sign_canonical(&body)?;
    Ok(SignedCertificationCheck {
        body,
        signer_public_key: keypair.public_key(),
        signature,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use chio_conformance::{
        DeploymentMode, PeerRole, RequiredCapabilities, ResultStatus, ScenarioCategory,
        ScenarioDescriptor, ScenarioResult, Transport,
    };
    use chio_core::Keypair;
    use chio_test_support::prelude::*;

    use super::super::schema::CRITERIA_PROFILE_ALL_PASS_V1;
    use super::super::types::CertificationVerdict;
    use super::{build_certification_body, evaluate_all_pass_profile, sign_artifact};

    fn scenario(id: &str) -> ScenarioDescriptor {
        ScenarioDescriptor {
            id: id.to_string(),
            title: format!("Scenario {id}"),
            area: "core".to_string(),
            category: ScenarioCategory::McpCore,
            spec_versions: vec!["2025-11-25".to_string()],
            transport: vec![Transport::Stdio],
            peer_roles: vec![PeerRole::ClientToChioServer],
            deployment_modes: vec![DeploymentMode::WrappedStdio],
            required_capabilities: RequiredCapabilities::default(),
            tags: vec!["core".to_string()],
            expected: ResultStatus::Pass,
            timeout_ms: None,
            notes: None,
        }
    }

    fn result(id: &str, status: ResultStatus) -> ScenarioResult {
        ScenarioResult {
            scenario_id: id.to_string(),
            peer: "js".to_string(),
            peer_role: PeerRole::ClientToChioServer,
            deployment_mode: DeploymentMode::WrappedStdio,
            transport: Transport::Stdio,
            spec_version: "2025-11-25".to_string(),
            category: ScenarioCategory::McpCore,
            status,
            duration_ms: 25,
            assertions: Vec::new(),
            notes: None,
            artifacts: BTreeMap::new(),
            failure_kind: None,
            failure_message: None,
            expected_failure: None,
        }
    }

    #[test]
    fn all_pass_profile_produces_pass_verdict() {
        let evaluation = evaluate_all_pass_profile(
            &[scenario("initialize")],
            &[result("initialize", ResultStatus::Pass)],
        );
        assert_eq!(evaluation.verdict, CertificationVerdict::Pass);
        assert!(evaluation.findings.is_empty());
        assert_eq!(evaluation.summary.pass_count, 1);
    }

    #[test]
    fn all_pass_profile_fails_on_missing_unknown_and_non_pass_results() {
        let evaluation = evaluate_all_pass_profile(
            &[scenario("initialize"), scenario("list-tools")],
            &[
                result("initialize", ResultStatus::Pass),
                result("unknown", ResultStatus::Fail),
                result("initialize", ResultStatus::Unsupported),
            ],
        );

        assert_eq!(evaluation.verdict, CertificationVerdict::Fail);
        assert!(evaluation
            .findings
            .iter()
            .any(|finding| finding.kind == "missing-scenario-result"));
        assert!(evaluation
            .findings
            .iter()
            .any(|finding| finding.kind == "unknown-scenario-result"));
        assert!(evaluation
            .findings
            .iter()
            .any(|finding| finding.kind == "non-pass-result"));
    }

    #[test]
    fn signed_artifact_verifies_against_body() {
        let (body, _) = build_certification_body(
            CRITERIA_PROFILE_ALL_PASS_V1,
            "demo-server",
            Some("Demo"),
            Path::new("/tmp/scenarios"),
            Path::new("/tmp/results"),
            None,
            vec![scenario("initialize")],
            vec![result("initialize", ResultStatus::Pass)],
        )
        .test_expect("build body");
        let keypair = Keypair::generate();
        let artifact = sign_artifact(body, &keypair).test_expect("sign artifact");

        assert!(artifact
            .signer_public_key
            .verify_canonical(&artifact.body, &artifact.signature)
            .test_expect("verify canonical"));
    }
}
