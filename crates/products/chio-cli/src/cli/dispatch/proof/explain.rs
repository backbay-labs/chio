use super::*;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

#[derive(serde::Serialize)]
struct ProofExplainReport {
    schema: &'static str,
    claim_id: String,
    status: &'static str,
    bundle: String,
    passport_path: String,
    verifier_report_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verifier_error: Option<String>,
    #[serde(rename = "failureCode", skip_serializing_if = "Option::is_none")]
    failure_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    checker: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    caveat: Option<String>,
    evidence_paths: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    receipt_coverage: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_web: Option<ProofExplainAgentWeb>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risk: Option<ProofExplainRisk>,
}

#[derive(serde::Serialize)]
struct ProofExplainAgentWeb {
    projections: Vec<serde_json::Value>,
    unsupported_claims: Vec<String>,
    limitations: Vec<String>,
}

#[derive(serde::Serialize)]
struct ProofExplainRisk {
    risk_comptroller_report_ref: String,
    facility: serde_json::Value,
    facility_lifecycle: Vec<serde_json::Value>,
    coverage: serde_json::Value,
    reconciliation: serde_json::Value,
    actuarial_evidence: serde_json::Value,
    insurance_copy: serde_json::Value,
    reserve_ledger: Vec<serde_json::Value>,
    sanction_reserve_ledger: Vec<serde_json::Value>,
    appeals: Vec<serde_json::Value>,
}

pub(super) fn explain_proof_claim(
    bundle: &Path,
    claim_id: &str,
    json_output: bool,
) -> Result<(), CliError> {
    let archive_root = archive::extract_proof_archive(bundle)?;
    let input_path = match archive_root.as_ref() {
        Some(archive_root) => archive_root.path(),
        None => bundle,
    };
    verify_proof_room_bundle_if_present(input_path)?;
    let passport_path = resolve_proof_passport_path(input_path)?;
    let manifest_claim = load_manifest_claim(input_path, claim_id)?;
    let receipt_coverage = load_explain_receipt_coverage(input_path, claim_id)?;
    let manifest_metadata = manifest_claim_metadata(manifest_claim.as_ref());
    let verification = verify_transaction_passport_file(&passport_path);
    let (status, verifier_report_id, verifier_error, failure_code, evidence_paths, agent_web, risk) =
        match verification {
            Ok(report) => {
                ensure_explain_claim_known(manifest_claim.as_ref(), &report, claim_id)?;
                let verified = proof_claim_verified(&report, manifest_claim.as_ref(), claim_id);
                (
                    if verified { "verified" } else { "not_verified" },
                    report
                        .get("id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                    None,
                    None,
                    proof_claim_evidence_paths(&report, &passport_path, manifest_claim.as_ref()),
                    agent_web_claim_details(&report, claim_id),
                    risk_claim_details(&report, &passport_path, claim_id)?,
                )
            }
            Err(error) => {
                ensure_failed_explain_claim_known(manifest_claim.as_ref(), claim_id)?;
                (
                    "failed",
                    None,
                    Some(error.to_string()),
                    cli_error_failure_code(&error),
                    proof_claim_failure_evidence_paths(&passport_path, manifest_claim.as_ref()),
                    None,
                    None,
                )
            }
        };
    let explain_report = ProofExplainReport {
        schema: "chio.proof.explain-report.v1",
        claim_id: claim_id.to_string(),
        status,
        bundle: bundle.to_string_lossy().into_owned(),
        passport_path: passport_path.to_string_lossy().into_owned(),
        verifier_report_id,
        verifier_error,
        failure_code,
        checker: manifest_metadata.checker,
        proof_level: manifest_metadata.proof_level,
        caveat: manifest_metadata.caveat,
        evidence_paths,
        receipt_coverage,
        agent_web,
        risk,
    };
    write_explain_report(&explain_report, json_output)
}

fn write_explain_report(report: &ProofExplainReport, json_output: bool) -> Result<(), CliError> {
    let mut stdout = std::io::stdout();
    if json_output {
        serde_json::to_writer(&mut stdout, report)?;
        stdout.write_all(b"\n")?;
    } else {
        writeln!(stdout, "claim: {}", report.claim_id)?;
        writeln!(stdout, "status: {}", report.status)?;
        if let Some(error) = &report.verifier_error {
            writeln!(stdout, "verifier-error: {error}")?;
        }
        if let Some(failure_code) = &report.failure_code {
            writeln!(stdout, "failure-code: {failure_code}")?;
        }
        if let Some(checker) = &report.checker {
            writeln!(stdout, "checker: {checker}")?;
        }
        if let Some(proof_level) = &report.proof_level {
            writeln!(stdout, "proof-level: {proof_level}")?;
        }
        if let Some(caveat) = &report.caveat {
            writeln!(stdout, "caveat: {caveat}")?;
        }
        for path in &report.evidence_paths {
            writeln!(stdout, "evidence: {path}")?;
        }
        for coverage in &report.receipt_coverage {
            write_receipt_coverage_line(&mut stdout, coverage)?;
        }
        if let Some(agent_web) = &report.agent_web {
            for projection in &agent_web.projections {
                write_agent_web_projection_line(&mut stdout, projection)?;
            }
            for claim in &agent_web.unsupported_claims {
                writeln!(stdout, "agent-web-unsupported-claim: {claim}")?;
            }
            for limitation in &agent_web.limitations {
                writeln!(stdout, "agent-web-limitation: {limitation}")?;
            }
        }
        if let Some(risk) = &report.risk {
            writeln!(
                stdout,
                "risk-comptroller-report: {}",
                risk.risk_comptroller_report_ref
            )?;
            write_risk_value_line(&mut stdout, "risk-facility", &risk.facility)?;
            for transition in &risk.facility_lifecycle {
                write_risk_value_line(&mut stdout, "risk-facility-transition", transition)?;
            }
            write_risk_value_line(&mut stdout, "risk-coverage", &risk.coverage)?;
            write_risk_value_line(&mut stdout, "risk-reconciliation", &risk.reconciliation)?;
            write_risk_value_line(&mut stdout, "risk-actuarial", &risk.actuarial_evidence)?;
            write_risk_value_line(&mut stdout, "risk-insurance-copy", &risk.insurance_copy)?;
            for entry in &risk.reserve_ledger {
                write_risk_value_line(&mut stdout, "risk-reserve-ledger", entry)?;
            }
            for entry in &risk.sanction_reserve_ledger {
                write_risk_value_line(&mut stdout, "risk-sanction-reserve-ledger", entry)?;
            }
            for appeal in &risk.appeals {
                write_risk_value_line(&mut stdout, "risk-appeal", appeal)?;
            }
        }
    }
    Ok(())
}

fn cli_error_failure_code(error: &CliError) -> Option<String> {
    match error {
        CliError::Chio(error) => Some(error.code().as_str().to_string()),
        _ => None,
    }
}

struct ManifestClaimMetadata {
    checker: Option<String>,
    proof_level: Option<String>,
    caveat: Option<String>,
}

fn manifest_claim_metadata(
    manifest_claim: Option<&ProofBundleManifestClaim>,
) -> ManifestClaimMetadata {
    let Some(claim) = manifest_claim else {
        return ManifestClaimMetadata {
            checker: None,
            proof_level: None,
            caveat: None,
        };
    };

    ManifestClaimMetadata {
        checker: non_empty_manifest_string(claim.checker.clone()),
        proof_level: non_empty_manifest_string(claim.proof_level.clone()),
        caveat: non_empty_manifest_string(claim.caveat.clone()),
    }
}

fn non_empty_manifest_string(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

fn write_agent_web_projection_line(
    stdout: &mut impl Write,
    projection: &serde_json::Value,
) -> Result<(), CliError> {
    let source_protocol = projection
        .get("source_protocol")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let external_subject_digest = projection
        .get("external_subject_digest")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    writeln!(
        stdout,
        "agent-web-projection: {source_protocol} {external_subject_digest}"
    )?;
    Ok(())
}

fn write_risk_value_line(
    stdout: &mut impl Write,
    label: &str,
    value: &serde_json::Value,
) -> Result<(), CliError> {
    write!(stdout, "{label}: ")?;
    serde_json::to_writer(&mut *stdout, value)?;
    stdout.write_all(b"\n")?;
    Ok(())
}

fn write_receipt_coverage_line(
    stdout: &mut impl Write,
    coverage: &serde_json::Value,
) -> Result<(), CliError> {
    let Some(category) = coverage.get("category").and_then(serde_json::Value::as_str) else {
        return Ok(());
    };
    let status = coverage
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    match coverage
        .get("terminal_status")
        .and_then(serde_json::Value::as_str)
    {
        Some(terminal_status) => {
            writeln!(stdout, "coverage: {category} {status} {terminal_status}")?;
        }
        None => {
            writeln!(stdout, "coverage: {category} {status}")?;
        }
    }
    if let Some(reason) = coverage
        .get("exclusion_reason")
        .and_then(serde_json::Value::as_str)
    {
        writeln!(stdout, "coverage-reason: {reason}")?;
    }
    Ok(())
}

fn load_explain_receipt_coverage(
    bundle: &Path,
    claim_id: &str,
) -> Result<Vec<serde_json::Value>, CliError> {
    if claim_id != "claim.proof_room.receipt_coverage_matrix_bound" {
        return Ok(Vec::new());
    }
    let Some(manifest_path) = proof_room_manifest_path(bundle) else {
        return Ok(Vec::new());
    };
    let manifest_bytes = fs::read(manifest_path)?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)?;
    Ok(manifest
        .get("receipt_coverage")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default())
}

fn proof_room_manifest_path(bundle: &Path) -> Option<PathBuf> {
    proof_room_bundle_manifest_path_for_input(bundle)
}

fn proof_claim_evidence_paths(
    report: &serde_json::Value,
    passport_path: &Path,
    manifest_claim: Option<&ProofBundleManifestClaim>,
) -> Vec<String> {
    if let Some(claim) = manifest_claim {
        let mut paths = manifest_claim_evidence_paths(claim);
        push_passport_support_evidence_paths(passport_path, &mut paths);
        return paths;
    }

    let mut paths = Vec::new();
    let passport_evidence_path = report
        .get("passport_path")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| passport_path.to_string_lossy().into_owned());
    paths.push(passport_evidence_path);
    push_passport_support_evidence_paths(passport_path, &mut paths);
    paths
}

fn proof_claim_failure_evidence_paths(
    passport_path: &Path,
    manifest_claim: Option<&ProofBundleManifestClaim>,
) -> Vec<String> {
    if let Some(claim) = manifest_claim {
        let mut paths = manifest_claim_evidence_paths(claim);
        push_passport_support_evidence_paths(passport_path, &mut paths);
        return paths;
    }

    let mut paths = vec![passport_path.to_string_lossy().into_owned()];
    push_passport_support_evidence_paths(passport_path, &mut paths);
    paths
}

fn agent_web_claim_details(
    report: &serde_json::Value,
    claim_id: &str,
) -> Option<ProofExplainAgentWeb> {
    if !claim_id.starts_with("claim.agent_web.") {
        return None;
    }

    let reports = reports_with_claim(report, claim_id);
    let projections = reports
        .iter()
        .flat_map(|report| {
            report
                .get("projections")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter(|projection| projection_supports_claim(projection, claim_id))
        .cloned()
        .collect::<Vec<_>>();
    let unsupported_claims = string_array_field_from_reports(&reports, "unsupported_claims");
    let limitations = string_array_field_from_reports(&reports, "limitations");

    if projections.is_empty() && unsupported_claims.is_empty() && limitations.is_empty() {
        None
    } else {
        Some(ProofExplainAgentWeb {
            projections,
            unsupported_claims,
            limitations,
        })
    }
}

fn reports_with_claim<'a>(
    report: &'a serde_json::Value,
    claim_id: &str,
) -> Vec<&'a serde_json::Value> {
    let mut reports = report
        .get("family_reports")
        .and_then(serde_json::Value::as_array)
        .map(|family_reports| {
            family_reports
                .iter()
                .filter(|family_report| report_verifies_claim(family_report, claim_id))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if report_verifies_claim(report, claim_id) {
        reports.push(report);
    }
    reports
}

fn report_verifies_claim(report: &serde_json::Value, claim_id: &str) -> bool {
    verified_claims_array(report)
        .is_some_and(|claims| claims.iter().any(|claim| claim.as_str() == Some(claim_id)))
}

fn projection_supports_claim(projection: &serde_json::Value, claim_id: &str) -> bool {
    projection
        .get("claim_evidence")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|claim_evidence| {
            claim_evidence.iter().any(|entry| {
                entry.get("claim_ref").and_then(serde_json::Value::as_str) == Some(claim_id)
            })
        })
}

fn risk_claim_details(
    report: &serde_json::Value,
    passport_path: &Path,
    claim_id: &str,
) -> Result<Option<ProofExplainRisk>, CliError> {
    if !claim_id.starts_with("claim.risk.") {
        return Ok(None);
    }
    let Some(risk_ref) = risk_comptroller_report_ref(report) else {
        return Ok(None);
    };
    let Some(risk_report) = load_bound_risk_comptroller_report(passport_path, risk_ref)? else {
        return Ok(None);
    };

    Ok(Some(ProofExplainRisk {
        risk_comptroller_report_ref: risk_ref.to_string(),
        facility: risk_report
            .get("facility")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        facility_lifecycle: value_array_field(&risk_report, "facility_lifecycle"),
        coverage: risk_report
            .get("coverage")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        reconciliation: risk_report
            .get("reconciliation")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        actuarial_evidence: risk_report
            .get("actuarial_evidence")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        insurance_copy: risk_report
            .get("insurance_copy")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        reserve_ledger: value_array_field(&risk_report, "reserve_ledger"),
        sanction_reserve_ledger: value_array_field(&risk_report, "sanction_reserve_ledger"),
        appeals: value_array_field(&risk_report, "appeals"),
    }))
}

fn risk_comptroller_report_ref(report: &serde_json::Value) -> Option<&str> {
    risk_comptroller_report_ref_from_report(report).or_else(|| {
        report
            .get("family_reports")
            .and_then(serde_json::Value::as_array)
            .and_then(|family_reports| {
                family_reports
                    .iter()
                    .find_map(risk_comptroller_report_ref_from_report)
            })
    })
}

fn risk_comptroller_report_ref_from_report(report: &serde_json::Value) -> Option<&str> {
    report
        .get("risk_comptroller_report_ref")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            report
                .get("trust_market_sections")
                .and_then(|sections| sections.get("risk_comptroller_report_ref"))
                .and_then(serde_json::Value::as_str)
        })
}

fn load_bound_risk_comptroller_report(
    passport_path: &Path,
    risk_ref: &str,
) -> Result<Option<serde_json::Value>, CliError> {
    let passport = read_transaction_passport(passport_path)?;
    let evidence_graph_path = bundle_relative_path(passport_path, &passport.evidence_graph_path)?;
    let evidence_graph_bytes = fs::read(evidence_graph_path)?;
    let evidence_graph: serde_json::Value = serde_json::from_slice(&evidence_graph_bytes)?;
    let Some(nodes) = evidence_graph
        .get("nodes")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(None);
    };

    for node in nodes {
        if !is_risk_comptroller_node(node) {
            continue;
        }
        let Some(path) = node.get("path").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let artifact_path = bundle_relative_path(passport_path, path)?;
        let artifact_bytes = fs::read(artifact_path)?;
        if !node_digest_matches(node, &artifact_bytes) {
            continue;
        }
        let artifact: serde_json::Value = serde_json::from_slice(&artifact_bytes)?;
        if artifact.get("id").and_then(serde_json::Value::as_str) == Some(risk_ref) {
            return Ok(Some(artifact));
        }
    }

    Ok(None)
}

fn read_transaction_passport(
    passport_path: &Path,
) -> Result<chio_control_plane::transaction_passport::TransactionPassport, CliError> {
    let bytes = fs::read(passport_path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn bundle_relative_path(passport_path: &Path, relative: &str) -> Result<PathBuf, CliError> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(CliError::cli_other_error(format!(
            "proof explain: unsafe bundle-relative path: {relative}"
        )));
    }
    Ok(passport_path
        .parent()
        .map(|parent| parent.join(path))
        .unwrap_or_else(|| path.to_path_buf()))
}

fn is_risk_comptroller_node(node: &serde_json::Value) -> bool {
    node.get("schema").and_then(serde_json::Value::as_str)
        == Some("chio.risk.comptroller-report.v1")
        || node.get("role").and_then(serde_json::Value::as_str) == Some("risk-comptroller-report")
}

fn node_digest_matches(node: &serde_json::Value, bytes: &[u8]) -> bool {
    node.get("sha256")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|sha256| sha256 == chio_core::sha256_hex(bytes))
}

fn string_array_field(report: &serde_json::Value, field: &str) -> Vec<String> {
    report
        .get(field)
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn string_array_field_from_reports(reports: &[&serde_json::Value], field: &str) -> Vec<String> {
    let mut values = Vec::new();
    for report in reports {
        for value in string_array_field(report, field) {
            if !values.iter().any(|existing| existing == &value) {
                values.push(value);
            }
        }
    }
    values
}

fn value_array_field(report: &serde_json::Value, field: &str) -> Vec<serde_json::Value> {
    report
        .get(field)
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn manifest_claim_evidence_paths(claim: &ProofBundleManifestClaim) -> Vec<String> {
    let mut paths = claim.required_artifacts.clone();
    for source_ref in &claim.source_refs {
        if !paths.iter().any(|path| path == source_ref) {
            paths.push(source_ref.clone());
        }
    }
    paths
}

fn ensure_explain_claim_known(
    manifest_claim: Option<&ProofBundleManifestClaim>,
    report: &serde_json::Value,
    claim_id: &str,
) -> Result<(), CliError> {
    if manifest_claim.is_some()
        || claim_id == "claim.transaction.passport_root_verified"
        || report_mentions_claim(report, claim_id)
    {
        return Ok(());
    }

    Err(unknown_proof_claim(claim_id))
}

fn ensure_failed_explain_claim_known(
    manifest_claim: Option<&ProofBundleManifestClaim>,
    claim_id: &str,
) -> Result<(), CliError> {
    if manifest_claim.is_some()
        || claim_id == "claim.transaction.passport_root_verified"
        || VERIFIER_CLAIM_PREFIXES
            .iter()
            .any(|prefix| claim_id.starts_with(prefix))
    {
        return Ok(());
    }

    Err(unknown_proof_claim(claim_id))
}

fn unknown_proof_claim(claim_id: &str) -> CliError {
    CliError::cli_other_error(format!("unknown proof claim: {claim_id}"))
}

fn report_mentions_claim(report: &serde_json::Value, claim_id: &str) -> bool {
    report_verifies_claim(report, claim_id)
        || claim_results_mention_claim(report, claim_id)
        || report
            .get("family_reports")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|family_reports| {
                family_reports
                    .iter()
                    .any(|family_report| report_mentions_claim(family_report, claim_id))
            })
}

fn claim_results_mention_claim(report: &serde_json::Value, claim_id: &str) -> bool {
    report
        .get("claimResults")
        .or_else(|| report.get("claim_results"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|results| {
            results.iter().any(|result| {
                result
                    .get("claim_id")
                    .or_else(|| result.get("claimId"))
                    .and_then(serde_json::Value::as_str)
                    == Some(claim_id)
            })
        })
}

fn push_passport_support_evidence_paths(passport_path: &Path, paths: &mut Vec<String>) {
    if let Ok(passport_bytes) = fs::read(passport_path) {
        if let Ok(passport) = serde_json::from_slice::<
            chio_control_plane::transaction_passport::TransactionPassport,
        >(&passport_bytes)
        {
            push_bundle_relative_evidence_path(passport_path, paths, &passport.evidence_graph_path);
            push_bundle_relative_evidence_path(
                passport_path,
                paths,
                &passport.verifier_policy_path,
            );
        }
    }
}

fn push_bundle_relative_evidence_path(
    passport_path: &Path,
    paths: &mut Vec<String>,
    relative: &str,
) {
    let path = passport_path
        .parent()
        .map(|parent| parent.join(relative))
        .unwrap_or_else(|| PathBuf::from(relative))
        .to_string_lossy()
        .into_owned();
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

fn proof_claim_verified(
    report: &serde_json::Value,
    manifest_claim: Option<&ProofBundleManifestClaim>,
    claim_id: &str,
) -> bool {
    if report.get("verdict").and_then(serde_json::Value::as_str) != Some("verified") {
        return false;
    }
    if verified_claims_array(report)
        .is_some_and(|claims| claims.iter().any(|claim| claim.as_str() == Some(claim_id)))
    {
        return true;
    }
    if let Some(claim) = manifest_claim {
        return claim.result == "verified";
    }
    claim_id == "claim.transaction.passport_root_verified"
}
