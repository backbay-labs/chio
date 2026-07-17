use super::{
    read_utf8_json_file, validate_runtime_relative_path, write_json_string,
    BUYER_REVIEW_ARTIFACT_FILES,
};
use crate::CliError;
use std::fs;
use std::path::Path;

use chio_errors::_generated::error_codes::TRANSACTION_BUYER_REVIEW_REJECTED;

pub(crate) fn cmd_chio_attest_buyer_package(run_output: &Path, out: &Path) -> Result<(), CliError> {
    let run_output_root = run_output.canonicalize().map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to canonicalize Chio buyer run output {}: {error}",
            run_output.display()
        ))
    })?;
    let out_parent = out.parent().unwrap_or_else(|| Path::new("."));
    if !out_parent.as_os_str().is_empty() {
        fs::create_dir_all(out_parent).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to create Chio buyer package directory {}: {error}",
                out_parent.display()
            ))
        })?;
    }
    let package_root = out_parent.canonicalize().map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to canonicalize Chio buyer package directory {}: {error}",
            out_parent.display()
        ))
    })?;
    if package_root != run_output_root {
        return Err(CliError::cli_other_error(
            "Chio buyer package --out must be written directly inside --run-output so artifact paths remain verifier-resolvable"
                .to_string(),
        ));
    }
    let mut artifacts = Vec::new();
    let mut packet_json = None;
    let mut generated_at_unix_ms = None;
    for (role, relative_path) in BUYER_REVIEW_ARTIFACT_FILES {
        validate_runtime_relative_path(relative_path)?;
        let path = run_output.join(relative_path);
        let bytes = fs::read(&path).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chio buyer review artifact {}: {error}",
                path.display()
            ))
        })?;
        if *role == "buyer_attestation_packet" {
            packet_json = Some(String::from_utf8(bytes.clone()).map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chio buyer attestation packet {} is not UTF-8 JSON: {error}",
                    path.display()
                ))
            })?);
        }
        if *role == "runtime_evidence_manifest" {
            let manifest_json = String::from_utf8(bytes.clone()).map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chio runtime evidence manifest {} is not UTF-8 JSON: {error}",
                    path.display()
                ))
            })?;
            let manifest: chio_attest_buyer::RuntimeEvidenceManifest =
                serde_json::from_str(&manifest_json).map_err(|error| {
                    CliError::cli_other_error(format!(
                        "Chio runtime evidence manifest {} parse: {error}",
                        path.display()
                    ))
                })?;
            generated_at_unix_ms = Some(manifest.generated_at_unix_ms);
        }
        let byte_count = u64::try_from(bytes.len()).map_err(|error| {
            CliError::cli_other_error(format!("Chio buyer artifact byte count: {error}"))
        })?;
        artifacts.push(chio_attest_buyer::BuyerAttestationReviewArtifactRef {
            role: (*role).to_string(),
            relative_path: (*relative_path).to_string(),
            artifact_sha256: chio_core::sha256_hex(&bytes),
            byte_count,
        });
    }
    let packet_json = packet_json.ok_or_else(|| {
        CliError::cli_other_error("Chio buyer package is missing buyer packet artifact")
    })?;
    let packet =
        chio_attest_buyer::buyer_attestation_packet_from_json(&packet_json).map_err(|error| {
            CliError::cli_other_error(format!("Chio buyer attestation packet: {error}"))
        })?;
    let generated_at_unix_ms = generated_at_unix_ms.ok_or_else(|| {
        CliError::cli_other_error("Chio buyer package is missing runtime evidence manifest")
    })?;
    let package = chio_attest_buyer::BuyerAttestationReviewPackage {
        schema: chio_attest_buyer::CHIO_ATTEST_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA.to_string(),
        package_id: format!("buyer-review:{}", packet.packet_id),
        packet_id: packet.packet_id,
        buyer_id: packet.buyer_id,
        generated_at_unix_ms,
        artifacts,
    };
    let json = serde_json::to_string_pretty(&package)
        .map_err(|error| CliError::cli_other_error(format!("Chio buyer package JSON: {error}")))?;
    write_json_string(out, &format!("{json}\n"))
}

pub(crate) fn cmd_chio_attest_buyer_verify(
    package_path: &Path,
    trust_bundle_path: &Path,
    context_path: &Path,
    report_path: &Path,
) -> Result<(), CliError> {
    let package_json = read_utf8_json_file(package_path, "Chio buyer review package")?;
    let package = chio_attest_buyer::buyer_attestation_review_package_from_json(&package_json)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio buyer review package: {error}"))
        })?;
    let base_dir = package_path.parent().unwrap_or_else(|| Path::new("."));
    let sources = read_buyer_review_sources(base_dir, &package)?;
    let trust_bundle_json = read_utf8_json_file(trust_bundle_path, "Chio verifier trust bundle")?;
    let context_json = read_utf8_json_file(context_path, "Chio verification context")?;
    let report = chio_attest_buyer::verify_buyer_attestation_review_package_with_proof_replay_json(
        &package,
        &sources,
        &trust_bundle_json,
        &context_json,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio buyer review verification: {error}"))
    })?;
    let json = chio_attest_buyer::buyer_attestation_review_report_json(&report)
        .map_err(|error| CliError::cli_other_error(format!("Chio buyer review report: {error}")))?;
    write_json_string(report_path, &format!("{json}\n"))?;
    if report.accepted {
        Ok(())
    } else {
        Err(CliError::registry_error(
            &TRANSACTION_BUYER_REVIEW_REJECTED,
            format!(
                "Chio buyer verification rejected package: {}",
                report
                    .failure_code
                    .as_deref()
                    .unwrap_or("unknown_buyer_review_rejection")
            ),
        ))
    }
}

pub(crate) fn cmd_chio_attest_buyer_verify_proof(
    package_path: &Path,
    trust_bundle_path: &Path,
    context_path: &Path,
    report_path: &Path,
) -> Result<(), CliError> {
    let package_json = read_utf8_json_file(package_path, "Chio attest proof package")?;
    let trust_bundle_json = read_utf8_json_file(trust_bundle_path, "Chio verifier trust bundle")?;
    let context_json = read_utf8_json_file(context_path, "Chio verification context")?;
    let report = chio_attest_buyer::verify_proof_package_json(
        &package_json,
        &trust_bundle_json,
        &context_json,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio attest proof verification: {error}"))
    })?;
    write_json_string(report_path, &format!("{}\n", report.json))?;
    if report.accepted {
        Ok(())
    } else {
        Err(CliError::cli_other_error(format!(
            "Chio attest proof verification rejected package: {}",
            report
                .failure_code
                .as_deref()
                .unwrap_or("unknown_proof_rejection")
        )))
    }
}

pub(crate) fn cmd_chio_attest_buyer_explain(
    report_path: &Path,
    format: &str,
    out: &Path,
) -> Result<(), CliError> {
    let report_json = read_utf8_json_file(report_path, "Chio buyer review report")?;
    let report: chio_attest_buyer::BuyerAttestationReviewReport =
        serde_json::from_str(&report_json).map_err(|error| {
            CliError::cli_other_error(format!("Chio buyer review report: {error}"))
        })?;
    let verification_state = buyer_review_verification_state(&report);
    match format {
        "json" => {
            let explanation = serde_json::json!({
                "schema": chio_attest_buyer::CHIO_ATTEST_BUYER_ATTESTATION_EXPLANATION_SCHEMA,
                "packageId": report.package_id,
                "packetId": report.packet_id,
                "accepted": report.accepted,
                "verificationState": verification_state,
                "failureCode": report.failure_code,
                "checks": report.checks,
            });
            let json = serde_json::to_string_pretty(&explanation).map_err(|error| {
                CliError::cli_other_error(format!("Chio buyer explanation: {error}"))
            })?;
            write_json_string(out, &format!("{json}\n"))
        }
        "text" => {
            let mut text = String::new();
            text.push_str(&format!("Buyer review package: {}\n", report.package_id));
            text.push_str(&format!("Packet: {}\n", report.packet_id));
            text.push_str(&format!("Accepted: {}\n", report.accepted));
            text.push_str(&format!("Verification state: {verification_state}\n"));
            if let Some(code) = report.failure_code.as_deref() {
                text.push_str(&format!("Failure code: {code}\n"));
            }
            text.push_str("Checks:\n");
            for check in &report.checks {
                text.push_str(&format!(
                    "- [{}] {} ({}) - {}\n",
                    if check.passed { "pass" } else { "fail" },
                    check.code,
                    check.artifact_role,
                    check.message
                ));
            }
            write_json_string(out, &text)
        }
        other => Err(CliError::cli_other_error(format!(
            "unknown Chio buyer explain format {other}"
        ))),
    }
}

pub(crate) fn buyer_review_verification_state(
    report: &chio_attest_buyer::BuyerAttestationReviewReport,
) -> &'static str {
    if report.failure_code.as_deref().is_some_and(|code| {
        code.contains("unsupported_claim")
            || code.contains("settlement_claim")
            || code.contains("hidden_predicate")
            || code.contains("dynamic_trust")
    }) || report.checks.iter().any(|check| {
        !check.passed
            && (check.code.contains("unsupported_claim")
                || check.code.contains("settlement_claim")
                || check.code.contains("hidden_predicate")
                || check.code.contains("dynamic_trust"))
    }) {
        return "unsupported_claim";
    }
    if !report.accepted {
        return "rejected";
    }
    if report
        .checks
        .iter()
        .any(|check| !check.passed && check.code.contains("fixture"))
    {
        return "fixture_only";
    }
    let has_strict_dsse = report.checks.iter().any(|check| {
        check.passed
            && matches!(
                check.code.as_str(),
                "chio_attest_buyer.review.strict_dsse_treaty_bound"
                    | "chio_buyer_review.strict_dsse_treaty_bound"
            )
    });
    let proof_accepted = report.checks.iter().any(|check| {
        check.passed
            && matches!(
                check.code.as_str(),
                "chio_attest_buyer.review.proof_verifier_accepted"
                    | "chio_buyer_review.proof_verifier_accepted"
            )
    });
    let existing_verifier_replayed = report.checks.iter().any(|check| {
        check.passed
            && matches!(
                check.code.as_str(),
                "chio_attest_buyer.review.existing_verifier_replayed"
                    | "chio_buyer_review.existing_verifier_replayed"
            )
    });
    if has_strict_dsse && proof_accepted && existing_verifier_replayed {
        "strict_verified"
    } else {
        "provisional"
    }
}

pub(crate) fn read_buyer_review_sources(
    base_dir: &Path,
    package: &chio_attest_buyer::BuyerAttestationReviewPackage,
) -> Result<Vec<chio_attest_buyer::BuyerAttestationReviewSource>, CliError> {
    let mut sources = Vec::new();
    let mut roles = std::collections::BTreeSet::new();
    let mut paths = std::collections::BTreeSet::new();
    for artifact in &package.artifacts {
        validate_runtime_relative_path(&artifact.relative_path)?;
        if !roles.insert(artifact.role.clone()) {
            return Err(CliError::cli_other_error(format!(
                "duplicate Chio buyer artifact role {}",
                artifact.role
            )));
        }
        if !paths.insert(artifact.relative_path.clone()) {
            return Err(CliError::cli_other_error(format!(
                "duplicate Chio buyer artifact path {}",
                artifact.relative_path
            )));
        }
        let path = base_dir.join(&artifact.relative_path);
        let bytes = fs::read(&path).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chio buyer review artifact {}: {error}",
                path.display()
            ))
        })?;
        sources.push(chio_attest_buyer::BuyerAttestationReviewSource {
            role: artifact.role.clone(),
            relative_path: artifact.relative_path.clone(),
            bytes,
        });
    }
    Ok(sources)
}
