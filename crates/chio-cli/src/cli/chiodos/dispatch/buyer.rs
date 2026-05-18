use crate::CliError;
use std::fs;
use std::path::Path;
use super::{
    BUYER_REVIEW_ARTIFACT_FILES,
    read_utf8_json_file,
    validate_runtime_relative_path,
    write_json_string,
};


pub(crate) fn cmd_chiodos_buyer_package(run_output: &Path, out: &Path) -> Result<(), CliError> {
    let run_output_root = run_output.canonicalize().map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to canonicalize Chiodos buyer run output {}: {error}",
            run_output.display()
        ))
    })?;
    let out_parent = out.parent().unwrap_or_else(|| Path::new("."));
    if !out_parent.as_os_str().is_empty() {
        fs::create_dir_all(out_parent).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to create Chiodos buyer package directory {}: {error}",
                out_parent.display()
            ))
        })?;
    }
    let package_root = out_parent.canonicalize().map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to canonicalize Chiodos buyer package directory {}: {error}",
            out_parent.display()
        ))
    })?;
    if package_root != run_output_root {
        return Err(CliError::cli_other_error(
            "Chiodos buyer package --out must be written directly inside --run-output so artifact paths remain verifier-resolvable"
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
                "failed to read Chiodos buyer review artifact {}: {error}",
                path.display()
            ))
        })?;
        if *role == "buyer_attestation_packet" {
            packet_json = Some(String::from_utf8(bytes.clone()).map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos buyer attestation packet {} is not UTF-8 JSON: {error}",
                    path.display()
                ))
            })?);
        }
        if *role == "runtime_evidence_manifest" {
            let manifest_json = String::from_utf8(bytes.clone()).map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime evidence manifest {} is not UTF-8 JSON: {error}",
                    path.display()
                ))
            })?;
            let manifest: chio_chiodos_runtime::RuntimeEvidenceManifest =
                serde_json::from_str(&manifest_json).map_err(|error| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime evidence manifest {} parse: {error}",
                        path.display()
                    ))
                })?;
            generated_at_unix_ms = Some(manifest.generated_at_unix_ms);
        }
        let byte_count = u64::try_from(bytes.len()).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos buyer artifact byte count: {error}"))
        })?;
        artifacts.push(chio_chiodos_runtime::BuyerAttestationReviewArtifactRef {
            role: (*role).to_string(),
            relative_path: (*relative_path).to_string(),
            artifact_sha256: chio_core::sha256_hex(&bytes),
            byte_count,
        });
    }
    let packet_json = packet_json.ok_or_else(|| {
        CliError::cli_other_error("Chiodos buyer package is missing buyer packet artifact")
    })?;
    let packet = chio_chiodos_runtime::buyer_attestation_packet_from_json(&packet_json).map_err(
        |error| CliError::cli_other_error(format!("Chiodos buyer attestation packet: {error}")),
    )?;
    let generated_at_unix_ms = generated_at_unix_ms.ok_or_else(|| {
        CliError::cli_other_error("Chiodos buyer package is missing runtime evidence manifest")
    })?;
    let package = chio_chiodos_runtime::BuyerAttestationReviewPackage {
        schema: chio_chiodos_runtime::CHIODOS_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA.to_string(),
        package_id: format!("buyer-review:{}", packet.packet_id),
        packet_id: packet.packet_id,
        buyer_id: packet.buyer_id,
        generated_at_unix_ms,
        artifacts,
    };
    let json = serde_json::to_string_pretty(&package)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos buyer package JSON: {error}")))?;
    write_json_string(out, &format!("{json}\n"))
}

pub(crate) fn cmd_chiodos_buyer_verify(
    package_path: &Path,
    trust_bundle_path: &Path,
    context_path: &Path,
    report_path: &Path,
) -> Result<(), CliError> {
    let package_json = read_utf8_json_file(package_path, "Chiodos buyer review package")?;
    let package = chio_chiodos_runtime::buyer_attestation_review_package_from_json(&package_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos buyer review package: {error}")))?;
    let base_dir = package_path.parent().unwrap_or_else(|| Path::new("."));
    let sources = read_buyer_review_sources(base_dir, &package)?;
    let trust_bundle_json =
        read_utf8_json_file(trust_bundle_path, "Chiodos verifier trust bundle")?;
    let verifier_trust_bundle_value: serde_json::Value =
        serde_json::from_str(&trust_bundle_json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos trust bundle JSON parse: {error}"))
        })?;
    let context_json = read_utf8_json_file(context_path, "Chiodos verification context")?;
    let verification_context_value: serde_json::Value =
        serde_json::from_str(&context_json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos context JSON parse: {error}"))
        })?;
    let trust_context = chio_chiodos_runtime::BuyerAttestationReviewTrustContext {
        verifier_trust_bundle: &verifier_trust_bundle_value,
        verification_context: &verification_context_value,
    };
    let mut report = chio_chiodos_runtime::verify_buyer_attestation_review_package_with_trust(
        &package,
        &sources,
        &trust_context,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos buyer review verification: {error}"))
    })?;
    if report.accepted {
        let proof_package_bytes = buyer_review_source_bytes(&sources, "proof_package").ok_or_else(|| {
            CliError::cli_other_error("Chiodos buyer package is missing proof_package artifact")
        })?;
        let proof_package_json = std::str::from_utf8(proof_package_bytes).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos buyer proof package artifact is not UTF-8 JSON: {error}"
            ))
        })?;
        let proof_package = chio_chiodos::proof_package_from_json(proof_package_json)
            .map_err(|error| CliError::cli_other_error(format!("Chiodos package parse: {error}")))?;
        let trust_bundle = chio_chiodos::verifier_trust_bundle_from_json(&trust_bundle_json)
            .map_err(|error| {
                CliError::cli_other_error(format!("Chiodos trust bundle parse: {error}"))
            })?;
        let context = chio_chiodos::verification_context_from_json(&context_json)
            .map_err(|error| CliError::cli_other_error(format!("Chiodos context parse: {error}")))?;
        let verifier_report =
            chio_chiodos::verify_package_report(&proof_package, &trust_bundle, &context);
        if verifier_report.accepted {
            report
                .checks
                .push(chio_chiodos_runtime::BuyerAttestationReviewCheck {
                    code: "chiodos_buyer_review.existing_verifier_replayed".to_string(),
                    passed: true,
                    severity: "info".to_string(),
                    artifact_role: "proof_package".to_string(),
                    expected_sha256: None,
                    observed_sha256: None,
                    message: "existing Chiodos verifier accepted the bundled proof package"
                        .to_string(),
                });
        } else {
            report.accepted = false;
            report.failure_code = Some("chiodos_buyer_review_verifier_report_rejected".to_string());
            report
                .checks
                .push(chio_chiodos_runtime::BuyerAttestationReviewCheck {
                    code: "chiodos_buyer_review.existing_verifier_replayed".to_string(),
                    passed: false,
                    severity: "error".to_string(),
                    artifact_role: "proof_package".to_string(),
                    expected_sha256: None,
                    observed_sha256: None,
                    message: "existing Chiodos verifier rejected the bundled proof package"
                        .to_string(),
                });
        }
    }
    let json = chio_chiodos_runtime::buyer_attestation_review_report_json(&report).map_err(
        |error| CliError::cli_other_error(format!("Chiodos buyer review report: {error}")),
    )?;
    write_json_string(report_path, &format!("{json}\n"))?;
    if report.accepted {
        Ok(())
    } else {
        Err(CliError::cli_other_error(format!(
            "Chiodos buyer verification rejected package: {}",
            report
                .failure_code
                .as_deref()
                .unwrap_or("unknown_buyer_review_rejection")
        )))
    }
}

pub(crate) fn cmd_chiodos_buyer_explain(report_path: &Path, format: &str, out: &Path) -> Result<(), CliError> {
    let report_json = read_utf8_json_file(report_path, "Chiodos buyer review report")?;
    let report: chio_chiodos_runtime::BuyerAttestationReviewReport =
        serde_json::from_str(&report_json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos buyer review report: {error}"))
        })?;
    let verification_state = buyer_review_verification_state(&report);
    match format {
        "json" => {
            let explanation = serde_json::json!({
                "schema": "chio.chiodos.buyer-attestation-explanation.v1",
                "packageId": report.package_id,
                "packetId": report.packet_id,
                "accepted": report.accepted,
                "verificationState": verification_state,
                "failureCode": report.failure_code,
                "checks": report.checks,
            });
            let json = serde_json::to_string_pretty(&explanation).map_err(|error| {
                CliError::cli_other_error(format!("Chiodos buyer explanation: {error}"))
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
            "unknown Chiodos buyer explain format {other}"
        ))),
    }
}

pub(crate) fn buyer_review_verification_state(
    report: &chio_chiodos_runtime::BuyerAttestationReviewReport,
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
        check.passed && check.code == "chiodos_buyer_review.strict_dsse_treaty_bound"
    });
    let proof_accepted = report.checks.iter().any(|check| {
        check.passed && check.code == "chiodos_buyer_review.proof_verifier_accepted"
    });
    let existing_verifier_replayed = report.checks.iter().any(|check| {
        check.passed && check.code == "chiodos_buyer_review.existing_verifier_replayed"
    });
    if has_strict_dsse && proof_accepted && existing_verifier_replayed {
        "strict_verified"
    } else {
        "provisional"
    }
}

pub(crate) fn read_buyer_review_sources(
    base_dir: &Path,
    package: &chio_chiodos_runtime::BuyerAttestationReviewPackage,
) -> Result<Vec<chio_chiodos_runtime::BuyerAttestationReviewSource>, CliError> {
    let mut sources = Vec::new();
    let mut roles = std::collections::BTreeSet::new();
    let mut paths = std::collections::BTreeSet::new();
    for artifact in &package.artifacts {
        validate_runtime_relative_path(&artifact.relative_path)?;
        if !roles.insert(artifact.role.clone()) {
            return Err(CliError::cli_other_error(format!(
                "duplicate Chiodos buyer artifact role {}",
                artifact.role
            )));
        }
        if !paths.insert(artifact.relative_path.clone()) {
            return Err(CliError::cli_other_error(format!(
                "duplicate Chiodos buyer artifact path {}",
                artifact.relative_path
            )));
        }
        let path = base_dir.join(&artifact.relative_path);
        let bytes = fs::read(&path).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos buyer review artifact {}: {error}",
                path.display()
            ))
        })?;
        sources.push(chio_chiodos_runtime::BuyerAttestationReviewSource {
            role: artifact.role.clone(),
            relative_path: artifact.relative_path.clone(),
            bytes,
        });
    }
    Ok(sources)
}

pub(crate) fn buyer_review_source_bytes<'a>(
    sources: &'a [chio_chiodos_runtime::BuyerAttestationReviewSource],
    role: &str,
) -> Option<&'a [u8]> {
    sources
        .iter()
        .find(|source| source.role == role)
        .map(|source| source.bytes.as_slice())
}
