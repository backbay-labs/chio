//! Relay alert assurance archive, closeout, and retention report generators.

use super::*;
use crate::{
    canonical_sha256, contains_secret_marker, generate_relay_alert_assurance_recovery_drill_report,
    generate_relay_alert_assurance_replay_report, generate_relay_alert_assurance_retention_report,
    is_sha256_hex, validate_export_path, validate_retention_profile,
    verify_relay_alert_assurance_export_bundle, PheromoneRelayError,
    RelayAlertAssuranceExportBundle, RelayAlertAssuranceRecoveryDrillInput,
    RelayAlertAssuranceRecoveryDrillReport, RelayAlertAssuranceReplayInput,
    RelayAlertAssuranceRetentionInput, RelayAlertAssuranceRetentionProfileDocument,
    RelayAlertAssuranceTrustedExportersDocument, RelayAlertCheck, RelayOperatorRecommendation,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_REVIEW_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_EVIDENCE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RECOVERY_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_EVIDENCE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_REPORT_SCHEMA,
};
use std::collections::BTreeSet;

pub fn generate_relay_alert_assurance_archive_report(
    input: RelayAlertAssuranceArchiveInput<'_>,
) -> Result<RelayAlertAssuranceArchiveReport, PheromoneRelayError> {
    validate_archive_profile(input.archive_profile, input.now_unix_ms)?;
    validate_retention_profile(input.retention_profile, input.now_unix_ms)?;
    validate_archive_input_roots(
        input.archive_profile.local_kernel_id.as_str(),
        input.trusted_exporters.local_kernel_id.as_str(),
        input.retention_profile.local_kernel_id.as_str(),
    )?;
    validate_archive_candidates(input.bundles)?;

    let mut reviews = Vec::new();
    for candidate in input.bundles {
        reviews.push(review_archive_candidate(
            candidate,
            input.trusted_exporters,
            input.retention_profile,
            input.archive_profile.require_replay_match,
            input.archive_profile.require_recovery_drill,
            input.now_unix_ms,
        )?);
    }
    let archive_ready_count = reviews
        .iter()
        .filter(|review| review.state == "archive_ready")
        .count() as u64;
    let archive_blocked_count = reviews
        .iter()
        .filter(|review| review.state == "archive_blocked")
        .count() as u64;
    let quarantine_count = reviews
        .iter()
        .filter(|review| review.state == "quarantine")
        .count() as u64;
    let legal_hold_count = reviews.iter().map(|review| review.legal_hold_count).sum();
    let eligible_for_delete_count = reviews
        .iter()
        .map(|review| review.eligible_for_delete_count)
        .sum();
    let accepted = archive_blocked_count == 0 && quarantine_count == 0;
    Ok(RelayAlertAssuranceArchiveReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "archive_attention_required"
        }
        .to_string(),
        local_kernel_id: input.archive_profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        bundle_count: reviews.len() as u64,
        archive_ready_count,
        archive_blocked_count,
        quarantine_count,
        legal_hold_count,
        eligible_for_delete_count,
        reviews,
        checks: vec![RelayAlertCheck {
            code: "archive_report_only".to_string(),
            accepted: true,
            detail: "archive lifecycle evaluation is report-only and does not move, delete, or upload evidence"
                .to_string(),
        }],
    })
}
pub fn generate_relay_alert_assurance_closeout_report(
    input: RelayAlertAssuranceCloseoutInput<'_>,
) -> Result<RelayAlertAssuranceCloseoutReport, PheromoneRelayError> {
    validate_closeout_profile(input.closeout_profile, input.now_unix_ms)?;
    validate_retention_profile(input.retention_profile, input.now_unix_ms)?;
    validate_archive_input_roots(
        input.closeout_profile.local_kernel_id.as_str(),
        input.trusted_exporters.local_kernel_id.as_str(),
        input.retention_profile.local_kernel_id.as_str(),
    )?;
    let archive_profile = RelayAlertAssuranceArchiveProfileDocument {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PROFILE_SCHEMA.to_string(),
        local_kernel_id: input.closeout_profile.local_kernel_id.clone(),
        issued_at_unix_ms: input.closeout_profile.issued_at_unix_ms,
        expires_at_unix_ms: input.closeout_profile.expires_at_unix_ms,
        require_replay_match: input.closeout_profile.require_replay_match,
        require_recovery_drill: input.closeout_profile.require_recovery_drill,
    };
    let archive_report =
        generate_relay_alert_assurance_archive_report(RelayAlertAssuranceArchiveInput {
            bundles: input.bundles,
            trusted_exporters: input.trusted_exporters,
            archive_profile: &archive_profile,
            retention_profile: input.retention_profile,
            now_unix_ms: input.now_unix_ms,
        })?;

    let mut reviews = Vec::new();
    for archive_review in archive_report.reviews {
        reviews.push(closeout_review_from_archive(
            archive_review,
            input.closeout_profile,
        ));
    }
    let closeout_ready_count = reviews
        .iter()
        .filter(|review| review.state == "closeout_ready")
        .count() as u64;
    let closeout_blocked_count = reviews
        .iter()
        .filter(|review| review.state == "closeout_blocked")
        .count() as u64;
    let quarantine_count = reviews
        .iter()
        .filter(|review| review.state == "quarantine")
        .count() as u64;
    let legal_hold_count = reviews.iter().map(|review| review.legal_hold_count).sum();
    let eligible_for_delete_count = reviews
        .iter()
        .map(|review| review.eligible_for_delete_count)
        .sum();
    let accepted = closeout_blocked_count == 0 && quarantine_count == 0;
    Ok(RelayAlertAssuranceCloseoutReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "closeout_blocked"
        }
        .to_string(),
        local_kernel_id: input.closeout_profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        bundle_count: reviews.len() as u64,
        closeout_ready_count,
        closeout_blocked_count,
        quarantine_count,
        legal_hold_count,
        eligible_for_delete_count,
        reviews,
        checks: vec![RelayAlertCheck {
            code: "closeout_report_only".to_string(),
            accepted: true,
            detail: "closeout review is report-only and makes no human notification claim"
                .to_string(),
        }],
    })
}
pub fn generate_relay_alert_assurance_archive_restore_drill_report(
    input: RelayAlertAssuranceArchiveRestoreDrillInput<'_>,
) -> Result<RelayAlertAssuranceArchiveRestoreDrillReport, PheromoneRelayError> {
    validate_archive_restore_profile(input.restore_profile, input.now_unix_ms)?;
    if input.package_reports.is_empty() {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "restore drill requires at least one package report".to_string(),
        ));
    }
    let max_package_count =
        usize::try_from(input.restore_profile.max_package_count).map_err(|_| {
            PheromoneRelayError::ArchivePackageInvalid("restore package count overflow".to_string())
        })?;
    if input.package_reports.len() > max_package_count {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "restore drill package count exceeds profile limit".to_string(),
        ));
    }

    let mut package_reports: Vec<&RelayAlertAssuranceArchivePackageReport> =
        input.package_reports.iter().collect();
    package_reports.sort_by_key(|report| report.package_generation);
    let mut seen_generations = BTreeSet::new();
    let mut reviews = Vec::new();
    let mut checks = Vec::new();
    let mut previous_manifest_hash: Option<String> = None;
    let mut latest_generation = 0_u64;
    let mut quarantine_count = 0_u64;

    for report in package_reports {
        let package_report_failure = archive_package_report_integrity_failure(report);
        let mut accepted = report.accepted;
        let mut code = if report.accepted {
            "accepted".to_string()
        } else {
            "package_report_rejected".to_string()
        };
        if let Some(failure) = package_report_failure {
            accepted = false;
            code = failure.to_string();
        }
        if accepted && report.local_kernel_id != input.restore_profile.local_kernel_id {
            accepted = false;
            code = "local_kernel_mismatch".to_string();
        }
        if accepted && seen_generations.contains(&report.package_generation) {
            accepted = false;
            code = "duplicate_generation".to_string();
        }
        if accepted && input.restore_profile.require_generation_continuity {
            let expected_generation = latest_generation.saturating_add(1);
            if report.package_generation != expected_generation {
                accepted = false;
                code = "generation_gap".to_string();
            } else if report.package_generation > 1
                && report.previous_package_manifest_sha256 != previous_manifest_hash
            {
                accepted = false;
                code = "previous_manifest_hash_mismatch".to_string();
            }
        }
        if accepted
            && input.restore_profile.require_physical_readback
            && !has_matching_physical_readback(report, input.physical_drill_reports)?
        {
            accepted = false;
            code = "missing_physical_readback".to_string();
        }
        if accepted
            && input.restore_profile.require_retention_handoff_ready
            && !has_matching_retention_handoff(report, input.retention_handoff_reports)?
        {
            accepted = false;
            code = "retention_handoff_not_ready".to_string();
        }
        if !accepted {
            quarantine_count = quarantine_count.saturating_add(1);
        }
        checks.push(RelayAlertCheck {
            code: format!("package_generation_{}", report.package_generation),
            accepted,
            detail: code.clone(),
        });
        reviews.push(RelayAlertAssuranceArchiveRestorePackageReview {
            package_id: report.package_id.clone(),
            package_generation: report.package_generation,
            package_manifest_sha256: report.package_manifest_sha256.clone(),
            previous_package_manifest_sha256: report.previous_package_manifest_sha256.clone(),
            accepted,
            code,
        });
        if accepted {
            seen_generations.insert(report.package_generation);
            latest_generation = latest_generation.max(report.package_generation);
            previous_manifest_hash = Some(report.package_manifest_sha256.clone());
        }
    }

    let accepted = checks.iter().all(|check| check.accepted);
    let package_count = u64::try_from(input.package_reports.len()).map_err(|_| {
        PheromoneRelayError::ArchivePackageInvalid("restore package count overflow".to_string())
    })?;
    Ok(RelayAlertAssuranceArchiveRestoreDrillReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_DRILL_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted".to_string()
        } else {
            "restore_blocked".to_string()
        },
        local_kernel_id: input.restore_profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        package_count,
        verified_generation_count: package_count.saturating_sub(quarantine_count),
        latest_package_generation: latest_generation,
        quarantine_count,
        blocked_count: quarantine_count,
        packages: reviews,
        checks,
    })
}
pub fn generate_relay_alert_assurance_physical_archive_drill_report(
    input: RelayAlertAssurancePhysicalArchiveDrillInput<'_>,
) -> Result<RelayAlertAssurancePhysicalArchiveDrillReport, PheromoneRelayError> {
    validate_physical_archive_evidence(input.evidence)?;
    if input.evidence.package_id != input.expected_package_id {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "physical archive evidence package id mismatch".to_string(),
        ));
    }
    if input.evidence.package_report_sha256 != input.expected_package_report_sha256 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "physical archive evidence package report hash mismatch".to_string(),
        ));
    }
    if input.evidence.package_manifest_sha256 != input.expected_package_manifest_sha256 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "physical archive evidence package manifest hash mismatch".to_string(),
        ));
    }
    if input.now_unix_ms < input.evidence.observed_at_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "physical archive evidence is from the future".to_string(),
        ));
    }
    Ok(RelayAlertAssurancePhysicalArchiveDrillReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_DRILL_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: input.evidence.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        evidence_id: input.evidence.evidence_id.clone(),
        package_id: input.evidence.package_id.clone(),
        package_report_sha256: input.evidence.package_report_sha256.clone(),
        sampled_member_count: input.evidence.sampled_member_count,
        checks: vec![
            RelayAlertCheck {
                code: "local_readback_evidence".to_string(),
                accepted: true,
                detail: "operator-provided local readback evidence is hash-bound to package report"
                    .to_string(),
            },
            RelayAlertCheck {
                code: "physical_media_not_controlled".to_string(),
                accepted: true,
                detail: "report does not claim Chio wrote to or controls physical media"
                    .to_string(),
            },
        ],
    })
}
pub fn generate_relay_alert_assurance_retention_handoff_report(
    input: RelayAlertAssuranceRetentionHandoffInput<'_>,
) -> Result<RelayAlertAssuranceRetentionHandoffReport, PheromoneRelayError> {
    validate_retention_handoff_profile(input.profile, input.now_unix_ms)?;
    validate_retention_handoff_evidence(input.evidence)?;
    if input.evidence.package_id != input.expected_package_id {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "retention handoff package id mismatch".to_string(),
        ));
    }
    if input.evidence.package_report_sha256 != input.expected_package_report_sha256 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "retention handoff package report hash mismatch".to_string(),
        ));
    }
    if input.evidence.local_kernel_id != input.profile.local_kernel_id {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "retention handoff local kernel id mismatch".to_string(),
        ));
    }
    if !input
        .profile
        .allowed_system_aliases
        .iter()
        .any(|alias| alias == &input.evidence.target_system_alias)
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "retention handoff target alias is not allowed".to_string(),
        ));
    }
    if input.now_unix_ms < input.evidence.observed_at_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "retention handoff evidence is from the future".to_string(),
        ));
    }
    Ok(RelayAlertAssuranceRetentionHandoffReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: input.evidence.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        evidence_id: input.evidence.evidence_id.clone(),
        package_id: input.evidence.package_id.clone(),
        package_report_sha256: input.evidence.package_report_sha256.clone(),
        target_system_alias: input.evidence.target_system_alias.clone(),
        ready_for_operator_handoff: true,
        checks: vec![
            RelayAlertCheck {
                code: "local_evidence_only".to_string(),
                accepted: true,
                detail: "retention handoff uses bounded aliases and local hashes only".to_string(),
            },
            RelayAlertCheck {
                code: "operator_managed_handoff".to_string(),
                accepted: true,
                detail: "report claims readiness for operator-managed handoff only".to_string(),
            },
        ],
    })
}
pub fn relay_alert_assurance_external_retention_profile_from_json(
    input: &str,
    now_unix_ms: u64,
) -> Result<RelayAlertAssuranceExternalRetentionProfileDocument, PheromoneRelayError> {
    let profile: RelayAlertAssuranceExternalRetentionProfileDocument = serde_json::from_str(input)?;
    validate_external_retention_profile(&profile, now_unix_ms)?;
    Ok(profile)
}
pub fn generate_relay_alert_assurance_external_retention_review_report(
    input: RelayAlertAssuranceExternalRetentionReviewInput<'_>,
) -> Result<RelayAlertAssuranceExternalRetentionReviewReport, PheromoneRelayError> {
    validate_external_retention_profile(input.profile, input.now_unix_ms)?;
    if input.since_unix_ms > input.until_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention review window is invalid".to_string(),
        ));
    }
    if input.package_reports.is_empty() {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention review requires at least one package report".to_string(),
        ));
    }
    let max_package_count = usize::try_from(input.profile.max_package_count).map_err(|_| {
        PheromoneRelayError::ArchivePackageInvalid(
            "external retention package count overflow".to_string(),
        )
    })?;
    if input.package_reports.len() > max_package_count {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention package count exceeds profile limit".to_string(),
        ));
    }

    let mut package_reports: Vec<&RelayAlertAssuranceArchivePackageReport> =
        input.package_reports.iter().collect();
    package_reports.sort_by_key(|report| report.package_generation);

    let mut seen_generations = BTreeSet::new();
    let mut previous_manifest_hash: Option<String> = None;
    let mut latest_generation = 0_u64;
    let mut expected_alias: Option<String> = None;
    let mut reviews = Vec::new();
    let mut checks = Vec::new();
    let mut quarantine_count = 0_u64;
    let mut drift_count = 0_u64;
    let mut insufficient_sample_count = 0_u64;

    for report in package_reports {
        if let Some(failure) = archive_package_report_integrity_failure(report) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
                "external retention package report rejected: {failure}"
            )));
        }
        let package_report_sha256 = canonical_sha256(report)?;
        let mut accepted = true;
        let mut code = "accepted".to_string();
        let mut restore_status = "not_required".to_string();
        let mut physical_readback_status = "not_required".to_string();
        let mut retention_handoff_status = "not_required".to_string();
        let mut target_system_alias = None;
        let mut accepted_alias_candidate = None;
        let mut sample_coverage_basis_points = 0_u64;

        external_retention_check(
            &mut checks,
            &mut accepted,
            &mut code,
            report.local_kernel_id == input.profile.local_kernel_id,
            "local_kernel",
            "local_kernel_mismatch",
            "package report local kernel matches external retention profile",
        );
        external_retention_check(
            &mut checks,
            &mut accepted,
            &mut code,
            report.accepted,
            "package_report",
            "package_report_rejected",
            "archive package report is accepted",
        );
        external_retention_check(
            &mut checks,
            &mut accepted,
            &mut code,
            report.source_reports_matched,
            "source_reports_matched",
            "source_report_mismatch",
            "archive package report is bound to matching archive and closeout reports",
        );
        external_retention_check(
            &mut checks,
            &mut accepted,
            &mut code,
            report.closeout_ready_verified,
            "closeout_ready",
            "closeout_not_ready",
            "archive package report verified closeout readiness",
        );
        external_retention_check(
            &mut checks,
            &mut accepted,
            &mut code,
            report.total_byte_count_matched,
            "total_byte_count",
            "total_byte_mismatch",
            "archive package report verified package byte totals",
        );
        external_retention_check(
            &mut checks,
            &mut accepted,
            &mut code,
            report.extractable,
            "package_extractable",
            "package_not_extractable",
            "archive package report is extractable by the safe archive path",
        );
        external_retention_check(
            &mut checks,
            &mut accepted,
            &mut code,
            report.trusted_packager_verified,
            "trusted_packager",
            "untrusted_packager",
            "archive package report verified the trusted packager",
        );
        external_retention_check(
            &mut checks,
            &mut accepted,
            &mut code,
            report.nested_exporter_verified,
            "trusted_exporter",
            "untrusted_exporter",
            "archive package report verified nested exporters",
        );
        external_retention_check(
            &mut checks,
            &mut accepted,
            &mut code,
            external_retention_fresh(
                report.generated_at_unix_ms,
                input.since_unix_ms,
                input.until_unix_ms,
                input.now_unix_ms,
                input.profile.max_evidence_age_ms,
            ),
            "package_report_freshness",
            "stale_evidence",
            "archive package report is inside the review window and freshness bound",
        );

        if !seen_generations.insert(report.package_generation) {
            external_retention_fail(
                &mut checks,
                &mut accepted,
                &mut code,
                "duplicate_generation",
                "duplicate package generation in external retention review",
            );
        }
        if input.profile.require_generation_continuity {
            let expected_generation = latest_generation.saturating_add(1);
            if report.package_generation != expected_generation {
                external_retention_fail(
                    &mut checks,
                    &mut accepted,
                    &mut code,
                    "generation_gap",
                    "package generations are not contiguous",
                );
            }
            if report.package_generation > 1
                && report.previous_package_manifest_sha256 != previous_manifest_hash
            {
                external_retention_fail(
                    &mut checks,
                    &mut accepted,
                    &mut code,
                    "previous_manifest_mismatch",
                    "previous package manifest hash does not bind to prior generation",
                );
            }
        }

        let package_level_accepted = accepted;
        let package_level_code = code.clone();

        if input.profile.require_restore_accepted {
            match external_retention_restore_status(input.restore_drill_reports, report) {
                ExternalRetentionEvidence::Missing => {
                    restore_status = "missing".to_string();
                    external_retention_fail(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        "missing_restore_drill",
                        "no restore drill report covers this package generation",
                    );
                }
                ExternalRetentionEvidence::Single(restore) => {
                    let (status, status_valid) = external_retention_report_status(
                        &restore.code,
                        "restore drill report status",
                    );
                    restore_status = status;
                    if !status_valid {
                        external_retention_fail(
                            &mut checks,
                            &mut accepted,
                            &mut code,
                            "invalid_secondary_status",
                            "restore drill report status is not schema-safe",
                        );
                    }
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        restore.local_kernel_id == input.profile.local_kernel_id,
                        "restore_drill_local_kernel",
                        "local_kernel_mismatch",
                        "restore drill report local kernel matches external retention profile",
                    );
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        restore.accepted,
                        "restore_drill",
                        "rejected_restore_drill",
                        "restore drill accepts this package generation",
                    );
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        external_retention_fresh(
                            restore.generated_at_unix_ms,
                            input.since_unix_ms,
                            input.until_unix_ms,
                            input.now_unix_ms,
                            input.profile.max_evidence_age_ms,
                        ),
                        "restore_drill_freshness",
                        "stale_evidence",
                        "restore drill report is inside the review window and freshness bound",
                    );
                }
                ExternalRetentionEvidence::Duplicate => {
                    restore_status = "duplicate".to_string();
                    external_retention_fail(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        "duplicate_restore_drill_evidence",
                        "multiple restore drill reports match this package report",
                    );
                }
            }
        }

        if input.profile.require_physical_readback {
            match external_retention_physical_reports(
                input.physical_drill_reports,
                &package_report_sha256,
                &report.package_id,
            )
            .as_slice()
            {
                [] => {
                    physical_readback_status = "missing".to_string();
                    external_retention_fail(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        "missing_physical_readback",
                        "no physical readback report matches this package report",
                    );
                }
                [physical] => {
                    let (status, status_valid) = external_retention_report_status(
                        &physical.code,
                        "physical readback report status",
                    );
                    physical_readback_status = status;
                    if !status_valid {
                        external_retention_fail(
                            &mut checks,
                            &mut accepted,
                            &mut code,
                            "invalid_secondary_status",
                            "physical readback report status is not schema-safe",
                        );
                    }
                    let package_member_count =
                        u64::try_from(report.package_member_count).map_err(|_| {
                            PheromoneRelayError::ArchivePackageInvalid(
                                "external retention member count overflow".to_string(),
                            )
                        })?;
                    let sample_within_package =
                        physical.sampled_member_count <= package_member_count;
                    sample_coverage_basis_points = external_retention_sample_coverage(
                        physical.sampled_member_count,
                        package_member_count,
                    );
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        physical.local_kernel_id == input.profile.local_kernel_id,
                        "physical_readback_local_kernel",
                        "local_kernel_mismatch",
                        "physical readback report local kernel matches external retention profile",
                    );
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        physical.accepted,
                        "physical_readback",
                        "rejected_physical_readback",
                        "physical readback report is accepted",
                    );
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        external_retention_fresh(
                            physical.generated_at_unix_ms,
                            input.since_unix_ms,
                            input.until_unix_ms,
                            input.now_unix_ms,
                            input.profile.max_evidence_age_ms,
                        ),
                        "physical_readback_freshness",
                        "stale_evidence",
                        "physical readback report is inside the review window and freshness bound",
                    );
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        sample_within_package,
                        "physical_readback_sample_bound",
                        "sample_exceeds_package_size",
                        "physical readback sample count does not exceed package member count",
                    );
                    let sample_ok = sample_within_package
                        && physical.sampled_member_count >= input.profile.min_sampled_members
                        && sample_coverage_basis_points
                            >= input.profile.min_sample_coverage_basis_points;
                    if sample_within_package && !sample_ok {
                        insufficient_sample_count = insufficient_sample_count.saturating_add(1);
                    }
                    if sample_within_package {
                        external_retention_check(
                            &mut checks,
                            &mut accepted,
                            &mut code,
                            sample_ok,
                            "physical_readback_sample",
                            "insufficient_sample",
                            "physical readback sample satisfies external retention profile",
                        );
                    }
                }
                _ => {
                    physical_readback_status = "duplicate".to_string();
                    external_retention_fail(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        "duplicate_physical_readback_evidence",
                        "multiple physical readback reports match this package report",
                    );
                }
            }
        }

        if input.profile.require_retention_handoff_ready {
            let matching_handoffs = external_retention_handoffs(
                input.retention_handoff_reports,
                &package_report_sha256,
                &report.package_id,
            );
            match matching_handoffs.as_slice() {
                [] => {
                    retention_handoff_status = "missing".to_string();
                    external_retention_fail(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        "missing_retention_handoff",
                        "no retention handoff report matches this package report",
                    );
                }
                [handoff] => {
                    let (status, status_valid) = external_retention_report_status(
                        &handoff.code,
                        "retention handoff report status",
                    );
                    retention_handoff_status = status;
                    if !status_valid {
                        external_retention_fail(
                            &mut checks,
                            &mut accepted,
                            &mut code,
                            "invalid_secondary_status",
                            "retention handoff report status is not schema-safe",
                        );
                    }
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        handoff.local_kernel_id == input.profile.local_kernel_id,
                        "retention_handoff_local_kernel",
                        "local_kernel_mismatch",
                        "retention handoff report local kernel matches external retention profile",
                    );
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        handoff.accepted && handoff.ready_for_operator_handoff,
                        "retention_handoff",
                        "retention_handoff_not_ready",
                        "retention handoff report is ready for operator review",
                    );
                    external_retention_check(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        external_retention_fresh(
                            handoff.generated_at_unix_ms,
                            input.since_unix_ms,
                            input.until_unix_ms,
                            input.now_unix_ms,
                            input.profile.max_evidence_age_ms,
                        ),
                        "retention_handoff_freshness",
                        "stale_evidence",
                        "retention handoff report is inside the review window and freshness bound",
                    );
                    let alias_schema_valid = validate_external_retention_schema_token(
                        &handoff.target_system_alias,
                        "retention handoff target alias",
                    )
                    .is_ok();
                    let alias_allowed = alias_schema_valid
                        && input
                            .profile
                            .allowed_retention_system_aliases
                            .iter()
                            .any(|alias| alias == &handoff.target_system_alias);
                    if alias_schema_valid {
                        target_system_alias = Some(handoff.target_system_alias.clone());
                    }
                    if !alias_allowed {
                        drift_count = drift_count.saturating_add(1);
                        external_retention_fail(
                            &mut checks,
                            &mut accepted,
                            &mut code,
                            "unknown_retention_alias",
                            "retention handoff target alias is not allowed by profile",
                        );
                    }
                    match (&expected_alias, alias_allowed) {
                        (Some(alias), true) if alias != &handoff.target_system_alias => {
                            drift_count = drift_count.saturating_add(1);
                            external_retention_fail(
                                &mut checks,
                                &mut accepted,
                                &mut code,
                                "alias_drift",
                                "retention handoff target alias drifted across generations",
                            );
                        }
                        (None, true) => {
                            accepted_alias_candidate = Some(handoff.target_system_alias.clone());
                        }
                        _ => {}
                    }
                }
                _ => {
                    retention_handoff_status = "duplicate".to_string();
                    external_retention_fail(
                        &mut checks,
                        &mut accepted,
                        &mut code,
                        "duplicate_handoff_evidence",
                        "multiple retention handoff reports match this package report",
                    );
                }
            }
        }

        if !accepted {
            quarantine_count = quarantine_count.saturating_add(1);
        }
        if !package_level_accepted {
            code = package_level_code;
        }
        if accepted {
            if let Some(alias) = accepted_alias_candidate {
                expected_alias = Some(alias);
            }
            latest_generation = latest_generation.max(report.package_generation);
            previous_manifest_hash = Some(report.package_manifest_sha256.clone());
        }
        reviews.push(RelayAlertAssuranceExternalRetentionPackageReview {
            package_id: report.package_id.clone(),
            package_generation: report.package_generation,
            package_manifest_sha256: report.package_manifest_sha256.clone(),
            package_report_sha256,
            target_system_alias,
            sample_coverage_basis_points,
            restore_status,
            physical_readback_status,
            retention_handoff_status,
            accepted,
            code,
        });
    }

    let package_count = u64::try_from(input.package_reports.len()).map_err(|_| {
        PheromoneRelayError::ArchivePackageInvalid(
            "external retention package count overflow".to_string(),
        )
    })?;
    let ready_count = package_count.saturating_sub(quarantine_count);
    let accepted = quarantine_count == 0;
    Ok(RelayAlertAssuranceExternalRetentionReviewReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_REVIEW_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted".to_string()
        } else {
            "external_retention_blocked".to_string()
        },
        local_kernel_id: input.profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        since_unix_ms: input.since_unix_ms,
        until_unix_ms: input.until_unix_ms,
        package_count,
        ready_count,
        latest_package_generation: latest_generation,
        quarantine_count,
        drift_count,
        insufficient_sample_count,
        reviews,
        recommendations: input
            .profile
            .recommendation_codes
            .iter()
            .map(|code| RelayOperatorRecommendation {
                code: code.clone(),
                severity: if accepted { "info" } else { "warning" }.to_string(),
            })
            .collect(),
        checks,
    })
}
fn validate_archive_restore_profile(
    profile: &RelayAlertAssuranceArchiveRestoreProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    validate_archive_package_identity(&profile.profile_id, "restore profile id")?;
    if profile.max_package_count == 0 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "restore profile max package count must be positive".to_string(),
        ));
    }
    if profile.issued_at_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "restore profile validity window is invalid".to_string(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "restore profile is outside its validity window".to_string(),
        ));
    }
    Ok(())
}
fn has_matching_physical_readback(
    package_report: &RelayAlertAssuranceArchivePackageReport,
    physical_reports: &[RelayAlertAssurancePhysicalArchiveDrillReport],
) -> Result<bool, PheromoneRelayError> {
    let report_hash = canonical_sha256(package_report)?;
    Ok(physical_reports.iter().any(|report| {
        report.accepted
            && report.schema == PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_DRILL_REPORT_SCHEMA
            && report.local_kernel_id == package_report.local_kernel_id
            && report.package_id == package_report.package_id
            && report.package_report_sha256 == report_hash
            && report.sampled_member_count > 0
            && !report.checks.is_empty()
    }))
}
fn has_matching_retention_handoff(
    package_report: &RelayAlertAssuranceArchivePackageReport,
    handoff_reports: &[RelayAlertAssuranceRetentionHandoffReport],
) -> Result<bool, PheromoneRelayError> {
    let report_hash = canonical_sha256(package_report)?;
    Ok(handoff_reports.iter().any(|report| {
        report.accepted
            && report.schema == PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_REPORT_SCHEMA
            && report.ready_for_operator_handoff
            && report.local_kernel_id == package_report.local_kernel_id
            && report.package_id == package_report.package_id
            && report.package_report_sha256 == report_hash
            && validate_archive_package_identity(&report.target_system_alias, "target system alias")
                .is_ok()
            && !report.checks.is_empty()
    }))
}
fn validate_physical_archive_evidence(
    evidence: &RelayAlertAssurancePhysicalArchiveEvidence,
) -> Result<(), PheromoneRelayError> {
    if evidence.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_EVIDENCE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            evidence.schema.clone(),
        ));
    }
    validate_archive_package_identity(&evidence.evidence_id, "evidence id")?;
    validate_archive_package_identity(&evidence.package_id, "package id")?;
    validate_archive_package_identity(&evidence.media_alias, "media alias")?;
    if !is_sha256_hex(&evidence.package_report_sha256)
        || !is_sha256_hex(&evidence.package_manifest_sha256)
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "physical archive evidence hashes are invalid".to_string(),
        ));
    }
    if evidence.sampled_member_count == 0 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "physical archive evidence must sample at least one member".to_string(),
        ));
    }
    for claim in &evidence.claims {
        validate_archive_safety_claim(claim)?;
    }
    Ok(())
}
fn validate_retention_handoff_profile(
    profile: &RelayAlertAssuranceRetentionHandoffProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "retention handoff profile is not fresh".to_string(),
        ));
    }
    if profile.allowed_system_aliases.is_empty() {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "retention handoff profile has no allowed aliases".to_string(),
        ));
    }
    let mut seen = BTreeSet::new();
    for alias in &profile.allowed_system_aliases {
        validate_archive_package_identity(alias, "retention system alias")?;
        if !seen.insert(alias) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "duplicate retention system alias".to_string(),
            ));
        }
    }
    Ok(())
}
fn validate_retention_handoff_evidence(
    evidence: &RelayAlertAssuranceRetentionHandoffEvidence,
) -> Result<(), PheromoneRelayError> {
    if evidence.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_EVIDENCE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            evidence.schema.clone(),
        ));
    }
    validate_archive_package_identity(&evidence.evidence_id, "evidence id")?;
    validate_archive_package_identity(&evidence.package_id, "package id")?;
    validate_archive_package_identity(&evidence.target_system_alias, "target system alias")?;
    if !is_sha256_hex(&evidence.package_report_sha256) {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "retention handoff evidence package report hash is invalid".to_string(),
        ));
    }
    for claim in &evidence.claims {
        validate_archive_safety_claim(claim)?;
    }
    Ok(())
}
fn validate_external_retention_profile(
    profile: &RelayAlertAssuranceExternalRetentionProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    if profile.local_kernel_id.is_empty() {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention profile local kernel id is empty".to_string(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention profile is not fresh".to_string(),
        ));
    }
    if profile.max_package_count == 0 || profile.max_evidence_age_ms == 0 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention profile limits must be positive".to_string(),
        ));
    }
    if profile.min_sampled_members == 0 || profile.min_sample_coverage_basis_points == 0 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention sample requirements must be positive".to_string(),
        ));
    }
    if profile.min_sample_coverage_basis_points > 10_000 {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention sample coverage exceeds 100 percent".to_string(),
        ));
    }
    if profile.allowed_retention_system_aliases.is_empty() {
        return Err(PheromoneRelayError::ArchivePackageInvalid(
            "external retention profile has no allowed aliases".to_string(),
        ));
    }
    let mut seen_aliases = BTreeSet::new();
    for alias in &profile.allowed_retention_system_aliases {
        validate_external_retention_schema_token(alias, "external retention alias")?;
        if !seen_aliases.insert(alias) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "duplicate external retention alias".to_string(),
            ));
        }
    }
    let mut seen_recommendations = BTreeSet::new();
    for code in &profile.recommendation_codes {
        validate_external_retention_schema_token(code, "external retention recommendation")?;
        if !seen_recommendations.insert(code) {
            return Err(PheromoneRelayError::ArchivePackageInvalid(
                "duplicate external retention recommendation".to_string(),
            ));
        }
    }
    Ok(())
}
fn validate_external_retention_schema_token(
    value: &str,
    field: &str,
) -> Result<(), PheromoneRelayError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Err(PheromoneRelayError::ArchivePackageInvalid(format!(
            "{field} is invalid"
        )));
    }
    Ok(())
}
enum ExternalRetentionEvidence<T> {
    Missing,
    Single(T),
    Duplicate,
}
struct ExternalRetentionRestoreStatus {
    code: String,
    accepted: bool,
    generated_at_unix_ms: u64,
    local_kernel_id: String,
}
fn external_retention_report_status(value: &str, field: &str) -> (String, bool) {
    if validate_external_retention_schema_token(value, field).is_ok() {
        return (value.to_string(), true);
    }
    ("invalid".to_string(), false)
}
fn external_retention_restore_status(
    restore_reports: &[RelayAlertAssuranceArchiveRestoreDrillReport],
    package_report: &RelayAlertAssuranceArchivePackageReport,
) -> ExternalRetentionEvidence<ExternalRetentionRestoreStatus> {
    let mut matches = restore_reports.iter().filter_map(|restore| {
        restore.packages.iter().find_map(|package| {
            if package.package_id == package_report.package_id
                && package.package_generation == package_report.package_generation
                && package.package_manifest_sha256 == package_report.package_manifest_sha256
            {
                Some(ExternalRetentionRestoreStatus {
                    code: package.code.clone(),
                    accepted: restore.accepted && package.accepted,
                    generated_at_unix_ms: restore.generated_at_unix_ms,
                    local_kernel_id: restore.local_kernel_id.clone(),
                })
            } else {
                None
            }
        })
    });
    let Some(first) = matches.next() else {
        return ExternalRetentionEvidence::Missing;
    };
    if matches.next().is_some() {
        return ExternalRetentionEvidence::Duplicate;
    }
    ExternalRetentionEvidence::Single(first)
}
fn external_retention_physical_reports<'a>(
    physical_reports: &'a [RelayAlertAssurancePhysicalArchiveDrillReport],
    package_report_sha256: &str,
    package_id: &str,
) -> Vec<&'a RelayAlertAssurancePhysicalArchiveDrillReport> {
    physical_reports
        .iter()
        .filter(|report| {
            report.package_report_sha256 == package_report_sha256 && report.package_id == package_id
        })
        .collect()
}
fn external_retention_handoffs<'a>(
    handoff_reports: &'a [RelayAlertAssuranceRetentionHandoffReport],
    package_report_sha256: &str,
    package_id: &str,
) -> Vec<&'a RelayAlertAssuranceRetentionHandoffReport> {
    handoff_reports
        .iter()
        .filter(|report| {
            report.package_report_sha256 == package_report_sha256 && report.package_id == package_id
        })
        .collect()
}
fn external_retention_sample_coverage(sampled: u64, member_count: u64) -> u64 {
    if member_count == 0 {
        return 0;
    }
    sampled.min(member_count).saturating_mul(10_000) / member_count
}
fn external_retention_fresh(
    generated_at_unix_ms: u64,
    since_unix_ms: u64,
    until_unix_ms: u64,
    now_unix_ms: u64,
    max_age_ms: u64,
) -> bool {
    generated_at_unix_ms >= since_unix_ms
        && generated_at_unix_ms <= until_unix_ms
        && generated_at_unix_ms <= now_unix_ms
        && now_unix_ms.saturating_sub(generated_at_unix_ms) <= max_age_ms
}
fn external_retention_check(
    checks: &mut Vec<RelayAlertCheck>,
    accepted: &mut bool,
    code: &mut String,
    condition: bool,
    check_code: &str,
    failure_code: &str,
    detail: &str,
) {
    checks.push(RelayAlertCheck {
        code: if condition {
            check_code.to_string()
        } else {
            failure_code.to_string()
        },
        accepted: condition,
        detail: detail.to_string(),
    });
    if !condition {
        *accepted = false;
        *code = failure_code.to_string();
    }
}
fn external_retention_fail(
    checks: &mut Vec<RelayAlertCheck>,
    accepted: &mut bool,
    code: &mut String,
    failure_code: &str,
    detail: &str,
) {
    external_retention_check(
        checks,
        accepted,
        code,
        false,
        failure_code,
        failure_code,
        detail,
    );
}
pub(crate) fn validate_archive_profile(
    profile: &RelayAlertAssuranceArchiveProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    validate_local_kernel_id(profile.local_kernel_id.as_str())?;
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::AlertAssuranceInvalid(
            "archive profile is outside its validity window".to_string(),
        ));
    }
    Ok(())
}
pub(crate) fn validate_closeout_profile(
    profile: &RelayAlertAssuranceCloseoutProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    validate_local_kernel_id(profile.local_kernel_id.as_str())?;
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::AlertAssuranceInvalid(
            "closeout profile is outside its validity window".to_string(),
        ));
    }
    Ok(())
}
pub(crate) fn validate_archive_input_roots(
    profile_kernel_id: &str,
    trusted_kernel_id: &str,
    retention_kernel_id: &str,
) -> Result<(), PheromoneRelayError> {
    if profile_kernel_id != trusted_kernel_id || profile_kernel_id != retention_kernel_id {
        return Err(PheromoneRelayError::AlertAssuranceInvalid(
            "archive closeout inputs use mixed local kernel ids".to_string(),
        ));
    }
    Ok(())
}
pub(crate) fn validate_local_kernel_id(value: &str) -> Result<(), PheromoneRelayError> {
    if value.trim().is_empty() || contains_secret_marker(value) || value.contains("://") {
        return Err(PheromoneRelayError::AlertAssuranceInvalid(
            "local kernel id is empty or unsafe".to_string(),
        ));
    }
    Ok(())
}
pub(crate) fn validate_archive_candidates(
    candidates: &[RelayAlertAssuranceArchiveBundleCandidate],
) -> Result<(), PheromoneRelayError> {
    if candidates.is_empty() {
        return Err(PheromoneRelayError::AlertAssuranceInvalid(
            "archive review requires at least one bundle candidate".to_string(),
        ));
    }
    let mut paths = BTreeSet::new();
    let mut bundle_ids = BTreeSet::new();
    for candidate in candidates {
        validate_export_path(&candidate.bundle_path)?;
        if !paths.insert(candidate.bundle_path.as_str()) {
            return Err(PheromoneRelayError::AlertAssuranceInvalid(format!(
                "duplicate bundle path {}",
                candidate.bundle_path
            )));
        }
        if let Some(bundle) = &candidate.bundle {
            let bundle_id = bundle.manifest.body.bundle_id.as_str();
            if !bundle_ids.insert(bundle_id) {
                return Err(PheromoneRelayError::AlertAssuranceInvalid(format!(
                    "duplicate bundle id {bundle_id}"
                )));
            }
        }
    }
    Ok(())
}
pub(crate) fn review_archive_candidate(
    candidate: &RelayAlertAssuranceArchiveBundleCandidate,
    trusted_exporters: &RelayAlertAssuranceTrustedExportersDocument,
    retention_profile: &RelayAlertAssuranceRetentionProfileDocument,
    require_replay_match: bool,
    require_recovery_drill: bool,
    now_unix_ms: u64,
) -> Result<RelayAlertAssuranceArchiveBundleReview, PheromoneRelayError> {
    let Some(bundle) = &candidate.bundle else {
        return Ok(archive_quarantine_review(
            candidate,
            candidate
                .error_code
                .as_deref()
                .unwrap_or("bundle_unreadable"),
            candidate
                .error_detail
                .as_deref()
                .unwrap_or("bundle could not be loaded"),
        ));
    };
    let manifest_sha256 = Some(canonical_sha256(&bundle.manifest)?);
    let source_package_sha256 = Some(bundle.manifest.body.source_package_sha256.clone());
    let artifact_count = bundle.manifest.body.artifacts.len() as u64;
    let route_review_present = bundle
        .manifest
        .body
        .artifacts
        .iter()
        .any(|artifact| artifact.role == "route_review_packet");
    let mut checks = Vec::new();

    if let Err(error) =
        verify_relay_alert_assurance_export_bundle(bundle, trusted_exporters, now_unix_ms)
    {
        let code = error.code().to_string();
        checks.push(RelayAlertCheck {
            code: "trusted_exporter".to_string(),
            accepted: false,
            detail: error.to_string(),
        });
        return Ok(RelayAlertAssuranceArchiveBundleReview {
            bundle_id: bundle.manifest.body.bundle_id.clone(),
            bundle_path: candidate.bundle_path.clone(),
            manifest_sha256,
            source_package_sha256,
            artifact_count,
            state: "quarantine".to_string(),
            code,
            detail: "bundle failed trusted-exporter verification".to_string(),
            trusted_exporter_verified: false,
            replay_matched: false,
            recovery_drill_accepted: false,
            route_review_present,
            retained_count: 0,
            expiring_soon_count: 0,
            eligible_for_delete_count: 0,
            legal_hold_count: 0,
            missing_count: 0,
            quarantine_count: 1,
            checks,
        });
    }
    checks.push(RelayAlertCheck {
        code: "trusted_exporter".to_string(),
        accepted: true,
        detail: "bundle manifest verifies against caller-supplied trusted exporters".to_string(),
    });

    let replay = generate_relay_alert_assurance_replay_report(RelayAlertAssuranceReplayInput {
        bundle,
        trusted_exporters,
        now_unix_ms,
    });
    let replay_matched = replay.as_ref().is_ok_and(|report| report.accepted);
    checks.push(RelayAlertCheck {
        code: "assurance_replay".to_string(),
        accepted: replay_matched,
        detail: match &replay {
            Ok(report) => report.code.clone(),
            Err(error) => error.to_string(),
        },
    });
    if require_replay_match && !replay_matched {
        return Ok(archive_blocked_review(
            bundle,
            candidate,
            manifest_sha256,
            source_package_sha256,
            artifact_count,
            route_review_present,
            checks,
            "replay_mismatch",
            "bundle did not replay to the exported assurance package",
            false,
            false,
        ));
    }

    let retention =
        generate_relay_alert_assurance_retention_report(RelayAlertAssuranceRetentionInput {
            bundles: std::slice::from_ref(bundle),
            retention_profile,
            now_unix_ms,
        })?;
    let recovery = if require_recovery_drill {
        generate_relay_alert_assurance_recovery_drill_report(
            RelayAlertAssuranceRecoveryDrillInput {
                bundle,
                trusted_exporters,
                case_id: "all",
                now_unix_ms,
            },
        )
    } else {
        Ok(RelayAlertAssuranceRecoveryDrillReport {
            schema: PHEROMONE_RELAY_ALERT_ASSURANCE_RECOVERY_DRILL_REPORT_SCHEMA.to_string(),
            accepted: true,
            code: "accepted".to_string(),
            local_kernel_id: bundle.manifest.body.local_kernel_id.clone(),
            generated_at_unix_ms: now_unix_ms,
            drill_count: 0,
            drills: Vec::new(),
            checks: Vec::new(),
        })
    };
    let recovery_drill_accepted = recovery.as_ref().is_ok_and(|report| report.accepted);
    checks.push(RelayAlertCheck {
        code: "recovery_drill".to_string(),
        accepted: recovery_drill_accepted,
        detail: match &recovery {
            Ok(report) => report.code.clone(),
            Err(error) => error.to_string(),
        },
    });
    if require_recovery_drill && !recovery_drill_accepted {
        return Ok(archive_blocked_review(
            bundle,
            candidate,
            manifest_sha256,
            source_package_sha256,
            artifact_count,
            route_review_present,
            checks,
            "recovery_drill_failed",
            "bundle recovery drill did not complete",
            replay_matched,
            false,
        ));
    }
    if !route_review_present {
        return Ok(archive_blocked_review(
            bundle,
            candidate,
            manifest_sha256,
            source_package_sha256,
            artifact_count,
            route_review_present,
            checks,
            "missing_route_review",
            "bundle is missing route-owner review evidence",
            replay_matched,
            recovery_drill_accepted,
        ));
    }

    Ok(RelayAlertAssuranceArchiveBundleReview {
        bundle_id: bundle.manifest.body.bundle_id.clone(),
        bundle_path: candidate.bundle_path.clone(),
        manifest_sha256,
        source_package_sha256,
        artifact_count,
        state: "archive_ready".to_string(),
        code: "accepted".to_string(),
        detail: "bundle verified, replayed, retained, and recovery-drilled for archive closeout"
            .to_string(),
        trusted_exporter_verified: true,
        replay_matched,
        recovery_drill_accepted,
        route_review_present,
        retained_count: retention.retained_count,
        expiring_soon_count: retention.expiring_soon_count,
        eligible_for_delete_count: retention.eligible_for_delete_count,
        legal_hold_count: retention.blocked_count,
        missing_count: retention.missing_count,
        quarantine_count: retention.quarantine_count,
        checks,
    })
}
pub(crate) fn archive_quarantine_review(
    candidate: &RelayAlertAssuranceArchiveBundleCandidate,
    code: &str,
    detail: &str,
) -> RelayAlertAssuranceArchiveBundleReview {
    RelayAlertAssuranceArchiveBundleReview {
        bundle_id: candidate.bundle_path.clone(),
        bundle_path: candidate.bundle_path.clone(),
        manifest_sha256: None,
        source_package_sha256: None,
        artifact_count: 0,
        state: "quarantine".to_string(),
        code: code.to_string(),
        detail: detail.to_string(),
        trusted_exporter_verified: false,
        replay_matched: false,
        recovery_drill_accepted: false,
        route_review_present: false,
        retained_count: 0,
        expiring_soon_count: 0,
        eligible_for_delete_count: 0,
        legal_hold_count: 0,
        missing_count: 0,
        quarantine_count: 1,
        checks: vec![RelayAlertCheck {
            code: code.to_string(),
            accepted: false,
            detail: detail.to_string(),
        }],
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn archive_blocked_review(
    bundle: &RelayAlertAssuranceExportBundle,
    candidate: &RelayAlertAssuranceArchiveBundleCandidate,
    manifest_sha256: Option<String>,
    source_package_sha256: Option<String>,
    artifact_count: u64,
    route_review_present: bool,
    checks: Vec<RelayAlertCheck>,
    code: &str,
    detail: &str,
    replay_matched: bool,
    recovery_drill_accepted: bool,
) -> RelayAlertAssuranceArchiveBundleReview {
    RelayAlertAssuranceArchiveBundleReview {
        bundle_id: bundle.manifest.body.bundle_id.clone(),
        bundle_path: candidate.bundle_path.clone(),
        manifest_sha256,
        source_package_sha256,
        artifact_count,
        state: "archive_blocked".to_string(),
        code: code.to_string(),
        detail: detail.to_string(),
        trusted_exporter_verified: true,
        replay_matched,
        recovery_drill_accepted,
        route_review_present,
        retained_count: 0,
        expiring_soon_count: 0,
        eligible_for_delete_count: 0,
        legal_hold_count: 0,
        missing_count: 0,
        quarantine_count: 0,
        checks,
    }
}
pub(crate) fn closeout_review_from_archive(
    archive: RelayAlertAssuranceArchiveBundleReview,
    profile: &RelayAlertAssuranceCloseoutProfileDocument,
) -> RelayAlertAssuranceCloseoutBundleReview {
    let retention_safe = archive.missing_count == 0
        && archive.quarantine_count == 0
        && (!profile.block_legal_hold || archive.legal_hold_count == 0)
        && (!profile.block_eligible_for_delete || archive.eligible_for_delete_count == 0);
    let (state, code, detail) = if archive.state == "quarantine" {
        (
            "quarantine",
            archive.code.as_str(),
            "bundle is quarantined before closeout review",
        )
    } else if archive.state != "archive_ready" {
        (
            "closeout_blocked",
            archive.code.as_str(),
            "bundle is not archive-ready",
        )
    } else if !archive.route_review_present {
        (
            "closeout_blocked",
            "missing_route_review",
            "bundle is missing route-owner review evidence",
        )
    } else if profile.block_legal_hold && archive.legal_hold_count > 0 {
        (
            "closeout_blocked",
            "legal_hold_blocked",
            "bundle has legal-hold retention rows",
        )
    } else if profile.block_eligible_for_delete && archive.eligible_for_delete_count > 0 {
        (
            "closeout_blocked",
            "eligible_for_delete_present",
            "bundle has dry-run delete eligibility rows",
        )
    } else {
        (
            "closeout_ready",
            "accepted",
            "bundle is ready for operator-managed closeout",
        )
    };
    RelayAlertAssuranceCloseoutBundleReview {
        bundle_id: archive.bundle_id,
        bundle_path: archive.bundle_path,
        manifest_sha256: archive.manifest_sha256,
        artifact_count: archive.artifact_count,
        state: state.to_string(),
        code: code.to_string(),
        detail: detail.to_string(),
        verified_bundle: archive.trusted_exporter_verified,
        replay_matched: archive.replay_matched,
        retention_safe,
        recovery_drill_accepted: archive.recovery_drill_accepted,
        route_review_present: archive.route_review_present,
        legal_hold_count: archive.legal_hold_count,
        eligible_for_delete_count: archive.eligible_for_delete_count,
        missing_count: archive.missing_count,
        quarantine_count: archive.quarantine_count,
        checks: archive.checks,
    }
}
