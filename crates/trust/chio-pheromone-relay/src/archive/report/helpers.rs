use super::*;

pub(crate) fn has_matching_physical_readback(
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
pub(crate) fn has_matching_retention_handoff(
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
