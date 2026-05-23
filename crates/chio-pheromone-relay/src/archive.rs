use crate::{
    canonical_sha256, contains_secret_marker, generate_relay_alert_assurance_recovery_drill_report,
    generate_relay_alert_assurance_replay_report, generate_relay_alert_assurance_retention_report,
    validate_export_path, validate_retention_profile, verify_relay_alert_assurance_export_bundle,
    PheromoneRelayError, RelayAlertAssuranceExportBundle, RelayAlertAssuranceRecoveryDrillInput,
    RelayAlertAssuranceRecoveryDrillReport, RelayAlertAssuranceReplayInput,
    RelayAlertAssuranceRetentionInput, RelayAlertAssuranceRetentionProfileDocument,
    RelayAlertAssuranceTrustedExportersDocument, RelayAlertCheck,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RECOVERY_DRILL_REPORT_SCHEMA,
};
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceArchiveProfileDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub require_replay_match: bool,
    pub require_recovery_drill: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceCloseoutProfileDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub require_replay_match: bool,
    pub require_recovery_drill: bool,
    pub block_legal_hold: bool,
    pub block_eligible_for_delete: bool,
}

#[derive(Debug, Clone)]
pub struct RelayAlertAssuranceArchiveBundleCandidate {
    pub bundle_path: String,
    pub bundle: Option<RelayAlertAssuranceExportBundle>,
    pub error_code: Option<String>,
    pub error_detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceArchiveBundleReview {
    pub bundle_id: String,
    pub bundle_path: String,
    pub manifest_sha256: Option<String>,
    pub source_package_sha256: Option<String>,
    pub artifact_count: u64,
    pub state: String,
    pub code: String,
    pub detail: String,
    pub trusted_exporter_verified: bool,
    pub replay_matched: bool,
    pub recovery_drill_accepted: bool,
    pub route_review_present: bool,
    pub retained_count: u64,
    pub expiring_soon_count: u64,
    pub eligible_for_delete_count: u64,
    pub legal_hold_count: u64,
    pub missing_count: u64,
    pub quarantine_count: u64,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceArchiveReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub bundle_count: u64,
    pub archive_ready_count: u64,
    pub archive_blocked_count: u64,
    pub quarantine_count: u64,
    pub legal_hold_count: u64,
    pub eligible_for_delete_count: u64,
    pub reviews: Vec<RelayAlertAssuranceArchiveBundleReview>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceCloseoutBundleReview {
    pub bundle_id: String,
    pub bundle_path: String,
    pub manifest_sha256: Option<String>,
    pub artifact_count: u64,
    pub state: String,
    pub code: String,
    pub detail: String,
    pub verified_bundle: bool,
    pub replay_matched: bool,
    pub retention_safe: bool,
    pub recovery_drill_accepted: bool,
    pub route_review_present: bool,
    pub legal_hold_count: u64,
    pub eligible_for_delete_count: u64,
    pub missing_count: u64,
    pub quarantine_count: u64,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceCloseoutReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub bundle_count: u64,
    pub closeout_ready_count: u64,
    pub closeout_blocked_count: u64,
    pub quarantine_count: u64,
    pub legal_hold_count: u64,
    pub eligible_for_delete_count: u64,
    pub reviews: Vec<RelayAlertAssuranceCloseoutBundleReview>,
    pub checks: Vec<RelayAlertCheck>,
}

pub struct RelayAlertAssuranceArchiveInput<'a> {
    pub bundles: &'a [RelayAlertAssuranceArchiveBundleCandidate],
    pub trusted_exporters: &'a RelayAlertAssuranceTrustedExportersDocument,
    pub archive_profile: &'a RelayAlertAssuranceArchiveProfileDocument,
    pub retention_profile: &'a RelayAlertAssuranceRetentionProfileDocument,
    pub now_unix_ms: u64,
}

pub struct RelayAlertAssuranceCloseoutInput<'a> {
    pub bundles: &'a [RelayAlertAssuranceArchiveBundleCandidate],
    pub trusted_exporters: &'a RelayAlertAssuranceTrustedExportersDocument,
    pub closeout_profile: &'a RelayAlertAssuranceCloseoutProfileDocument,
    pub retention_profile: &'a RelayAlertAssuranceRetentionProfileDocument,
    pub now_unix_ms: u64,
}

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
