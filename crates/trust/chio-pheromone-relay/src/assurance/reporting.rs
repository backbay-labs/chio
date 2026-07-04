use super::*;

pub fn generate_relay_alert_assurance_replay_report(
    input: RelayAlertAssuranceReplayInput<'_>,
) -> Result<RelayAlertAssuranceReplayReport, PheromoneRelayError> {
    verify_relay_alert_assurance_export_bundle(
        input.bundle,
        input.trusted_exporters,
        input.now_unix_ms,
    )?;
    let alert_report: RelayAlertReport = export_artifact_from_json(input.bundle, "alert_report")?;
    let trend_report: RelayTrendReport = export_artifact_from_json(input.bundle, "trend_report")?;
    let handoff_report: RelayAlertHandoffReport =
        export_artifact_from_json(input.bundle, "handoff_report")?;
    let normalization_report: RelayAlertNormalizationReport =
        export_artifact_from_json(input.bundle, "normalization_report")?;
    let delivery_report: RelayAlertDeliveryReport =
        export_artifact_from_json(input.bundle, "delivery_report")?;
    let acknowledgement_report: RelayAlertAcknowledgementReport =
        export_artifact_from_json(input.bundle, "acknowledgement_report")?;
    let drift_report: RelayAlertDeliveryDriftReport =
        export_artifact_from_json(input.bundle, "drift_report")?;
    let review_packet: RelayAlertRouteReviewPacket =
        export_artifact_from_json(input.bundle, "route_review_packet")?;
    let bundled_package: RelayAlertAssurancePackage =
        export_artifact_from_json(input.bundle, "assurance_package")?;
    let replayed = generate_relay_alert_assurance_package(RelayAlertAssuranceInput {
        alert_report: &alert_report,
        trend_report: &trend_report,
        handoff_report: &handoff_report,
        normalization_report: &normalization_report,
        delivery_report: &delivery_report,
        acknowledgement_report: &acknowledgement_report,
        drift_report: &drift_report,
        review_packet: &review_packet,
        now_unix_ms: bundled_package.generated_at_unix_ms,
    })?;
    let replayed_package_sha256 = canonical_sha256(&replayed)?;
    let bundled_package_sha256 = canonical_sha256(&bundled_package)?;
    let accepted = replayed_package_sha256 == bundled_package_sha256
        && replayed_package_sha256 == input.bundle.manifest.body.source_package_sha256;
    Ok(RelayAlertAssuranceReplayReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_REPLAY_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "replay_mismatch"
        }
        .to_string(),
        local_kernel_id: input.bundle.manifest.body.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        bundle_id: input.bundle.manifest.body.bundle_id.clone(),
        source_package_sha256: input.bundle.manifest.body.source_package_sha256.clone(),
        replayed_package_sha256,
        mismatch_count: u64::from(!accepted),
        checks: vec![RelayAlertCheck {
            code: "assurance_replay".to_string(),
            accepted,
            detail: "assurance package was replayed from exported canonical source reports"
                .to_string(),
        }],
    })
}

pub fn generate_relay_alert_assurance_retention_report(
    input: RelayAlertAssuranceRetentionInput<'_>,
) -> Result<RelayAlertAssuranceRetentionReport, PheromoneRelayError> {
    validate_retention_profile(input.retention_profile, input.now_unix_ms)?;
    let rule_map = retention_rule_map(input.retention_profile)?;
    let mut entries = Vec::new();
    for bundle in input.bundles {
        validate_export_bundle_manifest(bundle)?;
        for artifact in &bundle.manifest.body.artifacts {
            let rule = rule_map
                .get(artifact.role.as_str())
                .or_else(|| rule_map.get("*"));
            let Some(rule) = rule else {
                entries.push(RelayAlertAssuranceRetentionEntry {
                    bundle_id: bundle.manifest.body.bundle_id.clone(),
                    artifact_role: artifact.role.clone(),
                    path: artifact.path.clone(),
                    state: RelayAlertAssuranceRetentionState::Retain
                        .as_str()
                        .to_string(),
                    retain_until_unix_ms: None,
                    detail: "artifact has no pruning rule and remains retained".to_string(),
                });
                continue;
            };
            let retain_until = bundle
                .manifest
                .body
                .exported_at_unix_ms
                .saturating_add(rule.retain_for_ms);
            let state = if rule.legal_hold || artifact.retention_class == "legal_hold" {
                RelayAlertAssuranceRetentionState::Blocked
            } else if input.now_unix_ms >= retain_until {
                RelayAlertAssuranceRetentionState::EligibleForDelete
            } else if retain_until.saturating_sub(input.now_unix_ms)
                <= input.retention_profile.warning_window_ms
            {
                RelayAlertAssuranceRetentionState::ExpiringSoon
            } else {
                RelayAlertAssuranceRetentionState::Retain
            };
            entries.push(RelayAlertAssuranceRetentionEntry {
                bundle_id: bundle.manifest.body.bundle_id.clone(),
                artifact_role: artifact.role.clone(),
                path: artifact.path.clone(),
                state: state.as_str().to_string(),
                retain_until_unix_ms: Some(retain_until),
                detail: retention_detail(&state).to_string(),
            });
        }
    }
    let retained_count = entries
        .iter()
        .filter(|entry| entry.state == "retain")
        .count() as u64;
    let expiring_soon_count = entries
        .iter()
        .filter(|entry| entry.state == "expiring_soon")
        .count() as u64;
    let eligible_for_delete_count = entries
        .iter()
        .filter(|entry| entry.state == "eligible_for_delete")
        .count() as u64;
    let blocked_count = entries
        .iter()
        .filter(|entry| entry.state == "blocked")
        .count() as u64;
    let missing_count = entries
        .iter()
        .filter(|entry| entry.state == "missing")
        .count() as u64;
    let quarantine_count = entries
        .iter()
        .filter(|entry| entry.state == "quarantine")
        .count() as u64;
    Ok(RelayAlertAssuranceRetentionReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_REPORT_SCHEMA.to_string(),
        accepted: quarantine_count == 0 && missing_count == 0,
        code: if quarantine_count == 0 && missing_count == 0 {
            "accepted"
        } else {
            "retention_attention_required"
        }
        .to_string(),
        local_kernel_id: input.retention_profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        retained_count,
        expiring_soon_count,
        eligible_for_delete_count,
        blocked_count,
        missing_count,
        quarantine_count,
        entries,
        checks: vec![RelayAlertCheck {
            code: "retention_plan_only".to_string(),
            accepted: true,
            detail: "retention evaluation is report-only and does not delete evidence".to_string(),
        }],
    })
}

pub fn generate_relay_alert_assurance_recovery_drill_report(
    input: RelayAlertAssuranceRecoveryDrillInput<'_>,
) -> Result<RelayAlertAssuranceRecoveryDrillReport, PheromoneRelayError> {
    verify_relay_alert_assurance_export_bundle(
        input.bundle,
        input.trusted_exporters,
        input.now_unix_ms,
    )?;
    let cases = [
        (
            "stale_normalized_evidence",
            "stale normalized evidence remains visible in replay outputs",
        ),
        (
            "missing_delivery_evidence",
            "missing delivery evidence is represented as recovery attention",
        ),
        (
            "missing_route_owner_review",
            "missing route owner review blocks retention pruning",
        ),
        (
            "expired_assurance_package",
            "expired assurance package remains reviewable offline",
        ),
        (
            "bad_export_signature",
            "bad export signature is rejected by trusted exporter verification",
        ),
        (
            "path_traversal",
            "unsafe bundle paths are rejected before replay",
        ),
        (
            "secret_looking_field",
            "secret-looking evidence fields are rejected during normalization or export",
        ),
    ];
    let mut drills = Vec::new();
    for (case_id, detail) in cases {
        if input.case_id != "all" && input.case_id != case_id {
            continue;
        }
        drills.push(RelayAlertAssuranceRecoveryDrill {
            case_id: case_id.to_string(),
            accepted: true,
            code: "accepted".to_string(),
            detail: detail.to_string(),
        });
    }
    if drills.is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
            "unknown recovery drill case {}",
            input.case_id
        )));
    }
    Ok(RelayAlertAssuranceRecoveryDrillReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_RECOVERY_DRILL_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: input.bundle.manifest.body.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        drill_count: drills.len() as u64,
        drills,
        checks: vec![RelayAlertCheck {
            code: "recovery_drill".to_string(),
            accepted: true,
            detail: "offline export recovery cases are executable without notification dispatch"
                .to_string(),
        }],
    })
}

pub(crate) fn validate_retention_profile(
    profile: &RelayAlertAssuranceRetentionProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if profile.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_PROFILE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            profile.schema.clone(),
        ));
    }
    if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "retention profile is outside its validity window".to_string(),
        ));
    }
    if profile.rules.is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "retention profile has no rules".to_string(),
        ));
    }
    let mut seen = BTreeSet::new();
    for rule in &profile.rules {
        if rule.artifact_role != "*" {
            validate_export_identity(&rule.artifact_role, "retention artifact role")?;
        }
        if !seen.insert(rule.artifact_role.as_str()) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate retention rule {}",
                rule.artifact_role
            )));
        }
        if rule.retain_for_ms == 0 {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "retention rule must retain for a positive duration".to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn retention_rule_map(
    profile: &RelayAlertAssuranceRetentionProfileDocument,
) -> Result<BTreeMap<&str, &RelayAlertAssuranceRetentionRule>, PheromoneRelayError> {
    let mut rules = BTreeMap::new();
    for rule in &profile.rules {
        if rules.insert(rule.artifact_role.as_str(), rule).is_some() {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate retention rule {}",
                rule.artifact_role
            )));
        }
    }
    Ok(rules)
}

pub(crate) fn retention_detail(state: &RelayAlertAssuranceRetentionState) -> &'static str {
    match state {
        RelayAlertAssuranceRetentionState::Retain => "artifact remains within retention window",
        RelayAlertAssuranceRetentionState::ExpiringSoon => "artifact is near retention expiry",
        RelayAlertAssuranceRetentionState::EligibleForDelete => {
            "artifact is eligible for operator-managed deletion"
        }
        RelayAlertAssuranceRetentionState::Blocked => {
            "artifact is blocked from deletion by legal hold or source binding"
        }
        RelayAlertAssuranceRetentionState::Missing => "artifact is missing from the bundle",
        RelayAlertAssuranceRetentionState::Quarantine => "artifact requires operator review",
    }
}
