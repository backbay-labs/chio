use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssurancePackage {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub source_alert_report_sha256: String,
    pub source_trend_report_sha256: String,
    pub source_handoff_report_sha256: String,
    pub source_normalization_report_sha256: String,
    pub source_delivery_report_sha256: String,
    pub source_acknowledgement_report_sha256: String,
    pub source_drift_report_sha256: String,
    pub source_review_packet_sha256: String,
    pub firing_alert_count: u64,
    pub critical_firing_alert_count: u64,
    pub normalized_count: u64,
    pub ready_route_count: u64,
    pub delivery_attention_count: u64,
    pub acknowledgement_pending_count: u64,
    pub drift_count: u64,
    pub operator_action_codes: Vec<String>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceExportArtifact {
    pub role: String,
    pub schema: String,
    pub path: String,
    pub sha256: String,
    pub byte_count: u64,
    pub retention_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceExportManifestBody {
    pub schema: String,
    pub bundle_id: String,
    pub local_kernel_id: String,
    pub exporter_id: String,
    pub exporter_key_id: String,
    pub exported_at_unix_ms: u64,
    pub source_package_sha256: String,
    pub artifacts: Vec<RelayAlertAssuranceExportArtifact>,
    pub safety_claims: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceExportManifest {
    pub schema: String,
    pub body: RelayAlertAssuranceExportManifestBody,
    pub signer_public_key: PublicKey,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceExportFile {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceExportReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub bundle_id: String,
    pub manifest_sha256: String,
    pub source_package_sha256: String,
    pub artifact_count: u64,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceExportBundle {
    pub manifest: RelayAlertAssuranceExportManifest,
    pub report: RelayAlertAssuranceExportReport,
    pub files: Vec<RelayAlertAssuranceExportFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceTrustedExporter {
    pub exporter_id: String,
    pub key_id: String,
    pub public_key: PublicKey,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceTrustedExportersDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub min_exported_at_unix_ms: u64,
    pub exporters: Vec<RelayAlertAssuranceTrustedExporter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceRetentionRule {
    pub artifact_role: String,
    pub retain_for_ms: u64,
    pub legal_hold: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceRetentionProfileDocument {
    pub schema: String,
    pub local_kernel_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub warning_window_ms: u64,
    pub rules: Vec<RelayAlertAssuranceRetentionRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceReplayReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub bundle_id: String,
    pub source_package_sha256: String,
    pub replayed_package_sha256: String,
    pub mismatch_count: u64,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayAlertAssuranceRetentionState {
    Retain,
    ExpiringSoon,
    EligibleForDelete,
    Blocked,
    Missing,
    Quarantine,
}

impl RelayAlertAssuranceRetentionState {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Retain => "retain",
            Self::ExpiringSoon => "expiring_soon",
            Self::EligibleForDelete => "eligible_for_delete",
            Self::Blocked => "blocked",
            Self::Missing => "missing",
            Self::Quarantine => "quarantine",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceRetentionEntry {
    pub bundle_id: String,
    pub artifact_role: String,
    pub path: String,
    pub state: String,
    pub retain_until_unix_ms: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceRetentionReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub retained_count: u64,
    pub expiring_soon_count: u64,
    pub eligible_for_delete_count: u64,
    pub blocked_count: u64,
    pub missing_count: u64,
    pub quarantine_count: u64,
    pub entries: Vec<RelayAlertAssuranceRetentionEntry>,
    pub checks: Vec<RelayAlertCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceRecoveryDrill {
    pub case_id: String,
    pub accepted: bool,
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayAlertAssuranceRecoveryDrillReport {
    pub schema: String,
    pub accepted: bool,
    pub code: String,
    pub local_kernel_id: String,
    pub generated_at_unix_ms: u64,
    pub drill_count: u64,
    pub drills: Vec<RelayAlertAssuranceRecoveryDrill>,
    pub checks: Vec<RelayAlertCheck>,
}

pub struct RelayAlertAssuranceInput<'a> {
    pub alert_report: &'a RelayAlertReport,
    pub trend_report: &'a RelayTrendReport,
    pub handoff_report: &'a RelayAlertHandoffReport,
    pub normalization_report: &'a RelayAlertNormalizationReport,
    pub delivery_report: &'a RelayAlertDeliveryReport,
    pub acknowledgement_report: &'a RelayAlertAcknowledgementReport,
    pub drift_report: &'a RelayAlertDeliveryDriftReportV2,
    pub review_packet: &'a RelayAlertRouteReviewPacket,
    pub now_unix_ms: u64,
}

pub struct RelayAlertAssuranceExportBuildInput<'a> {
    pub bundle_id: &'a str,
    pub exporter_id: &'a str,
    pub exporter_key_id: &'a str,
    pub signing_key: &'a Keypair,
    pub alert_report: &'a RelayAlertReport,
    pub trend_report: &'a RelayTrendReport,
    pub handoff_report: &'a RelayAlertHandoffReport,
    pub normalization_report: &'a RelayAlertNormalizationReport,
    pub delivery_report: &'a RelayAlertDeliveryReport,
    pub acknowledgement_report: &'a RelayAlertAcknowledgementReport,
    pub drift_report: &'a RelayAlertDeliveryDriftReportV2,
    pub review_packet: &'a RelayAlertRouteReviewPacket,
    pub assurance_package: &'a RelayAlertAssurancePackage,
    pub normalized_delivery_evidence: &'a [RelayAlertDeliveryEvidence],
    pub retention_profile: &'a RelayAlertAssuranceRetentionProfileDocument,
    pub exported_at_unix_ms: u64,
}

pub struct RelayAlertAssuranceReplayInput<'a> {
    pub bundle: &'a RelayAlertAssuranceExportBundle,
    pub trusted_exporters: &'a RelayAlertAssuranceTrustedExportersDocument,
    pub now_unix_ms: u64,
}

pub struct RelayAlertAssuranceRetentionInput<'a> {
    pub bundles: &'a [RelayAlertAssuranceExportBundle],
    pub retention_profile: &'a RelayAlertAssuranceRetentionProfileDocument,
    pub now_unix_ms: u64,
}

pub struct RelayAlertAssuranceRecoveryDrillInput<'a> {
    pub bundle: &'a RelayAlertAssuranceExportBundle,
    pub trusted_exporters: &'a RelayAlertAssuranceTrustedExportersDocument,
    pub case_id: &'a str,
    pub now_unix_ms: u64,
}

pub fn generate_relay_alert_assurance_package(
    input: RelayAlertAssuranceInput<'_>,
) -> Result<RelayAlertAssurancePackage, PheromoneRelayError> {
    validate_assurance_source_chain(&input)?;
    let delivery_attention_count = input.delivery_report.delayed_count
        + input.delivery_report.failed_count
        + input.delivery_report.unknown_count;
    let acknowledgement_pending_count =
        input.acknowledgement_report.pending_count + input.acknowledgement_report.failed_count;
    let accepted = input.alert_report.accepted
        && input.normalization_report.accepted
        && input.delivery_report.accepted
        && input.acknowledgement_report.accepted
        && input.drift_report.accepted
        && input.review_packet.accepted
        && delivery_attention_count == 0
        && acknowledgement_pending_count == 0;
    let mut operator_action_codes = Vec::new();
    if accepted {
        operator_action_codes.push("ready".to_string());
    } else {
        if !input.alert_report.accepted {
            operator_action_codes.push("active_alerts_present".to_string());
        }
        if !input.normalization_report.accepted {
            operator_action_codes.push("normalization_attention_required".to_string());
        }
        if delivery_attention_count > 0 {
            operator_action_codes.push("delivery_attention_required".to_string());
        }
        if acknowledgement_pending_count > 0 {
            operator_action_codes.push("acknowledgement_attention_required".to_string());
        }
        if input.drift_report.drift_count > 0 || !input.drift_report.accepted {
            operator_action_codes.push("delivery_drift_detected".to_string());
        }
        if !input.review_packet.accepted {
            operator_action_codes.push("route_review_attention_required".to_string());
        }
        if operator_action_codes.is_empty() {
            operator_action_codes.push("assurance_attention_required".to_string());
        }
    }
    for code in &operator_action_codes {
        if !is_bounded_code(code) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "assurance action code is not bounded".to_string(),
            ));
        }
    }
    Ok(RelayAlertAssurancePackage {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_PACKAGE_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "assurance_attention_required"
        }
        .to_string(),
        local_kernel_id: input.alert_report.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        source_alert_report_sha256: canonical_sha256(input.alert_report)?,
        source_trend_report_sha256: canonical_sha256(input.trend_report)?,
        source_handoff_report_sha256: canonical_sha256(input.handoff_report)?,
        source_normalization_report_sha256: canonical_sha256(input.normalization_report)?,
        source_delivery_report_sha256: canonical_sha256(input.delivery_report)?,
        source_acknowledgement_report_sha256: canonical_sha256(input.acknowledgement_report)?,
        source_drift_report_sha256: canonical_sha256(input.drift_report)?,
        source_review_packet_sha256: canonical_sha256(input.review_packet)?,
        firing_alert_count: input.handoff_report.firing_alert_count,
        critical_firing_alert_count: input.handoff_report.critical_firing_count,
        normalized_count: input.normalization_report.normalized_count,
        ready_route_count: input.review_packet.ready_route_count,
        delivery_attention_count,
        acknowledgement_pending_count,
        drift_count: input.drift_report.drift_count,
        operator_action_codes,
        checks: vec![RelayAlertCheck {
            code: "alert_assurance_chain".to_string(),
            accepted,
            detail: "alert, handoff, normalized delivery, acknowledgement, drift, and review reports are hash-bound".to_string(),
        }],
    })
}

pub fn sign_relay_alert_assurance_export_bundle(
    input: RelayAlertAssuranceExportBuildInput<'_>,
) -> Result<RelayAlertAssuranceExportBundle, PheromoneRelayError> {
    validate_assurance_source_chain(&RelayAlertAssuranceInput {
        alert_report: input.alert_report,
        trend_report: input.trend_report,
        handoff_report: input.handoff_report,
        normalization_report: input.normalization_report,
        delivery_report: input.delivery_report,
        acknowledgement_report: input.acknowledgement_report,
        drift_report: input.drift_report,
        review_packet: input.review_packet,
        now_unix_ms: input.exported_at_unix_ms,
    })?;
    validate_assurance_package_sources(&input)?;
    validate_retention_profile(input.retention_profile, input.exported_at_unix_ms)?;
    validate_export_identity(input.bundle_id, "bundle id")?;
    validate_export_identity(input.exporter_id, "exporter id")?;
    validate_export_identity(input.exporter_key_id, "exporter key id")?;

    let mut artifacts = Vec::new();
    let mut files = Vec::new();
    push_export_artifact(
        &mut artifacts,
        &mut files,
        "alert_report",
        PHEROMONE_RELAY_ALERT_REPORT_SCHEMA,
        "reports/relay-alert-report.json",
        "incident_evidence",
        input.alert_report,
    )?;
    push_export_artifact(
        &mut artifacts,
        &mut files,
        "trend_report",
        PHEROMONE_RELAY_TREND_REPORT_SCHEMA,
        "reports/relay-trend-report.json",
        "incident_evidence",
        input.trend_report,
    )?;
    push_export_artifact(
        &mut artifacts,
        &mut files,
        "handoff_report",
        PHEROMONE_RELAY_ALERT_HANDOFF_REPORT_SCHEMA,
        "reports/relay-alert-handoff-report.json",
        "incident_evidence",
        input.handoff_report,
    )?;
    push_export_artifact(
        &mut artifacts,
        &mut files,
        "normalization_report",
        PHEROMONE_RELAY_ALERT_NORMALIZATION_REPORT_SCHEMA,
        "reports/relay-alert-normalization-report.json",
        "incident_evidence",
        input.normalization_report,
    )?;
    push_export_artifact(
        &mut artifacts,
        &mut files,
        "delivery_report",
        PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA,
        "reports/relay-alert-delivery-report.json",
        "incident_evidence",
        input.delivery_report,
    )?;
    push_export_artifact(
        &mut artifacts,
        &mut files,
        "acknowledgement_report",
        PHEROMONE_RELAY_ALERT_ACKNOWLEDGEMENT_REPORT_SCHEMA,
        "reports/relay-alert-acknowledgement-report.json",
        "incident_evidence",
        input.acknowledgement_report,
    )?;
    push_export_artifact(
        &mut artifacts,
        &mut files,
        "drift_report",
        PHEROMONE_RELAY_ALERT_DELIVERY_DRIFT_REPORT_V2_SCHEMA,
        "reports/relay-alert-delivery-drift-report-v2.json",
        "incident_evidence",
        input.drift_report,
    )?;
    push_export_artifact(
        &mut artifacts,
        &mut files,
        "route_review_packet",
        PHEROMONE_RELAY_ALERT_ROUTE_REVIEW_PACKET_SCHEMA,
        "reports/relay-alert-route-review-packet.json",
        "incident_evidence",
        input.review_packet,
    )?;
    push_export_artifact(
        &mut artifacts,
        &mut files,
        "assurance_package",
        PHEROMONE_RELAY_ALERT_ASSURANCE_PACKAGE_SCHEMA,
        "reports/relay-alert-assurance-package.json",
        "legal_hold",
        input.assurance_package,
    )?;
    push_export_artifact(
        &mut artifacts,
        &mut files,
        "retention_profile",
        PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_PROFILE_SCHEMA,
        "profiles/relay-alert-assurance-retention-profile.json",
        "operator_profile",
        input.retention_profile,
    )?;
    for (index, evidence) in input.normalized_delivery_evidence.iter().enumerate() {
        let path = format!("evidence/relay-alert-delivery-evidence-{index:03}.json");
        push_export_artifact(
            &mut artifacts,
            &mut files,
            "normalized_delivery_evidence",
            PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA,
            &path,
            "incident_evidence",
            evidence,
        )?;
    }
    validate_export_artifact_set(&artifacts, &files)?;

    let source_package_sha256 = canonical_sha256(input.assurance_package)?;
    let body = RelayAlertAssuranceExportManifestBody {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_MANIFEST_SCHEMA.to_string(),
        bundle_id: input.bundle_id.to_string(),
        local_kernel_id: input.assurance_package.local_kernel_id.clone(),
        exporter_id: input.exporter_id.to_string(),
        exporter_key_id: input.exporter_key_id.to_string(),
        exported_at_unix_ms: input.exported_at_unix_ms,
        source_package_sha256,
        artifacts,
        safety_claims: vec![
            "local_export_only".to_string(),
            "no_live_notification_delivery".to_string(),
            "retention_report_only".to_string(),
        ],
    };
    let (signature, _) = input
        .signing_key
        .sign_canonical(&body)
        .map_err(|error| PheromoneRelayError::CanonicalJson(error.to_string()))?;
    let manifest = RelayAlertAssuranceExportManifest {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_MANIFEST_SCHEMA.to_string(),
        body,
        signer_public_key: input.signing_key.public_key(),
        signature,
    };
    let report = build_export_report(
        &manifest,
        true,
        "accepted",
        input.exported_at_unix_ms,
        vec![RelayAlertCheck {
            code: "export_manifest_signed".to_string(),
            accepted: true,
            detail: "export manifest is signed over canonical bundle metadata".to_string(),
        }],
    )?;
    Ok(RelayAlertAssuranceExportBundle {
        manifest,
        report,
        files,
    })
}

pub fn verify_relay_alert_assurance_export_bundle(
    bundle: &RelayAlertAssuranceExportBundle,
    trusted_exporters: &RelayAlertAssuranceTrustedExportersDocument,
    now_unix_ms: u64,
) -> Result<RelayAlertAssuranceExportReport, PheromoneRelayError> {
    validate_export_bundle_manifest(bundle)?;
    validate_trusted_exporters(trusted_exporters, &bundle.manifest, now_unix_ms)?;
    validate_export_artifact_set(&bundle.manifest.body.artifacts, &bundle.files)?;
    build_export_report(
        &bundle.manifest,
        true,
        "accepted",
        now_unix_ms,
        vec![
            RelayAlertCheck {
                code: "trusted_exporter".to_string(),
                accepted: true,
                detail: "manifest signer is trusted by caller-supplied exporter roots".to_string(),
            },
            RelayAlertCheck {
                code: "bundle_hashes".to_string(),
                accepted: true,
                detail: "bundle files match manifest paths, byte counts, and hashes".to_string(),
            },
        ],
    )
}

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
    let drift_report: RelayAlertDeliveryDriftReportV2 =
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

pub(crate) fn validate_assurance_source_chain(
    input: &RelayAlertAssuranceInput<'_>,
) -> Result<(), PheromoneRelayError> {
    let local_kernel_id = input.alert_report.local_kernel_id.as_str();
    for (name, candidate) in [
        ("handoff", input.handoff_report.local_kernel_id.as_str()),
        (
            "normalization",
            input.normalization_report.local_kernel_id.as_str(),
        ),
        ("delivery", input.delivery_report.local_kernel_id.as_str()),
        (
            "acknowledgement",
            input.acknowledgement_report.local_kernel_id.as_str(),
        ),
        ("drift", input.drift_report.local_kernel_id.as_str()),
        ("review", input.review_packet.local_kernel_id.as_str()),
    ] {
        if candidate != local_kernel_id {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "assurance {name} local kernel id mismatch"
            )));
        }
    }
    if input.trend_report.local_kernel_id != local_kernel_id {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "assurance trend local kernel id mismatch".to_string(),
        ));
    }
    if input.handoff_report.source_alert_report_sha256 != canonical_sha256(input.alert_report)?
        || input.handoff_report.source_trend_report_sha256 != canonical_sha256(input.trend_report)?
        || input.delivery_report.source_handoff_report_sha256
            != canonical_sha256(input.handoff_report)?
        || input.acknowledgement_report.source_delivery_report_sha256
            != canonical_sha256(input.delivery_report)?
        || input.review_packet.source_handoff_report_sha256
            != canonical_sha256(input.handoff_report)?
        || input.review_packet.source_delivery_report_sha256
            != canonical_sha256(input.delivery_report)?
        || input.review_packet.source_acknowledgement_report_sha256
            != canonical_sha256(input.acknowledgement_report)?
        || input.review_packet.source_drift_report_sha256 != canonical_sha256(input.drift_report)?
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "assurance source hash mismatch".to_string(),
        ));
    }
    for (name, generated_at) in [
        ("alert report", input.alert_report.generated_at_unix_ms),
        ("handoff report", input.handoff_report.generated_at_unix_ms),
        (
            "normalization report",
            input.normalization_report.generated_at_unix_ms,
        ),
        (
            "delivery report",
            input.delivery_report.generated_at_unix_ms,
        ),
        (
            "acknowledgement report",
            input.acknowledgement_report.generated_at_unix_ms,
        ),
        ("drift report", input.drift_report.generated_at_unix_ms),
        ("review packet", input.review_packet.generated_at_unix_ms),
    ] {
        if generated_at > input.now_unix_ms {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "assurance {name} timestamp is in the future"
            )));
        }
    }
    if input.trend_report.until_unix_ms > input.now_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "assurance trend report timestamp is in the future".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_assurance_package_sources(
    input: &RelayAlertAssuranceExportBuildInput<'_>,
) -> Result<(), PheromoneRelayError> {
    if input.assurance_package.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_PACKAGE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            input.assurance_package.schema.clone(),
        ));
    }
    let expected = [
        (
            input.assurance_package.source_alert_report_sha256.as_str(),
            canonical_sha256(input.alert_report)?,
        ),
        (
            input.assurance_package.source_trend_report_sha256.as_str(),
            canonical_sha256(input.trend_report)?,
        ),
        (
            input
                .assurance_package
                .source_handoff_report_sha256
                .as_str(),
            canonical_sha256(input.handoff_report)?,
        ),
        (
            input
                .assurance_package
                .source_normalization_report_sha256
                .as_str(),
            canonical_sha256(input.normalization_report)?,
        ),
        (
            input
                .assurance_package
                .source_delivery_report_sha256
                .as_str(),
            canonical_sha256(input.delivery_report)?,
        ),
        (
            input
                .assurance_package
                .source_acknowledgement_report_sha256
                .as_str(),
            canonical_sha256(input.acknowledgement_report)?,
        ),
        (
            input.assurance_package.source_drift_report_sha256.as_str(),
            canonical_sha256(input.drift_report)?,
        ),
        (
            input.assurance_package.source_review_packet_sha256.as_str(),
            canonical_sha256(input.review_packet)?,
        ),
    ];
    for (actual, expected) in expected {
        if actual != expected {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "assurance package source hash mismatch".to_string(),
            ));
        }
    }
    for evidence in input.normalized_delivery_evidence {
        validate_delivery_evidence_shape(evidence)?;
        if !input
            .normalization_report
            .evidence_hashes
            .contains(&canonical_sha256(evidence)?)
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "normalized delivery evidence is not bound to normalization report".to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_export_identity(value: &str, name: &str) -> Result<(), PheromoneRelayError> {
    if !is_bounded_route_token(value) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
            "export {name} is not bounded"
        )));
    }
    if contains_secret_marker(value) || value.contains("://") {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
            "export {name} contains secret material or a dynamic URL"
        )));
    }
    Ok(())
}

pub(crate) fn push_export_artifact<T: Serialize>(
    artifacts: &mut Vec<RelayAlertAssuranceExportArtifact>,
    files: &mut Vec<RelayAlertAssuranceExportFile>,
    role: &str,
    schema: &str,
    path: &str,
    retention_class: &str,
    value: &T,
) -> Result<(), PheromoneRelayError> {
    validate_export_identity(role, "artifact role")?;
    validate_export_identity(retention_class, "retention class")?;
    validate_export_path(path)?;
    let value = serde_json::to_value(value)?;
    reject_downstream_source_secrets(&value)?;
    let bytes = canonical_json_bytes(&value)
        .map_err(|error| PheromoneRelayError::CanonicalJson(error.to_string()))?;
    let byte_count = u64::try_from(bytes.len()).map_err(|_| {
        PheromoneRelayError::AlertDeliveryInvalid("artifact byte count overflow".to_string())
    })?;
    artifacts.push(RelayAlertAssuranceExportArtifact {
        role: role.to_string(),
        schema: schema.to_string(),
        path: path.to_string(),
        sha256: sha256_hex(&bytes),
        byte_count,
        retention_class: retention_class.to_string(),
    });
    files.push(RelayAlertAssuranceExportFile {
        path: path.to_string(),
        bytes,
    });
    Ok(())
}

pub(crate) fn validate_export_bundle_manifest(
    bundle: &RelayAlertAssuranceExportBundle,
) -> Result<(), PheromoneRelayError> {
    if bundle.manifest.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_MANIFEST_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            bundle.manifest.schema.clone(),
        ));
    }
    if bundle.manifest.body.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_MANIFEST_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            bundle.manifest.body.schema.clone(),
        ));
    }
    validate_export_identity(&bundle.manifest.body.bundle_id, "bundle id")?;
    validate_export_identity(&bundle.manifest.body.exporter_id, "exporter id")?;
    validate_export_identity(&bundle.manifest.body.exporter_key_id, "exporter key id")?;
    if !is_sha256_hex(&bundle.manifest.body.source_package_sha256) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "export manifest source package hash is invalid".to_string(),
        ));
    }
    for claim in &bundle.manifest.body.safety_claims {
        validate_export_identity(claim, "safety claim")?;
    }
    Ok(())
}

pub(crate) fn validate_export_artifact_set(
    artifacts: &[RelayAlertAssuranceExportArtifact],
    files: &[RelayAlertAssuranceExportFile],
) -> Result<(), PheromoneRelayError> {
    if artifacts.is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "export manifest has no artifacts".to_string(),
        ));
    }
    let mut roles = BTreeSet::new();
    let mut artifact_paths = BTreeSet::new();
    for artifact in artifacts {
        validate_export_identity(&artifact.role, "artifact role")?;
        validate_export_identity(&artifact.retention_class, "retention class")?;
        validate_export_path(&artifact.path)?;
        if artifact.schema.trim().is_empty() || artifact.schema.contains("..") {
            return Err(PheromoneRelayError::UnsupportedSchema(
                artifact.schema.clone(),
            ));
        }
        if !is_sha256_hex(&artifact.sha256) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "artifact {} has invalid hash",
                artifact.role
            )));
        }
        if artifact.role != "normalized_delivery_evidence" && !roles.insert(&artifact.role) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate artifact role {}",
                artifact.role
            )));
        }
        if !artifact_paths.insert(&artifact.path) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate artifact path {}",
                artifact.path
            )));
        }
    }
    let mut file_paths = BTreeSet::new();
    for file in files {
        validate_export_path(&file.path)?;
        if !file_paths.insert(&file.path) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate export file {}",
                file.path
            )));
        }
    }
    for artifact in artifacts {
        let file = files
            .iter()
            .find(|file| file.path == artifact.path)
            .ok_or_else(|| {
                PheromoneRelayError::BodyHashMismatch(format!(
                    "artifact {} file is missing",
                    artifact.role
                ))
            })?;
        let actual_hash = sha256_hex(&file.bytes);
        if actual_hash != artifact.sha256 {
            return Err(PheromoneRelayError::BodyHashMismatch(format!(
                "artifact {} hash does not match manifest",
                artifact.role
            )));
        }
        let actual_len = u64::try_from(file.bytes.len()).map_err(|_| {
            PheromoneRelayError::AlertDeliveryInvalid("artifact byte count overflow".to_string())
        })?;
        if actual_len != artifact.byte_count {
            return Err(PheromoneRelayError::BodyHashMismatch(format!(
                "artifact {} byte count does not match manifest",
                artifact.role
            )));
        }
    }
    for file in files {
        if !artifact_paths.contains(&file.path) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "export file {} is not listed in manifest",
                file.path
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_export_path(path: &str) -> Result<(), PheromoneRelayError> {
    if path.trim() != path
        || path.is_empty()
        || path.contains('\\')
        || path.contains(':')
        || Path::new(path).is_absolute()
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "export path must be relative and portable".to_string(),
        ));
    }
    let mut has_segment = false;
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "export path contains an unsafe segment".to_string(),
            ));
        }
        has_segment = true;
    }
    if !has_segment {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "export path is empty".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_trusted_exporters(
    trusted_exporters: &RelayAlertAssuranceTrustedExportersDocument,
    manifest: &RelayAlertAssuranceExportManifest,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    if trusted_exporters.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_TRUSTED_EXPORTERS_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            trusted_exporters.schema.clone(),
        ));
    }
    if trusted_exporters.local_kernel_id != manifest.body.local_kernel_id {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "trusted exporters local kernel id mismatch".to_string(),
        ));
    }
    if manifest.body.exported_at_unix_ms < trusted_exporters.min_exported_at_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "export is older than trusted exporter floor".to_string(),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut exporter = None;
    for candidate in &trusted_exporters.exporters {
        validate_export_identity(&candidate.exporter_id, "exporter id")?;
        validate_export_identity(&candidate.key_id, "exporter key id")?;
        if !seen.insert((candidate.exporter_id.as_str(), candidate.key_id.as_str())) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "duplicate trusted exporter".to_string(),
            ));
        }
        if candidate.exporter_id == manifest.body.exporter_id
            && candidate.key_id == manifest.body.exporter_key_id
        {
            exporter = Some(candidate);
        }
    }
    let exporter = exporter.ok_or(PheromoneRelayError::SignatureInvalid)?;
    if exporter.status != "active" {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "trusted exporter is not active".to_string(),
        ));
    }
    if manifest.signer_public_key != exporter.public_key {
        return Err(PheromoneRelayError::SignatureInvalid);
    }
    if now_unix_ms < exporter.valid_from_unix_ms
        || now_unix_ms >= exporter.valid_until_unix_ms
        || manifest.body.exported_at_unix_ms < exporter.valid_from_unix_ms
        || manifest.body.exported_at_unix_ms >= exporter.valid_until_unix_ms
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "trusted exporter key is outside its validity window".to_string(),
        ));
    }
    if !exporter
        .public_key
        .verify_canonical(&manifest.body, &manifest.signature)
        .map_err(|error| PheromoneRelayError::CanonicalJson(error.to_string()))?
    {
        return Err(PheromoneRelayError::SignatureInvalid);
    }
    Ok(())
}

pub(crate) fn build_export_report(
    manifest: &RelayAlertAssuranceExportManifest,
    accepted: bool,
    code: &str,
    generated_at_unix_ms: u64,
    checks: Vec<RelayAlertCheck>,
) -> Result<RelayAlertAssuranceExportReport, PheromoneRelayError> {
    Ok(RelayAlertAssuranceExportReport {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_REPORT_SCHEMA.to_string(),
        accepted,
        code: code.to_string(),
        local_kernel_id: manifest.body.local_kernel_id.clone(),
        generated_at_unix_ms,
        bundle_id: manifest.body.bundle_id.clone(),
        manifest_sha256: canonical_sha256(manifest)?,
        source_package_sha256: manifest.body.source_package_sha256.clone(),
        artifact_count: manifest.body.artifacts.len() as u64,
        checks,
    })
}

pub(crate) fn export_artifact_from_json<T: DeserializeOwned>(
    bundle: &RelayAlertAssuranceExportBundle,
    role: &str,
) -> Result<T, PheromoneRelayError> {
    let matches = bundle
        .manifest
        .body
        .artifacts
        .iter()
        .filter(|artifact| artifact.role == role)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
            "expected exactly one export artifact for role {role}"
        )));
    }
    let artifact = matches[0];
    let file = bundle
        .files
        .iter()
        .find(|file| file.path == artifact.path)
        .ok_or_else(|| {
            PheromoneRelayError::BodyHashMismatch(format!("artifact {role} file is missing"))
        })?;
    Ok(serde_json::from_slice(&file.bytes)?)
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
