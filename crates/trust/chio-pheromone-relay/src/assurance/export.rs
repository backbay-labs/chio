use super::*;

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
        PHEROMONE_RELAY_ALERT_DELIVERY_DRIFT_REPORT_SCHEMA,
        "reports/relay-alert-delivery-drift-report.json",
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
