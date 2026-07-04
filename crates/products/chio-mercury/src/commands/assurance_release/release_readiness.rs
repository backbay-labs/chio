use super::super::*;
use super::export_trust_network;

pub(in crate::commands) fn export_release_readiness(
    output: &Path,
) -> Result<MercuryReleaseReadinessExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let trust_network_dir = output.join("trust-network");
    let trust_network = export_trust_network(&trust_network_dir)?;
    let workflow_id = trust_network.workflow_id.clone();

    let profile = build_release_readiness_profile(&workflow_id)?;
    let profile_path = output.join("release-readiness-profile.json");
    write_json_file(&profile_path, &profile)?;

    let partner_bundle_dir = output.join("partner-delivery");
    fs::create_dir_all(&partner_bundle_dir)?;

    let proof_package_path = partner_bundle_dir.join("proof-package.json");
    let inquiry_package_path = partner_bundle_dir.join("inquiry-package.json");
    let inquiry_verification_path = partner_bundle_dir.join("inquiry-verification.json");
    let assurance_suite_package_path = partner_bundle_dir.join("assurance-suite-package.json");
    let trust_network_package_path = partner_bundle_dir.join("trust-network-package.json");
    let reviewer_package_path = partner_bundle_dir.join("reviewer-package.json");
    let qualification_report_path = partner_bundle_dir.join("qualification-report.json");

    copy_file(
        &trust_network_dir.join("trust-network-share/shared-proof-package.json"),
        &proof_package_path,
    )?;
    copy_file(
        &trust_network_dir.join("trust-network-share/inquiry-package.json"),
        &inquiry_package_path,
    )?;
    copy_file(
        &trust_network_dir.join("trust-network-share/inquiry-verification.json"),
        &inquiry_verification_path,
    )?;
    copy_file(
        &trust_network_dir.join("embedded-oem/assurance-suite/assurance-suite-package.json"),
        &assurance_suite_package_path,
    )?;
    copy_file(
        &trust_network_dir.join("trust-network-package.json"),
        &trust_network_package_path,
    )?;
    copy_file(
        &trust_network_dir.join("trust-network-share/reviewer-package.json"),
        &reviewer_package_path,
    )?;
    copy_file(
        &trust_network_dir.join("trust-network-share/qualification-report.json"),
        &qualification_report_path,
    )?;

    let operator_release_checklist = MercuryReleaseReadinessOperatorChecklist {
        schema: "chio.mercury.release_readiness_operator_checklist.v1".to_string(),
        workflow_id: workflow_id.clone(),
        release_owner: MERCURY_RELEASE_OWNER.to_string(),
        partner_owner: MERCURY_RELEASE_PARTNER_OWNER.to_string(),
        support_owner: MERCURY_RELEASE_SUPPORT_OWNER.to_string(),
        fail_closed: true,
        gating_checks: vec![
            "confirm release-readiness profile matches reviewer, partner, and operator audiences"
                .to_string(),
            "confirm partner-delivery bundle contains proof, inquiry, assurance, trust-network, reviewer, and qualification artifacts"
                .to_string(),
            "confirm the same workflow sentence remains unchanged across all exported artifacts"
                .to_string(),
            "confirm operator escalation and support handoff files are present before launch"
                .to_string(),
        ],
        note: "The operator checklist is limited to one bounded Mercury release-readiness lane and does not authorize a generic Chio release console."
            .to_string(),
    };
    let operator_release_checklist_path = output.join("operator-release-checklist.json");
    write_json_file(
        &operator_release_checklist_path,
        &operator_release_checklist,
    )?;

    let escalation_manifest = MercuryReleaseReadinessEscalationManifest {
        schema: "chio.mercury.release_readiness_escalation_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        release_owner: MERCURY_RELEASE_OWNER.to_string(),
        support_owner: MERCURY_RELEASE_SUPPORT_OWNER.to_string(),
        fail_closed: true,
        escalation_triggers: vec![
            "partner-delivery manifest mismatch".to_string(),
            "missing proof, inquiry, assurance, or trust-network file".to_string(),
            "reviewer package and qualification report cannot be matched to the same workflow"
                .to_string(),
            "operator checklist is incomplete at launch time".to_string(),
        ],
        note: "Escalation remains product-owned inside Mercury and must not be shifted into Chio generic crates."
            .to_string(),
    };
    let escalation_manifest_path = output.join("escalation-manifest.json");
    write_json_file(&escalation_manifest_path, &escalation_manifest)?;

    let support_handoff = MercuryReleaseReadinessSupportHandoff {
        schema: "chio.mercury.release_readiness_support_handoff.v1".to_string(),
        workflow_id: workflow_id.clone(),
        release_owner: MERCURY_RELEASE_OWNER.to_string(),
        support_owner: MERCURY_RELEASE_SUPPORT_OWNER.to_string(),
        active_window: "launch + initial controlled adoption window".to_string(),
        required_files: vec![
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &assurance_suite_package_path)?,
            relative_display(output, &trust_network_package_path)?,
            relative_display(output, &reviewer_package_path)?,
            relative_display(output, &qualification_report_path)?,
        ],
        note: "This handoff is bounded to one Mercury launch lane and one support-owner path."
            .to_string(),
    };
    let support_handoff_path = output.join("support-handoff.json");
    write_json_file(&support_handoff_path, &support_handoff)?;

    let partner_manifest = MercuryReleaseReadinessPartnerManifest {
        schema: "chio.mercury.release_readiness_partner_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        delivery_surface: MercuryReleaseReadinessDeliverySurface::SignedPartnerReviewBundle
            .as_str()
            .to_string(),
        reviewer_population: trust_network.reviewer_population.clone(),
        acknowledgement_required: true,
        fail_closed: true,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        inquiry_verification_file: relative_display(output, &inquiry_verification_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        operator_release_checklist_file: relative_display(output, &operator_release_checklist_path)?,
        escalation_manifest_file: relative_display(output, &escalation_manifest_path)?,
        support_handoff_file: relative_display(output, &support_handoff_path)?,
        note: "This manifest delivers one bounded Mercury package to one partner path while preserving the same proof, inquiry, assurance, and trust-network truth chain."
            .to_string(),
    };
    let partner_manifest_path = output.join("partner-delivery-manifest.json");
    write_json_file(&partner_manifest_path, &partner_manifest)?;

    let acknowledgement = MercuryReleaseReadinessDeliveryAcknowledgement {
        schema: "chio.mercury.release_readiness_delivery_acknowledgement.v1".to_string(),
        workflow_id: workflow_id.clone(),
        delivery_surface: MercuryReleaseReadinessDeliverySurface::SignedPartnerReviewBundle
            .as_str()
            .to_string(),
        partner_owner: MERCURY_RELEASE_PARTNER_OWNER.to_string(),
        status: "acknowledged".to_string(),
        acknowledged_at: unix_now(),
        acknowledged_by: MERCURY_RELEASE_PARTNER_OWNER.to_string(),
        delivered_files: vec![
            relative_display(output, &partner_manifest_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &assurance_suite_package_path)?,
            relative_display(output, &trust_network_package_path)?,
            relative_display(output, &reviewer_package_path)?,
            relative_display(output, &qualification_report_path)?,
        ],
        note: "Acknowledgement is required before this bounded release-readiness lane may be treated as launched."
            .to_string(),
    };
    let acknowledgement_path = output.join("delivery-acknowledgement.json");
    write_json_file(&acknowledgement_path, &acknowledgement)?;

    let package = MercuryReleaseReadinessPackage {
        schema: MERCURY_RELEASE_READINESS_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "release-readiness-signed-partner-review-bundle-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        audiences: profile.audiences.clone(),
        delivery_surface: MercuryReleaseReadinessDeliverySurface::SignedPartnerReviewBundle,
        release_owner: MERCURY_RELEASE_OWNER.to_string(),
        partner_owner: MERCURY_RELEASE_PARTNER_OWNER.to_string(),
        support_owner: MERCURY_RELEASE_SUPPORT_OWNER.to_string(),
        acknowledgement_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        artifacts: vec![
            MercuryReleaseReadinessArtifact {
                artifact_kind: MercuryReleaseReadinessArtifactKind::PartnerDeliveryManifest,
                relative_path: relative_display(output, &partner_manifest_path)?,
            },
            MercuryReleaseReadinessArtifact {
                artifact_kind: MercuryReleaseReadinessArtifactKind::DeliveryAcknowledgement,
                relative_path: relative_display(output, &acknowledgement_path)?,
            },
            MercuryReleaseReadinessArtifact {
                artifact_kind: MercuryReleaseReadinessArtifactKind::OperatorReleaseChecklist,
                relative_path: relative_display(output, &operator_release_checklist_path)?,
            },
            MercuryReleaseReadinessArtifact {
                artifact_kind: MercuryReleaseReadinessArtifactKind::EscalationManifest,
                relative_path: relative_display(output, &escalation_manifest_path)?,
            },
            MercuryReleaseReadinessArtifact {
                artifact_kind: MercuryReleaseReadinessArtifactKind::SupportHandoff,
                relative_path: relative_display(output, &support_handoff_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("release-readiness-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryReleaseReadinessExportSummary {
        workflow_id,
        audiences: profile
            .audiences
            .iter()
            .map(|audience| audience.as_str().to_string())
            .collect(),
        delivery_surface: MercuryReleaseReadinessDeliverySurface::SignedPartnerReviewBundle
            .as_str()
            .to_string(),
        release_owner: MERCURY_RELEASE_OWNER.to_string(),
        partner_owner: MERCURY_RELEASE_PARTNER_OWNER.to_string(),
        support_owner: MERCURY_RELEASE_SUPPORT_OWNER.to_string(),
        trust_network_dir: trust_network_dir.display().to_string(),
        release_readiness_profile_file: profile_path.display().to_string(),
        release_readiness_package_file: package_path.display().to_string(),
        partner_delivery_manifest_file: partner_manifest_path.display().to_string(),
        acknowledgement_file: acknowledgement_path.display().to_string(),
        operator_release_checklist_file: operator_release_checklist_path.display().to_string(),
        escalation_manifest_file: escalation_manifest_path.display().to_string(),
        support_handoff_file: support_handoff_path.display().to_string(),
        partner_bundle_dir: partner_bundle_dir.display().to_string(),
        proof_package_file: proof_package_path.display().to_string(),
        inquiry_package_file: inquiry_package_path.display().to_string(),
        inquiry_verification_file: inquiry_verification_path.display().to_string(),
        assurance_suite_package_file: assurance_suite_package_path.display().to_string(),
        trust_network_package_file: trust_network_package_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
    };
    write_json_file(&output.join("release-readiness-summary.json"), &summary)?;

    Ok(summary)
}
