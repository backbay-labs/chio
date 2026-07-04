use super::super::*;
use super::export_assurance_suite;

pub(in crate::commands) fn export_embedded_oem(
    output: &Path,
) -> Result<MercuryEmbeddedOemExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let assurance_dir = output.join("assurance-suite");
    let assurance_summary = export_assurance_suite(&assurance_dir)?;
    let workflow_id = assurance_summary.workflow_id.clone();

    let profile = build_embedded_oem_profile(&workflow_id)?;
    let profile_path = output.join("embedded-oem-profile.json");
    write_json_file(&profile_path, &profile)?;

    let partner_bundle_dir = output.join("partner-sdk-bundle");
    fs::create_dir_all(&partner_bundle_dir)?;

    let assurance_suite_package_src = assurance_dir.join("assurance-suite-package.json");
    let governance_decision_package_src =
        assurance_dir.join("governance-workbench/governance-decision-package.json");
    let disclosure_profile_src =
        assurance_dir.join("reviewer-populations/counterparty-review/disclosure-profile.json");
    let review_package_src =
        assurance_dir.join("reviewer-populations/counterparty-review/review-package.json");
    let investigation_package_src =
        assurance_dir.join("reviewer-populations/counterparty-review/investigation-package.json");
    let reviewer_package_src =
        assurance_dir.join("governance-workbench/qualification/reviewer-package.json");
    let qualification_report_src =
        assurance_dir.join("governance-workbench/qualification/qualification-report.json");

    let assurance_suite_package_path = partner_bundle_dir.join("assurance-suite-package.json");
    let governance_decision_package_path =
        partner_bundle_dir.join("governance-decision-package.json");
    let disclosure_profile_path = partner_bundle_dir.join("disclosure-profile.json");
    let review_package_path = partner_bundle_dir.join("review-package.json");
    let investigation_package_path = partner_bundle_dir.join("investigation-package.json");
    let reviewer_package_path = partner_bundle_dir.join("reviewer-package.json");
    let qualification_report_path = partner_bundle_dir.join("qualification-report.json");

    copy_file(&assurance_suite_package_src, &assurance_suite_package_path)?;
    copy_file(
        &governance_decision_package_src,
        &governance_decision_package_path,
    )?;
    copy_file(&disclosure_profile_src, &disclosure_profile_path)?;
    copy_file(&review_package_src, &review_package_path)?;
    copy_file(&investigation_package_src, &investigation_package_path)?;
    copy_file(&reviewer_package_src, &reviewer_package_path)?;
    copy_file(&qualification_report_src, &qualification_report_path)?;

    let acknowledgement = MercuryEmbeddedDeliveryAcknowledgement {
        schema: "chio.mercury.embedded_delivery_acknowledgement.v1".to_string(),
        workflow_id: workflow_id.clone(),
        partner_surface: MercuryEmbeddedPartnerSurface::ReviewerWorkbenchEmbed
            .as_str()
            .to_string(),
        partner_owner: MERCURY_EMBEDDED_PARTNER_OWNER.to_string(),
        status: "acknowledged".to_string(),
        acknowledged_at: unix_now(),
        acknowledged_by: "partner-review-platform-drop".to_string(),
        delivered_files: vec![
            "assurance-suite-package.json".to_string(),
            "governance-decision-package.json".to_string(),
            "disclosure-profile.json".to_string(),
            "review-package.json".to_string(),
            "investigation-package.json".to_string(),
            "reviewer-package.json".to_string(),
            "qualification-report.json".to_string(),
        ],
        note: "The embedded OEM bundle is limited to one reviewer-workbench surface, one signed artifact bundle, and one counterparty-review population. Any missing or inconsistent artifact must fail closed."
            .to_string(),
    };
    let acknowledgement_path = partner_bundle_dir.join("delivery-acknowledgement.json");
    write_json_file(&acknowledgement_path, &acknowledgement)?;

    let sdk_manifest = MercuryEmbeddedPartnerManifest {
        schema: "chio.mercury.embedded_partner_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        partner_surface: MercuryEmbeddedPartnerSurface::ReviewerWorkbenchEmbed
            .as_str()
            .to_string(),
        sdk_surface: MercuryEmbeddedSdkSurface::SignedArtifactBundle
            .as_str()
            .to_string(),
        reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview
            .as_str()
            .to_string(),
        fail_closed: true,
        acknowledgement_required: true,
        profile_file: relative_display(output, &profile_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        governance_decision_package_file: relative_display(
            output,
            &governance_decision_package_path,
        )?,
        disclosure_profile_file: relative_display(output, &disclosure_profile_path)?,
        review_package_file: relative_display(output, &review_package_path)?,
        investigation_package_file: relative_display(output, &investigation_package_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        support_owner: MERCURY_EMBEDDED_SUPPORT_OWNER.to_string(),
        note: "This manifest is the bounded embedded OEM surface. It packages one counterparty-review Mercury bundle for one partner reviewer workbench and does not imply a generic SDK or multi-partner OEM platform."
            .to_string(),
    };
    let sdk_manifest_path = output.join("partner-sdk-manifest.json");
    write_json_file(&sdk_manifest_path, &sdk_manifest)?;

    let package = MercuryEmbeddedOemPackage {
        schema: MERCURY_EMBEDDED_OEM_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "embedded-oem-reviewer-workbench-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        partner_surface: MercuryEmbeddedPartnerSurface::ReviewerWorkbenchEmbed,
        sdk_surface: MercuryEmbeddedSdkSurface::SignedArtifactBundle,
        reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview,
        partner_owner: MERCURY_EMBEDDED_PARTNER_OWNER.to_string(),
        support_owner: MERCURY_EMBEDDED_SUPPORT_OWNER.to_string(),
        acknowledgement_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        sdk_manifest_file: relative_display(output, &sdk_manifest_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        governance_decision_package_file: relative_display(
            output,
            &governance_decision_package_path,
        )?,
        artifacts: vec![
            MercuryEmbeddedOemArtifact {
                artifact_kind: MercuryEmbeddedArtifactKind::DisclosureProfile,
                relative_path: relative_display(output, &disclosure_profile_path)?,
            },
            MercuryEmbeddedOemArtifact {
                artifact_kind: MercuryEmbeddedArtifactKind::ReviewPackage,
                relative_path: relative_display(output, &review_package_path)?,
            },
            MercuryEmbeddedOemArtifact {
                artifact_kind: MercuryEmbeddedArtifactKind::InvestigationPackage,
                relative_path: relative_display(output, &investigation_package_path)?,
            },
            MercuryEmbeddedOemArtifact {
                artifact_kind: MercuryEmbeddedArtifactKind::ReviewerPackage,
                relative_path: relative_display(output, &reviewer_package_path)?,
            },
            MercuryEmbeddedOemArtifact {
                artifact_kind: MercuryEmbeddedArtifactKind::QualificationReport,
                relative_path: relative_display(output, &qualification_report_path)?,
            },
            MercuryEmbeddedOemArtifact {
                artifact_kind: MercuryEmbeddedArtifactKind::DeliveryAcknowledgement,
                relative_path: relative_display(output, &acknowledgement_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("embedded-oem-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryEmbeddedOemExportSummary {
        workflow_id,
        partner_surface: MercuryEmbeddedPartnerSurface::ReviewerWorkbenchEmbed
            .as_str()
            .to_string(),
        sdk_surface: MercuryEmbeddedSdkSurface::SignedArtifactBundle
            .as_str()
            .to_string(),
        reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview
            .as_str()
            .to_string(),
        partner_owner: MERCURY_EMBEDDED_PARTNER_OWNER.to_string(),
        support_owner: MERCURY_EMBEDDED_SUPPORT_OWNER.to_string(),
        assurance_suite_dir: assurance_dir.display().to_string(),
        embedded_oem_profile_file: profile_path.display().to_string(),
        embedded_oem_package_file: package_path.display().to_string(),
        partner_sdk_manifest_file: sdk_manifest_path.display().to_string(),
        assurance_suite_package_file: assurance_suite_package_path.display().to_string(),
        governance_decision_package_file: governance_decision_package_path.display().to_string(),
        disclosure_profile_file: disclosure_profile_path.display().to_string(),
        review_package_file: review_package_path.display().to_string(),
        investigation_package_file: investigation_package_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
        acknowledgement_file: acknowledgement_path.display().to_string(),
        partner_sdk_bundle_dir: partner_bundle_dir.display().to_string(),
    };
    write_json_file(&output.join("embedded-oem-summary.json"), &summary)?;

    Ok(summary)
}
