use super::super::*;
use super::export_release_readiness;

pub(in crate::commands) fn export_controlled_adoption(
    output: &Path,
) -> Result<MercuryControlledAdoptionExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let release_readiness_dir = output.join("release-readiness");
    let release_readiness = export_release_readiness(&release_readiness_dir)?;
    let workflow_id = release_readiness.workflow_id.clone();

    let profile = build_controlled_adoption_profile(&workflow_id)?;
    let profile_path = output.join("controlled-adoption-profile.json");
    write_json_file(&profile_path, &profile)?;

    let adoption_evidence_dir = output.join("adoption-evidence");
    fs::create_dir_all(&adoption_evidence_dir)?;

    let release_readiness_package_path =
        adoption_evidence_dir.join("release-readiness-package.json");
    let trust_network_package_path = adoption_evidence_dir.join("trust-network-package.json");
    let assurance_suite_package_path = adoption_evidence_dir.join("assurance-suite-package.json");
    let proof_package_path = adoption_evidence_dir.join("proof-package.json");
    let inquiry_package_path = adoption_evidence_dir.join("inquiry-package.json");
    let inquiry_verification_path = adoption_evidence_dir.join("inquiry-verification.json");
    let reviewer_package_path = adoption_evidence_dir.join("reviewer-package.json");
    let qualification_report_path = adoption_evidence_dir.join("qualification-report.json");

    copy_file(
        &release_readiness_dir.join("release-readiness-package.json"),
        &release_readiness_package_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/trust-network-package.json"),
        &trust_network_package_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/assurance-suite-package.json"),
        &assurance_suite_package_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/proof-package.json"),
        &proof_package_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/inquiry-package.json"),
        &inquiry_package_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/inquiry-verification.json"),
        &inquiry_verification_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/reviewer-package.json"),
        &reviewer_package_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/qualification-report.json"),
        &qualification_report_path,
    )?;

    let customer_success_checklist = MercuryControlledAdoptionCustomerSuccessChecklist {
        schema: "chio.mercury.controlled_adoption_customer_success_checklist.v1".to_string(),
        workflow_id: workflow_id.clone(),
        customer_success_owner: MERCURY_CUSTOMER_SUCCESS_OWNER.to_string(),
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        support_owner: MERCURY_ADOPTION_SUPPORT_OWNER.to_string(),
        fail_closed: true,
        readiness_checks: vec![
            "confirm the adoption cohort remains design-partner renewal only".to_string(),
            "confirm renewal evidence points back to the same release-readiness package and Mercury workflow".to_string(),
            "confirm reference-readiness materials use only the bounded approved claim".to_string(),
            "confirm customer-success and support escalation files exist before any renewal or reference motion".to_string(),
        ],
        note: "This checklist governs one Mercury post-launch adoption lane only and does not authorize generic Chio renewal tooling or broader Mercury delivery surfaces."
            .to_string(),
    };
    let customer_success_checklist_path = output.join("customer-success-checklist.json");
    write_json_file(
        &customer_success_checklist_path,
        &customer_success_checklist,
    )?;

    let renewal_manifest = MercuryControlledAdoptionRenewalManifest {
        schema: "chio.mercury.controlled_adoption_renewal_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        cohort: MercuryControlledAdoptionCohort::DesignPartnerRenewal
            .as_str()
            .to_string(),
        adoption_surface: MercuryControlledAdoptionSurface::RenewalReferenceBundle
            .as_str()
            .to_string(),
        success_window: profile.success_window.clone(),
        renewal_signal: "design partner confirms continued Mercury use with proof-backed renewal and reference review".to_string(),
        release_readiness_package_file: relative_display(output, &release_readiness_package_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        inquiry_verification_file: relative_display(output, &inquiry_verification_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        note: "This manifest freezes one bounded renewal-evidence lane on top of the validated Mercury release-readiness stack and does not imply a generic customer-success platform."
            .to_string(),
    };
    let renewal_manifest_path = output.join("renewal-evidence-manifest.json");
    write_json_file(&renewal_manifest_path, &renewal_manifest)?;

    let renewal_acknowledgement = MercuryControlledAdoptionRenewalAcknowledgement {
        schema: "chio.mercury.controlled_adoption_renewal_acknowledgement.v1".to_string(),
        workflow_id: workflow_id.clone(),
        cohort: MercuryControlledAdoptionCohort::DesignPartnerRenewal
            .as_str()
            .to_string(),
        adoption_surface: MercuryControlledAdoptionSurface::RenewalReferenceBundle
            .as_str()
            .to_string(),
        customer_success_owner: MERCURY_CUSTOMER_SUCCESS_OWNER.to_string(),
        status: "acknowledged".to_string(),
        acknowledged_at: unix_now(),
        acknowledged_by: MERCURY_CUSTOMER_SUCCESS_OWNER.to_string(),
        delivered_files: vec![
            relative_display(output, &renewal_manifest_path)?,
            relative_display(output, &release_readiness_package_path)?,
            relative_display(output, &trust_network_package_path)?,
            relative_display(output, &assurance_suite_package_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &reviewer_package_path)?,
            relative_display(output, &qualification_report_path)?,
        ],
        note: "Acknowledgement is required before the bounded renewal and reference lane may be treated as ready for scaled Mercury adoption."
            .to_string(),
    };
    let renewal_acknowledgement_path = output.join("renewal-acknowledgement.json");
    write_json_file(&renewal_acknowledgement_path, &renewal_acknowledgement)?;

    let reference_readiness_brief = MercuryControlledAdoptionReferenceReadinessBrief {
        schema: "chio.mercury.controlled_adoption_reference_readiness_brief.v1".to_string(),
        workflow_id: workflow_id.clone(),
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        cohort: MercuryControlledAdoptionCohort::DesignPartnerRenewal
            .as_str()
            .to_string(),
        adoption_surface: MercuryControlledAdoptionSurface::RenewalReferenceBundle
            .as_str()
            .to_string(),
        approved_claim: "Mercury can support one bounded controlled-adoption lane for renewal and reference readiness over the validated release-readiness evidence stack."
            .to_string(),
        required_files: vec![
            relative_display(output, &renewal_manifest_path)?,
            relative_display(output, &renewal_acknowledgement_path)?,
            relative_display(output, &release_readiness_package_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
        ],
        note: "Reference material remains bounded to one approved claim and one design-partner renewal cohort. Broader marketing claims are outside this approved reference scope."
            .to_string(),
    };
    let reference_readiness_brief_path = output.join("reference-readiness-brief.json");
    write_json_file(&reference_readiness_brief_path, &reference_readiness_brief)?;

    let support_escalation_manifest = MercuryControlledAdoptionSupportEscalationManifest {
        schema: "chio.mercury.controlled_adoption_support_escalation_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        support_owner: MERCURY_ADOPTION_SUPPORT_OWNER.to_string(),
        customer_success_owner: MERCURY_CUSTOMER_SUCCESS_OWNER.to_string(),
        fail_closed: true,
        escalation_triggers: vec![
            "renewal evidence no longer maps to the same release-readiness package".to_string(),
            "reference-readiness brief uses an unapproved claim or missing artifact".to_string(),
            "proof, inquiry, assurance, or trust-network adoption evidence is missing".to_string(),
            "customer-success acknowledgement is missing before renewal or reference use".to_string(),
        ],
        note: "Escalation remains Mercury-owned for one bounded controlled-adoption lane and must not migrate into Chio generic release or support surfaces."
            .to_string(),
    };
    let support_escalation_manifest_path = output.join("support-escalation-manifest.json");
    write_json_file(
        &support_escalation_manifest_path,
        &support_escalation_manifest,
    )?;

    let package = MercuryControlledAdoptionPackage {
        schema: MERCURY_CONTROLLED_ADOPTION_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "controlled-adoption-design-partner-renewal-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        cohort: MercuryControlledAdoptionCohort::DesignPartnerRenewal,
        adoption_surface: MercuryControlledAdoptionSurface::RenewalReferenceBundle,
        customer_success_owner: MERCURY_CUSTOMER_SUCCESS_OWNER.to_string(),
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        support_owner: MERCURY_ADOPTION_SUPPORT_OWNER.to_string(),
        acknowledgement_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        release_readiness_package_file: relative_display(output, &release_readiness_package_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        artifacts: vec![
            MercuryControlledAdoptionArtifact {
                artifact_kind: MercuryControlledAdoptionArtifactKind::CustomerSuccessChecklist,
                relative_path: relative_display(output, &customer_success_checklist_path)?,
            },
            MercuryControlledAdoptionArtifact {
                artifact_kind: MercuryControlledAdoptionArtifactKind::RenewalEvidenceManifest,
                relative_path: relative_display(output, &renewal_manifest_path)?,
            },
            MercuryControlledAdoptionArtifact {
                artifact_kind: MercuryControlledAdoptionArtifactKind::RenewalAcknowledgement,
                relative_path: relative_display(output, &renewal_acknowledgement_path)?,
            },
            MercuryControlledAdoptionArtifact {
                artifact_kind: MercuryControlledAdoptionArtifactKind::ReferenceReadinessBrief,
                relative_path: relative_display(output, &reference_readiness_brief_path)?,
            },
            MercuryControlledAdoptionArtifact {
                artifact_kind: MercuryControlledAdoptionArtifactKind::SupportEscalationManifest,
                relative_path: relative_display(output, &support_escalation_manifest_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("controlled-adoption-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryControlledAdoptionExportSummary {
        workflow_id,
        cohort: MercuryControlledAdoptionCohort::DesignPartnerRenewal
            .as_str()
            .to_string(),
        adoption_surface: MercuryControlledAdoptionSurface::RenewalReferenceBundle
            .as_str()
            .to_string(),
        customer_success_owner: MERCURY_CUSTOMER_SUCCESS_OWNER.to_string(),
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        support_owner: MERCURY_ADOPTION_SUPPORT_OWNER.to_string(),
        release_readiness_dir: release_readiness_dir.display().to_string(),
        controlled_adoption_profile_file: profile_path.display().to_string(),
        controlled_adoption_package_file: package_path.display().to_string(),
        customer_success_checklist_file: customer_success_checklist_path.display().to_string(),
        renewal_evidence_manifest_file: renewal_manifest_path.display().to_string(),
        renewal_acknowledgement_file: renewal_acknowledgement_path.display().to_string(),
        reference_readiness_brief_file: reference_readiness_brief_path.display().to_string(),
        support_escalation_manifest_file: support_escalation_manifest_path.display().to_string(),
        adoption_evidence_dir: adoption_evidence_dir.display().to_string(),
        release_readiness_package_file: release_readiness_package_path.display().to_string(),
        trust_network_package_file: trust_network_package_path.display().to_string(),
        assurance_suite_package_file: assurance_suite_package_path.display().to_string(),
        proof_package_file: proof_package_path.display().to_string(),
        inquiry_package_file: inquiry_package_path.display().to_string(),
        inquiry_verification_file: inquiry_verification_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
    };
    write_json_file(&output.join("controlled-adoption-summary.json"), &summary)?;

    let _ = release_readiness;

    Ok(summary)
}
