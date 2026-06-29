use super::super::*;

pub(in crate::commands) fn export_assurance_suite(
    output: &Path,
) -> Result<MercuryAssuranceSuiteExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let governance_dir = output.join("governance-workbench");
    let governance_summary = export_governance_workbench(&governance_dir)?;
    let proof_package_path =
        governance_dir.join("qualification/supervised-live/proof-package.json");
    let proof_package: MercuryProofPackage = read_json_file(&proof_package_path)?;
    proof_package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;

    let reviewer_package_path = governance_dir.join("qualification/reviewer-package.json");
    let qualification_report_path = governance_dir.join("qualification/qualification-report.json");
    let governance_decision_package_path = governance_dir.join("governance-decision-package.json");
    let investigation_inputs = collect_assurance_investigation_inputs(&proof_package);

    let populations_dir = output.join("reviewer-populations");
    fs::create_dir_all(&populations_dir)?;

    let mut reviewer_populations = Vec::new();
    let mut artifacts = Vec::new();
    let mut internal_review_package_file = String::new();
    let mut auditor_review_package_file = String::new();
    let mut counterparty_review_package_file = String::new();
    let mut internal_investigation_package_file = String::new();
    let mut auditor_investigation_package_file = String::new();
    let mut counterparty_investigation_package_file = String::new();

    for config in assurance_suite_population_configs() {
        let population_dir = populations_dir.join(config.dir_name);
        fs::create_dir_all(&population_dir)?;

        let disclosure_profile =
            build_assurance_disclosure_profile(&governance_summary.workflow_id, config)?;
        let disclosure_profile_path = population_dir.join("disclosure-profile.json");
        write_json_file(&disclosure_profile_path, &disclosure_profile)?;

        let inquiry_package = build_inquiry_package(
            proof_package.clone(),
            config.audience,
            Some(config.redaction_profile),
            config.verifier_equivalent,
        )?;
        let inquiry_report = inquiry_package
            .verify(unix_now())
            .map_err(|error| CliError::Other(error.to_string()))?;
        let inquiry_package_path = population_dir.join("inquiry-package.json");
        let inquiry_verification_path = population_dir.join("inquiry-verification.json");
        write_json_file(&inquiry_package_path, &inquiry_package)?;
        write_verification_report(&inquiry_verification_path, &inquiry_report)?;

        let review_package = build_assurance_review_package(AssuranceReviewPackageArgs {
            workflow_id: &governance_summary.workflow_id,
            reviewer_population: config.reviewer_population,
            disclosure_profile_file: &relative_display(output, &disclosure_profile_path)?,
            proof_package_file: &relative_display(output, &proof_package_path)?,
            inquiry_package_file: &relative_display(output, &inquiry_package_path)?,
            inquiry_verification_file: &relative_display(output, &inquiry_verification_path)?,
            reviewer_package_file: &relative_display(output, &reviewer_package_path)?,
            qualification_report_file: &relative_display(output, &qualification_report_path)?,
            governance_decision_package_file: &relative_display(
                output,
                &governance_decision_package_path,
            )?,
            verifier_equivalent: config.verifier_equivalent,
        })?;
        let review_package_path = population_dir.join("review-package.json");
        write_json_file(&review_package_path, &review_package)?;

        let investigation_package = build_assurance_investigation_package(
            &governance_summary.workflow_id,
            config.reviewer_population,
            &relative_display(output, &review_package_path)?,
            &investigation_inputs,
            config.investigation_focus,
        )?;
        let investigation_package_path = population_dir.join("investigation-package.json");
        write_json_file(&investigation_package_path, &investigation_package)?;

        reviewer_populations.push(config.reviewer_population.as_str().to_string());
        artifacts.push(MercuryAssuranceSuiteArtifact {
            reviewer_population: config.reviewer_population,
            artifact_kind: MercuryAssuranceArtifactKind::DisclosureProfile,
            relative_path: relative_display(output, &disclosure_profile_path)?,
        });
        artifacts.push(MercuryAssuranceSuiteArtifact {
            reviewer_population: config.reviewer_population,
            artifact_kind: MercuryAssuranceArtifactKind::ReviewPackage,
            relative_path: relative_display(output, &review_package_path)?,
        });
        artifacts.push(MercuryAssuranceSuiteArtifact {
            reviewer_population: config.reviewer_population,
            artifact_kind: MercuryAssuranceArtifactKind::InvestigationPackage,
            relative_path: relative_display(output, &investigation_package_path)?,
        });

        match config.reviewer_population {
            MercuryAssuranceReviewerPopulation::InternalReview => {
                internal_review_package_file = review_package_path.display().to_string();
                internal_investigation_package_file =
                    investigation_package_path.display().to_string();
            }
            MercuryAssuranceReviewerPopulation::AuditorReview => {
                auditor_review_package_file = review_package_path.display().to_string();
                auditor_investigation_package_file =
                    investigation_package_path.display().to_string();
            }
            MercuryAssuranceReviewerPopulation::CounterpartyReview => {
                counterparty_review_package_file = review_package_path.display().to_string();
                counterparty_investigation_package_file =
                    investigation_package_path.display().to_string();
            }
        }
    }

    let assurance_suite_package = MercuryAssuranceSuitePackage {
        schema: MERCURY_ASSURANCE_SUITE_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "assurance-suite-{}-{}",
            governance_summary.workflow_id,
            current_utc_date()
        ),
        workflow_id: governance_summary.workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        reviewer_owner: MERCURY_ASSURANCE_REVIEWER_OWNER.to_string(),
        support_owner: MERCURY_ASSURANCE_SUPPORT_OWNER.to_string(),
        fail_closed: true,
        governance_decision_package_file: relative_display(
            output,
            &governance_decision_package_path,
        )?,
        reviewer_populations: vec![
            MercuryAssuranceReviewerPopulation::InternalReview,
            MercuryAssuranceReviewerPopulation::AuditorReview,
            MercuryAssuranceReviewerPopulation::CounterpartyReview,
        ],
        artifacts,
    };
    assurance_suite_package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let assurance_suite_package_path = output.join("assurance-suite-package.json");
    write_json_file(&assurance_suite_package_path, &assurance_suite_package)?;

    let summary = MercuryAssuranceSuiteExportSummary {
        workflow_id: governance_summary.workflow_id,
        reviewer_owner: MERCURY_ASSURANCE_REVIEWER_OWNER.to_string(),
        support_owner: MERCURY_ASSURANCE_SUPPORT_OWNER.to_string(),
        reviewer_populations,
        qualification_dir: governance_summary.qualification_dir,
        governance_workbench_dir: governance_dir.display().to_string(),
        governance_decision_package_file: governance_summary.governance_decision_package_file,
        assurance_suite_package_file: assurance_suite_package_path.display().to_string(),
        internal_review_package_file,
        auditor_review_package_file,
        counterparty_review_package_file,
        internal_investigation_package_file,
        auditor_investigation_package_file,
        counterparty_investigation_package_file,
    };
    write_json_file(&output.join("assurance-suite-summary.json"), &summary)?;

    Ok(summary)
}
