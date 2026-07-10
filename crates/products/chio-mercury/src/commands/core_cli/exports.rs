use super::super::*;

pub(super) fn export_supervised_live_qualification(
    output: &Path,
) -> Result<
    (
        MercurySupervisedLiveQualificationReport,
        MercurySupervisedLiveReviewerPackage,
    ),
    CliError,
> {
    ensure_empty_directory(output)?;

    let supervised_live_dir = output.join("supervised-live");
    let pilot_dir = output.join("pilot");
    let supervised_live = export_supervised_live_capture(
        &supervised_live_dir,
        MercurySupervisedLiveCapture::sample(MercurySupervisedLiveMode::Live),
    )?;
    let pilot = export_pilot_scenario(&pilot_dir, MercuryPilotScenario::gold_release_control())?;

    let qualification_report = MercurySupervisedLiveQualificationReport {
        workflow_id: supervised_live.workflow_id.clone(),
        decision: MERCURY_SUPERVISED_LIVE_DECISION.to_string(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        supervised_live: supervised_live.clone(),
        pilot: pilot.clone(),
    };
    let qualification_report_file = output.join("qualification-report.json");
    write_json_file(&qualification_report_file, &qualification_report)?;

    let reviewer_package = MercurySupervisedLiveReviewerPackage {
        workflow_id: supervised_live.workflow_id.clone(),
        decision: MERCURY_SUPERVISED_LIVE_DECISION.to_string(),
        qualification_report_file: qualification_report_file.display().to_string(),
        supervised_live_dir: supervised_live_dir.display().to_string(),
        pilot_dir: pilot_dir.display().to_string(),
        supervised_live_proof_package_file: supervised_live.export.proof_package_file.clone(),
        supervised_live_inquiry_package_file: supervised_live.export.inquiry_package_file.clone(),
        rollback_proof_package_file: pilot.rollback.proof_package_file.clone(),
    };
    write_json_file(&output.join("reviewer-package.json"), &reviewer_package)?;

    Ok((qualification_report, reviewer_package))
}

pub(super) fn export_downstream_review(
    output: &Path,
) -> Result<MercuryDownstreamReviewExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let qualification_dir = output.join("qualification");
    let (qualification_report, reviewer_package) =
        export_supervised_live_qualification(&qualification_dir)?;
    let proof_package_path = qualification_dir.join("supervised-live/proof-package.json");
    let proof_package: MercuryProofPackage = read_json_file(&proof_package_path)?;
    proof_package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;

    let reviewer_package_path = qualification_dir.join("reviewer-package.json");
    let qualification_report_path = qualification_dir.join("qualification-report.json");

    let assurance_dir = output.join("assurance");
    let internal_dir = assurance_dir.join("internal-review");
    let external_dir = assurance_dir.join("external-review");
    fs::create_dir_all(&internal_dir)?;
    fs::create_dir_all(&external_dir)?;

    let internal_inquiry = build_inquiry_package(
        proof_package.clone(),
        "internal-review",
        Some("internal-review-default"),
        false,
    )?;
    let internal_inquiry_report = internal_inquiry
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    let internal_inquiry_path = internal_dir.join("inquiry-package.json");
    let internal_inquiry_report_path = internal_dir.join("inquiry-verification.json");
    write_json_file(&internal_inquiry_path, &internal_inquiry)?;
    write_verification_report(&internal_inquiry_report_path, &internal_inquiry_report)?;

    let internal_assurance = build_assurance_package(AssurancePackageArgs {
        workflow_id: &qualification_report.workflow_id,
        audience: MercuryAssuranceAudience::InternalReview,
        disclosure_profile: "internal-review-default",
        proof_package_file: &relative_display(output, &proof_package_path)?,
        inquiry_package_file: &relative_display(output, &internal_inquiry_path)?,
        reviewer_package_file: &relative_display(output, &reviewer_package_path)?,
        qualification_report_file: &relative_display(output, &qualification_report_path)?,
        verifier_equivalent: internal_inquiry_report.verifier_equivalent,
    })?;
    let internal_assurance_path = internal_dir.join("assurance-package.json");
    write_json_file(&internal_assurance_path, &internal_assurance)?;

    let external_inquiry = build_inquiry_package(
        proof_package,
        "external-review",
        Some("external-review-default"),
        false,
    )?;
    let external_inquiry_report = external_inquiry
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    let external_inquiry_path = external_dir.join("inquiry-package.json");
    let external_inquiry_report_path = external_dir.join("inquiry-verification.json");
    write_json_file(&external_inquiry_path, &external_inquiry)?;
    write_verification_report(&external_inquiry_report_path, &external_inquiry_report)?;

    let external_assurance = build_assurance_package(AssurancePackageArgs {
        workflow_id: &qualification_report.workflow_id,
        audience: MercuryAssuranceAudience::ExternalReview,
        disclosure_profile: "external-review-default",
        proof_package_file: &relative_display(output, &proof_package_path)?,
        inquiry_package_file: &relative_display(output, &external_inquiry_path)?,
        reviewer_package_file: &relative_display(output, &reviewer_package_path)?,
        qualification_report_file: &relative_display(output, &qualification_report_path)?,
        verifier_equivalent: external_inquiry_report.verifier_equivalent,
    })?;
    let external_assurance_path = external_dir.join("assurance-package.json");
    write_json_file(&external_assurance_path, &external_assurance)?;

    let consumer_drop_dir = output.join("consumer-drop");
    fs::create_dir_all(&consumer_drop_dir)?;
    let consumer_reviewer_package_path = consumer_drop_dir.join("reviewer-package.json");
    let consumer_qualification_report_path = consumer_drop_dir.join("qualification-report.json");
    let consumer_external_assurance_path =
        consumer_drop_dir.join("external-assurance-package.json");
    let consumer_external_inquiry_path = consumer_drop_dir.join("external-inquiry-package.json");
    let consumer_external_inquiry_verification_path =
        consumer_drop_dir.join("external-inquiry-verification.json");
    copy_file(&reviewer_package_path, &consumer_reviewer_package_path)?;
    copy_file(
        &qualification_report_path,
        &consumer_qualification_report_path,
    )?;
    copy_file(&external_assurance_path, &consumer_external_assurance_path)?;
    copy_file(&external_inquiry_path, &consumer_external_inquiry_path)?;
    copy_file(
        &external_inquiry_report_path,
        &consumer_external_inquiry_verification_path,
    )?;

    let consumer_manifest = MercuryDownstreamConsumerManifest {
        schema: "chio.mercury.consumer_manifest.v1".to_string(),
        workflow_id: qualification_report.workflow_id.clone(),
        consumer_profile: MercuryDownstreamConsumerProfile::CaseManagementReview
            .as_str()
            .to_string(),
        transport: MercuryDownstreamTransport::FileDrop.as_str().to_string(),
        acknowledgement_required: true,
        fail_closed: true,
        reviewer_package_file: "reviewer-package.json".to_string(),
        qualification_report_file: "qualification-report.json".to_string(),
        external_assurance_package_file: "external-assurance-package.json".to_string(),
        external_inquiry_package_file: "external-inquiry-package.json".to_string(),
        external_inquiry_verification_file: "external-inquiry-verification.json".to_string(),
    };
    let consumer_manifest_path = consumer_drop_dir.join("consumer-manifest.json");
    write_json_file(&consumer_manifest_path, &consumer_manifest)?;

    let acknowledgement = MercuryDownstreamDeliveryAcknowledgement {
        schema: "chio.mercury.delivery_acknowledgement.v1".to_string(),
        workflow_id: qualification_report.workflow_id.clone(),
        consumer_profile: MercuryDownstreamConsumerProfile::CaseManagementReview
            .as_str()
            .to_string(),
        destination_label: MERCURY_DOWNSTREAM_DESTINATION_LABEL.to_string(),
        status: "acknowledged".to_string(),
        acknowledged_at: unix_now(),
        acknowledged_by: "mercury-file-drop".to_string(),
        delivered_files: vec![
            "consumer-manifest.json".to_string(),
            "external-assurance-package.json".to_string(),
            "external-inquiry-package.json".to_string(),
            "external-inquiry-verification.json".to_string(),
            "qualification-report.json".to_string(),
            "reviewer-package.json".to_string(),
        ],
        note: "The bounded case-management review package has been staged in the file-drop intake. Any delivery failure must fail closed and no broader consumer path is implied."
            .to_string(),
    };
    let acknowledgement_path = consumer_drop_dir.join("delivery-acknowledgement.json");
    write_json_file(&acknowledgement_path, &acknowledgement)?;

    let downstream_package = MercuryDownstreamReviewPackage {
        schema: MERCURY_DOWNSTREAM_REVIEW_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "downstream-review-case-management-{}-{}",
            qualification_report.workflow_id,
            current_utc_date()
        ),
        workflow_id: qualification_report.workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        consumer_profile: MercuryDownstreamConsumerProfile::CaseManagementReview,
        transport: MercuryDownstreamTransport::FileDrop,
        destination_label: MERCURY_DOWNSTREAM_DESTINATION_LABEL.to_string(),
        destination_owner: MERCURY_DOWNSTREAM_DESTINATION_OWNER.to_string(),
        support_owner: MERCURY_DOWNSTREAM_SUPPORT_OWNER.to_string(),
        acknowledgement_required: true,
        fail_closed: true,
        artifacts: vec![
            MercuryDownstreamArtifact {
                role: MercuryDownstreamArtifactRole::InternalAssurancePackage,
                relative_path: relative_display(output, &internal_assurance_path)?,
                disclosure_profile: "internal-review-default".to_string(),
            },
            MercuryDownstreamArtifact {
                role: MercuryDownstreamArtifactRole::ExternalAssurancePackage,
                relative_path: relative_display(output, &external_assurance_path)?,
                disclosure_profile: "external-review-default".to_string(),
            },
            MercuryDownstreamArtifact {
                role: MercuryDownstreamArtifactRole::ReviewerPackage,
                relative_path: relative_display(output, &reviewer_package_path)?,
                disclosure_profile: "review-package".to_string(),
            },
            MercuryDownstreamArtifact {
                role: MercuryDownstreamArtifactRole::QualificationReport,
                relative_path: relative_display(output, &qualification_report_path)?,
                disclosure_profile: "review-package".to_string(),
            },
            MercuryDownstreamArtifact {
                role: MercuryDownstreamArtifactRole::ExternalInquiryPackage,
                relative_path: relative_display(output, &external_inquiry_path)?,
                disclosure_profile: "external-review-default".to_string(),
            },
            MercuryDownstreamArtifact {
                role: MercuryDownstreamArtifactRole::ExternalInquiryVerification,
                relative_path: relative_display(output, &external_inquiry_report_path)?,
                disclosure_profile: "external-review-default".to_string(),
            },
            MercuryDownstreamArtifact {
                role: MercuryDownstreamArtifactRole::ConsumerManifest,
                relative_path: relative_display(output, &consumer_manifest_path)?,
                disclosure_profile: "case-management-intake".to_string(),
            },
            MercuryDownstreamArtifact {
                role: MercuryDownstreamArtifactRole::DeliveryAcknowledgement,
                relative_path: relative_display(output, &acknowledgement_path)?,
                disclosure_profile: "case-management-intake".to_string(),
            },
        ],
    };
    downstream_package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let downstream_package_path = output.join("downstream-review-package.json");
    write_json_file(&downstream_package_path, &downstream_package)?;

    let summary = MercuryDownstreamReviewExportSummary {
        workflow_id: qualification_report.workflow_id,
        consumer_profile: MercuryDownstreamConsumerProfile::CaseManagementReview
            .as_str()
            .to_string(),
        transport: MercuryDownstreamTransport::FileDrop.as_str().to_string(),
        qualification_dir: qualification_dir.display().to_string(),
        internal_assurance_package_file: internal_assurance_path.display().to_string(),
        external_assurance_package_file: external_assurance_path.display().to_string(),
        downstream_review_package_file: downstream_package_path.display().to_string(),
        consumer_manifest_file: consumer_manifest_path.display().to_string(),
        acknowledgement_file: acknowledgement_path.display().to_string(),
        consumer_drop_dir: consumer_drop_dir.display().to_string(),
    };
    write_json_file(&output.join("downstream-review-summary.json"), &summary)?;

    let _ = reviewer_package;

    Ok(summary)
}

pub(crate) fn export_governance_workbench(
    output: &Path,
) -> Result<MercuryGovernanceWorkbenchExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let qualification_dir = output.join("qualification");
    let (qualification_report, reviewer_package) =
        export_supervised_live_qualification(&qualification_dir)?;
    let proof_package_path = qualification_dir.join("supervised-live/proof-package.json");
    let proof_package: MercuryProofPackage = read_json_file(&proof_package_path)?;
    proof_package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;

    let reviewer_package_path = qualification_dir.join("reviewer-package.json");
    let qualification_report_path = qualification_dir.join("qualification-report.json");
    let decision_package_path = output.join("governance-decision-package.json");

    let review_dir = output.join("governance-reviews");
    let workflow_owner_dir = review_dir.join("workflow-owner");
    let control_team_dir = review_dir.join("control-team");
    fs::create_dir_all(&workflow_owner_dir)?;
    fs::create_dir_all(&control_team_dir)?;

    let workflow_owner_inquiry = build_inquiry_package(
        proof_package.clone(),
        "workflow-owner",
        Some("workflow-owner-default"),
        false,
    )?;
    let workflow_owner_inquiry_report = workflow_owner_inquiry
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    let workflow_owner_inquiry_path = workflow_owner_dir.join("inquiry-package.json");
    let workflow_owner_inquiry_report_path = workflow_owner_dir.join("inquiry-verification.json");
    write_json_file(&workflow_owner_inquiry_path, &workflow_owner_inquiry)?;
    write_verification_report(
        &workflow_owner_inquiry_report_path,
        &workflow_owner_inquiry_report,
    )?;

    let control_team_inquiry = build_inquiry_package(
        proof_package,
        "control-team",
        Some("control-team-default"),
        false,
    )?;
    let control_team_inquiry_report = control_team_inquiry
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    let control_team_inquiry_path = control_team_dir.join("inquiry-package.json");
    let control_team_inquiry_report_path = control_team_dir.join("inquiry-verification.json");
    write_json_file(&control_team_inquiry_path, &control_team_inquiry)?;
    write_verification_report(
        &control_team_inquiry_report_path,
        &control_team_inquiry_report,
    )?;

    let control_state = MercuryGovernanceControlState {
        approval_gate: MercuryGovernanceGateState::Approved,
        release_gate: MercuryGovernanceGateState::Approved,
        rollback_gate: MercuryGovernanceGateState::Ready,
        exception_gate: MercuryGovernanceGateState::Routed,
        escalation_owner: MERCURY_GOVERNANCE_CONTROL_TEAM_OWNER.to_string(),
    };
    let control_state_path = output.join("governance-control-state.json");
    write_json_file(&control_state_path, &control_state)?;

    let workflow_owner_review = build_governance_review_package(GovernanceReviewPackageArgs {
        workflow_id: &qualification_report.workflow_id,
        audience: MercuryGovernanceReviewAudience::WorkflowOwner,
        disclosure_profile: "workflow-owner-default",
        proof_package_file: &relative_display(output, &proof_package_path)?,
        inquiry_package_file: &relative_display(output, &workflow_owner_inquiry_path)?,
        reviewer_package_file: &relative_display(output, &reviewer_package_path)?,
        qualification_report_file: &relative_display(output, &qualification_report_path)?,
        decision_package_file: &relative_display(output, &decision_package_path)?,
        verifier_equivalent: workflow_owner_inquiry_report.verifier_equivalent,
    })?;
    let workflow_owner_review_path = workflow_owner_dir.join("review-package.json");
    write_json_file(&workflow_owner_review_path, &workflow_owner_review)?;

    let control_team_review = build_governance_review_package(GovernanceReviewPackageArgs {
        workflow_id: &qualification_report.workflow_id,
        audience: MercuryGovernanceReviewAudience::ControlTeam,
        disclosure_profile: "control-team-default",
        proof_package_file: &relative_display(output, &proof_package_path)?,
        inquiry_package_file: &relative_display(output, &control_team_inquiry_path)?,
        reviewer_package_file: &relative_display(output, &reviewer_package_path)?,
        qualification_report_file: &relative_display(output, &qualification_report_path)?,
        decision_package_file: &relative_display(output, &decision_package_path)?,
        verifier_equivalent: control_team_inquiry_report.verifier_equivalent,
    })?;
    let control_team_review_path = control_team_dir.join("review-package.json");
    write_json_file(&control_team_review_path, &control_team_review)?;

    let decision_package = MercuryGovernanceDecisionPackage {
        schema: MERCURY_GOVERNANCE_DECISION_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "governance-change-review-release-control-{}-{}",
            qualification_report.workflow_id,
            current_utc_date()
        ),
        workflow_id: qualification_report.workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        workflow_path: MercuryGovernanceWorkflowPath::ChangeReviewReleaseControl,
        change_classes: vec![
            MercuryGovernanceChangeClass::Model,
            MercuryGovernanceChangeClass::Prompt,
            MercuryGovernanceChangeClass::Policy,
            MercuryGovernanceChangeClass::Parameter,
            MercuryGovernanceChangeClass::Release,
        ],
        workflow_owner: MERCURY_GOVERNANCE_WORKFLOW_OWNER.to_string(),
        control_team_owner: MERCURY_GOVERNANCE_CONTROL_TEAM_OWNER.to_string(),
        fail_closed: true,
        control_state: control_state.clone(),
        workflow_owner_review_package_file: relative_display(output, &workflow_owner_review_path)?,
        control_team_review_package_file: relative_display(output, &control_team_review_path)?,
    };
    decision_package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    write_json_file(&decision_package_path, &decision_package)?;

    let summary = MercuryGovernanceWorkbenchExportSummary {
        workflow_id: qualification_report.workflow_id,
        workflow_path: MercuryGovernanceWorkflowPath::ChangeReviewReleaseControl
            .as_str()
            .to_string(),
        workflow_owner: MERCURY_GOVERNANCE_WORKFLOW_OWNER.to_string(),
        control_team_owner: MERCURY_GOVERNANCE_CONTROL_TEAM_OWNER.to_string(),
        qualification_dir: qualification_dir.display().to_string(),
        control_state,
        control_state_file: control_state_path.display().to_string(),
        governance_decision_package_file: decision_package_path.display().to_string(),
        workflow_owner_review_package_file: workflow_owner_review_path.display().to_string(),
        control_team_review_package_file: control_team_review_path.display().to_string(),
    };
    write_json_file(&output.join("governance-workbench-summary.json"), &summary)?;

    let _ = reviewer_package;

    Ok(summary)
}

pub(super) fn export_mercury_run(
    run_dir: &Path,
    input_name: &str,
    input_value: &impl Serialize,
    capability_id: &str,
    steps: &[MercuryPilotStep],
    bundle_manifests: &[MercuryBundleManifest],
    inquiry: Option<PilotInquiryConfig<'_>>,
) -> Result<MercuryExportRunPaths, CliError> {
    fs::create_dir_all(run_dir)?;

    let input_file = run_dir.join(input_name);
    let receipt_db = run_dir.join("receipts.sqlite3");
    let evidence_dir = run_dir.join("evidence");
    let bundle_manifest_dir = run_dir.join("bundle-manifests");
    let proof_package_file = run_dir.join("proof-package.json");
    let proof_verification_file = run_dir.join("proof-verification.json");
    let inquiry_package_file = run_dir.join("inquiry-package.json");
    let inquiry_verification_file = run_dir.join("inquiry-verification.json");

    write_json_file(&input_file, input_value)?;
    let bundle_manifest_paths = write_bundle_manifests(&bundle_manifest_dir, bundle_manifests)?;
    populate_mercury_receipt_store(&receipt_db, capability_id, steps)?;
    evidence_export::cmd_evidence_export(
        &evidence_dir,
        None,
        None,
        None,
        None,
        None,
        true,
        None,
        None,
        true,
        Some(&receipt_db),
        None,
        None,
    )?;

    let proof_package = build_proof_package(&evidence_dir, &bundle_manifest_paths)?;
    let proof_report = proof_package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    write_json_file(&proof_package_file, &proof_package)?;
    write_verification_report(&proof_verification_file, &proof_report)?;

    let (inquiry_package_file, inquiry_verification_file) = if let Some(config) = inquiry {
        let inquiry_package = build_inquiry_package(
            proof_package,
            config.audience,
            config.redaction_profile,
            config.verifier_equivalent,
        )?;
        let inquiry_report = inquiry_package
            .verify(unix_now())
            .map_err(|error| CliError::Other(error.to_string()))?;
        write_json_file(&inquiry_package_file, &inquiry_package)?;
        write_verification_report(&inquiry_verification_file, &inquiry_report)?;
        (
            Some(inquiry_package_file.display().to_string()),
            Some(inquiry_verification_file.display().to_string()),
        )
    } else {
        (None, None)
    };

    Ok(MercuryExportRunPaths {
        input_file: input_file.display().to_string(),
        receipt_db: receipt_db.display().to_string(),
        evidence_dir: evidence_dir.display().to_string(),
        bundle_manifest_files: bundle_manifest_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        proof_package_file: proof_package_file.display().to_string(),
        proof_verification_file: proof_verification_file.display().to_string(),
        inquiry_package_file,
        inquiry_verification_file,
    })
}

pub(super) fn export_pilot_scenario(
    output: &Path,
    scenario: MercuryPilotScenario,
) -> Result<MercuryPilotExportSummary, CliError> {
    scenario
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let scenario_file = output.join("scenario.json");
    write_json_file(&scenario_file, &scenario)?;

    let primary = MercuryPilotRunPaths::from_export(export_mercury_run(
        &output.join("primary"),
        "events.json",
        &scenario.primary_path,
        "cap-mercury-pilot-primary",
        &scenario.primary_path,
        std::slice::from_ref(&scenario.primary_bundle_manifest),
        Some(PilotInquiryConfig {
            audience: "design-partner",
            redaction_profile: Some("design-partner-default"),
            verifier_equivalent: false,
        }),
    )?)?;
    let rollback = MercuryPilotRunPaths::from_export(export_mercury_run(
        &output.join("rollback"),
        "events.json",
        &scenario.rollback_variant,
        "cap-mercury-pilot-rollback",
        &scenario.rollback_variant,
        std::slice::from_ref(&scenario.rollback_bundle_manifest),
        None,
    )?)?;

    let summary = MercuryPilotExportSummary {
        scenario_id: scenario.scenario_id,
        workflow_id: scenario.workflow_id,
        scenario_file: scenario_file.display().to_string(),
        primary_receipt_count: scenario.primary_path.len(),
        rollback_receipt_count: scenario.rollback_variant.len(),
        primary,
        rollback,
    };
    write_json_file(&output.join("pilot-summary.json"), &summary)?;
    Ok(summary)
}

pub(super) fn export_supervised_live_capture(
    output: &Path,
    capture: MercurySupervisedLiveCapture,
) -> Result<MercurySupervisedLiveExportSummary, CliError> {
    capture
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    capture
        .ensure_export_ready()
        .map_err(|error| CliError::Other(error.to_string()))?;

    let inquiry = capture.inquiry.as_ref().map(|config| PilotInquiryConfig {
        audience: config.audience.as_str(),
        redaction_profile: config.redaction_profile.as_deref(),
        verifier_equivalent: config.verifier_equivalent,
    });
    let export = export_mercury_run(
        output,
        "capture.json",
        &capture,
        &format!("cap-{}", capture.capture_id),
        &capture.steps,
        &capture.bundle_manifests,
        inquiry,
    )?;

    let summary = MercurySupervisedLiveExportSummary {
        capture_id: capture.capture_id,
        workflow_id: capture.workflow_id,
        mode: capture.mode.as_str().to_string(),
        receipt_count: capture.steps.len(),
        control_state: capture.control_state,
        export,
    };
    write_json_file(&output.join("supervised-live-summary.json"), &summary)?;
    Ok(summary)
}
