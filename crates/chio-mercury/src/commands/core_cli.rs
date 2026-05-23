fn export_supervised_live_qualification(
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
    let docs = reviewer_doc_refs();

    let qualification_report = MercurySupervisedLiveQualificationReport {
        workflow_id: supervised_live.workflow_id.clone(),
        decision: MERCURY_SUPERVISED_LIVE_DECISION.to_string(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        supervised_live: supervised_live.clone(),
        pilot: pilot.clone(),
        docs: docs.clone(),
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
        docs,
    };
    write_json_file(&output.join("reviewer-package.json"), &reviewer_package)?;

    Ok((qualification_report, reviewer_package))
}

fn export_downstream_review(
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

fn export_governance_workbench(
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

fn export_mercury_run(
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

fn export_pilot_scenario(
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

fn export_supervised_live_capture(
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

pub fn cmd_mercury_proof_export(
    input: &Path,
    output: &Path,
    bundle_manifest_paths: &[PathBuf],
    json_output: bool,
) -> Result<(), CliError> {
    let package = build_proof_package(input, bundle_manifest_paths)?;
    package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    write_json_file(output, &package)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&package)?);
    } else {
        println!("mercury proof package exported");
        println!("output:              {}", output.display());
        println!("package_id:          {}", package.package_id);
        println!("workflow_id:         {}", package.workflow_id);
        println!("receipt_count:       {}", package.receipt_records.len());
        println!("bundle_manifests:    {}", package.bundle_manifests.len());
    }

    Ok(())
}

pub fn cmd_mercury_inquiry_export(
    input: &Path,
    output: &Path,
    audience: &str,
    redaction_profile: Option<&str>,
    verifier_equivalent: bool,
    json_output: bool,
) -> Result<(), CliError> {
    let proof_package: MercuryProofPackage = read_json_file(input)?;
    proof_package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package = build_inquiry_package(
        proof_package,
        audience,
        redaction_profile,
        verifier_equivalent,
    )?;
    package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    write_json_file(output, &package)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&package)?);
    } else {
        println!("mercury inquiry package exported");
        println!("output:              {}", output.display());
        println!("inquiry_id:          {}", package.inquiry_id);
        println!("workflow_id:         {}", package.proof_package.workflow_id);
        println!("audience:            {}", package.audience);
        println!("verifier_equivalent: {}", package.verifier_equivalent);
    }

    Ok(())
}

pub fn cmd_mercury_verify(input: &Path, json_output: bool, explain: bool) -> Result<(), CliError> {
    let value: serde_json::Value = read_json_file(input)?;
    let schema = value
        .get("schema")
        .and_then(|schema| schema.as_str())
        .ok_or_else(|| CliError::Other("mercury package is missing schema".to_string()))?;
    let report = match schema {
        MERCURY_PROOF_PACKAGE_SCHEMA => {
            let package: MercuryProofPackage = serde_json::from_value(value)?;
            package
                .verify(unix_now())
                .map_err(|error| CliError::Other(error.to_string()))?
        }
        MERCURY_INQUIRY_PACKAGE_SCHEMA => {
            let package: MercuryInquiryPackage = serde_json::from_value(value)?;
            package
                .verify(unix_now())
                .map_err(|error| CliError::Other(error.to_string()))?
        }
        _ => {
            return Err(CliError::Other(format!(
                "unsupported mercury package schema: {schema}"
            )))
        }
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        let package_kind = match report.package_kind {
            MercuryPackageKind::Proof => "proof",
            MercuryPackageKind::Inquiry => "inquiry",
        };
        println!("mercury {package_kind} package verified");
        println!("package_id:          {}", report.package_id);
        println!("workflow_id:         {}", report.workflow_id);
        println!("receipt_count:       {}", report.receipt_count);
        println!("verifier_equivalent: {}", report.verifier_equivalent);
        if explain {
            println!("steps:");
            for step in &report.steps {
                println!("  - {}: {}", step.name, step.detail);
            }
        }
    }

    Ok(())
}

pub fn cmd_mercury_pilot_export(output: &Path, json_output: bool) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let summary = export_pilot_scenario(output, MercuryPilotScenario::gold_release_control())?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury pilot corpus exported");
        println!("output:              {}", output.display());
        println!("scenario_id:         {}", summary.scenario_id);
        println!("workflow_id:         {}", summary.workflow_id);
        println!("primary_receipts:    {}", summary.primary_receipt_count);
        println!("rollback_receipts:   {}", summary.rollback_receipt_count);
        println!(
            "primary_proof:       {}",
            summary.primary.proof_package_file
        );
        if let Some(inquiry_package_file) = summary.primary.inquiry_package_file.as_deref() {
            println!("primary_inquiry:     {}", inquiry_package_file);
        }
        println!(
            "rollback_proof:      {}",
            summary.rollback.proof_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_supervised_live_export(
    input: &Path,
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let capture: MercurySupervisedLiveCapture = read_json_file(input)?;
    let summary = export_supervised_live_capture(output, capture)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury supervised-live capture exported");
        println!("output:              {}", output.display());
        println!("capture_id:          {}", summary.capture_id);
        println!("workflow_id:         {}", summary.workflow_id);
        println!("mode:                {}", summary.mode);
        println!("receipt_count:       {}", summary.receipt_count);
        println!(
            "coverage_state:      {}",
            summary.control_state.coverage_state.as_str()
        );
        println!(
            "release_gate:        {}",
            summary.control_state.release_gate.state.as_str()
        );
        println!(
            "rollback_gate:       {}",
            summary.control_state.rollback_gate.state.as_str()
        );
        println!("proof_package:       {}", summary.export.proof_package_file);
        if let Some(inquiry_package_file) = summary.export.inquiry_package_file.as_deref() {
            println!("inquiry_package:     {}", inquiry_package_file);
        }
    }

    Ok(())
}

pub fn cmd_mercury_supervised_live_qualify(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let (_, reviewer_package) = export_supervised_live_qualification(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&reviewer_package)?);
    } else {
        println!("mercury supervised-live qualification package exported");
        println!("output:                     {}", output.display());
        println!(
            "workflow_id:                {}",
            reviewer_package.workflow_id
        );
        println!("decision:                   {}", reviewer_package.decision);
        println!(
            "qualification_report:       {}",
            reviewer_package.qualification_report_file
        );
        println!(
            "reviewer_package:           {}",
            output.join("reviewer-package.json").display()
        );
        println!(
            "supervised_live_proof:      {}",
            reviewer_package.supervised_live_proof_package_file
        );
        println!(
            "rollback_proof:             {}",
            reviewer_package.rollback_proof_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_downstream_review_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_downstream_review(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury downstream-review package exported");
        println!("output:                     {}", output.display());
        println!("workflow_id:                {}", summary.workflow_id);
        println!("consumer_profile:           {}", summary.consumer_profile);
        println!("transport:                  {}", summary.transport);
        println!(
            "internal_assurance:         {}",
            summary.internal_assurance_package_file
        );
        println!(
            "external_assurance:         {}",
            summary.external_assurance_package_file
        );
        println!(
            "downstream_review_package:  {}",
            summary.downstream_review_package_file
        );
        println!(
            "consumer_manifest:          {}",
            summary.consumer_manifest_file
        );
        println!(
            "acknowledgement:            {}",
            summary.acknowledgement_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_downstream_review_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let downstream_review_dir = output.join("downstream-review");
    let summary = export_downstream_review(&downstream_review_dir)?;
    let docs = downstream_review_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryDownstreamReviewDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_DOWNSTREAM_DECISION.to_string(),
        selected_consumer_profile: summary.consumer_profile.clone(),
        approved_scope:
            "Proceed with the bounded case-management review consumer path only."
                .to_string(),
        deferred_scope: vec![
            "additional archive connectors".to_string(),
            "surveillance connectors".to_string(),
            "governance workbench breadth".to_string(),
            "OMS/EMS or FIX coupling".to_string(),
            "OEM packaging and trust-network work".to_string(),
        ],
        rationale: "The downstream review package now strengthens buyer review flows without widening MERCURY into multi-consumer sprawl or deep runtime coupling."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryDownstreamReviewValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_DOWNSTREAM_DECISION.to_string(),
        consumer_profile: summary.consumer_profile.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        downstream_review: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury downstream-review validation package exported");
        println!("output:                     {}", output.display());
        println!("workflow_id:                {}", report.workflow_id);
        println!("decision:                   {}", report.decision);
        println!("consumer_profile:           {}", report.consumer_profile);
        println!(
            "validation_report:          {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:            {}",
            decision_record_file.display()
        );
        println!(
            "downstream_review_package:  {}",
            report.downstream_review.downstream_review_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_governance_workbench_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_governance_workbench(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury governance-workbench package exported");
        println!("output:                     {}", output.display());
        println!("workflow_id:                {}", summary.workflow_id);
        println!("workflow_path:              {}", summary.workflow_path);
        println!("workflow_owner:             {}", summary.workflow_owner);
        println!("control_team_owner:         {}", summary.control_team_owner);
        println!(
            "governance_decision:        {}",
            summary.governance_decision_package_file
        );
        println!(
            "workflow_owner_review:      {}",
            summary.workflow_owner_review_package_file
        );
        println!(
            "control_team_review:        {}",
            summary.control_team_review_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_governance_workbench_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let governance_dir = output.join("governance-workbench");
    let summary = export_governance_workbench(&governance_dir)?;
    let docs = governance_workbench_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryGovernanceWorkbenchDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_GOVERNANCE_DECISION.to_string(),
        selected_workflow_path: summary.workflow_path.clone(),
        approved_scope:
            "Proceed with the bounded governance workbench change-review path only."
                .to_string(),
        deferred_scope: vec![
            "additional governance workflow breadth".to_string(),
            "additional downstream consumer connectors".to_string(),
            "OMS/EMS or FIX coupling".to_string(),
            "OEM packaging and trust-network work".to_string(),
            "generic workflow orchestration".to_string(),
        ],
        rationale: "The governance workbench package now deepens buyer review and control workflows without widening MERCURY into generic orchestration, connector sprawl, or deep runtime coupling."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryGovernanceWorkbenchValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_GOVERNANCE_DECISION.to_string(),
        workflow_path: summary.workflow_path.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        governance_workbench: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury governance-workbench validation package exported");
        println!("output:                     {}", output.display());
        println!("workflow_id:                {}", report.workflow_id);
        println!("decision:                   {}", report.decision);
        println!("workflow_path:              {}", report.workflow_path);
        println!(
            "validation_report:          {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:            {}",
            decision_record_file.display()
        );
        println!(
            "governance_decision:        {}",
            report.governance_workbench.governance_decision_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_assurance_suite_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_assurance_suite(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury assurance-suite package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", summary.workflow_id);
        println!("reviewer_owner:                {}", summary.reviewer_owner);
        println!("support_owner:                 {}", summary.support_owner);
        println!(
            "assurance_suite_package:       {}",
            summary.assurance_suite_package_file
        );
        println!(
            "internal_review_package:       {}",
            summary.internal_review_package_file
        );
        println!(
            "auditor_review_package:        {}",
            summary.auditor_review_package_file
        );
        println!(
            "counterparty_review_package:   {}",
            summary.counterparty_review_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_assurance_suite_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let assurance_dir = output.join("assurance-suite");
    let summary = export_assurance_suite(&assurance_dir)?;
    let docs = assurance_suite_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryAssuranceSuiteDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_ASSURANCE_DECISION.to_string(),
        selected_reviewer_populations: summary.reviewer_populations.clone(),
        approved_scope:
            "Proceed with the bounded assurance-suite reviewer populations only."
                .to_string(),
        deferred_scope: vec![
            "additional reviewer populations".to_string(),
            "generic review portal or case-management product breadth".to_string(),
            "additional downstream or governance workflow lanes".to_string(),
            "OMS/EMS or FIX coupling".to_string(),
            "OEM packaging and trust-network work".to_string(),
        ],
        rationale: "The assurance suite now packages internal, auditor, and counterparty review over the same Mercury proof chain without widening Mercury into a generic portal, connector sprawl, or embedded platform."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryAssuranceSuiteValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_ASSURANCE_DECISION.to_string(),
        reviewer_owner: summary.reviewer_owner.clone(),
        support_owner: summary.support_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        assurance_suite: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury assurance-suite validation package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", report.workflow_id);
        println!("decision:                      {}", report.decision);
        println!("reviewer_owner:                {}", report.reviewer_owner);
        println!("support_owner:                 {}", report.support_owner);
        println!(
            "validation_report:             {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:               {}",
            decision_record_file.display()
        );
        println!(
            "assurance_suite_package:       {}",
            report.assurance_suite.assurance_suite_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_embedded_oem_export(output: &Path, json_output: bool) -> Result<(), CliError> {
    let summary = export_embedded_oem(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury embedded-oem package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", summary.workflow_id);
        println!("partner_surface:               {}", summary.partner_surface);
        println!("sdk_surface:                   {}", summary.sdk_surface);
        println!(
            "reviewer_population:           {}",
            summary.reviewer_population
        );
        println!("partner_owner:                 {}", summary.partner_owner);
        println!("support_owner:                 {}", summary.support_owner);
        println!(
            "embedded_oem_package:          {}",
            summary.embedded_oem_package_file
        );
        println!(
            "partner_sdk_manifest:          {}",
            summary.partner_sdk_manifest_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_embedded_oem_validate(output: &Path, json_output: bool) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let embedded_oem_dir = output.join("embedded-oem");
    let summary = export_embedded_oem(&embedded_oem_dir)?;
    let docs = embedded_oem_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryEmbeddedOemDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_EMBEDDED_OEM_DECISION.to_string(),
        selected_partner_surface: summary.partner_surface.clone(),
        selected_sdk_surface: summary.sdk_surface.clone(),
        selected_reviewer_population: summary.reviewer_population.clone(),
        approved_scope:
            "Proceed with the bounded reviewer-workbench embedded OEM path only."
                .to_string(),
        deferred_scope: vec![
            "additional partner surfaces".to_string(),
            "multi-partner OEM breadth".to_string(),
            "generic SDK platform or multi-language client breadth".to_string(),
            "trust-network services".to_string(),
            "Chio-Wall and companion-product work".to_string(),
        ],
        rationale: "The embedded OEM bundle now packages one counterparty-review Mercury surface for one partner workbench without widening Mercury into a generic SDK platform, multi-partner OEM program, or separate trust service."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryEmbeddedOemValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_EMBEDDED_OEM_DECISION.to_string(),
        partner_surface: summary.partner_surface.clone(),
        sdk_surface: summary.sdk_surface.clone(),
        reviewer_population: summary.reviewer_population.clone(),
        partner_owner: summary.partner_owner.clone(),
        support_owner: summary.support_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        embedded_oem: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury embedded-oem validation package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", report.workflow_id);
        println!("decision:                      {}", report.decision);
        println!("partner_surface:               {}", report.partner_surface);
        println!("sdk_surface:                   {}", report.sdk_surface);
        println!(
            "reviewer_population:           {}",
            report.reviewer_population
        );
        println!(
            "validation_report:             {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:               {}",
            decision_record_file.display()
        );
        println!(
            "embedded_oem_package:          {}",
            report.embedded_oem.embedded_oem_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_trust_network_export(output: &Path, json_output: bool) -> Result<(), CliError> {
    let summary = export_trust_network(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury trust-network package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", summary.workflow_id);
        println!(
            "sponsor_boundary:              {}",
            summary.sponsor_boundary
        );
        println!("trust_anchor:                  {}", summary.trust_anchor);
        println!("interop_surface:               {}", summary.interop_surface);
        println!(
            "reviewer_population:           {}",
            summary.reviewer_population
        );
        println!(
            "trust_network_package:         {}",
            summary.trust_network_package_file
        );
        println!(
            "interop_manifest:              {}",
            summary.interop_manifest_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_trust_network_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let trust_network_dir = output.join("trust-network");
    let summary = export_trust_network(&trust_network_dir)?;
    let docs = trust_network_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryTrustNetworkDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_TRUST_NETWORK_DECISION.to_string(),
        selected_sponsor_boundary: summary.sponsor_boundary.clone(),
        selected_trust_anchor: summary.trust_anchor.clone(),
        selected_interop_surface: summary.interop_surface.clone(),
        selected_reviewer_population: summary.reviewer_population.clone(),
        approved_scope:
            "Proceed with the bounded counterparty-review trust-network path only."
                .to_string(),
        deferred_scope: vec![
            "additional trust-network sponsor boundaries".to_string(),
            "multi-network witness or trust-broker services".to_string(),
            "generic ecosystem interoperability infrastructure".to_string(),
            "Chio-Wall companion-product work".to_string(),
            "multi-product platform hardening".to_string(),
        ],
        rationale: "The trust-network lane now shares one bounded counterparty-review proof and inquiry bundle over one checkpoint-backed witness chain without widening Mercury into a generic trust broker, ecosystem network, or companion-product platform."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryTrustNetworkValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_TRUST_NETWORK_DECISION.to_string(),
        sponsor_boundary: summary.sponsor_boundary.clone(),
        trust_anchor: summary.trust_anchor.clone(),
        interop_surface: summary.interop_surface.clone(),
        reviewer_population: summary.reviewer_population.clone(),
        sponsor_owner: summary.sponsor_owner.clone(),
        support_owner: summary.support_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        trust_network: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury trust-network validation package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", report.workflow_id);
        println!("decision:                      {}", report.decision);
        println!("sponsor_boundary:              {}", report.sponsor_boundary);
        println!("trust_anchor:                  {}", report.trust_anchor);
        println!("interop_surface:               {}", report.interop_surface);
        println!(
            "reviewer_population:           {}",
            report.reviewer_population
        );
        println!(
            "validation_report:             {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:               {}",
            decision_record_file.display()
        );
        println!(
            "trust_network_package:         {}",
            report.trust_network.trust_network_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_release_readiness_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_release_readiness(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury release-readiness package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", summary.workflow_id);
        println!(
            "delivery_surface:              {}",
            summary.delivery_surface
        );
        println!(
            "audiences:                     {}",
            summary.audiences.join(", ")
        );
        println!("release_owner:                 {}", summary.release_owner);
        println!("partner_owner:                 {}", summary.partner_owner);
        println!("support_owner:                 {}", summary.support_owner);
        println!(
            "release_readiness_package:     {}",
            summary.release_readiness_package_file
        );
        println!(
            "partner_delivery_manifest:     {}",
            summary.partner_delivery_manifest_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_release_readiness_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let release_readiness_dir = output.join("release-readiness");
    let summary = export_release_readiness(&release_readiness_dir)?;
    let docs = release_readiness_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryReleaseReadinessDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_RELEASE_READINESS_DECISION.to_string(),
        selected_delivery_surface: summary.delivery_surface.clone(),
        selected_audiences: summary.audiences.clone(),
        approved_scope: "Launch one bounded Mercury release-readiness lane only.".to_string(),
        deferred_scope: vec![
            "additional partner-delivery surfaces".to_string(),
            "generic Chio release console or merged shell".to_string(),
            "new Mercury product-line claims".to_string(),
            "additional trust-network sponsor breadth".to_string(),
            "Chio-Wall or cross-product packaging unification".to_string(),
        ],
        rationale: "The release-readiness lane now packages one Mercury reviewer, partner, and operator path over the validated proof, inquiry, assurance, and trust-network stack without widening Chio or creating a new product line."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryReleaseReadinessValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_RELEASE_READINESS_DECISION.to_string(),
        audiences: summary.audiences.clone(),
        delivery_surface: summary.delivery_surface.clone(),
        release_owner: summary.release_owner.clone(),
        partner_owner: summary.partner_owner.clone(),
        support_owner: summary.support_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        release_readiness: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury release-readiness validation package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", report.workflow_id);
        println!("decision:                      {}", report.decision);
        println!("delivery_surface:              {}", report.delivery_surface);
        println!(
            "audiences:                     {}",
            report.audiences.join(", ")
        );
        println!("release_owner:                 {}", report.release_owner);
        println!("partner_owner:                 {}", report.partner_owner);
        println!("support_owner:                 {}", report.support_owner);
        println!(
            "validation_report:             {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:               {}",
            decision_record_file.display()
        );
        println!(
            "release_readiness_package:     {}",
            report.release_readiness.release_readiness_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_controlled_adoption_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_controlled_adoption(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury controlled-adoption package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", summary.workflow_id);
        println!("cohort:                        {}", summary.cohort);
        println!(
            "adoption_surface:              {}",
            summary.adoption_surface
        );
        println!(
            "customer_success_owner:        {}",
            summary.customer_success_owner
        );
        println!("reference_owner:               {}", summary.reference_owner);
        println!("support_owner:                 {}", summary.support_owner);
        println!(
            "controlled_adoption_package:   {}",
            summary.controlled_adoption_package_file
        );
        println!(
            "renewal_evidence_manifest:     {}",
            summary.renewal_evidence_manifest_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_controlled_adoption_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let controlled_adoption_dir = output.join("controlled-adoption");
    let summary = export_controlled_adoption(&controlled_adoption_dir)?;
    let docs = controlled_adoption_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryControlledAdoptionDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_CONTROLLED_ADOPTION_DECISION.to_string(),
        selected_cohort: summary.cohort.clone(),
        selected_adoption_surface: summary.adoption_surface.clone(),
        approved_scope: "Scale one bounded Mercury controlled-adoption lane only.".to_string(),
        deferred_scope: vec![
            "additional adoption cohorts".to_string(),
            "broader Mercury product lines or delivery surfaces".to_string(),
            "generic Chio renewal tooling or release consoles".to_string(),
            "merged Mercury and Chio-Wall packaging".to_string(),
            "new cross-product runtime coupling".to_string(),
        ],
        rationale: "The controlled-adoption lane now packages one design-partner renewal and reference path over the validated Mercury release-readiness stack without widening Mercury into a new product surface or polluting Chio generic crates."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryControlledAdoptionValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_CONTROLLED_ADOPTION_DECISION.to_string(),
        cohort: summary.cohort.clone(),
        adoption_surface: summary.adoption_surface.clone(),
        customer_success_owner: summary.customer_success_owner.clone(),
        reference_owner: summary.reference_owner.clone(),
        support_owner: summary.support_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        controlled_adoption: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury controlled-adoption validation package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", report.workflow_id);
        println!("decision:                      {}", report.decision);
        println!("cohort:                        {}", report.cohort);
        println!("adoption_surface:              {}", report.adoption_surface);
        println!(
            "customer_success_owner:        {}",
            report.customer_success_owner
        );
        println!("reference_owner:               {}", report.reference_owner);
        println!("support_owner:                 {}", report.support_owner);
        println!(
            "validation_report:             {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:               {}",
            decision_record_file.display()
        );
        println!(
            "controlled_adoption_package:   {}",
            report.controlled_adoption.controlled_adoption_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_reference_distribution_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_reference_distribution(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury reference-distribution package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", summary.workflow_id);
        println!(
            "expansion_motion:              {}",
            summary.expansion_motion
        );
        println!(
            "distribution_surface:          {}",
            summary.distribution_surface
        );
        println!("reference_owner:               {}", summary.reference_owner);
        println!(
            "buyer_approval_owner:          {}",
            summary.buyer_approval_owner
        );
        println!("sales_owner:                   {}", summary.sales_owner);
        println!(
            "reference_distribution_package: {}",
            summary.reference_distribution_package_file
        );
        println!(
            "buyer_reference_approval:      {}",
            summary.buyer_reference_approval_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_reference_distribution_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let reference_distribution_dir = output.join("reference-distribution");
    let summary = export_reference_distribution(&reference_distribution_dir)?;
    let docs = reference_distribution_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryReferenceDistributionDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_REFERENCE_DISTRIBUTION_DECISION.to_string(),
        selected_expansion_motion: summary.expansion_motion.clone(),
        selected_distribution_surface: summary.distribution_surface.clone(),
        approved_scope:
            "Proceed with one bounded Mercury reference-distribution lane only.".to_string(),
        deferred_scope: vec![
            "additional landed-account motions".to_string(),
            "generic sales tooling, CRM workflows, or commercial consoles".to_string(),
            "merged Mercury and Chio-Wall commercial packaging".to_string(),
            "Chio-side commercial control surfaces".to_string(),
            "broader product-family or universal rollout claims".to_string(),
        ],
        rationale: "The reference-distribution lane now packages one approved landed-account expansion motion over the validated controlled-adoption stack without widening Mercury into a generic sales platform or polluting Chio's generic substrate."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryReferenceDistributionValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_REFERENCE_DISTRIBUTION_DECISION.to_string(),
        expansion_motion: summary.expansion_motion.clone(),
        distribution_surface: summary.distribution_surface.clone(),
        reference_owner: summary.reference_owner.clone(),
        buyer_approval_owner: summary.buyer_approval_owner.clone(),
        sales_owner: summary.sales_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        reference_distribution: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury reference-distribution validation package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", report.workflow_id);
        println!("decision:                      {}", report.decision);
        println!("expansion_motion:              {}", report.expansion_motion);
        println!(
            "distribution_surface:          {}",
            report.distribution_surface
        );
        println!("reference_owner:               {}", report.reference_owner);
        println!(
            "buyer_approval_owner:          {}",
            report.buyer_approval_owner
        );
        println!("sales_owner:                   {}", report.sales_owner);
        println!(
            "validation_report:             {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:               {}",
            decision_record_file.display()
        );
        println!(
            "reference_distribution_package: {}",
            report
                .reference_distribution
                .reference_distribution_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_broader_distribution_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_broader_distribution(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury broader-distribution package exported");
        println!("output:                         {}", output.display());
        println!("workflow_id:                    {}", summary.workflow_id);
        println!(
            "distribution_motion:            {}",
            summary.distribution_motion
        );
        println!(
            "distribution_surface:           {}",
            summary.distribution_surface
        );
        println!(
            "qualification_owner:            {}",
            summary.qualification_owner
        );
        println!("approval_owner:                 {}", summary.approval_owner);
        println!(
            "distribution_owner:             {}",
            summary.distribution_owner
        );
        println!(
            "broader_distribution_package:   {}",
            summary.broader_distribution_package_file
        );
        println!(
            "selective_account_approval:     {}",
            summary.selective_account_approval_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_broader_distribution_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let broader_distribution_dir = output.join("broader-distribution");
    let summary = export_broader_distribution(&broader_distribution_dir)?;
    let docs = broader_distribution_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryBroaderDistributionDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_BROADER_DISTRIBUTION_DECISION.to_string(),
        selected_distribution_motion: summary.distribution_motion.clone(),
        selected_distribution_surface: summary.distribution_surface.clone(),
        approved_scope:
            "Proceed with one bounded Mercury broader-distribution lane only.".to_string(),
        deferred_scope: vec![
            "additional broader-distribution motions or surfaces".to_string(),
            "generic sales tooling, CRM workflows, or commercial consoles".to_string(),
            "multi-segment channel programs or partner marketplaces".to_string(),
            "merged Mercury and Chio-Wall commercial packaging".to_string(),
            "Chio-side commercial control surfaces".to_string(),
        ],
        rationale: "The broader-distribution lane now packages one governed selective-account qualification motion over the validated reference-distribution stack without widening Mercury into a generic commercial platform or polluting Chio's generic substrate."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("broader-distribution-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryBroaderDistributionValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_BROADER_DISTRIBUTION_DECISION.to_string(),
        distribution_motion: summary.distribution_motion.clone(),
        distribution_surface: summary.distribution_surface.clone(),
        qualification_owner: summary.qualification_owner.clone(),
        approval_owner: summary.approval_owner.clone(),
        distribution_owner: summary.distribution_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        broader_distribution: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury broader-distribution validation package exported");
        println!("output:                         {}", output.display());
        println!("workflow_id:                    {}", report.workflow_id);
        println!("decision:                       {}", report.decision);
        println!(
            "distribution_motion:            {}",
            report.distribution_motion
        );
        println!(
            "distribution_surface:           {}",
            report.distribution_surface
        );
        println!(
            "qualification_owner:            {}",
            report.qualification_owner
        );
        println!("approval_owner:                 {}", report.approval_owner);
        println!(
            "distribution_owner:             {}",
            report.distribution_owner
        );
        println!(
            "validation_report:              {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:                {}",
            decision_record_file.display()
        );
        println!(
            "broader_distribution_package:   {}",
            report
                .broader_distribution
                .broader_distribution_package_file
        );
    }

    Ok(())
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySelectiveAccountActivationDocRefs {
    selective_account_activation_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySelectiveAccountActivationScopeFreeze {
    schema: String,
    workflow_id: String,
    activation_motion: String,
    delivery_surface: String,
    target_account_label: String,
    entry_gates: Vec<String>,
    non_goals: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySelectiveAccountActivationManifest {
    schema: String,
    workflow_id: String,
    activation_motion: String,
    delivery_surface: String,
    broader_distribution_package_file: String,
    target_account_freeze_file: String,
    broader_distribution_manifest_file: String,
    claim_governance_rules_file: String,
    selective_account_approval_file: String,
    distribution_handoff_brief_file: String,
    reference_distribution_package_file: String,
    controlled_adoption_package_file: String,
    release_readiness_package_file: String,
    trust_network_package_file: String,
    assurance_suite_package_file: String,
    proof_package_file: String,
    inquiry_package_file: String,
    inquiry_verification_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySelectiveAccountActivationClaimContainmentRules {
    schema: String,
    workflow_id: String,
    activation_owner: String,
    approval_owner: String,
    fail_closed: bool,
    approved_claims: Vec<String>,
    prohibited_claims: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySelectiveAccountActivationApprovalRefresh {
    schema: String,
    workflow_id: String,
    approval_owner: String,
    status: String,
    refreshed_at: u64,
    refreshed_by: String,
    approved_claims: Vec<String>,
    required_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySelectiveAccountActivationCustomerHandoffBrief {
    schema: String,
    workflow_id: String,
    delivery_owner: String,
    activation_owner: String,
    approval_owner: String,
    activation_motion: String,
    delivery_surface: String,
    approved_scope: String,
    entry_criteria: Vec<String>,
    escalation_triggers: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySelectiveAccountActivationExportSummary {
    workflow_id: String,
    activation_motion: String,
    delivery_surface: String,
    activation_owner: String,
    approval_owner: String,
    delivery_owner: String,
    broader_distribution_dir: String,
    selective_account_activation_profile_file: String,
    selective_account_activation_package_file: String,
    activation_scope_freeze_file: String,
    selective_account_activation_manifest_file: String,
    claim_containment_rules_file: String,
    activation_approval_refresh_file: String,
    customer_handoff_brief_file: String,
    activation_evidence_dir: String,
    broader_distribution_package_file: String,
    target_account_freeze_file: String,
    broader_distribution_manifest_file: String,
    claim_governance_rules_file: String,
    selective_account_approval_file: String,
    distribution_handoff_brief_file: String,
    reference_distribution_package_file: String,
    controlled_adoption_package_file: String,
    release_readiness_package_file: String,
    trust_network_package_file: String,
    assurance_suite_package_file: String,
    proof_package_file: String,
    inquiry_package_file: String,
    inquiry_verification_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySelectiveAccountActivationDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_activation_motion: String,
    selected_delivery_surface: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySelectiveAccountActivationValidationReport {
    workflow_id: String,
    decision: String,
    activation_motion: String,
    delivery_surface: String,
    activation_owner: String,
    approval_owner: String,
    delivery_owner: String,
    same_workflow_boundary: String,
    selective_account_activation: MercurySelectiveAccountActivationExportSummary,
    decision_record_file: String,
    docs: MercurySelectiveAccountActivationDocRefs,
}

fn selective_account_activation_doc_refs() -> MercurySelectiveAccountActivationDocRefs {
    MercurySelectiveAccountActivationDocRefs {
        selective_account_activation_file: "docs/mercury/SELECTIVE_ACCOUNT_ACTIVATION.md"
            .to_string(),
        operations_file: "docs/mercury/SELECTIVE_ACCOUNT_ACTIVATION_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/SELECTIVE_ACCOUNT_ACTIVATION_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/SELECTIVE_ACCOUNT_ACTIVATION_DECISION_RECORD.md"
            .to_string(),
    }
}

fn build_selective_account_activation_profile(
    workflow_id: &str,
) -> Result<MercurySelectiveAccountActivationProfile, CliError> {
    let profile = MercurySelectiveAccountActivationProfile {
        schema: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "selective-account-activation-controlled-delivery-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        activation_motion: MercurySelectiveAccountActivationMotion::SelectiveAccountActivation,
        delivery_surface: MercurySelectiveAccountActivationSurface::ControlledDeliveryBundle,
        claim_containment: "controlled-delivery-evidence-only".to_string(),
        retained_artifact_policy:
            "retain-bounded-selective-account-activation-and-controlled-delivery-artifacts"
                .to_string(),
        intended_use: "Activate one bounded Mercury selective-account lane over the validated broader-distribution package without widening into generic onboarding tooling, CRM workflows, channel marketplaces, merged shells, or Chio commercial surfaces."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}
