use super::*;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryThirdProgramDocRefs {
    third_program_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryThirdProgramBoundaryFreeze {
    schema: String,
    workflow_id: String,
    program_motion: String,
    review_surface: String,
    repeatability_boundary_label: String,
    entry_gates: Vec<String>,
    non_goals: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryThirdProgramManifest {
    schema: String,
    workflow_id: String,
    program_motion: String,
    review_surface: String,
    second_portfolio_program_package_file: String,
    second_portfolio_program_boundary_freeze_file: String,
    second_portfolio_program_manifest_file: String,
    portfolio_reuse_summary_file: String,
    portfolio_reuse_approval_file: String,
    revenue_boundary_guardrails_file: String,
    second_program_handoff_file: String,
    portfolio_program_package_file: String,
    proof_package_file: String,
    inquiry_package_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryMultiProgramReuseSummary {
    schema: String,
    workflow_id: String,
    program_owner: String,
    review_owner: String,
    multi_program_guardrails_owner: String,
    program_motion: String,
    review_surface: String,
    approved_claims: Vec<String>,
    evidence_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryApprovalRefresh {
    schema: String,
    workflow_id: String,
    review_owner: String,
    status: String,
    reviewed_at: u64,
    reviewed_by: String,
    approved_claims: Vec<String>,
    required_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryMultiProgramGuardrails {
    schema: String,
    workflow_id: String,
    program_owner: String,
    review_owner: String,
    multi_program_guardrails_owner: String,
    program_motion: String,
    review_surface: String,
    approved_scope: String,
    permitted_reuse: Vec<String>,
    blocked_reuse: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryThirdProgramHandoff {
    schema: String,
    workflow_id: String,
    program_owner: String,
    review_owner: String,
    multi_program_guardrails_owner: String,
    program_motion: String,
    review_surface: String,
    approved_scope: String,
    required_evidence: Vec<String>,
    deferred_requests: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MercuryThirdProgramExportSummary {
    pub(super) workflow_id: String,
    pub(super) program_motion: String,
    pub(super) review_surface: String,
    pub(super) program_owner: String,
    pub(super) multi_program_review_owner: String,
    pub(super) multi_program_guardrails_owner: String,
    pub(super) second_portfolio_program_dir: String,
    pub(super) third_program_profile_file: String,
    pub(super) third_program_package_file: String,
    pub(super) third_program_boundary_freeze_file: String,
    pub(super) third_program_manifest_file: String,
    pub(super) multi_program_reuse_summary_file: String,
    pub(super) approval_refresh_file: String,
    pub(super) multi_program_guardrails_file: String,
    pub(super) third_program_handoff_file: String,
    pub(super) multi_program_evidence_dir: String,
    pub(super) second_portfolio_program_package_file: String,
    pub(super) second_portfolio_program_boundary_freeze_file: String,
    pub(super) second_portfolio_program_manifest_file: String,
    pub(super) portfolio_reuse_summary_file: String,
    pub(super) portfolio_reuse_approval_file: String,
    pub(super) revenue_boundary_guardrails_file: String,
    pub(super) second_program_handoff_file: String,
    pub(super) portfolio_program_package_file: String,
    pub(super) proof_package_file: String,
    pub(super) inquiry_package_file: String,
    pub(super) reviewer_package_file: String,
    pub(super) qualification_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryThirdProgramDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_program_motion: String,
    selected_review_surface: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryThirdProgramValidationReport {
    workflow_id: String,
    decision: String,
    program_motion: String,
    review_surface: String,
    program_owner: String,
    multi_program_review_owner: String,
    multi_program_guardrails_owner: String,
    same_workflow_boundary: String,
    third_program: MercuryThirdProgramExportSummary,
    decision_record_file: String,
    docs: MercuryThirdProgramDocRefs,
}

fn third_program_doc_refs() -> MercuryThirdProgramDocRefs {
    MercuryThirdProgramDocRefs {
        third_program_file: "docs/mercury/THIRD_PROGRAM.md".to_string(),
        operations_file: "docs/mercury/THIRD_PROGRAM_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/THIRD_PROGRAM_VALIDATION_PACKAGE.md".to_string(),
        decision_record_file: "docs/mercury/THIRD_PROGRAM_DECISION_RECORD.md".to_string(),
    }
}

fn build_third_program_profile(workflow_id: &str) -> Result<MercuryThirdProgramProfile, CliError> {
    let profile = MercuryThirdProgramProfile {
        schema: MERCURY_THIRD_PROGRAM_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "third-program-multi-program-reuse-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        program_motion: MercuryThirdProgramMotion::ThirdProgram,
        review_surface: MercuryThirdProgramSurface::MultiProgramReuseBundle,
        approval_gate: "evidence_backed_third_program_only".to_string(),
        retained_artifact_policy: "retain-bounded-third-program-and-repeatability-artifacts"
            .to_string(),
        intended_use: "Qualify one bounded Mercury third program through one multi_program_reuse_bundle rooted in the validated second-portfolio-program chain without widening into generic portfolio-management tooling, revenue operations systems, forecasting stacks, billing platforms, channel programs, or Chio commercial surfaces.".to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

pub(super) fn export_third_program(
    output: &Path,
) -> Result<MercuryThirdProgramExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let second_portfolio_program_stage_dir = unique_temp_dir("chio-mercury-third-program-stage");
    let second_program = export_second_portfolio_program(&second_portfolio_program_stage_dir)?;
    let workflow_id = second_program.workflow_id.clone();

    let second_portfolio_program_dir = output.join("second-portfolio-program");
    fs::create_dir_all(&second_portfolio_program_dir)?;
    let second_portfolio_program_package_copy =
        second_portfolio_program_dir.join("second-portfolio-program-package.json");
    copy_file(
        Path::new(&second_program.second_portfolio_program_package_file),
        &second_portfolio_program_package_copy,
    )?;

    let profile = build_third_program_profile(&workflow_id)?;
    let profile_path = output.join("third-program-profile.json");
    write_json_file(&profile_path, &profile)?;

    let multi_program_evidence_dir = output.join("multi-program-evidence");
    fs::create_dir_all(&multi_program_evidence_dir)?;

    let second_portfolio_program_package_path =
        multi_program_evidence_dir.join("second-portfolio-program-package.json");
    let second_portfolio_program_boundary_freeze_path =
        multi_program_evidence_dir.join("second-portfolio-program-boundary-freeze.json");
    let second_portfolio_program_manifest_path =
        multi_program_evidence_dir.join("second-portfolio-program-manifest.json");
    let portfolio_reuse_summary_path =
        multi_program_evidence_dir.join("portfolio-reuse-summary.json");
    let portfolio_reuse_approval_path =
        multi_program_evidence_dir.join("portfolio-reuse-approval.json");
    let revenue_boundary_guardrails_path =
        multi_program_evidence_dir.join("revenue-boundary-guardrails.json");
    let second_program_handoff_path =
        multi_program_evidence_dir.join("second-program-handoff.json");
    let portfolio_program_package_path =
        multi_program_evidence_dir.join("portfolio-program-package.json");
    let proof_package_path = multi_program_evidence_dir.join("proof-package.json");
    let inquiry_package_path = multi_program_evidence_dir.join("inquiry-package.json");
    let reviewer_package_path = multi_program_evidence_dir.join("reviewer-package.json");
    let qualification_report_path = multi_program_evidence_dir.join("qualification-report.json");

    copy_file(
        Path::new(&second_program.second_portfolio_program_package_file),
        &second_portfolio_program_package_path,
    )?;
    copy_file(
        Path::new(&second_program.second_portfolio_program_boundary_freeze_file),
        &second_portfolio_program_boundary_freeze_path,
    )?;
    copy_file(
        Path::new(&second_program.second_portfolio_program_manifest_file),
        &second_portfolio_program_manifest_path,
    )?;
    copy_file(
        Path::new(&second_program.portfolio_reuse_summary_file),
        &portfolio_reuse_summary_path,
    )?;
    copy_file(
        Path::new(&second_program.portfolio_reuse_approval_file),
        &portfolio_reuse_approval_path,
    )?;
    copy_file(
        Path::new(&second_program.revenue_boundary_guardrails_file),
        &revenue_boundary_guardrails_path,
    )?;
    copy_file(
        Path::new(&second_program.second_program_handoff_file),
        &second_program_handoff_path,
    )?;
    copy_file(
        Path::new(&second_program.portfolio_program_package_file),
        &portfolio_program_package_path,
    )?;
    copy_file(
        Path::new(&second_program.proof_package_file),
        &proof_package_path,
    )?;
    copy_file(
        Path::new(&second_program.inquiry_package_file),
        &inquiry_package_path,
    )?;
    copy_file(
        Path::new(&second_program.reviewer_package_file),
        &reviewer_package_path,
    )?;
    copy_file(
        Path::new(&second_program.qualification_report_file),
        &qualification_report_path,
    )?;

    let approved_claim = "Mercury can qualify one bounded third program through one third_program motion using one multi_program_reuse_bundle rooted in the validated second-portfolio-program chain."
        .to_string();

    let third_program_boundary_freeze = MercuryThirdProgramBoundaryFreeze {
        schema: "chio.mercury.third_program_boundary_freeze.v1".to_string(),
        workflow_id: workflow_id.clone(),
        program_motion: MercuryThirdProgramMotion::ThirdProgram.as_str().to_string(),
        review_surface: MercuryThirdProgramSurface::MultiProgramReuseBundle
            .as_str()
            .to_string(),
        repeatability_boundary_label:
            "one bounded Mercury third-program lane over one repeated adjacent-program reuse decision only"
                .to_string(),
        entry_gates: vec![
            "second-portfolio-program package, approval, guardrails, and handoff remain current"
                .to_string(),
            "portfolio-program evidence remains unchanged and workflow-equivalent".to_string(),
            "proof, inquiry, reviewer, and qualification artifacts remain available".to_string(),
        ],
        non_goals: vec![
            "generic portfolio-management tooling".to_string(),
            "revenue operations systems, forecasting stacks, or billing platforms".to_string(),
            "channel programs, merged shells, or Chio commercial surfaces".to_string(),
        ],
        note: "This freeze allows one repeated adjacent-program reuse proof point only."
            .to_string(),
    };
    let third_program_boundary_freeze_path = output.join("third-program-boundary-freeze.json");
    write_json_file(
        &third_program_boundary_freeze_path,
        &third_program_boundary_freeze,
    )?;

    let third_program_manifest = MercuryThirdProgramManifest {
        schema: "chio.mercury.third_program_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        program_motion: MercuryThirdProgramMotion::ThirdProgram.as_str().to_string(),
        review_surface: MercuryThirdProgramSurface::MultiProgramReuseBundle
            .as_str()
            .to_string(),
        second_portfolio_program_package_file: relative_display(
            output,
            &second_portfolio_program_package_path,
        )?,
        second_portfolio_program_boundary_freeze_file: relative_display(
            output,
            &second_portfolio_program_boundary_freeze_path,
        )?,
        second_portfolio_program_manifest_file: relative_display(
            output,
            &second_portfolio_program_manifest_path,
        )?,
        portfolio_reuse_summary_file: relative_display(output, &portfolio_reuse_summary_path)?,
        portfolio_reuse_approval_file: relative_display(output, &portfolio_reuse_approval_path)?,
        revenue_boundary_guardrails_file: relative_display(
            output,
            &revenue_boundary_guardrails_path,
        )?,
        second_program_handoff_file: relative_display(output, &second_program_handoff_path)?,
        portfolio_program_package_file: relative_display(output, &portfolio_program_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        note:
            "Third-program packaging stays rooted in the validated second-portfolio-program chain."
                .to_string(),
    };
    let third_program_manifest_path = output.join("third-program-manifest.json");
    write_json_file(&third_program_manifest_path, &third_program_manifest)?;

    let multi_program_reuse_summary = MercuryMultiProgramReuseSummary {
        schema: "chio.mercury.third_program_multi_program_reuse_summary.v1".to_string(),
        workflow_id: workflow_id.clone(),
        program_owner: MERCURY_THIRD_PROGRAM_OWNER.to_string(),
        review_owner: MERCURY_MULTI_PROGRAM_REVIEW_OWNER.to_string(),
        multi_program_guardrails_owner: MERCURY_MULTI_PROGRAM_GUARDRAILS_OWNER.to_string(),
        program_motion: MercuryThirdProgramMotion::ThirdProgram.as_str().to_string(),
        review_surface: MercuryThirdProgramSurface::MultiProgramReuseBundle
            .as_str()
            .to_string(),
        approved_claims: vec![approved_claim.clone()],
        evidence_files: vec![
            relative_display(output, &third_program_manifest_path)?,
            relative_display(output, &second_portfolio_program_package_path)?,
            relative_display(output, &portfolio_reuse_summary_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
        ],
        note: "Repeated program reuse stays bounded to one additional third-program proof point."
            .to_string(),
    };
    let multi_program_reuse_summary_path = output.join("multi-program-reuse-summary.json");
    write_json_file(
        &multi_program_reuse_summary_path,
        &multi_program_reuse_summary,
    )?;

    let approval_refresh = MercuryApprovalRefresh {
        schema: "chio.mercury.third_program_approval_refresh.v1".to_string(),
        workflow_id: workflow_id.clone(),
        review_owner: MERCURY_MULTI_PROGRAM_REVIEW_OWNER.to_string(),
        status: "ready".to_string(),
        reviewed_at: unix_now(),
        reviewed_by: MERCURY_MULTI_PROGRAM_REVIEW_OWNER.to_string(),
        approved_claims: vec![approved_claim.clone()],
        required_files: vec![
            relative_display(output, &third_program_boundary_freeze_path)?,
            relative_display(output, &third_program_manifest_path)?,
            relative_display(output, &second_portfolio_program_package_path)?,
            relative_display(output, &proof_package_path)?,
        ],
        note: "Approval refresh is required before Mercury can assert one repeated adjacent-program reuse decision.".to_string(),
    };
    let approval_refresh_path = output.join("approval-refresh.json");
    write_json_file(&approval_refresh_path, &approval_refresh)?;

    let multi_program_guardrails = MercuryMultiProgramGuardrails {
        schema: "chio.mercury.third_program_multi_program_guardrails.v1".to_string(),
        workflow_id: workflow_id.clone(),
        program_owner: MERCURY_THIRD_PROGRAM_OWNER.to_string(),
        review_owner: MERCURY_MULTI_PROGRAM_REVIEW_OWNER.to_string(),
        multi_program_guardrails_owner: MERCURY_MULTI_PROGRAM_GUARDRAILS_OWNER.to_string(),
        program_motion: MercuryThirdProgramMotion::ThirdProgram.as_str().to_string(),
        review_surface: MercuryThirdProgramSurface::MultiProgramReuseBundle
            .as_str()
            .to_string(),
        approved_scope: "one bounded third-program review bundle over one repeated adjacent-program reuse decision only".to_string(),
        permitted_reuse: vec![
            "second-portfolio-program evidence that remains workflow-equivalent".to_string(),
            "one additional adjacent-program reuse assertion inside Mercury".to_string(),
        ],
        blocked_reuse: vec![
            "generic multi-program portfolio automation".to_string(),
            "revenue platforms, billing, or forecasting systems".to_string(),
            "channel programs or Chio commercial controls".to_string(),
        ],
        note: "Multi-program guardrails keep the third-program lane narrow and Mercury-owned."
            .to_string(),
    };
    let multi_program_guardrails_path = output.join("multi-program-guardrails.json");
    write_json_file(&multi_program_guardrails_path, &multi_program_guardrails)?;

    let third_program_handoff = MercuryThirdProgramHandoff {
        schema: "chio.mercury.third_program_handoff.v1".to_string(),
        workflow_id: workflow_id.clone(),
        program_owner: MERCURY_THIRD_PROGRAM_OWNER.to_string(),
        review_owner: MERCURY_MULTI_PROGRAM_REVIEW_OWNER.to_string(),
        multi_program_guardrails_owner: MERCURY_MULTI_PROGRAM_GUARDRAILS_OWNER.to_string(),
        program_motion: MercuryThirdProgramMotion::ThirdProgram.as_str().to_string(),
        review_surface: MercuryThirdProgramSurface::MultiProgramReuseBundle
            .as_str()
            .to_string(),
        approved_scope:
            "one bounded third-program lane over the validated second-portfolio-program chain only"
                .to_string(),
        required_evidence: vec![
            relative_display(output, &third_program_manifest_path)?,
            relative_display(output, &multi_program_reuse_summary_path)?,
            relative_display(output, &approval_refresh_path)?,
            relative_display(output, &multi_program_guardrails_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
        ],
        deferred_requests: vec![
            "generic portfolio-management tooling".to_string(),
            "revenue-platform, billing, or channel-program breadth".to_string(),
            "Chio-side commercial control surfaces".to_string(),
        ],
        note: "Third-program handoff exists to support one repeatability proof point only."
            .to_string(),
    };
    let third_program_handoff_path = output.join("third-program-handoff.json");
    write_json_file(&third_program_handoff_path, &third_program_handoff)?;

    let package = MercuryThirdProgramPackage {
        schema: MERCURY_THIRD_PROGRAM_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "third-program-multi-program-reuse-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        program_motion: MercuryThirdProgramMotion::ThirdProgram,
        review_surface: MercuryThirdProgramSurface::MultiProgramReuseBundle,
        program_owner: MERCURY_THIRD_PROGRAM_OWNER.to_string(),
        multi_program_review_owner: MERCURY_MULTI_PROGRAM_REVIEW_OWNER.to_string(),
        multi_program_guardrails_owner: MERCURY_MULTI_PROGRAM_GUARDRAILS_OWNER.to_string(),
        approval_refresh_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        second_portfolio_program_package_file: relative_display(
            output,
            &second_portfolio_program_package_path,
        )?,
        second_portfolio_program_boundary_freeze_file: relative_display(
            output,
            &second_portfolio_program_boundary_freeze_path,
        )?,
        second_portfolio_program_manifest_file: relative_display(
            output,
            &second_portfolio_program_manifest_path,
        )?,
        portfolio_reuse_summary_file: relative_display(output, &portfolio_reuse_summary_path)?,
        portfolio_reuse_approval_file: relative_display(output, &portfolio_reuse_approval_path)?,
        revenue_boundary_guardrails_file: relative_display(
            output,
            &revenue_boundary_guardrails_path,
        )?,
        second_program_handoff_file: relative_display(output, &second_program_handoff_path)?,
        portfolio_program_package_file: relative_display(output, &portfolio_program_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        artifacts: vec![
            MercuryThirdProgramArtifact {
                artifact_kind: MercuryThirdProgramArtifactKind::ThirdProgramBoundaryFreeze,
                relative_path: relative_display(output, &third_program_boundary_freeze_path)?,
            },
            MercuryThirdProgramArtifact {
                artifact_kind: MercuryThirdProgramArtifactKind::ThirdProgramManifest,
                relative_path: relative_display(output, &third_program_manifest_path)?,
            },
            MercuryThirdProgramArtifact {
                artifact_kind: MercuryThirdProgramArtifactKind::MultiProgramReuseSummary,
                relative_path: relative_display(output, &multi_program_reuse_summary_path)?,
            },
            MercuryThirdProgramArtifact {
                artifact_kind: MercuryThirdProgramArtifactKind::ApprovalRefresh,
                relative_path: relative_display(output, &approval_refresh_path)?,
            },
            MercuryThirdProgramArtifact {
                artifact_kind: MercuryThirdProgramArtifactKind::MultiProgramGuardrails,
                relative_path: relative_display(output, &multi_program_guardrails_path)?,
            },
            MercuryThirdProgramArtifact {
                artifact_kind: MercuryThirdProgramArtifactKind::ThirdProgramHandoff,
                relative_path: relative_display(output, &third_program_handoff_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("third-program-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryThirdProgramExportSummary {
        workflow_id,
        program_motion: MercuryThirdProgramMotion::ThirdProgram.as_str().to_string(),
        review_surface: MercuryThirdProgramSurface::MultiProgramReuseBundle
            .as_str()
            .to_string(),
        program_owner: MERCURY_THIRD_PROGRAM_OWNER.to_string(),
        multi_program_review_owner: MERCURY_MULTI_PROGRAM_REVIEW_OWNER.to_string(),
        multi_program_guardrails_owner: MERCURY_MULTI_PROGRAM_GUARDRAILS_OWNER.to_string(),
        second_portfolio_program_dir: second_portfolio_program_dir.display().to_string(),
        third_program_profile_file: profile_path.display().to_string(),
        third_program_package_file: package_path.display().to_string(),
        third_program_boundary_freeze_file: third_program_boundary_freeze_path
            .display()
            .to_string(),
        third_program_manifest_file: third_program_manifest_path.display().to_string(),
        multi_program_reuse_summary_file: multi_program_reuse_summary_path.display().to_string(),
        approval_refresh_file: approval_refresh_path.display().to_string(),
        multi_program_guardrails_file: multi_program_guardrails_path.display().to_string(),
        third_program_handoff_file: third_program_handoff_path.display().to_string(),
        multi_program_evidence_dir: multi_program_evidence_dir.display().to_string(),
        second_portfolio_program_package_file: second_portfolio_program_package_path
            .display()
            .to_string(),
        second_portfolio_program_boundary_freeze_file:
            second_portfolio_program_boundary_freeze_path
                .display()
                .to_string(),
        second_portfolio_program_manifest_file: second_portfolio_program_manifest_path
            .display()
            .to_string(),
        portfolio_reuse_summary_file: portfolio_reuse_summary_path.display().to_string(),
        portfolio_reuse_approval_file: portfolio_reuse_approval_path.display().to_string(),
        revenue_boundary_guardrails_file: revenue_boundary_guardrails_path.display().to_string(),
        second_program_handoff_file: second_program_handoff_path.display().to_string(),
        portfolio_program_package_file: portfolio_program_package_path.display().to_string(),
        proof_package_file: proof_package_path.display().to_string(),
        inquiry_package_file: inquiry_package_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
    };
    write_json_file(&output.join("third-program-summary.json"), &summary)?;
    let _ = fs::remove_dir_all(&second_portfolio_program_stage_dir);

    Ok(summary)
}

pub fn cmd_mercury_third_program_export(output: &Path, json_output: bool) -> Result<(), CliError> {
    let summary = export_third_program(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury third-program package exported");
        println!("output:                             {}", output.display());
        println!(
            "workflow_id:                        {}",
            summary.workflow_id
        );
        println!(
            "program_motion:                     {}",
            summary.program_motion
        );
        println!(
            "review_surface:                     {}",
            summary.review_surface
        );
        println!(
            "program_owner:                      {}",
            summary.program_owner
        );
        println!(
            "multi_program_review_owner:         {}",
            summary.multi_program_review_owner
        );
        println!(
            "multi_program_guardrails_owner:     {}",
            summary.multi_program_guardrails_owner
        );
        println!(
            "third_program_package:              {}",
            summary.third_program_package_file
        );
        println!(
            "approval_refresh:                   {}",
            summary.approval_refresh_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_third_program_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let third_program_dir = output.join("third-program");
    let summary = export_third_program(&third_program_dir)?;
    let docs = third_program_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryThirdProgramDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_THIRD_PROGRAM_DECISION.to_string(),
        selected_program_motion: summary.program_motion.clone(),
        selected_review_surface: summary.review_surface.clone(),
        approved_scope: "Proceed with one bounded Mercury third-program lane only.".to_string(),
        deferred_scope: vec![
            "generic multi-program portfolio-management tooling".to_string(),
            "revenue operations systems, forecasting stacks, or billing platforms".to_string(),
            "channel programs, merged shells, or Chio-side commercial controls".to_string(),
        ],
        rationale: "The third-program lane packages one bounded repeated portfolio-reuse proof point, one approval refresh, one multi-program-guardrails artifact, and one explicit handoff over the validated second-portfolio-program chain without widening Mercury into a generic multi-program or revenue platform.".to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("third-program-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryThirdProgramValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_THIRD_PROGRAM_DECISION.to_string(),
        program_motion: summary.program_motion.clone(),
        review_surface: summary.review_surface.clone(),
        program_owner: summary.program_owner.clone(),
        multi_program_review_owner: summary.multi_program_review_owner.clone(),
        multi_program_guardrails_owner: summary.multi_program_guardrails_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        third_program: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury third-program validation package exported");
        println!("output:                             {}", output.display());
        println!("workflow_id:                        {}", report.workflow_id);
        println!("decision:                           {}", report.decision);
        println!(
            "program_motion:                     {}",
            report.program_motion
        );
        println!(
            "review_surface:                     {}",
            report.review_surface
        );
        println!(
            "program_owner:                      {}",
            report.program_owner
        );
        println!(
            "multi_program_review_owner:         {}",
            report.multi_program_review_owner
        );
        println!(
            "multi_program_guardrails_owner:     {}",
            report.multi_program_guardrails_owner
        );
        println!(
            "validation_report:                  {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:                    {}",
            decision_record_file.display()
        );
        println!(
            "third_program_package:              {}",
            report.third_program.third_program_package_file
        );
    }

    Ok(())
}
