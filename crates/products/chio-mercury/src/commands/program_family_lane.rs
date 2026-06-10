use super::*;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryProgramFamilyDocRefs {
    program_family_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryProgramFamilyBoundaryFreeze {
    schema: String,
    workflow_id: String,
    program_motion: String,
    review_surface: String,
    family_boundary_label: String,
    entry_gates: Vec<String>,
    non_goals: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryProgramFamilyManifest {
    schema: String,
    workflow_id: String,
    program_motion: String,
    review_surface: String,
    third_program_package_file: String,
    third_program_boundary_freeze_file: String,
    third_program_manifest_file: String,
    multi_program_reuse_summary_file: String,
    approval_refresh_file: String,
    multi_program_guardrails_file: String,
    third_program_handoff_file: String,
    second_portfolio_program_package_file: String,
    proof_package_file: String,
    inquiry_package_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySharedReviewSummary {
    schema: String,
    workflow_id: String,
    family_owner: String,
    review_owner: String,
    claim_discipline_owner: String,
    program_motion: String,
    review_surface: String,
    approved_claims: Vec<String>,
    evidence_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySharedReviewApproval {
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
struct MercuryPortfolioClaimDiscipline {
    schema: String,
    workflow_id: String,
    family_owner: String,
    review_owner: String,
    claim_discipline_owner: String,
    program_motion: String,
    review_surface: String,
    approved_scope: String,
    permitted_claims: Vec<String>,
    blocked_claims: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryFamilyHandoff {
    schema: String,
    workflow_id: String,
    family_owner: String,
    review_owner: String,
    claim_discipline_owner: String,
    program_motion: String,
    review_surface: String,
    approved_scope: String,
    required_evidence: Vec<String>,
    deferred_requests: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MercuryProgramFamilyExportSummary {
    pub(super) workflow_id: String,
    pub(super) program_motion: String,
    pub(super) review_surface: String,
    pub(super) program_family_owner: String,
    pub(super) shared_review_owner: String,
    pub(super) portfolio_claim_discipline_owner: String,
    pub(super) third_program_dir: String,
    pub(super) program_family_profile_file: String,
    pub(super) program_family_package_file: String,
    pub(super) program_family_boundary_freeze_file: String,
    pub(super) program_family_manifest_file: String,
    pub(super) shared_review_summary_file: String,
    pub(super) shared_review_approval_file: String,
    pub(super) portfolio_claim_discipline_file: String,
    pub(super) family_handoff_file: String,
    pub(super) shared_review_evidence_dir: String,
    pub(super) third_program_package_file: String,
    pub(super) third_program_boundary_freeze_file: String,
    pub(super) third_program_manifest_file: String,
    pub(super) multi_program_reuse_summary_file: String,
    pub(super) approval_refresh_file: String,
    pub(super) multi_program_guardrails_file: String,
    pub(super) third_program_handoff_file: String,
    pub(super) second_portfolio_program_package_file: String,
    pub(super) proof_package_file: String,
    pub(super) inquiry_package_file: String,
    pub(super) reviewer_package_file: String,
    pub(super) qualification_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryProgramFamilyDecisionRecord {
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
struct MercuryProgramFamilyValidationReport {
    workflow_id: String,
    decision: String,
    program_motion: String,
    review_surface: String,
    program_family_owner: String,
    shared_review_owner: String,
    portfolio_claim_discipline_owner: String,
    same_workflow_boundary: String,
    program_family: MercuryProgramFamilyExportSummary,
    decision_record_file: String,
    docs: MercuryProgramFamilyDocRefs,
}

fn program_family_doc_refs() -> MercuryProgramFamilyDocRefs {
    MercuryProgramFamilyDocRefs {
        program_family_file: "docs/mercury/PROGRAM_FAMILY.md".to_string(),
        operations_file: "docs/mercury/PROGRAM_FAMILY_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/PROGRAM_FAMILY_VALIDATION_PACKAGE.md".to_string(),
        decision_record_file: "docs/mercury/PROGRAM_FAMILY_DECISION_RECORD.md".to_string(),
    }
}

fn build_program_family_profile(
    workflow_id: &str,
) -> Result<MercuryProgramFamilyProfile, CliError> {
    let profile = MercuryProgramFamilyProfile {
        schema: MERCURY_PROGRAM_FAMILY_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "program-family-shared-review-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        program_motion: MercuryProgramFamilyMotion::ProgramFamily,
        review_surface: MercuryProgramFamilySurface::SharedReviewPackage,
        approval_gate: "evidence_backed_program_family_only".to_string(),
        retained_artifact_policy: "retain-bounded-program-family-and-shared-review-artifacts"
            .to_string(),
        intended_use: "Qualify one bounded Mercury program family through one shared_review_package rooted in the validated third-program chain without widening into generic portfolio-management tooling, revenue operations systems, forecasting stacks, billing platforms, channel programs, or Chio commercial surfaces.".to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

pub(super) fn export_program_family(
    output: &Path,
) -> Result<MercuryProgramFamilyExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let third_program_stage_dir = unique_temp_dir("chio-mercury-program-family-stage");
    let third_program = export_third_program(&third_program_stage_dir)?;
    let workflow_id = third_program.workflow_id.clone();

    let third_program_dir = output.join("third-program");
    fs::create_dir_all(&third_program_dir)?;
    let third_program_package_copy = third_program_dir.join("third-program-package.json");
    copy_file(
        Path::new(&third_program.third_program_package_file),
        &third_program_package_copy,
    )?;

    let profile = build_program_family_profile(&workflow_id)?;
    let profile_path = output.join("program-family-profile.json");
    write_json_file(&profile_path, &profile)?;

    let shared_review_evidence_dir = output.join("shared-review-evidence");
    fs::create_dir_all(&shared_review_evidence_dir)?;

    let third_program_package_path = shared_review_evidence_dir.join("third-program-package.json");
    let third_program_boundary_freeze_path =
        shared_review_evidence_dir.join("third-program-boundary-freeze.json");
    let third_program_manifest_path =
        shared_review_evidence_dir.join("third-program-manifest.json");
    let multi_program_reuse_summary_path =
        shared_review_evidence_dir.join("multi-program-reuse-summary.json");
    let approval_refresh_path = shared_review_evidence_dir.join("approval-refresh.json");
    let multi_program_guardrails_path =
        shared_review_evidence_dir.join("multi-program-guardrails.json");
    let third_program_handoff_path = shared_review_evidence_dir.join("third-program-handoff.json");
    let second_portfolio_program_package_path =
        shared_review_evidence_dir.join("second-portfolio-program-package.json");
    let proof_package_path = shared_review_evidence_dir.join("proof-package.json");
    let inquiry_package_path = shared_review_evidence_dir.join("inquiry-package.json");
    let reviewer_package_path = shared_review_evidence_dir.join("reviewer-package.json");
    let qualification_report_path = shared_review_evidence_dir.join("qualification-report.json");

    copy_file(
        Path::new(&third_program.third_program_package_file),
        &third_program_package_path,
    )?;
    copy_file(
        Path::new(&third_program.third_program_boundary_freeze_file),
        &third_program_boundary_freeze_path,
    )?;
    copy_file(
        Path::new(&third_program.third_program_manifest_file),
        &third_program_manifest_path,
    )?;
    copy_file(
        Path::new(&third_program.multi_program_reuse_summary_file),
        &multi_program_reuse_summary_path,
    )?;
    copy_file(
        Path::new(&third_program.approval_refresh_file),
        &approval_refresh_path,
    )?;
    copy_file(
        Path::new(&third_program.multi_program_guardrails_file),
        &multi_program_guardrails_path,
    )?;
    copy_file(
        Path::new(&third_program.third_program_handoff_file),
        &third_program_handoff_path,
    )?;
    copy_file(
        Path::new(&third_program.second_portfolio_program_package_file),
        &second_portfolio_program_package_path,
    )?;
    copy_file(
        Path::new(&third_program.proof_package_file),
        &proof_package_path,
    )?;
    copy_file(
        Path::new(&third_program.inquiry_package_file),
        &inquiry_package_path,
    )?;
    copy_file(
        Path::new(&third_program.reviewer_package_file),
        &reviewer_package_path,
    )?;
    copy_file(
        Path::new(&third_program.qualification_report_file),
        &qualification_report_path,
    )?;

    let approved_claim = "Mercury can qualify one bounded program family through one program_family motion using one shared_review_package rooted in the validated third-program chain."
        .to_string();

    let program_family_boundary_freeze = MercuryProgramFamilyBoundaryFreeze {
        schema: "chio.mercury.program_family_boundary_freeze.v1".to_string(),
        workflow_id: workflow_id.clone(),
        program_motion: MercuryProgramFamilyMotion::ProgramFamily
            .as_str()
            .to_string(),
        review_surface: MercuryProgramFamilySurface::SharedReviewPackage
            .as_str()
            .to_string(),
        family_boundary_label:
            "one bounded Mercury program-family lane over one explicitly named adjacent program family only"
                .to_string(),
        entry_gates: vec![
            "third-program package, approval refresh, guardrails, and handoff remain current"
                .to_string(),
            "shared review stays inside one named small family".to_string(),
            "proof, inquiry, reviewer, and qualification artifacts remain available".to_string(),
        ],
        non_goals: vec![
            "generic portfolio-management tooling".to_string(),
            "revenue operations or commercial platform automation".to_string(),
            "channel programs, merged shells, or Chio commercial surfaces".to_string(),
        ],
        note: "This freeze allows one named small program-family review only.".to_string(),
    };
    let program_family_boundary_freeze_path = output.join("program-family-boundary-freeze.json");
    write_json_file(
        &program_family_boundary_freeze_path,
        &program_family_boundary_freeze,
    )?;

    let program_family_manifest = MercuryProgramFamilyManifest {
        schema: "chio.mercury.program_family_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        program_motion: MercuryProgramFamilyMotion::ProgramFamily
            .as_str()
            .to_string(),
        review_surface: MercuryProgramFamilySurface::SharedReviewPackage
            .as_str()
            .to_string(),
        third_program_package_file: relative_display(output, &third_program_package_path)?,
        third_program_boundary_freeze_file: relative_display(
            output,
            &third_program_boundary_freeze_path,
        )?,
        third_program_manifest_file: relative_display(output, &third_program_manifest_path)?,
        multi_program_reuse_summary_file: relative_display(
            output,
            &multi_program_reuse_summary_path,
        )?,
        approval_refresh_file: relative_display(output, &approval_refresh_path)?,
        multi_program_guardrails_file: relative_display(output, &multi_program_guardrails_path)?,
        third_program_handoff_file: relative_display(output, &third_program_handoff_path)?,
        second_portfolio_program_package_file: relative_display(
            output,
            &second_portfolio_program_package_path,
        )?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        note: "Program-family packaging stays rooted in the validated third-program chain."
            .to_string(),
    };
    let program_family_manifest_path = output.join("program-family-manifest.json");
    write_json_file(&program_family_manifest_path, &program_family_manifest)?;

    let shared_review_summary = MercurySharedReviewSummary {
        schema: "chio.mercury.program_family_shared_review_summary.v1".to_string(),
        workflow_id: workflow_id.clone(),
        family_owner: MERCURY_PROGRAM_FAMILY_OWNER.to_string(),
        review_owner: MERCURY_SHARED_REVIEW_OWNER.to_string(),
        claim_discipline_owner: MERCURY_PORTFOLIO_CLAIM_DISCIPLINE_OWNER.to_string(),
        program_motion: MercuryProgramFamilyMotion::ProgramFamily
            .as_str()
            .to_string(),
        review_surface: MercuryProgramFamilySurface::SharedReviewPackage
            .as_str()
            .to_string(),
        approved_claims: vec![approved_claim.clone()],
        evidence_files: vec![
            relative_display(output, &program_family_manifest_path)?,
            relative_display(output, &third_program_package_path)?,
            relative_display(output, &multi_program_reuse_summary_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
        ],
        note: "Shared review stays bounded to one named family of adjacent programs.".to_string(),
    };
    let shared_review_summary_path = output.join("shared-review-summary.json");
    write_json_file(&shared_review_summary_path, &shared_review_summary)?;

    let shared_review_approval = MercurySharedReviewApproval {
        schema: "chio.mercury.program_family_shared_review_approval.v1".to_string(),
        workflow_id: workflow_id.clone(),
        review_owner: MERCURY_SHARED_REVIEW_OWNER.to_string(),
        status: "ready".to_string(),
        reviewed_at: unix_now(),
        reviewed_by: MERCURY_SHARED_REVIEW_OWNER.to_string(),
        approved_claims: vec![approved_claim.clone()],
        required_files: vec![
            relative_display(output, &program_family_boundary_freeze_path)?,
            relative_display(output, &program_family_manifest_path)?,
            relative_display(output, &third_program_package_path)?,
            relative_display(output, &proof_package_path)?,
        ],
        note: "Shared review approval is required before Mercury can claim one bounded program family.".to_string(),
    };
    let shared_review_approval_path = output.join("shared-review-approval.json");
    write_json_file(&shared_review_approval_path, &shared_review_approval)?;

    let portfolio_claim_discipline = MercuryPortfolioClaimDiscipline {
        schema: "chio.mercury.program_family_portfolio_claim_discipline.v1".to_string(),
        workflow_id: workflow_id.clone(),
        family_owner: MERCURY_PROGRAM_FAMILY_OWNER.to_string(),
        review_owner: MERCURY_SHARED_REVIEW_OWNER.to_string(),
        claim_discipline_owner: MERCURY_PORTFOLIO_CLAIM_DISCIPLINE_OWNER.to_string(),
        program_motion: MercuryProgramFamilyMotion::ProgramFamily
            .as_str()
            .to_string(),
        review_surface: MercuryProgramFamilySurface::SharedReviewPackage
            .as_str()
            .to_string(),
        approved_scope: "one bounded program-family shared review package over one named family only".to_string(),
        permitted_claims: vec![
            "one evidence-backed named family of adjacent programs".to_string(),
            "one shared review package that remains workflow-equivalent".to_string(),
        ],
        blocked_claims: vec![
            "generic multi-program portfolio automation".to_string(),
            "revenue platforms or commercial consoles".to_string(),
            "channel programs or Chio commercial surfaces".to_string(),
        ],
        note: "Portfolio claim discipline prevents family-level claims from becoming generalized portfolio claims.".to_string(),
    };
    let portfolio_claim_discipline_path = output.join("portfolio-claim-discipline.json");
    write_json_file(
        &portfolio_claim_discipline_path,
        &portfolio_claim_discipline,
    )?;

    let family_handoff = MercuryFamilyHandoff {
        schema: "chio.mercury.program_family_handoff.v1".to_string(),
        workflow_id: workflow_id.clone(),
        family_owner: MERCURY_PROGRAM_FAMILY_OWNER.to_string(),
        review_owner: MERCURY_SHARED_REVIEW_OWNER.to_string(),
        claim_discipline_owner: MERCURY_PORTFOLIO_CLAIM_DISCIPLINE_OWNER.to_string(),
        program_motion: MercuryProgramFamilyMotion::ProgramFamily
            .as_str()
            .to_string(),
        review_surface: MercuryProgramFamilySurface::SharedReviewPackage
            .as_str()
            .to_string(),
        approved_scope:
            "one bounded program-family lane over the validated third-program chain only"
                .to_string(),
        required_evidence: vec![
            relative_display(output, &program_family_manifest_path)?,
            relative_display(output, &shared_review_summary_path)?,
            relative_display(output, &shared_review_approval_path)?,
            relative_display(output, &portfolio_claim_discipline_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
        ],
        deferred_requests: vec![
            "generic portfolio-management tooling".to_string(),
            "revenue-platform or commercial automation".to_string(),
            "channel programs, merged shells, or Chio-side commercial controls".to_string(),
        ],
        note: "Family handoff keeps the lane limited to one named shared-review package."
            .to_string(),
    };
    let family_handoff_path = output.join("family-handoff.json");
    write_json_file(&family_handoff_path, &family_handoff)?;

    let package = MercuryProgramFamilyPackage {
        schema: MERCURY_PROGRAM_FAMILY_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "program-family-shared-review-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        program_motion: MercuryProgramFamilyMotion::ProgramFamily,
        review_surface: MercuryProgramFamilySurface::SharedReviewPackage,
        program_family_owner: MERCURY_PROGRAM_FAMILY_OWNER.to_string(),
        shared_review_owner: MERCURY_SHARED_REVIEW_OWNER.to_string(),
        portfolio_claim_discipline_owner: MERCURY_PORTFOLIO_CLAIM_DISCIPLINE_OWNER.to_string(),
        shared_review_approval_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        third_program_package_file: relative_display(output, &third_program_package_path)?,
        third_program_boundary_freeze_file: relative_display(
            output,
            &third_program_boundary_freeze_path,
        )?,
        third_program_manifest_file: relative_display(output, &third_program_manifest_path)?,
        multi_program_reuse_summary_file: relative_display(
            output,
            &multi_program_reuse_summary_path,
        )?,
        approval_refresh_file: relative_display(output, &approval_refresh_path)?,
        multi_program_guardrails_file: relative_display(output, &multi_program_guardrails_path)?,
        third_program_handoff_file: relative_display(output, &third_program_handoff_path)?,
        second_portfolio_program_package_file: relative_display(
            output,
            &second_portfolio_program_package_path,
        )?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        artifacts: vec![
            MercuryProgramFamilyArtifact {
                artifact_kind: MercuryProgramFamilyArtifactKind::ProgramFamilyBoundaryFreeze,
                relative_path: relative_display(output, &program_family_boundary_freeze_path)?,
            },
            MercuryProgramFamilyArtifact {
                artifact_kind: MercuryProgramFamilyArtifactKind::ProgramFamilyManifest,
                relative_path: relative_display(output, &program_family_manifest_path)?,
            },
            MercuryProgramFamilyArtifact {
                artifact_kind: MercuryProgramFamilyArtifactKind::SharedReviewSummary,
                relative_path: relative_display(output, &shared_review_summary_path)?,
            },
            MercuryProgramFamilyArtifact {
                artifact_kind: MercuryProgramFamilyArtifactKind::SharedReviewApproval,
                relative_path: relative_display(output, &shared_review_approval_path)?,
            },
            MercuryProgramFamilyArtifact {
                artifact_kind: MercuryProgramFamilyArtifactKind::PortfolioClaimDiscipline,
                relative_path: relative_display(output, &portfolio_claim_discipline_path)?,
            },
            MercuryProgramFamilyArtifact {
                artifact_kind: MercuryProgramFamilyArtifactKind::FamilyHandoff,
                relative_path: relative_display(output, &family_handoff_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("program-family-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryProgramFamilyExportSummary {
        workflow_id,
        program_motion: MercuryProgramFamilyMotion::ProgramFamily
            .as_str()
            .to_string(),
        review_surface: MercuryProgramFamilySurface::SharedReviewPackage
            .as_str()
            .to_string(),
        program_family_owner: MERCURY_PROGRAM_FAMILY_OWNER.to_string(),
        shared_review_owner: MERCURY_SHARED_REVIEW_OWNER.to_string(),
        portfolio_claim_discipline_owner: MERCURY_PORTFOLIO_CLAIM_DISCIPLINE_OWNER.to_string(),
        third_program_dir: third_program_dir.display().to_string(),
        program_family_profile_file: profile_path.display().to_string(),
        program_family_package_file: package_path.display().to_string(),
        program_family_boundary_freeze_file: program_family_boundary_freeze_path
            .display()
            .to_string(),
        program_family_manifest_file: program_family_manifest_path.display().to_string(),
        shared_review_summary_file: shared_review_summary_path.display().to_string(),
        shared_review_approval_file: shared_review_approval_path.display().to_string(),
        portfolio_claim_discipline_file: portfolio_claim_discipline_path.display().to_string(),
        family_handoff_file: family_handoff_path.display().to_string(),
        shared_review_evidence_dir: shared_review_evidence_dir.display().to_string(),
        third_program_package_file: third_program_package_path.display().to_string(),
        third_program_boundary_freeze_file: third_program_boundary_freeze_path
            .display()
            .to_string(),
        third_program_manifest_file: third_program_manifest_path.display().to_string(),
        multi_program_reuse_summary_file: multi_program_reuse_summary_path.display().to_string(),
        approval_refresh_file: approval_refresh_path.display().to_string(),
        multi_program_guardrails_file: multi_program_guardrails_path.display().to_string(),
        third_program_handoff_file: third_program_handoff_path.display().to_string(),
        second_portfolio_program_package_file: second_portfolio_program_package_path
            .display()
            .to_string(),
        proof_package_file: proof_package_path.display().to_string(),
        inquiry_package_file: inquiry_package_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
    };
    write_json_file(&output.join("program-family-summary.json"), &summary)?;
    let _ = fs::remove_dir_all(&third_program_stage_dir);

    Ok(summary)
}

pub fn cmd_mercury_program_family_export(output: &Path, json_output: bool) -> Result<(), CliError> {
    let summary = export_program_family(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury program-family package exported");
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
            "program_family_owner:               {}",
            summary.program_family_owner
        );
        println!(
            "shared_review_owner:                {}",
            summary.shared_review_owner
        );
        println!(
            "portfolio_claim_discipline_owner:   {}",
            summary.portfolio_claim_discipline_owner
        );
        println!(
            "program_family_package:             {}",
            summary.program_family_package_file
        );
        println!(
            "shared_review_approval:             {}",
            summary.shared_review_approval_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_program_family_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let program_family_dir = output.join("program-family");
    let summary = export_program_family(&program_family_dir)?;
    let docs = program_family_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryProgramFamilyDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_PROGRAM_FAMILY_DECISION.to_string(),
        selected_program_motion: summary.program_motion.clone(),
        selected_review_surface: summary.review_surface.clone(),
        approved_scope: "Proceed with one bounded Mercury program-family lane only.".to_string(),
        deferred_scope: vec![
            "generic portfolio-management or universal multi-program tooling".to_string(),
            "revenue-platform or commercial automation".to_string(),
            "channel programs, merged shells, or Chio-side commercial controls".to_string(),
        ],
        rationale: "The program-family lane packages one bounded shared-review surface, one shared-review approval, one portfolio-claim-discipline artifact, and one family handoff over the validated third-program chain without widening Mercury into a generic portfolio-management or commercial platform.".to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("program-family-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryProgramFamilyValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_PROGRAM_FAMILY_DECISION.to_string(),
        program_motion: summary.program_motion.clone(),
        review_surface: summary.review_surface.clone(),
        program_family_owner: summary.program_family_owner.clone(),
        shared_review_owner: summary.shared_review_owner.clone(),
        portfolio_claim_discipline_owner: summary.portfolio_claim_discipline_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        program_family: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury program-family validation package exported");
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
            "program_family_owner:               {}",
            report.program_family_owner
        );
        println!(
            "shared_review_owner:                {}",
            report.shared_review_owner
        );
        println!(
            "portfolio_claim_discipline_owner:   {}",
            report.portfolio_claim_discipline_owner
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
            "program_family_package:             {}",
            report.program_family.program_family_package_file
        );
    }

    Ok(())
}
