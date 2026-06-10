use super::*;

struct TempStage {
    path: PathBuf,
}

impl TempStage {
    fn new(prefix: &str) -> Self {
        Self {
            path: unique_temp_dir(prefix),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempStage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryPortfolioRevenueBoundaryDocRefs {
    portfolio_revenue_boundary_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryRevenueBoundaryFreeze {
    schema: String,
    workflow_id: String,
    program_motion: String,
    review_surface: String,
    commercial_boundary_label: String,
    entry_gates: Vec<String>,
    non_goals: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryRevenueBoundaryManifest {
    schema: String,
    workflow_id: String,
    program_motion: String,
    review_surface: String,
    program_family_package_file: String,
    program_family_boundary_freeze_file: String,
    program_family_manifest_file: String,
    shared_review_summary_file: String,
    shared_review_approval_file: String,
    portfolio_claim_discipline_file: String,
    family_handoff_file: String,
    third_program_package_file: String,
    proof_package_file: String,
    inquiry_package_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryCommercialReviewSummary {
    schema: String,
    workflow_id: String,
    revenue_boundary_owner: String,
    commercial_review_owner: String,
    channel_boundary_owner: String,
    program_motion: String,
    review_surface: String,
    approved_claims: Vec<String>,
    evidence_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryCommercialApproval {
    schema: String,
    workflow_id: String,
    commercial_review_owner: String,
    status: String,
    reviewed_at: u64,
    reviewed_by: String,
    approved_claims: Vec<String>,
    required_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryChannelBoundaryRules {
    schema: String,
    workflow_id: String,
    revenue_boundary_owner: String,
    commercial_review_owner: String,
    channel_boundary_owner: String,
    program_motion: String,
    review_surface: String,
    approved_scope: String,
    permitted_claims: Vec<String>,
    blocked_claims: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryCommercialHandoff {
    schema: String,
    workflow_id: String,
    revenue_boundary_owner: String,
    commercial_review_owner: String,
    channel_boundary_owner: String,
    program_motion: String,
    review_surface: String,
    approved_scope: String,
    required_evidence: Vec<String>,
    deferred_requests: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryPortfolioRevenueBoundaryExportSummary {
    workflow_id: String,
    program_motion: String,
    review_surface: String,
    revenue_boundary_owner: String,
    commercial_review_owner: String,
    channel_boundary_owner: String,
    program_family_dir: String,
    portfolio_revenue_boundary_profile_file: String,
    portfolio_revenue_boundary_package_file: String,
    revenue_boundary_freeze_file: String,
    revenue_boundary_manifest_file: String,
    commercial_review_summary_file: String,
    commercial_approval_file: String,
    channel_boundary_rules_file: String,
    commercial_handoff_file: String,
    commercial_review_evidence_dir: String,
    program_family_package_file: String,
    program_family_boundary_freeze_file: String,
    program_family_manifest_file: String,
    shared_review_summary_file: String,
    shared_review_approval_file: String,
    portfolio_claim_discipline_file: String,
    family_handoff_file: String,
    third_program_package_file: String,
    proof_package_file: String,
    inquiry_package_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryPortfolioRevenueBoundaryDecisionRecord {
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
struct MercuryPortfolioRevenueBoundaryValidationReport {
    workflow_id: String,
    decision: String,
    program_motion: String,
    review_surface: String,
    revenue_boundary_owner: String,
    commercial_review_owner: String,
    channel_boundary_owner: String,
    same_workflow_boundary: String,
    portfolio_revenue_boundary: MercuryPortfolioRevenueBoundaryExportSummary,
    decision_record_file: String,
    docs: MercuryPortfolioRevenueBoundaryDocRefs,
}

fn portfolio_revenue_boundary_doc_refs() -> MercuryPortfolioRevenueBoundaryDocRefs {
    MercuryPortfolioRevenueBoundaryDocRefs {
        portfolio_revenue_boundary_file: "docs/mercury/PORTFOLIO_REVENUE_BOUNDARY.md".to_string(),
        operations_file: "docs/mercury/PORTFOLIO_REVENUE_BOUNDARY_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/PORTFOLIO_REVENUE_BOUNDARY_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/PORTFOLIO_REVENUE_BOUNDARY_DECISION_RECORD.md"
            .to_string(),
    }
}

fn build_portfolio_revenue_boundary_profile(
    workflow_id: &str,
) -> Result<MercuryPortfolioRevenueBoundaryProfile, CliError> {
    let profile = MercuryPortfolioRevenueBoundaryProfile {
        schema: MERCURY_PORTFOLIO_REVENUE_BOUNDARY_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "portfolio-revenue-boundary-commercial-review-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        program_motion: MercuryPortfolioRevenueBoundaryMotion::PortfolioRevenueBoundary,
        review_surface: MercuryPortfolioRevenueBoundarySurface::CommercialReviewBundle,
        approval_gate: "evidence_backed_portfolio_revenue_boundary_only".to_string(),
        retained_artifact_policy:
            "retain-bounded-portfolio-revenue-boundary-and-commercial-review-artifacts"
                .to_string(),
        intended_use: "Qualify one bounded Mercury portfolio revenue boundary through one commercial_review_bundle rooted in the validated program-family chain without widening into generic revenue-platform tooling, billing systems, channel programs, or Chio commercial surfaces.".to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

fn export_portfolio_revenue_boundary(
    output: &Path,
) -> Result<MercuryPortfolioRevenueBoundaryExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let program_family_stage = TempStage::new("chio-mercury-portfolio-revenue-stage");
    let program_family = export_program_family(program_family_stage.path())?;
    let workflow_id = program_family.workflow_id.clone();

    let program_family_dir = output.join("program-family");
    fs::create_dir_all(&program_family_dir)?;
    let program_family_package_copy = program_family_dir.join("program-family-package.json");
    copy_file(
        Path::new(&program_family.program_family_package_file),
        &program_family_package_copy,
    )?;

    let profile = build_portfolio_revenue_boundary_profile(&workflow_id)?;
    let profile_path = output.join("portfolio-revenue-boundary-profile.json");
    write_json_file(&profile_path, &profile)?;

    let commercial_review_evidence_dir = output.join("commercial-review-evidence");
    fs::create_dir_all(&commercial_review_evidence_dir)?;

    let program_family_package_path =
        commercial_review_evidence_dir.join("program-family-package.json");
    let program_family_boundary_freeze_path =
        commercial_review_evidence_dir.join("program-family-boundary-freeze.json");
    let program_family_manifest_path =
        commercial_review_evidence_dir.join("program-family-manifest.json");
    let shared_review_summary_path =
        commercial_review_evidence_dir.join("shared-review-summary.json");
    let shared_review_approval_path =
        commercial_review_evidence_dir.join("shared-review-approval.json");
    let portfolio_claim_discipline_path =
        commercial_review_evidence_dir.join("portfolio-claim-discipline.json");
    let family_handoff_path = commercial_review_evidence_dir.join("family-handoff.json");
    let third_program_package_path =
        commercial_review_evidence_dir.join("third-program-package.json");
    let proof_package_path = commercial_review_evidence_dir.join("proof-package.json");
    let inquiry_package_path = commercial_review_evidence_dir.join("inquiry-package.json");
    let reviewer_package_path = commercial_review_evidence_dir.join("reviewer-package.json");
    let qualification_report_path =
        commercial_review_evidence_dir.join("qualification-report.json");

    copy_file(
        Path::new(&program_family.program_family_package_file),
        &program_family_package_path,
    )?;
    copy_file(
        Path::new(&program_family.program_family_boundary_freeze_file),
        &program_family_boundary_freeze_path,
    )?;
    copy_file(
        Path::new(&program_family.program_family_manifest_file),
        &program_family_manifest_path,
    )?;
    copy_file(
        Path::new(&program_family.shared_review_summary_file),
        &shared_review_summary_path,
    )?;
    copy_file(
        Path::new(&program_family.shared_review_approval_file),
        &shared_review_approval_path,
    )?;
    copy_file(
        Path::new(&program_family.portfolio_claim_discipline_file),
        &portfolio_claim_discipline_path,
    )?;
    copy_file(
        Path::new(&program_family.family_handoff_file),
        &family_handoff_path,
    )?;
    copy_file(
        Path::new(&program_family.third_program_package_file),
        &third_program_package_path,
    )?;
    copy_file(
        Path::new(&program_family.proof_package_file),
        &proof_package_path,
    )?;
    copy_file(
        Path::new(&program_family.inquiry_package_file),
        &inquiry_package_path,
    )?;
    copy_file(
        Path::new(&program_family.reviewer_package_file),
        &reviewer_package_path,
    )?;
    copy_file(
        Path::new(&program_family.qualification_report_file),
        &qualification_report_path,
    )?;

    let approved_claim = "Mercury can qualify one bounded portfolio revenue boundary through one portfolio_revenue_boundary motion using one commercial_review_bundle rooted in the validated program-family chain."
        .to_string();

    let revenue_boundary_freeze = MercuryRevenueBoundaryFreeze {
        schema: "chio.mercury.portfolio_revenue_boundary_freeze.v1".to_string(),
        workflow_id: workflow_id.clone(),
        program_motion: MercuryPortfolioRevenueBoundaryMotion::PortfolioRevenueBoundary
            .as_str()
            .to_string(),
        review_surface: MercuryPortfolioRevenueBoundarySurface::CommercialReviewBundle
            .as_str()
            .to_string(),
        commercial_boundary_label:
            "one bounded Mercury portfolio-revenue-boundary lane over one named commercial handoff only"
                .to_string(),
        entry_gates: vec![
            "program-family package, shared-review approval, claim discipline, and handoff remain current".to_string(),
            "commercial review stays inside one named revenue boundary".to_string(),
            "proof, inquiry, reviewer, and qualification artifacts remain available".to_string(),
        ],
        non_goals: vec![
            "generic revenue-platform or billing tooling".to_string(),
            "channel-program automation".to_string(),
            "Chio-side commercial controls or merged shells".to_string(),
        ],
        note: "This freeze allows one bounded commercial handoff proof point only.".to_string(),
    };
    let revenue_boundary_freeze_path = output.join("revenue-boundary-freeze.json");
    write_json_file(&revenue_boundary_freeze_path, &revenue_boundary_freeze)?;

    let revenue_boundary_manifest = MercuryRevenueBoundaryManifest {
        schema: "chio.mercury.portfolio_revenue_boundary_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        program_motion: MercuryPortfolioRevenueBoundaryMotion::PortfolioRevenueBoundary
            .as_str()
            .to_string(),
        review_surface: MercuryPortfolioRevenueBoundarySurface::CommercialReviewBundle
            .as_str()
            .to_string(),
        program_family_package_file: relative_display(output, &program_family_package_path)?,
        program_family_boundary_freeze_file: relative_display(
            output,
            &program_family_boundary_freeze_path,
        )?,
        program_family_manifest_file: relative_display(output, &program_family_manifest_path)?,
        shared_review_summary_file: relative_display(output, &shared_review_summary_path)?,
        shared_review_approval_file: relative_display(output, &shared_review_approval_path)?,
        portfolio_claim_discipline_file: relative_display(
            output,
            &portfolio_claim_discipline_path,
        )?,
        family_handoff_file: relative_display(output, &family_handoff_path)?,
        third_program_package_file: relative_display(output, &third_program_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        note: "Portfolio-revenue-boundary packaging stays rooted in the validated program-family chain.".to_string(),
    };
    let revenue_boundary_manifest_path = output.join("revenue-boundary-manifest.json");
    write_json_file(&revenue_boundary_manifest_path, &revenue_boundary_manifest)?;

    let commercial_review_summary = MercuryCommercialReviewSummary {
        schema: "chio.mercury.portfolio_revenue_boundary_commercial_review_summary.v1".to_string(),
        workflow_id: workflow_id.clone(),
        revenue_boundary_owner: MERCURY_PORTFOLIO_REVENUE_BOUNDARY_OWNER.to_string(),
        commercial_review_owner: MERCURY_COMMERCIAL_REVIEW_OWNER.to_string(),
        channel_boundary_owner: MERCURY_CHANNEL_BOUNDARY_OWNER.to_string(),
        program_motion: MercuryPortfolioRevenueBoundaryMotion::PortfolioRevenueBoundary
            .as_str()
            .to_string(),
        review_surface: MercuryPortfolioRevenueBoundarySurface::CommercialReviewBundle
            .as_str()
            .to_string(),
        approved_claims: vec![approved_claim.clone()],
        evidence_files: vec![
            relative_display(output, &revenue_boundary_manifest_path)?,
            relative_display(output, &program_family_package_path)?,
            relative_display(output, &shared_review_summary_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
        ],
        note: "Commercial review stays bounded to one evidence-backed revenue boundary only."
            .to_string(),
    };
    let commercial_review_summary_path = output.join("commercial-review-summary.json");
    write_json_file(&commercial_review_summary_path, &commercial_review_summary)?;

    let commercial_approval = MercuryCommercialApproval {
        schema: "chio.mercury.portfolio_revenue_boundary_commercial_approval.v1".to_string(),
        workflow_id: workflow_id.clone(),
        commercial_review_owner: MERCURY_COMMERCIAL_REVIEW_OWNER.to_string(),
        status: "ready".to_string(),
        reviewed_at: unix_now(),
        reviewed_by: MERCURY_COMMERCIAL_REVIEW_OWNER.to_string(),
        approved_claims: vec![approved_claim.clone()],
        required_files: vec![
            relative_display(output, &revenue_boundary_freeze_path)?,
            relative_display(output, &revenue_boundary_manifest_path)?,
            relative_display(output, &program_family_package_path)?,
            relative_display(output, &proof_package_path)?,
        ],
        note: "Commercial approval is required before Mercury can assert one bounded revenue boundary.".to_string(),
    };
    let commercial_approval_path = output.join("commercial-approval.json");
    write_json_file(&commercial_approval_path, &commercial_approval)?;

    let channel_boundary_rules = MercuryChannelBoundaryRules {
        schema: "chio.mercury.portfolio_revenue_boundary_channel_boundary_rules.v1"
            .to_string(),
        workflow_id: workflow_id.clone(),
        revenue_boundary_owner: MERCURY_PORTFOLIO_REVENUE_BOUNDARY_OWNER.to_string(),
        commercial_review_owner: MERCURY_COMMERCIAL_REVIEW_OWNER.to_string(),
        channel_boundary_owner: MERCURY_CHANNEL_BOUNDARY_OWNER.to_string(),
        program_motion: MercuryPortfolioRevenueBoundaryMotion::PortfolioRevenueBoundary
            .as_str()
            .to_string(),
        review_surface: MercuryPortfolioRevenueBoundarySurface::CommercialReviewBundle
            .as_str()
            .to_string(),
        approved_scope:
            "one bounded commercial review bundle over one named portfolio revenue boundary only"
                .to_string(),
        permitted_claims: vec![
            "one evidence-backed commercial handoff rooted in the program-family chain".to_string(),
            "one named revenue boundary with explicit handoff ownership".to_string(),
        ],
        blocked_claims: vec![
            "generic revenue platforms, forecasting stacks, or billing systems".to_string(),
            "channel-program automation or marketplaces".to_string(),
            "Chio-side commercial consoles or merged product shells".to_string(),
        ],
        note: "Channel boundary rules prevent the commercial handoff from widening into a general channel or revenue platform.".to_string(),
    };
    let channel_boundary_rules_path = output.join("channel-boundary-rules.json");
    write_json_file(&channel_boundary_rules_path, &channel_boundary_rules)?;

    let commercial_handoff = MercuryCommercialHandoff {
        schema: "chio.mercury.portfolio_revenue_boundary_commercial_handoff.v1".to_string(),
        workflow_id: workflow_id.clone(),
        revenue_boundary_owner: MERCURY_PORTFOLIO_REVENUE_BOUNDARY_OWNER.to_string(),
        commercial_review_owner: MERCURY_COMMERCIAL_REVIEW_OWNER.to_string(),
        channel_boundary_owner: MERCURY_CHANNEL_BOUNDARY_OWNER.to_string(),
        program_motion: MercuryPortfolioRevenueBoundaryMotion::PortfolioRevenueBoundary
            .as_str()
            .to_string(),
        review_surface: MercuryPortfolioRevenueBoundarySurface::CommercialReviewBundle
            .as_str()
            .to_string(),
        approved_scope:
            "one bounded portfolio-revenue-boundary lane over the validated program-family chain only"
                .to_string(),
        required_evidence: vec![
            relative_display(output, &revenue_boundary_manifest_path)?,
            relative_display(output, &commercial_review_summary_path)?,
            relative_display(output, &commercial_approval_path)?,
            relative_display(output, &channel_boundary_rules_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
        ],
        deferred_requests: vec![
            "generic revenue-platform, forecasting, or billing tooling".to_string(),
            "channel-program automation or marketplaces".to_string(),
            "Chio-side commercial controls or merged shells".to_string(),
        ],
        note: "Commercial handoff stays bounded to one named revenue boundary and one explicit handoff only.".to_string(),
    };
    let commercial_handoff_path = output.join("commercial-handoff.json");
    write_json_file(&commercial_handoff_path, &commercial_handoff)?;

    let package = MercuryPortfolioRevenueBoundaryPackage {
        schema: MERCURY_PORTFOLIO_REVENUE_BOUNDARY_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "portfolio-revenue-boundary-commercial-review-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        program_motion: MercuryPortfolioRevenueBoundaryMotion::PortfolioRevenueBoundary,
        review_surface: MercuryPortfolioRevenueBoundarySurface::CommercialReviewBundle,
        revenue_boundary_owner: MERCURY_PORTFOLIO_REVENUE_BOUNDARY_OWNER.to_string(),
        commercial_review_owner: MERCURY_COMMERCIAL_REVIEW_OWNER.to_string(),
        channel_boundary_owner: MERCURY_CHANNEL_BOUNDARY_OWNER.to_string(),
        commercial_approval_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        program_family_package_file: relative_display(output, &program_family_package_path)?,
        program_family_boundary_freeze_file: relative_display(
            output,
            &program_family_boundary_freeze_path,
        )?,
        program_family_manifest_file: relative_display(output, &program_family_manifest_path)?,
        shared_review_summary_file: relative_display(output, &shared_review_summary_path)?,
        shared_review_approval_file: relative_display(output, &shared_review_approval_path)?,
        portfolio_claim_discipline_file: relative_display(
            output,
            &portfolio_claim_discipline_path,
        )?,
        family_handoff_file: relative_display(output, &family_handoff_path)?,
        third_program_package_file: relative_display(output, &third_program_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        artifacts: vec![
            MercuryPortfolioRevenueBoundaryArtifact {
                artifact_kind: MercuryPortfolioRevenueBoundaryArtifactKind::RevenueBoundaryFreeze,
                relative_path: relative_display(output, &revenue_boundary_freeze_path)?,
            },
            MercuryPortfolioRevenueBoundaryArtifact {
                artifact_kind: MercuryPortfolioRevenueBoundaryArtifactKind::RevenueBoundaryManifest,
                relative_path: relative_display(output, &revenue_boundary_manifest_path)?,
            },
            MercuryPortfolioRevenueBoundaryArtifact {
                artifact_kind: MercuryPortfolioRevenueBoundaryArtifactKind::CommercialReviewSummary,
                relative_path: relative_display(output, &commercial_review_summary_path)?,
            },
            MercuryPortfolioRevenueBoundaryArtifact {
                artifact_kind: MercuryPortfolioRevenueBoundaryArtifactKind::CommercialApproval,
                relative_path: relative_display(output, &commercial_approval_path)?,
            },
            MercuryPortfolioRevenueBoundaryArtifact {
                artifact_kind: MercuryPortfolioRevenueBoundaryArtifactKind::ChannelBoundaryRules,
                relative_path: relative_display(output, &channel_boundary_rules_path)?,
            },
            MercuryPortfolioRevenueBoundaryArtifact {
                artifact_kind: MercuryPortfolioRevenueBoundaryArtifactKind::CommercialHandoff,
                relative_path: relative_display(output, &commercial_handoff_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("portfolio-revenue-boundary-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryPortfolioRevenueBoundaryExportSummary {
        workflow_id,
        program_motion: MercuryPortfolioRevenueBoundaryMotion::PortfolioRevenueBoundary
            .as_str()
            .to_string(),
        review_surface: MercuryPortfolioRevenueBoundarySurface::CommercialReviewBundle
            .as_str()
            .to_string(),
        revenue_boundary_owner: MERCURY_PORTFOLIO_REVENUE_BOUNDARY_OWNER.to_string(),
        commercial_review_owner: MERCURY_COMMERCIAL_REVIEW_OWNER.to_string(),
        channel_boundary_owner: MERCURY_CHANNEL_BOUNDARY_OWNER.to_string(),
        program_family_dir: program_family_dir.display().to_string(),
        portfolio_revenue_boundary_profile_file: profile_path.display().to_string(),
        portfolio_revenue_boundary_package_file: package_path.display().to_string(),
        revenue_boundary_freeze_file: revenue_boundary_freeze_path.display().to_string(),
        revenue_boundary_manifest_file: revenue_boundary_manifest_path.display().to_string(),
        commercial_review_summary_file: commercial_review_summary_path.display().to_string(),
        commercial_approval_file: commercial_approval_path.display().to_string(),
        channel_boundary_rules_file: channel_boundary_rules_path.display().to_string(),
        commercial_handoff_file: commercial_handoff_path.display().to_string(),
        commercial_review_evidence_dir: commercial_review_evidence_dir.display().to_string(),
        program_family_package_file: program_family_package_path.display().to_string(),
        program_family_boundary_freeze_file: program_family_boundary_freeze_path
            .display()
            .to_string(),
        program_family_manifest_file: program_family_manifest_path.display().to_string(),
        shared_review_summary_file: shared_review_summary_path.display().to_string(),
        shared_review_approval_file: shared_review_approval_path.display().to_string(),
        portfolio_claim_discipline_file: portfolio_claim_discipline_path.display().to_string(),
        family_handoff_file: family_handoff_path.display().to_string(),
        third_program_package_file: third_program_package_path.display().to_string(),
        proof_package_file: proof_package_path.display().to_string(),
        inquiry_package_file: inquiry_package_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
    };
    write_json_file(
        &output.join("portfolio-revenue-boundary-summary.json"),
        &summary,
    )?;

    Ok(summary)
}

fn print_export_summary(summary: &MercuryPortfolioRevenueBoundaryExportSummary, output: &Path) {
    println!("mercury portfolio-revenue-boundary package exported");
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
        "revenue_boundary_owner:             {}",
        summary.revenue_boundary_owner
    );
    println!(
        "commercial_review_owner:            {}",
        summary.commercial_review_owner
    );
    println!(
        "channel_boundary_owner:             {}",
        summary.channel_boundary_owner
    );
    println!(
        "portfolio_revenue_boundary_package: {}",
        summary.portfolio_revenue_boundary_package_file
    );
    println!(
        "commercial_approval:                {}",
        summary.commercial_approval_file
    );
}

fn print_validation_summary(
    report: &MercuryPortfolioRevenueBoundaryValidationReport,
    validation_report_file: &Path,
    decision_record_file: &Path,
    output: &Path,
) {
    println!("mercury portfolio-revenue-boundary validation package exported");
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
        "revenue_boundary_owner:             {}",
        report.revenue_boundary_owner
    );
    println!(
        "commercial_review_owner:            {}",
        report.commercial_review_owner
    );
    println!(
        "channel_boundary_owner:             {}",
        report.channel_boundary_owner
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
        "portfolio_revenue_boundary_package: {}",
        report
            .portfolio_revenue_boundary
            .portfolio_revenue_boundary_package_file
    );
}

pub fn cmd_mercury_portfolio_revenue_boundary_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_portfolio_revenue_boundary(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        print_export_summary(&summary, output);
    }

    Ok(())
}

pub fn cmd_mercury_portfolio_revenue_boundary_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let revenue_boundary_dir = output.join("portfolio-revenue-boundary");
    let summary = export_portfolio_revenue_boundary(&revenue_boundary_dir)?;
    let docs = portfolio_revenue_boundary_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryPortfolioRevenueBoundaryDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_PORTFOLIO_REVENUE_BOUNDARY_DECISION.to_string(),
        selected_program_motion: summary.program_motion.clone(),
        selected_review_surface: summary.review_surface.clone(),
        approved_scope:
            "Proceed with one bounded Mercury portfolio-revenue-boundary lane only.".to_string(),
        deferred_scope: vec![
            "generic revenue platforms, forecasting stacks, or billing systems".to_string(),
            "channel-program automation or marketplaces".to_string(),
            "Chio-side commercial consoles or merged shells".to_string(),
        ],
        rationale: "The portfolio-revenue-boundary lane packages one bounded commercial review surface, one commercial approval, one channel-boundary-rules artifact, and one commercial handoff over the validated program-family chain without widening Mercury into a generic revenue or channel platform.".to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("portfolio-revenue-boundary-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryPortfolioRevenueBoundaryValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_PORTFOLIO_REVENUE_BOUNDARY_DECISION.to_string(),
        program_motion: summary.program_motion.clone(),
        review_surface: summary.review_surface.clone(),
        revenue_boundary_owner: summary.revenue_boundary_owner.clone(),
        commercial_review_owner: summary.commercial_review_owner.clone(),
        channel_boundary_owner: summary.channel_boundary_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        portfolio_revenue_boundary: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_validation_summary(
            &report,
            &validation_report_file,
            &decision_record_file,
            output,
        );
    }

    Ok(())
}
