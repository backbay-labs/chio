use super::*;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryPortfolioProgramDocRefs {
    portfolio_program_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryPortfolioProgramBoundaryFreeze {
    schema: String,
    workflow_id: String,
    program_motion: String,
    review_surface: String,
    multi_account_boundary_label: String,
    entry_gates: Vec<String>,
    non_goals: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryPortfolioProgramManifest {
    schema: String,
    workflow_id: String,
    program_motion: String,
    review_surface: String,
    second_account_expansion_package_file: String,
    second_account_expansion_boundary_freeze_file: String,
    second_account_expansion_manifest_file: String,
    second_account_portfolio_review_summary_file: String,
    second_account_expansion_approval_file: String,
    second_account_reuse_governance_file: String,
    second_account_handoff_file: String,
    renewal_qualification_package_file: String,
    renewal_boundary_freeze_file: String,
    renewal_qualification_manifest_file: String,
    outcome_review_summary_file: String,
    renewal_approval_file: String,
    reference_reuse_discipline_file: String,
    expansion_boundary_handoff_file: String,
    delivery_continuity_package_file: String,
    account_boundary_freeze_file: String,
    delivery_continuity_manifest_file: String,
    outcome_evidence_summary_file: String,
    renewal_gate_file: String,
    delivery_escalation_brief_file: String,
    customer_evidence_handoff_file: String,
    selective_account_activation_package_file: String,
    broader_distribution_package_file: String,
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
struct MercuryProgramReviewSummary {
    schema: String,
    workflow_id: String,
    program_owner: String,
    review_owner: String,
    revenue_operations_guardrails_owner: String,
    program_motion: String,
    review_surface: String,
    approved_claims: Vec<String>,
    evidence_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryPortfolioApproval {
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
struct MercuryRevenueOperationsGuardrails {
    schema: String,
    workflow_id: String,
    program_owner: String,
    review_owner: String,
    revenue_operations_guardrails_owner: String,
    program_motion: String,
    review_surface: String,
    approved_scope: String,
    permitted_reuse: Vec<String>,
    blocked_reuse: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryProgramHandoff {
    schema: String,
    workflow_id: String,
    program_owner: String,
    review_owner: String,
    revenue_operations_guardrails_owner: String,
    program_motion: String,
    review_surface: String,
    approved_scope: String,
    required_evidence: Vec<String>,
    deferred_requests: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MercuryPortfolioProgramExportSummary {
    pub(super) workflow_id: String,
    pub(super) program_motion: String,
    pub(super) review_surface: String,
    pub(super) program_owner: String,
    pub(super) program_review_owner: String,
    pub(super) revenue_operations_guardrails_owner: String,
    pub(super) second_account_expansion_dir: String,
    pub(super) portfolio_program_profile_file: String,
    pub(super) portfolio_program_package_file: String,
    pub(super) portfolio_program_boundary_freeze_file: String,
    pub(super) portfolio_program_manifest_file: String,
    pub(super) program_review_summary_file: String,
    pub(super) portfolio_approval_file: String,
    pub(super) revenue_operations_guardrails_file: String,
    pub(super) program_handoff_file: String,
    pub(super) portfolio_evidence_dir: String,
    pub(super) second_account_expansion_package_file: String,
    pub(super) second_account_expansion_boundary_freeze_file: String,
    pub(super) second_account_expansion_manifest_file: String,
    pub(super) second_account_portfolio_review_summary_file: String,
    pub(super) second_account_expansion_approval_file: String,
    pub(super) second_account_reuse_governance_file: String,
    pub(super) second_account_handoff_file: String,
    pub(super) renewal_qualification_package_file: String,
    pub(super) renewal_boundary_freeze_file: String,
    pub(super) renewal_qualification_manifest_file: String,
    pub(super) outcome_review_summary_file: String,
    pub(super) renewal_approval_file: String,
    pub(super) reference_reuse_discipline_file: String,
    pub(super) expansion_boundary_handoff_file: String,
    pub(super) delivery_continuity_package_file: String,
    pub(super) account_boundary_freeze_file: String,
    pub(super) delivery_continuity_manifest_file: String,
    pub(super) outcome_evidence_summary_file: String,
    pub(super) renewal_gate_file: String,
    pub(super) delivery_escalation_brief_file: String,
    pub(super) customer_evidence_handoff_file: String,
    pub(super) selective_account_activation_package_file: String,
    pub(super) broader_distribution_package_file: String,
    pub(super) reference_distribution_package_file: String,
    pub(super) controlled_adoption_package_file: String,
    pub(super) release_readiness_package_file: String,
    pub(super) trust_network_package_file: String,
    pub(super) assurance_suite_package_file: String,
    pub(super) proof_package_file: String,
    pub(super) inquiry_package_file: String,
    pub(super) inquiry_verification_file: String,
    pub(super) reviewer_package_file: String,
    pub(super) qualification_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryPortfolioProgramDecisionRecord {
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
struct MercuryPortfolioProgramValidationReport {
    workflow_id: String,
    decision: String,
    program_motion: String,
    review_surface: String,
    program_owner: String,
    program_review_owner: String,
    revenue_operations_guardrails_owner: String,
    same_workflow_boundary: String,
    portfolio_program: MercuryPortfolioProgramExportSummary,
    decision_record_file: String,
    docs: MercuryPortfolioProgramDocRefs,
}

fn portfolio_program_doc_refs() -> MercuryPortfolioProgramDocRefs {
    MercuryPortfolioProgramDocRefs {
        portfolio_program_file: "docs/mercury/PORTFOLIO_PROGRAM.md".to_string(),
        operations_file: "docs/mercury/PORTFOLIO_PROGRAM_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/PORTFOLIO_PROGRAM_VALIDATION_PACKAGE.md".to_string(),
        decision_record_file: "docs/mercury/PORTFOLIO_PROGRAM_DECISION_RECORD.md".to_string(),
    }
}

fn build_portfolio_program_profile(
    workflow_id: &str,
) -> Result<MercuryPortfolioProgramProfile, CliError> {
    let profile = MercuryPortfolioProgramProfile {
        schema: MERCURY_PORTFOLIO_PROGRAM_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "portfolio-program-program-review-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        program_motion: MercuryPortfolioProgramMotion::PortfolioProgram,
        review_surface: MercuryPortfolioProgramSurface::ProgramReviewBundle,
        approval_gate: "evidence_backed_portfolio_program_only".to_string(),
        retained_artifact_policy:
            "retain-bounded-portfolio-program-and-program-review-artifacts".to_string(),
        intended_use: "Qualify one bounded Mercury portfolio program through one program-review lane rooted in the validated second-account-expansion, renewal-qualification, delivery-continuity, selective-account-activation, broader-distribution, reference-distribution, controlled-adoption, release-readiness, trust-network, assurance, proof, and inquiry chain without widening into generic account-management tooling, revenue operations systems, forecasting or billing platforms, channel programs, or Chio commercial surfaces."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

pub(super) fn export_portfolio_program(
    output: &Path,
) -> Result<MercuryPortfolioProgramExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let second_account_expansion_dir = output.join("second-account-expansion");
    let second_account_expansion = export_second_account_expansion(&second_account_expansion_dir)?;
    let workflow_id = second_account_expansion.workflow_id.clone();

    let profile = build_portfolio_program_profile(&workflow_id)?;
    let profile_path = output.join("portfolio-program-profile.json");
    write_json_file(&profile_path, &profile)?;

    let portfolio_evidence_dir = output.join("portfolio-evidence");
    fs::create_dir_all(&portfolio_evidence_dir)?;

    let second_account_expansion_package_path =
        portfolio_evidence_dir.join("second-account-expansion-package.json");
    let second_account_expansion_boundary_freeze_path =
        portfolio_evidence_dir.join("second-account-portfolio-boundary-freeze.json");
    let second_account_expansion_manifest_path =
        portfolio_evidence_dir.join("second-account-expansion-manifest.json");
    let second_account_portfolio_review_summary_path =
        portfolio_evidence_dir.join("second-account-portfolio-review-summary.json");
    let second_account_expansion_approval_path =
        portfolio_evidence_dir.join("second-account-expansion-approval.json");
    let second_account_reuse_governance_path =
        portfolio_evidence_dir.join("second-account-reuse-governance.json");
    let second_account_handoff_path = portfolio_evidence_dir.join("second-account-handoff.json");
    let renewal_qualification_package_path =
        portfolio_evidence_dir.join("renewal-qualification-package.json");
    let renewal_boundary_freeze_path = portfolio_evidence_dir.join("renewal-boundary-freeze.json");
    let renewal_qualification_manifest_path =
        portfolio_evidence_dir.join("renewal-qualification-manifest.json");
    let outcome_review_summary_path = portfolio_evidence_dir.join("outcome-review-summary.json");
    let renewal_approval_path = portfolio_evidence_dir.join("renewal-approval.json");
    let reference_reuse_discipline_path =
        portfolio_evidence_dir.join("reference-reuse-discipline.json");
    let expansion_boundary_handoff_path =
        portfolio_evidence_dir.join("expansion-boundary-handoff.json");
    let delivery_continuity_package_path =
        portfolio_evidence_dir.join("delivery-continuity-package.json");
    let account_boundary_freeze_path = portfolio_evidence_dir.join("account-boundary-freeze.json");
    let delivery_continuity_manifest_path =
        portfolio_evidence_dir.join("delivery-continuity-manifest.json");
    let outcome_evidence_summary_path =
        portfolio_evidence_dir.join("outcome-evidence-summary.json");
    let renewal_gate_path = portfolio_evidence_dir.join("renewal-gate.json");
    let delivery_escalation_brief_path =
        portfolio_evidence_dir.join("delivery-escalation-brief.json");
    let customer_evidence_handoff_path =
        portfolio_evidence_dir.join("customer-evidence-handoff.json");
    let selective_account_activation_package_path =
        portfolio_evidence_dir.join("selective-account-activation-package.json");
    let broader_distribution_package_path =
        portfolio_evidence_dir.join("broader-distribution-package.json");
    let reference_distribution_package_path =
        portfolio_evidence_dir.join("reference-distribution-package.json");
    let controlled_adoption_package_path =
        portfolio_evidence_dir.join("controlled-adoption-package.json");
    let release_readiness_package_path =
        portfolio_evidence_dir.join("release-readiness-package.json");
    let trust_network_package_path = portfolio_evidence_dir.join("trust-network-package.json");
    let assurance_suite_package_path = portfolio_evidence_dir.join("assurance-suite-package.json");
    let proof_package_path = portfolio_evidence_dir.join("proof-package.json");
    let inquiry_package_path = portfolio_evidence_dir.join("inquiry-package.json");
    let inquiry_verification_path = portfolio_evidence_dir.join("inquiry-verification.json");
    let reviewer_package_path = portfolio_evidence_dir.join("reviewer-package.json");
    let qualification_report_path = portfolio_evidence_dir.join("qualification-report.json");

    copy_file(
        Path::new(&second_account_expansion.second_account_expansion_package_file),
        &second_account_expansion_package_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.portfolio_boundary_freeze_file),
        &second_account_expansion_boundary_freeze_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.second_account_expansion_manifest_file),
        &second_account_expansion_manifest_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.portfolio_review_summary_file),
        &second_account_portfolio_review_summary_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.expansion_approval_file),
        &second_account_expansion_approval_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.reuse_governance_file),
        &second_account_reuse_governance_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.second_account_handoff_file),
        &second_account_handoff_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.renewal_qualification_package_file),
        &renewal_qualification_package_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.renewal_boundary_freeze_file),
        &renewal_boundary_freeze_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.renewal_qualification_manifest_file),
        &renewal_qualification_manifest_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.outcome_review_summary_file),
        &outcome_review_summary_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.renewal_approval_file),
        &renewal_approval_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.reference_reuse_discipline_file),
        &reference_reuse_discipline_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.expansion_boundary_handoff_file),
        &expansion_boundary_handoff_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.delivery_continuity_package_file),
        &delivery_continuity_package_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.account_boundary_freeze_file),
        &account_boundary_freeze_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.delivery_continuity_manifest_file),
        &delivery_continuity_manifest_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.outcome_evidence_summary_file),
        &outcome_evidence_summary_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.renewal_gate_file),
        &renewal_gate_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.delivery_escalation_brief_file),
        &delivery_escalation_brief_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.customer_evidence_handoff_file),
        &customer_evidence_handoff_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.selective_account_activation_package_file),
        &selective_account_activation_package_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.broader_distribution_package_file),
        &broader_distribution_package_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.reference_distribution_package_file),
        &reference_distribution_package_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.controlled_adoption_package_file),
        &controlled_adoption_package_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.release_readiness_package_file),
        &release_readiness_package_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.trust_network_package_file),
        &trust_network_package_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.assurance_suite_package_file),
        &assurance_suite_package_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.proof_package_file),
        &proof_package_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.inquiry_package_file),
        &inquiry_package_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.inquiry_verification_file),
        &inquiry_verification_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.reviewer_package_file),
        &reviewer_package_path,
    )?;
    copy_file(
        Path::new(&second_account_expansion.qualification_report_file),
        &qualification_report_path,
    )?;

    let approved_claim = "Mercury can qualify one bounded portfolio program through one portfolio_program motion using one program_review_bundle rooted in the validated second-account-expansion, renewal-qualification, delivery-continuity, selective-account-activation, broader-distribution, reference-distribution, controlled-adoption, release-readiness, trust-network, assurance, proof, and inquiry chain."
        .to_string();

    let portfolio_program_boundary_freeze = MercuryPortfolioProgramBoundaryFreeze {
        schema: "chio.mercury.portfolio_program_boundary_freeze.v1".to_string(),
        workflow_id: workflow_id.clone(),
        program_motion: MercuryPortfolioProgramMotion::PortfolioProgram
            .as_str()
            .to_string(),
        review_surface: MercuryPortfolioProgramSurface::ProgramReviewBundle
            .as_str()
            .to_string(),
        multi_account_boundary_label:
            "one bounded Mercury portfolio-program lane over one reviewed multi-account program only"
                .to_string(),
        entry_gates: vec![
            "second-account-expansion package, expansion approval, reuse governance, and second-account handoff remain current for the same workflow".to_string(),
            "portfolio program stays inside one program motion and one program-review bundle rooted in the existing Mercury evidence chain".to_string(),
            "portfolio approval, revenue-operations guardrails, and program handoff are present before any portfolio-program claim is reused".to_string(),
        ],
        non_goals: vec![
            "generic account-management tooling, CRM workflows, or customer-success suites"
                .to_string(),
            "revenue operations systems, forecasting stacks, billing platforms, or channel programs"
                .to_string(),
            "Chio-side commercial control surfaces or merged product shells".to_string(),
        ],
        note: "This freeze keeps the next Mercury step bounded to one portfolio-program motion over the validated second-account-expansion chain only."
            .to_string(),
    };
    let portfolio_program_boundary_freeze_path =
        output.join("portfolio-program-boundary-freeze.json");
    write_json_file(
        &portfolio_program_boundary_freeze_path,
        &portfolio_program_boundary_freeze,
    )?;

    let portfolio_program_manifest = MercuryPortfolioProgramManifest {
        schema: "chio.mercury.portfolio_program_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        program_motion: MercuryPortfolioProgramMotion::PortfolioProgram
            .as_str()
            .to_string(),
        review_surface: MercuryPortfolioProgramSurface::ProgramReviewBundle
            .as_str()
            .to_string(),
        second_account_expansion_package_file: relative_display(
            output,
            &second_account_expansion_package_path,
        )?,
        second_account_expansion_boundary_freeze_file: relative_display(
            output,
            &second_account_expansion_boundary_freeze_path,
        )?,
        second_account_expansion_manifest_file: relative_display(
            output,
            &second_account_expansion_manifest_path,
        )?,
        second_account_portfolio_review_summary_file: relative_display(
            output,
            &second_account_portfolio_review_summary_path,
        )?,
        second_account_expansion_approval_file: relative_display(
            output,
            &second_account_expansion_approval_path,
        )?,
        second_account_reuse_governance_file: relative_display(
            output,
            &second_account_reuse_governance_path,
        )?,
        second_account_handoff_file: relative_display(output, &second_account_handoff_path)?,
        renewal_qualification_package_file: relative_display(
            output,
            &renewal_qualification_package_path,
        )?,
        renewal_boundary_freeze_file: relative_display(output, &renewal_boundary_freeze_path)?,
        renewal_qualification_manifest_file: relative_display(
            output,
            &renewal_qualification_manifest_path,
        )?,
        outcome_review_summary_file: relative_display(output, &outcome_review_summary_path)?,
        renewal_approval_file: relative_display(output, &renewal_approval_path)?,
        reference_reuse_discipline_file: relative_display(
            output,
            &reference_reuse_discipline_path,
        )?,
        expansion_boundary_handoff_file: relative_display(
            output,
            &expansion_boundary_handoff_path,
        )?,
        delivery_continuity_package_file: relative_display(
            output,
            &delivery_continuity_package_path,
        )?,
        account_boundary_freeze_file: relative_display(output, &account_boundary_freeze_path)?,
        delivery_continuity_manifest_file: relative_display(
            output,
            &delivery_continuity_manifest_path,
        )?,
        outcome_evidence_summary_file: relative_display(output, &outcome_evidence_summary_path)?,
        renewal_gate_file: relative_display(output, &renewal_gate_path)?,
        delivery_escalation_brief_file: relative_display(
            output,
            &delivery_escalation_brief_path,
        )?,
        customer_evidence_handoff_file: relative_display(
            output,
            &customer_evidence_handoff_path,
        )?,
        selective_account_activation_package_file: relative_display(
            output,
            &selective_account_activation_package_path,
        )?,
        broader_distribution_package_file: relative_display(
            output,
            &broader_distribution_package_path,
        )?,
        reference_distribution_package_file: relative_display(
            output,
            &reference_distribution_package_path,
        )?,
        controlled_adoption_package_file: relative_display(
            output,
            &controlled_adoption_package_path,
        )?,
        release_readiness_package_file: relative_display(
            output,
            &release_readiness_package_path,
        )?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        inquiry_verification_file: relative_display(output, &inquiry_verification_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        note: "This manifest freezes one program-review bundle over the second-account-expansion and prior Mercury evidence chain and does not imply a generic account-management platform, revenue operations system, channel program, or Chio commercial console."
            .to_string(),
    };
    let portfolio_program_manifest_path = output.join("portfolio-program-manifest.json");
    write_json_file(
        &portfolio_program_manifest_path,
        &portfolio_program_manifest,
    )?;

    let program_review_summary = MercuryProgramReviewSummary {
        schema: "chio.mercury.portfolio_program_program_review_summary.v1".to_string(),
        workflow_id: workflow_id.clone(),
        program_owner: MERCURY_PORTFOLIO_PROGRAM_OWNER.to_string(),
        review_owner: MERCURY_PROGRAM_REVIEW_OWNER.to_string(),
        revenue_operations_guardrails_owner:
            MERCURY_REVENUE_OPERATIONS_GUARDRAILS_OWNER.to_string(),
        program_motion: MercuryPortfolioProgramMotion::PortfolioProgram
            .as_str()
            .to_string(),
        review_surface: MercuryPortfolioProgramSurface::ProgramReviewBundle
            .as_str()
            .to_string(),
        approved_claims: vec![
            approved_claim.clone(),
            "The portfolio-program bundle remains bounded to one portfolio_program motion, one program_review_bundle surface, and one explicit revenue-operations-guardrails handoff."
                .to_string(),
        ],
        evidence_files: vec![
            relative_display(output, &second_account_expansion_package_path)?,
            relative_display(output, &second_account_portfolio_review_summary_path)?,
            relative_display(output, &second_account_expansion_approval_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &reviewer_package_path)?,
            relative_display(output, &qualification_report_path)?,
        ],
        note: "Program review remains Mercury-owned and evidence-backed for one bounded portfolio-program motion only."
            .to_string(),
    };
    let program_review_summary_path = output.join("program-review-summary.json");
    write_json_file(&program_review_summary_path, &program_review_summary)?;

    let portfolio_approval = MercuryPortfolioApproval {
        schema: "chio.mercury.portfolio_program_approval.v1".to_string(),
        workflow_id: workflow_id.clone(),
        review_owner: MERCURY_PROGRAM_REVIEW_OWNER.to_string(),
        status: "ready".to_string(),
        reviewed_at: unix_now(),
        reviewed_by: MERCURY_PROGRAM_REVIEW_OWNER.to_string(),
        approved_claims: program_review_summary.approved_claims.clone(),
        required_files: vec![
            relative_display(output, &portfolio_program_boundary_freeze_path)?,
            relative_display(output, &portfolio_program_manifest_path)?,
            relative_display(output, &program_review_summary_path)?,
            relative_display(output, &second_account_expansion_approval_path)?,
            relative_display(output, &second_account_reuse_governance_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &reviewer_package_path)?,
        ],
        note: "Portfolio approval must be refreshed before Mercury can reuse second-account expansion evidence for one bounded portfolio program."
            .to_string(),
    };
    let portfolio_approval_path = output.join("portfolio-approval.json");
    write_json_file(&portfolio_approval_path, &portfolio_approval)?;

    let revenue_operations_guardrails = MercuryRevenueOperationsGuardrails {
        schema: "chio.mercury.portfolio_program_revenue_operations_guardrails.v1".to_string(),
        workflow_id: workflow_id.clone(),
        program_owner: MERCURY_PORTFOLIO_PROGRAM_OWNER.to_string(),
        review_owner: MERCURY_PROGRAM_REVIEW_OWNER.to_string(),
        revenue_operations_guardrails_owner:
            MERCURY_REVENUE_OPERATIONS_GUARDRAILS_OWNER.to_string(),
        program_motion: MercuryPortfolioProgramMotion::PortfolioProgram
            .as_str()
            .to_string(),
        review_surface: MercuryPortfolioProgramSurface::ProgramReviewBundle
            .as_str()
            .to_string(),
        approved_scope:
            "one bounded portfolio-program review bundle over one explicit multi-account Mercury program only"
                .to_string(),
        permitted_reuse: vec![
            "second-account-expansion evidence that maps back to the same workflow and current approval set".to_string(),
            "program-review reuse inside the same bounded portfolio_program motion".to_string(),
        ],
        blocked_reuse: vec![
            "generic account-management or customer-success automation".to_string(),
            "revenue operations systems, forecasting stacks, or billing platforms".to_string(),
            "channel programs, universal multi-account portfolio claims, or Chio commercial controls"
                .to_string(),
        ],
        note: "Revenue-operations guardrails stay bounded to one portfolio-program motion and cannot imply a generalized portfolio-management or revenue platform."
            .to_string(),
    };
    let revenue_operations_guardrails_path = output.join("revenue-operations-guardrails.json");
    write_json_file(
        &revenue_operations_guardrails_path,
        &revenue_operations_guardrails,
    )?;

    let program_handoff = MercuryProgramHandoff {
        schema: "chio.mercury.portfolio_program_handoff.v1".to_string(),
        workflow_id: workflow_id.clone(),
        program_owner: MERCURY_PORTFOLIO_PROGRAM_OWNER.to_string(),
        review_owner: MERCURY_PROGRAM_REVIEW_OWNER.to_string(),
        revenue_operations_guardrails_owner:
            MERCURY_REVENUE_OPERATIONS_GUARDRAILS_OWNER.to_string(),
        program_motion: MercuryPortfolioProgramMotion::PortfolioProgram
            .as_str()
            .to_string(),
        review_surface: MercuryPortfolioProgramSurface::ProgramReviewBundle
            .as_str()
            .to_string(),
        approved_scope:
            "one bounded portfolio-program lane over the validated second-account-expansion chain only"
                .to_string(),
        required_evidence: vec![
            relative_display(output, &portfolio_program_manifest_path)?,
            relative_display(output, &program_review_summary_path)?,
            relative_display(output, &portfolio_approval_path)?,
            relative_display(output, &revenue_operations_guardrails_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
        ],
        deferred_requests: vec![
            "generic account-management, customer-success, or revenue operations platforms"
                .to_string(),
            "forecasting, billing, or channel program automation".to_string(),
            "Chio-side commercial control surfaces or merged product shells".to_string(),
        ],
        note: "Program handoff exists to keep the portfolio-program lane narrow and evidence-backed, not to imply broad portfolio automation is already approved."
            .to_string(),
    };
    let program_handoff_path = output.join("program-handoff.json");
    write_json_file(&program_handoff_path, &program_handoff)?;

    let package = MercuryPortfolioProgramPackage {
        schema: MERCURY_PORTFOLIO_PROGRAM_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "portfolio-program-program-review-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        program_motion: MercuryPortfolioProgramMotion::PortfolioProgram,
        review_surface: MercuryPortfolioProgramSurface::ProgramReviewBundle,
        program_owner: MERCURY_PORTFOLIO_PROGRAM_OWNER.to_string(),
        program_review_owner: MERCURY_PROGRAM_REVIEW_OWNER.to_string(),
        revenue_operations_guardrails_owner: MERCURY_REVENUE_OPERATIONS_GUARDRAILS_OWNER
            .to_string(),
        portfolio_approval_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        second_account_expansion_package_file: relative_display(
            output,
            &second_account_expansion_package_path,
        )?,
        second_account_expansion_boundary_freeze_file: relative_display(
            output,
            &second_account_expansion_boundary_freeze_path,
        )?,
        second_account_expansion_manifest_file: relative_display(
            output,
            &second_account_expansion_manifest_path,
        )?,
        second_account_portfolio_review_summary_file: relative_display(
            output,
            &second_account_portfolio_review_summary_path,
        )?,
        second_account_expansion_approval_file: relative_display(
            output,
            &second_account_expansion_approval_path,
        )?,
        second_account_reuse_governance_file: relative_display(
            output,
            &second_account_reuse_governance_path,
        )?,
        second_account_handoff_file: relative_display(output, &second_account_handoff_path)?,
        renewal_qualification_package_file: relative_display(
            output,
            &renewal_qualification_package_path,
        )?,
        renewal_boundary_freeze_file: relative_display(output, &renewal_boundary_freeze_path)?,
        renewal_qualification_manifest_file: relative_display(
            output,
            &renewal_qualification_manifest_path,
        )?,
        outcome_review_summary_file: relative_display(output, &outcome_review_summary_path)?,
        renewal_approval_file: relative_display(output, &renewal_approval_path)?,
        reference_reuse_discipline_file: relative_display(
            output,
            &reference_reuse_discipline_path,
        )?,
        expansion_boundary_handoff_file: relative_display(
            output,
            &expansion_boundary_handoff_path,
        )?,
        delivery_continuity_package_file: relative_display(
            output,
            &delivery_continuity_package_path,
        )?,
        account_boundary_freeze_file: relative_display(output, &account_boundary_freeze_path)?,
        delivery_continuity_manifest_file: relative_display(
            output,
            &delivery_continuity_manifest_path,
        )?,
        outcome_evidence_summary_file: relative_display(output, &outcome_evidence_summary_path)?,
        renewal_gate_file: relative_display(output, &renewal_gate_path)?,
        delivery_escalation_brief_file: relative_display(output, &delivery_escalation_brief_path)?,
        customer_evidence_handoff_file: relative_display(output, &customer_evidence_handoff_path)?,
        selective_account_activation_package_file: relative_display(
            output,
            &selective_account_activation_package_path,
        )?,
        broader_distribution_package_file: relative_display(
            output,
            &broader_distribution_package_path,
        )?,
        reference_distribution_package_file: relative_display(
            output,
            &reference_distribution_package_path,
        )?,
        controlled_adoption_package_file: relative_display(
            output,
            &controlled_adoption_package_path,
        )?,
        release_readiness_package_file: relative_display(output, &release_readiness_package_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        inquiry_verification_file: relative_display(output, &inquiry_verification_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        artifacts: vec![
            MercuryPortfolioProgramArtifact {
                artifact_kind: MercuryPortfolioProgramArtifactKind::PortfolioProgramBoundaryFreeze,
                relative_path: relative_display(output, &portfolio_program_boundary_freeze_path)?,
            },
            MercuryPortfolioProgramArtifact {
                artifact_kind: MercuryPortfolioProgramArtifactKind::PortfolioProgramManifest,
                relative_path: relative_display(output, &portfolio_program_manifest_path)?,
            },
            MercuryPortfolioProgramArtifact {
                artifact_kind: MercuryPortfolioProgramArtifactKind::ProgramReviewSummary,
                relative_path: relative_display(output, &program_review_summary_path)?,
            },
            MercuryPortfolioProgramArtifact {
                artifact_kind: MercuryPortfolioProgramArtifactKind::PortfolioApproval,
                relative_path: relative_display(output, &portfolio_approval_path)?,
            },
            MercuryPortfolioProgramArtifact {
                artifact_kind: MercuryPortfolioProgramArtifactKind::RevenueOperationsGuardrails,
                relative_path: relative_display(output, &revenue_operations_guardrails_path)?,
            },
            MercuryPortfolioProgramArtifact {
                artifact_kind: MercuryPortfolioProgramArtifactKind::ProgramHandoff,
                relative_path: relative_display(output, &program_handoff_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("portfolio-program-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryPortfolioProgramExportSummary {
        workflow_id,
        program_motion: MercuryPortfolioProgramMotion::PortfolioProgram
            .as_str()
            .to_string(),
        review_surface: MercuryPortfolioProgramSurface::ProgramReviewBundle
            .as_str()
            .to_string(),
        program_owner: MERCURY_PORTFOLIO_PROGRAM_OWNER.to_string(),
        program_review_owner: MERCURY_PROGRAM_REVIEW_OWNER.to_string(),
        revenue_operations_guardrails_owner: MERCURY_REVENUE_OPERATIONS_GUARDRAILS_OWNER
            .to_string(),
        second_account_expansion_dir: second_account_expansion_dir.display().to_string(),
        portfolio_program_profile_file: profile_path.display().to_string(),
        portfolio_program_package_file: package_path.display().to_string(),
        portfolio_program_boundary_freeze_file: portfolio_program_boundary_freeze_path
            .display()
            .to_string(),
        portfolio_program_manifest_file: portfolio_program_manifest_path.display().to_string(),
        program_review_summary_file: program_review_summary_path.display().to_string(),
        portfolio_approval_file: portfolio_approval_path.display().to_string(),
        revenue_operations_guardrails_file: revenue_operations_guardrails_path
            .display()
            .to_string(),
        program_handoff_file: program_handoff_path.display().to_string(),
        portfolio_evidence_dir: portfolio_evidence_dir.display().to_string(),
        second_account_expansion_package_file: second_account_expansion_package_path
            .display()
            .to_string(),
        second_account_expansion_boundary_freeze_file:
            second_account_expansion_boundary_freeze_path
                .display()
                .to_string(),
        second_account_expansion_manifest_file: second_account_expansion_manifest_path
            .display()
            .to_string(),
        second_account_portfolio_review_summary_file: second_account_portfolio_review_summary_path
            .display()
            .to_string(),
        second_account_expansion_approval_file: second_account_expansion_approval_path
            .display()
            .to_string(),
        second_account_reuse_governance_file: second_account_reuse_governance_path
            .display()
            .to_string(),
        second_account_handoff_file: second_account_handoff_path.display().to_string(),
        renewal_qualification_package_file: renewal_qualification_package_path
            .display()
            .to_string(),
        renewal_boundary_freeze_file: renewal_boundary_freeze_path.display().to_string(),
        renewal_qualification_manifest_file: renewal_qualification_manifest_path
            .display()
            .to_string(),
        outcome_review_summary_file: outcome_review_summary_path.display().to_string(),
        renewal_approval_file: renewal_approval_path.display().to_string(),
        reference_reuse_discipline_file: reference_reuse_discipline_path.display().to_string(),
        expansion_boundary_handoff_file: expansion_boundary_handoff_path.display().to_string(),
        delivery_continuity_package_file: delivery_continuity_package_path.display().to_string(),
        account_boundary_freeze_file: account_boundary_freeze_path.display().to_string(),
        delivery_continuity_manifest_file: delivery_continuity_manifest_path.display().to_string(),
        outcome_evidence_summary_file: outcome_evidence_summary_path.display().to_string(),
        renewal_gate_file: renewal_gate_path.display().to_string(),
        delivery_escalation_brief_file: delivery_escalation_brief_path.display().to_string(),
        customer_evidence_handoff_file: customer_evidence_handoff_path.display().to_string(),
        selective_account_activation_package_file: selective_account_activation_package_path
            .display()
            .to_string(),
        broader_distribution_package_file: broader_distribution_package_path.display().to_string(),
        reference_distribution_package_file: reference_distribution_package_path
            .display()
            .to_string(),
        controlled_adoption_package_file: controlled_adoption_package_path.display().to_string(),
        release_readiness_package_file: release_readiness_package_path.display().to_string(),
        trust_network_package_file: trust_network_package_path.display().to_string(),
        assurance_suite_package_file: assurance_suite_package_path.display().to_string(),
        proof_package_file: proof_package_path.display().to_string(),
        inquiry_package_file: inquiry_package_path.display().to_string(),
        inquiry_verification_file: inquiry_verification_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
    };
    write_json_file(&output.join("portfolio-program-summary.json"), &summary)?;

    Ok(summary)
}

pub fn cmd_mercury_portfolio_program_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_portfolio_program(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury portfolio-program package exported");
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
            "program_review_owner:               {}",
            summary.program_review_owner
        );
        println!(
            "revenue_operations_guardrails_owner: {}",
            summary.revenue_operations_guardrails_owner
        );
        println!(
            "portfolio_program_package:          {}",
            summary.portfolio_program_package_file
        );
        println!(
            "portfolio_approval:                 {}",
            summary.portfolio_approval_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_portfolio_program_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let portfolio_program_dir = output.join("portfolio-program");
    let summary = export_portfolio_program(&portfolio_program_dir)?;
    let docs = portfolio_program_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryPortfolioProgramDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_PORTFOLIO_PROGRAM_DECISION.to_string(),
        selected_program_motion: summary.program_motion.clone(),
        selected_review_surface: summary.review_surface.clone(),
        approved_scope:
            "Proceed with one bounded Mercury portfolio-program lane only.".to_string(),
        deferred_scope: vec![
            "additional portfolio-program motions or review surfaces".to_string(),
            "generic account-management, customer-success, or CRM workflow platforms".to_string(),
            "revenue operations systems, forecasting stacks, or billing platforms".to_string(),
            "channel programs, Chio commercial controls, or merged product shells".to_string(),
        ],
        rationale: "The portfolio-program lane now packages one bounded program-review bundle, one portfolio approval, one revenue-operations-guardrails artifact, and one explicit program handoff over the validated second-account-expansion chain without widening Mercury into a generic account-management or revenue platform and without polluting Chio's generic substrate."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("portfolio-program-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryPortfolioProgramValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_PORTFOLIO_PROGRAM_DECISION.to_string(),
        program_motion: summary.program_motion.clone(),
        review_surface: summary.review_surface.clone(),
        program_owner: summary.program_owner.clone(),
        program_review_owner: summary.program_review_owner.clone(),
        revenue_operations_guardrails_owner: summary.revenue_operations_guardrails_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        portfolio_program: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury portfolio-program validation package exported");
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
            "program_review_owner:               {}",
            report.program_review_owner
        );
        println!(
            "revenue_operations_guardrails_owner: {}",
            report.revenue_operations_guardrails_owner
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
            "portfolio_program_package:          {}",
            report.portfolio_program.portfolio_program_package_file
        );
    }

    Ok(())
}
