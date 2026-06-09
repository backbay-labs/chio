use super::*;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySecondPortfolioProgramDocRefs {
    second_portfolio_program_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySecondPortfolioProgramBoundaryFreeze {
    schema: String,
    workflow_id: String,
    program_motion: String,
    review_surface: String,
    reuse_boundary_label: String,
    entry_gates: Vec<String>,
    non_goals: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySecondPortfolioProgramManifest {
    schema: String,
    workflow_id: String,
    program_motion: String,
    review_surface: String,
    portfolio_program_package_file: String,
    portfolio_program_boundary_freeze_file: String,
    portfolio_program_manifest_file: String,
    program_review_summary_file: String,
    portfolio_approval_file: String,
    revenue_operations_guardrails_file: String,
    program_handoff_file: String,
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
struct MercuryPortfolioReuseSummary {
    schema: String,
    workflow_id: String,
    program_owner: String,
    review_owner: String,
    revenue_boundary_guardrails_owner: String,
    program_motion: String,
    review_surface: String,
    approved_claims: Vec<String>,
    evidence_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryPortfolioReuseApproval {
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
struct MercuryRevenueBoundaryGuardrails {
    schema: String,
    workflow_id: String,
    program_owner: String,
    review_owner: String,
    revenue_boundary_guardrails_owner: String,
    program_motion: String,
    review_surface: String,
    approved_scope: String,
    permitted_reuse: Vec<String>,
    blocked_reuse: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySecondProgramHandoff {
    schema: String,
    workflow_id: String,
    program_owner: String,
    review_owner: String,
    revenue_boundary_guardrails_owner: String,
    program_motion: String,
    review_surface: String,
    approved_scope: String,
    required_evidence: Vec<String>,
    deferred_requests: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MercurySecondPortfolioProgramExportSummary {
    pub(super) workflow_id: String,
    pub(super) program_motion: String,
    pub(super) review_surface: String,
    pub(super) program_owner: String,
    pub(super) portfolio_reuse_review_owner: String,
    pub(super) revenue_boundary_guardrails_owner: String,
    pub(super) portfolio_program_dir: String,
    pub(super) second_portfolio_program_profile_file: String,
    pub(super) second_portfolio_program_package_file: String,
    pub(super) second_portfolio_program_boundary_freeze_file: String,
    pub(super) second_portfolio_program_manifest_file: String,
    pub(super) portfolio_reuse_summary_file: String,
    pub(super) portfolio_reuse_approval_file: String,
    pub(super) revenue_boundary_guardrails_file: String,
    pub(super) second_program_handoff_file: String,
    pub(super) portfolio_reuse_evidence_dir: String,
    pub(super) portfolio_program_package_file: String,
    pub(super) portfolio_program_boundary_freeze_file: String,
    pub(super) portfolio_program_manifest_file: String,
    pub(super) program_review_summary_file: String,
    pub(super) portfolio_approval_file: String,
    pub(super) revenue_operations_guardrails_file: String,
    pub(super) program_handoff_file: String,
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
struct MercurySecondPortfolioProgramDecisionRecord {
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
struct MercurySecondPortfolioProgramValidationReport {
    workflow_id: String,
    decision: String,
    program_motion: String,
    review_surface: String,
    program_owner: String,
    portfolio_reuse_review_owner: String,
    revenue_boundary_guardrails_owner: String,
    same_workflow_boundary: String,
    second_portfolio_program: MercurySecondPortfolioProgramExportSummary,
    decision_record_file: String,
    docs: MercurySecondPortfolioProgramDocRefs,
}

fn second_portfolio_program_doc_refs() -> MercurySecondPortfolioProgramDocRefs {
    MercurySecondPortfolioProgramDocRefs {
        second_portfolio_program_file: "docs/mercury/SECOND_PORTFOLIO_PROGRAM.md".to_string(),
        operations_file: "docs/mercury/SECOND_PORTFOLIO_PROGRAM_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/SECOND_PORTFOLIO_PROGRAM_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/SECOND_PORTFOLIO_PROGRAM_DECISION_RECORD.md"
            .to_string(),
    }
}

fn build_second_portfolio_program_profile(
    workflow_id: &str,
) -> Result<MercurySecondPortfolioProgramProfile, CliError> {
    let profile = MercurySecondPortfolioProgramProfile {
        schema: MERCURY_SECOND_PORTFOLIO_PROGRAM_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "second-portfolio-program-portfolio-reuse-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        program_motion: MercurySecondPortfolioProgramMotion::SecondPortfolioProgram,
        review_surface: MercurySecondPortfolioProgramSurface::PortfolioReuseBundle,
        approval_gate: "evidence_backed_second_portfolio_program_only".to_string(),
        retained_artifact_policy:
            "retain-bounded-second-portfolio-program-and-portfolio-reuse-artifacts".to_string(),
        intended_use: "Qualify one bounded Mercury second portfolio program through one portfolio-reuse bundle rooted in the validated portfolio-program, second-account-expansion, renewal-qualification, delivery-continuity, selective-account-activation, broader-distribution, reference-distribution, controlled-adoption, release-readiness, trust-network, assurance, proof, and inquiry chain without widening into generic portfolio-management tooling, revenue operations systems, forecasting or billing platforms, channel programs, or Chio commercial surfaces."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

pub(super) fn export_second_portfolio_program(
    output: &Path,
) -> Result<MercurySecondPortfolioProgramExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let portfolio_program_dir = output.join("portfolio-program");
    let portfolio_program = export_portfolio_program(&portfolio_program_dir)?;
    let workflow_id = portfolio_program.workflow_id.clone();

    let profile = build_second_portfolio_program_profile(&workflow_id)?;
    let profile_path = output.join("second-portfolio-program-profile.json");
    write_json_file(&profile_path, &profile)?;

    let portfolio_reuse_evidence_dir = output.join("portfolio-reuse-evidence");
    fs::create_dir_all(&portfolio_reuse_evidence_dir)?;

    let portfolio_program_package_path =
        portfolio_reuse_evidence_dir.join("portfolio-program-package.json");
    let portfolio_program_boundary_freeze_path =
        portfolio_reuse_evidence_dir.join("portfolio-program-boundary-freeze.json");
    let portfolio_program_manifest_path =
        portfolio_reuse_evidence_dir.join("portfolio-program-manifest.json");
    let program_review_summary_path =
        portfolio_reuse_evidence_dir.join("program-review-summary.json");
    let portfolio_approval_path = portfolio_reuse_evidence_dir.join("portfolio-approval.json");
    let revenue_operations_guardrails_path =
        portfolio_reuse_evidence_dir.join("revenue-operations-guardrails.json");
    let program_handoff_path = portfolio_reuse_evidence_dir.join("program-handoff.json");
    let second_account_expansion_package_path =
        portfolio_reuse_evidence_dir.join("second-account-expansion-package.json");
    let second_account_expansion_boundary_freeze_path =
        portfolio_reuse_evidence_dir.join("second-account-portfolio-boundary-freeze.json");
    let second_account_expansion_manifest_path =
        portfolio_reuse_evidence_dir.join("second-account-expansion-manifest.json");
    let second_account_portfolio_review_summary_path =
        portfolio_reuse_evidence_dir.join("second-account-portfolio-review-summary.json");
    let second_account_expansion_approval_path =
        portfolio_reuse_evidence_dir.join("second-account-expansion-approval.json");
    let second_account_reuse_governance_path =
        portfolio_reuse_evidence_dir.join("second-account-reuse-governance.json");
    let second_account_handoff_path =
        portfolio_reuse_evidence_dir.join("second-account-handoff.json");
    let renewal_qualification_package_path =
        portfolio_reuse_evidence_dir.join("renewal-qualification-package.json");
    let renewal_boundary_freeze_path =
        portfolio_reuse_evidence_dir.join("renewal-boundary-freeze.json");
    let renewal_qualification_manifest_path =
        portfolio_reuse_evidence_dir.join("renewal-qualification-manifest.json");
    let outcome_review_summary_path =
        portfolio_reuse_evidence_dir.join("outcome-review-summary.json");
    let renewal_approval_path = portfolio_reuse_evidence_dir.join("renewal-approval.json");
    let reference_reuse_discipline_path =
        portfolio_reuse_evidence_dir.join("reference-reuse-discipline.json");
    let expansion_boundary_handoff_path =
        portfolio_reuse_evidence_dir.join("expansion-boundary-handoff.json");
    let delivery_continuity_package_path =
        portfolio_reuse_evidence_dir.join("delivery-continuity-package.json");
    let account_boundary_freeze_path =
        portfolio_reuse_evidence_dir.join("account-boundary-freeze.json");
    let delivery_continuity_manifest_path =
        portfolio_reuse_evidence_dir.join("delivery-continuity-manifest.json");
    let outcome_evidence_summary_path =
        portfolio_reuse_evidence_dir.join("outcome-evidence-summary.json");
    let renewal_gate_path = portfolio_reuse_evidence_dir.join("renewal-gate.json");
    let delivery_escalation_brief_path =
        portfolio_reuse_evidence_dir.join("delivery-escalation-brief.json");
    let customer_evidence_handoff_path =
        portfolio_reuse_evidence_dir.join("customer-evidence-handoff.json");
    let selective_account_activation_package_path =
        portfolio_reuse_evidence_dir.join("selective-account-activation-package.json");
    let broader_distribution_package_path =
        portfolio_reuse_evidence_dir.join("broader-distribution-package.json");
    let reference_distribution_package_path =
        portfolio_reuse_evidence_dir.join("reference-distribution-package.json");
    let controlled_adoption_package_path =
        portfolio_reuse_evidence_dir.join("controlled-adoption-package.json");
    let release_readiness_package_path =
        portfolio_reuse_evidence_dir.join("release-readiness-package.json");
    let trust_network_package_path =
        portfolio_reuse_evidence_dir.join("trust-network-package.json");
    let assurance_suite_package_path =
        portfolio_reuse_evidence_dir.join("assurance-suite-package.json");
    let proof_package_path = portfolio_reuse_evidence_dir.join("proof-package.json");
    let inquiry_package_path = portfolio_reuse_evidence_dir.join("inquiry-package.json");
    let inquiry_verification_path = portfolio_reuse_evidence_dir.join("inquiry-verification.json");
    let reviewer_package_path = portfolio_reuse_evidence_dir.join("reviewer-package.json");
    let qualification_report_path = portfolio_reuse_evidence_dir.join("qualification-report.json");

    copy_file(
        Path::new(&portfolio_program.portfolio_program_package_file),
        &portfolio_program_package_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.portfolio_program_boundary_freeze_file),
        &portfolio_program_boundary_freeze_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.portfolio_program_manifest_file),
        &portfolio_program_manifest_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.program_review_summary_file),
        &program_review_summary_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.portfolio_approval_file),
        &portfolio_approval_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.revenue_operations_guardrails_file),
        &revenue_operations_guardrails_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.program_handoff_file),
        &program_handoff_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.second_account_expansion_package_file),
        &second_account_expansion_package_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.second_account_expansion_boundary_freeze_file),
        &second_account_expansion_boundary_freeze_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.second_account_expansion_manifest_file),
        &second_account_expansion_manifest_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.second_account_portfolio_review_summary_file),
        &second_account_portfolio_review_summary_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.second_account_expansion_approval_file),
        &second_account_expansion_approval_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.second_account_reuse_governance_file),
        &second_account_reuse_governance_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.second_account_handoff_file),
        &second_account_handoff_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.renewal_qualification_package_file),
        &renewal_qualification_package_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.renewal_boundary_freeze_file),
        &renewal_boundary_freeze_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.renewal_qualification_manifest_file),
        &renewal_qualification_manifest_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.outcome_review_summary_file),
        &outcome_review_summary_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.renewal_approval_file),
        &renewal_approval_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.reference_reuse_discipline_file),
        &reference_reuse_discipline_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.expansion_boundary_handoff_file),
        &expansion_boundary_handoff_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.delivery_continuity_package_file),
        &delivery_continuity_package_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.account_boundary_freeze_file),
        &account_boundary_freeze_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.delivery_continuity_manifest_file),
        &delivery_continuity_manifest_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.outcome_evidence_summary_file),
        &outcome_evidence_summary_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.renewal_gate_file),
        &renewal_gate_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.delivery_escalation_brief_file),
        &delivery_escalation_brief_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.customer_evidence_handoff_file),
        &customer_evidence_handoff_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.selective_account_activation_package_file),
        &selective_account_activation_package_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.broader_distribution_package_file),
        &broader_distribution_package_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.reference_distribution_package_file),
        &reference_distribution_package_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.controlled_adoption_package_file),
        &controlled_adoption_package_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.release_readiness_package_file),
        &release_readiness_package_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.trust_network_package_file),
        &trust_network_package_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.assurance_suite_package_file),
        &assurance_suite_package_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.proof_package_file),
        &proof_package_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.inquiry_package_file),
        &inquiry_package_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.inquiry_verification_file),
        &inquiry_verification_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.reviewer_package_file),
        &reviewer_package_path,
    )?;
    copy_file(
        Path::new(&portfolio_program.qualification_report_file),
        &qualification_report_path,
    )?;

    let approved_claim = "Mercury can qualify one bounded second portfolio program through one second_portfolio_program motion using one portfolio_reuse_bundle rooted in the validated portfolio-program, second-account-expansion, renewal-qualification, delivery-continuity, selective-account-activation, broader-distribution, reference-distribution, controlled-adoption, release-readiness, trust-network, assurance, proof, and inquiry chain."
        .to_string();

    let second_portfolio_program_boundary_freeze = MercurySecondPortfolioProgramBoundaryFreeze {
        schema: "chio.mercury.second_portfolio_program_boundary_freeze.v1".to_string(),
        workflow_id: workflow_id.clone(),
        program_motion: MercurySecondPortfolioProgramMotion::SecondPortfolioProgram
            .as_str()
            .to_string(),
        review_surface: MercurySecondPortfolioProgramSurface::PortfolioReuseBundle
            .as_str()
            .to_string(),
        reuse_boundary_label:
            "one bounded Mercury second-portfolio-program lane over one adjacent portfolio program only"
                .to_string(),
        entry_gates: vec![
            "portfolio-program package, portfolio approval, revenue-operations guardrails, and program handoff remain current for the same workflow".to_string(),
            "the adjacent program stays inside one second_portfolio_program motion and one portfolio_reuse_bundle rooted in the existing Mercury evidence chain".to_string(),
            "portfolio-reuse approval, revenue-boundary guardrails, and second-program handoff are present before any second-program claim is reused".to_string(),
        ],
        non_goals: vec![
            "generic portfolio-management tooling, account-management suites, or customer-success platforms"
                .to_string(),
            "revenue operations systems, forecasting stacks, billing platforms, or channel programs"
                .to_string(),
            "Chio-side commercial control surfaces or merged product shells".to_string(),
        ],
        note: "This freeze keeps the next Mercury step bounded to one adjacent second portfolio program over the validated portfolio-program chain only."
            .to_string(),
    };
    let second_portfolio_program_boundary_freeze_path =
        output.join("second-portfolio-program-boundary-freeze.json");
    write_json_file(
        &second_portfolio_program_boundary_freeze_path,
        &second_portfolio_program_boundary_freeze,
    )?;

    let second_portfolio_program_manifest = MercurySecondPortfolioProgramManifest {
        schema: "chio.mercury.second_portfolio_program_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        program_motion: MercurySecondPortfolioProgramMotion::SecondPortfolioProgram
            .as_str()
            .to_string(),
        review_surface: MercurySecondPortfolioProgramSurface::PortfolioReuseBundle
            .as_str()
            .to_string(),
        portfolio_program_package_file: relative_display(output, &portfolio_program_package_path)?,
        portfolio_program_boundary_freeze_file: relative_display(
            output,
            &portfolio_program_boundary_freeze_path,
        )?,
        portfolio_program_manifest_file: relative_display(output, &portfolio_program_manifest_path)?,
        program_review_summary_file: relative_display(output, &program_review_summary_path)?,
        portfolio_approval_file: relative_display(output, &portfolio_approval_path)?,
        revenue_operations_guardrails_file: relative_display(
            output,
            &revenue_operations_guardrails_path,
        )?,
        program_handoff_file: relative_display(output, &program_handoff_path)?,
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
        note: "This manifest freezes one portfolio-reuse bundle over the portfolio-program and prior Mercury evidence chain and does not imply a generic portfolio-management platform, revenue operations system, channel program, or Chio commercial console."
            .to_string(),
    };
    let second_portfolio_program_manifest_path =
        output.join("second-portfolio-program-manifest.json");
    write_json_file(
        &second_portfolio_program_manifest_path,
        &second_portfolio_program_manifest,
    )?;

    let portfolio_reuse_summary = MercuryPortfolioReuseSummary {
        schema: "chio.mercury.second_portfolio_program_portfolio_reuse_summary.v1".to_string(),
        workflow_id: workflow_id.clone(),
        program_owner: MERCURY_SECOND_PORTFOLIO_PROGRAM_OWNER.to_string(),
        review_owner: MERCURY_PORTFOLIO_REUSE_REVIEW_OWNER.to_string(),
        revenue_boundary_guardrails_owner: MERCURY_REVENUE_BOUNDARY_GUARDRAILS_OWNER
            .to_string(),
        program_motion: MercurySecondPortfolioProgramMotion::SecondPortfolioProgram
            .as_str()
            .to_string(),
        review_surface: MercurySecondPortfolioProgramSurface::PortfolioReuseBundle
            .as_str()
            .to_string(),
        approved_claims: vec![
            approved_claim.clone(),
            "The second-portfolio-program bundle remains bounded to one second_portfolio_program motion, one portfolio_reuse_bundle surface, and one explicit revenue-boundary-guardrails handoff."
                .to_string(),
        ],
        evidence_files: vec![
            relative_display(output, &portfolio_program_package_path)?,
            relative_display(output, &program_review_summary_path)?,
            relative_display(output, &portfolio_approval_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &reviewer_package_path)?,
            relative_display(output, &qualification_report_path)?,
        ],
        note: "Portfolio-reuse review remains Mercury-owned and evidence-backed for one bounded second-portfolio-program motion only."
            .to_string(),
    };
    let portfolio_reuse_summary_path = output.join("portfolio-reuse-summary.json");
    write_json_file(&portfolio_reuse_summary_path, &portfolio_reuse_summary)?;

    let portfolio_reuse_approval = MercuryPortfolioReuseApproval {
        schema: "chio.mercury.second_portfolio_program_portfolio_reuse_approval.v1".to_string(),
        workflow_id: workflow_id.clone(),
        review_owner: MERCURY_PORTFOLIO_REUSE_REVIEW_OWNER.to_string(),
        status: "ready".to_string(),
        reviewed_at: unix_now(),
        reviewed_by: MERCURY_PORTFOLIO_REUSE_REVIEW_OWNER.to_string(),
        approved_claims: portfolio_reuse_summary.approved_claims.clone(),
        required_files: vec![
            relative_display(output, &second_portfolio_program_boundary_freeze_path)?,
            relative_display(output, &second_portfolio_program_manifest_path)?,
            relative_display(output, &portfolio_reuse_summary_path)?,
            relative_display(output, &portfolio_approval_path)?,
            relative_display(output, &program_handoff_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &reviewer_package_path)?,
        ],
        note: "Portfolio-reuse approval must be refreshed before Mercury can reuse portfolio-program evidence for one bounded adjacent second portfolio program."
            .to_string(),
    };
    let portfolio_reuse_approval_path = output.join("portfolio-reuse-approval.json");
    write_json_file(&portfolio_reuse_approval_path, &portfolio_reuse_approval)?;

    let revenue_boundary_guardrails = MercuryRevenueBoundaryGuardrails {
        schema: "chio.mercury.second_portfolio_program_revenue_boundary_guardrails.v1"
            .to_string(),
        workflow_id: workflow_id.clone(),
        program_owner: MERCURY_SECOND_PORTFOLIO_PROGRAM_OWNER.to_string(),
        review_owner: MERCURY_PORTFOLIO_REUSE_REVIEW_OWNER.to_string(),
        revenue_boundary_guardrails_owner: MERCURY_REVENUE_BOUNDARY_GUARDRAILS_OWNER
            .to_string(),
        program_motion: MercurySecondPortfolioProgramMotion::SecondPortfolioProgram
            .as_str()
            .to_string(),
        review_surface: MercurySecondPortfolioProgramSurface::PortfolioReuseBundle
            .as_str()
            .to_string(),
        approved_scope:
            "one bounded second-portfolio-program review bundle over one adjacent Mercury portfolio program only"
                .to_string(),
        permitted_reuse: vec![
            "portfolio-program evidence that maps back to the same workflow and current approval set".to_string(),
            "adjacent program reuse inside the same bounded second_portfolio_program motion".to_string(),
        ],
        blocked_reuse: vec![
            "generic portfolio-management or account-management automation".to_string(),
            "revenue operations systems, forecasting stacks, or billing platforms".to_string(),
            "channel programs, universal multi-program claims, or Chio commercial controls"
                .to_string(),
        ],
        note: "Revenue-boundary guardrails stay bounded to one second-portfolio-program motion and cannot imply a generalized portfolio-management or revenue platform."
            .to_string(),
    };
    let revenue_boundary_guardrails_path = output.join("revenue-boundary-guardrails.json");
    write_json_file(
        &revenue_boundary_guardrails_path,
        &revenue_boundary_guardrails,
    )?;

    let second_program_handoff = MercurySecondProgramHandoff {
        schema: "chio.mercury.second_portfolio_program_handoff.v1".to_string(),
        workflow_id: workflow_id.clone(),
        program_owner: MERCURY_SECOND_PORTFOLIO_PROGRAM_OWNER.to_string(),
        review_owner: MERCURY_PORTFOLIO_REUSE_REVIEW_OWNER.to_string(),
        revenue_boundary_guardrails_owner: MERCURY_REVENUE_BOUNDARY_GUARDRAILS_OWNER
            .to_string(),
        program_motion: MercurySecondPortfolioProgramMotion::SecondPortfolioProgram
            .as_str()
            .to_string(),
        review_surface: MercurySecondPortfolioProgramSurface::PortfolioReuseBundle
            .as_str()
            .to_string(),
        approved_scope:
            "one bounded second-portfolio-program lane over the validated portfolio-program chain only"
                .to_string(),
        required_evidence: vec![
            relative_display(output, &second_portfolio_program_manifest_path)?,
            relative_display(output, &portfolio_reuse_summary_path)?,
            relative_display(output, &portfolio_reuse_approval_path)?,
            relative_display(output, &revenue_boundary_guardrails_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
        ],
        deferred_requests: vec![
            "generic portfolio-management, account-management, or customer-success platforms"
                .to_string(),
            "revenue operations systems, forecasting stacks, billing platforms, or channel programs"
                .to_string(),
            "Chio-side commercial control surfaces or merged product shells".to_string(),
        ],
        note: "Second-program handoff exists to keep the second-portfolio-program lane narrow and evidence-backed, not to imply broad multi-program automation is already approved."
            .to_string(),
    };
    let second_program_handoff_path = output.join("second-program-handoff.json");
    write_json_file(&second_program_handoff_path, &second_program_handoff)?;

    let package = MercurySecondPortfolioProgramPackage {
        schema: MERCURY_SECOND_PORTFOLIO_PROGRAM_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "second-portfolio-program-portfolio-reuse-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        program_motion: MercurySecondPortfolioProgramMotion::SecondPortfolioProgram,
        review_surface: MercurySecondPortfolioProgramSurface::PortfolioReuseBundle,
        program_owner: MERCURY_SECOND_PORTFOLIO_PROGRAM_OWNER.to_string(),
        portfolio_reuse_review_owner: MERCURY_PORTFOLIO_REUSE_REVIEW_OWNER.to_string(),
        revenue_boundary_guardrails_owner: MERCURY_REVENUE_BOUNDARY_GUARDRAILS_OWNER.to_string(),
        portfolio_reuse_approval_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        portfolio_program_package_file: relative_display(output, &portfolio_program_package_path)?,
        portfolio_program_boundary_freeze_file: relative_display(
            output,
            &portfolio_program_boundary_freeze_path,
        )?,
        portfolio_program_manifest_file: relative_display(
            output,
            &portfolio_program_manifest_path,
        )?,
        program_review_summary_file: relative_display(output, &program_review_summary_path)?,
        portfolio_approval_file: relative_display(output, &portfolio_approval_path)?,
        revenue_operations_guardrails_file: relative_display(
            output,
            &revenue_operations_guardrails_path,
        )?,
        program_handoff_file: relative_display(output, &program_handoff_path)?,
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
            MercurySecondPortfolioProgramArtifact {
                artifact_kind:
                    MercurySecondPortfolioProgramArtifactKind::SecondPortfolioProgramBoundaryFreeze,
                relative_path: relative_display(
                    output,
                    &second_portfolio_program_boundary_freeze_path,
                )?,
            },
            MercurySecondPortfolioProgramArtifact {
                artifact_kind:
                    MercurySecondPortfolioProgramArtifactKind::SecondPortfolioProgramManifest,
                relative_path: relative_display(output, &second_portfolio_program_manifest_path)?,
            },
            MercurySecondPortfolioProgramArtifact {
                artifact_kind: MercurySecondPortfolioProgramArtifactKind::PortfolioReuseSummary,
                relative_path: relative_display(output, &portfolio_reuse_summary_path)?,
            },
            MercurySecondPortfolioProgramArtifact {
                artifact_kind: MercurySecondPortfolioProgramArtifactKind::PortfolioReuseApproval,
                relative_path: relative_display(output, &portfolio_reuse_approval_path)?,
            },
            MercurySecondPortfolioProgramArtifact {
                artifact_kind: MercurySecondPortfolioProgramArtifactKind::RevenueBoundaryGuardrails,
                relative_path: relative_display(output, &revenue_boundary_guardrails_path)?,
            },
            MercurySecondPortfolioProgramArtifact {
                artifact_kind: MercurySecondPortfolioProgramArtifactKind::SecondProgramHandoff,
                relative_path: relative_display(output, &second_program_handoff_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("second-portfolio-program-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercurySecondPortfolioProgramExportSummary {
        workflow_id,
        program_motion: MercurySecondPortfolioProgramMotion::SecondPortfolioProgram
            .as_str()
            .to_string(),
        review_surface: MercurySecondPortfolioProgramSurface::PortfolioReuseBundle
            .as_str()
            .to_string(),
        program_owner: MERCURY_SECOND_PORTFOLIO_PROGRAM_OWNER.to_string(),
        portfolio_reuse_review_owner: MERCURY_PORTFOLIO_REUSE_REVIEW_OWNER.to_string(),
        revenue_boundary_guardrails_owner: MERCURY_REVENUE_BOUNDARY_GUARDRAILS_OWNER.to_string(),
        portfolio_program_dir: portfolio_program_dir.display().to_string(),
        second_portfolio_program_profile_file: profile_path.display().to_string(),
        second_portfolio_program_package_file: package_path.display().to_string(),
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
        portfolio_reuse_evidence_dir: portfolio_reuse_evidence_dir.display().to_string(),
        portfolio_program_package_file: portfolio_program_package_path.display().to_string(),
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
    write_json_file(
        &output.join("second-portfolio-program-summary.json"),
        &summary,
    )?;

    Ok(summary)
}

pub fn cmd_mercury_second_portfolio_program_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_second_portfolio_program(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury second-portfolio-program package exported");
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
            "portfolio_reuse_review_owner:       {}",
            summary.portfolio_reuse_review_owner
        );
        println!(
            "revenue_boundary_guardrails_owner:  {}",
            summary.revenue_boundary_guardrails_owner
        );
        println!(
            "second_portfolio_program_package:   {}",
            summary.second_portfolio_program_package_file
        );
        println!(
            "portfolio_reuse_approval:           {}",
            summary.portfolio_reuse_approval_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_second_portfolio_program_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let second_portfolio_program_dir = output.join("second-portfolio-program");
    let summary = export_second_portfolio_program(&second_portfolio_program_dir)?;
    let docs = second_portfolio_program_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercurySecondPortfolioProgramDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_SECOND_PORTFOLIO_PROGRAM_DECISION.to_string(),
        selected_program_motion: summary.program_motion.clone(),
        selected_review_surface: summary.review_surface.clone(),
        approved_scope:
            "Proceed with one bounded Mercury second-portfolio-program lane only.".to_string(),
        deferred_scope: vec![
            "additional second-portfolio-program motions or review surfaces".to_string(),
            "generic portfolio-management, account-management, or customer-success workflow platforms"
                .to_string(),
            "revenue operations systems, forecasting stacks, billing platforms, or channel programs"
                .to_string(),
            "Chio commercial controls, merged product shells, or generalized portfolio automation"
                .to_string(),
        ],
        rationale: "The second-portfolio-program lane now packages one bounded portfolio-reuse bundle, one portfolio-reuse approval, one revenue-boundary-guardrails artifact, and one explicit second-program handoff over the validated portfolio-program chain without widening Mercury into a generic portfolio-management or revenue platform and without polluting Chio's generic substrate."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("second-portfolio-program-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercurySecondPortfolioProgramValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_SECOND_PORTFOLIO_PROGRAM_DECISION.to_string(),
        program_motion: summary.program_motion.clone(),
        review_surface: summary.review_surface.clone(),
        program_owner: summary.program_owner.clone(),
        portfolio_reuse_review_owner: summary.portfolio_reuse_review_owner.clone(),
        revenue_boundary_guardrails_owner: summary.revenue_boundary_guardrails_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        second_portfolio_program: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury second-portfolio-program validation package exported");
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
            "portfolio_reuse_review_owner:       {}",
            report.portfolio_reuse_review_owner
        );
        println!(
            "revenue_boundary_guardrails_owner:  {}",
            report.revenue_boundary_guardrails_owner
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
            "second_portfolio_program_package:   {}",
            report
                .second_portfolio_program
                .second_portfolio_program_package_file
        );
    }

    Ok(())
}
