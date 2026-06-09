use super::*;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySecondAccountExpansionDocRefs {
    second_account_expansion_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryPortfolioBoundaryFreeze {
    schema: String,
    workflow_id: String,
    expansion_motion: String,
    review_surface: String,
    portfolio_boundary_label: String,
    entry_gates: Vec<String>,
    non_goals: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySecondAccountExpansionManifest {
    schema: String,
    workflow_id: String,
    expansion_motion: String,
    review_surface: String,
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
struct MercuryPortfolioReviewSummary {
    schema: String,
    workflow_id: String,
    expansion_owner: String,
    review_owner: String,
    reuse_governance_owner: String,
    expansion_motion: String,
    review_surface: String,
    approved_claims: Vec<String>,
    evidence_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryExpansionApproval {
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
struct MercuryReuseGovernance {
    schema: String,
    workflow_id: String,
    expansion_owner: String,
    review_owner: String,
    reuse_governance_owner: String,
    expansion_motion: String,
    review_surface: String,
    approved_scope: String,
    permitted_reuse: Vec<String>,
    blocked_reuse: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySecondAccountHandoff {
    schema: String,
    workflow_id: String,
    expansion_owner: String,
    review_owner: String,
    reuse_governance_owner: String,
    expansion_motion: String,
    review_surface: String,
    approved_scope: String,
    required_evidence: Vec<String>,
    deferred_requests: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MercurySecondAccountExpansionExportSummary {
    pub(super) workflow_id: String,
    pub(super) expansion_motion: String,
    pub(super) review_surface: String,
    pub(super) expansion_owner: String,
    pub(super) portfolio_review_owner: String,
    pub(super) reuse_governance_owner: String,
    pub(super) renewal_qualification_dir: String,
    pub(super) second_account_expansion_profile_file: String,
    pub(super) second_account_expansion_package_file: String,
    pub(super) portfolio_boundary_freeze_file: String,
    pub(super) second_account_expansion_manifest_file: String,
    pub(super) portfolio_review_summary_file: String,
    pub(super) expansion_approval_file: String,
    pub(super) reuse_governance_file: String,
    pub(super) second_account_handoff_file: String,
    pub(super) expansion_evidence_dir: String,
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
struct MercurySecondAccountExpansionDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_expansion_motion: String,
    selected_review_surface: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySecondAccountExpansionValidationReport {
    workflow_id: String,
    decision: String,
    expansion_motion: String,
    review_surface: String,
    expansion_owner: String,
    portfolio_review_owner: String,
    reuse_governance_owner: String,
    same_workflow_boundary: String,
    second_account_expansion: MercurySecondAccountExpansionExportSummary,
    decision_record_file: String,
    docs: MercurySecondAccountExpansionDocRefs,
}

fn second_account_expansion_doc_refs() -> MercurySecondAccountExpansionDocRefs {
    MercurySecondAccountExpansionDocRefs {
        second_account_expansion_file: "docs/mercury/SECOND_ACCOUNT_EXPANSION.md".to_string(),
        operations_file: "docs/mercury/SECOND_ACCOUNT_EXPANSION_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/SECOND_ACCOUNT_EXPANSION_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/SECOND_ACCOUNT_EXPANSION_DECISION_RECORD.md"
            .to_string(),
    }
}

fn build_second_account_expansion_profile(
    workflow_id: &str,
) -> Result<MercurySecondAccountExpansionProfile, CliError> {
    let profile = MercurySecondAccountExpansionProfile {
        schema: MERCURY_SECOND_ACCOUNT_EXPANSION_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "second-account-expansion-portfolio-review-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        expansion_motion: MercurySecondAccountExpansionMotion::SecondAccountExpansion,
        review_surface: MercurySecondAccountExpansionSurface::PortfolioReviewBundle,
        expansion_decision_gate: "evidence_backed_second_account_expansion_only".to_string(),
        retained_artifact_policy:
            "retain-bounded-second-account-expansion-and-portfolio-review-artifacts"
                .to_string(),
        intended_use: "Qualify one second Mercury account through one bounded portfolio-review lane rooted in the validated renewal-qualification, delivery-continuity, selective-account-activation, broader-distribution, reference-distribution, controlled-adoption, release-readiness, trust-network, assurance, proof, and inquiry chain without widening into generic customer-success tooling, CRM workflows, account-management platforms, revenue operations systems, channel marketplaces, or Chio commercial surfaces."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

pub(super) fn export_second_account_expansion(
    output: &Path,
) -> Result<MercurySecondAccountExpansionExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let renewal_qualification_dir = output.join("renewal-qualification");
    let renewal_qualification = export_renewal_qualification(&renewal_qualification_dir)?;
    let workflow_id = renewal_qualification.workflow_id.clone();

    let profile = build_second_account_expansion_profile(&workflow_id)?;
    let profile_path = output.join("second-account-expansion-profile.json");
    write_json_file(&profile_path, &profile)?;

    let expansion_evidence_dir = output.join("expansion-evidence");
    fs::create_dir_all(&expansion_evidence_dir)?;

    let renewal_qualification_package_path =
        expansion_evidence_dir.join("renewal-qualification-package.json");
    let renewal_boundary_freeze_path = expansion_evidence_dir.join("renewal-boundary-freeze.json");
    let renewal_qualification_manifest_path =
        expansion_evidence_dir.join("renewal-qualification-manifest.json");
    let outcome_review_summary_path = expansion_evidence_dir.join("outcome-review-summary.json");
    let renewal_approval_path = expansion_evidence_dir.join("renewal-approval.json");
    let reference_reuse_discipline_path =
        expansion_evidence_dir.join("reference-reuse-discipline.json");
    let expansion_boundary_handoff_path =
        expansion_evidence_dir.join("expansion-boundary-handoff.json");
    let delivery_continuity_package_path =
        expansion_evidence_dir.join("delivery-continuity-package.json");
    let account_boundary_freeze_path = expansion_evidence_dir.join("account-boundary-freeze.json");
    let delivery_continuity_manifest_path =
        expansion_evidence_dir.join("delivery-continuity-manifest.json");
    let outcome_evidence_summary_path =
        expansion_evidence_dir.join("outcome-evidence-summary.json");
    let renewal_gate_path = expansion_evidence_dir.join("renewal-gate.json");
    let delivery_escalation_brief_path =
        expansion_evidence_dir.join("delivery-escalation-brief.json");
    let customer_evidence_handoff_path =
        expansion_evidence_dir.join("customer-evidence-handoff.json");
    let selective_account_activation_package_path =
        expansion_evidence_dir.join("selective-account-activation-package.json");
    let broader_distribution_package_path =
        expansion_evidence_dir.join("broader-distribution-package.json");
    let reference_distribution_package_path =
        expansion_evidence_dir.join("reference-distribution-package.json");
    let controlled_adoption_package_path =
        expansion_evidence_dir.join("controlled-adoption-package.json");
    let release_readiness_package_path =
        expansion_evidence_dir.join("release-readiness-package.json");
    let trust_network_package_path = expansion_evidence_dir.join("trust-network-package.json");
    let assurance_suite_package_path = expansion_evidence_dir.join("assurance-suite-package.json");
    let proof_package_path = expansion_evidence_dir.join("proof-package.json");
    let inquiry_package_path = expansion_evidence_dir.join("inquiry-package.json");
    let inquiry_verification_path = expansion_evidence_dir.join("inquiry-verification.json");
    let reviewer_package_path = expansion_evidence_dir.join("reviewer-package.json");
    let qualification_report_path = expansion_evidence_dir.join("qualification-report.json");

    copy_file(
        Path::new(&renewal_qualification.renewal_qualification_package_file),
        &renewal_qualification_package_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.renewal_boundary_freeze_file),
        &renewal_boundary_freeze_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.renewal_qualification_manifest_file),
        &renewal_qualification_manifest_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.outcome_review_summary_file),
        &outcome_review_summary_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.renewal_approval_file),
        &renewal_approval_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.reference_reuse_discipline_file),
        &reference_reuse_discipline_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.expansion_boundary_handoff_file),
        &expansion_boundary_handoff_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.delivery_continuity_package_file),
        &delivery_continuity_package_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.account_boundary_freeze_file),
        &account_boundary_freeze_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.delivery_continuity_manifest_file),
        &delivery_continuity_manifest_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.outcome_evidence_summary_file),
        &outcome_evidence_summary_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.renewal_gate_file),
        &renewal_gate_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.delivery_escalation_brief_file),
        &delivery_escalation_brief_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.customer_evidence_handoff_file),
        &customer_evidence_handoff_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.selective_account_activation_package_file),
        &selective_account_activation_package_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.broader_distribution_package_file),
        &broader_distribution_package_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.reference_distribution_package_file),
        &reference_distribution_package_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.controlled_adoption_package_file),
        &controlled_adoption_package_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.release_readiness_package_file),
        &release_readiness_package_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.trust_network_package_file),
        &trust_network_package_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.assurance_suite_package_file),
        &assurance_suite_package_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.proof_package_file),
        &proof_package_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.inquiry_package_file),
        &inquiry_package_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.inquiry_verification_file),
        &inquiry_verification_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.reviewer_package_file),
        &reviewer_package_path,
    )?;
    copy_file(
        Path::new(&renewal_qualification.qualification_report_file),
        &qualification_report_path,
    )?;

    let approved_claim = "Mercury can qualify one second-account expansion through one second-account-expansion motion using one portfolio-review bundle rooted in the validated renewal-qualification, delivery-continuity, selective-account-activation, broader-distribution, reference-distribution, controlled-adoption, release-readiness, trust-network, assurance, proof, and inquiry chain."
        .to_string();

    let portfolio_boundary_freeze = MercuryPortfolioBoundaryFreeze {
        schema: "chio.mercury.second_account_expansion_boundary_freeze.v1".to_string(),
        workflow_id: workflow_id.clone(),
        expansion_motion: MercurySecondAccountExpansionMotion::SecondAccountExpansion
            .as_str()
            .to_string(),
        review_surface: MercurySecondAccountExpansionSurface::PortfolioReviewBundle
            .as_str()
            .to_string(),
        portfolio_boundary_label:
            "one second Mercury account inside one bounded second-account-expansion lane"
                .to_string(),
        entry_gates: vec![
            "renewal-qualification package, renewal approval, and expansion-boundary handoff remain current for the same workflow".to_string(),
            "second-account expansion stays within one additional account, one motion, and one portfolio-review bundle".to_string(),
            "expansion approval, reuse governance, and second-account handoff are present before second-account claims are reused".to_string(),
        ],
        non_goals: vec![
            "generic customer-success tooling or CRM workflows".to_string(),
            "account-management platforms, revenue operations systems, or channel marketplaces"
                .to_string(),
            "Chio-side commercial control surfaces or merged product shells".to_string(),
        ],
        note: "This freeze keeps the next Mercury step bounded to one second-account expansion motion over one renewed account only."
            .to_string(),
    };
    let portfolio_boundary_freeze_path = output.join("portfolio-boundary-freeze.json");
    write_json_file(&portfolio_boundary_freeze_path, &portfolio_boundary_freeze)?;

    let second_account_expansion_manifest = MercurySecondAccountExpansionManifest {
        schema: "chio.mercury.second_account_expansion_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        expansion_motion: MercurySecondAccountExpansionMotion::SecondAccountExpansion
            .as_str()
            .to_string(),
        review_surface: MercurySecondAccountExpansionSurface::PortfolioReviewBundle
            .as_str()
            .to_string(),
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
        note: "This manifest freezes one portfolio-review bundle over the existing Mercury renewal evidence chain and does not imply a generic account portfolio platform, customer-success suite, or Chio commercial console."
            .to_string(),
    };
    let second_account_expansion_manifest_path =
        output.join("second-account-expansion-manifest.json");
    write_json_file(
        &second_account_expansion_manifest_path,
        &second_account_expansion_manifest,
    )?;

    let portfolio_review_summary = MercuryPortfolioReviewSummary {
        schema: "chio.mercury.second_account_expansion_portfolio_review_summary.v1".to_string(),
        workflow_id: workflow_id.clone(),
        expansion_owner: MERCURY_SECOND_ACCOUNT_EXPANSION_OWNER.to_string(),
        review_owner: MERCURY_PORTFOLIO_REVIEW_OWNER.to_string(),
        reuse_governance_owner: MERCURY_REUSE_GOVERNANCE_OWNER.to_string(),
        expansion_motion: MercurySecondAccountExpansionMotion::SecondAccountExpansion
            .as_str()
            .to_string(),
        review_surface: MercurySecondAccountExpansionSurface::PortfolioReviewBundle
            .as_str()
            .to_string(),
        approved_claims: vec![
            approved_claim.clone(),
            "The expansion bundle remains bounded to one second-account-expansion motion, one portfolio-review surface, and one explicit reuse-governance handoff."
                .to_string(),
        ],
        evidence_files: vec![
            relative_display(output, &renewal_qualification_package_path)?,
            relative_display(output, &outcome_review_summary_path)?,
            relative_display(output, &renewal_approval_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &reviewer_package_path)?,
            relative_display(output, &qualification_report_path)?,
        ],
        note: "Portfolio review remains Mercury-owned and evidence-backed for one second-account expansion motion only."
            .to_string(),
    };
    let portfolio_review_summary_path = output.join("portfolio-review-summary.json");
    write_json_file(&portfolio_review_summary_path, &portfolio_review_summary)?;

    let expansion_approval = MercuryExpansionApproval {
        schema: "chio.mercury.second_account_expansion_approval.v1".to_string(),
        workflow_id: workflow_id.clone(),
        review_owner: MERCURY_PORTFOLIO_REVIEW_OWNER.to_string(),
        status: "ready".to_string(),
        reviewed_at: unix_now(),
        reviewed_by: MERCURY_PORTFOLIO_REVIEW_OWNER.to_string(),
        approved_claims: portfolio_review_summary.approved_claims.clone(),
        required_files: vec![
            relative_display(output, &portfolio_boundary_freeze_path)?,
            relative_display(output, &second_account_expansion_manifest_path)?,
            relative_display(output, &portfolio_review_summary_path)?,
            relative_display(output, &renewal_approval_path)?,
            relative_display(output, &reference_reuse_discipline_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &reviewer_package_path)?,
        ],
        note: "Expansion approval must be refreshed before Mercury can reuse renewal evidence for one second-account expansion."
            .to_string(),
    };
    let expansion_approval_path = output.join("expansion-approval.json");
    write_json_file(&expansion_approval_path, &expansion_approval)?;

    let reuse_governance = MercuryReuseGovernance {
        schema: "chio.mercury.second_account_expansion_reuse_governance.v1".to_string(),
        workflow_id: workflow_id.clone(),
        expansion_owner: MERCURY_SECOND_ACCOUNT_EXPANSION_OWNER.to_string(),
        review_owner: MERCURY_PORTFOLIO_REVIEW_OWNER.to_string(),
        reuse_governance_owner: MERCURY_REUSE_GOVERNANCE_OWNER.to_string(),
        expansion_motion: MercurySecondAccountExpansionMotion::SecondAccountExpansion
            .as_str()
            .to_string(),
        review_surface: MercurySecondAccountExpansionSurface::PortfolioReviewBundle
            .as_str()
            .to_string(),
        approved_scope:
            "one second-account-expansion portfolio-review bundle for one follow-on Mercury account only".to_string(),
        permitted_reuse: vec![
            "renewal claims that map back to the same workflow and the same renewal-qualification package".to_string(),
            "portfolio-review reuse inside the same bounded second-account expansion motion".to_string(),
        ],
        blocked_reuse: vec![
            "multi-account portfolio claims".to_string(),
            "generic customer-success, CRM, or account-management workflow reuse".to_string(),
            "channel, marketplace, revenue operations, or Chio commercial control claims"
                .to_string(),
        ],
        note: "Reuse governance stays bounded to one second-account motion and cannot imply a broader Mercury account portfolio program."
            .to_string(),
    };
    let reuse_governance_path = output.join("reuse-governance.json");
    write_json_file(&reuse_governance_path, &reuse_governance)?;

    let second_account_handoff = MercurySecondAccountHandoff {
        schema: "chio.mercury.second_account_expansion_handoff.v1".to_string(),
        workflow_id: workflow_id.clone(),
        expansion_owner: MERCURY_SECOND_ACCOUNT_EXPANSION_OWNER.to_string(),
        review_owner: MERCURY_PORTFOLIO_REVIEW_OWNER.to_string(),
        reuse_governance_owner: MERCURY_REUSE_GOVERNANCE_OWNER.to_string(),
        expansion_motion: MercurySecondAccountExpansionMotion::SecondAccountExpansion
            .as_str()
            .to_string(),
        review_surface: MercurySecondAccountExpansionSurface::PortfolioReviewBundle
            .as_str()
            .to_string(),
        approved_scope:
            "one bounded second-account-expansion lane over one renewed Mercury account only".to_string(),
        required_evidence: vec![
            relative_display(output, &second_account_expansion_manifest_path)?,
            relative_display(output, &portfolio_review_summary_path)?,
            relative_display(output, &expansion_approval_path)?,
            relative_display(output, &reuse_governance_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
        ],
        deferred_requests: vec![
            "multi-account portfolio programs".to_string(),
            "generic account-management, customer-success, or revenue operations platforms"
                .to_string(),
            "channel marketplaces or Chio commercial control surfaces".to_string(),
        ],
        note: "Second-account handoff exists to keep the expansion lane narrow and evidence-backed, not to imply broader portfolio expansion is already approved."
            .to_string(),
    };
    let second_account_handoff_path = output.join("second-account-handoff.json");
    write_json_file(&second_account_handoff_path, &second_account_handoff)?;

    let package = MercurySecondAccountExpansionPackage {
        schema: MERCURY_SECOND_ACCOUNT_EXPANSION_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "second-account-expansion-portfolio-review-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        expansion_motion: MercurySecondAccountExpansionMotion::SecondAccountExpansion,
        review_surface: MercurySecondAccountExpansionSurface::PortfolioReviewBundle,
        expansion_owner: MERCURY_SECOND_ACCOUNT_EXPANSION_OWNER.to_string(),
        portfolio_review_owner: MERCURY_PORTFOLIO_REVIEW_OWNER.to_string(),
        reuse_governance_owner: MERCURY_REUSE_GOVERNANCE_OWNER.to_string(),
        expansion_approval_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
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
            MercurySecondAccountExpansionArtifact {
                artifact_kind: MercurySecondAccountExpansionArtifactKind::PortfolioBoundaryFreeze,
                relative_path: relative_display(output, &portfolio_boundary_freeze_path)?,
            },
            MercurySecondAccountExpansionArtifact {
                artifact_kind:
                    MercurySecondAccountExpansionArtifactKind::SecondAccountExpansionManifest,
                relative_path: relative_display(output, &second_account_expansion_manifest_path)?,
            },
            MercurySecondAccountExpansionArtifact {
                artifact_kind: MercurySecondAccountExpansionArtifactKind::PortfolioReviewSummary,
                relative_path: relative_display(output, &portfolio_review_summary_path)?,
            },
            MercurySecondAccountExpansionArtifact {
                artifact_kind: MercurySecondAccountExpansionArtifactKind::ExpansionApproval,
                relative_path: relative_display(output, &expansion_approval_path)?,
            },
            MercurySecondAccountExpansionArtifact {
                artifact_kind: MercurySecondAccountExpansionArtifactKind::ReuseGovernance,
                relative_path: relative_display(output, &reuse_governance_path)?,
            },
            MercurySecondAccountExpansionArtifact {
                artifact_kind: MercurySecondAccountExpansionArtifactKind::SecondAccountHandoff,
                relative_path: relative_display(output, &second_account_handoff_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("second-account-expansion-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercurySecondAccountExpansionExportSummary {
        workflow_id,
        expansion_motion: MercurySecondAccountExpansionMotion::SecondAccountExpansion
            .as_str()
            .to_string(),
        review_surface: MercurySecondAccountExpansionSurface::PortfolioReviewBundle
            .as_str()
            .to_string(),
        expansion_owner: MERCURY_SECOND_ACCOUNT_EXPANSION_OWNER.to_string(),
        portfolio_review_owner: MERCURY_PORTFOLIO_REVIEW_OWNER.to_string(),
        reuse_governance_owner: MERCURY_REUSE_GOVERNANCE_OWNER.to_string(),
        renewal_qualification_dir: renewal_qualification_dir.display().to_string(),
        second_account_expansion_profile_file: profile_path.display().to_string(),
        second_account_expansion_package_file: package_path.display().to_string(),
        portfolio_boundary_freeze_file: portfolio_boundary_freeze_path.display().to_string(),
        second_account_expansion_manifest_file: second_account_expansion_manifest_path
            .display()
            .to_string(),
        portfolio_review_summary_file: portfolio_review_summary_path.display().to_string(),
        expansion_approval_file: expansion_approval_path.display().to_string(),
        reuse_governance_file: reuse_governance_path.display().to_string(),
        second_account_handoff_file: second_account_handoff_path.display().to_string(),
        expansion_evidence_dir: expansion_evidence_dir.display().to_string(),
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
        &output.join("second-account-expansion-summary.json"),
        &summary,
    )?;

    Ok(summary)
}

pub fn cmd_mercury_second_account_expansion_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_second_account_expansion(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury second-account-expansion package exported");
        println!("output:                             {}", output.display());
        println!(
            "workflow_id:                        {}",
            summary.workflow_id
        );
        println!(
            "expansion_motion:                   {}",
            summary.expansion_motion
        );
        println!(
            "review_surface:                     {}",
            summary.review_surface
        );
        println!(
            "expansion_owner:                    {}",
            summary.expansion_owner
        );
        println!(
            "portfolio_review_owner:             {}",
            summary.portfolio_review_owner
        );
        println!(
            "reuse_governance_owner:             {}",
            summary.reuse_governance_owner
        );
        println!(
            "second_account_expansion_package:   {}",
            summary.second_account_expansion_package_file
        );
        println!(
            "expansion_approval:                 {}",
            summary.expansion_approval_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_second_account_expansion_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let second_account_expansion_dir = output.join("second-account-expansion");
    let summary = export_second_account_expansion(&second_account_expansion_dir)?;
    let docs = second_account_expansion_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercurySecondAccountExpansionDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_SECOND_ACCOUNT_EXPANSION_DECISION.to_string(),
        selected_expansion_motion: summary.expansion_motion.clone(),
        selected_review_surface: summary.review_surface.clone(),
        approved_scope:
            "Proceed with one bounded Mercury second-account-expansion lane only."
                .to_string(),
        deferred_scope: vec![
            "additional expansion motions or review surfaces".to_string(),
            "generic customer-success tooling, CRM workflows, or account-management platforms"
                .to_string(),
            "revenue operations systems or multi-account portfolio programs".to_string(),
            "channel marketplaces or Chio-side commercial control surfaces".to_string(),
        ],
        rationale: "The second-account-expansion lane now packages one bounded portfolio-review bundle, one expansion approval, one reuse-governance artifact, and one explicit second-account handoff over the validated renewal-qualification chain without widening Mercury into a generic account-management platform or polluting Chio's generic substrate."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("second-account-expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercurySecondAccountExpansionValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_SECOND_ACCOUNT_EXPANSION_DECISION.to_string(),
        expansion_motion: summary.expansion_motion.clone(),
        review_surface: summary.review_surface.clone(),
        expansion_owner: summary.expansion_owner.clone(),
        portfolio_review_owner: summary.portfolio_review_owner.clone(),
        reuse_governance_owner: summary.reuse_governance_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        second_account_expansion: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury second-account-expansion validation package exported");
        println!("output:                             {}", output.display());
        println!("workflow_id:                        {}", report.workflow_id);
        println!("decision:                           {}", report.decision);
        println!(
            "expansion_motion:                   {}",
            report.expansion_motion
        );
        println!(
            "review_surface:                     {}",
            report.review_surface
        );
        println!(
            "expansion_owner:                    {}",
            report.expansion_owner
        );
        println!(
            "portfolio_review_owner:             {}",
            report.portfolio_review_owner
        );
        println!(
            "reuse_governance_owner:             {}",
            report.reuse_governance_owner
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
            "second_account_expansion_package:   {}",
            report
                .second_account_expansion
                .second_account_expansion_package_file
        );
    }

    Ok(())
}
