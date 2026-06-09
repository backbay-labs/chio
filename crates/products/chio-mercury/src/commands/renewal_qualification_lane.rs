use super::*;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryRenewalQualificationDocRefs {
    renewal_qualification_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryRenewalBoundaryFreeze {
    schema: String,
    workflow_id: String,
    renewal_motion: String,
    review_surface: String,
    renewal_boundary_label: String,
    entry_gates: Vec<String>,
    non_goals: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryRenewalQualificationManifest {
    schema: String,
    workflow_id: String,
    renewal_motion: String,
    review_surface: String,
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
struct MercuryOutcomeReviewSummary {
    schema: String,
    workflow_id: String,
    qualification_owner: String,
    review_owner: String,
    expansion_owner: String,
    renewal_motion: String,
    review_surface: String,
    approved_claims: Vec<String>,
    evidence_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryRenewalApproval {
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
struct MercuryReferenceReuseDiscipline {
    schema: String,
    workflow_id: String,
    qualification_owner: String,
    review_owner: String,
    expansion_owner: String,
    renewal_motion: String,
    review_surface: String,
    approved_scope: String,
    permitted_reuse: Vec<String>,
    blocked_reuse: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryExpansionBoundaryHandoff {
    schema: String,
    workflow_id: String,
    expansion_owner: String,
    qualification_owner: String,
    review_owner: String,
    renewal_motion: String,
    review_surface: String,
    approved_scope: String,
    required_evidence: Vec<String>,
    deferred_requests: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MercuryRenewalQualificationExportSummary {
    pub(super) workflow_id: String,
    pub(super) renewal_motion: String,
    pub(super) review_surface: String,
    pub(super) qualification_owner: String,
    pub(super) review_owner: String,
    pub(super) expansion_owner: String,
    pub(super) delivery_continuity_dir: String,
    pub(super) renewal_qualification_profile_file: String,
    pub(super) renewal_qualification_package_file: String,
    pub(super) renewal_boundary_freeze_file: String,
    pub(super) renewal_qualification_manifest_file: String,
    pub(super) outcome_review_summary_file: String,
    pub(super) renewal_approval_file: String,
    pub(super) reference_reuse_discipline_file: String,
    pub(super) expansion_boundary_handoff_file: String,
    pub(super) renewal_evidence_dir: String,
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
struct MercuryRenewalQualificationDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_renewal_motion: String,
    selected_review_surface: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryRenewalQualificationValidationReport {
    workflow_id: String,
    decision: String,
    renewal_motion: String,
    review_surface: String,
    qualification_owner: String,
    review_owner: String,
    expansion_owner: String,
    same_workflow_boundary: String,
    renewal_qualification: MercuryRenewalQualificationExportSummary,
    decision_record_file: String,
    docs: MercuryRenewalQualificationDocRefs,
}

fn renewal_qualification_doc_refs() -> MercuryRenewalQualificationDocRefs {
    MercuryRenewalQualificationDocRefs {
        renewal_qualification_file: "docs/mercury/RENEWAL_QUALIFICATION.md".to_string(),
        operations_file: "docs/mercury/RENEWAL_QUALIFICATION_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/RENEWAL_QUALIFICATION_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/RENEWAL_QUALIFICATION_DECISION_RECORD.md".to_string(),
    }
}

fn build_renewal_qualification_profile(
    workflow_id: &str,
) -> Result<MercuryRenewalQualificationProfile, CliError> {
    let profile = MercuryRenewalQualificationProfile {
        schema: MERCURY_RENEWAL_QUALIFICATION_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "renewal-qualification-outcome-review-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        renewal_motion: MercuryRenewalQualificationMotion::RenewalQualification,
        review_surface: MercuryRenewalQualificationSurface::OutcomeReviewBundle,
        renewal_decision_gate: "evidence_backed_renewal_review_only".to_string(),
        retained_artifact_policy:
            "retain-bounded-renewal-qualification-and-outcome-review-artifacts".to_string(),
        intended_use: "Renew one previously stabilized Mercury account through one bounded outcome-review lane over the validated delivery-continuity, selective-account-activation, broader-distribution, reference-distribution, controlled-adoption, release-readiness, trust-network, assurance, proof, and inquiry chain without widening into generic customer-success tooling, CRM workflows, account-management platforms, channel marketplaces, or Chio commercial surfaces."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

pub(super) fn export_renewal_qualification(
    output: &Path,
) -> Result<MercuryRenewalQualificationExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let delivery_continuity_dir = output.join("delivery-continuity");
    let delivery_continuity = export_delivery_continuity(&delivery_continuity_dir)?;
    let workflow_id = delivery_continuity.workflow_id.clone();

    let profile = build_renewal_qualification_profile(&workflow_id)?;
    let profile_path = output.join("renewal-qualification-profile.json");
    write_json_file(&profile_path, &profile)?;

    let renewal_evidence_dir = output.join("renewal-evidence");
    fs::create_dir_all(&renewal_evidence_dir)?;

    let delivery_continuity_package_path =
        renewal_evidence_dir.join("delivery-continuity-package.json");
    let account_boundary_freeze_path = renewal_evidence_dir.join("account-boundary-freeze.json");
    let delivery_continuity_manifest_path =
        renewal_evidence_dir.join("delivery-continuity-manifest.json");
    let outcome_evidence_summary_path = renewal_evidence_dir.join("outcome-evidence-summary.json");
    let renewal_gate_path = renewal_evidence_dir.join("renewal-gate.json");
    let delivery_escalation_brief_path =
        renewal_evidence_dir.join("delivery-escalation-brief.json");
    let customer_evidence_handoff_path =
        renewal_evidence_dir.join("customer-evidence-handoff.json");
    let selective_account_activation_package_path =
        renewal_evidence_dir.join("selective-account-activation-package.json");
    let broader_distribution_package_path =
        renewal_evidence_dir.join("broader-distribution-package.json");
    let reference_distribution_package_path =
        renewal_evidence_dir.join("reference-distribution-package.json");
    let controlled_adoption_package_path =
        renewal_evidence_dir.join("controlled-adoption-package.json");
    let release_readiness_package_path =
        renewal_evidence_dir.join("release-readiness-package.json");
    let trust_network_package_path = renewal_evidence_dir.join("trust-network-package.json");
    let assurance_suite_package_path = renewal_evidence_dir.join("assurance-suite-package.json");
    let proof_package_path = renewal_evidence_dir.join("proof-package.json");
    let inquiry_package_path = renewal_evidence_dir.join("inquiry-package.json");
    let inquiry_verification_path = renewal_evidence_dir.join("inquiry-verification.json");
    let reviewer_package_path = renewal_evidence_dir.join("reviewer-package.json");
    let qualification_report_path = renewal_evidence_dir.join("qualification-report.json");

    copy_file(
        Path::new(&delivery_continuity.delivery_continuity_package_file),
        &delivery_continuity_package_path,
    )?;
    copy_file(
        Path::new(&delivery_continuity.account_boundary_freeze_file),
        &account_boundary_freeze_path,
    )?;
    copy_file(
        Path::new(&delivery_continuity.delivery_continuity_manifest_file),
        &delivery_continuity_manifest_path,
    )?;
    copy_file(
        Path::new(&delivery_continuity.outcome_evidence_summary_file),
        &outcome_evidence_summary_path,
    )?;
    copy_file(
        Path::new(&delivery_continuity.renewal_gate_file),
        &renewal_gate_path,
    )?;
    copy_file(
        Path::new(&delivery_continuity.delivery_escalation_brief_file),
        &delivery_escalation_brief_path,
    )?;
    copy_file(
        Path::new(&delivery_continuity.customer_evidence_handoff_file),
        &customer_evidence_handoff_path,
    )?;
    copy_file(
        Path::new(&delivery_continuity.selective_account_activation_package_file),
        &selective_account_activation_package_path,
    )?;
    copy_file(
        Path::new(&delivery_continuity.broader_distribution_package_file),
        &broader_distribution_package_path,
    )?;
    copy_file(
        Path::new(&delivery_continuity.reference_distribution_package_file),
        &reference_distribution_package_path,
    )?;
    copy_file(
        Path::new(&delivery_continuity.controlled_adoption_package_file),
        &controlled_adoption_package_path,
    )?;
    copy_file(
        Path::new(&delivery_continuity.release_readiness_package_file),
        &release_readiness_package_path,
    )?;
    copy_file(
        Path::new(&delivery_continuity.trust_network_package_file),
        &trust_network_package_path,
    )?;
    copy_file(
        Path::new(&delivery_continuity.assurance_suite_package_file),
        &assurance_suite_package_path,
    )?;
    copy_file(
        Path::new(&delivery_continuity.proof_package_file),
        &proof_package_path,
    )?;
    copy_file(
        Path::new(&delivery_continuity.inquiry_package_file),
        &inquiry_package_path,
    )?;
    copy_file(
        Path::new(&delivery_continuity.inquiry_verification_file),
        &inquiry_verification_path,
    )?;
    copy_file(
        Path::new(&delivery_continuity.reviewer_package_file),
        &reviewer_package_path,
    )?;
    copy_file(
        Path::new(&delivery_continuity.qualification_report_file),
        &qualification_report_path,
    )?;

    let approved_claim = "Mercury can renew one previously stabilized account through one renewal-qualification motion using one outcome-review bundle rooted in the validated delivery-continuity, selective-account-activation, broader-distribution, reference-distribution, controlled-adoption, release-readiness, trust-network, assurance, proof, and inquiry chain."
        .to_string();

    let renewal_boundary_freeze = MercuryRenewalBoundaryFreeze {
        schema: "chio.mercury.renewal_qualification_boundary_freeze.v1".to_string(),
        workflow_id: workflow_id.clone(),
        renewal_motion: MercuryRenewalQualificationMotion::RenewalQualification
            .as_str()
            .to_string(),
        review_surface: MercuryRenewalQualificationSurface::OutcomeReviewBundle
            .as_str()
            .to_string(),
        renewal_boundary_label:
            "one previously stabilized account inside one bounded renewal-qualification lane"
                .to_string(),
        entry_gates: vec![
            "delivery-continuity package and renewal gate remain current for the same workflow"
                .to_string(),
            "renewal qualification stays within one account, one renewal motion, and one outcome-review bundle"
                .to_string(),
            "renewal approval, reference reuse discipline, and expansion boundary handoff are present before renewal claims are reused"
                .to_string(),
        ],
        non_goals: vec![
            "generic customer-success tooling or CRM workflows".to_string(),
            "account-management platforms or channel marketplaces".to_string(),
            "Chio-side commercial control surfaces or merged product shells".to_string(),
        ],
        note: "This freeze keeps the next Mercury step bounded to one renewal motion over one already stabilized account."
            .to_string(),
    };
    let renewal_boundary_freeze_path = output.join("renewal-boundary-freeze.json");
    write_json_file(&renewal_boundary_freeze_path, &renewal_boundary_freeze)?;

    let renewal_qualification_manifest = MercuryRenewalQualificationManifest {
        schema: "chio.mercury.renewal_qualification_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        renewal_motion: MercuryRenewalQualificationMotion::RenewalQualification
            .as_str()
            .to_string(),
        review_surface: MercuryRenewalQualificationSurface::OutcomeReviewBundle
            .as_str()
            .to_string(),
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
        note: "This manifest freezes one outcome-review bundle over the existing Mercury renewal evidence chain and does not imply a generic customer-success, account-management, or Chio commercial surface."
            .to_string(),
    };
    let renewal_qualification_manifest_path = output.join("renewal-qualification-manifest.json");
    write_json_file(
        &renewal_qualification_manifest_path,
        &renewal_qualification_manifest,
    )?;

    let outcome_review_summary = MercuryOutcomeReviewSummary {
        schema: "chio.mercury.renewal_qualification_outcome_review_summary.v1".to_string(),
        workflow_id: workflow_id.clone(),
        qualification_owner: MERCURY_RENEWAL_QUALIFICATION_OWNER.to_string(),
        review_owner: MERCURY_OUTCOME_REVIEW_OWNER.to_string(),
        expansion_owner: MERCURY_EXPANSION_BOUNDARY_OWNER.to_string(),
        renewal_motion: MercuryRenewalQualificationMotion::RenewalQualification
            .as_str()
            .to_string(),
        review_surface: MercuryRenewalQualificationSurface::OutcomeReviewBundle
            .as_str()
            .to_string(),
        approved_claims: vec![
            approved_claim.clone(),
            "The renewal bundle remains bounded to one renewal motion, one outcome-review surface, and one explicit expansion-boundary handoff."
                .to_string(),
        ],
        evidence_files: vec![
            relative_display(output, &delivery_continuity_package_path)?,
            relative_display(output, &outcome_evidence_summary_path)?,
            relative_display(output, &renewal_gate_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &reviewer_package_path)?,
            relative_display(output, &qualification_report_path)?,
        ],
        note: "Outcome review remains Mercury-owned and evidence-backed for one renewal motion only."
            .to_string(),
    };
    let outcome_review_summary_path = output.join("outcome-review-summary.json");
    write_json_file(&outcome_review_summary_path, &outcome_review_summary)?;

    let renewal_approval = MercuryRenewalApproval {
        schema: "chio.mercury.renewal_qualification_approval.v1".to_string(),
        workflow_id: workflow_id.clone(),
        review_owner: MERCURY_OUTCOME_REVIEW_OWNER.to_string(),
        status: "ready".to_string(),
        reviewed_at: unix_now(),
        reviewed_by: MERCURY_OUTCOME_REVIEW_OWNER.to_string(),
        approved_claims: outcome_review_summary.approved_claims.clone(),
        required_files: vec![
            relative_display(output, &renewal_boundary_freeze_path)?,
            relative_display(output, &renewal_qualification_manifest_path)?,
            relative_display(output, &outcome_review_summary_path)?,
            relative_display(output, &renewal_gate_path)?,
            relative_display(output, &customer_evidence_handoff_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &reviewer_package_path)?,
        ],
        note: "Renewal approval must be refreshed before Mercury can reuse renewal claims for the same account."
            .to_string(),
    };
    let renewal_approval_path = output.join("renewal-approval.json");
    write_json_file(&renewal_approval_path, &renewal_approval)?;

    let reference_reuse_discipline = MercuryReferenceReuseDiscipline {
        schema: "chio.mercury.renewal_qualification_reference_reuse_discipline.v1".to_string(),
        workflow_id: workflow_id.clone(),
        qualification_owner: MERCURY_RENEWAL_QUALIFICATION_OWNER.to_string(),
        review_owner: MERCURY_OUTCOME_REVIEW_OWNER.to_string(),
        expansion_owner: MERCURY_EXPANSION_BOUNDARY_OWNER.to_string(),
        renewal_motion: MercuryRenewalQualificationMotion::RenewalQualification
            .as_str()
            .to_string(),
        review_surface: MercuryRenewalQualificationSurface::OutcomeReviewBundle
            .as_str()
            .to_string(),
        approved_scope:
            "one renewal-qualification outcome-review bundle for one previously stabilized Mercury account only".to_string(),
        permitted_reuse: vec![
            "renewal claims that map back to the same workflow and the same delivery-continuity package".to_string(),
            "reference reuse inside the same bounded account renewal motion".to_string(),
        ],
        blocked_reuse: vec![
            "new account expansion claims".to_string(),
            "generic customer-success or CRM workflow reuse".to_string(),
            "channel, marketplace, or Chio commercial control claims".to_string(),
        ],
        note: "Reference reuse stays bounded to the same renewal motion and cannot imply broader account expansion."
            .to_string(),
    };
    let reference_reuse_discipline_path = output.join("reference-reuse-discipline.json");
    write_json_file(
        &reference_reuse_discipline_path,
        &reference_reuse_discipline,
    )?;

    let expansion_boundary_handoff = MercuryExpansionBoundaryHandoff {
        schema: "chio.mercury.renewal_qualification_expansion_boundary_handoff.v1".to_string(),
        workflow_id: workflow_id.clone(),
        expansion_owner: MERCURY_EXPANSION_BOUNDARY_OWNER.to_string(),
        qualification_owner: MERCURY_RENEWAL_QUALIFICATION_OWNER.to_string(),
        review_owner: MERCURY_OUTCOME_REVIEW_OWNER.to_string(),
        renewal_motion: MercuryRenewalQualificationMotion::RenewalQualification
            .as_str()
            .to_string(),
        review_surface: MercuryRenewalQualificationSurface::OutcomeReviewBundle
            .as_str()
            .to_string(),
        approved_scope:
            "one bounded renewal-qualification lane over one previously stabilized Mercury account only".to_string(),
        required_evidence: vec![
            relative_display(output, &renewal_qualification_manifest_path)?,
            relative_display(output, &outcome_review_summary_path)?,
            relative_display(output, &renewal_approval_path)?,
            relative_display(output, &reference_reuse_discipline_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
        ],
        deferred_requests: vec![
            "multi-account expansion programs".to_string(),
            "generic account-management or customer-success platforms".to_string(),
            "channel marketplaces or Chio commercial control surfaces".to_string(),
        ],
        note: "Expansion handoff exists to keep the renewal lane narrow and evidence-backed, not to imply the next expansion decision is already approved."
            .to_string(),
    };
    let expansion_boundary_handoff_path = output.join("expansion-boundary-handoff.json");
    write_json_file(
        &expansion_boundary_handoff_path,
        &expansion_boundary_handoff,
    )?;

    let package = MercuryRenewalQualificationPackage {
        schema: MERCURY_RENEWAL_QUALIFICATION_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "renewal-qualification-outcome-review-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        renewal_motion: MercuryRenewalQualificationMotion::RenewalQualification,
        review_surface: MercuryRenewalQualificationSurface::OutcomeReviewBundle,
        qualification_owner: MERCURY_RENEWAL_QUALIFICATION_OWNER.to_string(),
        review_owner: MERCURY_OUTCOME_REVIEW_OWNER.to_string(),
        expansion_owner: MERCURY_EXPANSION_BOUNDARY_OWNER.to_string(),
        renewal_approval_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
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
            MercuryRenewalQualificationArtifact {
                artifact_kind: MercuryRenewalQualificationArtifactKind::RenewalBoundaryFreeze,
                relative_path: relative_display(output, &renewal_boundary_freeze_path)?,
            },
            MercuryRenewalQualificationArtifact {
                artifact_kind:
                    MercuryRenewalQualificationArtifactKind::RenewalQualificationManifest,
                relative_path: relative_display(output, &renewal_qualification_manifest_path)?,
            },
            MercuryRenewalQualificationArtifact {
                artifact_kind: MercuryRenewalQualificationArtifactKind::OutcomeReviewSummary,
                relative_path: relative_display(output, &outcome_review_summary_path)?,
            },
            MercuryRenewalQualificationArtifact {
                artifact_kind: MercuryRenewalQualificationArtifactKind::RenewalApproval,
                relative_path: relative_display(output, &renewal_approval_path)?,
            },
            MercuryRenewalQualificationArtifact {
                artifact_kind: MercuryRenewalQualificationArtifactKind::ReferenceReuseDiscipline,
                relative_path: relative_display(output, &reference_reuse_discipline_path)?,
            },
            MercuryRenewalQualificationArtifact {
                artifact_kind: MercuryRenewalQualificationArtifactKind::ExpansionBoundaryHandoff,
                relative_path: relative_display(output, &expansion_boundary_handoff_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("renewal-qualification-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryRenewalQualificationExportSummary {
        workflow_id,
        renewal_motion: MercuryRenewalQualificationMotion::RenewalQualification
            .as_str()
            .to_string(),
        review_surface: MercuryRenewalQualificationSurface::OutcomeReviewBundle
            .as_str()
            .to_string(),
        qualification_owner: MERCURY_RENEWAL_QUALIFICATION_OWNER.to_string(),
        review_owner: MERCURY_OUTCOME_REVIEW_OWNER.to_string(),
        expansion_owner: MERCURY_EXPANSION_BOUNDARY_OWNER.to_string(),
        delivery_continuity_dir: delivery_continuity_dir.display().to_string(),
        renewal_qualification_profile_file: profile_path.display().to_string(),
        renewal_qualification_package_file: package_path.display().to_string(),
        renewal_boundary_freeze_file: renewal_boundary_freeze_path.display().to_string(),
        renewal_qualification_manifest_file: renewal_qualification_manifest_path
            .display()
            .to_string(),
        outcome_review_summary_file: outcome_review_summary_path.display().to_string(),
        renewal_approval_file: renewal_approval_path.display().to_string(),
        reference_reuse_discipline_file: reference_reuse_discipline_path.display().to_string(),
        expansion_boundary_handoff_file: expansion_boundary_handoff_path.display().to_string(),
        renewal_evidence_dir: renewal_evidence_dir.display().to_string(),
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
    write_json_file(&output.join("renewal-qualification-summary.json"), &summary)?;

    Ok(summary)
}

pub fn cmd_mercury_renewal_qualification_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_renewal_qualification(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury renewal-qualification package exported");
        println!("output:                             {}", output.display());
        println!(
            "workflow_id:                        {}",
            summary.workflow_id
        );
        println!(
            "renewal_motion:                     {}",
            summary.renewal_motion
        );
        println!(
            "review_surface:                     {}",
            summary.review_surface
        );
        println!(
            "qualification_owner:                {}",
            summary.qualification_owner
        );
        println!(
            "review_owner:                       {}",
            summary.review_owner
        );
        println!(
            "expansion_owner:                    {}",
            summary.expansion_owner
        );
        println!(
            "renewal_qualification_package:      {}",
            summary.renewal_qualification_package_file
        );
        println!(
            "renewal_approval:                   {}",
            summary.renewal_approval_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_renewal_qualification_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let renewal_qualification_dir = output.join("renewal-qualification");
    let summary = export_renewal_qualification(&renewal_qualification_dir)?;
    let docs = renewal_qualification_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryRenewalQualificationDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_RENEWAL_QUALIFICATION_DECISION.to_string(),
        selected_renewal_motion: summary.renewal_motion.clone(),
        selected_review_surface: summary.review_surface.clone(),
        approved_scope:
            "Proceed with one bounded Mercury renewal-qualification lane only."
                .to_string(),
        deferred_scope: vec![
            "additional renewal motions or review surfaces".to_string(),
            "generic customer-success tooling, CRM workflows, or account-management platforms"
                .to_string(),
            "channel marketplaces or multi-account renewal programs".to_string(),
            "Chio-side commercial control surfaces".to_string(),
        ],
        rationale: "The renewal-qualification lane now packages one bounded outcome-review bundle, one renewal approval, one reference-reuse discipline, and one explicit expansion-boundary handoff over the validated delivery-continuity chain without widening Mercury into a generic customer platform or polluting Chio's generic substrate."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("renewal-qualification-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryRenewalQualificationValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_RENEWAL_QUALIFICATION_DECISION.to_string(),
        renewal_motion: summary.renewal_motion.clone(),
        review_surface: summary.review_surface.clone(),
        qualification_owner: summary.qualification_owner.clone(),
        review_owner: summary.review_owner.clone(),
        expansion_owner: summary.expansion_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        renewal_qualification: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury renewal-qualification validation package exported");
        println!("output:                             {}", output.display());
        println!("workflow_id:                        {}", report.workflow_id);
        println!("decision:                           {}", report.decision);
        println!(
            "renewal_motion:                     {}",
            report.renewal_motion
        );
        println!(
            "review_surface:                     {}",
            report.review_surface
        );
        println!(
            "qualification_owner:                {}",
            report.qualification_owner
        );
        println!(
            "review_owner:                       {}",
            report.review_owner
        );
        println!(
            "expansion_owner:                    {}",
            report.expansion_owner
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
            "renewal_qualification_package:      {}",
            report
                .renewal_qualification
                .renewal_qualification_package_file
        );
    }

    Ok(())
}
