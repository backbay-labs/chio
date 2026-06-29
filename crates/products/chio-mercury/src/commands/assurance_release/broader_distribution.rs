use super::super::*;
use super::export_reference_distribution;

pub(in crate::commands) fn export_broader_distribution(
    output: &Path,
) -> Result<MercuryBroaderDistributionExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let reference_distribution_dir = output.join("reference-distribution");
    let reference_distribution = export_reference_distribution(&reference_distribution_dir)?;
    let workflow_id = reference_distribution.workflow_id.clone();

    let profile = build_broader_distribution_profile(&workflow_id)?;
    let profile_path = output.join("broader-distribution-profile.json");
    write_json_file(&profile_path, &profile)?;

    let qualification_evidence_dir = output.join("qualification-evidence");
    fs::create_dir_all(&qualification_evidence_dir)?;

    let reference_distribution_package_path =
        qualification_evidence_dir.join("reference-distribution-package.json");
    let account_motion_freeze_path = qualification_evidence_dir.join("account-motion-freeze.json");
    let reference_distribution_manifest_path =
        qualification_evidence_dir.join("reference-distribution-manifest.json");
    let reference_claim_discipline_path =
        qualification_evidence_dir.join("reference-claim-discipline-rules.json");
    let reference_buyer_approval_path =
        qualification_evidence_dir.join("reference-buyer-approval.json");
    let reference_sales_handoff_path =
        qualification_evidence_dir.join("reference-sales-handoff-brief.json");
    let controlled_adoption_package_path =
        qualification_evidence_dir.join("controlled-adoption-package.json");
    let renewal_evidence_manifest_path =
        qualification_evidence_dir.join("renewal-evidence-manifest.json");
    let renewal_acknowledgement_path =
        qualification_evidence_dir.join("renewal-acknowledgement.json");
    let reference_readiness_brief_path =
        qualification_evidence_dir.join("reference-readiness-brief.json");
    let release_readiness_package_path =
        qualification_evidence_dir.join("release-readiness-package.json");
    let trust_network_package_path = qualification_evidence_dir.join("trust-network-package.json");
    let assurance_suite_package_path =
        qualification_evidence_dir.join("assurance-suite-package.json");
    let proof_package_path = qualification_evidence_dir.join("proof-package.json");
    let inquiry_package_path = qualification_evidence_dir.join("inquiry-package.json");
    let inquiry_verification_path = qualification_evidence_dir.join("inquiry-verification.json");
    let reviewer_package_path = qualification_evidence_dir.join("reviewer-package.json");
    let qualification_report_path = qualification_evidence_dir.join("qualification-report.json");

    copy_file(
        Path::new(&reference_distribution.reference_distribution_package_file),
        &reference_distribution_package_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.account_motion_freeze_file),
        &account_motion_freeze_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.reference_distribution_manifest_file),
        &reference_distribution_manifest_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.claim_discipline_rules_file),
        &reference_claim_discipline_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.buyer_reference_approval_file),
        &reference_buyer_approval_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.sales_handoff_brief_file),
        &reference_sales_handoff_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.controlled_adoption_package_file),
        &controlled_adoption_package_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.renewal_evidence_manifest_file),
        &renewal_evidence_manifest_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.renewal_acknowledgement_file),
        &renewal_acknowledgement_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.reference_readiness_brief_file),
        &reference_readiness_brief_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.release_readiness_package_file),
        &release_readiness_package_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.trust_network_package_file),
        &trust_network_package_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.assurance_suite_package_file),
        &assurance_suite_package_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.proof_package_file),
        &proof_package_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.inquiry_package_file),
        &inquiry_package_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.inquiry_verification_file),
        &inquiry_verification_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.reviewer_package_file),
        &reviewer_package_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.qualification_report_file),
        &qualification_report_path,
    )?;

    let approved_claim = "Mercury can support one bounded broader-distribution readiness motion using one governed distribution bundle for selective account qualification rooted in the validated reference-distribution, controlled-adoption, release-readiness, trust-network, assurance, proof, and inquiry stack.".to_string();

    let target_account_freeze = MercuryBroaderDistributionTargetAccountFreeze {
        schema: "chio.mercury.broader_distribution_target_account_freeze.v1".to_string(),
        workflow_id: workflow_id.clone(),
        distribution_motion: MercuryBroaderDistributionMotion::SelectiveAccountQualification
            .as_str()
            .to_string(),
        distribution_surface: MercuryBroaderDistributionSurface::GovernedDistributionBundle
            .as_str()
            .to_string(),
        target_account_segment:
            "one adjacent account matching the validated reference-backed workflow pattern"
                .to_string(),
        qualification_gates: vec![
            "same workflow boundary as the reference-distribution package".to_string(),
            "selective-account review stays within one governed bundle".to_string(),
            "claim-governance approval is present before handoff".to_string(),
        ],
        non_goals: vec![
            "generic sales tooling or CRM workflows".to_string(),
            "multi-segment channel programs or partner marketplaces".to_string(),
            "merged Mercury and Chio-Wall commercial packaging".to_string(),
        ],
        note: "This freeze keeps the next Mercury step bounded to one selective account-qualification motion over the existing reference-distribution package."
            .to_string(),
    };
    let target_account_freeze_path = output.join("target-account-freeze.json");
    write_json_file(&target_account_freeze_path, &target_account_freeze)?;

    let broader_distribution_manifest = MercuryBroaderDistributionManifest {
        schema: "chio.mercury.broader_distribution_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        distribution_motion: MercuryBroaderDistributionMotion::SelectiveAccountQualification
            .as_str()
            .to_string(),
        distribution_surface: MercuryBroaderDistributionSurface::GovernedDistributionBundle
            .as_str()
            .to_string(),
        reference_distribution_package_file: relative_display(
            output,
            &reference_distribution_package_path,
        )?,
        account_motion_freeze_file: relative_display(output, &account_motion_freeze_path)?,
        reference_distribution_manifest_file: relative_display(
            output,
            &reference_distribution_manifest_path,
        )?,
        reference_claim_discipline_file: relative_display(
            output,
            &reference_claim_discipline_path,
        )?,
        reference_buyer_approval_file: relative_display(output, &reference_buyer_approval_path)?,
        reference_sales_handoff_file: relative_display(output, &reference_sales_handoff_path)?,
        controlled_adoption_package_file: relative_display(
            output,
            &controlled_adoption_package_path,
        )?,
        renewal_evidence_manifest_file: relative_display(output, &renewal_evidence_manifest_path)?,
        renewal_acknowledgement_file: relative_display(output, &renewal_acknowledgement_path)?,
        reference_readiness_brief_file: relative_display(output, &reference_readiness_brief_path)?,
        release_readiness_package_file: relative_display(output, &release_readiness_package_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        inquiry_verification_file: relative_display(output, &inquiry_verification_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        note: "This manifest freezes one governed broader-distribution bundle over the existing Mercury truth chain and does not imply generic commercial tooling."
            .to_string(),
    };
    let broader_distribution_manifest_path = output.join("broader-distribution-manifest.json");
    write_json_file(
        &broader_distribution_manifest_path,
        &broader_distribution_manifest,
    )?;

    let claim_governance_rules = MercuryBroaderDistributionClaimGovernanceRules {
        schema: "chio.mercury.broader_distribution_claim_governance_rules.v1".to_string(),
        workflow_id: workflow_id.clone(),
        qualification_owner: MERCURY_QUALIFICATION_OWNER.to_string(),
        approval_owner: MERCURY_DISTRIBUTION_APPROVAL_OWNER.to_string(),
        fail_closed: true,
        approved_claims: vec![
            approved_claim.clone(),
            "The broader-distribution bundle remains bounded to one selective account-qualification motion and one governed distribution surface.".to_string(),
        ],
        prohibited_claims: vec![
            "Mercury is now a generic sales or channel platform".to_string(),
            "Chio provides a commercial broader-distribution console".to_string(),
            "the bundle proves universal rollout readiness or broad business performance".to_string(),
        ],
        note: "Claim governance stays Mercury-owned and fail-closed for one governed broader-distribution path."
            .to_string(),
    };
    let claim_governance_rules_path = output.join("claim-governance-rules.json");
    write_json_file(&claim_governance_rules_path, &claim_governance_rules)?;

    let selective_account_approval = MercuryBroaderDistributionSelectiveAccountApproval {
        schema: "chio.mercury.broader_distribution_selective_account_approval.v1".to_string(),
        workflow_id: workflow_id.clone(),
        approval_owner: MERCURY_DISTRIBUTION_APPROVAL_OWNER.to_string(),
        status: "approved".to_string(),
        approved_at: unix_now(),
        approved_by: MERCURY_DISTRIBUTION_APPROVAL_OWNER.to_string(),
        approved_claims: claim_governance_rules.approved_claims.clone(),
        required_files: vec![
            relative_display(output, &target_account_freeze_path)?,
            relative_display(output, &broader_distribution_manifest_path)?,
            relative_display(output, &claim_governance_rules_path)?,
            relative_display(output, &reference_distribution_package_path)?,
            relative_display(output, &reference_buyer_approval_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &reviewer_package_path)?,
        ],
        note: "Selective-account approval is required before the governed broader-distribution bundle can be handed off."
            .to_string(),
    };
    let selective_account_approval_path = output.join("selective-account-approval.json");
    write_json_file(
        &selective_account_approval_path,
        &selective_account_approval,
    )?;

    let distribution_handoff_brief = MercuryBroaderDistributionHandoffBrief {
        schema: "chio.mercury.broader_distribution_handoff_brief.v1".to_string(),
        workflow_id: workflow_id.clone(),
        distribution_owner: MERCURY_BROADER_DISTRIBUTION_OWNER.to_string(),
        qualification_owner: MERCURY_QUALIFICATION_OWNER.to_string(),
        approval_owner: MERCURY_DISTRIBUTION_APPROVAL_OWNER.to_string(),
        distribution_motion: MercuryBroaderDistributionMotion::SelectiveAccountQualification
            .as_str()
            .to_string(),
        distribution_surface: MercuryBroaderDistributionSurface::GovernedDistributionBundle
            .as_str()
            .to_string(),
        approved_scope: "one governed broader-distribution bundle for one selective account-qualification motion only"
            .to_string(),
        entry_criteria: vec![
            "reference-distribution package is present and internally consistent".to_string(),
            "claim-governance rules and selective-account approval are current".to_string(),
            "the target account remains within the frozen workflow boundary".to_string(),
        ],
        escalation_triggers: vec![
            "approved claim drifts from the governed bundle contents".to_string(),
            "required files are missing or no longer map to the same workflow".to_string(),
            "the motion broadens beyond one selective account or one governed bundle".to_string(),
        ],
        note: "The handoff brief exists to move one governed Mercury bundle into one selective account-qualification motion, not to define a generic commercial system."
            .to_string(),
    };
    let distribution_handoff_brief_path = output.join("distribution-handoff-brief.json");
    write_json_file(
        &distribution_handoff_brief_path,
        &distribution_handoff_brief,
    )?;

    let package = MercuryBroaderDistributionPackage {
        schema: MERCURY_BROADER_DISTRIBUTION_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "broader-distribution-selective-account-qualification-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        distribution_motion: MercuryBroaderDistributionMotion::SelectiveAccountQualification,
        distribution_surface: MercuryBroaderDistributionSurface::GovernedDistributionBundle,
        qualification_owner: MERCURY_QUALIFICATION_OWNER.to_string(),
        approval_owner: MERCURY_DISTRIBUTION_APPROVAL_OWNER.to_string(),
        distribution_owner: MERCURY_BROADER_DISTRIBUTION_OWNER.to_string(),
        approval_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        reference_distribution_package_file: relative_display(
            output,
            &reference_distribution_package_path,
        )?,
        account_motion_freeze_file: relative_display(output, &account_motion_freeze_path)?,
        reference_distribution_manifest_file: relative_display(
            output,
            &reference_distribution_manifest_path,
        )?,
        reference_claim_discipline_file: relative_display(
            output,
            &reference_claim_discipline_path,
        )?,
        reference_buyer_approval_file: relative_display(output, &reference_buyer_approval_path)?,
        reference_sales_handoff_file: relative_display(output, &reference_sales_handoff_path)?,
        controlled_adoption_package_file: relative_display(
            output,
            &controlled_adoption_package_path,
        )?,
        renewal_evidence_manifest_file: relative_display(output, &renewal_evidence_manifest_path)?,
        renewal_acknowledgement_file: relative_display(output, &renewal_acknowledgement_path)?,
        reference_readiness_brief_file: relative_display(output, &reference_readiness_brief_path)?,
        release_readiness_package_file: relative_display(output, &release_readiness_package_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        inquiry_verification_file: relative_display(output, &inquiry_verification_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        artifacts: vec![
            MercuryBroaderDistributionArtifact {
                artifact_kind: MercuryBroaderDistributionArtifactKind::TargetAccountFreeze,
                relative_path: relative_display(output, &target_account_freeze_path)?,
            },
            MercuryBroaderDistributionArtifact {
                artifact_kind: MercuryBroaderDistributionArtifactKind::BroaderDistributionManifest,
                relative_path: relative_display(output, &broader_distribution_manifest_path)?,
            },
            MercuryBroaderDistributionArtifact {
                artifact_kind: MercuryBroaderDistributionArtifactKind::ClaimGovernanceRules,
                relative_path: relative_display(output, &claim_governance_rules_path)?,
            },
            MercuryBroaderDistributionArtifact {
                artifact_kind: MercuryBroaderDistributionArtifactKind::SelectiveAccountApproval,
                relative_path: relative_display(output, &selective_account_approval_path)?,
            },
            MercuryBroaderDistributionArtifact {
                artifact_kind: MercuryBroaderDistributionArtifactKind::DistributionHandoffBrief,
                relative_path: relative_display(output, &distribution_handoff_brief_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("broader-distribution-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryBroaderDistributionExportSummary {
        workflow_id,
        distribution_motion: MercuryBroaderDistributionMotion::SelectiveAccountQualification
            .as_str()
            .to_string(),
        distribution_surface: MercuryBroaderDistributionSurface::GovernedDistributionBundle
            .as_str()
            .to_string(),
        qualification_owner: MERCURY_QUALIFICATION_OWNER.to_string(),
        approval_owner: MERCURY_DISTRIBUTION_APPROVAL_OWNER.to_string(),
        distribution_owner: MERCURY_BROADER_DISTRIBUTION_OWNER.to_string(),
        reference_distribution_dir: reference_distribution_dir.display().to_string(),
        broader_distribution_profile_file: profile_path.display().to_string(),
        broader_distribution_package_file: package_path.display().to_string(),
        target_account_freeze_file: target_account_freeze_path.display().to_string(),
        broader_distribution_manifest_file: broader_distribution_manifest_path
            .display()
            .to_string(),
        claim_governance_rules_file: claim_governance_rules_path.display().to_string(),
        selective_account_approval_file: selective_account_approval_path.display().to_string(),
        distribution_handoff_brief_file: distribution_handoff_brief_path.display().to_string(),
        qualification_evidence_dir: qualification_evidence_dir.display().to_string(),
        reference_distribution_package_file: reference_distribution_package_path
            .display()
            .to_string(),
        account_motion_freeze_file: account_motion_freeze_path.display().to_string(),
        reference_distribution_manifest_file: reference_distribution_manifest_path
            .display()
            .to_string(),
        reference_claim_discipline_file: reference_claim_discipline_path.display().to_string(),
        reference_buyer_approval_file: reference_buyer_approval_path.display().to_string(),
        reference_sales_handoff_file: reference_sales_handoff_path.display().to_string(),
        controlled_adoption_package_file: controlled_adoption_package_path.display().to_string(),
        renewal_evidence_manifest_file: renewal_evidence_manifest_path.display().to_string(),
        renewal_acknowledgement_file: renewal_acknowledgement_path.display().to_string(),
        reference_readiness_brief_file: reference_readiness_brief_path.display().to_string(),
        release_readiness_package_file: release_readiness_package_path.display().to_string(),
        trust_network_package_file: trust_network_package_path.display().to_string(),
        assurance_suite_package_file: assurance_suite_package_path.display().to_string(),
        proof_package_file: proof_package_path.display().to_string(),
        inquiry_package_file: inquiry_package_path.display().to_string(),
        inquiry_verification_file: inquiry_verification_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
    };
    write_json_file(&output.join("broader-distribution-summary.json"), &summary)?;

    let _ = reference_distribution;

    Ok(summary)
}
