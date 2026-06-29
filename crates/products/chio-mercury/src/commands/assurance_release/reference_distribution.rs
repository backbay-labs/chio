use super::super::*;
use super::export_controlled_adoption;

pub(in crate::commands) fn export_reference_distribution(
    output: &Path,
) -> Result<MercuryReferenceDistributionExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let controlled_adoption_dir = output.join("controlled-adoption");
    let controlled_adoption = export_controlled_adoption(&controlled_adoption_dir)?;
    let workflow_id = controlled_adoption.workflow_id.clone();

    let profile = build_reference_distribution_profile(&workflow_id)?;
    let profile_path = output.join("reference-distribution-profile.json");
    write_json_file(&profile_path, &profile)?;

    let reference_evidence_dir = output.join("reference-evidence");
    fs::create_dir_all(&reference_evidence_dir)?;

    let controlled_adoption_package_path =
        reference_evidence_dir.join("controlled-adoption-package.json");
    let renewal_evidence_manifest_path =
        reference_evidence_dir.join("renewal-evidence-manifest.json");
    let renewal_acknowledgement_path = reference_evidence_dir.join("renewal-acknowledgement.json");
    let reference_readiness_brief_path =
        reference_evidence_dir.join("reference-readiness-brief.json");
    let release_readiness_package_path =
        reference_evidence_dir.join("release-readiness-package.json");
    let trust_network_package_path = reference_evidence_dir.join("trust-network-package.json");
    let assurance_suite_package_path = reference_evidence_dir.join("assurance-suite-package.json");
    let proof_package_path = reference_evidence_dir.join("proof-package.json");
    let inquiry_package_path = reference_evidence_dir.join("inquiry-package.json");
    let inquiry_verification_path = reference_evidence_dir.join("inquiry-verification.json");
    let reviewer_package_path = reference_evidence_dir.join("reviewer-package.json");
    let qualification_report_path = reference_evidence_dir.join("qualification-report.json");

    copy_file(
        Path::new(&controlled_adoption.controlled_adoption_package_file),
        &controlled_adoption_package_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.renewal_evidence_manifest_file),
        &renewal_evidence_manifest_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.renewal_acknowledgement_file),
        &renewal_acknowledgement_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.reference_readiness_brief_file),
        &reference_readiness_brief_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.release_readiness_package_file),
        &release_readiness_package_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.trust_network_package_file),
        &trust_network_package_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.assurance_suite_package_file),
        &assurance_suite_package_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.proof_package_file),
        &proof_package_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.inquiry_package_file),
        &inquiry_package_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.inquiry_verification_file),
        &inquiry_verification_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.reviewer_package_file),
        &reviewer_package_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.qualification_report_file),
        &qualification_report_path,
    )?;

    let approved_claim = "Mercury can support one bounded landed-account expansion motion using one approved reference bundle rooted in the validated controlled-adoption, release-readiness, trust-network, assurance, proof, and inquiry stack.".to_string();

    let account_motion_freeze = MercuryReferenceDistributionAccountMotionFreeze {
        schema: "chio.mercury.reference_distribution_account_motion_freeze.v1".to_string(),
        workflow_id: workflow_id.clone(),
        expansion_motion: MercuryReferenceDistributionMotion::LandedAccountExpansion
            .as_str()
            .to_string(),
        distribution_surface: MercuryReferenceDistributionSurface::ApprovedReferenceBundle
            .as_str()
            .to_string(),
        landed_account_target:
            "one landed account already carrying design-partner renewal evidence".to_string(),
        approved_buyer_path: vec![
            "workflow engineering lead".to_string(),
            "head of trading platform or control-program sponsor".to_string(),
            "economic buyer reviewing one bounded reference bundle".to_string(),
        ],
        non_goals: vec![
            "generic sales tooling or CRM workflows".to_string(),
            "merged Mercury and Chio-Wall commercial packaging".to_string(),
            "additional landed-account motions or broader product-family claims".to_string(),
        ],
        note: "This freeze keeps the next Mercury step bounded to one landed-account expansion motion over the existing controlled-adoption package."
            .to_string(),
    };
    let account_motion_freeze_path = output.join("account-motion-freeze.json");
    write_json_file(&account_motion_freeze_path, &account_motion_freeze)?;

    let reference_distribution_manifest = MercuryReferenceDistributionManifest {
        schema: "chio.mercury.reference_distribution_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        expansion_motion: MercuryReferenceDistributionMotion::LandedAccountExpansion
            .as_str()
            .to_string(),
        distribution_surface: MercuryReferenceDistributionSurface::ApprovedReferenceBundle
            .as_str()
            .to_string(),
        controlled_adoption_package_file: relative_display(output, &controlled_adoption_package_path)?,
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
        note: "This manifest freezes one approved reference bundle over the existing Mercury truth chain and does not imply generic commercial packaging."
            .to_string(),
    };
    let reference_distribution_manifest_path = output.join("reference-distribution-manifest.json");
    write_json_file(
        &reference_distribution_manifest_path,
        &reference_distribution_manifest,
    )?;

    let claim_discipline_rules = MercuryReferenceDistributionClaimDisciplineRules {
        schema: "chio.mercury.reference_distribution_claim_discipline_rules.v1".to_string(),
        workflow_id: workflow_id.clone(),
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        buyer_approval_owner: MERCURY_BUYER_APPROVAL_OWNER.to_string(),
        fail_closed: true,
        approved_claims: vec![
            approved_claim.clone(),
            "The reference bundle remains bounded to one landed-account motion and one approved evidence chain.".to_string(),
        ],
        prohibited_claims: vec![
            "Mercury is now a generic sales platform".to_string(),
            "Chio provides a commercial expansion console".to_string(),
            "the bundle proves broad best-execution or universal rollout readiness".to_string(),
        ],
        note: "Claim discipline stays Mercury-owned and fail-closed for one approved reference-backed expansion path."
            .to_string(),
    };
    let claim_discipline_rules_path = output.join("claim-discipline-rules.json");
    write_json_file(&claim_discipline_rules_path, &claim_discipline_rules)?;

    let buyer_reference_approval = MercuryReferenceDistributionBuyerApproval {
        schema: "chio.mercury.reference_distribution_buyer_reference_approval.v1".to_string(),
        workflow_id: workflow_id.clone(),
        buyer_approval_owner: MERCURY_BUYER_APPROVAL_OWNER.to_string(),
        status: "approved".to_string(),
        approved_at: unix_now(),
        approved_by: MERCURY_BUYER_APPROVAL_OWNER.to_string(),
        approved_claims: claim_discipline_rules.approved_claims.clone(),
        required_files: vec![
            relative_display(output, &account_motion_freeze_path)?,
            relative_display(output, &reference_distribution_manifest_path)?,
            relative_display(output, &claim_discipline_rules_path)?,
            relative_display(output, &renewal_acknowledgement_path)?,
            relative_display(output, &reference_readiness_brief_path)?,
            relative_display(output, &controlled_adoption_package_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
        ],
        note: "Buyer-reference approval is required before the bounded landed-account motion can use the approved reference bundle."
            .to_string(),
    };
    let buyer_reference_approval_path = output.join("buyer-reference-approval.json");
    write_json_file(&buyer_reference_approval_path, &buyer_reference_approval)?;

    let sales_handoff_brief = MercuryReferenceDistributionSalesHandoffBrief {
        schema: "chio.mercury.reference_distribution_sales_handoff_brief.v1".to_string(),
        workflow_id: workflow_id.clone(),
        sales_owner: MERCURY_LANDED_ACCOUNT_SALES_OWNER.to_string(),
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        buyer_approval_owner: MERCURY_BUYER_APPROVAL_OWNER.to_string(),
        expansion_motion: MercuryReferenceDistributionMotion::LandedAccountExpansion
            .as_str()
            .to_string(),
        distribution_surface: MercuryReferenceDistributionSurface::ApprovedReferenceBundle
            .as_str()
            .to_string(),
        approved_scope: "one approved reference-backed landed-account expansion motion only"
            .to_string(),
        entry_criteria: vec![
            "controlled-adoption package is present and internally consistent".to_string(),
            "renewal acknowledgement and reference-readiness brief are current".to_string(),
            "buyer-reference approval is present before handoff".to_string(),
        ],
        escalation_triggers: vec![
            "approved claim drifts from the bundle contents".to_string(),
            "required files are missing or no longer map to the same workflow".to_string(),
            "the motion broadens beyond one landed account or one reference bundle".to_string(),
        ],
        note: "The handoff brief exists to move one approved Mercury reference bundle into one landed-account motion, not to define a generic sales system."
            .to_string(),
    };
    let sales_handoff_brief_path = output.join("sales-handoff-brief.json");
    write_json_file(&sales_handoff_brief_path, &sales_handoff_brief)?;

    let package = MercuryReferenceDistributionPackage {
        schema: MERCURY_REFERENCE_DISTRIBUTION_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "reference-distribution-landed-account-expansion-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        expansion_motion: MercuryReferenceDistributionMotion::LandedAccountExpansion,
        distribution_surface: MercuryReferenceDistributionSurface::ApprovedReferenceBundle,
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        buyer_approval_owner: MERCURY_BUYER_APPROVAL_OWNER.to_string(),
        sales_owner: MERCURY_LANDED_ACCOUNT_SALES_OWNER.to_string(),
        approval_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
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
            MercuryReferenceDistributionArtifact {
                artifact_kind: MercuryReferenceDistributionArtifactKind::AccountMotionFreeze,
                relative_path: relative_display(output, &account_motion_freeze_path)?,
            },
            MercuryReferenceDistributionArtifact {
                artifact_kind:
                    MercuryReferenceDistributionArtifactKind::ReferenceDistributionManifest,
                relative_path: relative_display(output, &reference_distribution_manifest_path)?,
            },
            MercuryReferenceDistributionArtifact {
                artifact_kind: MercuryReferenceDistributionArtifactKind::ClaimDisciplineRules,
                relative_path: relative_display(output, &claim_discipline_rules_path)?,
            },
            MercuryReferenceDistributionArtifact {
                artifact_kind: MercuryReferenceDistributionArtifactKind::BuyerReferenceApproval,
                relative_path: relative_display(output, &buyer_reference_approval_path)?,
            },
            MercuryReferenceDistributionArtifact {
                artifact_kind: MercuryReferenceDistributionArtifactKind::SalesHandoffBrief,
                relative_path: relative_display(output, &sales_handoff_brief_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("reference-distribution-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryReferenceDistributionExportSummary {
        workflow_id,
        expansion_motion: MercuryReferenceDistributionMotion::LandedAccountExpansion
            .as_str()
            .to_string(),
        distribution_surface: MercuryReferenceDistributionSurface::ApprovedReferenceBundle
            .as_str()
            .to_string(),
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        buyer_approval_owner: MERCURY_BUYER_APPROVAL_OWNER.to_string(),
        sales_owner: MERCURY_LANDED_ACCOUNT_SALES_OWNER.to_string(),
        controlled_adoption_dir: controlled_adoption_dir.display().to_string(),
        reference_distribution_profile_file: profile_path.display().to_string(),
        reference_distribution_package_file: package_path.display().to_string(),
        account_motion_freeze_file: account_motion_freeze_path.display().to_string(),
        reference_distribution_manifest_file: reference_distribution_manifest_path
            .display()
            .to_string(),
        claim_discipline_rules_file: claim_discipline_rules_path.display().to_string(),
        buyer_reference_approval_file: buyer_reference_approval_path.display().to_string(),
        sales_handoff_brief_file: sales_handoff_brief_path.display().to_string(),
        reference_evidence_dir: reference_evidence_dir.display().to_string(),
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
    write_json_file(
        &output.join("reference-distribution-summary.json"),
        &summary,
    )?;

    let _ = controlled_adoption;

    Ok(summary)
}
