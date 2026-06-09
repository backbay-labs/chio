fn export_selective_account_activation(
    output: &Path,
) -> Result<MercurySelectiveAccountActivationExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let broader_distribution_dir = output.join("broader-distribution");
    let broader_distribution = export_broader_distribution(&broader_distribution_dir)?;
    let workflow_id = broader_distribution.workflow_id.clone();

    let profile = build_selective_account_activation_profile(&workflow_id)?;
    let profile_path = output.join("selective-account-activation-profile.json");
    write_json_file(&profile_path, &profile)?;

    let activation_evidence_dir = output.join("activation-evidence");
    fs::create_dir_all(&activation_evidence_dir)?;

    let broader_distribution_package_path =
        activation_evidence_dir.join("broader-distribution-package.json");
    let target_account_freeze_path = activation_evidence_dir.join("target-account-freeze.json");
    let broader_distribution_manifest_path =
        activation_evidence_dir.join("broader-distribution-manifest.json");
    let claim_governance_rules_path = activation_evidence_dir.join("claim-governance-rules.json");
    let selective_account_approval_path =
        activation_evidence_dir.join("selective-account-approval.json");
    let distribution_handoff_brief_path =
        activation_evidence_dir.join("distribution-handoff-brief.json");
    let reference_distribution_package_path =
        activation_evidence_dir.join("reference-distribution-package.json");
    let controlled_adoption_package_path =
        activation_evidence_dir.join("controlled-adoption-package.json");
    let release_readiness_package_path =
        activation_evidence_dir.join("release-readiness-package.json");
    let trust_network_package_path = activation_evidence_dir.join("trust-network-package.json");
    let assurance_suite_package_path = activation_evidence_dir.join("assurance-suite-package.json");
    let proof_package_path = activation_evidence_dir.join("proof-package.json");
    let inquiry_package_path = activation_evidence_dir.join("inquiry-package.json");
    let inquiry_verification_path = activation_evidence_dir.join("inquiry-verification.json");
    let reviewer_package_path = activation_evidence_dir.join("reviewer-package.json");
    let qualification_report_path = activation_evidence_dir.join("qualification-report.json");

    copy_file(
        Path::new(&broader_distribution.broader_distribution_package_file),
        &broader_distribution_package_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.target_account_freeze_file),
        &target_account_freeze_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.broader_distribution_manifest_file),
        &broader_distribution_manifest_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.claim_governance_rules_file),
        &claim_governance_rules_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.selective_account_approval_file),
        &selective_account_approval_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.distribution_handoff_brief_file),
        &distribution_handoff_brief_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.reference_distribution_package_file),
        &reference_distribution_package_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.controlled_adoption_package_file),
        &controlled_adoption_package_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.release_readiness_package_file),
        &release_readiness_package_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.trust_network_package_file),
        &trust_network_package_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.assurance_suite_package_file),
        &assurance_suite_package_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.proof_package_file),
        &proof_package_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.inquiry_package_file),
        &inquiry_package_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.inquiry_verification_file),
        &inquiry_verification_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.reviewer_package_file),
        &reviewer_package_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.qualification_report_file),
        &qualification_report_path,
    )?;

    let approved_claim = "Mercury can activate one previously qualified account using one controlled delivery bundle rooted in the validated broader-distribution, reference-distribution, controlled-adoption, release-readiness, trust-network, assurance, proof, and inquiry stack."
        .to_string();

    let activation_scope_freeze = MercurySelectiveAccountActivationScopeFreeze {
        schema: "chio.mercury.selective_account_activation_scope_freeze.v1".to_string(),
        workflow_id: workflow_id.clone(),
        activation_motion: MercurySelectiveAccountActivationMotion::SelectiveAccountActivation
            .as_str()
            .to_string(),
        delivery_surface: MercurySelectiveAccountActivationSurface::ControlledDeliveryBundle
            .as_str()
            .to_string(),
        target_account_label:
            "one previously qualified account accepted through the broader-distribution lane"
                .to_string(),
        entry_gates: vec![
            "broader-distribution approval remains current for the same workflow".to_string(),
            "delivery stays within one controlled bundle and one product-owned handoff".to_string(),
            "claim containment and approval refresh are present before activation".to_string(),
        ],
        non_goals: vec![
            "generic onboarding tooling or success automation".to_string(),
            "CRM workflows or channel marketplace routing".to_string(),
            "Chio-side commercial control surfaces or merged shells".to_string(),
        ],
        note: "This freeze keeps the next Mercury step bounded to one selective-account activation motion over the existing broader-distribution package."
            .to_string(),
    };
    let activation_scope_freeze_path = output.join("activation-scope-freeze.json");
    write_json_file(&activation_scope_freeze_path, &activation_scope_freeze)?;

    let activation_manifest = MercurySelectiveAccountActivationManifest {
        schema: "chio.mercury.selective_account_activation_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        activation_motion: MercurySelectiveAccountActivationMotion::SelectiveAccountActivation
            .as_str()
            .to_string(),
        delivery_surface: MercurySelectiveAccountActivationSurface::ControlledDeliveryBundle
            .as_str()
            .to_string(),
        broader_distribution_package_file: relative_display(
            output,
            &broader_distribution_package_path,
        )?,
        target_account_freeze_file: relative_display(output, &target_account_freeze_path)?,
        broader_distribution_manifest_file: relative_display(
            output,
            &broader_distribution_manifest_path,
        )?,
        claim_governance_rules_file: relative_display(output, &claim_governance_rules_path)?,
        selective_account_approval_file: relative_display(output, &selective_account_approval_path)?,
        distribution_handoff_brief_file: relative_display(output, &distribution_handoff_brief_path)?,
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
        note: "This manifest freezes one controlled-delivery bundle over the existing Mercury truth chain and does not imply a generic onboarding or channel system."
            .to_string(),
    };
    let activation_manifest_path = output.join("selective-account-activation-manifest.json");
    write_json_file(&activation_manifest_path, &activation_manifest)?;

    let claim_containment_rules = MercurySelectiveAccountActivationClaimContainmentRules {
        schema: "chio.mercury.selective_account_activation_claim_containment_rules.v1".to_string(),
        workflow_id: workflow_id.clone(),
        activation_owner: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_OWNER.to_string(),
        approval_owner: MERCURY_ACTIVATION_APPROVAL_OWNER.to_string(),
        fail_closed: true,
        approved_claims: vec![
            approved_claim.clone(),
            "The selective-account activation bundle remains bounded to one activation motion and one controlled delivery surface."
                .to_string(),
        ],
        prohibited_claims: vec![
            "Mercury now provides a generic onboarding or CRM platform".to_string(),
            "Chio exposes a commercial activation console".to_string(),
            "the bundle proves universal rollout readiness or broad business performance"
                .to_string(),
        ],
        note: "Claim containment stays Mercury-owned and fail-closed for one selective-account activation path."
            .to_string(),
    };
    let claim_containment_rules_path = output.join("claim-containment-rules.json");
    write_json_file(&claim_containment_rules_path, &claim_containment_rules)?;

    let activation_approval_refresh = MercurySelectiveAccountActivationApprovalRefresh {
        schema: "chio.mercury.selective_account_activation_approval_refresh.v1".to_string(),
        workflow_id: workflow_id.clone(),
        approval_owner: MERCURY_ACTIVATION_APPROVAL_OWNER.to_string(),
        status: "refreshed".to_string(),
        refreshed_at: unix_now(),
        refreshed_by: MERCURY_ACTIVATION_APPROVAL_OWNER.to_string(),
        approved_claims: claim_containment_rules.approved_claims.clone(),
        required_files: vec![
            relative_display(output, &activation_scope_freeze_path)?,
            relative_display(output, &activation_manifest_path)?,
            relative_display(output, &claim_containment_rules_path)?,
            relative_display(output, &broader_distribution_package_path)?,
            relative_display(output, &selective_account_approval_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &reviewer_package_path)?,
        ],
        note: "Approval refresh is required before controlled delivery can proceed for the bounded selective-account activation bundle."
            .to_string(),
    };
    let activation_approval_refresh_path = output.join("activation-approval-refresh.json");
    write_json_file(
        &activation_approval_refresh_path,
        &activation_approval_refresh,
    )?;

    let customer_handoff_brief = MercurySelectiveAccountActivationCustomerHandoffBrief {
        schema: "chio.mercury.selective_account_activation_customer_handoff_brief.v1".to_string(),
        workflow_id: workflow_id.clone(),
        delivery_owner: MERCURY_CONTROLLED_DELIVERY_OWNER.to_string(),
        activation_owner: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_OWNER.to_string(),
        approval_owner: MERCURY_ACTIVATION_APPROVAL_OWNER.to_string(),
        activation_motion: MercurySelectiveAccountActivationMotion::SelectiveAccountActivation
            .as_str()
            .to_string(),
        delivery_surface: MercurySelectiveAccountActivationSurface::ControlledDeliveryBundle
            .as_str()
            .to_string(),
        approved_scope: "one controlled-delivery bundle for one previously qualified account only"
            .to_string(),
        entry_criteria: vec![
            "broader-distribution package and approval remain internally consistent".to_string(),
            "claim-containment rules and approval refresh are current".to_string(),
            "customer handoff stays within one product-owned delivery motion".to_string(),
        ],
        escalation_triggers: vec![
            "approved claim drifts from the delivery bundle contents".to_string(),
            "required files are missing or no longer map to the same workflow".to_string(),
            "the motion widens beyond one account or one controlled delivery bundle".to_string(),
        ],
        note: "The customer handoff brief exists to move one governed Mercury bundle into one controlled delivery motion, not to define a generic onboarding or account-management system."
            .to_string(),
    };
    let customer_handoff_brief_path = output.join("customer-handoff-brief.json");
    write_json_file(&customer_handoff_brief_path, &customer_handoff_brief)?;

    let package = MercurySelectiveAccountActivationPackage {
        schema: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "selective-account-activation-controlled-delivery-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        activation_motion: MercurySelectiveAccountActivationMotion::SelectiveAccountActivation,
        delivery_surface: MercurySelectiveAccountActivationSurface::ControlledDeliveryBundle,
        activation_owner: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_OWNER.to_string(),
        approval_owner: MERCURY_ACTIVATION_APPROVAL_OWNER.to_string(),
        delivery_owner: MERCURY_CONTROLLED_DELIVERY_OWNER.to_string(),
        approval_refresh_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        broader_distribution_package_file: relative_display(
            output,
            &broader_distribution_package_path,
        )?,
        target_account_freeze_file: relative_display(output, &target_account_freeze_path)?,
        broader_distribution_manifest_file: relative_display(
            output,
            &broader_distribution_manifest_path,
        )?,
        claim_governance_rules_file: relative_display(output, &claim_governance_rules_path)?,
        selective_account_approval_file: relative_display(
            output,
            &selective_account_approval_path,
        )?,
        distribution_handoff_brief_file: relative_display(
            output,
            &distribution_handoff_brief_path,
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
            MercurySelectiveAccountActivationArtifact {
                artifact_kind: MercurySelectiveAccountActivationArtifactKind::ActivationScopeFreeze,
                relative_path: relative_display(output, &activation_scope_freeze_path)?,
            },
            MercurySelectiveAccountActivationArtifact {
                artifact_kind: MercurySelectiveAccountActivationArtifactKind::ActivationManifest,
                relative_path: relative_display(output, &activation_manifest_path)?,
            },
            MercurySelectiveAccountActivationArtifact {
                artifact_kind: MercurySelectiveAccountActivationArtifactKind::ClaimContainmentRules,
                relative_path: relative_display(output, &claim_containment_rules_path)?,
            },
            MercurySelectiveAccountActivationArtifact {
                artifact_kind:
                    MercurySelectiveAccountActivationArtifactKind::ActivationApprovalRefresh,
                relative_path: relative_display(output, &activation_approval_refresh_path)?,
            },
            MercurySelectiveAccountActivationArtifact {
                artifact_kind: MercurySelectiveAccountActivationArtifactKind::CustomerHandoffBrief,
                relative_path: relative_display(output, &customer_handoff_brief_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("selective-account-activation-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercurySelectiveAccountActivationExportSummary {
        workflow_id,
        activation_motion: MercurySelectiveAccountActivationMotion::SelectiveAccountActivation
            .as_str()
            .to_string(),
        delivery_surface: MercurySelectiveAccountActivationSurface::ControlledDeliveryBundle
            .as_str()
            .to_string(),
        activation_owner: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_OWNER.to_string(),
        approval_owner: MERCURY_ACTIVATION_APPROVAL_OWNER.to_string(),
        delivery_owner: MERCURY_CONTROLLED_DELIVERY_OWNER.to_string(),
        broader_distribution_dir: broader_distribution_dir.display().to_string(),
        selective_account_activation_profile_file: profile_path.display().to_string(),
        selective_account_activation_package_file: package_path.display().to_string(),
        activation_scope_freeze_file: activation_scope_freeze_path.display().to_string(),
        selective_account_activation_manifest_file: activation_manifest_path.display().to_string(),
        claim_containment_rules_file: claim_containment_rules_path.display().to_string(),
        activation_approval_refresh_file: activation_approval_refresh_path.display().to_string(),
        customer_handoff_brief_file: customer_handoff_brief_path.display().to_string(),
        activation_evidence_dir: activation_evidence_dir.display().to_string(),
        broader_distribution_package_file: broader_distribution_package_path.display().to_string(),
        target_account_freeze_file: target_account_freeze_path.display().to_string(),
        broader_distribution_manifest_file: broader_distribution_manifest_path
            .display()
            .to_string(),
        claim_governance_rules_file: claim_governance_rules_path.display().to_string(),
        selective_account_approval_file: selective_account_approval_path.display().to_string(),
        distribution_handoff_brief_file: distribution_handoff_brief_path.display().to_string(),
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
        &output.join("selective-account-activation-summary.json"),
        &summary,
    )?;

    Ok(summary)
}

pub fn cmd_mercury_selective_account_activation_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_selective_account_activation(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury selective-account-activation package exported");
        println!("output:                             {}", output.display());
        println!(
            "workflow_id:                        {}",
            summary.workflow_id
        );
        println!(
            "activation_motion:                  {}",
            summary.activation_motion
        );
        println!(
            "delivery_surface:                   {}",
            summary.delivery_surface
        );
        println!(
            "activation_owner:                   {}",
            summary.activation_owner
        );
        println!(
            "approval_owner:                     {}",
            summary.approval_owner
        );
        println!(
            "delivery_owner:                     {}",
            summary.delivery_owner
        );
        println!(
            "selective_account_activation_package: {}",
            summary.selective_account_activation_package_file
        );
        println!(
            "activation_approval_refresh:        {}",
            summary.activation_approval_refresh_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_selective_account_activation_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let selective_account_activation_dir = output.join("selective-account-activation");
    let summary = export_selective_account_activation(&selective_account_activation_dir)?;
    let docs = selective_account_activation_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercurySelectiveAccountActivationDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_DECISION.to_string(),
        selected_activation_motion: summary.activation_motion.clone(),
        selected_delivery_surface: summary.delivery_surface.clone(),
        approved_scope:
            "Proceed with one bounded Mercury selective-account activation lane only."
                .to_string(),
        deferred_scope: vec![
            "additional selective-account activation motions or surfaces".to_string(),
            "generic onboarding tooling, CRM workflows, or commercial consoles".to_string(),
            "channel marketplaces or multi-segment activation programs".to_string(),
            "merged Mercury and Chio-Wall commercial packaging".to_string(),
            "Chio-side commercial control surfaces".to_string(),
        ],
        rationale: "The selective-account activation lane now packages one controlled delivery motion over the validated broader-distribution stack without widening Mercury into a generic onboarding platform or polluting Chio's generic substrate."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("selective-account-activation-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercurySelectiveAccountActivationValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_DECISION.to_string(),
        activation_motion: summary.activation_motion.clone(),
        delivery_surface: summary.delivery_surface.clone(),
        activation_owner: summary.activation_owner.clone(),
        approval_owner: summary.approval_owner.clone(),
        delivery_owner: summary.delivery_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        selective_account_activation: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury selective-account-activation validation package exported");
        println!("output:                             {}", output.display());
        println!("workflow_id:                        {}", report.workflow_id);
        println!("decision:                           {}", report.decision);
        println!(
            "activation_motion:                  {}",
            report.activation_motion
        );
        println!(
            "delivery_surface:                   {}",
            report.delivery_surface
        );
        println!(
            "activation_owner:                   {}",
            report.activation_owner
        );
        println!(
            "approval_owner:                     {}",
            report.approval_owner
        );
        println!(
            "delivery_owner:                     {}",
            report.delivery_owner
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
            "selective_account_activation_package: {}",
            report
                .selective_account_activation
                .selective_account_activation_package_file
        );
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDeliveryContinuityDocRefs {
    delivery_continuity_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDeliveryContinuityAccountBoundaryFreeze {
    schema: String,
    workflow_id: String,
    continuity_motion: String,
    continuity_surface: String,
    account_boundary_label: String,
    entry_gates: Vec<String>,
    non_goals: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDeliveryContinuityManifest {
    schema: String,
    workflow_id: String,
    continuity_motion: String,
    continuity_surface: String,
    selective_account_activation_package_file: String,
    activation_scope_freeze_file: String,
    selective_account_activation_manifest_file: String,
    claim_containment_rules_file: String,
    activation_approval_refresh_file: String,
    customer_handoff_brief_file: String,
    broader_distribution_package_file: String,
    broader_distribution_manifest_file: String,
    target_account_freeze_file: String,
    claim_governance_rules_file: String,
    selective_account_approval_file: String,
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
struct MercuryDeliveryContinuityOutcomeEvidenceSummary {
    schema: String,
    workflow_id: String,
    continuity_owner: String,
    renewal_owner: String,
    evidence_owner: String,
    continuity_motion: String,
    continuity_surface: String,
    supported_claims: Vec<String>,
    evidence_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDeliveryContinuityRenewalGate {
    schema: String,
    workflow_id: String,
    renewal_owner: String,
    status: String,
    reviewed_at: u64,
    reviewed_by: String,
    approved_claims: Vec<String>,
    required_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDeliveryContinuityDeliveryEscalationBrief {
    schema: String,
    workflow_id: String,
    continuity_owner: String,
    evidence_owner: String,
    renewal_owner: String,
    continuity_motion: String,
    continuity_surface: String,
    service_boundary: String,
    escalation_triggers: Vec<String>,
    immediate_actions: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDeliveryContinuityCustomerEvidenceHandoff {
    schema: String,
    workflow_id: String,
    evidence_owner: String,
    continuity_owner: String,
    renewal_owner: String,
    continuity_motion: String,
    continuity_surface: String,
    approved_scope: String,
    required_evidence: Vec<String>,
    deferred_requests: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDeliveryContinuityExportSummary {
    workflow_id: String,
    continuity_motion: String,
    continuity_surface: String,
    continuity_owner: String,
    renewal_owner: String,
    evidence_owner: String,
    selective_account_activation_dir: String,
    delivery_continuity_profile_file: String,
    delivery_continuity_package_file: String,
    account_boundary_freeze_file: String,
    delivery_continuity_manifest_file: String,
    outcome_evidence_summary_file: String,
    renewal_gate_file: String,
    delivery_escalation_brief_file: String,
    customer_evidence_handoff_file: String,
    continuity_evidence_dir: String,
    selective_account_activation_package_file: String,
    activation_scope_freeze_file: String,
    selective_account_activation_manifest_file: String,
    claim_containment_rules_file: String,
    activation_approval_refresh_file: String,
    customer_handoff_brief_file: String,
    broader_distribution_package_file: String,
    broader_distribution_manifest_file: String,
    target_account_freeze_file: String,
    claim_governance_rules_file: String,
    selective_account_approval_file: String,
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
struct MercuryDeliveryContinuityDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_continuity_motion: String,
    selected_continuity_surface: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDeliveryContinuityValidationReport {
    workflow_id: String,
    decision: String,
    continuity_motion: String,
    continuity_surface: String,
    continuity_owner: String,
    renewal_owner: String,
    evidence_owner: String,
    same_workflow_boundary: String,
    delivery_continuity: MercuryDeliveryContinuityExportSummary,
    decision_record_file: String,
    docs: MercuryDeliveryContinuityDocRefs,
}

fn delivery_continuity_doc_refs() -> MercuryDeliveryContinuityDocRefs {
    MercuryDeliveryContinuityDocRefs {
        delivery_continuity_file: "docs/mercury/DELIVERY_CONTINUITY.md".to_string(),
        operations_file: "docs/mercury/DELIVERY_CONTINUITY_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/DELIVERY_CONTINUITY_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/DELIVERY_CONTINUITY_DECISION_RECORD.md".to_string(),
    }
}

fn build_delivery_continuity_profile(
    workflow_id: &str,
) -> Result<MercuryDeliveryContinuityProfile, CliError> {
    let profile = MercuryDeliveryContinuityProfile {
        schema: MERCURY_DELIVERY_CONTINUITY_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "delivery-continuity-outcome-evidence-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        continuity_motion: MercuryDeliveryContinuityMotion::ControlledDeliveryContinuity,
        continuity_surface: MercuryDeliveryContinuitySurface::OutcomeEvidenceBundle,
        renewal_gate: "evidence_backed_renewal_only".to_string(),
        retained_artifact_policy:
            "retain-bounded-delivery-continuity-and-renewal-gate-artifacts".to_string(),
        intended_use: "Maintain one previously activated Mercury account inside one bounded controlled-delivery continuity lane with one renewal gate over the validated selective-account-activation package, without widening into generic onboarding tooling, CRM workflows, support desks, channel marketplaces, or Chio commercial surfaces."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

fn export_delivery_continuity(
    output: &Path,
) -> Result<MercuryDeliveryContinuityExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let selective_account_activation_dir = output.join("selective-account-activation");
    let selective_account_activation =
        export_selective_account_activation(&selective_account_activation_dir)?;
    let workflow_id = selective_account_activation.workflow_id.clone();

    let profile = build_delivery_continuity_profile(&workflow_id)?;
    let profile_path = output.join("delivery-continuity-profile.json");
    write_json_file(&profile_path, &profile)?;

    let continuity_evidence_dir = output.join("continuity-evidence");
    fs::create_dir_all(&continuity_evidence_dir)?;

    let selective_account_activation_package_path =
        continuity_evidence_dir.join("selective-account-activation-package.json");
    let activation_scope_freeze_path = continuity_evidence_dir.join("activation-scope-freeze.json");
    let selective_account_activation_manifest_path =
        continuity_evidence_dir.join("selective-account-activation-manifest.json");
    let claim_containment_rules_path = continuity_evidence_dir.join("claim-containment-rules.json");
    let activation_approval_refresh_path =
        continuity_evidence_dir.join("activation-approval-refresh.json");
    let customer_handoff_brief_path = continuity_evidence_dir.join("customer-handoff-brief.json");
    let broader_distribution_package_path =
        continuity_evidence_dir.join("broader-distribution-package.json");
    let broader_distribution_manifest_path =
        continuity_evidence_dir.join("broader-distribution-manifest.json");
    let target_account_freeze_path = continuity_evidence_dir.join("target-account-freeze.json");
    let claim_governance_rules_path = continuity_evidence_dir.join("claim-governance-rules.json");
    let selective_account_approval_path =
        continuity_evidence_dir.join("selective-account-approval.json");
    let reference_distribution_package_path =
        continuity_evidence_dir.join("reference-distribution-package.json");
    let controlled_adoption_package_path =
        continuity_evidence_dir.join("controlled-adoption-package.json");
    let release_readiness_package_path =
        continuity_evidence_dir.join("release-readiness-package.json");
    let trust_network_package_path = continuity_evidence_dir.join("trust-network-package.json");
    let assurance_suite_package_path = continuity_evidence_dir.join("assurance-suite-package.json");
    let proof_package_path = continuity_evidence_dir.join("proof-package.json");
    let inquiry_package_path = continuity_evidence_dir.join("inquiry-package.json");
    let inquiry_verification_path = continuity_evidence_dir.join("inquiry-verification.json");
    let reviewer_package_path = continuity_evidence_dir.join("reviewer-package.json");
    let qualification_report_path = continuity_evidence_dir.join("qualification-report.json");

    copy_file(
        Path::new(&selective_account_activation.selective_account_activation_package_file),
        &selective_account_activation_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.activation_scope_freeze_file),
        &activation_scope_freeze_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.selective_account_activation_manifest_file),
        &selective_account_activation_manifest_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.claim_containment_rules_file),
        &claim_containment_rules_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.activation_approval_refresh_file),
        &activation_approval_refresh_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.customer_handoff_brief_file),
        &customer_handoff_brief_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.broader_distribution_package_file),
        &broader_distribution_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.broader_distribution_manifest_file),
        &broader_distribution_manifest_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.target_account_freeze_file),
        &target_account_freeze_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.claim_governance_rules_file),
        &claim_governance_rules_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.selective_account_approval_file),
        &selective_account_approval_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.reference_distribution_package_file),
        &reference_distribution_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.controlled_adoption_package_file),
        &controlled_adoption_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.release_readiness_package_file),
        &release_readiness_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.trust_network_package_file),
        &trust_network_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.assurance_suite_package_file),
        &assurance_suite_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.proof_package_file),
        &proof_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.inquiry_package_file),
        &inquiry_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.inquiry_verification_file),
        &inquiry_verification_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.reviewer_package_file),
        &reviewer_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.qualification_report_file),
        &qualification_report_path,
    )?;

    let approved_claim = "Mercury can maintain one previously activated account inside one controlled-delivery continuity lane and carry one evidence-backed renewal gate over the validated selective-account-activation, broader-distribution, reference-distribution, controlled-adoption, release-readiness, trust-network, assurance, proof, and inquiry chain."
        .to_string();

    let account_boundary_freeze = MercuryDeliveryContinuityAccountBoundaryFreeze {
        schema: "chio.mercury.delivery_continuity_account_boundary_freeze.v1".to_string(),
        workflow_id: workflow_id.clone(),
        continuity_motion: MercuryDeliveryContinuityMotion::ControlledDeliveryContinuity
            .as_str()
            .to_string(),
        continuity_surface: MercuryDeliveryContinuitySurface::OutcomeEvidenceBundle
            .as_str()
            .to_string(),
        account_boundary_label:
            "one already activated account operating inside one previously validated selective-account-activation lane".to_string(),
        entry_gates: vec![
            "selective-account-activation package and approval refresh remain current for the same workflow".to_string(),
            "delivery continuity stays within one activated account and one outcome-evidence bundle".to_string(),
            "renewal gate, escalation brief, and customer-evidence handoff are present before continuity claims are reused".to_string(),
        ],
        non_goals: vec![
            "generic onboarding tooling or CRM workflows".to_string(),
            "support desks, customer success platforms, or channel marketplaces".to_string(),
            "Chio-side commercial control surfaces or merged product shells".to_string(),
        ],
        note: "This freeze keeps the next Mercury step bounded to one controlled-delivery continuity motion over one already activated account."
            .to_string(),
    };
    let account_boundary_freeze_path = output.join("account-boundary-freeze.json");
    write_json_file(&account_boundary_freeze_path, &account_boundary_freeze)?;

    let delivery_continuity_manifest = MercuryDeliveryContinuityManifest {
        schema: "chio.mercury.delivery_continuity_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        continuity_motion: MercuryDeliveryContinuityMotion::ControlledDeliveryContinuity
            .as_str()
            .to_string(),
        continuity_surface: MercuryDeliveryContinuitySurface::OutcomeEvidenceBundle
            .as_str()
            .to_string(),
        selective_account_activation_package_file: relative_display(
            output,
            &selective_account_activation_package_path,
        )?,
        activation_scope_freeze_file: relative_display(output, &activation_scope_freeze_path)?,
        selective_account_activation_manifest_file: relative_display(
            output,
            &selective_account_activation_manifest_path,
        )?,
        claim_containment_rules_file: relative_display(output, &claim_containment_rules_path)?,
        activation_approval_refresh_file: relative_display(
            output,
            &activation_approval_refresh_path,
        )?,
        customer_handoff_brief_file: relative_display(output, &customer_handoff_brief_path)?,
        broader_distribution_package_file: relative_display(
            output,
            &broader_distribution_package_path,
        )?,
        broader_distribution_manifest_file: relative_display(
            output,
            &broader_distribution_manifest_path,
        )?,
        target_account_freeze_file: relative_display(output, &target_account_freeze_path)?,
        claim_governance_rules_file: relative_display(output, &claim_governance_rules_path)?,
        selective_account_approval_file: relative_display(
            output,
            &selective_account_approval_path,
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
        note: "This manifest freezes one outcome-evidence bundle over the existing Mercury truth chain and does not imply a generic onboarding, support, or customer platform."
            .to_string(),
    };
    let delivery_continuity_manifest_path = output.join("delivery-continuity-manifest.json");
    write_json_file(
        &delivery_continuity_manifest_path,
        &delivery_continuity_manifest,
    )?;

    let outcome_evidence_summary = MercuryDeliveryContinuityOutcomeEvidenceSummary {
        schema: "chio.mercury.delivery_continuity_outcome_evidence_summary.v1".to_string(),
        workflow_id: workflow_id.clone(),
        continuity_owner: MERCURY_DELIVERY_CONTINUITY_OWNER.to_string(),
        renewal_owner: MERCURY_RENEWAL_GATE_OWNER.to_string(),
        evidence_owner: MERCURY_CUSTOMER_EVIDENCE_OWNER.to_string(),
        continuity_motion: MercuryDeliveryContinuityMotion::ControlledDeliveryContinuity
            .as_str()
            .to_string(),
        continuity_surface: MercuryDeliveryContinuitySurface::OutcomeEvidenceBundle
            .as_str()
            .to_string(),
        supported_claims: vec![
            approved_claim.clone(),
            "The continuity bundle remains bounded to one continuity motion, one renewal gate, and one outcome-evidence surface."
                .to_string(),
        ],
        evidence_files: vec![
            relative_display(output, &selective_account_activation_package_path)?,
            relative_display(output, &activation_approval_refresh_path)?,
            relative_display(output, &broader_distribution_package_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &reviewer_package_path)?,
            relative_display(output, &qualification_report_path)?,
        ],
        note: "Outcome evidence remains Mercury-owned and evidence-backed for one already activated account only."
            .to_string(),
    };
    let outcome_evidence_summary_path = output.join("outcome-evidence-summary.json");
    write_json_file(&outcome_evidence_summary_path, &outcome_evidence_summary)?;

    let renewal_gate = MercuryDeliveryContinuityRenewalGate {
        schema: "chio.mercury.delivery_continuity_renewal_gate.v1".to_string(),
        workflow_id: workflow_id.clone(),
        renewal_owner: MERCURY_RENEWAL_GATE_OWNER.to_string(),
        status: "ready".to_string(),
        reviewed_at: unix_now(),
        reviewed_by: MERCURY_RENEWAL_GATE_OWNER.to_string(),
        approved_claims: outcome_evidence_summary.supported_claims.clone(),
        required_files: vec![
            relative_display(output, &account_boundary_freeze_path)?,
            relative_display(output, &delivery_continuity_manifest_path)?,
            relative_display(output, &outcome_evidence_summary_path)?,
            relative_display(output, &selective_account_activation_package_path)?,
            relative_display(output, &activation_approval_refresh_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &reviewer_package_path)?,
        ],
        note: "The renewal gate must be refreshed before Mercury can reuse controlled-delivery continuity claims for the same activated account."
            .to_string(),
    };
    let renewal_gate_path = output.join("renewal-gate.json");
    write_json_file(&renewal_gate_path, &renewal_gate)?;

    let delivery_escalation_brief = MercuryDeliveryContinuityDeliveryEscalationBrief {
        schema: "chio.mercury.delivery_continuity_delivery_escalation_brief.v1".to_string(),
        workflow_id: workflow_id.clone(),
        continuity_owner: MERCURY_DELIVERY_CONTINUITY_OWNER.to_string(),
        evidence_owner: MERCURY_CUSTOMER_EVIDENCE_OWNER.to_string(),
        renewal_owner: MERCURY_RENEWAL_GATE_OWNER.to_string(),
        continuity_motion: MercuryDeliveryContinuityMotion::ControlledDeliveryContinuity
            .as_str()
            .to_string(),
        continuity_surface: MercuryDeliveryContinuitySurface::OutcomeEvidenceBundle
            .as_str()
            .to_string(),
        service_boundary: "one already activated account in one controlled-delivery continuity lane only".to_string(),
        escalation_triggers: vec![
            "continuity claims drift beyond the outcome-evidence bundle".to_string(),
            "renewal-gate state is stale, missing, or no longer maps to the same workflow".to_string(),
            "requested support expands into generic onboarding, CRM, or multi-account delivery".to_string(),
        ],
        immediate_actions: vec![
            "pause reuse of the continuity bundle".to_string(),
            "regenerate the export from the canonical selective-account-activation lane".to_string(),
            "require a fresh renewal-gate review before any further customer-facing use".to_string(),
        ],
        note: "Delivery escalation exists to keep the lane bounded and evidence-backed, not to create a generic support desk."
            .to_string(),
    };
    let delivery_escalation_brief_path = output.join("delivery-escalation-brief.json");
    write_json_file(&delivery_escalation_brief_path, &delivery_escalation_brief)?;

    let customer_evidence_handoff = MercuryDeliveryContinuityCustomerEvidenceHandoff {
        schema: "chio.mercury.delivery_continuity_customer_evidence_handoff.v1".to_string(),
        workflow_id: workflow_id.clone(),
        evidence_owner: MERCURY_CUSTOMER_EVIDENCE_OWNER.to_string(),
        continuity_owner: MERCURY_DELIVERY_CONTINUITY_OWNER.to_string(),
        renewal_owner: MERCURY_RENEWAL_GATE_OWNER.to_string(),
        continuity_motion: MercuryDeliveryContinuityMotion::ControlledDeliveryContinuity
            .as_str()
            .to_string(),
        continuity_surface: MercuryDeliveryContinuitySurface::OutcomeEvidenceBundle
            .as_str()
            .to_string(),
        approved_scope:
            "one outcome-evidence bundle for one already activated account only".to_string(),
        required_evidence: vec![
            relative_display(output, &delivery_continuity_manifest_path)?,
            relative_display(output, &outcome_evidence_summary_path)?,
            relative_display(output, &renewal_gate_path)?,
            relative_display(output, &delivery_escalation_brief_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
        ],
        deferred_requests: vec![
            "generic onboarding requests".to_string(),
            "broad customer-success or support programs".to_string(),
            "multi-account expansions or channel-marketplace asks".to_string(),
        ],
        note: "Customer evidence handoff stays product-owned and bounded to one continuity motion over one activated account."
            .to_string(),
    };
    let customer_evidence_handoff_path = output.join("customer-evidence-handoff.json");
    write_json_file(&customer_evidence_handoff_path, &customer_evidence_handoff)?;

    let package = MercuryDeliveryContinuityPackage {
        schema: MERCURY_DELIVERY_CONTINUITY_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "delivery-continuity-outcome-evidence-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        continuity_motion: MercuryDeliveryContinuityMotion::ControlledDeliveryContinuity,
        continuity_surface: MercuryDeliveryContinuitySurface::OutcomeEvidenceBundle,
        continuity_owner: MERCURY_DELIVERY_CONTINUITY_OWNER.to_string(),
        renewal_owner: MERCURY_RENEWAL_GATE_OWNER.to_string(),
        evidence_owner: MERCURY_CUSTOMER_EVIDENCE_OWNER.to_string(),
        renewal_gate_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        selective_account_activation_package_file: relative_display(
            output,
            &selective_account_activation_package_path,
        )?,
        activation_scope_freeze_file: relative_display(output, &activation_scope_freeze_path)?,
        selective_account_activation_manifest_file: relative_display(
            output,
            &selective_account_activation_manifest_path,
        )?,
        claim_containment_rules_file: relative_display(output, &claim_containment_rules_path)?,
        activation_approval_refresh_file: relative_display(
            output,
            &activation_approval_refresh_path,
        )?,
        customer_handoff_brief_file: relative_display(output, &customer_handoff_brief_path)?,
        broader_distribution_package_file: relative_display(
            output,
            &broader_distribution_package_path,
        )?,
        broader_distribution_manifest_file: relative_display(
            output,
            &broader_distribution_manifest_path,
        )?,
        target_account_freeze_file: relative_display(output, &target_account_freeze_path)?,
        claim_governance_rules_file: relative_display(output, &claim_governance_rules_path)?,
        selective_account_approval_file: relative_display(
            output,
            &selective_account_approval_path,
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
            MercuryDeliveryContinuityArtifact {
                artifact_kind: MercuryDeliveryContinuityArtifactKind::AccountBoundaryFreeze,
                relative_path: relative_display(output, &account_boundary_freeze_path)?,
            },
            MercuryDeliveryContinuityArtifact {
                artifact_kind: MercuryDeliveryContinuityArtifactKind::DeliveryContinuityManifest,
                relative_path: relative_display(output, &delivery_continuity_manifest_path)?,
            },
            MercuryDeliveryContinuityArtifact {
                artifact_kind: MercuryDeliveryContinuityArtifactKind::OutcomeEvidenceSummary,
                relative_path: relative_display(output, &outcome_evidence_summary_path)?,
            },
            MercuryDeliveryContinuityArtifact {
                artifact_kind: MercuryDeliveryContinuityArtifactKind::RenewalGateRecord,
                relative_path: relative_display(output, &renewal_gate_path)?,
            },
            MercuryDeliveryContinuityArtifact {
                artifact_kind: MercuryDeliveryContinuityArtifactKind::DeliveryEscalationBrief,
                relative_path: relative_display(output, &delivery_escalation_brief_path)?,
            },
            MercuryDeliveryContinuityArtifact {
                artifact_kind: MercuryDeliveryContinuityArtifactKind::CustomerEvidenceHandoff,
                relative_path: relative_display(output, &customer_evidence_handoff_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("delivery-continuity-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryDeliveryContinuityExportSummary {
        workflow_id,
        continuity_motion: MercuryDeliveryContinuityMotion::ControlledDeliveryContinuity
            .as_str()
            .to_string(),
        continuity_surface: MercuryDeliveryContinuitySurface::OutcomeEvidenceBundle
            .as_str()
            .to_string(),
        continuity_owner: MERCURY_DELIVERY_CONTINUITY_OWNER.to_string(),
        renewal_owner: MERCURY_RENEWAL_GATE_OWNER.to_string(),
        evidence_owner: MERCURY_CUSTOMER_EVIDENCE_OWNER.to_string(),
        selective_account_activation_dir: selective_account_activation_dir.display().to_string(),
        delivery_continuity_profile_file: profile_path.display().to_string(),
        delivery_continuity_package_file: package_path.display().to_string(),
        account_boundary_freeze_file: account_boundary_freeze_path.display().to_string(),
        delivery_continuity_manifest_file: delivery_continuity_manifest_path.display().to_string(),
        outcome_evidence_summary_file: outcome_evidence_summary_path.display().to_string(),
        renewal_gate_file: renewal_gate_path.display().to_string(),
        delivery_escalation_brief_file: delivery_escalation_brief_path.display().to_string(),
        customer_evidence_handoff_file: customer_evidence_handoff_path.display().to_string(),
        continuity_evidence_dir: continuity_evidence_dir.display().to_string(),
        selective_account_activation_package_file: selective_account_activation_package_path
            .display()
            .to_string(),
        activation_scope_freeze_file: activation_scope_freeze_path.display().to_string(),
        selective_account_activation_manifest_file: selective_account_activation_manifest_path
            .display()
            .to_string(),
        claim_containment_rules_file: claim_containment_rules_path.display().to_string(),
        activation_approval_refresh_file: activation_approval_refresh_path.display().to_string(),
        customer_handoff_brief_file: customer_handoff_brief_path.display().to_string(),
        broader_distribution_package_file: broader_distribution_package_path.display().to_string(),
        broader_distribution_manifest_file: broader_distribution_manifest_path
            .display()
            .to_string(),
        target_account_freeze_file: target_account_freeze_path.display().to_string(),
        claim_governance_rules_file: claim_governance_rules_path.display().to_string(),
        selective_account_approval_file: selective_account_approval_path.display().to_string(),
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
    write_json_file(&output.join("delivery-continuity-summary.json"), &summary)?;

    Ok(summary)
}

pub fn cmd_mercury_delivery_continuity_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_delivery_continuity(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury delivery-continuity package exported");
        println!("output:                             {}", output.display());
        println!(
            "workflow_id:                        {}",
            summary.workflow_id
        );
        println!(
            "continuity_motion:                  {}",
            summary.continuity_motion
        );
        println!(
            "continuity_surface:                 {}",
            summary.continuity_surface
        );
        println!(
            "continuity_owner:                   {}",
            summary.continuity_owner
        );
        println!(
            "renewal_owner:                      {}",
            summary.renewal_owner
        );
        println!(
            "evidence_owner:                     {}",
            summary.evidence_owner
        );
        println!(
            "delivery_continuity_package:        {}",
            summary.delivery_continuity_package_file
        );
        println!(
            "renewal_gate:                       {}",
            summary.renewal_gate_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_delivery_continuity_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let delivery_continuity_dir = output.join("delivery-continuity");
    let summary = export_delivery_continuity(&delivery_continuity_dir)?;
    let docs = delivery_continuity_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryDeliveryContinuityDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_DELIVERY_CONTINUITY_DECISION.to_string(),
        selected_continuity_motion: summary.continuity_motion.clone(),
        selected_continuity_surface: summary.continuity_surface.clone(),
        approved_scope:
            "Proceed with one bounded Mercury controlled-delivery continuity lane only."
                .to_string(),
        deferred_scope: vec![
            "additional continuity motions or delivery surfaces".to_string(),
            "generic onboarding tooling, CRM workflows, or support desks".to_string(),
            "channel marketplaces, multi-account continuity programs, or merged shells"
                .to_string(),
            "Chio-side commercial control surfaces".to_string(),
        ],
        rationale: "The controlled-delivery continuity lane now packages one outcome-evidence bundle and one renewal gate over the validated selective-account-activation chain without widening Mercury into a generic customer platform or polluting Chio's generic substrate."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("delivery-continuity-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryDeliveryContinuityValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_DELIVERY_CONTINUITY_DECISION.to_string(),
        continuity_motion: summary.continuity_motion.clone(),
        continuity_surface: summary.continuity_surface.clone(),
        continuity_owner: summary.continuity_owner.clone(),
        renewal_owner: summary.renewal_owner.clone(),
        evidence_owner: summary.evidence_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        delivery_continuity: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury delivery-continuity validation package exported");
        println!("output:                             {}", output.display());
        println!("workflow_id:                        {}", report.workflow_id);
        println!("decision:                           {}", report.decision);
        println!(
            "continuity_motion:                  {}",
            report.continuity_motion
        );
        println!(
            "continuity_surface:                 {}",
            report.continuity_surface
        );
        println!(
            "continuity_owner:                   {}",
            report.continuity_owner
        );
        println!(
            "renewal_owner:                      {}",
            report.renewal_owner
        );
        println!(
            "evidence_owner:                     {}",
            report.evidence_owner
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
            "delivery_continuity_package:        {}",
            report.delivery_continuity.delivery_continuity_package_file
        );
    }

    Ok(())
}
