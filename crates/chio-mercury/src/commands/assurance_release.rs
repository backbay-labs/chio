fn export_assurance_suite(output: &Path) -> Result<MercuryAssuranceSuiteExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let governance_dir = output.join("governance-workbench");
    let governance_summary = export_governance_workbench(&governance_dir)?;
    let proof_package_path =
        governance_dir.join("qualification/supervised-live/proof-package.json");
    let proof_package: MercuryProofPackage = read_json_file(&proof_package_path)?;
    proof_package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;

    let reviewer_package_path = governance_dir.join("qualification/reviewer-package.json");
    let qualification_report_path = governance_dir.join("qualification/qualification-report.json");
    let governance_decision_package_path = governance_dir.join("governance-decision-package.json");
    let investigation_inputs = collect_assurance_investigation_inputs(&proof_package);

    let populations_dir = output.join("reviewer-populations");
    fs::create_dir_all(&populations_dir)?;

    let mut reviewer_populations = Vec::new();
    let mut artifacts = Vec::new();
    let mut internal_review_package_file = String::new();
    let mut auditor_review_package_file = String::new();
    let mut counterparty_review_package_file = String::new();
    let mut internal_investigation_package_file = String::new();
    let mut auditor_investigation_package_file = String::new();
    let mut counterparty_investigation_package_file = String::new();

    for config in assurance_suite_population_configs() {
        let population_dir = populations_dir.join(config.dir_name);
        fs::create_dir_all(&population_dir)?;

        let disclosure_profile =
            build_assurance_disclosure_profile(&governance_summary.workflow_id, config)?;
        let disclosure_profile_path = population_dir.join("disclosure-profile.json");
        write_json_file(&disclosure_profile_path, &disclosure_profile)?;

        let inquiry_package = build_inquiry_package(
            proof_package.clone(),
            config.audience,
            Some(config.redaction_profile),
            config.verifier_equivalent,
        )?;
        let inquiry_report = inquiry_package
            .verify(unix_now())
            .map_err(|error| CliError::Other(error.to_string()))?;
        let inquiry_package_path = population_dir.join("inquiry-package.json");
        let inquiry_verification_path = population_dir.join("inquiry-verification.json");
        write_json_file(&inquiry_package_path, &inquiry_package)?;
        write_verification_report(&inquiry_verification_path, &inquiry_report)?;

        let review_package = build_assurance_review_package(AssuranceReviewPackageArgs {
            workflow_id: &governance_summary.workflow_id,
            reviewer_population: config.reviewer_population,
            disclosure_profile_file: &relative_display(output, &disclosure_profile_path)?,
            proof_package_file: &relative_display(output, &proof_package_path)?,
            inquiry_package_file: &relative_display(output, &inquiry_package_path)?,
            inquiry_verification_file: &relative_display(output, &inquiry_verification_path)?,
            reviewer_package_file: &relative_display(output, &reviewer_package_path)?,
            qualification_report_file: &relative_display(output, &qualification_report_path)?,
            governance_decision_package_file: &relative_display(
                output,
                &governance_decision_package_path,
            )?,
            verifier_equivalent: config.verifier_equivalent,
        })?;
        let review_package_path = population_dir.join("review-package.json");
        write_json_file(&review_package_path, &review_package)?;

        let investigation_package = build_assurance_investigation_package(
            &governance_summary.workflow_id,
            config.reviewer_population,
            &relative_display(output, &review_package_path)?,
            &investigation_inputs,
            config.investigation_focus,
        )?;
        let investigation_package_path = population_dir.join("investigation-package.json");
        write_json_file(&investigation_package_path, &investigation_package)?;

        reviewer_populations.push(config.reviewer_population.as_str().to_string());
        artifacts.push(MercuryAssuranceSuiteArtifact {
            reviewer_population: config.reviewer_population,
            artifact_kind: MercuryAssuranceArtifactKind::DisclosureProfile,
            relative_path: relative_display(output, &disclosure_profile_path)?,
        });
        artifacts.push(MercuryAssuranceSuiteArtifact {
            reviewer_population: config.reviewer_population,
            artifact_kind: MercuryAssuranceArtifactKind::ReviewPackage,
            relative_path: relative_display(output, &review_package_path)?,
        });
        artifacts.push(MercuryAssuranceSuiteArtifact {
            reviewer_population: config.reviewer_population,
            artifact_kind: MercuryAssuranceArtifactKind::InvestigationPackage,
            relative_path: relative_display(output, &investigation_package_path)?,
        });

        match config.reviewer_population {
            MercuryAssuranceReviewerPopulation::InternalReview => {
                internal_review_package_file = review_package_path.display().to_string();
                internal_investigation_package_file =
                    investigation_package_path.display().to_string();
            }
            MercuryAssuranceReviewerPopulation::AuditorReview => {
                auditor_review_package_file = review_package_path.display().to_string();
                auditor_investigation_package_file =
                    investigation_package_path.display().to_string();
            }
            MercuryAssuranceReviewerPopulation::CounterpartyReview => {
                counterparty_review_package_file = review_package_path.display().to_string();
                counterparty_investigation_package_file =
                    investigation_package_path.display().to_string();
            }
        }
    }

    let assurance_suite_package = MercuryAssuranceSuitePackage {
        schema: MERCURY_ASSURANCE_SUITE_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "assurance-suite-{}-{}",
            governance_summary.workflow_id,
            current_utc_date()
        ),
        workflow_id: governance_summary.workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        reviewer_owner: MERCURY_ASSURANCE_REVIEWER_OWNER.to_string(),
        support_owner: MERCURY_ASSURANCE_SUPPORT_OWNER.to_string(),
        fail_closed: true,
        governance_decision_package_file: relative_display(
            output,
            &governance_decision_package_path,
        )?,
        reviewer_populations: vec![
            MercuryAssuranceReviewerPopulation::InternalReview,
            MercuryAssuranceReviewerPopulation::AuditorReview,
            MercuryAssuranceReviewerPopulation::CounterpartyReview,
        ],
        artifacts,
    };
    assurance_suite_package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let assurance_suite_package_path = output.join("assurance-suite-package.json");
    write_json_file(&assurance_suite_package_path, &assurance_suite_package)?;

    let summary = MercuryAssuranceSuiteExportSummary {
        workflow_id: governance_summary.workflow_id,
        reviewer_owner: MERCURY_ASSURANCE_REVIEWER_OWNER.to_string(),
        support_owner: MERCURY_ASSURANCE_SUPPORT_OWNER.to_string(),
        reviewer_populations,
        qualification_dir: governance_summary.qualification_dir,
        governance_workbench_dir: governance_dir.display().to_string(),
        governance_decision_package_file: governance_summary.governance_decision_package_file,
        assurance_suite_package_file: assurance_suite_package_path.display().to_string(),
        internal_review_package_file,
        auditor_review_package_file,
        counterparty_review_package_file,
        internal_investigation_package_file,
        auditor_investigation_package_file,
        counterparty_investigation_package_file,
    };
    write_json_file(&output.join("assurance-suite-summary.json"), &summary)?;

    Ok(summary)
}

fn export_embedded_oem(output: &Path) -> Result<MercuryEmbeddedOemExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let assurance_dir = output.join("assurance-suite");
    let assurance_summary = export_assurance_suite(&assurance_dir)?;
    let workflow_id = assurance_summary.workflow_id.clone();

    let profile = build_embedded_oem_profile(&workflow_id)?;
    let profile_path = output.join("embedded-oem-profile.json");
    write_json_file(&profile_path, &profile)?;

    let partner_bundle_dir = output.join("partner-sdk-bundle");
    fs::create_dir_all(&partner_bundle_dir)?;

    let assurance_suite_package_src = assurance_dir.join("assurance-suite-package.json");
    let governance_decision_package_src =
        assurance_dir.join("governance-workbench/governance-decision-package.json");
    let disclosure_profile_src =
        assurance_dir.join("reviewer-populations/counterparty-review/disclosure-profile.json");
    let review_package_src =
        assurance_dir.join("reviewer-populations/counterparty-review/review-package.json");
    let investigation_package_src =
        assurance_dir.join("reviewer-populations/counterparty-review/investigation-package.json");
    let reviewer_package_src =
        assurance_dir.join("governance-workbench/qualification/reviewer-package.json");
    let qualification_report_src =
        assurance_dir.join("governance-workbench/qualification/qualification-report.json");

    let assurance_suite_package_path = partner_bundle_dir.join("assurance-suite-package.json");
    let governance_decision_package_path =
        partner_bundle_dir.join("governance-decision-package.json");
    let disclosure_profile_path = partner_bundle_dir.join("disclosure-profile.json");
    let review_package_path = partner_bundle_dir.join("review-package.json");
    let investigation_package_path = partner_bundle_dir.join("investigation-package.json");
    let reviewer_package_path = partner_bundle_dir.join("reviewer-package.json");
    let qualification_report_path = partner_bundle_dir.join("qualification-report.json");

    copy_file(&assurance_suite_package_src, &assurance_suite_package_path)?;
    copy_file(
        &governance_decision_package_src,
        &governance_decision_package_path,
    )?;
    copy_file(&disclosure_profile_src, &disclosure_profile_path)?;
    copy_file(&review_package_src, &review_package_path)?;
    copy_file(&investigation_package_src, &investigation_package_path)?;
    copy_file(&reviewer_package_src, &reviewer_package_path)?;
    copy_file(&qualification_report_src, &qualification_report_path)?;

    let acknowledgement = MercuryEmbeddedDeliveryAcknowledgement {
        schema: "chio.mercury.embedded_delivery_acknowledgement.v1".to_string(),
        workflow_id: workflow_id.clone(),
        partner_surface: MercuryEmbeddedPartnerSurface::ReviewerWorkbenchEmbed
            .as_str()
            .to_string(),
        partner_owner: MERCURY_EMBEDDED_PARTNER_OWNER.to_string(),
        status: "acknowledged".to_string(),
        acknowledged_at: unix_now(),
        acknowledged_by: "partner-review-platform-drop".to_string(),
        delivered_files: vec![
            "assurance-suite-package.json".to_string(),
            "governance-decision-package.json".to_string(),
            "disclosure-profile.json".to_string(),
            "review-package.json".to_string(),
            "investigation-package.json".to_string(),
            "reviewer-package.json".to_string(),
            "qualification-report.json".to_string(),
        ],
        note: "The embedded OEM bundle is limited to one reviewer-workbench surface, one signed artifact bundle, and one counterparty-review population. Any missing or inconsistent artifact must fail closed."
            .to_string(),
    };
    let acknowledgement_path = partner_bundle_dir.join("delivery-acknowledgement.json");
    write_json_file(&acknowledgement_path, &acknowledgement)?;

    let sdk_manifest = MercuryEmbeddedPartnerManifest {
        schema: "chio.mercury.embedded_partner_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        partner_surface: MercuryEmbeddedPartnerSurface::ReviewerWorkbenchEmbed
            .as_str()
            .to_string(),
        sdk_surface: MercuryEmbeddedSdkSurface::SignedArtifactBundle
            .as_str()
            .to_string(),
        reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview
            .as_str()
            .to_string(),
        fail_closed: true,
        acknowledgement_required: true,
        profile_file: relative_display(output, &profile_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        governance_decision_package_file: relative_display(
            output,
            &governance_decision_package_path,
        )?,
        disclosure_profile_file: relative_display(output, &disclosure_profile_path)?,
        review_package_file: relative_display(output, &review_package_path)?,
        investigation_package_file: relative_display(output, &investigation_package_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        support_owner: MERCURY_EMBEDDED_SUPPORT_OWNER.to_string(),
        note: "This manifest is the bounded embedded OEM surface. It packages one counterparty-review Mercury bundle for one partner reviewer workbench and does not imply a generic SDK or multi-partner OEM platform."
            .to_string(),
    };
    let sdk_manifest_path = output.join("partner-sdk-manifest.json");
    write_json_file(&sdk_manifest_path, &sdk_manifest)?;

    let package = MercuryEmbeddedOemPackage {
        schema: MERCURY_EMBEDDED_OEM_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "embedded-oem-reviewer-workbench-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        partner_surface: MercuryEmbeddedPartnerSurface::ReviewerWorkbenchEmbed,
        sdk_surface: MercuryEmbeddedSdkSurface::SignedArtifactBundle,
        reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview,
        partner_owner: MERCURY_EMBEDDED_PARTNER_OWNER.to_string(),
        support_owner: MERCURY_EMBEDDED_SUPPORT_OWNER.to_string(),
        acknowledgement_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        sdk_manifest_file: relative_display(output, &sdk_manifest_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        governance_decision_package_file: relative_display(
            output,
            &governance_decision_package_path,
        )?,
        artifacts: vec![
            MercuryEmbeddedOemArtifact {
                artifact_kind: MercuryEmbeddedArtifactKind::DisclosureProfile,
                relative_path: relative_display(output, &disclosure_profile_path)?,
            },
            MercuryEmbeddedOemArtifact {
                artifact_kind: MercuryEmbeddedArtifactKind::ReviewPackage,
                relative_path: relative_display(output, &review_package_path)?,
            },
            MercuryEmbeddedOemArtifact {
                artifact_kind: MercuryEmbeddedArtifactKind::InvestigationPackage,
                relative_path: relative_display(output, &investigation_package_path)?,
            },
            MercuryEmbeddedOemArtifact {
                artifact_kind: MercuryEmbeddedArtifactKind::ReviewerPackage,
                relative_path: relative_display(output, &reviewer_package_path)?,
            },
            MercuryEmbeddedOemArtifact {
                artifact_kind: MercuryEmbeddedArtifactKind::QualificationReport,
                relative_path: relative_display(output, &qualification_report_path)?,
            },
            MercuryEmbeddedOemArtifact {
                artifact_kind: MercuryEmbeddedArtifactKind::DeliveryAcknowledgement,
                relative_path: relative_display(output, &acknowledgement_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("embedded-oem-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryEmbeddedOemExportSummary {
        workflow_id,
        partner_surface: MercuryEmbeddedPartnerSurface::ReviewerWorkbenchEmbed
            .as_str()
            .to_string(),
        sdk_surface: MercuryEmbeddedSdkSurface::SignedArtifactBundle
            .as_str()
            .to_string(),
        reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview
            .as_str()
            .to_string(),
        partner_owner: MERCURY_EMBEDDED_PARTNER_OWNER.to_string(),
        support_owner: MERCURY_EMBEDDED_SUPPORT_OWNER.to_string(),
        assurance_suite_dir: assurance_dir.display().to_string(),
        embedded_oem_profile_file: profile_path.display().to_string(),
        embedded_oem_package_file: package_path.display().to_string(),
        partner_sdk_manifest_file: sdk_manifest_path.display().to_string(),
        assurance_suite_package_file: assurance_suite_package_path.display().to_string(),
        governance_decision_package_file: governance_decision_package_path.display().to_string(),
        disclosure_profile_file: disclosure_profile_path.display().to_string(),
        review_package_file: review_package_path.display().to_string(),
        investigation_package_file: investigation_package_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
        acknowledgement_file: acknowledgement_path.display().to_string(),
        partner_sdk_bundle_dir: partner_bundle_dir.display().to_string(),
    };
    write_json_file(&output.join("embedded-oem-summary.json"), &summary)?;

    Ok(summary)
}

fn export_trust_network(output: &Path) -> Result<MercuryTrustNetworkExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let embedded_oem_dir = output.join("embedded-oem");
    let embedded_summary = export_embedded_oem(&embedded_oem_dir)?;
    let workflow_id = embedded_summary.workflow_id.clone();

    let profile = build_trust_network_profile(&workflow_id)?;
    let profile_path = output.join("trust-network-profile.json");
    write_json_file(&profile_path, &profile)?;

    let share_dir = output.join("trust-network-share");
    fs::create_dir_all(&share_dir)?;

    let shared_proof_package_src = embedded_oem_dir.join(
        "assurance-suite/governance-workbench/qualification/supervised-live/proof-package.json",
    );
    let shared_review_package_src = embedded_oem_dir.join("partner-sdk-bundle/review-package.json");
    let reviewer_package_src = embedded_oem_dir.join("partner-sdk-bundle/reviewer-package.json");
    let qualification_report_src =
        embedded_oem_dir.join("partner-sdk-bundle/qualification-report.json");

    let witness_record_path = share_dir.join("witness-record.json");
    let trust_anchor_record_path = share_dir.join("trust-anchor-record.json");
    let shared_proof_package_path = share_dir.join("shared-proof-package.json");
    let shared_review_package_path = share_dir.join("review-package.json");
    let reviewer_package_path = share_dir.join("reviewer-package.json");
    let qualification_report_path = share_dir.join("qualification-report.json");

    let witness_record = MercuryTrustNetworkWitnessRecord {
        schema: "chio.mercury.trust_network_witness_record.v1".to_string(),
        workflow_id: workflow_id.clone(),
        sponsor_boundary: MercuryTrustNetworkSponsorBoundary::CounterpartyReviewExchange
            .as_str()
            .to_string(),
        trust_anchor: MercuryTrustNetworkTrustAnchor::ChioCheckpointWitnessChain
            .as_str()
            .to_string(),
        checkpoint_continuity: "append_only".to_string(),
        witness_steps: profile
            .witness_steps
            .iter()
            .map(|step| step.as_str().to_string())
            .collect(),
        witness_operator: MERCURY_TRUST_NETWORK_SPONSOR_OWNER.to_string(),
        note: "The trust-network lane remains bounded to one counterparty-review exchange sponsor, one checkpoint-backed witness chain, and one fail-closed interoperability path."
            .to_string(),
    };
    write_json_file(&witness_record_path, &witness_record)?;

    let trust_anchor_record = MercuryTrustAnchorRecord {
        schema: "chio.mercury.trust_anchor_record.v1".to_string(),
        workflow_id: workflow_id.clone(),
        trust_anchor: MercuryTrustNetworkTrustAnchor::ChioCheckpointWitnessChain
            .as_str()
            .to_string(),
        anchor_scope:
            "chio checkpoint signatures plus one bounded trust-network witness chain".to_string(),
        verification_material:
            "shared-proof-package publicationProfile binds witness and trust-anchor references."
                .to_string(),
        note: "This trust anchor is limited to one counterparty-review trust-network lane and does not imply a generic ecosystem trust service."
            .to_string(),
    };
    write_json_file(&trust_anchor_record_path, &trust_anchor_record)?;

    let mut shared_proof_package: MercuryProofPackage = read_json_file(&shared_proof_package_src)?;
    let witness_record_ref = relative_display(output, &witness_record_path)?;
    let trust_anchor_ref = relative_display(output, &trust_anchor_record_path)?;
    let anchored_publications = shared_proof_package
        .chio_bundle
        .checkpoints
        .iter()
        .map(|checkpoint| {
            let binding = chio_core::receipt::checkpoint::CheckpointPublicationTrustAnchorBinding {
                publication_identity: chio_core::receipt::checkpoint::CheckpointPublicationIdentity::new(
                    chio_core::receipt::checkpoint::CheckpointPublicationIdentityKind::LocalLog,
                    chio_kernel::checkpoint::checkpoint_log_id(checkpoint),
                ),
                trust_anchor_identity: chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentity::new(
                    chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentityKind::ChainRoot,
                    "chio-checkpoint-witness-chain",
                ),
                trust_anchor_ref: trust_anchor_ref.clone(),
                signer_cert_ref: "chio-kernel-signing-key".to_string(),
                publication_profile_version: "chio.mercury.trust_network.append_only.v1"
                    .to_string(),
            };
            chio_kernel::checkpoint::build_trust_anchored_checkpoint_publication(
                checkpoint,
                binding,
            )
            .map_err(|error| CliError::Other(error.to_string()))
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let mut checkpoint_transparency = match shared_proof_package.checkpoint_transparency.clone() {
        Some(summary) => summary,
        None => chio_kernel::checkpoint::validate_checkpoint_transparency(
            &shared_proof_package.chio_bundle.checkpoints,
        )
        .map_err(|error| CliError::Other(error.to_string()))?,
    };
    checkpoint_transparency.publications = anchored_publications;

    shared_proof_package.publication_profile.checkpoint_continuity = "append_only".to_string();
    shared_proof_package.publication_profile.witness_record = Some(witness_record_ref);
    shared_proof_package.publication_profile.trust_anchor = Some(trust_anchor_ref.clone());
    shared_proof_package
        .publication_profile
        .freshness_window_secs = Some(86_400);
    shared_proof_package.publication_claim_boundary = Some(
        chio_kernel::evidence_export::build_evidence_transparency_claims(
            &shared_proof_package.chio_bundle,
            &checkpoint_transparency,
            Some(&trust_anchor_ref),
        ),
    );
    shared_proof_package.checkpoint_transparency = Some(checkpoint_transparency);
    shared_proof_package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    write_json_file(&shared_proof_package_path, &shared_proof_package)?;

    let shared_inquiry_package = build_inquiry_package(
        shared_proof_package.clone(),
        "trust-network-review",
        Some("shared-proof-exchange"),
        false,
    )?;
    let shared_inquiry_report = shared_inquiry_package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    let shared_inquiry_package_path = share_dir.join("inquiry-package.json");
    let shared_inquiry_verification_path = share_dir.join("inquiry-verification.json");
    write_json_file(&shared_inquiry_package_path, &shared_inquiry_package)?;
    write_verification_report(&shared_inquiry_verification_path, &shared_inquiry_report)?;

    copy_file(&shared_review_package_src, &shared_review_package_path)?;
    copy_file(&reviewer_package_src, &reviewer_package_path)?;
    copy_file(&qualification_report_src, &qualification_report_path)?;

    let interop_manifest = MercuryTrustNetworkInteroperabilityManifest {
        schema: "chio.mercury.trust_network_interop_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        sponsor_boundary: MercuryTrustNetworkSponsorBoundary::CounterpartyReviewExchange
            .as_str()
            .to_string(),
        trust_anchor: MercuryTrustNetworkTrustAnchor::ChioCheckpointWitnessChain
            .as_str()
            .to_string(),
        interop_surface: MercuryTrustNetworkInteropSurface::ProofInquiryBundleExchange
            .as_str()
            .to_string(),
        reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview
            .as_str()
            .to_string(),
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        shared_proof_package_file: relative_display(output, &shared_proof_package_path)?,
        shared_review_package_file: relative_display(output, &shared_review_package_path)?,
        shared_inquiry_package_file: relative_display(output, &shared_inquiry_package_path)?,
        shared_inquiry_verification_file: relative_display(
            output,
            &shared_inquiry_verification_path,
        )?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        witness_record_file: relative_display(output, &witness_record_path)?,
        trust_anchor_record_file: relative_display(output, &trust_anchor_record_path)?,
        support_owner: MERCURY_TRUST_NETWORK_SUPPORT_OWNER.to_string(),
        note: "This manifest is the bounded trust-network exchange surface. It shares one counterparty-review proof and inquiry bundle over one checkpoint-backed witness chain and does not imply a generic trust broker or multi-network service."
            .to_string(),
    };
    let interop_manifest_path = output.join("trust-network-interoperability-manifest.json");
    write_json_file(&interop_manifest_path, &interop_manifest)?;

    let package = MercuryTrustNetworkPackage {
        schema: MERCURY_TRUST_NETWORK_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "trust-network-counterparty-review-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        sponsor_boundary: MercuryTrustNetworkSponsorBoundary::CounterpartyReviewExchange,
        trust_anchor: MercuryTrustNetworkTrustAnchor::ChioCheckpointWitnessChain,
        interop_surface: MercuryTrustNetworkInteropSurface::ProofInquiryBundleExchange,
        reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview,
        sponsor_owner: MERCURY_TRUST_NETWORK_SPONSOR_OWNER.to_string(),
        support_owner: MERCURY_TRUST_NETWORK_SUPPORT_OWNER.to_string(),
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        embedded_oem_package_file: relative_display(
            output,
            &embedded_oem_dir.join("embedded-oem-package.json"),
        )?,
        embedded_partner_manifest_file: relative_display(
            output,
            &embedded_oem_dir.join("partner-sdk-manifest.json"),
        )?,
        artifacts: vec![
            MercuryTrustNetworkArtifact {
                artifact_kind: MercuryTrustNetworkArtifactKind::SharedProofPackage,
                relative_path: relative_display(output, &shared_proof_package_path)?,
            },
            MercuryTrustNetworkArtifact {
                artifact_kind: MercuryTrustNetworkArtifactKind::SharedReviewPackage,
                relative_path: relative_display(output, &shared_review_package_path)?,
            },
            MercuryTrustNetworkArtifact {
                artifact_kind: MercuryTrustNetworkArtifactKind::SharedInquiryPackage,
                relative_path: relative_display(output, &shared_inquiry_package_path)?,
            },
            MercuryTrustNetworkArtifact {
                artifact_kind: MercuryTrustNetworkArtifactKind::InquiryVerification,
                relative_path: relative_display(output, &shared_inquiry_verification_path)?,
            },
            MercuryTrustNetworkArtifact {
                artifact_kind: MercuryTrustNetworkArtifactKind::InteroperabilityManifest,
                relative_path: relative_display(output, &interop_manifest_path)?,
            },
            MercuryTrustNetworkArtifact {
                artifact_kind: MercuryTrustNetworkArtifactKind::WitnessRecord,
                relative_path: relative_display(output, &witness_record_path)?,
            },
            MercuryTrustNetworkArtifact {
                artifact_kind: MercuryTrustNetworkArtifactKind::TrustAnchorRecord,
                relative_path: relative_display(output, &trust_anchor_record_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("trust-network-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryTrustNetworkExportSummary {
        workflow_id,
        sponsor_boundary: MercuryTrustNetworkSponsorBoundary::CounterpartyReviewExchange
            .as_str()
            .to_string(),
        trust_anchor: MercuryTrustNetworkTrustAnchor::ChioCheckpointWitnessChain
            .as_str()
            .to_string(),
        interop_surface: MercuryTrustNetworkInteropSurface::ProofInquiryBundleExchange
            .as_str()
            .to_string(),
        reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview
            .as_str()
            .to_string(),
        sponsor_owner: MERCURY_TRUST_NETWORK_SPONSOR_OWNER.to_string(),
        support_owner: MERCURY_TRUST_NETWORK_SUPPORT_OWNER.to_string(),
        embedded_oem_dir: embedded_oem_dir.display().to_string(),
        trust_network_profile_file: profile_path.display().to_string(),
        trust_network_package_file: package_path.display().to_string(),
        interop_manifest_file: interop_manifest_path.display().to_string(),
        shared_proof_package_file: shared_proof_package_path.display().to_string(),
        shared_review_package_file: shared_review_package_path.display().to_string(),
        shared_inquiry_package_file: shared_inquiry_package_path.display().to_string(),
        shared_inquiry_verification_file: shared_inquiry_verification_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
        witness_record_file: witness_record_path.display().to_string(),
        trust_anchor_record_file: trust_anchor_record_path.display().to_string(),
        share_dir: share_dir.display().to_string(),
    };
    write_json_file(&output.join("trust-network-summary.json"), &summary)?;

    Ok(summary)
}

fn export_release_readiness(
    output: &Path,
) -> Result<MercuryReleaseReadinessExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let trust_network_dir = output.join("trust-network");
    let trust_network = export_trust_network(&trust_network_dir)?;
    let workflow_id = trust_network.workflow_id.clone();

    let profile = build_release_readiness_profile(&workflow_id)?;
    let profile_path = output.join("release-readiness-profile.json");
    write_json_file(&profile_path, &profile)?;

    let partner_bundle_dir = output.join("partner-delivery");
    fs::create_dir_all(&partner_bundle_dir)?;

    let proof_package_path = partner_bundle_dir.join("proof-package.json");
    let inquiry_package_path = partner_bundle_dir.join("inquiry-package.json");
    let inquiry_verification_path = partner_bundle_dir.join("inquiry-verification.json");
    let assurance_suite_package_path = partner_bundle_dir.join("assurance-suite-package.json");
    let trust_network_package_path = partner_bundle_dir.join("trust-network-package.json");
    let reviewer_package_path = partner_bundle_dir.join("reviewer-package.json");
    let qualification_report_path = partner_bundle_dir.join("qualification-report.json");

    copy_file(
        &trust_network_dir.join("trust-network-share/shared-proof-package.json"),
        &proof_package_path,
    )?;
    copy_file(
        &trust_network_dir.join("trust-network-share/inquiry-package.json"),
        &inquiry_package_path,
    )?;
    copy_file(
        &trust_network_dir.join("trust-network-share/inquiry-verification.json"),
        &inquiry_verification_path,
    )?;
    copy_file(
        &trust_network_dir.join("embedded-oem/assurance-suite/assurance-suite-package.json"),
        &assurance_suite_package_path,
    )?;
    copy_file(
        &trust_network_dir.join("trust-network-package.json"),
        &trust_network_package_path,
    )?;
    copy_file(
        &trust_network_dir.join("trust-network-share/reviewer-package.json"),
        &reviewer_package_path,
    )?;
    copy_file(
        &trust_network_dir.join("trust-network-share/qualification-report.json"),
        &qualification_report_path,
    )?;

    let operator_release_checklist = MercuryReleaseReadinessOperatorChecklist {
        schema: "chio.mercury.release_readiness_operator_checklist.v1".to_string(),
        workflow_id: workflow_id.clone(),
        release_owner: MERCURY_RELEASE_OWNER.to_string(),
        partner_owner: MERCURY_RELEASE_PARTNER_OWNER.to_string(),
        support_owner: MERCURY_RELEASE_SUPPORT_OWNER.to_string(),
        fail_closed: true,
        gating_checks: vec![
            "confirm release-readiness profile matches reviewer, partner, and operator audiences"
                .to_string(),
            "confirm partner-delivery bundle contains proof, inquiry, assurance, trust-network, reviewer, and qualification artifacts"
                .to_string(),
            "confirm the same workflow sentence remains unchanged across all exported artifacts"
                .to_string(),
            "confirm operator escalation and support handoff files are present before launch"
                .to_string(),
        ],
        note: "The operator checklist is limited to one bounded Mercury release-readiness lane and does not authorize a generic Chio release console."
            .to_string(),
    };
    let operator_release_checklist_path = output.join("operator-release-checklist.json");
    write_json_file(
        &operator_release_checklist_path,
        &operator_release_checklist,
    )?;

    let escalation_manifest = MercuryReleaseReadinessEscalationManifest {
        schema: "chio.mercury.release_readiness_escalation_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        release_owner: MERCURY_RELEASE_OWNER.to_string(),
        support_owner: MERCURY_RELEASE_SUPPORT_OWNER.to_string(),
        fail_closed: true,
        escalation_triggers: vec![
            "partner-delivery manifest mismatch".to_string(),
            "missing proof, inquiry, assurance, or trust-network file".to_string(),
            "reviewer package and qualification report cannot be matched to the same workflow"
                .to_string(),
            "operator checklist is incomplete at launch time".to_string(),
        ],
        note: "Escalation remains product-owned inside Mercury and must not be shifted into Chio generic crates."
            .to_string(),
    };
    let escalation_manifest_path = output.join("escalation-manifest.json");
    write_json_file(&escalation_manifest_path, &escalation_manifest)?;

    let support_handoff = MercuryReleaseReadinessSupportHandoff {
        schema: "chio.mercury.release_readiness_support_handoff.v1".to_string(),
        workflow_id: workflow_id.clone(),
        release_owner: MERCURY_RELEASE_OWNER.to_string(),
        support_owner: MERCURY_RELEASE_SUPPORT_OWNER.to_string(),
        active_window: "launch + initial controlled adoption window".to_string(),
        required_files: vec![
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &assurance_suite_package_path)?,
            relative_display(output, &trust_network_package_path)?,
            relative_display(output, &reviewer_package_path)?,
            relative_display(output, &qualification_report_path)?,
        ],
        note: "This handoff is bounded to one Mercury launch lane and one support-owner path."
            .to_string(),
    };
    let support_handoff_path = output.join("support-handoff.json");
    write_json_file(&support_handoff_path, &support_handoff)?;

    let partner_manifest = MercuryReleaseReadinessPartnerManifest {
        schema: "chio.mercury.release_readiness_partner_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        delivery_surface: MercuryReleaseReadinessDeliverySurface::SignedPartnerReviewBundle
            .as_str()
            .to_string(),
        reviewer_population: trust_network.reviewer_population.clone(),
        acknowledgement_required: true,
        fail_closed: true,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        inquiry_verification_file: relative_display(output, &inquiry_verification_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        operator_release_checklist_file: relative_display(output, &operator_release_checklist_path)?,
        escalation_manifest_file: relative_display(output, &escalation_manifest_path)?,
        support_handoff_file: relative_display(output, &support_handoff_path)?,
        note: "This manifest delivers one bounded Mercury package to one partner path while preserving the same proof, inquiry, assurance, and trust-network truth chain."
            .to_string(),
    };
    let partner_manifest_path = output.join("partner-delivery-manifest.json");
    write_json_file(&partner_manifest_path, &partner_manifest)?;

    let acknowledgement = MercuryReleaseReadinessDeliveryAcknowledgement {
        schema: "chio.mercury.release_readiness_delivery_acknowledgement.v1".to_string(),
        workflow_id: workflow_id.clone(),
        delivery_surface: MercuryReleaseReadinessDeliverySurface::SignedPartnerReviewBundle
            .as_str()
            .to_string(),
        partner_owner: MERCURY_RELEASE_PARTNER_OWNER.to_string(),
        status: "acknowledged".to_string(),
        acknowledged_at: unix_now(),
        acknowledged_by: MERCURY_RELEASE_PARTNER_OWNER.to_string(),
        delivered_files: vec![
            relative_display(output, &partner_manifest_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &assurance_suite_package_path)?,
            relative_display(output, &trust_network_package_path)?,
            relative_display(output, &reviewer_package_path)?,
            relative_display(output, &qualification_report_path)?,
        ],
        note: "Acknowledgement is required before this bounded release-readiness lane may be treated as launched."
            .to_string(),
    };
    let acknowledgement_path = output.join("delivery-acknowledgement.json");
    write_json_file(&acknowledgement_path, &acknowledgement)?;

    let package = MercuryReleaseReadinessPackage {
        schema: MERCURY_RELEASE_READINESS_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "release-readiness-signed-partner-review-bundle-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        audiences: profile.audiences.clone(),
        delivery_surface: MercuryReleaseReadinessDeliverySurface::SignedPartnerReviewBundle,
        release_owner: MERCURY_RELEASE_OWNER.to_string(),
        partner_owner: MERCURY_RELEASE_PARTNER_OWNER.to_string(),
        support_owner: MERCURY_RELEASE_SUPPORT_OWNER.to_string(),
        acknowledgement_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        artifacts: vec![
            MercuryReleaseReadinessArtifact {
                artifact_kind: MercuryReleaseReadinessArtifactKind::PartnerDeliveryManifest,
                relative_path: relative_display(output, &partner_manifest_path)?,
            },
            MercuryReleaseReadinessArtifact {
                artifact_kind: MercuryReleaseReadinessArtifactKind::DeliveryAcknowledgement,
                relative_path: relative_display(output, &acknowledgement_path)?,
            },
            MercuryReleaseReadinessArtifact {
                artifact_kind: MercuryReleaseReadinessArtifactKind::OperatorReleaseChecklist,
                relative_path: relative_display(output, &operator_release_checklist_path)?,
            },
            MercuryReleaseReadinessArtifact {
                artifact_kind: MercuryReleaseReadinessArtifactKind::EscalationManifest,
                relative_path: relative_display(output, &escalation_manifest_path)?,
            },
            MercuryReleaseReadinessArtifact {
                artifact_kind: MercuryReleaseReadinessArtifactKind::SupportHandoff,
                relative_path: relative_display(output, &support_handoff_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("release-readiness-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryReleaseReadinessExportSummary {
        workflow_id,
        audiences: profile
            .audiences
            .iter()
            .map(|audience| audience.as_str().to_string())
            .collect(),
        delivery_surface: MercuryReleaseReadinessDeliverySurface::SignedPartnerReviewBundle
            .as_str()
            .to_string(),
        release_owner: MERCURY_RELEASE_OWNER.to_string(),
        partner_owner: MERCURY_RELEASE_PARTNER_OWNER.to_string(),
        support_owner: MERCURY_RELEASE_SUPPORT_OWNER.to_string(),
        trust_network_dir: trust_network_dir.display().to_string(),
        release_readiness_profile_file: profile_path.display().to_string(),
        release_readiness_package_file: package_path.display().to_string(),
        partner_delivery_manifest_file: partner_manifest_path.display().to_string(),
        acknowledgement_file: acknowledgement_path.display().to_string(),
        operator_release_checklist_file: operator_release_checklist_path.display().to_string(),
        escalation_manifest_file: escalation_manifest_path.display().to_string(),
        support_handoff_file: support_handoff_path.display().to_string(),
        partner_bundle_dir: partner_bundle_dir.display().to_string(),
        proof_package_file: proof_package_path.display().to_string(),
        inquiry_package_file: inquiry_package_path.display().to_string(),
        inquiry_verification_file: inquiry_verification_path.display().to_string(),
        assurance_suite_package_file: assurance_suite_package_path.display().to_string(),
        trust_network_package_file: trust_network_package_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
    };
    write_json_file(&output.join("release-readiness-summary.json"), &summary)?;

    Ok(summary)
}

fn export_controlled_adoption(
    output: &Path,
) -> Result<MercuryControlledAdoptionExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let release_readiness_dir = output.join("release-readiness");
    let release_readiness = export_release_readiness(&release_readiness_dir)?;
    let workflow_id = release_readiness.workflow_id.clone();

    let profile = build_controlled_adoption_profile(&workflow_id)?;
    let profile_path = output.join("controlled-adoption-profile.json");
    write_json_file(&profile_path, &profile)?;

    let adoption_evidence_dir = output.join("adoption-evidence");
    fs::create_dir_all(&adoption_evidence_dir)?;

    let release_readiness_package_path =
        adoption_evidence_dir.join("release-readiness-package.json");
    let trust_network_package_path = adoption_evidence_dir.join("trust-network-package.json");
    let assurance_suite_package_path = adoption_evidence_dir.join("assurance-suite-package.json");
    let proof_package_path = adoption_evidence_dir.join("proof-package.json");
    let inquiry_package_path = adoption_evidence_dir.join("inquiry-package.json");
    let inquiry_verification_path = adoption_evidence_dir.join("inquiry-verification.json");
    let reviewer_package_path = adoption_evidence_dir.join("reviewer-package.json");
    let qualification_report_path = adoption_evidence_dir.join("qualification-report.json");

    copy_file(
        &release_readiness_dir.join("release-readiness-package.json"),
        &release_readiness_package_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/trust-network-package.json"),
        &trust_network_package_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/assurance-suite-package.json"),
        &assurance_suite_package_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/proof-package.json"),
        &proof_package_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/inquiry-package.json"),
        &inquiry_package_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/inquiry-verification.json"),
        &inquiry_verification_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/reviewer-package.json"),
        &reviewer_package_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/qualification-report.json"),
        &qualification_report_path,
    )?;

    let customer_success_checklist = MercuryControlledAdoptionCustomerSuccessChecklist {
        schema: "chio.mercury.controlled_adoption_customer_success_checklist.v1".to_string(),
        workflow_id: workflow_id.clone(),
        customer_success_owner: MERCURY_CUSTOMER_SUCCESS_OWNER.to_string(),
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        support_owner: MERCURY_ADOPTION_SUPPORT_OWNER.to_string(),
        fail_closed: true,
        readiness_checks: vec![
            "confirm the adoption cohort remains design-partner renewal only".to_string(),
            "confirm renewal evidence points back to the same release-readiness package and Mercury workflow".to_string(),
            "confirm reference-readiness materials use only the bounded approved claim".to_string(),
            "confirm customer-success and support escalation files exist before any renewal or reference motion".to_string(),
        ],
        note: "This checklist governs one Mercury post-launch adoption lane only and does not authorize generic Chio renewal tooling or broader Mercury delivery surfaces."
            .to_string(),
    };
    let customer_success_checklist_path = output.join("customer-success-checklist.json");
    write_json_file(
        &customer_success_checklist_path,
        &customer_success_checklist,
    )?;

    let renewal_manifest = MercuryControlledAdoptionRenewalManifest {
        schema: "chio.mercury.controlled_adoption_renewal_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        cohort: MercuryControlledAdoptionCohort::DesignPartnerRenewal
            .as_str()
            .to_string(),
        adoption_surface: MercuryControlledAdoptionSurface::RenewalReferenceBundle
            .as_str()
            .to_string(),
        success_window: profile.success_window.clone(),
        renewal_signal: "design partner confirms continued Mercury use with proof-backed renewal and reference review".to_string(),
        release_readiness_package_file: relative_display(output, &release_readiness_package_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        inquiry_verification_file: relative_display(output, &inquiry_verification_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        note: "This manifest freezes one bounded renewal-evidence lane on top of the validated Mercury release-readiness stack and does not imply a generic customer-success platform."
            .to_string(),
    };
    let renewal_manifest_path = output.join("renewal-evidence-manifest.json");
    write_json_file(&renewal_manifest_path, &renewal_manifest)?;

    let renewal_acknowledgement = MercuryControlledAdoptionRenewalAcknowledgement {
        schema: "chio.mercury.controlled_adoption_renewal_acknowledgement.v1".to_string(),
        workflow_id: workflow_id.clone(),
        cohort: MercuryControlledAdoptionCohort::DesignPartnerRenewal
            .as_str()
            .to_string(),
        adoption_surface: MercuryControlledAdoptionSurface::RenewalReferenceBundle
            .as_str()
            .to_string(),
        customer_success_owner: MERCURY_CUSTOMER_SUCCESS_OWNER.to_string(),
        status: "acknowledged".to_string(),
        acknowledged_at: unix_now(),
        acknowledged_by: MERCURY_CUSTOMER_SUCCESS_OWNER.to_string(),
        delivered_files: vec![
            relative_display(output, &renewal_manifest_path)?,
            relative_display(output, &release_readiness_package_path)?,
            relative_display(output, &trust_network_package_path)?,
            relative_display(output, &assurance_suite_package_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &reviewer_package_path)?,
            relative_display(output, &qualification_report_path)?,
        ],
        note: "Acknowledgement is required before the bounded renewal and reference lane may be treated as ready for scaled Mercury adoption."
            .to_string(),
    };
    let renewal_acknowledgement_path = output.join("renewal-acknowledgement.json");
    write_json_file(&renewal_acknowledgement_path, &renewal_acknowledgement)?;

    let reference_readiness_brief = MercuryControlledAdoptionReferenceReadinessBrief {
        schema: "chio.mercury.controlled_adoption_reference_readiness_brief.v1".to_string(),
        workflow_id: workflow_id.clone(),
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        cohort: MercuryControlledAdoptionCohort::DesignPartnerRenewal
            .as_str()
            .to_string(),
        adoption_surface: MercuryControlledAdoptionSurface::RenewalReferenceBundle
            .as_str()
            .to_string(),
        approved_claim: "Mercury can support one bounded controlled-adoption lane for renewal and reference readiness over the validated release-readiness evidence stack."
            .to_string(),
        required_files: vec![
            relative_display(output, &renewal_manifest_path)?,
            relative_display(output, &renewal_acknowledgement_path)?,
            relative_display(output, &release_readiness_package_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
        ],
        note: "Reference material remains bounded to one approved claim and one design-partner renewal cohort. Broader marketing claims require a later milestone."
            .to_string(),
    };
    let reference_readiness_brief_path = output.join("reference-readiness-brief.json");
    write_json_file(&reference_readiness_brief_path, &reference_readiness_brief)?;

    let support_escalation_manifest = MercuryControlledAdoptionSupportEscalationManifest {
        schema: "chio.mercury.controlled_adoption_support_escalation_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        support_owner: MERCURY_ADOPTION_SUPPORT_OWNER.to_string(),
        customer_success_owner: MERCURY_CUSTOMER_SUCCESS_OWNER.to_string(),
        fail_closed: true,
        escalation_triggers: vec![
            "renewal evidence no longer maps to the same release-readiness package".to_string(),
            "reference-readiness brief uses an unapproved claim or missing artifact".to_string(),
            "proof, inquiry, assurance, or trust-network adoption evidence is missing".to_string(),
            "customer-success acknowledgement is missing before renewal or reference use".to_string(),
        ],
        note: "Escalation remains Mercury-owned for one bounded controlled-adoption lane and must not migrate into Chio generic release or support surfaces."
            .to_string(),
    };
    let support_escalation_manifest_path = output.join("support-escalation-manifest.json");
    write_json_file(
        &support_escalation_manifest_path,
        &support_escalation_manifest,
    )?;

    let package = MercuryControlledAdoptionPackage {
        schema: MERCURY_CONTROLLED_ADOPTION_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "controlled-adoption-design-partner-renewal-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        cohort: MercuryControlledAdoptionCohort::DesignPartnerRenewal,
        adoption_surface: MercuryControlledAdoptionSurface::RenewalReferenceBundle,
        customer_success_owner: MERCURY_CUSTOMER_SUCCESS_OWNER.to_string(),
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        support_owner: MERCURY_ADOPTION_SUPPORT_OWNER.to_string(),
        acknowledgement_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        release_readiness_package_file: relative_display(output, &release_readiness_package_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        artifacts: vec![
            MercuryControlledAdoptionArtifact {
                artifact_kind: MercuryControlledAdoptionArtifactKind::CustomerSuccessChecklist,
                relative_path: relative_display(output, &customer_success_checklist_path)?,
            },
            MercuryControlledAdoptionArtifact {
                artifact_kind: MercuryControlledAdoptionArtifactKind::RenewalEvidenceManifest,
                relative_path: relative_display(output, &renewal_manifest_path)?,
            },
            MercuryControlledAdoptionArtifact {
                artifact_kind: MercuryControlledAdoptionArtifactKind::RenewalAcknowledgement,
                relative_path: relative_display(output, &renewal_acknowledgement_path)?,
            },
            MercuryControlledAdoptionArtifact {
                artifact_kind: MercuryControlledAdoptionArtifactKind::ReferenceReadinessBrief,
                relative_path: relative_display(output, &reference_readiness_brief_path)?,
            },
            MercuryControlledAdoptionArtifact {
                artifact_kind: MercuryControlledAdoptionArtifactKind::SupportEscalationManifest,
                relative_path: relative_display(output, &support_escalation_manifest_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("controlled-adoption-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryControlledAdoptionExportSummary {
        workflow_id,
        cohort: MercuryControlledAdoptionCohort::DesignPartnerRenewal
            .as_str()
            .to_string(),
        adoption_surface: MercuryControlledAdoptionSurface::RenewalReferenceBundle
            .as_str()
            .to_string(),
        customer_success_owner: MERCURY_CUSTOMER_SUCCESS_OWNER.to_string(),
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        support_owner: MERCURY_ADOPTION_SUPPORT_OWNER.to_string(),
        release_readiness_dir: release_readiness_dir.display().to_string(),
        controlled_adoption_profile_file: profile_path.display().to_string(),
        controlled_adoption_package_file: package_path.display().to_string(),
        customer_success_checklist_file: customer_success_checklist_path.display().to_string(),
        renewal_evidence_manifest_file: renewal_manifest_path.display().to_string(),
        renewal_acknowledgement_file: renewal_acknowledgement_path.display().to_string(),
        reference_readiness_brief_file: reference_readiness_brief_path.display().to_string(),
        support_escalation_manifest_file: support_escalation_manifest_path.display().to_string(),
        adoption_evidence_dir: adoption_evidence_dir.display().to_string(),
        release_readiness_package_file: release_readiness_package_path.display().to_string(),
        trust_network_package_file: trust_network_package_path.display().to_string(),
        assurance_suite_package_file: assurance_suite_package_path.display().to_string(),
        proof_package_file: proof_package_path.display().to_string(),
        inquiry_package_file: inquiry_package_path.display().to_string(),
        inquiry_verification_file: inquiry_verification_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
    };
    write_json_file(&output.join("controlled-adoption-summary.json"), &summary)?;

    let _ = release_readiness;

    Ok(summary)
}

fn export_reference_distribution(
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

fn export_broader_distribution(
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
