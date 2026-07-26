use super::super::*;
use super::export_embedded_oem;

pub(in crate::commands) fn export_trust_network(
    output: &Path,
) -> Result<MercuryTrustNetworkExportSummary, CliError> {
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

    shared_proof_package
        .publication_profile
        .checkpoint_continuity = "append_only".to_string();
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
        .refresh_package_id()
        .map_err(|error| CliError::Other(error.to_string()))?;
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
