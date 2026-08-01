use super::super::*;
use super::types::*;
use super::utils::*;

pub(crate) fn build_proof_package(
    input: &Path,
    bundle_manifest_paths: &[PathBuf],
) -> Result<MercuryProofPackage, CliError> {
    let verified = evidence_export::load_verified_evidence_package_summary(input)?;
    let bundle_manifests = load_bundle_manifests(bundle_manifest_paths)?;
    MercuryProofPackage::build(
        verified.bundle,
        verified.manifest_hash,
        verified.manifest_schema,
        verified.exported_at,
        unix_now(),
        MercuryPublicationProfile::pilot_default(),
        verified.transparency,
        bundle_manifests,
    )
    .map_err(|error| CliError::Other(error.to_string()))
}

pub(crate) fn build_inquiry_package(
    proof_package: MercuryProofPackage,
    audience: &str,
    redaction_profile: Option<&str>,
    verifier_equivalent: bool,
) -> Result<MercuryInquiryPackage, CliError> {
    let latest = proof_package
        .receipt_records
        .last()
        .ok_or_else(|| CliError::Other("proof package is missing receipt_records".to_string()))?
        .metadata
        .clone();
    let workflow_id = proof_package.workflow_id.clone();
    let proof_package_id = proof_package.package_id.clone();
    let disclosure_policy = latest.disclosure.policy.clone();
    let approval_state = latest.approval_state.state.as_str().to_string();
    let rendered_export = serde_json::json!({
        "workflowId": workflow_id,
        "proofPackageId": proof_package_id,
        "audience": audience,
        "redactionProfile": redaction_profile,
        "verifierEquivalent": verifier_equivalent,
        "receiptIds": proof_package
            .receipt_records
            .iter()
            .map(|record| record.receipt_id.clone())
            .collect::<Vec<_>>(),
        "disclosurePolicy": disclosure_policy,
        "approvalState": approval_state,
    });
    MercuryInquiryPackage::build(
        proof_package,
        MercuryInquiryPackageArgs {
            created_at: unix_now(),
            audience: audience.to_string(),
            redaction_profile: redaction_profile.map(ToOwned::to_owned),
            rendered_export,
            disclosure: latest.disclosure,
            approval_state: latest.approval_state,
            verifier_equivalent,
        },
    )
    .map_err(|error| CliError::Other(error.to_string()))
}

pub(crate) fn write_verification_report(
    path: &Path,
    report: &MercuryVerificationReport,
) -> Result<(), CliError> {
    write_json_file(path, report)
}

pub(crate) fn pilot_capability_with_id(
    id: &str,
    subject: &Keypair,
    issuer: &Keypair,
) -> Result<CapabilityToken, CliError> {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "mercury".to_string(),
                    tool_name: "*".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            issued_at: 100,
            expires_at: 10_000,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        issuer,
    )
    .map_err(CliError::from)
}

pub(crate) fn pilot_receipt(
    step: &MercuryPilotStep,
    capability_id: &str,
    kernel_keypair: &Keypair,
) -> Result<ChioReceipt, CliError> {
    let action = ToolCallAction::from_parameters(serde_json::json!({
        "workflowId": step.metadata.business_ids.workflow_id,
        "eventId": step.metadata.chronology.event_id,
        "decisionType": step.metadata.decision_context.decision_type.as_str(),
        "stage": serde_json::to_value(step.metadata.chronology.stage)?,
    }))?;
    let metadata = step
        .metadata
        .into_receipt_metadata_value()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let content_hash = sha256_hex(&canonical_json_bytes(&step.metadata)?);
    ChioReceipt::sign(
        ChioReceiptBody {
            id: step.receipt_id.clone(),
            timestamp: step.timestamp,
            capability_id: capability_id.to_string(),
            tool_server: "mercury".to_string(),
            tool_name: step.tool_name.clone(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash,
            policy_hash: "policy-mercury-pilot-v1".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kernel_keypair.public_key(),
            bbs_projection_version: None,
        },
        kernel_keypair,
    )
    .map_err(CliError::from)
}

pub(crate) fn populate_mercury_receipt_store(
    receipt_db: &Path,
    capability_id: &str,
    steps: &[MercuryPilotStep],
) -> Result<(), CliError> {
    let store = SqliteReceiptStore::open(receipt_db)?;
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let kernel_keypair = Keypair::generate();
    let capability = pilot_capability_with_id(capability_id, &subject, &issuer)?;
    store
        .record_capability_snapshot(&capability, None)
        .map_err(|error| CliError::Other(error.to_string()))?;

    let mut start_seq = None;
    let mut end_seq = None;
    for step in steps {
        let receipt = pilot_receipt(step, capability_id, &kernel_keypair)?;
        let seq = store.append_chio_receipt_returning_seq(&receipt)?;
        if start_seq.is_none() {
            start_seq = Some(seq);
        }
        end_seq = Some(seq);
    }

    let start_seq = start_seq
        .ok_or_else(|| CliError::Other("capture did not generate any receipts".to_string()))?;
    let end_seq = end_seq
        .ok_or_else(|| CliError::Other("capture did not generate any receipts".to_string()))?;
    let canonical = store.receipts_canonical_bytes_range(start_seq, end_seq)?;
    let checkpoint = build_checkpoint(
        1,
        start_seq,
        end_seq,
        &canonical
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>(),
        &kernel_keypair,
    )?;
    store.store_checkpoint(&checkpoint)?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AssurancePackageArgs<'a> {
    pub(crate) workflow_id: &'a str,
    pub(crate) audience: MercuryAssuranceAudience,
    pub(crate) disclosure_profile: &'a str,
    pub(crate) proof_package_file: &'a str,
    pub(crate) inquiry_package_file: &'a str,
    pub(crate) reviewer_package_file: &'a str,
    pub(crate) qualification_report_file: &'a str,
    pub(crate) verifier_equivalent: bool,
}

pub(crate) fn build_assurance_package(
    args: AssurancePackageArgs<'_>,
) -> Result<MercuryAssurancePackage, CliError> {
    let package = MercuryAssurancePackage {
        schema: MERCURY_ASSURANCE_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "assurance-{}-{}-{}",
            args.audience.as_str(),
            args.workflow_id,
            current_utc_date()
        ),
        workflow_id: args.workflow_id.to_string(),
        audience: args.audience,
        disclosure_profile: args.disclosure_profile.to_string(),
        proof_package_file: args.proof_package_file.to_string(),
        inquiry_package_file: args.inquiry_package_file.to_string(),
        reviewer_package_file: args.reviewer_package_file.to_string(),
        qualification_report_file: args.qualification_report_file.to_string(),
        verifier_equivalent: args.verifier_equivalent,
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(package)
}

pub(crate) struct GovernanceReviewPackageArgs<'a> {
    pub(crate) workflow_id: &'a str,
    pub(crate) audience: MercuryGovernanceReviewAudience,
    pub(crate) disclosure_profile: &'a str,
    pub(crate) proof_package_file: &'a str,
    pub(crate) inquiry_package_file: &'a str,
    pub(crate) reviewer_package_file: &'a str,
    pub(crate) qualification_report_file: &'a str,
    pub(crate) decision_package_file: &'a str,
    pub(crate) verifier_equivalent: bool,
}

pub(crate) fn build_governance_review_package(
    args: GovernanceReviewPackageArgs<'_>,
) -> Result<MercuryGovernanceReviewPackage, CliError> {
    let package = MercuryGovernanceReviewPackage {
        schema: MERCURY_GOVERNANCE_REVIEW_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "governance-review-{}-{}-{}",
            args.audience.as_str(),
            args.workflow_id,
            current_utc_date()
        ),
        workflow_id: args.workflow_id.to_string(),
        audience: args.audience,
        disclosure_profile: args.disclosure_profile.to_string(),
        proof_package_file: args.proof_package_file.to_string(),
        inquiry_package_file: args.inquiry_package_file.to_string(),
        reviewer_package_file: args.reviewer_package_file.to_string(),
        qualification_report_file: args.qualification_report_file.to_string(),
        decision_package_file: args.decision_package_file.to_string(),
        verifier_equivalent: args.verifier_equivalent,
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(package)
}

pub(crate) fn build_assurance_disclosure_profile(
    workflow_id: &str,
    config: MercuryAssurancePopulationConfig<'_>,
) -> Result<MercuryAssuranceDisclosureProfile, CliError> {
    let profile = MercuryAssuranceDisclosureProfile {
        schema: MERCURY_ASSURANCE_DISCLOSURE_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "assurance-{}-{}-{}",
            config.reviewer_population.as_str(),
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        reviewer_population: config.reviewer_population,
        redaction_profile: config.redaction_profile.to_string(),
        verifier_equivalent: config.verifier_equivalent,
        retained_artifact_policy: config.retained_artifact_policy.to_string(),
        intended_use: config.intended_use.to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

pub(crate) struct AssuranceReviewPackageArgs<'a> {
    pub(crate) workflow_id: &'a str,
    pub(crate) reviewer_population: MercuryAssuranceReviewerPopulation,
    pub(crate) disclosure_profile_file: &'a str,
    pub(crate) proof_package_file: &'a str,
    pub(crate) inquiry_package_file: &'a str,
    pub(crate) inquiry_verification_file: &'a str,
    pub(crate) reviewer_package_file: &'a str,
    pub(crate) qualification_report_file: &'a str,
    pub(crate) governance_decision_package_file: &'a str,
    pub(crate) verifier_equivalent: bool,
}

pub(crate) fn build_assurance_review_package(
    args: AssuranceReviewPackageArgs<'_>,
) -> Result<MercuryAssuranceReviewPackage, CliError> {
    let package = MercuryAssuranceReviewPackage {
        schema: MERCURY_ASSURANCE_REVIEW_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "assurance-review-{}-{}-{}",
            args.reviewer_population.as_str(),
            args.workflow_id,
            current_utc_date()
        ),
        workflow_id: args.workflow_id.to_string(),
        reviewer_population: args.reviewer_population,
        disclosure_profile_file: args.disclosure_profile_file.to_string(),
        proof_package_file: args.proof_package_file.to_string(),
        inquiry_package_file: args.inquiry_package_file.to_string(),
        inquiry_verification_file: args.inquiry_verification_file.to_string(),
        reviewer_package_file: args.reviewer_package_file.to_string(),
        qualification_report_file: args.qualification_report_file.to_string(),
        governance_decision_package_file: args.governance_decision_package_file.to_string(),
        verifier_equivalent: args.verifier_equivalent,
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(package)
}

pub(crate) fn collect_assurance_investigation_inputs(
    proof_package: &MercuryProofPackage,
) -> MercuryAssuranceInvestigationInputs {
    let event_ids = proof_package
        .receipt_records
        .iter()
        .map(|record| record.metadata.chronology.event_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let source_record_ids = proof_package
        .receipt_records
        .iter()
        .filter_map(|record| record.metadata.provenance.source_record_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let idempotency_keys = proof_package
        .receipt_records
        .iter()
        .filter_map(|record| record.metadata.chronology.idempotency_key.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    MercuryAssuranceInvestigationInputs {
        account_id: proof_package.account_id.clone(),
        desk_id: proof_package.desk_id.clone(),
        strategy_id: proof_package.strategy_id.clone(),
        event_ids,
        source_record_ids,
        idempotency_keys,
    }
}

pub(crate) fn build_assurance_investigation_package(
    workflow_id: &str,
    reviewer_population: MercuryAssuranceReviewerPopulation,
    assurance_review_package_file: &str,
    investigation_inputs: &MercuryAssuranceInvestigationInputs,
    investigation_focus: &[&str],
) -> Result<MercuryAssuranceInvestigationPackage, CliError> {
    let package = MercuryAssuranceInvestigationPackage {
        schema: MERCURY_ASSURANCE_INVESTIGATION_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "assurance-investigation-{}-{}-{}",
            reviewer_population.as_str(),
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        reviewer_population,
        assurance_review_package_file: assurance_review_package_file.to_string(),
        account_id: investigation_inputs.account_id.clone(),
        desk_id: investigation_inputs.desk_id.clone(),
        strategy_id: investigation_inputs.strategy_id.clone(),
        investigation_focus: investigation_focus
            .iter()
            .map(ToString::to_string)
            .collect(),
        event_ids: investigation_inputs.event_ids.clone(),
        source_record_ids: investigation_inputs.source_record_ids.clone(),
        idempotency_keys: investigation_inputs.idempotency_keys.clone(),
        fail_closed: true,
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(package)
}

pub(crate) fn build_embedded_oem_profile(
    workflow_id: &str,
) -> Result<MercuryEmbeddedOemProfile, CliError> {
    let profile = MercuryEmbeddedOemProfile {
        schema: MERCURY_EMBEDDED_OEM_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "embedded-oem-reviewer-workbench-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        partner_surface: MercuryEmbeddedPartnerSurface::ReviewerWorkbenchEmbed,
        sdk_surface: MercuryEmbeddedSdkSurface::SignedArtifactBundle,
        reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview,
        retained_artifact_policy: "retain-bounded-redacted-review-artifacts".to_string(),
        intended_use: "Embed a bounded counterparty-review Mercury evidence bundle inside one partner reviewer workbench without widening into a generic SDK platform."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

pub(crate) fn build_trust_network_profile(
    workflow_id: &str,
) -> Result<MercuryTrustNetworkProfile, CliError> {
    let profile = MercuryTrustNetworkProfile {
        schema: MERCURY_TRUST_NETWORK_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "trust-network-counterparty-review-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        sponsor_boundary: MercuryTrustNetworkSponsorBoundary::CounterpartyReviewExchange,
        trust_anchor: MercuryTrustNetworkTrustAnchor::ChioCheckpointWitnessChain,
        interop_surface: MercuryTrustNetworkInteropSurface::ProofInquiryBundleExchange,
        reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview,
        witness_steps: vec![
            MercuryTrustNetworkWitnessStep::CheckpointPublication,
            MercuryTrustNetworkWitnessStep::IndependentWitnessRecord,
            MercuryTrustNetworkWitnessStep::CounterpartyResolution,
        ],
        retained_artifact_policy:
            "retain-shared-proof-and-counterparty-review-exchange-artifacts".to_string(),
        intended_use: "Share one bounded counterparty-review proof and inquiry bundle across one checkpoint-backed witness chain without widening Mercury into a generic trust broker."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

pub(crate) fn build_release_readiness_profile(
    workflow_id: &str,
) -> Result<MercuryReleaseReadinessProfile, CliError> {
    let profile = MercuryReleaseReadinessProfile {
        schema: MERCURY_RELEASE_READINESS_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "release-readiness-signed-partner-review-bundle-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        audiences: vec![
            MercuryReleaseReadinessAudience::Reviewer,
            MercuryReleaseReadinessAudience::Partner,
            MercuryReleaseReadinessAudience::Operator,
        ],
        delivery_surface: MercuryReleaseReadinessDeliverySurface::SignedPartnerReviewBundle,
        retained_artifact_policy:
            "retain-bounded-release-review-and-partner-delivery-artifacts".to_string(),
        intended_use: "Launch one bounded Mercury release-readiness lane for reviewer, partner, and operator audiences over the validated trust-network bundle without widening Mercury into a new product line."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

pub(crate) fn build_controlled_adoption_profile(
    workflow_id: &str,
) -> Result<MercuryControlledAdoptionProfile, CliError> {
    let profile = MercuryControlledAdoptionProfile {
        schema: MERCURY_CONTROLLED_ADOPTION_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "controlled-adoption-design-partner-renewal-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        cohort: MercuryControlledAdoptionCohort::DesignPartnerRenewal,
        adoption_surface: MercuryControlledAdoptionSurface::RenewalReferenceBundle,
        success_window: "first-90-days-post-launch".to_string(),
        retained_artifact_policy:
            "retain-bounded-adoption-renewal-and-reference-artifacts".to_string(),
        intended_use: "Qualify one bounded Mercury controlled-adoption lane for renewal and reference evidence over the validated release-readiness package without widening Mercury into new product surfaces or polluting Chio generic crates."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

pub(crate) fn build_reference_distribution_profile(
    workflow_id: &str,
) -> Result<MercuryReferenceDistributionProfile, CliError> {
    let profile = MercuryReferenceDistributionProfile {
        schema: MERCURY_REFERENCE_DISTRIBUTION_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "reference-distribution-landed-account-expansion-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        expansion_motion: MercuryReferenceDistributionMotion::LandedAccountExpansion,
        distribution_surface: MercuryReferenceDistributionSurface::ApprovedReferenceBundle,
        claim_discipline: "approved-reference-evidence-only".to_string(),
        retained_artifact_policy:
            "retain-bounded-reference-distribution-and-landed-account-expansion-artifacts"
                .to_string(),
        intended_use: "Qualify one bounded Mercury reference-distribution lane for landed-account expansion over the validated controlled-adoption package without widening into generic sales tooling, merged shells, or Chio commercial surfaces."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

pub(crate) fn build_broader_distribution_profile(
    workflow_id: &str,
) -> Result<MercuryBroaderDistributionProfile, CliError> {
    let profile = MercuryBroaderDistributionProfile {
        schema: MERCURY_BROADER_DISTRIBUTION_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "broader-distribution-selective-account-qualification-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        distribution_motion: MercuryBroaderDistributionMotion::SelectiveAccountQualification,
        distribution_surface: MercuryBroaderDistributionSurface::GovernedDistributionBundle,
        claim_governance: "governed-broader-distribution-evidence-only".to_string(),
        retained_artifact_policy:
            "retain-bounded-broader-distribution-and-selective-account-qualification-artifacts"
                .to_string(),
        intended_use: "Qualify one bounded Mercury broader-distribution lane for selective account qualification over the validated reference-distribution package without widening into generic sales tooling, CRM workflows, merged shells, or Chio commercial surfaces."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}
