fn current_utc_date() -> String {
    Utc::now().format("%Y-%m-%d").to_string()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("{prefix}-{stamp}-{}", std::process::id()))
}

fn read_json_file<T: for<'de> serde::Deserialize<'de>>(path: &Path) -> Result<T, CliError> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn write_json_file<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn ensure_empty_directory(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        if !path.is_dir() {
            return Err(CliError::Other(format!(
                "output path must be a directory: {}",
                path.display()
            )));
        }
        if fs::read_dir(path)?.next().is_some() {
            return Err(CliError::Other(format!(
                "output directory must be empty: {}",
                path.display()
            )));
        }
    } else {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

fn relative_display(root: &Path, path: &Path) -> Result<String, CliError> {
    path.strip_prefix(root)
        .map(|relative| relative.display().to_string())
        .map_err(|error| CliError::Other(error.to_string()))
}

fn copy_file(src: &Path, dst: &Path) -> Result<(), CliError> {
    let parent = dst.parent().ok_or_else(|| {
        CliError::Other(format!(
            "destination path is missing parent directory: {}",
            dst.display()
        ))
    })?;
    fs::create_dir_all(parent)?;
    fs::copy(src, dst)?;
    Ok(())
}

fn load_bundle_manifests(paths: &[PathBuf]) -> Result<Vec<MercuryBundleManifest>, CliError> {
    paths
        .iter()
        .map(|path| {
            let manifest: MercuryBundleManifest = read_json_file(path)?;
            manifest
                .validate()
                .map_err(|error| CliError::Other(error.to_string()))?;
            Ok(manifest)
        })
        .collect()
}

fn write_bundle_manifests(
    dir: &Path,
    manifests: &[MercuryBundleManifest],
) -> Result<Vec<PathBuf>, CliError> {
    if manifests.len() == 1 {
        let path = dir.with_file_name("bundle-manifest.json");
        write_json_file(&path, &manifests[0])?;
        return Ok(vec![path]);
    }

    fs::create_dir_all(dir)?;
    let mut paths = Vec::with_capacity(manifests.len());
    for (index, manifest) in manifests.iter().enumerate() {
        let path = dir.join(format!("{:02}-{}.json", index + 1, manifest.bundle_id));
        write_json_file(&path, manifest)?;
        paths.push(path);
    }
    Ok(paths)
}

fn build_proof_package(
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

fn build_inquiry_package(
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

fn write_verification_report(
    path: &Path,
    report: &MercuryVerificationReport,
) -> Result<(), CliError> {
    write_json_file(path, report)
}

fn pilot_capability_with_id(
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
        },
        issuer,
    )
    .map_err(CliError::from)
}

fn pilot_receipt(
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
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kernel_keypair.public_key(),
        },
        kernel_keypair,
    )
    .map_err(CliError::from)
}

fn populate_mercury_receipt_store(
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
struct PilotInquiryConfig<'a> {
    audience: &'a str,
    redaction_profile: Option<&'a str>,
    verifier_equivalent: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryPilotRunPaths {
    events_file: String,
    receipt_db: String,
    evidence_dir: String,
    bundle_manifest_file: String,
    proof_package_file: String,
    proof_verification_file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inquiry_package_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inquiry_verification_file: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryExportRunPaths {
    input_file: String,
    receipt_db: String,
    evidence_dir: String,
    bundle_manifest_files: Vec<String>,
    proof_package_file: String,
    proof_verification_file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inquiry_package_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inquiry_verification_file: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryPilotExportSummary {
    scenario_id: String,
    workflow_id: String,
    scenario_file: String,
    primary_receipt_count: usize,
    rollback_receipt_count: usize,
    primary: MercuryPilotRunPaths,
    rollback: MercuryPilotRunPaths,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySupervisedLiveExportSummary {
    capture_id: String,
    workflow_id: String,
    mode: String,
    receipt_count: usize,
    control_state: MercurySupervisedLiveControlState,
    export: MercuryExportRunPaths,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryQualificationDocRefs {
    bridge_file: String,
    operating_model_file: String,
    operations_runbook_file: String,
    qualification_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySupervisedLiveQualificationReport {
    workflow_id: String,
    decision: String,
    same_workflow_boundary: String,
    supervised_live: MercurySupervisedLiveExportSummary,
    pilot: MercuryPilotExportSummary,
    docs: MercuryQualificationDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySupervisedLiveReviewerPackage {
    workflow_id: String,
    decision: String,
    qualification_report_file: String,
    supervised_live_dir: String,
    pilot_dir: String,
    supervised_live_proof_package_file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    supervised_live_inquiry_package_file: Option<String>,
    rollback_proof_package_file: String,
    docs: MercuryQualificationDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDownstreamReviewDocRefs {
    distribution_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDownstreamConsumerManifest {
    schema: String,
    workflow_id: String,
    consumer_profile: String,
    transport: String,
    acknowledgement_required: bool,
    fail_closed: bool,
    reviewer_package_file: String,
    qualification_report_file: String,
    external_assurance_package_file: String,
    external_inquiry_package_file: String,
    external_inquiry_verification_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDownstreamDeliveryAcknowledgement {
    schema: String,
    workflow_id: String,
    consumer_profile: String,
    destination_label: String,
    status: String,
    acknowledged_at: u64,
    acknowledged_by: String,
    delivered_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDownstreamReviewExportSummary {
    workflow_id: String,
    consumer_profile: String,
    transport: String,
    qualification_dir: String,
    internal_assurance_package_file: String,
    external_assurance_package_file: String,
    downstream_review_package_file: String,
    consumer_manifest_file: String,
    acknowledgement_file: String,
    consumer_drop_dir: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDownstreamReviewDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_consumer_profile: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDownstreamReviewValidationReport {
    workflow_id: String,
    decision: String,
    consumer_profile: String,
    same_workflow_boundary: String,
    downstream_review: MercuryDownstreamReviewExportSummary,
    decision_record_file: String,
    docs: MercuryDownstreamReviewDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryGovernanceWorkbenchDocRefs {
    workbench_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryGovernanceWorkbenchExportSummary {
    workflow_id: String,
    workflow_path: String,
    workflow_owner: String,
    control_team_owner: String,
    qualification_dir: String,
    control_state: MercuryGovernanceControlState,
    control_state_file: String,
    governance_decision_package_file: String,
    workflow_owner_review_package_file: String,
    control_team_review_package_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryGovernanceWorkbenchDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_workflow_path: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryGovernanceWorkbenchValidationReport {
    workflow_id: String,
    decision: String,
    workflow_path: String,
    same_workflow_boundary: String,
    governance_workbench: MercuryGovernanceWorkbenchExportSummary,
    decision_record_file: String,
    docs: MercuryGovernanceWorkbenchDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryAssuranceSuiteDocRefs {
    suite_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Copy)]
struct MercuryAssurancePopulationConfig<'a> {
    reviewer_population: MercuryAssuranceReviewerPopulation,
    dir_name: &'a str,
    audience: &'a str,
    redaction_profile: &'a str,
    retained_artifact_policy: &'a str,
    intended_use: &'a str,
    verifier_equivalent: bool,
    investigation_focus: &'a [&'a str],
}

#[derive(Debug, Clone)]
struct MercuryAssuranceInvestigationInputs {
    account_id: Option<String>,
    desk_id: Option<String>,
    strategy_id: Option<String>,
    event_ids: Vec<String>,
    source_record_ids: Vec<String>,
    idempotency_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryAssuranceSuiteExportSummary {
    workflow_id: String,
    reviewer_owner: String,
    support_owner: String,
    reviewer_populations: Vec<String>,
    qualification_dir: String,
    governance_workbench_dir: String,
    governance_decision_package_file: String,
    assurance_suite_package_file: String,
    internal_review_package_file: String,
    auditor_review_package_file: String,
    counterparty_review_package_file: String,
    internal_investigation_package_file: String,
    auditor_investigation_package_file: String,
    counterparty_investigation_package_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryAssuranceSuiteDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_reviewer_populations: Vec<String>,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryAssuranceSuiteValidationReport {
    workflow_id: String,
    decision: String,
    reviewer_owner: String,
    support_owner: String,
    same_workflow_boundary: String,
    assurance_suite: MercuryAssuranceSuiteExportSummary,
    decision_record_file: String,
    docs: MercuryAssuranceSuiteDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryEmbeddedOemDocRefs {
    oem_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryEmbeddedPartnerManifest {
    schema: String,
    workflow_id: String,
    partner_surface: String,
    sdk_surface: String,
    reviewer_population: String,
    fail_closed: bool,
    acknowledgement_required: bool,
    profile_file: String,
    assurance_suite_package_file: String,
    governance_decision_package_file: String,
    disclosure_profile_file: String,
    review_package_file: String,
    investigation_package_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
    support_owner: String,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryEmbeddedDeliveryAcknowledgement {
    schema: String,
    workflow_id: String,
    partner_surface: String,
    partner_owner: String,
    status: String,
    acknowledged_at: u64,
    acknowledged_by: String,
    delivered_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryEmbeddedOemExportSummary {
    workflow_id: String,
    partner_surface: String,
    sdk_surface: String,
    reviewer_population: String,
    partner_owner: String,
    support_owner: String,
    assurance_suite_dir: String,
    embedded_oem_profile_file: String,
    embedded_oem_package_file: String,
    partner_sdk_manifest_file: String,
    assurance_suite_package_file: String,
    governance_decision_package_file: String,
    disclosure_profile_file: String,
    review_package_file: String,
    investigation_package_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
    acknowledgement_file: String,
    partner_sdk_bundle_dir: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryEmbeddedOemDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_partner_surface: String,
    selected_sdk_surface: String,
    selected_reviewer_population: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryEmbeddedOemValidationReport {
    workflow_id: String,
    decision: String,
    partner_surface: String,
    sdk_surface: String,
    reviewer_population: String,
    partner_owner: String,
    support_owner: String,
    same_workflow_boundary: String,
    embedded_oem: MercuryEmbeddedOemExportSummary,
    decision_record_file: String,
    docs: MercuryEmbeddedOemDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryTrustNetworkDocRefs {
    trust_network_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryTrustNetworkInteroperabilityManifest {
    schema: String,
    workflow_id: String,
    sponsor_boundary: String,
    trust_anchor: String,
    interop_surface: String,
    reviewer_population: String,
    fail_closed: bool,
    profile_file: String,
    shared_proof_package_file: String,
    shared_review_package_file: String,
    shared_inquiry_package_file: String,
    shared_inquiry_verification_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
    witness_record_file: String,
    trust_anchor_record_file: String,
    support_owner: String,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryTrustNetworkWitnessRecord {
    schema: String,
    workflow_id: String,
    sponsor_boundary: String,
    trust_anchor: String,
    checkpoint_continuity: String,
    witness_steps: Vec<String>,
    witness_operator: String,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryTrustAnchorRecord {
    schema: String,
    workflow_id: String,
    trust_anchor: String,
    anchor_scope: String,
    verification_material: String,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryTrustNetworkExportSummary {
    workflow_id: String,
    sponsor_boundary: String,
    trust_anchor: String,
    interop_surface: String,
    reviewer_population: String,
    sponsor_owner: String,
    support_owner: String,
    embedded_oem_dir: String,
    trust_network_profile_file: String,
    trust_network_package_file: String,
    interop_manifest_file: String,
    shared_proof_package_file: String,
    shared_review_package_file: String,
    shared_inquiry_package_file: String,
    shared_inquiry_verification_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
    witness_record_file: String,
    trust_anchor_record_file: String,
    share_dir: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryTrustNetworkDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_sponsor_boundary: String,
    selected_trust_anchor: String,
    selected_interop_surface: String,
    selected_reviewer_population: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryTrustNetworkValidationReport {
    workflow_id: String,
    decision: String,
    sponsor_boundary: String,
    trust_anchor: String,
    interop_surface: String,
    reviewer_population: String,
    sponsor_owner: String,
    support_owner: String,
    same_workflow_boundary: String,
    trust_network: MercuryTrustNetworkExportSummary,
    decision_record_file: String,
    docs: MercuryTrustNetworkDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReleaseReadinessDocRefs {
    release_readiness_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReleaseReadinessPartnerManifest {
    schema: String,
    workflow_id: String,
    delivery_surface: String,
    reviewer_population: String,
    acknowledgement_required: bool,
    fail_closed: bool,
    proof_package_file: String,
    inquiry_package_file: String,
    inquiry_verification_file: String,
    assurance_suite_package_file: String,
    trust_network_package_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
    operator_release_checklist_file: String,
    escalation_manifest_file: String,
    support_handoff_file: String,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReleaseReadinessDeliveryAcknowledgement {
    schema: String,
    workflow_id: String,
    delivery_surface: String,
    partner_owner: String,
    status: String,
    acknowledged_at: u64,
    acknowledged_by: String,
    delivered_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReleaseReadinessOperatorChecklist {
    schema: String,
    workflow_id: String,
    release_owner: String,
    partner_owner: String,
    support_owner: String,
    fail_closed: bool,
    gating_checks: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReleaseReadinessEscalationManifest {
    schema: String,
    workflow_id: String,
    release_owner: String,
    support_owner: String,
    fail_closed: bool,
    escalation_triggers: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReleaseReadinessSupportHandoff {
    schema: String,
    workflow_id: String,
    release_owner: String,
    support_owner: String,
    active_window: String,
    required_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReleaseReadinessExportSummary {
    workflow_id: String,
    audiences: Vec<String>,
    delivery_surface: String,
    release_owner: String,
    partner_owner: String,
    support_owner: String,
    trust_network_dir: String,
    release_readiness_profile_file: String,
    release_readiness_package_file: String,
    partner_delivery_manifest_file: String,
    acknowledgement_file: String,
    operator_release_checklist_file: String,
    escalation_manifest_file: String,
    support_handoff_file: String,
    partner_bundle_dir: String,
    proof_package_file: String,
    inquiry_package_file: String,
    inquiry_verification_file: String,
    assurance_suite_package_file: String,
    trust_network_package_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReleaseReadinessDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_delivery_surface: String,
    selected_audiences: Vec<String>,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReleaseReadinessValidationReport {
    workflow_id: String,
    decision: String,
    audiences: Vec<String>,
    delivery_surface: String,
    release_owner: String,
    partner_owner: String,
    support_owner: String,
    same_workflow_boundary: String,
    release_readiness: MercuryReleaseReadinessExportSummary,
    decision_record_file: String,
    docs: MercuryReleaseReadinessDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryControlledAdoptionDocRefs {
    controlled_adoption_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryControlledAdoptionCustomerSuccessChecklist {
    schema: String,
    workflow_id: String,
    customer_success_owner: String,
    reference_owner: String,
    support_owner: String,
    fail_closed: bool,
    readiness_checks: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryControlledAdoptionRenewalManifest {
    schema: String,
    workflow_id: String,
    cohort: String,
    adoption_surface: String,
    success_window: String,
    renewal_signal: String,
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
struct MercuryControlledAdoptionRenewalAcknowledgement {
    schema: String,
    workflow_id: String,
    cohort: String,
    adoption_surface: String,
    customer_success_owner: String,
    status: String,
    acknowledged_at: u64,
    acknowledged_by: String,
    delivered_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryControlledAdoptionReferenceReadinessBrief {
    schema: String,
    workflow_id: String,
    reference_owner: String,
    cohort: String,
    adoption_surface: String,
    approved_claim: String,
    required_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryControlledAdoptionSupportEscalationManifest {
    schema: String,
    workflow_id: String,
    support_owner: String,
    customer_success_owner: String,
    fail_closed: bool,
    escalation_triggers: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryControlledAdoptionExportSummary {
    workflow_id: String,
    cohort: String,
    adoption_surface: String,
    customer_success_owner: String,
    reference_owner: String,
    support_owner: String,
    release_readiness_dir: String,
    controlled_adoption_profile_file: String,
    controlled_adoption_package_file: String,
    customer_success_checklist_file: String,
    renewal_evidence_manifest_file: String,
    renewal_acknowledgement_file: String,
    reference_readiness_brief_file: String,
    support_escalation_manifest_file: String,
    adoption_evidence_dir: String,
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
struct MercuryControlledAdoptionDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_cohort: String,
    selected_adoption_surface: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryControlledAdoptionValidationReport {
    workflow_id: String,
    decision: String,
    cohort: String,
    adoption_surface: String,
    customer_success_owner: String,
    reference_owner: String,
    support_owner: String,
    same_workflow_boundary: String,
    controlled_adoption: MercuryControlledAdoptionExportSummary,
    decision_record_file: String,
    docs: MercuryControlledAdoptionDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReferenceDistributionDocRefs {
    reference_distribution_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReferenceDistributionAccountMotionFreeze {
    schema: String,
    workflow_id: String,
    expansion_motion: String,
    distribution_surface: String,
    landed_account_target: String,
    approved_buyer_path: Vec<String>,
    non_goals: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReferenceDistributionManifest {
    schema: String,
    workflow_id: String,
    expansion_motion: String,
    distribution_surface: String,
    controlled_adoption_package_file: String,
    renewal_evidence_manifest_file: String,
    renewal_acknowledgement_file: String,
    reference_readiness_brief_file: String,
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
struct MercuryReferenceDistributionClaimDisciplineRules {
    schema: String,
    workflow_id: String,
    reference_owner: String,
    buyer_approval_owner: String,
    fail_closed: bool,
    approved_claims: Vec<String>,
    prohibited_claims: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReferenceDistributionBuyerApproval {
    schema: String,
    workflow_id: String,
    buyer_approval_owner: String,
    status: String,
    approved_at: u64,
    approved_by: String,
    approved_claims: Vec<String>,
    required_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReferenceDistributionSalesHandoffBrief {
    schema: String,
    workflow_id: String,
    sales_owner: String,
    reference_owner: String,
    buyer_approval_owner: String,
    expansion_motion: String,
    distribution_surface: String,
    approved_scope: String,
    entry_criteria: Vec<String>,
    escalation_triggers: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReferenceDistributionExportSummary {
    workflow_id: String,
    expansion_motion: String,
    distribution_surface: String,
    reference_owner: String,
    buyer_approval_owner: String,
    sales_owner: String,
    controlled_adoption_dir: String,
    reference_distribution_profile_file: String,
    reference_distribution_package_file: String,
    account_motion_freeze_file: String,
    reference_distribution_manifest_file: String,
    claim_discipline_rules_file: String,
    buyer_reference_approval_file: String,
    sales_handoff_brief_file: String,
    reference_evidence_dir: String,
    controlled_adoption_package_file: String,
    renewal_evidence_manifest_file: String,
    renewal_acknowledgement_file: String,
    reference_readiness_brief_file: String,
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
struct MercuryReferenceDistributionDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_expansion_motion: String,
    selected_distribution_surface: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReferenceDistributionValidationReport {
    workflow_id: String,
    decision: String,
    expansion_motion: String,
    distribution_surface: String,
    reference_owner: String,
    buyer_approval_owner: String,
    sales_owner: String,
    same_workflow_boundary: String,
    reference_distribution: MercuryReferenceDistributionExportSummary,
    decision_record_file: String,
    docs: MercuryReferenceDistributionDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryBroaderDistributionDocRefs {
    broader_distribution_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryBroaderDistributionTargetAccountFreeze {
    schema: String,
    workflow_id: String,
    distribution_motion: String,
    distribution_surface: String,
    target_account_segment: String,
    qualification_gates: Vec<String>,
    non_goals: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryBroaderDistributionManifest {
    schema: String,
    workflow_id: String,
    distribution_motion: String,
    distribution_surface: String,
    reference_distribution_package_file: String,
    account_motion_freeze_file: String,
    reference_distribution_manifest_file: String,
    reference_claim_discipline_file: String,
    reference_buyer_approval_file: String,
    reference_sales_handoff_file: String,
    controlled_adoption_package_file: String,
    renewal_evidence_manifest_file: String,
    renewal_acknowledgement_file: String,
    reference_readiness_brief_file: String,
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
struct MercuryBroaderDistributionClaimGovernanceRules {
    schema: String,
    workflow_id: String,
    qualification_owner: String,
    approval_owner: String,
    fail_closed: bool,
    approved_claims: Vec<String>,
    prohibited_claims: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryBroaderDistributionSelectiveAccountApproval {
    schema: String,
    workflow_id: String,
    approval_owner: String,
    status: String,
    approved_at: u64,
    approved_by: String,
    approved_claims: Vec<String>,
    required_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryBroaderDistributionHandoffBrief {
    schema: String,
    workflow_id: String,
    distribution_owner: String,
    qualification_owner: String,
    approval_owner: String,
    distribution_motion: String,
    distribution_surface: String,
    approved_scope: String,
    entry_criteria: Vec<String>,
    escalation_triggers: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryBroaderDistributionExportSummary {
    workflow_id: String,
    distribution_motion: String,
    distribution_surface: String,
    qualification_owner: String,
    approval_owner: String,
    distribution_owner: String,
    reference_distribution_dir: String,
    broader_distribution_profile_file: String,
    broader_distribution_package_file: String,
    target_account_freeze_file: String,
    broader_distribution_manifest_file: String,
    claim_governance_rules_file: String,
    selective_account_approval_file: String,
    distribution_handoff_brief_file: String,
    qualification_evidence_dir: String,
    reference_distribution_package_file: String,
    account_motion_freeze_file: String,
    reference_distribution_manifest_file: String,
    reference_claim_discipline_file: String,
    reference_buyer_approval_file: String,
    reference_sales_handoff_file: String,
    controlled_adoption_package_file: String,
    renewal_evidence_manifest_file: String,
    renewal_acknowledgement_file: String,
    reference_readiness_brief_file: String,
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
struct MercuryBroaderDistributionDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_distribution_motion: String,
    selected_distribution_surface: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryBroaderDistributionValidationReport {
    workflow_id: String,
    decision: String,
    distribution_motion: String,
    distribution_surface: String,
    qualification_owner: String,
    approval_owner: String,
    distribution_owner: String,
    same_workflow_boundary: String,
    broader_distribution: MercuryBroaderDistributionExportSummary,
    decision_record_file: String,
    docs: MercuryBroaderDistributionDocRefs,
}

impl MercuryPilotRunPaths {
    fn from_export(paths: MercuryExportRunPaths) -> Result<Self, CliError> {
        let bundle_manifest_file =
            paths
                .bundle_manifest_files
                .first()
                .cloned()
                .ok_or_else(|| {
                    CliError::Other("pilot export is missing bundle manifest".to_string())
                })?;
        Ok(Self {
            events_file: paths.input_file,
            receipt_db: paths.receipt_db,
            evidence_dir: paths.evidence_dir,
            bundle_manifest_file,
            proof_package_file: paths.proof_package_file,
            proof_verification_file: paths.proof_verification_file,
            inquiry_package_file: paths.inquiry_package_file,
            inquiry_verification_file: paths.inquiry_verification_file,
        })
    }
}

fn reviewer_doc_refs() -> MercuryQualificationDocRefs {
    MercuryQualificationDocRefs {
        bridge_file: "docs/mercury/SUPERVISED_LIVE_BRIDGE.md".to_string(),
        operating_model_file: "docs/mercury/SUPERVISED_LIVE_OPERATING_MODEL.md".to_string(),
        operations_runbook_file: "docs/mercury/SUPERVISED_LIVE_OPERATIONS_RUNBOOK.md".to_string(),
        qualification_package_file: "docs/mercury/SUPERVISED_LIVE_QUALIFICATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/SUPERVISED_LIVE_DECISION_RECORD.md".to_string(),
    }
}

fn downstream_review_doc_refs() -> MercuryDownstreamReviewDocRefs {
    MercuryDownstreamReviewDocRefs {
        distribution_file: "docs/mercury/DOWNSTREAM_REVIEW_DISTRIBUTION.md".to_string(),
        operations_file: "docs/mercury/DOWNSTREAM_REVIEW_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/DOWNSTREAM_REVIEW_VALIDATION_PACKAGE.md".to_string(),
        decision_record_file: "docs/mercury/DOWNSTREAM_REVIEW_DECISION_RECORD.md".to_string(),
    }
}

fn governance_workbench_doc_refs() -> MercuryGovernanceWorkbenchDocRefs {
    MercuryGovernanceWorkbenchDocRefs {
        workbench_file: "docs/mercury/GOVERNANCE_WORKBENCH.md".to_string(),
        operations_file: "docs/mercury/GOVERNANCE_WORKBENCH_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/GOVERNANCE_WORKBENCH_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/GOVERNANCE_WORKBENCH_DECISION_RECORD.md".to_string(),
    }
}

fn assurance_suite_doc_refs() -> MercuryAssuranceSuiteDocRefs {
    MercuryAssuranceSuiteDocRefs {
        suite_file: "docs/mercury/ASSURANCE_SUITE.md".to_string(),
        operations_file: "docs/mercury/ASSURANCE_SUITE_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/ASSURANCE_SUITE_VALIDATION_PACKAGE.md".to_string(),
        decision_record_file: "docs/mercury/ASSURANCE_SUITE_DECISION_RECORD.md".to_string(),
    }
}

fn embedded_oem_doc_refs() -> MercuryEmbeddedOemDocRefs {
    MercuryEmbeddedOemDocRefs {
        oem_file: "docs/mercury/EMBEDDED_OEM.md".to_string(),
        operations_file: "docs/mercury/EMBEDDED_OEM_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/EMBEDDED_OEM_VALIDATION_PACKAGE.md".to_string(),
        decision_record_file: "docs/mercury/EMBEDDED_OEM_DECISION_RECORD.md".to_string(),
    }
}

fn trust_network_doc_refs() -> MercuryTrustNetworkDocRefs {
    MercuryTrustNetworkDocRefs {
        trust_network_file: "docs/mercury/TRUST_NETWORK.md".to_string(),
        operations_file: "docs/mercury/TRUST_NETWORK_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/TRUST_NETWORK_VALIDATION_PACKAGE.md".to_string(),
        decision_record_file: "docs/mercury/TRUST_NETWORK_DECISION_RECORD.md".to_string(),
    }
}

fn release_readiness_doc_refs() -> MercuryReleaseReadinessDocRefs {
    MercuryReleaseReadinessDocRefs {
        release_readiness_file: "docs/mercury/RELEASE_READINESS.md".to_string(),
        operations_file: "docs/mercury/RELEASE_READINESS_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/RELEASE_READINESS_VALIDATION_PACKAGE.md".to_string(),
        decision_record_file: "docs/mercury/RELEASE_READINESS_DECISION_RECORD.md".to_string(),
    }
}

fn controlled_adoption_doc_refs() -> MercuryControlledAdoptionDocRefs {
    MercuryControlledAdoptionDocRefs {
        controlled_adoption_file: "docs/mercury/CONTROLLED_ADOPTION.md".to_string(),
        operations_file: "docs/mercury/CONTROLLED_ADOPTION_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/CONTROLLED_ADOPTION_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/CONTROLLED_ADOPTION_DECISION_RECORD.md".to_string(),
    }
}

fn reference_distribution_doc_refs() -> MercuryReferenceDistributionDocRefs {
    MercuryReferenceDistributionDocRefs {
        reference_distribution_file: "docs/mercury/REFERENCE_DISTRIBUTION.md".to_string(),
        operations_file: "docs/mercury/REFERENCE_DISTRIBUTION_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/REFERENCE_DISTRIBUTION_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/REFERENCE_DISTRIBUTION_DECISION_RECORD.md".to_string(),
    }
}

fn broader_distribution_doc_refs() -> MercuryBroaderDistributionDocRefs {
    MercuryBroaderDistributionDocRefs {
        broader_distribution_file: "docs/mercury/BROADER_DISTRIBUTION.md".to_string(),
        operations_file: "docs/mercury/BROADER_DISTRIBUTION_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/BROADER_DISTRIBUTION_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/BROADER_DISTRIBUTION_DECISION_RECORD.md".to_string(),
    }
}

fn assurance_suite_population_configs() -> [MercuryAssurancePopulationConfig<'static>; 3] {
    [
        MercuryAssurancePopulationConfig {
            reviewer_population: MercuryAssuranceReviewerPopulation::InternalReview,
            dir_name: "internal-review",
            audience: "internal-review",
            redaction_profile: "internal-review-default",
            retained_artifact_policy: "retain-all-qualified-review-artifacts",
            intended_use:
                "Internal review over the same qualified workflow evidence without lossy redaction.",
            verifier_equivalent: true,
            investigation_focus: &[
                "release approval continuity",
                "rollback readiness and supervisory coverage",
            ],
        },
        MercuryAssurancePopulationConfig {
            reviewer_population: MercuryAssuranceReviewerPopulation::AuditorReview,
            dir_name: "auditor-review",
            audience: "auditor-review",
            redaction_profile: "auditor-review-default",
            retained_artifact_policy: "retain-qualified-audit-artifacts-and-source-links",
            intended_use:
                "Auditor review over the same governed workflow with retained provenance and checkpoint continuity.",
            verifier_equivalent: true,
            investigation_focus: &[
                "checkpoint and retained-artifact continuity",
                "control-state and exception routing evidence",
            ],
        },
        MercuryAssurancePopulationConfig {
            reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview,
            dir_name: "counterparty-review",
            audience: "counterparty-review",
            redaction_profile: "counterparty-review-default",
            retained_artifact_policy: "retain-bounded-redacted-review-artifacts",
            intended_use:
                "Counterparty review over a bounded redacted export without widening into a generic portal.",
            verifier_equivalent: false,
            investigation_focus: &[
                "bounded disclosure and inquiry continuity",
                "release and rollback reconstruction from redacted evidence",
            ],
        },
    ]
}

struct AssurancePackageArgs<'a> {
    workflow_id: &'a str,
    audience: MercuryAssuranceAudience,
    disclosure_profile: &'a str,
    proof_package_file: &'a str,
    inquiry_package_file: &'a str,
    reviewer_package_file: &'a str,
    qualification_report_file: &'a str,
    verifier_equivalent: bool,
}

fn build_assurance_package(args: AssurancePackageArgs<'_>) -> Result<MercuryAssurancePackage, CliError> {
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

struct GovernanceReviewPackageArgs<'a> {
    workflow_id: &'a str,
    audience: MercuryGovernanceReviewAudience,
    disclosure_profile: &'a str,
    proof_package_file: &'a str,
    inquiry_package_file: &'a str,
    reviewer_package_file: &'a str,
    qualification_report_file: &'a str,
    decision_package_file: &'a str,
    verifier_equivalent: bool,
}

fn build_governance_review_package(
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

fn build_assurance_disclosure_profile(
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

struct AssuranceReviewPackageArgs<'a> {
    workflow_id: &'a str,
    reviewer_population: MercuryAssuranceReviewerPopulation,
    disclosure_profile_file: &'a str,
    proof_package_file: &'a str,
    inquiry_package_file: &'a str,
    inquiry_verification_file: &'a str,
    reviewer_package_file: &'a str,
    qualification_report_file: &'a str,
    governance_decision_package_file: &'a str,
    verifier_equivalent: bool,
}

fn build_assurance_review_package(
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

fn collect_assurance_investigation_inputs(
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

fn build_assurance_investigation_package(
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

fn build_embedded_oem_profile(workflow_id: &str) -> Result<MercuryEmbeddedOemProfile, CliError> {
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

fn build_trust_network_profile(workflow_id: &str) -> Result<MercuryTrustNetworkProfile, CliError> {
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

fn build_release_readiness_profile(
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

fn build_controlled_adoption_profile(
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

fn build_reference_distribution_profile(
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

fn build_broader_distribution_profile(
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
