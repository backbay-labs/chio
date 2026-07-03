use super::super::*;

pub(crate) struct PilotInquiryConfig<'a> {
    pub(crate) audience: &'a str,
    pub(crate) redaction_profile: Option<&'a str>,
    pub(crate) verifier_equivalent: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryPilotRunPaths {
    pub(crate) events_file: String,
    pub(crate) receipt_db: String,
    pub(crate) evidence_dir: String,
    pub(crate) bundle_manifest_file: String,
    pub(crate) proof_package_file: String,
    pub(crate) proof_verification_file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) inquiry_package_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) inquiry_verification_file: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryExportRunPaths {
    pub(crate) input_file: String,
    pub(crate) receipt_db: String,
    pub(crate) evidence_dir: String,
    pub(crate) bundle_manifest_files: Vec<String>,
    pub(crate) proof_package_file: String,
    pub(crate) proof_verification_file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) inquiry_package_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) inquiry_verification_file: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryPilotExportSummary {
    pub(crate) scenario_id: String,
    pub(crate) workflow_id: String,
    pub(crate) scenario_file: String,
    pub(crate) primary_receipt_count: usize,
    pub(crate) rollback_receipt_count: usize,
    pub(crate) primary: MercuryPilotRunPaths,
    pub(crate) rollback: MercuryPilotRunPaths,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercurySupervisedLiveExportSummary {
    pub(crate) capture_id: String,
    pub(crate) workflow_id: String,
    pub(crate) mode: String,
    pub(crate) receipt_count: usize,
    pub(crate) control_state: MercurySupervisedLiveControlState,
    pub(crate) export: MercuryExportRunPaths,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercurySupervisedLiveQualificationReport {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) same_workflow_boundary: String,
    pub(crate) supervised_live: MercurySupervisedLiveExportSummary,
    pub(crate) pilot: MercuryPilotExportSummary,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercurySupervisedLiveReviewerPackage {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) qualification_report_file: String,
    pub(crate) supervised_live_dir: String,
    pub(crate) pilot_dir: String,
    pub(crate) supervised_live_proof_package_file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) supervised_live_inquiry_package_file: Option<String>,
    pub(crate) rollback_proof_package_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryDownstreamConsumerManifest {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) consumer_profile: String,
    pub(crate) transport: String,
    pub(crate) acknowledgement_required: bool,
    pub(crate) fail_closed: bool,
    pub(crate) reviewer_package_file: String,
    pub(crate) qualification_report_file: String,
    pub(crate) external_assurance_package_file: String,
    pub(crate) external_inquiry_package_file: String,
    pub(crate) external_inquiry_verification_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryDownstreamDeliveryAcknowledgement {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) consumer_profile: String,
    pub(crate) destination_label: String,
    pub(crate) status: String,
    pub(crate) acknowledged_at: u64,
    pub(crate) acknowledged_by: String,
    pub(crate) delivered_files: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryDownstreamReviewExportSummary {
    pub(crate) workflow_id: String,
    pub(crate) consumer_profile: String,
    pub(crate) transport: String,
    pub(crate) qualification_dir: String,
    pub(crate) internal_assurance_package_file: String,
    pub(crate) external_assurance_package_file: String,
    pub(crate) downstream_review_package_file: String,
    pub(crate) consumer_manifest_file: String,
    pub(crate) acknowledgement_file: String,
    pub(crate) consumer_drop_dir: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryDownstreamReviewDecisionRecord {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) selected_consumer_profile: String,
    pub(crate) approved_scope: String,
    pub(crate) deferred_scope: Vec<String>,
    pub(crate) rationale: String,
    pub(crate) validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryDownstreamReviewValidationReport {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) consumer_profile: String,
    pub(crate) same_workflow_boundary: String,
    pub(crate) downstream_review: MercuryDownstreamReviewExportSummary,
    pub(crate) decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryGovernanceWorkbenchExportSummary {
    pub(crate) workflow_id: String,
    pub(crate) workflow_path: String,
    pub(crate) workflow_owner: String,
    pub(crate) control_team_owner: String,
    pub(crate) qualification_dir: String,
    pub(crate) control_state: MercuryGovernanceControlState,
    pub(crate) control_state_file: String,
    pub(crate) governance_decision_package_file: String,
    pub(crate) workflow_owner_review_package_file: String,
    pub(crate) control_team_review_package_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryGovernanceWorkbenchDecisionRecord {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) selected_workflow_path: String,
    pub(crate) approved_scope: String,
    pub(crate) deferred_scope: Vec<String>,
    pub(crate) rationale: String,
    pub(crate) validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryGovernanceWorkbenchValidationReport {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) workflow_path: String,
    pub(crate) same_workflow_boundary: String,
    pub(crate) governance_workbench: MercuryGovernanceWorkbenchExportSummary,
    pub(crate) decision_record_file: String,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct MercuryAssurancePopulationConfig<'a> {
    pub(crate) reviewer_population: MercuryAssuranceReviewerPopulation,
    pub(crate) dir_name: &'a str,
    pub(crate) audience: &'a str,
    pub(crate) redaction_profile: &'a str,
    pub(crate) retained_artifact_policy: &'a str,
    pub(crate) intended_use: &'a str,
    pub(crate) verifier_equivalent: bool,
    pub(crate) investigation_focus: &'a [&'a str],
}

#[derive(Debug, Clone)]
pub(crate) struct MercuryAssuranceInvestigationInputs {
    pub(crate) account_id: Option<String>,
    pub(crate) desk_id: Option<String>,
    pub(crate) strategy_id: Option<String>,
    pub(crate) event_ids: Vec<String>,
    pub(crate) source_record_ids: Vec<String>,
    pub(crate) idempotency_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryAssuranceSuiteExportSummary {
    pub(crate) workflow_id: String,
    pub(crate) reviewer_owner: String,
    pub(crate) support_owner: String,
    pub(crate) reviewer_populations: Vec<String>,
    pub(crate) qualification_dir: String,
    pub(crate) governance_workbench_dir: String,
    pub(crate) governance_decision_package_file: String,
    pub(crate) assurance_suite_package_file: String,
    pub(crate) internal_review_package_file: String,
    pub(crate) auditor_review_package_file: String,
    pub(crate) counterparty_review_package_file: String,
    pub(crate) internal_investigation_package_file: String,
    pub(crate) auditor_investigation_package_file: String,
    pub(crate) counterparty_investigation_package_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryAssuranceSuiteDecisionRecord {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) selected_reviewer_populations: Vec<String>,
    pub(crate) approved_scope: String,
    pub(crate) deferred_scope: Vec<String>,
    pub(crate) rationale: String,
    pub(crate) validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryAssuranceSuiteValidationReport {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) reviewer_owner: String,
    pub(crate) support_owner: String,
    pub(crate) same_workflow_boundary: String,
    pub(crate) assurance_suite: MercuryAssuranceSuiteExportSummary,
    pub(crate) decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryEmbeddedPartnerManifest {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) partner_surface: String,
    pub(crate) sdk_surface: String,
    pub(crate) reviewer_population: String,
    pub(crate) fail_closed: bool,
    pub(crate) acknowledgement_required: bool,
    pub(crate) profile_file: String,
    pub(crate) assurance_suite_package_file: String,
    pub(crate) governance_decision_package_file: String,
    pub(crate) disclosure_profile_file: String,
    pub(crate) review_package_file: String,
    pub(crate) investigation_package_file: String,
    pub(crate) reviewer_package_file: String,
    pub(crate) qualification_report_file: String,
    pub(crate) support_owner: String,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryEmbeddedDeliveryAcknowledgement {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) partner_surface: String,
    pub(crate) partner_owner: String,
    pub(crate) status: String,
    pub(crate) acknowledged_at: u64,
    pub(crate) acknowledged_by: String,
    pub(crate) delivered_files: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryEmbeddedOemExportSummary {
    pub(crate) workflow_id: String,
    pub(crate) partner_surface: String,
    pub(crate) sdk_surface: String,
    pub(crate) reviewer_population: String,
    pub(crate) partner_owner: String,
    pub(crate) support_owner: String,
    pub(crate) assurance_suite_dir: String,
    pub(crate) embedded_oem_profile_file: String,
    pub(crate) embedded_oem_package_file: String,
    pub(crate) partner_sdk_manifest_file: String,
    pub(crate) assurance_suite_package_file: String,
    pub(crate) governance_decision_package_file: String,
    pub(crate) disclosure_profile_file: String,
    pub(crate) review_package_file: String,
    pub(crate) investigation_package_file: String,
    pub(crate) reviewer_package_file: String,
    pub(crate) qualification_report_file: String,
    pub(crate) acknowledgement_file: String,
    pub(crate) partner_sdk_bundle_dir: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryEmbeddedOemDecisionRecord {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) selected_partner_surface: String,
    pub(crate) selected_sdk_surface: String,
    pub(crate) selected_reviewer_population: String,
    pub(crate) approved_scope: String,
    pub(crate) deferred_scope: Vec<String>,
    pub(crate) rationale: String,
    pub(crate) validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryEmbeddedOemValidationReport {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) partner_surface: String,
    pub(crate) sdk_surface: String,
    pub(crate) reviewer_population: String,
    pub(crate) partner_owner: String,
    pub(crate) support_owner: String,
    pub(crate) same_workflow_boundary: String,
    pub(crate) embedded_oem: MercuryEmbeddedOemExportSummary,
    pub(crate) decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryTrustNetworkInteroperabilityManifest {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) sponsor_boundary: String,
    pub(crate) trust_anchor: String,
    pub(crate) interop_surface: String,
    pub(crate) reviewer_population: String,
    pub(crate) fail_closed: bool,
    pub(crate) profile_file: String,
    pub(crate) shared_proof_package_file: String,
    pub(crate) shared_review_package_file: String,
    pub(crate) shared_inquiry_package_file: String,
    pub(crate) shared_inquiry_verification_file: String,
    pub(crate) reviewer_package_file: String,
    pub(crate) qualification_report_file: String,
    pub(crate) witness_record_file: String,
    pub(crate) trust_anchor_record_file: String,
    pub(crate) support_owner: String,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryTrustNetworkWitnessRecord {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) sponsor_boundary: String,
    pub(crate) trust_anchor: String,
    pub(crate) checkpoint_continuity: String,
    pub(crate) witness_steps: Vec<String>,
    pub(crate) witness_operator: String,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryTrustAnchorRecord {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) trust_anchor: String,
    pub(crate) anchor_scope: String,
    pub(crate) verification_material: String,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryTrustNetworkExportSummary {
    pub(crate) workflow_id: String,
    pub(crate) sponsor_boundary: String,
    pub(crate) trust_anchor: String,
    pub(crate) interop_surface: String,
    pub(crate) reviewer_population: String,
    pub(crate) sponsor_owner: String,
    pub(crate) support_owner: String,
    pub(crate) embedded_oem_dir: String,
    pub(crate) trust_network_profile_file: String,
    pub(crate) trust_network_package_file: String,
    pub(crate) interop_manifest_file: String,
    pub(crate) shared_proof_package_file: String,
    pub(crate) shared_review_package_file: String,
    pub(crate) shared_inquiry_package_file: String,
    pub(crate) shared_inquiry_verification_file: String,
    pub(crate) reviewer_package_file: String,
    pub(crate) qualification_report_file: String,
    pub(crate) witness_record_file: String,
    pub(crate) trust_anchor_record_file: String,
    pub(crate) share_dir: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryTrustNetworkDecisionRecord {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) selected_sponsor_boundary: String,
    pub(crate) selected_trust_anchor: String,
    pub(crate) selected_interop_surface: String,
    pub(crate) selected_reviewer_population: String,
    pub(crate) approved_scope: String,
    pub(crate) deferred_scope: Vec<String>,
    pub(crate) rationale: String,
    pub(crate) validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryTrustNetworkValidationReport {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) sponsor_boundary: String,
    pub(crate) trust_anchor: String,
    pub(crate) interop_surface: String,
    pub(crate) reviewer_population: String,
    pub(crate) sponsor_owner: String,
    pub(crate) support_owner: String,
    pub(crate) same_workflow_boundary: String,
    pub(crate) trust_network: MercuryTrustNetworkExportSummary,
    pub(crate) decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryReleaseReadinessPartnerManifest {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) delivery_surface: String,
    pub(crate) reviewer_population: String,
    pub(crate) acknowledgement_required: bool,
    pub(crate) fail_closed: bool,
    pub(crate) proof_package_file: String,
    pub(crate) inquiry_package_file: String,
    pub(crate) inquiry_verification_file: String,
    pub(crate) assurance_suite_package_file: String,
    pub(crate) trust_network_package_file: String,
    pub(crate) reviewer_package_file: String,
    pub(crate) qualification_report_file: String,
    pub(crate) operator_release_checklist_file: String,
    pub(crate) escalation_manifest_file: String,
    pub(crate) support_handoff_file: String,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryReleaseReadinessDeliveryAcknowledgement {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) delivery_surface: String,
    pub(crate) partner_owner: String,
    pub(crate) status: String,
    pub(crate) acknowledged_at: u64,
    pub(crate) acknowledged_by: String,
    pub(crate) delivered_files: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryReleaseReadinessOperatorChecklist {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) release_owner: String,
    pub(crate) partner_owner: String,
    pub(crate) support_owner: String,
    pub(crate) fail_closed: bool,
    pub(crate) gating_checks: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryReleaseReadinessEscalationManifest {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) release_owner: String,
    pub(crate) support_owner: String,
    pub(crate) fail_closed: bool,
    pub(crate) escalation_triggers: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryReleaseReadinessSupportHandoff {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) release_owner: String,
    pub(crate) support_owner: String,
    pub(crate) active_window: String,
    pub(crate) required_files: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryReleaseReadinessExportSummary {
    pub(crate) workflow_id: String,
    pub(crate) audiences: Vec<String>,
    pub(crate) delivery_surface: String,
    pub(crate) release_owner: String,
    pub(crate) partner_owner: String,
    pub(crate) support_owner: String,
    pub(crate) trust_network_dir: String,
    pub(crate) release_readiness_profile_file: String,
    pub(crate) release_readiness_package_file: String,
    pub(crate) partner_delivery_manifest_file: String,
    pub(crate) acknowledgement_file: String,
    pub(crate) operator_release_checklist_file: String,
    pub(crate) escalation_manifest_file: String,
    pub(crate) support_handoff_file: String,
    pub(crate) partner_bundle_dir: String,
    pub(crate) proof_package_file: String,
    pub(crate) inquiry_package_file: String,
    pub(crate) inquiry_verification_file: String,
    pub(crate) assurance_suite_package_file: String,
    pub(crate) trust_network_package_file: String,
    pub(crate) reviewer_package_file: String,
    pub(crate) qualification_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryReleaseReadinessDecisionRecord {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) selected_delivery_surface: String,
    pub(crate) selected_audiences: Vec<String>,
    pub(crate) approved_scope: String,
    pub(crate) deferred_scope: Vec<String>,
    pub(crate) rationale: String,
    pub(crate) validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryReleaseReadinessValidationReport {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) audiences: Vec<String>,
    pub(crate) delivery_surface: String,
    pub(crate) release_owner: String,
    pub(crate) partner_owner: String,
    pub(crate) support_owner: String,
    pub(crate) same_workflow_boundary: String,
    pub(crate) release_readiness: MercuryReleaseReadinessExportSummary,
    pub(crate) decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryControlledAdoptionCustomerSuccessChecklist {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) customer_success_owner: String,
    pub(crate) reference_owner: String,
    pub(crate) support_owner: String,
    pub(crate) fail_closed: bool,
    pub(crate) readiness_checks: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryControlledAdoptionRenewalManifest {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) cohort: String,
    pub(crate) adoption_surface: String,
    pub(crate) success_window: String,
    pub(crate) renewal_signal: String,
    pub(crate) release_readiness_package_file: String,
    pub(crate) trust_network_package_file: String,
    pub(crate) assurance_suite_package_file: String,
    pub(crate) proof_package_file: String,
    pub(crate) inquiry_package_file: String,
    pub(crate) inquiry_verification_file: String,
    pub(crate) reviewer_package_file: String,
    pub(crate) qualification_report_file: String,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryControlledAdoptionRenewalAcknowledgement {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) cohort: String,
    pub(crate) adoption_surface: String,
    pub(crate) customer_success_owner: String,
    pub(crate) status: String,
    pub(crate) acknowledged_at: u64,
    pub(crate) acknowledged_by: String,
    pub(crate) delivered_files: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryControlledAdoptionReferenceReadinessBrief {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) reference_owner: String,
    pub(crate) cohort: String,
    pub(crate) adoption_surface: String,
    pub(crate) approved_claim: String,
    pub(crate) required_files: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryControlledAdoptionSupportEscalationManifest {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) support_owner: String,
    pub(crate) customer_success_owner: String,
    pub(crate) fail_closed: bool,
    pub(crate) escalation_triggers: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryControlledAdoptionExportSummary {
    pub(crate) workflow_id: String,
    pub(crate) cohort: String,
    pub(crate) adoption_surface: String,
    pub(crate) customer_success_owner: String,
    pub(crate) reference_owner: String,
    pub(crate) support_owner: String,
    pub(crate) release_readiness_dir: String,
    pub(crate) controlled_adoption_profile_file: String,
    pub(crate) controlled_adoption_package_file: String,
    pub(crate) customer_success_checklist_file: String,
    pub(crate) renewal_evidence_manifest_file: String,
    pub(crate) renewal_acknowledgement_file: String,
    pub(crate) reference_readiness_brief_file: String,
    pub(crate) support_escalation_manifest_file: String,
    pub(crate) adoption_evidence_dir: String,
    pub(crate) release_readiness_package_file: String,
    pub(crate) trust_network_package_file: String,
    pub(crate) assurance_suite_package_file: String,
    pub(crate) proof_package_file: String,
    pub(crate) inquiry_package_file: String,
    pub(crate) inquiry_verification_file: String,
    pub(crate) reviewer_package_file: String,
    pub(crate) qualification_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryControlledAdoptionDecisionRecord {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) selected_cohort: String,
    pub(crate) selected_adoption_surface: String,
    pub(crate) approved_scope: String,
    pub(crate) deferred_scope: Vec<String>,
    pub(crate) rationale: String,
    pub(crate) validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryControlledAdoptionValidationReport {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) cohort: String,
    pub(crate) adoption_surface: String,
    pub(crate) customer_success_owner: String,
    pub(crate) reference_owner: String,
    pub(crate) support_owner: String,
    pub(crate) same_workflow_boundary: String,
    pub(crate) controlled_adoption: MercuryControlledAdoptionExportSummary,
    pub(crate) decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryReferenceDistributionAccountMotionFreeze {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) expansion_motion: String,
    pub(crate) distribution_surface: String,
    pub(crate) landed_account_target: String,
    pub(crate) approved_buyer_path: Vec<String>,
    pub(crate) non_goals: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryReferenceDistributionManifest {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) expansion_motion: String,
    pub(crate) distribution_surface: String,
    pub(crate) controlled_adoption_package_file: String,
    pub(crate) renewal_evidence_manifest_file: String,
    pub(crate) renewal_acknowledgement_file: String,
    pub(crate) reference_readiness_brief_file: String,
    pub(crate) release_readiness_package_file: String,
    pub(crate) trust_network_package_file: String,
    pub(crate) assurance_suite_package_file: String,
    pub(crate) proof_package_file: String,
    pub(crate) inquiry_package_file: String,
    pub(crate) inquiry_verification_file: String,
    pub(crate) reviewer_package_file: String,
    pub(crate) qualification_report_file: String,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryReferenceDistributionClaimDisciplineRules {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) reference_owner: String,
    pub(crate) buyer_approval_owner: String,
    pub(crate) fail_closed: bool,
    pub(crate) approved_claims: Vec<String>,
    pub(crate) prohibited_claims: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryReferenceDistributionBuyerApproval {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) buyer_approval_owner: String,
    pub(crate) status: String,
    pub(crate) approved_at: u64,
    pub(crate) approved_by: String,
    pub(crate) approved_claims: Vec<String>,
    pub(crate) required_files: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryReferenceDistributionSalesHandoffBrief {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) sales_owner: String,
    pub(crate) reference_owner: String,
    pub(crate) buyer_approval_owner: String,
    pub(crate) expansion_motion: String,
    pub(crate) distribution_surface: String,
    pub(crate) approved_scope: String,
    pub(crate) entry_criteria: Vec<String>,
    pub(crate) escalation_triggers: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryReferenceDistributionExportSummary {
    pub(crate) workflow_id: String,
    pub(crate) expansion_motion: String,
    pub(crate) distribution_surface: String,
    pub(crate) reference_owner: String,
    pub(crate) buyer_approval_owner: String,
    pub(crate) sales_owner: String,
    pub(crate) controlled_adoption_dir: String,
    pub(crate) reference_distribution_profile_file: String,
    pub(crate) reference_distribution_package_file: String,
    pub(crate) account_motion_freeze_file: String,
    pub(crate) reference_distribution_manifest_file: String,
    pub(crate) claim_discipline_rules_file: String,
    pub(crate) buyer_reference_approval_file: String,
    pub(crate) sales_handoff_brief_file: String,
    pub(crate) reference_evidence_dir: String,
    pub(crate) controlled_adoption_package_file: String,
    pub(crate) renewal_evidence_manifest_file: String,
    pub(crate) renewal_acknowledgement_file: String,
    pub(crate) reference_readiness_brief_file: String,
    pub(crate) release_readiness_package_file: String,
    pub(crate) trust_network_package_file: String,
    pub(crate) assurance_suite_package_file: String,
    pub(crate) proof_package_file: String,
    pub(crate) inquiry_package_file: String,
    pub(crate) inquiry_verification_file: String,
    pub(crate) reviewer_package_file: String,
    pub(crate) qualification_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryReferenceDistributionDecisionRecord {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) selected_expansion_motion: String,
    pub(crate) selected_distribution_surface: String,
    pub(crate) approved_scope: String,
    pub(crate) deferred_scope: Vec<String>,
    pub(crate) rationale: String,
    pub(crate) validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryReferenceDistributionValidationReport {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) expansion_motion: String,
    pub(crate) distribution_surface: String,
    pub(crate) reference_owner: String,
    pub(crate) buyer_approval_owner: String,
    pub(crate) sales_owner: String,
    pub(crate) same_workflow_boundary: String,
    pub(crate) reference_distribution: MercuryReferenceDistributionExportSummary,
    pub(crate) decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryBroaderDistributionTargetAccountFreeze {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) distribution_motion: String,
    pub(crate) distribution_surface: String,
    pub(crate) target_account_segment: String,
    pub(crate) qualification_gates: Vec<String>,
    pub(crate) non_goals: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryBroaderDistributionManifest {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) distribution_motion: String,
    pub(crate) distribution_surface: String,
    pub(crate) reference_distribution_package_file: String,
    pub(crate) account_motion_freeze_file: String,
    pub(crate) reference_distribution_manifest_file: String,
    pub(crate) reference_claim_discipline_file: String,
    pub(crate) reference_buyer_approval_file: String,
    pub(crate) reference_sales_handoff_file: String,
    pub(crate) controlled_adoption_package_file: String,
    pub(crate) renewal_evidence_manifest_file: String,
    pub(crate) renewal_acknowledgement_file: String,
    pub(crate) reference_readiness_brief_file: String,
    pub(crate) release_readiness_package_file: String,
    pub(crate) trust_network_package_file: String,
    pub(crate) assurance_suite_package_file: String,
    pub(crate) proof_package_file: String,
    pub(crate) inquiry_package_file: String,
    pub(crate) inquiry_verification_file: String,
    pub(crate) reviewer_package_file: String,
    pub(crate) qualification_report_file: String,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryBroaderDistributionClaimGovernanceRules {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) qualification_owner: String,
    pub(crate) approval_owner: String,
    pub(crate) fail_closed: bool,
    pub(crate) approved_claims: Vec<String>,
    pub(crate) prohibited_claims: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryBroaderDistributionSelectiveAccountApproval {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) approval_owner: String,
    pub(crate) status: String,
    pub(crate) approved_at: u64,
    pub(crate) approved_by: String,
    pub(crate) approved_claims: Vec<String>,
    pub(crate) required_files: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryBroaderDistributionHandoffBrief {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) distribution_owner: String,
    pub(crate) qualification_owner: String,
    pub(crate) approval_owner: String,
    pub(crate) distribution_motion: String,
    pub(crate) distribution_surface: String,
    pub(crate) approved_scope: String,
    pub(crate) entry_criteria: Vec<String>,
    pub(crate) escalation_triggers: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryBroaderDistributionExportSummary {
    pub(crate) workflow_id: String,
    pub(crate) distribution_motion: String,
    pub(crate) distribution_surface: String,
    pub(crate) qualification_owner: String,
    pub(crate) approval_owner: String,
    pub(crate) distribution_owner: String,
    pub(crate) reference_distribution_dir: String,
    pub(crate) broader_distribution_profile_file: String,
    pub(crate) broader_distribution_package_file: String,
    pub(crate) target_account_freeze_file: String,
    pub(crate) broader_distribution_manifest_file: String,
    pub(crate) claim_governance_rules_file: String,
    pub(crate) selective_account_approval_file: String,
    pub(crate) distribution_handoff_brief_file: String,
    pub(crate) qualification_evidence_dir: String,
    pub(crate) reference_distribution_package_file: String,
    pub(crate) account_motion_freeze_file: String,
    pub(crate) reference_distribution_manifest_file: String,
    pub(crate) reference_claim_discipline_file: String,
    pub(crate) reference_buyer_approval_file: String,
    pub(crate) reference_sales_handoff_file: String,
    pub(crate) controlled_adoption_package_file: String,
    pub(crate) renewal_evidence_manifest_file: String,
    pub(crate) renewal_acknowledgement_file: String,
    pub(crate) reference_readiness_brief_file: String,
    pub(crate) release_readiness_package_file: String,
    pub(crate) trust_network_package_file: String,
    pub(crate) assurance_suite_package_file: String,
    pub(crate) proof_package_file: String,
    pub(crate) inquiry_package_file: String,
    pub(crate) inquiry_verification_file: String,
    pub(crate) reviewer_package_file: String,
    pub(crate) qualification_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryBroaderDistributionDecisionRecord {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) selected_distribution_motion: String,
    pub(crate) selected_distribution_surface: String,
    pub(crate) approved_scope: String,
    pub(crate) deferred_scope: Vec<String>,
    pub(crate) rationale: String,
    pub(crate) validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryBroaderDistributionValidationReport {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) distribution_motion: String,
    pub(crate) distribution_surface: String,
    pub(crate) qualification_owner: String,
    pub(crate) approval_owner: String,
    pub(crate) distribution_owner: String,
    pub(crate) same_workflow_boundary: String,
    pub(crate) broader_distribution: MercuryBroaderDistributionExportSummary,
    pub(crate) decision_record_file: String,
}

impl MercuryPilotRunPaths {
    pub(crate) fn from_export(paths: MercuryExportRunPaths) -> Result<Self, CliError> {
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
