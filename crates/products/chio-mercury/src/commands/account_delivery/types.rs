use super::*;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryDeliveryContinuityAccountBoundaryFreeze {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) continuity_motion: String,
    pub(crate) continuity_surface: String,
    pub(crate) account_boundary_label: String,
    pub(crate) entry_gates: Vec<String>,
    pub(crate) non_goals: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryDeliveryContinuityManifest {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) continuity_motion: String,
    pub(crate) continuity_surface: String,
    pub(crate) selective_account_activation_package_file: String,
    pub(crate) activation_scope_freeze_file: String,
    pub(crate) selective_account_activation_manifest_file: String,
    pub(crate) claim_containment_rules_file: String,
    pub(crate) activation_approval_refresh_file: String,
    pub(crate) customer_handoff_brief_file: String,
    pub(crate) broader_distribution_package_file: String,
    pub(crate) broader_distribution_manifest_file: String,
    pub(crate) target_account_freeze_file: String,
    pub(crate) claim_governance_rules_file: String,
    pub(crate) selective_account_approval_file: String,
    pub(crate) reference_distribution_package_file: String,
    pub(crate) controlled_adoption_package_file: String,
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
pub(crate) struct MercuryDeliveryContinuityOutcomeEvidenceSummary {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) continuity_owner: String,
    pub(crate) renewal_owner: String,
    pub(crate) evidence_owner: String,
    pub(crate) continuity_motion: String,
    pub(crate) continuity_surface: String,
    pub(crate) supported_claims: Vec<String>,
    pub(crate) evidence_files: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryDeliveryContinuityRenewalGate {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) renewal_owner: String,
    pub(crate) status: String,
    pub(crate) reviewed_at: u64,
    pub(crate) reviewed_by: String,
    pub(crate) approved_claims: Vec<String>,
    pub(crate) required_files: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryDeliveryContinuityDeliveryEscalationBrief {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) continuity_owner: String,
    pub(crate) evidence_owner: String,
    pub(crate) renewal_owner: String,
    pub(crate) continuity_motion: String,
    pub(crate) continuity_surface: String,
    pub(crate) service_boundary: String,
    pub(crate) escalation_triggers: Vec<String>,
    pub(crate) immediate_actions: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryDeliveryContinuityCustomerEvidenceHandoff {
    pub(crate) schema: String,
    pub(crate) workflow_id: String,
    pub(crate) evidence_owner: String,
    pub(crate) continuity_owner: String,
    pub(crate) renewal_owner: String,
    pub(crate) continuity_motion: String,
    pub(crate) continuity_surface: String,
    pub(crate) approved_scope: String,
    pub(crate) required_evidence: Vec<String>,
    pub(crate) deferred_requests: Vec<String>,
    pub(crate) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryDeliveryContinuityExportSummary {
    pub(crate) workflow_id: String,
    pub(crate) continuity_motion: String,
    pub(crate) continuity_surface: String,
    pub(crate) continuity_owner: String,
    pub(crate) renewal_owner: String,
    pub(crate) evidence_owner: String,
    pub(crate) selective_account_activation_dir: String,
    pub(crate) delivery_continuity_profile_file: String,
    pub(crate) delivery_continuity_package_file: String,
    pub(crate) account_boundary_freeze_file: String,
    pub(crate) delivery_continuity_manifest_file: String,
    pub(crate) outcome_evidence_summary_file: String,
    pub(crate) renewal_gate_file: String,
    pub(crate) delivery_escalation_brief_file: String,
    pub(crate) customer_evidence_handoff_file: String,
    pub(crate) continuity_evidence_dir: String,
    pub(crate) selective_account_activation_package_file: String,
    pub(crate) activation_scope_freeze_file: String,
    pub(crate) selective_account_activation_manifest_file: String,
    pub(crate) claim_containment_rules_file: String,
    pub(crate) activation_approval_refresh_file: String,
    pub(crate) customer_handoff_brief_file: String,
    pub(crate) broader_distribution_package_file: String,
    pub(crate) broader_distribution_manifest_file: String,
    pub(crate) target_account_freeze_file: String,
    pub(crate) claim_governance_rules_file: String,
    pub(crate) selective_account_approval_file: String,
    pub(crate) reference_distribution_package_file: String,
    pub(crate) controlled_adoption_package_file: String,
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
pub(crate) struct MercuryDeliveryContinuityDecisionRecord {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) selected_continuity_motion: String,
    pub(crate) selected_continuity_surface: String,
    pub(crate) approved_scope: String,
    pub(crate) deferred_scope: Vec<String>,
    pub(crate) rationale: String,
    pub(crate) validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MercuryDeliveryContinuityValidationReport {
    pub(crate) workflow_id: String,
    pub(crate) decision: String,
    pub(crate) continuity_motion: String,
    pub(crate) continuity_surface: String,
    pub(crate) continuity_owner: String,
    pub(crate) renewal_owner: String,
    pub(crate) evidence_owner: String,
    pub(crate) same_workflow_boundary: String,
    pub(crate) delivery_continuity: MercuryDeliveryContinuityExportSummary,
    pub(crate) decision_record_file: String,
}
