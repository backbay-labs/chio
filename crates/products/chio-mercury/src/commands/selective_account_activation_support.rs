use super::*;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MercurySelectiveAccountActivationScopeFreeze {
    pub(super) schema: String,
    pub(super) workflow_id: String,
    pub(super) activation_motion: String,
    pub(super) delivery_surface: String,
    pub(super) target_account_label: String,
    pub(super) entry_gates: Vec<String>,
    pub(super) non_goals: Vec<String>,
    pub(super) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MercurySelectiveAccountActivationManifest {
    pub(super) schema: String,
    pub(super) workflow_id: String,
    pub(super) activation_motion: String,
    pub(super) delivery_surface: String,
    pub(super) broader_distribution_package_file: String,
    pub(super) target_account_freeze_file: String,
    pub(super) broader_distribution_manifest_file: String,
    pub(super) claim_governance_rules_file: String,
    pub(super) selective_account_approval_file: String,
    pub(super) distribution_handoff_brief_file: String,
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
    pub(super) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MercurySelectiveAccountActivationClaimContainmentRules {
    pub(super) schema: String,
    pub(super) workflow_id: String,
    pub(super) activation_owner: String,
    pub(super) approval_owner: String,
    pub(super) fail_closed: bool,
    pub(super) approved_claims: Vec<String>,
    pub(super) prohibited_claims: Vec<String>,
    pub(super) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MercurySelectiveAccountActivationApprovalRefresh {
    pub(super) schema: String,
    pub(super) workflow_id: String,
    pub(super) approval_owner: String,
    pub(super) status: String,
    pub(super) refreshed_at: u64,
    pub(super) refreshed_by: String,
    pub(super) approved_claims: Vec<String>,
    pub(super) required_files: Vec<String>,
    pub(super) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MercurySelectiveAccountActivationCustomerHandoffBrief {
    pub(super) schema: String,
    pub(super) workflow_id: String,
    pub(super) delivery_owner: String,
    pub(super) activation_owner: String,
    pub(super) approval_owner: String,
    pub(super) activation_motion: String,
    pub(super) delivery_surface: String,
    pub(super) approved_scope: String,
    pub(super) entry_criteria: Vec<String>,
    pub(super) escalation_triggers: Vec<String>,
    pub(super) note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MercurySelectiveAccountActivationExportSummary {
    pub(super) workflow_id: String,
    pub(super) activation_motion: String,
    pub(super) delivery_surface: String,
    pub(super) activation_owner: String,
    pub(super) approval_owner: String,
    pub(super) delivery_owner: String,
    pub(super) broader_distribution_dir: String,
    pub(super) selective_account_activation_profile_file: String,
    pub(super) selective_account_activation_package_file: String,
    pub(super) activation_scope_freeze_file: String,
    pub(super) selective_account_activation_manifest_file: String,
    pub(super) claim_containment_rules_file: String,
    pub(super) activation_approval_refresh_file: String,
    pub(super) customer_handoff_brief_file: String,
    pub(super) activation_evidence_dir: String,
    pub(super) broader_distribution_package_file: String,
    pub(super) target_account_freeze_file: String,
    pub(super) broader_distribution_manifest_file: String,
    pub(super) claim_governance_rules_file: String,
    pub(super) selective_account_approval_file: String,
    pub(super) distribution_handoff_brief_file: String,
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
pub(super) struct MercurySelectiveAccountActivationDecisionRecord {
    pub(super) workflow_id: String,
    pub(super) decision: String,
    pub(super) selected_activation_motion: String,
    pub(super) selected_delivery_surface: String,
    pub(super) approved_scope: String,
    pub(super) deferred_scope: Vec<String>,
    pub(super) rationale: String,
    pub(super) validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MercurySelectiveAccountActivationValidationReport {
    pub(super) workflow_id: String,
    pub(super) decision: String,
    pub(super) activation_motion: String,
    pub(super) delivery_surface: String,
    pub(super) activation_owner: String,
    pub(super) approval_owner: String,
    pub(super) delivery_owner: String,
    pub(super) same_workflow_boundary: String,
    pub(super) selective_account_activation: MercurySelectiveAccountActivationExportSummary,
    pub(super) decision_record_file: String,
}

pub(super) fn build_selective_account_activation_profile(
    workflow_id: &str,
) -> Result<MercurySelectiveAccountActivationProfile, CliError> {
    let profile = MercurySelectiveAccountActivationProfile {
        schema: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "selective-account-activation-controlled-delivery-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        activation_motion: MercurySelectiveAccountActivationMotion::SelectiveAccountActivation,
        delivery_surface: MercurySelectiveAccountActivationSurface::ControlledDeliveryBundle,
        claim_containment: "controlled-delivery-evidence-only".to_string(),
        retained_artifact_policy:
            "retain-bounded-selective-account-activation-and-controlled-delivery-artifacts"
                .to_string(),
        intended_use: "Activate one bounded Mercury selective-account lane over the validated broader-distribution package without widening into generic onboarding tooling, CRM workflows, channel marketplaces, merged shells, or Chio commercial surfaces."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}
