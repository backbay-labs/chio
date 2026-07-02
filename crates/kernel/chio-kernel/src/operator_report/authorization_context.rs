use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GovernedAuthorizationCommerceDetail {
    pub seller: String,
    pub shared_payment_token_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GovernedAuthorizationMeteredBillingDetail {
    pub settlement_mode: MeteredSettlementMode,
    pub provider: String,
    pub quote_id: String,
    pub billing_unit: String,
    pub quoted_units: u64,
    pub quoted_cost: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_billed_units: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GovernedAuthorizationDetail {
    #[serde(rename = "type")]
    pub detail_type: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commerce: Option<GovernedAuthorizationCommerceDetail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metered_billing: Option<GovernedAuthorizationMeteredBillingDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GovernedAuthorizationTransactionContext {
    pub intent_id: String,
    pub intent_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_token_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_approved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance_tier: Option<RuntimeAssuranceTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance_schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance_verifier_family: Option<AttestationVerifierFamily>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance_verifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance_evidence_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_chain: Option<GovernedCallChainProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_assertion: Option<ChioIdentityAssertion>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GovernedTransactionDiagnostics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asserted_call_chain: Option<GovernedCallChainProvenance>,
    #[serde(default, skip_serializing_if = "EvidenceLineageReferences::is_empty")]
    pub lineage_references: EvidenceLineageReferences,
}

impl GovernedTransactionDiagnostics {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.asserted_call_chain.is_none() && self.lineage_references.is_empty()
    }
}

fn default_authorization_context_report_schema() -> String {
    CHIO_OAUTH_AUTHORIZATION_CONTEXT_REPORT_SCHEMA.to_string()
}

fn default_chio_oauth_authorization_profile() -> ChioOAuthAuthorizationProfile {
    ChioOAuthAuthorizationProfile::default()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthAuthorizationProfile {
    pub schema: String,
    pub id: String,
    pub authoritative_source: String,
    pub authorization_detail_types: Vec<String>,
    pub transaction_context_fields: Vec<String>,
    #[serde(default)]
    pub portable_claim_catalog: ChioPortableClaimCatalog,
    #[serde(default)]
    pub portable_identity_binding: ChioPortableIdentityBinding,
    #[serde(default)]
    pub governed_auth_binding: ChioGovernedAuthorizationBinding,
    #[serde(default)]
    pub request_time_contract: ChioOAuthRequestTimeContract,
    #[serde(default)]
    pub resource_binding: ChioOAuthResourceBinding,
    #[serde(default)]
    pub artifact_boundary: ChioOAuthArtifactBoundary,
    pub sender_constraints: ChioOAuthSenderConstraintProfile,
    pub unsupported_shapes_fail_closed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthRequestTimeContract {
    pub authorization_details_parameter: String,
    pub transaction_context_parameter: String,
    pub access_token_authorization_details_claim: String,
    pub access_token_transaction_context_claim: String,
    pub request_time_authorization_details_supported: bool,
    pub request_time_transaction_context_supported: bool,
    pub governed_receipts_authoritative_post_execution: bool,
}

impl Default for ChioOAuthRequestTimeContract {
    fn default() -> Self {
        Self {
            authorization_details_parameter:
                CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_PARAMETER.to_string(),
            transaction_context_parameter: CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_PARAMETER
                .to_string(),
            access_token_authorization_details_claim:
                CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_CLAIM.to_string(),
            access_token_transaction_context_claim:
                CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_CLAIM.to_string(),
            request_time_authorization_details_supported: true,
            request_time_transaction_context_supported: true,
            governed_receipts_authoritative_post_execution: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthResourceBinding {
    pub protected_resource_field: String,
    pub request_resource_parameter: String,
    pub access_token_audience_claim: String,
    pub access_token_resource_claim: String,
    pub request_resource_must_match_protected_resource: bool,
    pub bearer_token_must_include_audience_or_resource: bool,
}

impl Default for ChioOAuthResourceBinding {
    fn default() -> Self {
        Self {
            protected_resource_field: "resource".to_string(),
            request_resource_parameter: "resource".to_string(),
            access_token_audience_claim: "aud".to_string(),
            access_token_resource_claim: "resource".to_string(),
            request_resource_must_match_protected_resource: true,
            bearer_token_must_include_audience_or_resource: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthArtifactBoundary {
    pub access_tokens_runtime_admission_supported: bool,
    pub approval_tokens_runtime_admission_supported: bool,
    pub capabilities_runtime_admission_supported: bool,
    pub reviewer_evidence_runtime_admission_supported: bool,
    pub governed_receipts_audit_evidence_supported: bool,
}

impl Default for ChioOAuthArtifactBoundary {
    fn default() -> Self {
        Self {
            access_tokens_runtime_admission_supported: true,
            approval_tokens_runtime_admission_supported: false,
            capabilities_runtime_admission_supported: false,
            reviewer_evidence_runtime_admission_supported: false,
            governed_receipts_audit_evidence_supported: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthSenderConstraintProfile {
    pub schema: String,
    pub subject_binding: String,
    pub proof_types_supported: Vec<String>,
    pub proof_required_when: String,
    pub runtime_assurance_binding_fields: Vec<String>,
    pub delegated_call_chain_field: String,
    pub unsupported_sender_shapes_fail_closed: bool,
}

impl Default for ChioOAuthSenderConstraintProfile {
    fn default() -> Self {
        Self {
            schema: CHIO_OAUTH_SENDER_CONSTRAINT_SCHEMA.to_string(),
            subject_binding: CHIO_OAUTH_SENDER_BINDING_CAPABILITY_SUBJECT.to_string(),
            proof_types_supported: vec![
                CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP.to_string(),
                CHIO_OAUTH_SENDER_PROOF_CHIO_MTLS.to_string(),
                CHIO_OAUTH_SENDER_PROOF_CHIO_ATTESTATION.to_string(),
            ],
            proof_required_when: "matchedGrant.dpopRequired == true".to_string(),
            runtime_assurance_binding_fields: vec![
                "runtimeAssuranceTier".to_string(),
                "runtimeAssuranceSchema".to_string(),
                "runtimeAssuranceVerifierFamily".to_string(),
                "runtimeAssuranceVerifier".to_string(),
                "runtimeAssuranceEvidenceSha256".to_string(),
            ],
            delegated_call_chain_field: "callChain".to_string(),
            unsupported_sender_shapes_fail_closed: true,
        }
    }
}

impl Default for ChioOAuthAuthorizationProfile {
    fn default() -> Self {
        Self {
            schema: CHIO_OAUTH_AUTHORIZATION_PROFILE_SCHEMA.to_string(),
            id: CHIO_OAUTH_AUTHORIZATION_PROFILE_ID.to_string(),
            authoritative_source: "governed_receipt_projection".to_string(),
            authorization_detail_types: vec![
                CHIO_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE.to_string(),
                CHIO_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE.to_string(),
                CHIO_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE.to_string(),
            ],
            transaction_context_fields: vec![
                "intentId".to_string(),
                "intentHash".to_string(),
                "approvalTokenId".to_string(),
                "approvalApproved".to_string(),
                "approverKey".to_string(),
                "runtimeAssuranceTier".to_string(),
                "runtimeAssuranceSchema".to_string(),
                "runtimeAssuranceVerifierFamily".to_string(),
                "runtimeAssuranceVerifier".to_string(),
                "runtimeAssuranceEvidenceSha256".to_string(),
                "callChain".to_string(),
                "identityAssertion".to_string(),
            ],
            portable_claim_catalog: ChioPortableClaimCatalog::default(),
            portable_identity_binding: ChioPortableIdentityBinding::default(),
            governed_auth_binding: ChioGovernedAuthorizationBinding::default(),
            request_time_contract: ChioOAuthRequestTimeContract::default(),
            resource_binding: ChioOAuthResourceBinding::default(),
            artifact_boundary: ChioOAuthArtifactBoundary::default(),
            sender_constraints: ChioOAuthSenderConstraintProfile::default(),
            unsupported_shapes_fail_closed: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationContextSummary {
    pub matching_receipts: u64,
    pub returned_receipts: u64,
    pub approval_receipts: u64,
    pub approved_receipts: u64,
    pub commerce_receipts: u64,
    pub metered_billing_receipts: u64,
    pub runtime_assurance_receipts: u64,
    pub call_chain_receipts: u64,
    pub asserted_call_chain_receipts: u64,
    pub observed_call_chain_receipts: u64,
    pub verified_call_chain_receipts: u64,
    pub max_amount_receipts: u64,
    pub sender_bound_receipts: u64,
    pub dpop_bound_receipts: u64,
    pub runtime_assurance_bound_receipts: u64,
    pub delegated_sender_bound_receipts: u64,
    pub session_anchor_receipts: u64,
    pub request_lineage_receipts: u64,
    pub receipt_lineage_statement_receipts: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationContextSenderConstraint {
    pub subject_key: String,
    pub subject_key_source: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub issuer_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub issuer_key_source: String,
    pub matched_grant_index: u32,
    pub proof_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_schema: Option<String>,
    pub runtime_assurance_bound: bool,
    pub delegated_call_chain_bound: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationContextRow {
    pub receipt_id: String,
    pub timestamp: u64,
    pub capability_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_key: Option<String>,
    pub tool_server: String,
    pub tool_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    pub authorization_details: Vec<GovernedAuthorizationDetail>,
    pub transaction_context: GovernedAuthorizationTransactionContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_transaction_diagnostics: Option<GovernedTransactionDiagnostics>,
    pub sender_constraint: AuthorizationContextSenderConstraint,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationContextReport {
    #[serde(default = "default_authorization_context_report_schema")]
    pub schema: String,
    #[serde(default = "default_chio_oauth_authorization_profile")]
    pub profile: ChioOAuthAuthorizationProfile,
    pub summary: AuthorizationContextSummary,
    pub receipts: Vec<AuthorizationContextRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthAuthorizationDiscoveryMetadata {
    pub protected_resource_metadata_paths: Vec<String>,
    pub authorization_server_metadata_path_template: String,
    pub discovery_informational_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthAuthorizationSupportBoundary {
    pub governed_receipts_authoritative: bool,
    pub hosted_request_time_authorization_supported: bool,
    pub resource_indicator_binding_supported: bool,
    pub sender_constrained_projection: bool,
    pub runtime_assurance_projection: bool,
    pub delegated_call_chain_projection: bool,
    pub generic_token_issuance_supported: bool,
    pub oidc_identity_assertions_supported: bool,
    pub mtls_transport_binding_in_profile: bool,
    pub approval_tokens_runtime_authorization_supported: bool,
    pub capabilities_runtime_authorization_supported: bool,
    pub reviewer_evidence_runtime_authorization_supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthAuthorizationExampleMapping {
    pub authorization_detail_types: Vec<String>,
    pub transaction_context_fields: Vec<String>,
    pub sender_constraint_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthAuthorizationMetadataReport {
    pub schema: String,
    pub generated_at: u64,
    pub profile: ChioOAuthAuthorizationProfile,
    pub report_schema: String,
    pub discovery: ChioOAuthAuthorizationDiscoveryMetadata,
    pub support_boundary: ChioOAuthAuthorizationSupportBoundary,
    pub example_mapping: ChioOAuthAuthorizationExampleMapping,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthAuthorizationReviewPackSummary {
    pub matching_receipts: u64,
    pub returned_receipts: u64,
    pub dpop_required_receipts: u64,
    pub runtime_assurance_receipts: u64,
    pub delegated_call_chain_receipts: u64,
    pub asserted_call_chain_receipts: u64,
    pub observed_call_chain_receipts: u64,
    pub verified_call_chain_receipts: u64,
    pub session_anchor_receipts: u64,
    pub request_lineage_receipts: u64,
    pub receipt_lineage_statement_receipts: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthAuthorizationReviewPackRecord {
    pub receipt_id: String,
    pub capability_id: String,
    pub authorization_context: AuthorizationContextRow,
    pub governed_transaction: GovernedTransactionReceiptMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_transaction_diagnostics: Option<GovernedTransactionDiagnostics>,
    pub signed_receipt: ChioReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChioOAuthAuthorizationReviewPack {
    pub schema: String,
    pub generated_at: u64,
    pub filters: OperatorReportQuery,
    pub metadata: ChioOAuthAuthorizationMetadataReport,
    pub summary: ChioOAuthAuthorizationReviewPackSummary,
    pub records: Vec<ChioOAuthAuthorizationReviewPackRecord>,
}
