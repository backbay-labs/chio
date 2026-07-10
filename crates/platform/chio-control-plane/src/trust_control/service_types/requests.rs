use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustAuthorityStatus {
    pub configured: bool,
    pub backend: Option<String>,
    pub public_key: Option<String>,
    pub generation: Option<u64>,
    pub rotated_at: Option<u64>,
    pub applies_to_future_sessions_only: bool,
    #[serde(default)]
    pub trusted_public_keys: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IssueCapabilityRequest {
    pub(crate) subject_public_key: String,
    pub(crate) scope: ChioScope,
    pub(crate) ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) runtime_attestation: Option<RuntimeAttestationEvidence>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IssueCapabilityResponse {
    pub(crate) capability: CapabilityToken,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FederatedIssueRequest {
    pub presentation: PassportPresentationResponse,
    pub expected_challenge: PassportPresentationChallenge,
    pub capability: crate::policy::DefaultCapability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_policy: Option<chio_policy::HushSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_identity: Option<EnterpriseIdentityContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_policy: Option<FederatedDelegationPolicyDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_capability_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FederatedIssueResponse {
    pub subject: String,
    pub subject_public_key: String,
    pub verification: PassportPresentationVerification,
    pub capability: CapabilityToken,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_identity_provenance: Option<EnterpriseIdentityProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_audit: Option<EnterpriseAdmissionAudit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_anchor_capability_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseAdmissionAudit {
    pub provider_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_record_id: Option<String>,
    pub provider_kind: String,
    pub federation_method: String,
    pub principal: String,
    pub subject_key: String,
    pub subject_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attribute_sources: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_material_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_origin_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseProviderListResponse {
    pub configured: bool,
    pub count: usize,
    pub providers: Vec<EnterpriseProviderRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseProviderDeleteResponse {
    pub provider_id: String,
    pub deleted: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierPolicyListResponse {
    pub configured: bool,
    pub count: usize,
    pub policies: Vec<SignedPassportVerifierPolicy>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierPolicyDeleteResponse {
    pub policy_id: String,
    pub deleted: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePassportChallengeRequest {
    pub verifier: String,
    pub ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_credentials: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PassportVerifierPolicy>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyPassportChallengeRequest {
    pub presentation: PassportPresentationResponse,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_challenge: Option<PassportPresentationChallenge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassportPresentationTransport {
    pub challenge_id: String,
    pub challenge_url: String,
    pub submit_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePassportChallengeResponse {
    pub challenge: PassportPresentationChallenge,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<PassportPresentationTransport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateIdentityAssertionRequest {
    pub subject: String,
    pub continuity_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOid4vpRequest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disclosure_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuer_allowlist: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_assertion: Option<CreateIdentityAssertionRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOid4vpRequestResponse {
    pub request: Oid4vpRequestObject,
    pub transport: chio_credentials::Oid4vpRequestTransport,
    pub wallet_exchange: WalletExchangeStatusResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletExchangeStatusResponse {
    pub descriptor: WalletExchangeDescriptor,
    pub transaction: WalletExchangeTransactionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_assertion: Option<ChioIdentityAssertion>,
}

#[derive(Debug, Deserialize)]
pub struct Oid4vpDirectPostForm {
    pub response: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePassportIssuanceOfferRequest {
    pub passport: AgentPassport,
    pub ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_configuration_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FederatedDelegationPolicyBody {
    pub schema: String,
    pub issuer: String,
    pub partner: String,
    pub verifier: String,
    pub signer_public_key: PublicKey,
    pub created_at: u64,
    pub expires_at: u64,
    pub ttl_seconds: u64,
    pub scope: ChioScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_capability_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FederatedDelegationPolicyDocument {
    pub body: FederatedDelegationPolicyBody,
    pub signature: Signature,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordCapabilitySnapshotRequest {
    pub(crate) capability: CapabilityToken,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) parent_capability_id: Option<String>,
}

pub fn verify_federated_delegation_policy(
    policy: &FederatedDelegationPolicyDocument,
) -> Result<(), CliError> {
    if policy.body.schema != FEDERATED_DELEGATION_POLICY_SCHEMA {
        return Err(CliError::cli_other_error(format!(
            "unsupported federated delegation policy schema: expected {}, got {}",
            FEDERATED_DELEGATION_POLICY_SCHEMA, policy.body.schema
        )));
    }
    if policy.body.created_at > policy.body.expires_at {
        return Err(CliError::cli_other_error(
            "federated delegation policy created_at must be less than or equal to expires_at"
                .to_string(),
        ));
    }
    if policy.body.ttl_seconds == 0 {
        return Err(CliError::cli_other_error(
            "federated delegation policy ttl_seconds must be greater than zero".to_string(),
        ));
    }
    if !policy
        .body
        .signer_public_key
        .verify_canonical(&policy.body, &policy.signature)?
    {
        return Err(CliError::cli_other_error(
            "federated delegation policy signature verification failed".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn ensure_federated_delegation_policy_active(
    policy: &FederatedDelegationPolicyDocument,
    now: u64,
) -> Result<(), CliError> {
    if now < policy.body.created_at {
        return Err(CliError::cli_other_error(
            "federated delegation policy is not yet valid".to_string(),
        ));
    }
    if now > policy.body.expires_at {
        return Err(CliError::cli_other_error(
            "federated delegation policy has expired".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn ensure_requested_capability_within_delegation_policy(
    capability: &crate::policy::DefaultCapability,
    policy: &FederatedDelegationPolicyDocument,
    now: u64,
) -> Result<(), CliError> {
    if !capability.scope.is_subset_of(&policy.body.scope) {
        return Err(CliError::cli_other_error(
            "requested capability scope exceeds the signed federated delegation policy ceiling"
                .to_string(),
        ));
    }
    if capability.ttl > policy.body.ttl_seconds {
        return Err(CliError::cli_other_error(
            "requested capability ttl exceeds the signed federated delegation policy ceiling"
                .to_string(),
        ));
    }
    let requested_expires_at = now.saturating_add(capability.ttl);
    if requested_expires_at > policy.body.expires_at {
        return Err(CliError::cli_other_error(
            "requested capability expires after the federated delegation policy validity window"
                .to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn ensure_requested_capability_within_parent_snapshot(
    capability: &crate::policy::DefaultCapability,
    parent_snapshot: &CapabilitySnapshot,
    now: u64,
) -> Result<(), CliError> {
    let parent_scope: ChioScope = serde_json::from_str(&parent_snapshot.grants_json)?;
    if !capability.scope.is_subset_of(&parent_scope) {
        return Err(CliError::cli_other_error(
            "requested capability scope exceeds the imported upstream capability scope".to_string(),
        ));
    }
    let requested_expires_at = now.saturating_add(capability.ttl);
    if requested_expires_at > parent_snapshot.expires_at {
        return Err(CliError::cli_other_error(
            "requested capability expires after the imported upstream capability validity window"
                .to_string(),
        ));
    }
    if now >= parent_snapshot.expires_at {
        return Err(CliError::cli_other_error(
            "imported upstream capability has already expired".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn build_capability_snapshot(
    token: &CapabilityToken,
    delegation_depth: u64,
    parent_capability_id: Option<String>,
) -> Result<CapabilitySnapshot, CliError> {
    Ok(CapabilitySnapshot {
        capability_id: token.id.clone(),
        subject_key: token.subject.to_hex(),
        issuer_key: token.issuer.to_hex(),
        issued_at: token.issued_at,
        expires_at: token.expires_at,
        grants_json: serde_json::to_string(&token.scope)?,
        delegation_depth,
        parent_capability_id,
    })
}

pub(crate) fn build_federated_delegation_anchor_snapshot(
    policy: &FederatedDelegationPolicyDocument,
    subject_key: &str,
    challenge: &PassportPresentationChallenge,
    now: u64,
    parent_capability: Option<&CapabilitySnapshot>,
) -> Result<CapabilitySnapshot, CliError> {
    let anchor_descriptor = json!({
        "policySha256": sha256_hex(&canonical_json_bytes(&policy.body)?),
        "subjectKey": subject_key,
        "verifier": challenge.verifier,
        "nonce": challenge.nonce,
        "challengeIssuedAt": challenge.issued_at,
        "challengeExpiresAt": challenge.expires_at,
        "parentCapabilityId": parent_capability.map(|snapshot| snapshot.capability_id.clone()),
    });
    Ok(CapabilitySnapshot {
        capability_id: format!(
            "fed-del-{}",
            sha256_hex(&canonical_json_bytes(&anchor_descriptor)?)
        ),
        subject_key: subject_key.to_string(),
        issuer_key: policy.body.signer_public_key.to_hex(),
        issued_at: now,
        expires_at: parent_capability
            .map(|snapshot| snapshot.expires_at.min(policy.body.expires_at))
            .unwrap_or(policy.body.expires_at),
        grants_json: serde_json::to_string(&policy.body.scope)?,
        delegation_depth: parent_capability
            .map(|snapshot| snapshot.delegation_depth.saturating_add(1))
            .unwrap_or(0),
        parent_capability_id: None,
    })
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ToolReceiptQuery {
    /// Point-load a single tool receipt by its `receipt_id`. When set, the
    /// handler resolves exactly this receipt from the durable store (bounded to
    /// one row) rather than a filtered list, so a store-authoritative
    /// `--control-url` deployment can resolve a parent receipt that the kernel's
    /// bounded in-memory mirror has evicted.
    #[serde(default)]
    pub receipt_id: Option<String>,
    #[serde(default)]
    pub capability_id: Option<String>,
    #[serde(default)]
    pub tool_server: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

/// HTTP query parameters for the GET /v1/receipts/query endpoint.
/// Supports receipt filters and cursor pagination.
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptQueryHttpQuery {
    #[serde(default)]
    pub capability_id: Option<String>,
    #[serde(default)]
    pub tool_server: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub since: Option<u64>,
    #[serde(default)]
    pub until: Option<u64>,
    #[serde(default)]
    pub min_cost: Option<u64>,
    #[serde(default)]
    pub max_cost: Option<u64>,
    #[serde(default)]
    pub cursor: Option<u64>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub agent_subject: Option<String>,
}

/// Query parameters for GET /v1/agents/:subject_key/receipts.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentReceiptsHttpQuery {
    #[serde(default)]
    pub cursor: Option<u64>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LocalReputationQuery {
    #[serde(default)]
    pub since: Option<u64>,
    #[serde(default)]
    pub until: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReputationCompareRequest {
    pub passport: AgentPassport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_policy: Option<PassportVerifierPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
}

/// Response body for GET /v1/receipts/query.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptQueryResponse {
    pub total_count: u64,
    pub next_cursor: Option<u64>,
    pub receipts: Vec<Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SettlementReconciliationUpdateRequest {
    pub receipt_id: String,
    pub reconciliation_state: SettlementReconciliationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SettlementReconciliationUpdateResponse {
    pub receipt_id: String,
    pub reconciliation_state: SettlementReconciliationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub updated_at: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MeteredBillingReconciliationUpdateRequest {
    pub receipt_id: String,
    pub adapter_kind: String,
    pub evidence_id: String,
    pub observed_units: u64,
    pub billed_cost: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_sha256: Option<String>,
    pub recorded_at: u64,
    pub reconciliation_state: MeteredBillingReconciliationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MeteredBillingReconciliationUpdateResponse {
    pub receipt_id: String,
    pub evidence: MeteredBillingEvidenceRecord,
    pub reconciliation_state: MeteredBillingReconciliationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub updated_at: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UnderwritingDecisionIssueRequest {
    pub query: UnderwritingPolicyInputQuery,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_decision_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreditFacilityIssueRequest {
    pub query: ExposureLedgerQuery,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_facility_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreditBondIssueRequest {
    pub query: ExposureLedgerQuery,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_bond_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CapitalExecutionInstructionRequest {
    pub query: CapitalBookQuery,
    pub source_kind: CapitalBookSourceKind,
    pub action: CapitalExecutionInstructionAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<MonetaryAmount>,
    pub authority_chain: Vec<CapitalExecutionAuthorityStep>,
    pub execution_window: CapitalExecutionWindow,
    pub rail: CapitalExecutionRail,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_instruction_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_execution: Option<CapitalExecutionObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CapitalAllocationDecisionRequest {
    pub query: CapitalBookQuery,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    pub authority_chain: Vec<CapitalExecutionAuthorityStep>,
    pub execution_window: CapitalExecutionWindow,
    pub rail: CapitalExecutionRail,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreditLossLifecycleIssueRequest {
    pub query: CreditLossLifecycleQuery,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_chain: Vec<CapitalExecutionAuthorityStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_window: Option<CapitalExecutionWindow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rail: Option<CapitalExecutionRail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_execution: Option<CapitalExecutionObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appeal_window_ends_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityProviderIssueRequest {
    pub report: LiabilityProviderReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_provider_record_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityQuoteRequestIssueRequest {
    pub provider_id: String,
    pub jurisdiction: String,
    pub coverage_class: LiabilityCoverageClass,
    pub requested_coverage_amount: MonetaryAmount,
    pub requested_effective_from: u64,
    pub requested_effective_until: u64,
    pub risk_package: SignedCreditProviderRiskPackage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityQuoteResponseIssueRequest {
    pub quote_request: SignedLiabilityQuoteRequest,
    pub provider_quote_ref: String,
    pub disposition: LiabilityQuoteDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_quote_response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quoted_terms: Option<LiabilityQuoteTerms>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decline_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityPricingAuthorityIssueRequest {
    pub quote_request: SignedLiabilityQuoteRequest,
    pub facility: SignedCreditFacility,
    pub underwriting_decision: SignedUnderwritingDecision,
    pub capital_book: SignedCapitalBookReport,
    pub envelope: LiabilityPricingAuthorityEnvelope,
    pub max_coverage_amount: MonetaryAmount,
    pub max_premium_amount: MonetaryAmount,
    pub expires_at: u64,
    pub auto_bind_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityPlacementIssueRequest {
    pub quote_response: SignedLiabilityQuoteResponse,
    pub selected_coverage_amount: MonetaryAmount,
    pub selected_premium_amount: MonetaryAmount,
    pub effective_from: u64,
    pub effective_until: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityBoundCoverageIssueRequest {
    pub placement: SignedLiabilityPlacement,
    pub policy_number: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_at: Option<u64>,
    pub effective_from: u64,
    pub effective_until: u64,
    pub coverage_amount: MonetaryAmount,
    pub premium_amount: MonetaryAmount,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityAutoBindIssueRequest {
    pub authority: SignedLiabilityPricingAuthority,
    pub quote_response: SignedLiabilityQuoteResponse,
    pub policy_number: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimPackageIssueRequest {
    pub bound_coverage: SignedLiabilityBoundCoverage,
    pub exposure: SignedExposureLedgerReport,
    pub bond: SignedCreditBond,
    pub loss_event: SignedCreditLossLifecycle,
    pub claimant: String,
    pub claim_event_at: u64,
    pub claim_amount: MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_ref: Option<String>,
    pub narrative: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipt_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimResponseIssueRequest {
    pub claim: SignedLiabilityClaimPackage,
    pub provider_response_ref: String,
    pub disposition: LiabilityClaimResponseDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimDisputeIssueRequest {
    pub provider_response: SignedLiabilityClaimResponse,
    pub opened_by: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimAdjudicationIssueRequest {
    pub dispute: SignedLiabilityClaimDispute,
    pub adjudicator: String,
    pub outcome: LiabilityClaimAdjudicationOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub awarded_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimPayoutInstructionIssueRequest {
    pub adjudication: SignedLiabilityClaimAdjudication,
    pub capital_instruction: SignedCapitalExecutionInstruction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimPayoutReceiptIssueRequest {
    pub payout_instruction: SignedLiabilityClaimPayoutInstruction,
    pub payout_receipt_ref: String,
    pub reconciliation_state: LiabilityClaimPayoutReconciliationState,
    pub observed_execution: CapitalExecutionObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimSettlementInstructionIssueRequest {
    pub payout_receipt: SignedLiabilityClaimPayoutReceipt,
    pub capital_book: SignedCapitalBookReport,
    pub settlement_kind: LiabilityClaimSettlementKind,
    pub settlement_amount: MonetaryAmount,
    pub topology: LiabilityClaimSettlementRoleTopology,
    pub authority_chain: Vec<CapitalExecutionAuthorityStep>,
    pub execution_window: CapitalExecutionWindow,
    pub rail: CapitalExecutionRail,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiabilityClaimSettlementReceiptIssueRequest {
    pub settlement_instruction: SignedLiabilityClaimSettlementInstruction,
    pub settlement_receipt_ref: String,
    pub reconciliation_state: LiabilityClaimSettlementReconciliationState,
    pub observed_execution: CapitalExecutionObservation,
    pub observed_payer_id: String,
    pub observed_payee_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}
