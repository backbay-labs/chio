use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::runtime_attestation::RuntimeAssuranceTier;
use chio_core::capability::scope::{ChioScope, MonetaryAmount, Operation, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::crypto::Ed25519Backend;
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::crypto_floor::ReceiptCryptoFloor;
use chio_core::receipt::decision::{Decision, ToolCallAction};
use chio_core::receipt::economics::{
    EconomicAmountBoundsReceiptMetadata, EconomicAuthorizationMode,
    EconomicAuthorizationReceiptMetadata, EconomicAuthorizationReceiptMetadataVersion,
    EconomicBudgetReceiptMetadata, EconomicMerchantReceiptMetadata, EconomicPayeeReceiptMetadata,
    EconomicPayerReceiptMetadata, EconomicRailReceiptMetadata, EconomicSettlementReceiptMetadata,
    FinancialReceiptMetadata, SettlementStatus,
};
use chio_core::receipt::governance::{
    GovernedApprovalReceiptMetadata, GovernedCommerceReceiptMetadata,
    GovernedTransactionReceiptMetadata,
};
use chio_core::receipt::kinds::TrustLevel;
use chio_credit::factor::{
    verify_assignment_agreement, verify_assignment_bind_authorization, verify_receivable_claim,
    AssignmentAgreementBodyV1, AssignmentAgreementTrustV1, AssignmentAgreementVerificationV1,
    AssignmentBindAuthorizationBodyV1, AssignmentBindAuthorizationInputV1,
    AssignmentBindAuthorizationTrustV1, AssignmentBindAuthorizationVerificationV1,
    AssignmentNotAppliedReasonV1, AssignmentOfferV1, FactorError,
    NormalizedAssignmentRequestInputV1, NormalizedAssignmentRequestV1, ReceivableClaimInputV1,
    ReceivableClaimTrustV1, ReceivableClaimV1, ReceivableClaimVerificationV1,
    SignedAssignmentAgreementV1, SignedAssignmentBindAuthorizationV1,
    VerifiedAssignmentAuthorizationSetV1, VerifiedReceivableClaimV1,
};
use chio_credit::obligation::{
    derive_obligation_payee_binding_digest, verify_credit_facility_bind,
    verify_obligation_status_proof, ConfiguredCreditAuthorityArtifactV1,
    ConfiguredCreditAuthorityResolverV1, CreditAdmissionStoreAdapter, CreditAuthorityKindV1,
    CreditAuthorityResolutionRequestV1, CreditAuthorityResolverConfigurationV1,
    CreditAuthoritySourceV1, CreditExposureReservationRequest, CreditExposureReservationStateV1,
    CreditFacilityBindBodyV1, CreditFacilityBindInputV1, CreditFacilityBindTrustInputV1,
    CreditFacilityBindTrustV1, CreditFacilityBindVerificationContextV1, ObligationAtomInputV1,
    ObligationAtomV1, ObligationCreditElectionV1, ObligationDispositionRecordV1,
    ObligationDispositionV1, ObligationSettlementLifecycleV1, ObligationSettlementTransitionV1,
    ObligationStatusProofBodyV1, ObligationStatusProofContextV1, ObligationStatusProofTrustV1,
    ObligationStatusProofVerificationContextV1, SignedCreditFacilityBindV1,
    SignedObligationStatusProofV1, VerifiedCreditAuthoritySet, VerifiedCreditFacilityBindV1,
};
use chio_credit::{
    CreditFacilityArtifact, CreditFacilityCapitalSource, CreditFacilityDisposition,
    CreditFacilityLifecycleState, CreditFacilityPrerequisites, CreditFacilityReport,
    CreditFacilitySupportBoundary, CreditFacilityTerms, CreditScorecardBand,
    CreditScorecardConfidence, CreditScorecardSummary, ExposureLedgerQuery,
    IouEnvelopeCryptoFloorV2, IouEnvelopeIssuerTrustV2, IouEnvelopeMintContextV2,
    IouEnvelopeReceiptTrustV2, LocalCreditAccount, SignedCreditFacility,
    CREDIT_FACILITY_ARTIFACT_SCHEMA, CREDIT_FACILITY_REPORT_SCHEMA,
};
use chio_kernel::admission_operation::{
    AdmissionCompensationStatus, AdmissionCompletedProjection, AdmissionDispatchState,
    AdmissionReceiptMetadataV1, AdmissionReceiptSchema, AdmissionTerminalProjection,
    ObligationProjection, VerifiedAdmissionReceipt, ADMISSION_RECEIPT_METADATA_KEY,
};
use chio_kernel::tool_outcome::test_support::{
    prepared_evaluation, record_external_step, record_pure_step, resolve, returned_value,
};
use chio_kernel::tool_outcome::{SettlementDispositionV1, ToolOutcomeTerminalEvidenceV1};
use rusqlite::params;

use super::*;

const SNAPSHOT_VERSION: u64 = 1;
const RESOURCE_FENCE: u64 = 1;
const CLAIM_KERNEL_SEED: u8 = 111;
const CLAIM_IOU_ISSUER_SEED: u8 = 112;
const CLAIM_IOU_ISSUER_ID: &str = "factor-credit-issuer";
const CLAIM_IOU_ISSUER_EPOCH: u64 = 7;
const CLAIM_CREDIT_FACILITY_ID: &str = "facility:factor-working-capital";
const CLAIM_CREDIT_AUTHORITY_ID: &str = "factor-credit-facility-authority";
const CLAIM_CREDIT_AUTHORITY_EPOCH: u64 = 3;
const CLAIM_CREDIT_AUTHORITY_SEED: u8 = 114;
const CLAIM_CREDIT_CAPABILITY_AUTHORITY_ID: &str = "factor-credit-capability-authority";
const CLAIM_CREDIT_CAPABILITY_AUTHORITY_EPOCH: u64 = 4;
const CLAIM_CREDIT_CAPABILITY_AUTHORITY_SEED: u8 = 116;
const CLAIM_CREDIT_DEBTOR_ID: &str = "did:chio:factor-debtor";
const CLAIM_CREDIT_DEBTOR_EPOCH: u64 = 5;
const CLAIM_CREDIT_DEBTOR_SEED: u8 = 115;
const CLAIM_TOOL_SERVER: &str = "tools.factor.example";
const CLAIM_TOOL_NAME: &str = "priced_call";

#[derive(Clone, Copy)]
struct AuthoritySpec {
    bind_id: &'static str,
    bind_epoch: u64,
    bind_seed: u8,
    seller_id: &'static str,
    seller_epoch: u64,
    seller_seed: u8,
    buyer_id: &'static str,
    buyer_epoch: u64,
    buyer_seed: u8,
    buyer_destination: &'static str,
    result_id: &'static str,
    result_epoch: u64,
    result_seed: u8,
}

const AUTHORITY_A: AuthoritySpec = AuthoritySpec {
    bind_id: "factor-bind-authority-a",
    bind_epoch: 5,
    bind_seed: 41,
    seller_id: "did:chio:factor-seller-a",
    seller_epoch: 11,
    seller_seed: 42,
    buyer_id: "did:chio:factor-buyer-a",
    buyer_epoch: 12,
    buyer_seed: 43,
    buyer_destination: "acct:factor-buyer-a",
    result_id: "factor-decision-authority",
    result_epoch: 3,
    result_seed: 44,
};

const AUTHORITY_B: AuthoritySpec = AuthoritySpec {
    bind_id: "factor-bind-authority-b",
    bind_epoch: 6,
    bind_seed: 45,
    seller_id: "did:chio:factor-seller-b",
    seller_epoch: 13,
    seller_seed: 46,
    buyer_id: "did:chio:factor-buyer-b",
    buyer_epoch: 14,
    buyer_seed: 47,
    buyer_destination: "acct:factor-buyer-b",
    result_id: "factor-decision-authority",
    result_epoch: 3,
    result_seed: 44,
};

impl AuthoritySpec {
    fn verification_authority(
        self,
    ) -> Result<FactorAssignmentVerificationAuthorityV1, FactorError> {
        self.verification_authority_with_claim_trust(claim_trust(false)?)
    }

    fn verification_authority_with_claim_trust(
        self,
        claim_trust: ReceivableClaimTrustV1,
    ) -> Result<FactorAssignmentVerificationAuthorityV1, FactorError> {
        let bind = Keypair::from_seed(&[self.bind_seed; 32]);
        let seller = Keypair::from_seed(&[self.seller_seed; 32]);
        let buyer = Keypair::from_seed(&[self.buyer_seed; 32]);
        let result = Keypair::from_seed(&[self.result_seed; 32]);
        FactorAssignmentVerificationAuthorityV1::new(
            AssignmentBindAuthorizationTrustV1::new(
                self.bind_id.to_owned(),
                bind.public_key(),
                self.bind_epoch,
                60_000,
            )?,
            AssignmentAgreementTrustV1::new(
                self.seller_id.to_owned(),
                seller.public_key(),
                self.seller_epoch,
                self.buyer_id.to_owned(),
                buyer.public_key(),
                self.buyer_epoch,
            )?,
            ObligationStatusProofTrustV1::new(
                self.result_id.to_owned(),
                result.public_key(),
                self.result_epoch,
                60_000,
            )
            .map_err(|error| FactorError::Canonicalization(error.to_string()))?,
            claim_trust,
            self.result_id.to_owned(),
            self.result_epoch,
            result.public_key(),
        )
    }

    fn signing_authority(self) -> Result<FactorAssignmentSigningAuthorityV1, FactorError> {
        FactorAssignmentSigningAuthorityV1::new(
            self.result_id.to_owned(),
            self.result_epoch,
            Keypair::from_seed(&[self.result_seed; 32]),
        )
    }
}

fn claim_receipt_trust(alternate: bool) -> IouEnvelopeReceiptTrustV2 {
    let mut keys = vec![Keypair::from_seed(&[CLAIM_KERNEL_SEED; 32]).public_key()];
    if alternate {
        keys.push(Keypair::from_seed(&[113; 32]).public_key());
    }
    IouEnvelopeReceiptTrustV2::new(keys, ReceiptCryptoFloor::AllowClassical)
}

fn claim_credit_facility_bind_trust(
    authority: AuthoritySpec,
) -> Result<CreditFacilityBindTrustV1, FactorError> {
    CreditFacilityBindTrustV1::new(CreditFacilityBindTrustInputV1 {
        authority_id: CLAIM_CREDIT_AUTHORITY_ID.to_owned(),
        authority_key: Keypair::from_seed(&[CLAIM_CREDIT_AUTHORITY_SEED; 32]).public_key(),
        authority_key_epoch: CLAIM_CREDIT_AUTHORITY_EPOCH,
        debtor_id: CLAIM_CREDIT_DEBTOR_ID.to_owned(),
        debtor_key: Keypair::from_seed(&[CLAIM_CREDIT_DEBTOR_SEED; 32]).public_key(),
        debtor_key_epoch: CLAIM_CREDIT_DEBTOR_EPOCH,
        creditor_id: authority.seller_id.to_owned(),
        creditor_key: Keypair::from_seed(&[authority.seller_seed; 32]).public_key(),
        creditor_key_epoch: authority.seller_epoch,
        max_lifetime_ms: 60_000,
    })
    .map_err(|error| FactorError::Canonicalization(error.to_string()))
}

fn claim_trust(alternate: bool) -> Result<ReceivableClaimTrustV1, FactorError> {
    let status_trust = ObligationStatusProofTrustV1::new(
        AUTHORITY_A.result_id.to_owned(),
        Keypair::from_seed(&[AUTHORITY_A.result_seed; 32]).public_key(),
        AUTHORITY_A.result_epoch,
        60_000,
    )
    .map_err(|error| FactorError::Canonicalization(error.to_string()))?;
    ReceivableClaimTrustV1::new(
        &status_trust,
        claim_receipt_trust(alternate),
        [IouEnvelopeIssuerTrustV2::new(
            CLAIM_IOU_ISSUER_ID.to_owned(),
            CLAIM_IOU_ISSUER_EPOCH,
            Keypair::from_seed(&[CLAIM_IOU_ISSUER_SEED; 32]).public_key(),
            IouEnvelopeCryptoFloorV2::AllowClassical,
        )
        .map_err(|error| FactorError::Canonicalization(error.to_string()))?],
        [
            claim_credit_facility_bind_trust(AUTHORITY_A)?,
            claim_credit_facility_bind_trust(AUTHORITY_B)?,
        ],
    )
}

fn credit_authorities(
    operation: &AdmissionOperationV1,
    at: u64,
) -> AnchoredTestResult<VerifiedCreditAuthoritySet> {
    let issued_at = at / 1_000;
    let expires_at = issued_at + 120;
    let facility_authority = Keypair::from_seed(&[CLAIM_CREDIT_AUTHORITY_SEED; 32]);
    let capability_authority = Keypair::from_seed(&[CLAIM_CREDIT_CAPABILITY_AUTHORITY_SEED; 32]);
    let debtor = Keypair::from_seed(&[CLAIM_CREDIT_DEBTOR_SEED; 32]);
    let amount = MonetaryAmount {
        units: 500,
        currency: "USD".to_owned(),
    };
    let facility = SignedCreditFacility::sign(
        CreditFacilityArtifact {
            schema: CREDIT_FACILITY_ARTIFACT_SCHEMA.to_owned(),
            facility_id: CLAIM_CREDIT_FACILITY_ID.to_owned(),
            issued_at,
            expires_at,
            lifecycle_state: CreditFacilityLifecycleState::Active,
            supersedes_facility_id: None,
            report: CreditFacilityReport {
                schema: CREDIT_FACILITY_REPORT_SCHEMA.to_owned(),
                generated_at: issued_at,
                filters: ExposureLedgerQuery {
                    capability_id: Some(operation.binding().capability_id().as_str().to_owned()),
                    agent_subject: Some(CLAIM_CREDIT_DEBTOR_ID.to_owned()),
                    tool_server: Some(CLAIM_TOOL_SERVER.to_owned()),
                    tool_name: Some(CLAIM_TOOL_NAME.to_owned()),
                    since: None,
                    until: None,
                    receipt_limit: None,
                    decision_limit: None,
                },
                scorecard: CreditScorecardSummary {
                    matching_receipts: 1,
                    returned_receipts: 1,
                    matching_decisions: 1,
                    returned_decisions: 1,
                    currencies: vec![amount.currency.clone()],
                    mixed_currency_book: false,
                    confidence: CreditScorecardConfidence::High,
                    band: CreditScorecardBand::Prime,
                    overall_score: 1.0,
                    anomaly_count: 0,
                    probationary: false,
                },
                disposition: CreditFacilityDisposition::Grant,
                prerequisites: CreditFacilityPrerequisites {
                    minimum_runtime_assurance_tier: RuntimeAssuranceTier::Verified,
                    runtime_assurance_met: true,
                    certification_required: false,
                    certification_met: true,
                    manual_review_required: false,
                },
                support_boundary: CreditFacilitySupportBoundary::default(),
                terms: Some(CreditFacilityTerms {
                    credit_limit: amount.clone(),
                    utilization_ceiling_bps: 10_000,
                    reserve_ratio_bps: 0,
                    concentration_cap_bps: 10_000,
                    ttl_seconds: expires_at - issued_at,
                    capital_source: CreditFacilityCapitalSource::OperatorInternal,
                }),
                findings: Vec::new(),
            },
        },
        &facility_authority,
    )?;
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: operation.binding().capability_id().as_str().to_owned(),
            issuer: capability_authority.public_key(),
            subject: debtor.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: CLAIM_TOOL_SERVER.to_owned(),
                    tool_name: CLAIM_TOOL_NAME.to_owned(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: Some(amount.clone()),
                    max_total_cost: Some(amount.clone()),
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            issued_at,
            expires_at,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &capability_authority,
    )?;
    let resolver =
        ConfiguredCreditAuthorityResolverV1::new(CreditAuthorityResolverConfigurationV1 {
            complete_sources: vec![
                CreditAuthoritySourceV1 {
                    kind: CreditAuthorityKindV1::Facility,
                    authority_id: CLAIM_CREDIT_AUTHORITY_ID.to_owned(),
                    authority_key: facility_authority.public_key(),
                    authority_epoch: CLAIM_CREDIT_AUTHORITY_EPOCH,
                },
                CreditAuthoritySourceV1 {
                    kind: CreditAuthorityKindV1::Capability,
                    authority_id: CLAIM_CREDIT_CAPABILITY_AUTHORITY_ID.to_owned(),
                    authority_key: capability_authority.public_key(),
                    authority_epoch: CLAIM_CREDIT_CAPABILITY_AUTHORITY_EPOCH,
                },
            ],
            complete_artifact_catalog: vec![
                ConfiguredCreditAuthorityArtifactV1::Facility {
                    authority_id: CLAIM_CREDIT_AUTHORITY_ID.to_owned(),
                    authority_epoch: CLAIM_CREDIT_AUTHORITY_EPOCH,
                    signed: Box::new(facility),
                },
                ConfiguredCreditAuthorityArtifactV1::Capability {
                    authority_id: CLAIM_CREDIT_CAPABILITY_AUTHORITY_ID.to_owned(),
                    authority_epoch: CLAIM_CREDIT_CAPABILITY_AUTHORITY_EPOCH,
                    signed: Box::new(capability),
                },
            ],
        })?;
    Ok(resolver.resolve(&CreditAuthorityResolutionRequestV1 {
        debtor_id: CLAIM_CREDIT_DEBTOR_ID.to_owned(),
        debtor_key: debtor.public_key(),
        capability_id: operation.binding().capability_id().as_str().to_owned(),
        tool_server: CLAIM_TOOL_SERVER.to_owned(),
        tool_name: CLAIM_TOOL_NAME.to_owned(),
        currency: amount.currency,
        trusted_at_unix_seconds: issued_at,
    })?)
}

fn registry(
    active: &[AuthoritySpec],
    retained: &[AuthoritySpec],
) -> Result<FactorAssignmentAuthorityRegistryV1, FactorError> {
    FactorAssignmentAuthorityRegistryV1::new(
        active
            .iter()
            .copied()
            .map(AuthoritySpec::verification_authority)
            .collect::<Result<Vec<_>, _>>()?,
        retained
            .iter()
            .copied()
            .map(AuthoritySpec::verification_authority)
            .collect::<Result<Vec<_>, _>>()?,
    )
}

struct Receivable {
    atom: ObligationAtomV1,
    disposition: ObligationDispositionRecordV1,
    settlement: ObligationSettlementLifecycleV1,
    credit_facility_bind: VerifiedCreditFacilityBindV1,
    receipt: ChioReceipt,
    receipt_bytes: Vec<u8>,
}

fn persist_receivable(
    fixture: &Fixture,
    authority: AuthoritySpec,
    suffix: &str,
    at: u64,
) -> AnchoredTestResult<Receivable> {
    let action = ToolCallAction::from_parameters(serde_json::json!({ "units": 1 }))?;
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        obligation: true,
        credit_exposure: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace: AuthenticatedRequestNamespace::for_local_system(identifier(
            "coordinator_authority_id",
            "local-factor-source-authority",
        ))?,
        request_id: identifier("request_id", &format!("factor-source-request-{suffix}")),
        capability_id: identifier(
            "capability_id",
            &format!("factor-source-capability-{suffix}"),
        ),
        authorization_capability_hash: AdmissionDigest::try_new(
            "authorization_capability_hash",
            economic_digest(&format!("factor-source-capability-authorization-{suffix}")),
        )?,
        request_binding: AdmissionRequestBindingV1::new_with_action_parameter_hash(
            AdmissionDigest::try_new(
                "immutable_request_hash",
                economic_digest(&format!("factor-source-request-binding-{suffix}")),
            )?,
            AdmissionDigest::try_new("action_parameter_hash", action.parameter_hash.clone())?,
            requirements,
        )?,
        policy_hash: AdmissionDigest::try_new(
            "policy_hash",
            economic_digest(&format!("factor-source-policy-{suffix}")),
        )?,
        effect_class: SideEffectClass::Monetary,
    })?;
    let mut operation = AdmissionOperationV1::prepare(binding, fixture.fence.owner_epoch)?;
    fixture.store.begin(&operation, &fixture.fence, at)?;
    let recovery = claim(fixture, &operation, suffix, at);
    operation = fixture
        .store
        .compare_and_swap(
            &command(
                &operation,
                recovery,
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &operation,
                    &format!("factor-source-attempt-{suffix}"),
                ))],
                AdmissionOperationState::BrokerAttemptRegistered,
                None,
            ),
            at,
        )?
        .into_operation();
    let settlement_destination = format!("acct:factor-seller-{suffix}");
    let intent_digest = operation
        .binding()
        .request_binding_hash()
        .as_str()
        .to_owned();
    let authority_digest = economic_digest(&format!("factor-authority-{suffix}"));
    let amount = MonetaryAmount {
        units: 500,
        currency: "USD".to_owned(),
    };
    let due_at_unix_ms = at + 120_000;
    let payee_binding_digest =
        derive_obligation_payee_binding_digest(authority.seller_id, &settlement_destination)?;
    let authorities = credit_authorities(&operation, at)?;
    let facility_artifact_digest = authorities
        .evidence()
        .iter()
        .find(|evidence| evidence.kind() == CreditAuthorityKindV1::Facility)
        .ok_or("factor credit authority set omitted its facility")?
        .artifact_digest()
        .to_owned();
    let credit_authority = Keypair::from_seed(&[CLAIM_CREDIT_AUTHORITY_SEED; 32]);
    let debtor = Keypair::from_seed(&[CLAIM_CREDIT_DEBTOR_SEED; 32]);
    let creditor = Keypair::from_seed(&[authority.seller_seed; 32]);
    let bind_issued_at_unix_ms = at - at % 1_000;
    let signed_credit_facility_bind = SignedCreditFacilityBindV1::sign(
        CreditFacilityBindBodyV1::new(CreditFacilityBindInputV1 {
            operation_id: operation.binding().operation_id().as_str().to_owned(),
            request_id: operation.binding().request_id().as_str().to_owned(),
            economic_intent_digest: intent_digest.clone(),
            facility_id: CLAIM_CREDIT_FACILITY_ID.to_owned(),
            facility_artifact_digest,
            authority_set_digest: authorities.authority_set_digest().to_owned(),
            debtor_id: CLAIM_CREDIT_DEBTOR_ID.to_owned(),
            original_creditor_id: authority.seller_id.to_owned(),
            original_settlement_destination_ref: settlement_destination.clone(),
            capability_id: operation.binding().capability_id().as_str().to_owned(),
            tool_server: CLAIM_TOOL_SERVER.to_owned(),
            tool_name: CLAIM_TOOL_NAME.to_owned(),
            amount: amount.clone(),
            effective_ceiling: authorities.effective_ceiling().clone(),
            expected_exposure_version: 1,
            expected_exposure_fence: 1,
            due_at_unix_ms,
            action_nonce: format!("factor-credit-action-{suffix}"),
            issued_at_unix_ms: bind_issued_at_unix_ms,
            expires_at_unix_ms: bind_issued_at_unix_ms + 60_000,
            authority_id: CLAIM_CREDIT_AUTHORITY_ID.to_owned(),
            authority_key_epoch: CLAIM_CREDIT_AUTHORITY_EPOCH,
            debtor_key_epoch: CLAIM_CREDIT_DEBTOR_EPOCH,
            creditor_key_epoch: authority.seller_epoch,
        })?,
        &credit_authority,
        &debtor,
        &creditor,
    )?;
    let credit_facility_bind_bytes = signed_credit_facility_bind.canonical_bytes()?;
    let credit_facility_bind_trust = claim_credit_facility_bind_trust(authority)?;
    let credit_facility_bind = verify_credit_facility_bind(
        &credit_facility_bind_bytes,
        &CreditFacilityBindVerificationContextV1 {
            trust: &credit_facility_bind_trust,
            trusted_at_unix_ms: at,
        },
    )?;
    let credit_request = CreditExposureReservationRequest {
        operation_id: operation.binding().operation_id().as_str().to_owned(),
        request_id: operation.binding().request_id().as_str().to_owned(),
        action_nonce: format!("factor-credit-action-{suffix}"),
        economic_intent_digest: intent_digest.clone(),
        debtor_id: CLAIM_CREDIT_DEBTOR_ID.to_owned(),
        amount: amount.clone(),
        authorities,
        credit_facility_bind: credit_facility_bind.clone(),
    };
    fixture
        .store
        .provision_credit_exposure_account(&credit_request, &fixture.fence, at)?;
    let hold_id = format!("factor-source-hold-{suffix}");
    let authorization_lease = claim(fixture, &operation, suffix, at);
    let (decision, authorized) = fixture.store.authorize_budget_and_commit_admission(
        &operation,
        &authorization_lease,
        BudgetAuthorizeHoldRequest {
            capability_id: operation.binding().capability_id().as_str().to_owned(),
            grant_index: 0,
            max_invocations: Some(1),
            invocation_quotas: Vec::new(),
            cumulative_approval: None,
            admission_binding: Some(BudgetAdmissionBinding {
                operation_id: operation.binding().operation_id().as_str().to_owned(),
                revocation_set: CanonicalRevocationSet::canonicalize(vec![operation
                    .binding()
                    .capability_id()
                    .as_str()
                    .to_owned()])?,
                authorization_artifact_digests: vec![credit_facility_bind
                    .artifact_digest()
                    .to_owned()],
                last_observed_revocation: None,
                supplemental_verifier_id: None,
                supplemental_verifier_config_digest: None,
                supplemental_authorization_artifact_digest: None,
                supplemental_authorization_expires_at: None,
            }),
            requested_exposure_units: amount.units,
            max_cost_per_invocation: Some(amount.units),
            max_total_cost_units: Some(amount.units),
            hold_id: Some(hold_id.clone()),
            event_id: Some(format!("factor-source-authorize-{suffix}")),
            authority: Some(BudgetEventAuthority {
                authority_id: fixture.fence.store_uuid.clone(),
                lease_id: fixture.fence.lease_id.clone(),
                lease_epoch: fixture.fence.owner_epoch,
            }),
        },
        None,
        Some(credit_request),
        &fixture.fence,
        at,
    )?;
    if !matches!(decision, BudgetAuthorizeHoldDecision::Authorized(_)) {
        return Err("factor credit authorization unexpectedly replayed".into());
    }
    operation = authorized;
    for state in [
        AdmissionOperationState::ReadyToDispatch,
        AdmissionOperationState::CapturePending,
    ] {
        let recovery = claim(fixture, &operation, suffix, at);
        operation = fixture
            .store
            .compare_and_swap(&command(&operation, recovery, Vec::new(), state, None), at)?
            .into_operation();
    }
    let capture_lease = claim(fixture, &operation, suffix, at);
    let (_, dispatched) = fixture.store.capture_invocation_and_commit_dispatch(
        &operation,
        &capture_lease,
        BudgetCaptureInvocationRequest {
            capability_id: operation.binding().capability_id().as_str().to_owned(),
            grant_index: 0,
            hold_id,
            event_id: format!("factor-source-capture-{suffix}"),
            trusted_time: None,
            authority: Some(BudgetEventAuthority {
                authority_id: fixture.fence.store_uuid.clone(),
                lease_id: fixture.fence.lease_id.clone(),
                lease_epoch: fixture.fence.owner_epoch,
            }),
        },
        &fixture.fence,
        at,
    )?;
    operation = dispatched;
    let (_, returned) = returned_value(
        &operation,
        fixture.fence.clone(),
        at,
        serde_json::json!({ "result": "ok" }),
        None,
    )?;
    let evaluation = prepared_evaluation(&operation, &returned, at)
        .and_then(|value| record_pure_step(&value))
        .and_then(|value| record_external_step(&value, at))?;
    let (evaluation, outcome) = resolve(
        &returned,
        &evaluation,
        SettlementDispositionV1::Capture {
            amount: amount.clone(),
        },
    )?;
    let finalizing_lease = claim(fixture, &operation, suffix, at);
    operation = fixture
        .store
        .compare_and_swap(
            &command(
                &operation,
                finalizing_lease,
                vec![AdmissionAttachment::ToolOutcomeId(
                    outcome.outcome_id().clone(),
                )],
                AdmissionOperationState::Finalizing,
                None,
            ),
            at,
        )?
        .into_operation();
    let terminal_lease = claim(fixture, &operation, suffix, at);
    let context = AdmissionProjectionContext {
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.replay_key().request_id,
        expected_operation_version: operation.version(),
        trusted_time_unix_ms: at,
        coordinator_lease_id: terminal_lease.coordinator_lease_id().clone(),
        coordinator_lease_epoch: terminal_lease.coordinator_lease_epoch(),
        store_fence: terminal_lease.store_fence().clone(),
    };
    let tool_outcome = ToolOutcomeTerminalEvidenceV1::from_records_for_test(
        &operation,
        &context,
        &outcome,
        &evaluation,
    )?;
    let content_hash = outcome
        .resolved_output_ref()
        .ok_or("factor source output is absent")?
        .0
        .digest()
        .clone();
    let receipt = signed_receipt(
        suffix,
        &operation,
        &context,
        &action,
        &content_hash,
        authority.seller_id,
        &settlement_destination,
        &intent_digest,
        &authority_digest,
        &payee_binding_digest,
        credit_facility_bind.artifact_digest(),
        outcome.outcome_id(),
        outcome.version(),
    )?;
    let kernel = Keypair::from_seed(&[CLAIM_KERNEL_SEED; 32]);
    let verified_receipt = VerifiedAdmissionReceipt::from_kernel_verified_for_test(
        receipt.clone(),
        &kernel.public_key(),
        &Decision::Allow,
        CLAIM_TOOL_SERVER,
        CLAIM_TOOL_NAME,
        operation.binding().action_parameter_hash(),
        &content_hash,
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
        Some((outcome.outcome_id(), outcome.version())),
    )?;
    let receipt_bytes = canonical_json_bytes(&receipt)?;
    let atom = ObligationAtomV1::new(ObligationAtomInputV1 {
        economic_intent_digest: intent_digest,
        source_receipt_id: receipt.id.clone(),
        source_receipt_digest: sha256_hex(&receipt_bytes),
        debtor_id: CLAIM_CREDIT_DEBTOR_ID.to_owned(),
        original_creditor_id: authority.seller_id.to_owned(),
        original_settlement_destination_ref: settlement_destination.clone(),
        payee_binding_digest,
        amount,
        credit_election: ObligationCreditElectionV1::CreditFacility {
            facility_id: CLAIM_CREDIT_FACILITY_ID.to_owned(),
            authority_digest: credit_facility_bind.artifact_digest().to_owned(),
        },
        pre_action_authority_digest: authority_digest,
        created_at_unix_ms: at,
        due_at_unix_ms,
    })?;
    let obligation = ObligationProjection::from_credit_source_verified(
        &operation,
        &context,
        &verified_receipt,
        atom.clone(),
        outcome.outcome_id().clone(),
        outcome.version(),
    )?;
    fixture
        .store
        .commit_terminal_projection(&AdmissionTerminalProjection::Completed(Box::new(
            AdmissionCompletedProjection {
                context,
                receipt: verified_receipt,
                tool_outcome: Some(tool_outcome),
                payment_evidence: None,
                authorization: None,
                eligibility: None,
                observer_work: None,
                obligation: Some(obligation),
                channel_terminal: None,
            },
        )))?;
    let reservation = fixture
        .store
        .load_credit_exposure_reservation(operation.binding().operation_id().as_str())?
        .ok_or("factor credit reservation was not persisted")?;
    if reservation.state() != CreditExposureReservationStateV1::Committed {
        return Err("factor credit reservation was not committed".into());
    }
    reservation.validate_committed_obligation(&atom)?;
    let durable = fixture
        .store
        .load_obligation(atom.obligation_id())?
        .ok_or("factor obligation was not persisted")?;
    if durable.atom() != &atom {
        return Err("factor obligation changed during terminal commit".into());
    }
    Ok(Receivable {
        atom,
        disposition: durable.disposition().clone(),
        settlement: durable.settlement_lifecycle().clone(),
        credit_facility_bind,
        receipt,
        receipt_bytes,
    })
}

#[allow(clippy::too_many_arguments)]
fn signed_receipt(
    suffix: &str,
    operation: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
    action: &ToolCallAction,
    content_hash: &AdmissionDigest,
    seller_id: &str,
    settlement_destination: &str,
    intent_digest: &str,
    authority_digest: &str,
    payee_binding_digest: &str,
    credit_authority_digest: &str,
    outcome_id: &AdmissionDigest,
    outcome_version: u64,
) -> AnchoredTestResult<ChioReceipt> {
    let amount = MonetaryAmount {
        units: 500,
        currency: "USD".to_owned(),
    };
    let debtor_id = CLAIM_CREDIT_DEBTOR_ID.to_owned();
    let governed = GovernedTransactionReceiptMetadata {
        intent_id: format!("factor-intent-{suffix}"),
        intent_hash: intent_digest.to_owned(),
        purpose: "deferred supplier payment".to_owned(),
        server_id: CLAIM_TOOL_SERVER.to_owned(),
        tool_name: CLAIM_TOOL_NAME.to_owned(),
        max_amount: Some(amount.clone()),
        commerce: Some(GovernedCommerceReceiptMetadata {
            seller: seller_id.to_owned(),
            shared_payment_token_id: format!("factor-payment-token-{suffix}"),
            settlement_destination_ref: Some(settlement_destination.to_owned()),
        }),
        metered_billing: None,
        approval: Some(GovernedApprovalReceiptMetadata {
            token_id: format!("factor-approval-{suffix}"),
            approver_key: "factor-approver".to_owned(),
            approval_artifact_digest: Some(authority_digest.to_owned()),
            approved: true,
        }),
        runtime_assurance: None,
        call_chain: None,
        autonomy: None,
        economic_authorization: Some(EconomicAuthorizationReceiptMetadata {
            version: EconomicAuthorizationReceiptMetadataVersion::V1,
            economic_intent_digest: Some(intent_digest.to_owned()),
            payee_binding_digest: Some(payee_binding_digest.to_owned()),
            pre_action_authority_digest: Some(authority_digest.to_owned()),
            credit_authority_digest: Some(credit_authority_digest.to_owned()),
            economic_mode: EconomicAuthorizationMode::BudgetOnly,
            payer: EconomicPayerReceiptMetadata {
                party_id: debtor_id.clone(),
                funding_source_ref: CLAIM_CREDIT_FACILITY_ID.to_owned(),
                custody_provider: None,
                obligor_ref: None,
            },
            merchant: EconomicMerchantReceiptMetadata {
                merchant_id: seller_id.to_owned(),
                merchant_of_record: None,
                order_ref: Some(format!("factor-order-{suffix}")),
            },
            payee: EconomicPayeeReceiptMetadata {
                beneficiary_id: seller_id.to_owned(),
                settlement_destination_ref: settlement_destination.to_owned(),
            },
            rail: EconomicRailReceiptMetadata {
                kind: "credit_facility".to_owned(),
                asset: "USD".to_owned(),
                network: None,
                facilitator: None,
                contract_or_account_ref: Some(CLAIM_CREDIT_FACILITY_ID.to_owned()),
            },
            amount_bounds: EconomicAmountBoundsReceiptMetadata {
                approved_max: amount.clone(),
                hold_amount: None,
                settlement_cap: amount.clone(),
            },
            pricing_basis: None,
            metering: None,
            liability_refs: None,
            budget: EconomicBudgetReceiptMetadata {
                grant_index: 0,
                cost_charged: amount.units,
                currency: amount.currency.clone(),
                budget_remaining: 0,
                budget_total: amount.units,
                delegation_depth: 1,
                root_budget_holder: debtor_id.clone(),
                attempted_cost: None,
            },
            settlement: EconomicSettlementReceiptMetadata {
                settlement_status: SettlementStatus::Pending,
            },
        }),
    };
    let admission = AdmissionReceiptMetadataV1 {
        schema: AdmissionReceiptSchema::V1,
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.replay_key().request_id,
        request_namespace_digest: operation.binding().request_namespace_digest().clone(),
        request_binding_hash: operation.binding().request_binding_hash().clone(),
        projected_operation_version: operation
            .version()
            .checked_add(1)
            .ok_or("factor terminal operation version overflow")?,
        projected_state: AdmissionOperationState::Completed,
        projected_dispatch_state: AdmissionDispatchState::Terminal,
        trusted_time_unix_ms: context.trusted_time_unix_ms,
        coordinator_lease_id: context.coordinator_lease_id.clone(),
        coordinator_lease_epoch: context.coordinator_lease_epoch,
        store_fence: context.store_fence.clone(),
        retained_dispatch_commit: operation.dispatch_commit().cloned(),
        compensation_status: AdmissionCompensationStatus::NotCompensated,
        tool_outcome_id: Some(outcome_id.clone()),
        tool_outcome_version: Some(outcome_version),
    };
    let kernel = Keypair::from_seed(&[CLAIM_KERNEL_SEED; 32]);
    Ok(ChioReceipt::sign(
        ChioReceiptBody {
            id: format!("factor-receipt-{suffix}"),
            timestamp: context.trusted_time_unix_ms / 1_000,
            capability_id: operation.binding().capability_id().as_str().to_owned(),
            tool_server: CLAIM_TOOL_SERVER.to_owned(),
            tool_name: CLAIM_TOOL_NAME.to_owned(),
            action: action.clone(),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: content_hash.as_str().to_owned(),
            policy_hash: operation.binding().policy_hash().as_str().to_owned(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "financial": FinancialReceiptMetadata {
                    grant_index: 0,
                    cost_charged: amount.units,
                    currency: amount.currency.clone(),
                    budget_remaining: 0,
                    budget_total: amount.units,
                    delegation_depth: 1,
                    root_budget_holder: debtor_id,
                    payment_reference: None,
                    settlement_status: SettlementStatus::Pending,
                    cost_breakdown: None,
                    oracle_evidence: None,
                    attempted_cost: None,
                },
                "governed_transaction": governed,
                ADMISSION_RECEIPT_METADATA_KEY: admission,
                "receipt_context": {
                    "request_id": operation.binding().request_id().as_str(),
                },
            })),
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: kernel.public_key(),
            bbs_projection_version: None,
        },
        &kernel,
    )?)
}

#[derive(Clone, Copy)]
enum Expiry {
    Live,
    Authorization,
    Request,
    Offer,
}

#[derive(Clone, Copy)]
struct FactorTimes {
    status_issued: u64,
    claim_built: u64,
    offer_issued: u64,
    effective: u64,
    status_expires: u64,
    authorization_expires: u64,
    request_expires: u64,
    offer_expires: u64,
    commit_at: u64,
}

impl FactorTimes {
    fn new(status_issued: u64, effective: u64, expiry: Expiry) -> Self {
        let live_expiry = effective + 30_000;
        let expired_at_commit = effective + 5;
        Self {
            status_issued,
            claim_built: status_issued + 1,
            offer_issued: status_issued + 2,
            effective,
            status_expires: live_expiry,
            authorization_expires: if matches!(expiry, Expiry::Authorization) {
                expired_at_commit
            } else {
                live_expiry
            },
            request_expires: if matches!(expiry, Expiry::Request) {
                expired_at_commit
            } else {
                live_expiry
            },
            offer_expires: if matches!(expiry, Expiry::Offer) {
                expired_at_commit
            } else {
                live_expiry
            },
            commit_at: effective + 6,
        }
    }
}

struct FactorCase {
    operation: AdmissionOperationV1,
    request: NormalizedAssignmentRequestV1,
    claim: VerifiedReceivableClaimV1,
    offer: AssignmentOfferV1,
    authorization: VerifiedAssignmentAuthorizationSetV1,
    status_proof: chio_credit::obligation::VerifiedObligationStatusProofV1,
    signing_authority: FactorAssignmentSigningAuthorityV1,
    commit_at: u64,
}

impl FactorCase {
    fn new(
        fixture: &Fixture,
        receivable: &Receivable,
        authority: AuthoritySpec,
        suffix: &str,
        times: FactorTimes,
    ) -> AnchoredTestResult<Self> {
        let result_signer = Keypair::from_seed(&[authority.result_seed; 32]);
        let status_trust = ObligationStatusProofTrustV1::new(
            authority.result_id.to_owned(),
            result_signer.public_key(),
            authority.result_epoch,
            60_000,
        )?;
        let signed_status = SignedObligationStatusProofV1::sign(
            ObligationStatusProofBodyV1::new(&ObligationStatusProofContextV1 {
                atom: &receivable.atom,
                disposition: &receivable.disposition,
                settlement_lifecycle: &receivable.settlement,
                snapshot_version: SNAPSHOT_VERSION,
                resource_fence: RESOURCE_FENCE,
                issued_at_unix_ms: times.status_issued,
                expires_at_unix_ms: times.status_expires,
                authority_id: authority.result_id,
                authority_key_epoch: authority.result_epoch,
            })?,
            &result_signer,
        )?;
        let status_bytes = signed_status.canonical_bytes()?;
        let status_proof = verify_obligation_status_proof(
            &status_bytes,
            &ObligationStatusProofVerificationContextV1 {
                atom: &receivable.atom,
                disposition: &receivable.disposition,
                settlement_lifecycle: &receivable.settlement,
                snapshot_version: SNAPSHOT_VERSION,
                resource_fence: RESOURCE_FENCE,
                trust: &status_trust,
                trusted_now_unix_ms: times.effective,
            },
        )?;
        let account = LocalCreditAccount::new_with_receipt_trust(
            Ed25519Backend::new(Keypair::from_seed(&[CLAIM_IOU_ISSUER_SEED; 32])),
            claim_receipt_trust(false),
        );
        let credit_admission = CreditAdmissionStoreAdapter::new(fixture.store.clone());
        let signed_iou = account.mint_obligation_iou_v2(
            &credit_admission,
            &IouEnvelopeMintContextV2 {
                atom: &receivable.atom,
                disposition: &receivable.disposition,
                settlement_lifecycle: &receivable.settlement,
                receipt: &receivable.receipt,
                credit_facility_bind: &receivable.credit_facility_bind,
                issuer_id: CLAIM_IOU_ISSUER_ID,
                issuer_key_epoch: CLAIM_IOU_ISSUER_EPOCH,
                trusted_issued_at_unix_ms: times.status_issued,
            },
        )?;
        let iou_bytes = signed_iou.canonical_bytes()?;
        let claim_body = ReceivableClaimV1::new(ReceivableClaimInputV1 {
            obligation_id: receivable.atom.obligation_id().to_owned(),
            obligation_atom_digest: receivable.atom.digest()?,
            seller_id: authority.seller_id.to_owned(),
            receipt_id: receivable.atom.source_receipt_id().to_owned(),
            receipt_digest: receivable.atom.source_receipt_digest().to_owned(),
            iou_id: signed_iou.body().iou_id().to_owned(),
            iou_digest: sha256_hex(&iou_bytes),
            payee_binding_digest: receivable.atom.payee_binding_digest().to_owned(),
            status_proof_digest: status_proof.envelope_digest().to_owned(),
            face_value: receivable.atom.amount().clone(),
            due_at_unix_ms: receivable.atom.due_at_unix_ms(),
            built_at_unix_ms: times.claim_built,
        })?;
        let claim_bytes = claim_body.canonical_bytes()?;
        let trust = claim_trust(false)?;
        let verified_claim = verify_receivable_claim(
            &claim_bytes,
            &receivable.receipt_bytes,
            &iou_bytes,
            &credit_admission,
            &ReceivableClaimVerificationV1 {
                atom: &receivable.atom,
                disposition: &receivable.disposition,
                settlement_lifecycle: &receivable.settlement,
                status_proof: &status_proof,
                trusted_now_unix_ms: times.claim_built,
                trust: &trust,
            },
        )?;
        let offer = AssignmentOfferV1::new(
            verified_claim.claim(),
            100,
            times.offer_issued,
            times.offer_expires,
        )?;
        let request = NormalizedAssignmentRequestV1::new(NormalizedAssignmentRequestInputV1 {
            obligation_id: receivable.atom.obligation_id().to_owned(),
            obligation_atom_digest: receivable.atom.digest()?,
            claim_digest: verified_claim.claim_digest().to_owned(),
            offer_digest: offer.digest()?,
            seller_id: authority.seller_id.to_owned(),
            buyer_id: authority.buyer_id.to_owned(),
            buyer_settlement_destination_ref: authority.buyer_destination.to_owned(),
            agreed_price: offer.minimum_price().clone(),
            agreed_discount_bps: offer.asking_discount_bps(),
            expected_disposition_version: receivable.disposition.version(),
            expected_disposition_lifecycle_fence: receivable.disposition.lifecycle_fence(),
            expected_settlement_lifecycle_version: receivable.settlement.version(),
            expected_settlement_lifecycle_fence: receivable.settlement.lifecycle_fence(),
            action_nonce: format!("factor-action-{suffix}"),
            effective_at_unix_ms: times.effective,
            due_at_unix_ms: receivable.atom.due_at_unix_ms(),
            expires_at_unix_ms: times.request_expires,
        })?;
        let request_digest = request.digest()?;
        let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
            kind: AdmissionOperationKind::GovernedEconomicMutation,
            namespace: AuthenticatedRequestNamespace::for_local_system(identifier(
                "coordinator_authority_id",
                "local-factor-authority",
            ))?,
            request_id: identifier("request_id", &format!("factor-request-{suffix}")),
            capability_id: identifier("capability_id", &format!("factor-capability-{suffix}")),
            authorization_capability_hash: AdmissionDigest::try_new(
                "authorization_capability_hash",
                economic_digest(&format!("factor-capability-authorization-{suffix}")),
            )?,
            request_binding: AdmissionRequestBindingV1::new(
                AdmissionDigest::try_new("immutable_request_hash", request_digest.clone())?,
                AdmissionParticipantRequirements {
                    supplemental_authorization: true,
                    ..AdmissionParticipantRequirements::NONE
                },
            )?,
            policy_hash: AdmissionDigest::try_new(
                "policy_hash",
                economic_digest(&format!("factor-policy-{suffix}")),
            )?,
            effect_class: SideEffectClass::Monetary,
        })?;
        let mut operation = AdmissionOperationV1::prepare(binding, fixture.fence.owner_epoch)?;
        fixture
            .store
            .begin(&operation, &fixture.fence, times.effective)?;

        let bind_signer = Keypair::from_seed(&[authority.bind_seed; 32]);
        let signed_bind = SignedAssignmentBindAuthorizationV1::sign(
            AssignmentBindAuthorizationBodyV1::new(AssignmentBindAuthorizationInputV1 {
                operation_id: operation.binding().operation_id().as_str().to_owned(),
                normalized_request_digest: request_digest.clone(),
                obligation_atom_digest: receivable.atom.digest()?,
                seller_id: authority.seller_id.to_owned(),
                buyer_id: authority.buyer_id.to_owned(),
                agreement_id: format!("factor-agreement-{suffix}"),
                buyer_settlement_destination_ref: authority.buyer_destination.to_owned(),
                effective_at_unix_ms: times.effective,
                action_nonce: request.action_nonce().to_owned(),
                issued_at_unix_ms: times.status_issued,
                expires_at_unix_ms: times.authorization_expires,
                authority_id: authority.bind_id.to_owned(),
                authority_key_epoch: authority.bind_epoch,
            })?,
            &bind_signer,
        )?;
        let bind_bytes = signed_bind.canonical_bytes()?;
        let bind_trust = AssignmentBindAuthorizationTrustV1::new(
            authority.bind_id.to_owned(),
            bind_signer.public_key(),
            authority.bind_epoch,
            60_000,
        )?;
        let agreement_id = format!("factor-agreement-{suffix}");
        let verified_bind = verify_assignment_bind_authorization(
            &bind_bytes,
            &AssignmentBindAuthorizationVerificationV1 {
                operation_id: operation.binding().operation_id().as_str(),
                normalized_request_digest: &request_digest,
                obligation_atom_digest: &receivable.atom.digest()?,
                seller_id: authority.seller_id,
                buyer_id: authority.buyer_id,
                agreement_id: &agreement_id,
                buyer_settlement_destination_ref: authority.buyer_destination,
                effective_at_unix_ms: times.effective,
                action_nonce: request.action_nonce(),
                trust: &bind_trust,
                trusted_now_unix_ms: times.effective,
            },
        )?;
        let seller = Keypair::from_seed(&[authority.seller_seed; 32]);
        let buyer = Keypair::from_seed(&[authority.buyer_seed; 32]);
        let signed_agreement = SignedAssignmentAgreementV1::sign(
            AssignmentAgreementBodyV1::new(
                agreement_id,
                operation.binding().operation_id().as_str().to_owned(),
                &request,
                verified_claim.claim(),
                &offer,
                &verified_bind,
            )?,
            authority.seller_epoch,
            &seller,
            authority.buyer_epoch,
            &buyer,
        )?;
        let agreement_bytes = signed_agreement.canonical_bytes()?;
        let agreement_trust = AssignmentAgreementTrustV1::new(
            authority.seller_id.to_owned(),
            seller.public_key(),
            authority.seller_epoch,
            authority.buyer_id.to_owned(),
            buyer.public_key(),
            authority.buyer_epoch,
        )?;
        let verified_agreement = verify_assignment_agreement(
            &agreement_bytes,
            &AssignmentAgreementVerificationV1 {
                operation_id: operation.binding().operation_id().as_str(),
                normalized_request_digest: &request_digest,
                assignment_authority_digest: verified_bind.envelope_digest(),
                trust: &agreement_trust,
            },
        )?;
        let authorization =
            VerifiedAssignmentAuthorizationSetV1::new(verified_bind, verified_agreement)?;
        let transitions = [
            (
                vec![AdmissionAttachment::SupplementalAuthorizationDigest(
                    AdmissionDigest::try_new(
                        "supplemental_authorization_digest",
                        authorization.digest().to_owned(),
                    )?,
                )],
                None,
            ),
            (Vec::new(), Some(AdmissionOperationState::MutationReady)),
            (Vec::new(), Some(AdmissionOperationState::MutationSubmitted)),
        ];
        for (index, (attachments, state)) in transitions.into_iter().enumerate() {
            let at = times.effective + 1 + u64::try_from(index)?;
            let recovery = fixture.store.claim_recovery(
                operation.binding().operation_id(),
                operation.version(),
                &identifier("claimant_id", "factor-submitter"),
                at,
                at + 1,
                &fixture.fence,
            )?;
            let command = AdmissionOperationCommand::new(
                operation.binding().operation_id().clone(),
                operation.version(),
                recovery,
                attachments,
                state,
                None,
                None,
            )?;
            operation = fixture
                .store
                .compare_and_swap(&command, at)?
                .into_operation();
        }
        Ok(Self {
            operation,
            request,
            claim: verified_claim,
            offer,
            authorization,
            status_proof,
            signing_authority: authority.signing_authority()?,
            commit_at: times.commit_at,
        })
    }

    fn recovery(
        &self,
        store: &SqliteAdmissionOperationStore,
        fence: &StoreMutationFence,
        claimant: &str,
        at: u64,
    ) -> Result<AdmissionRecoveryLease, AdmissionOperationStoreError> {
        store.claim_recovery(
            self.operation.binding().operation_id(),
            self.operation.version(),
            &identifier("claimant_id", claimant),
            at,
            at + 10_000,
            fence,
        )
    }

    fn commit(
        &self,
        store: &SqliteFactorAssignmentStore,
        recovery: &AdmissionRecoveryLease,
        fence: &StoreMutationFence,
        at: u64,
    ) -> Result<DurableFactorAssignmentResultV1, AdmissionOperationStoreError> {
        store.commit_factor_assignment(FactorAssignmentCommitV1 {
            operation: &self.operation,
            recovery_lease: recovery,
            request: &self.request,
            claim: &self.claim,
            offer: &self.offer,
            authorization: &self.authorization,
            status_proof: &self.status_proof,
            signing_authority: &self.signing_authority,
            active_fence: fence,
            trusted_now_unix_ms: at,
        })
    }
}

fn assert_applied(result: &DurableFactorAssignmentResultV1) {
    assert!(matches!(
        result,
        DurableFactorAssignmentResultV1::Applied(_)
    ));
}

fn assert_not_applied(
    result: &DurableFactorAssignmentResultV1,
    expected: AssignmentNotAppliedReasonV1,
) {
    match result {
        DurableFactorAssignmentResultV1::NotApplied(result) => {
            assert_eq!(result.body().reason(), expected);
        }
        DurableFactorAssignmentResultV1::Applied(_) => panic!("assignment unexpectedly applied"),
    }
}

#[test]
fn assignment_commit_is_atomic_and_exact_replay_is_idempotent() -> AnchoredTestResult {
    let fixture = fixture();
    let base = now_ms() + 100;
    let receivable = persist_receivable(&fixture, AUTHORITY_A, "atomic", base)?;
    let factor_store = fixture.store.activate_factor_assignment_authorities(
        registry(&[AUTHORITY_A], &[])?,
        0,
        &fixture.fence,
        base + 1,
    )?;
    let case = FactorCase::new(
        &fixture,
        &receivable,
        AUTHORITY_A,
        "atomic",
        FactorTimes::new(base + 2, base + 5, Expiry::Live),
    )?;
    let recovery = case.recovery(
        &fixture.store,
        &fixture.fence,
        "factor-atomic",
        case.commit_at,
    )?;
    let applied = case.commit(&factor_store, &recovery, &fixture.fence, case.commit_at)?;
    assert_applied(&applied);
    let terminal_operation = fixture
        .store
        .load_by_operation_id(case.operation.binding().operation_id())?
        .ok_or("assignment operation was not retained")?;
    assert_eq!(
        terminal_operation.state(),
        AdmissionOperationState::EconomicMutationApplied
    );
    let stored = factor_store
        .load_factor_assignment_result(case.operation.binding().operation_id())?
        .ok_or("assignment result was not durable")?;
    assert_eq!(stored.observed_head_sequence(), 1);
    assert_eq!(stored.resulting_head_sequence(), 2);
    assert_eq!(stored.result(), &applied);
    assert_eq!(
        stored.authority_configuration_digest(),
        AUTHORITY_A.verification_authority()?.configuration_digest()
    );
    assert_eq!(stored.receipt_digest(), case.claim.receipt_digest());
    assert_eq!(stored.iou_digest(), case.claim.iou_digest());
    let connection = fixture.store.connection()?;
    let evidence: (Vec<u8>, Vec<u8>) = connection.query_row(
        r#"
        SELECT receipt_json, iou_json
        FROM obligation_assignment_results
        WHERE operation_id = ?1
        "#,
        [case.operation.binding().operation_id().as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(evidence.0, case.claim.receipt_canonical_bytes());
    assert_eq!(evidence.1, case.claim.iou_canonical_bytes());
    drop(connection);
    let current = fixture
        .store
        .load_obligation(receivable.atom.obligation_id())?
        .ok_or("assigned obligation disappeared")?;
    assert_eq!(current.head_sequence(), 2);
    assert!(matches!(
        current.disposition().disposition(),
        ObligationDispositionV1::Assigned { creditor_id, .. }
            if creditor_id == AUTHORITY_A.buyer_id
    ));
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(factor_store);
    drop(store);
    drop(authority);

    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fence = authority.mutation_fence();
    let store = authority.admission_operation_store();
    let factor_store = store.activate_factor_assignment_authorities(
        registry(&[AUTHORITY_A], &[])?,
        1,
        &fence,
        case.commit_at + 1,
    )?;
    let assigned = store
        .load_obligation(receivable.atom.obligation_id())?
        .ok_or("assigned obligation disappeared after restart")?;
    let settlement = assigned.settlement_lifecycle().advance(
        assigned.atom(),
        ObligationSettlementTransitionV1::Settle {
            settlement_id: "factor-settlement-atomic".to_owned(),
            evidence_digest: economic_digest("factor-settlement-evidence-atomic"),
            authority_digest: economic_digest("factor-settlement-authority-atomic"),
        },
    )?;
    let settlement_operation = prepared_operation(
        &fence,
        AdmissionOperationKind::GovernedEconomicMutation,
        "factor-settlement-request-atomic",
        "factor-settlement-capability-atomic",
    );
    let settlement_at = case.commit_at + 3;
    store.begin(&settlement_operation, &fence, settlement_at - 1)?;
    let settlement_recovery = store.claim_recovery(
        settlement_operation.binding().operation_id(),
        settlement_operation.version(),
        &identifier("claimant_id", "factor-settlement-worker"),
        settlement_at,
        settlement_at + 10_000,
        &fence,
    )?;
    let participant_digest = economic_digest("factor-settlement-participant-atomic");
    let mut connection = store.connection()?;
    let transaction = store.begin_write(&mut connection, Some(&fence))?;
    append_participant_update_tx(
        &transaction,
        &store.serving_owner,
        &settlement_operation,
        &settlement_recovery,
        &participant_digest,
        settlement_at,
    )?;
    super::super::obligation::append_obligation_settlement_transition(
        &transaction,
        settlement_operation.binding().operation_id(),
        assigned.atom(),
        assigned.disposition(),
        assigned.settlement_lifecycle(),
        &settlement,
        assigned.snapshot_version(),
        assigned.resource_fence(),
        &participant_digest,
        settlement_at,
        &fence,
    )?;
    store.commit_write(transaction)?;
    store.sync_after_write(&connection)?;
    drop(connection);
    let later = store
        .load_obligation(receivable.atom.obligation_id())?
        .ok_or("settled obligation disappeared")?;
    assert_eq!(later.head_sequence(), 3);
    assert_eq!(later.settlement_lifecycle(), &settlement);
    let later_head_digest = later.head_digest().to_owned();

    let loaded = factor_store
        .load_factor_assignment_result(case.operation.binding().operation_id())?
        .ok_or("assignment result disappeared after later settlement")?;
    assert_eq!(loaded.result(), &applied);
    let replayed = case.commit(&factor_store, &recovery, &fence, case.commit_at + 4)?;
    assert_eq!(replayed, applied);
    let current = store
        .load_obligation(receivable.atom.obligation_id())?
        .ok_or("settled obligation disappeared after assignment replay")?;
    assert_eq!(current.head_sequence(), 3);
    assert_eq!(current.head_digest(), later_head_digest);
    let connection = store.connection()?;
    let (results, heads): (i64, i64) = connection.query_row(
        r#"
        SELECT
            (SELECT COUNT(*) FROM obligation_assignment_results WHERE operation_id = ?1),
            (SELECT COUNT(*) FROM obligation_head_commits WHERE obligation_id = ?2)
        "#,
        params![
            case.operation.binding().operation_id().as_str(),
            receivable.atom.obligation_id()
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!((results, heads), (1, 3));
    drop(_temp);
    Ok(())
}

#[test]
fn terminal_projection_failure_rolls_back_assignment_and_result() -> AnchoredTestResult {
    let fixture = fixture();
    let base = now_ms() + 100;
    let receivable = persist_receivable(&fixture, AUTHORITY_A, "terminal-rollback", base)?;
    let factor_store = fixture.store.activate_factor_assignment_authorities(
        registry(&[AUTHORITY_A], &[])?,
        0,
        &fixture.fence,
        base + 1,
    )?;
    let case = FactorCase::new(
        &fixture,
        &receivable,
        AUTHORITY_A,
        "terminal-rollback",
        FactorTimes::new(base + 2, base + 5, Expiry::Live),
    )?;
    let recovery = case.recovery(
        &fixture.store,
        &fixture.fence,
        "factor-terminal-rollback",
        case.commit_at,
    )?;
    {
        let connection = fixture.store.connection()?;
        connection.execute_batch(
            r#"
            CREATE TRIGGER reject_factor_terminal_projection
            BEFORE INSERT ON admission_operation_terminal_records
            WHEN NEW.record_kind = 'economic_mutation_result'
            BEGIN
                SELECT RAISE(ABORT, 'injected terminal projection failure');
            END;
            "#,
        )?;
    }
    assert!(case
        .commit(&factor_store, &recovery, &fixture.fence, case.commit_at)
        .is_err());
    let unchanged = fixture
        .store
        .load_obligation(receivable.atom.obligation_id())?
        .ok_or("obligation disappeared after rollback")?;
    assert_eq!(unchanged.head_sequence(), 1);
    assert_eq!(unchanged.disposition(), &receivable.disposition);
    assert!(factor_store
        .load_factor_assignment_result(case.operation.binding().operation_id())?
        .is_none());
    let operation = fixture
        .store
        .load_by_operation_id(case.operation.binding().operation_id())?
        .ok_or("assignment operation disappeared after rollback")?;
    assert_eq!(operation, case.operation);
    {
        let connection = fixture.store.connection()?;
        connection.execute_batch("DROP TRIGGER reject_factor_terminal_projection;")?;
    }
    let applied = case.commit(&factor_store, &recovery, &fixture.fence, case.commit_at)?;
    assert_applied(&applied);
    Ok(())
}

#[test]
fn stale_status_produces_durable_not_applied_without_advancing_the_head() -> AnchoredTestResult {
    let fixture = fixture();
    let base = now_ms() + 100;
    let receivable = persist_receivable(&fixture, AUTHORITY_A, "stale", base)?;
    let factor_store = fixture.store.activate_factor_assignment_authorities(
        registry(&[AUTHORITY_A], &[])?,
        0,
        &fixture.fence,
        base + 1,
    )?;
    let first = FactorCase::new(
        &fixture,
        &receivable,
        AUTHORITY_A,
        "stale-first",
        FactorTimes::new(base + 2, base + 5, Expiry::Live),
    )?;
    let second = FactorCase::new(
        &fixture,
        &receivable,
        AUTHORITY_A,
        "stale-second",
        FactorTimes::new(base + 3, base + 15, Expiry::Live),
    )?;
    let first_at = base + 20;
    let first_recovery = first.recovery(
        &fixture.store,
        &fixture.fence,
        "factor-stale-first",
        first_at,
    )?;
    assert_applied(&first.commit(&factor_store, &first_recovery, &fixture.fence, first_at)?);
    let before = fixture
        .store
        .load_obligation(receivable.atom.obligation_id())?
        .ok_or("assigned obligation disappeared")?;
    let second_at = base + 21;
    let second_recovery = second.recovery(
        &fixture.store,
        &fixture.fence,
        "factor-stale-second",
        second_at,
    )?;
    let not_applied = second.commit(&factor_store, &second_recovery, &fixture.fence, second_at)?;
    assert_not_applied(&not_applied, AssignmentNotAppliedReasonV1::AlreadyAssigned);
    let terminal_operation = fixture
        .store
        .load_by_operation_id(second.operation.binding().operation_id())?
        .ok_or("not-applied operation was not retained")?;
    assert_eq!(
        terminal_operation.state(),
        AdmissionOperationState::EconomicMutationNotApplied
    );
    let after = fixture
        .store
        .load_obligation(receivable.atom.obligation_id())?
        .ok_or("assigned obligation disappeared")?;
    assert_eq!(after.head_sequence(), before.head_sequence());
    assert_eq!(after.head_digest(), before.head_digest());
    let stored = factor_store
        .load_factor_assignment_result(second.operation.binding().operation_id())?
        .ok_or("not-applied result was not durable")?;
    assert_eq!(
        stored.observed_head_sequence(),
        stored.resulting_head_sequence()
    );
    assert_eq!(
        stored.observed_head_digest(),
        stored.resulting_head_digest()
    );
    Ok(())
}

#[test]
fn expiry_reasons_are_distinct_and_durable() -> AnchoredTestResult {
    for (suffix, expiry, expected) in [
        (
            "authorization-expired",
            Expiry::Authorization,
            AssignmentNotAppliedReasonV1::AuthorizationExpired,
        ),
        (
            "request-expired",
            Expiry::Request,
            AssignmentNotAppliedReasonV1::RequestExpired,
        ),
        (
            "offer-expired",
            Expiry::Offer,
            AssignmentNotAppliedReasonV1::OfferExpired,
        ),
    ] {
        let fixture = fixture();
        let base = now_ms() + 100;
        let receivable = persist_receivable(&fixture, AUTHORITY_A, suffix, base)?;
        let factor_store = fixture.store.activate_factor_assignment_authorities(
            registry(&[AUTHORITY_A], &[])?,
            0,
            &fixture.fence,
            base + 1,
        )?;
        let case = FactorCase::new(
            &fixture,
            &receivable,
            AUTHORITY_A,
            suffix,
            FactorTimes::new(base + 2, base + 5, expiry),
        )?;
        let recovery = case.recovery(&fixture.store, &fixture.fence, suffix, case.commit_at)?;
        let result = case.commit(&factor_store, &recovery, &fixture.fence, case.commit_at)?;
        assert_not_applied(&result, expected);
        let current = fixture
            .store
            .load_obligation(receivable.atom.obligation_id())?
            .ok_or("unassigned obligation disappeared")?;
        assert_eq!(current.head_sequence(), 1);
        assert!(factor_store
            .load_factor_assignment_result(case.operation.binding().operation_id())?
            .is_some());
    }
    Ok(())
}

#[test]
fn serving_owner_rotation_fences_stale_recovery_then_accepts_a_new_claim() -> AnchoredTestResult {
    let fixture = fixture();
    let base = now_ms() + 100;
    let receivable = persist_receivable(&fixture, AUTHORITY_A, "owner-rotation", base)?;
    let factor_store = fixture.store.activate_factor_assignment_authorities(
        registry(&[AUTHORITY_A], &[])?,
        0,
        &fixture.fence,
        base + 1,
    )?;
    let case = FactorCase::new(
        &fixture,
        &receivable,
        AUTHORITY_A,
        "owner-rotation",
        FactorTimes::new(base + 2, base + 5, Expiry::Live),
    )?;
    let stale_recovery = case.recovery(
        &fixture.store,
        &fixture.fence,
        "factor-old-owner",
        case.commit_at,
    )?;
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(factor_store);
    drop(store);
    drop(authority);

    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fence = authority.mutation_fence();
    let store = authority.admission_operation_store();
    let factor_store = store.activate_factor_assignment_authorities(
        registry(&[AUTHORITY_A], &[])?,
        1,
        &fence,
        case.commit_at + 1,
    )?;
    assert!(matches!(
        case.commit(&factor_store, &stale_recovery, &fence, case.commit_at + 2),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    let recovery = case.recovery(&store, &fence, "factor-new-owner", case.commit_at + 3)?;
    let applied = case.commit(&factor_store, &recovery, &fence, case.commit_at + 3)?;
    assert_applied(&applied);
    drop(_temp);
    Ok(())
}

#[test]
fn retained_configuration_replays_after_claim_trust_rotation_with_shared_coordinates(
) -> AnchoredTestResult {
    let fixture = fixture();
    let base = now_ms() + 100;
    let receivable = persist_receivable(&fixture, AUTHORITY_A, "retained", base)?;
    let factor_store = fixture.store.activate_factor_assignment_authorities(
        registry(&[AUTHORITY_A], &[])?,
        0,
        &fixture.fence,
        base + 1,
    )?;
    let case = FactorCase::new(
        &fixture,
        &receivable,
        AUTHORITY_A,
        "retained",
        FactorTimes::new(base + 2, base + 5, Expiry::Live),
    )?;
    let recovery = case.recovery(
        &fixture.store,
        &fixture.fence,
        "factor-retained",
        case.commit_at,
    )?;
    let applied = case.commit(&factor_store, &recovery, &fixture.fence, case.commit_at)?;
    assert_applied(&applied);
    let original = AUTHORITY_A.verification_authority()?;
    let rotated_authority =
        AUTHORITY_A.verification_authority_with_claim_trust(claim_trust(true)?)?;
    let rotated = fixture.store.activate_factor_assignment_authorities(
        FactorAssignmentAuthorityRegistryV1::new([rotated_authority], [original])?,
        1,
        &fixture.fence,
        case.commit_at + 1,
    )?;
    let replayed = case.commit(&rotated, &recovery, &fixture.fence, case.commit_at + 2)?;
    assert_eq!(replayed, applied);
    assert_eq!(
        rotated
            .load_factor_assignment_result(case.operation.binding().operation_id())?
            .ok_or("retained result disappeared")?
            .result(),
        &applied
    );
    Ok(())
}

#[test]
fn authority_generation_fences_stale_clone_across_aba_rotation() -> AnchoredTestResult {
    let fixture = fixture();
    let base = now_ms() + 100;
    let receivable = persist_receivable(&fixture, AUTHORITY_A, "aba", base)?;
    let stale = fixture.store.activate_factor_assignment_authorities(
        registry(&[AUTHORITY_A], &[])?,
        0,
        &fixture.fence,
        base + 1,
    )?;
    let stale_clone = stale.clone();
    fixture.store.activate_factor_assignment_authorities(
        registry(&[AUTHORITY_B], &[])?,
        1,
        &fixture.fence,
        base + 2,
    )?;
    let current = fixture.store.activate_factor_assignment_authorities(
        registry(&[AUTHORITY_A], &[])?,
        2,
        &fixture.fence,
        base + 3,
    )?;
    let case = FactorCase::new(
        &fixture,
        &receivable,
        AUTHORITY_A,
        "aba",
        FactorTimes::new(base + 4, base + 7, Expiry::Live),
    )?;
    let recovery = case.recovery(&fixture.store, &fixture.fence, "factor-aba", case.commit_at)?;
    assert!(matches!(
        case.commit(&stale_clone, &recovery, &fixture.fence, case.commit_at),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    assert_applied(&case.commit(&current, &recovery, &fixture.fence, case.commit_at)?);
    let head = fixture
        .store
        .factor_assignment_authority_set_head()?
        .ok_or("authority set head disappeared")?;
    assert_eq!(head.generation(), 3);
    assert_eq!(
        head.digest(),
        registry(&[AUTHORITY_A], &[])?.active_set_digest()
    );
    Ok(())
}

#[test]
fn stored_result_tampering_is_rejected_on_load_and_retry() -> AnchoredTestResult {
    let fixture = fixture();
    let base = now_ms() + 100;
    let receivable = persist_receivable(&fixture, AUTHORITY_A, "tamper", base)?;
    let factor_store = fixture.store.activate_factor_assignment_authorities(
        registry(&[AUTHORITY_A], &[])?,
        0,
        &fixture.fence,
        base + 1,
    )?;
    let case = FactorCase::new(
        &fixture,
        &receivable,
        AUTHORITY_A,
        "tamper",
        FactorTimes::new(base + 2, base + 5, Expiry::Live),
    )?;
    let recovery = case.recovery(
        &fixture.store,
        &fixture.fence,
        "factor-tamper",
        case.commit_at,
    )?;
    assert_applied(&case.commit(&factor_store, &recovery, &fixture.fence, case.commit_at)?);
    {
        let connection = fixture.store.connection()?;
        connection.execute_batch("DROP TRIGGER obligation_assignment_results_immutable")?;
        connection.execute(
            "UPDATE obligation_assignment_results SET result_json = X'7b7d' WHERE operation_id = ?1",
            [case.operation.binding().operation_id().as_str()],
        )?;
    }
    assert!(factor_store
        .load_factor_assignment_result(case.operation.binding().operation_id())
        .is_err());
    assert!(case
        .commit(&factor_store, &recovery, &fixture.fence, case.commit_at + 1,)
        .is_err());
    Ok(())
}

#[test]
fn stored_claim_evidence_and_authority_configuration_tampering_is_rejected() -> AnchoredTestResult {
    for suffix in ["receipt", "iou", "configuration"] {
        let fixture = fixture();
        let base = now_ms() + 100;
        let receivable = persist_receivable(&fixture, AUTHORITY_A, suffix, base)?;
        let factor_store = fixture.store.activate_factor_assignment_authorities(
            registry(&[AUTHORITY_A], &[])?,
            0,
            &fixture.fence,
            base + 1,
        )?;
        let case = FactorCase::new(
            &fixture,
            &receivable,
            AUTHORITY_A,
            suffix,
            FactorTimes::new(base + 2, base + 5, Expiry::Live),
        )?;
        let recovery = case.recovery(&fixture.store, &fixture.fence, suffix, case.commit_at)?;
        assert_applied(&case.commit(&factor_store, &recovery, &fixture.fence, case.commit_at)?);
        let connection = fixture.store.connection()?;
        connection.execute_batch("DROP TRIGGER obligation_assignment_results_immutable")?;
        match suffix {
            "receipt" => {
                connection.execute(
                    "UPDATE obligation_assignment_results SET receipt_json = X'7b7d' WHERE operation_id = ?1",
                    [case.operation.binding().operation_id().as_str()],
                )?;
            }
            "iou" => {
                connection.execute(
                    "UPDATE obligation_assignment_results SET iou_json = X'7b7d' WHERE operation_id = ?1",
                    [case.operation.binding().operation_id().as_str()],
                )?;
            }
            "configuration" => {
                connection.execute(
                    "UPDATE obligation_assignment_results SET authority_configuration_digest = ?1 WHERE operation_id = ?2",
                    params!["0".repeat(64), case.operation.binding().operation_id().as_str()],
                )?;
            }
            _ => return Err("unknown factor tamper fixture".into()),
        }
        drop(connection);
        assert!(factor_store
            .load_factor_assignment_result(case.operation.binding().operation_id())
            .is_err());
        assert!(case
            .commit(&factor_store, &recovery, &fixture.fence, case.commit_at + 1,)
            .is_err());
    }
    Ok(())
}

#[test]
fn registry_rejects_conflicting_keys_for_one_authority_epoch() -> AnchoredTestResult {
    let conflicting = AuthoritySpec {
        result_seed: 99,
        ..AUTHORITY_B
    };
    let error = match registry(&[AUTHORITY_A, conflicting], &[]) {
        Ok(_) => return Err("conflicting authority key was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error, FactorError::InvalidField("authority_key"));
    Ok(())
}

#[test]
fn registry_rejects_two_active_configurations_with_shared_coordinates() -> AnchoredTestResult {
    let original = AUTHORITY_A.verification_authority()?;
    let alternate = AUTHORITY_A.verification_authority_with_claim_trust(claim_trust(true)?)?;
    let error = match FactorAssignmentAuthorityRegistryV1::new(
        [original, alternate],
        std::iter::empty::<FactorAssignmentVerificationAuthorityV1>(),
    ) {
        Ok(_) => return Err("duplicate active authority coordinate was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error, FactorError::InvalidField("authority_coordinate"));
    Ok(())
}
