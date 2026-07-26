use std::error::Error;
use std::sync::{Arc, Mutex};

use chio_core_types::capability::runtime_attestation::RuntimeAssuranceTier;
use chio_core_types::capability::scope::{ChioScope, MonetaryAmount, Operation, ToolGrant};
use chio_core_types::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core_types::crypto::Keypair;
use chio_credit::obligation::{
    verify_credit_facility_bind, ConfiguredCreditAuthorityArtifactV1,
    ConfiguredCreditAuthorityResolverV1, CreditAdmissionError, CreditAdmissionStore,
    CreditAdmissionStoreAdapter, CreditAuthorityKindV1, CreditAuthorityResolutionRequestV1,
    CreditAuthorityResolverConfigurationV1, CreditAuthoritySourceV1,
    CreditExposureReservationRecordV1, CreditExposureReservationRequest, CreditFacilityBindBodyV1,
    CreditFacilityBindInputV1, CreditFacilityBindTrustInputV1, CreditFacilityBindTrustV1,
    CreditFacilityBindVerificationContextV1, ObligationAtomV1, SignedCreditFacilityBindV1,
    VerifiedCreditFacilityBindV1,
};
use chio_credit::{
    CreditFacilityArtifact, CreditFacilityCapitalSource, CreditFacilityDisposition,
    CreditFacilityLifecycleState, CreditFacilityPrerequisites, CreditFacilityReport,
    CreditFacilitySupportBoundary, CreditFacilityTerms, CreditScorecardBand,
    CreditScorecardConfidence, CreditScorecardSummary, ExposureLedgerQuery, SignedCreditFacility,
    CREDIT_FACILITY_ARTIFACT_SCHEMA, CREDIT_FACILITY_REPORT_SCHEMA,
};

pub type TestResult<T> = Result<T, Box<dyn Error>>;

const FACILITY_AUTHORITY_ID: &str = "test-credit-facility-authority";
const CAPABILITY_AUTHORITY_ID: &str = "test-credit-capability-authority";

pub struct CreditAdmissionInput<'a> {
    pub operation_id: &'a str,
    pub request_id: &'a str,
    pub action_nonce: &'a str,
    pub economic_intent_digest: &'a str,
    pub facility_id: &'a str,
    pub debtor_id: &'a str,
    pub original_creditor_id: &'a str,
    pub original_settlement_destination_ref: &'a str,
    pub capability_id: &'a str,
    pub tool_server: &'a str,
    pub tool_name: &'a str,
    pub amount: MonetaryAmount,
    pub expected_exposure_version: u64,
    pub due_at_unix_ms: u64,
    pub bind_issued_at_unix_ms: u64,
    pub bind_expires_at_unix_ms: u64,
    pub trusted_at_unix_ms: u64,
    pub bind_authority_id: &'a str,
    pub bind_authority_epoch: u64,
    pub debtor_key_epoch: u64,
    pub creditor_key_epoch: u64,
    pub bind_authority: &'a Keypair,
    pub debtor: &'a Keypair,
    pub creditor: &'a Keypair,
}

pub struct PreparedCreditAdmission {
    request: CreditExposureReservationRequest,
    bind_trust: CreditFacilityBindTrustV1,
}

impl PreparedCreditAdmission {
    pub fn new(input: CreditAdmissionInput<'_>) -> TestResult<Self> {
        let resolved_at_unix_seconds = input.trusted_at_unix_ms / 1_000;
        let authority_expires_at_unix_seconds = input
            .bind_expires_at_unix_ms
            .checked_add(999)
            .ok_or(CreditAdmissionError::ArithmeticOverflow)?
            / 1_000;
        if resolved_at_unix_seconds == 0
            || authority_expires_at_unix_seconds <= resolved_at_unix_seconds
        {
            return Err(CreditAdmissionError::AuthorityNotCurrent.into());
        }
        let facility_authority = Keypair::from_seed(&[201; 32]);
        let capability_authority = Keypair::from_seed(&[202; 32]);
        let authority_lifetime = authority_expires_at_unix_seconds
            .checked_sub(resolved_at_unix_seconds)
            .ok_or(CreditAdmissionError::ArithmeticOverflow)?;
        let facility = SignedCreditFacility::sign(
            CreditFacilityArtifact {
                schema: CREDIT_FACILITY_ARTIFACT_SCHEMA.to_owned(),
                facility_id: input.facility_id.to_owned(),
                issued_at: resolved_at_unix_seconds,
                expires_at: authority_expires_at_unix_seconds,
                lifecycle_state: CreditFacilityLifecycleState::Active,
                supersedes_facility_id: None,
                report: CreditFacilityReport {
                    schema: CREDIT_FACILITY_REPORT_SCHEMA.to_owned(),
                    generated_at: resolved_at_unix_seconds,
                    filters: ExposureLedgerQuery {
                        capability_id: Some(input.capability_id.to_owned()),
                        agent_subject: Some(input.debtor_id.to_owned()),
                        tool_server: Some(input.tool_server.to_owned()),
                        tool_name: Some(input.tool_name.to_owned()),
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
                        currencies: vec![input.amount.currency.clone()],
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
                        credit_limit: input.amount.clone(),
                        utilization_ceiling_bps: 10_000,
                        reserve_ratio_bps: 0,
                        concentration_cap_bps: 10_000,
                        ttl_seconds: authority_lifetime,
                        capital_source: CreditFacilityCapitalSource::OperatorInternal,
                    }),
                    findings: Vec::new(),
                },
            },
            &facility_authority,
        )?;
        let capability = CapabilityToken::sign(
            CapabilityTokenBody {
                id: input.capability_id.to_owned(),
                issuer: capability_authority.public_key(),
                subject: input.debtor.public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: input.tool_server.to_owned(),
                        tool_name: input.tool_name.to_owned(),
                        operations: vec![Operation::Invoke],
                        constraints: Vec::new(),
                        max_invocations: None,
                        max_cost_per_invocation: Some(input.amount.clone()),
                        max_total_cost: Some(input.amount.clone()),
                        dpop_required: None,
                    }],
                    resource_grants: Vec::new(),
                    prompt_grants: Vec::new(),
                },
                issued_at: resolved_at_unix_seconds,
                expires_at: authority_expires_at_unix_seconds,
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
                        authority_id: FACILITY_AUTHORITY_ID.to_owned(),
                        authority_key: facility_authority.public_key(),
                        authority_epoch: 1,
                    },
                    CreditAuthoritySourceV1 {
                        kind: CreditAuthorityKindV1::Capability,
                        authority_id: CAPABILITY_AUTHORITY_ID.to_owned(),
                        authority_key: capability_authority.public_key(),
                        authority_epoch: 1,
                    },
                ],
                complete_artifact_catalog: vec![
                    ConfiguredCreditAuthorityArtifactV1::Facility {
                        authority_id: FACILITY_AUTHORITY_ID.to_owned(),
                        authority_epoch: 1,
                        signed: Box::new(facility),
                    },
                    ConfiguredCreditAuthorityArtifactV1::Capability {
                        authority_id: CAPABILITY_AUTHORITY_ID.to_owned(),
                        authority_epoch: 1,
                        signed: Box::new(capability),
                    },
                ],
            })?;
        let authorities = resolver.resolve(&CreditAuthorityResolutionRequestV1 {
            debtor_id: input.debtor_id.to_owned(),
            debtor_key: input.debtor.public_key(),
            capability_id: input.capability_id.to_owned(),
            tool_server: input.tool_server.to_owned(),
            tool_name: input.tool_name.to_owned(),
            currency: input.amount.currency.clone(),
            trusted_at_unix_seconds: resolved_at_unix_seconds,
        })?;
        let facility_evidence = authorities
            .evidence()
            .iter()
            .find(|evidence| evidence.kind() == CreditAuthorityKindV1::Facility)
            .ok_or(CreditAdmissionError::IncompleteAuthoritySet)?;
        let bind_trust = CreditFacilityBindTrustV1::new(CreditFacilityBindTrustInputV1 {
            authority_id: input.bind_authority_id.to_owned(),
            authority_key: input.bind_authority.public_key(),
            authority_key_epoch: input.bind_authority_epoch,
            debtor_id: input.debtor_id.to_owned(),
            debtor_key: input.debtor.public_key(),
            debtor_key_epoch: input.debtor_key_epoch,
            creditor_id: input.original_creditor_id.to_owned(),
            creditor_key: input.creditor.public_key(),
            creditor_key_epoch: input.creditor_key_epoch,
            max_lifetime_ms: input
                .bind_expires_at_unix_ms
                .checked_sub(input.bind_issued_at_unix_ms)
                .ok_or(CreditAdmissionError::ArithmeticOverflow)?,
        })?;
        let signed_bind = SignedCreditFacilityBindV1::sign(
            CreditFacilityBindBodyV1::new(CreditFacilityBindInputV1 {
                operation_id: input.operation_id.to_owned(),
                request_id: input.request_id.to_owned(),
                economic_intent_digest: input.economic_intent_digest.to_owned(),
                facility_id: input.facility_id.to_owned(),
                facility_artifact_digest: facility_evidence.artifact_digest().to_owned(),
                authority_set_digest: authorities.authority_set_digest().to_owned(),
                debtor_id: input.debtor_id.to_owned(),
                original_creditor_id: input.original_creditor_id.to_owned(),
                original_settlement_destination_ref: input
                    .original_settlement_destination_ref
                    .to_owned(),
                capability_id: input.capability_id.to_owned(),
                tool_server: input.tool_server.to_owned(),
                tool_name: input.tool_name.to_owned(),
                amount: input.amount.clone(),
                effective_ceiling: authorities.effective_ceiling().clone(),
                expected_exposure_version: input.expected_exposure_version,
                expected_exposure_fence: input.expected_exposure_version,
                due_at_unix_ms: input.due_at_unix_ms,
                action_nonce: input.action_nonce.to_owned(),
                issued_at_unix_ms: input.bind_issued_at_unix_ms,
                expires_at_unix_ms: input.bind_expires_at_unix_ms,
                authority_id: input.bind_authority_id.to_owned(),
                authority_key_epoch: input.bind_authority_epoch,
                debtor_key_epoch: input.debtor_key_epoch,
                creditor_key_epoch: input.creditor_key_epoch,
            })?,
            input.bind_authority,
            input.debtor,
            input.creditor,
        )?;
        let canonical_bind = signed_bind.canonical_bytes()?;
        let credit_facility_bind = verify_credit_facility_bind(
            &canonical_bind,
            &CreditFacilityBindVerificationContextV1 {
                trust: &bind_trust,
                trusted_at_unix_ms: input.trusted_at_unix_ms,
            },
        )?;
        let request = CreditExposureReservationRequest {
            operation_id: input.operation_id.to_owned(),
            request_id: input.request_id.to_owned(),
            action_nonce: input.action_nonce.to_owned(),
            economic_intent_digest: input.economic_intent_digest.to_owned(),
            debtor_id: input.debtor_id.to_owned(),
            amount: input.amount,
            authorities,
            credit_facility_bind,
        };
        request.validate()?;
        Ok(Self {
            request,
            bind_trust,
        })
    }

    pub fn credit_facility_bind(&self) -> &VerifiedCreditFacilityBindV1 {
        &self.request.credit_facility_bind
    }

    pub fn bind_trust(&self) -> &CreditFacilityBindTrustV1 {
        &self.bind_trust
    }

    pub fn committed_record(
        &self,
        atom: &ObligationAtomV1,
    ) -> Result<CreditExposureReservationRecordV1, CreditAdmissionError> {
        let source_version = self
            .request
            .credit_facility_bind
            .body()
            .expected_exposure_version();
        let reserved_version = source_version
            .checked_add(1)
            .ok_or(CreditAdmissionError::ArithmeticOverflow)?;
        let committed_version = reserved_version
            .checked_add(1)
            .ok_or(CreditAdmissionError::ArithmeticOverflow)?;
        CreditExposureReservationRecordV1::prepare_reserved(
            &self.request,
            reserved_version,
            reserved_version,
        )?
        .prepare_committed(atom, committed_version, committed_version)
    }
}

#[derive(Clone)]
pub struct TestCreditAdmissionStore {
    response: Arc<Mutex<Result<Option<CreditExposureReservationRecordV1>, String>>>,
}

impl TestCreditAdmissionStore {
    pub fn committed(record: CreditExposureReservationRecordV1) -> Self {
        Self {
            response: Arc::new(Mutex::new(Ok(Some(record)))),
        }
    }

    pub fn replace(
        &self,
        record: CreditExposureReservationRecordV1,
    ) -> Result<(), CreditAdmissionError> {
        *self
            .response
            .lock()
            .map_err(|error| CreditAdmissionError::Store(error.to_string()))? = Ok(Some(record));
        Ok(())
    }

    pub fn record(
        &self,
    ) -> Result<Option<CreditExposureReservationRecordV1>, CreditAdmissionError> {
        self.response
            .lock()
            .map_err(|error| CreditAdmissionError::Store(error.to_string()))?
            .clone()
            .map_err(CreditAdmissionError::Store)
    }

    pub fn clear(&self) -> Result<(), CreditAdmissionError> {
        *self
            .response
            .lock()
            .map_err(|error| CreditAdmissionError::Store(error.to_string()))? = Ok(None);
        Ok(())
    }

    pub fn fail(&self, detail: &str) -> Result<(), CreditAdmissionError> {
        *self
            .response
            .lock()
            .map_err(|error| CreditAdmissionError::Store(error.to_string()))? =
            Err(detail.to_owned());
        Ok(())
    }

    pub fn adapter(&self) -> CreditAdmissionStoreAdapter<Self> {
        CreditAdmissionStoreAdapter::new(self.clone())
    }
}

impl CreditAdmissionStore for TestCreditAdmissionStore {
    fn lookup_record_by_operation(
        &self,
        _operation_id: &str,
    ) -> Result<Option<CreditExposureReservationRecordV1>, CreditAdmissionError> {
        self.response
            .lock()
            .map_err(|error| CreditAdmissionError::Store(error.to_string()))?
            .clone()
            .map_err(CreditAdmissionError::Store)
    }
}
