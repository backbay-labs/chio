use chio_core_types::capability::scope::{ChioScope, MonetaryAmount, Operation, ToolGrant};
use chio_core_types::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_credit::obligation::{
    credit_facility_scope_digest, derive_obligation_payee_binding_digest,
    verify_credit_facility_bind, ConfiguredCreditAuthorityArtifactV1,
    ConfiguredCreditAuthorityResolverV1, CreditAdmissionError, CreditAdmissionStore,
    CreditAdmissionStoreAdapter, CreditAuthorityKindV1, CreditAuthorityResolutionRequestV1,
    CreditAuthorityResolverConfigurationV1, CreditAuthoritySourceV1,
    CreditExposureReservationRecordV1, CreditExposureReservationRequest,
    CreditExposureReservationStateV1, CreditFacilityBindBodyV1, CreditFacilityBindInputV1,
    CreditFacilityBindTrustInputV1, CreditFacilityBindTrustV1,
    CreditFacilityBindVerificationContextV1, ObligationAtomInputV1, ObligationAtomV1,
    ObligationCreditElectionV1, SignedCreditFacilityBindV1, VerifiedCreditFacilityBindV1,
};
use chio_credit::{
    CreditFacilityArtifact, CreditFacilityCapitalSource, CreditFacilityDisposition,
    CreditFacilityLifecycleState, CreditFacilityPrerequisites, CreditFacilityReport,
    CreditFacilitySupportBoundary, CreditFacilityTerms, CreditScorecardBand,
    CreditScorecardConfidence, CreditScorecardSummary, ExposureLedgerQuery, SignedCreditFacility,
    CREDIT_FACILITY_ARTIFACT_SCHEMA, CREDIT_FACILITY_REPORT_SCHEMA,
};
use std::sync::{Arc, Mutex};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const DEBTOR_ID: &str = "did:chio:debtor";
const CAPABILITY_ID: &str = "capability-credit-1";
const TOOL_SERVER: &str = "tools.credit.example";
const TOOL_NAME: &str = "metered-search";
const FACILITY_AUTHORITY_ID: &str = "facility-authority";
const CAPABILITY_AUTHORITY_ID: &str = "capability-authority";
const BIND_AUTHORITY_ID: &str = "credit-admission-authority";
const CREDITOR_ID: &str = "did:chio:creditor";
const CREDITOR_DESTINATION: &str = "bank:creditor:operating";
const ISSUED_AT: u64 = 1_700_000_000;
const NOW: u64 = 1_700_000_100;
const EXPIRES_AT: u64 = 1_700_001_000;

struct Fixture {
    facility_authority: Keypair,
    capability_authority: Keypair,
    bind_authority: Keypair,
    debtor: Keypair,
    creditor: Keypair,
    facility: SignedCreditFacility,
    capability: CapabilityToken,
}

fn amount(units: u64, currency: &str) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: currency.to_owned(),
    }
}

fn summary() -> CreditScorecardSummary {
    CreditScorecardSummary {
        matching_receipts: 10,
        returned_receipts: 10,
        matching_decisions: 2,
        returned_decisions: 2,
        currencies: vec!["USD".to_owned()],
        mixed_currency_book: false,
        confidence: CreditScorecardConfidence::High,
        band: CreditScorecardBand::Prime,
        overall_score: 0.95,
        anomaly_count: 0,
        probationary: false,
    }
}

fn signed_facility(
    signer: &Keypair,
    facility_id: &str,
    credit_limit_units: u64,
    utilization_ceiling_bps: u16,
    expires_at: u64,
) -> TestResult<SignedCreditFacility> {
    Ok(SignedCreditFacility::sign(
        CreditFacilityArtifact {
            schema: CREDIT_FACILITY_ARTIFACT_SCHEMA.to_owned(),
            facility_id: facility_id.to_owned(),
            issued_at: ISSUED_AT,
            expires_at,
            lifecycle_state: CreditFacilityLifecycleState::Active,
            supersedes_facility_id: None,
            report: CreditFacilityReport {
                schema: CREDIT_FACILITY_REPORT_SCHEMA.to_owned(),
                generated_at: ISSUED_AT,
                filters: ExposureLedgerQuery {
                    capability_id: Some(CAPABILITY_ID.to_owned()),
                    agent_subject: Some(DEBTOR_ID.to_owned()),
                    tool_server: Some(TOOL_SERVER.to_owned()),
                    tool_name: Some(TOOL_NAME.to_owned()),
                    since: None,
                    until: None,
                    receipt_limit: None,
                    decision_limit: None,
                },
                scorecard: summary(),
                disposition: CreditFacilityDisposition::Grant,
                prerequisites: CreditFacilityPrerequisites {
                    minimum_runtime_assurance_tier:
                        chio_core_types::capability::runtime_attestation::RuntimeAssuranceTier::Verified,
                    runtime_assurance_met: true,
                    certification_required: false,
                    certification_met: true,
                    manual_review_required: false,
                },
                support_boundary: CreditFacilitySupportBoundary::default(),
                terms: Some(CreditFacilityTerms {
                    credit_limit: amount(credit_limit_units, "USD"),
                    utilization_ceiling_bps,
                    reserve_ratio_bps: 1_000,
                    concentration_cap_bps: 5_000,
                    ttl_seconds: expires_at - ISSUED_AT,
                    capital_source: CreditFacilityCapitalSource::OperatorInternal,
                }),
                findings: Vec::new(),
            },
        },
        signer,
    )?)
}

fn signed_capability(
    authority: &Keypair,
    debtor: &Keypair,
    capability_id: &str,
    server_id: &str,
    ceiling_units: u64,
    expires_at: u64,
) -> TestResult<CapabilityToken> {
    Ok(CapabilityToken::sign(
        CapabilityTokenBody {
            id: capability_id.to_owned(),
            issuer: authority.public_key(),
            subject: debtor.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: server_id.to_owned(),
                    tool_name: TOOL_NAME.to_owned(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: Some(amount(2_000, "USD")),
                    max_total_cost: Some(amount(ceiling_units, "USD")),
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            issued_at: ISSUED_AT,
            expires_at,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        authority,
    )?)
}

fn fixture() -> TestResult<Fixture> {
    let facility_authority = Keypair::from_seed(&[31; 32]);
    let capability_authority = Keypair::from_seed(&[32; 32]);
    let debtor = Keypair::from_seed(&[33; 32]);
    let bind_authority = Keypair::from_seed(&[34; 32]);
    let creditor = Keypair::from_seed(&[35; 32]);
    let facility = signed_facility(
        &facility_authority,
        "facility-working-capital",
        9_000,
        8_000,
        EXPIRES_AT,
    )?;
    let capability = signed_capability(
        &capability_authority,
        &debtor,
        CAPABILITY_ID,
        TOOL_SERVER,
        5_000,
        EXPIRES_AT,
    )?;
    Ok(Fixture {
        facility_authority,
        capability_authority,
        bind_authority,
        debtor,
        creditor,
        facility,
        capability,
    })
}

fn sources(fixture: &Fixture) -> Vec<CreditAuthoritySourceV1> {
    vec![
        CreditAuthoritySourceV1 {
            kind: CreditAuthorityKindV1::Facility,
            authority_id: FACILITY_AUTHORITY_ID.to_owned(),
            authority_key: fixture.facility_authority.public_key(),
            authority_epoch: 7,
        },
        CreditAuthoritySourceV1 {
            kind: CreditAuthorityKindV1::Capability,
            authority_id: CAPABILITY_AUTHORITY_ID.to_owned(),
            authority_key: fixture.capability_authority.public_key(),
            authority_epoch: 11,
        },
    ]
}

fn artifacts(fixture: &Fixture) -> Vec<ConfiguredCreditAuthorityArtifactV1> {
    vec![
        ConfiguredCreditAuthorityArtifactV1::Facility {
            authority_id: FACILITY_AUTHORITY_ID.to_owned(),
            authority_epoch: 7,
            signed: Box::new(fixture.facility.clone()),
        },
        ConfiguredCreditAuthorityArtifactV1::Capability {
            authority_id: CAPABILITY_AUTHORITY_ID.to_owned(),
            authority_epoch: 11,
            signed: Box::new(fixture.capability.clone()),
        },
    ]
}

fn request(fixture: &Fixture, trusted_at_unix_seconds: u64) -> CreditAuthorityResolutionRequestV1 {
    CreditAuthorityResolutionRequestV1 {
        debtor_id: DEBTOR_ID.to_owned(),
        debtor_key: fixture.debtor.public_key(),
        capability_id: CAPABILITY_ID.to_owned(),
        tool_server: TOOL_SERVER.to_owned(),
        tool_name: TOOL_NAME.to_owned(),
        currency: "USD".to_owned(),
        trusted_at_unix_seconds,
    }
}

fn resolver(
    fixture: &Fixture,
) -> Result<ConfiguredCreditAuthorityResolverV1, CreditAdmissionError> {
    ConfiguredCreditAuthorityResolverV1::new(CreditAuthorityResolverConfigurationV1 {
        complete_sources: sources(fixture),
        complete_artifact_catalog: artifacts(fixture),
    })
}

fn verified_bind_with_facility_digest(
    fixture: &Fixture,
    authorities: &chio_credit::obligation::VerifiedCreditAuthoritySet,
    facility_artifact_digest: Option<&str>,
) -> TestResult<VerifiedCreditFacilityBindV1> {
    let facility = authorities
        .evidence()
        .iter()
        .find(|evidence| evidence.kind() == CreditAuthorityKindV1::Facility)
        .ok_or("resolved authority set omitted the facility")?;
    let trust = CreditFacilityBindTrustV1::new(CreditFacilityBindTrustInputV1 {
        authority_id: BIND_AUTHORITY_ID.to_owned(),
        authority_key: fixture.bind_authority.public_key(),
        authority_key_epoch: 13,
        debtor_id: DEBTOR_ID.to_owned(),
        debtor_key: fixture.debtor.public_key(),
        debtor_key_epoch: 17,
        creditor_id: CREDITOR_ID.to_owned(),
        creditor_key: fixture.creditor.public_key(),
        creditor_key_epoch: 19,
        max_lifetime_ms: (EXPIRES_AT - ISSUED_AT) * 1_000,
    })?;
    let signed = SignedCreditFacilityBindV1::sign(
        CreditFacilityBindBodyV1::new(CreditFacilityBindInputV1 {
            operation_id: sha256_hex(b"credit-operation"),
            request_id: "credit-request".to_owned(),
            economic_intent_digest: sha256_hex(b"credit-intent"),
            facility_id: facility.artifact_id().to_owned(),
            facility_artifact_digest: facility_artifact_digest
                .unwrap_or_else(|| facility.artifact_digest())
                .to_owned(),
            authority_set_digest: authorities.authority_set_digest().to_owned(),
            debtor_id: DEBTOR_ID.to_owned(),
            original_creditor_id: CREDITOR_ID.to_owned(),
            original_settlement_destination_ref: CREDITOR_DESTINATION.to_owned(),
            capability_id: CAPABILITY_ID.to_owned(),
            tool_server: TOOL_SERVER.to_owned(),
            tool_name: TOOL_NAME.to_owned(),
            amount: amount(1_000, "USD"),
            effective_ceiling: authorities.effective_ceiling().clone(),
            expected_exposure_version: 7,
            expected_exposure_fence: 7,
            due_at_unix_ms: EXPIRES_AT * 1_000 + 1_000,
            action_nonce: "credit-action-nonce".to_owned(),
            issued_at_unix_ms: ISSUED_AT * 1_000,
            expires_at_unix_ms: EXPIRES_AT * 1_000,
            authority_id: BIND_AUTHORITY_ID.to_owned(),
            authority_key_epoch: 13,
            debtor_key_epoch: 17,
            creditor_key_epoch: 19,
        })?,
        &fixture.bind_authority,
        &fixture.debtor,
        &fixture.creditor,
    )?;
    Ok(verify_credit_facility_bind(
        &signed.canonical_bytes()?,
        &CreditFacilityBindVerificationContextV1 {
            trust: &trust,
            trusted_at_unix_ms: NOW * 1_000,
        },
    )?)
}

fn verified_bind(
    fixture: &Fixture,
    authorities: &chio_credit::obligation::VerifiedCreditAuthoritySet,
) -> TestResult<VerifiedCreditFacilityBindV1> {
    verified_bind_with_facility_digest(fixture, authorities, None)
}

fn reservation_request(fixture: &Fixture) -> TestResult<CreditExposureReservationRequest> {
    let authorities = resolver(fixture)?.resolve(&request(fixture, NOW))?;
    let credit_facility_bind = verified_bind(fixture, &authorities)?;
    Ok(CreditExposureReservationRequest {
        operation_id: sha256_hex(b"credit-operation"),
        request_id: "credit-request".to_owned(),
        action_nonce: "credit-action-nonce".to_owned(),
        economic_intent_digest: sha256_hex(b"credit-intent"),
        debtor_id: DEBTOR_ID.to_owned(),
        amount: amount(1_000, "USD"),
        authorities,
        credit_facility_bind,
    })
}

fn obligation_atom(request: &CreditExposureReservationRequest) -> TestResult<ObligationAtomV1> {
    let bind = request.credit_facility_bind.body();
    Ok(ObligationAtomV1::new(ObligationAtomInputV1 {
        economic_intent_digest: request.economic_intent_digest.clone(),
        source_receipt_id: "receipt-credit-1".to_owned(),
        source_receipt_digest: sha256_hex(b"receipt-credit-1"),
        debtor_id: request.debtor_id.clone(),
        original_creditor_id: bind.original_creditor_id().to_owned(),
        original_settlement_destination_ref: bind.original_settlement_destination_ref().to_owned(),
        payee_binding_digest: derive_obligation_payee_binding_digest(
            bind.original_creditor_id(),
            bind.original_settlement_destination_ref(),
        )?,
        amount: request.amount.clone(),
        credit_election: ObligationCreditElectionV1::CreditFacility {
            facility_id: bind.facility_id().to_owned(),
            authority_digest: request.credit_facility_bind.artifact_digest().to_owned(),
        },
        pre_action_authority_digest: sha256_hex(b"pre-action-authority"),
        created_at_unix_ms: NOW * 1_000 + 1,
        due_at_unix_ms: bind.due_at_unix_ms(),
    })?)
}

#[derive(Clone, Default)]
struct TestBackend {
    record: Arc<Mutex<Option<CreditExposureReservationRecordV1>>>,
}

impl TestBackend {
    fn replace(
        &self,
        record: CreditExposureReservationRecordV1,
    ) -> Result<(), CreditAdmissionError> {
        *self
            .record
            .lock()
            .map_err(|error| CreditAdmissionError::Store(error.to_string()))? = Some(record);
        Ok(())
    }
}

impl CreditAdmissionStore for TestBackend {
    fn lookup_record_by_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<CreditExposureReservationRecordV1>, CreditAdmissionError> {
        let record = self
            .record
            .lock()
            .map_err(|error| CreditAdmissionError::Store(error.to_string()))?
            .clone();
        Ok(record.filter(|record| record.operation_id() == operation_id))
    }
}

#[test]
fn configured_resolver_seals_the_complete_minimum_authority_set_deterministically() -> TestResult {
    let fixture = fixture()?;
    let first = resolver(&fixture)?;
    let mut reversed_sources = sources(&fixture);
    reversed_sources.reverse();
    let mut reversed_artifacts = artifacts(&fixture);
    reversed_artifacts.reverse();
    let second =
        ConfiguredCreditAuthorityResolverV1::new(CreditAuthorityResolverConfigurationV1 {
            complete_sources: reversed_sources,
            complete_artifact_catalog: reversed_artifacts,
        })?;
    assert_eq!(first.configuration_digest(), second.configuration_digest());
    assert_eq!(first.catalog_digest(), second.catalog_digest());

    let resolved = first.resolve(&request(&fixture, NOW))?;
    let resolved_again = second.resolve(&request(&fixture, NOW))?;
    assert_eq!(resolved, resolved_again);
    assert_eq!(resolved.debtor_id(), DEBTOR_ID);
    assert_eq!(resolved.debtor_key(), &fixture.debtor.public_key());
    assert_eq!(resolved.capability_id(), CAPABILITY_ID);
    assert_eq!(resolved.effective_ceiling(), &amount(2_000, "USD"));
    assert_eq!(resolved.expires_at_unix_seconds(), EXPIRES_AT);
    assert_eq!(resolved.resolved_at_unix_seconds(), NOW);
    assert_eq!(
        resolved.configuration_digest(),
        first.configuration_digest()
    );
    assert_eq!(resolved.authority_set_digest().len(), 64);
    assert_eq!(resolved.evidence().len(), 2);
    assert_eq!(
        resolved.evidence()[0].kind(),
        CreditAuthorityKindV1::Facility
    );
    assert_eq!(resolved.evidence()[0].authority_epoch(), 7);
    assert_eq!(resolved.evidence()[0].ceiling(), &amount(7_200, "USD"));
    assert_eq!(
        resolved.evidence()[1].kind(),
        CreditAuthorityKindV1::Capability
    );
    assert_eq!(resolved.evidence()[1].authority_epoch(), 11);
    assert_eq!(resolved.evidence()[1].ceiling(), &amount(2_000, "USD"));
    assert!(resolved
        .evidence()
        .iter()
        .all(|evidence| evidence.artifact_digest().len() == 64));
    assert_eq!(
        resolved.scope_digest(),
        credit_facility_scope_digest(DEBTOR_ID, CAPABILITY_ID, TOOL_SERVER, TOOL_NAME, "USD")?
    );
    assert_eq!(resolved.ensure_current_at(NOW), Ok(()));
    assert_eq!(
        resolved.ensure_current_at(EXPIRES_AT),
        Err(CreditAdmissionError::AuthorityNotCurrent)
    );
    Ok(())
}

#[test]
fn configured_resolver_rejects_incomplete_conflicting_expired_and_tampered_sets() -> TestResult {
    let fixture = fixture()?;
    let mut incomplete_artifacts = artifacts(&fixture);
    incomplete_artifacts.pop();
    assert!(matches!(
        ConfiguredCreditAuthorityResolverV1::new(CreditAuthorityResolverConfigurationV1 {
            complete_sources: sources(&fixture),
            complete_artifact_catalog: incomplete_artifacts,
        }),
        Err(CreditAdmissionError::IncompleteAuthoritySet)
    ));

    let conflicting = signed_facility(
        &fixture.facility_authority,
        "facility-working-capital",
        8_000,
        8_000,
        EXPIRES_AT,
    )?;
    let mut conflicting_artifacts = artifacts(&fixture);
    conflicting_artifacts.push(ConfiguredCreditAuthorityArtifactV1::Facility {
        authority_id: FACILITY_AUTHORITY_ID.to_owned(),
        authority_epoch: 7,
        signed: Box::new(conflicting),
    });
    assert!(matches!(
        ConfiguredCreditAuthorityResolverV1::new(CreditAuthorityResolverConfigurationV1 {
            complete_sources: sources(&fixture),
            complete_artifact_catalog: conflicting_artifacts,
        }),
        Err(CreditAdmissionError::ConflictingAuthoritySet)
    ));

    let mut tampered = fixture.facility.clone();
    tampered.body.expires_at += 1;
    let mut tampered_artifacts = artifacts(&fixture);
    tampered_artifacts[0] = ConfiguredCreditAuthorityArtifactV1::Facility {
        authority_id: FACILITY_AUTHORITY_ID.to_owned(),
        authority_epoch: 7,
        signed: Box::new(tampered),
    };
    assert!(matches!(
        ConfiguredCreditAuthorityResolverV1::new(CreditAuthorityResolverConfigurationV1 {
            complete_sources: sources(&fixture),
            complete_artifact_catalog: tampered_artifacts,
        }),
        Err(CreditAdmissionError::AuthorityVerification)
    ));

    let resolver = resolver(&fixture)?;
    assert_eq!(
        resolver.resolve(&request(&fixture, EXPIRES_AT)),
        Err(CreditAdmissionError::AuthorityNotCurrent)
    );
    let mut favorable_subset = request(&fixture, NOW);
    favorable_subset.capability_id = "capability-without-stricter-ceiling".to_owned();
    assert_eq!(
        resolver.resolve(&favorable_subset),
        Err(CreditAdmissionError::IncompleteAuthoritySet)
    );
    let mut wrong_currency = request(&fixture, NOW);
    wrong_currency.currency = "EUR".to_owned();
    assert_eq!(
        resolver.resolve(&wrong_currency),
        Err(CreditAdmissionError::CurrencyMismatch)
    );
    Ok(())
}

#[test]
fn resolver_uses_literal_capability_wildcards_and_wide_money_arithmetic() -> TestResult {
    let fixture = fixture()?;
    let prefix_capability = signed_capability(
        &fixture.capability_authority,
        &fixture.debtor,
        CAPABILITY_ID,
        "tools.*",
        5_000,
        EXPIRES_AT,
    )?;
    let mut prefix_artifacts = artifacts(&fixture);
    prefix_artifacts[1] = ConfiguredCreditAuthorityArtifactV1::Capability {
        authority_id: CAPABILITY_AUTHORITY_ID.to_owned(),
        authority_epoch: 11,
        signed: Box::new(prefix_capability),
    };
    let prefix_resolver =
        ConfiguredCreditAuthorityResolverV1::new(CreditAuthorityResolverConfigurationV1 {
            complete_sources: sources(&fixture),
            complete_artifact_catalog: prefix_artifacts,
        })?;
    assert_eq!(
        prefix_resolver.resolve(&request(&fixture, NOW)),
        Err(CreditAdmissionError::IncompleteAuthoritySet)
    );

    let wide_facility = signed_facility(
        &fixture.facility_authority,
        "facility-working-capital-wide",
        (1_u64 << 53) - 1,
        10_000,
        EXPIRES_AT,
    )?;
    let mut wide_artifacts = artifacts(&fixture);
    wide_artifacts[0] = ConfiguredCreditAuthorityArtifactV1::Facility {
        authority_id: FACILITY_AUTHORITY_ID.to_owned(),
        authority_epoch: 7,
        signed: Box::new(wide_facility),
    };
    let wide = ConfiguredCreditAuthorityResolverV1::new(CreditAuthorityResolverConfigurationV1 {
        complete_sources: sources(&fixture),
        complete_artifact_catalog: wide_artifacts,
    })?
    .resolve(&request(&fixture, NOW))?;
    assert_eq!(wide.effective_ceiling(), &amount(2_000, "USD"));
    assert_eq!(
        wide.evidence()[0].ceiling(),
        &amount((1_u64 << 53) - 1, "USD")
    );
    Ok(())
}

#[test]
fn reservation_contract_checks_capacity_and_all_terminal_states() -> TestResult {
    let fixture = fixture()?;
    let request = reservation_request(&fixture)?;
    assert_eq!(request.checked_total_exposure(500, 500), Ok(2_000));
    assert_eq!(
        request.checked_total_exposure(501, 500),
        Err(CreditAdmissionError::ExposureExceeded)
    );
    assert_eq!(
        request.checked_total_exposure((1_u64 << 53) - 1, 1),
        Err(CreditAdmissionError::ArithmeticOverflow)
    );

    let backend = TestBackend::default();
    let store = CreditAdmissionStoreAdapter::new(backend.clone());
    let reservation = CreditExposureReservationRecordV1::prepare_reserved(&request, 8, 8)?;
    assert_eq!(
        reservation.state(),
        CreditExposureReservationStateV1::Reserved
    );
    assert_eq!(reservation.obligation_id(), None);
    assert_eq!(reservation.source_account_version(), 7);
    assert_eq!(reservation.source_resource_fence(), 7);
    assert_eq!(reservation.account_version(), 8);
    assert_eq!(reservation.resource_fence(), 8);
    assert_eq!(reservation.action_nonce(), "credit-action-nonce");
    assert_eq!(reservation.reservation_digest().len(), 64);
    assert_eq!(reservation.authority_evidence().len(), 2);
    assert_eq!(reservation.amount(), &amount(1_000, "USD"));
    assert_eq!(reservation.effective_ceiling(), &amount(2_000, "USD"));
    assert_eq!(
        reservation.authority_set_digest(),
        request.authorities.authority_set_digest()
    );
    let canonical = serde_json::to_vec(&reservation)?;
    let decoded: CreditExposureReservationRecordV1 = serde_json::from_slice(&canonical)?;
    decoded.validate()?;
    assert_eq!(decoded, reservation);

    let atom = obligation_atom(&request)?;
    let committed_record = decoded.prepare_committed(&atom, 9, 9)?;
    assert_eq!(
        committed_record.reservation_digest(),
        decoded.reservation_digest()
    );
    assert_eq!(
        committed_record.state(),
        CreditExposureReservationStateV1::Committed
    );
    assert_eq!(committed_record.account_version(), 9);
    assert_eq!(committed_record.resource_fence(), 9);
    assert_eq!(committed_record.obligation_id(), Some(atom.obligation_id()));
    assert_eq!(
        committed_record.obligation_atom_digest(),
        Some(atom.digest()?.as_str())
    );
    assert_eq!(
        committed_record.prepare_outcome_unknown(10, 10),
        Err(CreditAdmissionError::IllegalReservationTransition)
    );
    backend.replace(committed_record)?;
    let reloaded = store
        .lookup_committed_by_operation(&request.operation_id)?
        .ok_or("committed reservation was not reloadable")?;
    assert_eq!(
        reloaded.state(),
        CreditExposureReservationStateV1::Committed
    );
    assert_eq!(reloaded.obligation_id(), Some(atom.obligation_id()));
    assert_eq!(
        reloaded.obligation_atom_digest(),
        Some(atom.digest()?.as_str())
    );
    assert_eq!(
        reloaded.validate_committed_binding(&atom, &request.credit_facility_bind),
        Ok(())
    );
    assert_eq!(reloaded.action_nonce(), "credit-action-nonce");
    assert_eq!(reloaded.reservation_digest(), decoded.reservation_digest());
    let mut mismatched_atom_digest = serde_json::to_value(reloaded.store_record())?;
    mismatched_atom_digest["obligationAtomDigest"] =
        serde_json::json!(sha256_hex(b"other-obligation-atom"));
    backend.replace(serde_json::from_value(mismatched_atom_digest)?)?;
    let mismatched = store
        .lookup_committed_by_operation(&request.operation_id)?
        .ok_or("mismatched committed reservation was not reloadable")?;
    assert_eq!(
        mismatched.validate_committed_binding(&atom, &request.credit_facility_bind),
        Err(CreditAdmissionError::OperationConflict)
    );

    let unknown = decoded.prepare_outcome_unknown(9, 9)?;
    assert_eq!(unknown.reservation_digest(), decoded.reservation_digest());
    assert_eq!(
        unknown.state(),
        CreditExposureReservationStateV1::OutcomeUnknown
    );
    assert_eq!(
        decoded.prepare_committed(&atom, 8, 8),
        Err(CreditAdmissionError::IllegalReservationTransition)
    );

    let mut wrong_debtor = request.clone();
    wrong_debtor.debtor_id = "did:chio:other".to_owned();
    assert_eq!(
        wrong_debtor.validate(),
        Err(CreditAdmissionError::ScopeMismatch)
    );
    let mut unlisted_facility = request.clone();
    unlisted_facility.credit_facility_bind = verified_bind_with_facility_digest(
        &fixture,
        &unlisted_facility.authorities,
        Some(&sha256_hex(b"unlisted-facility-artifact")),
    )?;
    assert_eq!(
        unlisted_facility.validate(),
        Err(CreditAdmissionError::IncompleteAuthoritySet)
    );
    let mut over_ceiling = request;
    over_ceiling.amount.units = 2_001;
    assert_eq!(
        over_ceiling.validate(),
        Err(CreditAdmissionError::ScopeMismatch)
    );
    Ok(())
}

#[test]
fn reservation_identity_rejects_nonce_and_digest_tampering() -> TestResult {
    let fixture = fixture()?;
    let request = reservation_request(&fixture)?;
    let reservation = CreditExposureReservationRecordV1::prepare_reserved(&request, 8, 8)?;

    let mut wrong_nonce = serde_json::to_value(&reservation)?;
    *wrong_nonce
        .get_mut("actionNonce")
        .ok_or("serialized reservation omitted actionNonce")? =
        serde_json::Value::String("different-credit-action-nonce".to_owned());
    let wrong_nonce: CreditExposureReservationRecordV1 = serde_json::from_value(wrong_nonce)?;
    assert_eq!(
        wrong_nonce.validate(),
        Err(CreditAdmissionError::InvalidField("reservation_binding"))
    );

    let mut wrong_digest = serde_json::to_value(&reservation)?;
    *wrong_digest
        .get_mut("reservationDigest")
        .ok_or("serialized reservation omitted reservationDigest")? =
        serde_json::Value::String(sha256_hex(b"different-reservation"));
    let wrong_digest: CreditExposureReservationRecordV1 = serde_json::from_value(wrong_digest)?;
    assert_eq!(
        wrong_digest.validate(),
        Err(CreditAdmissionError::InvalidField("reservation_binding"))
    );

    let mut wrong_trust_coordinate = serde_json::to_value(&reservation)?;
    *wrong_trust_coordinate
        .get_mut("bindTrustConfigurationDigest")
        .ok_or("serialized reservation omitted bindTrustConfigurationDigest")? =
        serde_json::Value::String(sha256_hex(b"different-bind-trust-configuration"));
    let wrong_trust_coordinate: CreditExposureReservationRecordV1 =
        serde_json::from_value(wrong_trust_coordinate)?;
    assert_eq!(
        wrong_trust_coordinate.validate(),
        Err(CreditAdmissionError::InvalidField("reservation_binding"))
    );

    let mut wrong_request_nonce = request;
    wrong_request_nonce.action_nonce = "different-credit-action-nonce".to_owned();
    assert_eq!(
        wrong_request_nonce.validate(),
        Err(CreditAdmissionError::ScopeMismatch)
    );
    Ok(())
}
