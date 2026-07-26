use chio_core::capability::runtime_attestation::RuntimeAssuranceTier;
use chio_core::capability::scope::{ChioScope, MonetaryAmount, Operation, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_credit::obligation::{
    verify_credit_facility_bind, ConfiguredCreditAuthorityArtifactV1,
    ConfiguredCreditAuthorityResolverV1, CreditAuthorityKindV1, CreditAuthorityResolutionRequestV1,
    CreditAuthorityResolverConfigurationV1, CreditAuthoritySourceV1,
    CreditExposureReservationRequest, CreditExposureReservationStateV1, CreditFacilityBindBodyV1,
    CreditFacilityBindInputV1, CreditFacilityBindTrustInputV1, CreditFacilityBindTrustV1,
    CreditFacilityBindVerificationContextV1, SignedCreditFacilityBindV1,
};
use chio_credit::{
    CreditFacilityArtifact, CreditFacilityCapitalSource, CreditFacilityDisposition,
    CreditFacilityLifecycleState, CreditFacilityPrerequisites, CreditFacilityReport,
    CreditFacilitySupportBoundary, CreditFacilityTerms, CreditScorecardBand,
    CreditScorecardConfidence, CreditScorecardSummary, ExposureLedgerQuery, SignedCreditFacility,
    CREDIT_FACILITY_ARTIFACT_SCHEMA, CREDIT_FACILITY_REPORT_SCHEMA,
};
use chio_kernel::admission_operation::AdmissionCaptureError;

use super::*;

type CreditAuthorizationTestResult<T = ()> = Result<T, Box<dyn Error>>;

const DEBTOR_ID: &str = "did:chio:sqlite-credit-debtor";
const CREDITOR_ID: &str = "did:chio:sqlite-credit-creditor";
const CREDITOR_DESTINATION: &str = "bank:sqlite-credit-creditor";
const CAPABILITY_ID: &str = "capability-sqlite-credit";
const TOOL_SERVER: &str = "tools.sqlite-credit.example";
const TOOL_NAME: &str = "metered-search";
const FACILITY_AUTHORITY_ID: &str = "sqlite-credit-facility-authority";
const CAPABILITY_AUTHORITY_ID: &str = "sqlite-credit-capability-authority";
const BIND_AUTHORITY_ID: &str = "sqlite-credit-bind-authority";
const FACILITY_ID: &str = "sqlite-credit-facility";
const AUTHORITY_ISSUED_AT: u64 = 1_700_000_000;
const AUTHORITY_EXPIRES_AT: u64 = 2_000_000_000;
const SOURCE_VERSION: u64 = 7;
const EXPOSURE_UNITS: u64 = 1_000;

struct CreditAuthorityFixture {
    bind_authority: Keypair,
    debtor: Keypair,
    creditor: Keypair,
    resolver: ConfiguredCreditAuthorityResolverV1,
}

impl CreditAuthorityFixture {
    fn new() -> CreditAuthorizationTestResult<Self> {
        let facility_authority = Keypair::from_seed(&[71; 32]);
        let capability_authority = Keypair::from_seed(&[72; 32]);
        let bind_authority = Keypair::from_seed(&[73; 32]);
        let debtor = Keypair::from_seed(&[74; 32]);
        let creditor = Keypair::from_seed(&[75; 32]);
        let facility = SignedCreditFacility::sign(
            CreditFacilityArtifact {
                schema: CREDIT_FACILITY_ARTIFACT_SCHEMA.to_owned(),
                facility_id: FACILITY_ID.to_owned(),
                issued_at: AUTHORITY_ISSUED_AT,
                expires_at: AUTHORITY_EXPIRES_AT,
                lifecycle_state: CreditFacilityLifecycleState::Active,
                supersedes_facility_id: None,
                report: CreditFacilityReport {
                    schema: CREDIT_FACILITY_REPORT_SCHEMA.to_owned(),
                    generated_at: AUTHORITY_ISSUED_AT,
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
                    scorecard: CreditScorecardSummary {
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
                        credit_limit: amount(9_000),
                        utilization_ceiling_bps: 8_000,
                        reserve_ratio_bps: 1_000,
                        concentration_cap_bps: 5_000,
                        ttl_seconds: AUTHORITY_EXPIRES_AT - AUTHORITY_ISSUED_AT,
                        capital_source: CreditFacilityCapitalSource::OperatorInternal,
                    }),
                    findings: Vec::new(),
                },
            },
            &facility_authority,
        )?;
        let capability = CapabilityToken::sign(
            CapabilityTokenBody {
                id: CAPABILITY_ID.to_owned(),
                issuer: capability_authority.public_key(),
                subject: debtor.public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: TOOL_SERVER.to_owned(),
                        tool_name: TOOL_NAME.to_owned(),
                        operations: vec![Operation::Invoke],
                        constraints: Vec::new(),
                        max_invocations: None,
                        max_cost_per_invocation: Some(amount(2_000)),
                        max_total_cost: Some(amount(2_000)),
                        dpop_required: None,
                    }],
                    resource_grants: Vec::new(),
                    prompt_grants: Vec::new(),
                },
                issued_at: AUTHORITY_ISSUED_AT,
                expires_at: AUTHORITY_EXPIRES_AT,
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
                        authority_epoch: 7,
                    },
                    CreditAuthoritySourceV1 {
                        kind: CreditAuthorityKindV1::Capability,
                        authority_id: CAPABILITY_AUTHORITY_ID.to_owned(),
                        authority_key: capability_authority.public_key(),
                        authority_epoch: 11,
                    },
                ],
                complete_artifact_catalog: vec![
                    ConfiguredCreditAuthorityArtifactV1::Facility {
                        authority_id: FACILITY_AUTHORITY_ID.to_owned(),
                        authority_epoch: 7,
                        signed: Box::new(facility),
                    },
                    ConfiguredCreditAuthorityArtifactV1::Capability {
                        authority_id: CAPABILITY_AUTHORITY_ID.to_owned(),
                        authority_epoch: 11,
                        signed: Box::new(capability),
                    },
                ],
            })?;
        Ok(Self {
            bind_authority,
            debtor,
            creditor,
            resolver,
        })
    }

    fn reservation_request(
        &self,
        operation_id: &str,
        request_id: &str,
        action_nonce: &str,
        expected_version: u64,
        trusted_now_unix_ms: u64,
    ) -> CreditAuthorizationTestResult<CreditExposureReservationRequest> {
        let authorities = self.resolver.resolve(&CreditAuthorityResolutionRequestV1 {
            debtor_id: DEBTOR_ID.to_owned(),
            debtor_key: self.debtor.public_key(),
            capability_id: CAPABILITY_ID.to_owned(),
            tool_server: TOOL_SERVER.to_owned(),
            tool_name: TOOL_NAME.to_owned(),
            currency: "USD".to_owned(),
            trusted_at_unix_seconds: trusted_now_unix_ms / 1_000,
        })?;
        let facility = authorities
            .evidence()
            .iter()
            .find(|evidence| evidence.kind() == CreditAuthorityKindV1::Facility)
            .ok_or("credit authority set omitted its facility")?;
        let trust = CreditFacilityBindTrustV1::new(CreditFacilityBindTrustInputV1 {
            authority_id: BIND_AUTHORITY_ID.to_owned(),
            authority_key: self.bind_authority.public_key(),
            authority_key_epoch: 13,
            debtor_id: DEBTOR_ID.to_owned(),
            debtor_key: self.debtor.public_key(),
            debtor_key_epoch: 17,
            creditor_id: CREDITOR_ID.to_owned(),
            creditor_key: self.creditor.public_key(),
            creditor_key_epoch: 19,
            max_lifetime_ms: (AUTHORITY_EXPIRES_AT - AUTHORITY_ISSUED_AT) * 1_000,
        })?;
        let economic_intent_digest = sha256_hex(b"sqlite-credit-economic-intent");
        let signed = SignedCreditFacilityBindV1::sign(
            CreditFacilityBindBodyV1::new(CreditFacilityBindInputV1 {
                operation_id: operation_id.to_owned(),
                request_id: request_id.to_owned(),
                economic_intent_digest: economic_intent_digest.clone(),
                facility_id: facility.artifact_id().to_owned(),
                facility_artifact_digest: facility.artifact_digest().to_owned(),
                authority_set_digest: authorities.authority_set_digest().to_owned(),
                debtor_id: DEBTOR_ID.to_owned(),
                original_creditor_id: CREDITOR_ID.to_owned(),
                original_settlement_destination_ref: CREDITOR_DESTINATION.to_owned(),
                capability_id: CAPABILITY_ID.to_owned(),
                tool_server: TOOL_SERVER.to_owned(),
                tool_name: TOOL_NAME.to_owned(),
                amount: amount(EXPOSURE_UNITS),
                effective_ceiling: authorities.effective_ceiling().clone(),
                expected_exposure_version: expected_version,
                expected_exposure_fence: expected_version,
                due_at_unix_ms: AUTHORITY_EXPIRES_AT * 1_000 + 1_000,
                action_nonce: action_nonce.to_owned(),
                issued_at_unix_ms: AUTHORITY_ISSUED_AT * 1_000,
                expires_at_unix_ms: AUTHORITY_EXPIRES_AT * 1_000,
                authority_id: BIND_AUTHORITY_ID.to_owned(),
                authority_key_epoch: 13,
                debtor_key_epoch: 17,
                creditor_key_epoch: 19,
            })?,
            &self.bind_authority,
            &self.debtor,
            &self.creditor,
        )?;
        let canonical = signed.canonical_bytes()?;
        let credit_facility_bind = verify_credit_facility_bind(
            &canonical,
            &CreditFacilityBindVerificationContextV1 {
                trust: &trust,
                trusted_at_unix_ms: trusted_now_unix_ms,
            },
        )?;
        Ok(CreditExposureReservationRequest {
            operation_id: operation_id.to_owned(),
            request_id: request_id.to_owned(),
            action_nonce: action_nonce.to_owned(),
            economic_intent_digest,
            debtor_id: DEBTOR_ID.to_owned(),
            amount: amount(EXPOSURE_UNITS),
            authorities,
            credit_facility_bind,
        })
    }
}

fn amount(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_owned(),
    }
}

fn prepared_credit_operation(
    fixture: &Fixture,
    request_id: &str,
) -> CreditAuthorizationTestResult<AdmissionOperationV1> {
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
            "sqlite-credit-test-authority",
        ))?,
        request_id: identifier("request_id", request_id),
        capability_id: identifier("capability_id", CAPABILITY_ID),
        authorization_capability_hash: digest("authorization_capability_hash", 'a'),
        request_binding: AdmissionRequestBindingV1::new(
            digest("immutable_request_hash", 'b'),
            requirements,
        )?,
        policy_hash: digest("policy_hash", 'c'),
        effect_class: SideEffectClass::Monetary,
    })?;
    Ok(AdmissionOperationV1::prepare(
        binding,
        fixture.fence.owner_epoch,
    )?)
}

fn broker_registered_credit_operation(
    fixture: &Fixture,
    request_id: &str,
    begun_at_unix_ms: u64,
) -> CreditAuthorizationTestResult<AdmissionOperationV1> {
    let operation = prepared_credit_operation(fixture, request_id)?;
    fixture
        .store
        .begin(&operation, &fixture.fence, begun_at_unix_ms)?;
    let lease = claim(
        fixture,
        &operation,
        "sqlite-credit-authorizer",
        begun_at_unix_ms + 1,
    );
    Ok(fixture
        .store
        .compare_and_swap(
            &command(
                &operation,
                lease,
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &operation,
                    &format!("attempt-{request_id}"),
                ))],
                AdmissionOperationState::BrokerAttemptRegistered,
                None,
            ),
            begun_at_unix_ms + 2,
        )?
        .into_operation())
}

fn budget_authorization_request(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    identity: &str,
) -> BudgetAuthorizeHoldRequest {
    BudgetAuthorizeHoldRequest {
        capability_id: CAPABILITY_ID.to_owned(),
        grant_index: 0,
        max_invocations: Some(2),
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: Some(BudgetAdmissionBinding {
            operation_id: operation.binding().operation_id().as_str().to_owned(),
            revocation_set: CanonicalRevocationSet::canonicalize(vec![CAPABILITY_ID.to_owned()])
                .expect("canonical credit revocation set"),
            authorization_artifact_digests: vec!["a".repeat(64)],
            last_observed_revocation: None,
            supplemental_verifier_id: None,
            supplemental_verifier_config_digest: None,
            supplemental_authorization_artifact_digest: None,
            supplemental_authorization_expires_at: None,
        }),
        requested_exposure_units: EXPOSURE_UNITS,
        max_cost_per_invocation: Some(EXPOSURE_UNITS),
        max_total_cost_units: Some(EXPOSURE_UNITS * 2),
        hold_id: Some(format!("hold-{identity}")),
        event_id: Some(format!("authorize-{identity}")),
        authority: Some(BudgetEventAuthority {
            authority_id: fixture.fence.store_uuid.clone(),
            lease_id: fixture.fence.lease_id.clone(),
            lease_epoch: fixture.fence.owner_epoch,
        }),
    }
}

fn provision_account(
    fixture: &Fixture,
    request: &CreditExposureReservationRequest,
    trusted_now_unix_ms: u64,
) -> CreditAuthorizationTestResult<CreditExposureAccountSnapshot> {
    Ok(fixture.store.provision_credit_exposure_account(
        request,
        &fixture.fence,
        trusted_now_unix_ms,
    )?)
}

fn account_state(fixture: &Fixture) -> CreditAuthorizationTestResult<(i64, i64, i64, i64, i64)> {
    Ok(fixture.store.connection()?.query_row(
        r#"
        SELECT COUNT(*), COALESCE(SUM(open_units), 0), COALESCE(SUM(reserved_units), 0),
               COALESCE(MAX(account_version), 0), COALESCE(MAX(resource_fence), 0)
        FROM credit_exposure_accounts
        WHERE debtor_id = ?1 AND currency = 'USD'
        "#,
        [DEBTOR_ID],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?)
}

fn authorization_mutation_counts(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    identity: &str,
) -> CreditAuthorizationTestResult<(i64, i64, i64, i64)> {
    Ok(fixture.store.connection()?.query_row(
        r#"
        SELECT
            (SELECT COUNT(*) FROM budget_mutation_events WHERE event_id = ?1),
            (SELECT COUNT(*) FROM budget_authorization_holds WHERE hold_id = ?2),
            (SELECT COUNT(*) FROM credit_exposure_reservations WHERE operation_id = ?3),
            (SELECT COUNT(*) FROM admission_operation_commits
             WHERE operation_id = ?3 AND participant_digest IS NOT NULL)
        "#,
        params![
            format!("authorize-{identity}"),
            format!("hold-{identity}"),
            operation.binding().operation_id().as_str(),
        ],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?)
}

#[test]
fn credit_account_provisioning_authorization_and_replay_are_exact() -> CreditAuthorizationTestResult
{
    let fixture = fixture();
    let authorities = CreditAuthorityFixture::new()?;
    let now = now_ms();
    let operation = broker_registered_credit_operation(&fixture, "request-credit-success", now)?;
    let credit_request = authorities.reservation_request(
        operation.binding().operation_id().as_str(),
        operation.binding().request_id().as_str(),
        "nonce-credit-success",
        SOURCE_VERSION,
        now + 3,
    )?;
    let provisioned = provision_account(&fixture, &credit_request, now + 3)?;
    assert_eq!(provisioned.open_units(), 0);
    assert_eq!(provisioned.reserved_units(), 0);
    assert_eq!(provisioned.account_version(), SOURCE_VERSION);
    assert_eq!(provisioned.resource_fence(), SOURCE_VERSION);
    assert_eq!(
        provision_account(&fixture, &credit_request, now + 3)?,
        provisioned
    );
    let lease = claim(&fixture, &operation, "sqlite-credit-authorizer", now + 4);
    let budget_request = budget_authorization_request(&fixture, &operation, "credit-success");
    let (decision, authorized) = fixture.store.authorize_budget_and_commit_admission(
        &operation,
        &lease,
        budget_request.clone(),
        None,
        Some(credit_request.clone()),
        &fixture.fence,
        now + 5,
    )?;
    assert!(matches!(
        &decision,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    assert_eq!(
        authorized.state(),
        AdmissionOperationState::BudgetAuthorized
    );
    let replayed = fixture.store.authorize_budget_and_commit_admission(
        &operation,
        &lease,
        budget_request,
        None,
        Some(credit_request),
        &fixture.fence,
        now + 5,
    )?;
    assert_eq!(replayed.0, decision);
    assert_eq!(replayed.1, authorized);
    let reservation = fixture
        .store
        .load_credit_exposure_reservation(operation.binding().operation_id().as_str())?
        .ok_or("authorized credit reservation was not persisted")?;
    assert_eq!(
        reservation.state(),
        CreditExposureReservationStateV1::Reserved
    );
    assert_eq!(reservation.account_version(), SOURCE_VERSION + 1);
    assert_eq!(reservation.resource_fence(), SOURCE_VERSION + 1);
    assert_eq!(account_state(&fixture)?, (1, 0, 1_000, 8, 8));
    assert_eq!(
        authorization_mutation_counts(&fixture, &operation, "credit-success")?,
        (1, 1, 1, 1)
    );
    Ok(())
}

#[test]
fn cumulative_credit_exposure_rejects_the_first_request_above_the_effective_ceiling(
) -> CreditAuthorizationTestResult {
    let fixture = fixture();
    let authorities = CreditAuthorityFixture::new()?;
    let now = now_ms();

    for (index, expected_version) in [SOURCE_VERSION, SOURCE_VERSION + 1].into_iter().enumerate() {
        let identity = format!("credit-capacity-{index}");
        let operation = broker_registered_credit_operation(
            &fixture,
            &format!("request-{identity}"),
            now + index as u64 * 10,
        )?;
        let credit_request = authorities.reservation_request(
            operation.binding().operation_id().as_str(),
            operation.binding().request_id().as_str(),
            &format!("nonce-{identity}"),
            expected_version,
            now + index as u64 * 10 + 3,
        )?;
        if index == 0 {
            provision_account(&fixture, &credit_request, now + 3)?;
        }
        let lease = claim(
            &fixture,
            &operation,
            "sqlite-credit-authorizer",
            now + index as u64 * 10 + 4,
        );
        let mut budget_request = budget_authorization_request(&fixture, &operation, &identity);
        budget_request.max_invocations = None;
        budget_request.max_total_cost_units = None;
        fixture.store.authorize_budget_and_commit_admission(
            &operation,
            &lease,
            budget_request,
            None,
            Some(credit_request),
            &fixture.fence,
            now + index as u64 * 10 + 5,
        )?;
    }
    assert_eq!(account_state(&fixture)?, (1, 0, 2_000, 9, 9));

    let denied_operation =
        broker_registered_credit_operation(&fixture, "request-credit-capacity-denied", now + 20)?;
    let denied_credit = authorities.reservation_request(
        denied_operation.binding().operation_id().as_str(),
        denied_operation.binding().request_id().as_str(),
        "nonce-credit-capacity-denied",
        SOURCE_VERSION + 2,
        now + 23,
    )?;
    let denied_lease = claim(
        &fixture,
        &denied_operation,
        "sqlite-credit-authorizer",
        now + 24,
    );
    let mut denied_budget =
        budget_authorization_request(&fixture, &denied_operation, "credit-capacity-denied");
    denied_budget.max_invocations = None;
    denied_budget.max_total_cost_units = None;
    assert_eq!(
        fixture.store.authorize_budget_and_commit_admission(
            &denied_operation,
            &denied_lease,
            denied_budget,
            None,
            Some(denied_credit),
            &fixture.fence,
            now + 25,
        ),
        Err(AdmissionCaptureError::Invariant(
            "budget state invariant violated: admission operation invariant failed: credit exposure exceeds the effective ceiling".to_owned()
        ))
    );
    assert_eq!(account_state(&fixture)?, (1, 0, 2_000, 9, 9));
    Ok(())
}

#[test]
fn credit_authorization_rollback_restores_budget_reservation_and_account(
) -> CreditAuthorizationTestResult {
    let fixture = fixture();
    let authorities = CreditAuthorityFixture::new()?;
    let now = now_ms();
    let operation = broker_registered_credit_operation(&fixture, "request-credit-rollback", now)?;
    let credit_request = authorities.reservation_request(
        operation.binding().operation_id().as_str(),
        operation.binding().request_id().as_str(),
        "nonce-credit-rollback",
        SOURCE_VERSION,
        now + 3,
    )?;
    provision_account(&fixture, &credit_request, now + 3)?;
    let lease = claim(&fixture, &operation, "sqlite-credit-authorizer", now + 4);
    {
        let connection = fixture.store.connection()?;
        connection.execute_batch(
            r#"
            CREATE TEMP TRIGGER fail_credit_authorization_admission_commit
            BEFORE INSERT ON admission_operation_commits
            WHEN NEW.mutation_kind = 'compare_and_swap'
             AND NEW.participant_digest IS NOT NULL
            BEGIN
                SELECT RAISE(ROLLBACK, 'injected credit authorization rollback');
            END;
            "#,
        )?;
    }
    let result = fixture.store.authorize_budget_and_commit_admission(
        &operation,
        &lease,
        budget_authorization_request(&fixture, &operation, "credit-rollback"),
        None,
        Some(credit_request),
        &fixture.fence,
        now + 5,
    );
    assert!(result.is_err());
    fixture
        .store
        .connection()?
        .execute_batch("DROP TRIGGER fail_credit_authorization_admission_commit")?;
    assert_eq!(account_state(&fixture)?, (1, 0, 0, 7, 7));
    assert_eq!(
        authorization_mutation_counts(&fixture, &operation, "credit-rollback")?,
        (0, 0, 0, 0)
    );
    assert!(fixture
        .store
        .load_credit_exposure_reservation(operation.binding().operation_id().as_str())?
        .is_none());
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())?
            .ok_or("credit rollback operation was lost")?
            .state(),
        AdmissionOperationState::BrokerAttemptRegistered
    );
    Ok(())
}

#[test]
fn credit_authorization_rejects_request_identity_mismatch_without_mutation(
) -> CreditAuthorizationTestResult {
    let fixture = fixture();
    let authorities = CreditAuthorityFixture::new()?;
    let now = now_ms();
    let operation = broker_registered_credit_operation(&fixture, "request-credit-mismatch", now)?;
    let provision_request = authorities.reservation_request(
        operation.binding().operation_id().as_str(),
        operation.binding().request_id().as_str(),
        "nonce-credit-mismatch",
        SOURCE_VERSION,
        now + 3,
    )?;
    provision_account(&fixture, &provision_request, now + 3)?;
    let mismatched = authorities.reservation_request(
        &sha256_hex(b"wrong-sqlite-credit-operation"),
        operation.binding().request_id().as_str(),
        "nonce-credit-mismatch",
        SOURCE_VERSION,
        now + 3,
    )?;
    let lease = claim(&fixture, &operation, "sqlite-credit-authorizer", now + 4);
    let error = fixture
        .store
        .authorize_budget_and_commit_admission(
            &operation,
            &lease,
            budget_authorization_request(&fixture, &operation, "credit-mismatch"),
            None,
            Some(mismatched),
            &fixture.fence,
            now + 5,
        )
        .expect_err("mismatched credit request must be rejected");
    assert!(matches!(
        error,
        AdmissionCaptureError::Invariant(ref detail)
            if detail.contains("does not match the combined authorization")
    ));
    assert_eq!(account_state(&fixture)?, (1, 0, 0, 7, 7));
    assert_eq!(
        authorization_mutation_counts(&fixture, &operation, "credit-mismatch")?,
        (0, 0, 0, 0)
    );
    Ok(())
}

#[test]
fn credit_authorization_rejects_stale_account_fence_without_mutation(
) -> CreditAuthorizationTestResult {
    let fixture = fixture();
    let authorities = CreditAuthorityFixture::new()?;
    let now = now_ms();
    let operation = broker_registered_credit_operation(&fixture, "request-credit-stale", now)?;
    let provision_request = authorities.reservation_request(
        operation.binding().operation_id().as_str(),
        operation.binding().request_id().as_str(),
        "nonce-credit-stale",
        SOURCE_VERSION,
        now + 3,
    )?;
    provision_account(&fixture, &provision_request, now + 3)?;
    let stale = authorities.reservation_request(
        operation.binding().operation_id().as_str(),
        operation.binding().request_id().as_str(),
        "nonce-credit-stale",
        SOURCE_VERSION - 1,
        now + 3,
    )?;
    let lease = claim(&fixture, &operation, "sqlite-credit-authorizer", now + 4);
    assert_eq!(
        fixture.store.authorize_budget_and_commit_admission(
            &operation,
            &lease,
            budget_authorization_request(&fixture, &operation, "credit-stale"),
            None,
            Some(stale),
            &fixture.fence,
            now + 5,
        ),
        Err(AdmissionCaptureError::Fenced)
    );
    assert_eq!(account_state(&fixture)?, (1, 0, 0, 7, 7));
    assert_eq!(
        authorization_mutation_counts(&fixture, &operation, "credit-stale")?,
        (0, 0, 0, 0)
    );
    Ok(())
}

#[test]
fn credit_authorization_rejects_duplicate_action_nonce_without_second_mutation(
) -> CreditAuthorizationTestResult {
    let fixture = fixture();
    let authorities = CreditAuthorityFixture::new()?;
    let now = now_ms();
    let first = broker_registered_credit_operation(&fixture, "request-credit-first", now)?;
    let first_request = authorities.reservation_request(
        first.binding().operation_id().as_str(),
        first.binding().request_id().as_str(),
        "nonce-credit-shared",
        SOURCE_VERSION,
        now + 3,
    )?;
    provision_account(&fixture, &first_request, now + 3)?;
    let first_lease = claim(&fixture, &first, "sqlite-credit-authorizer", now + 4);
    fixture.store.authorize_budget_and_commit_admission(
        &first,
        &first_lease,
        budget_authorization_request(&fixture, &first, "credit-first"),
        None,
        Some(first_request),
        &fixture.fence,
        now + 5,
    )?;

    let second = broker_registered_credit_operation(&fixture, "request-credit-second", now + 10)?;
    let second_request = authorities.reservation_request(
        second.binding().operation_id().as_str(),
        second.binding().request_id().as_str(),
        "nonce-credit-shared",
        SOURCE_VERSION + 1,
        now + 13,
    )?;
    let second_lease = claim(&fixture, &second, "sqlite-credit-authorizer", now + 14);
    let error = fixture
        .store
        .authorize_budget_and_commit_admission(
            &second,
            &second_lease,
            budget_authorization_request(&fixture, &second, "credit-second"),
            None,
            Some(second_request),
            &fixture.fence,
            now + 15,
        )
        .expect_err("duplicate credit action nonce must be rejected");
    assert!(matches!(
        error,
        AdmissionCaptureError::Invariant(ref detail)
            if detail.contains("action nonce was already consumed")
    ));
    assert_eq!(account_state(&fixture)?, (1, 0, 1_000, 8, 8));
    assert_eq!(
        authorization_mutation_counts(&fixture, &second, "credit-second")?,
        (0, 0, 0, 0)
    );
    assert_eq!(
        fixture.store.connection()?.query_row(
            "SELECT COUNT(*) FROM credit_exposure_reservations",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        1
    );
    Ok(())
}

#[path = "credit_terminal_invariants.rs"]
mod credit_terminal_invariants;
