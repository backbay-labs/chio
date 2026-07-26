use std::error::Error;

use chio_core::crypto::{sha256_hex, Keypair};
use chio_credit::factor::*;
use chio_credit::obligation::*;

use super::*;

#[path = "../../../../../economy/chio-credit/tests/factor_claim_support/mod.rs"]
mod factor_claim_support;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const EFFECTIVE_AT: u64 = 1_050;
const RESULT_AT: u64 = 1_100;
const TRUSTED_TIME: u64 = 1_200;
const EXPIRES_AT: u64 = 1_300;
const DUE_AT: u64 = 10_000;
const SNAPSHOT_VERSION: u64 = 7;
const RESOURCE_FENCE: u64 = 11;
const OBSERVED_SNAPSHOT_VERSION: u64 = 9;
const OBSERVED_RESOURCE_FENCE: u64 = 15;
const AGREEMENT_ID: &str = "assignment-agreement-1";
const SELLER_ID: &str = "did:chio:seller";
const BUYER_ID: &str = "did:chio:buyer";
const BUYER_DESTINATION: &str = "acct:buyer";
const RESULT_AUTHORITY_ID: &str = "obligor-disposition-authority";
const RESULT_AUTHORITY_EPOCH: u64 = 3;

struct EconomyFixture {
    atom: ObligationAtomV1,
    disposition: ObligationDispositionRecordV1,
    settlement: ObligationSettlementLifecycleV1,
    status: VerifiedObligationStatusProofV1,
    claim: VerifiedReceivableClaimV1,
    offer: AssignmentOfferV1,
    request: NormalizedAssignmentRequestV1,
    result_signer: Keypair,
    result_trust: AssignmentResultAuthorityTrustV1,
    assignment_signer: Keypair,
    seller_signer: Keypair,
    buyer_signer: Keypair,
}

struct ProjectionFixture {
    economy: EconomyFixture,
    authorization: VerifiedAssignmentAuthorizationSetV1,
    prepared: AdmissionOperationV1,
    ready: AdmissionOperationV1,
    submitted: AdmissionOperationV1,
    acknowledgement: VerifiedAssignmentAcknowledgementV1,
    not_applied: VerifiedAssignmentNotAppliedV1,
    context: AdmissionProjectionContext,
}

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn identifier(field: &'static str, value: impl Into<String>) -> TestResult<AdmissionIdentifier> {
    Ok(AdmissionIdentifier::try_new(field, value.into())?)
}

fn admission_digest(field: &'static str, value: impl Into<String>) -> TestResult<AdmissionDigest> {
    Ok(AdmissionDigest::try_new(field, value.into())?)
}

fn store_fence() -> StoreMutationFence {
    StoreMutationFence {
        store_uuid: "factor-store".to_owned(),
        lease_id: "factor-owner-lease".to_owned(),
        owner_epoch: 3,
    }
}

fn operation_binding(
    kind: AdmissionOperationKind,
    request_digest: &str,
    request_id: &str,
) -> TestResult<AdmissionOperationBindingV1> {
    let requirements = match kind {
        AdmissionOperationKind::ToolDispatch => AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            ..AdmissionParticipantRequirements::NONE
        },
        AdmissionOperationKind::GovernedActiveResponse => AdmissionParticipantRequirements {
            approval: true,
            ..AdmissionParticipantRequirements::NONE
        },
        AdmissionOperationKind::GovernedEconomicMutation => AdmissionParticipantRequirements {
            supplemental_authorization: true,
            ..AdmissionParticipantRequirements::NONE
        },
    };
    Ok(AdmissionOperationBindingV1::new(
        AdmissionOperationBindingInputV1 {
            kind,
            namespace: AuthenticatedRequestNamespace::from_authentication_context(
                identifier("coordinator_authority_id", "https://coordinator.example")?,
                "tenant-factor",
            )?,
            request_id: identifier("request_id", request_id)?,
            capability_id: identifier("capability_id", "factor-capability")?,
            authorization_capability_hash: admission_digest(
                "authorization_capability_hash",
                digest("factor-admission-authorization"),
            )?,
            request_binding: AdmissionRequestBindingV1::new(
                admission_digest("immutable_request_hash", request_digest)?,
                requirements,
            )?,
            policy_hash: admission_digest("policy_hash", digest("factor-policy"))?,
            effect_class: SideEffectClass::Monetary,
        },
    )?)
}

fn prepared_operation(
    kind: AdmissionOperationKind,
    request_digest: &str,
    request_id: &str,
) -> TestResult<AdmissionOperationV1> {
    Ok(AdmissionOperationV1::prepare(
        operation_binding(kind, request_digest, request_id)?,
        3,
    )?)
}

fn recovery_lease(operation: &AdmissionOperationV1) -> TestResult<AdmissionRecoveryLease> {
    let fence = store_fence();
    let claim = UntrustedAdmissionRecoveryClaim::new(
        operation.binding().operation_id().clone(),
        identifier("claimant_id", "factor-worker")?,
        identifier("coordinator_lease_id", "factor-coordinator-lease")?,
        operation.coordinator_lease_epoch(),
        operation.version(),
        2_000,
        fence.clone(),
    )?;
    Ok(qualify_recovery_claim_for_test(
        operation, claim, 900, &fence,
    )?)
}

fn apply(
    operation: &AdmissionOperationV1,
    attachments: Vec<AdmissionAttachment>,
    next_state: Option<AdmissionOperationState>,
) -> TestResult<AdmissionOperationV1> {
    let command = AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        recovery_lease(operation)?,
        attachments,
        next_state,
        None,
        None,
    )?;
    Ok(operation
        .apply_command(&command, TRUSTED_TIME)?
        .into_operation())
}

fn submitted_with_authorization(
    prepared: &AdmissionOperationV1,
    authorization_digest: &str,
) -> TestResult<(AdmissionOperationV1, AdmissionOperationV1)> {
    let attached = apply(
        prepared,
        vec![AdmissionAttachment::SupplementalAuthorizationDigest(
            admission_digest("supplemental_authorization_digest", authorization_digest)?,
        )],
        None,
    )?;
    let ready = apply(
        &attached,
        Vec::new(),
        Some(AdmissionOperationState::MutationReady),
    )?;
    let submitted = apply(
        &ready,
        Vec::new(),
        Some(AdmissionOperationState::MutationSubmitted),
    )?;
    Ok((ready, submitted))
}

fn assignment_request(
    atom: &ObligationAtomV1,
    disposition: &ObligationDispositionRecordV1,
    settlement: &ObligationSettlementLifecycleV1,
    claim: &ReceivableClaimV1,
    offer: &AssignmentOfferV1,
    action_nonce: &str,
) -> TestResult<NormalizedAssignmentRequestV1> {
    Ok(NormalizedAssignmentRequestV1::new(
        NormalizedAssignmentRequestInputV1 {
            obligation_id: atom.obligation_id().to_owned(),
            obligation_atom_digest: atom.digest()?,
            claim_digest: claim.digest()?,
            offer_digest: offer.digest()?,
            seller_id: SELLER_ID.to_owned(),
            buyer_id: BUYER_ID.to_owned(),
            buyer_settlement_destination_ref: BUYER_DESTINATION.to_owned(),
            agreed_price: offer.minimum_price().clone(),
            agreed_discount_bps: offer.asking_discount_bps(),
            expected_disposition_version: disposition.version(),
            expected_disposition_lifecycle_fence: disposition.lifecycle_fence(),
            expected_settlement_lifecycle_version: settlement.version(),
            expected_settlement_lifecycle_fence: settlement.lifecycle_fence(),
            action_nonce: action_nonce.to_owned(),
            effective_at_unix_ms: EFFECTIVE_AT,
            due_at_unix_ms: atom.due_at_unix_ms(),
            expires_at_unix_ms: EXPIRES_AT,
        },
    )?)
}

fn economy_fixture() -> TestResult<EconomyFixture> {
    let evidence = factor_claim_support::build_claim_evidence()?;
    let atom = evidence.atom;
    let disposition = evidence.disposition;
    let settlement = evidence.settlement_lifecycle;
    let status = evidence.status_proof;
    let claim = evidence.verified_claim;
    let result_signer = evidence.result_signer;
    let offer = AssignmentOfferV1::new(claim.claim(), 1_000, 1_020, 1_400)?;
    let request = assignment_request(
        &atom,
        &disposition,
        &settlement,
        claim.claim(),
        &offer,
        "factor-action-nonce",
    )?;
    Ok(EconomyFixture {
        atom,
        disposition,
        settlement,
        status,
        claim,
        offer,
        request,
        result_trust: AssignmentResultAuthorityTrustV1::new(
            RESULT_AUTHORITY_ID.to_owned(),
            result_signer.public_key(),
            RESULT_AUTHORITY_EPOCH,
        )?,
        result_signer,
        assignment_signer: Keypair::from_seed(&[42; 32]),
        seller_signer: Keypair::from_seed(&[43; 32]),
        buyer_signer: Keypair::from_seed(&[44; 32]),
    })
}

fn assignment_authorization(
    economy: &EconomyFixture,
    operation_id: &str,
    request: &NormalizedAssignmentRequestV1,
) -> TestResult<VerifiedAssignmentAuthorizationSetV1> {
    let request_digest = request.digest()?;
    let bind_body = AssignmentBindAuthorizationBodyV1::new(AssignmentBindAuthorizationInputV1 {
        operation_id: operation_id.to_owned(),
        normalized_request_digest: request_digest.clone(),
        obligation_atom_digest: economy.atom.digest()?,
        seller_id: SELLER_ID.to_owned(),
        buyer_id: BUYER_ID.to_owned(),
        agreement_id: AGREEMENT_ID.to_owned(),
        buyer_settlement_destination_ref: BUYER_DESTINATION.to_owned(),
        effective_at_unix_ms: EFFECTIVE_AT,
        action_nonce: request.action_nonce().to_owned(),
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: EXPIRES_AT,
        authority_id: "factor-assignment-authority".to_owned(),
        authority_key_epoch: 8,
    })?;
    let signed_bind =
        SignedAssignmentBindAuthorizationV1::sign(bind_body, &economy.assignment_signer)?;
    let bind_bytes = signed_bind.canonical_bytes()?;
    let bind_trust = AssignmentBindAuthorizationTrustV1::new(
        "factor-assignment-authority".to_owned(),
        economy.assignment_signer.public_key(),
        8,
        500,
    )?;
    let verified_bind = verify_assignment_bind_authorization(
        &bind_bytes,
        &AssignmentBindAuthorizationVerificationV1 {
            operation_id,
            normalized_request_digest: &request_digest,
            obligation_atom_digest: &economy.atom.digest()?,
            seller_id: SELLER_ID,
            buyer_id: BUYER_ID,
            agreement_id: AGREEMENT_ID,
            buyer_settlement_destination_ref: BUYER_DESTINATION,
            effective_at_unix_ms: EFFECTIVE_AT,
            action_nonce: request.action_nonce(),
            trust: &bind_trust,
            trusted_now_unix_ms: EFFECTIVE_AT,
        },
    )?;
    let agreement_body = AssignmentAgreementBodyV1::new(
        AGREEMENT_ID.to_owned(),
        operation_id.to_owned(),
        request,
        economy.claim.claim(),
        &economy.offer,
        &verified_bind,
    )?;
    let signed_agreement = SignedAssignmentAgreementV1::sign(
        agreement_body,
        9,
        &economy.seller_signer,
        10,
        &economy.buyer_signer,
    )?;
    let agreement_bytes = signed_agreement.canonical_bytes()?;
    let agreement_trust = AssignmentAgreementTrustV1::new(
        SELLER_ID.to_owned(),
        economy.seller_signer.public_key(),
        9,
        BUYER_ID.to_owned(),
        economy.buyer_signer.public_key(),
        10,
    )?;
    let verified_agreement = verify_assignment_agreement(
        &agreement_bytes,
        &AssignmentAgreementVerificationV1 {
            operation_id,
            normalized_request_digest: &request_digest,
            assignment_authority_digest: verified_bind.envelope_digest(),
            trust: &agreement_trust,
        },
    )?;
    let authorization =
        VerifiedAssignmentAuthorizationSetV1::new(verified_bind, verified_agreement)?;
    authorization.validate_submission(request, economy.claim.claim(), &economy.offer, RESULT_AT)?;
    Ok(authorization)
}

fn resulting_disposition(
    economy: &EconomyFixture,
    operation_id: &str,
    request: &NormalizedAssignmentRequestV1,
    authorization: &VerifiedAssignmentAuthorizationSetV1,
) -> TestResult<ObligationDispositionRecordV1> {
    let operation = ObligationAssignmentOperationSnapshotV1::new(
        operation_id.to_owned(),
        request.digest()?,
        &economy.disposition,
        &economy.settlement,
        SNAPSHOT_VERSION,
        RESOURCE_FENCE,
    )?
    .attach_supplemental_authorization(authorization)?;
    let assignment = ObligationAssignmentCasV1::new(
        operation,
        ObligationAssignmentCasInputV1 {
            schema: OBLIGATION_ASSIGNMENT_CAS_SCHEMA.to_owned(),
            operation_id: operation_id.to_owned(),
            normalized_request_digest: request.digest()?,
            agreement_id: AGREEMENT_ID.to_owned(),
            buyer_id: BUYER_ID.to_owned(),
            buyer_settlement_destination_ref: BUYER_DESTINATION.to_owned(),
            supplemental_authorization_digest: authorization.digest().to_owned(),
            status_proof_digest: economy.status.envelope_digest().to_owned(),
            effective_at_unix_ms: EFFECTIVE_AT,
        },
        authorization.clone(),
        request,
    )?;
    Ok(economy.disposition.compare_and_swap_assignment(
        &economy.atom,
        &economy.settlement,
        &economy.status,
        &assignment,
        RESULT_AT,
    )?)
}

fn acknowledgement(
    economy: &EconomyFixture,
    operation_id: &str,
    request: &NormalizedAssignmentRequestV1,
    authorization: &VerifiedAssignmentAuthorizationSetV1,
    resulting_disposition: &ObligationDispositionRecordV1,
    acknowledged_at_unix_ms: u64,
) -> TestResult<VerifiedAssignmentAcknowledgementV1> {
    let body = AssignmentAcknowledgementBodyV1::new(AssignmentAcknowledgementInputV1 {
        operation_id: operation_id.to_owned(),
        normalized_request_digest: request.digest()?,
        agreement_id: AGREEMENT_ID.to_owned(),
        agreement_body_digest: authorization.agreement().body_digest().to_owned(),
        obligation_id: economy.atom.obligation_id().to_owned(),
        obligation_atom_digest: economy.atom.digest()?,
        buyer_id: BUYER_ID.to_owned(),
        buyer_settlement_destination_ref: BUYER_DESTINATION.to_owned(),
        assignment_authorization_set_digest: authorization.digest().to_owned(),
        status_proof_digest: economy.status.envelope_digest().to_owned(),
        prior_disposition_version: economy.disposition.version(),
        prior_disposition_lifecycle_fence: economy.disposition.lifecycle_fence(),
        prior_disposition_digest: economy.disposition.digest(&economy.atom)?,
        resulting_disposition_version: resulting_disposition.version(),
        resulting_disposition_lifecycle_fence: resulting_disposition.lifecycle_fence(),
        resulting_disposition_digest: resulting_disposition.digest(&economy.atom)?,
        expected_snapshot_version: SNAPSHOT_VERSION,
        resulting_snapshot_version: SNAPSHOT_VERSION + 1,
        expected_resource_fence: RESOURCE_FENCE,
        resulting_resource_fence: RESOURCE_FENCE + 1,
        authority_id: RESULT_AUTHORITY_ID.to_owned(),
        authority_key_epoch: RESULT_AUTHORITY_EPOCH,
        effective_at_unix_ms: EFFECTIVE_AT,
        due_at_unix_ms: DUE_AT,
        acknowledged_at_unix_ms,
    })?;
    let signed = SignedAssignmentAcknowledgementV1::sign(body, &economy.result_signer)?;
    let canonical = signed.canonical_bytes()?;
    Ok(verify_assignment_acknowledgement(
        &canonical,
        &AssignmentAcknowledgementVerificationV1 {
            atom: &economy.atom,
            request,
            claim: &economy.claim,
            offer: &economy.offer,
            authorization,
            status_proof: &economy.status,
            resulting_disposition,
            trust: &economy.result_trust,
        },
    )?)
}

fn not_applied(
    economy: &EconomyFixture,
    operation_id: &str,
    authorization: &VerifiedAssignmentAuthorizationSetV1,
) -> TestResult<VerifiedAssignmentNotAppliedV1> {
    let no_mutation_proof_digest = digest("factor-no-mutation-proof");
    let body = AssignmentNotAppliedBodyV1::new(AssignmentNotAppliedInputV1 {
        operation_id: operation_id.to_owned(),
        normalized_request_digest: economy.request.digest()?,
        agreement_id: AGREEMENT_ID.to_owned(),
        agreement_body_digest: authorization.agreement().body_digest().to_owned(),
        obligation_id: economy.atom.obligation_id().to_owned(),
        obligation_atom_digest: economy.atom.digest()?,
        assignment_authorization_set_digest: authorization.digest().to_owned(),
        status_proof_digest: economy.status.envelope_digest().to_owned(),
        expected_disposition_version: economy.request.expected_disposition_version(),
        expected_disposition_lifecycle_fence: economy
            .request
            .expected_disposition_lifecycle_fence(),
        expected_settlement_lifecycle_version: economy
            .request
            .expected_settlement_lifecycle_version(),
        expected_settlement_lifecycle_fence: economy.request.expected_settlement_lifecycle_fence(),
        expected_snapshot_version: SNAPSHOT_VERSION,
        expected_resource_fence: RESOURCE_FENCE,
        observed_disposition_version: economy.disposition.version(),
        observed_disposition_lifecycle_fence: economy.disposition.lifecycle_fence(),
        observed_disposition_digest: economy.disposition.digest(&economy.atom)?,
        observed_settlement_lifecycle_version: economy.settlement.version(),
        observed_settlement_lifecycle_fence: economy.settlement.lifecycle_fence(),
        observed_settlement_lifecycle_digest: economy.settlement.digest(&economy.atom)?,
        observed_snapshot_version: OBSERVED_SNAPSHOT_VERSION,
        resource_fence: OBSERVED_RESOURCE_FENCE,
        reason: AssignmentNotAppliedReasonV1::OperationConflict,
        no_mutation_proof_digest: no_mutation_proof_digest.clone(),
        authority_id: RESULT_AUTHORITY_ID.to_owned(),
        authority_key_epoch: RESULT_AUTHORITY_EPOCH,
        decided_at_unix_ms: RESULT_AT,
    })?;
    let signed = SignedAssignmentNotAppliedV1::sign(body, &economy.result_signer)?;
    let canonical = signed.canonical_bytes()?;
    Ok(verify_assignment_not_applied(
        &canonical,
        &AssignmentNotAppliedVerificationV1 {
            atom: &economy.atom,
            request: &economy.request,
            claim: &economy.claim,
            offer: &economy.offer,
            authorization,
            status_proof: &economy.status,
            observed_disposition: &economy.disposition,
            observed_settlement_lifecycle: &economy.settlement,
            observed_snapshot_version: OBSERVED_SNAPSHOT_VERSION,
            observed_resource_fence: OBSERVED_RESOURCE_FENCE,
            no_mutation_proof_digest: &no_mutation_proof_digest,
            trust: &economy.result_trust,
        },
    )?)
}

fn projection_context(operation: &AdmissionOperationV1) -> TestResult<AdmissionProjectionContext> {
    Ok(AdmissionProjectionContext {
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.binding().request_id().clone(),
        expected_operation_version: operation.version(),
        trusted_time_unix_ms: TRUSTED_TIME,
        coordinator_lease_id: identifier("coordinator_lease_id", "factor-coordinator-lease")?,
        coordinator_lease_epoch: operation.coordinator_lease_epoch(),
        store_fence: store_fence(),
    })
}

fn economic_terminal_capabilities() -> AdmissionProjectionCapabilities {
    AdmissionProjectionCapabilities {
        operation_terminal: true,
        economic_mutation_terminal: true,
        ..AdmissionProjectionCapabilities::default()
    }
}

fn fixture() -> TestResult<ProjectionFixture> {
    let economy = economy_fixture()?;
    let request_digest = economy.request.digest()?;
    let prepared = prepared_operation(
        AdmissionOperationKind::GovernedEconomicMutation,
        &request_digest,
        "factor-request",
    )?;
    let operation_id = prepared.binding().operation_id().as_str().to_owned();
    let authorization = assignment_authorization(&economy, &operation_id, &economy.request)?;
    let resulting_disposition =
        resulting_disposition(&economy, &operation_id, &economy.request, &authorization)?;
    let acknowledgement = acknowledgement(
        &economy,
        &operation_id,
        &economy.request,
        &authorization,
        &resulting_disposition,
        RESULT_AT,
    )?;
    let not_applied = not_applied(&economy, &operation_id, &authorization)?;
    let (ready, submitted) = submitted_with_authorization(&prepared, authorization.digest())?;
    let context = projection_context(&submitted)?;
    Ok(ProjectionFixture {
        economy,
        authorization,
        prepared,
        ready,
        submitted,
        acknowledgement,
        not_applied,
        context,
    })
}

#[test]
fn signed_anchored_economic_terminal_preserves_the_anchor_requirement() -> TestResult {
    let fixture = fixture()?;
    let signer = Keypair::from_seed(&[92; 32]);
    let mut not_applied = verified_factor_assignment_not_applied_projection(
        &fixture.submitted,
        fixture.context.clone(),
        &fixture.not_applied,
    )?;
    let AdmissionTerminalProjection::EconomicMutationNotApplied { result, .. } = &mut not_applied
    else {
        return Err("expected not-applied economic mutation projection".into());
    };
    result.0.anchored_effect = true;
    let not_applied = SignedAdmissionTerminalProjectionV1::from_verified(
        &fixture.submitted,
        &not_applied,
        &economic_terminal_capabilities(),
        &signer,
    )?
    .verify()?;
    assert!(not_applied.requires_anchored_economic_commit());
    Ok(())
}

#[test]
fn signed_legacy_factor_terminals_remain_unanchored() -> TestResult {
    let fixture = fixture()?;
    let signer = Keypair::from_seed(&[93; 32]);
    let projections = [
        verified_factor_assignment_applied_projection(
            &fixture.submitted,
            fixture.context.clone(),
            &fixture.acknowledgement,
        )?,
        verified_factor_assignment_not_applied_projection(
            &fixture.submitted,
            fixture.context.clone(),
            &fixture.not_applied,
        )?,
    ];
    for projection in projections {
        let verified = SignedAdmissionTerminalProjectionV1::from_verified(
            &fixture.submitted,
            &projection,
            &economic_terminal_capabilities(),
            &signer,
        )?
        .verify()?;
        assert!(!verified.requires_anchored_economic_commit());
    }
    Ok(())
}

#[test]
fn applied_projection_maps_the_verified_result_exactly() -> TestResult {
    let fixture = fixture()?;
    let projection = verified_factor_assignment_applied_projection(
        &fixture.submitted,
        fixture.context.clone(),
        &fixture.acknowledgement,
    )?;
    let AdmissionTerminalProjection::EconomicMutationApplied {
        context,
        result,
        audit_event,
    } = projection
    else {
        return Err("expected applied economic mutation projection".into());
    };
    let binding = &result.0;
    let body = fixture.acknowledgement.body();
    assert_eq!(context, fixture.context);
    assert_eq!(binding.record_id.as_str(), body.acknowledgement_id());
    assert_eq!(
        binding.record_digest.as_str(),
        fixture.acknowledgement.envelope_digest()
    );
    assert_eq!(binding.participant_id.as_str(), body.authority_id());
    assert_eq!(binding.participant_key_epoch, body.authority_key_epoch());
    assert_eq!(binding.resource_id.as_str(), body.obligation_id());
    assert_eq!(
        binding.expected_resource_version,
        body.expected_snapshot_version()
    );
    assert_eq!(
        binding.resulting_resource_version,
        body.resulting_snapshot_version()
    );
    assert_ne!(
        binding.expected_resource_version,
        body.expected_resource_fence()
    );
    assert_ne!(
        binding.resulting_resource_version,
        body.resulting_resource_fence()
    );
    assert_eq!(
        binding.expected_resource_fence.as_str(),
        format!(
            "factor-assignment-resource-fence:{}",
            body.expected_resource_fence()
        )
    );
    assert_eq!(
        binding.resulting_resource_fence.as_str(),
        format!(
            "factor-assignment-resource-fence:{}",
            body.resulting_resource_fence()
        )
    );
    assert_ne!(
        binding.expected_resource_fence,
        binding.resulting_resource_fence
    );
    assert_eq!(
        binding.immutable_request_digest,
        *fixture.submitted.binding().request_binding_hash()
    );
    assert_eq!(
        binding.signature_digest.as_str(),
        fixture.acknowledgement.signature_digest()
    );
    assert_ne!(
        binding.signature_digest.as_str(),
        fixture.acknowledgement.envelope_digest()
    );
    assert_eq!(binding.status, EconomicMutationTerminalStatus::Applied);
    assert_eq!(
        audit_event.record_id.as_str(),
        format!("{}:audit", body.acknowledgement_id())
    );
    assert_eq!(
        audit_event.record_digest.as_str(),
        fixture.acknowledgement.envelope_digest()
    );
    Ok(())
}

#[test]
fn not_applied_projection_preserves_observed_snapshot_and_fence() -> TestResult {
    let fixture = fixture()?;
    let projection = verified_factor_assignment_not_applied_projection(
        &fixture.submitted,
        fixture.context.clone(),
        &fixture.not_applied,
    )?;
    let AdmissionTerminalProjection::EconomicMutationNotApplied {
        context,
        result,
        audit_event,
    } = projection
    else {
        return Err("expected not-applied economic mutation projection".into());
    };
    let binding = &result.0;
    let body = fixture.not_applied.body();
    assert_eq!(context, fixture.context);
    assert_eq!(binding.record_id.as_str(), body.result_id());
    assert_eq!(
        binding.record_digest.as_str(),
        fixture.not_applied.envelope_digest()
    );
    assert_eq!(binding.participant_id.as_str(), body.authority_id());
    assert_eq!(binding.participant_key_epoch, body.authority_key_epoch());
    assert_eq!(binding.resource_id.as_str(), body.obligation_id());
    assert_eq!(
        binding.expected_resource_version,
        body.expected_snapshot_version()
    );
    assert_eq!(
        binding.resulting_resource_version,
        body.observed_snapshot_version()
    );
    assert_ne!(
        binding.expected_resource_version,
        body.expected_resource_fence()
    );
    assert_ne!(binding.resulting_resource_version, body.resource_fence());
    assert_eq!(
        binding.expected_resource_fence.as_str(),
        format!(
            "factor-assignment-resource-fence:{}",
            body.expected_resource_fence()
        )
    );
    assert_eq!(
        binding.resulting_resource_fence.as_str(),
        format!("factor-assignment-resource-fence:{}", body.resource_fence())
    );
    assert_ne!(
        binding.expected_resource_fence,
        binding.resulting_resource_fence
    );
    assert_eq!(
        binding.immutable_request_digest,
        *fixture.submitted.binding().request_binding_hash()
    );
    assert_eq!(
        binding.signature_digest.as_str(),
        fixture.not_applied.signature_digest()
    );
    assert_ne!(
        binding.signature_digest.as_str(),
        fixture.not_applied.envelope_digest()
    );
    assert_eq!(
        binding.status,
        EconomicMutationTerminalStatus::PermanentlyNotApplied
    );
    assert_eq!(
        audit_event.record_id.as_str(),
        format!("{}:audit", body.result_id())
    );
    assert_eq!(
        audit_event.record_digest.as_str(),
        fixture.not_applied.envelope_digest()
    );
    Ok(())
}

#[test]
fn projection_rejects_mismatched_source_and_context() -> TestResult {
    let fixture = fixture()?;
    let request_digest = fixture.economy.request.digest()?;
    let wrong_kind = prepared_operation(
        AdmissionOperationKind::GovernedActiveResponse,
        &request_digest,
        "factor-wrong-kind",
    )?;
    assert!(matches!(
        verified_factor_assignment_applied_projection(
            &wrong_kind,
            projection_context(&wrong_kind)?,
            &fixture.acknowledgement,
        ),
        Err(AdmissionOperationError::InvalidEconomicMutationBinding)
    ));

    assert!(matches!(
        verified_factor_assignment_applied_projection(
            &fixture.ready,
            projection_context(&fixture.ready)?,
            &fixture.acknowledgement,
        ),
        Err(AdmissionOperationError::InvalidEconomicMutationBinding)
    ));

    let other_prepared = prepared_operation(
        AdmissionOperationKind::GovernedEconomicMutation,
        &request_digest,
        "factor-other-operation",
    )?;
    let (_, wrong_operation) =
        submitted_with_authorization(&other_prepared, fixture.authorization.digest())?;
    assert!(matches!(
        verified_factor_assignment_applied_projection(
            &wrong_operation,
            projection_context(&wrong_operation)?,
            &fixture.acknowledgement,
        ),
        Err(AdmissionOperationError::InvalidEconomicMutationBinding)
    ));

    let wrong_request = assignment_request(
        &fixture.economy.atom,
        &fixture.economy.disposition,
        &fixture.economy.settlement,
        fixture.economy.claim.claim(),
        &fixture.economy.offer,
        "factor-other-action-nonce",
    )?;
    let wrong_request_authorization = assignment_authorization(
        &fixture.economy,
        fixture.prepared.binding().operation_id().as_str(),
        &wrong_request,
    )?;
    let wrong_request_result = resulting_disposition(
        &fixture.economy,
        fixture.prepared.binding().operation_id().as_str(),
        &wrong_request,
        &wrong_request_authorization,
    )?;
    let wrong_request_acknowledgement = acknowledgement(
        &fixture.economy,
        fixture.prepared.binding().operation_id().as_str(),
        &wrong_request,
        &wrong_request_authorization,
        &wrong_request_result,
        RESULT_AT,
    )?;
    let (_, wrong_request_operation) =
        submitted_with_authorization(&fixture.prepared, wrong_request_authorization.digest())?;
    assert!(matches!(
        verified_factor_assignment_applied_projection(
            &wrong_request_operation,
            projection_context(&wrong_request_operation)?,
            &wrong_request_acknowledgement,
        ),
        Err(AdmissionOperationError::InvalidEconomicMutationBinding)
    ));

    let (_, wrong_authorization) =
        submitted_with_authorization(&fixture.prepared, &digest("wrong-authorization-set"))?;
    assert!(matches!(
        verified_factor_assignment_applied_projection(
            &wrong_authorization,
            projection_context(&wrong_authorization)?,
            &fixture.acknowledgement,
        ),
        Err(AdmissionOperationError::InvalidEconomicMutationBinding)
    ));

    let mut future_context = fixture.context.clone();
    future_context.trusted_time_unix_ms = RESULT_AT - 1;
    assert!(matches!(
        verified_factor_assignment_applied_projection(
            &fixture.submitted,
            future_context,
            &fixture.acknowledgement,
        ),
        Err(AdmissionOperationError::InvalidEconomicMutationBinding)
    ));

    let mut mismatched_context = fixture.context.clone();
    mismatched_context.expected_operation_version += 1;
    assert!(matches!(
        verified_factor_assignment_applied_projection(
            &fixture.submitted,
            mismatched_context,
            &fixture.acknowledgement,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));
    Ok(())
}
