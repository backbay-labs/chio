use std::fmt::Debug;

use chio_core_types::economic_continuity::{
    EconomicAdmissionHandoffStateV1, EconomicAdmissionHandoffV1, EconomicEffectSlotV1,
    EconomicEffectStateV1, EconomicEffectTargetV1, EconomicFrostBindingV1,
    EconomicRequestBindingV1, EconomicResourceKeyV1, CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA,
};
use chio_core_types::StoreMutationFence;

use super::*;
use crate::credit::{
    CapitalBookQuery, CapitalBookSourceKind, CapitalExecutionAuthorityStep,
    CapitalExecutionInstructionAction, CapitalExecutionInstructionArtifact,
    CapitalExecutionInstructionSupportBoundary, CapitalExecutionIntendedState,
    CapitalExecutionRail, CapitalExecutionReconciledState, CapitalExecutionRole,
    CapitalExecutionWindow, SignedCapitalExecutionInstruction,
    CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA,
};
use crate::crypto::Keypair;

fn required<T, E: Debug>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error:?}"),
    }
}

fn present<T>(value: Option<T>, context: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("{context}"),
    }
}

fn digest(byte: &str) -> String {
    byte.repeat(64)
}

fn money(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn claim() -> ParametricClaimRecordV1 {
    let key = TriggerInstanceKeyV1 {
        parametric_policy_body_digest: digest("1"),
        bound_coverage_body_digest: digest("2"),
        subject_key: "subject-1".to_string(),
        trigger_predicate_body_digest: digest("3"),
        window_start: 100,
        window_end: 200,
        evidence_range_digest: digest("4"),
    };
    let trigger_instance_id = required(key.trigger_instance_id(), "trigger instance id");
    let claim_id = required(
        parametric_claim_id(&trigger_instance_id),
        "parametric claim id",
    );
    let record = ParametricClaimRecordV1 {
        schema: PARAMETRIC_CLAIM_RECORD_SCHEMA.to_string(),
        identity: ParametricClaimIdentity {
            key,
            trigger_instance_id,
            claim_id,
        },
        coverage_authority_id: "carrier-1".to_string(),
        payer_id: "payer-1".to_string(),
        beneficiary_id: "subject-1".to_string(),
        funding_facility_id: "facility-1".to_string(),
        payout_rail: ParametricPayoutRail {
            kind: CapitalExecutionRailKind::Web3,
            rail_id: "rail-1".to_string(),
            destination_account_digest: required(
                parametric_payout_destination_account_digest("destination-1"),
                "destination digest",
            ),
        },
        payout_mode: ParametricPayoutMode::Automatic,
        trigger_magnitude: TriggerMagnitude::Count { value: 1 },
        payout_amount: money(500),
        opened_at: 200,
        contest_deadline: None,
        state: ParametricClaimStateV1::Ready,
        version: 1,
        lifecycle_fence: 1,
        contest_digest: None,
        payout_binding: None,
    };
    required(record.validate(), "valid claim");
    record
}

fn signed_authority_step(
    role: CapitalExecutionRole,
    signer: &Keypair,
) -> CapitalExecutionAuthorityStep {
    required(
        CapitalExecutionAuthorityStep::signed(role, signer, 10, 30, None),
        "capital authority step",
    )
}

fn capital_instruction_body(
    facility_signer: &Keypair,
    custodian: &Keypair,
) -> CapitalExecutionInstructionArtifact {
    CapitalExecutionInstructionArtifact {
        schema: CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
        instruction_id: String::new(),
        issued_at: 10,
        query: CapitalBookQuery {
            agent_subject: Some("subject-1".to_string()),
            ..CapitalBookQuery::default()
        },
        subject_key: "subject-1".to_string(),
        source_id: "facility-1".to_string(),
        source_kind: CapitalBookSourceKind::FacilityCommitment,
        governed_receipt_id: Some("receipt-1".to_string()),
        completion_flow_row_id: Some("completion-1".to_string()),
        action: CapitalExecutionInstructionAction::TransferFunds,
        owner_role: CapitalExecutionRole::FacilityProvider,
        counterparty_role: CapitalExecutionRole::AgentCounterparty,
        counterparty_id: "subject-1".to_string(),
        amount: Some(money(500)),
        authority_chain: vec![
            signed_authority_step(CapitalExecutionRole::FacilityProvider, facility_signer),
            signed_authority_step(CapitalExecutionRole::Custodian, custodian),
        ],
        execution_window: CapitalExecutionWindow {
            not_before: 10,
            not_after: 30,
        },
        rail: CapitalExecutionRail {
            kind: CapitalExecutionRailKind::Web3,
            rail_id: "rail-1".to_string(),
            custody_provider_id: custodian.public_key().to_hex(),
            source_account_ref: Some("facility-source-1".to_string()),
            destination_account_ref: Some("destination-1".to_string()),
            jurisdiction: Some("US-NY".to_string()),
        },
        intended_state: CapitalExecutionIntendedState::PendingExecution,
        reconciled_state: CapitalExecutionReconciledState::NotObserved,
        related_instruction_id: None,
        observed_execution: None,
        support_boundary: CapitalExecutionInstructionSupportBoundary {
            automatic_dispatch_supported: true,
            ..CapitalExecutionInstructionSupportBoundary::default()
        },
        evidence_refs: Vec::new(),
        description: "parametric payout".to_string(),
    }
}

struct PayoutFixture {
    claim: ParametricClaimRecordV1,
    intent: ParametricPayoutIntentV1,
    preparation: ParametricPayoutPreparationBindingV1,
    intent_signer: Keypair,
    instruction_signer: Keypair,
    facility_signer: Keypair,
    custodian: Keypair,
}

impl PayoutFixture {
    fn trust_at(&self, trusted_now: u64) -> ParametricPayoutInstructionTrustV1 {
        required(
            ParametricPayoutInstructionTrustV1::new(ParametricPayoutInstructionTrustInputV1 {
                trusted_now,
                instruction_signer_key: self.instruction_signer.public_key(),
                instruction_signer_key_epoch: 2,
                funding_facility_id: "facility-1".to_string(),
                facility_authority_key: self.facility_signer.public_key(),
                facility_authority_key_epoch: 4,
                authorized_source_account_digest: required(
                    parametric_payout_source_account_digest("facility-source-1"),
                    "authorized source account digest",
                ),
                custody_provider_id: self.custodian.public_key().to_hex(),
                custodian_authority_key: self.custodian.public_key(),
                custodian_authority_key_epoch: 3,
            }),
            "payout instruction trust",
        )
    }

    fn signed_intent(&self) -> SignedParametricPayoutIntentV1 {
        required(
            SignedParametricPayoutIntentV1::sign(self.intent.clone(), &self.intent_signer),
            "signed payout intent",
        )
    }
}

fn fixture() -> PayoutFixture {
    let claim = claim();
    let intent_signer = Keypair::from_seed(&[21; 32]);
    let instruction_signer = Keypair::from_seed(&[11; 32]);
    let facility_signer = Keypair::from_seed(&[12; 32]);
    let custodian = Keypair::from_seed(&[13; 32]);
    let mut instruction_body = capital_instruction_body(&facility_signer, &custodian);
    let request = EconomicRequestBindingV1 {
        request_namespace_digest: digest("7"),
        request_id: "request-1".to_string(),
        request_binding_digest: digest("8"),
    };
    let coverage_head_digest = digest("c");
    let coverage_reservation_id = digest("5");
    let operation_id = digest("6");
    let target_id = custodian.public_key().to_hex();
    let admission_handoff = EconomicAdmissionHandoffV1 {
        state: EconomicAdmissionHandoffStateV1::MutationSubmitted,
        operation_version: 2,
        lifecycle_fence: 2,
        store_fence: StoreMutationFence {
            store_uuid: "store-1".to_string(),
            lease_id: "lease-1".to_string(),
            owner_epoch: 1,
        },
    };
    let template_digest = required(
        capital_instruction_template_digest(&instruction_body),
        "capital instruction template digest",
    );
    let mut preparation = ParametricPayoutPreparationBindingV1 {
        schema: PARAMETRIC_PAYOUT_PREPARATION_BINDING_SCHEMA.to_string(),
        claim_id: claim.claim_id().to_string(),
        anchor_id: "anchor-1".to_string(),
        operation_id: operation_id.clone(),
        request: request.clone(),
        admission_handoff: admission_handoff.clone(),
        bound_coverage_body_digest: claim.identity.key.bound_coverage_body_digest.clone(),
        coverage_reservation_id: coverage_reservation_id.clone(),
        coverage_reservation_version: 1,
        coverage_reservation_lifecycle_fence: 1,
        coverage_head_digest: coverage_head_digest.clone(),
        target_id: target_id.clone(),
        target_key_epoch: 3,
        capital_instruction_template_digest: template_digest.clone(),
        capital_instruction_id: digest("0"),
        capital_instruction_body_digest: digest("0"),
    };
    preparation.capital_instruction_id = required(
        preparation.derived_capital_instruction_id(),
        "capital instruction id",
    );
    instruction_body.instruction_id = preparation.capital_instruction_id.clone();
    let instruction = required(
        SignedCapitalExecutionInstruction::sign(instruction_body, &instruction_signer),
        "signed capital instruction",
    );
    let body_digest = required(canonical_digest(&instruction.body), "capital body digest");
    preparation.capital_instruction_body_digest = body_digest.clone();
    required(preparation.validate(), "valid payout preparation");
    let action_digest = required(preparation.action_digest(), "payout action digest");
    let target_qualification_digest = required(
        preparation.target_qualification_digest(),
        "payout target qualification digest",
    );
    let effect_idempotency_key = required(
        preparation.effect_idempotency_key(),
        "payout effect idempotency key",
    );
    let mut effect_slot = EconomicEffectSlotV1 {
        schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_string(),
        slot_id: String::new(),
        anchor_id: "anchor-1".to_string(),
        namespace: PARAMETRIC_PAYOUT_ECONOMIC_NAMESPACE.to_string(),
        resource_key: EconomicResourceKeyV1 {
            resource_family: PARAMETRIC_LIABILITY_COVERAGE_RESOURCE_FAMILY.to_string(),
            scope_id: claim.identity.key.bound_coverage_body_digest.clone(),
            resource_id: coverage_reservation_id.clone(),
        },
        operation_id: operation_id.clone(),
        effect_kind: PARAMETRIC_PAYOUT_EFFECT_KIND.to_string(),
        request: request.clone(),
        admission_handoff,
        target: EconomicEffectTargetV1 {
            target_id,
            target_key_epoch: 3,
            qualification_digest: target_qualification_digest,
        },
        action_digest,
        parameters_digest: body_digest.clone(),
        resource_head_digest: coverage_head_digest.clone(),
        frost: None,
        idempotency_key: effect_idempotency_key,
        state: EconomicEffectStateV1::Ready,
        terminal: None,
    };
    effect_slot.slot_id = required(effect_slot.recompute_slot_id(), "effect slot id");
    let binding = ParametricPayoutBindingV1 {
        schema: PARAMETRIC_PAYOUT_BINDING_SCHEMA.to_string(),
        claim_id: claim.claim_id().to_string(),
        trigger_instance_id: claim.trigger_instance_id().to_string(),
        parametric_policy_body_digest: claim.identity.key.parametric_policy_body_digest.clone(),
        expected_claim_version: claim.version(),
        expected_lifecycle_fence: claim.lifecycle_fence(),
        bound_coverage_body_digest: claim.identity.key.bound_coverage_body_digest.clone(),
        coverage_reservation_id,
        coverage_reservation_version: 1,
        coverage_reservation_lifecycle_fence: 1,
        coverage_head_digest,
        payer_id: claim.payer_id.clone(),
        beneficiary_id: claim.beneficiary_id.clone(),
        funding_facility_id: claim.funding_facility_id.clone(),
        payout_rail: claim.payout_rail.clone(),
        operation_id,
        request,
        effect_slot_id: effect_slot.slot_id.clone(),
        effect_idempotency_key: effect_slot.idempotency_key.clone(),
        effect_slot,
        capital_instruction_id: preparation.capital_instruction_id.clone(),
        governed_receipt_id: present(
            instruction.body.governed_receipt_id.clone(),
            "governed receipt id",
        ),
        completion_flow_row_id: present(
            instruction.body.completion_flow_row_id.clone(),
            "completion flow row id",
        ),
        source_account_digest: required(
            parametric_payout_source_account_digest("facility-source-1"),
            "source account digest",
        ),
        instruction_signer_key_epoch: 2,
        facility_authority_key_epoch: 4,
        custodian_authority_key_epoch: 3,
        capital_instruction_template_digest: template_digest,
        capital_instruction_body_digest: body_digest,
        capital_instruction_envelope_digest: required(
            canonical_digest(&instruction),
            "capital envelope digest",
        ),
        amount: claim.payout_amount().clone(),
    };
    let intent = ParametricPayoutIntentV1 {
        schema: PARAMETRIC_PAYOUT_INTENT_SCHEMA.to_string(),
        payout_intent_id: required(
            parametric_payout_intent_id(claim.claim_id()),
            "payout intent id",
        ),
        binding,
        capital_instruction: instruction,
    };
    required(
        intent.validate_against_eligible_claim(&claim),
        "valid intent",
    );
    assert_eq!(
        required(intent.binding.preparation_binding(), "intent preparation"),
        preparation
    );
    PayoutFixture {
        claim,
        intent,
        preparation,
        intent_signer,
        instruction_signer,
        facility_signer,
        custodian,
    }
}

fn reseal_preparation(
    intent: &mut ParametricPayoutIntentV1,
    instruction_signer: &Keypair,
) -> ParametricPayoutPreparationBindingV1 {
    let template_digest = required(
        capital_instruction_template_digest(&intent.capital_instruction.body),
        "resealed instruction template digest",
    );
    let binding = &mut intent.binding;
    binding.capital_instruction_template_digest = template_digest.clone();
    let mut preparation = ParametricPayoutPreparationBindingV1 {
        schema: PARAMETRIC_PAYOUT_PREPARATION_BINDING_SCHEMA.to_string(),
        claim_id: binding.claim_id.clone(),
        anchor_id: binding.effect_slot.anchor_id.clone(),
        operation_id: binding.operation_id.clone(),
        request: binding.request.clone(),
        admission_handoff: binding.effect_slot.admission_handoff.clone(),
        bound_coverage_body_digest: binding.bound_coverage_body_digest.clone(),
        coverage_reservation_id: binding.coverage_reservation_id.clone(),
        coverage_reservation_version: binding.coverage_reservation_version,
        coverage_reservation_lifecycle_fence: binding.coverage_reservation_lifecycle_fence,
        coverage_head_digest: binding.coverage_head_digest.clone(),
        target_id: binding.effect_slot.target.target_id.clone(),
        target_key_epoch: binding.effect_slot.target.target_key_epoch,
        capital_instruction_template_digest: template_digest,
        capital_instruction_id: digest("0"),
        capital_instruction_body_digest: digest("0"),
    };
    preparation.capital_instruction_id = required(
        preparation.derived_capital_instruction_id(),
        "resealed capital instruction id",
    );
    intent.capital_instruction.body.instruction_id = preparation.capital_instruction_id.clone();
    intent.capital_instruction = required(
        SignedCapitalExecutionInstruction::sign(
            intent.capital_instruction.body.clone(),
            instruction_signer,
        ),
        "resealed capital instruction",
    );
    preparation.capital_instruction_body_digest = required(
        canonical_digest(&intent.capital_instruction.body),
        "resealed instruction body digest",
    );
    required(preparation.validate(), "resealed preparation");
    binding.capital_instruction_id = preparation.capital_instruction_id.clone();
    binding.capital_instruction_body_digest = preparation.capital_instruction_body_digest.clone();
    binding.capital_instruction_envelope_digest = required(
        canonical_digest(&intent.capital_instruction),
        "resealed instruction envelope digest",
    );
    binding.effect_slot.parameters_digest = binding.capital_instruction_body_digest.clone();
    binding.effect_slot.action_digest =
        required(preparation.action_digest(), "resealed action digest");
    binding.effect_slot.target.qualification_digest = required(
        preparation.target_qualification_digest(),
        "resealed target qualification digest",
    );
    binding.effect_idempotency_key = required(
        preparation.effect_idempotency_key(),
        "resealed idempotency key",
    );
    binding.effect_slot.idempotency_key = binding.effect_idempotency_key.clone();
    binding.effect_slot.slot_id = required(
        binding.effect_slot.recompute_slot_id(),
        "resealed effect slot id",
    );
    binding.effect_slot_id = binding.effect_slot.slot_id.clone();
    required(
        intent.validate(),
        "internally valid resealed payout preparation",
    );
    preparation
}

fn distinct_claim() -> ParametricClaimRecordV1 {
    let mut other = claim();
    other.identity.key.evidence_range_digest = digest("9");
    other.identity.trigger_instance_id = required(
        other.identity.key.trigger_instance_id(),
        "distinct trigger instance id",
    );
    other.identity.claim_id = required(
        parametric_claim_id(&other.identity.trigger_instance_id),
        "distinct claim id",
    );
    required(other.validate(), "distinct claim");
    other
}

#[test]
fn payout_reservation_is_fail_closed_without_the_shared_coordinator() {
    let fixture = fixture();
    let mut injected = fixture.claim.clone();
    injected.state = ParametricClaimStateV1::PayoutReserved;
    injected.version = 2;
    injected.lifecycle_fence = 2;
    injected.payout_binding = Some(fixture.intent.binding);

    assert_eq!(
        injected.validate(),
        Err(ParametricClaimError::PayoutReservationRequiresCoordinator)
    );
}

#[test]
fn signed_pre_reservation_intent_pins_current_capital_trust() {
    let fixture = fixture();
    required(
        ValidatedPreReservationParametricPayoutIntentV1::validate_pre_reservation(
            fixture.signed_intent(),
            &fixture.intent_signer.public_key(),
            &fixture.trust_at(20),
            &fixture.claim,
            &fixture.preparation,
        ),
        "verified payout intent",
    );

    assert!(
        ValidatedPreReservationParametricPayoutIntentV1::validate_pre_reservation(
            fixture.signed_intent(),
            &fixture.intent_signer.public_key(),
            &fixture.trust_at(31),
            &fixture.claim,
            &fixture.preparation,
        )
        .is_err()
    );
}

#[test]
fn pre_reservation_intent_rejects_each_continuity_substitution() {
    let fixture = fixture();

    let mut changed = fixture.intent.clone();
    changed.binding.operation_id = digest("e");
    assert!(changed
        .validate_against_eligible_claim(&fixture.claim)
        .is_err());

    let mut changed = fixture.intent.clone();
    changed.binding.request.request_id = "request-2".to_string();
    assert!(changed
        .validate_against_eligible_claim(&fixture.claim)
        .is_err());

    let mut changed = fixture.intent.clone();
    changed.binding.effect_slot.target.target_key_epoch += 1;
    assert!(changed
        .validate_against_eligible_claim(&fixture.claim)
        .is_err());

    let mut changed = fixture.intent.clone();
    changed.binding.effect_idempotency_key = digest("f");
    assert!(changed
        .validate_against_eligible_claim(&fixture.claim)
        .is_err());

    let mut changed = fixture.intent.clone();
    changed.binding.coverage_head_digest = digest("0");
    assert!(changed
        .validate_against_eligible_claim(&fixture.claim)
        .is_err());

    let mut changed = fixture.intent.clone();
    changed.binding.claim_id = digest("9");
    assert!(changed
        .validate_against_eligible_claim(&fixture.claim)
        .is_err());
}

#[test]
fn pre_reservation_validation_rejects_coherent_preparation_rebinding() {
    let fixture = fixture();
    let mut changed = fixture.intent.clone();
    changed.binding.operation_id = digest("e");
    changed.binding.effect_slot.operation_id = changed.binding.operation_id.clone();
    changed.binding.request.request_id = "request-2".to_string();
    changed.binding.effect_slot.request = changed.binding.request.clone();
    changed.binding.coverage_reservation_id = digest("f");
    changed.binding.effect_slot.resource_key.resource_id =
        changed.binding.coverage_reservation_id.clone();
    changed.binding.coverage_head_digest = digest("a");
    changed.binding.effect_slot.resource_head_digest = changed.binding.coverage_head_digest.clone();
    changed
        .binding
        .effect_slot
        .admission_handoff
        .store_fence
        .owner_epoch += 1;
    let changed_preparation = reseal_preparation(&mut changed, &fixture.instruction_signer);
    assert_ne!(changed_preparation, fixture.preparation);
    let signed = required(
        SignedParametricPayoutIntentV1::sign(changed, &fixture.intent_signer),
        "coherently rebound payout intent",
    );
    assert!(matches!(
        ValidatedPreReservationParametricPayoutIntentV1::validate_pre_reservation(
            signed,
            &fixture.intent_signer.public_key(),
            &fixture.trust_at(20),
            &fixture.claim,
            &fixture.preparation,
        ),
        Err(ParametricClaimError::PayoutIntentConflict)
    ));
}

#[test]
fn pre_reservation_validation_rejects_untrusted_source_account() {
    let fixture = fixture();
    let mut changed = fixture.intent.clone();
    changed.capital_instruction.body.rail.source_account_ref = Some("attacker-source".to_string());
    changed.binding.source_account_digest = required(
        parametric_payout_source_account_digest("attacker-source"),
        "attacker source digest",
    );
    let changed_preparation = reseal_preparation(&mut changed, &fixture.instruction_signer);
    let signed = required(
        SignedParametricPayoutIntentV1::sign(changed, &fixture.intent_signer),
        "source-rebound payout intent",
    );
    assert!(matches!(
        ValidatedPreReservationParametricPayoutIntentV1::validate_pre_reservation(
            signed,
            &fixture.intent_signer.public_key(),
            &fixture.trust_at(20),
            &fixture.claim,
            &changed_preparation,
        ),
        Err(ParametricClaimError::UntrustedCapitalInstruction)
    ));
}

#[test]
fn payout_preparation_rejects_action_target_frost_and_resource_substitution() {
    let fixture = fixture();

    let mut changed = fixture.intent.clone();
    changed.binding.effect_slot.action_digest = digest("a");
    assert!(changed.validate().is_err());

    let mut changed = fixture.intent.clone();
    changed.binding.effect_slot.target.qualification_digest = digest("a");
    assert!(changed.validate().is_err());

    let mut changed = fixture.intent.clone();
    changed.binding.effect_slot.frost = Some(EconomicFrostBindingV1 {
        authorization_slot_id: digest("a"),
        authorization_id: digest("b"),
        action_digest: changed.binding.effect_slot.action_digest.clone(),
        signed_envelope_digest: digest("c"),
    });
    assert!(changed.validate().is_err());

    let mut changed = fixture.intent.clone();
    changed.binding.effect_slot.namespace = "other".to_string();
    changed.binding.effect_slot.slot_id = required(
        changed.binding.effect_slot.recompute_slot_id(),
        "substituted namespace slot id",
    );
    changed.binding.effect_slot_id = changed.binding.effect_slot.slot_id.clone();
    assert!(changed.validate().is_err());

    let mut changed = fixture.intent.clone();
    changed.binding.effect_slot.resource_key.resource_family = "other".to_string();
    changed.binding.effect_slot.slot_id = required(
        changed.binding.effect_slot.recompute_slot_id(),
        "substituted resource slot id",
    );
    changed.binding.effect_slot_id = changed.binding.effect_slot.slot_id.clone();
    assert!(changed.validate().is_err());
}

#[test]
fn preparation_ids_do_not_rebind_across_claims() {
    let fixture = fixture();
    let other_claim = distinct_claim();
    let mut other = fixture.intent.clone();
    other.binding.claim_id = other_claim.claim_id().to_string();
    other.binding.trigger_instance_id = other_claim.trigger_instance_id().to_string();
    other.payout_intent_id = required(
        parametric_payout_intent_id(other_claim.claim_id()),
        "distinct payout intent id",
    );
    let other_preparation = reseal_preparation(&mut other, &fixture.instruction_signer);
    required(
        other.validate_against_eligible_claim(&other_claim),
        "distinct claim payout preparation",
    );
    assert_ne!(
        other.binding.capital_instruction_id,
        fixture.intent.binding.capital_instruction_id
    );
    assert_ne!(
        other.binding.effect_idempotency_key,
        fixture.intent.binding.effect_idempotency_key
    );
    let signed = required(
        SignedParametricPayoutIntentV1::sign(other.clone(), &fixture.intent_signer),
        "distinct signed payout intent",
    );
    required(
        ValidatedPreReservationParametricPayoutIntentV1::validate_pre_reservation(
            signed,
            &fixture.intent_signer.public_key(),
            &fixture.trust_at(20),
            &other_claim,
            &other_preparation,
        ),
        "distinct validated preparation",
    );

    let mut reused_instruction = other.clone();
    reused_instruction.capital_instruction = fixture.intent.capital_instruction.clone();
    reused_instruction.binding.capital_instruction_id =
        fixture.intent.binding.capital_instruction_id.clone();
    reused_instruction
        .binding
        .capital_instruction_template_digest = fixture
        .intent
        .binding
        .capital_instruction_template_digest
        .clone();
    reused_instruction.binding.capital_instruction_body_digest = fixture
        .intent
        .binding
        .capital_instruction_body_digest
        .clone();
    reused_instruction
        .binding
        .capital_instruction_envelope_digest = fixture
        .intent
        .binding
        .capital_instruction_envelope_digest
        .clone();
    reused_instruction.binding.effect_slot.parameters_digest = reused_instruction
        .binding
        .capital_instruction_body_digest
        .clone();
    assert!(reused_instruction.validate().is_err());

    let mut reused_idempotency = other;
    reused_idempotency.binding.effect_idempotency_key =
        fixture.intent.binding.effect_idempotency_key.clone();
    reused_idempotency.binding.effect_slot.idempotency_key =
        reused_idempotency.binding.effect_idempotency_key.clone();
    assert!(reused_idempotency.validate().is_err());
}

#[test]
fn payout_intent_rejects_capital_instruction_and_trust_substitution() {
    let fixture = fixture();

    let mut changed = fixture.intent.clone();
    changed.binding.capital_instruction_id = "instruction-2".to_string();
    assert!(changed
        .validate_against_eligible_claim(&fixture.claim)
        .is_err());

    let mut changed = fixture.intent.clone();
    changed.binding.governed_receipt_id = "receipt-2".to_string();
    assert!(changed
        .validate_against_eligible_claim(&fixture.claim)
        .is_err());

    let mut changed = fixture.intent.clone();
    changed.binding.completion_flow_row_id = "completion-2".to_string();
    assert!(changed
        .validate_against_eligible_claim(&fixture.claim)
        .is_err());

    let mut changed = fixture.intent.clone();
    changed.binding.source_account_digest = digest("a");
    assert!(changed
        .validate_against_eligible_claim(&fixture.claim)
        .is_err());

    let alternate_instruction_signer = Keypair::from_seed(&[31; 32]);
    let mut changed = fixture.intent.clone();
    changed.capital_instruction = required(
        SignedCapitalExecutionInstruction::sign(
            changed.capital_instruction.body.clone(),
            &alternate_instruction_signer,
        ),
        "alternate instruction signature",
    );
    changed.binding.capital_instruction_envelope_digest = required(
        canonical_digest(&changed.capital_instruction),
        "alternate instruction digest",
    );
    let signed = required(
        SignedParametricPayoutIntentV1::sign(changed, &fixture.intent_signer),
        "changed signed intent",
    );
    assert!(
        ValidatedPreReservationParametricPayoutIntentV1::validate_pre_reservation(
            signed,
            &fixture.intent_signer.public_key(),
            &fixture.trust_at(20),
            &fixture.claim,
            &fixture.preparation,
        )
        .is_err()
    );

    let mut changed = fixture.intent.clone();
    changed
        .capital_instruction
        .body
        .support_boundary
        .automatic_dispatch_supported = false;
    let changed_preparation = reseal_preparation(&mut changed, &fixture.instruction_signer);
    let signed = required(
        SignedParametricPayoutIntentV1::sign(changed, &fixture.intent_signer),
        "non-automatic signed intent",
    );
    assert!(matches!(
        ValidatedPreReservationParametricPayoutIntentV1::validate_pre_reservation(
            signed,
            &fixture.intent_signer.public_key(),
            &fixture.trust_at(20),
            &fixture.claim,
            &changed_preparation,
        ),
        Err(ParametricClaimError::AutomaticDispatchUnsupported)
    ));
}
