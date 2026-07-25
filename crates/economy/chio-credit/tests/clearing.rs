use std::sync::Arc;

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::economic_continuity::{
    verify_economic_state_batch_advance, verify_economic_state_view,
    EconomicAdmissionHandoffStateV1, EconomicAdmissionHandoffV1, EconomicContentV1,
    EconomicEffectSlotV1, EconomicEffectStateV1, EconomicEffectTargetV1, EconomicEffectTerminalV1,
    EconomicFrostBindingV1, EconomicRequestBindingV1, EconomicResourceHeadV1,
    EconomicResourceKeyV1, EconomicStateAnchorPins, EconomicStateAnchorViewV1,
    EconomicStateBatchV1, EconomicTransitionAuthorizationV1, CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA,
    CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA, CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA,
    CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
};
use chio_core_types::StoreMutationFence;
use chio_credit::clearing::{
    compose_clearing_dispatch_transition, compose_clearing_lifecycle_transition,
    compose_clearing_reconciliation_transition, compose_clearing_satisfaction_transition,
    compose_clearing_zero_intent_reconciliation_transition, compute_netting_round,
    prepare_clearing_round_abort, prepare_clearing_round_finalization,
    prepare_clearing_round_satisfaction, prepare_clearing_zero_dispatch_proof,
    prepare_clearing_zero_intent_reconciliation, sign_clearing_round_abort,
    sign_clearing_round_finalization, sign_clearing_zero_dispatch_proof, sign_netting_round,
    verify_clearing_lifecycle_replay_authority,
    verify_clearing_lifecycle_replay_authority_with_outcome,
    verify_clearing_participant_acceptances, verify_clearing_round_abort,
    verify_clearing_zero_dispatch_proof, verify_netting_round, verify_signed_netting_round,
    AnchoredClearingObligationV1, ClearingAbortReplayV1, ClearingAcceptancesReplayV1,
    ClearingAuthorityTrustV1, ClearingDispatchReplayV1, ClearingDisputeWindowResolver,
    ClearingDisputeWindowStatusV1, ClearingFinalizationReplayV1, ClearingInputManifestBodyV1,
    ClearingInputManifestEntryV1, ClearingIntentDispatchStatusV1, ClearingLifecycleAuthorityPinsV1,
    ClearingLifecycleReplayBatchVerifier, ClearingLifecycleReplayEvidenceV1,
    ClearingLifecycleReplayV1, ClearingObligationInputV1, ClearingParticipantAcceptanceBodyV1,
    ClearingParticipantBindingV1, ClearingParticipantSnapshotAcknowledgementBodyV1,
    ClearingParticipantSnapshotBodyV1, ClearingReconciliationReplayV1, ClearingRoundAbortReasonV1,
    ClearingRoundFinalizationBodyV1, ClearingRoundLifecycleRecordV1, ClearingRoundRequestV1,
    ClearingRoundTransitionV1, ClearingSatisfactionReplayV1, ClearingSettlementObservedStatusV1,
    ClearingSettlementOutcomeVerifier, ClearingSettlementReconciliationBodyV1,
    ClearingZeroDispatchTrustV1, ClearingZeroIntentReconciliationReplayV1,
    SignedClearingInputManifestV1, SignedClearingParticipantAcceptanceV1,
    SignedClearingParticipantSnapshotAcknowledgementV1, SignedClearingParticipantSnapshotV1,
    SignedClearingRoundSatisfactionV1, SignedClearingSettlementReconciliationV1,
    SignedClearingZeroIntentReconciliationV1, SignedNettingRoundCoreV1, CLEARING_ALGORITHM_V1,
    CLEARING_INPUT_MANIFEST_SCHEMA, CLEARING_LIFECYCLE_REPLAY_FORMAT,
    CLEARING_PARTICIPANT_ACCEPTANCE_SCHEMA, CLEARING_PARTICIPANT_SNAPSHOT_ACKNOWLEDGEMENT_SCHEMA,
    CLEARING_PARTICIPANT_SNAPSHOT_SCHEMA, CLEARING_SETTLEMENT_DISPATCH_EFFECT_KIND,
    CLEARING_SETTLEMENT_RECONCILIATION_SCHEMA,
};
use chio_credit::obligation::{
    derive_obligation_payee_binding_digest, ObligationAtomInputV1, ObligationAtomV1,
    ObligationCreditElectionV1, ObligationDispositionRecordV1, ObligationDispositionTransitionV1,
    ObligationDispositionV1,
};
use chio_federation::frost::{
    frost_action_registration, frost_authorization_session_id, frost_authorization_slot_id,
    FrostAnchoredAuthorizationSlot, FrostArtifactAuthorityRole, FrostArtifactTrustRoot,
    FrostArtifactTrustStore, FrostAuthorizationBodyV1, FrostAuthorizationDomain,
    FrostAuthorizationSlotCheckpointV1, FrostAuthorizationSlotState, FrostAuthorizationV1,
    FrostParticipantV1, FrostRosterKeyOrigin, FrostRosterV1, CHIO_FROST_AUTHORIZATION_BODY_SCHEMA,
    CHIO_FROST_AUTHORIZATION_SCHEMA, CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SCHEMA,
    CHIO_FROST_ROSTER_SCHEMA, FROST_ED25519_SHA512_SUITE_ID,
};
use frost_ed25519::keys::{SigningShare, VerifyingShare};
use frost_ed25519::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn validate_schema(name: &str, artifact: &impl serde::Serialize) -> TestResult {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-economy")
        .join(name);
    let schema = chio_spec_validate::load_json(&path)?;
    let value = serde_json::to_value(artifact)?;
    chio_spec_validate::validate_value(
        &path,
        &schema,
        &std::path::PathBuf::from("<clearing-artifact>"),
        &value,
    )?;
    Ok(())
}

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn state_anchor_key() -> Keypair {
    Keypair::from_seed(&[0x41; 32])
}

fn state_anchor_pins() -> EconomicStateAnchorPins {
    EconomicStateAnchorPins {
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        signer_public_key: state_anchor_key().public_key(),
    }
}

fn signed_anchor_view(
    mut heads: Vec<EconomicResourceHeadV1>,
    observed_at: u64,
) -> Result<EconomicStateAnchorViewV1, Box<dyn std::error::Error>> {
    heads.sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    let mut view = EconomicStateAnchorViewV1 {
        schema: CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA.to_owned(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        checkpoint_sequence: 10,
        checkpoint_digest: digest("reconciliation-checkpoint"),
        heads_root: String::new(),
        heads,
        absent_resource_keys: Vec::new(),
        request_replays_root: String::new(),
        request_replays: Vec::new(),
        absent_request_keys: Vec::new(),
        observed_at,
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    view.seal(&state_anchor_key())?;
    Ok(view)
}

fn signed_projection_batch(
    projection: &chio_credit::clearing::ClearingLifecycleProjectionV1,
    current: &EconomicStateAnchorViewV1,
) -> Result<EconomicStateBatchV1, Box<dyn std::error::Error>> {
    let mut batch = EconomicStateBatchV1 {
        schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
        batch_id: String::new(),
        checkpoint_digest: String::new(),
        anchor_id: current.anchor_id.clone(),
        namespace: current.namespace.clone(),
        checkpoint_sequence: current.checkpoint_sequence + 1,
        previous_checkpoint_digest: Some(current.checkpoint_digest.clone()),
        expected_heads_root: String::new(),
        next_heads_root: String::new(),
        transitions: projection.transitions().to_vec(),
        effect_slots: projection.effect_slots().to_vec(),
        request_replays: projection.request_replays().to_vec(),
        operation_id: projection.operation_id().map(str::to_owned),
        issued_at: current.observed_at + 1,
        signer_key_id: current.signer_key_id.clone(),
        signer_key_epoch: current.signer_key_epoch,
        anchor_signature: String::new(),
    };
    batch.seal(&state_anchor_key())?;
    Ok(batch)
}

const FROST_SECRET_KEY: &str = "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304";
const FROST_VERIFYING_KEY: &str =
    "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";
const FROST_SHARES: [&str; 3] = [
    "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509",
    "a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d",
    "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02",
];

struct FrostFinalizationFixture {
    roster: FrostRosterV1,
    authorization: FrostAuthorizationV1,
    bound_slot: FrostAuthorizationSlotCheckpointV1,
    completed_slot: FrostAnchoredAuthorizationSlot,
    trust: FrostArtifactTrustStore,
    binding: EconomicFrostBindingV1,
}

fn roster_authority() -> Keypair {
    Keypair::from_seed(&[0x42; 32])
}

fn slot_authority() -> Keypair {
    Keypair::from_seed(&[0x44; 32])
}

fn frost_verifying_share(share: &str) -> Result<String, Box<dyn std::error::Error>> {
    let signing_share = SigningShare::deserialize(&hex::decode(share)?)?;
    Ok(hex::encode(
        VerifyingShare::from(signing_share).serialize()?,
    ))
}

fn sign_frost_roster(roster: &mut FrostRosterV1) -> TestResult {
    roster.roster_id = roster.recompute_roster_id()?;
    roster.roster_authority_signature = roster_authority().sign(&roster.signing_bytes()?).to_hex();
    roster.roster_digest = roster.recompute_roster_digest()?;
    Ok(())
}

fn sign_frost_slot(checkpoint: &mut FrostAuthorizationSlotCheckpointV1) -> TestResult {
    checkpoint.anchor_signature = slot_authority().sign(&checkpoint.signing_bytes()?).to_hex();
    checkpoint.checkpoint_digest = checkpoint.recompute_checkpoint_digest()?;
    Ok(())
}

fn frost_finalization_fixture(
    finalization: &ClearingRoundFinalizationBodyV1,
) -> Result<FrostFinalizationFixture, Box<dyn std::error::Error>> {
    let mut roster = FrostRosterV1 {
        schema: CHIO_FROST_ROSTER_SCHEMA.to_owned(),
        roster_id: String::new(),
        roster_digest: String::new(),
        authority_scope: "treaty".to_owned(),
        scope_id: finalization.governance_scope_id.clone(),
        allowed_domains: vec![FrostAuthorizationDomain::ClearingRoundFinalize],
        key_epoch: 4,
        threshold: 2,
        participant_count: 3,
        participants: FROST_SHARES
            .iter()
            .enumerate()
            .map(|(index, share)| {
                Ok(FrostParticipantV1 {
                    participant_id: format!("operator-{}", index + 1),
                    verification_share: frost_verifying_share(share)?,
                })
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?,
        group_public_key: FROST_VERIFYING_KEY.to_owned(),
        suite_id: FROST_ED25519_SHA512_SUITE_ID.to_owned(),
        key_origin: FrostRosterKeyOrigin::DistributedDkg,
        ceremony_transcript_digest: digest("clearing-frost-ceremony"),
        predecessor_roster_digest: Some(digest("clearing-frost-predecessor")),
        valid_from: 500,
        valid_until: 590,
        roster_authority_key_id: "authority.treaty.v1".to_owned(),
        roster_authority_signature: String::new(),
    };
    sign_frost_roster(&mut roster)?;
    let action = finalization.frost_action_preimage()?;
    let registration = frost_action_registration(FrostAuthorizationDomain::ClearingRoundFinalize)
        .ok_or("clearing finalization FROST domain is disabled")?;
    let mut body = FrostAuthorizationBodyV1 {
        schema: CHIO_FROST_AUTHORIZATION_BODY_SCHEMA.to_owned(),
        authorization_id: String::new(),
        domain: registration.domain,
        ladder_action_class: registration.ladder_action_class.to_owned(),
        ladder_contract_digest: registration.ladder_contract_digest()?,
        quorum_n: registration.quorum_n,
        quorum_m: registration.quorum_m,
        quorum_scope: registration.quorum_scope.to_owned(),
        scope_id: finalization.governance_scope_id.clone(),
        resource_id: action.resource_id().to_owned(),
        resource_version: action.resource_version(),
        resource_fence: action.resource_fence(),
        action_digest: action.action_digest()?,
        roster_digest: roster.roster_digest.clone(),
        key_epoch: roster.key_epoch,
        issued_at: 555,
        expires_at: 580,
    };
    body.authorization_id = body.recompute_authorization_id()?;
    let signing_bytes = body.signing_bytes()?;
    let signing_key = SigningKey::deserialize(&hex::decode(FROST_SECRET_KEY)?)?;
    let signature = signing_key.sign(ChaCha20Rng::from_seed([7; 32]), &signing_bytes);
    let signature_bytes = signature.serialize()?;
    let authorization = FrostAuthorizationV1 {
        schema: CHIO_FROST_AUTHORIZATION_SCHEMA.to_owned(),
        body,
        suite_id: FROST_ED25519_SHA512_SUITE_ID.to_owned(),
        group_signature: hex::encode(&signature_bytes),
    };
    let authorization_blob = authorization.canonical_bytes()?;
    let mut bound_slot = FrostAuthorizationSlotCheckpointV1 {
        schema: CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SCHEMA.to_owned(),
        anchor_id: "slot-anchor.primary".to_owned(),
        checkpoint_digest: String::new(),
        scope_id: authorization.body.scope_id.clone(),
        slot_id: frost_authorization_slot_id(&authorization.body)?,
        slot_version: 1,
        predecessor_digest: None,
        domain: authorization.body.domain,
        ladder_action_class: authorization.body.ladder_action_class.clone(),
        resource_id: authorization.body.resource_id.clone(),
        resource_version: authorization.body.resource_version,
        resource_fence: authorization.body.resource_fence,
        authorization_id: authorization.body.authorization_id.clone(),
        signing_message_digest: sha256_hex(&signing_bytes),
        action_digest: authorization.body.action_digest.clone(),
        roster_digest: authorization.body.roster_digest.clone(),
        key_epoch: authorization.body.key_epoch,
        session_id: frost_authorization_session_id(&authorization.body)?,
        state: FrostAuthorizationSlotState::Bound,
        aggregate_signature_digest: None,
        authorization_blob_digest: None,
        availability_receipt: None,
        clock_high_water: 555,
        anchor_key_id: "slot-anchor-key.v1".to_owned(),
        anchor_signature: String::new(),
    };
    sign_frost_slot(&mut bound_slot)?;
    let mut completed_checkpoint = bound_slot.clone();
    completed_checkpoint.slot_version = 2;
    completed_checkpoint.predecessor_digest = Some(bound_slot.checkpoint_digest.clone());
    completed_checkpoint.state = FrostAuthorizationSlotState::Completed;
    completed_checkpoint.aggregate_signature_digest = Some(sha256_hex(&signature_bytes));
    completed_checkpoint.authorization_blob_digest = Some(sha256_hex(&authorization_blob));
    completed_checkpoint.availability_receipt =
        Some("availability.slot-anchor.primary.v1".to_owned());
    completed_checkpoint.clock_high_water = 560;
    completed_checkpoint.anchor_signature.clear();
    completed_checkpoint.checkpoint_digest.clear();
    sign_frost_slot(&mut completed_checkpoint)?;
    let trust = FrostArtifactTrustStore::new([
        FrostArtifactTrustRoot {
            role: FrostArtifactAuthorityRole::Roster,
            key_id: "authority.treaty.v1".to_owned(),
            public_key: roster_authority().public_key(),
        },
        FrostArtifactTrustRoot {
            role: FrostArtifactAuthorityRole::AuthorizationSlotAnchor,
            key_id: "slot-anchor-key.v1".to_owned(),
            public_key: slot_authority().public_key(),
        },
    ])?;
    let binding = EconomicFrostBindingV1 {
        authorization_slot_id: frost_authorization_slot_id(&authorization.body)?,
        authorization_id: authorization.body.authorization_id.clone(),
        action_digest: authorization.body.action_digest.clone(),
        signed_envelope_digest: sha256_hex(&authorization_blob),
    };
    Ok(FrostFinalizationFixture {
        roster,
        authorization,
        bound_slot,
        completed_slot: FrostAnchoredAuthorizationSlot {
            checkpoint: completed_checkpoint,
            authorization_blob: Some(authorization_blob),
        },
        trust,
        binding,
    })
}

fn participant_key(participant: &str) -> Keypair {
    let seed = match participant {
        "A" => 10,
        "B" => 11,
        "C" => 12,
        _ => 13,
    };
    Keypair::from_seed(&[seed; 32])
}

fn reserved_obligation(
    sequence: u64,
    debtor_id: &str,
    creditor_id: &str,
    currency: &str,
    units: u64,
) -> Result<ClearingObligationInputV1, Box<dyn std::error::Error>> {
    let atom = ObligationAtomV1::new(ObligationAtomInputV1 {
        economic_intent_digest: digest(&format!("intent-{sequence}")),
        source_receipt_id: format!("receipt-{sequence}"),
        source_receipt_digest: digest(&format!("receipt-{sequence}")),
        debtor_id: debtor_id.to_owned(),
        original_creditor_id: creditor_id.to_owned(),
        original_settlement_destination_ref: format!("acct:{creditor_id}"),
        payee_binding_digest: derive_obligation_payee_binding_digest(
            creditor_id,
            &format!("acct:{creditor_id}"),
        )?,
        amount: MonetaryAmount {
            currency: currency.to_owned(),
            units,
        },
        credit_election: ObligationCreditElectionV1::NotCredit,
        pre_action_authority_digest: digest(&format!("authority-{sequence}")),
        created_at_unix_ms: 100,
        due_at_unix_ms: 10_000,
    })?;
    let disposition = ObligationDispositionRecordV1::produced(&atom)?.advance(
        &atom,
        ObligationDispositionTransitionV1::ReserveClearing {
            round_id: "round-1".to_owned(),
            authority_digest: digest(&format!("reservation-{sequence}")),
        },
    )?;
    Ok(ClearingObligationInputV1 {
        source_sequence: sequence,
        atom,
        disposition,
    })
}

fn signed_request(
    obligations: Vec<ClearingObligationInputV1>,
    participant_authority: &Keypair,
    obligation_authority: &Keypair,
) -> Result<ClearingRoundRequestV1, Box<dyn std::error::Error>> {
    let participant_snapshot = SignedClearingParticipantSnapshotV1::sign(
        ClearingParticipantSnapshotBodyV1 {
            schema: CLEARING_PARTICIPANT_SNAPSHOT_SCHEMA.to_owned(),
            authority_id: "participant-authority".to_owned(),
            key_epoch: 7,
            algorithm_version: CLEARING_ALGORITHM_V1.to_owned(),
            valid_from_unix_ms: 50,
            expires_at_unix_ms: 1_000,
            participants: ["A", "B", "C"]
                .into_iter()
                .map(|participant| ClearingParticipantBindingV1 {
                    participant_id: participant.to_owned(),
                    identities: vec![participant.to_owned()],
                    settlement_destination: format!("acct:{participant}"),
                    acknowledgement_key: participant_key(participant).public_key(),
                    acknowledgement_key_epoch: 1,
                })
                .collect(),
        },
        participant_authority,
    )?;
    let participant_snapshot_digest = participant_snapshot.body.digest()?;
    let participant_acknowledgements = ["A", "B", "C"]
        .into_iter()
        .map(|participant| {
            SignedClearingParticipantSnapshotAcknowledgementV1::sign(
                ClearingParticipantSnapshotAcknowledgementBodyV1 {
                    schema: CLEARING_PARTICIPANT_SNAPSHOT_ACKNOWLEDGEMENT_SCHEMA.to_owned(),
                    participant_snapshot_digest: participant_snapshot_digest.clone(),
                    participant_id: participant.to_owned(),
                    algorithm_version: CLEARING_ALGORITHM_V1.to_owned(),
                    key_epoch: 1,
                    accepted_at_unix_ms: 90,
                    expires_at_unix_ms: 600,
                },
                &participant_key(participant),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let entries = obligations
        .iter()
        .map(ClearingInputManifestEntryV1::from_reserved)
        .collect::<Result<Vec<_>, _>>()?;
    let input_manifest = SignedClearingInputManifestV1::sign(
        ClearingInputManifestBodyV1 {
            schema: CLEARING_INPUT_MANIFEST_SCHEMA.to_owned(),
            authority_id: "obligation-authority".to_owned(),
            key_epoch: 11,
            source_id: "obligations-primary".to_owned(),
            epoch: 3,
            range_start_sequence: 1,
            range_end_sequence: u64::try_from(entries.len())?,
            start_checkpoint_digest: digest("checkpoint-start"),
            end_checkpoint_digest: digest("checkpoint-end"),
            entries,
            has_more: false,
            next_cursor: None,
            issued_at_unix_ms: 80,
            expires_at_unix_ms: 200,
        },
        obligation_authority,
    )?;
    Ok(ClearingRoundRequestV1 {
        round_id: "round-1".to_owned(),
        epoch: 3,
        governance_scope_id: "clearing-governance".to_owned(),
        currency: "USD".to_owned(),
        algorithm_version: CLEARING_ALGORITHM_V1.to_owned(),
        participant_snapshot,
        participant_acknowledgements,
        input_manifest,
        obligations,
        dispute_window_ends_at_unix_ms: 500,
        generated_at_unix_ms: 100,
    })
}

fn trust(
    participant_authority: &Keypair,
    obligation_authority: &Keypair,
) -> ClearingAuthorityTrustV1 {
    ClearingAuthorityTrustV1 {
        clearing_authority_id: "clearing-authority".to_owned(),
        clearing_authority_key: participant_authority.public_key(),
        clearing_authority_key_epoch: 13,
        participant_authority_id: "participant-authority".to_owned(),
        participant_authority_key: participant_authority.public_key(),
        participant_key_epoch: 7,
        obligation_authority_id: "obligation-authority".to_owned(),
        obligation_authority_key: obligation_authority.public_key(),
        obligation_key_epoch: 11,
        trusted_time_unix_ms: 100,
    }
}

fn lifecycle_pins(trust: &ClearingAuthorityTrustV1) -> ClearingLifecycleAuthorityPinsV1 {
    ClearingLifecycleAuthorityPinsV1 {
        clearing_authority_id: trust.clearing_authority_id.clone(),
        clearing_authority_key: trust.clearing_authority_key.clone(),
        clearing_authority_key_epoch: trust.clearing_authority_key_epoch,
        participant_authority_id: trust.participant_authority_id.clone(),
        participant_authority_key: trust.participant_authority_key.clone(),
        participant_key_epoch: trust.participant_key_epoch,
        obligation_authority_id: trust.obligation_authority_id.clone(),
        obligation_authority_key: trust.obligation_authority_key.clone(),
        obligation_key_epoch: trust.obligation_key_epoch,
        zero_dispatch_authority_id: "zero-dispatch-authority".to_owned(),
        zero_dispatch_authority_key: Keypair::from_seed(&[0x55; 32]).public_key(),
        zero_dispatch_authority_key_epoch: 1,
        admission_store_id: "admission-store-1".to_owned(),
    }
}

fn signed_acceptances(
    output: &chio_credit::clearing::ClearingRoundOutputV1,
) -> Result<Vec<SignedClearingParticipantAcceptanceV1>, Box<dyn std::error::Error>> {
    let output_manifest_digest = output.output_manifest.digest()?;
    output
        .participant_statements
        .iter()
        .map(|statement| {
            Ok(SignedClearingParticipantAcceptanceV1::sign(
                ClearingParticipantAcceptanceBodyV1 {
                    schema: CLEARING_PARTICIPANT_ACCEPTANCE_SCHEMA.to_owned(),
                    round_id: output.core.round_id.clone(),
                    round_core_digest: output.core.digest()?,
                    output_manifest_digest: output_manifest_digest.clone(),
                    participant_statement_digest: statement.digest()?,
                    participant_id: statement.participant_id.clone(),
                    key_epoch: 1,
                    accepted_at_unix_ms: 510,
                    expires_at_unix_ms: 600,
                },
                &participant_key(&statement.participant_id),
            )?)
        })
        .collect()
}

struct DisputeWindow {
    unresolved_dispute_count: u64,
}

impl ClearingDisputeWindowResolver for DisputeWindow {
    fn resolve_closed_window(
        &self,
        round_id: &str,
        round_core_digest: &str,
        output_manifest_digest: &str,
        dispute_window_ends_at_unix_ms: u64,
    ) -> Result<ClearingDisputeWindowStatusV1, chio_credit::clearing::ClearingError> {
        Ok(ClearingDisputeWindowStatusV1 {
            round_id: round_id.to_owned(),
            round_core_digest: round_core_digest.to_owned(),
            output_manifest_digest: output_manifest_digest.to_owned(),
            dispute_window_ends_at_unix_ms,
            observed_through_unix_ms: dispute_window_ends_at_unix_ms,
            unresolved_dispute_count: self.unresolved_dispute_count,
            checkpoint_digest: digest("dispute-window-checkpoint"),
        })
    }
}

fn clearing_head(
    record: &ClearingRoundLifecycleRecordV1,
) -> Result<EconomicResourceHeadV1, Box<dyn std::error::Error>> {
    let state = EconomicContentV1::Inline {
        value: serde_json::to_value(record)?,
    };
    Ok(EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        resource_key: EconomicResourceKeyV1 {
            resource_family: "clearing_round".to_owned(),
            scope_id: record.governance_scope_id().to_owned(),
            resource_id: record.round_id().to_owned(),
        },
        head_version: record.row_version(),
        resource_version: record.row_version(),
        lifecycle_fence: record.fence(),
        lifecycle_state: record.state().as_str().to_owned(),
        state_digest: state.digest()?,
        state,
        operation_id: None,
        effect_idempotency_key: None,
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 500,
        predecessor_digest: None,
    })
}

fn anchored_obligations(
    obligations: &[ClearingObligationInputV1],
    scope_id: &str,
) -> Result<Vec<AnchoredClearingObligationV1>, Box<dyn std::error::Error>> {
    obligations
        .iter()
        .map(|input| {
            let state = EconomicContentV1::Inline {
                value: serde_json::to_value(&input.disposition)?,
            };
            Ok(AnchoredClearingObligationV1 {
                input: input.clone(),
                head: EconomicResourceHeadV1 {
                    schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
                    anchor_id: "anchor-1".to_owned(),
                    namespace: "economy-prod".to_owned(),
                    resource_key: EconomicResourceKeyV1 {
                        resource_family: "obligation_disposition".to_owned(),
                        scope_id: scope_id.to_owned(),
                        resource_id: input.atom.obligation_id().to_owned(),
                    },
                    head_version: 1,
                    resource_version: input.disposition.version(),
                    lifecycle_fence: input.disposition.lifecycle_fence(),
                    lifecycle_state: "clearing_reserved".to_owned(),
                    state_digest: state.digest()?,
                    state,
                    operation_id: None,
                    effect_idempotency_key: None,
                    frost: None,
                    terminal_result: None,
                    trusted_clock_high_water: 500,
                    predecessor_digest: None,
                },
            })
        })
        .collect()
}

fn advance_anchored_obligations(
    inputs: &[ClearingObligationInputV1],
    heads: &[EconomicResourceHeadV1],
) -> Result<Vec<AnchoredClearingObligationV1>, Box<dyn std::error::Error>> {
    inputs
        .iter()
        .map(|input| {
            let head = heads
                .iter()
                .find(|head| head.resource_key.resource_id == input.atom.obligation_id())
                .ok_or("missing obligation head")?;
            Ok(AnchoredClearingObligationV1 {
                input: input.clone(),
                head: head.clone(),
            })
        })
        .collect()
}

fn effect_slot_successor(
    current: &EconomicResourceHeadV1,
    slot: &EconomicEffectSlotV1,
    trusted_clock_high_water: u64,
) -> Result<EconomicResourceHeadV1, Box<dyn std::error::Error>> {
    let state = EconomicContentV1::Inline {
        value: serde_json::to_value(slot)?,
    };
    let next = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: current.anchor_id.clone(),
        namespace: current.namespace.clone(),
        resource_key: current.resource_key.clone(),
        head_version: current.head_version + 1,
        resource_version: current.resource_version + 1,
        lifecycle_fence: current.lifecycle_fence + 1,
        lifecycle_state: match slot.state {
            EconomicEffectStateV1::DispatchCommitted => "dispatch_committed",
            EconomicEffectStateV1::Completed => "completed",
            EconomicEffectStateV1::NoEffect => "no_effect",
            EconomicEffectStateV1::Unknown => "unknown",
            EconomicEffectStateV1::Ready => "ready",
        }
        .to_owned(),
        state_digest: state.digest()?,
        state,
        operation_id: Some(slot.operation_id.clone()),
        effect_idempotency_key: Some(slot.idempotency_key.clone()),
        frost: slot.frost.clone(),
        terminal_result: None,
        trusted_clock_high_water,
        predecessor_digest: Some(current.digest()?),
    };
    current.validate_successor(&next)?;
    Ok(next)
}

#[derive(Debug)]
struct ReplaySettledOutcome;

impl ClearingSettlementOutcomeVerifier for ReplaySettledOutcome {
    fn verify_outcome(
        &self,
        _slot: &EconomicEffectSlotV1,
        settlement_outcome_digest: &str,
        external_references: &[String],
    ) -> Result<Option<EconomicEffectTerminalV1>, chio_credit::clearing::ClearingError> {
        if settlement_outcome_digest != digest("clearing-settlement-outcome")
            || external_references != ["rail:transaction:clearing-1"]
        {
            return Err(chio_credit::clearing::ClearingError::AuthorityVerification);
        }
        let result = EconomicContentV1::Inline {
            value: serde_json::json!({"settlementReference": "clearing-1"}),
        };
        let result_digest = result
            .digest()
            .map_err(|_| chio_credit::clearing::ClearingError::AuthorityVerification)?;
        Ok(Some(EconomicEffectTerminalV1::Completed {
            result_id: "clearing-1".to_owned(),
            result_digest,
            result,
        }))
    }
}

#[test]
fn acyclic_chain_reduces_to_one_direct_intent() -> TestResult {
    let participant_authority = Keypair::from_seed(&[1; 32]);
    let obligation_authority = Keypair::from_seed(&[2; 32]);
    let obligations = vec![
        reserved_obligation(1, "A", "B", "USD", 100)?,
        reserved_obligation(2, "B", "C", "USD", 100)?,
    ];
    let request = signed_request(
        obligations.clone(),
        &participant_authority,
        &obligation_authority,
    )?;
    let output = compute_netting_round(
        &request,
        &trust(&participant_authority, &obligation_authority),
    )?;

    assert_eq!(output.intents.len(), 1);
    assert_eq!(output.intents[0].debtor_participant_id, "A");
    assert_eq!(output.intents[0].creditor_participant_id, "C");
    assert_eq!(output.intents[0].amount.units, 100);
    verify_netting_round(
        &request,
        &trust(&participant_authority, &obligation_authority),
        &output,
    )?;
    let mut tampered = output.clone();
    tampered.intents[0].amount.units = 101;
    assert!(verify_netting_round(
        &request,
        &trust(&participant_authority, &obligation_authority),
        &tampered,
    )
    .is_err());
    let authority_trust = trust(&participant_authority, &obligation_authority);
    assert!(sign_netting_round(
        &request,
        &tampered,
        &authority_trust,
        &participant_authority,
    )
    .is_err());
    let signed = sign_netting_round(&request, &output, &authority_trust, &participant_authority)?;
    validate_schema(
        "clearing-participant-snapshot.v1.json",
        &request.participant_snapshot,
    )?;
    for acknowledgement in &request.participant_acknowledgements {
        validate_schema(
            "clearing-participant-snapshot-acknowledgement.v1.json",
            acknowledgement,
        )?;
    }
    validate_schema("clearing-input-manifest.v1.json", &request.input_manifest)?;
    validate_schema("clearing-netting-round-core.v1.json", &signed.core)?;
    for statement in &signed.participant_statements {
        validate_schema("clearing-participant-statement.v1.json", statement)?;
    }
    for intent in &signed.intents {
        validate_schema("clearing-settlement-intent.v1.json", intent)?;
    }
    for transformation in &signed.transformations {
        validate_schema("clearing-atom-transformation.v1.json", transformation)?;
    }
    validate_schema("clearing-output-manifest.v1.json", &signed.output_manifest)?;
    assert_eq!(
        verify_signed_netting_round(&request, &authority_trust, &signed)?,
        output
    );
    let mut tampered_signed = signed;
    tampered_signed.intents[0].body.amount.units = 101;
    assert!(verify_signed_netting_round(&request, &authority_trust, &tampered_signed).is_err());
    let mut unknown_field = serde_json::to_value(&tampered_signed.core)?;
    unknown_field["unexpected"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<SignedNettingRoundCoreV1>(unknown_field).is_err());

    let mut missing_acknowledgement = request.clone();
    missing_acknowledgement.participant_acknowledgements.pop();
    assert!(compute_netting_round(&missing_acknowledgement, &authority_trust).is_err());

    let mut shuffled = request;
    shuffled.obligations.reverse();
    let shuffled_output = compute_netting_round(
        &shuffled,
        &trust(&participant_authority, &obligation_authority),
    )?;
    assert_eq!(output, shuffled_output);
    Ok(())
}

#[test]
fn participant_acceptances_bind_every_affected_statement_after_the_dispute_window() -> TestResult {
    let participant_authority = Keypair::from_seed(&[21; 32]);
    let obligation_authority = Keypair::from_seed(&[22; 32]);
    let request = signed_request(
        vec![
            reserved_obligation(1, "A", "B", "USD", 100)?,
            reserved_obligation(2, "B", "C", "USD", 100)?,
        ],
        &participant_authority,
        &obligation_authority,
    )?;
    let mut finalization_trust = trust(&participant_authority, &obligation_authority);
    let admission_trust = finalization_trust.clone();
    let output = compute_netting_round(&request, &admission_trust)?;
    let signed_output =
        sign_netting_round(&request, &output, &admission_trust, &participant_authority)?;
    let acceptances = signed_acceptances(&output)?;
    let closed_dispute_window = DisputeWindow {
        unresolved_dispute_count: 0,
    };
    finalization_trust.trusted_time_unix_ms = 550;

    let verified = verify_clearing_participant_acceptances(
        &request,
        &signed_output,
        &acceptances,
        &closed_dispute_window,
        &finalization_trust,
    )?;
    assert_eq!(verified.acceptance_count(), 3);
    assert_eq!(verified.round_id(), "round-1");
    assert_eq!(
        verified.output_manifest_digest(),
        output.output_manifest.digest()?
    );
    for acceptance in &acceptances {
        validate_schema("clearing-participant-acceptance.v1.json", acceptance)?;
    }
    assert!(matches!(
        verified.begin_finalization_transition(),
        ClearingRoundTransitionV1::BeginFinalization {
            acceptance_count: 3,
            ..
        }
    ));

    let reserved = ClearingRoundLifecycleRecordV1::reserved(&output.core)?;
    let reserved_head = clearing_head(&reserved)?;
    let anchored = anchored_obligations(&request.obligations, &output.core.governance_scope_id)?;
    let proposed = compose_clearing_lifecycle_transition(
        &reserved_head,
        &anchored,
        ClearingRoundTransitionV1::Propose {
            output_manifest_digest: output.output_manifest.digest()?,
            authority_digest: signed_output.output_manifest.digest()?,
        },
        501,
    )?;
    let proposed_heads = proposed
        .transitions()
        .iter()
        .map(|transition| transition.next_head.clone())
        .collect::<Vec<_>>();
    let proposed_head = proposed_heads
        .iter()
        .find(|head| head.resource_key.resource_family == "clearing_round")
        .ok_or("missing proposed round head")?;
    let proposed_obligations = advance_anchored_obligations(&request.obligations, &proposed_heads)?;
    let finalizing = compose_clearing_lifecycle_transition(
        proposed_head,
        &proposed_obligations,
        verified.begin_finalization_transition(),
        502,
    )?;
    let finalizing_head = finalizing
        .transitions()
        .iter()
        .find(|transition| transition.resource_key.resource_family == "clearing_round")
        .map(|transition| &transition.next_head)
        .ok_or("missing finalizing round head")?;
    let finalization_body =
        prepare_clearing_round_finalization(finalizing_head, &verified, &finalization_trust)?;
    let signed_finalization = sign_clearing_round_finalization(
        finalization_body.clone(),
        &finalization_trust,
        &participant_authority,
    )?;
    validate_schema("clearing-round-finalization.v1.json", &signed_finalization)?;
    let action = finalization_body.frost_action_preimage()?;
    assert_eq!(action.resource_id(), "round-1");
    assert_eq!(action.resource_version(), finalizing_head.resource_version);
    assert_eq!(action.resource_fence(), finalizing_head.lifecycle_fence);

    let replay_pins = ClearingLifecycleAuthorityPinsV1 {
        clearing_authority_id: finalization_trust.clearing_authority_id.clone(),
        clearing_authority_key: finalization_trust.clearing_authority_key.clone(),
        clearing_authority_key_epoch: finalization_trust.clearing_authority_key_epoch,
        participant_authority_id: finalization_trust.participant_authority_id.clone(),
        participant_authority_key: finalization_trust.participant_authority_key.clone(),
        participant_key_epoch: finalization_trust.participant_key_epoch,
        obligation_authority_id: finalization_trust.obligation_authority_id.clone(),
        obligation_authority_key: finalization_trust.obligation_authority_key.clone(),
        obligation_key_epoch: finalization_trust.obligation_key_epoch,
        zero_dispatch_authority_id: "admission-authority".to_owned(),
        zero_dispatch_authority_key: Keypair::from_seed(&[23; 32]).public_key(),
        zero_dispatch_authority_key_epoch: 1,
        admission_store_id: "admission-store-primary".to_owned(),
    };
    let dispute_status = closed_dispute_window.resolve_closed_window(
        &request.round_id,
        &output.core.digest()?,
        &output.output_manifest.digest()?,
        request.dispute_window_ends_at_unix_ms,
    )?;
    let acceptances_replay = ClearingAcceptancesReplayV1 {
        request: request.clone(),
        signed_output: signed_output.clone(),
        acceptances: acceptances.clone(),
        dispute_status,
        verified_at_unix_ms: finalization_trust.trusted_time_unix_ms,
    };
    let begin_replay = ClearingLifecycleReplayV1 {
        format: CLEARING_LIFECYCLE_REPLAY_FORMAT.to_owned(),
        proof: finalizing.proof().clone(),
        evidence: ClearingLifecycleReplayEvidenceV1::BeginFinalization {
            acceptances: Box::new(acceptances_replay.clone()),
        },
    };
    assert_eq!(
        verify_clearing_lifecycle_replay_authority(
            proposed_head,
            &begin_replay,
            &replay_pins,
            None,
            Some(&closed_dispute_window),
        )?,
        EconomicTransitionAuthorizationV1::Direct
    );
    let mut forged_dispute_replay = begin_replay;
    let ClearingLifecycleReplayEvidenceV1::BeginFinalization {
        acceptances: replay_acceptances,
    } = &mut forged_dispute_replay.evidence
    else {
        return Err("begin-finalization replay used the wrong evidence".into());
    };
    replay_acceptances.dispute_status.checkpoint_digest = digest("forged-dispute-checkpoint");
    assert!(verify_clearing_lifecycle_replay_authority(
        proposed_head,
        &forged_dispute_replay,
        &replay_pins,
        None,
        Some(&closed_dispute_window),
    )
    .is_err());

    let frost = frost_finalization_fixture(&finalization_body)?;
    let finalizing_heads = finalizing
        .transitions()
        .iter()
        .map(|transition| transition.next_head.clone())
        .collect::<Vec<_>>();
    let finalizing_obligations =
        advance_anchored_obligations(&request.obligations, &finalizing_heads)?;
    let finalized = compose_clearing_lifecycle_transition(
        finalizing_head,
        &finalizing_obligations,
        ClearingRoundTransitionV1::Finalize {
            finalization_digest: signed_finalization.digest()?,
            frost: frost.binding.clone(),
        },
        560,
    )?;
    let finalization_replay = ClearingLifecycleReplayV1 {
        format: CLEARING_LIFECYCLE_REPLAY_FORMAT.to_owned(),
        proof: finalized.proof().clone(),
        evidence: ClearingLifecycleReplayEvidenceV1::Finalize {
            finalization: Box::new(ClearingFinalizationReplayV1 {
                begin_finalization_proof: finalizing.proof().clone(),
                acceptances: acceptances_replay,
                signed_finalization: signed_finalization.clone(),
                frost_authorization: frost.authorization,
                historical_roster: frost.roster,
                bound_slot: frost.bound_slot,
                completed_slot: frost.completed_slot,
            }),
        },
    };
    assert_eq!(
        verify_clearing_lifecycle_replay_authority(
            finalizing_head,
            &finalization_replay,
            &replay_pins,
            Some(&frost.trust),
            Some(&closed_dispute_window),
        )?,
        EconomicTransitionAuthorizationV1::NOfM {
            frost: frost.binding.clone(),
        }
    );

    let finalized_heads = finalized
        .transitions()
        .iter()
        .map(|transition| transition.next_head.clone())
        .collect::<Vec<_>>();
    let finalized_head = finalized_heads
        .iter()
        .find(|head| head.resource_key.resource_family == "clearing_round")
        .ok_or("missing finalized round head")?;
    let finalized_obligations =
        advance_anchored_obligations(&request.obligations, &finalized_heads)?;
    let signed_intent = &signed_output.intents[0];
    let mut effect_slot = EconomicEffectSlotV1 {
        schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
        slot_id: String::new(),
        anchor_id: finalized_head.anchor_id.clone(),
        namespace: finalized_head.namespace.clone(),
        resource_key: finalized_head.resource_key.clone(),
        operation_id: digest("clearing-dispatch-operation"),
        effect_kind: CLEARING_SETTLEMENT_DISPATCH_EFFECT_KIND.to_owned(),
        request: EconomicRequestBindingV1 {
            request_namespace_digest: digest("settlement-request-namespace"),
            request_id: "settlement-request-1".to_owned(),
            request_binding_digest: digest("settlement-request-binding"),
        },
        admission_handoff: EconomicAdmissionHandoffV1 {
            state: EconomicAdmissionHandoffStateV1::DispatchCommitted,
            operation_version: 6,
            lifecycle_fence: 9,
            store_fence: StoreMutationFence {
                store_uuid: "admission-store-primary".to_owned(),
                lease_id: "admission-lease-1".to_owned(),
                owner_epoch: 4,
            },
        },
        target: EconomicEffectTargetV1 {
            target_id: "settlement-rail".to_owned(),
            target_key_epoch: 2,
            qualification_digest: digest("settlement-rail-qualification"),
        },
        action_digest: signed_intent.digest()?,
        parameters_digest: signed_intent.body.digest()?,
        resource_head_digest: finalized_head.digest()?,
        frost: None,
        idempotency_key: signed_intent.body.dispatch_idempotency_key.clone(),
        state: EconomicEffectStateV1::Ready,
        terminal: None,
    };
    effect_slot.slot_id = effect_slot.recompute_slot_id()?;
    let dispatch_projection = compose_clearing_dispatch_transition(
        finalized_head,
        &finalized_obligations,
        signed_intent,
        effect_slot.clone(),
        561,
    )?;
    let dispatch_replay = ClearingLifecycleReplayV1 {
        format: CLEARING_LIFECYCLE_REPLAY_FORMAT.to_owned(),
        proof: dispatch_projection.proof().clone(),
        evidence: ClearingLifecycleReplayEvidenceV1::BeginDispatch {
            dispatch: Box::new(ClearingDispatchReplayV1 {
                request: request.clone(),
                signed_output: signed_output.clone(),
                intent_id: signed_intent.body.intent_id.clone(),
                effect_slot: effect_slot.clone(),
            }),
        },
    };
    assert_eq!(
        verify_clearing_lifecycle_replay_authority(
            finalized_head,
            &dispatch_replay,
            &replay_pins,
            None,
            None,
        )?,
        EconomicTransitionAuthorizationV1::Direct
    );
    let canonical_dispatch_replay = canonical_json_bytes(&dispatch_replay)?;
    let decoded_dispatch_replay: ClearingLifecycleReplayV1 =
        serde_json::from_slice(&canonical_dispatch_replay)?;
    assert_eq!(decoded_dispatch_replay, dispatch_replay);

    let mut wrong_source = dispatch_replay.clone();
    let ClearingLifecycleReplayEvidenceV1::BeginDispatch { dispatch } = &mut wrong_source.evidence
    else {
        return Err("dispatch replay used the wrong evidence".into());
    };
    dispatch.effect_slot.resource_head_digest = digest("wrong-round-head");
    assert!(verify_clearing_lifecycle_replay_authority(
        finalized_head,
        &wrong_source,
        &replay_pins,
        None,
        None,
    )
    .is_err());

    let mut wrong_intent = dispatch_replay.clone();
    let ClearingLifecycleReplayEvidenceV1::BeginDispatch { dispatch } = &mut wrong_intent.evidence
    else {
        return Err("dispatch replay used the wrong evidence".into());
    };
    dispatch.intent_id = "missing-intent".to_owned();
    assert!(verify_clearing_lifecycle_replay_authority(
        finalized_head,
        &wrong_intent,
        &replay_pins,
        None,
        None,
    )
    .is_err());

    let mut wrong_idempotency = dispatch_replay.clone();
    let ClearingLifecycleReplayEvidenceV1::BeginDispatch { dispatch } =
        &mut wrong_idempotency.evidence
    else {
        return Err("dispatch replay used the wrong evidence".into());
    };
    dispatch.effect_slot.idempotency_key = digest("wrong-idempotency-key");
    assert!(verify_clearing_lifecycle_replay_authority(
        finalized_head,
        &wrong_idempotency,
        &replay_pins,
        None,
        None,
    )
    .is_err());

    let dispatch_heads = dispatch_projection
        .transitions()
        .iter()
        .map(|transition| transition.next_head.clone())
        .collect::<Vec<_>>();
    let dispatching_head = dispatch_heads
        .iter()
        .find(|head| head.resource_key.resource_family == "clearing_round")
        .ok_or("missing dispatching round head")?;
    let ready_slot_head = dispatch_heads
        .iter()
        .find(|head| head.resource_key == effect_slot.resource_head_key())
        .ok_or("missing ready effect slot head")?;
    let dispatching_obligations =
        advance_anchored_obligations(&request.obligations, &dispatch_heads)?;
    let mut committed_slot = effect_slot.clone();
    committed_slot.state = EconomicEffectStateV1::DispatchCommitted;
    let committed_slot_head = effect_slot_successor(ready_slot_head, &committed_slot, 562)?;
    finalization_trust.trusted_time_unix_ms = 562;
    let reconciliation = SignedClearingSettlementReconciliationV1::sign(
        ClearingSettlementReconciliationBodyV1 {
            schema: CLEARING_SETTLEMENT_RECONCILIATION_SCHEMA.to_owned(),
            round_id: output.core.round_id.clone(),
            round_core_digest: output.core.digest()?,
            output_manifest_digest: output.output_manifest.digest()?,
            intent_id: signed_intent.body.intent_id.clone(),
            intent_digest: signed_intent.body.digest()?,
            effect_slot_id: committed_slot.slot_id.clone(),
            source_effect_slot_digest: committed_slot_head.digest()?,
            settlement_outcome_digest: digest("clearing-settlement-outcome"),
            external_references: vec!["rail:transaction:clearing-1".to_owned()],
            observed_status: ClearingSettlementObservedStatusV1::Settled,
            attempt_number: 1,
            source_lifecycle_head_digest: dispatching_head.digest()?,
            source_lifecycle_version: dispatching_head.resource_version,
            source_lifecycle_fence: dispatching_head.lifecycle_fence,
            next_lifecycle_version: dispatching_head.resource_version + 1,
            next_lifecycle_fence: dispatching_head.lifecycle_fence + 1,
            authority_digest: digest("settlement-reconciliation-authority"),
            disposition_authority_id: finalization_trust.obligation_authority_id.clone(),
            disposition_authority_key_epoch: finalization_trust.obligation_key_epoch,
            observed_at_unix_ms: 562,
        },
        &obligation_authority,
    )?;
    let reconciliation_projection = compose_clearing_reconciliation_transition(
        dispatching_head,
        &dispatching_obligations,
        &committed_slot_head,
        signed_intent,
        &reconciliation,
        &finalization_trust,
        &ReplaySettledOutcome,
    )?;
    let reconciliation_replay = ClearingLifecycleReplayV1 {
        format: CLEARING_LIFECYCLE_REPLAY_FORMAT.to_owned(),
        proof: reconciliation_projection.proof().clone(),
        evidence: ClearingLifecycleReplayEvidenceV1::Reconciliation {
            reconciliation: Box::new(ClearingReconciliationReplayV1 {
                request: request.clone(),
                signed_output: signed_output.clone(),
                intent_id: signed_intent.body.intent_id.clone(),
                source_effect_slot_head: committed_slot_head.clone(),
                signed_reconciliation: reconciliation.clone(),
            }),
        },
    };
    assert_eq!(
        verify_clearing_lifecycle_replay_authority_with_outcome(
            dispatching_head,
            &reconciliation_replay,
            &replay_pins,
            None,
            None,
            Some(&ReplaySettledOutcome),
        )?,
        EconomicTransitionAuthorizationV1::Direct
    );
    let mut reconciliation_heads = vec![dispatching_head.clone(), committed_slot_head.clone()];
    reconciliation_heads.extend(
        dispatching_obligations
            .iter()
            .map(|obligation| obligation.head.clone()),
    );
    let reconciliation_view = signed_anchor_view(reconciliation_heads, 562)?;
    let verified_reconciliation_view =
        verify_economic_state_view(reconciliation_view.clone(), &state_anchor_pins())?;
    let reconciliation_batch =
        signed_projection_batch(&reconciliation_projection, &reconciliation_view)?;
    let replay_verifier = ClearingLifecycleReplayBatchVerifier::new(
        reconciliation_replay.clone(),
        replay_pins.clone(),
        None,
        None,
    )?
    .with_settlement_outcome_verifier(Arc::new(ReplaySettledOutcome));
    verify_economic_state_batch_advance(
        &verified_reconciliation_view,
        reconciliation_batch.clone(),
        &state_anchor_pins(),
        &replay_verifier,
    )?;
    let mut substituted_reconciliation_clock = reconciliation_batch.clone();
    substituted_reconciliation_clock.transitions[0]
        .next_head
        .trusted_clock_high_water += 1;
    substituted_reconciliation_clock.seal(&state_anchor_key())?;
    assert!(verify_economic_state_batch_advance(
        &verified_reconciliation_view,
        substituted_reconciliation_clock,
        &state_anchor_pins(),
        &replay_verifier,
    )
    .is_err());
    let mut substituted_terminal = reconciliation_batch;
    let terminal_transition = substituted_terminal
        .transitions
        .iter_mut()
        .find(|transition| transition.resource_key == committed_slot.resource_head_key())
        .ok_or("reconciliation batch omitted the effect slot transition")?;
    let EconomicContentV1::Inline { value } = &mut terminal_transition.next_head.state else {
        return Err("reconciliation effect slot is not inline".into());
    };
    let mut terminal_slot: EconomicEffectSlotV1 = serde_json::from_value(value.clone())?;
    let substituted_result = EconomicContentV1::Inline {
        value: serde_json::json!({"settlementReference": "substituted"}),
    };
    terminal_slot.terminal = Some(EconomicEffectTerminalV1::Completed {
        result_id: "substituted".to_owned(),
        result_digest: substituted_result.digest()?,
        result: substituted_result,
    });
    *value = serde_json::to_value(terminal_slot)?;
    terminal_transition.next_head.state_digest = terminal_transition.next_head.state.digest()?;
    substituted_terminal.seal(&state_anchor_key())?;
    assert!(verify_economic_state_batch_advance(
        &verified_reconciliation_view,
        substituted_terminal,
        &state_anchor_pins(),
        &replay_verifier,
    )
    .is_err());
    let reconciled_heads = reconciliation_projection
        .transitions()
        .iter()
        .map(|transition| transition.next_head.clone())
        .collect::<Vec<_>>();
    let reconciled_round_head = reconciled_heads
        .iter()
        .find(|head| head.resource_key.resource_family == "clearing_round")
        .ok_or("reconciliation omitted the next round head")?;
    let reconciled_obligations =
        advance_anchored_obligations(&request.obligations, &reconciled_heads)?;
    let mut satisfaction_trust = finalization_trust.clone();
    satisfaction_trust.trusted_time_unix_ms = 563;
    let satisfaction_body = prepare_clearing_round_satisfaction(
        reconciled_round_head,
        &reconciled_obligations,
        &request,
        &signed_output,
        &satisfaction_trust,
        digest("round-satisfaction-authority"),
        563,
    )?;
    let signed_satisfaction =
        SignedClearingRoundSatisfactionV1::sign(satisfaction_body, &obligation_authority)?;
    validate_schema("clearing-round-satisfaction.v1.json", &signed_satisfaction)?;
    let satisfaction_projection = compose_clearing_satisfaction_transition(
        reconciled_round_head,
        &reconciled_obligations,
        &request,
        &signed_output,
        &signed_satisfaction,
        &satisfaction_trust,
    )?;
    assert_eq!(
        satisfaction_projection.transitions().len(),
        request.obligations.len() + 1
    );
    for transition in satisfaction_projection.transitions() {
        if transition.resource_key.resource_family == "clearing_round" {
            assert_eq!(transition.next_head.lifecycle_state, "satisfied");
        } else {
            assert_eq!(transition.next_head.lifecycle_state, "clearing_satisfied");
            let EconomicContentV1::Inline { value } = &transition.next_head.state else {
                return Err("satisfied obligation state is not inline".into());
            };
            let disposition: ObligationDispositionRecordV1 = serde_json::from_value(value.clone())?;
            assert!(matches!(
                disposition.disposition(),
                ObligationDispositionV1::ClearingSatisfied {
                    satisfaction_digest,
                    ..
                } if satisfaction_digest == &signed_satisfaction.digest()?
            ));
        }
    }
    let satisfaction_replay = ClearingLifecycleReplayV1 {
        format: CLEARING_LIFECYCLE_REPLAY_FORMAT.to_owned(),
        proof: satisfaction_projection.proof().clone(),
        evidence: ClearingLifecycleReplayEvidenceV1::Satisfaction {
            satisfaction: Box::new(ClearingSatisfactionReplayV1 {
                request: request.clone(),
                signed_output: signed_output.clone(),
                signed_satisfaction: signed_satisfaction.clone(),
            }),
        },
    };
    assert_eq!(
        verify_clearing_lifecycle_replay_authority(
            reconciled_round_head,
            &satisfaction_replay,
            &replay_pins,
            None,
            None,
        )?,
        EconomicTransitionAuthorizationV1::Direct
    );
    let satisfaction_view = signed_anchor_view(reconciled_heads.clone(), 563)?;
    let verified_satisfaction_view =
        verify_economic_state_view(satisfaction_view.clone(), &state_anchor_pins())?;
    let satisfaction_batch = signed_projection_batch(&satisfaction_projection, &satisfaction_view)?;
    let satisfaction_verifier = ClearingLifecycleReplayBatchVerifier::new(
        satisfaction_replay,
        replay_pins.clone(),
        None,
        None,
    )?;
    verify_economic_state_batch_advance(
        &verified_satisfaction_view,
        satisfaction_batch.clone(),
        &state_anchor_pins(),
        &satisfaction_verifier,
    )?;
    let mut substituted_satisfaction_clock = satisfaction_batch;
    substituted_satisfaction_clock.transitions[0]
        .next_head
        .trusted_clock_high_water += 1;
    substituted_satisfaction_clock.seal(&state_anchor_key())?;
    assert!(verify_economic_state_batch_advance(
        &verified_satisfaction_view,
        substituted_satisfaction_clock,
        &state_anchor_pins(),
        &satisfaction_verifier,
    )
    .is_err());
    let canonical_reconciliation_replay = canonical_json_bytes(&reconciliation_replay)?;
    let decoded_reconciliation_replay: ClearingLifecycleReplayV1 =
        serde_json::from_slice(&canonical_reconciliation_replay)?;
    assert_eq!(decoded_reconciliation_replay, reconciliation_replay);
    let mut substituted_reconciliation = reconciliation_replay;
    let ClearingLifecycleReplayEvidenceV1::Reconciliation { reconciliation } =
        &mut substituted_reconciliation.evidence
    else {
        return Err("reconciliation replay used the wrong evidence".into());
    };
    reconciliation
        .source_effect_slot_head
        .trusted_clock_high_water += 1;
    assert!(verify_clearing_lifecycle_replay_authority_with_outcome(
        dispatching_head,
        &substituted_reconciliation,
        &replay_pins,
        None,
        None,
        Some(&ReplaySettledOutcome),
    )
    .is_err());

    let canonical_replay = canonical_json_bytes(&finalization_replay)?;
    let decoded_replay: ClearingLifecycleReplayV1 = serde_json::from_slice(&canonical_replay)?;
    assert_eq!(decoded_replay, finalization_replay);
    let mut substituted_lineage = finalization_replay;
    let ClearingLifecycleReplayEvidenceV1::Finalize { finalization } =
        &mut substituted_lineage.evidence
    else {
        return Err("finalization replay used the wrong evidence".into());
    };
    let ClearingRoundTransitionV1::BeginFinalization {
        authority_digest, ..
    } = &mut finalization.begin_finalization_proof.transition
    else {
        return Err("finalization replay lineage used the wrong transition".into());
    };
    *authority_digest = digest("substituted-acceptance-authority");
    assert!(verify_clearing_lifecycle_replay_authority(
        finalizing_head,
        &substituted_lineage,
        &replay_pins,
        Some(&frost.trust),
        Some(&closed_dispute_window),
    )
    .is_err());

    let mut alternate_acceptances = acceptances.clone();
    alternate_acceptances[0] = SignedClearingParticipantAcceptanceV1::sign(
        ClearingParticipantAcceptanceBodyV1 {
            accepted_at_unix_ms: 511,
            ..alternate_acceptances[0].body.clone()
        },
        &participant_key("A"),
    )?;
    let alternate_verified = verify_clearing_participant_acceptances(
        &request,
        &signed_output,
        &alternate_acceptances,
        &closed_dispute_window,
        &finalization_trust,
    )?;
    assert!(prepare_clearing_round_finalization(
        finalizing_head,
        &alternate_verified,
        &finalization_trust,
    )
    .is_err());

    let mut expired_finalization_trust = finalization_trust.clone();
    expired_finalization_trust.trusted_time_unix_ms = 600;
    assert!(prepare_clearing_round_finalization(
        finalizing_head,
        &verified,
        &expired_finalization_trust,
    )
    .is_err());

    let mut incomplete = acceptances.clone();
    incomplete.pop();
    assert!(verify_clearing_participant_acceptances(
        &request,
        &signed_output,
        &incomplete,
        &closed_dispute_window,
        &finalization_trust,
    )
    .is_err());

    let mut wrong_statement = acceptances.clone();
    wrong_statement[0] = SignedClearingParticipantAcceptanceV1::sign(
        ClearingParticipantAcceptanceBodyV1 {
            participant_statement_digest: output.participant_statements[1].digest()?,
            ..wrong_statement[0].body.clone()
        },
        &participant_key("A"),
    )?;
    assert!(verify_clearing_participant_acceptances(
        &request,
        &signed_output,
        &wrong_statement,
        &closed_dispute_window,
        &finalization_trust,
    )
    .is_err());

    let mut expired = acceptances.clone();
    expired[0] = SignedClearingParticipantAcceptanceV1::sign(
        ClearingParticipantAcceptanceBodyV1 {
            expires_at_unix_ms: 550,
            ..expired[0].body.clone()
        },
        &participant_key("A"),
    )?;
    assert!(verify_clearing_participant_acceptances(
        &request,
        &signed_output,
        &expired,
        &closed_dispute_window,
        &finalization_trust,
    )
    .is_err());

    finalization_trust.trusted_time_unix_ms = 499;
    assert!(verify_clearing_participant_acceptances(
        &request,
        &signed_output,
        &acceptances,
        &closed_dispute_window,
        &finalization_trust,
    )
    .is_err());
    finalization_trust.trusted_time_unix_ms = 550;
    assert!(verify_clearing_participant_acceptances(
        &request,
        &signed_output,
        &acceptances,
        &DisputeWindow {
            unresolved_dispute_count: 1,
        },
        &finalization_trust,
    )
    .is_err());
    Ok(())
}

#[test]
fn signed_abort_releases_only_after_complete_zero_dispatch_and_the_winning_fence() -> TestResult {
    let participant_authority = Keypair::from_seed(&[31; 32]);
    let obligation_authority = Keypair::from_seed(&[32; 32]);
    let admission_authority = Keypair::from_seed(&[33; 32]);
    let request = signed_request(
        vec![
            reserved_obligation(1, "A", "B", "USD", 100)?,
            reserved_obligation(2, "B", "C", "USD", 100)?,
        ],
        &participant_authority,
        &obligation_authority,
    )?;
    let mut clearing_trust = trust(&participant_authority, &obligation_authority);
    let output = compute_netting_round(&request, &clearing_trust)?;
    let signed_output =
        sign_netting_round(&request, &output, &clearing_trust, &participant_authority)?;
    let reserved = ClearingRoundLifecycleRecordV1::reserved(&output.core)?;
    let reserved_head = clearing_head(&reserved)?;
    let anchored = anchored_obligations(&request.obligations, &output.core.governance_scope_id)?;
    let proposed = compose_clearing_lifecycle_transition(
        &reserved_head,
        &anchored,
        ClearingRoundTransitionV1::Propose {
            output_manifest_digest: output.output_manifest.digest()?,
            authority_digest: signed_output.output_manifest.digest()?,
        },
        501,
    )?;
    let proposed_heads = proposed
        .transitions()
        .iter()
        .map(|transition| transition.next_head.clone())
        .collect::<Vec<_>>();
    let proposed_head = proposed_heads
        .iter()
        .find(|head| head.resource_key.resource_family == "clearing_round")
        .ok_or("missing proposed round head")?;
    let proposed_obligations = advance_anchored_obligations(&request.obligations, &proposed_heads)?;

    clearing_trust.trusted_time_unix_ms = 520;
    let proof_trust = ClearingZeroDispatchTrustV1 {
        authority_id: "admission-authority".to_owned(),
        authority_key: admission_authority.public_key(),
        authority_key_epoch: 9,
        admission_store_id: "admission-store-primary".to_owned(),
        admission_commit_sequence: 12,
        admission_commit_digest: digest("admission-commit"),
        trusted_time_unix_ms: 520,
    };
    let statuses = output
        .intents
        .iter()
        .map(ClearingIntentDispatchStatusV1::absent)
        .collect::<Result<Vec<_>, _>>()?;
    let proof_body = prepare_clearing_zero_dispatch_proof(
        proposed_head,
        &request,
        Some(&signed_output),
        statuses.clone(),
        &clearing_trust,
        &proof_trust,
        560,
    )?;
    let signed_proof =
        sign_clearing_zero_dispatch_proof(proof_body, &proof_trust, &admission_authority)?;
    validate_schema("clearing-zero-dispatch-proof.v1.json", &signed_proof)?;
    let verified_proof = verify_clearing_zero_dispatch_proof(
        proposed_head,
        &request,
        Some(&signed_output),
        &signed_proof,
        &clearing_trust,
        &proof_trust,
    )?;
    let mut advanced_checkpoint = proof_trust.clone();
    advanced_checkpoint.admission_commit_sequence += 1;
    advanced_checkpoint.admission_commit_digest = digest("advanced-admission-commit");
    assert!(verify_clearing_zero_dispatch_proof(
        proposed_head,
        &request,
        Some(&signed_output),
        &signed_proof,
        &clearing_trust,
        &advanced_checkpoint,
    )
    .is_err());

    clearing_trust.trusted_time_unix_ms = 525;
    let abort_body = prepare_clearing_round_abort(
        proposed_head,
        &verified_proof,
        ClearingRoundAbortReasonV1::OperatorCancelled,
        digest("abort-authority"),
        None,
        &clearing_trust,
    )?;
    let signed_abort =
        sign_clearing_round_abort(abort_body, &clearing_trust, &obligation_authority)?;
    validate_schema("clearing-round-abort.v1.json", &signed_abort)?;
    let verified_abort = verify_clearing_round_abort(
        proposed_head,
        &verified_proof,
        &signed_abort,
        None,
        &clearing_trust,
    )?;
    let aborting = compose_clearing_lifecycle_transition(
        proposed_head,
        &proposed_obligations,
        verified_abort.begin_abort_transition(),
        525,
    )?;
    let aborting_heads = aborting
        .transitions()
        .iter()
        .map(|transition| transition.next_head.clone())
        .collect::<Vec<_>>();
    let aborting_head = aborting_heads
        .iter()
        .find(|head| head.resource_key.resource_family == "clearing_round")
        .ok_or("missing aborting round head")?;
    let aborting_obligations = advance_anchored_obligations(&request.obligations, &aborting_heads)?;
    let aborted = compose_clearing_lifecycle_transition(
        aborting_head,
        &aborting_obligations,
        verified_abort.abort_transition(aborting_head, aborting.proof())?,
        526,
    )?;
    let aborted_round = aborted
        .transitions()
        .iter()
        .find(|transition| transition.resource_key.resource_family == "clearing_round")
        .ok_or("missing aborted round head")?;
    assert_eq!(aborted_round.next_head.lifecycle_state, "aborted");
    let replay_pins = ClearingLifecycleAuthorityPinsV1 {
        clearing_authority_id: clearing_trust.clearing_authority_id.clone(),
        clearing_authority_key: clearing_trust.clearing_authority_key.clone(),
        clearing_authority_key_epoch: clearing_trust.clearing_authority_key_epoch,
        participant_authority_id: clearing_trust.participant_authority_id.clone(),
        participant_authority_key: clearing_trust.participant_authority_key.clone(),
        participant_key_epoch: clearing_trust.participant_key_epoch,
        obligation_authority_id: clearing_trust.obligation_authority_id.clone(),
        obligation_authority_key: clearing_trust.obligation_authority_key.clone(),
        obligation_key_epoch: clearing_trust.obligation_key_epoch,
        zero_dispatch_authority_id: proof_trust.authority_id.clone(),
        zero_dispatch_authority_key: proof_trust.authority_key.clone(),
        zero_dispatch_authority_key_epoch: proof_trust.authority_key_epoch,
        admission_store_id: proof_trust.admission_store_id.clone(),
    };
    let proposal_replay = ClearingLifecycleReplayV1 {
        format: CLEARING_LIFECYCLE_REPLAY_FORMAT.to_owned(),
        proof: proposed.proof().clone(),
        evidence: ClearingLifecycleReplayEvidenceV1::Proposal {
            request: Box::new(request.clone()),
            signed_output: Box::new(signed_output.clone()),
        },
    };
    assert_eq!(
        verify_clearing_lifecycle_replay_authority(
            &reserved_head,
            &proposal_replay,
            &replay_pins,
            None,
            None,
        )?,
        EconomicTransitionAuthorizationV1::Direct
    );
    let abort_replay = ClearingAbortReplayV1 {
        request: request.clone(),
        signed_output: Some(signed_output.clone()),
        zero_dispatch_proof: signed_proof.clone(),
        abort: signed_abort.clone(),
        finalization_burn: None,
    };
    let begin_replay = ClearingLifecycleReplayV1 {
        format: CLEARING_LIFECYCLE_REPLAY_FORMAT.to_owned(),
        proof: aborting.proof().clone(),
        evidence: ClearingLifecycleReplayEvidenceV1::BeginAbort {
            abort: Box::new(abort_replay.clone()),
        },
    };
    assert_eq!(
        verify_clearing_lifecycle_replay_authority(
            proposed_head,
            &begin_replay,
            &replay_pins,
            None,
            None,
        )?,
        EconomicTransitionAuthorizationV1::Direct
    );
    assert_eq!(
        begin_replay.admission_checkpoint(),
        Some((
            proof_trust.admission_store_id.as_str(),
            proof_trust.admission_commit_sequence,
            proof_trust.admission_commit_digest.as_str(),
        ))
    );
    let completion_replay = ClearingLifecycleReplayV1 {
        format: CLEARING_LIFECYCLE_REPLAY_FORMAT.to_owned(),
        proof: aborted.proof().clone(),
        evidence: ClearingLifecycleReplayEvidenceV1::Abort {
            preabort_round_head: Box::new(proposed_head.clone()),
            begin_abort_proof: Box::new(aborting.proof().clone()),
            abort: Box::new(abort_replay),
        },
    };
    assert_eq!(
        verify_clearing_lifecycle_replay_authority(
            aborting_head,
            &completion_replay,
            &replay_pins,
            None,
            None,
        )?,
        EconomicTransitionAuthorizationV1::Direct
    );
    let canonical_replay = canonical_json_bytes(&completion_replay)?;
    let decoded_replay: ClearingLifecycleReplayV1 = serde_json::from_slice(&canonical_replay)?;
    assert_eq!(decoded_replay, completion_replay);
    let mut substituted_replay = completion_replay;
    let ClearingLifecycleReplayEvidenceV1::Abort {
        begin_abort_proof, ..
    } = &mut substituted_replay.evidence
    else {
        return Err("completion replay used the wrong evidence".into());
    };
    begin_abort_proof.source_round_head_digest = digest("substituted-source");
    assert!(verify_clearing_lifecycle_replay_authority(
        aborting_head,
        &substituted_replay,
        &replay_pins,
        None,
        None,
    )
    .is_err());
    for transition in aborted
        .transitions()
        .iter()
        .filter(|transition| transition.resource_key.resource_family == "obligation_disposition")
    {
        let EconomicContentV1::Inline { value } = &transition.next_head.state else {
            return Err("released obligation did not contain inline state".into());
        };
        let disposition: ObligationDispositionRecordV1 = serde_json::from_value(value.clone())?;
        assert_eq!(disposition.disposition(), &ObligationDispositionV1::PerCall);
    }

    let mut incomplete = statuses;
    incomplete.pop();
    assert!(prepare_clearing_zero_dispatch_proof(
        proposed_head,
        &request,
        Some(&signed_output),
        incomplete,
        &clearing_trust,
        &proof_trust,
        560,
    )
    .is_err());
    assert!(sign_clearing_round_abort(
        signed_abort.body.clone(),
        &clearing_trust,
        &participant_authority,
    )
    .is_err());
    assert!(verified_abort
        .abort_transition(proposed_head, aborting.proof())
        .is_err());
    let mut substituted_proof = aborting.proof().clone();
    let ClearingRoundTransitionV1::BeginAbort {
        zero_dispatch_proof_digest,
        ..
    } = &mut substituted_proof.transition
    else {
        return Err("aborting proof used the wrong transition".into());
    };
    *zero_dispatch_proof_digest = digest("substituted-zero-dispatch");
    assert!(verified_abort
        .abort_transition(aborting_head, &substituted_proof)
        .is_err());
    let mut expired_trust = clearing_trust;
    expired_trust.trusted_time_unix_ms = 560;
    assert!(prepare_clearing_round_abort(
        proposed_head,
        &verified_proof,
        ClearingRoundAbortReasonV1::OperatorCancelled,
        digest("abort-authority"),
        None,
        &expired_trust,
    )
    .is_err());
    Ok(())
}

#[path = "clearing/netting_edge_cases.rs"]
mod netting_edge_cases;

#[path = "clearing/zero_intent.rs"]
mod zero_intent;
