use chio_core_types::{sha256_hex, Keypair};
use chio_federation::frost::{
    frost_action_registration, frost_authorization_session_id, frost_authorization_slot_id,
    resolve_active_roster_for_execution, verify_bound_frost_authorization_slot,
    verify_burned_frost_authorization_slot, verify_completed_frost_authorization_slot,
    verify_for_execution, verify_frost_authorization_slot_bind,
    verify_frost_authorization_slot_burn, verify_frost_authorization_slot_completion,
    verify_frost_epoch_advance, ActiveFrostRosterResolver, ExpectedFrostAuthorization,
    FrostActionPreimageV1, FrostAnchorError, FrostAnchoredAuthorizationSlot,
    FrostArtifactAuthorityRole, FrostArtifactTrustRoot, FrostArtifactTrustStore,
    FrostAuthorizationBodyV1, FrostAuthorizationDomain, FrostAuthorizationSlotAnchor,
    FrostAuthorizationSlotCheckpointV1, FrostAuthorizationSlotState, FrostAuthorizationV1,
    FrostEpochAnchor, FrostEpochCheckpointV1, FrostParticipantV1, FrostRosterKeyOrigin,
    FrostRosterResolutionError, FrostRosterRotateActionV1, FrostRosterV1,
    FrostSessionBurnSummaryV1, CHIO_FROST_AUTHORIZATION_BODY_SCHEMA,
    CHIO_FROST_AUTHORIZATION_SCHEMA, CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SCHEMA,
    CHIO_FROST_EPOCH_CHECKPOINT_SCHEMA, CHIO_FROST_ROSTER_ROTATE_ACTION_SCHEMA,
    CHIO_FROST_ROSTER_SCHEMA, FROST_ED25519_SHA512_SUITE_ID,
};
use frost_ed25519::keys::{IdentifierList, KeyPackage};
use frost_ed25519::{keys, SigningKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

struct ThresholdGroup {
    signing_key: SigningKey,
    group_public_key: String,
    participants: Vec<FrostParticipantV1>,
}

fn threshold_group(seed: u8, threshold: u16, participant_count: u16) -> ThresholdGroup {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let signing_key = SigningKey::new(&mut rng);
    let (shares, public_key_package) = keys::split(
        &signing_key,
        participant_count,
        threshold,
        IdentifierList::Default,
        &mut rng,
    )
    .unwrap_or_else(|error| panic!("split threshold group: {error}"));
    let participants = shares
        .into_values()
        .enumerate()
        .map(|(index, share)| {
            let key_package = KeyPackage::try_from(share)
                .unwrap_or_else(|error| panic!("verify threshold share: {error}"));
            FrostParticipantV1 {
                participant_id: format!("operator-{}", index + 1),
                verification_share: hex::encode(
                    key_package
                        .verifying_share()
                        .serialize()
                        .unwrap_or_else(|error| panic!("serialize verification share: {error}")),
                ),
            }
        })
        .collect();
    ThresholdGroup {
        signing_key,
        group_public_key: hex::encode(
            public_key_package
                .verifying_key()
                .serialize()
                .unwrap_or_else(|error| panic!("serialize group key: {error}")),
        ),
        participants,
    }
}

fn roster_authority() -> Keypair {
    Keypair::from_seed(&[0x31; 32])
}

fn epoch_authority() -> Keypair {
    Keypair::from_seed(&[0x32; 32])
}

fn slot_authority() -> Keypair {
    Keypair::from_seed(&[0x33; 32])
}

fn trust_store() -> FrostArtifactTrustStore {
    FrostArtifactTrustStore::new([
        FrostArtifactTrustRoot {
            role: FrostArtifactAuthorityRole::Roster,
            key_id: "roster-authority.v1".to_string(),
            public_key: roster_authority().public_key(),
        },
        FrostArtifactTrustRoot {
            role: FrostArtifactAuthorityRole::EpochAnchor,
            key_id: "epoch-authority.v1".to_string(),
            public_key: epoch_authority().public_key(),
        },
        FrostArtifactTrustRoot {
            role: FrostArtifactAuthorityRole::AuthorizationSlotAnchor,
            key_id: "slot-authority.v1".to_string(),
            public_key: slot_authority().public_key(),
        },
    ])
    .unwrap_or_else(|error| panic!("build artifact trust: {error}"))
}

fn signed_roster(
    group: &ThresholdGroup,
    scope_id: &str,
    domain: FrostAuthorizationDomain,
    key_epoch: u64,
    predecessor: Option<String>,
    transcript_byte: u8,
) -> FrostRosterV1 {
    let registration =
        frost_action_registration(domain).unwrap_or_else(|| panic!("registered FROST domain"));
    let mut roster = FrostRosterV1 {
        schema: CHIO_FROST_ROSTER_SCHEMA.to_string(),
        roster_id: String::new(),
        roster_digest: String::new(),
        authority_scope: registration.quorum_scope.to_string(),
        scope_id: scope_id.to_string(),
        allowed_domains: vec![domain],
        key_epoch,
        threshold: registration.quorum_n,
        participant_count: registration.quorum_m,
        participants: group.participants.clone(),
        group_public_key: group.group_public_key.clone(),
        suite_id: FROST_ED25519_SHA512_SUITE_ID.to_string(),
        key_origin: FrostRosterKeyOrigin::DistributedDkg,
        ceremony_transcript_digest: format!("{transcript_byte:02x}").repeat(32),
        predecessor_roster_digest: predecessor,
        valid_from: 100,
        valid_until: 500,
        roster_authority_key_id: "roster-authority.v1".to_string(),
        roster_authority_signature: String::new(),
    };
    roster.roster_id = roster
        .recompute_roster_id()
        .unwrap_or_else(|error| panic!("compute roster id: {error}"));
    roster.roster_authority_signature = roster_authority()
        .sign(
            &roster
                .signing_bytes()
                .unwrap_or_else(|error| panic!("canonicalize roster: {error}")),
        )
        .to_hex();
    roster.roster_digest = roster
        .recompute_roster_digest()
        .unwrap_or_else(|error| panic!("compute roster digest: {error}"));
    roster
}

fn signed_checkpoint(roster: &FrostRosterV1, activation_fence: u64) -> FrostEpochCheckpointV1 {
    let mut checkpoint = FrostEpochCheckpointV1 {
        schema: CHIO_FROST_EPOCH_CHECKPOINT_SCHEMA.to_string(),
        anchor_id: "epoch-anchor.primary".to_string(),
        checkpoint_digest: String::new(),
        scope_id: roster.scope_id.clone(),
        checkpoint_sequence: 1,
        predecessor_digest: None,
        active_roster_id: roster.roster_id.clone(),
        active_roster_digest: roster.roster_digest.clone(),
        key_epoch: roster.key_epoch,
        group_public_key_digest: sha256_hex(
            &hex::decode(&roster.group_public_key)
                .unwrap_or_else(|error| panic!("decode group key: {error}")),
        ),
        rotation_authorization_digest: None,
        activation_fence,
        clock_high_water: 100,
        anchor_key_id: "epoch-authority.v1".to_string(),
        anchor_signature: String::new(),
    };
    checkpoint.anchor_signature = epoch_authority()
        .sign(
            &checkpoint
                .signing_bytes()
                .unwrap_or_else(|error| panic!("canonicalize checkpoint: {error}")),
        )
        .to_hex();
    checkpoint.checkpoint_digest = checkpoint
        .recompute_checkpoint_digest()
        .unwrap_or_else(|error| panic!("compute checkpoint digest: {error}"));
    checkpoint
}

struct Resolver(FrostRosterV1);

impl ActiveFrostRosterResolver for Resolver {
    fn resolve_active_roster(
        &self,
        scope_id: &str,
    ) -> Result<Option<FrostRosterV1>, FrostRosterResolutionError> {
        Ok((self.0.scope_id == scope_id).then(|| self.0.clone()))
    }

    fn classify_scope(&self, scope_id: &str) -> Result<Option<String>, FrostRosterResolutionError> {
        Ok((self.0.scope_id == scope_id).then(|| self.0.authority_scope.clone()))
    }
}

struct EpochAnchor(FrostEpochCheckpointV1);

impl FrostEpochAnchor for EpochAnchor {
    fn resolve_epoch_checkpoint(
        &self,
        scope_id: &str,
    ) -> Result<FrostEpochCheckpointV1, FrostAnchorError> {
        (self.0.scope_id == scope_id)
            .then(|| self.0.clone())
            .ok_or_else(|| FrostAnchorError::Unavailable("epoch is absent".to_string()))
    }
}

struct SlotAnchor(FrostAnchoredAuthorizationSlot);

impl FrostAuthorizationSlotAnchor for SlotAnchor {
    fn resolve_authorization_slot(
        &self,
        scope_id: &str,
        slot_id: &str,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError> {
        (self.0.checkpoint.scope_id == scope_id && self.0.checkpoint.slot_id == slot_id)
            .then(|| self.0.clone())
            .ok_or_else(|| FrostAnchorError::Unavailable("slot is absent".to_string()))
    }
}

fn verified_rotation(
    governance_group: &ThresholdGroup,
    governance_roster: &FrostRosterV1,
    governance_checkpoint: &FrostEpochCheckpointV1,
    action: &FrostRosterRotateActionV1,
) -> chio_federation::frost::VerifiedFrostAuthorization {
    let registration = frost_action_registration(FrostAuthorizationDomain::RosterRotate)
        .unwrap_or_else(|| panic!("rotation domain is registered"));
    let preimage = FrostActionPreimageV1::RosterRotate(action.clone());
    let mut body = FrostAuthorizationBodyV1 {
        schema: CHIO_FROST_AUTHORIZATION_BODY_SCHEMA.to_string(),
        authorization_id: String::new(),
        domain: FrostAuthorizationDomain::RosterRotate,
        ladder_action_class: registration.ladder_action_class.to_string(),
        ladder_contract_digest: registration
            .ladder_contract_digest()
            .unwrap_or_else(|error| panic!("compute ladder digest: {error}")),
        quorum_n: registration.quorum_n,
        quorum_m: registration.quorum_m,
        quorum_scope: registration.quorum_scope.to_string(),
        scope_id: governance_roster.scope_id.clone(),
        resource_id: action.scope_id.clone(),
        resource_version: action.current_key_epoch,
        resource_fence: action.activation_fence,
        action_digest: preimage
            .action_digest()
            .unwrap_or_else(|error| panic!("compute action digest: {error}")),
        roster_digest: governance_roster.roster_digest.clone(),
        key_epoch: governance_roster.key_epoch,
        issued_at: 150,
        expires_at: 300,
    };
    body.authorization_id = body
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("compute authorization id: {error}"));
    let signing_bytes = body
        .signing_bytes()
        .unwrap_or_else(|error| panic!("canonicalize authorization: {error}"));
    let signature = governance_group
        .signing_key
        .sign(ChaCha20Rng::from_seed([0x55; 32]), &signing_bytes);
    let signature_bytes = signature
        .serialize()
        .unwrap_or_else(|error| panic!("serialize group signature: {error}"));
    let proof = FrostAuthorizationV1 {
        schema: CHIO_FROST_AUTHORIZATION_SCHEMA.to_string(),
        body,
        suite_id: FROST_ED25519_SHA512_SUITE_ID.to_string(),
        group_signature: hex::encode(&signature_bytes),
    };
    let proof_bytes = proof
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("canonicalize proof: {error}"));
    let active = resolve_active_roster_for_execution(
        &governance_roster.scope_id,
        &Resolver(governance_roster.clone()),
        &EpochAnchor(governance_checkpoint.clone()),
        &trust_store(),
        200,
    )
    .unwrap_or_else(|error| panic!("resolve governance roster: {error}"));
    let bind = verify_frost_authorization_slot_bind(
        &proof.body,
        &active,
        &EpochAnchor(governance_checkpoint.clone()),
        &trust_store(),
        150,
    )
    .unwrap_or_else(|error| panic!("verify slot bind: {error}"));
    let slot_id = frost_authorization_slot_id(&proof.body)
        .unwrap_or_else(|error| panic!("compute slot id: {error}"));
    assert_eq!(bind.request().scope_id(), proof.body.scope_id);
    assert_eq!(bind.request().slot_id(), slot_id);

    let mut bound = FrostAuthorizationSlotCheckpointV1 {
        schema: CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SCHEMA.to_string(),
        anchor_id: "slot-anchor.primary".to_string(),
        checkpoint_digest: String::new(),
        scope_id: proof.body.scope_id.clone(),
        slot_id,
        slot_version: 1,
        predecessor_digest: None,
        domain: proof.body.domain,
        ladder_action_class: proof.body.ladder_action_class.clone(),
        resource_id: proof.body.resource_id.clone(),
        resource_version: proof.body.resource_version,
        resource_fence: proof.body.resource_fence,
        authorization_id: proof.body.authorization_id.clone(),
        signing_message_digest: sha256_hex(&signing_bytes),
        action_digest: proof.body.action_digest.clone(),
        roster_digest: proof.body.roster_digest.clone(),
        key_epoch: proof.body.key_epoch,
        session_id: frost_authorization_session_id(&proof.body)
            .unwrap_or_else(|error| panic!("compute session id: {error}")),
        state: FrostAuthorizationSlotState::Bound,
        aggregate_signature_digest: None,
        authorization_blob_digest: None,
        availability_receipt: None,
        clock_high_water: 150,
        anchor_key_id: "slot-authority.v1".to_string(),
        anchor_signature: String::new(),
    };
    bound.anchor_signature = slot_authority()
        .sign(
            &bound
                .signing_bytes()
                .unwrap_or_else(|error| panic!("canonicalize slot: {error}")),
        )
        .to_hex();
    bound.checkpoint_digest = bound
        .recompute_checkpoint_digest()
        .unwrap_or_else(|error| panic!("compute slot digest: {error}"));
    let verified_bound = verify_bound_frost_authorization_slot(
        &proof.body,
        &active,
        &EpochAnchor(governance_checkpoint.clone()),
        &FrostAnchoredAuthorizationSlot {
            checkpoint: bound.clone(),
            authorization_blob: None,
        },
        &trust_store(),
        150,
    )
    .unwrap_or_else(|error| panic!("verify bound slot: {error}"));
    assert_eq!(verified_bound.checkpoint_digest(), bound.checkpoint_digest);
    let burn = verify_frost_authorization_slot_burn(&bound, &trust_store(), 151)
        .unwrap_or_else(|error| panic!("verify slot burn: {error}"));
    assert_eq!(
        burn.request().expected_bound_checkpoint_digest(),
        bound.checkpoint_digest
    );
    let mut burned = FrostAuthorizationSlotCheckpointV1 {
        slot_version: 2,
        predecessor_digest: Some(bound.checkpoint_digest.clone()),
        state: FrostAuthorizationSlotState::Burned,
        clock_high_water: 151,
        anchor_signature: String::new(),
        checkpoint_digest: String::new(),
        ..bound.clone()
    };
    burned.anchor_signature = slot_authority()
        .sign(
            &burned
                .signing_bytes()
                .unwrap_or_else(|error| panic!("canonicalize burned slot: {error}")),
        )
        .to_hex();
    burned.checkpoint_digest = burned
        .recompute_checkpoint_digest()
        .unwrap_or_else(|error| panic!("compute burned slot digest: {error}"));
    let burned_anchor = FrostAnchoredAuthorizationSlot {
        checkpoint: burned.clone(),
        authorization_blob: None,
    };
    assert_eq!(
        verify_burned_frost_authorization_slot(&bound, &burned_anchor, &trust_store(), 151)
            .unwrap_or_else(|error| panic!("verify burned successor: {error}"))
            .checkpoint(),
        &burned
    );
    assert!(
        verify_burned_frost_authorization_slot(&bound, &burned_anchor, &trust_store(), 150)
            .is_err()
    );
    let completion = verify_frost_authorization_slot_completion(
        &bound,
        &proof,
        &active,
        &EpochAnchor(governance_checkpoint.clone()),
        &trust_store(),
        "availability.rotation.v1",
        151,
    )
    .unwrap_or_else(|error| panic!("verify slot completion: {error}"));
    assert_eq!(
        completion.request().expected_bound_checkpoint_digest(),
        bound.checkpoint_digest
    );
    assert_eq!(completion.request().authorization_blob(), proof_bytes);

    let bound_checkpoint_digest = bound.checkpoint_digest.clone();
    let mut slot = FrostAuthorizationSlotCheckpointV1 {
        slot_version: 2,
        predecessor_digest: Some(bound_checkpoint_digest.clone()),
        state: FrostAuthorizationSlotState::Completed,
        aggregate_signature_digest: Some(sha256_hex(&signature_bytes)),
        authorization_blob_digest: Some(sha256_hex(&proof_bytes)),
        availability_receipt: Some("availability.rotation.v1".to_string()),
        clock_high_water: 151,
        anchor_signature: String::new(),
        checkpoint_digest: String::new(),
        ..bound
    };
    slot.anchor_signature = slot_authority()
        .sign(
            &slot
                .signing_bytes()
                .unwrap_or_else(|error| panic!("canonicalize slot: {error}")),
        )
        .to_hex();
    slot.checkpoint_digest = slot
        .recompute_checkpoint_digest()
        .unwrap_or_else(|error| panic!("compute slot digest: {error}"));
    let anchored = FrostAnchoredAuthorizationSlot {
        checkpoint: slot.clone(),
        authorization_blob: Some(proof_bytes.clone()),
    };
    let completed = verify_completed_frost_authorization_slot(
        &proof.body,
        &active,
        &EpochAnchor(governance_checkpoint.clone()),
        &anchored,
        &trust_store(),
        &bound_checkpoint_digest,
        200,
    )
    .unwrap_or_else(|error| panic!("verify exact completed slot: {error}"));
    assert_eq!(completed.proof(), &proof);

    let mut wrong_predecessor = slot.clone();
    wrong_predecessor.predecessor_digest = Some("ff".repeat(32));
    wrong_predecessor.anchor_signature = slot_authority()
        .sign(
            &wrong_predecessor
                .signing_bytes()
                .unwrap_or_else(|error| panic!("canonicalize wrong predecessor: {error}")),
        )
        .to_hex();
    wrong_predecessor.checkpoint_digest = wrong_predecessor
        .recompute_checkpoint_digest()
        .unwrap_or_else(|error| panic!("compute wrong predecessor digest: {error}"));
    assert!(verify_completed_frost_authorization_slot(
        &proof.body,
        &active,
        &EpochAnchor(governance_checkpoint.clone()),
        &FrostAnchoredAuthorizationSlot {
            checkpoint: wrong_predecessor,
            authorization_blob: Some(proof_bytes.clone()),
        },
        &trust_store(),
        &bound_checkpoint_digest,
        200,
    )
    .is_err());
    let expected = ExpectedFrostAuthorization {
        domain: proof.body.domain,
        ladder_action_class: &proof.body.ladder_action_class,
        ladder_contract_digest: &proof.body.ladder_contract_digest,
        scope_id: &proof.body.scope_id,
        resource_id: &proof.body.resource_id,
        resource_version: proof.body.resource_version,
        resource_fence: proof.body.resource_fence,
        action_digest: &proof.body.action_digest,
    };
    verify_for_execution(
        &proof,
        &expected,
        &active,
        &EpochAnchor(governance_checkpoint.clone()),
        &SlotAnchor(anchored),
        &trust_store(),
        200,
    )
    .unwrap_or_else(|error| panic!("verify rotation authorization: {error}"))
}

#[test]
fn epoch_advance_requires_distinct_governance_quorum_and_zero_live_sessions() {
    let current_group = threshold_group(1, 2, 3);
    let current_roster = signed_roster(
        &current_group,
        "settlement.atlantic.v1",
        FrostAuthorizationDomain::SettleCommitment,
        1,
        None,
        0x41,
    );
    let current_checkpoint = signed_checkpoint(&current_roster, 7);
    let target_group = threshold_group(2, 2, 3);
    let target_roster = signed_roster(
        &target_group,
        "settlement.atlantic.v1",
        FrostAuthorizationDomain::SettleCommitment,
        2,
        Some(current_roster.roster_digest.clone()),
        0x42,
    );
    let governance_group = threshold_group(3, 3, 5);
    let governance_roster = signed_roster(
        &governance_group,
        "governance.rotation.atlantic.v1",
        FrostAuthorizationDomain::RosterRotate,
        1,
        None,
        0x43,
    );
    let governance_checkpoint = signed_checkpoint(&governance_roster, 3);
    let burn = FrostSessionBurnSummaryV1::new(current_roster.scope_id.clone(), 1, Vec::new())
        .unwrap_or_else(|error| panic!("build empty burn summary: {error}"));
    let action = FrostRosterRotateActionV1 {
        schema: CHIO_FROST_ROSTER_ROTATE_ACTION_SCHEMA.to_string(),
        predecessor_roster_digest: current_roster.roster_digest.clone(),
        new_roster_digest: target_roster.roster_digest.clone(),
        scope_id: current_roster.scope_id.clone(),
        current_key_epoch: 1,
        new_key_epoch: 2,
        current_checkpoint_sequence: current_checkpoint.checkpoint_sequence,
        current_checkpoint_digest: current_checkpoint.checkpoint_digest.clone(),
        activation_fence: 8,
        old_session_burn_root: burn.burn_root.clone(),
    };
    let authorization = verified_rotation(
        &governance_group,
        &governance_roster,
        &governance_checkpoint,
        &action,
    );

    let advance = verify_frost_epoch_advance(
        &current_checkpoint,
        &target_roster,
        &authorization,
        &action,
        &burn,
        &trust_store(),
        200,
    )
    .unwrap_or_else(|error| panic!("verify epoch advance: {error}"));
    assert_eq!(advance.expected_checkpoint_sequence(), 2);
    assert_eq!(
        advance.target_roster().roster_digest,
        target_roster.roster_digest
    );

    let mut live = burn;
    live.live_session_count = 1;
    assert!(verify_frost_epoch_advance(
        &current_checkpoint,
        &target_roster,
        &authorization,
        &action,
        &live,
        &trust_store(),
        200,
    )
    .is_err());
}
