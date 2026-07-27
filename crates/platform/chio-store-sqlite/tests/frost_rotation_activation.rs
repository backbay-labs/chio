use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use chio_core::{sha256_hex, Keypair};
use chio_federation::frost::{
    frost_action_registration, frost_authorization_session_id, frost_authorization_slot_id,
    resolve_active_roster_for_execution, verify_for_execution, verify_frost_epoch_advance,
    ActiveFrostRosterResolver, ExpectedFrostAuthorization, FrostActionPreimageV1, FrostAnchorError,
    FrostAnchoredAuthorizationSlot, FrostArtifactAuthorityRole, FrostArtifactTrustRoot,
    FrostArtifactTrustStore, FrostAuthorizationBodyV1, FrostAuthorizationDomain,
    FrostAuthorizationSlotAnchor, FrostAuthorizationSlotCheckpointV1, FrostAuthorizationSlotState,
    FrostAuthorizationV1, FrostEpochAnchor, FrostEpochAnchorWriter, FrostEpochCheckpointV1,
    FrostParticipantV1, FrostRosterKeyOrigin, FrostRosterResolutionError,
    FrostRosterRotateActionV1, FrostRosterV1, FrostSessionBurnSummaryV1, VerifiedFrostEpochAdvance,
    CHIO_FROST_AUTHORIZATION_BODY_SCHEMA, CHIO_FROST_AUTHORIZATION_SCHEMA,
    CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SCHEMA, CHIO_FROST_EPOCH_CHECKPOINT_SCHEMA,
    CHIO_FROST_ROSTER_ROTATE_ACTION_SCHEMA, CHIO_FROST_ROSTER_SCHEMA,
    FROST_ED25519_SHA512_SUITE_ID,
};
use chio_federation_authority::{
    advance_frost_ceremony, begin_frost_ceremony, FrostCeremonyConfig, FrostCeremonyParticipant,
};
use chio_store_sqlite::{
    FrostCustodyKey, FrostRotationState, SqliteAuthorityStore, SqliteFrostStore,
    StoredFrostCeremonyCompletion,
};
use frost_ed25519::keys::{IdentifierList, KeyPackage};
use frost_ed25519::{keys, SigningKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use rusqlite::Connection;
use tempfile::TempDir;

struct StoreFixture {
    _temp: TempDir,
    database: PathBuf,
    lock_root: PathBuf,
}

impl StoreFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        fs::create_dir(&lock_root).unwrap_or_else(|error| panic!("create lock root: {error}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|error| panic!("secure database parent: {error}"));
            fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|error| panic!("secure lock root: {error}"));
        }
        SqliteAuthorityStore::provision(&database, &lock_root)
            .unwrap_or_else(|error| panic!("provision authority: {error}"));
        Self {
            _temp: temp,
            database,
            lock_root,
        }
    }

    fn open(&self) -> (SqliteAuthorityStore, SqliteFrostStore) {
        let authority = SqliteAuthorityStore::open_serving(&self.database, &self.lock_root)
            .unwrap_or_else(|error| panic!("open authority: {error}"));
        let frost = authority.frost_store();
        (authority, frost)
    }
}

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
            let package = KeyPackage::try_from(share)
                .unwrap_or_else(|error| panic!("verify threshold share: {error}"));
            FrostParticipantV1 {
                participant_id: format!("operator-{}", index + 1),
                verification_share: hex::encode(
                    package
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
    Keypair::from_seed(&[0x21; 32])
}

fn epoch_authority() -> Keypair {
    Keypair::from_seed(&[0x22; 32])
}

fn slot_authority() -> Keypair {
    Keypair::from_seed(&[0x23; 32])
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
    .unwrap_or_else(|error| panic!("build trust store: {error}"))
}

fn sign_roster(mut roster: FrostRosterV1) -> FrostRosterV1 {
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

fn group_roster(
    group: &ThresholdGroup,
    scope_id: &str,
    domain: FrostAuthorizationDomain,
    key_epoch: u64,
    predecessor: Option<String>,
) -> FrostRosterV1 {
    let registration =
        frost_action_registration(domain).unwrap_or_else(|| panic!("registered FROST domain"));
    sign_roster(FrostRosterV1 {
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
        ceremony_transcript_digest: "61".repeat(32),
        predecessor_roster_digest: predecessor,
        valid_from: 100,
        valid_until: 500,
        roster_authority_key_id: "roster-authority.v1".to_string(),
        roster_authority_signature: String::new(),
    })
}

fn ceremony_roster(
    completion: &StoredFrostCeremonyCompletion,
    scope_id: &str,
    predecessor: String,
) -> FrostRosterV1 {
    sign_roster(FrostRosterV1 {
        schema: CHIO_FROST_ROSTER_SCHEMA.to_string(),
        roster_id: String::new(),
        roster_digest: String::new(),
        authority_scope: "treaty".to_string(),
        scope_id: scope_id.to_string(),
        allowed_domains: vec![FrostAuthorizationDomain::SettleCommitment],
        key_epoch: 2,
        threshold: 2,
        participant_count: 3,
        participants: completion
            .verification_shares
            .iter()
            .map(|(participant_id, verification_share)| FrostParticipantV1 {
                participant_id: participant_id.clone(),
                verification_share: verification_share.clone(),
            })
            .collect(),
        group_public_key: completion.group_public_key.clone(),
        suite_id: FROST_ED25519_SHA512_SUITE_ID.to_string(),
        key_origin: FrostRosterKeyOrigin::DistributedDkg,
        ceremony_transcript_digest: completion.transcript_digest.clone(),
        predecessor_roster_digest: Some(predecessor),
        valid_from: 100,
        valid_until: 500,
        roster_authority_key_id: "roster-authority.v1".to_string(),
        roster_authority_signature: String::new(),
    })
}

fn sign_checkpoint(mut checkpoint: FrostEpochCheckpointV1) -> FrostEpochCheckpointV1 {
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

fn initial_checkpoint(roster: &FrostRosterV1, activation_fence: u64) -> FrostEpochCheckpointV1 {
    sign_checkpoint(FrostEpochCheckpointV1 {
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
    })
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

struct FixedEpochAnchor(FrostEpochCheckpointV1);

impl FrostEpochAnchor for FixedEpochAnchor {
    fn resolve_epoch_checkpoint(
        &self,
        scope_id: &str,
    ) -> Result<FrostEpochCheckpointV1, FrostAnchorError> {
        (self.0.scope_id == scope_id)
            .then(|| self.0.clone())
            .ok_or_else(|| FrostAnchorError::Unavailable("epoch is absent".to_string()))
    }
}

struct FixedSlotAnchor(FrostAnchoredAuthorizationSlot);

impl FrostAuthorizationSlotAnchor for FixedSlotAnchor {
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

struct MutableEpochAnchor {
    checkpoint: Mutex<FrostEpochCheckpointV1>,
}

impl MutableEpochAnchor {
    fn new(checkpoint: FrostEpochCheckpointV1) -> Self {
        Self {
            checkpoint: Mutex::new(checkpoint),
        }
    }
}

impl FrostEpochAnchor for MutableEpochAnchor {
    fn resolve_epoch_checkpoint(
        &self,
        scope_id: &str,
    ) -> Result<FrostEpochCheckpointV1, FrostAnchorError> {
        let checkpoint = self
            .checkpoint
            .lock()
            .map_err(|_| FrostAnchorError::Unavailable("anchor lock poisoned".to_string()))?;
        if checkpoint.scope_id != scope_id {
            return Err(FrostAnchorError::Unavailable("epoch is absent".to_string()));
        }
        Ok(checkpoint.clone())
    }
}

impl FrostEpochAnchorWriter for MutableEpochAnchor {
    fn compare_and_swap_epoch(
        &self,
        expected_checkpoint_digest: &str,
        advance: &VerifiedFrostEpochAdvance,
    ) -> Result<FrostEpochCheckpointV1, FrostAnchorError> {
        let mut checkpoint = self
            .checkpoint
            .lock()
            .map_err(|_| FrostAnchorError::Unavailable("anchor lock poisoned".to_string()))?;
        if checkpoint.checkpoint_digest != expected_checkpoint_digest {
            return Err(FrostAnchorError::InvalidResponse(
                "epoch compare-and-swap conflict".to_string(),
            ));
        }
        let target = advance.target_roster();
        let successor = sign_checkpoint(FrostEpochCheckpointV1 {
            schema: CHIO_FROST_EPOCH_CHECKPOINT_SCHEMA.to_string(),
            anchor_id: checkpoint.anchor_id.clone(),
            checkpoint_digest: String::new(),
            scope_id: target.scope_id.clone(),
            checkpoint_sequence: advance.expected_checkpoint_sequence(),
            predecessor_digest: Some(checkpoint.checkpoint_digest.clone()),
            active_roster_id: target.roster_id.clone(),
            active_roster_digest: target.roster_digest.clone(),
            key_epoch: target.key_epoch,
            group_public_key_digest: sha256_hex(
                &hex::decode(&target.group_public_key)
                    .map_err(|_| FrostAnchorError::InvalidResponse("target key hex".to_string()))?,
            ),
            rotation_authorization_digest: Some(
                advance.rotation_authorization_digest().to_string(),
            ),
            activation_fence: advance.activation_fence(),
            clock_high_water: advance.clock_high_water(),
            anchor_key_id: "epoch-authority.v1".to_string(),
            anchor_signature: String::new(),
        });
        *checkpoint = successor.clone();
        Ok(successor)
    }
}

fn complete_target_ceremony(
    authority: &SqliteAuthorityStore,
    frost: &SqliteFrostStore,
    predecessor: &str,
) -> StoredFrostCeremonyCompletion {
    let transport_keys = [
        Keypair::from_seed(&[0x41; 32]),
        Keypair::from_seed(&[0x42; 32]),
        Keypair::from_seed(&[0x43; 32]),
    ];
    let participants = transport_keys
        .iter()
        .enumerate()
        .map(|(index, key)| FrostCeremonyParticipant {
            participant_id: format!("operator-{}", index + 1),
            transport_key_id: format!("operator-{}.dkg.v1", index + 1),
            transport_public_key: key.public_key(),
        })
        .collect::<Vec<_>>();
    let configs = (0..3)
        .map(|index| FrostCeremonyConfig {
            scope_id: "settlement.atlantic.v1".to_string(),
            key_epoch: 2,
            threshold: 2,
            predecessor_roster_digest: Some(predecessor.to_string()),
            participants: participants.clone(),
            local_participant_id: format!("operator-{}", index + 1),
        })
        .collect::<Vec<_>>();
    let custody = FrostCustodyKey::new("custody-generation-rotation", [0xa1; 32])
        .unwrap_or_else(|error| panic!("build custody: {error}"));
    let mut local_rng = ChaCha20Rng::from_seed([0x51; 32]);
    let local_round1 = frost
        .begin_ceremony(
            &configs[0],
            &transport_keys[0],
            &custody,
            &mut local_rng,
            &authority.mutation_fence(),
            1_000,
        )
        .unwrap_or_else(|error| panic!("persist local round one: {error}"));
    let mut round1 = vec![local_round1.package];
    let mut peer_secrets = Vec::new();
    for index in 1..3 {
        let mut rng = ChaCha20Rng::from_seed([0x51 + index as u8; 32]);
        let transition = begin_frost_ceremony(&configs[index], &transport_keys[index], &mut rng)
            .unwrap_or_else(|error| panic!("peer round one: {error}"));
        round1.push(transition.package);
        peer_secrets.push(transition.secret);
    }
    let local_round2 = frost
        .advance_ceremony(
            &configs[0],
            &transport_keys[0],
            &custody,
            &round1,
            &authority.mutation_fence(),
            2_000,
        )
        .unwrap_or_else(|error| panic!("persist local round two: {error}"));
    let mut round2 = local_round2.packages;
    for index in 1..3 {
        let transition = advance_frost_ceremony(
            &configs[index],
            &transport_keys[index],
            peer_secrets.remove(0),
            &round1,
        )
        .unwrap_or_else(|error| panic!("peer round two: {error}"));
        round2.extend(transition.packages);
    }
    frost
        .complete_ceremony(
            &configs[0],
            &custody,
            &round1,
            &round2,
            &authority.mutation_fence(),
            3_000,
        )
        .unwrap_or_else(|error| panic!("complete local ceremony: {error}"))
}

fn verified_rotation_authorization(
    group: &ThresholdGroup,
    roster: &FrostRosterV1,
    checkpoint: &FrostEpochCheckpointV1,
    action: &FrostRosterRotateActionV1,
) -> chio_federation::frost::VerifiedFrostAuthorization {
    let registration = frost_action_registration(FrostAuthorizationDomain::RosterRotate)
        .unwrap_or_else(|| panic!("rotation domain registered"));
    let preimage = FrostActionPreimageV1::RosterRotate(action.clone());
    let mut body = FrostAuthorizationBodyV1 {
        schema: CHIO_FROST_AUTHORIZATION_BODY_SCHEMA.to_string(),
        authorization_id: String::new(),
        domain: FrostAuthorizationDomain::RosterRotate,
        ladder_action_class: registration.ladder_action_class.to_string(),
        ladder_contract_digest: registration
            .ladder_contract_digest()
            .unwrap_or_else(|error| panic!("ladder digest: {error}")),
        quorum_n: 3,
        quorum_m: 5,
        quorum_scope: "treaty".to_string(),
        scope_id: roster.scope_id.clone(),
        resource_id: action.scope_id.clone(),
        resource_version: action.current_key_epoch,
        resource_fence: action.activation_fence,
        action_digest: preimage
            .action_digest()
            .unwrap_or_else(|error| panic!("action digest: {error}")),
        roster_digest: roster.roster_digest.clone(),
        key_epoch: roster.key_epoch,
        issued_at: 150,
        expires_at: 300,
    };
    body.authorization_id = body
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("authorization id: {error}"));
    let signing_bytes = body
        .signing_bytes()
        .unwrap_or_else(|error| panic!("authorization bytes: {error}"));
    let signature = group
        .signing_key
        .sign(ChaCha20Rng::from_seed([0x72; 32]), &signing_bytes);
    let signature_bytes = signature
        .serialize()
        .unwrap_or_else(|error| panic!("serialize signature: {error}"));
    let proof = FrostAuthorizationV1 {
        schema: CHIO_FROST_AUTHORIZATION_SCHEMA.to_string(),
        body,
        suite_id: FROST_ED25519_SHA512_SUITE_ID.to_string(),
        group_signature: hex::encode(&signature_bytes),
    };
    let proof_bytes = proof
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("proof bytes: {error}"));
    let mut slot = FrostAuthorizationSlotCheckpointV1 {
        schema: CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SCHEMA.to_string(),
        anchor_id: "slot-anchor.primary".to_string(),
        checkpoint_digest: String::new(),
        scope_id: proof.body.scope_id.clone(),
        slot_id: frost_authorization_slot_id(&proof.body)
            .unwrap_or_else(|error| panic!("slot id: {error}")),
        slot_version: 2,
        predecessor_digest: Some("ab".repeat(32)),
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
            .unwrap_or_else(|error| panic!("session id: {error}")),
        state: FrostAuthorizationSlotState::Completed,
        aggregate_signature_digest: Some(sha256_hex(&signature_bytes)),
        authorization_blob_digest: Some(sha256_hex(&proof_bytes)),
        availability_receipt: Some("availability.rotation.v1".to_string()),
        clock_high_water: 150,
        anchor_key_id: "slot-authority.v1".to_string(),
        anchor_signature: String::new(),
    };
    slot.anchor_signature = slot_authority()
        .sign(
            &slot
                .signing_bytes()
                .unwrap_or_else(|error| panic!("slot bytes: {error}")),
        )
        .to_hex();
    slot.checkpoint_digest = slot
        .recompute_checkpoint_digest()
        .unwrap_or_else(|error| panic!("slot digest: {error}"));
    let active = resolve_active_roster_for_execution(
        &roster.scope_id,
        &Resolver(roster.clone()),
        &FixedEpochAnchor(checkpoint.clone()),
        &trust_store(),
        200,
    )
    .unwrap_or_else(|error| panic!("resolve governance roster: {error}"));
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
        &FixedEpochAnchor(checkpoint.clone()),
        &FixedSlotAnchor(FrostAnchoredAuthorizationSlot {
            checkpoint: slot,
            authorization_blob: Some(proof_bytes),
        }),
        &trust_store(),
        200,
    )
    .unwrap_or_else(|error| panic!("verify rotation authorization: {error}"))
}

#[test]
fn frost_anchored_rotation_recovers_after_crash_before_local_acknowledgement() {
    let fixture = StoreFixture::new();
    let (authority, frost) = fixture.open();
    let current_group = threshold_group(1, 2, 3);
    let current_roster = group_roster(
        &current_group,
        "settlement.atlantic.v1",
        FrostAuthorizationDomain::SettleCommitment,
        1,
        None,
    );
    let current_checkpoint = initial_checkpoint(&current_roster, 7);
    frost
        .import_active_roster(
            &current_roster,
            &current_checkpoint,
            &trust_store(),
            &authority.mutation_fence(),
            200,
        )
        .unwrap_or_else(|error| panic!("import active roster: {error}"));
    let completion = complete_target_ceremony(&authority, &frost, &current_roster.roster_digest);
    let target_roster = ceremony_roster(
        &completion,
        &current_roster.scope_id,
        current_roster.roster_digest.clone(),
    );
    let governance_group = threshold_group(2, 3, 5);
    let governance_roster = group_roster(
        &governance_group,
        "governance.rotation.atlantic.v1",
        FrostAuthorizationDomain::RosterRotate,
        1,
        None,
    );
    let governance_checkpoint = initial_checkpoint(&governance_roster, 3);
    let burn = FrostSessionBurnSummaryV1::new(current_roster.scope_id.clone(), 1, Vec::new())
        .unwrap_or_else(|error| panic!("build burn summary: {error}"));
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
    let authorization = verified_rotation_authorization(
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
    let staged = frost
        .stage_rotation(advance, &authority.mutation_fence(), 201)
        .unwrap_or_else(|error| panic!("stage rotation: {error}"));
    let anchor = MutableEpochAnchor::new(current_checkpoint);
    anchor
        .compare_and_swap_epoch(
            &staged.advance().predecessor().checkpoint_digest,
            staged.advance(),
        )
        .unwrap_or_else(|error| panic!("advance external epoch: {error}"));
    let rotation_id = staged.rotation_id().to_string();
    drop(staged);
    drop(frost);
    drop(authority);

    let (authority, frost) = fixture.open();
    let recovered = frost
        .recover_rotation(
            "settlement.atlantic.v1",
            &anchor,
            &trust_store(),
            &authority.mutation_fence(),
            202,
        )
        .unwrap_or_else(|error| panic!("recover anchored rotation: {error}"))
        .unwrap_or_else(|| panic!("recovery must find the durable stage"));
    assert_eq!(recovered.rotation_id, rotation_id);
    assert_eq!(recovered.state, FrostRotationState::Active);
    let (active, active_checkpoint) = frost
        .load_active_roster("settlement.atlantic.v1")
        .unwrap_or_else(|error| panic!("load active roster: {error}"))
        .unwrap_or_else(|| panic!("active roster must exist"));
    assert_eq!(active.roster_digest, target_roster.roster_digest);
    assert_eq!(active_checkpoint.key_epoch, 2);
    drop(frost);
    drop(authority);

    let connection = Connection::open(&fixture.database)
        .unwrap_or_else(|error| panic!("open database for tamper check: {error}"));
    let tamper = connection.execute(
        "UPDATE frost_roster_rotations SET anchored_checkpoint_digest = ?1 WHERE rotation_id = ?2",
        ["ff".repeat(32), rotation_id],
    );
    assert!(tamper.is_err(), "terminal anchor digest must be immutable");
}

#[test]
fn frost_unanchored_rotation_is_discarded_after_restart() {
    let fixture = StoreFixture::new();
    let (authority, frost) = fixture.open();
    let current_group = threshold_group(4, 2, 3);
    let current_roster = group_roster(
        &current_group,
        "settlement.atlantic.v1",
        FrostAuthorizationDomain::SettleCommitment,
        1,
        None,
    );
    let current_checkpoint = initial_checkpoint(&current_roster, 7);
    frost
        .import_active_roster(
            &current_roster,
            &current_checkpoint,
            &trust_store(),
            &authority.mutation_fence(),
            200,
        )
        .unwrap_or_else(|error| panic!("import active roster: {error}"));
    let completion = complete_target_ceremony(&authority, &frost, &current_roster.roster_digest);
    let target_roster = ceremony_roster(
        &completion,
        &current_roster.scope_id,
        current_roster.roster_digest.clone(),
    );
    let governance_group = threshold_group(5, 3, 5);
    let governance_roster = group_roster(
        &governance_group,
        "governance.rotation.atlantic.v1",
        FrostAuthorizationDomain::RosterRotate,
        1,
        None,
    );
    let governance_checkpoint = initial_checkpoint(&governance_roster, 3);
    let burn = FrostSessionBurnSummaryV1::new(current_roster.scope_id.clone(), 1, Vec::new())
        .unwrap_or_else(|error| panic!("build burn summary: {error}"));
    let action = FrostRosterRotateActionV1 {
        schema: CHIO_FROST_ROSTER_ROTATE_ACTION_SCHEMA.to_string(),
        predecessor_roster_digest: current_roster.roster_digest.clone(),
        new_roster_digest: target_roster.roster_digest.clone(),
        scope_id: current_roster.scope_id.clone(),
        current_key_epoch: 1,
        new_key_epoch: 2,
        current_checkpoint_sequence: 1,
        current_checkpoint_digest: current_checkpoint.checkpoint_digest.clone(),
        activation_fence: 8,
        old_session_burn_root: burn.burn_root.clone(),
    };
    let authorization = verified_rotation_authorization(
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
    frost
        .stage_rotation(advance, &authority.mutation_fence(), 201)
        .unwrap_or_else(|error| panic!("stage rotation: {error}"));
    let anchor = MutableEpochAnchor::new(current_checkpoint);
    drop(frost);
    drop(authority);

    let (authority, frost) = fixture.open();
    let recovered = frost
        .recover_rotation(
            "settlement.atlantic.v1",
            &anchor,
            &trust_store(),
            &authority.mutation_fence(),
            202,
        )
        .unwrap_or_else(|error| panic!("recover unanchored rotation: {error}"))
        .unwrap_or_else(|| panic!("recovery must find stage"));
    assert_eq!(recovered.state, FrostRotationState::Discarded);
    let (active, _) = frost
        .load_active_roster("settlement.atlantic.v1")
        .unwrap_or_else(|error| panic!("load active roster: {error}"))
        .unwrap_or_else(|| panic!("active roster must exist"));
    assert_eq!(active.roster_digest, current_roster.roster_digest);
}
