use std::collections::BTreeMap;
use std::fs;
use std::fs::{File, OpenOptions};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chio_core::{sha256_hex, Keypair};
use chio_federation::frost::{
    frost_action_registration, frost_authorization_session_id, frost_authorization_slot_id,
    resolve_active_roster_for_execution, verify_frost_authorization_slot_burn,
    verify_frost_authorization_slot_completion, ActiveFrostRosterResolver, FrostActionPreimageV1,
    FrostAnchorError, FrostAnchoredAuthorizationSlot, FrostArtifactAuthorityRole,
    FrostArtifactTrustRoot, FrostArtifactTrustStore, FrostAuthorizationBodyV1,
    FrostAuthorizationDomain, FrostAuthorizationSlotAnchor, FrostAuthorizationSlotAnchorWriter,
    FrostAuthorizationSlotCheckpointV1, FrostAuthorizationSlotState, FrostAuthorizationV1,
    FrostEpochAnchor, FrostEpochCheckpointV1, FrostParticipantV1, FrostRosterKeyOrigin,
    FrostRosterResolutionError, FrostRosterV1, FrostSettleCommitmentActionV1,
    VerifiedFrostAuthorizationSlotBind, VerifiedFrostAuthorizationSlotBurn,
    VerifiedFrostAuthorizationSlotCompletion, CHIO_FROST_AUTHORIZATION_BODY_SCHEMA,
    CHIO_FROST_AUTHORIZATION_SCHEMA, CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SCHEMA,
    CHIO_FROST_EPOCH_CHECKPOINT_SCHEMA, CHIO_FROST_ROSTER_SCHEMA,
    CHIO_FROST_SETTLE_COMMITMENT_ACTION_SCHEMA, FROST_ED25519_SHA512_SUITE_ID,
};
use chio_federation_authority::{
    advance_frost_ceremony, begin_frost_ceremony, complete_frost_ceremony,
    create_frost_signature_share, prepare_frost_signer, FrostCeremonyConfig,
    FrostCeremonyParticipant, FrostCeremonySecret,
};
use chio_store_sqlite::{
    FrostCustodyKey, FrostSignerSessionRequest, FrostSignerSessionState, SqliteAuthorityStore,
    SqliteFrostStore, StoredFrostCeremonyCompletion,
};
use frost_ed25519::keys::{IdentifierList, KeyPackage, PublicKeyPackage};
use frost_ed25519::{keys, round1, round2, Identifier, SigningKey, SigningPackage};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use rusqlite::Connection;
use tempfile::TempDir;

struct StoreFixture {
    _temp: TempDir,
    database: PathBuf,
    lock_root: PathBuf,
}

struct CompletedCeremony {
    stored: StoredFrostCeremonyCompletion,
    peer_key_package: FrostCeremonySecret,
    public_key_package: Vec<u8>,
}

impl Deref for CompletedCeremony {
    type Target = StoredFrostCeremonyCompletion;

    fn deref(&self) -> &Self::Target {
        &self.stored
    }
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

fn roster_authority() -> Keypair {
    Keypair::from_seed(&[0x91; 32])
}

fn epoch_authority() -> Keypair {
    Keypair::from_seed(&[0x92; 32])
}

fn slot_authority() -> Keypair {
    Keypair::from_seed(&[0x93; 32])
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

fn custody() -> FrostCustodyKey {
    FrostCustodyKey::new("signer-custody-generation", [0xb1; 32])
        .unwrap_or_else(|error| panic!("build custody: {error}"))
}

fn complete_ceremony(
    authority: &SqliteAuthorityStore,
    frost: &SqliteFrostStore,
) -> CompletedCeremony {
    let transport_keys = [
        Keypair::from_seed(&[0xa1; 32]),
        Keypair::from_seed(&[0xa2; 32]),
        Keypair::from_seed(&[0xa3; 32]),
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
            key_epoch: 1,
            threshold: 2,
            predecessor_roster_digest: None,
            participants: participants.clone(),
            local_participant_id: format!("operator-{}", index + 1),
        })
        .collect::<Vec<_>>();
    let mut local_rng = ChaCha20Rng::from_seed([0xc1; 32]);
    let local_round1 = frost
        .begin_ceremony(
            &configs[0],
            &transport_keys[0],
            &custody(),
            &mut local_rng,
            &authority.mutation_fence(),
            1_000,
        )
        .unwrap_or_else(|error| panic!("local round one: {error}"));
    let mut round1 = vec![local_round1.package];
    let mut peer_secrets = Vec::new();
    for index in 1..3 {
        let mut rng = ChaCha20Rng::from_seed([0xc1 + index as u8; 32]);
        let transition = begin_frost_ceremony(&configs[index], &transport_keys[index], &mut rng)
            .unwrap_or_else(|error| panic!("peer round one: {error}"));
        round1.push(transition.package);
        peer_secrets.push(transition.secret);
    }
    let local_round2 = frost
        .advance_ceremony(
            &configs[0],
            &transport_keys[0],
            &custody(),
            &round1,
            &authority.mutation_fence(),
            2_000,
        )
        .unwrap_or_else(|error| panic!("local round two: {error}"));
    let mut round2 = local_round2.packages;
    let mut peer_round2_secrets = Vec::new();
    for index in 1..3 {
        let transition = advance_frost_ceremony(
            &configs[index],
            &transport_keys[index],
            peer_secrets.remove(0),
            &round1,
        )
        .unwrap_or_else(|error| panic!("peer round two: {error}"));
        peer_round2_secrets.push(transition.secret);
        round2.extend(transition.packages);
    }
    let stored = frost
        .complete_ceremony(
            &configs[0],
            &custody(),
            &round1,
            &round2,
            &authority.mutation_fence(),
            3_000,
        )
        .unwrap_or_else(|error| panic!("complete ceremony: {error}"));
    let peer =
        complete_frost_ceremony(&configs[1], peer_round2_secrets.remove(0), &round1, &round2)
            .unwrap_or_else(|error| panic!("complete peer ceremony: {error}"));
    CompletedCeremony {
        stored,
        peer_key_package: peer.key_package,
        public_key_package: peer.public_key_package,
    }
}

fn signed_roster(completion: &StoredFrostCeremonyCompletion) -> FrostRosterV1 {
    let registration = frost_action_registration(FrostAuthorizationDomain::SettleCommitment)
        .unwrap_or_else(|| panic!("settlement FROST registration"));
    let mut roster = FrostRosterV1 {
        schema: CHIO_FROST_ROSTER_SCHEMA.to_string(),
        roster_id: String::new(),
        roster_digest: String::new(),
        authority_scope: registration.quorum_scope.to_string(),
        scope_id: "settlement.atlantic.v1".to_string(),
        allowed_domains: vec![FrostAuthorizationDomain::SettleCommitment],
        key_epoch: 1,
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
        predecessor_roster_digest: None,
        valid_from: 100,
        valid_until: 10_000,
        roster_authority_key_id: "roster-authority.v1".to_string(),
        roster_authority_signature: String::new(),
    };
    roster.roster_id = roster
        .recompute_roster_id()
        .unwrap_or_else(|error| panic!("roster id: {error}"));
    roster.roster_authority_signature = roster_authority()
        .sign(
            &roster
                .signing_bytes()
                .unwrap_or_else(|error| panic!("roster bytes: {error}")),
        )
        .to_hex();
    roster.roster_digest = roster
        .recompute_roster_digest()
        .unwrap_or_else(|error| panic!("roster digest: {error}"));
    roster
}

fn signed_epoch(roster: &FrostRosterV1) -> FrostEpochCheckpointV1 {
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
        activation_fence: 1,
        clock_high_water: 100,
        anchor_key_id: "epoch-authority.v1".to_string(),
        anchor_signature: String::new(),
    };
    checkpoint.anchor_signature = epoch_authority()
        .sign(
            &checkpoint
                .signing_bytes()
                .unwrap_or_else(|error| panic!("epoch bytes: {error}")),
        )
        .to_hex();
    checkpoint.checkpoint_digest = checkpoint
        .recompute_checkpoint_digest()
        .unwrap_or_else(|error| panic!("epoch digest: {error}"));
    checkpoint
}

fn authorization_body(
    roster: &FrostRosterV1,
    operation: &str,
    fence: u64,
) -> FrostAuthorizationBodyV1 {
    let registration = frost_action_registration(FrostAuthorizationDomain::SettleCommitment)
        .unwrap_or_else(|| panic!("settlement FROST registration"));
    let action = FrostActionPreimageV1::SettleCommitment(FrostSettleCommitmentActionV1 {
        schema: CHIO_FROST_SETTLE_COMMITMENT_ACTION_SCHEMA.to_string(),
        settlement_body_digest: "41".repeat(32),
        payer_id: "payer-1".to_string(),
        payee_id: "payee-1".to_string(),
        amount_base_units: "100".to_string(),
        asset_id: "usd.test".to_string(),
        operation_id: operation.to_string(),
        rail_idempotency_key: format!("rail-{operation}"),
        resource_version: 1,
        resource_fence: fence,
    });
    let mut body = FrostAuthorizationBodyV1 {
        schema: CHIO_FROST_AUTHORIZATION_BODY_SCHEMA.to_string(),
        authorization_id: String::new(),
        domain: FrostAuthorizationDomain::SettleCommitment,
        ladder_action_class: registration.ladder_action_class.to_string(),
        ladder_contract_digest: registration
            .ladder_contract_digest()
            .unwrap_or_else(|error| panic!("ladder digest: {error}")),
        quorum_n: registration.quorum_n,
        quorum_m: registration.quorum_m,
        quorum_scope: registration.quorum_scope.to_string(),
        scope_id: roster.scope_id.clone(),
        resource_id: operation.to_string(),
        resource_version: 1,
        resource_fence: fence,
        action_digest: action
            .action_digest()
            .unwrap_or_else(|error| panic!("action digest: {error}")),
        roster_digest: roster.roster_digest.clone(),
        key_epoch: roster.key_epoch,
        issued_at: 100,
        expires_at: 10_000,
    };
    body.authorization_id = body
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("authorization id: {error}"));
    body
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

struct FixedEpoch(FrostEpochCheckpointV1);

impl FrostEpochAnchor for FixedEpoch {
    fn resolve_epoch_checkpoint(
        &self,
        scope_id: &str,
    ) -> Result<FrostEpochCheckpointV1, FrostAnchorError> {
        (self.0.scope_id == scope_id)
            .then(|| self.0.clone())
            .ok_or_else(|| FrostAnchorError::Unavailable("epoch absent".to_string()))
    }
}

struct MutableSlotAnchor {
    body: FrostAuthorizationBodyV1,
    slot: Mutex<Option<FrostAnchoredAuthorizationSlot>>,
}

impl MutableSlotAnchor {
    fn new(body: FrostAuthorizationBodyV1) -> Self {
        Self {
            body,
            slot: Mutex::new(None),
        }
    }

    fn sign_checkpoint(
        &self,
        mut checkpoint: FrostAuthorizationSlotCheckpointV1,
    ) -> FrostAuthorizationSlotCheckpointV1 {
        checkpoint.anchor_signature = slot_authority()
            .sign(
                &checkpoint
                    .signing_bytes()
                    .unwrap_or_else(|error| panic!("slot bytes: {error}")),
            )
            .to_hex();
        checkpoint.checkpoint_digest = checkpoint
            .recompute_checkpoint_digest()
            .unwrap_or_else(|error| panic!("slot digest: {error}"));
        checkpoint
    }

    fn bound_checkpoint(&self, now: u64) -> FrostAuthorizationSlotCheckpointV1 {
        let signing_bytes = self
            .body
            .signing_bytes()
            .unwrap_or_else(|error| panic!("authorization bytes: {error}"));
        self.sign_checkpoint(FrostAuthorizationSlotCheckpointV1 {
            schema: CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SCHEMA.to_string(),
            anchor_id: "slot-anchor.primary".to_string(),
            checkpoint_digest: String::new(),
            scope_id: self.body.scope_id.clone(),
            slot_id: frost_authorization_slot_id(&self.body)
                .unwrap_or_else(|error| panic!("slot id: {error}")),
            slot_version: 1,
            predecessor_digest: None,
            domain: self.body.domain,
            ladder_action_class: self.body.ladder_action_class.clone(),
            resource_id: self.body.resource_id.clone(),
            resource_version: self.body.resource_version,
            resource_fence: self.body.resource_fence,
            authorization_id: self.body.authorization_id.clone(),
            signing_message_digest: sha256_hex(&signing_bytes),
            action_digest: self.body.action_digest.clone(),
            roster_digest: self.body.roster_digest.clone(),
            key_epoch: self.body.key_epoch,
            session_id: frost_authorization_session_id(&self.body)
                .unwrap_or_else(|error| panic!("session id: {error}")),
            state: FrostAuthorizationSlotState::Bound,
            aggregate_signature_digest: None,
            authorization_blob_digest: None,
            availability_receipt: None,
            clock_high_water: now,
            anchor_key_id: "slot-authority.v1".to_string(),
            anchor_signature: String::new(),
        })
    }

    fn replace_bound_checkpoint(&self, now: u64) {
        let mut slot = self
            .slot
            .lock()
            .unwrap_or_else(|error| panic!("slot lock: {error}"));
        let current = slot.as_ref().unwrap_or_else(|| panic!("bound slot exists"));
        assert_eq!(current.checkpoint.state, FrostAuthorizationSlotState::Bound);
        let replacement = self.sign_checkpoint(FrostAuthorizationSlotCheckpointV1 {
            anchor_id: "slot-anchor.replacement".to_string(),
            checkpoint_digest: String::new(),
            clock_high_water: now,
            anchor_signature: String::new(),
            ..current.checkpoint.clone()
        });
        *slot = Some(FrostAnchoredAuthorizationSlot {
            checkpoint: replacement,
            authorization_blob: None,
        });
    }
}

impl FrostAuthorizationSlotAnchor for MutableSlotAnchor {
    fn resolve_authorization_slot(
        &self,
        scope_id: &str,
        slot_id: &str,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError> {
        let slot = self
            .slot
            .lock()
            .map_err(|_| FrostAnchorError::Unavailable("slot lock poisoned".to_string()))?;
        slot.as_ref()
            .filter(|anchored| {
                anchored.checkpoint.scope_id == scope_id && anchored.checkpoint.slot_id == slot_id
            })
            .cloned()
            .ok_or_else(|| FrostAnchorError::Unavailable("slot absent".to_string()))
    }
}

impl FrostAuthorizationSlotAnchorWriter for MutableSlotAnchor {
    fn compare_and_swap_bind(
        &self,
        bind: &VerifiedFrostAuthorizationSlotBind,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError> {
        let mut slot = self
            .slot
            .lock()
            .map_err(|_| FrostAnchorError::Unavailable("slot lock poisoned".to_string()))?;
        if let Some(anchored) = slot.as_ref() {
            if anchored.checkpoint.state == FrostAuthorizationSlotState::Bound
                && anchored.checkpoint.slot_id == bind.request().slot_id()
            {
                return Ok(anchored.clone());
            }
            return Err(FrostAnchorError::InvalidResponse(
                "slot is already terminal".to_string(),
            ));
        }
        let anchored = FrostAnchoredAuthorizationSlot {
            checkpoint: self.bound_checkpoint(bind.request().clock_high_water()),
            authorization_blob: None,
        };
        *slot = Some(anchored.clone());
        Ok(anchored)
    }

    fn compare_and_swap_complete(
        &self,
        completion: &VerifiedFrostAuthorizationSlotCompletion,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError> {
        let mut slot = self
            .slot
            .lock()
            .map_err(|_| FrostAnchorError::Unavailable("slot lock poisoned".to_string()))?;
        let current = slot
            .as_ref()
            .ok_or_else(|| FrostAnchorError::Unavailable("slot absent".to_string()))?;
        let request = completion.request();
        if current.checkpoint.state == FrostAuthorizationSlotState::Completed {
            if current.checkpoint.predecessor_digest.as_deref()
                == Some(request.expected_bound_checkpoint_digest())
                && current.checkpoint.aggregate_signature_digest.as_deref()
                    == Some(request.aggregate_signature_digest())
                && current.checkpoint.authorization_blob_digest.as_deref()
                    == Some(request.authorization_blob_digest())
                && current.checkpoint.availability_receipt.as_deref()
                    == Some(request.availability_receipt())
                && current.authorization_blob.as_deref() == Some(request.authorization_blob())
            {
                return Ok(current.clone());
            }
            return Err(FrostAnchorError::InvalidResponse(
                "completion differs from the terminal slot".to_string(),
            ));
        }
        if current.checkpoint.state != FrostAuthorizationSlotState::Bound
            || current.checkpoint.checkpoint_digest != request.expected_bound_checkpoint_digest()
        {
            return Err(FrostAnchorError::InvalidResponse(
                "completion compare-and-swap conflict".to_string(),
            ));
        }
        let completed = self.sign_checkpoint(FrostAuthorizationSlotCheckpointV1 {
            checkpoint_digest: String::new(),
            slot_version: 2,
            predecessor_digest: Some(current.checkpoint.checkpoint_digest.clone()),
            state: FrostAuthorizationSlotState::Completed,
            aggregate_signature_digest: Some(request.aggregate_signature_digest().to_string()),
            authorization_blob_digest: Some(request.authorization_blob_digest().to_string()),
            availability_receipt: Some(request.availability_receipt().to_string()),
            clock_high_water: request.clock_high_water(),
            anchor_signature: String::new(),
            ..current.checkpoint.clone()
        });
        let anchored = FrostAnchoredAuthorizationSlot {
            checkpoint: completed,
            authorization_blob: Some(request.authorization_blob().to_vec()),
        };
        *slot = Some(anchored.clone());
        Ok(anchored)
    }

    fn compare_and_swap_burn(
        &self,
        burn: &VerifiedFrostAuthorizationSlotBurn,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError> {
        let mut slot = self
            .slot
            .lock()
            .map_err(|_| FrostAnchorError::Unavailable("slot lock poisoned".to_string()))?;
        let current = slot
            .as_ref()
            .ok_or_else(|| FrostAnchorError::Unavailable("slot absent".to_string()))?;
        if current.checkpoint.state == FrostAuthorizationSlotState::Burned {
            return Ok(current.clone());
        }
        if current.checkpoint.checkpoint_digest != burn.request().expected_bound_checkpoint_digest()
        {
            return Err(FrostAnchorError::InvalidResponse(
                "burn compare-and-swap conflict".to_string(),
            ));
        }
        let burned = self.sign_checkpoint(FrostAuthorizationSlotCheckpointV1 {
            checkpoint_digest: String::new(),
            slot_version: 2,
            predecessor_digest: Some(current.checkpoint.checkpoint_digest.clone()),
            state: FrostAuthorizationSlotState::Burned,
            clock_high_water: burn.request().clock_high_water(),
            anchor_signature: String::new(),
            ..current.checkpoint.clone()
        });
        let anchored = FrostAnchoredAuthorizationSlot {
            checkpoint: burned,
            authorization_blob: None,
        };
        *slot = Some(anchored.clone());
        Ok(anchored)
    }
}

fn signing_package(commitment: &[u8], signer_identifier: &[u8], message: &[u8]) -> Vec<u8> {
    let local_id = Identifier::deserialize(signer_identifier)
        .unwrap_or_else(|error| panic!("decode signer id: {error}"));
    let local_commitment = round1::SigningCommitments::deserialize(commitment)
        .unwrap_or_else(|error| panic!("decode commitment: {error}"));
    let mut rng = ChaCha20Rng::from_seed([0xd1; 32]);
    let signing_key = SigningKey::new(&mut rng);
    let (shares, _) = keys::split(&signing_key, 3, 2, IdentifierList::Default, &mut rng)
        .unwrap_or_else(|error| panic!("split peer key: {error}"));
    let peer = shares
        .into_values()
        .filter_map(|share| KeyPackage::try_from(share).ok())
        .find(|package| package.identifier() != &local_id)
        .unwrap_or_else(|| panic!("distinct peer identifier"));
    let (_, peer_commitment) = round1::commit(peer.signing_share(), &mut rng);
    let mut commitments = BTreeMap::new();
    commitments.insert(local_id, local_commitment);
    commitments.insert(*peer.identifier(), peer_commitment);
    SigningPackage::new(commitments, message)
        .serialize()
        .unwrap_or_else(|error| panic!("serialize signing package: {error}"))
}

fn reopen(
    fixture: &StoreFixture,
    authority: SqliteAuthorityStore,
    frost: SqliteFrostStore,
) -> (SqliteAuthorityStore, SqliteFrostStore) {
    drop(frost);
    drop(authority);
    fixture.open()
}

fn database_snapshot(database: &Path, target: &Path) {
    let connection = Connection::open(database)
        .unwrap_or_else(|error| panic!("open database for snapshot: {error}"));
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap_or_else(|error| panic!("checkpoint snapshot: {error}"));
    drop(connection);
    fs::copy(database, target).unwrap_or_else(|error| panic!("copy snapshot: {error}"));
}

fn restore_database_in_place(database: &Path, snapshot: &Path) {
    let mut input =
        File::open(snapshot).unwrap_or_else(|error| panic!("open signer snapshot: {error}"));
    let mut output = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(database)
        .unwrap_or_else(|error| panic!("open signer database for restore: {error}"));
    std::io::copy(&mut input, &mut output)
        .unwrap_or_else(|error| panic!("restore signer snapshot: {error}"));
    output
        .sync_all()
        .unwrap_or_else(|error| panic!("sync signer restore: {error}"));
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(PathBuf::from(format!("{}{suffix}", database.display())));
    }
}

#[test]
fn frost_signer_persists_exact_outputs_across_every_restart_and_zeroizes_nonce() {
    let fixture = StoreFixture::new();
    let (mut authority, mut frost) = fixture.open();
    let completion = complete_ceremony(&authority, &frost);
    let roster = signed_roster(&completion);
    let epoch = signed_epoch(&roster);
    let active = resolve_active_roster_for_execution(
        &roster.scope_id,
        &Resolver(roster.clone()),
        &FixedEpoch(epoch.clone()),
        &trust_store(),
        4_000,
    )
    .unwrap_or_else(|error| panic!("resolve active roster: {error}"));
    let body = authorization_body(&roster, "settlement-operation-1", 7);
    let slot = MutableSlotAnchor::new(body.clone());

    let prepared = {
        let request = FrostSignerSessionRequest {
            body: &body,
            active_roster: &active,
            epoch_anchor: &FixedEpoch(epoch.clone()),
            slot_anchor: &slot,
            artifact_trust: &trust_store(),
            ceremony_id: &completion.ceremony_id,
            participant_id: "operator-1",
            coordinator_id: "coordinator-1",
        };
        let mut rng = ChaCha20Rng::from_seed([0xe1; 32]);
        frost
            .prepare_signer_session(
                &request,
                &custody(),
                &mut rng,
                &authority.mutation_fence(),
                4_001,
            )
            .unwrap_or_else(|error| panic!("prepare signer: {error}"))
    };
    assert_eq!(prepared.state, FrostSignerSessionState::Prepared);
    (authority, frost) = reopen(&fixture, authority, frost);

    let commitment =
        {
            let request = FrostSignerSessionRequest {
                body: &body,
                active_roster: &active,
                epoch_anchor: &FixedEpoch(epoch.clone()),
                slot_anchor: &slot,
                artifact_trust: &trust_store(),
                ceremony_id: &completion.ceremony_id,
                participant_id: "operator-1",
                coordinator_id: "coordinator-1",
            };
            let wrong_custody = FrostCustodyKey::new("other-generation", [0xb1; 32])
                .unwrap_or_else(|error| panic!("wrong custody: {error}"));
            assert!(frost
                .publish_signer_commitment(
                    &request,
                    &wrong_custody,
                    &authority.mutation_fence(),
                    4_002,
                )
                .is_err());
            frost
                .publish_signer_commitment(&request, &custody(), &authority.mutation_fence(), 4_002)
                .unwrap_or_else(|error| panic!("publish commitment: {error}"))
        };
    (authority, frost) = reopen(&fixture, authority, frost);
    let package = signing_package(
        &commitment.commitment_bytes,
        &commitment.signer_identifier,
        &body
            .signing_bytes()
            .unwrap_or_else(|error| panic!("message bytes: {error}")),
    );
    let share = {
        let request = FrostSignerSessionRequest {
            body: &body,
            active_roster: &active,
            epoch_anchor: &FixedEpoch(epoch.clone()),
            slot_anchor: &slot,
            artifact_trust: &trust_store(),
            ceremony_id: &completion.ceremony_id,
            participant_id: "operator-1",
            coordinator_id: "coordinator-1",
        };
        let share_ready = frost
            .prepare_signer_share(
                &request,
                &package,
                &custody(),
                &authority.mutation_fence(),
                4_003,
            )
            .unwrap_or_else(|error| panic!("prepare share: {error}"));
        assert_eq!(share_ready.state, FrostSignerSessionState::ShareReady);
        let wrong_custody = FrostCustodyKey::new("other-generation", [0xb1; 32])
            .unwrap_or_else(|error| panic!("wrong custody: {error}"));
        assert!(frost
            .publish_signer_share(&request, &wrong_custody, &authority.mutation_fence(), 4_003,)
            .is_err());
        frost
            .publish_signer_share(&request, &custody(), &authority.mutation_fence(), 4_003)
            .unwrap_or_else(|error| panic!("publish share: {error}"))
    };
    (authority, frost) = reopen(&fixture, authority, frost);
    {
        let request = FrostSignerSessionRequest {
            body: &body,
            active_roster: &active,
            epoch_anchor: &FixedEpoch(epoch.clone()),
            slot_anchor: &slot,
            artifact_trust: &trust_store(),
            ceremony_id: &completion.ceremony_id,
            participant_id: "operator-1",
            coordinator_id: "coordinator-1",
        };
        let replayed = frost
            .prepare_signer_share(
                &request,
                &package,
                &custody(),
                &authority.mutation_fence(),
                4_004,
            )
            .unwrap_or_else(|error| panic!("replay share preparation: {error}"));
        assert_eq!(replayed.state, FrostSignerSessionState::ShareReady);
        let replayed_share = frost
            .publish_signer_share(&request, &custody(), &authority.mutation_fence(), 4_004)
            .unwrap_or_else(|error| panic!("replay share: {error}"));
        assert_eq!(replayed_share.share_bytes, share.share_bytes);
        let completed = frost
            .complete_signer_session(&request, &custody(), &authority.mutation_fence(), 4_005)
            .unwrap_or_else(|error| panic!("complete signer: {error}"));
        assert_eq!(completed.state, FrostSignerSessionState::Completed);
    }
    (authority, frost) = reopen(&fixture, authority, frost);
    let loaded = frost
        .load_signer_session(&prepared.session_id, "operator-1")
        .unwrap_or_else(|error| panic!("load signer: {error}"))
        .unwrap_or_else(|| panic!("completed signer exists"));
    assert_eq!(loaded.state, FrostSignerSessionState::Completed);
    drop(frost);
    drop(authority);
    let connection = Connection::open(&fixture.database)
        .unwrap_or_else(|error| panic!("open signer database: {error}"));
    let (nonce_is_null, share_bytes): (bool, Vec<u8>) = connection
        .query_row(
            "SELECT nonce_ciphertext IS NULL, signature_share FROM frost_signer_sessions WHERE session_id = ?1",
            [&prepared.session_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or_else(|error| panic!("inspect signer tombstone: {error}"));
    assert!(nonce_is_null);
    assert_eq!(share_bytes, share.share_bytes);
}

#[test]
fn frost_conflicting_signing_package_burns_external_slot_and_local_nonce() {
    let fixture = StoreFixture::new();
    let (authority, frost) = fixture.open();
    let completion = complete_ceremony(&authority, &frost);
    let roster = signed_roster(&completion);
    let epoch = signed_epoch(&roster);
    let active = resolve_active_roster_for_execution(
        &roster.scope_id,
        &Resolver(roster.clone()),
        &FixedEpoch(epoch.clone()),
        &trust_store(),
        4_000,
    )
    .unwrap_or_else(|error| panic!("resolve active roster: {error}"));
    let body = authorization_body(&roster, "settlement-operation-2", 8);
    let slot = MutableSlotAnchor::new(body.clone());
    let request = FrostSignerSessionRequest {
        body: &body,
        active_roster: &active,
        epoch_anchor: &FixedEpoch(epoch),
        slot_anchor: &slot,
        artifact_trust: &trust_store(),
        ceremony_id: &completion.ceremony_id,
        participant_id: "operator-1",
        coordinator_id: "coordinator-1",
    };
    let mut rng = ChaCha20Rng::from_seed([0xe2; 32]);
    let prepared = frost
        .prepare_signer_session(
            &request,
            &custody(),
            &mut rng,
            &authority.mutation_fence(),
            4_001,
        )
        .unwrap_or_else(|error| panic!("prepare signer: {error}"));
    let commitment = frost
        .publish_signer_commitment(&request, &custody(), &authority.mutation_fence(), 4_002)
        .unwrap_or_else(|error| panic!("publish commitment: {error}"));
    let conflicting_package = signing_package(
        &commitment.commitment_bytes,
        &commitment.signer_identifier,
        b"conflicting message",
    );
    assert!(frost
        .prepare_signer_share(
            &request,
            &conflicting_package,
            &custody(),
            &authority.mutation_fence(),
            4_003,
        )
        .is_err());
    let burned = frost
        .load_signer_session(&prepared.session_id, "operator-1")
        .unwrap_or_else(|error| panic!("load burned signer: {error}"))
        .unwrap_or_else(|| panic!("burned signer exists"));
    assert_eq!(burned.state, FrostSignerSessionState::Burned);
    assert_eq!(
        slot.resolve_authorization_slot(&body.scope_id, &prepared.authorization_slot_id)
            .unwrap_or_else(|error| panic!("load burned slot: {error}"))
            .checkpoint
            .state,
        FrostAuthorizationSlotState::Burned
    );
}

#[test]
fn frost_restart_reconciles_external_burn_before_releasing_a_live_commitment() {
    let fixture = StoreFixture::new();
    let (authority, frost) = fixture.open();
    let completion = complete_ceremony(&authority, &frost);
    let roster = signed_roster(&completion);
    let epoch = signed_epoch(&roster);
    let epoch_anchor = FixedEpoch(epoch.clone());
    let trust = trust_store();
    let active = resolve_active_roster_for_execution(
        &roster.scope_id,
        &Resolver(roster.clone()),
        &epoch_anchor,
        &trust,
        4_000,
    )
    .unwrap_or_else(|error| panic!("resolve active roster: {error}"));
    let body = authorization_body(&roster, "settlement-operation-3", 9);
    let slot = MutableSlotAnchor::new(body.clone());
    let request = FrostSignerSessionRequest {
        body: &body,
        active_roster: &active,
        epoch_anchor: &epoch_anchor,
        slot_anchor: &slot,
        artifact_trust: &trust,
        ceremony_id: &completion.ceremony_id,
        participant_id: "operator-1",
        coordinator_id: "coordinator-1",
    };
    let mut rng = ChaCha20Rng::from_seed([0xe3; 32]);
    let prepared = frost
        .prepare_signer_session(
            &request,
            &custody(),
            &mut rng,
            &authority.mutation_fence(),
            4_001,
        )
        .unwrap_or_else(|error| panic!("prepare signer: {error}"));
    frost
        .publish_signer_commitment(&request, &custody(), &authority.mutation_fence(), 4_002)
        .unwrap_or_else(|error| panic!("publish commitment: {error}"));

    let bound = slot
        .resolve_authorization_slot(&body.scope_id, &prepared.authorization_slot_id)
        .unwrap_or_else(|error| panic!("resolve bound slot: {error}"));
    let burn = verify_frost_authorization_slot_burn(&bound.checkpoint, &trust, 4_003)
        .unwrap_or_else(|error| panic!("verify burn: {error}"));
    slot.compare_and_swap_burn(&burn)
        .unwrap_or_else(|error| panic!("burn external slot: {error}"));

    let (authority, frost) = reopen(&fixture, authority, frost);
    assert!(frost
        .publish_signer_commitment(&request, &custody(), &authority.mutation_fence(), 4_004)
        .is_err());
    let reconciled = frost
        .load_signer_session(&prepared.session_id, "operator-1")
        .unwrap_or_else(|error| panic!("load reconciled signer: {error}"))
        .unwrap_or_else(|| panic!("reconciled signer exists"));
    assert_eq!(reconciled.state, FrostSignerSessionState::Burned);

    drop(frost);
    drop(authority);
    let connection = Connection::open(&fixture.database)
        .unwrap_or_else(|error| panic!("open signer database: {error}"));
    let nonce_is_null: bool = connection
        .query_row(
            "SELECT nonce_ciphertext IS NULL FROM frost_signer_sessions WHERE session_id = ?1",
            [&prepared.session_id],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("inspect reconciled signer: {error}"));
    assert!(nonce_is_null);
}

#[test]
fn frost_signer_rejects_different_valid_bound_checkpoint_for_same_message() {
    let fixture = StoreFixture::new();
    let (authority, frost) = fixture.open();
    let completion = complete_ceremony(&authority, &frost);
    let roster = signed_roster(&completion);
    let epoch = signed_epoch(&roster);
    let epoch_anchor = FixedEpoch(epoch);
    let trust = trust_store();
    let active = resolve_active_roster_for_execution(
        &roster.scope_id,
        &Resolver(roster.clone()),
        &epoch_anchor,
        &trust,
        4_000,
    )
    .unwrap_or_else(|error| panic!("resolve active roster: {error}"));
    let body = authorization_body(&roster, "settlement-operation-4", 10);
    let slot = MutableSlotAnchor::new(body.clone());
    let request = FrostSignerSessionRequest {
        body: &body,
        active_roster: &active,
        epoch_anchor: &epoch_anchor,
        slot_anchor: &slot,
        artifact_trust: &trust,
        ceremony_id: &completion.ceremony_id,
        participant_id: "operator-1",
        coordinator_id: "coordinator-1",
    };
    let mut rng = ChaCha20Rng::from_seed([0xe4; 32]);
    let prepared = frost
        .prepare_signer_session(
            &request,
            &custody(),
            &mut rng,
            &authority.mutation_fence(),
            4_001,
        )
        .unwrap_or_else(|error| panic!("prepare signer: {error}"));

    slot.replace_bound_checkpoint(4_002);
    assert!(frost
        .publish_signer_commitment(&request, &custody(), &authority.mutation_fence(), 4_002)
        .is_err());
    let retained = frost
        .load_signer_session(&prepared.session_id, "operator-1")
        .unwrap_or_else(|error| panic!("load signer: {error}"))
        .unwrap_or_else(|| panic!("signer exists"));
    assert_eq!(retained.state, FrostSignerSessionState::Prepared);
}

#[test]
fn frost_restart_after_external_completion_replays_share_and_erases_nonce() {
    let fixture = StoreFixture::new();
    let (authority, frost) = fixture.open();
    let completion = complete_ceremony(&authority, &frost);
    let roster = signed_roster(&completion);
    let epoch = signed_epoch(&roster);
    let epoch_anchor = FixedEpoch(epoch);
    let trust = trust_store();
    let active = resolve_active_roster_for_execution(
        &roster.scope_id,
        &Resolver(roster.clone()),
        &epoch_anchor,
        &trust,
        4_000,
    )
    .unwrap_or_else(|error| panic!("resolve active roster: {error}"));
    let body = authorization_body(&roster, "settlement-operation-5", 11);
    let slot = MutableSlotAnchor::new(body.clone());
    let request = FrostSignerSessionRequest {
        body: &body,
        active_roster: &active,
        epoch_anchor: &epoch_anchor,
        slot_anchor: &slot,
        artifact_trust: &trust,
        ceremony_id: &completion.ceremony_id,
        participant_id: "operator-1",
        coordinator_id: "coordinator-1",
    };
    let mut local_rng = ChaCha20Rng::from_seed([0xe5; 32]);
    let prepared = frost
        .prepare_signer_session(
            &request,
            &custody(),
            &mut local_rng,
            &authority.mutation_fence(),
            4_001,
        )
        .unwrap_or_else(|error| panic!("prepare signer: {error}"));
    let commitment = frost
        .publish_signer_commitment(&request, &custody(), &authority.mutation_fence(), 4_002)
        .unwrap_or_else(|error| panic!("publish commitment: {error}"));

    let message = body
        .signing_bytes()
        .unwrap_or_else(|error| panic!("authorization bytes: {error}"));
    let local_identifier = Identifier::deserialize(&commitment.signer_identifier)
        .unwrap_or_else(|error| panic!("decode local identifier: {error}"));
    let local_commitment = round1::SigningCommitments::deserialize(&commitment.commitment_bytes)
        .unwrap_or_else(|error| panic!("decode local commitment: {error}"));
    let mut peer_rng = ChaCha20Rng::from_seed([0xe6; 32]);
    let peer_preparation = prepare_frost_signer(&completion.peer_key_package, &mut peer_rng)
        .unwrap_or_else(|error| panic!("prepare peer signer: {error}"));
    let peer_identifier = Identifier::deserialize(peer_preparation.signer_identifier_bytes())
        .unwrap_or_else(|error| panic!("decode peer identifier: {error}"));
    let peer_commitment =
        round1::SigningCommitments::deserialize(peer_preparation.commitment_bytes())
            .unwrap_or_else(|error| panic!("decode peer commitment: {error}"));
    let mut commitments = BTreeMap::new();
    commitments.insert(local_identifier, local_commitment);
    commitments.insert(peer_identifier, peer_commitment);
    let signing_package = SigningPackage::new(commitments, &message);
    let signing_package_bytes = signing_package
        .serialize()
        .unwrap_or_else(|error| panic!("serialize signing package: {error}"));
    frost
        .prepare_signer_share(
            &request,
            &signing_package_bytes,
            &custody(),
            &authority.mutation_fence(),
            4_003,
        )
        .unwrap_or_else(|error| panic!("prepare local share: {error}"));
    let local_share = frost
        .publish_signer_share(&request, &custody(), &authority.mutation_fence(), 4_003)
        .unwrap_or_else(|error| panic!("publish local share: {error}"));
    let peer_commitment_bytes = peer_preparation.commitment_bytes().to_vec();
    let peer_share = create_frost_signature_share(
        &completion.peer_key_package,
        peer_preparation.into_nonce_secret(),
        &signing_package_bytes,
        &sha256_hex(&message),
        &peer_commitment_bytes,
    )
    .unwrap_or_else(|error| panic!("create peer share: {error}"));
    let mut shares = BTreeMap::new();
    shares.insert(
        local_identifier,
        round2::SignatureShare::deserialize(&local_share.share_bytes)
            .unwrap_or_else(|error| panic!("decode local share: {error}")),
    );
    shares.insert(
        peer_identifier,
        round2::SignatureShare::deserialize(peer_share.share_bytes())
            .unwrap_or_else(|error| panic!("decode peer share: {error}")),
    );
    let public_key_package = PublicKeyPackage::deserialize(&completion.public_key_package)
        .unwrap_or_else(|error| panic!("decode public key package: {error}"));
    let signature = frost_ed25519::aggregate(&signing_package, &shares, &public_key_package)
        .unwrap_or_else(|error| panic!("aggregate signature: {error}"));
    let signature_bytes = signature
        .serialize()
        .unwrap_or_else(|error| panic!("serialize signature: {error}"));
    let proof = FrostAuthorizationV1 {
        schema: CHIO_FROST_AUTHORIZATION_SCHEMA.to_string(),
        body: body.clone(),
        suite_id: FROST_ED25519_SHA512_SUITE_ID.to_string(),
        group_signature: hex::encode(signature_bytes),
    };
    let bound = slot
        .resolve_authorization_slot(&body.scope_id, &prepared.authorization_slot_id)
        .unwrap_or_else(|error| panic!("resolve bound slot: {error}"));
    let terminal = verify_frost_authorization_slot_completion(
        &bound.checkpoint,
        &proof,
        &active,
        &epoch_anchor,
        &trust,
        "availability.signer-test.v1",
        4_004,
    )
    .unwrap_or_else(|error| panic!("verify slot completion: {error}"));
    slot.compare_and_swap_complete(&terminal)
        .unwrap_or_else(|error| panic!("complete external slot: {error}"));

    let (authority, frost) = reopen(&fixture, authority, frost);
    let replayed = frost
        .publish_signer_share(&request, &custody(), &authority.mutation_fence(), 4_005)
        .unwrap_or_else(|error| panic!("replay completed share: {error}"));
    assert_eq!(replayed.share_bytes, local_share.share_bytes);
    let reconciled = frost
        .load_signer_session(&prepared.session_id, "operator-1")
        .unwrap_or_else(|error| panic!("load completed signer: {error}"))
        .unwrap_or_else(|| panic!("completed signer exists"));
    assert_eq!(reconciled.state, FrostSignerSessionState::Completed);

    drop(frost);
    drop(authority);
    let connection = Connection::open(&fixture.database)
        .unwrap_or_else(|error| panic!("open signer database: {error}"));
    let nonce_is_null: bool = connection
        .query_row(
            "SELECT nonce_ciphertext IS NULL FROM frost_signer_sessions WHERE session_id = ?1",
            [&prepared.session_id],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("inspect completed signer: {error}"));
    assert!(nonce_is_null);
}

#[test]
fn frost_restored_pre_transition_signer_snapshot_is_rejected_by_global_anchor() {
    let fixture = StoreFixture::new();
    let snapshot = fixture._temp.path().join("bound-signer.db");
    let (authority, frost) = fixture.open();
    let completion = complete_ceremony(&authority, &frost);
    let roster = signed_roster(&completion);
    let epoch = signed_epoch(&roster);
    let epoch_anchor = FixedEpoch(epoch);
    let trust = trust_store();
    let active = resolve_active_roster_for_execution(
        &roster.scope_id,
        &Resolver(roster.clone()),
        &epoch_anchor,
        &trust,
        4_000,
    )
    .unwrap_or_else(|error| panic!("resolve active roster: {error}"));
    let body = authorization_body(&roster, "settlement-operation-6", 12);
    let slot = MutableSlotAnchor::new(body.clone());
    let request = FrostSignerSessionRequest {
        body: &body,
        active_roster: &active,
        epoch_anchor: &epoch_anchor,
        slot_anchor: &slot,
        artifact_trust: &trust,
        ceremony_id: &completion.ceremony_id,
        participant_id: "operator-1",
        coordinator_id: "coordinator-1",
    };
    let mut rng = ChaCha20Rng::from_seed([0xe7; 32]);
    frost
        .prepare_signer_session(
            &request,
            &custody(),
            &mut rng,
            &authority.mutation_fence(),
            4_001,
        )
        .unwrap_or_else(|error| panic!("prepare signer: {error}"));
    drop(frost);
    drop(authority);
    database_snapshot(&fixture.database, &snapshot);

    let (authority, frost) = fixture.open();
    frost
        .publish_signer_commitment(&request, &custody(), &authority.mutation_fence(), 4_002)
        .unwrap_or_else(|error| panic!("publish commitment: {error}"));
    drop(frost);
    drop(authority);

    restore_database_in_place(&fixture.database, &snapshot);
    assert!(SqliteAuthorityStore::open_serving(&fixture.database, &fixture.lock_root).is_err());
}
