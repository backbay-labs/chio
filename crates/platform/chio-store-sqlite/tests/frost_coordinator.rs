use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chio_core::{sha256_hex, Keypair};
use chio_federation::frost::{
    frost_action_registration, frost_authorization_session_id, frost_authorization_slot_id,
    resolve_active_roster_for_execution, verify_frost_authorization_slot_completion,
    ActiveFrostRosterResolver, FrostActionPreimageV1, FrostAnchorError,
    FrostAnchoredAuthorizationSlot, FrostArtifactAuthorityRole, FrostArtifactTrustRoot,
    FrostArtifactTrustStore, FrostAuthorizationBodyV1, FrostAuthorizationDomain,
    FrostAuthorizationSlotAnchor, FrostAuthorizationSlotAnchorWriter,
    FrostAuthorizationSlotCheckpointV1, FrostAuthorizationSlotState, FrostEpochAnchor,
    FrostEpochCheckpointV1, FrostParticipantV1, FrostRosterKeyOrigin, FrostRosterResolutionError,
    FrostRosterV1, FrostSettleCommitmentActionV1, VerifiedActiveFrostRoster,
    VerifiedFrostAuthorizationSlotBind, VerifiedFrostAuthorizationSlotBurn,
    VerifiedFrostAuthorizationSlotCompletion, CHIO_FROST_AUTHORIZATION_BODY_SCHEMA,
    CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SCHEMA, CHIO_FROST_EPOCH_CHECKPOINT_SCHEMA,
    CHIO_FROST_ROSTER_SCHEMA, CHIO_FROST_SETTLE_COMMITMENT_ACTION_SCHEMA,
    FROST_ED25519_SHA512_SUITE_ID,
};
use chio_federation_authority::{
    aggregate_frost_authorization, frost_participant_identifier_bytes,
};
use chio_store_sqlite::{
    FrostCoordinatorCommitment, FrostCoordinatorLease, FrostCoordinatorSessionRequest,
    FrostCoordinatorSessionState, FrostCoordinatorShare, FrostStoreError, SqliteAuthorityStore,
    SqliteFrostStore,
};
use frost_ed25519::keys::{IdentifierList, KeyPackage};
use frost_ed25519::{keys, round1, round2, Identifier, SigningKey, SigningPackage};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tempfile::TempDir;

struct StoreFixture {
    _temp: TempDir,
    database: PathBuf,
    lock_root: PathBuf,
}

fn secure_directory(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("secure private directory: {error}"));
    }
}

fn create_private_directory(path: &Path) {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .unwrap_or_else(|error| panic!("create private directory: {error}"));
    secure_directory(path);
}

impl StoreFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        secure_directory(temp.path());
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        create_private_directory(&lock_root);
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

struct CryptoFixture {
    active: VerifiedActiveFrostRoster,
    epoch: FrostEpochCheckpointV1,
    body: FrostAuthorizationBodyV1,
    key_packages: BTreeMap<String, KeyPackage>,
}

fn roster_authority() -> Keypair {
    Keypair::from_seed(&[0x71; 32])
}

fn epoch_authority() -> Keypair {
    Keypair::from_seed(&[0x72; 32])
}

fn slot_authority() -> Keypair {
    Keypair::from_seed(&[0x73; 32])
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

fn crypto_fixture() -> CryptoFixture {
    let registration = frost_action_registration(FrostAuthorizationDomain::SettleCommitment)
        .unwrap_or_else(|| panic!("settlement registration"));
    let participant_ids = (1..=registration.quorum_m)
        .map(|index| format!("operator-{index}"))
        .collect::<Vec<_>>();
    let identifiers = participant_ids
        .iter()
        .map(|participant_id| {
            Identifier::derive(participant_id.as_bytes())
                .unwrap_or_else(|error| panic!("derive identifier: {error}"))
        })
        .collect::<Vec<_>>();
    let mut rng = ChaCha20Rng::from_seed([0x74; 32]);
    let signing_key = SigningKey::new(&mut rng);
    let (shares, public_keys) = keys::split(
        &signing_key,
        registration.quorum_m,
        registration.quorum_n,
        IdentifierList::Custom(&identifiers),
        &mut rng,
    )
    .unwrap_or_else(|error| panic!("split threshold group: {error}"));
    let key_packages = participant_ids
        .iter()
        .zip(identifiers.iter())
        .map(|(participant_id, identifier)| {
            let share = shares
                .get(identifier)
                .cloned()
                .unwrap_or_else(|| panic!("participant share"));
            let package = KeyPackage::try_from(share)
                .unwrap_or_else(|error| panic!("validate key package: {error}"));
            (participant_id.clone(), package)
        })
        .collect::<BTreeMap<_, _>>();
    let mut roster = FrostRosterV1 {
        schema: CHIO_FROST_ROSTER_SCHEMA.to_string(),
        roster_id: String::new(),
        roster_digest: String::new(),
        authority_scope: registration.quorum_scope.to_string(),
        scope_id: "settlement.atlantic.v1".to_string(),
        allowed_domains: vec![FrostAuthorizationDomain::SettleCommitment],
        key_epoch: 1,
        threshold: registration.quorum_n,
        participant_count: registration.quorum_m,
        participants: participant_ids
            .iter()
            .map(|participant_id| {
                let package = key_packages
                    .get(participant_id)
                    .unwrap_or_else(|| panic!("key package"));
                FrostParticipantV1 {
                    participant_id: participant_id.clone(),
                    verification_share: hex::encode(
                        package
                            .verifying_share()
                            .serialize()
                            .unwrap_or_else(|error| panic!("serialize share: {error}")),
                    ),
                }
            })
            .collect(),
        group_public_key: hex::encode(
            public_keys
                .verifying_key()
                .serialize()
                .unwrap_or_else(|error| panic!("serialize group key: {error}")),
        ),
        suite_id: FROST_ED25519_SHA512_SUITE_ID.to_string(),
        key_origin: FrostRosterKeyOrigin::DistributedDkg,
        ceremony_transcript_digest: "75".repeat(32),
        predecessor_roster_digest: None,
        valid_from: 100,
        valid_until: 20_000,
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
    let epoch = signed_epoch(&roster);
    let body = authorization_body(&roster, "settlement-operation-1", 7);
    let active = resolve_active_roster_for_execution(
        &roster.scope_id,
        &Resolver(roster.clone()),
        &FixedEpoch(epoch.clone()),
        &trust_store(),
        1_000,
    )
    .unwrap_or_else(|error| panic!("resolve active roster: {error}"));
    CryptoFixture {
        active,
        epoch,
        body,
        key_packages,
    }
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
        .unwrap_or_else(|| panic!("settlement registration"));
    let action = FrostActionPreimageV1::SettleCommitment(FrostSettleCommitmentActionV1 {
        schema: CHIO_FROST_SETTLE_COMMITMENT_ACTION_SCHEMA.to_string(),
        settlement_body_digest: "76".repeat(32),
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
        expires_at: 20_000,
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
    state: Mutex<SlotState>,
}

struct SlotState {
    slot: Option<FrostAnchoredAuthorizationSlot>,
    fail_after_completion: bool,
}

impl MutableSlotAnchor {
    fn new(body: FrostAuthorizationBodyV1) -> Self {
        Self {
            body,
            state: Mutex::new(SlotState {
                slot: None,
                fail_after_completion: false,
            }),
        }
    }

    fn fail_after_next_completion(&self) {
        self.state
            .lock()
            .unwrap_or_else(|error| panic!("slot lock: {error}"))
            .fail_after_completion = true;
    }

    fn current_state(&self) -> FrostAuthorizationSlotState {
        self.state
            .lock()
            .unwrap_or_else(|error| panic!("slot lock: {error}"))
            .slot
            .as_ref()
            .unwrap_or_else(|| panic!("slot exists"))
            .checkpoint
            .state
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
}

impl FrostAuthorizationSlotAnchor for MutableSlotAnchor {
    fn resolve_authorization_slot(
        &self,
        scope_id: &str,
        slot_id: &str,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError> {
        self.state
            .lock()
            .map_err(|_| FrostAnchorError::Unavailable("slot lock poisoned".to_string()))?
            .slot
            .as_ref()
            .filter(|slot| {
                slot.checkpoint.scope_id == scope_id && slot.checkpoint.slot_id == slot_id
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
        let mut state = self
            .state
            .lock()
            .map_err(|_| FrostAnchorError::Unavailable("slot lock poisoned".to_string()))?;
        if let Some(slot) = state.slot.as_ref() {
            if slot.checkpoint.state == FrostAuthorizationSlotState::Bound
                && slot.checkpoint.slot_id == bind.request().slot_id()
            {
                return Ok(slot.clone());
            }
            return Err(FrostAnchorError::InvalidResponse(
                "slot is already terminal".to_string(),
            ));
        }
        let slot = FrostAnchoredAuthorizationSlot {
            checkpoint: self.bound_checkpoint(bind.request().clock_high_water()),
            authorization_blob: None,
        };
        state.slot = Some(slot.clone());
        Ok(slot)
    }

    fn compare_and_swap_complete(
        &self,
        completion: &VerifiedFrostAuthorizationSlotCompletion,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| FrostAnchorError::Unavailable("slot lock poisoned".to_string()))?;
        let current = state
            .slot
            .as_ref()
            .ok_or_else(|| FrostAnchorError::Unavailable("slot absent".to_string()))?;
        let request = completion.request();
        if current.checkpoint.state == FrostAuthorizationSlotState::Completed {
            return Ok(current.clone());
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
        state.slot = Some(anchored.clone());
        if state.fail_after_completion {
            state.fail_after_completion = false;
            return Err(FrostAnchorError::Unavailable(
                "completion response was lost".to_string(),
            ));
        }
        Ok(anchored)
    }

    fn compare_and_swap_burn(
        &self,
        burn: &VerifiedFrostAuthorizationSlotBurn,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| FrostAnchorError::Unavailable("slot lock poisoned".to_string()))?;
        let current = state
            .slot
            .as_ref()
            .ok_or_else(|| FrostAnchorError::Unavailable("slot absent".to_string()))?;
        if current.checkpoint.state == FrostAuthorizationSlotState::Burned {
            return Ok(current.clone());
        }
        if current.checkpoint.state != FrostAuthorizationSlotState::Bound
            || current.checkpoint.checkpoint_digest
                != burn.request().expected_bound_checkpoint_digest()
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
        state.slot = Some(anchored.clone());
        Ok(anchored)
    }
}

fn request<'a>(
    crypto: &'a CryptoFixture,
    body: &'a FrostAuthorizationBodyV1,
    epoch: &'a FixedEpoch,
    slot: &'a MutableSlotAnchor,
    trust: &'a FrostArtifactTrustStore,
) -> FrostCoordinatorSessionRequest<'a> {
    FrostCoordinatorSessionRequest {
        body,
        active_roster: &crypto.active,
        epoch_anchor: epoch,
        slot_anchor: slot,
        artifact_trust: trust,
        coordinator_id: "coordinator-1",
    }
}

fn commitments(
    crypto: &CryptoFixture,
) -> (
    Vec<FrostCoordinatorCommitment>,
    BTreeMap<String, round1::SigningNonces>,
) {
    let mut rng = ChaCha20Rng::from_seed([0x77; 32]);
    let mut commitments = Vec::new();
    let mut nonces = BTreeMap::new();
    for (participant_id, key_package) in &crypto.key_packages {
        let (participant_nonces, commitment) =
            round1::commit(key_package.signing_share(), &mut rng);
        commitments.push(FrostCoordinatorCommitment {
            participant_id: participant_id.clone(),
            signer_identifier: frost_participant_identifier_bytes(participant_id)
                .unwrap_or_else(|error| panic!("participant identifier: {error}")),
            commitment_bytes: commitment
                .serialize()
                .unwrap_or_else(|error| panic!("serialize commitment: {error}")),
        });
        nonces.insert(participant_id.clone(), participant_nonces);
    }
    (commitments, nonces)
}

fn signature_shares(
    crypto: &CryptoFixture,
    package: &[u8],
    participant_ids: &[String],
    nonces: &BTreeMap<String, round1::SigningNonces>,
) -> Vec<FrostCoordinatorShare> {
    let package = SigningPackage::deserialize(package)
        .unwrap_or_else(|error| panic!("decode signing package: {error}"));
    participant_ids
        .iter()
        .map(|participant_id| {
            let share = round2::sign(
                &package,
                nonces
                    .get(participant_id)
                    .unwrap_or_else(|| panic!("participant nonces")),
                crypto
                    .key_packages
                    .get(participant_id)
                    .unwrap_or_else(|| panic!("participant key package")),
            )
            .unwrap_or_else(|error| panic!("create signature share: {error}"));
            FrostCoordinatorShare {
                participant_id: participant_id.clone(),
                share_bytes: share.serialize(),
            }
        })
        .collect()
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
    let connection = rusqlite::Connection::open(database)
        .unwrap_or_else(|error| panic!("open coordinator database for snapshot: {error}"));
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap_or_else(|error| panic!("checkpoint coordinator snapshot: {error}"));
    drop(connection);
    fs::copy(database, target).unwrap_or_else(|error| panic!("copy coordinator snapshot: {error}"));
}

fn restore_database_in_place(database: &Path, snapshot: &Path) {
    let mut input =
        File::open(snapshot).unwrap_or_else(|error| panic!("open coordinator snapshot: {error}"));
    let mut output = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(database)
        .unwrap_or_else(|error| panic!("open coordinator database for restore: {error}"));
    std::io::copy(&mut input, &mut output)
        .unwrap_or_else(|error| panic!("restore coordinator snapshot: {error}"));
    output
        .sync_all()
        .unwrap_or_else(|error| panic!("sync coordinator restore: {error}"));
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(PathBuf::from(format!("{}{suffix}", database.display())));
    }
}

#[test]
fn frost_coordinator_recovers_every_persisted_transition_and_exact_terminal_proof() {
    let stores = StoreFixture::new();
    let crypto = crypto_fixture();
    let epoch = FixedEpoch(crypto.epoch.clone());
    let trust = trust_store();
    let slot = MutableSlotAnchor::new(crypto.body.clone());
    let (mut authority, mut frost) = stores.open();
    let mut lease = frost
        .claim_coordinator_session(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            "worker-1",
            "lease-1",
            100,
            &authority.mutation_fence(),
            1_000,
        )
        .unwrap_or_else(|error| panic!("claim coordinator: {error}"));
    assert_eq!(lease.owner_epoch, 1);
    assert!(frost
        .claim_coordinator_session(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            "worker-2",
            "lease-2",
            100,
            &authority.mutation_fence(),
            1_050,
        )
        .is_err());
    lease = frost
        .claim_coordinator_session(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            "worker-2",
            "lease-2",
            5_000,
            &authority.mutation_fence(),
            1_100,
        )
        .unwrap_or_else(|error| panic!("take over coordinator: {error}"));
    assert_eq!(lease.owner_epoch, 2);
    (authority, frost) = reopen(&stores, authority, frost);

    let (commitments, nonces) = commitments(&crypto);
    for commitment in &commitments {
        frost
            .submit_coordinator_commitment(
                &request(&crypto, &crypto.body, &epoch, &slot, &trust),
                &lease,
                commitment,
                &authority.mutation_fence(),
                1_200,
            )
            .unwrap_or_else(|error| panic!("submit commitment: {error}"));
    }
    let after_commitments = frost
        .submit_coordinator_commitment(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            &lease,
            &commitments[0],
            &authority.mutation_fence(),
            1_200,
        )
        .unwrap_or_else(|error| panic!("retry commitment: {error}"));
    assert_eq!(
        after_commitments.commitment_count,
        crypto.key_packages.len()
    );
    (authority, frost) = reopen(&stores, authority, frost);

    let package = frost
        .build_coordinator_signing_package(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            &lease,
            &authority.mutation_fence(),
            1_300,
        )
        .unwrap_or_else(|error| panic!("build package: {error}"));
    let retried_package = frost
        .build_coordinator_signing_package(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            &lease,
            &authority.mutation_fence(),
            1_300,
        )
        .unwrap_or_else(|error| panic!("retry package: {error}"));
    assert_eq!(retried_package, package);
    (authority, frost) = reopen(&stores, authority, frost);

    let shares = signature_shares(
        &crypto,
        &package.signing_package_bytes,
        &package.participant_ids,
        &nonces,
    );
    for share in &shares {
        frost
            .submit_coordinator_share(
                &request(&crypto, &crypto.body, &epoch, &slot, &trust),
                &lease,
                share,
                &authority.mutation_fence(),
                1_400,
            )
            .unwrap_or_else(|error| panic!("submit share: {error}"));
    }
    (authority, frost) = reopen(&stores, authority, frost);

    slot.fail_after_next_completion();
    assert!(frost
        .complete_coordinator_session(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            &lease,
            "availability.coordinator.v1",
            &authority.mutation_fence(),
            1_500,
        )
        .is_err());
    assert_eq!(slot.current_state(), FrostAuthorizationSlotState::Completed);
    (authority, frost) = reopen(&stores, authority, frost);
    let proof = frost
        .complete_coordinator_session(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            &lease,
            "availability.coordinator.v1",
            &authority.mutation_fence(),
            1_501,
        )
        .unwrap_or_else(|error| panic!("recover completed authorization: {error}"));
    assert_eq!(proof.body, crypto.body);
    let session = frost
        .load_coordinator_session(&lease.session_id)
        .unwrap_or_else(|error| panic!("load coordinator: {error}"))
        .unwrap_or_else(|| panic!("coordinator exists"));
    assert_eq!(session.state, FrostCoordinatorSessionState::Completed);
}

#[test]
fn frost_coordinator_burns_changed_messages_and_rejects_late_shares() {
    let stores = StoreFixture::new();
    let crypto = crypto_fixture();
    let epoch = FixedEpoch(crypto.epoch.clone());
    let trust = trust_store();
    let slot = MutableSlotAnchor::new(crypto.body.clone());
    let (authority, frost) = stores.open();
    let lease = frost
        .claim_coordinator_session(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            "worker-1",
            "lease-1",
            5_000,
            &authority.mutation_fence(),
            1_000,
        )
        .unwrap_or_else(|error| panic!("claim coordinator: {error}"));
    let (commitments, _) = commitments(&crypto);
    frost
        .submit_coordinator_commitment(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            &lease,
            &commitments[0],
            &authority.mutation_fence(),
            1_100,
        )
        .unwrap_or_else(|error| panic!("submit commitment: {error}"));

    let mut changed_body = crypto.body.clone();
    changed_body.action_digest = "ff".repeat(32);
    changed_body.authorization_id = changed_body
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("changed authorization id: {error}"));
    assert!(frost
        .claim_coordinator_session(
            &request(&crypto, &changed_body, &epoch, &slot, &trust),
            "worker-1",
            "lease-1",
            5_000,
            &authority.mutation_fence(),
            1_200,
        )
        .is_err());
    assert_eq!(slot.current_state(), FrostAuthorizationSlotState::Burned);
    let session = frost
        .load_coordinator_session(&lease.session_id)
        .unwrap_or_else(|error| panic!("load coordinator: {error}"))
        .unwrap_or_else(|| panic!("coordinator exists"));
    assert_eq!(session.state, FrostCoordinatorSessionState::Burned);
    assert!(frost
        .submit_coordinator_share(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            &lease,
            &FrostCoordinatorShare {
                participant_id: "operator-1".to_string(),
                share_bytes: vec![1],
            },
            &authority.mutation_fence(),
            1_300,
        )
        .is_err());
    let unchanged = frost
        .load_coordinator_session(&lease.session_id)
        .unwrap_or_else(|error| panic!("reload coordinator: {error}"))
        .unwrap_or_else(|| panic!("coordinator exists"));
    assert_eq!(unchanged.row_version, session.row_version);
}

#[test]
fn frost_coordinator_cancellation_publishes_external_tombstone_before_fanout() {
    let stores = StoreFixture::new();
    let crypto = crypto_fixture();
    let epoch = FixedEpoch(crypto.epoch.clone());
    let trust = trust_store();
    let slot = MutableSlotAnchor::new(crypto.body.clone());
    let (authority, frost) = stores.open();
    let lease: FrostCoordinatorLease = frost
        .claim_coordinator_session(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            "worker-1",
            "lease-1",
            5_000,
            &authority.mutation_fence(),
            1_000,
        )
        .unwrap_or_else(|error| panic!("claim coordinator: {error}"));
    let (commitments, _) = commitments(&crypto);
    frost
        .submit_coordinator_commitment(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            &lease,
            &commitments[0],
            &authority.mutation_fence(),
            1_100,
        )
        .unwrap_or_else(|error| panic!("submit commitment: {error}"));
    let cancellation = frost
        .cancel_coordinator_session(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            &lease,
            "operator request canceled",
            &authority.mutation_fence(),
            1_200,
        )
        .unwrap_or_else(|error| panic!("cancel coordinator: {error}"));
    assert_eq!(slot.current_state(), FrostAuthorizationSlotState::Burned);
    assert_eq!(
        cancellation.session.state,
        FrostCoordinatorSessionState::Burned
    );
    assert_eq!(
        cancellation.participant_ids,
        vec![commitments[0].participant_id.clone()]
    );
}

#[test]
fn frost_preaggregate_snapshot_recovers_exact_external_completion_without_resigning() {
    let stores = StoreFixture::new();
    let snapshot = stores._temp.path().join("coordinator-package-ready.db");
    let crypto = crypto_fixture();
    let epoch = FixedEpoch(crypto.epoch.clone());
    let trust = trust_store();
    let slot = MutableSlotAnchor::new(crypto.body.clone());
    let (authority, frost) = stores.open();
    let lease = frost
        .claim_coordinator_session(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            "worker-1",
            "lease-1",
            5_000,
            &authority.mutation_fence(),
            1_000,
        )
        .unwrap_or_else(|error| panic!("claim coordinator: {error}"));
    let (commitments, nonces) = commitments(&crypto);
    for commitment in &commitments {
        frost
            .submit_coordinator_commitment(
                &request(&crypto, &crypto.body, &epoch, &slot, &trust),
                &lease,
                commitment,
                &authority.mutation_fence(),
                1_100,
            )
            .unwrap_or_else(|error| panic!("submit commitment: {error}"));
    }
    let package = frost
        .build_coordinator_signing_package(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            &lease,
            &authority.mutation_fence(),
            1_200,
        )
        .unwrap_or_else(|error| panic!("build package: {error}"));
    let shares = signature_shares(
        &crypto,
        &package.signing_package_bytes,
        &package.participant_ids,
        &nonces,
    );
    for share in &shares {
        let record = frost
            .submit_coordinator_share(
                &request(&crypto, &crypto.body, &epoch, &slot, &trust),
                &lease,
                share,
                &authority.mutation_fence(),
                1_300,
            )
            .unwrap_or_else(|error| panic!("submit share: {error}"));
        assert_eq!(record.state, FrostCoordinatorSessionState::PackageReady);
    }
    drop(frost);
    drop(authority);
    database_snapshot(&stores.database, &snapshot);

    let shares_by_participant = shares
        .iter()
        .map(|share| (share.participant_id.clone(), share.share_bytes.clone()))
        .collect::<BTreeMap<_, _>>();
    let proof = aggregate_frost_authorization(
        &crypto.body,
        crypto.active.roster(),
        &package.signing_package_bytes,
        &shares_by_participant,
    )
    .unwrap_or_else(|error| panic!("aggregate external authorization: {error}"));
    let bound = slot
        .resolve_authorization_slot(
            &crypto.body.scope_id,
            &frost_authorization_slot_id(&crypto.body)
                .unwrap_or_else(|error| panic!("authorization slot id: {error}")),
        )
        .unwrap_or_else(|error| panic!("resolve bound slot: {error}"));
    let completion = verify_frost_authorization_slot_completion(
        &bound.checkpoint,
        &proof,
        &crypto.active,
        &epoch,
        &trust,
        "availability.coordinator.v1",
        1_400,
    )
    .unwrap_or_else(|error| panic!("verify external completion: {error}"));
    slot.compare_and_swap_complete(&completion)
        .unwrap_or_else(|error| panic!("complete external slot: {error}"));

    restore_database_in_place(&stores.database, &snapshot);
    let (authority, frost) = stores.open();
    frost
        .claim_coordinator_session(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            "worker-1",
            "lease-1",
            5_000,
            &authority.mutation_fence(),
            1_401,
        )
        .unwrap_or_else(|error| panic!("reconcile completed coordinator: {error}"));
    let recovered = frost
        .complete_coordinator_session(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            &lease,
            "availability.coordinator.v1",
            &authority.mutation_fence(),
            1_402,
        )
        .unwrap_or_else(|error| panic!("recover exact external authorization: {error}"));
    assert_eq!(recovered, proof);
    let record = frost
        .load_coordinator_session(&lease.session_id)
        .unwrap_or_else(|error| panic!("load recovered coordinator: {error}"))
        .unwrap_or_else(|| panic!("recovered coordinator exists"));
    assert_eq!(record.state, FrostCoordinatorSessionState::Completed);
}

#[test]
fn frost_stale_sqlite_serving_owner_cannot_advance_coordinator() {
    let stores = StoreFixture::new();
    let crypto = crypto_fixture();
    let epoch = FixedEpoch(crypto.epoch.clone());
    let trust = trust_store();
    let slot = MutableSlotAnchor::new(crypto.body.clone());
    let (authority, frost) = stores.open();
    let fence = authority.mutation_fence();
    let lease = frost
        .claim_coordinator_session(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            "worker-1",
            "lease-1",
            5_000,
            &fence,
            1_000,
        )
        .unwrap_or_else(|error| panic!("claim coordinator: {error}"));
    let connection = rusqlite::Connection::open(&stores.database)
        .unwrap_or_else(|error| panic!("open replacement serving owner: {error}"));
    connection
        .execute(
            "UPDATE chio_serving_owner SET owner_epoch = ?1, lease_id = 'replacement-lease' WHERE singleton = 1",
            [i64::try_from(fence.owner_epoch + 1)
                .unwrap_or_else(|error| panic!("replacement owner epoch: {error}"))],
        )
        .unwrap_or_else(|error| panic!("advance serving owner: {error}"));
    let (commitments, _) = commitments(&crypto);
    assert!(matches!(
        frost.submit_coordinator_commitment(
            &request(&crypto, &crypto.body, &epoch, &slot, &trust),
            &lease,
            &commitments[0],
            &fence,
            1_100,
        ),
        Err(FrostStoreError::Fenced)
    ));
    assert_eq!(slot.current_state(), FrostAuthorizationSlotState::Bound);
}
