use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chio_core::capability::scope::MonetaryAmount;
use chio_core::{is_supported_signed_artifact_schema, sha256_hex, Keypair};
use chio_credit::clearing::{
    verify_clearing_round_finalization_burn, verify_clearing_round_finalization_frost,
    ClearingRoundFinalizationBodyV1, CLEARING_ROUND_FINALIZATION_SCHEMA,
};
use chio_federation::frost::{
    frost_action_registration, frost_authorization_session_id, frost_authorization_slot_id,
    registered_frost_actions, resolve_active_roster_for_execution,
    verify_burned_frost_authorization_slot, verify_for_execution, verify_historical_evidence,
    ActiveFrostRosterResolver, ExpectedFrostAuthorization, FrostActionPreimageV1, FrostAnchorError,
    FrostAnchoredAuthorizationSlot, FrostArtifactAuthorityRole, FrostArtifactTrustRoot,
    FrostArtifactTrustStore, FrostAuthorizationBodyV1, FrostAuthorizationDomain,
    FrostAuthorizationSlotAnchor, FrostAuthorizationSlotCheckpointV1, FrostAuthorizationSlotState,
    FrostAuthorizationV1, FrostChannelCloseActionV1, FrostCredentialsPassportRevokeActionV1,
    FrostEpochAnchor, FrostEpochCheckpointV1, FrostGovernanceCaseEnforceSanctionActionV1,
    FrostHistoricalRosterResolver, FrostParticipantV1, FrostPouncerRevokeCredentialActionV1,
    FrostRosterKeyOrigin, FrostRosterResolutionError, FrostRosterRotateActionV1, FrostRosterV1,
    FrostSettleCommitmentActionV1, VerifiedBurnedFrostAuthorizationSlot,
    VerifiedFrostAuthorization, CHIO_FROST_AUTHORIZATION_BODY_SCHEMA,
    CHIO_FROST_AUTHORIZATION_SCHEMA, CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SCHEMA,
    CHIO_FROST_CHANNEL_CLOSE_ACTION_SCHEMA, CHIO_FROST_CLEARING_ROUND_FINALIZE_ACTION_SCHEMA,
    CHIO_FROST_CREDENTIALS_PASSPORT_REVOKE_ACTION_SCHEMA, CHIO_FROST_EPOCH_CHECKPOINT_SCHEMA,
    CHIO_FROST_GOVERNANCE_CASE_ENFORCE_SANCTION_ACTION_SCHEMA,
    CHIO_FROST_POUNCER_REVOKE_CREDENTIAL_ACTION_SCHEMA, CHIO_FROST_ROSTER_ROTATE_ACTION_SCHEMA,
    CHIO_FROST_ROSTER_SCHEMA, CHIO_FROST_SETTLE_COMMITMENT_ACTION_SCHEMA,
    FROST_ED25519_SHA512_SUITE_ID,
};
use frost_ed25519::keys::{IdentifierList, KeyPackage};
use frost_ed25519::{keys, Identifier, SigningKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn load_json(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

#[test]
fn frost_registered_signed_artifacts_are_runtime_supported() {
    let registry = load_json(&repo_root().join("spec/schemas/registry.json"));
    let rows: BTreeMap<&str, (&str, &str)> = registry["artifacts"]
        .as_array()
        .unwrap_or_else(|| panic!("registry must carry an artifacts array"))
        .iter()
        .filter_map(|row| {
            let schema = row["schema"].as_str()?;
            schema.starts_with("chio.frost.").then(|| {
                (
                    schema,
                    (
                        row["artifactKind"]
                            .as_str()
                            .unwrap_or_else(|| panic!("FROST row must carry artifactKind")),
                        row["schemaFile"]
                            .as_str()
                            .unwrap_or_else(|| panic!("FROST row must carry schemaFile")),
                    ),
                )
            })
        })
        .collect();
    let expected = BTreeMap::from([
        (
            "chio.frost.authorization-slot-checkpoint.v1",
            (
                "frost_authorization_slot_checkpoint",
                "spec/schemas/chio-frost/v1/authorization-slot-checkpoint.schema.json",
            ),
        ),
        (
            "chio.frost.authorization.v1",
            (
                "frost_authorization",
                "spec/schemas/chio-frost/v1/authorization.schema.json",
            ),
        ),
        (
            "chio.frost.epoch-checkpoint.v1",
            (
                "frost_epoch_checkpoint",
                "spec/schemas/chio-frost/v1/epoch-checkpoint.schema.json",
            ),
        ),
        (
            "chio.frost.roster.v1",
            (
                "frost_roster",
                "spec/schemas/chio-frost/v1/roster.schema.json",
            ),
        ),
    ]);
    assert_eq!(rows, expected);
    for schema in rows.keys() {
        assert!(is_supported_signed_artifact_schema(schema));
    }
}

#[test]
fn frost_roster_schema_and_pinned_signature_are_separate_gates() {
    let family = repo_root().join("spec/schemas/chio-frost/v1");
    let schema = load_json(&family.join("roster.schema.json"));
    let positive = load_json(&family.join("fixtures/roster.positive.json"));
    let tampered = load_json(&family.join("fixtures/roster.tampered-signature.json"));
    let validator = jsonschema::validator_for(&schema)
        .unwrap_or_else(|error| panic!("compile FROST roster schema: {error}"));
    assert!(validator.is_valid(&positive));
    assert!(validator.is_valid(&tampered));

    let trust = FrostArtifactTrustStore::new([FrostArtifactTrustRoot {
        role: FrostArtifactAuthorityRole::Roster,
        key_id: "authority.treaty.v1".to_string(),
        public_key: Keypair::from_seed(&[0x42; 32]).public_key(),
    }])
    .unwrap_or_else(|error| panic!("build pinned FROST trust store: {error}"));
    let positive: FrostRosterV1 = serde_json::from_value(positive)
        .unwrap_or_else(|error| panic!("decode positive roster: {error}"));
    let tampered: FrostRosterV1 = serde_json::from_value(tampered)
        .unwrap_or_else(|error| panic!("decode tampered roster: {error}"));
    trust
        .verify_roster(&positive)
        .unwrap_or_else(|error| panic!("verify pinned roster: {error}"));
    assert!(trust.verify_roster(&tampered).is_err());
}

fn roster_authority() -> Keypair {
    Keypair::from_seed(&[0xa1; 32])
}

fn epoch_authority() -> Keypair {
    Keypair::from_seed(&[0xa2; 32])
}

fn slot_authority() -> Keypair {
    Keypair::from_seed(&[0xa3; 32])
}

fn artifact_trust() -> FrostArtifactTrustStore {
    FrostArtifactTrustStore::new([
        FrostArtifactTrustRoot {
            role: FrostArtifactAuthorityRole::Roster,
            key_id: "frost-roster-authority.v1".to_string(),
            public_key: roster_authority().public_key(),
        },
        FrostArtifactTrustRoot {
            role: FrostArtifactAuthorityRole::EpochAnchor,
            key_id: "frost-epoch-anchor.v1".to_string(),
            public_key: epoch_authority().public_key(),
        },
        FrostArtifactTrustRoot {
            role: FrostArtifactAuthorityRole::AuthorizationSlotAnchor,
            key_id: "frost-slot-anchor.v1".to_string(),
            public_key: slot_authority().public_key(),
        },
    ])
    .unwrap_or_else(|error| panic!("build FROST artifact trust: {error}"))
}

fn digest(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

#[derive(Clone)]
struct ActionCase {
    domain: FrostAuthorizationDomain,
    ladder_action_class: &'static str,
    quorum_n: u16,
    quorum_m: u16,
    action_schema: &'static str,
    preimage: FrostActionPreimageV1,
}

fn action_cases() -> Vec<ActionCase> {
    vec![
        ActionCase {
            domain: FrostAuthorizationDomain::SettleCommitment,
            ladder_action_class: "settle.commitment",
            quorum_n: 2,
            quorum_m: 3,
            action_schema: CHIO_FROST_SETTLE_COMMITMENT_ACTION_SCHEMA,
            preimage: FrostActionPreimageV1::SettleCommitment(FrostSettleCommitmentActionV1 {
                schema: CHIO_FROST_SETTLE_COMMITMENT_ACTION_SCHEMA.to_string(),
                settlement_body_digest: digest(0x11),
                payer_id: "payer.conformance".to_string(),
                payee_id: "payee.conformance".to_string(),
                amount_base_units: "12500".to_string(),
                asset_id: "usd.conformance".to_string(),
                operation_id: "settlement.conformance".to_string(),
                rail_idempotency_key: "rail.settlement.conformance".to_string(),
                resource_version: 1,
                resource_fence: 11,
            }),
        },
        ActionCase {
            domain: FrostAuthorizationDomain::ClearingRoundFinalize,
            ladder_action_class: "clearing.round_finalize",
            quorum_n: 2,
            quorum_m: 3,
            action_schema: CHIO_FROST_CLEARING_ROUND_FINALIZE_ACTION_SCHEMA,
            preimage: clearing_finalization_body()
                .frost_action_preimage()
                .unwrap_or_else(|error| panic!("build clearing finalization action: {error}")),
        },
        ActionCase {
            domain: FrostAuthorizationDomain::ChannelClose,
            ladder_action_class: "channel.close",
            quorum_n: 2,
            quorum_m: 3,
            action_schema: CHIO_FROST_CHANNEL_CLOSE_ACTION_SCHEMA,
            preimage: FrostActionPreimageV1::ChannelClose(FrostChannelCloseActionV1 {
                schema: CHIO_FROST_CHANNEL_CLOSE_ACTION_SCHEMA.to_string(),
                close_body_digest: digest(0x15),
                effective_close_digest: digest(0x17),
                channel_id: "channel.conformance".to_string(),
                final_state_digest: digest(0x16),
                final_state_sequence: 2,
                final_cumulative_owed: MonetaryAmount {
                    units: 250,
                    currency: "USD".to_owned(),
                },
                channel_state_version: 4,
                escrow_reservation_version: 3,
                token_base_unit_release: "250".to_string(),
                publisher_fence: 13,
                lifecycle_fence: 14,
            }),
        },
        ActionCase {
            domain: FrostAuthorizationDomain::PouncerRevokeCredential,
            ladder_action_class: "pouncer.revoke_credential",
            quorum_n: 2,
            quorum_m: 3,
            action_schema: CHIO_FROST_POUNCER_REVOKE_CREDENTIAL_ACTION_SCHEMA,
            preimage: FrostActionPreimageV1::PouncerRevokeCredential(
                FrostPouncerRevokeCredentialActionV1 {
                    schema: CHIO_FROST_POUNCER_REVOKE_CREDENTIAL_ACTION_SCHEMA.to_string(),
                    credential_body_digest: digest(0x17),
                    credential_id: "credential.conformance".to_string(),
                    issuer_id: "issuer.conformance".to_string(),
                    subject_id: "subject.conformance".to_string(),
                    registry_epoch: 4,
                    anchor_epoch: 5,
                    reason: "confirmed compromise".to_string(),
                    evidence_root: digest(0x18),
                    resource_version: 4,
                    resource_fence: 15,
                },
            ),
        },
        ActionCase {
            domain: FrostAuthorizationDomain::GovernanceCaseEnforceSanction,
            ladder_action_class: "governance.case_enforce_sanction",
            quorum_n: 3,
            quorum_m: 5,
            action_schema: CHIO_FROST_GOVERNANCE_CASE_ENFORCE_SANCTION_ACTION_SCHEMA,
            preimage: FrostActionPreimageV1::GovernanceCaseEnforceSanction(
                FrostGovernanceCaseEnforceSanctionActionV1 {
                    schema: CHIO_FROST_GOVERNANCE_CASE_ENFORCE_SANCTION_ACTION_SCHEMA.to_string(),
                    case_body_digest: digest(0x19),
                    case_id: "governance.case.conformance".to_string(),
                    subject_operator_id: "operator.conformance".to_string(),
                    sanction_body_digest: digest(0x1a),
                    evidence_root: digest(0x1b),
                    enforcement_target: "operator.registry".to_string(),
                    resource_version: 5,
                    resource_fence: 16,
                },
            ),
        },
        ActionCase {
            domain: FrostAuthorizationDomain::CredentialsPassportRevoke,
            ladder_action_class: "credentials.passport_revoke",
            quorum_n: 2,
            quorum_m: 3,
            action_schema: CHIO_FROST_CREDENTIALS_PASSPORT_REVOKE_ACTION_SCHEMA,
            preimage: FrostActionPreimageV1::CredentialsPassportRevoke(
                FrostCredentialsPassportRevokeActionV1 {
                    schema: CHIO_FROST_CREDENTIALS_PASSPORT_REVOKE_ACTION_SCHEMA.to_string(),
                    passport_body_digest: digest(0x1c),
                    passport_id: "passport.conformance".to_string(),
                    issuer_id: "issuer.conformance".to_string(),
                    subject_id: "subject.conformance".to_string(),
                    revocation_generation: 2,
                    reason: "issuer revocation".to_string(),
                    evidence_root: digest(0x1d),
                    resource_version: 6,
                    resource_fence: 17,
                },
            ),
        },
        ActionCase {
            domain: FrostAuthorizationDomain::RosterRotate,
            ladder_action_class: "governance.roster_rotate",
            quorum_n: 3,
            quorum_m: 5,
            action_schema: CHIO_FROST_ROSTER_ROTATE_ACTION_SCHEMA,
            preimage: FrostActionPreimageV1::RosterRotate(FrostRosterRotateActionV1 {
                schema: CHIO_FROST_ROSTER_ROTATE_ACTION_SCHEMA.to_string(),
                predecessor_roster_digest: digest(0x1e),
                new_roster_digest: digest(0x1f),
                scope_id: "treaty.conformance".to_string(),
                current_key_epoch: 7,
                new_key_epoch: 8,
                current_checkpoint_sequence: 9,
                current_checkpoint_digest: digest(0x20),
                activation_fence: 18,
                old_session_burn_root: digest(0x21),
            }),
        },
    ]
}

fn clearing_finalization_body() -> ClearingRoundFinalizationBodyV1 {
    ClearingRoundFinalizationBodyV1 {
        schema: CLEARING_ROUND_FINALIZATION_SCHEMA.to_string(),
        round_id: "clearing.round.conformance".to_string(),
        governance_scope_id: "treaty.conformance".to_string(),
        round_core_digest: digest(0x12),
        output_manifest_digest: digest(0x13),
        participant_acceptance_root: digest(0x14),
        participant_acceptance_count: 3,
        source_lifecycle_head_digest: digest(0x15),
        source_lifecycle_version: 12,
        source_lifecycle_fence: 12,
        clearing_authority_id: "clearing.authority.conformance".to_string(),
        clearing_authority_key_epoch: 7,
        finalized_at_unix_ms: 500,
    }
}

struct ActiveResolver {
    roster: FrostRosterV1,
}

impl ActiveFrostRosterResolver for ActiveResolver {
    fn resolve_active_roster(
        &self,
        scope_id: &str,
    ) -> Result<Option<FrostRosterV1>, FrostRosterResolutionError> {
        Ok((self.roster.scope_id == scope_id).then(|| self.roster.clone()))
    }

    fn classify_scope(&self, scope_id: &str) -> Result<Option<String>, FrostRosterResolutionError> {
        Ok((self.roster.scope_id == scope_id).then(|| self.roster.authority_scope.clone()))
    }
}

struct HistoricalResolver {
    roster: FrostRosterV1,
}

impl FrostHistoricalRosterResolver for HistoricalResolver {
    fn resolve_historical_roster(
        &self,
        roster_digest: &str,
        key_epoch: u64,
        issued_at: u64,
    ) -> Result<Option<FrostRosterV1>, FrostRosterResolutionError> {
        Ok((self.roster.roster_digest == roster_digest
            && self.roster.key_epoch == key_epoch
            && self.roster.valid_from <= issued_at
            && issued_at < self.roster.valid_until)
            .then(|| self.roster.clone()))
    }
}

#[derive(Clone)]
struct EpochAnchor {
    checkpoint: FrostEpochCheckpointV1,
}

impl FrostEpochAnchor for EpochAnchor {
    fn resolve_epoch_checkpoint(
        &self,
        scope_id: &str,
    ) -> Result<FrostEpochCheckpointV1, FrostAnchorError> {
        if self.checkpoint.scope_id != scope_id {
            return Err(FrostAnchorError::Unavailable(
                "epoch checkpoint is absent".to_string(),
            ));
        }
        Ok(self.checkpoint.clone())
    }
}

#[derive(Clone)]
struct SlotAnchor {
    slot: FrostAnchoredAuthorizationSlot,
}

impl FrostAuthorizationSlotAnchor for SlotAnchor {
    fn resolve_authorization_slot(
        &self,
        scope_id: &str,
        slot_id: &str,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError> {
        if self.slot.checkpoint.scope_id != scope_id || self.slot.checkpoint.slot_id != slot_id {
            return Err(FrostAnchorError::Unavailable(
                "authorization slot is absent".to_string(),
            ));
        }
        Ok(self.slot.clone())
    }
}

struct RuntimeFixture {
    preimage: FrostActionPreimageV1,
    signing_key: SigningKey,
    roster: FrostRosterV1,
    epoch: FrostEpochCheckpointV1,
    proof: FrostAuthorizationV1,
    slot: FrostAnchoredAuthorizationSlot,
}

impl RuntimeFixture {
    fn expected(&self) -> ExpectedFrostAuthorization<'_> {
        ExpectedFrostAuthorization {
            domain: self.proof.body.domain,
            ladder_action_class: &self.proof.body.ladder_action_class,
            ladder_contract_digest: &self.proof.body.ladder_contract_digest,
            scope_id: &self.proof.body.scope_id,
            resource_id: &self.proof.body.resource_id,
            resource_version: self.proof.body.resource_version,
            resource_fence: self.proof.body.resource_fence,
            action_digest: &self.proof.body.action_digest,
        }
    }

    fn verify(&self) -> VerifiedFrostAuthorization {
        let trust = artifact_trust();
        let epoch = EpochAnchor {
            checkpoint: self.epoch.clone(),
        };
        let active = resolve_active_roster_for_execution(
            &self.roster.scope_id,
            &ActiveResolver {
                roster: self.roster.clone(),
            },
            &epoch,
            &trust,
            500,
        )
        .unwrap_or_else(|error| panic!("resolve active FROST roster: {error}"));
        verify_for_execution(
            &self.proof,
            &self.expected(),
            &active,
            &epoch,
            &SlotAnchor {
                slot: self.slot.clone(),
            },
            &trust,
            500,
        )
        .unwrap_or_else(|error| panic!("verify FROST execution authorization: {error}"))
    }
}

fn sign_roster(roster: &mut FrostRosterV1) {
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
}

fn sign_epoch(checkpoint: &mut FrostEpochCheckpointV1) {
    checkpoint.anchor_signature = epoch_authority()
        .sign(
            &checkpoint
                .signing_bytes()
                .unwrap_or_else(|error| panic!("canonicalize epoch checkpoint: {error}")),
        )
        .to_hex();
    checkpoint.checkpoint_digest = checkpoint
        .recompute_checkpoint_digest()
        .unwrap_or_else(|error| panic!("compute epoch checkpoint digest: {error}"));
}

fn sign_slot(checkpoint: &mut FrostAuthorizationSlotCheckpointV1) {
    checkpoint.anchor_signature = slot_authority()
        .sign(
            &checkpoint
                .signing_bytes()
                .unwrap_or_else(|error| panic!("canonicalize slot checkpoint: {error}")),
        )
        .to_hex();
    checkpoint.checkpoint_digest = checkpoint
        .recompute_checkpoint_digest()
        .unwrap_or_else(|error| panic!("compute slot checkpoint digest: {error}"));
}

fn burned_slot(fixture: &RuntimeFixture, burned_at: u64) -> VerifiedBurnedFrostAuthorizationSlot {
    let signing_bytes = fixture
        .proof
        .body
        .signing_bytes()
        .unwrap_or_else(|error| panic!("canonicalize burned authorization body: {error}"));
    let body = &fixture.proof.body;
    let mut bound = FrostAuthorizationSlotCheckpointV1 {
        schema: CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SCHEMA.to_string(),
        anchor_id: "frost-slot-anchor.primary".to_string(),
        checkpoint_digest: String::new(),
        scope_id: body.scope_id.clone(),
        slot_id: frost_authorization_slot_id(body)
            .unwrap_or_else(|error| panic!("compute burned authorization slot id: {error}")),
        slot_version: 1,
        predecessor_digest: None,
        domain: body.domain,
        ladder_action_class: body.ladder_action_class.clone(),
        resource_id: body.resource_id.clone(),
        resource_version: body.resource_version,
        resource_fence: body.resource_fence,
        authorization_id: body.authorization_id.clone(),
        signing_message_digest: sha256_hex(&signing_bytes),
        action_digest: body.action_digest.clone(),
        roster_digest: body.roster_digest.clone(),
        key_epoch: body.key_epoch,
        session_id: frost_authorization_session_id(body)
            .unwrap_or_else(|error| panic!("compute burned authorization session id: {error}")),
        state: FrostAuthorizationSlotState::Bound,
        aggregate_signature_digest: None,
        authorization_blob_digest: None,
        availability_receipt: None,
        clock_high_water: body.issued_at,
        anchor_key_id: "frost-slot-anchor.v1".to_string(),
        anchor_signature: String::new(),
    };
    sign_slot(&mut bound);
    let mut burned = FrostAuthorizationSlotCheckpointV1 {
        checkpoint_digest: String::new(),
        slot_version: 2,
        predecessor_digest: Some(bound.checkpoint_digest.clone()),
        state: FrostAuthorizationSlotState::Burned,
        clock_high_water: burned_at,
        anchor_signature: String::new(),
        ..bound.clone()
    };
    sign_slot(&mut burned);
    verify_burned_frost_authorization_slot(
        &bound,
        &FrostAnchoredAuthorizationSlot {
            checkpoint: burned,
            authorization_blob: None,
        },
        &artifact_trust(),
        burned_at,
    )
    .unwrap_or_else(|error| panic!("verify burned authorization slot: {error}"))
}

fn threshold_group(case: &ActionCase, seed: u8) -> (SigningKey, Vec<FrostParticipantV1>, String) {
    let participant_ids = (1..=case.quorum_m)
        .map(|index| format!("operator-{index}"))
        .collect::<Vec<_>>();
    let identifiers = participant_ids
        .iter()
        .map(|participant_id| {
            Identifier::derive(participant_id.as_bytes())
                .unwrap_or_else(|error| panic!("derive FROST identifier: {error}"))
        })
        .collect::<Vec<_>>();
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let signing_key = SigningKey::new(&mut rng);
    let (shares, public_keys) = keys::split(
        &signing_key,
        case.quorum_m,
        case.quorum_n,
        IdentifierList::Custom(&identifiers),
        &mut rng,
    )
    .unwrap_or_else(|error| panic!("split FROST group: {error}"));
    let participants = participant_ids
        .iter()
        .zip(identifiers.iter())
        .map(|(participant_id, identifier)| {
            let share = shares
                .get(identifier)
                .cloned()
                .unwrap_or_else(|| panic!("participant share must exist"));
            let package = KeyPackage::try_from(share)
                .unwrap_or_else(|error| panic!("validate key package: {error}"));
            FrostParticipantV1 {
                participant_id: participant_id.clone(),
                verification_share: hex::encode(
                    package
                        .verifying_share()
                        .serialize()
                        .unwrap_or_else(|error| panic!("serialize verifying share: {error}")),
                ),
            }
        })
        .collect();
    let group_public_key = hex::encode(
        public_keys
            .verifying_key()
            .serialize()
            .unwrap_or_else(|error| panic!("serialize group key: {error}")),
    );
    (signing_key, participants, group_public_key)
}

fn sign_authorization(
    body: FrostAuthorizationBodyV1,
    signing_key: &SigningKey,
    seed: u8,
) -> FrostAuthorizationV1 {
    let signing_bytes = body
        .signing_bytes()
        .unwrap_or_else(|error| panic!("canonicalize authorization body: {error}"));
    let signature = signing_key.sign(ChaCha20Rng::from_seed([seed; 32]), &signing_bytes);
    FrostAuthorizationV1 {
        schema: CHIO_FROST_AUTHORIZATION_SCHEMA.to_string(),
        body,
        suite_id: FROST_ED25519_SHA512_SUITE_ID.to_string(),
        group_signature: hex::encode(
            signature
                .serialize()
                .unwrap_or_else(|error| panic!("serialize group signature: {error}")),
        ),
    }
}

fn runtime_fixture(case: &ActionCase, seed: u8) -> RuntimeFixture {
    let registration = frost_action_registration(case.domain)
        .unwrap_or_else(|| panic!("registered action must resolve"));
    let (signing_key, participants, group_public_key) = threshold_group(case, seed);
    let mut roster = FrostRosterV1 {
        schema: CHIO_FROST_ROSTER_SCHEMA.to_string(),
        roster_id: String::new(),
        roster_digest: String::new(),
        authority_scope: "treaty".to_string(),
        scope_id: "treaty.conformance".to_string(),
        allowed_domains: vec![case.domain],
        key_epoch: 7,
        threshold: case.quorum_n,
        participant_count: case.quorum_m,
        participants,
        group_public_key,
        suite_id: FROST_ED25519_SHA512_SUITE_ID.to_string(),
        key_origin: FrostRosterKeyOrigin::DistributedDkg,
        ceremony_transcript_digest: digest(seed),
        predecessor_roster_digest: Some(digest(seed.wrapping_add(1))),
        valid_from: 100,
        valid_until: 10_000,
        roster_authority_key_id: "frost-roster-authority.v1".to_string(),
        roster_authority_signature: String::new(),
    };
    sign_roster(&mut roster);

    let mut body = FrostAuthorizationBodyV1 {
        schema: CHIO_FROST_AUTHORIZATION_BODY_SCHEMA.to_string(),
        authorization_id: String::new(),
        domain: case.domain,
        ladder_action_class: case.ladder_action_class.to_string(),
        ladder_contract_digest: registration
            .ladder_contract_digest()
            .unwrap_or_else(|error| panic!("compute ladder digest: {error}")),
        quorum_n: case.quorum_n,
        quorum_m: case.quorum_m,
        quorum_scope: "treaty".to_string(),
        scope_id: roster.scope_id.clone(),
        resource_id: case.preimage.resource_id().to_string(),
        resource_version: case.preimage.resource_version(),
        resource_fence: case.preimage.resource_fence(),
        action_digest: case
            .preimage
            .action_digest()
            .unwrap_or_else(|error| panic!("compute action digest: {error}")),
        roster_digest: roster.roster_digest.clone(),
        key_epoch: roster.key_epoch,
        issued_at: 400,
        expires_at: 900,
    };
    body.authorization_id = body
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("compute authorization id: {error}"));
    body.validate_action_preimage(&case.preimage)
        .unwrap_or_else(|error| panic!("validate action preimage: {error}"));
    let proof = sign_authorization(body, &signing_key, seed.wrapping_add(2));

    let mut epoch = FrostEpochCheckpointV1 {
        schema: CHIO_FROST_EPOCH_CHECKPOINT_SCHEMA.to_string(),
        anchor_id: "frost-epoch-anchor.primary".to_string(),
        checkpoint_digest: String::new(),
        scope_id: roster.scope_id.clone(),
        checkpoint_sequence: 9,
        predecessor_digest: Some(digest(seed.wrapping_add(3))),
        active_roster_id: roster.roster_id.clone(),
        active_roster_digest: roster.roster_digest.clone(),
        key_epoch: roster.key_epoch,
        group_public_key_digest: sha256_hex(
            &hex::decode(&roster.group_public_key)
                .unwrap_or_else(|error| panic!("decode group key: {error}")),
        ),
        rotation_authorization_digest: Some(digest(seed.wrapping_add(4))),
        activation_fence: 30,
        clock_high_water: 400,
        anchor_key_id: "frost-epoch-anchor.v1".to_string(),
        anchor_signature: String::new(),
    };
    sign_epoch(&mut epoch);

    let signing_bytes = proof
        .body
        .signing_bytes()
        .unwrap_or_else(|error| panic!("canonicalize signed body: {error}"));
    let signature_bytes = hex::decode(&proof.group_signature)
        .unwrap_or_else(|error| panic!("decode group signature: {error}"));
    let canonical_proof = proof
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("canonicalize authorization: {error}"));
    let mut slot_checkpoint = FrostAuthorizationSlotCheckpointV1 {
        schema: CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SCHEMA.to_string(),
        anchor_id: "frost-slot-anchor.primary".to_string(),
        checkpoint_digest: String::new(),
        scope_id: proof.body.scope_id.clone(),
        slot_id: frost_authorization_slot_id(&proof.body)
            .unwrap_or_else(|error| panic!("compute authorization slot id: {error}")),
        slot_version: 2,
        predecessor_digest: Some(digest(seed.wrapping_add(5))),
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
            .unwrap_or_else(|error| panic!("compute authorization session id: {error}")),
        state: FrostAuthorizationSlotState::Completed,
        aggregate_signature_digest: Some(sha256_hex(&signature_bytes)),
        authorization_blob_digest: Some(sha256_hex(&canonical_proof)),
        availability_receipt: Some("frost.authorization.available".to_string()),
        clock_high_water: 450,
        anchor_key_id: "frost-slot-anchor.v1".to_string(),
        anchor_signature: String::new(),
    };
    sign_slot(&mut slot_checkpoint);
    RuntimeFixture {
        preimage: case.preimage.clone(),
        signing_key,
        roster,
        epoch,
        proof,
        slot: FrostAnchoredAuthorizationSlot {
            checkpoint: slot_checkpoint,
            authorization_blob: Some(canonical_proof),
        },
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConsumptionKey {
    authorization_slot_id: String,
    authorization_id: String,
    resource_id: String,
    resource_version: u64,
    resource_fence: u64,
    action_digest: String,
}

impl ConsumptionKey {
    fn from_verified(authorization: &VerifiedFrostAuthorization) -> Self {
        Self {
            authorization_slot_id: authorization.authorization_slot_id().to_string(),
            authorization_id: authorization.authorization_id().to_string(),
            resource_id: authorization.resource_id().to_string(),
            resource_version: authorization.resource_version(),
            resource_fence: authorization.resource_fence(),
            action_digest: authorization.action_digest().to_string(),
        }
    }
}

struct ExternalResourceHead {
    current: ConsumptionKey,
    consumed: Mutex<Option<ConsumptionKey>>,
}

impl ExternalResourceHead {
    fn new(current: ConsumptionKey) -> Self {
        Self {
            current,
            consumed: Mutex::new(None),
        }
    }

    fn compare_and_swap_consume(
        &self,
        authorization: &VerifiedFrostAuthorization,
    ) -> Result<(), &'static str> {
        let candidate = ConsumptionKey::from_verified(authorization);
        if candidate != self.current {
            return Err("authorization does not match the external resource head");
        }
        let mut consumed = self
            .consumed
            .lock()
            .map_err(|_| "external resource head lock is poisoned")?;
        if consumed.is_some() {
            return Err("authorization was already consumed");
        }
        *consumed = Some(candidate);
        Ok(())
    }

    fn consumed(&self) -> Option<ConsumptionKey> {
        self.consumed
            .lock()
            .unwrap_or_else(|_| panic!("external resource head lock"))
            .clone()
    }
}

#[derive(Clone, Default)]
struct LocalResourceProjection {
    execution_count: u64,
}

fn execute_resource(
    local: &mut LocalResourceProjection,
    external: &ExternalResourceHead,
    authorization: &VerifiedFrostAuthorization,
) -> Result<(), &'static str> {
    external.compare_and_swap_consume(authorization)?;
    local.execution_count += 1;
    Ok(())
}

struct AnchoredSigningHead {
    signed: Mutex<Option<(String, FrostAuthorizationV1)>>,
}

impl AnchoredSigningHead {
    fn new() -> Self {
        Self {
            signed: Mutex::new(None),
        }
    }

    fn sign(
        &self,
        body: FrostAuthorizationBodyV1,
        signing_key: &SigningKey,
    ) -> Result<FrostAuthorizationV1, &'static str> {
        body.validate()
            .map_err(|_| "authorization body is invalid")?;
        let slot_id =
            frost_authorization_slot_id(&body).map_err(|_| "authorization slot id is invalid")?;
        let mut signed = self
            .signed
            .lock()
            .map_err(|_| "signing head lock is poisoned")?;
        if let Some((bound_slot_id, proof)) = signed.as_ref() {
            if *bound_slot_id == slot_id && proof.body == body {
                return Ok(proof.clone());
            }
            return Err("authorization slot is already bound to another message");
        }
        let proof = sign_authorization(body, signing_key, 0xee);
        *signed = Some((slot_id, proof.clone()));
        Ok(proof)
    }
}

#[test]
fn every_registered_ladder_action_verifies_its_exact_contract_and_preimage() {
    let cases = action_cases();
    assert_eq!(registered_frost_actions().len(), cases.len());
    for (index, case) in cases.iter().enumerate() {
        let registration = frost_action_registration(case.domain)
            .unwrap_or_else(|| panic!("case {} must be registered", case.ladder_action_class));
        assert_eq!(registration.ladder_action_class, case.ladder_action_class);
        assert_eq!(registration.quorum_n, case.quorum_n);
        assert_eq!(registration.quorum_m, case.quorum_m);
        assert_eq!(registration.quorum_scope, "treaty");
        assert_eq!(registration.action_preimage_schema, case.action_schema);
        assert_eq!(case.preimage.domain(), case.domain);
        case.preimage.validate().unwrap_or_else(|error| {
            panic!("validate {} preimage: {error}", case.ladder_action_class)
        });

        let fixture = runtime_fixture(case, 0x40 + index as u8);
        let verified = fixture.verify();
        assert_eq!(verified.domain(), case.domain);
        assert_eq!(verified.ladder_action_class(), case.ladder_action_class);
        assert_eq!(verified.quorum_n(), case.quorum_n);
        assert_eq!(verified.quorum_m(), case.quorum_m);
        assert_eq!(verified.quorum_scope(), "treaty");
        assert_eq!(verified.resource_id(), case.preimage.resource_id());
        assert_eq!(
            verified.resource_version(),
            case.preimage.resource_version()
        );
        assert_eq!(verified.resource_fence(), case.preimage.resource_fence());
        verified
            .verify_action_preimage(&case.preimage)
            .unwrap_or_else(|error| {
                panic!("verify {} preimage: {error}", case.ladder_action_class)
            });

        let historical = verify_historical_evidence(
            &fixture.proof,
            &HistoricalResolver {
                roster: fixture.roster.clone(),
            },
            &artifact_trust(),
        )
        .unwrap_or_else(|error| {
            panic!("verify {} historically: {error}", case.ladder_action_class)
        });
        assert_eq!(historical.authorization_id(), verified.authorization_id());

        let next = &cases[(index + 1) % cases.len()];
        let mut cross_paired = fixture.proof.body.clone();
        cross_paired.ladder_action_class = next.ladder_action_class.to_string();
        cross_paired.authorization_id = cross_paired
            .recompute_authorization_id()
            .unwrap_or_else(|error| panic!("recompute cross-paired id: {error}"));
        assert!(cross_paired.validate().is_err());
    }
}

#[test]
fn clearing_consumer_accepts_only_its_verified_finalization_action() {
    let mut case = action_cases()
        .into_iter()
        .find(|case| case.domain == FrostAuthorizationDomain::ClearingRoundFinalize)
        .unwrap_or_else(|| panic!("clearing finalization action case"));
    let premature_fixture = runtime_fixture(&case, 0xb4);
    let premature = premature_fixture.verify();
    assert!(verify_clearing_round_finalization_frost(
        &clearing_finalization_body(),
        &premature,
        500,
    )
    .is_err());

    let mut body = clearing_finalization_body();
    body.finalized_at_unix_ms = 400;
    case.preimage = body
        .frost_action_preimage()
        .unwrap_or_else(|error| panic!("build current clearing action: {error}"));
    let fixture = runtime_fixture(&case, 0xb5);
    let verified = fixture.verify();
    let binding = verify_clearing_round_finalization_frost(&body, &verified, 500)
        .unwrap_or_else(|error| panic!("verify clearing finalization consumer: {error}"));
    assert_eq!(binding.authorization_id, verified.authorization_id());
    assert_eq!(binding.action_digest, verified.action_digest());

    let mut wrong_head = body;
    wrong_head.source_lifecycle_fence += 1;
    assert!(verify_clearing_round_finalization_frost(&wrong_head, &verified, 500).is_err());
}

#[test]
fn clearing_abort_accepts_only_the_exact_burned_finalization_slot() {
    let mut body = clearing_finalization_body();
    body.finalized_at_unix_ms = 400;
    let mut case = action_cases()
        .into_iter()
        .find(|case| case.domain == FrostAuthorizationDomain::ClearingRoundFinalize)
        .unwrap_or_else(|| panic!("clearing finalization action case"));
    case.preimage = body
        .frost_action_preimage()
        .unwrap_or_else(|error| panic!("build burned clearing action: {error}"));
    let fixture = runtime_fixture(&case, 0xb6);
    let burned = burned_slot(&fixture, 500);
    let checkpoint_digest = verify_clearing_round_finalization_burn(&body, &burned, 500)
        .unwrap_or_else(|error| panic!("verify clearing finalization burn: {error}"));
    assert_eq!(checkpoint_digest, burned.checkpoint().checkpoint_digest);

    let mut wrong_fence = body.clone();
    wrong_fence.source_lifecycle_fence += 1;
    wrong_fence.source_lifecycle_version += 1;
    assert!(verify_clearing_round_finalization_burn(&wrong_fence, &burned, 500).is_err());
    assert!(verify_clearing_round_finalization_burn(&body, &burned, 499).is_err());
}

#[test]
fn reserved_adjudication_domain_remains_disabled() {
    assert!(
        frost_action_registration(FrostAuthorizationDomain::AdjudicationPanelDecision).is_none()
    );
    assert!(registered_frost_actions()
        .iter()
        .all(|registration| registration.domain
            != FrostAuthorizationDomain::AdjudicationPanelDecision));
    let mut body = FrostAuthorizationBodyV1 {
        schema: CHIO_FROST_AUTHORIZATION_BODY_SCHEMA.to_string(),
        authorization_id: digest(0xd1),
        domain: FrostAuthorizationDomain::AdjudicationPanelDecision,
        ladder_action_class: "insurance.adjudication_panel_decision".to_string(),
        ladder_contract_digest: digest(0xd2),
        quorum_n: 3,
        quorum_m: 5,
        quorum_scope: "treaty".to_string(),
        scope_id: "treaty.conformance".to_string(),
        resource_id: "insurance.claim.conformance".to_string(),
        resource_version: 1,
        resource_fence: 1,
        action_digest: digest(0xd3),
        roster_digest: digest(0xd4),
        key_epoch: 1,
        issued_at: 100,
        expires_at: 200,
    };
    body.authorization_id = body
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("compute reserved-domain id: {error}"));
    assert!(body.validate().is_err());
}

#[test]
fn external_slot_and_resource_heads_prevent_conflicting_signatures_and_reexecution() {
    let case = action_cases()
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("settlement action case"));
    let fixture = runtime_fixture(&case, 0xc1);
    let signing_head = AnchoredSigningHead::new();
    let first = signing_head
        .sign(fixture.proof.body.clone(), &fixture.signing_key)
        .unwrap_or_else(|error| panic!("sign first bound message: {error}"));
    let retry = signing_head
        .sign(fixture.proof.body.clone(), &fixture.signing_key)
        .unwrap_or_else(|error| panic!("retry first bound message: {error}"));
    assert_eq!(retry, first);

    let mut conflicting_preimage = fixture.preimage.clone();
    match &mut conflicting_preimage {
        FrostActionPreimageV1::SettleCommitment(action) => {
            action.amount_base_units = "12501".to_string();
        }
        _ => panic!("settlement fixture must use a settlement preimage"),
    }
    let mut conflicting_body = fixture.proof.body.clone();
    conflicting_body.action_digest = conflicting_preimage
        .action_digest()
        .unwrap_or_else(|error| panic!("compute conflicting action digest: {error}"));
    conflicting_body.authorization_id = conflicting_body
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("compute conflicting authorization id: {error}"));
    assert_eq!(
        frost_authorization_slot_id(&conflicting_body)
            .unwrap_or_else(|error| panic!("compute conflicting slot id: {error}")),
        frost_authorization_slot_id(&fixture.proof.body)
            .unwrap_or_else(|error| panic!("compute original slot id: {error}"))
    );
    assert!(signing_head
        .sign(conflicting_body, &fixture.signing_key)
        .is_err());

    let verified = fixture.verify();
    let consumption = ConsumptionKey::from_verified(&verified);
    let external = ExternalResourceHead::new(consumption.clone());
    let mut local = LocalResourceProjection::default();
    let snapshot = local.clone();
    execute_resource(&mut local, &external, &verified)
        .unwrap_or_else(|error| panic!("consume authorization: {error}"));
    assert_eq!(local.execution_count, 1);
    assert_eq!(external.consumed(), Some(consumption));

    local = snapshot;
    assert!(execute_resource(&mut local, &external, &verified).is_err());
    assert_eq!(local.execution_count, 0);
}
