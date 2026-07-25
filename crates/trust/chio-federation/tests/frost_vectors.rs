use std::path::PathBuf;

use chio_core_types::{sha256_hex, Keypair};
use chio_federation::frost::{
    frost_action_registration, frost_authorization_session_id, frost_authorization_slot_id,
    resolve_active_roster_for_execution, verify_for_execution,
    verify_historical_completed_authorization, verify_historical_evidence,
    ActiveFrostRosterResolver, ExpectedFrostAuthorization, FrostActionPreimageV1, FrostAnchorError,
    FrostAnchoredAuthorizationSlot, FrostArtifactAuthorityRole, FrostArtifactTrustRoot,
    FrostArtifactTrustStore, FrostAuthorizationBodyV1, FrostAuthorizationDomain,
    FrostAuthorizationError, FrostAuthorizationSlotAnchor, FrostAuthorizationSlotCheckpointV1,
    FrostAuthorizationSlotState, FrostAuthorizationV1, FrostChannelCloseActionV1, FrostEpochAnchor,
    FrostEpochCheckpointV1, FrostHistoricalRosterResolver, FrostParticipantV1, FrostRosterError,
    FrostRosterKeyOrigin, FrostRosterResolutionError, FrostRosterV1, FrostVerificationError,
    VerifiedFrostAuthorization, VerifiedHistoricalCompletedFrostAuthorization,
    CHIO_FROST_AUTHORIZATION_BODY_SCHEMA, CHIO_FROST_AUTHORIZATION_SCHEMA,
    CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SCHEMA, CHIO_FROST_CHANNEL_CLOSE_ACTION_SCHEMA,
    CHIO_FROST_EPOCH_CHECKPOINT_SCHEMA, CHIO_FROST_ROSTER_SCHEMA, FROST_ED25519_SHA512_SUITE_ID,
};
use frost_ed25519::keys::{SigningShare, VerifyingShare};
use frost_ed25519::{Signature, SigningKey, VerifyingKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const OFFICIAL_SECRET_KEY: &str =
    "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304";
const OFFICIAL_VERIFYING_KEY: &str =
    "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";
const OFFICIAL_TEST_SIGNATURE: &str = concat!(
    "154fb694ee7fcb37bf2381d94488c2a84b03b3352ad085feca81ad26d45852b7",
    "ecfe971ce4da95c4a95db93ac376b053897fca212ef85f99cf696bffeb178f07"
);
const OFFICIAL_SHARES: [&str; 3] = [
    "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509",
    "a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d",
    "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02",
];

fn roster_authority() -> Keypair {
    Keypair::from_seed(&[0x42; 32])
}

fn epoch_anchor_authority() -> Keypair {
    Keypair::from_seed(&[0x43; 32])
}

fn slot_anchor_authority() -> Keypair {
    Keypair::from_seed(&[0x44; 32])
}

fn artifact_trust() -> FrostArtifactTrustStore {
    FrostArtifactTrustStore::new([
        FrostArtifactTrustRoot {
            role: FrostArtifactAuthorityRole::Roster,
            key_id: "authority.treaty.v1".to_string(),
            public_key: roster_authority().public_key(),
        },
        FrostArtifactTrustRoot {
            role: FrostArtifactAuthorityRole::EpochAnchor,
            key_id: "epoch-anchor-key.v1".to_string(),
            public_key: epoch_anchor_authority().public_key(),
        },
        FrostArtifactTrustRoot {
            role: FrostArtifactAuthorityRole::AuthorizationSlotAnchor,
            key_id: "slot-anchor-key.v1".to_string(),
            public_key: slot_anchor_authority().public_key(),
        },
    ])
    .unwrap_or_else(|error| panic!("fixture artifact trust must build: {error}"))
}

#[derive(Clone)]
struct TestActiveResolver {
    roster: FrostRosterV1,
    scope_classification: String,
}

impl ActiveFrostRosterResolver for TestActiveResolver {
    fn resolve_active_roster(
        &self,
        scope_id: &str,
    ) -> Result<Option<FrostRosterV1>, FrostRosterResolutionError> {
        Ok((self.roster.scope_id == scope_id).then(|| self.roster.clone()))
    }

    fn classify_scope(&self, scope_id: &str) -> Result<Option<String>, FrostRosterResolutionError> {
        Ok((self.roster.scope_id == scope_id).then(|| self.scope_classification.clone()))
    }
}

#[derive(Clone)]
struct TestHistoricalResolver {
    roster: FrostRosterV1,
}

impl FrostHistoricalRosterResolver for TestHistoricalResolver {
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
struct TestEpochAnchor {
    checkpoint: FrostEpochCheckpointV1,
}

impl FrostEpochAnchor for TestEpochAnchor {
    fn resolve_epoch_checkpoint(
        &self,
        scope_id: &str,
    ) -> Result<FrostEpochCheckpointV1, FrostAnchorError> {
        if self.checkpoint.scope_id != scope_id {
            return Err(FrostAnchorError::Unavailable(
                "scope has no epoch checkpoint".to_string(),
            ));
        }
        Ok(self.checkpoint.clone())
    }
}

#[derive(Clone)]
struct TestSlotAnchor {
    slot: FrostAnchoredAuthorizationSlot,
}

impl FrostAuthorizationSlotAnchor for TestSlotAnchor {
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

#[derive(Clone)]
struct Fixture {
    proof: FrostAuthorizationV1,
    roster: FrostRosterV1,
    epoch_checkpoint: FrostEpochCheckpointV1,
    slot: FrostAnchoredAuthorizationSlot,
}

impl Fixture {
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

    fn active_roster(&self, now: u64) -> chio_federation::frost::VerifiedActiveFrostRoster {
        let resolver = TestActiveResolver {
            roster: self.roster.clone(),
            scope_classification: "treaty".to_string(),
        };
        resolve_active_roster_for_execution(
            &self.proof.body.scope_id,
            &resolver,
            &TestEpochAnchor {
                checkpoint: self.epoch_checkpoint.clone(),
            },
            &artifact_trust(),
            now,
        )
        .unwrap_or_else(|error| panic!("fixture active roster must resolve: {error}"))
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    hex::decode(value).unwrap_or_else(|error| panic!("fixture hex must decode: {error}"))
}

fn official_verifying_share(share: &str) -> String {
    let signing_share = SigningShare::deserialize(&decode_hex(share))
        .unwrap_or_else(|error| panic!("official signing share must decode: {error}"));
    let verifying_share = VerifyingShare::from(signing_share);
    hex::encode(
        verifying_share
            .serialize()
            .unwrap_or_else(|error| panic!("verifying share must serialize: {error}")),
    )
}

fn roster(group_public_key: &str, key_epoch: u64) -> FrostRosterV1 {
    let mut roster = FrostRosterV1 {
        schema: CHIO_FROST_ROSTER_SCHEMA.to_string(),
        roster_id: String::new(),
        roster_digest: String::new(),
        authority_scope: "treaty".to_string(),
        scope_id: "treaty.atlantic.v1".to_string(),
        allowed_domains: vec![FrostAuthorizationDomain::SettleCommitment],
        key_epoch,
        threshold: 2,
        participant_count: 3,
        participants: OFFICIAL_SHARES
            .iter()
            .enumerate()
            .map(|(index, share)| FrostParticipantV1 {
                participant_id: format!("operator-{}", index + 1),
                verification_share: official_verifying_share(share),
            })
            .collect(),
        group_public_key: group_public_key.to_string(),
        suite_id: FROST_ED25519_SHA512_SUITE_ID.to_string(),
        key_origin: FrostRosterKeyOrigin::DistributedDkg,
        ceremony_transcript_digest: "44".repeat(32),
        predecessor_roster_digest: (key_epoch > 1).then(|| "55".repeat(32)),
        valid_from: 100,
        valid_until: 1_000,
        roster_authority_key_id: "authority.treaty.v1".to_string(),
        roster_authority_signature: String::new(),
    };
    sign_roster(&mut roster);
    roster
}

fn sign_roster(roster: &mut FrostRosterV1) {
    roster.roster_id = roster
        .recompute_roster_id()
        .unwrap_or_else(|error| panic!("fixture roster id must compute: {error}"));
    roster.roster_authority_signature = roster_authority()
        .sign(
            &roster
                .signing_bytes()
                .unwrap_or_else(|error| panic!("fixture roster must canonicalize: {error}")),
        )
        .to_hex();
    roster.roster_digest = roster
        .recompute_roster_digest()
        .unwrap_or_else(|error| panic!("fixture roster digest must compute: {error}"));
}

fn epoch_checkpoint(roster: &FrostRosterV1) -> FrostEpochCheckpointV1 {
    let mut checkpoint = FrostEpochCheckpointV1 {
        schema: CHIO_FROST_EPOCH_CHECKPOINT_SCHEMA.to_string(),
        anchor_id: "epoch-anchor.primary".to_string(),
        checkpoint_digest: String::new(),
        scope_id: roster.scope_id.clone(),
        checkpoint_sequence: roster.key_epoch,
        predecessor_digest: Some("77".repeat(32)),
        active_roster_id: roster.roster_id.clone(),
        active_roster_digest: roster.roster_digest.clone(),
        key_epoch: roster.key_epoch,
        group_public_key_digest: sha256_hex(&decode_hex(&roster.group_public_key)),
        rotation_authorization_digest: Some("88".repeat(32)),
        activation_fence: 19,
        clock_high_water: 200,
        anchor_key_id: "epoch-anchor-key.v1".to_string(),
        anchor_signature: String::new(),
    };
    sign_epoch_checkpoint(&mut checkpoint);
    checkpoint
}

fn sign_epoch_checkpoint(checkpoint: &mut FrostEpochCheckpointV1) {
    checkpoint.anchor_signature = epoch_anchor_authority()
        .sign(
            &checkpoint
                .signing_bytes()
                .unwrap_or_else(|error| panic!("epoch checkpoint must canonicalize: {error}")),
        )
        .to_hex();
    checkpoint.checkpoint_digest = checkpoint
        .recompute_checkpoint_digest()
        .unwrap_or_else(|error| panic!("epoch checkpoint digest must compute: {error}"));
}

fn sign_slot_checkpoint(checkpoint: &mut FrostAuthorizationSlotCheckpointV1) {
    checkpoint.anchor_signature = slot_anchor_authority()
        .sign(
            &checkpoint
                .signing_bytes()
                .unwrap_or_else(|error| panic!("slot checkpoint must canonicalize: {error}")),
        )
        .to_hex();
    checkpoint.checkpoint_digest = checkpoint
        .recompute_checkpoint_digest()
        .unwrap_or_else(|error| panic!("slot checkpoint digest must compute: {error}"));
}

fn historical_slot_pair(
    fixture: &Fixture,
) -> (
    FrostAuthorizationSlotCheckpointV1,
    FrostAnchoredAuthorizationSlot,
) {
    let mut bound = fixture.slot.checkpoint.clone();
    bound.slot_version = 1;
    bound.predecessor_digest = None;
    bound.state = FrostAuthorizationSlotState::Bound;
    bound.aggregate_signature_digest = None;
    bound.authorization_blob_digest = None;
    bound.availability_receipt = None;
    bound.anchor_signature.clear();
    bound.checkpoint_digest.clear();
    sign_slot_checkpoint(&mut bound);

    let mut completed = fixture.slot.clone();
    completed.checkpoint.predecessor_digest = Some(bound.checkpoint_digest.clone());
    completed.checkpoint.anchor_signature.clear();
    completed.checkpoint.checkpoint_digest.clear();
    sign_slot_checkpoint(&mut completed.checkpoint);
    (bound, completed)
}

fn fixture_with_keys(roster_key: &str, signing_key: &str) -> Fixture {
    let roster = roster(roster_key, 4);
    let registration = frost_action_registration(FrostAuthorizationDomain::SettleCommitment)
        .unwrap_or_else(|| panic!("settlement authorization domain must be registered"));
    let mut body = FrostAuthorizationBodyV1 {
        schema: CHIO_FROST_AUTHORIZATION_BODY_SCHEMA.to_string(),
        authorization_id: String::new(),
        domain: registration.domain,
        ladder_action_class: registration.ladder_action_class.to_string(),
        ladder_contract_digest: registration
            .ladder_contract_digest()
            .unwrap_or_else(|error| panic!("ladder digest must compute: {error}")),
        quorum_n: registration.quorum_n,
        quorum_m: registration.quorum_m,
        quorum_scope: registration.quorum_scope.to_string(),
        scope_id: roster.scope_id.clone(),
        resource_id: "settlement.set-974".to_string(),
        resource_version: 7,
        resource_fence: 11,
        action_digest: "aa".repeat(32),
        roster_digest: roster.roster_digest.clone(),
        key_epoch: roster.key_epoch,
        issued_at: 200,
        expires_at: 400,
    };
    body.authorization_id = body
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("fixture authorization id must compute: {error}"));
    let signing_bytes = body
        .signing_bytes()
        .unwrap_or_else(|error| panic!("fixture body must produce signing bytes: {error}"));
    let secret = SigningKey::deserialize(&decode_hex(signing_key))
        .unwrap_or_else(|error| panic!("official group secret must decode: {error}"));
    let signature = secret.sign(ChaCha20Rng::from_seed([7; 32]), &signing_bytes);
    let signature_bytes = signature
        .serialize()
        .unwrap_or_else(|error| panic!("fixture signature must serialize: {error}"));
    let proof = FrostAuthorizationV1 {
        schema: CHIO_FROST_AUTHORIZATION_SCHEMA.to_string(),
        body,
        suite_id: FROST_ED25519_SHA512_SUITE_ID.to_string(),
        group_signature: hex::encode(&signature_bytes),
    };
    let signing_message_digest = sha256_hex(&signing_bytes);
    let signature_digest = sha256_hex(&signature_bytes);
    let canonical_proof = proof
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("fixture proof must canonicalize: {error}"));
    let checkpoint = FrostAuthorizationSlotCheckpointV1 {
        schema: CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SCHEMA.to_string(),
        anchor_id: "slot-anchor.primary".to_string(),
        checkpoint_digest: String::new(),
        scope_id: proof.body.scope_id.clone(),
        slot_id: frost_authorization_slot_id(&proof.body)
            .unwrap_or_else(|error| panic!("slot id must compute: {error}")),
        slot_version: 2,
        predecessor_digest: Some("bb".repeat(32)),
        domain: proof.body.domain,
        ladder_action_class: proof.body.ladder_action_class.clone(),
        resource_id: proof.body.resource_id.clone(),
        resource_version: proof.body.resource_version,
        resource_fence: proof.body.resource_fence,
        authorization_id: proof.body.authorization_id.clone(),
        signing_message_digest,
        action_digest: proof.body.action_digest.clone(),
        roster_digest: proof.body.roster_digest.clone(),
        key_epoch: proof.body.key_epoch,
        session_id: frost_authorization_session_id(&proof.body)
            .unwrap_or_else(|error| panic!("session id must compute: {error}")),
        state: FrostAuthorizationSlotState::Completed,
        aggregate_signature_digest: Some(signature_digest),
        authorization_blob_digest: Some(sha256_hex(&canonical_proof)),
        availability_receipt: Some("availability.slot-anchor.primary.v1".to_string()),
        clock_high_water: 200,
        anchor_key_id: "slot-anchor-key.v1".to_string(),
        anchor_signature: String::new(),
    };
    let mut checkpoint = checkpoint;
    checkpoint.anchor_signature = slot_anchor_authority()
        .sign(
            &checkpoint
                .signing_bytes()
                .unwrap_or_else(|error| panic!("slot checkpoint must canonicalize: {error}")),
        )
        .to_hex();
    checkpoint.checkpoint_digest = checkpoint
        .recompute_checkpoint_digest()
        .unwrap_or_else(|error| panic!("slot checkpoint digest must compute: {error}"));
    Fixture {
        proof,
        epoch_checkpoint: epoch_checkpoint(&roster),
        roster,
        slot: FrostAnchoredAuthorizationSlot {
            checkpoint,
            authorization_blob: Some(canonical_proof),
        },
    }
}

fn fixture() -> Fixture {
    fixture_with_keys(OFFICIAL_VERIFYING_KEY, OFFICIAL_SECRET_KEY)
}

#[test]
fn signed_frost_numbers_enforce_ijson_boundaries() {
    const MAX_SAFE: u64 = (1_u64 << 53) - 1;
    const UNSAFE: u64 = MAX_SAFE + 1;

    let channel_close = FrostActionPreimageV1::ChannelClose(FrostChannelCloseActionV1 {
        schema: CHIO_FROST_CHANNEL_CLOSE_ACTION_SCHEMA.to_string(),
        close_body_digest: "11".repeat(32),
        effective_close_digest: "33".repeat(32),
        channel_id: "channel.ch-974".to_string(),
        final_state_digest: "22".repeat(32),
        final_state_sequence: MAX_SAFE,
        final_cumulative_owed: chio_core_types::capability::scope::MonetaryAmount {
            units: MAX_SAFE,
            currency: "USD".to_owned(),
        },
        channel_state_version: MAX_SAFE,
        escrow_reservation_version: MAX_SAFE,
        token_base_unit_release: "0".to_string(),
        publisher_fence: MAX_SAFE,
        lifecycle_fence: MAX_SAFE,
    });
    channel_close
        .action_digest()
        .unwrap_or_else(|error| panic!("maximum safe channel action must validate: {error}"));
    for field in [
        "final_state_sequence",
        "final_cumulative_owed",
        "channel_state_version",
        "escrow_reservation_version",
        "publisher_fence",
        "lifecycle_fence",
    ] {
        let mut invalid = channel_close.clone();
        let FrostActionPreimageV1::ChannelClose(action) = &mut invalid else {
            panic!("fixture must remain a channel close action");
        };
        match field {
            "final_state_sequence" => action.final_state_sequence = UNSAFE,
            "final_cumulative_owed" => action.final_cumulative_owed.units = UNSAFE,
            "channel_state_version" => action.channel_state_version = UNSAFE,
            "escrow_reservation_version" => action.escrow_reservation_version = UNSAFE,
            "publisher_fence" => action.publisher_fence = UNSAFE,
            "lifecycle_fence" => action.lifecycle_fence = UNSAFE,
            _ => unreachable!(),
        }
        assert_eq!(
            invalid.action_digest(),
            Err(FrostAuthorizationError::InvalidField {
                field,
                detail: if matches!(field, "final_state_sequence" | "final_cumulative_owed") {
                    "must be an I-JSON safe integer"
                } else {
                    "must be a positive I-JSON safe integer"
                },
            })
        );
    }

    let fixture = fixture();
    let mut body = fixture.proof.body.clone();
    body.resource_version = MAX_SAFE;
    body.resource_fence = MAX_SAFE;
    body.key_epoch = MAX_SAFE;
    body.issued_at = MAX_SAFE - 1;
    body.expires_at = MAX_SAFE;
    body.authorization_id = body
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("maximum safe authorization id must compute: {error}"));
    body.validate()
        .unwrap_or_else(|error| panic!("maximum safe authorization must validate: {error}"));
    for field in [
        "resource_version",
        "resource_fence",
        "key_epoch",
        "issued_at",
        "expires_at",
    ] {
        let mut invalid = body.clone();
        match field {
            "resource_version" => invalid.resource_version = UNSAFE,
            "resource_fence" => invalid.resource_fence = UNSAFE,
            "key_epoch" => invalid.key_epoch = UNSAFE,
            "issued_at" => invalid.issued_at = UNSAFE,
            "expires_at" => invalid.expires_at = UNSAFE,
            _ => unreachable!(),
        }
        invalid.authorization_id = invalid
            .recompute_authorization_id()
            .unwrap_or_else(|error| panic!("unsafe authorization id must compute: {error}"));
        let detail = if matches!(field, "issued_at" | "expires_at") {
            "must be an I-JSON safe integer"
        } else {
            "must be a positive I-JSON safe integer"
        };
        assert_eq!(
            invalid.validate(),
            Err(FrostAuthorizationError::InvalidField { field, detail })
        );
    }

    let mut checkpoint = fixture.slot.checkpoint.clone();
    checkpoint.slot_version = MAX_SAFE;
    checkpoint.resource_version = body.resource_version;
    checkpoint.resource_fence = body.resource_fence;
    checkpoint.slot_id = frost_authorization_slot_id(&body)
        .unwrap_or_else(|error| panic!("maximum safe slot id must compute: {error}"));
    checkpoint.authorization_id = body.authorization_id.clone();
    checkpoint.signing_message_digest = sha256_hex(
        &body
            .signing_bytes()
            .unwrap_or_else(|error| panic!("maximum safe body must canonicalize: {error}")),
    );
    checkpoint.key_epoch = body.key_epoch;
    checkpoint.session_id = frost_authorization_session_id(&body)
        .unwrap_or_else(|error| panic!("maximum safe session id must compute: {error}"));
    checkpoint.clock_high_water = MAX_SAFE;
    checkpoint.anchor_signature.clear();
    checkpoint.checkpoint_digest.clear();
    sign_slot_checkpoint(&mut checkpoint);
    checkpoint
        .validate()
        .unwrap_or_else(|error| panic!("maximum safe slot checkpoint must validate: {error}"));
    for field in [
        "slot_version",
        "resource_version",
        "resource_fence",
        "key_epoch",
        "clock_high_water",
    ] {
        let mut invalid = checkpoint.clone();
        match field {
            "slot_version" => invalid.slot_version = UNSAFE,
            "resource_version" => invalid.resource_version = UNSAFE,
            "resource_fence" => invalid.resource_fence = UNSAFE,
            "key_epoch" => invalid.key_epoch = UNSAFE,
            "clock_high_water" => invalid.clock_high_water = UNSAFE,
            _ => unreachable!(),
        }
        assert_eq!(
            invalid.validate(),
            Err(FrostVerificationError::Authorization(
                FrostAuthorizationError::InvalidField {
                    field,
                    detail: "must be a positive I-JSON safe integer",
                }
            ))
        );
    }

    let mut roster = fixture.roster.clone();
    roster.key_epoch = MAX_SAFE;
    roster.valid_from = MAX_SAFE - 1;
    roster.valid_until = MAX_SAFE;
    sign_roster(&mut roster);
    roster
        .validate()
        .unwrap_or_else(|error| panic!("maximum safe roster must validate: {error}"));
    for field in ["key_epoch", "valid_from", "valid_until"] {
        let mut invalid = roster.clone();
        match field {
            "key_epoch" => invalid.key_epoch = UNSAFE,
            "valid_from" => invalid.valid_from = UNSAFE,
            "valid_until" => invalid.valid_until = UNSAFE,
            _ => unreachable!(),
        }
        assert_eq!(
            invalid.validate(),
            Err(FrostRosterError::InvalidField {
                field,
                detail: if field == "key_epoch" {
                    "must be a positive I-JSON safe integer"
                } else {
                    "must be an I-JSON safe integer"
                },
            })
        );
    }

    let mut epoch_checkpoint = fixture.epoch_checkpoint.clone();
    epoch_checkpoint.checkpoint_sequence = MAX_SAFE;
    epoch_checkpoint.key_epoch = MAX_SAFE;
    epoch_checkpoint.activation_fence = MAX_SAFE;
    epoch_checkpoint.clock_high_water = MAX_SAFE;
    epoch_checkpoint.anchor_signature.clear();
    epoch_checkpoint.checkpoint_digest.clear();
    sign_epoch_checkpoint(&mut epoch_checkpoint);
    epoch_checkpoint
        .validate()
        .unwrap_or_else(|error| panic!("maximum safe epoch checkpoint must validate: {error}"));
    for field in [
        "checkpoint_sequence",
        "key_epoch",
        "activation_fence",
        "clock_high_water",
    ] {
        let mut invalid = epoch_checkpoint.clone();
        match field {
            "checkpoint_sequence" => invalid.checkpoint_sequence = UNSAFE,
            "key_epoch" => invalid.key_epoch = UNSAFE,
            "activation_fence" => invalid.activation_fence = UNSAFE,
            "clock_high_water" => invalid.clock_high_water = UNSAFE,
            _ => unreachable!(),
        }
        assert_eq!(
            invalid.validate(),
            Err(FrostRosterError::InvalidField {
                field,
                detail: "must be a positive I-JSON safe integer",
            })
        );
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let family = root.join("spec/schemas/chio-frost/v1");
    let authorization_schema_path = family.join("authorization.schema.json");
    let authorization_schema = chio_spec_validate::load_json(&authorization_schema_path)
        .unwrap_or_else(|error| panic!("authorization schema must load: {error}"));
    let mut proof = fixture.proof;
    proof.body = body;
    let proof_value = serde_json::to_value(proof)
        .unwrap_or_else(|error| panic!("maximum safe authorization must serialize: {error}"));
    chio_spec_validate::validate_value(
        &authorization_schema_path,
        &authorization_schema,
        &PathBuf::from("<maximum safe authorization>"),
        &proof_value,
    )
    .unwrap_or_else(|error| panic!("maximum safe authorization schema failed: {error}"));
    for field in [
        "resourceVersion",
        "resourceFence",
        "keyEpoch",
        "issuedAt",
        "expiresAt",
    ] {
        let mut invalid = proof_value.clone();
        invalid["body"][field] = serde_json::json!(UNSAFE);
        assert!(
            chio_spec_validate::validate_value(
                &authorization_schema_path,
                &authorization_schema,
                &PathBuf::from(format!("<unsafe {field}>")),
                &invalid,
            )
            .is_err(),
            "authorization schema accepted unsafe {field}"
        );
    }

    let checkpoint_schema_path = family.join("authorization-slot-checkpoint.schema.json");
    let checkpoint_schema = chio_spec_validate::load_json(&checkpoint_schema_path)
        .unwrap_or_else(|error| panic!("slot checkpoint schema must load: {error}"));
    let checkpoint_value = serde_json::to_value(checkpoint)
        .unwrap_or_else(|error| panic!("maximum safe checkpoint must serialize: {error}"));
    chio_spec_validate::validate_value(
        &checkpoint_schema_path,
        &checkpoint_schema,
        &PathBuf::from("<maximum safe slot checkpoint>"),
        &checkpoint_value,
    )
    .unwrap_or_else(|error| panic!("maximum safe checkpoint schema failed: {error}"));
    for field in [
        "slotVersion",
        "resourceVersion",
        "resourceFence",
        "keyEpoch",
        "clockHighWater",
    ] {
        let mut invalid = checkpoint_value.clone();
        invalid[field] = serde_json::json!(UNSAFE);
        assert!(
            chio_spec_validate::validate_value(
                &checkpoint_schema_path,
                &checkpoint_schema,
                &PathBuf::from(format!("<unsafe {field}>")),
                &invalid,
            )
            .is_err(),
            "slot checkpoint schema accepted unsafe {field}"
        );
    }

    let roster_schema_path = family.join("roster.schema.json");
    let roster_schema = chio_spec_validate::load_json(&roster_schema_path)
        .unwrap_or_else(|error| panic!("roster schema must load: {error}"));
    let roster_value = serde_json::to_value(roster)
        .unwrap_or_else(|error| panic!("maximum safe roster must serialize: {error}"));
    chio_spec_validate::validate_value(
        &roster_schema_path,
        &roster_schema,
        &PathBuf::from("<maximum safe roster>"),
        &roster_value,
    )
    .unwrap_or_else(|error| panic!("maximum safe roster schema failed: {error}"));
    for field in ["keyEpoch", "validFrom", "validUntil"] {
        let mut invalid = roster_value.clone();
        invalid[field] = serde_json::json!(UNSAFE);
        assert!(
            chio_spec_validate::validate_value(
                &roster_schema_path,
                &roster_schema,
                &PathBuf::from(format!("<unsafe {field}>")),
                &invalid,
            )
            .is_err(),
            "roster schema accepted unsafe {field}"
        );
    }

    let epoch_schema_path = family.join("epoch-checkpoint.schema.json");
    let epoch_schema = chio_spec_validate::load_json(&epoch_schema_path)
        .unwrap_or_else(|error| panic!("epoch checkpoint schema must load: {error}"));
    let epoch_value = serde_json::to_value(epoch_checkpoint)
        .unwrap_or_else(|error| panic!("maximum safe epoch checkpoint must serialize: {error}"));
    chio_spec_validate::validate_value(
        &epoch_schema_path,
        &epoch_schema,
        &PathBuf::from("<maximum safe epoch checkpoint>"),
        &epoch_value,
    )
    .unwrap_or_else(|error| panic!("maximum safe epoch schema failed: {error}"));
    for field in [
        "checkpointSequence",
        "keyEpoch",
        "activationFence",
        "clockHighWater",
    ] {
        let mut invalid = epoch_value.clone();
        invalid[field] = serde_json::json!(UNSAFE);
        assert!(
            chio_spec_validate::validate_value(
                &epoch_schema_path,
                &epoch_schema,
                &PathBuf::from(format!("<unsafe {field}>")),
                &invalid,
            )
            .is_err(),
            "epoch checkpoint schema accepted unsafe {field}"
        );
    }
    let mut invalid_currency = channel_close;
    let FrostActionPreimageV1::ChannelClose(action) = &mut invalid_currency else {
        panic!("fixture must remain a channel close action");
    };
    action.final_cumulative_owed.currency = "usd".to_owned();
    assert_eq!(
        invalid_currency.action_digest(),
        Err(FrostAuthorizationError::InvalidField {
            field: "final_cumulative_owed",
            detail: "currency must be a 3-letter uppercase code",
        })
    );
}

#[test]
fn upstream_official_vector_and_active_execution_authorization_verify() {
    let verifying_key = VerifyingKey::deserialize(&decode_hex(OFFICIAL_VERIFYING_KEY))
        .unwrap_or_else(|error| panic!("official verifying key must decode: {error}"));
    let signature = Signature::deserialize(&decode_hex(OFFICIAL_TEST_SIGNATURE))
        .unwrap_or_else(|error| panic!("official signature must decode: {error}"));
    verifying_key
        .verify(b"test", &signature)
        .unwrap_or_else(|error| panic!("upstream official vector must verify: {error}"));

    let fixture = fixture();
    let active_roster = fixture.active_roster(250);
    let verified = verify_for_execution(
        &fixture.proof,
        &fixture.expected(),
        &active_roster,
        &TestEpochAnchor {
            checkpoint: fixture.epoch_checkpoint.clone(),
        },
        &TestSlotAnchor {
            slot: fixture.slot.clone(),
        },
        &artifact_trust(),
        250,
    )
    .unwrap_or_else(|error| panic!("active FROST authorization must verify: {error}"));
    assert_eq!(
        verified.authorization_id(),
        fixture.proof.body.authorization_id
    );
    assert_eq!(
        verified.authorization_slot_id(),
        frost_authorization_slot_id(&fixture.proof.body)
            .unwrap_or_else(|error| panic!("fixture slot id must compute: {error}"))
    );
}

#[test]
fn active_verification_rejects_wrong_group_key_and_altered_body() {
    let wrong_key = SigningKey::deserialize(&[
        2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ])
    .unwrap_or_else(|error| panic!("alternate signing key must decode: {error}"));
    let wrong_verifying_key = VerifyingKey::from(&wrong_key)
        .serialize()
        .unwrap_or_else(|error| panic!("alternate verifying key must serialize: {error}"));
    let wrong_key_fixture =
        fixture_with_keys(&hex::encode(wrong_verifying_key), OFFICIAL_SECRET_KEY);
    assert!(
        verify_for_execution(
            &wrong_key_fixture.proof,
            &wrong_key_fixture.expected(),
            &wrong_key_fixture.active_roster(250),
            &TestEpochAnchor {
                checkpoint: wrong_key_fixture.epoch_checkpoint.clone(),
            },
            &TestSlotAnchor {
                slot: wrong_key_fixture.slot.clone(),
            },
            &artifact_trust(),
            250,
        )
        .is_err(),
        "a signature from another group key must reject"
    );

    let mut altered = fixture();
    altered.proof.body.resource_fence += 1;
    assert!(
        verify_for_execution(
            &altered.proof,
            &altered.expected(),
            &altered.active_roster(250),
            &TestEpochAnchor {
                checkpoint: altered.epoch_checkpoint.clone(),
            },
            &TestSlotAnchor {
                slot: altered.slot.clone(),
            },
            &artifact_trust(),
            250,
        )
        .is_err(),
        "a body changed after signing must reject"
    );
}

#[test]
fn active_verification_rejects_forged_epoch_and_slot_checkpoints() {
    let fixture = fixture();
    let resolver = TestActiveResolver {
        roster: fixture.roster.clone(),
        scope_classification: "treaty".to_string(),
    };
    let mut forged_epoch = fixture.epoch_checkpoint.clone();
    forged_epoch.clock_high_water += 1;
    forged_epoch.checkpoint_digest = forged_epoch
        .recompute_checkpoint_digest()
        .unwrap_or_else(|error| panic!("forged epoch digest must compute: {error}"));
    assert!(resolve_active_roster_for_execution(
        &fixture.proof.body.scope_id,
        &resolver,
        &TestEpochAnchor {
            checkpoint: forged_epoch,
        },
        &artifact_trust(),
        250,
    )
    .is_err());

    let active_roster = fixture.active_roster(250);
    let mut forged_slot = fixture.slot.clone();
    forged_slot.checkpoint.clock_high_water += 1;
    forged_slot.checkpoint.checkpoint_digest = forged_slot
        .checkpoint
        .recompute_checkpoint_digest()
        .unwrap_or_else(|error| panic!("forged slot digest must compute: {error}"));
    assert!(verify_for_execution(
        &fixture.proof,
        &fixture.expected(),
        &active_roster,
        &TestEpochAnchor {
            checkpoint: fixture.epoch_checkpoint.clone(),
        },
        &TestSlotAnchor { slot: forged_slot },
        &artifact_trust(),
        250,
    )
    .is_err());
}

#[test]
fn active_verification_rejects_wrong_domain_stale_epoch_and_expiry() {
    let fixture = fixture();
    let active_roster = fixture.active_roster(250);
    let mut wrong_expected = fixture.expected();
    wrong_expected.domain = FrostAuthorizationDomain::ChannelClose;
    assert!(verify_for_execution(
        &fixture.proof,
        &wrong_expected,
        &active_roster,
        &TestEpochAnchor {
            checkpoint: fixture.epoch_checkpoint.clone(),
        },
        &TestSlotAnchor {
            slot: fixture.slot.clone(),
        },
        &artifact_trust(),
        250,
    )
    .is_err());

    let mut stale_checkpoint = fixture.epoch_checkpoint.clone();
    stale_checkpoint.key_epoch += 1;
    let resolver = TestActiveResolver {
        roster: fixture.roster.clone(),
        scope_classification: "treaty".to_string(),
    };
    assert!(
        resolve_active_roster_for_execution(
            &fixture.proof.body.scope_id,
            &resolver,
            &TestEpochAnchor {
                checkpoint: stale_checkpoint,
            },
            &artifact_trust(),
            250,
        )
        .is_err(),
        "local roster state behind the external epoch must reject"
    );

    let mut rotated_checkpoint = fixture.epoch_checkpoint.clone();
    rotated_checkpoint.checkpoint_sequence += 1;
    rotated_checkpoint.predecessor_digest =
        Some(fixture.epoch_checkpoint.checkpoint_digest.clone());
    rotated_checkpoint.active_roster_id = "dd".repeat(32);
    rotated_checkpoint.active_roster_digest = "ee".repeat(32);
    rotated_checkpoint.key_epoch += 1;
    rotated_checkpoint.activation_fence += 1;
    sign_epoch_checkpoint(&mut rotated_checkpoint);
    assert!(
        verify_for_execution(
            &fixture.proof,
            &fixture.expected(),
            &active_roster,
            &TestEpochAnchor {
                checkpoint: rotated_checkpoint,
            },
            &TestSlotAnchor {
                slot: fixture.slot.clone(),
            },
            &artifact_trust(),
            250,
        )
        .is_err(),
        "a retained roster handle must fail after the external epoch rotates"
    );

    assert!(
        verify_for_execution(
            &fixture.proof,
            &fixture.expected(),
            &active_roster,
            &TestEpochAnchor {
                checkpoint: fixture.epoch_checkpoint.clone(),
            },
            &TestSlotAnchor {
                slot: fixture.slot.clone(),
            },
            &artifact_trust(),
            400,
        )
        .is_err(),
        "authorization expiry is exclusive"
    );
}

#[test]
fn retired_epoch_is_historical_evidence_but_not_execution_authority() {
    let retired = fixture();
    let mut current_roster = retired.roster.clone();
    current_roster.key_epoch += 1;
    current_roster.predecessor_roster_digest = Some(retired.roster.roster_digest.clone());
    sign_roster(&mut current_roster);
    let current_checkpoint = epoch_checkpoint(&current_roster);
    let current_scope_id = current_roster.scope_id.clone();
    let current = resolve_active_roster_for_execution(
        &current_scope_id,
        &TestActiveResolver {
            roster: current_roster,
            scope_classification: "treaty".to_string(),
        },
        &TestEpochAnchor {
            checkpoint: current_checkpoint,
        },
        &artifact_trust(),
        250,
    )
    .unwrap_or_else(|error| panic!("current roster must resolve: {error}"));

    assert!(
        verify_for_execution(
            &retired.proof,
            &retired.expected(),
            &current,
            &TestEpochAnchor {
                checkpoint: epoch_checkpoint(&retired.roster),
            },
            &TestSlotAnchor {
                slot: retired.slot.clone(),
            },
            &artifact_trust(),
            250,
        )
        .is_err(),
        "retired roster signatures cannot authorize current execution"
    );
    let historical = verify_historical_evidence(
        &retired.proof,
        &TestHistoricalResolver {
            roster: retired.roster.clone(),
        },
        &artifact_trust(),
    )
    .unwrap_or_else(|error| panic!("retired proof must remain valid historical evidence: {error}"));
    assert_eq!(
        historical.authorization_id(),
        retired.proof.body.authorization_id
    );
}

#[test]
fn historical_completion_requires_the_exact_bound_slot_and_live_completion_window() {
    let fixture = fixture();
    let (bound, completed) = historical_slot_pair(&fixture);
    let verified = verify_historical_completed_authorization(
        &fixture.proof,
        &bound,
        &completed,
        &TestHistoricalResolver {
            roster: fixture.roster.clone(),
        },
        &artifact_trust(),
    )
    .unwrap_or_else(|error| panic!("historical completed authorization must verify: {error}"));
    assert_eq!(
        verified.authorization_id(),
        fixture.proof.body.authorization_id
    );
    assert_eq!(verified.action_digest(), fixture.proof.body.action_digest);
    assert_eq!(
        verified.completed_at(),
        completed.checkpoint.clock_high_water
    );
    assert_eq!(
        (&verified as &dyn std::any::Any).type_id(),
        std::any::TypeId::of::<VerifiedHistoricalCompletedFrostAuthorization>(),
    );
    assert_ne!(
        std::any::TypeId::of::<VerifiedHistoricalCompletedFrostAuthorization>(),
        std::any::TypeId::of::<VerifiedFrostAuthorization>(),
    );

    let mut substituted_bound = bound.clone();
    substituted_bound.action_digest = "cc".repeat(32);
    substituted_bound.anchor_signature.clear();
    substituted_bound.checkpoint_digest.clear();
    sign_slot_checkpoint(&mut substituted_bound);
    let mut substituted_completed = completed.clone();
    substituted_completed.checkpoint.predecessor_digest =
        Some(substituted_bound.checkpoint_digest.clone());
    substituted_completed.checkpoint.anchor_signature.clear();
    substituted_completed.checkpoint.checkpoint_digest.clear();
    sign_slot_checkpoint(&mut substituted_completed.checkpoint);
    assert!(verify_historical_completed_authorization(
        &fixture.proof,
        &substituted_bound,
        &substituted_completed,
        &TestHistoricalResolver {
            roster: fixture.roster.clone(),
        },
        &artifact_trust(),
    )
    .is_err());

    let mut expired = completed;
    expired.checkpoint.clock_high_water = fixture.proof.body.expires_at;
    expired.checkpoint.anchor_signature.clear();
    expired.checkpoint.checkpoint_digest.clear();
    sign_slot_checkpoint(&mut expired.checkpoint);
    assert!(verify_historical_completed_authorization(
        &fixture.proof,
        &bound,
        &expired,
        &TestHistoricalResolver {
            roster: fixture.roster,
        },
        &artifact_trust(),
    )
    .is_err());
}
