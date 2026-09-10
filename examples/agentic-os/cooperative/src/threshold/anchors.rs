//! Retained authority records for this single-operator local-credit rail.
//! Member custody is separate. Protect and back up this authority store as one unit.
use anyhow::{Context, Result};
use chio_agent_os_shared::{host::private_directory, json, Value};
use chio_core::{crypto::Keypair, sha256_hex};
use chio_federation::frost::*;
use chio_personal_network::directory::key;
use rusqlite::{params, Connection, OptionalExtension};
use std::{path::Path, sync::Mutex};
pub struct Anchors {
    pub key: Keypair,
    epoch_key: Keypair,
    slot_key: Keypair,
    pub db: Mutex<Connection>,
}
impl Anchors {
    pub fn open(root: &Path) -> Result<Self> {
        private_directory(root)?;
        let epoch_key = key(&root.join("epoch-authority.key"))?;
        let slot_key = key(&root.join("slot-authority.key"))?;
        let key = key(&root.join("roster-authority.key"))?;
        let db = Connection::open(root.join("authority.db"))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY, body TEXT NOT NULL); CREATE TABLE IF NOT EXISTS settlements(id TEXT PRIMARY KEY, action_digest TEXT NOT NULL, result TEXT NOT NULL); INSERT OR IGNORE INTO records VALUES('credits','{\"research\":100,\"compute\":0}');")?;
        Ok(Self {
            key,
            epoch_key,
            slot_key,
            db: Mutex::new(db),
        })
    }
    pub fn trust(&self) -> Result<FrostArtifactTrustStore> {
        Ok(FrostArtifactTrustStore::new([
            FrostArtifactTrustRoot {
                role: FrostArtifactAuthorityRole::Roster,
                key_id: "cooperative-roster.v1".into(),
                public_key: self.key.public_key(),
            },
            FrostArtifactTrustRoot {
                role: FrostArtifactAuthorityRole::EpochAnchor,
                key_id: "cooperative-epoch.v1".into(),
                public_key: self.epoch_key.public_key(),
            },
            FrostArtifactTrustRoot {
                role: FrostArtifactAuthorityRole::AuthorizationSlotAnchor,
                key_id: "cooperative-slot.v1".into(),
                public_key: self.slot_key.public_key(),
            },
        ])?)
    }
    pub fn read<T: serde::de::DeserializeOwned>(&self, id: &str) -> Result<T> {
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Authority lock failed"))?;
        let value: String =
            db.query_row("SELECT body FROM records WHERE id=?1", [id], |r| r.get(0))?;
        Ok(serde_json::from_str(&value)?)
    }
    pub fn install(&self, public: &Value) -> Result<FrostRosterV1> {
        anyhow::ensure!(
            self.read::<FrostRosterV1>("roster").is_err(),
            "An authority roster is already installed"
        );
        let registration = frost_action_registration(FrostAuthorizationDomain::SettleCommitment)
            .context("Settlement action is not registered")?;
        let shares: std::collections::BTreeMap<String, String> =
            serde_json::from_value(public["verification_shares"].clone())?;
        let now = super::now();
        let mut roster = FrostRosterV1 {
            schema: CHIO_FROST_ROSTER_SCHEMA.into(),
            roster_id: String::new(),
            roster_digest: String::new(),
            authority_scope: registration.quorum_scope.into(),
            scope_id: super::SCOPE.into(),
            allowed_domains: vec![FrostAuthorizationDomain::SettleCommitment],
            key_epoch: 1,
            threshold: registration.quorum_n,
            participant_count: registration.quorum_m,
            participants: shares
                .into_iter()
                .map(|(participant_id, verification_share)| FrostParticipantV1 {
                    participant_id,
                    verification_share,
                })
                .collect(),
            group_public_key: public["group_public_key"]
                .as_str()
                .context("Missing DKG group")?
                .into(),
            suite_id: FROST_ED25519_SHA512_SUITE_ID.into(),
            key_origin: FrostRosterKeyOrigin::DistributedDkg,
            ceremony_transcript_digest: public["transcript_digest"]
                .as_str()
                .context("Missing DKG transcript")?
                .into(),
            predecessor_roster_digest: None,
            valid_from: now.saturating_sub(1),
            valid_until: now + 3600,
            roster_authority_key_id: "cooperative-roster.v1".into(),
            roster_authority_signature: String::new(),
        };
        roster.roster_id = roster.recompute_roster_id()?;
        roster.roster_authority_signature = self.key.sign(&roster.signing_bytes()?).to_hex();
        roster.roster_digest = roster.recompute_roster_digest()?;
        roster.validate_for_active_resolution()?;
        let mut epoch = FrostEpochCheckpointV1 {
            schema: CHIO_FROST_EPOCH_CHECKPOINT_SCHEMA.into(),
            anchor_id: "cooperative-local-authority".into(),
            checkpoint_digest: String::new(),
            scope_id: roster.scope_id.clone(),
            checkpoint_sequence: 1,
            predecessor_digest: None,
            active_roster_id: roster.roster_id.clone(),
            active_roster_digest: roster.roster_digest.clone(),
            key_epoch: roster.key_epoch,
            group_public_key_digest: sha256_hex(&hex::decode(&roster.group_public_key)?),
            rotation_authorization_digest: None,
            activation_fence: 1,
            clock_high_water: now,
            anchor_key_id: "cooperative-epoch.v1".into(),
            anchor_signature: String::new(),
        };
        epoch.anchor_signature = self.epoch_key.sign(&epoch.signing_bytes()?).to_hex();
        epoch.checkpoint_digest = epoch.recompute_checkpoint_digest()?;
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Authority lock failed"))?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO records(id,body) VALUES('roster',?1)",
            [serde_json::to_string(&roster)?],
        )?;
        tx.execute(
            "INSERT INTO records(id,body) VALUES('epoch',?1)",
            [serde_json::to_string(&epoch)?],
        )?;
        tx.commit()?;
        Ok(roster)
    }
    pub fn active(&self) -> Result<VerifiedActiveFrostRoster> {
        Ok(resolve_active_roster_for_execution(
            super::SCOPE,
            self,
            self,
            &self.trust()?,
            super::now(),
        )?)
    }
    fn sign_slot(
        &self,
        mut slot: FrostAuthorizationSlotCheckpointV1,
    ) -> Result<FrostAuthorizationSlotCheckpointV1> {
        slot.anchor_signature = self.slot_key.sign(&slot.signing_bytes()?).to_hex();
        slot.checkpoint_digest = slot.recompute_checkpoint_digest()?;
        Ok(slot)
    }
    pub fn bind(
        &self,
        body: &FrostAuthorizationBodyV1,
    ) -> Result<FrostAuthorizationSlotCheckpointV1> {
        let active = self.active()?;
        let trust = self.trust()?;
        let now = super::now();
        let bind = verify_frost_authorization_slot_bind(body, &active, self, &trust, now)?;
        let id = format!("slot:{}", bind.request().slot_id());
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Authority lock failed"))?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let existing: Option<String> = tx
            .query_row("SELECT body FROM records WHERE id=?1", [&id], |r| r.get(0))
            .optional()?;
        if let Some(existing) = existing {
            let slot: FrostAnchoredAuthorizationSlot = serde_json::from_str(&existing)?;
            anyhow::ensure!(
                slot.checkpoint.authorization_id == body.authorization_id,
                "The resource slot is already bound to another authorization"
            );
            return Ok(slot.checkpoint);
        }
        let slot = self.sign_slot(FrostAuthorizationSlotCheckpointV1 {
            schema: CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SCHEMA.into(),
            anchor_id: "cooperative-local-authority".into(),
            checkpoint_digest: String::new(),
            scope_id: body.scope_id.clone(),
            slot_id: bind.request().slot_id().into(),
            slot_version: 1,
            predecessor_digest: None,
            domain: body.domain,
            ladder_action_class: body.ladder_action_class.clone(),
            resource_id: body.resource_id.clone(),
            resource_version: body.resource_version,
            resource_fence: body.resource_fence,
            authorization_id: body.authorization_id.clone(),
            signing_message_digest: sha256_hex(&body.signing_bytes()?),
            action_digest: body.action_digest.clone(),
            roster_digest: body.roster_digest.clone(),
            key_epoch: body.key_epoch,
            session_id: frost_authorization_session_id(body)?,
            state: FrostAuthorizationSlotState::Bound,
            aggregate_signature_digest: None,
            authorization_blob_digest: None,
            availability_receipt: None,
            clock_high_water: now,
            anchor_key_id: "cooperative-slot.v1".into(),
            anchor_signature: String::new(),
        })?;
        tx.execute(
            "INSERT INTO records(id,body) VALUES(?1,?2)",
            params![
                id,
                serde_json::to_string(&FrostAnchoredAuthorizationSlot {
                    checkpoint: slot.clone(),
                    authorization_blob: None
                })?
            ],
        )?;
        tx.commit()?;
        Ok(slot)
    }
    pub fn complete(&self, proof: &FrostAuthorizationV1) -> Result<()> {
        let bound = self.bind(&proof.body)?;
        if bound.state == FrostAuthorizationSlotState::Completed {
            let current = self.resolve_authorization_slot(super::SCOPE, &bound.slot_id)?;
            anyhow::ensure!(
                current.authorization_blob.as_deref() == Some(proof.canonical_bytes()?.as_slice()),
                "A different proof already completed this slot"
            );
            return Ok(());
        }
        let completion = verify_frost_authorization_slot_completion(
            &bound,
            proof,
            &self.active()?,
            self,
            &self.trust()?,
            format!("retained:{}", proof.body.authorization_id),
            super::now(),
        )?;
        let request = completion.request();
        let completed = self.sign_slot(FrostAuthorizationSlotCheckpointV1 {
            checkpoint_digest: String::new(),
            slot_version: 2,
            predecessor_digest: Some(bound.checkpoint_digest.clone()),
            state: FrostAuthorizationSlotState::Completed,
            aggregate_signature_digest: Some(request.aggregate_signature_digest().into()),
            authorization_blob_digest: Some(request.authorization_blob_digest().into()),
            availability_receipt: Some(request.availability_receipt().into()),
            clock_high_water: request.clock_high_water(),
            anchor_signature: String::new(),
            ..bound.clone()
        })?;
        let anchored = FrostAnchoredAuthorizationSlot {
            checkpoint: completed,
            authorization_blob: Some(request.authorization_blob().to_vec()),
        };
        let id = format!("slot:{}", bound.slot_id);
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Authority lock failed"))?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: String =
            tx.query_row("SELECT body FROM records WHERE id=?1", [&id], |r| r.get(0))?;
        let current: FrostAnchoredAuthorizationSlot = serde_json::from_str(&current)?;
        anyhow::ensure!(
            current.checkpoint.checkpoint_digest == request.expected_bound_checkpoint_digest(),
            "Authorization completion lost its compare-and-swap"
        );
        tx.execute(
            "UPDATE records SET body=?1 WHERE id=?2",
            params![serde_json::to_string(&anchored)?, id],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn state(&self) -> Result<Value> {
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Authority lock failed"))?;
        let credits: String =
            db.query_row("SELECT body FROM records WHERE id='credits'", [], |r| {
                r.get(0)
            })?;
        let count: i64 = db.query_row("SELECT COUNT(*) FROM settlements", [], |r| r.get(0))?;
        Ok(
            json!({"credits":serde_json::from_str::<Value>(&credits)?,"completed_computations":count}),
        )
    }
}
impl ActiveFrostRosterResolver for Anchors {
    fn resolve_active_roster(
        &self,
        scope: &str,
    ) -> std::result::Result<Option<FrostRosterV1>, FrostRosterResolutionError> {
        if scope != super::SCOPE {
            return Ok(None);
        };
        self.read("roster")
            .map(Some)
            .map_err(|e| FrostRosterResolutionError::Unavailable(e.to_string()))
    }
    fn classify_scope(
        &self,
        scope: &str,
    ) -> std::result::Result<Option<String>, FrostRosterResolutionError> {
        Ok(self
            .resolve_active_roster(scope)?
            .map(|r| r.authority_scope))
    }
}
impl FrostEpochAnchor for Anchors {
    fn resolve_epoch_checkpoint(
        &self,
        scope: &str,
    ) -> std::result::Result<FrostEpochCheckpointV1, FrostAnchorError> {
        if scope != super::SCOPE {
            return Err(FrostAnchorError::Unavailable("Scope not served".into()));
        }
        self.read("epoch")
            .map_err(|e| FrostAnchorError::Unavailable(e.to_string()))
    }
}
impl FrostAuthorizationSlotAnchor for Anchors {
    fn resolve_authorization_slot(
        &self,
        scope: &str,
        slot: &str,
    ) -> std::result::Result<FrostAnchoredAuthorizationSlot, FrostAnchorError> {
        if scope != super::SCOPE {
            return Err(FrostAnchorError::Unavailable("Scope not served".into()));
        }
        self.read(&format!("slot:{slot}"))
            .map_err(|e| FrostAnchorError::Unavailable(e.to_string()))
    }
}
