use chio_core::canonical::canonical_json_bytes;
use chio_core::{sha256_hex, StoreMutationFence};
use chio_federation::frost::{
    FrostArtifactTrustStore, FrostEpochAnchor, FrostEpochAnchorWriter, FrostEpochCheckpointV1,
    FrostRosterV1, FrostSessionBurnSummaryV1, VerifiedFrostEpochAdvance,
};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use serde::Serialize;

use super::commit::{append_projection_commit, prefixed_digest, ProjectionMutation};
use super::rotation_validation::{
    verify_active_predecessor, verify_advance_checkpoint, verify_checkpoint_roster,
    verify_completed_ceremony, verify_local_burn_summary, verify_stored_rotation_matches_advance,
    verify_stored_successor,
};
use super::{
    FrostActiveRosterRecord, FrostRotationRecord, FrostRotationState, FrostStoreError,
    SqliteFrostStore, StagedFrostRotation,
};

const ROTATION_ID_PREFIX: &[u8] = b"chio.frost.rotation.id.v1\0";
const ROTATION_RECORD_PREFIX: &[u8] = b"chio.frost.rotation-record.digest.v1\0";
const ROSTER_HISTORY_RECORD_PREFIX: &[u8] = b"chio.frost.roster-history.digest.v1\0";

#[derive(Debug, Clone)]
pub(super) struct StoredRotation {
    pub(super) rotation_id: String,
    pub(super) scope_id: String,
    pub(super) state: FrostRotationState,
    pub(super) state_version: u64,
    pub(super) predecessor_checkpoint_digest: String,
    pub(super) predecessor_checkpoint_json: Vec<u8>,
    pub(super) target_roster_digest: String,
    pub(super) target_roster_json: Vec<u8>,
    pub(super) target_key_epoch: u64,
    pub(super) rotation_authorization_digest: String,
    pub(super) burn_summary_json: Vec<u8>,
    pub(super) old_session_burn_root: String,
    pub(super) expected_checkpoint_sequence: u64,
    pub(super) activation_fence: u64,
    pub(super) clock_high_water: u64,
    pub(super) anchored_checkpoint_digest: Option<String>,
    pub(super) anchored_checkpoint_json: Option<Vec<u8>>,
    pub(super) source_fence: StoreMutationFence,
    pub(super) created_at_unix_ms: u64,
    pub(super) updated_at_unix_ms: u64,
    pub(super) record_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RotationIdPreimage<'a> {
    predecessor_checkpoint_digest: &'a str,
    target_roster_digest: &'a str,
    rotation_authorization_digest: &'a str,
    old_session_burn_root: &'a str,
    activation_fence: u64,
    clock_high_water: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RotationRecordPreimage<'a> {
    rotation_id: &'a str,
    scope_id: &'a str,
    state: FrostRotationState,
    state_version: u64,
    predecessor_checkpoint_digest: &'a str,
    predecessor_checkpoint_json_digest: String,
    target_roster_digest: &'a str,
    target_roster_json_digest: String,
    target_key_epoch: u64,
    rotation_authorization_digest: &'a str,
    burn_summary_json_digest: String,
    old_session_burn_root: &'a str,
    expected_checkpoint_sequence: u64,
    activation_fence: u64,
    clock_high_water: u64,
    anchored_checkpoint_digest: Option<&'a str>,
    anchored_checkpoint_json_digest: Option<String>,
    source_store_uuid: &'a str,
    source_lease_id: &'a str,
    source_owner_epoch: u64,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RosterHistoryRecordPreimage<'a> {
    scope_id: &'a str,
    key_epoch: u64,
    roster_id: &'a str,
    roster_digest: &'a str,
    roster_json_digest: String,
    checkpoint_sequence: u64,
    checkpoint_digest: &'a str,
    checkpoint_json_digest: String,
    activation_fence: u64,
    clock_high_water: u64,
    activated_at_unix_ms: u64,
    source_store_uuid: &'a str,
    source_lease_id: &'a str,
    source_owner_epoch: u64,
}

impl SqliteFrostStore {
    pub fn import_active_roster(
        &self,
        roster: &FrostRosterV1,
        checkpoint: &FrostEpochCheckpointV1,
        artifact_trust: &FrostArtifactTrustStore,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostActiveRosterRecord, FrostStoreError> {
        validate_trusted_time(trusted_now_unix_ms)?;
        verify_checkpoint_roster(roster, checkpoint, artifact_trust, trusted_now_unix_ms)?;
        let roster_json = canonical_json_bytes(roster).map_err(canonical_error)?;
        let checkpoint_json = canonical_json_bytes(checkpoint).map_err(canonical_error)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        if let Some(active) = load_active_record(&transaction, &roster.scope_id)? {
            if active.key_epoch == roster.key_epoch
                && active.roster_digest == roster.roster_digest
                && active.checkpoint_digest == checkpoint.checkpoint_digest
            {
                transaction.commit().map_err(super::sqlite_error)?;
                return Ok(active);
            }
            return Err(FrostStoreError::Conflict(
                "active roster already exists and must advance through rotation",
            ));
        }
        insert_roster_history(
            &transaction,
            roster,
            &roster_json,
            checkpoint,
            &checkpoint_json,
            fence,
            trusted_now_unix_ms,
        )?;
        insert_active_pointer(&transaction, roster, checkpoint, fence)?;
        let history_digest = roster_history_record_digest(
            roster,
            &roster_json,
            checkpoint,
            &checkpoint_json,
            fence,
            trusted_now_unix_ms,
        )?;
        append_projection_commit(
            &transaction,
            self,
            &roster_projection_key(&roster.scope_id, roster.key_epoch),
            ProjectionMutation {
                sequence: 1,
                projection_type: "rotation",
                mutation_kind: "frost.roster.import",
                record_digest: &history_digest,
            },
            fence,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(active_record(roster, checkpoint))
    }

    pub fn load_active_roster(
        &self,
        scope_id: &str,
    ) -> Result<Option<(FrostRosterV1, FrostEpochCheckpointV1)>, FrostStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection, None)?;
        let result = load_active_artifacts(&transaction, scope_id)?;
        transaction.commit().map_err(super::sqlite_error)?;
        Ok(result)
    }

    pub fn stage_rotation(
        &self,
        advance: VerifiedFrostEpochAdvance,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<StagedFrostRotation, FrostStoreError> {
        validate_trusted_time(trusted_now_unix_ms)?;
        let rotation_id = rotation_id(&advance)?;
        let predecessor_json =
            canonical_json_bytes(advance.predecessor()).map_err(canonical_error)?;
        let target_roster_json =
            canonical_json_bytes(advance.target_roster()).map_err(canonical_error)?;
        let burn_summary_json =
            canonical_json_bytes(advance.burn_summary()).map_err(canonical_error)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        verify_active_predecessor(&transaction, &advance)?;
        verify_completed_ceremony(&transaction, advance.target_roster())?;
        verify_local_burn_summary(&transaction, advance.burn_summary())?;
        if let Some(stored) = load_rotation_query(&transaction, &rotation_id)? {
            verify_stored_rotation_matches_advance(&stored, &advance)?;
            if stored.state == FrostRotationState::Discarded {
                return Err(FrostStoreError::Conflict(
                    "the exact rotation stage was discarded",
                ));
            }
            transaction.commit().map_err(super::sqlite_error)?;
            return Ok(StagedFrostRotation {
                rotation_id,
                advance,
            });
        }
        let mut stored = StoredRotation {
            rotation_id: rotation_id.clone(),
            scope_id: advance.target_roster().scope_id.clone(),
            state: FrostRotationState::Staged,
            state_version: 1,
            predecessor_checkpoint_digest: advance.predecessor().checkpoint_digest.clone(),
            predecessor_checkpoint_json: predecessor_json,
            target_roster_digest: advance.target_roster().roster_digest.clone(),
            target_roster_json,
            target_key_epoch: advance.target_roster().key_epoch,
            rotation_authorization_digest: advance.rotation_authorization_digest().to_string(),
            burn_summary_json,
            old_session_burn_root: advance.burn_summary().burn_root.clone(),
            expected_checkpoint_sequence: advance.expected_checkpoint_sequence(),
            activation_fence: advance.activation_fence(),
            clock_high_water: advance.clock_high_water(),
            anchored_checkpoint_digest: None,
            anchored_checkpoint_json: None,
            source_fence: fence.clone(),
            created_at_unix_ms: trusted_now_unix_ms,
            updated_at_unix_ms: trusted_now_unix_ms,
            record_digest: String::new(),
        };
        stored.record_digest = rotation_record_digest(&stored)?;
        insert_rotation(&transaction, &stored)?;
        append_projection_commit(
            &transaction,
            self,
            &rotation_projection_key(&rotation_id),
            ProjectionMutation {
                sequence: 1,
                projection_type: "rotation",
                mutation_kind: "frost.rotation.stage",
                record_digest: &stored.record_digest,
            },
            fence,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(StagedFrostRotation {
            rotation_id,
            advance,
        })
    }

    pub fn advance_rotation_anchor(
        &self,
        staged: &StagedFrostRotation,
        anchor: &dyn FrostEpochAnchorWriter,
        artifact_trust: &FrostArtifactTrustStore,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostEpochCheckpointV1, FrostStoreError> {
        validate_trusted_time(trusted_now_unix_ms)?;
        if let Some(checkpoint) = self.persisted_rotation_checkpoint(staged.rotation_id())? {
            verify_advance_checkpoint(&checkpoint, staged.advance(), artifact_trust)?;
            return Ok(checkpoint);
        }
        let checkpoint = match anchor.compare_and_swap_epoch(
            &staged.advance().predecessor().checkpoint_digest,
            staged.advance(),
        ) {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                let reconciled = anchor
                    .resolve_epoch_checkpoint(&staged.advance().target_roster().scope_id)
                    .map_err(|reconcile_error| {
                        FrostStoreError::Unavailable(format!(
                            "FROST epoch CAS failed ({error}); reconciliation failed ({reconcile_error})"
                        ))
                    })?;
                if verify_advance_checkpoint(&reconciled, staged.advance(), artifact_trust).is_err()
                {
                    return Err(FrostStoreError::Unavailable(format!(
                        "FROST epoch CAS failed without an exact anchored successor: {error}"
                    )));
                }
                reconciled
            }
        };
        verify_advance_checkpoint(&checkpoint, staged.advance(), artifact_trust)?;
        self.persist_anchor_advanced(
            staged.rotation_id(),
            &checkpoint,
            fence,
            trusted_now_unix_ms,
        )?;
        Ok(checkpoint)
    }

    pub fn activate_rotation(
        &self,
        rotation_id: &str,
        anchor: &dyn FrostEpochAnchor,
        artifact_trust: &FrostArtifactTrustStore,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostRotationRecord, FrostStoreError> {
        validate_trusted_time(trusted_now_unix_ms)?;
        let stored = self
            .load_stored_rotation(rotation_id)?
            .ok_or(FrostStoreError::Conflict("rotation stage is absent"))?;
        let checkpoint = anchor
            .resolve_epoch_checkpoint(&stored.scope_id)
            .map_err(anchor_error)?;
        verify_stored_successor(&stored, &checkpoint, artifact_trust)?;
        self.activate_with_checkpoint(rotation_id, &checkpoint, fence, trusted_now_unix_ms)
    }

    pub fn recover_rotation(
        &self,
        scope_id: &str,
        anchor: &dyn FrostEpochAnchor,
        artifact_trust: &FrostArtifactTrustStore,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<FrostRotationRecord>, FrostStoreError> {
        validate_trusted_time(trusted_now_unix_ms)?;
        let stored = self.load_live_rotation(scope_id)?;
        let Some(stored) = stored else {
            return Ok(None);
        };
        let checkpoint = anchor
            .resolve_epoch_checkpoint(scope_id)
            .map_err(anchor_error)?;
        artifact_trust
            .verify_epoch_checkpoint(&checkpoint)
            .map_err(trust_error)?;
        if checkpoint.checkpoint_digest == stored.predecessor_checkpoint_digest {
            if stored.state != FrostRotationState::Staged {
                return Err(FrostStoreError::Conflict(
                    "anchor regressed behind an acknowledged rotation",
                ));
            }
            return self
                .discard_rotation(&stored.rotation_id, fence, trusted_now_unix_ms)
                .map(Some);
        }
        verify_stored_successor(&stored, &checkpoint, artifact_trust)?;
        if stored.state == FrostRotationState::Staged {
            self.persist_anchor_advanced(
                &stored.rotation_id,
                &checkpoint,
                fence,
                trusted_now_unix_ms,
            )?;
        }
        self.activate_with_checkpoint(&stored.rotation_id, &checkpoint, fence, trusted_now_unix_ms)
            .map(Some)
    }

    pub fn load_rotation(
        &self,
        rotation_id: &str,
    ) -> Result<Option<FrostRotationRecord>, FrostStoreError> {
        self.load_stored_rotation(rotation_id)
            .map(|stored| stored.map(|value| public_rotation_record(&value)))
    }

    fn persisted_rotation_checkpoint(
        &self,
        rotation_id: &str,
    ) -> Result<Option<FrostEpochCheckpointV1>, FrostStoreError> {
        let stored = self.load_stored_rotation(rotation_id)?;
        let Some(stored) = stored else {
            return Err(FrostStoreError::Conflict("rotation stage is absent"));
        };
        if stored.state == FrostRotationState::Discarded {
            return Err(FrostStoreError::Conflict("rotation stage was discarded"));
        }
        stored
            .anchored_checkpoint_json
            .map(|json| serde_json::from_slice(&json).map_err(canonical_error))
            .transpose()
    }

    fn persist_anchor_advanced(
        &self,
        rotation_id: &str,
        checkpoint: &FrostEpochCheckpointV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(), FrostStoreError> {
        let checkpoint_json = canonical_json_bytes(checkpoint).map_err(canonical_error)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        let mut stored = load_rotation_query(&transaction, rotation_id)?
            .ok_or(FrostStoreError::Conflict("rotation stage is absent"))?;
        if stored.state == FrostRotationState::AnchorAdvanced
            || stored.state == FrostRotationState::Active
        {
            if stored.anchored_checkpoint_digest.as_deref()
                != Some(checkpoint.checkpoint_digest.as_str())
            {
                return Err(FrostStoreError::Conflict(
                    "rotation retained another anchored checkpoint",
                ));
            }
            transaction.commit().map_err(super::sqlite_error)?;
            return Ok(());
        }
        if stored.state != FrostRotationState::Staged {
            return Err(FrostStoreError::Conflict("rotation stage is not live"));
        }
        stored.state = FrostRotationState::AnchorAdvanced;
        stored.state_version = 2;
        stored.anchored_checkpoint_digest = Some(checkpoint.checkpoint_digest.clone());
        stored.anchored_checkpoint_json = Some(checkpoint_json);
        stored.source_fence = fence.clone();
        stored.updated_at_unix_ms = trusted_now_unix_ms;
        stored.record_digest = rotation_record_digest(&stored)?;
        update_rotation(&transaction, &stored, FrostRotationState::Staged)?;
        append_projection_commit(
            &transaction,
            self,
            &rotation_projection_key(rotation_id),
            ProjectionMutation {
                sequence: 2,
                projection_type: "rotation",
                mutation_kind: "frost.rotation.anchor_advanced",
                record_digest: &stored.record_digest,
            },
            fence,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)
    }

    fn activate_with_checkpoint(
        &self,
        rotation_id: &str,
        checkpoint: &FrostEpochCheckpointV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostRotationRecord, FrostStoreError> {
        let checkpoint_json = canonical_json_bytes(checkpoint).map_err(canonical_error)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        let mut stored = load_rotation_query(&transaction, rotation_id)?
            .ok_or(FrostStoreError::Conflict("rotation stage is absent"))?;
        if stored.state == FrostRotationState::Active {
            if stored.anchored_checkpoint_digest.as_deref()
                != Some(checkpoint.checkpoint_digest.as_str())
            {
                return Err(FrostStoreError::Conflict(
                    "active rotation retained another checkpoint",
                ));
            }
            transaction.commit().map_err(super::sqlite_error)?;
            return Ok(public_rotation_record(&stored));
        }
        if stored.state != FrostRotationState::AnchorAdvanced {
            return Err(FrostStoreError::Conflict(
                "rotation anchor has not been durably acknowledged",
            ));
        }
        let target: FrostRosterV1 =
            serde_json::from_slice(&stored.target_roster_json).map_err(canonical_error)?;
        let burn: FrostSessionBurnSummaryV1 =
            serde_json::from_slice(&stored.burn_summary_json).map_err(canonical_error)?;
        verify_local_burn_summary(&transaction, &burn)?;
        let predecessor_key_epoch =
            target
                .key_epoch
                .checked_sub(1)
                .ok_or(FrostStoreError::Conflict(
                    "target roster key epoch has no predecessor",
                ))?;
        insert_roster_history(
            &transaction,
            &target,
            &stored.target_roster_json,
            checkpoint,
            &checkpoint_json,
            fence,
            trusted_now_unix_ms,
        )?;
        let changed = transaction
            .execute(
                r#"
                UPDATE frost_active_rosters
                SET key_epoch = ?1, roster_digest = ?2,
                    checkpoint_sequence = ?3, checkpoint_digest = ?4,
                    activation_fence = ?5, clock_high_water = ?6,
                    source_store_uuid = ?7, source_lease_id = ?8,
                    source_owner_epoch = ?9
                WHERE scope_id = ?10 AND key_epoch = ?11
                  AND checkpoint_digest = ?12
                "#,
                params![
                    sqlite_u64(target.key_epoch, "target key epoch")?,
                    &target.roster_digest,
                    sqlite_u64(checkpoint.checkpoint_sequence, "checkpoint sequence")?,
                    &checkpoint.checkpoint_digest,
                    sqlite_u64(checkpoint.activation_fence, "activation fence")?,
                    sqlite_u64(checkpoint.clock_high_water, "clock high-water")?,
                    &fence.store_uuid,
                    &fence.lease_id,
                    sqlite_u64(fence.owner_epoch, "source owner epoch")?,
                    &target.scope_id,
                    sqlite_u64(predecessor_key_epoch, "predecessor key epoch")?,
                    &stored.predecessor_checkpoint_digest,
                ],
            )
            .map_err(super::sqlite_error)?;
        if changed != 1 {
            return Err(FrostStoreError::Conflict(
                "active roster changed after rotation staging",
            ));
        }
        stored.state = FrostRotationState::Active;
        stored.state_version = 3;
        stored.anchored_checkpoint_digest = Some(checkpoint.checkpoint_digest.clone());
        stored.anchored_checkpoint_json = Some(checkpoint_json);
        stored.source_fence = fence.clone();
        stored.updated_at_unix_ms = trusted_now_unix_ms;
        stored.record_digest = rotation_record_digest(&stored)?;
        update_rotation(&transaction, &stored, FrostRotationState::AnchorAdvanced)?;
        append_projection_commit(
            &transaction,
            self,
            &rotation_projection_key(rotation_id),
            ProjectionMutation {
                sequence: 3,
                projection_type: "rotation",
                mutation_kind: "frost.rotation.activate",
                record_digest: &stored.record_digest,
            },
            fence,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(public_rotation_record(&stored))
    }

    fn discard_rotation(
        &self,
        rotation_id: &str,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<FrostRotationRecord, FrostStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        let mut stored = load_rotation_query(&transaction, rotation_id)?
            .ok_or(FrostStoreError::Conflict("rotation stage is absent"))?;
        if stored.state == FrostRotationState::Discarded {
            transaction.commit().map_err(super::sqlite_error)?;
            return Ok(public_rotation_record(&stored));
        }
        if stored.state != FrostRotationState::Staged {
            return Err(FrostStoreError::Conflict(
                "only an unanchored stage may be discarded",
            ));
        }
        stored.state = FrostRotationState::Discarded;
        stored.state_version = 2;
        stored.source_fence = fence.clone();
        stored.updated_at_unix_ms = trusted_now_unix_ms;
        stored.record_digest = rotation_record_digest(&stored)?;
        update_rotation(&transaction, &stored, FrostRotationState::Staged)?;
        append_projection_commit(
            &transaction,
            self,
            &rotation_projection_key(rotation_id),
            ProjectionMutation {
                sequence: 2,
                projection_type: "rotation",
                mutation_kind: "frost.rotation.discard",
                record_digest: &stored.record_digest,
            },
            fence,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(public_rotation_record(&stored))
    }

    fn load_stored_rotation(
        &self,
        rotation_id: &str,
    ) -> Result<Option<StoredRotation>, FrostStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection, None)?;
        let stored = load_rotation_query(&transaction, rotation_id)?;
        transaction.commit().map_err(super::sqlite_error)?;
        Ok(stored)
    }

    fn load_live_rotation(
        &self,
        scope_id: &str,
    ) -> Result<Option<StoredRotation>, FrostStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection, None)?;
        let rotation_id = transaction
            .query_row(
                r#"
                SELECT rotation_id FROM frost_roster_rotations
                WHERE scope_id = ?1 AND state IN ('staged', 'anchor_advanced')
                "#,
                [scope_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(super::sqlite_error)?;
        let stored = rotation_id
            .as_deref()
            .map(|id| load_rotation_query(&transaction, id))
            .transpose()?
            .flatten();
        transaction.commit().map_err(super::sqlite_error)?;
        Ok(stored)
    }
}

pub(super) fn verify_rotation_invariants(connection: &Connection) -> Result<(), FrostStoreError> {
    let mut statement = connection
        .prepare("SELECT rotation_id FROM frost_roster_rotations ORDER BY rotation_id")
        .map_err(super::sqlite_error)?;
    let ids = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(super::sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(super::sqlite_error)?;
    drop(statement);
    for id in ids {
        let stored = load_rotation_query(connection, &id)?
            .ok_or_else(|| invalid("rotation disappeared during verification"))?;
        if rotation_record_digest(&stored)? != stored.record_digest {
            return Err(invalid("FROST rotation record digest is invalid"));
        }
        let latest = connection
            .query_row(
                r#"
                SELECT projection_sequence, record_digest
                FROM frost_projection_commits
                WHERE projection_key = ?1
                ORDER BY projection_sequence DESC LIMIT 1
                "#,
                [rotation_projection_key(&id)],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(super::sqlite_error)?
            .ok_or_else(|| invalid("rotation has no projection commit"))?;
        if read_u64(latest.0, "rotation projection sequence")? != stored.state_version
            || latest.1 != stored.record_digest
        {
            return Err(invalid("rotation does not match its projection head"));
        }
    }
    verify_active_roster_invariants(connection)
}

fn verify_active_roster_invariants(connection: &Connection) -> Result<(), FrostStoreError> {
    let mut statement = connection
        .prepare("SELECT scope_id FROM frost_active_rosters ORDER BY scope_id")
        .map_err(super::sqlite_error)?;
    let scopes = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(super::sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(super::sqlite_error)?;
    drop(statement);
    for scope in scopes {
        let (roster, checkpoint) = load_active_artifacts(connection, &scope)?
            .ok_or_else(|| invalid("active roster history is absent"))?;
        let active = load_active_record(connection, &scope)?
            .ok_or_else(|| invalid("active roster pointer disappeared"))?;
        if active != active_record(&roster, &checkpoint) {
            return Err(invalid("active roster pointer diverges from history"));
        }
    }
    Ok(())
}

fn insert_roster_history(
    transaction: &Transaction<'_>,
    roster: &FrostRosterV1,
    roster_json: &[u8],
    checkpoint: &FrostEpochCheckpointV1,
    checkpoint_json: &[u8],
    fence: &StoreMutationFence,
    activated_at_unix_ms: u64,
) -> Result<(), FrostStoreError> {
    let digest = roster_history_record_digest(
        roster,
        roster_json,
        checkpoint,
        checkpoint_json,
        fence,
        activated_at_unix_ms,
    )?;
    transaction
        .execute(
            r#"
            INSERT INTO frost_roster_history (
                scope_id, key_epoch, roster_id, roster_digest, roster_json,
                checkpoint_sequence, checkpoint_digest, checkpoint_json,
                activation_fence, clock_high_water, activated_at_unix_ms,
                source_store_uuid, source_lease_id, source_owner_epoch,
                record_digest
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, ?14, ?15
            )
            "#,
            params![
                &roster.scope_id,
                sqlite_u64(roster.key_epoch, "roster key epoch")?,
                &roster.roster_id,
                &roster.roster_digest,
                roster_json,
                sqlite_u64(checkpoint.checkpoint_sequence, "checkpoint sequence")?,
                &checkpoint.checkpoint_digest,
                checkpoint_json,
                sqlite_u64(checkpoint.activation_fence, "activation fence")?,
                sqlite_u64(checkpoint.clock_high_water, "clock high-water")?,
                sqlite_u64(activated_at_unix_ms, "activation time")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_u64(fence.owner_epoch, "source owner epoch")?,
                digest,
            ],
        )
        .map_err(super::sqlite_error)?;
    Ok(())
}

fn insert_active_pointer(
    transaction: &Transaction<'_>,
    roster: &FrostRosterV1,
    checkpoint: &FrostEpochCheckpointV1,
    fence: &StoreMutationFence,
) -> Result<(), FrostStoreError> {
    transaction
        .execute(
            r#"
            INSERT INTO frost_active_rosters (
                scope_id, key_epoch, roster_digest, checkpoint_sequence,
                checkpoint_digest, activation_fence, clock_high_water,
                source_store_uuid, source_lease_id, source_owner_epoch
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            params![
                &roster.scope_id,
                sqlite_u64(roster.key_epoch, "roster key epoch")?,
                &roster.roster_digest,
                sqlite_u64(checkpoint.checkpoint_sequence, "checkpoint sequence")?,
                &checkpoint.checkpoint_digest,
                sqlite_u64(checkpoint.activation_fence, "activation fence")?,
                sqlite_u64(checkpoint.clock_high_water, "clock high-water")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_u64(fence.owner_epoch, "source owner epoch")?,
            ],
        )
        .map_err(super::sqlite_error)?;
    Ok(())
}

fn insert_rotation(
    transaction: &Transaction<'_>,
    stored: &StoredRotation,
) -> Result<(), FrostStoreError> {
    transaction
        .execute(
            r#"
            INSERT INTO frost_roster_rotations (
                rotation_id, scope_id, state, state_version,
                predecessor_checkpoint_digest, predecessor_checkpoint_json,
                target_roster_digest, target_roster_json, target_key_epoch,
                rotation_authorization_digest, burn_summary_json,
                old_session_burn_root, expected_checkpoint_sequence,
                activation_fence, clock_high_water,
                anchored_checkpoint_digest, anchored_checkpoint_json,
                source_store_uuid, source_lease_id, source_owner_epoch,
                created_at_unix_ms, updated_at_unix_ms, record_digest
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23
            )
            "#,
            rusqlite::params_from_iter(rotation_params(stored)?),
        )
        .map_err(super::sqlite_error)?;
    Ok(())
}

fn update_rotation(
    transaction: &Transaction<'_>,
    stored: &StoredRotation,
    expected_state: FrostRotationState,
) -> Result<(), FrostStoreError> {
    let changed = transaction
        .execute(
            r#"
            UPDATE frost_roster_rotations
            SET state = ?1, state_version = ?2,
                anchored_checkpoint_digest = ?3, anchored_checkpoint_json = ?4,
                source_store_uuid = ?5, source_lease_id = ?6,
                source_owner_epoch = ?7, updated_at_unix_ms = ?8,
                record_digest = ?9
            WHERE rotation_id = ?10 AND state = ?11
            "#,
            params![
                stored.state.as_str(),
                sqlite_u64(stored.state_version, "rotation state version")?,
                stored.anchored_checkpoint_digest.as_deref(),
                stored.anchored_checkpoint_json.as_deref(),
                &stored.source_fence.store_uuid,
                &stored.source_fence.lease_id,
                sqlite_u64(stored.source_fence.owner_epoch, "source owner epoch")?,
                sqlite_u64(stored.updated_at_unix_ms, "rotation updated time")?,
                &stored.record_digest,
                &stored.rotation_id,
                expected_state.as_str(),
            ],
        )
        .map_err(super::sqlite_error)?;
    if changed != 1 {
        return Err(FrostStoreError::Conflict(
            "rotation state changed concurrently",
        ));
    }
    Ok(())
}

fn rotation_params(
    stored: &StoredRotation,
) -> Result<Vec<rusqlite::types::Value>, FrostStoreError> {
    use rusqlite::types::Value;
    Ok(vec![
        Value::Text(stored.rotation_id.clone()),
        Value::Text(stored.scope_id.clone()),
        Value::Text(stored.state.as_str().to_string()),
        Value::Integer(sqlite_u64(stored.state_version, "rotation state version")?),
        Value::Text(stored.predecessor_checkpoint_digest.clone()),
        Value::Blob(stored.predecessor_checkpoint_json.clone()),
        Value::Text(stored.target_roster_digest.clone()),
        Value::Blob(stored.target_roster_json.clone()),
        Value::Integer(sqlite_u64(stored.target_key_epoch, "target key epoch")?),
        Value::Text(stored.rotation_authorization_digest.clone()),
        Value::Blob(stored.burn_summary_json.clone()),
        Value::Text(stored.old_session_burn_root.clone()),
        Value::Integer(sqlite_u64(
            stored.expected_checkpoint_sequence,
            "expected checkpoint sequence",
        )?),
        Value::Integer(sqlite_u64(stored.activation_fence, "activation fence")?),
        Value::Integer(sqlite_u64(stored.clock_high_water, "clock high-water")?),
        stored
            .anchored_checkpoint_digest
            .clone()
            .map_or(Value::Null, Value::Text),
        stored
            .anchored_checkpoint_json
            .clone()
            .map_or(Value::Null, Value::Blob),
        Value::Text(stored.source_fence.store_uuid.clone()),
        Value::Text(stored.source_fence.lease_id.clone()),
        Value::Integer(sqlite_u64(
            stored.source_fence.owner_epoch,
            "source owner epoch",
        )?),
        Value::Integer(sqlite_u64(
            stored.created_at_unix_ms,
            "rotation created time",
        )?),
        Value::Integer(sqlite_u64(
            stored.updated_at_unix_ms,
            "rotation updated time",
        )?),
        Value::Text(stored.record_digest.clone()),
    ])
}

fn load_rotation_query(
    connection: &Connection,
    rotation_id: &str,
) -> Result<Option<StoredRotation>, FrostStoreError> {
    connection
        .query_row(
            r#"
            SELECT rotation_id, scope_id, state, state_version,
                   predecessor_checkpoint_digest, predecessor_checkpoint_json,
                   target_roster_digest, target_roster_json, target_key_epoch,
                   rotation_authorization_digest, burn_summary_json,
                   old_session_burn_root, expected_checkpoint_sequence,
                   activation_fence, clock_high_water,
                   anchored_checkpoint_digest, anchored_checkpoint_json,
                   source_store_uuid, source_lease_id, source_owner_epoch,
                   created_at_unix_ms, updated_at_unix_ms, record_digest
            FROM frost_roster_rotations WHERE rotation_id = ?1
            "#,
            [rotation_id],
            read_rotation_row,
        )
        .optional()
        .map_err(super::sqlite_error)
}

fn read_rotation_row(row: &Row<'_>) -> Result<StoredRotation, rusqlite::Error> {
    let state_value: String = row.get(2)?;
    let state = FrostRotationState::parse(&state_value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, error.into())
    })?;
    Ok(StoredRotation {
        rotation_id: row.get(0)?,
        scope_id: row.get(1)?,
        state,
        state_version: sqlite_read_u64(row, 3)?,
        predecessor_checkpoint_digest: row.get(4)?,
        predecessor_checkpoint_json: row.get(5)?,
        target_roster_digest: row.get(6)?,
        target_roster_json: row.get(7)?,
        target_key_epoch: sqlite_read_u64(row, 8)?,
        rotation_authorization_digest: row.get(9)?,
        burn_summary_json: row.get(10)?,
        old_session_burn_root: row.get(11)?,
        expected_checkpoint_sequence: sqlite_read_u64(row, 12)?,
        activation_fence: sqlite_read_u64(row, 13)?,
        clock_high_water: sqlite_read_u64(row, 14)?,
        anchored_checkpoint_digest: row.get(15)?,
        anchored_checkpoint_json: row.get(16)?,
        source_fence: StoreMutationFence {
            store_uuid: row.get(17)?,
            lease_id: row.get(18)?,
            owner_epoch: sqlite_read_u64(row, 19)?,
        },
        created_at_unix_ms: sqlite_read_u64(row, 20)?,
        updated_at_unix_ms: sqlite_read_u64(row, 21)?,
        record_digest: row.get(22)?,
    })
}

pub(super) fn load_active_record(
    connection: &Connection,
    scope_id: &str,
) -> Result<Option<FrostActiveRosterRecord>, FrostStoreError> {
    connection
        .query_row(
            r#"
            SELECT scope_id, key_epoch, roster_digest, checkpoint_sequence,
                   checkpoint_digest, activation_fence, clock_high_water
            FROM frost_active_rosters WHERE scope_id = ?1
            "#,
            [scope_id],
            |row| {
                Ok(FrostActiveRosterRecord {
                    scope_id: row.get(0)?,
                    key_epoch: sqlite_read_u64(row, 1)?,
                    roster_digest: row.get(2)?,
                    checkpoint_sequence: sqlite_read_u64(row, 3)?,
                    checkpoint_digest: row.get(4)?,
                    activation_fence: sqlite_read_u64(row, 5)?,
                    clock_high_water: sqlite_read_u64(row, 6)?,
                })
            },
        )
        .optional()
        .map_err(super::sqlite_error)
}

fn load_active_artifacts(
    connection: &Connection,
    scope_id: &str,
) -> Result<Option<(FrostRosterV1, FrostEpochCheckpointV1)>, FrostStoreError> {
    let values = connection
        .query_row(
            r#"
            SELECT history.roster_json, history.checkpoint_json
            FROM frost_active_rosters AS active
            JOIN frost_roster_history AS history
              ON history.scope_id = active.scope_id
             AND history.key_epoch = active.key_epoch
             AND history.roster_digest = active.roster_digest
             AND history.checkpoint_digest = active.checkpoint_digest
            WHERE active.scope_id = ?1
            "#,
            [scope_id],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(super::sqlite_error)?;
    values
        .map(|(roster, checkpoint)| {
            Ok((
                serde_json::from_slice(&roster).map_err(canonical_error)?,
                serde_json::from_slice(&checkpoint).map_err(canonical_error)?,
            ))
        })
        .transpose()
}

fn rotation_id(advance: &VerifiedFrostEpochAdvance) -> Result<String, FrostStoreError> {
    prefixed_digest(
        ROTATION_ID_PREFIX,
        &RotationIdPreimage {
            predecessor_checkpoint_digest: &advance.predecessor().checkpoint_digest,
            target_roster_digest: &advance.target_roster().roster_digest,
            rotation_authorization_digest: advance.rotation_authorization_digest(),
            old_session_burn_root: &advance.burn_summary().burn_root,
            activation_fence: advance.activation_fence(),
            clock_high_water: advance.clock_high_water(),
        },
    )
}

fn rotation_record_digest(stored: &StoredRotation) -> Result<String, FrostStoreError> {
    prefixed_digest(
        ROTATION_RECORD_PREFIX,
        &RotationRecordPreimage {
            rotation_id: &stored.rotation_id,
            scope_id: &stored.scope_id,
            state: stored.state,
            state_version: stored.state_version,
            predecessor_checkpoint_digest: &stored.predecessor_checkpoint_digest,
            predecessor_checkpoint_json_digest: sha256_hex(&stored.predecessor_checkpoint_json),
            target_roster_digest: &stored.target_roster_digest,
            target_roster_json_digest: sha256_hex(&stored.target_roster_json),
            target_key_epoch: stored.target_key_epoch,
            rotation_authorization_digest: &stored.rotation_authorization_digest,
            burn_summary_json_digest: sha256_hex(&stored.burn_summary_json),
            old_session_burn_root: &stored.old_session_burn_root,
            expected_checkpoint_sequence: stored.expected_checkpoint_sequence,
            activation_fence: stored.activation_fence,
            clock_high_water: stored.clock_high_water,
            anchored_checkpoint_digest: stored.anchored_checkpoint_digest.as_deref(),
            anchored_checkpoint_json_digest: stored
                .anchored_checkpoint_json
                .as_deref()
                .map(sha256_hex),
            source_store_uuid: &stored.source_fence.store_uuid,
            source_lease_id: &stored.source_fence.lease_id,
            source_owner_epoch: stored.source_fence.owner_epoch,
            created_at_unix_ms: stored.created_at_unix_ms,
            updated_at_unix_ms: stored.updated_at_unix_ms,
        },
    )
}

fn roster_history_record_digest(
    roster: &FrostRosterV1,
    roster_json: &[u8],
    checkpoint: &FrostEpochCheckpointV1,
    checkpoint_json: &[u8],
    fence: &StoreMutationFence,
    activated_at_unix_ms: u64,
) -> Result<String, FrostStoreError> {
    prefixed_digest(
        ROSTER_HISTORY_RECORD_PREFIX,
        &RosterHistoryRecordPreimage {
            scope_id: &roster.scope_id,
            key_epoch: roster.key_epoch,
            roster_id: &roster.roster_id,
            roster_digest: &roster.roster_digest,
            roster_json_digest: sha256_hex(roster_json),
            checkpoint_sequence: checkpoint.checkpoint_sequence,
            checkpoint_digest: &checkpoint.checkpoint_digest,
            checkpoint_json_digest: sha256_hex(checkpoint_json),
            activation_fence: checkpoint.activation_fence,
            clock_high_water: checkpoint.clock_high_water,
            activated_at_unix_ms,
            source_store_uuid: &fence.store_uuid,
            source_lease_id: &fence.lease_id,
            source_owner_epoch: fence.owner_epoch,
        },
    )
}

fn active_record(
    roster: &FrostRosterV1,
    checkpoint: &FrostEpochCheckpointV1,
) -> FrostActiveRosterRecord {
    FrostActiveRosterRecord {
        scope_id: roster.scope_id.clone(),
        key_epoch: roster.key_epoch,
        roster_digest: roster.roster_digest.clone(),
        checkpoint_sequence: checkpoint.checkpoint_sequence,
        checkpoint_digest: checkpoint.checkpoint_digest.clone(),
        activation_fence: checkpoint.activation_fence,
        clock_high_water: checkpoint.clock_high_water,
    }
}

fn public_rotation_record(stored: &StoredRotation) -> FrostRotationRecord {
    FrostRotationRecord {
        rotation_id: stored.rotation_id.clone(),
        scope_id: stored.scope_id.clone(),
        state: stored.state,
        state_version: stored.state_version,
        predecessor_checkpoint_digest: stored.predecessor_checkpoint_digest.clone(),
        target_roster_digest: stored.target_roster_digest.clone(),
        target_key_epoch: stored.target_key_epoch,
        anchored_checkpoint_digest: stored.anchored_checkpoint_digest.clone(),
    }
}

fn roster_projection_key(scope_id: &str, key_epoch: u64) -> String {
    format!("roster/{scope_id}/{key_epoch}")
}

fn rotation_projection_key(rotation_id: &str) -> String {
    format!("rotation/{rotation_id}")
}

fn validate_trusted_time(value: u64) -> Result<(), FrostStoreError> {
    if value == 0 || i64::try_from(value).is_err() {
        return Err(FrostStoreError::Conflict(
            "trusted time is outside the SQLite range",
        ));
    }
    Ok(())
}

fn sqlite_read_u64(row: &Row<'_>, index: usize) -> Result<u64, rusqlite::Error> {
    let value = row.get::<_, i64>(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

pub(super) fn sqlite_u64(value: u64, field: &'static str) -> Result<i64, FrostStoreError> {
    i64::try_from(value)
        .map_err(|_| FrostStoreError::InvalidState(format!("{field} exceeds SQLite range")))
}

fn read_u64(value: i64, field: &'static str) -> Result<u64, FrostStoreError> {
    u64::try_from(value).map_err(|_| FrostStoreError::InvalidState(format!("{field} is negative")))
}

pub(super) fn canonical_error(error: impl std::fmt::Display) -> FrostStoreError {
    FrostStoreError::InvalidState(error.to_string())
}

pub(super) fn trust_error(error: impl std::fmt::Display) -> FrostStoreError {
    FrostStoreError::InvalidState(format!("FROST artifact trust failed: {error}"))
}

fn anchor_error(error: impl std::fmt::Display) -> FrostStoreError {
    FrostStoreError::Unavailable(format!("FROST epoch anchor failed: {error}"))
}

pub(super) fn invalid(detail: impl Into<String>) -> FrostStoreError {
    FrostStoreError::InvalidState(detail.into())
}
