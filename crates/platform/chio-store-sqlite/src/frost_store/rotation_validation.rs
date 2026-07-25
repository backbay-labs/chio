use std::collections::BTreeMap;

use chio_core::sha256_hex;
use chio_federation::frost::{
    FrostArtifactTrustStore, FrostEpochCheckpointV1, FrostRosterV1, FrostSessionBurnSummaryV1,
    VerifiedFrostEpochAdvance,
};
use rusqlite::{params, Connection};

use super::rotation::{
    canonical_error, invalid, load_active_record, sqlite_u64, trust_error, StoredRotation,
};
use super::FrostStoreError;

pub(super) fn verify_checkpoint_roster(
    roster: &FrostRosterV1,
    checkpoint: &FrostEpochCheckpointV1,
    artifact_trust: &FrostArtifactTrustStore,
    trusted_now: u64,
) -> Result<(), FrostStoreError> {
    artifact_trust.verify_roster(roster).map_err(trust_error)?;
    roster
        .validate_for_active_resolution()
        .map_err(|error| invalid(error.to_string()))?;
    artifact_trust
        .verify_epoch_checkpoint(checkpoint)
        .map_err(trust_error)?;
    let group_key = hex::decode(&roster.group_public_key)
        .map_err(|_| invalid("active roster group key is not hexadecimal"))?;
    if checkpoint.scope_id != roster.scope_id
        || checkpoint.active_roster_id != roster.roster_id
        || checkpoint.active_roster_digest != roster.roster_digest
        || checkpoint.key_epoch != roster.key_epoch
        || checkpoint.group_public_key_digest != sha256_hex(&group_key)
        || trusted_now < checkpoint.clock_high_water
        || trusted_now < roster.valid_from
        || trusted_now >= roster.valid_until
    {
        return Err(FrostStoreError::Conflict(
            "roster and external epoch checkpoint do not match",
        ));
    }
    Ok(())
}

pub(super) fn verify_advance_checkpoint(
    checkpoint: &FrostEpochCheckpointV1,
    advance: &VerifiedFrostEpochAdvance,
    artifact_trust: &FrostArtifactTrustStore,
) -> Result<(), FrostStoreError> {
    artifact_trust
        .verify_epoch_checkpoint(checkpoint)
        .map_err(trust_error)?;
    let target = advance.target_roster();
    let group_key = hex::decode(&target.group_public_key)
        .map_err(|_| invalid("target roster group key is not hexadecimal"))?;
    if checkpoint.scope_id != target.scope_id
        || checkpoint.checkpoint_sequence != advance.expected_checkpoint_sequence()
        || checkpoint.predecessor_digest.as_deref()
            != Some(advance.predecessor().checkpoint_digest.as_str())
        || checkpoint.active_roster_id != target.roster_id
        || checkpoint.active_roster_digest != target.roster_digest
        || checkpoint.key_epoch != target.key_epoch
        || checkpoint.group_public_key_digest != sha256_hex(&group_key)
        || checkpoint.rotation_authorization_digest.as_deref()
            != Some(advance.rotation_authorization_digest())
        || checkpoint.activation_fence != advance.activation_fence()
        || checkpoint.clock_high_water != advance.clock_high_water()
    {
        return Err(FrostStoreError::Conflict(
            "external epoch checkpoint is not the exact verified successor",
        ));
    }
    Ok(())
}

pub(super) fn verify_stored_successor(
    stored: &StoredRotation,
    checkpoint: &FrostEpochCheckpointV1,
    artifact_trust: &FrostArtifactTrustStore,
) -> Result<(), FrostStoreError> {
    artifact_trust
        .verify_epoch_checkpoint(checkpoint)
        .map_err(trust_error)?;
    let target: FrostRosterV1 =
        serde_json::from_slice(&stored.target_roster_json).map_err(canonical_error)?;
    let group_key = hex::decode(&target.group_public_key)
        .map_err(|_| invalid("target roster group key is not hexadecimal"))?;
    if checkpoint.scope_id != stored.scope_id
        || checkpoint.checkpoint_sequence != stored.expected_checkpoint_sequence
        || checkpoint.predecessor_digest.as_deref()
            != Some(stored.predecessor_checkpoint_digest.as_str())
        || checkpoint.active_roster_id != target.roster_id
        || checkpoint.active_roster_digest != stored.target_roster_digest
        || checkpoint.key_epoch != stored.target_key_epoch
        || checkpoint.group_public_key_digest != sha256_hex(&group_key)
        || checkpoint.rotation_authorization_digest.as_deref()
            != Some(stored.rotation_authorization_digest.as_str())
        || checkpoint.activation_fence != stored.activation_fence
        || checkpoint.clock_high_water != stored.clock_high_water
    {
        return Err(FrostStoreError::Conflict(
            "external epoch checkpoint diverges from the durable stage",
        ));
    }
    Ok(())
}

pub(super) fn verify_active_predecessor(
    connection: &Connection,
    advance: &VerifiedFrostEpochAdvance,
) -> Result<(), FrostStoreError> {
    let active = load_active_record(connection, &advance.target_roster().scope_id)?.ok_or(
        FrostStoreError::Conflict("active predecessor roster is absent"),
    )?;
    if active.key_epoch != advance.predecessor().key_epoch
        || active.roster_digest != advance.predecessor().active_roster_digest
        || active.checkpoint_sequence != advance.predecessor().checkpoint_sequence
        || active.checkpoint_digest != advance.predecessor().checkpoint_digest
        || active.activation_fence != advance.predecessor().activation_fence
        || active.clock_high_water != advance.predecessor().clock_high_water
    {
        return Err(FrostStoreError::Conflict(
            "local active roster is not the verified predecessor",
        ));
    }
    Ok(())
}

pub(super) fn verify_completed_ceremony(
    connection: &Connection,
    target: &FrostRosterV1,
) -> Result<(), FrostStoreError> {
    let expected_shares = target
        .participants
        .iter()
        .map(|participant| {
            (
                participant.participant_id.clone(),
                participant.verification_share.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut statement = connection
        .prepare(
            r#"
            SELECT group_public_key, input_transcript_digest,
                   verification_shares_json
            FROM frost_ceremonies
            WHERE scope_id = ?1 AND key_epoch = ?2 AND state = 'completed'
            "#,
        )
        .map_err(super::sqlite_error)?;
    let rows = statement
        .query_map(
            params![
                &target.scope_id,
                sqlite_u64(target.key_epoch, "target key epoch")?
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .map_err(super::sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(super::sqlite_error)?;
    if rows.is_empty() {
        return Err(FrostStoreError::Conflict(
            "target roster has no completed local DKG ceremony",
        ));
    }
    for (group_key, transcript, shares_json) in rows {
        let shares: BTreeMap<String, String> =
            serde_json::from_slice(&shares_json).map_err(canonical_error)?;
        if group_key != target.group_public_key
            || transcript != target.ceremony_transcript_digest
            || shares != expected_shares
        {
            return Err(FrostStoreError::Conflict(
                "target roster does not match the completed DKG ceremony",
            ));
        }
    }
    Ok(())
}

pub(super) fn verify_local_burn_summary(
    connection: &Connection,
    summary: &FrostSessionBurnSummaryV1,
) -> Result<(), FrostStoreError> {
    summary
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    let table_exists = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'frost_signer_sessions')",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(super::sqlite_error)?;
    if !table_exists {
        if summary.burned_session_ids.is_empty() {
            return Ok(());
        }
        return Err(FrostStoreError::Conflict(
            "burn summary names signer sessions absent from this store",
        ));
    }
    let mut statement = connection
        .prepare(
            r#"
            SELECT session_id, state FROM frost_signer_sessions
            WHERE scope_id = ?1 AND key_epoch = ?2
            ORDER BY session_id
            "#,
        )
        .map_err(super::sqlite_error)?;
    let rows = statement
        .query_map(
            params![
                &summary.scope_id,
                sqlite_u64(summary.key_epoch, "burn key epoch")?
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(super::sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(super::sqlite_error)?;
    let burned = signer_burn_tombstones(rows)?;
    if burned != summary.burned_session_ids {
        return Err(FrostStoreError::Conflict(
            "burn summary does not match old-epoch signer tombstones",
        ));
    }
    Ok(())
}

fn signer_burn_tombstones(
    rows: impl IntoIterator<Item = (String, String)>,
) -> Result<Vec<String>, FrostStoreError> {
    let mut sessions = BTreeMap::new();
    for (session_id, state) in rows {
        match state.as_str() {
            "burned" => {
                sessions.insert(session_id, true);
            }
            "completed" => {
                sessions.entry(session_id).or_insert(false);
            }
            _ => {
                return Err(FrostStoreError::Conflict(
                    "live old-epoch signer session remains",
                ))
            }
        }
    }
    let burned = sessions
        .into_iter()
        .filter_map(|(session_id, is_burned)| is_burned.then_some(session_id))
        .collect::<Vec<_>>();
    Ok(burned)
}

pub(super) fn verify_stored_rotation_matches_advance(
    stored: &StoredRotation,
    advance: &VerifiedFrostEpochAdvance,
) -> Result<(), FrostStoreError> {
    if stored.scope_id != advance.target_roster().scope_id
        || stored.predecessor_checkpoint_digest != advance.predecessor().checkpoint_digest
        || stored.target_roster_digest != advance.target_roster().roster_digest
        || stored.target_key_epoch != advance.target_roster().key_epoch
        || stored.rotation_authorization_digest != advance.rotation_authorization_digest()
        || stored.old_session_burn_root != advance.burn_summary().burn_root
        || stored.expected_checkpoint_sequence != advance.expected_checkpoint_sequence()
        || stored.activation_fence != advance.activation_fence()
        || stored.clock_high_water != advance.clock_high_water()
    {
        return Err(FrostStoreError::Conflict(
            "durable rotation stage differs from verified input",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::signer_burn_tombstones;

    #[test]
    fn burn_tombstones_are_unique_per_group_session() {
        let burned = signer_burn_tombstones([
            ("session-a".to_string(), "burned".to_string()),
            ("session-a".to_string(), "burned".to_string()),
            ("session-b".to_string(), "completed".to_string()),
            ("session-b".to_string(), "completed".to_string()),
            ("session-c".to_string(), "completed".to_string()),
            ("session-c".to_string(), "burned".to_string()),
        ])
        .unwrap_or_else(|error| panic!("summarize tombstones: {error}"));
        assert_eq!(burned, ["session-a", "session-c"]);
    }

    #[test]
    fn burn_tombstones_reject_every_live_signer_state() {
        for state in ["prepared", "commitment_published", "share_ready"] {
            assert!(signer_burn_tombstones([
                ("session-a".to_string(), "burned".to_string()),
                ("session-a".to_string(), state.to_string()),
            ])
            .is_err());
        }
    }
}
