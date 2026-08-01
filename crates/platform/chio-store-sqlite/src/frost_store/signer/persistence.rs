use chio_core::{sha256_hex, StoreMutationFence};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

use super::{
    invalid, signer_projection_key, sqlite_read_u64, sqlite_u64, to_sql_conversion,
    SignerRecordPreimage, StoredSigner, SIGNER_RECORD_PREFIX,
};
use crate::encrypted_blob::EncryptedBlob;
use crate::frost_store::commit::{append_projection_commit, prefixed_digest, ProjectionMutation};
use crate::frost_store::{FrostSignerSessionState, FrostStoreError, SqliteFrostStore};

pub(super) fn insert_signer(
    transaction: &Transaction<'_>,
    stored: &StoredSigner,
) -> Result<(), FrostStoreError> {
    let nonce = stored
        .nonce
        .as_ref()
        .ok_or_else(|| invalid("prepared signer lacks encrypted nonce"))?;
    transaction
        .execute(
            r#"
            INSERT INTO frost_signer_sessions (
                session_id, participant_id, authorization_slot_id, scope_id,
                key_epoch, authorization_id, signing_message_digest, roster_digest,
                coordinator_id, resource_fence, ceremony_id, authorization_body_json,
                bound_checkpoint_digest, bound_checkpoint_json, signer_identifier,
                verification_share, state, state_version, custody_generation, nonce_aad,
                nonce_ciphertext, nonce_nonce, commitment_bytes, commitment_digest,
                signing_package_digest, signature_share, burn_reason, source_store_uuid,
                source_lease_id, source_owner_epoch, created_at_unix_ms,
                updated_at_unix_ms, record_digest
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21,
                ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31,
                ?32, ?33
            )
            "#,
            params![
                &stored.session_id,
                &stored.participant_id,
                &stored.authorization_slot_id,
                &stored.scope_id,
                sqlite_u64(stored.key_epoch, "signer key epoch")?,
                &stored.authorization_id,
                &stored.signing_message_digest,
                &stored.roster_digest,
                &stored.coordinator_id,
                sqlite_u64(stored.resource_fence, "signer resource fence")?,
                &stored.ceremony_id,
                &stored.authorization_body_json,
                &stored.bound_checkpoint_digest,
                &stored.bound_checkpoint_json,
                &stored.signer_identifier,
                &stored.verification_share,
                stored.state.as_str(),
                sqlite_u64(stored.state_version, "signer state version")?,
                &stored.custody_generation,
                &stored.nonce_aad,
                &nonce.ciphertext,
                nonce.nonce.as_slice(),
                &stored.commitment_bytes,
                &stored.commitment_digest,
                stored.signing_package_digest.as_deref(),
                stored.signature_share.as_deref(),
                stored.burn_reason.as_deref(),
                &stored.source_fence.store_uuid,
                &stored.source_fence.lease_id,
                sqlite_u64(stored.source_fence.owner_epoch, "signer owner epoch")?,
                sqlite_u64(stored.created_at_unix_ms, "signer created time")?,
                sqlite_u64(stored.updated_at_unix_ms, "signer updated time")?,
                &stored.record_digest,
            ],
        )
        .map_err(crate::frost_store::sqlite_error)?;
    Ok(())
}

pub(super) fn update_signer(
    transaction: &Transaction<'_>,
    stored: &StoredSigner,
    previous_state: FrostSignerSessionState,
    previous_version: u64,
) -> Result<(), FrostStoreError> {
    let changed = transaction
        .execute(
            r#"
            UPDATE frost_signer_sessions
            SET state = ?1, state_version = ?2, nonce_ciphertext = ?3,
                nonce_nonce = ?4, signing_package_digest = ?5,
                signature_share = ?6, burn_reason = ?7, source_store_uuid = ?8,
                source_lease_id = ?9, source_owner_epoch = ?10,
                updated_at_unix_ms = ?11, record_digest = ?12
            WHERE session_id = ?13 AND participant_id = ?14
              AND state = ?15 AND state_version = ?16
            "#,
            params![
                stored.state.as_str(),
                sqlite_u64(stored.state_version, "signer state version")?,
                stored
                    .nonce
                    .as_ref()
                    .map(|nonce| nonce.ciphertext.as_slice()),
                stored.nonce.as_ref().map(|nonce| nonce.nonce.as_slice()),
                stored.signing_package_digest.as_deref(),
                stored.signature_share.as_deref(),
                stored.burn_reason.as_deref(),
                &stored.source_fence.store_uuid,
                &stored.source_fence.lease_id,
                sqlite_u64(stored.source_fence.owner_epoch, "signer owner epoch")?,
                sqlite_u64(stored.updated_at_unix_ms, "signer updated time")?,
                &stored.record_digest,
                &stored.session_id,
                &stored.participant_id,
                previous_state.as_str(),
                sqlite_u64(previous_version, "previous signer state version")?,
            ],
        )
        .map_err(crate::frost_store::sqlite_error)?;
    if changed != 1 {
        return Err(FrostStoreError::Conflict(
            "signer session changed during transition",
        ));
    }
    Ok(())
}

pub(super) fn append_signer_commit(
    transaction: &Transaction<'_>,
    store: &SqliteFrostStore,
    stored: &StoredSigner,
    mutation_kind: &str,
    fence: &StoreMutationFence,
) -> Result<(), FrostStoreError> {
    append_projection_commit(
        transaction,
        store,
        &signer_projection_key(&stored.session_id, &stored.participant_id),
        ProjectionMutation {
            sequence: stored.state_version,
            projection_type: "signer",
            mutation_kind,
            record_digest: &stored.record_digest,
        },
        fence,
    )
}

pub(super) fn load_signer_by_slot_query(
    connection: &Connection,
    slot_id: &str,
    participant_id: &str,
) -> Result<Option<StoredSigner>, FrostStoreError> {
    connection
        .query_row(
            &format!(
                "{} WHERE authorization_slot_id = ?1 AND participant_id = ?2",
                signer_select()
            ),
            params![slot_id, participant_id],
            stored_signer_from_row,
        )
        .optional()
        .map_err(crate::frost_store::sqlite_error)
}

pub(super) fn load_signer_query(
    connection: &Connection,
    session_id: &str,
    participant_id: &str,
) -> Result<Option<StoredSigner>, FrostStoreError> {
    connection
        .query_row(
            &format!(
                "{} WHERE session_id = ?1 AND participant_id = ?2",
                signer_select()
            ),
            params![session_id, participant_id],
            stored_signer_from_row,
        )
        .optional()
        .map_err(crate::frost_store::sqlite_error)
}

fn signer_select() -> &'static str {
    r#"
    SELECT session_id, participant_id, authorization_slot_id, scope_id,
           key_epoch, authorization_id, signing_message_digest, roster_digest,
           coordinator_id, resource_fence, ceremony_id, authorization_body_json,
           bound_checkpoint_digest, bound_checkpoint_json, signer_identifier,
           verification_share, state, state_version, custody_generation, nonce_aad,
           nonce_ciphertext, nonce_nonce, commitment_bytes, commitment_digest,
           signing_package_digest, signature_share, burn_reason, source_store_uuid,
           source_lease_id, source_owner_epoch, created_at_unix_ms,
           updated_at_unix_ms, record_digest
    FROM frost_signer_sessions
    "#
}

fn stored_signer_from_row(row: &Row<'_>) -> rusqlite::Result<StoredSigner> {
    let nonce_ciphertext = row.get::<_, Option<Vec<u8>>>(20)?;
    let nonce_bytes = row.get::<_, Option<Vec<u8>>>(21)?;
    let nonce = match (nonce_ciphertext, nonce_bytes) {
        (Some(ciphertext), Some(bytes)) => {
            let nonce: [u8; 12] = bytes.as_slice().try_into().map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    21,
                    rusqlite::types::Type::Blob,
                    "invalid FROST signer nonce length".into(),
                )
            })?;
            Some(EncryptedBlob { ciphertext, nonce })
        }
        (None, None) => None,
        _ => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                20,
                rusqlite::types::Type::Blob,
                "partial FROST signer nonce".into(),
            ))
        }
    };
    let state = FrostSignerSessionState::parse(row.get::<_, String>(16)?.as_str())
        .map_err(to_sql_conversion)?;
    Ok(StoredSigner {
        session_id: row.get(0)?,
        participant_id: row.get(1)?,
        authorization_slot_id: row.get(2)?,
        scope_id: row.get(3)?,
        key_epoch: sqlite_read_u64(row, 4)?,
        authorization_id: row.get(5)?,
        signing_message_digest: row.get(6)?,
        roster_digest: row.get(7)?,
        coordinator_id: row.get(8)?,
        resource_fence: sqlite_read_u64(row, 9)?,
        ceremony_id: row.get(10)?,
        authorization_body_json: row.get(11)?,
        bound_checkpoint_digest: row.get(12)?,
        bound_checkpoint_json: row.get(13)?,
        signer_identifier: row.get(14)?,
        verification_share: row.get(15)?,
        state,
        state_version: sqlite_read_u64(row, 17)?,
        custody_generation: row.get(18)?,
        nonce_aad: row.get(19)?,
        nonce,
        commitment_bytes: row.get(22)?,
        commitment_digest: row.get(23)?,
        signing_package_digest: row.get(24)?,
        signature_share: row.get(25)?,
        burn_reason: row.get(26)?,
        source_fence: StoreMutationFence {
            store_uuid: row.get(27)?,
            lease_id: row.get(28)?,
            owner_epoch: sqlite_read_u64(row, 29)?,
        },
        created_at_unix_ms: sqlite_read_u64(row, 30)?,
        updated_at_unix_ms: sqlite_read_u64(row, 31)?,
        record_digest: row.get(32)?,
    })
}

pub(super) fn signer_record_digest(stored: &StoredSigner) -> Result<String, FrostStoreError> {
    prefixed_digest(
        SIGNER_RECORD_PREFIX,
        &SignerRecordPreimage {
            format: "chio.frost.signer-record.v1",
            session_id: &stored.session_id,
            participant_id: &stored.participant_id,
            authorization_slot_id: &stored.authorization_slot_id,
            scope_id: &stored.scope_id,
            key_epoch: stored.key_epoch,
            authorization_id: &stored.authorization_id,
            signing_message_digest: &stored.signing_message_digest,
            roster_digest: &stored.roster_digest,
            coordinator_id: &stored.coordinator_id,
            resource_fence: stored.resource_fence,
            ceremony_id: &stored.ceremony_id,
            authorization_body_json_digest: sha256_hex(&stored.authorization_body_json),
            bound_checkpoint_digest: &stored.bound_checkpoint_digest,
            bound_checkpoint_json_digest: sha256_hex(&stored.bound_checkpoint_json),
            signer_identifier: hex::encode(&stored.signer_identifier),
            verification_share: &stored.verification_share,
            state: stored.state,
            state_version: stored.state_version,
            custody_generation: &stored.custody_generation,
            nonce_aad_digest: sha256_hex(&stored.nonce_aad),
            nonce_ciphertext_digest: stored
                .nonce
                .as_ref()
                .map(|nonce| sha256_hex(&nonce.ciphertext)),
            nonce_nonce: stored.nonce.as_ref().map(|nonce| hex::encode(nonce.nonce)),
            commitment_digest: sha256_hex(&stored.commitment_bytes),
            signing_package_digest: stored.signing_package_digest.as_deref(),
            signature_share_digest: stored.signature_share.as_deref().map(sha256_hex),
            burn_reason: stored.burn_reason.as_deref(),
            source_store_uuid: &stored.source_fence.store_uuid,
            source_lease_id: &stored.source_fence.lease_id,
            source_owner_epoch: stored.source_fence.owner_epoch,
            created_at_unix_ms: stored.created_at_unix_ms,
            updated_at_unix_ms: stored.updated_at_unix_ms,
        },
    )
}
