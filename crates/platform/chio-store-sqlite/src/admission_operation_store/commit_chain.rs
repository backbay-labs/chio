use chio_core::canonical::canonical_json_bytes;
use chio_core::sha256_hex;
use chio_kernel::admission_operation::{
    AdmissionOperationStoreError, AdmissionOperationV1, UntrustedAdmissionRecoveryClaim,
};
use rusqlite::{params, Connection, Row, Transaction};
use serde::Serialize;

use crate::serving_owner::SqliteServingOwner;

use super::{
    invariant, recovery_claim_digest, sqlite_error, sqlite_i64, stored_u64, validate_trusted_time,
};

pub(crate) const GENESIS_CHAIN_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionCommitHead {
    pub(crate) head_sequence: u64,
    pub(crate) chain_digest: String,
    pub(crate) trusted_time_high_water_unix_ms: u64,
}

#[derive(Serialize)]
struct ChainEntry<'a> {
    format: &'static str,
    previous_chain_digest: &'a str,
    commit_sequence: u64,
    operation_id: &'a str,
    operation_version: u64,
    mutation_kind: &'a str,
    operation_digest: &'a str,
    recovery_claim_digest: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    participant_digest: Option<&'a str>,
    store_uuid: &'a str,
    store_lease_id: &'a str,
    store_owner_epoch: u64,
    recorded_at_unix_ms: u64,
}

struct CommitRow {
    sequence: u64,
    operation_id: String,
    operation_version: u64,
    mutation_kind: String,
    operation_digest: String,
    recovery_claim_digest: Option<String>,
    participant_digest: Option<String>,
    previous_chain_digest: String,
    chain_digest: String,
    store_uuid: String,
    store_lease_id: String,
    store_owner_epoch: u64,
    recorded_at_unix_ms: u64,
}

pub(super) fn append_operation_commit(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    encoded: &[u8],
    recovery_claim: Option<&UntrustedAdmissionRecoveryClaim>,
    mutation_kind: &'static str,
    owner: &SqliteServingOwner,
    recorded_at_unix_ms: u64,
) -> Result<(), AdmissionOperationStoreError> {
    append_operation_commit_with_participant(
        transaction,
        operation,
        encoded,
        recovery_claim,
        mutation_kind,
        None,
        owner,
        recorded_at_unix_ms,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn append_operation_commit_with_participant(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    encoded: &[u8],
    recovery_claim: Option<&UntrustedAdmissionRecoveryClaim>,
    mutation_kind: &'static str,
    participant_digest: Option<&str>,
    owner: &SqliteServingOwner,
    recorded_at_unix_ms: u64,
) -> Result<(), AdmissionOperationStoreError> {
    if participant_digest.is_some_and(|digest| !is_digest(digest)) {
        return Err(invariant("admission participant digest is malformed"));
    }
    let current = load_admission_commit_head(transaction)?;
    validate_trusted_time(recorded_at_unix_ms, "recorded_at_unix_ms")?;
    if recorded_at_unix_ms < current.trusted_time_high_water_unix_ms {
        return Err(invariant("trusted admission operation time regressed"));
    }
    let next = current
        .head_sequence
        .checked_add(1)
        .ok_or_else(|| invariant("admission operation commit sequence overflow"))?;
    let operation_digest = sha256_hex(encoded);
    let claim_digest = recovery_claim.map(recovery_claim_digest).transpose()?;
    let chain_digest = chain_digest(&ChainEntry {
        format: "chio.admission-operation-commit-chain.v1",
        previous_chain_digest: &current.chain_digest,
        commit_sequence: next,
        operation_id: operation.binding().operation_id().as_str(),
        operation_version: operation.version(),
        mutation_kind,
        operation_digest: &operation_digest,
        recovery_claim_digest: claim_digest.as_deref(),
        participant_digest,
        store_uuid: &owner.fence.store_uuid,
        store_lease_id: &owner.fence.lease_id,
        store_owner_epoch: owner.fence.owner_epoch,
        recorded_at_unix_ms,
    })?;
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO admission_operation_commits (
                commit_sequence, operation_id, operation_version, mutation_kind,
                operation_digest, recovery_claim_digest, participant_digest,
                previous_chain_digest, chain_digest,
                store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            "#,
            params![
                sqlite_i64(next, "commit_sequence")?,
                operation.binding().operation_id().as_str(),
                sqlite_i64(operation.version(), "operation_version")?,
                mutation_kind,
                operation_digest,
                claim_digest,
                participant_digest,
                &current.chain_digest,
                &chain_digest,
                &owner.fence.store_uuid,
                &owner.fence.lease_id,
                sqlite_i64(owner.fence.owner_epoch, "store_owner_epoch")?,
                sqlite_i64(recorded_at_unix_ms, "recorded_at_unix_ms")?,
            ],
        )
        .map_err(sqlite_error)?;
    let advanced = transaction
        .execute(
            r#"
            UPDATE admission_operation_commit_meta
            SET head_sequence = ?1, head_chain_digest = ?3,
                trusted_time_high_water_unix_ms = ?4
            WHERE singleton = 1 AND head_sequence = ?2
              AND head_chain_digest = ?5
              AND trusted_time_high_water_unix_ms = ?6
            "#,
            params![
                sqlite_i64(next, "commit_sequence")?,
                sqlite_i64(current.head_sequence, "current_commit_sequence")?,
                chain_digest,
                sqlite_i64(recorded_at_unix_ms, "recorded_at_unix_ms")?,
                current.chain_digest,
                sqlite_i64(
                    current.trusted_time_high_water_unix_ms,
                    "trusted_time_high_water_unix_ms"
                )?,
            ],
        )
        .map_err(sqlite_error)?;
    if inserted != 1 || advanced != 1 {
        return Err(invariant(
            "admission operation commit chain did not advance exactly once",
        ));
    }
    owner
        .append_global_commit(
            transaction,
            mutation_kind,
            "admission",
            operation.binding().operation_id().as_str(),
            next,
        )
        .map_err(|error| invariant(error.to_string()))?;
    Ok(())
}

pub(crate) fn load_admission_commit_head(
    connection: &Connection,
) -> Result<AdmissionCommitHead, AdmissionOperationStoreError> {
    let (head, digest, high_water): (i64, String, i64) = connection
        .query_row(
            r#"
            SELECT head_sequence, head_chain_digest,
                   trusted_time_high_water_unix_ms
            FROM admission_operation_commit_meta WHERE singleton = 1
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(sqlite_error)?;
    if !is_digest(&digest) {
        return Err(invariant("admission operation chain head is malformed"));
    }
    let head = AdmissionCommitHead {
        head_sequence: stored_u64(head, "head_sequence")?,
        chain_digest: digest,
        trusted_time_high_water_unix_ms: stored_u64(high_water, "trusted_time_high_water_unix_ms")?,
    };
    if (head.head_sequence == 0
        && (head.chain_digest != GENESIS_CHAIN_DIGEST || head.trusted_time_high_water_unix_ms != 0))
        || (head.head_sequence > 0 && head.trusted_time_high_water_unix_ms == 0)
    {
        return Err(invariant("admission operation chain head is inconsistent"));
    }
    Ok(head)
}

pub(crate) fn verify_admission_commit_chain(
    connection: &Connection,
) -> Result<AdmissionCommitHead, AdmissionOperationStoreError> {
    let committed = load_admission_commit_head(connection)?;
    let mut statement = connection
        .prepare(
            r#"
            SELECT commit_sequence, operation_id, operation_version, mutation_kind,
                   operation_digest, recovery_claim_digest, participant_digest,
                   previous_chain_digest, chain_digest,
                   store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
            FROM admission_operation_commits ORDER BY commit_sequence
            "#,
        )
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    let mut expected_sequence = 0_u64;
    let mut expected_digest = GENESIS_CHAIN_DIGEST.to_string();
    let mut expected_high_water = 0_u64;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let commit = read_commit(row)?;
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| invariant("admission operation chain sequence overflow"))?;
        (expected_digest, expected_high_water) = advance_chain(
            &commit,
            expected_sequence,
            &expected_digest,
            expected_high_water,
        )?;
    }
    if committed.head_sequence != expected_sequence
        || committed.chain_digest != expected_digest
        || committed.trusted_time_high_water_unix_ms != expected_high_water
    {
        return Err(invariant(
            "admission operation commit metadata does not match its chain",
        ));
    }
    Ok(committed)
}

pub(crate) fn verify_admission_commit_suffix(
    connection: &Connection,
    anchored: &AdmissionCommitHead,
    current: &AdmissionCommitHead,
) -> Result<(), AdmissionOperationStoreError> {
    if current.head_sequence < anchored.head_sequence
        || current.trusted_time_high_water_unix_ms < anchored.trusted_time_high_water_unix_ms
    {
        return Err(invariant("admission operation commit chain regressed"));
    }
    verify_anchored_ancestor(connection, anchored)?;
    let mut statement = connection
        .prepare(
            r#"
            SELECT commit_sequence, operation_id, operation_version, mutation_kind,
                   operation_digest, recovery_claim_digest, participant_digest,
                   previous_chain_digest, chain_digest,
                   store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
            FROM admission_operation_commits
            WHERE commit_sequence > ?1 ORDER BY commit_sequence
            "#,
        )
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query([sqlite_i64(
            anchored.head_sequence,
            "anchored_head_sequence",
        )?])
        .map_err(sqlite_error)?;
    let mut expected_sequence = anchored.head_sequence;
    let mut expected_digest = anchored.chain_digest.clone();
    let mut expected_high_water = anchored.trusted_time_high_water_unix_ms;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let commit = read_commit(row)?;
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| invariant("admission operation chain sequence overflow"))?;
        (expected_digest, expected_high_water) = advance_chain(
            &commit,
            expected_sequence,
            &expected_digest,
            expected_high_water,
        )?;
    }
    if expected_sequence != current.head_sequence
        || expected_digest != current.chain_digest
        || expected_high_water != current.trusted_time_high_water_unix_ms
    {
        return Err(invariant(
            "admission operation commit suffix does not reach its metadata head",
        ));
    }
    Ok(())
}

pub(crate) fn verify_anchored_ancestor(
    connection: &Connection,
    anchored: &AdmissionCommitHead,
) -> Result<(), AdmissionOperationStoreError> {
    if anchored.head_sequence == 0 {
        if anchored.chain_digest != GENESIS_CHAIN_DIGEST
            || anchored.trusted_time_high_water_unix_ms != 0
        {
            return Err(invariant("rollback anchor genesis is invalid"));
        }
        return Ok(());
    }
    let row = connection
        .query_row(
            r#"
            SELECT chain_digest, recorded_at_unix_ms
            FROM admission_operation_commits WHERE commit_sequence = ?1
            "#,
            [sqlite_i64(
                anchored.head_sequence,
                "anchored_head_sequence",
            )?],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .map_err(sqlite_error)?;
    if row.0 != anchored.chain_digest
        || stored_u64(row.1, "anchored_recorded_at_unix_ms")?
            != anchored.trusted_time_high_water_unix_ms
    {
        return Err(invariant(
            "admission operation history does not extend its rollback anchor",
        ));
    }
    Ok(())
}

fn chain_digest(entry: &ChainEntry<'_>) -> Result<String, AdmissionOperationStoreError> {
    canonical_json_bytes(entry)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| invariant(format!("admission commit chain encoding failed: {error}")))
}

fn read_commit(row: &Row<'_>) -> Result<CommitRow, AdmissionOperationStoreError> {
    Ok(CommitRow {
        sequence: stored_u64(row.get(0).map_err(sqlite_error)?, "commit_sequence")?,
        operation_id: row.get(1).map_err(sqlite_error)?,
        operation_version: stored_u64(row.get(2).map_err(sqlite_error)?, "operation_version")?,
        mutation_kind: row.get(3).map_err(sqlite_error)?,
        operation_digest: row.get(4).map_err(sqlite_error)?,
        recovery_claim_digest: row.get(5).map_err(sqlite_error)?,
        participant_digest: row.get(6).map_err(sqlite_error)?,
        previous_chain_digest: row.get(7).map_err(sqlite_error)?,
        chain_digest: row.get(8).map_err(sqlite_error)?,
        store_uuid: row.get(9).map_err(sqlite_error)?,
        store_lease_id: row.get(10).map_err(sqlite_error)?,
        store_owner_epoch: stored_u64(row.get(11).map_err(sqlite_error)?, "store_owner_epoch")?,
        recorded_at_unix_ms: stored_u64(row.get(12).map_err(sqlite_error)?, "recorded_at_unix_ms")?,
    })
}

fn advance_chain(
    commit: &CommitRow,
    expected_sequence: u64,
    previous_digest: &str,
    previous_time: u64,
) -> Result<(String, u64), AdmissionOperationStoreError> {
    if commit.sequence != expected_sequence
        || commit.previous_chain_digest != previous_digest
        || commit.recorded_at_unix_ms < previous_time
        || !is_digest(&commit.operation_digest)
        || commit
            .recovery_claim_digest
            .as_deref()
            .is_some_and(|digest| !is_digest(digest))
        || commit
            .participant_digest
            .as_deref()
            .is_some_and(|digest| !is_digest(digest))
    {
        return Err(invariant("admission operation commit chain is invalid"));
    }
    let calculated = chain_digest(&ChainEntry {
        format: "chio.admission-operation-commit-chain.v1",
        previous_chain_digest: previous_digest,
        commit_sequence: commit.sequence,
        operation_id: &commit.operation_id,
        operation_version: commit.operation_version,
        mutation_kind: &commit.mutation_kind,
        operation_digest: &commit.operation_digest,
        recovery_claim_digest: commit.recovery_claim_digest.as_deref(),
        participant_digest: commit.participant_digest.as_deref(),
        store_uuid: &commit.store_uuid,
        store_lease_id: &commit.store_lease_id,
        store_owner_epoch: commit.store_owner_epoch,
        recorded_at_unix_ms: commit.recorded_at_unix_ms,
    })?;
    if commit.chain_digest != calculated {
        return Err(invariant(
            "admission operation commit chain digest is invalid",
        ));
    }
    Ok((calculated, commit.recorded_at_unix_ms))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
