use chio_core::canonical::canonical_json_bytes;
use chio_core::{sha256_hex, StoreMutationFence};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::Serialize;

use super::{FrostStoreError, SqliteFrostStore};

const PROJECTION_CHAIN_GENESIS: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const COMMIT_DIGEST_PREFIX: &[u8] = b"chio.frost.projection-commit.digest.v1\0";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectionCommitPreimage<'a> {
    format: &'static str,
    projection_key: &'a str,
    projection_sequence: u64,
    projection_type: &'a str,
    mutation_kind: &'a str,
    record_digest: &'a str,
    previous_chain_digest: &'a str,
    store_uuid: &'a str,
    store_lease_id: &'a str,
    store_owner_epoch: u64,
}

pub(super) struct ProjectionMutation<'a> {
    pub sequence: u64,
    pub projection_type: &'a str,
    pub mutation_kind: &'a str,
    pub record_digest: &'a str,
}

pub(super) fn append_projection_commit(
    transaction: &Transaction<'_>,
    store: &SqliteFrostStore,
    projection_key: &str,
    mutation: ProjectionMutation<'_>,
    fence: &StoreMutationFence,
) -> Result<(), FrostStoreError> {
    if !matches!(
        mutation.projection_type,
        "ceremony" | "rotation" | "signer" | "coordinator"
    ) {
        return Err(invalid("unknown FROST projection type"));
    }
    let previous = if mutation.sequence == 1 {
        PROJECTION_CHAIN_GENESIS.to_string()
    } else {
        transaction
            .query_row(
                r#"
                SELECT chain_digest FROM frost_projection_commits
                WHERE projection_key = ?1 AND projection_sequence = ?2
                "#,
                params![
                    projection_key,
                    sqlite_u64(mutation.sequence - 1, "previous FROST sequence")?
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(super::sqlite_error)?
            .ok_or_else(|| invalid("previous FROST projection commit is absent"))?
    };
    let chain_digest = projection_commit_digest(
        projection_key,
        mutation.sequence,
        mutation.projection_type,
        mutation.mutation_kind,
        mutation.record_digest,
        &previous,
        fence,
    )?;
    transaction
        .execute(
            r#"
            INSERT INTO frost_projection_commits (
                projection_key, projection_sequence, projection_type,
                mutation_kind, record_digest, previous_chain_digest,
                chain_digest, store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            params![
                projection_key,
                sqlite_u64(mutation.sequence, "FROST projection sequence")?,
                mutation.projection_type,
                mutation.mutation_kind,
                mutation.record_digest,
                &previous,
                &chain_digest,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_u64(fence.owner_epoch, "FROST store owner epoch")?,
            ],
        )
        .map_err(super::sqlite_error)?;
    store
        .serving_owner
        .append_global_commit(
            transaction,
            mutation.mutation_kind,
            "frost",
            projection_key,
            mutation.sequence,
        )
        .map_err(|error| FrostStoreError::Unavailable(error.to_string()))
}

pub(super) fn verify_projection_commit_chains(
    connection: &Connection,
) -> Result<(), FrostStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT projection_key, projection_sequence, projection_type,
                   mutation_kind, record_digest, previous_chain_digest,
                   chain_digest, store_uuid, store_lease_id, store_owner_epoch
            FROM frost_projection_commits
            ORDER BY projection_key, projection_sequence
            "#,
        )
        .map_err(super::sqlite_error)?;
    let mut rows = statement.query([]).map_err(super::sqlite_error)?;
    let mut current_key = String::new();
    let mut expected_sequence = 0_u64;
    let mut previous = PROJECTION_CHAIN_GENESIS.to_string();
    while let Some(row) = rows.next().map_err(super::sqlite_error)? {
        let key: String = row.get(0).map_err(super::sqlite_error)?;
        let sequence = read_u64(
            row.get::<_, i64>(1).map_err(super::sqlite_error)?,
            "projection sequence",
        )?;
        let projection_type: String = row.get(2).map_err(super::sqlite_error)?;
        let mutation_kind: String = row.get(3).map_err(super::sqlite_error)?;
        let record_digest: String = row.get(4).map_err(super::sqlite_error)?;
        let committed_previous: String = row.get(5).map_err(super::sqlite_error)?;
        let chain_digest: String = row.get(6).map_err(super::sqlite_error)?;
        let fence = StoreMutationFence {
            store_uuid: row.get(7).map_err(super::sqlite_error)?,
            lease_id: row.get(8).map_err(super::sqlite_error)?,
            owner_epoch: read_u64(
                row.get::<_, i64>(9).map_err(super::sqlite_error)?,
                "projection owner epoch",
            )?,
        };
        if key != current_key {
            current_key = key.clone();
            expected_sequence = 0;
            previous = PROJECTION_CHAIN_GENESIS.to_string();
        }
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| invalid("projection sequence overflowed"))?;
        if !matches!(
            projection_type.as_str(),
            "ceremony" | "rotation" | "signer" | "coordinator"
        ) || sequence != expected_sequence
            || committed_previous != previous
        {
            return Err(invalid("FROST projection commit chain is discontinuous"));
        }
        let expected = projection_commit_digest(
            &key,
            sequence,
            &projection_type,
            &mutation_kind,
            &record_digest,
            &previous,
            &fence,
        )?;
        if chain_digest != expected {
            return Err(invalid("FROST projection commit digest is invalid"));
        }
        previous = chain_digest;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn projection_commit_digest(
    key: &str,
    sequence: u64,
    projection_type: &str,
    mutation_kind: &str,
    record_digest: &str,
    previous_chain_digest: &str,
    fence: &StoreMutationFence,
) -> Result<String, FrostStoreError> {
    prefixed_digest(
        COMMIT_DIGEST_PREFIX,
        &ProjectionCommitPreimage {
            format: "chio.frost.projection-commit.v1",
            projection_key: key,
            projection_sequence: sequence,
            projection_type,
            mutation_kind,
            record_digest,
            previous_chain_digest,
            store_uuid: &fence.store_uuid,
            store_lease_id: &fence.lease_id,
            store_owner_epoch: fence.owner_epoch,
        },
    )
}

pub(super) fn prefixed_digest<T: Serialize>(
    prefix: &[u8],
    value: &T,
) -> Result<String, FrostStoreError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| FrostStoreError::InvalidState(error.to_string()))?;
    let mut bytes = Vec::with_capacity(prefix.len() + canonical.len());
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(&canonical);
    Ok(sha256_hex(&bytes))
}

fn sqlite_u64(value: u64, field: &'static str) -> Result<i64, FrostStoreError> {
    i64::try_from(value)
        .map_err(|_| FrostStoreError::InvalidState(format!("{field} exceeds SQLite range")))
}

fn read_u64(value: i64, field: &'static str) -> Result<u64, FrostStoreError> {
    u64::try_from(value).map_err(|_| FrostStoreError::InvalidState(format!("{field} is negative")))
}

fn invalid(detail: impl Into<String>) -> FrostStoreError {
    FrostStoreError::InvalidState(detail.into())
}
