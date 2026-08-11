use chio_core::canonical::canonical_json_bytes;
use chio_core::{sha256_hex, StoreMutationFence};
use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};
use serde::Serialize;

use super::{read_u64, sqlite_u64, SqliteServingOwnerError};

pub(crate) const GLOBAL_GENESIS_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const GLOBAL_COMMIT_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS authority_global_commit_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    head_sequence INTEGER NOT NULL CHECK (head_sequence >= 0),
    head_chain_digest TEXT NOT NULL CHECK (
        length(head_chain_digest) = 64
        AND head_chain_digest NOT GLOB '*[^0-9a-f]*'
    )
);

INSERT INTO authority_global_commit_meta (
    singleton, head_sequence, head_chain_digest
) VALUES (
    1, 0,
    '0000000000000000000000000000000000000000000000000000000000000000'
) ON CONFLICT(singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS authority_global_commits (
    commit_sequence INTEGER PRIMARY KEY CHECK (commit_sequence > 0),
    mutation_kind TEXT NOT NULL CHECK (mutation_kind <> ''),
    projection_kind TEXT NOT NULL CHECK (
        projection_kind IN ('baseline', 'admission', 'budget', 'revocation', 'frost', 'payment', 'economic', 'channel_release_publication', 'factor_assignment_authority_set', 'fiscal', 'finding_challenge')
    ),
    projection_key TEXT NOT NULL,
    projection_sequence INTEGER NOT NULL CHECK (projection_sequence >= 0),
    projection_reference_digest TEXT NOT NULL CHECK (
        length(projection_reference_digest) = 64
        AND projection_reference_digest NOT GLOB '*[^0-9a-f]*'
    ),
    authority_projection_digest TEXT NOT NULL CHECK (
        length(authority_projection_digest) = 64
        AND authority_projection_digest NOT GLOB '*[^0-9a-f]*'
    ),
    previous_chain_digest TEXT NOT NULL CHECK (
        length(previous_chain_digest) = 64
        AND previous_chain_digest NOT GLOB '*[^0-9a-f]*'
    ),
    chain_digest TEXT NOT NULL CHECK (
        length(chain_digest) = 64
        AND chain_digest NOT GLOB '*[^0-9a-f]*'
    ),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT,
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch >= 0),
    CHECK (
        (projection_kind = 'baseline' AND commit_sequence = 1
         AND projection_key = '' AND projection_sequence = 0
         AND store_lease_id IS NULL AND store_owner_epoch = 0)
        OR
        (projection_kind <> 'baseline' AND projection_key <> ''
         AND projection_sequence > 0 AND store_lease_id IS NOT NULL
         AND store_owner_epoch > 0)
    )
);

CREATE INDEX IF NOT EXISTS authority_global_commits_projection
ON authority_global_commits(
    projection_kind, projection_key, projection_sequence
);

CREATE TRIGGER IF NOT EXISTS authority_global_commits_immutable
BEFORE UPDATE ON authority_global_commits
BEGIN
    SELECT RAISE(ABORT, 'global authority commit is immutable');
END;

CREATE TRIGGER IF NOT EXISTS authority_global_commits_no_delete
BEFORE DELETE ON authority_global_commits
BEGIN
    SELECT RAISE(ABORT, 'global authority commit is immutable');
END;
"#;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GlobalCommitHead {
    pub(crate) head_sequence: u64,
    pub(crate) chain_digest: String,
}

#[derive(Serialize)]
struct ChainEntry<'a> {
    format: &'static str,
    previous_chain_digest: &'a str,
    commit_sequence: u64,
    mutation_kind: &'a str,
    projection_kind: &'a str,
    projection_key: &'a str,
    projection_sequence: u64,
    projection_reference_digest: &'a str,
    authority_projection_digest: &'a str,
    store_uuid: &'a str,
    store_lease_id: Option<&'a str>,
    store_owner_epoch: u64,
}

#[derive(Serialize)]
struct ProjectionRootEntry<'a> {
    format: &'static str,
    previous_projection_digest: &'a str,
    commit_sequence: u64,
    mutation_kind: &'a str,
    projection_kind: &'a str,
    projection_key: &'a str,
    projection_sequence: u64,
    projection_reference_digest: &'a str,
}

#[derive(Serialize)]
struct FindingChallengeProjectionEntry<'a> {
    format: &'static str,
    previous_commit_digest: &'a str,
    projection_sequence: u64,
    mutation_kind: &'a str,
    snapshot_digest: &'a str,
}

struct CommitRow {
    sequence: u64,
    mutation_kind: String,
    projection_kind: String,
    projection_key: String,
    projection_sequence: u64,
    projection_reference_digest: String,
    authority_projection_digest: String,
    previous_chain_digest: String,
    chain_digest: String,
    store_uuid: String,
    store_lease_id: Option<String>,
    store_owner_epoch: u64,
}

#[derive(Serialize)]
struct AuthoritySnapshot {
    format: &'static str,
    tables: Vec<TableSnapshot>,
}

#[derive(Serialize)]
struct TableSnapshot {
    name: String,
    columns: Vec<String>,
    row_digests: Vec<String>,
}

#[derive(Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
enum SnapshotValue {
    Null,
    Integer(i64),
    RealBits(String),
    TextHex(String),
    BlobHex(String),
}

#[derive(Serialize)]
struct RevocationReference<'a> {
    format: &'static str,
    commit_index: u64,
    capability_id: &'a str,
    revoked_at: i64,
}

#[derive(Serialize)]
struct VersionedProjectionReference<'a> {
    format: &'static str,
    projection_key: &'a str,
    projection_sequence: u64,
    tables: Vec<TableSnapshot>,
}

#[derive(Serialize)]
struct FactorAssignmentAuthoritySetReference {
    format: &'static str,
    generation: u64,
    active_set_digest: String,
    previous_active_set_digest: Option<String>,
    activated_at_unix_ms: u64,
    store_uuid: String,
    store_lease_id: String,
    store_owner_epoch: u64,
}

type SchemaCatalogEntry = (String, String, String, Option<String>);

pub(crate) fn initialize_global_commit_schema(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    let table_exists = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'authority_global_commits')",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if !table_exists {
        connection.execute_batch(GLOBAL_COMMIT_SCHEMA)?;
    } else if verify_global_commit_schema(connection).is_err() {
        migrate_previous_global_commit_schema(connection)?;
    }
    verify_global_commit_schema(connection)
}

fn migrate_previous_global_commit_schema(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    let previous_schema = GLOBAL_COMMIT_SCHEMA.replace(", 'finding_challenge'", "");
    let expected_previous = Connection::open_in_memory()?;
    expected_previous.execute_batch(&previous_schema)?;
    if global_schema_catalog(connection)? != global_schema_catalog(&expected_previous)? {
        return Err(invalid("global authority commit schema is not canonical"));
    }
    let transaction = connection.unchecked_transaction()?;
    transaction.execute_batch(
        r#"
        DROP TRIGGER authority_global_commits_immutable;
        DROP TRIGGER authority_global_commits_no_delete;
        DROP INDEX authority_global_commits_projection;
        ALTER TABLE authority_global_commits
            RENAME TO authority_global_commits_previous;
        "#,
    )?;
    transaction.execute_batch(GLOBAL_COMMIT_SCHEMA)?;
    transaction.execute_batch(
        r#"
        INSERT INTO authority_global_commits
        SELECT * FROM authority_global_commits_previous;
        DROP TABLE authority_global_commits_previous;
        "#,
    )?;
    transaction.commit()?;
    Ok(())
}

pub(crate) fn verify_global_commit_schema(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(GLOBAL_COMMIT_SCHEMA)?;
    if global_schema_catalog(connection)? != global_schema_catalog(&expected)? {
        return Err(invalid("global authority commit schema is not canonical"));
    }
    Ok(())
}

pub(crate) fn seed_global_baseline(
    connection: &mut Connection,
) -> Result<(), SqliteServingOwnerError> {
    let transaction = connection.transaction()?;
    let head = load_global_commit_head(&transaction)?;
    if head.head_sequence != 0 || head.chain_digest != GLOBAL_GENESIS_DIGEST {
        transaction.rollback()?;
        return verify_global_commit_chain(connection).map(|_| ());
    }
    verify_pristine_baseline(&transaction)?;
    let store_uuid: String = transaction.query_row(
        "SELECT store_uuid FROM chio_serving_owner WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let baseline_digest = baseline_projection_digest(&transaction)?;
    let projection_digest = projection_root_digest(&ProjectionRootEntry {
        format: "chio.sqlite-authority-projection-root.v1",
        previous_projection_digest: GLOBAL_GENESIS_DIGEST,
        commit_sequence: 1,
        mutation_kind: "baseline",
        projection_kind: "baseline",
        projection_key: "",
        projection_sequence: 0,
        projection_reference_digest: &baseline_digest,
    })?;
    append_entry(
        &transaction,
        "baseline",
        "baseline",
        "",
        0,
        &baseline_digest,
        &projection_digest,
        &store_uuid,
        None,
        0,
    )?;
    transaction.commit()?;
    Ok(())
}

pub(crate) fn append_global_commit(
    transaction: &Transaction<'_>,
    mutation_kind: &str,
    projection_kind: &str,
    projection_key: &str,
    projection_sequence: u64,
    fence: &StoreMutationFence,
) -> Result<(), SqliteServingOwnerError> {
    if mutation_kind.is_empty() || projection_key.is_empty() || projection_sequence == 0 {
        return Err(invalid("global authority commit identity is incomplete"));
    }
    let reference_digest = projection_reference_digest(
        transaction,
        projection_kind,
        projection_key,
        projection_sequence,
    )?;
    let current = load_global_commit_head(transaction)?;
    let previous_projection_digest = load_projection_digest(transaction, &current)?;
    let next = current
        .head_sequence
        .checked_add(1)
        .ok_or_else(|| invalid("global authority commit sequence overflowed"))?;
    let projection_digest = projection_root_digest(&ProjectionRootEntry {
        format: "chio.sqlite-authority-projection-root.v1",
        previous_projection_digest: &previous_projection_digest,
        commit_sequence: next,
        mutation_kind,
        projection_kind,
        projection_key,
        projection_sequence,
        projection_reference_digest: &reference_digest,
    })?;
    append_entry(
        transaction,
        mutation_kind,
        projection_kind,
        projection_key,
        projection_sequence,
        &reference_digest,
        &projection_digest,
        &fence.store_uuid,
        Some(&fence.lease_id),
        fence.owner_epoch,
    )
}

/// Append the challenge projection and its authority-wide reference when
/// the current challenge snapshot differs from the latest committed one.
/// Identical replays produce no phantom history entry.
#[cfg(feature = "cognition-market-experimental")]
pub(crate) fn append_finding_challenge_projection_if_changed(
    transaction: &Transaction<'_>,
    fence: &StoreMutationFence,
) -> Result<bool, SqliteServingOwnerError> {
    let snapshot_digest = finding_market_snapshot_digest(transaction)?;
    let latest = transaction
        .query_row(
            r#"
            SELECT projection_sequence, snapshot_digest, commit_digest
            FROM finding_challenge_projection_commits
            ORDER BY projection_sequence DESC LIMIT 1
            "#,
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    if latest
        .as_ref()
        .is_some_and(|(_, committed_snapshot, _)| committed_snapshot == &snapshot_digest)
    {
        return Ok(false);
    }
    let (previous_sequence, previous_commit_digest) = match latest {
        Some((sequence, _, commit_digest)) => (
            read_u64(sequence, "finding challenge projection sequence")?,
            commit_digest,
        ),
        None => (0, GLOBAL_GENESIS_DIGEST.to_owned()),
    };
    let projection_sequence = previous_sequence
        .checked_add(1)
        .ok_or_else(|| invalid("finding challenge projection sequence overflowed"))?;
    let mutation_kind = "finding_challenge_write";
    let commit_digest = digest(&FindingChallengeProjectionEntry {
        format: "chio.sqlite-finding-challenge-projection.v1",
        previous_commit_digest: &previous_commit_digest,
        projection_sequence,
        mutation_kind,
        snapshot_digest: &snapshot_digest,
    })?;
    let inserted = transaction.execute(
        r#"
        INSERT INTO finding_challenge_projection_commits (
            projection_sequence, mutation_kind, snapshot_digest,
            previous_commit_digest, commit_digest
        ) VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        params![
            sqlite_u64(projection_sequence, "finding challenge projection sequence")?,
            mutation_kind,
            snapshot_digest,
            previous_commit_digest,
            commit_digest,
        ],
    )?;
    if inserted != 1 {
        return Err(invalid(
            "finding challenge projection did not advance exactly once",
        ));
    }
    append_global_commit(
        transaction,
        mutation_kind,
        "finding_challenge",
        "market",
        projection_sequence,
        fence,
    )?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn append_entry(
    transaction: &Transaction<'_>,
    mutation_kind: &str,
    projection_kind: &str,
    projection_key: &str,
    projection_sequence: u64,
    projection_reference_digest: &str,
    authority_projection_digest: &str,
    store_uuid: &str,
    store_lease_id: Option<&str>,
    store_owner_epoch: u64,
) -> Result<(), SqliteServingOwnerError> {
    let current = load_global_commit_head(transaction)?;
    let next = current
        .head_sequence
        .checked_add(1)
        .ok_or_else(|| invalid("global authority commit sequence overflowed"))?;
    let chain_digest = chain_digest(&ChainEntry {
        format: "chio.sqlite-authority-global-commit.v1",
        previous_chain_digest: &current.chain_digest,
        commit_sequence: next,
        mutation_kind,
        projection_kind,
        projection_key,
        projection_sequence,
        projection_reference_digest,
        authority_projection_digest,
        store_uuid,
        store_lease_id,
        store_owner_epoch,
    })?;
    let inserted = transaction.execute(
        r#"
        INSERT INTO authority_global_commits (
            commit_sequence, mutation_kind, projection_kind, projection_key,
            projection_sequence, projection_reference_digest,
            authority_projection_digest, previous_chain_digest, chain_digest,
            store_uuid, store_lease_id, store_owner_epoch
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
        params![
            sqlite_u64(next, "commit_sequence")?,
            mutation_kind,
            projection_kind,
            projection_key,
            sqlite_u64(projection_sequence, "projection_sequence")?,
            projection_reference_digest,
            authority_projection_digest,
            &current.chain_digest,
            &chain_digest,
            store_uuid,
            store_lease_id,
            sqlite_u64(store_owner_epoch, "store_owner_epoch")?,
        ],
    )?;
    let advanced = transaction.execute(
        r#"
        UPDATE authority_global_commit_meta
        SET head_sequence = ?1, head_chain_digest = ?2
        WHERE singleton = 1 AND head_sequence = ?3 AND head_chain_digest = ?4
        "#,
        params![
            sqlite_u64(next, "commit_sequence")?,
            chain_digest,
            sqlite_u64(current.head_sequence, "current_commit_sequence")?,
            current.chain_digest,
        ],
    )?;
    if inserted != 1 || advanced != 1 {
        return Err(invalid(
            "global authority commit chain did not advance exactly once",
        ));
    }
    Ok(())
}

pub(crate) fn load_global_commit_head(
    connection: &Connection,
) -> Result<GlobalCommitHead, SqliteServingOwnerError> {
    let (sequence, digest): (i64, String) = connection.query_row(
        r#"
        SELECT head_sequence, head_chain_digest
        FROM authority_global_commit_meta WHERE singleton = 1
        "#,
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let head = GlobalCommitHead {
        head_sequence: read_u64(sequence, "global commit head")?,
        chain_digest: digest,
    };
    if !is_digest(&head.chain_digest)
        || (head.head_sequence == 0 && head.chain_digest != GLOBAL_GENESIS_DIGEST)
    {
        return Err(invalid("global authority commit head is invalid"));
    }
    Ok(head)
}

fn load_projection_digest(
    connection: &Connection,
    head: &GlobalCommitHead,
) -> Result<String, SqliteServingOwnerError> {
    if head.head_sequence == 0 {
        return Ok(GLOBAL_GENESIS_DIGEST.to_string());
    }
    let digest = connection
        .query_row(
            r#"
            SELECT authority_projection_digest FROM authority_global_commits
            WHERE commit_sequence = ?1 AND chain_digest = ?2
            "#,
            params![
                sqlite_u64(head.head_sequence, "global commit head")?,
                &head.chain_digest,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| invalid("global authority head commit is absent"))?;
    if !is_digest(&digest) {
        return Err(invalid("global authority projection digest is invalid"));
    }
    Ok(digest)
}

pub(crate) fn verify_global_commit_chain(
    connection: &Connection,
) -> Result<GlobalCommitHead, SqliteServingOwnerError> {
    verify_global_commit_schema(connection)?;
    let committed = load_global_commit_head(connection)?;
    let mut statement = connection.prepare(
        r#"
        SELECT commit_sequence, mutation_kind, projection_kind, projection_key,
               projection_sequence, projection_reference_digest,
               authority_projection_digest, previous_chain_digest, chain_digest,
               store_uuid, store_lease_id, store_owner_epoch
        FROM authority_global_commits ORDER BY commit_sequence
        "#,
    )?;
    let mut rows = statement.query([])?;
    let mut expected_sequence = 0_u64;
    let mut expected_digest = GLOBAL_GENESIS_DIGEST.to_string();
    let mut expected_projection = GLOBAL_GENESIS_DIGEST.to_string();
    while let Some(row) = rows.next()? {
        let commit = read_commit(row)?;
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| invalid("global authority commit sequence overflowed"))?;
        (expected_digest, expected_projection) = verify_entry(
            connection,
            &commit,
            expected_sequence,
            &expected_digest,
            &expected_projection,
        )?;
    }
    drop(rows);
    drop(statement);
    if committed.head_sequence != expected_sequence || committed.chain_digest != expected_digest {
        return Err(invalid(
            "global authority commit metadata does not match its chain",
        ));
    }
    if expected_sequence == 0 {
        return Err(invalid("global authority commit chain has no baseline"));
    }
    verify_global_projection_coverage(connection)?;
    if committed.head_sequence == 1 {
        verify_live_baseline_projection(connection)?;
    }
    Ok(committed)
}

pub(crate) fn verify_global_projection_head(
    connection: &Connection,
) -> Result<GlobalCommitHead, SqliteServingOwnerError> {
    let head = load_global_commit_head(connection)?;
    if head.head_sequence == 0 {
        return Err(invalid("global authority commit chain has no baseline"));
    }
    let stored_projection = connection
        .query_row(
            r#"
            SELECT authority_projection_digest FROM authority_global_commits
            WHERE commit_sequence = ?1 AND chain_digest = ?2
            "#,
            params![
                sqlite_u64(head.head_sequence, "global commit head")?,
                &head.chain_digest,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| invalid("global authority head commit is absent"))?;
    if !is_digest(&stored_projection) {
        return Err(invalid(
            "global authority head projection digest is invalid",
        ));
    }
    Ok(head)
}

pub(crate) fn verify_global_commit_suffix(
    connection: &Connection,
    anchored: &GlobalCommitHead,
    current: &GlobalCommitHead,
) -> Result<(), SqliteServingOwnerError> {
    if current.head_sequence < anchored.head_sequence {
        return Err(invalid("global authority commit chain regressed"));
    }
    let mut expected_projection = verify_global_anchored_ancestor(connection, anchored)?;
    let mut statement = connection.prepare(
        r#"
        SELECT commit_sequence, mutation_kind, projection_kind, projection_key,
               projection_sequence, projection_reference_digest,
               authority_projection_digest, previous_chain_digest, chain_digest,
               store_uuid, store_lease_id, store_owner_epoch
        FROM authority_global_commits
        WHERE commit_sequence > ?1 ORDER BY commit_sequence
        "#,
    )?;
    let mut rows =
        statement.query([sqlite_u64(anchored.head_sequence, "anchored global head")?])?;
    let mut expected_sequence = anchored.head_sequence;
    let mut expected_digest = anchored.chain_digest.clone();
    while let Some(row) = rows.next()? {
        let commit = read_commit(row)?;
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| invalid("global authority commit sequence overflowed"))?;
        (expected_digest, expected_projection) = verify_entry(
            connection,
            &commit,
            expected_sequence,
            &expected_digest,
            &expected_projection,
        )?;
    }
    if expected_sequence != current.head_sequence || expected_digest != current.chain_digest {
        return Err(invalid(
            "global authority commit suffix does not reach its metadata head",
        ));
    }
    Ok(())
}

fn verify_global_anchored_ancestor(
    connection: &Connection,
    anchored: &GlobalCommitHead,
) -> Result<String, SqliteServingOwnerError> {
    if anchored.head_sequence == 0 {
        if anchored.chain_digest != GLOBAL_GENESIS_DIGEST {
            return Err(invalid("global rollback anchor genesis is invalid"));
        }
        return Ok(GLOBAL_GENESIS_DIGEST.to_string());
    }
    let (digest, projection_digest) = connection
        .query_row(
            r#"
            SELECT chain_digest, authority_projection_digest
            FROM authority_global_commits WHERE commit_sequence = ?1
            "#,
            [sqlite_u64(anchored.head_sequence, "anchored global head")?],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or_else(|| invalid("global rollback anchor commit is absent"))?;
    if digest != anchored.chain_digest {
        return Err(invalid(
            "global authority history does not extend its rollback anchor",
        ));
    }
    if !is_digest(&projection_digest) {
        return Err(invalid("anchored global projection digest is invalid"));
    }
    Ok(projection_digest)
}

fn read_commit(row: &Row<'_>) -> Result<CommitRow, SqliteServingOwnerError> {
    Ok(CommitRow {
        sequence: read_u64(row.get(0)?, "commit_sequence")?,
        mutation_kind: row.get(1)?,
        projection_kind: row.get(2)?,
        projection_key: row.get(3)?,
        projection_sequence: read_u64(row.get(4)?, "projection_sequence")?,
        projection_reference_digest: row.get(5)?,
        authority_projection_digest: row.get(6)?,
        previous_chain_digest: row.get(7)?,
        chain_digest: row.get(8)?,
        store_uuid: row.get(9)?,
        store_lease_id: row.get(10)?,
        store_owner_epoch: read_u64(row.get(11)?, "store_owner_epoch")?,
    })
}

fn verify_entry(
    connection: &Connection,
    commit: &CommitRow,
    expected_sequence: u64,
    previous_digest: &str,
    previous_projection_digest: &str,
) -> Result<(String, String), SqliteServingOwnerError> {
    if commit.sequence != expected_sequence
        || commit.previous_chain_digest != previous_digest
        || !is_digest(&commit.projection_reference_digest)
        || !is_digest(&commit.authority_projection_digest)
    {
        return Err(invalid("global authority commit chain is invalid"));
    }
    if commit.projection_kind == "baseline" {
        if commit.sequence != 1
            || commit.mutation_kind != "baseline"
            || !commit.projection_key.is_empty()
            || commit.projection_sequence != 0
            || commit.store_owner_epoch != 0
            || commit.store_lease_id.is_some()
        {
            return Err(invalid("global authority baseline is invalid"));
        }
    } else {
        verify_historical_lease(connection, commit)?;
        verify_projection_reference(connection, commit)?;
    }
    let projection_digest = projection_root_digest(&ProjectionRootEntry {
        format: "chio.sqlite-authority-projection-root.v1",
        previous_projection_digest,
        commit_sequence: commit.sequence,
        mutation_kind: &commit.mutation_kind,
        projection_kind: &commit.projection_kind,
        projection_key: &commit.projection_key,
        projection_sequence: commit.projection_sequence,
        projection_reference_digest: &commit.projection_reference_digest,
    })?;
    if projection_digest != commit.authority_projection_digest {
        return Err(invalid("global authority projection root is invalid"));
    }
    let calculated = chain_digest(&ChainEntry {
        format: "chio.sqlite-authority-global-commit.v1",
        previous_chain_digest: previous_digest,
        commit_sequence: commit.sequence,
        mutation_kind: &commit.mutation_kind,
        projection_kind: &commit.projection_kind,
        projection_key: &commit.projection_key,
        projection_sequence: commit.projection_sequence,
        projection_reference_digest: &commit.projection_reference_digest,
        authority_projection_digest: &commit.authority_projection_digest,
        store_uuid: &commit.store_uuid,
        store_lease_id: commit.store_lease_id.as_deref(),
        store_owner_epoch: commit.store_owner_epoch,
    })?;
    if calculated != commit.chain_digest {
        return Err(invalid("global authority commit digest is invalid"));
    }
    Ok((calculated, projection_digest))
}

fn verify_historical_lease(
    connection: &Connection,
    commit: &CommitRow,
) -> Result<(), SqliteServingOwnerError> {
    let valid = connection.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM chio_serving_leases
            WHERE store_uuid = ?1 AND owner_epoch = ?2 AND lease_id = ?3
        )
        "#,
        params![
            &commit.store_uuid,
            sqlite_u64(commit.store_owner_epoch, "store_owner_epoch")?,
            commit.store_lease_id.as_deref(),
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if !valid {
        return Err(invalid(
            "global authority commit is outside serving lease history",
        ));
    }
    Ok(())
}

fn projection_reference_digest(
    connection: &Connection,
    kind: &str,
    key: &str,
    sequence: u64,
) -> Result<String, SqliteServingOwnerError> {
    match kind {
        "admission" => connection
            .query_row(
                r#"
                SELECT chain_digest FROM admission_operation_commits
                WHERE commit_sequence = ?1 AND operation_id = ?2
                "#,
                params![sqlite_u64(sequence, "admission commit sequence")?, key],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| invalid("admission projection reference is absent")),
        "budget" => budget_event_reference_digest(connection, key, sequence),
        "payment" => payment_journal_reference_digest(connection, key, sequence),
        "revocation" => revocation_reference_digest(connection, key, sequence),
        "frost" => connection
            .query_row(
                r#"
                SELECT chain_digest FROM frost_projection_commits
                WHERE projection_key = ?1 AND projection_sequence = ?2
                "#,
                params![key, sqlite_u64(sequence, "FROST projection sequence")?],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| invalid("FROST projection reference is absent")),
        "economic" => connection
            .query_row(
                r#"
                SELECT commit_digest FROM economic_state_stage_commits
                WHERE batch_id = ?1 AND stage_version = ?2
                "#,
                params![key, sqlite_u64(sequence, "economic stage version")?],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| invalid("economic projection reference is absent")),
        "channel_release_publication" => {
            channel_release_projection_reference_digest(connection, key, sequence)
        }
        "factor_assignment_authority_set" => {
            factor_assignment_authority_set_reference_digest(connection, key, sequence)
        }
        "fiscal" => connection
            .query_row(
                r#"
                SELECT commit_digest FROM fiscal_projection_commits
                WHERE projection_key = ?1 AND projection_sequence = ?2
                "#,
                params![key, sqlite_u64(sequence, "fiscal projection sequence")?],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| invalid("fiscal projection reference is absent")),
        "finding_challenge" => {
            if key != "market" {
                return Err(invalid("finding challenge projection key is invalid"));
            }
            connection
                .query_row(
                    r#"
                    SELECT commit_digest FROM finding_challenge_projection_commits
                    WHERE projection_sequence = ?1
                    "#,
                    [sqlite_u64(
                        sequence,
                        "finding challenge projection sequence",
                    )?],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or_else(|| invalid("finding challenge projection reference is absent"))
        }
        _ => Err(invalid("unknown global authority projection kind")),
    }
}

fn factor_assignment_authority_set_reference_digest(
    connection: &Connection,
    key: &str,
    generation: u64,
) -> Result<String, SqliteServingOwnerError> {
    if key != "active" {
        return Err(invalid(
            "factor assignment authority set projection key is invalid",
        ));
    }
    let row = connection
        .query_row(
            r#"
            SELECT generation, active_set_digest, previous_active_set_digest,
                   activated_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch
            FROM factor_assignment_authority_sets
            WHERE generation = ?1
            "#,
            [sqlite_u64(generation, "factor authority set generation")?],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| invalid("factor assignment authority set projection is absent"))?;
    if read_u64(row.0, "factor authority set generation")? != generation {
        return Err(invalid(
            "factor assignment authority set generation does not match its projection",
        ));
    }
    digest(&FactorAssignmentAuthoritySetReference {
        format: "chio.sqlite-authority-factor-assignment-authority-set-reference.v1",
        generation,
        active_set_digest: row.1,
        previous_active_set_digest: row.2,
        activated_at_unix_ms: read_u64(row.3, "factor authority set activation time")?,
        store_uuid: row.4,
        store_lease_id: row.5,
        store_owner_epoch: read_u64(row.6, "factor authority set owner epoch")?,
    })
}

fn verify_projection_reference(
    connection: &Connection,
    commit: &CommitRow,
) -> Result<(), SqliteServingOwnerError> {
    if commit.projection_kind == "channel_release_publication" {
        let stored_version =
            load_channel_release_projection_sequence(connection, &commit.projection_key)?;
        if stored_version < commit.projection_sequence {
            return Err(invalid(
                "channel release publication projection history was truncated",
            ));
        }
        let superseded = connection.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM authority_global_commits
                WHERE projection_kind = ?1 AND projection_key = ?2
                  AND projection_sequence > ?3
            )
            "#,
            params![
                &commit.projection_kind,
                &commit.projection_key,
                sqlite_u64(commit.projection_sequence, "versioned projection sequence")?,
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if superseded {
            return Ok(());
        }
    }
    if commit.projection_kind == "payment" {
        let stored_version = connection
            .query_row(
                "SELECT journal_version FROM payment_journal WHERE operation_id = ?1",
                [&commit.projection_key],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or_else(|| invalid("payment journal projection reference is absent"))?;
        if read_u64(stored_version, "payment journal version")? < commit.projection_sequence {
            return Err(invalid("payment journal projection history was truncated"));
        }
        let superseded = connection.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM authority_global_commits
                WHERE projection_kind = 'payment' AND projection_key = ?1
                  AND projection_sequence > ?2
            )
            "#,
            params![
                &commit.projection_key,
                sqlite_u64(commit.projection_sequence, "payment journal version")?,
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if !superseded
            && payment_journal_reference_digest(
                connection,
                &commit.projection_key,
                commit.projection_sequence,
            )? != commit.projection_reference_digest
        {
            return Err(invalid(
                "global authority commit lost its exact payment projection",
            ));
        }
        return Ok(());
    }
    if commit.projection_kind == "revocation" {
        let committed = connection.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM admission_authority_commits
                WHERE commit_index = ?1 AND kind = 'revocation'
                  AND capability_id = ?2
            )
            "#,
            params![
                sqlite_u64(commit.projection_sequence, "revocation commit index")?,
                &commit.projection_key,
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if !committed {
            return Err(invalid("revocation projection reference is absent"));
        }
        let superseded = connection.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM authority_global_commits
                WHERE projection_kind = 'revocation' AND projection_key = ?1
                  AND projection_sequence > ?2
            )
            "#,
            params![
                &commit.projection_key,
                sqlite_u64(commit.projection_sequence, "revocation commit index")?,
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if !superseded
            && revocation_reference_digest(
                connection,
                &commit.projection_key,
                commit.projection_sequence,
            )? != commit.projection_reference_digest
        {
            return Err(invalid(
                "global authority commit lost its exact revocation projection",
            ));
        }
        return Ok(());
    }
    let reference = projection_reference_digest(
        connection,
        &commit.projection_kind,
        &commit.projection_key,
        commit.projection_sequence,
    )?;
    if reference != commit.projection_reference_digest {
        return Err(invalid(
            "global authority commit lost its exact projection reference",
        ));
    }
    Ok(())
}

fn channel_release_projection_reference_digest(
    connection: &Connection,
    key: &str,
    sequence: u64,
) -> Result<String, SqliteServingOwnerError> {
    let stored_sequence = load_channel_release_projection_sequence(connection, key)?;
    if stored_sequence != sequence {
        return Err(invalid(
            "channel release publication sequence does not match its record",
        ));
    }
    digest(&VersionedProjectionReference {
        format: "chio.sqlite-authority-channel-release-publication-reference.v1",
        projection_key: key,
        projection_sequence: sequence,
        tables: vec![table_snapshot(
            connection,
            "chio_channel_release_publications",
            Some(("channel_id", key)),
        )?],
    })
}

fn load_channel_release_projection_sequence(
    connection: &Connection,
    key: &str,
) -> Result<u64, SqliteServingOwnerError> {
    let stored = connection
        .query_row(
            "SELECT record_version FROM chio_channel_release_publications WHERE channel_id = ?1",
            [key],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| invalid("channel release publication reference is absent"))?;
    read_u64(stored, "channel release publication sequence")
}

fn revocation_reference_digest(
    connection: &Connection,
    capability_id: &str,
    commit_index: u64,
) -> Result<String, SqliteServingOwnerError> {
    let revoked_at = connection
        .query_row(
            r#"
            SELECT revoked_at FROM revoked_capabilities
            WHERE capability_id = ?1 AND admission_authority_commit_index = ?2
            "#,
            params![
                capability_id,
                sqlite_u64(commit_index, "revocation commit index")?,
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| invalid("revocation projection reference is absent"))?;
    digest(&RevocationReference {
        format: "chio.sqlite-authority-revocation-reference.v1",
        commit_index,
        capability_id,
        revoked_at,
    })
}

fn budget_event_reference_digest(
    connection: &Connection,
    event_id: &str,
    event_seq: u64,
) -> Result<String, SqliteServingOwnerError> {
    let stored_seq = connection
        .query_row(
            "SELECT event_seq FROM budget_mutation_events WHERE event_id = ?1",
            [event_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| invalid("budget projection reference is absent"))?;
    if read_u64(stored_seq, "budget event sequence")? != event_seq {
        return Err(invalid(
            "budget projection sequence does not match its event",
        ));
    }
    let tables = table_names(connection, true)?;
    let mut snapshots = Vec::new();
    for table in tables {
        snapshots.push(table_snapshot(
            connection,
            &table,
            Some(("event_id", event_id)),
        )?);
    }
    digest(&AuthoritySnapshot {
        format: "chio.sqlite-authority-budget-event-reference.v1",
        tables: snapshots,
    })
}

fn payment_journal_reference_digest(
    connection: &Connection,
    operation_id: &str,
    journal_version: u64,
) -> Result<String, SqliteServingOwnerError> {
    let stored_version = connection
        .query_row(
            "SELECT journal_version FROM payment_journal WHERE operation_id = ?1",
            [operation_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| invalid("payment journal projection reference is absent"))?;
    if read_u64(stored_version, "payment journal version")? != journal_version {
        return Err(invalid(
            "payment journal projection sequence does not match its record",
        ));
    }
    let tables = ["payment_journal", "payment_release_evidence"];
    let mut snapshots = Vec::with_capacity(tables.len());
    for table in tables {
        snapshots.push(table_snapshot(
            connection,
            table,
            Some(("operation_id", operation_id)),
        )?);
    }
    digest(&AuthoritySnapshot {
        format: "chio.sqlite-authority-payment-journal-reference.v1",
        tables: snapshots,
    })
}

fn baseline_projection_digest(connection: &Connection) -> Result<String, SqliteServingOwnerError> {
    baseline_projection_digest_for_tables(connection, table_names(connection, false)?)
}

fn finding_challenge_snapshot_digest_v1(
    connection: &Connection,
) -> Result<String, SqliteServingOwnerError> {
    let tables = [
        "challenges",
        "dispute_locks",
        "liability_heads",
        "governance_case_index",
        "claim_snapshots",
        "effect_intents",
        "listing_sales_blocks",
    ];
    let mut snapshots = Vec::with_capacity(tables.len());
    for table in tables {
        snapshots.push(if table == "liability_heads" {
            table_snapshot_without_column(connection, table, "seller_hex")?
        } else {
            table_snapshot(connection, table, None)?
        });
    }
    digest(&AuthoritySnapshot {
        format: "chio.sqlite-finding-challenge-snapshot.v1",
        tables: snapshots,
    })
}

/// Current rollback-protected cognition-market snapshot. Purchase claims
/// and every durable relation used to admit them share the challenge
/// projection, so restoring a database from before a settled purchase
/// cannot silently shrink a later sealed distribution.
fn finding_market_snapshot_digest(
    connection: &Connection,
) -> Result<String, SqliteServingOwnerError> {
    finding_market_snapshot_digest_version(
        connection, true, true, true, true, true, true, true, true, true, true,
    )
}

fn finding_market_snapshot_digest_v11(
    connection: &Connection,
) -> Result<String, SqliteServingOwnerError> {
    finding_market_snapshot_digest_version(
        connection, true, true, true, true, true, true, true, true, true, false,
    )
}

fn finding_market_snapshot_digest_v10(
    connection: &Connection,
) -> Result<String, SqliteServingOwnerError> {
    finding_market_snapshot_digest_version(
        connection, true, true, true, true, true, true, true, true, false, false,
    )
}

fn finding_market_snapshot_digest_v9(
    connection: &Connection,
) -> Result<String, SqliteServingOwnerError> {
    finding_market_snapshot_digest_version(
        connection, true, true, true, true, true, true, true, false, false, false,
    )
}

fn finding_market_snapshot_digest_v8(
    connection: &Connection,
) -> Result<String, SqliteServingOwnerError> {
    finding_market_snapshot_digest_version(
        connection, true, true, true, true, true, true, false, false, false, false,
    )
}

fn finding_market_snapshot_digest_v7(
    connection: &Connection,
) -> Result<String, SqliteServingOwnerError> {
    finding_market_snapshot_digest_version(
        connection, true, true, true, true, true, false, false, false, false, false,
    )
}

fn finding_market_snapshot_digest_v6(
    connection: &Connection,
) -> Result<String, SqliteServingOwnerError> {
    finding_market_snapshot_digest_version(
        connection, true, true, true, true, false, false, false, false, false, false,
    )
}

fn finding_market_snapshot_digest_v5(
    connection: &Connection,
) -> Result<String, SqliteServingOwnerError> {
    finding_market_snapshot_digest_version(
        connection, true, true, true, false, false, false, false, false, false, false,
    )
}

fn finding_market_snapshot_digest_v4(
    connection: &Connection,
) -> Result<String, SqliteServingOwnerError> {
    finding_market_snapshot_digest_version(
        connection, true, true, false, false, false, false, false, false, false, false,
    )
}

fn finding_market_snapshot_digest_v3(
    connection: &Connection,
) -> Result<String, SqliteServingOwnerError> {
    finding_market_snapshot_digest_version(
        connection, true, false, false, false, false, false, false, false, false, false,
    )
}

fn finding_market_snapshot_digest_v2(
    connection: &Connection,
) -> Result<String, SqliteServingOwnerError> {
    finding_market_snapshot_digest_version(
        connection, false, false, false, false, false, false, false, false, false, false,
    )
}

#[allow(clippy::too_many_arguments)]
fn finding_market_snapshot_digest_version(
    connection: &Connection,
    include_lock_reservations: bool,
    include_liability_seller: bool,
    include_inflight_purchases: bool,
    include_root_bindings: bool,
    include_outcomes: bool,
    include_capture_intents: bool,
    include_failed_deliveries: bool,
    include_finalizing_authorizations: bool,
    include_finalizing_authorization_refreshes: bool,
    include_terminal_reservations: bool,
) -> Result<String, SqliteServingOwnerError> {
    let mut challenge_tables = vec![
        "challenges",
        "dispute_locks",
        "liability_heads",
        "governance_case_index",
        "claim_snapshots",
        "effect_intents",
        "listing_sales_blocks",
    ];
    if include_root_bindings {
        challenge_tables.push("effect_root_bindings");
    }
    if include_outcomes {
        challenge_tables.push("finding_challenge_outcomes");
    }
    if include_finalizing_authorizations {
        challenge_tables.push("finding_finalizing_authorizations");
    }
    if include_finalizing_authorization_refreshes {
        challenge_tables.push("finding_finalizing_authorization_refreshes");
    }
    let mut snapshots = Vec::with_capacity(if include_lock_reservations { 17 } else { 16 });
    for table in challenge_tables {
        snapshots.push(if table == "liability_heads" && !include_liability_seller {
            table_snapshot_without_column(connection, table, "seller_hex")?
        } else {
            table_snapshot(connection, table, None)?
        });
        if include_lock_reservations && table == "challenges" {
            snapshots.push(table_snapshot(
                connection,
                "dispute_lock_reservations",
                None,
            )?);
        }
    }
    snapshots.push(table_snapshot(connection, "purchase_records", None)?);
    if include_capture_intents {
        snapshots.push(table_snapshot(
            connection,
            "purchase_capture_intents",
            None,
        )?);
    }
    if include_failed_deliveries {
        snapshots.push(table_snapshot(connection, "failed_delivery_records", None)?);
    }
    for table in [
        "purchase_reservations",
        "purchase_payout_bindings",
        "seller_exposure_encumbrances",
        "pending_purchase_slots",
    ] {
        snapshots.push(table_snapshot_where(
            connection,
            table,
            if include_terminal_reservations {
                "1 = 1"
            } else if include_failed_deliveries {
                r#"
                reservation_id IN (
                    SELECT reservation_id FROM purchase_records
                    UNION
                    SELECT reservation_id FROM failed_delivery_records
                    UNION
                    SELECT reservation_id FROM purchase_reservations
                    WHERE state IN ('open', 'slot_reserved')
                )
                "#
            } else if include_inflight_purchases {
                r#"
                reservation_id IN (
                    SELECT reservation_id FROM purchase_records
                    UNION
                    SELECT reservation_id FROM purchase_reservations
                    WHERE state IN ('open', 'slot_reserved')
                )
                "#
            } else {
                "reservation_id IN (SELECT reservation_id FROM purchase_records)"
            },
        )?);
    }
    snapshots.push(table_snapshot_where(
        connection,
        "payout_destinations",
        if include_finalizing_authorizations {
            // The current public admission API can create a buyer slot
            // before any purchase binding exists. Every such actionable row
            // affects collision and capacity decisions and must therefore be
            // committed even while it is unattached.
            "1 = 1"
        } else if include_failed_deliveries {
            r#"
            slot_index = 0 OR EXISTS (
                SELECT 1
                FROM purchase_payout_bindings AS bindings
                JOIN seller_exposure_encumbrances AS encumbrances
                  ON encumbrances.reservation_id = bindings.reservation_id
                WHERE bindings.reservation_id IN (
                    SELECT reservation_id FROM purchase_records
                    UNION
                    SELECT reservation_id FROM failed_delivery_records
                    UNION
                    SELECT reservation_id FROM purchase_reservations
                    WHERE state IN ('open', 'slot_reserved')
                )
                  AND encumbrances.allocation_id = payout_destinations.allocation_id
                  AND bindings.destination = payout_destinations.destination
            )
            "#
        } else if include_inflight_purchases {
            r#"
            slot_index = 0 OR EXISTS (
                SELECT 1
                FROM purchase_payout_bindings AS bindings
                JOIN seller_exposure_encumbrances AS encumbrances
                  ON encumbrances.reservation_id = bindings.reservation_id
                WHERE bindings.reservation_id IN (
                    SELECT reservation_id FROM purchase_records
                    UNION
                    SELECT reservation_id FROM purchase_reservations
                    WHERE state IN ('open', 'slot_reserved')
                )
                  AND encumbrances.allocation_id = payout_destinations.allocation_id
                  AND bindings.destination = payout_destinations.destination
            )
            "#
        } else {
            r#"
            slot_index = 0 OR EXISTS (
                SELECT 1
                FROM purchase_records AS records
                JOIN purchase_payout_bindings AS bindings
                  ON bindings.reservation_id = records.reservation_id
                JOIN seller_exposure_encumbrances AS encumbrances
                  ON encumbrances.reservation_id = records.reservation_id
                WHERE encumbrances.allocation_id = payout_destinations.allocation_id
                  AND bindings.destination = payout_destinations.destination
            )
            "#
        },
    )?);
    digest(&AuthoritySnapshot {
        format: if include_terminal_reservations {
            "chio.sqlite-finding-market-snapshot.v12"
        } else if include_failed_deliveries {
            "chio.sqlite-finding-market-snapshot.v9"
        } else if include_capture_intents {
            "chio.sqlite-finding-market-snapshot.v8"
        } else if include_outcomes {
            "chio.sqlite-finding-market-snapshot.v7"
        } else if include_root_bindings {
            "chio.sqlite-finding-market-snapshot.v6"
        } else if include_inflight_purchases {
            "chio.sqlite-finding-market-snapshot.v5"
        } else if include_liability_seller {
            "chio.sqlite-finding-market-snapshot.v4"
        } else if include_lock_reservations {
            "chio.sqlite-finding-market-snapshot.v3"
        } else {
            "chio.sqlite-finding-market-snapshot.v2"
        },
        tables: snapshots,
    })
}

/// Refuses any authority table that already carries rows, which a global baseline
/// cannot adopt. Enumerated from `sqlite_schema`, so tables that do not exist yet
/// are simply absent and provisioning can run this before it creates anything.
pub(crate) fn verify_pristine_authority_tables(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    for table in table_names(connection, false)? {
        if matches!(
            table.as_str(),
            "admission_authority_meta"
                | "admission_authority_commits"
                | "chio_authority_migrations"
                | "admission_operation_commit_meta"
                | "budget_replication_meta"
                | "budget_snapshot_coverage"
                | "chio_channel_release_publisher_meta"
        ) {
            continue;
        }
        let row_count = connection.query_row(
            &format!("SELECT COUNT(*) FROM {}", quote_identifier(&table)),
            [],
            |row| row.get::<_, i64>(0),
        )?;
        if row_count != 0 {
            return Err(invalid(format!(
                "global authority baseline refuses nonempty safety table `{table}`"
            )));
        }
    }
    Ok(())
}

fn verify_pristine_baseline(connection: &Connection) -> Result<(), SqliteServingOwnerError> {
    verify_pristine_authority_tables(connection)?;

    let canonical_seeds = connection.query_row(
        r#"
        SELECT
            (SELECT COUNT(*) FROM admission_authority_meta) = 1
            AND EXISTS(
                SELECT 1 FROM admission_authority_meta
                WHERE singleton = 1 AND head_index = 1
            )
            AND (SELECT COUNT(*) FROM admission_authority_commits) = 1
            AND EXISTS(
                SELECT 1 FROM admission_authority_commits
                WHERE commit_index = 1 AND kind = 'genesis'
                  AND capability_id IS NULL
            )
            AND (SELECT COUNT(*) FROM chio_authority_migrations) = 1
            AND EXISTS(
                SELECT 1 FROM chio_authority_migrations
                WHERE migration_key = 'revocation-admission-authority-v1'
                  AND completed_index = 1
            )
            AND (SELECT COUNT(*) FROM admission_operation_commit_meta) = 1
            AND EXISTS(
                SELECT 1 FROM admission_operation_commit_meta
                WHERE singleton = 1 AND head_sequence = 0
                  AND head_chain_digest = ?1
                  AND trusted_time_high_water_unix_ms = 0
            )
            AND (SELECT COUNT(*) FROM budget_replication_meta) = 1
            AND EXISTS(
                SELECT 1 FROM budget_replication_meta
                WHERE singleton = 1 AND next_seq = 0
            )
            AND (SELECT COUNT(*) FROM budget_snapshot_coverage) = 1
            AND EXISTS(
                SELECT 1 FROM budget_snapshot_coverage
                WHERE singleton = 1 AND covered_head = 0
            )
            AND (SELECT COUNT(*) FROM chio_channel_release_publisher_meta) = 1
            AND EXISTS(
                SELECT 1 FROM chio_channel_release_publisher_meta
                WHERE singleton = 1 AND trusted_time_high_water_unix_ms = 0
            )
        "#,
        [GLOBAL_GENESIS_DIGEST],
        |row| row.get::<_, bool>(0),
    )?;
    if !canonical_seeds {
        return Err(invalid(
            "global authority baseline requires canonical empty safety state",
        ));
    }
    Ok(())
}

fn verify_live_baseline_projection(connection: &Connection) -> Result<(), SqliteServingOwnerError> {
    let committed = connection.query_row(
        r#"
        SELECT projection_reference_digest FROM authority_global_commits
        WHERE commit_sequence = 1 AND projection_kind = 'baseline'
        "#,
        [],
        |row| row.get::<_, String>(0),
    )?;
    if committed == baseline_projection_digest(connection)? {
        return Ok(());
    }
    let factor_assignment_empty = factor_assignment_projection_is_empty(connection)?;
    if factor_assignment_empty
        && committed == pre_factor_assignment_baseline_projection_digest(connection)?
    {
        return Ok(());
    }
    if factor_assignment_empty
        && channel_release_projection_is_empty(connection)?
        && committed == pre_channel_release_baseline_projection_digest(connection)?
    {
        return Ok(());
    }
    if factor_assignment_empty
        && channel_release_projection_is_empty(connection)?
        && channel_projection_is_empty(connection)?
        && committed == pre_channel_baseline_projection_digest(connection)?
    {
        return Ok(());
    }
    if factor_assignment_empty
        && channel_release_projection_is_empty(connection)?
        && payment_projection_is_empty(connection)?
        && committed == pre_payment_baseline_projection_digest(connection)?
    {
        return Ok(());
    }
    if factor_assignment_empty
        && channel_release_projection_is_empty(connection)?
        && channel_projection_is_empty(connection)?
        && payment_projection_is_empty(connection)?
        && committed == pre_channel_pre_payment_baseline_projection_digest(connection)?
    {
        return Ok(());
    }
    Err(invalid(
        "global authority baseline does not match its live projection",
    ))
}

fn pre_factor_assignment_baseline_projection_digest(
    connection: &Connection,
) -> Result<String, SqliteServingOwnerError> {
    baseline_projection_digest_for_tables(
        connection,
        without_factor_assignment_tables(table_names(connection, false)?),
    )
}

fn pre_channel_baseline_projection_digest(
    connection: &Connection,
) -> Result<String, SqliteServingOwnerError> {
    baseline_projection_digest_for_tables(
        connection,
        without_factor_assignment_tables(table_names(connection, false)?)
            .into_iter()
            .filter(|table| {
                !table.starts_with("channel_") && !table.starts_with("chio_channel_release_")
            })
            .collect(),
    )
}

fn pre_channel_release_baseline_projection_digest(
    connection: &Connection,
) -> Result<String, SqliteServingOwnerError> {
    baseline_projection_digest_for_tables(
        connection,
        without_factor_assignment_tables(table_names(connection, false)?)
            .into_iter()
            .filter(|table| !table.starts_with("chio_channel_release_"))
            .collect(),
    )
}

fn pre_payment_baseline_projection_digest(
    connection: &Connection,
) -> Result<String, SqliteServingOwnerError> {
    baseline_projection_digest_for_tables(
        connection,
        without_factor_assignment_tables(without_channel_release_tables(authority_table_names(
            connection, true, false,
        )?)),
    )
}

fn pre_channel_pre_payment_baseline_projection_digest(
    connection: &Connection,
) -> Result<String, SqliteServingOwnerError> {
    baseline_projection_digest_for_tables(
        connection,
        without_factor_assignment_tables(authority_table_names(connection, true, false)?)
            .into_iter()
            .filter(|table| {
                !table.starts_with("channel_") && !table.starts_with("chio_channel_release_")
            })
            .collect(),
    )
}

fn payment_projection_is_empty(connection: &Connection) -> Result<bool, SqliteServingOwnerError> {
    projection_is_empty(connection, "payment_")
}

fn channel_release_projection_is_empty(
    connection: &Connection,
) -> Result<bool, SqliteServingOwnerError> {
    connection
        .query_row(
            r#"
            SELECT
                (SELECT COUNT(*) FROM chio_channel_release_publications) = 0
                AND (SELECT COUNT(*) FROM chio_channel_release_publisher_meta) = 1
                AND EXISTS(
                    SELECT 1 FROM chio_channel_release_publisher_meta
                    WHERE singleton = 1 AND trusted_time_high_water_unix_ms = 0
                )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(Into::into)
}

fn channel_projection_is_empty(connection: &Connection) -> Result<bool, SqliteServingOwnerError> {
    projection_is_empty(connection, "channel_")
}

fn factor_assignment_projection_is_empty(
    connection: &Connection,
) -> Result<bool, SqliteServingOwnerError> {
    projection_is_empty(connection, "factor_assignment_")
}

fn projection_is_empty(
    connection: &Connection,
    table_prefix: &str,
) -> Result<bool, SqliteServingOwnerError> {
    for table in table_names(connection, false)? {
        if !table.starts_with(table_prefix) {
            continue;
        }
        let count = connection.query_row(
            &format!("SELECT COUNT(*) FROM {}", quote_identifier(&table)),
            [],
            |row| row.get::<_, i64>(0),
        )?;
        if count != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn without_channel_release_tables(tables: Vec<String>) -> Vec<String> {
    tables
        .into_iter()
        .filter(|table| !table.starts_with("chio_channel_release_"))
        .collect()
}

fn without_factor_assignment_tables(tables: Vec<String>) -> Vec<String> {
    tables
        .into_iter()
        .filter(|table| !table.starts_with("factor_assignment_"))
        .collect()
}

fn verify_global_projection_coverage(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    verify_channel_release_projection_coverage(connection)?;
    verify_finding_challenge_projection_coverage(connection)?;
    let incomplete = connection.query_row(
        r#"
        SELECT
            EXISTS(
                SELECT 1 FROM admission_operation_commits AS local
                WHERE (
                    SELECT COUNT(*) FROM authority_global_commits AS global
                    WHERE global.projection_kind = 'admission'
                      AND global.projection_key = local.operation_id
                      AND global.projection_sequence = local.commit_sequence
                ) <> 1
            )
            OR EXISTS(
                SELECT 1 FROM budget_mutation_events AS local
                WHERE (
                    SELECT COUNT(*) FROM authority_global_commits AS global
                    WHERE global.projection_kind = 'budget'
                      AND global.projection_key = local.event_id
                      AND global.projection_sequence = local.event_seq
                ) <> 1
            )
            OR EXISTS(
                SELECT 1 FROM admission_authority_commits AS local
                WHERE local.kind = 'revocation'
                  AND (
                      SELECT COUNT(*) FROM authority_global_commits AS global
                      WHERE global.projection_kind = 'revocation'
                        AND global.projection_key = local.capability_id
                        AND global.projection_sequence = local.commit_index
                ) <> 1
            )
            OR EXISTS(
                SELECT 1 FROM frost_projection_commits AS local
                WHERE (
                    SELECT COUNT(*) FROM authority_global_commits AS global
                    WHERE global.projection_kind = 'frost'
                      AND global.projection_key = local.projection_key
                      AND global.projection_sequence = local.projection_sequence
                ) <> 1
            )
            OR EXISTS(
                SELECT 1 FROM payment_journal AS local
                WHERE (
                    SELECT COUNT(*) FROM authority_global_commits AS global
                    WHERE global.projection_kind = 'payment'
                      AND global.projection_key = local.operation_id
                      AND global.projection_sequence = local.journal_version
                ) <> 1
            )
            OR EXISTS(
                SELECT 1 FROM economic_state_stage_commits AS local
                WHERE (
                    SELECT COUNT(*) FROM authority_global_commits AS global
                    WHERE global.projection_kind = 'economic'
                      AND global.projection_key = local.batch_id
                      AND global.projection_sequence = local.stage_version
                ) <> 1
            )
            OR EXISTS(
                SELECT 1 FROM fiscal_projection_commits AS local
                WHERE (
                    SELECT COUNT(*) FROM authority_global_commits AS global
                    WHERE global.projection_kind = 'fiscal'
                      AND global.projection_key = local.projection_key
                      AND global.projection_sequence = local.projection_sequence
                ) <> 1
            )
            OR EXISTS(
                SELECT 1 FROM factor_assignment_authority_sets AS local
                WHERE (
                    SELECT COUNT(*) FROM authority_global_commits AS global
                    WHERE global.projection_kind = 'factor_assignment_authority_set'
                      AND global.projection_key = 'active'
                      AND global.projection_sequence = local.generation
                ) <> 1
            )
            OR EXISTS(
                SELECT 1 FROM authority_global_commits AS global
                WHERE global.projection_kind = 'factor_assignment_authority_set'
                  AND (
                      global.projection_key <> 'active'
                      OR NOT EXISTS(
                          SELECT 1 FROM factor_assignment_authority_sets AS local
                          WHERE local.generation = global.projection_sequence
                      )
                  )
            )
            OR EXISTS(
                SELECT 1 FROM authority_global_commits AS global
                WHERE global.projection_kind = 'payment'
                  AND NOT EXISTS(
                      SELECT 1 FROM payment_journal AS local
                      WHERE local.operation_id = global.projection_key
                        AND local.journal_version >= global.projection_sequence
                  )
            )
        "#,
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if incomplete {
        return Err(invalid("global authority projection coverage is not exact"));
    }
    Ok(())
}

pub(super) fn verify_finding_challenge_projection_coverage(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    let projection_table_present = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'finding_challenge_projection_commits')",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if !projection_table_present {
        let global_reference_present = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind = 'finding_challenge')",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        return if global_reference_present {
            Err(invalid("finding challenge projection table is absent"))
        } else {
            Ok(())
        };
    }
    let mut statement = connection.prepare(
        r#"
        SELECT projection_sequence, mutation_kind, snapshot_digest,
               previous_commit_digest, commit_digest
        FROM finding_challenge_projection_commits
        ORDER BY projection_sequence
        "#,
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut previous = GLOBAL_GENESIS_DIGEST.to_owned();
    let mut expected_sequence = 1_u64;
    for (stored_sequence, mutation_kind, snapshot_digest, previous_digest, commit_digest) in &rows {
        let sequence = read_u64(*stored_sequence, "finding challenge projection sequence")?;
        if sequence != expected_sequence
            || mutation_kind != "finding_challenge_write"
            || previous_digest != &previous
            || !is_digest(snapshot_digest)
            || !is_digest(commit_digest)
        {
            return Err(invalid("finding challenge projection chain is malformed"));
        }
        let expected_digest = digest(&FindingChallengeProjectionEntry {
            format: "chio.sqlite-finding-challenge-projection.v1",
            previous_commit_digest: &previous,
            projection_sequence: sequence,
            mutation_kind,
            snapshot_digest,
        })?;
        if expected_digest != *commit_digest {
            return Err(invalid("finding challenge projection digest mismatch"));
        }
        let global_count = connection.query_row(
            r#"
            SELECT COUNT(*) FROM authority_global_commits
            WHERE projection_kind = 'finding_challenge'
              AND projection_key = 'market' AND projection_sequence = ?1
            "#,
            [sqlite_u64(
                sequence,
                "finding challenge projection sequence",
            )?],
            |row| row.get::<_, i64>(0),
        )?;
        if global_count != 1 {
            return Err(invalid(
                "finding challenge global projection coverage is not exact",
            ));
        }
        previous.clone_from(commit_digest);
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| invalid("finding challenge projection sequence overflowed"))?;
    }
    let orphaned_global = connection.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM authority_global_commits AS global
            WHERE global.projection_kind = 'finding_challenge'
              AND (
                  global.projection_key <> 'market'
                  OR NOT EXISTS(
                      SELECT 1 FROM finding_challenge_projection_commits AS local
                      WHERE local.projection_sequence = global.projection_sequence
                  )
              )
        )
        "#,
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if orphaned_global {
        return Err(invalid(
            "finding challenge global projection reference is orphaned",
        ));
    }
    let has_state = connection.query_row(
        r#"
        SELECT EXISTS(SELECT 1 FROM challenges)
            OR EXISTS(SELECT 1 FROM dispute_lock_reservations)
            OR EXISTS(SELECT 1 FROM dispute_locks)
            OR EXISTS(SELECT 1 FROM liability_heads)
            OR EXISTS(SELECT 1 FROM finding_finalizing_authorizations)
            OR EXISTS(SELECT 1 FROM finding_finalizing_authorization_refreshes)
            OR EXISTS(SELECT 1 FROM governance_case_index)
            OR EXISTS(SELECT 1 FROM claim_snapshots)
            OR EXISTS(SELECT 1 FROM effect_intents)
            OR EXISTS(SELECT 1 FROM effect_root_bindings)
            OR EXISTS(SELECT 1 FROM finding_challenge_outcomes)
            OR EXISTS(SELECT 1 FROM listing_sales_blocks)
            OR EXISTS(SELECT 1 FROM purchase_records)
            OR EXISTS(SELECT 1 FROM failed_delivery_records)
            OR EXISTS(SELECT 1 FROM purchase_reservations)
            OR EXISTS(SELECT 1 FROM payout_destinations)
        "#,
        [],
        |row| row.get::<_, bool>(0),
    )?;
    match rows.last() {
        Some((_, _, snapshot_digest, _, _)) => {
            let current_market = finding_market_snapshot_digest(connection)?;
            let current_market_v11 = finding_market_snapshot_digest_v11(connection)?;
            let current_market_v10 = finding_market_snapshot_digest_v10(connection)?;
            let current_market_v9 = finding_market_snapshot_digest_v9(connection)?;
            let current_market_v8 = finding_market_snapshot_digest_v8(connection)?;
            let current_market_v7 = finding_market_snapshot_digest_v7(connection)?;
            let current_market_v6 = finding_market_snapshot_digest_v6(connection)?;
            let current_market_v5 = finding_market_snapshot_digest_v5(connection)?;
            let current_market_v4 = finding_market_snapshot_digest_v4(connection)?;
            let current_market_v3 = finding_market_snapshot_digest_v3(connection)?;
            let current_market_v2 = finding_market_snapshot_digest_v2(connection)?;
            let current_legacy = finding_challenge_snapshot_digest_v1(connection)?;
            let has_uncommitted_purchase_state = connection.query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1 FROM purchase_reservations
                    WHERE state IN ('open', 'slot_reserved')
                      AND reservation_id NOT IN (
                          SELECT reservation_id FROM purchase_records
                      )
                )
                "#,
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let has_v6_root_binding = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM effect_root_bindings)",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let has_v7_outcome = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM finding_challenge_outcomes)",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let has_v8_capture_intent = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM purchase_capture_intents)",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let has_v9_failed_delivery = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM failed_delivery_records)",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let has_v10_finalizing_authorization = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM finding_finalizing_authorizations)",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let has_v10_actionable_payout_slot = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM payout_destinations WHERE slot_index > 0)",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let has_v11_finalizing_authorization_refresh = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM finding_finalizing_authorization_refreshes)",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let has_v12_terminal_reservation = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM purchase_reservations WHERE state IN ('released', 'expired'))",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let uncovered_before_v10 = current_market_v9 != *snapshot_digest
                && (has_v9_failed_delivery
                    || (current_market_v8 != *snapshot_digest
                        && (has_v8_capture_intent
                            || (current_market_v7 != *snapshot_digest
                                && (has_uncommitted_purchase_state
                                    || has_v7_outcome
                                    || (current_market_v6 != *snapshot_digest
                                        && (has_v6_root_binding
                                            || (current_market_v4 != *snapshot_digest
                                                && current_market_v5 != *snapshot_digest
                                                && current_market_v3 != *snapshot_digest
                                                && current_market_v2 != *snapshot_digest
                                                && current_legacy != *snapshot_digest))))))));
            let uncovered_before_v11 = current_market_v10 != *snapshot_digest
                && (has_v10_finalizing_authorization
                    || has_v10_actionable_payout_slot
                    || uncovered_before_v10);
            let uncovered_before_v12 = current_market_v11 != *snapshot_digest
                && (has_v11_finalizing_authorization_refresh || uncovered_before_v11);
            if current_market != *snapshot_digest
                && (has_v12_terminal_reservation || uncovered_before_v12)
            {
                return Err(invalid(
                    "finding challenge projection does not cover current state",
                ));
            }
        }
        None if has_state => {
            return Err(invalid(
                "finding challenge state has no authenticated projection",
            ));
        }
        None => {}
    }
    Ok(())
}

fn verify_channel_release_projection_coverage(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    let exact = connection.query_row(
        r#"
        SELECT
            NOT EXISTS(
                SELECT 1 FROM chio_channel_release_publications AS local
                WHERE (
                    SELECT COUNT(*) FROM authority_global_commits AS global
                    WHERE global.projection_kind = 'channel_release_publication'
                      AND global.projection_key = local.channel_id
                      AND global.projection_sequence BETWEEN 1 AND local.record_version
                ) <> local.record_version
                OR (
                    SELECT COUNT(DISTINCT global.projection_sequence)
                    FROM authority_global_commits AS global
                    WHERE global.projection_kind = 'channel_release_publication'
                      AND global.projection_key = local.channel_id
                      AND global.projection_sequence BETWEEN 1 AND local.record_version
                ) <> local.record_version
            )
            AND NOT EXISTS(
                SELECT 1 FROM authority_global_commits AS global
                WHERE global.projection_kind = 'channel_release_publication'
                  AND NOT EXISTS(
                      SELECT 1 FROM chio_channel_release_publications AS local
                      WHERE local.channel_id = global.projection_key
                        AND local.record_version >= global.projection_sequence
                  )
            )
        "#,
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if !exact {
        return Err(invalid(
            "channel release global projection coverage is not exact",
        ));
    }
    Ok(())
}

fn table_names(
    connection: &Connection,
    budget_event_only: bool,
) -> Result<Vec<String>, SqliteServingOwnerError> {
    if budget_event_only {
        let mut statement = connection.prepare(
            r#"
        SELECT name FROM sqlite_schema
        WHERE type = 'table'
          AND (name = 'budget_mutation_events' OR name GLOB 'budget_event_*')
        ORDER BY name
        "#,
        )?;
        return statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into);
    }
    authority_table_names(connection, true, true)
}

fn authority_table_names(
    connection: &Connection,
    include_frost: bool,
    include_payment: bool,
) -> Result<Vec<String>, SqliteServingOwnerError> {
    let mut statement = connection.prepare(
        r#"
        SELECT name FROM sqlite_schema
        WHERE type = 'table'
          AND (
              name = 'capability_grant_budgets'
              OR name = 'revoked_capabilities'
              OR name = 'chio_authority_migrations'
              OR name GLOB 'admission_operation*'
              OR name GLOB 'admission_authority_*'
              OR name GLOB 'budget_*'
              OR name GLOB 'channel_*'
              OR name GLOB 'chio_channel_release_*'
              OR name GLOB 'factor_assignment_*'
              OR (?1 AND name GLOB 'frost_*')
              OR (?2 AND name GLOB 'payment_*')
          )
          AND name NOT IN ('budget_ack_head_watermark', 'budget_origin_ack_heads')
        ORDER BY name
        "#,
    )?;
    let names = statement
        .query_map(params![include_frost, include_payment], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(names)
}

fn baseline_projection_digest_for_tables(
    connection: &Connection,
    tables: Vec<String>,
) -> Result<String, SqliteServingOwnerError> {
    let mut snapshots = Vec::with_capacity(tables.len());
    for table in tables {
        snapshots.push(table_snapshot(connection, &table, None)?);
    }
    digest(&AuthoritySnapshot {
        format: "chio.sqlite-authority-projection.v1",
        tables: snapshots,
    })
}

fn table_snapshot(
    connection: &Connection,
    table: &str,
    filter: Option<(&str, &str)>,
) -> Result<TableSnapshot, SqliteServingOwnerError> {
    let table_identifier = quote_identifier(table);
    let probe = connection.prepare(&format!("SELECT * FROM {table_identifier} LIMIT 0"))?;
    let columns = probe
        .column_names()
        .into_iter()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    drop(probe);
    if let Some((column, _)) = filter {
        if !columns.iter().any(|candidate| candidate == column) {
            return Err(invalid(format!(
                "projection table `{table}` lost `{column}`"
            )));
        }
    }
    let order = columns
        .iter()
        .map(|column| quote_identifier(column))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = match filter {
        Some((column, _)) => format!(
            "SELECT * FROM {table_identifier} WHERE {} = ?1 ORDER BY {order}",
            quote_identifier(column)
        ),
        None => format!("SELECT * FROM {table_identifier} ORDER BY {order}"),
    };
    let mut statement = connection.prepare(&sql)?;
    let mut rows = match filter {
        Some((_, value)) => statement.query([value])?,
        None => statement.query([])?,
    };
    let mut row_digests = Vec::new();
    while let Some(row) = rows.next()? {
        let mut values = Vec::with_capacity(columns.len());
        for index in 0..columns.len() {
            values.push(snapshot_value(row.get_ref(index)?));
        }
        row_digests.push(digest(&values)?);
    }
    Ok(TableSnapshot {
        name: table.to_string(),
        columns,
        row_digests,
    })
}

/// Reproduce an older snapshot after a schema revision adds one column.
/// This is verification-only compatibility for an authenticated prior
/// head; every new commit uses the complete current table shape.
fn table_snapshot_without_column(
    connection: &Connection,
    table: &str,
    excluded: &str,
) -> Result<TableSnapshot, SqliteServingOwnerError> {
    let table_identifier = quote_identifier(table);
    let probe = connection.prepare(&format!("SELECT * FROM {table_identifier} LIMIT 0"))?;
    let columns = probe
        .column_names()
        .into_iter()
        .filter(|column| *column != excluded)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    drop(probe);
    if columns.is_empty() {
        return Err(invalid(format!(
            "projection table `{table}` has no retained columns"
        )));
    }
    let order = columns
        .iter()
        .map(|column| quote_identifier(column))
        .collect::<Vec<_>>()
        .join(", ");
    let mut statement = connection.prepare(&format!(
        "SELECT {order} FROM {table_identifier} ORDER BY {order}"
    ))?;
    let mut rows = statement.query([])?;
    let mut row_digests = Vec::new();
    while let Some(row) = rows.next()? {
        let mut values = Vec::with_capacity(columns.len());
        for index in 0..columns.len() {
            values.push(snapshot_value(row.get_ref(index)?));
        }
        row_digests.push(digest(&values)?);
    }
    Ok(TableSnapshot {
        name: table.to_owned(),
        columns,
        row_digests,
    })
}

/// Snapshot one table under a fixed internal predicate. Callers supply
/// only static predicates defined beside a projection, never external
/// input; table identifiers are still quoted and rows retain the same
/// canonical full-column ordering as an unfiltered snapshot.
fn table_snapshot_where(
    connection: &Connection,
    table: &str,
    predicate: &'static str,
) -> Result<TableSnapshot, SqliteServingOwnerError> {
    let table_identifier = quote_identifier(table);
    let probe = connection.prepare(&format!("SELECT * FROM {table_identifier} LIMIT 0"))?;
    let columns = probe
        .column_names()
        .into_iter()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    drop(probe);
    let order = columns
        .iter()
        .map(|column| quote_identifier(column))
        .collect::<Vec<_>>()
        .join(", ");
    let mut statement = connection.prepare(&format!(
        "SELECT * FROM {table_identifier} WHERE {predicate} ORDER BY {order}"
    ))?;
    let mut rows = statement.query([])?;
    let mut row_digests = Vec::new();
    while let Some(row) = rows.next()? {
        let mut values = Vec::with_capacity(columns.len());
        for index in 0..columns.len() {
            values.push(snapshot_value(row.get_ref(index)?));
        }
        row_digests.push(digest(&values)?);
    }
    Ok(TableSnapshot {
        name: table.to_string(),
        columns,
        row_digests,
    })
}

fn snapshot_value(value: ValueRef<'_>) -> SnapshotValue {
    match value {
        ValueRef::Null => SnapshotValue::Null,
        ValueRef::Integer(value) => SnapshotValue::Integer(value),
        ValueRef::Real(value) => SnapshotValue::RealBits(format!("{:016x}", value.to_bits())),
        ValueRef::Text(value) => SnapshotValue::TextHex(hex_bytes(value)),
        ValueRef::Blob(value) => SnapshotValue::BlobHex(hex_bytes(value)),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(crate) fn reset_derived_budget_ack_cache(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    connection.execute(
        "UPDATE budget_ack_head_watermark SET head_seq = 0 WHERE singleton = 1",
        [],
    )?;
    connection.execute("DELETE FROM budget_origin_ack_heads", [])?;
    Ok(())
}

fn global_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SchemaCatalogEntry>, SqliteServingOwnerError> {
    let mut statement = connection.prepare(
        r#"
        SELECT type, name, tbl_name, sql FROM sqlite_schema
        WHERE name GLOB 'authority_global_commit*'
           OR tbl_name GLOB 'authority_global_commit*'
        ORDER BY type, name, tbl_name
        "#,
    )?;
    let catalog = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(catalog)
}

fn chain_digest(entry: &ChainEntry<'_>) -> Result<String, SqliteServingOwnerError> {
    digest(entry)
}

fn projection_root_digest(
    entry: &ProjectionRootEntry<'_>,
) -> Result<String, SqliteServingOwnerError> {
    digest(entry)
}

fn digest(value: &impl Serialize) -> Result<String, SqliteServingOwnerError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| {
            invalid(format!(
                "global authority canonical encoding failed: {error}"
            ))
        })
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid(detail: impl Into<String>) -> SqliteServingOwnerError {
    SqliteServingOwnerError::Invalid(detail.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immediately_previous_global_schema_migrates_to_finding_challenge_kind(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        let previous_schema = GLOBAL_COMMIT_SCHEMA.replace(", 'finding_challenge'", "");
        connection.execute_batch(&previous_schema)?;
        assert!(verify_global_commit_schema(&connection).is_err());
        initialize_global_commit_schema(&connection)?;
        verify_global_commit_schema(&connection)?;
        Ok(())
    }

    fn projection_fixture() -> Result<Connection, rusqlite::Error> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            r#"
                CREATE TABLE budget_mutation_events (event_id TEXT PRIMARY KEY);
                CREATE TABLE channel_lifecycle_records (channel_id TEXT PRIMARY KEY);
                CREATE TABLE channel_prepared_admission_plans (operation_id TEXT PRIMARY KEY);
                CREATE TABLE frost_nonce_commitments (nonce_id TEXT PRIMARY KEY);
                CREATE TABLE payment_journal (operation_id TEXT PRIMARY KEY);
                CREATE TABLE payment_release_evidence (evidence_id TEXT PRIMARY KEY);
                "#,
        )?;
        Ok(connection)
    }

    fn factor_projection_fixture() -> Result<Connection, rusqlite::Error> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            r#"
            CREATE TABLE admission_operation_commits (
                operation_id TEXT NOT NULL,
                commit_sequence INTEGER NOT NULL
            );
            CREATE TABLE budget_mutation_events (
                event_id TEXT NOT NULL,
                event_seq INTEGER NOT NULL
            );
            CREATE TABLE admission_authority_commits (
                kind TEXT NOT NULL,
                capability_id TEXT NOT NULL,
                commit_index INTEGER NOT NULL
            );
            CREATE TABLE frost_projection_commits (
                projection_key TEXT NOT NULL,
                projection_sequence INTEGER NOT NULL
            );
            CREATE TABLE payment_journal (
                operation_id TEXT NOT NULL,
                journal_version INTEGER NOT NULL
            );
            CREATE TABLE economic_state_stage_commits (
                batch_id TEXT NOT NULL,
                stage_version INTEGER NOT NULL
            );
            CREATE TABLE chio_channel_release_publications (
                channel_id TEXT NOT NULL,
                record_version INTEGER NOT NULL
            );
            CREATE TABLE factor_assignment_authority_sets (
                generation INTEGER NOT NULL PRIMARY KEY,
                active_set_digest TEXT NOT NULL,
                previous_active_set_digest TEXT,
                activated_at_unix_ms INTEGER NOT NULL,
                store_uuid TEXT NOT NULL,
                store_lease_id TEXT NOT NULL,
                store_owner_epoch INTEGER NOT NULL
            );
            CREATE TABLE fiscal_projection_commits (
                projection_key TEXT NOT NULL,
                projection_sequence INTEGER NOT NULL,
                commit_digest TEXT NOT NULL
            );
            CREATE TABLE authority_global_commits (
                projection_kind TEXT NOT NULL,
                projection_key TEXT NOT NULL,
                projection_sequence INTEGER NOT NULL
            );
            INSERT INTO factor_assignment_authority_sets (
                generation, active_set_digest, previous_active_set_digest,
                activated_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (
                1,
                'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                NULL,
                1000,
                'store-1',
                'lease-1',
                1
            );
            "#,
        )?;
        Ok(connection)
    }

    fn factor_commit(reference_digest: String) -> CommitRow {
        CommitRow {
            sequence: 2,
            mutation_kind: "factor_assignment_authority_set".to_string(),
            projection_kind: "factor_assignment_authority_set".to_string(),
            projection_key: "active".to_string(),
            projection_sequence: 1,
            projection_reference_digest: reference_digest,
            authority_projection_digest: GLOBAL_GENESIS_DIGEST.to_string(),
            previous_chain_digest: GLOBAL_GENESIS_DIGEST.to_string(),
            chain_digest: GLOBAL_GENESIS_DIGEST.to_string(),
            store_uuid: "store-1".to_string(),
            store_lease_id: Some("lease-1".to_string()),
            store_owner_epoch: 1,
        }
    }

    fn insert_factor_global_commit(
        connection: &Connection,
        key: &str,
        generation: i64,
    ) -> Result<(), rusqlite::Error> {
        connection.execute(
            r#"
            INSERT INTO authority_global_commits (
                projection_kind, projection_key, projection_sequence
            ) VALUES ('factor_assignment_authority_set', ?1, ?2)
            "#,
            params![key, generation],
        )?;
        Ok(())
    }

    #[test]
    fn authority_snapshot_includes_payment_projection() -> Result<(), Box<dyn std::error::Error>> {
        let connection = projection_fixture()?;

        assert_eq!(
            table_names(&connection, false)?,
            vec![
                "budget_mutation_events",
                "channel_lifecycle_records",
                "channel_prepared_admission_plans",
                "frost_nonce_commitments",
                "payment_journal",
                "payment_release_evidence",
            ]
        );
        assert_ne!(
            baseline_projection_digest(&connection)?,
            pre_payment_baseline_projection_digest(&connection)?
        );
        Ok(())
    }

    #[test]
    fn pre_payment_compatibility_requires_empty_payment_projection(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = projection_fixture()?;
        assert!(payment_projection_is_empty(&connection)?);

        connection.execute(
            "INSERT INTO payment_journal (operation_id) VALUES ('operation-1')",
            [],
        )?;

        assert!(!payment_projection_is_empty(&connection)?);
        Ok(())
    }

    #[test]
    fn pre_channel_compatibility_requires_every_channel_table_to_be_empty(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = projection_fixture()?;
        assert!(projection_is_empty(&connection, "channel_")?);

        connection.execute(
            "INSERT INTO channel_prepared_admission_plans (operation_id) VALUES ('operation-1')",
            [],
        )?;

        assert!(!projection_is_empty(&connection, "channel_")?);
        Ok(())
    }

    #[test]
    fn pre_factor_assignment_compatibility_requires_empty_projection(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute(
            "CREATE TABLE factor_assignment_authority_sets (generation INTEGER PRIMARY KEY)",
            [],
        )?;

        assert!(factor_assignment_projection_is_empty(&connection)?);
        assert_ne!(
            baseline_projection_digest(&connection)?,
            pre_factor_assignment_baseline_projection_digest(&connection)?
        );

        connection.execute(
            "INSERT INTO factor_assignment_authority_sets (generation) VALUES (1)",
            [],
        )?;

        assert!(!factor_assignment_projection_is_empty(&connection)?);
        Ok(())
    }

    #[test]
    fn factor_assignment_authority_reference_is_exact() -> Result<(), Box<dyn std::error::Error>> {
        let connection = factor_projection_fixture()?;
        let reference = projection_reference_digest(
            &connection,
            "factor_assignment_authority_set",
            "active",
            1,
        )?;
        assert_eq!(
            reference,
            "65555c1ac79c44d41687384af06f00a441f0a1fd738d1415e74bdf136651f429"
        );
        let commit = factor_commit(reference);

        assert!(verify_projection_reference(&connection, &commit).is_ok());

        connection.execute(
            r#"
            UPDATE factor_assignment_authority_sets
            SET active_set_digest =
                'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
            WHERE generation = 1
            "#,
            [],
        )?;

        assert!(verify_projection_reference(&connection, &commit).is_err());
        Ok(())
    }

    #[test]
    fn factor_assignment_authority_coverage_is_exact_and_closed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = factor_projection_fixture()?;
        assert!(verify_global_projection_coverage(&connection).is_err());

        for (key, generation, exact) in [
            ("active", 1, true),
            ("retained", 1, false),
            ("active", 2, false),
        ] {
            let connection = factor_projection_fixture()?;
            insert_factor_global_commit(&connection, key, generation)?;
            assert_eq!(
                verify_global_projection_coverage(&connection).is_ok(),
                exact
            );
        }
        Ok(())
    }

    #[test]
    fn channel_release_projection_references_are_exact_and_unknown_kinds_stay_closed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            r#"
            CREATE TABLE chio_channel_release_publications (
                channel_id TEXT PRIMARY KEY,
                record_version INTEGER NOT NULL,
                publication_binding_digest TEXT NOT NULL,
                status TEXT NOT NULL
            );
            CREATE TABLE authority_global_commits (
                projection_kind TEXT NOT NULL,
                projection_key TEXT NOT NULL,
                projection_sequence INTEGER NOT NULL
            );
            INSERT INTO chio_channel_release_publications
                (channel_id, record_version, publication_binding_digest, status)
            VALUES ('channel-1', 1, 'binding-1', 'dispatch_committed');
            INSERT INTO authority_global_commits
                (projection_kind, projection_key, projection_sequence)
            VALUES ('channel_release_publication', 'channel-1', 1);
            "#,
        )?;

        assert!(projection_reference_digest(
            &connection,
            "channel_release_publication",
            "channel-1",
            1,
        )
        .is_ok());
        assert!(projection_reference_digest(
            &connection,
            "channel_release_publication",
            "channel-1",
            2,
        )
        .is_err());
        assert!(projection_reference_digest(&connection, "unknown", "channel-1", 1).is_err());
        assert!(verify_channel_release_projection_coverage(&connection).is_ok());

        connection.execute_batch(
            r#"
            UPDATE chio_channel_release_publications SET record_version = 3;
            INSERT INTO authority_global_commits
                (projection_kind, projection_key, projection_sequence)
            VALUES
                ('channel_release_publication', 'channel-1', 1),
                ('channel_release_publication', 'channel-1', 3);
            "#,
        )?;
        assert!(verify_channel_release_projection_coverage(&connection).is_err());
        Ok(())
    }
}
