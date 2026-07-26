use rusqlite::Connection;

use super::{read_u64, SqliteServingOwnerError};

const SERVING_LEASE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS chio_serving_leases (
    store_uuid TEXT NOT NULL,
    owner_epoch INTEGER NOT NULL CHECK (owner_epoch > 0),
    lease_id TEXT NOT NULL CHECK (lease_id <> ''),
    start_head_index INTEGER NOT NULL CHECK (start_head_index > 0),
    end_head_index INTEGER CHECK (
        end_head_index IS NULL OR end_head_index >= start_head_index
    ),
    opened_at_ms INTEGER NOT NULL CHECK (opened_at_ms > 0),
    PRIMARY KEY (store_uuid, owner_epoch),
    UNIQUE (lease_id),
    FOREIGN KEY (store_uuid) REFERENCES chio_serving_owner(store_uuid)
);

CREATE TRIGGER IF NOT EXISTS chio_serving_leases_close_only
BEFORE UPDATE ON chio_serving_leases
WHEN NOT (
    OLD.store_uuid IS NEW.store_uuid
    AND OLD.owner_epoch IS NEW.owner_epoch
    AND OLD.lease_id IS NEW.lease_id
    AND OLD.start_head_index IS NEW.start_head_index
    AND OLD.opened_at_ms IS NEW.opened_at_ms
    AND OLD.end_head_index IS NULL
    AND NEW.end_head_index IS NOT NULL
    AND NEW.end_head_index >= OLD.start_head_index
)
BEGIN
    SELECT RAISE(ABORT, 'serving lease history is immutable');
END;

CREATE TRIGGER IF NOT EXISTS chio_serving_leases_no_delete
BEFORE DELETE ON chio_serving_leases
BEGIN
    SELECT RAISE(ABORT, 'serving lease history is immutable');
END;
"#;

pub(super) fn initialize_serving_lease_schema(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    connection.execute_batch(SERVING_LEASE_SCHEMA)?;
    verify_serving_lease_schema(connection)
}

type SchemaCatalogEntry = (String, String, String, Option<String>);

fn serving_lease_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SchemaCatalogEntry>, SqliteServingOwnerError> {
    let mut statement = connection.prepare(
        r#"
        SELECT type, name, tbl_name, sql
        FROM sqlite_schema
        WHERE name GLOB '*chio_serving_leases*'
           OR tbl_name = 'chio_serving_leases'
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

fn verify_serving_lease_schema(connection: &Connection) -> Result<(), SqliteServingOwnerError> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(SERVING_LEASE_SCHEMA)?;
    if serving_lease_schema_catalog(connection)? != serving_lease_schema_catalog(&expected)? {
        return Err(SqliteServingOwnerError::Invalid(
            "serving lease schema differs from the canonical definition".to_string(),
        ));
    }
    Ok(())
}

struct ServingLeaseRecord {
    store_uuid: String,
    owner_epoch: u64,
    lease_id: String,
    start_head_index: u64,
    end_head_index: Option<u64>,
    opened_at_ms: u64,
}

pub(super) fn verify_serving_lease_history(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    verify_serving_lease_schema(connection)?;
    let (store_uuid, owner_epoch, active_lease_id, active_opened_at_ms) = connection.query_row(
        r#"
        SELECT store_uuid, owner_epoch, lease_id, opened_at_ms
        FROM chio_serving_owner WHERE singleton = 1
        "#,
        [],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        },
    )?;
    let owner_epoch = read_u64(owner_epoch, "owner_epoch")?;
    let authority_head = connection.query_row(
        "SELECT head_index FROM admission_authority_meta WHERE singleton = 1",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let authority_head = read_u64(authority_head, "admission authority head")?;

    let mut statement = connection.prepare(
        r#"
        SELECT store_uuid, owner_epoch, lease_id,
               start_head_index, end_head_index, opened_at_ms
        FROM chio_serving_leases
        ORDER BY owner_epoch ASC
        "#,
    )?;
    let leases = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Option<i64>>(4)?,
            row.get::<_, i64>(5)?,
        ))
    })?;

    let mut expected_epoch = 1_u64;
    let mut previous_end = None;
    for lease in leases {
        let lease = lease?;
        let lease = ServingLeaseRecord {
            store_uuid: lease.0,
            owner_epoch: read_u64(lease.1, "serving lease owner_epoch")?,
            lease_id: lease.2,
            start_head_index: read_u64(lease.3, "serving lease start_head_index")?,
            end_head_index: lease
                .4
                .map(|value| read_u64(value, "serving lease end_head_index"))
                .transpose()?,
            opened_at_ms: read_u64(lease.5, "serving lease opened_at_ms")?,
        };
        if lease.store_uuid != store_uuid
            || lease.owner_epoch != expected_epoch
            || lease.lease_id.is_empty()
            || lease.start_head_index == 0
            || lease.start_head_index > authority_head
            || lease.opened_at_ms == 0
            || previous_end.is_some_and(|end| end != lease.start_head_index)
        {
            return Err(SqliteServingOwnerError::Invalid(
                "serving lease history is not a dense authority chain".to_string(),
            ));
        }
        if lease.owner_epoch < owner_epoch {
            let end = lease.end_head_index.ok_or_else(|| {
                SqliteServingOwnerError::Invalid("a prior serving lease remains open".to_string())
            })?;
            if end < lease.start_head_index || end > authority_head {
                return Err(SqliteServingOwnerError::Invalid(
                    "a prior serving lease has an invalid authority interval".to_string(),
                ));
            }
            previous_end = Some(end);
        } else if lease.owner_epoch == owner_epoch {
            let active_opened_at_ms = active_opened_at_ms
                .ok_or_else(|| {
                    SqliteServingOwnerError::Invalid(
                        "active serving owner has no open timestamp".to_string(),
                    )
                })
                .and_then(|value| read_u64(value, "active serving owner opened_at_ms"))?;
            if lease.end_head_index.is_some()
                || active_lease_id.as_deref() != Some(lease.lease_id.as_str())
                || active_opened_at_ms != lease.opened_at_ms
            {
                return Err(SqliteServingOwnerError::Invalid(
                    "active serving lease does not match its owner fence".to_string(),
                ));
            }
            previous_end = None;
        } else {
            return Err(SqliteServingOwnerError::Invalid(
                "serving lease history extends beyond its owner epoch".to_string(),
            ));
        }
        expected_epoch = expected_epoch.checked_add(1).ok_or_else(|| {
            SqliteServingOwnerError::Invalid("serving lease epoch overflowed u64".to_string())
        })?;
    }

    let lease_count = expected_epoch - 1;
    if owner_epoch == 0 {
        if lease_count != 0 || active_lease_id.is_some() || active_opened_at_ms.is_some() {
            return Err(SqliteServingOwnerError::Invalid(
                "inactive serving owner has lease history".to_string(),
            ));
        }
    } else if lease_count != owner_epoch || previous_end.is_some() {
        return Err(SqliteServingOwnerError::Invalid(
            "serving lease history does not end at the active owner epoch".to_string(),
        ));
    }
    Ok(())
}
