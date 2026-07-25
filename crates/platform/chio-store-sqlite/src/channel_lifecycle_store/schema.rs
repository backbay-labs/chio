use super::*;

type SchemaCatalogEntry = (String, String, String, Option<String>);

pub(crate) fn initialize_channel_lifecycle_schema(
    connection: &mut Connection,
) -> Result<(), SqliteServingOwnerError> {
    let on_disk = crate::check_schema_version(
        connection,
        CHANNEL_LIFECYCLE_SCHEMA_KEY,
        CHANNEL_LIFECYCLE_SUPPORTED_SCHEMA_VERSION,
        CHANNEL_LIFECYCLE_SCHEMA_ANCHORS,
    )
    .map_err(|error| invalid_owner(error.to_string()))?;
    if on_disk == CHANNEL_LIFECYCLE_SUPPORTED_SCHEMA_VERSION {
        return verify_channel_lifecycle_invariants(connection);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(CHANNEL_LIFECYCLE_SCHEMA)?;
    crate::stamp_schema_version(
        &transaction,
        CHANNEL_LIFECYCLE_SCHEMA_KEY,
        CHANNEL_LIFECYCLE_SUPPORTED_SCHEMA_VERSION,
    )
    .map_err(|error| invalid_owner(error.to_string()))?;
    verify_channel_lifecycle_invariants(&transaction)?;
    transaction.commit().map_err(|error| {
        SqliteServingOwnerError::OutcomeUnknown(format!(
            "sqlite channel lifecycle schema commit outcome is unknown: {error}"
        ))
    })
}

pub(crate) fn verify_channel_lifecycle_invariants(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(CHANNEL_LIFECYCLE_SCHEMA)?;
    if channel_schema_catalog(connection)? != channel_schema_catalog(&expected)? {
        return Err(invalid_owner(
            "channel lifecycle schema differs from the canonical definition",
        ));
    }
    Ok(())
}

fn channel_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SchemaCatalogEntry>, SqliteServingOwnerError> {
    let mut statement = connection.prepare(
        r#"
        SELECT type, name, tbl_name, sql
        FROM sqlite_schema
        WHERE name GLOB 'channel_*' OR tbl_name GLOB 'channel_*'
        ORDER BY type, name, tbl_name
        "#,
    )?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(entries)
}

fn invalid_owner(detail: impl Into<String>) -> SqliteServingOwnerError {
    SqliteServingOwnerError::Invalid(detail.into())
}
