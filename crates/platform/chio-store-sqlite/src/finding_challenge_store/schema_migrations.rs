// Schema initialization, migration ladder, and catalog checks.

pub(crate) fn initialize_finding_challenge_schema(
    connection: &mut Connection,
) -> Result<(), FindingChallengeStoreError> {
    let on_disk = crate::check_schema_version(
        connection,
        FINDING_CHALLENGE_SCHEMA_KEY,
        FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION,
        FINDING_CHALLENGE_SCHEMA_ANCHORS,
    )
    .map_err(|error| invariant(error.to_string()))?;
    if on_disk == FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION {
        return verify_finding_challenge_invariants(connection);
    }
    if matches!(on_disk, 10..=13) {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if matches!(on_disk, 10 | 11)
            && table_has_rows_where(&transaction, "liability_heads", "state = 'finalizing'")?
        {
            return Err(invariant(
                "legacy finalizing liability has no retained settlement observer policy",
            ));
        }
        replace_legacy_effect_root_binding_trigger(&transaction, on_disk)?;
        transaction
            .execute_batch(FINDING_CHALLENGE_SCHEMA)
            .map_err(sqlite_error)?;
        crate::stamp_schema_version(
            &transaction,
            FINDING_CHALLENGE_SCHEMA_KEY,
            FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| invariant(error.to_string()))?;
        verify_finding_challenge_invariants(&transaction)?;
        return transaction.commit().map_err(sqlite_error);
    }
    if matches!(on_disk, 7..=9) {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if table_has_rows_where(&transaction, "liability_heads", "state = 'finalizing'")? {
            return Err(invariant(
                "legacy finalizing liability has no retained authorization",
            ));
        }
        replace_legacy_effect_root_binding_trigger(&transaction, on_disk)?;
        transaction
            .execute_batch(FINDING_CHALLENGE_SCHEMA)
            .map_err(sqlite_error)?;
        crate::stamp_schema_version(
            &transaction,
            FINDING_CHALLENGE_SCHEMA_KEY,
            FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| invariant(error.to_string()))?;
        verify_finding_challenge_invariants(&transaction)?;
        return transaction.commit().map_err(sqlite_error);
    }
    if on_disk == 0 {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        transaction
            .execute_batch(FINDING_CHALLENGE_SCHEMA)
            .map_err(sqlite_error)?;
        crate::stamp_schema_version(
            &transaction,
            FINDING_CHALLENGE_SCHEMA_KEY,
            FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| invariant(error.to_string()))?;
        verify_finding_challenge_invariants(&transaction)?;
        return transaction.commit().map_err(sqlite_error);
    }

    if matches!(on_disk, 5 | 6) {
        return migrate_recent_finding_challenge_schema(connection, on_disk);
    }

    if on_disk == 4 {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let has_unauthenticated_state = [
            "challenges",
            "dispute_locks",
            "liability_heads",
            "governance_case_index",
            "claim_snapshots",
            "effect_intents",
            "listing_sales_blocks",
        ]
        .into_iter()
        .try_fold(false, |found, table| {
            let present = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
                    [table],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(sqlite_error)?;
            if present {
                table_has_rows_where(&transaction, table, "1 = 1").map(|rows| found || rows)
            } else {
                Ok(found)
            }
        })?;
        if has_unauthenticated_state {
            return Err(invariant(
                "v4 finding challenge state has no authenticated projection history",
            ));
        }
        drop(transaction);
        return migrate_recent_finding_challenge_schema(connection, on_disk);
    }

    if !matches!(on_disk, 1..=3) {
        return Err(invariant(format!(
            "unsupported finding challenge schema version {on_disk}"
        )));
    }

    // Later revisions add columns to existing tables. `CREATE TABLE IF
    // NOT EXISTS` cannot install them, and ALTER-produced table SQL would
    // not match the canonical schema catalog. Rebuild the two tables under
    // an immediate transaction with foreign-key enforcement temporarily
    // off, then validate every reference before committing the new version.
    connection
        .execute_batch("PRAGMA foreign_keys = OFF;")
        .map_err(sqlite_error)?;
    let migration = migrate_finding_challenge_schema(connection);
    let foreign_keys = connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .map_err(sqlite_error);
    match (migration, foreign_keys) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
    }
}

fn migrate_recent_finding_challenge_schema(
    connection: &mut Connection,
    on_disk: i32,
) -> Result<(), FindingChallengeStoreError> {
    connection
        .execute_batch("PRAGMA foreign_keys = OFF;")
        .map_err(sqlite_error)?;
    let migration = (|| {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if table_has_rows_where(
            &transaction,
            "liability_heads",
            "state NOT IN ('settled', 'reversed_before_impairment')",
        )? {
            return Err(invariant(
                "actionable legacy liability state cannot migrate without its admitted seller binding",
            ));
        }
        transaction
            .execute_batch(&format!(
                r#"
                CREATE TEMP TABLE finding_terminal_liabilities_migration AS
                SELECT liability_key, defect_key, finding_id, listing_id,
                       allocation_id,
                       '{LEGACY_TERMINAL_UNBOUND_SELLER_HEX}' AS seller_hex,
                       venue_id, chain_id, vault_contract, vault_id,
                       state, upheld_challenge_id, purchase_cutoff_slot,
                       claim_deadline, appeal_window_opened_at, appeal_deadline,
                       appeal_terms_envelope_sha256, snapshot_digest,
                       allocation_digest, publication_pending, quarantined,
                       opened_at, updated_at
                FROM liability_heads;
                DROP TABLE liability_heads;
                "#
            ))
            .map_err(sqlite_error)?;
        transaction
            .execute_batch(FINDING_CHALLENGE_SCHEMA)
            .map_err(sqlite_error)?;
        transaction
            .execute_batch(
                r#"
                INSERT INTO liability_heads (
                    liability_key, defect_key, finding_id, listing_id,
                    allocation_id, seller_hex, venue_id, chain_id,
                    vault_contract, vault_id,
                    state, upheld_challenge_id, purchase_cutoff_slot,
                    claim_deadline, appeal_window_opened_at, appeal_deadline,
                    appeal_terms_envelope_sha256, snapshot_digest,
                    allocation_digest, publication_pending, quarantined,
                    opened_at, updated_at
                )
                SELECT liability_key, defect_key, finding_id, listing_id,
                       allocation_id, seller_hex, venue_id, chain_id,
                       vault_contract, vault_id,
                       state, upheld_challenge_id, purchase_cutoff_slot,
                       claim_deadline, appeal_window_opened_at, appeal_deadline,
                       appeal_terms_envelope_sha256, snapshot_digest,
                       allocation_digest, publication_pending, quarantined,
                       opened_at, updated_at
                FROM finding_terminal_liabilities_migration;
                DROP TABLE finding_terminal_liabilities_migration;
                "#,
            )
            .map_err(sqlite_error)?;
        if on_disk <= 5 {
            transaction
                .execute(
                    r#"
                    INSERT INTO dispute_lock_reservations (
                        lock_id, challenge_id, owner_hex,
                        schedule_envelope_sha256, amount_units, currency,
                        pool_principal_id, pool_rail_destination,
                        pool_authority_epoch, expires_at, locked_at, reserved_at
                    )
                    SELECT lock_id, challenge_id, owner_hex,
                           schedule_envelope_sha256, amount_units, currency,
                           pool_principal_id, pool_rail_destination,
                           pool_authority_epoch, expires_at, locked_at, locked_at
                    FROM dispute_locks
                    "#,
                    [],
                )
                .map_err(sqlite_error)?;
        }
        crate::stamp_schema_version(
            &transaction,
            FINDING_CHALLENGE_SCHEMA_KEY,
            FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| invariant(error.to_string()))?;
        verify_finding_challenge_invariants(&transaction)?;
        let foreign_key_violation: Option<String> = transaction
            .query_row(
                "SELECT 'foreign key violation in ' || \"table\" FROM pragma_foreign_key_check LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some(detail) = foreign_key_violation {
            return Err(invariant(detail));
        }
        transaction.commit().map_err(sqlite_error)
    })();
    let foreign_keys = connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .map_err(sqlite_error);
    match (migration, foreign_keys) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
    }
}

fn migrate_finding_challenge_schema(
    connection: &mut Connection,
) -> Result<(), FindingChallengeStoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;

    let has_claim_deadline = table_has_column(&transaction, "liability_heads", "claim_deadline")?;
    let has_appeal_window_opened_at =
        table_has_column(&transaction, "liability_heads", "appeal_window_opened_at")?;
    let has_appeal_deadline = table_has_column(&transaction, "liability_heads", "appeal_deadline")?;
    let has_appeal_terms = table_has_column(
        &transaction,
        "liability_heads",
        "appeal_terms_envelope_sha256",
    )?;
    let has_appeal_window = has_appeal_window_opened_at && has_appeal_deadline && has_appeal_terms;
    let has_settlement_required =
        table_has_column(&transaction, "effect_intents", "settlement_required")?;
    let has_pool_principal = table_has_column(&transaction, "dispute_locks", "pool_principal_id")?;
    let has_pool_destination =
        table_has_column(&transaction, "dispute_locks", "pool_rail_destination")?;
    let has_pool_epoch = table_has_column(&transaction, "dispute_locks", "pool_authority_epoch")?;
    let has_dispute_pool = has_pool_principal && has_pool_destination && has_pool_epoch;

    if (has_appeal_window_opened_at || has_appeal_deadline || has_appeal_terms)
        && !has_appeal_window
    {
        return Err(invariant(
            "legacy liability schema has only part of the appeal commitment",
        ));
    }
    if (has_pool_principal || has_pool_destination || has_pool_epoch) && !has_dispute_pool {
        return Err(invariant(
            "legacy dispute lock schema has only part of the admitted pool binding",
        ));
    }
    if table_has_rows_where(&transaction, "liability_heads", "1 = 1")? {
        return Err(invariant(
            "legacy liability state cannot migrate without its admitted seller binding",
        ));
    }
    if table_has_rows_where(&transaction, "dispute_locks", "1 = 1")? {
        return Err(invariant(
            "funded legacy dispute locks cannot be migrated without their admitted pool binding",
        ));
    }
    if table_has_rows_where(&transaction, "effect_intents", "kind = 'challenge_bond'")? {
        return Err(invariant(
            "legacy dispute funding intents cannot be migrated without their admitted pool binding",
        ));
    }

    if !has_claim_deadline
        && table_has_rows_where(&transaction, "liability_heads", "state <> 'open'")?
    {
        return Err(invariant(
            "v1 liability state cannot be migrated without its signed claim deadline",
        ));
    }
    if !has_appeal_window
        && table_has_rows_where(
            &transaction,
            "liability_heads",
            "state IN ('pending_appeal', 'finalizing', 'settled', 'reversed_before_impairment')",
        )?
    {
        return Err(invariant(
            "active legacy appeal state cannot be migrated without its signed appeal window",
        ));
    }
    if !has_settlement_required
        && table_has_rows_where(
            &transaction,
            "liability_heads",
            "state IN ('finalizing', 'settled')",
        )?
    {
        return Err(invariant(
            "legacy finalization state cannot be migrated without its required effect set",
        ));
    }

    let claim_deadline = if has_claim_deadline {
        "claim_deadline"
    } else {
        "NULL"
    };
    let appeal_window_opened_at = if has_appeal_window {
        "appeal_window_opened_at"
    } else {
        "NULL"
    };
    let appeal_deadline = if has_appeal_window {
        "appeal_deadline"
    } else {
        "NULL"
    };
    let appeal_terms = if has_appeal_window {
        "appeal_terms_envelope_sha256"
    } else {
        "NULL"
    };
    transaction
        .execute_batch(&format!(
            r#"
            CREATE TEMP TABLE finding_liability_heads_migration AS
            SELECT liability_key, defect_key, finding_id, listing_id,
                   allocation_id, '' AS seller_hex, venue_id, chain_id,
                   vault_contract, vault_id,
                   state, upheld_challenge_id, purchase_cutoff_slot,
                   {claim_deadline} AS claim_deadline,
                   {appeal_window_opened_at} AS appeal_window_opened_at,
                   {appeal_deadline} AS appeal_deadline,
                   {appeal_terms} AS appeal_terms_envelope_sha256,
                   snapshot_digest, allocation_digest, publication_pending,
                   quarantined, opened_at, updated_at
            FROM liability_heads;
            "#
        ))
        .map_err(sqlite_error)?;
    let settlement_required = if has_settlement_required {
        "settlement_required"
    } else {
        // Before finalizing, every liability-bound effect is one of the
        // signed enforcement bindings. The later anchor-evidence fence is
        // created only from finalizing, a state rejected above when this
        // column is absent.
        "CASE WHEN liability_key IS NULL THEN 0 ELSE 1 END"
    };
    transaction
        .execute_batch(&format!(
            r#"
            CREATE TEMP TABLE finding_effect_intents_migration AS
            SELECT intent_key, liability_key, kind, intent_digest,
                   {settlement_required} AS settlement_required, state,
                   attempt_count, recorded_at, updated_at
            FROM effect_intents;

            DROP TRIGGER IF EXISTS challenges_lifecycle;
            DROP TABLE dispute_locks;
            DROP TABLE effect_intents;
            DROP TABLE liability_heads;
            "#
        ))
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(FINDING_CHALLENGE_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(
            r#"
            INSERT INTO liability_heads (
                liability_key, defect_key, finding_id, listing_id,
                allocation_id, seller_hex, venue_id, chain_id,
                vault_contract, vault_id,
                state, upheld_challenge_id, purchase_cutoff_slot,
                claim_deadline, appeal_window_opened_at, appeal_deadline,
                appeal_terms_envelope_sha256, snapshot_digest,
                allocation_digest, publication_pending, quarantined,
                opened_at, updated_at
            )
            SELECT liability_key, defect_key, finding_id, listing_id,
                   allocation_id, seller_hex, venue_id, chain_id,
                   vault_contract, vault_id,
                   state, upheld_challenge_id, purchase_cutoff_slot,
                   claim_deadline, appeal_window_opened_at, appeal_deadline,
                   appeal_terms_envelope_sha256, snapshot_digest,
                   allocation_digest, publication_pending, quarantined,
                   opened_at, updated_at
            FROM finding_liability_heads_migration;

            INSERT INTO effect_intents (
                intent_key, liability_key, kind, intent_digest,
                settlement_required, state, attempt_count, recorded_at,
                updated_at
            )
            SELECT intent_key, liability_key, kind, intent_digest,
                   settlement_required, state, attempt_count, recorded_at,
                   updated_at
            FROM finding_effect_intents_migration;

            DROP TABLE finding_effect_intents_migration;
            DROP TABLE finding_liability_heads_migration;
            "#,
        )
        .map_err(sqlite_error)?;
    crate::stamp_schema_version(
        &transaction,
        FINDING_CHALLENGE_SCHEMA_KEY,
        FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION,
    )
    .map_err(|error| invariant(error.to_string()))?;
    verify_finding_challenge_invariants(&transaction)?;
    let foreign_key_violation: Option<String> = transaction
        .query_row(
            "SELECT 'foreign key violation in ' || \"table\" FROM pragma_foreign_key_check LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if let Some(detail) = foreign_key_violation {
        return Err(invariant(detail));
    }
    transaction.commit().map_err(sqlite_error)
}

fn table_has_column(
    connection: &Connection,
    table: &str,
    column: &str,
) -> Result<bool, FindingChallengeStoreError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2)",
            params![table, column],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn table_has_rows_where(
    connection: &Connection,
    table: &str,
    predicate: &str,
) -> Result<bool, FindingChallengeStoreError> {
    // Both inputs are private constants at the call sites above. Keeping the
    // query helper here makes the migration preconditions auditable without
    // accepting caller-controlled SQL.
    connection
        .query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {predicate})"),
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

/// Verify the challenge schema's shape: this database's table, index, and
/// trigger definitions against a freshly created canonical schema. The
/// cost is a handful of `sqlite_schema` rows, independent of how many
/// challenges have accumulated, so this runs on every open.
///
/// Fails closed: any schema-shape difference rejects the open, because a
/// missing lifecycle trigger is exactly the difference between a state
/// machine and a mutable row.
pub(crate) fn verify_finding_challenge_invariants(
    connection: &Connection,
) -> Result<(), FindingChallengeStoreError> {
    let expected = Connection::open_in_memory().map_err(sqlite_error)?;
    expected
        .execute_batch(FINDING_CHALLENGE_SCHEMA)
        .map_err(sqlite_error)?;
    let actual = finding_challenge_schema_catalog(connection)?;
    let canonical = finding_challenge_schema_catalog(&expected)?;
    if actual != canonical {
        return Err(invariant(
            "finding challenge schema differs from the canonical definition",
        ));
    }
    verify_challenge_submissions(connection)?;
    let invalid_authorization_coverage = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM liability_heads AS liability
                LEFT JOIN finding_finalizing_authorizations AS authorization
                  ON authorization.liability_key = liability.liability_key
                WHERE liability.state = 'finalizing'
                  AND authorization.liability_key IS NULL
            ) OR EXISTS(
                SELECT 1 FROM finding_finalizing_authorizations AS authorization
                JOIN liability_heads AS liability
                  ON liability.liability_key = authorization.liability_key
                WHERE liability.state NOT IN ('finalizing', 'settled')
            )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if invalid_authorization_coverage {
        return Err(invariant("finalizing authorization coverage is not exact"));
    }
    let invalid_authorization_refresh = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM finding_finalizing_authorization_refreshes AS refresh
                JOIN liability_heads AS liability
                  ON liability.liability_key = refresh.liability_key
                WHERE liability.state NOT IN ('finalizing', 'settled')
            ) OR EXISTS(
                SELECT 1
                FROM finding_finalizing_authorization_refreshes AS refresh
                WHERE (
                    refresh.refresh_ordinal = 1
                    AND refresh.previous_authorization_sha256 <> (
                        SELECT base.authorization_sha256
                        FROM finding_finalizing_authorizations AS base
                        WHERE base.liability_key = refresh.liability_key
                    )
                ) OR (
                    refresh.refresh_ordinal > 1
                    AND NOT EXISTS(
                        SELECT 1
                        FROM finding_finalizing_authorization_refreshes AS previous
                        WHERE previous.liability_key = refresh.liability_key
                          AND previous.refresh_ordinal = refresh.refresh_ordinal - 1
                          AND previous.authorization_sha256 =
                              refresh.previous_authorization_sha256
                          AND previous.recorded_at < refresh.recorded_at
                    )
                )
            )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if invalid_authorization_refresh {
        return Err(invariant(
            "finalizing authorization refresh lineage is invalid",
        ));
    }
    let invalid_seller_reconciliation = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM effect_intents AS intent
                LEFT JOIN finding_seller_impairment_reconciliations AS reconciliation
                  ON reconciliation.intent_key = intent.intent_key
                WHERE intent.kind = 'seller_impair'
                  AND intent.settlement_required = 1
                  AND intent.state = 'confirmed'
                  AND reconciliation.intent_key IS NULL
            ) OR EXISTS(
                SELECT 1
                FROM finding_seller_impairment_reconciliations AS reconciliation
                LEFT JOIN effect_intents AS intent
                  ON intent.intent_key = reconciliation.intent_key
                WHERE intent.intent_key IS NULL
                   OR intent.kind <> 'seller_impair'
                   OR intent.settlement_required <> 1
                   OR intent.state <> 'confirmed'
                   OR intent.liability_key <> reconciliation.liability_key
                   OR intent.intent_digest <> reconciliation.intent_digest
            )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if invalid_seller_reconciliation {
        return Err(invariant(
            "confirmed seller impairment reconciliation coverage is not exact",
        ));
    }
    verify_effect_root_refresh_invariants(connection)?;
    Ok(())
}

type SchemaCatalogEntry = (String, String, String, Option<String>);

fn finding_challenge_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SchemaCatalogEntry>, FindingChallengeStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT type, name, tbl_name, sql
            FROM sqlite_schema
            WHERE name GLOB 'challenges*' OR tbl_name GLOB 'challenges*'
               OR name GLOB 'finding_challenge_submissions*'
               OR tbl_name GLOB 'finding_challenge_submissions*'
               OR name GLOB 'finding_challenge_outcomes*'
               OR tbl_name GLOB 'finding_challenge_outcomes*'
               OR name GLOB 'dispute_locks*' OR tbl_name GLOB 'dispute_locks*'
               OR name GLOB 'liability_heads*'
               OR tbl_name GLOB 'liability_heads*'
               OR name GLOB 'finding_finalizing_authorizations*'
               OR tbl_name GLOB 'finding_finalizing_authorizations*'
               OR name GLOB 'finding_finalizing_authorization_refreshes*'
               OR tbl_name GLOB 'finding_finalizing_authorization_refreshes*'
               OR name GLOB 'governance_case_index*'
               OR tbl_name GLOB 'governance_case_index*'
               OR name GLOB 'claim_snapshots*'
               OR tbl_name GLOB 'claim_snapshots*'
               OR name GLOB 'effect_intents*'
               OR tbl_name GLOB 'effect_intents*'
               OR name GLOB 'finding_seller_impairment_reconciliations*'
               OR tbl_name GLOB 'finding_seller_impairment_reconciliations*'
               OR name GLOB 'effect_root_bindings*'
               OR tbl_name GLOB 'effect_root_bindings*'
               ORDER BY type, name, tbl_name
            "#,
        )
        .map_err(sqlite_error)?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(entries)
}
