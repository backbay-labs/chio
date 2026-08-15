// Append-only effect-root refresh storage and lineage checks.

#[allow(clippy::too_many_arguments)]
fn try_append_effect_root_refresh(
    transaction: &Transaction<'_>,
    intent: &FindingEffectIntentRecord,
    existing: &FindingEffectRootBindingRecord,
    intent_key: &str,
    liability_key: &str,
    merkle_root: &str,
    evidence_hash: &str,
    now: u64,
) -> Result<bool, FindingChallengeStoreError> {
    if intent.kind != FindingEffectIntentKind::RootIntent
        || intent.liability_key.as_deref() != Some(liability_key)
        || intent.state != FindingEffectIntentState::Confirmed
        || !intent.settlement_required
    {
        return Ok(false);
    }
    let failed_sellers = transaction
        .query_row(
            r#"
            SELECT COUNT(*) FROM effect_intents
            WHERE liability_key = ?1
              AND kind = 'seller_impair'
              AND state = 'failed'
              AND settlement_required = 1
            "#,
            [liability_key],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_error)?;
    if failed_sellers != 1 || now <= existing.bound_at {
        return Ok(false);
    }
    let latest_ordinal = transaction
        .query_row(
            "SELECT COALESCE(MAX(refresh_ordinal), 0) FROM effect_root_bindings_refreshes WHERE intent_key = ?1",
            [intent_key],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_error)?;
    let next_ordinal = latest_ordinal
        .checked_add(1)
        .ok_or_else(|| invariant("effect root refresh ordinal overflowed"))?;
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO effect_root_bindings_refreshes (
                intent_key, refresh_ordinal, liability_key,
                previous_merkle_root, previous_evidence_hash,
                previous_bound_at, merkle_root, evidence_hash, bound_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                intent_key,
                next_ordinal,
                liability_key,
                existing.merkle_root.as_str(),
                existing.evidence_hash.as_str(),
                sqlite_i64(existing.bound_at, "previous_bound_at")?,
                merkle_root,
                evidence_hash,
                sqlite_i64(now, "bound_at")?,
            ],
        )
        .map_err(sqlite_error)?;
    if inserted != 1 {
        return Err(invariant(
            "effect root binding refresh did not affect one row",
        ));
    }
    Ok(true)
}

fn load_effect_root_binding_tx(
    transaction: &Transaction<'_>,
    intent_key: &str,
) -> Result<Option<FindingEffectRootBindingRecord>, FindingChallengeStoreError> {
    transaction
        .query_row(
            r#"
            SELECT intent_key, liability_key, merkle_root, evidence_hash, bound_at
            FROM (
                SELECT intent_key, liability_key, merkle_root, evidence_hash,
                       bound_at, 0 AS refresh_ordinal
                FROM effect_root_bindings
                WHERE intent_key = ?1
                UNION ALL
                SELECT intent_key, liability_key, merkle_root, evidence_hash,
                       bound_at, refresh_ordinal
                FROM effect_root_bindings_refreshes
                WHERE intent_key = ?1
            )
            ORDER BY refresh_ordinal DESC
            LIMIT 1
            "#,
            [intent_key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?
        .map(
            |(intent_key, liability_key, merkle_root, evidence_hash, bound_at)| {
                Ok(FindingEffectRootBindingRecord {
                    intent_key,
                    liability_key,
                    merkle_root,
                    evidence_hash,
                    bound_at: stored_u64(bound_at, "bound_at")?,
                })
            },
        )
        .transpose()
}

fn verify_effect_root_refresh_invariants(
    connection: &Connection,
) -> Result<(), FindingChallengeStoreError> {
    let invalid = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM effect_root_bindings_refreshes AS refresh
                JOIN effect_intents AS root ON root.intent_key = refresh.intent_key
                WHERE root.liability_key <> refresh.liability_key
                   OR root.kind <> 'root_intent'
                   OR root.settlement_required <> 1
            ) OR EXISTS(
                SELECT 1 FROM effect_root_bindings_refreshes AS refresh
                WHERE (
                    refresh.refresh_ordinal = 1
                    AND NOT EXISTS(
                        SELECT 1 FROM effect_root_bindings AS base
                        WHERE base.intent_key = refresh.intent_key
                          AND base.liability_key = refresh.liability_key
                          AND base.merkle_root = refresh.previous_merkle_root
                          AND base.evidence_hash = refresh.previous_evidence_hash
                          AND base.bound_at = refresh.previous_bound_at
                    )
                ) OR (
                    refresh.refresh_ordinal > 1
                    AND NOT EXISTS(
                        SELECT 1 FROM effect_root_bindings_refreshes AS previous
                        WHERE previous.intent_key = refresh.intent_key
                          AND previous.refresh_ordinal = refresh.refresh_ordinal - 1
                          AND previous.liability_key = refresh.liability_key
                          AND previous.merkle_root = refresh.previous_merkle_root
                          AND previous.evidence_hash = refresh.previous_evidence_hash
                          AND previous.bound_at = refresh.previous_bound_at
                    )
                )
            )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if invalid {
        return Err(invariant("effect root refresh lineage is invalid"));
    }
    Ok(())
}
