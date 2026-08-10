fn replace_legacy_effect_root_binding_trigger(
    transaction: &Transaction<'_>,
    on_disk: i32,
) -> Result<(), FindingChallengeStoreError> {
    if matches!(on_disk, 9..=12) {
        transaction
            .execute_batch("DROP TRIGGER effect_root_bindings_valid_intent;")
            .map_err(sqlite_error)?;
    }
    Ok(())
}

/// Install the exact binding for an anchor intent retained from before root
/// bindings were mandatory. The immutable intent key and digest must already
/// commit to the caller-reconstructed proof, and only the legacy anchor lane
/// may use a post-dispatch state.
impl SqliteFindingChallengeStore {
pub fn reconcile_anchor_effect_root_binding(
    &self,
    intent_key: &str,
    liability_key: &str,
    expected_intent_digest: &str,
    merkle_root: &str,
    evidence_hash: &str,
    now: u64,
) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
    require_hex64(intent_key, "intent_key")?;
    require_hex64(liability_key, "liability_key")?;
    require_hex64(expected_intent_digest, "expected_intent_digest")?;
    require_chain_hash(merkle_root, "merkle_root")?;
    require_chain_hash(evidence_hash, "evidence_hash")?;
    require_trusted_time(now, "now")?;
    let mut connection = self.connection()?;
    let transaction = self.begin_write(&mut connection)?;
    let intent = load_effect_intent_tx(&transaction, intent_key)?
        .ok_or(FindingChallengeStoreError::NotFound)?;
    let recoverable_state = matches!(
        (intent.state, intent.attempt_count),
        (FindingEffectIntentState::Pending, 0)
            | (FindingEffectIntentState::Dispatched | FindingEffectIntentState::Confirmed, 1)
    );
    if intent.kind != FindingEffectIntentKind::RootIntent
        || intent.settlement_required
        || intent.liability_key.as_deref() != Some(liability_key)
        || intent.intent_digest != expected_intent_digest
        || !recoverable_state
    {
        return Err(FindingChallengeStoreError::Conflict(
            "legacy anchor intent does not match the reconstructed root binding".to_owned(),
        ));
    }
    if let Some(existing) = load_effect_root_binding_tx(&transaction, intent_key)? {
        if existing.liability_key == liability_key
            && existing.merkle_root == merkle_root
            && existing.evidence_hash == evidence_hash
        {
            return Ok(FindingChallengeWriteOutcome::ExistingSame);
        }
        return Err(FindingChallengeStoreError::Conflict(
            "anchor intent is already bound to a different proof".to_owned(),
        ));
    }
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO effect_root_bindings (
                intent_key, liability_key, merkle_root, evidence_hash, bound_at
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                intent_key,
                liability_key,
                merkle_root,
                evidence_hash,
                sqlite_i64(now, "now")?,
            ],
        )
        .map_err(sqlite_error)?;
    if inserted != 1 {
        return Err(invariant(
            "legacy anchor root binding insert did not affect one row",
        ));
    }
    self.commit_write(transaction)?;
    self.sync_after_write(&connection)?;
    Ok(FindingChallengeWriteOutcome::Inserted)
}
}
