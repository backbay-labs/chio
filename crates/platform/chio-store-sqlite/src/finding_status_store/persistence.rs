fn validate_epoch_input(
    input: &VerifiedFindingStatusEpochInput<'_>,
) -> Result<(), FindingStatusStoreError> {
    require_identifier(input.feed_id, "feed_id")?;
    require_identifier(input.operator_id, "operator_id")?;
    require_identifier_with_bound(input.operator_key, 4_096, "operator_key")?;
    require_fixed_nonce(input.key_domain_nonce)?;
    require_positive(input.map_epoch, "map_epoch")?;
    require_hex64(input.epoch_id, "epoch_id")?;
    require_hex64(input.root_hash, "root_hash")?;
    require_hex64(
        input.operator_authorization_sha256,
        "operator_authorization_sha256",
    )?;
    require_bytes(
        input.signed_epoch_bytes,
        MAX_FINDING_STATUS_EPOCH_BYTES,
        "signed_epoch_bytes",
    )?;
    require_positive(input.generated_at, "generated_at")?;
    if input.valid_until <= input.generated_at {
        return Err(invariant("epoch valid_until must follow generated_at"));
    }
    if input.recorded_at < input.generated_at {
        return Err(invariant("epoch recorded_at predates generated_at"));
    }
    sqlite_i64(input.operator_key_epoch, "operator_key_epoch")?;
    sqlite_i64(input.valid_until, "valid_until")?;
    sqlite_i64(input.recorded_at, "recorded_at")?;
    Ok(())
}

fn validate_intent_input(
    input: &FindingRetractionIntentInput<'_>,
) -> Result<(), FindingStatusStoreError> {
    require_hex64(input.intent_id, "intent_id")?;
    require_identifier(input.feed_id, "feed_id")?;
    require_identifier(input.operator_id, "operator_id")?;
    require_hex64(input.finding_id, "finding_id")?;
    require_bytes(
        input.intent_bytes,
        MAX_FINDING_RETRACTION_EVIDENCE_BYTES,
        "intent_bytes",
    )?;
    require_positive(input.issued_at, "issued_at")?;
    if input.inclusion_deadline <= input.issued_at {
        return Err(invariant("intent inclusion_deadline must follow issued_at"));
    }
    if input.created_at < input.issued_at {
        return Err(invariant("intent created_at predates issued_at"));
    }
    sqlite_i64(input.inclusion_deadline, "inclusion_deadline")?;
    sqlite_i64(input.created_at, "created_at")?;
    Ok(())
}

fn validate_leaf_input(
    input: &VerifiedFindingStatusLeafInput<'_>,
) -> Result<(), FindingStatusStoreError> {
    require_hex64(input.finding_id, "finding_id")?;
    require_bytes(
        input.status_value_bytes,
        MAX_FINDING_STATUS_VALUE_BYTES,
        "status_value_bytes",
    )?;
    require_hex64(input.retraction_intent_sha256, "retraction_intent_sha256")?;
    if let Some(intent_id) = input.local_intent_id {
        require_hex64(intent_id, "local_intent_id")?;
    }
    Ok(())
}

fn validate_proof_input(
    input: &VerifiedFindingStatusProofInput<'_>,
) -> Result<(), FindingStatusStoreError> {
    require_identifier(input.feed_id, "feed_id")?;
    require_identifier(input.operator_id, "operator_id")?;
    require_fixed_nonce(input.key_domain_nonce)?;
    require_positive(input.map_epoch, "map_epoch")?;
    require_hex64(input.epoch_id, "epoch_id")?;
    require_hex64(input.root_hash, "root_hash")?;
    require_hex64(input.finding_id, "finding_id")?;
    require_bytes(
        input.proof_bytes,
        MAX_FINDING_STATUS_PROOF_BYTES,
        "proof_bytes",
    )?;
    require_positive(input.checked_at, "checked_at")?;
    if input.valid_until <= input.checked_at {
        return Err(invariant("proof valid_until must follow checked_at"));
    }
    if input.recorded_at < input.checked_at {
        return Err(invariant("proof recorded_at predates checked_at"));
    }
    match input.kind {
        FindingStatusProofKind::Inclusion => {
            let value = input
                .status_value_bytes
                .ok_or_else(|| invariant("inclusion proof is missing its exact status value"))?;
            require_bytes(value, MAX_FINDING_STATUS_VALUE_BYTES, "status_value_bytes")?;
            require_hex64(
                input.retraction_intent_sha256.ok_or_else(|| {
                    invariant("inclusion proof is missing its retraction intent digest")
                })?,
                "retraction_intent_sha256",
            )?;
        }
        FindingStatusProofKind::NonInclusion => {
            if input.status_value_bytes.is_some() || input.retraction_intent_sha256.is_some() {
                return Err(invariant(
                    "non-inclusion proof carries inclusion-only fields",
                ));
            }
        }
    }
    sqlite_i64(input.valid_until, "valid_until")?;
    sqlite_i64(input.recorded_at, "recorded_at")?;
    Ok(())
}

fn verify_proof_epoch_binding(
    proof: &VerifiedFindingStatusProofInput<'_>,
    epoch: &VerifiedFindingStatusEpochInput<'_>,
) -> Result<(), FindingStatusStoreError> {
    if proof.feed_id != epoch.feed_id
        || proof.operator_id != epoch.operator_id
        || proof.key_domain_nonce != epoch.key_domain_nonce
        || proof.map_epoch != epoch.map_epoch
        || proof.epoch_id != epoch.epoch_id
        || proof.root_hash != epoch.root_hash
    {
        return Err(invariant("proof does not bind the supplied signed epoch"));
    }
    if proof.valid_until > epoch.valid_until {
        return Err(invariant("proof freshness exceeds its signed epoch"));
    }
    Ok(())
}

fn verify_proof_floor_binding(
    proof: &VerifiedFindingStatusProofInput<'_>,
    floor: &FindingStatusFeedFloor,
) -> Result<(), FindingStatusStoreError> {
    if proof.feed_id != floor.feed_id
        || proof.operator_id != floor.operator_id
        || proof.key_domain_nonce != floor.key_domain_nonce
    {
        return Err(invariant("proof does not bind the durable feed identity"));
    }
    if proof.map_epoch < floor.map_epoch {
        return Err(FindingStatusStoreError::Rollback {
            feed_id: proof.feed_id.to_owned(),
            current: floor.map_epoch,
            proposed: proof.map_epoch,
        });
    }
    if proof.map_epoch != floor.map_epoch
        || proof.epoch_id != floor.epoch_id
        || proof.root_hash != floor.root_hash
    {
        return Err(FindingStatusStoreError::Equivocation {
            feed_id: proof.feed_id.to_owned(),
            map_epoch: proof.map_epoch,
        });
    }
    Ok(())
}

fn require_unique_leaf_inputs(
    leaves: &[VerifiedFindingStatusLeafInput<'_>],
) -> Result<(), FindingStatusStoreError> {
    let mut ids = leaves
        .iter()
        .map(|leaf| leaf.finding_id)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invariant("epoch advance contains duplicate leaf updates"));
    }
    Ok(())
}

fn require_unique_proof_inputs(
    proofs: &[VerifiedFindingStatusProofInput<'_>],
) -> Result<(), FindingStatusStoreError> {
    let mut ids = proofs
        .iter()
        .map(|proof| proof.finding_id)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invariant("epoch advance contains duplicate proof inputs"));
    }
    Ok(())
}

fn require_leaf_proofs(
    leaves: &[VerifiedFindingStatusLeafInput<'_>],
    proofs: &[VerifiedFindingStatusProofInput<'_>],
) -> Result<(), FindingStatusStoreError> {
    for leaf in leaves {
        let matching = proofs.iter().find(|proof| {
            proof.finding_id == leaf.finding_id && proof.kind == FindingStatusProofKind::Inclusion
        });
        let Some(proof) = matching else {
            return Err(invariant(
                "every epoch leaf update requires its exact inclusion proof",
            ));
        };
        if proof.status_value_bytes != Some(leaf.status_value_bytes)
            || proof.retraction_intent_sha256 != Some(leaf.retraction_intent_sha256)
        {
            return Err(invariant(
                "leaf update does not match its portable inclusion proof",
            ));
        }
    }
    Ok(())
}

fn persist_epoch_tx(
    transaction: &Transaction<'_>,
    epoch: &VerifiedFindingStatusEpochInput<'_>,
    prior_floor: Option<&FindingStatusFeedFloor>,
) -> Result<FindingStatusWriteOutcome, FindingStatusStoreError> {
    let signed_epoch_sha256 = sha256_hex(epoch.signed_epoch_bytes);
    if let Some(floor) = prior_floor {
        if floor.operator_id != epoch.operator_id
            || floor.key_domain_nonce != epoch.key_domain_nonce
        {
            return Err(invariant(
                "signed epoch changed the durable feed/operator identity",
            ));
        }
        if epoch.map_epoch < floor.map_epoch {
            return Err(FindingStatusStoreError::Rollback {
                feed_id: epoch.feed_id.to_owned(),
                current: floor.map_epoch,
                proposed: epoch.map_epoch,
            });
        }
        if epoch.map_epoch == floor.map_epoch {
            let existing = load_epoch_tx(transaction, epoch.feed_id, epoch.map_epoch)?
                .ok_or_else(|| invariant("status floor points to a missing epoch"))?;
            if epoch_record_matches_input(&existing, epoch, &signed_epoch_sha256) {
                return Ok(FindingStatusWriteOutcome::ExactReplay);
            }
            return Err(FindingStatusStoreError::Equivocation {
                feed_id: epoch.feed_id.to_owned(),
                map_epoch: epoch.map_epoch,
            });
        }
        if epoch.operator_key_epoch < floor.operator_key_epoch {
            return Err(invariant("operator key epoch regressed across feed epochs"));
        }
        if epoch.operator_key_epoch == floor.operator_key_epoch
            && (epoch.operator_key != floor.operator_key
                || epoch.operator_authorization_sha256 != floor.operator_authorization_sha256)
        {
            return Err(invariant(
                "operator key or authorization changed without key-epoch rotation",
            ));
        }
    } else if feed_has_epochs_tx(transaction, epoch.feed_id)? {
        return Err(FindingStatusStoreError::MissingFloor {
            feed_id: epoch.feed_id.to_owned(),
        });
    }

    transaction
        .execute(
            r#"
            INSERT INTO finding_status_epochs (
                feed_id, operator_id, key_domain_nonce, map_epoch, epoch_id,
                root_hash, signed_epoch_sha256, signed_epoch_bytes,
                operator_key, operator_key_epoch,
                operator_authorization_sha256, generated_at, valid_until,
                recorded_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                      ?11, ?12, ?13, ?14)
            "#,
            params![
                epoch.feed_id,
                epoch.operator_id,
                sqlite_i64(epoch.key_domain_nonce, "key_domain_nonce")?,
                sqlite_i64(epoch.map_epoch, "map_epoch")?,
                epoch.epoch_id,
                epoch.root_hash,
                signed_epoch_sha256,
                epoch.signed_epoch_bytes,
                epoch.operator_key,
                sqlite_i64(epoch.operator_key_epoch, "operator_key_epoch")?,
                epoch.operator_authorization_sha256,
                sqlite_i64(epoch.generated_at, "generated_at")?,
                sqlite_i64(epoch.valid_until, "valid_until")?,
                sqlite_i64(epoch.recorded_at, "recorded_at")?,
            ],
        )
        .map_err(sqlite_error)?;

    if prior_floor.is_some() {
        transaction
            .execute(
                r#"
                UPDATE finding_status_feed_floors
                SET map_epoch = ?2, epoch_id = ?3, root_hash = ?4,
                    signed_epoch_sha256 = ?5, operator_key = ?6,
                    operator_key_epoch = ?7,
                    operator_authorization_sha256 = ?8, advanced_at = ?9
                WHERE feed_id = ?1
                "#,
                params![
                    epoch.feed_id,
                    sqlite_i64(epoch.map_epoch, "map_epoch")?,
                    epoch.epoch_id,
                    epoch.root_hash,
                    signed_epoch_sha256,
                    epoch.operator_key,
                    sqlite_i64(epoch.operator_key_epoch, "operator_key_epoch")?,
                    epoch.operator_authorization_sha256,
                    sqlite_i64(epoch.recorded_at, "recorded_at")?,
                ],
            )
            .map_err(sqlite_error)?;
    } else {
        transaction
            .execute(
                r#"
                INSERT INTO finding_status_feed_floors (
                    feed_id, operator_id, key_domain_nonce, map_epoch, epoch_id,
                    root_hash, signed_epoch_sha256, operator_key,
                    operator_key_epoch, operator_authorization_sha256,
                    advanced_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                "#,
                params![
                    epoch.feed_id,
                    epoch.operator_id,
                    sqlite_i64(epoch.key_domain_nonce, "key_domain_nonce")?,
                    sqlite_i64(epoch.map_epoch, "map_epoch")?,
                    epoch.epoch_id,
                    epoch.root_hash,
                    signed_epoch_sha256,
                    epoch.operator_key,
                    sqlite_i64(epoch.operator_key_epoch, "operator_key_epoch")?,
                    epoch.operator_authorization_sha256,
                    sqlite_i64(epoch.recorded_at, "recorded_at")?,
                ],
            )
            .map_err(sqlite_error)?;
    }
    Ok(FindingStatusWriteOutcome::Inserted)
}

fn persist_leaf_tx(
    transaction: &Transaction<'_>,
    epoch: &VerifiedFindingStatusEpochInput<'_>,
    leaf: &VerifiedFindingStatusLeafInput<'_>,
) -> Result<FindingStatusWriteOutcome, FindingStatusStoreError> {
    let value_sha256 = sha256_hex(leaf.status_value_bytes);
    let local_intent = load_intent_by_finding_tx(transaction, epoch.feed_id, leaf.finding_id)?;
    if let (Some(requested), Some(existing)) = (leaf.local_intent_id, local_intent.as_ref()) {
        if requested != existing.intent_id {
            return Err(FindingStatusStoreError::Conflict(format!(
                "leaf for {} names a different local intent",
                leaf.finding_id
            )));
        }
    }
    if leaf.local_intent_id.is_some() && local_intent.is_none() {
        return Err(FindingStatusStoreError::Conflict(format!(
            "leaf for {} names a missing local intent",
            leaf.finding_id
        )));
    }
    let effective_intent_id = local_intent
        .as_ref()
        .map(|intent| intent.intent_id.as_str())
        .or(leaf.local_intent_id);
    if let Some(intent) = local_intent.as_ref() {
        if intent.operator_id != epoch.operator_id
            || intent.finding_id != leaf.finding_id
            || intent.intent_sha256 != leaf.retraction_intent_sha256
        {
            return Err(FindingStatusStoreError::Conflict(format!(
                "leaf for {} does not match its durable intent",
                leaf.finding_id
            )));
        }
        if intent.state == FindingRetractionIntentState::WaitingFinality {
            return Err(FindingStatusStoreError::Conflict(format!(
                "retraction intent {} is not dispatch eligible",
                intent.intent_id
            )));
        }
        if intent
            .dispatch_eligible_at
            .is_some_and(|eligible_at| epoch.recorded_at < eligible_at)
        {
            return Err(invariant("status epoch predates dispatch eligibility"));
        }
    }

    let mut outcome = FindingStatusWriteOutcome::Inserted;
    if let Some(existing) = load_leaf_tx(transaction, epoch.feed_id, leaf.finding_id)? {
        if existing.operator_id != epoch.operator_id
            || existing.key_domain_nonce != epoch.key_domain_nonce
            || existing.status_value_sha256 != value_sha256
            || existing.status_value_bytes != leaf.status_value_bytes
            || existing.retraction_intent_sha256 != leaf.retraction_intent_sha256
            || (existing.local_intent_id.is_some()
                && existing.local_intent_id.as_deref() != effective_intent_id)
        {
            return Err(FindingStatusStoreError::Conflict(format!(
                "finding {} already has a different sticky leaf",
                leaf.finding_id
            )));
        }
        outcome = FindingStatusWriteOutcome::ExactReplay;
    } else {
        transaction
            .execute(
                r#"
                INSERT INTO finding_status_leaves (
                    feed_id, operator_id, finding_id, key_domain_nonce,
                    status_value_sha256, status_value_bytes,
                    retraction_intent_sha256, local_intent_id,
                    first_map_epoch, first_epoch_id, recorded_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                "#,
                params![
                    epoch.feed_id,
                    epoch.operator_id,
                    leaf.finding_id,
                    sqlite_i64(epoch.key_domain_nonce, "key_domain_nonce")?,
                    value_sha256,
                    leaf.status_value_bytes,
                    leaf.retraction_intent_sha256,
                    effective_intent_id,
                    sqlite_i64(epoch.map_epoch, "map_epoch")?,
                    epoch.epoch_id,
                    sqlite_i64(epoch.recorded_at, "recorded_at")?,
                ],
            )
            .map_err(sqlite_error)?;
    }

    match load_status_tx(transaction, epoch.feed_id, leaf.finding_id)? {
        Some(status) if status.retraction_intent_sha256 != leaf.retraction_intent_sha256 => {
            return Err(FindingStatusStoreError::Conflict(format!(
                "finding {} has a different sticky intent digest",
                leaf.finding_id
            )));
        }
        Some(status) if status.state == FindingStickyStatus::Pending => {
            transaction
                .execute(
                    r#"
                    UPDATE finding_status_states
                    SET state = 'retracted', updated_at = ?3,
                        retracted_map_epoch = ?4, retracted_epoch_id = ?5,
                        retracted_root_hash = ?6
                    WHERE feed_id = ?1 AND finding_id = ?2 AND state = 'pending'
                    "#,
                    params![
                        epoch.feed_id,
                        leaf.finding_id,
                        sqlite_i64(epoch.recorded_at, "recorded_at")?,
                        sqlite_i64(epoch.map_epoch, "map_epoch")?,
                        epoch.epoch_id,
                        epoch.root_hash,
                    ],
                )
                .map_err(sqlite_error)?;
        }
        Some(_) => {}
        None => {
            transaction
                .execute(
                    r#"
                    INSERT INTO finding_status_states (
                        feed_id, operator_id, finding_id, state,
                        retraction_intent_sha256, first_observed_at, updated_at,
                        retracted_map_epoch, retracted_epoch_id,
                        retracted_root_hash
                    ) VALUES (?1, ?2, ?3, 'retracted', ?4, ?5, ?5, ?6, ?7, ?8)
                    "#,
                    params![
                        epoch.feed_id,
                        epoch.operator_id,
                        leaf.finding_id,
                        leaf.retraction_intent_sha256,
                        sqlite_i64(epoch.recorded_at, "recorded_at")?,
                        sqlite_i64(epoch.map_epoch, "map_epoch")?,
                        epoch.epoch_id,
                        epoch.root_hash,
                    ],
                )
                .map_err(sqlite_error)?;
        }
    }

    if let Some(intent) = local_intent {
        match intent.state {
            FindingRetractionIntentState::DispatchEligible => {
                transaction
                    .execute(
                        r#"
                        UPDATE finding_retraction_intents
                        SET state = 'published', published_map_epoch = ?2,
                            published_epoch_id = ?3, updated_at = ?4
                        WHERE intent_id = ?1 AND state = 'dispatch_eligible'
                        "#,
                        params![
                            intent.intent_id,
                            sqlite_i64(epoch.map_epoch, "map_epoch")?,
                            epoch.epoch_id,
                            sqlite_i64(epoch.recorded_at, "recorded_at")?,
                        ],
                    )
                    .map_err(sqlite_error)?;
            }
            FindingRetractionIntentState::Published => {
                if intent.published_map_epoch != Some(epoch.map_epoch)
                    && intent
                        .published_map_epoch
                        .is_some_and(|published| published > epoch.map_epoch)
                {
                    return Err(FindingStatusStoreError::Rollback {
                        feed_id: epoch.feed_id.to_owned(),
                        current: intent.published_map_epoch.unwrap_or(epoch.map_epoch),
                        proposed: epoch.map_epoch,
                    });
                }
            }
            FindingRetractionIntentState::WaitingFinality => {
                return Err(invariant(
                    "waiting-finality intent reached leaf publication",
                ));
            }
        }
    }
    Ok(outcome)
}

fn persist_proof_tx(
    transaction: &Transaction<'_>,
    proof: &VerifiedFindingStatusProofInput<'_>,
) -> Result<FindingStatusWriteOutcome, FindingStatusStoreError> {
    let epoch = load_epoch_tx(transaction, proof.feed_id, proof.map_epoch)?
        .ok_or_else(|| invariant("proof names a missing signed epoch"))?;
    if epoch.operator_id != proof.operator_id
        || epoch.key_domain_nonce != proof.key_domain_nonce
        || epoch.epoch_id != proof.epoch_id
        || epoch.root_hash != proof.root_hash
    {
        return Err(invariant("proof does not match its retained signed epoch"));
    }
    if proof.valid_until > epoch.valid_until {
        return Err(invariant("proof freshness exceeds its retained epoch"));
    }

    match proof.kind {
        FindingStatusProofKind::NonInclusion => {
            if load_status_tx(transaction, proof.feed_id, proof.finding_id)?.is_some() {
                return Err(FindingStatusStoreError::ContradictoryNonInclusion {
                    finding_id: proof.finding_id.to_owned(),
                });
            }
        }
        FindingStatusProofKind::Inclusion => {
            let leaf = VerifiedFindingStatusLeafInput {
                finding_id: proof.finding_id,
                status_value_bytes: proof
                    .status_value_bytes
                    .ok_or_else(|| invariant("inclusion proof lost its exact status value"))?,
                retraction_intent_sha256: proof
                    .retraction_intent_sha256
                    .ok_or_else(|| invariant("inclusion proof lost its intent digest"))?,
                local_intent_id: None,
            };
            persist_leaf_tx(transaction, &epoch_as_input(&epoch), &leaf)?;
        }
    }

    let proof_sha256 = sha256_hex(proof.proof_bytes);
    let status_value_sha256 = proof.status_value_bytes.map(sha256_hex);
    if let Some(existing) = load_proof_tx(
        transaction,
        proof.feed_id,
        proof.finding_id,
        proof.map_epoch,
    )? {
        if proof_record_matches_input(
            &existing,
            proof,
            &proof_sha256,
            status_value_sha256.as_deref(),
        ) {
            return Ok(FindingStatusWriteOutcome::ExactReplay);
        }
        return Err(FindingStatusStoreError::Conflict(format!(
            "finding {} has a different proof at map epoch {}",
            proof.finding_id, proof.map_epoch
        )));
    }

    transaction
        .execute(
            r#"
            INSERT INTO finding_status_proofs (
                feed_id, operator_id, finding_id, key_domain_nonce, map_epoch,
                epoch_id, root_hash, proof_kind, proof_sha256, proof_bytes,
                status_value_sha256, status_value_bytes,
                retraction_intent_sha256, checked_at, valid_until, recorded_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                      ?12, ?13, ?14, ?15, ?16)
            "#,
            params![
                proof.feed_id,
                proof.operator_id,
                proof.finding_id,
                sqlite_i64(proof.key_domain_nonce, "key_domain_nonce")?,
                sqlite_i64(proof.map_epoch, "map_epoch")?,
                proof.epoch_id,
                proof.root_hash,
                proof_kind_name(proof.kind),
                proof_sha256,
                proof.proof_bytes,
                status_value_sha256,
                proof.status_value_bytes,
                proof.retraction_intent_sha256,
                sqlite_i64(proof.checked_at, "checked_at")?,
                sqlite_i64(proof.valid_until, "valid_until")?,
                sqlite_i64(proof.recorded_at, "recorded_at")?,
            ],
        )
        .map_err(sqlite_error)?;
    Ok(FindingStatusWriteOutcome::Inserted)
}

fn ensure_feed_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
    operator_id: &str,
    registered_at: u64,
) -> Result<(), FindingStatusStoreError> {
    let existing = transaction
        .query_row(
            "SELECT operator_id, key_domain_nonce FROM finding_status_feeds WHERE feed_id = ?1",
            [feed_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    match existing {
        Some((stored_operator, stored_nonce)) => {
            if stored_operator != operator_id
                || stored_u64(stored_nonce, "key_domain_nonce")? != FINDING_STATUS_KEY_DOMAIN_NONCE
            {
                return Err(FindingStatusStoreError::Conflict(format!(
                    "feed {feed_id} is bound to a different operator identity"
                )));
            }
        }
        None => {
            transaction
                .execute(
                    r#"
                    INSERT INTO finding_status_feeds (
                        feed_id, operator_id, key_domain_nonce, registered_at
                    ) VALUES (?1, ?2, ?3, ?4)
                    "#,
                    params![
                        feed_id,
                        operator_id,
                        sqlite_i64(FINDING_STATUS_KEY_DOMAIN_NONCE, "key_domain_nonce")?,
                        sqlite_i64(registered_at, "registered_at")?,
                    ],
                )
                .map_err(sqlite_error)?;
        }
    }
    Ok(())
}

fn ensure_feed_exists_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
    operator_id: &str,
) -> Result<(), FindingStatusStoreError> {
    let existing = transaction
        .query_row(
            "SELECT operator_id, key_domain_nonce FROM finding_status_feeds WHERE feed_id = ?1",
            [feed_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| {
            FindingStatusStoreError::Conflict(format!("feed {feed_id} is not registered"))
        })?;
    if existing.0 != operator_id
        || stored_u64(existing.1, "key_domain_nonce")? != FINDING_STATUS_KEY_DOMAIN_NONCE
    {
        return Err(FindingStatusStoreError::Conflict(format!(
            "feed {feed_id} is bound to a different operator identity"
        )));
    }
    Ok(())
}

fn ensure_feed_registered_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
) -> Result<(), FindingStatusStoreError> {
    let exists = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM finding_status_feeds WHERE feed_id = ?1)",
            [feed_id],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if !exists {
        return Err(FindingStatusStoreError::MissingFloor {
            feed_id: feed_id.to_owned(),
        });
    }
    Ok(())
}

fn feed_has_epochs_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
) -> Result<bool, FindingStatusStoreError> {
    transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM finding_status_epochs WHERE feed_id = ?1)",
            [feed_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

#[derive(Debug)]
struct RawEpoch {
    feed_id: String,
    operator_id: String,
    key_domain_nonce: i64,
    map_epoch: i64,
    epoch_id: String,
    root_hash: String,
    signed_epoch_sha256: String,
    signed_epoch_bytes: Vec<u8>,
    operator_key: String,
    operator_key_epoch: i64,
    operator_authorization_sha256: String,
    generated_at: i64,
    valid_until: i64,
    recorded_at: i64,
}

fn raw_epoch_from_row(row: &Row<'_>) -> rusqlite::Result<RawEpoch> {
    Ok(RawEpoch {
        feed_id: row.get(0)?,
        operator_id: row.get(1)?,
        key_domain_nonce: row.get(2)?,
        map_epoch: row.get(3)?,
        epoch_id: row.get(4)?,
        root_hash: row.get(5)?,
        signed_epoch_sha256: row.get(6)?,
        signed_epoch_bytes: row.get(7)?,
        operator_key: row.get(8)?,
        operator_key_epoch: row.get(9)?,
        operator_authorization_sha256: row.get(10)?,
        generated_at: row.get(11)?,
        valid_until: row.get(12)?,
        recorded_at: row.get(13)?,
    })
}

fn epoch_from_raw(raw: RawEpoch) -> Result<FindingStatusEpochRecord, FindingStatusStoreError> {
    require_fixed_nonce(stored_u64(raw.key_domain_nonce, "key_domain_nonce")?)?;
    require_hex64(&raw.epoch_id, "epoch_id")?;
    require_hex64(&raw.root_hash, "root_hash")?;
    require_hex64(&raw.signed_epoch_sha256, "signed_epoch_sha256")?;
    require_bytes(
        &raw.signed_epoch_bytes,
        MAX_FINDING_STATUS_EPOCH_BYTES,
        "signed_epoch_bytes",
    )?;
    if sha256_hex(&raw.signed_epoch_bytes) != raw.signed_epoch_sha256 {
        return Err(invariant("retained signed epoch bytes fail their digest"));
    }
    require_hex64(
        &raw.operator_authorization_sha256,
        "operator_authorization_sha256",
    )?;
    Ok(FindingStatusEpochRecord {
        feed_id: raw.feed_id,
        operator_id: raw.operator_id,
        key_domain_nonce: stored_u64(raw.key_domain_nonce, "key_domain_nonce")?,
        map_epoch: stored_u64(raw.map_epoch, "map_epoch")?,
        epoch_id: raw.epoch_id,
        root_hash: raw.root_hash,
        signed_epoch_sha256: raw.signed_epoch_sha256,
        signed_epoch_bytes: raw.signed_epoch_bytes,
        operator_key: raw.operator_key,
        operator_key_epoch: stored_u64(raw.operator_key_epoch, "operator_key_epoch")?,
        operator_authorization_sha256: raw.operator_authorization_sha256,
        generated_at: stored_u64(raw.generated_at, "generated_at")?,
        valid_until: stored_u64(raw.valid_until, "valid_until")?,
        recorded_at: stored_u64(raw.recorded_at, "recorded_at")?,
    })
}

fn load_epoch_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
    map_epoch: u64,
) -> Result<Option<FindingStatusEpochRecord>, FindingStatusStoreError> {
    let raw = transaction
        .query_row(
            r#"
            SELECT feed_id, operator_id, key_domain_nonce, map_epoch, epoch_id,
                   root_hash, signed_epoch_sha256, signed_epoch_bytes,
                   operator_key, operator_key_epoch,
                   operator_authorization_sha256, generated_at, valid_until,
                   recorded_at
            FROM finding_status_epochs
            WHERE feed_id = ?1 AND map_epoch = ?2
            "#,
            params![feed_id, sqlite_i64(map_epoch, "map_epoch")?],
            raw_epoch_from_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(epoch_from_raw).transpose()
}

fn epoch_as_input(epoch: &FindingStatusEpochRecord) -> VerifiedFindingStatusEpochInput<'_> {
    VerifiedFindingStatusEpochInput {
        feed_id: &epoch.feed_id,
        operator_id: &epoch.operator_id,
        key_domain_nonce: epoch.key_domain_nonce,
        map_epoch: epoch.map_epoch,
        epoch_id: &epoch.epoch_id,
        root_hash: &epoch.root_hash,
        signed_epoch_bytes: &epoch.signed_epoch_bytes,
        operator_key: &epoch.operator_key,
        operator_key_epoch: epoch.operator_key_epoch,
        operator_authorization_sha256: &epoch.operator_authorization_sha256,
        generated_at: epoch.generated_at,
        valid_until: epoch.valid_until,
        recorded_at: epoch.recorded_at,
    }
}

fn epoch_record_matches_input(
    record: &FindingStatusEpochRecord,
    input: &VerifiedFindingStatusEpochInput<'_>,
    signed_epoch_sha256: &str,
) -> bool {
    record.feed_id == input.feed_id
        && record.operator_id == input.operator_id
        && record.key_domain_nonce == input.key_domain_nonce
        && record.map_epoch == input.map_epoch
        && record.epoch_id == input.epoch_id
        && record.root_hash == input.root_hash
        && record.signed_epoch_sha256 == signed_epoch_sha256
        && record.signed_epoch_bytes == input.signed_epoch_bytes
        && record.operator_key == input.operator_key
        && record.operator_key_epoch == input.operator_key_epoch
        && record.operator_authorization_sha256 == input.operator_authorization_sha256
        && record.generated_at == input.generated_at
        && record.valid_until == input.valid_until
}

#[derive(Debug)]
struct RawFloor {
    feed_id: String,
    operator_id: String,
    key_domain_nonce: i64,
    map_epoch: i64,
    epoch_id: String,
    root_hash: String,
    signed_epoch_sha256: String,
    operator_key: String,
    operator_key_epoch: i64,
    operator_authorization_sha256: String,
    advanced_at: i64,
}

fn raw_floor_from_row(row: &Row<'_>) -> rusqlite::Result<RawFloor> {
    Ok(RawFloor {
        feed_id: row.get(0)?,
        operator_id: row.get(1)?,
        key_domain_nonce: row.get(2)?,
        map_epoch: row.get(3)?,
        epoch_id: row.get(4)?,
        root_hash: row.get(5)?,
        signed_epoch_sha256: row.get(6)?,
        operator_key: row.get(7)?,
        operator_key_epoch: row.get(8)?,
        operator_authorization_sha256: row.get(9)?,
        advanced_at: row.get(10)?,
    })
}

fn floor_from_raw(raw: RawFloor) -> Result<FindingStatusFeedFloor, FindingStatusStoreError> {
    let nonce = stored_u64(raw.key_domain_nonce, "key_domain_nonce")?;
    require_fixed_nonce(nonce)?;
    require_hex64(&raw.epoch_id, "epoch_id")?;
    require_hex64(&raw.root_hash, "root_hash")?;
    require_hex64(&raw.signed_epoch_sha256, "signed_epoch_sha256")?;
    require_hex64(
        &raw.operator_authorization_sha256,
        "operator_authorization_sha256",
    )?;
    Ok(FindingStatusFeedFloor {
        feed_id: raw.feed_id,
        operator_id: raw.operator_id,
        key_domain_nonce: nonce,
        map_epoch: stored_u64(raw.map_epoch, "map_epoch")?,
        epoch_id: raw.epoch_id,
        root_hash: raw.root_hash,
        signed_epoch_sha256: raw.signed_epoch_sha256,
        operator_key: raw.operator_key,
        operator_key_epoch: stored_u64(raw.operator_key_epoch, "operator_key_epoch")?,
        operator_authorization_sha256: raw.operator_authorization_sha256,
        advanced_at: stored_u64(raw.advanced_at, "advanced_at")?,
    })
}

fn load_floor_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
) -> Result<Option<FindingStatusFeedFloor>, FindingStatusStoreError> {
    let raw = transaction
        .query_row(
            r#"
            SELECT feed_id, operator_id, key_domain_nonce, map_epoch, epoch_id,
                   root_hash, signed_epoch_sha256, operator_key,
                   operator_key_epoch, operator_authorization_sha256,
                   advanced_at
            FROM finding_status_feed_floors
            WHERE feed_id = ?1
            "#,
            [feed_id],
            raw_floor_from_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(floor_from_raw).transpose()
}

fn verify_floor_epoch_consistency(
    floor: &FindingStatusFeedFloor,
    epoch: &FindingStatusEpochRecord,
) -> Result<(), FindingStatusStoreError> {
    if floor.feed_id != epoch.feed_id
        || floor.operator_id != epoch.operator_id
        || floor.key_domain_nonce != epoch.key_domain_nonce
        || floor.map_epoch != epoch.map_epoch
        || floor.epoch_id != epoch.epoch_id
        || floor.root_hash != epoch.root_hash
        || floor.signed_epoch_sha256 != epoch.signed_epoch_sha256
        || floor.operator_key != epoch.operator_key
        || floor.operator_key_epoch != epoch.operator_key_epoch
        || floor.operator_authorization_sha256 != epoch.operator_authorization_sha256
    {
        return Err(invariant(
            "durable status floor does not match its retained signed epoch",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct RawIntent {
    intent_id: String,
    feed_id: String,
    operator_id: String,
    finding_id: String,
    source: String,
    intent_sha256: String,
    intent_bytes: Vec<u8>,
    issued_at: i64,
    inclusion_deadline: i64,
    state: String,
    finality_evidence_sha256: Option<String>,
    finality_evidence_bytes: Option<Vec<u8>>,
    dispatch_eligible_at: Option<i64>,
    published_map_epoch: Option<i64>,
    published_epoch_id: Option<String>,
    created_at: i64,
    updated_at: i64,
}

fn raw_intent_from_row(row: &Row<'_>) -> rusqlite::Result<RawIntent> {
    Ok(RawIntent {
        intent_id: row.get(0)?,
        feed_id: row.get(1)?,
        operator_id: row.get(2)?,
        finding_id: row.get(3)?,
        source: row.get(4)?,
        intent_sha256: row.get(5)?,
        intent_bytes: row.get(6)?,
        issued_at: row.get(7)?,
        inclusion_deadline: row.get(8)?,
        state: row.get(9)?,
        finality_evidence_sha256: row.get(10)?,
        finality_evidence_bytes: row.get(11)?,
        dispatch_eligible_at: row.get(12)?,
        published_map_epoch: row.get(13)?,
        published_epoch_id: row.get(14)?,
        created_at: row.get(15)?,
        updated_at: row.get(16)?,
    })
}

fn intent_from_raw(
    raw: RawIntent,
) -> Result<FindingRetractionIntentRecord, FindingStatusStoreError> {
    require_hex64(&raw.intent_id, "intent_id")?;
    require_hex64(&raw.finding_id, "finding_id")?;
    require_hex64(&raw.intent_sha256, "intent_sha256")?;
    require_bytes(
        &raw.intent_bytes,
        MAX_FINDING_RETRACTION_EVIDENCE_BYTES,
        "intent_bytes",
    )?;
    if sha256_hex(&raw.intent_bytes) != raw.intent_sha256 {
        return Err(invariant("retained retraction intent fails its digest"));
    }
    if let Some(digest) = raw.finality_evidence_sha256.as_deref() {
        require_hex64(digest, "finality_evidence_sha256")?;
    }
    if let Some(bytes) = raw.finality_evidence_bytes.as_deref() {
        require_bytes(
            bytes,
            MAX_FINDING_RETRACTION_EVIDENCE_BYTES,
            "finality_evidence_bytes",
        )?;
        if raw.finality_evidence_sha256.as_deref() != Some(sha256_hex(bytes).as_str()) {
            return Err(invariant("retained finality evidence fails its digest"));
        }
    }
    let record = FindingRetractionIntentRecord {
        intent_id: raw.intent_id,
        feed_id: raw.feed_id,
        operator_id: raw.operator_id,
        finding_id: raw.finding_id,
        source: intent_source_from_name(&raw.source)?,
        intent_sha256: raw.intent_sha256,
        intent_bytes: raw.intent_bytes,
        issued_at: stored_u64(raw.issued_at, "issued_at")?,
        inclusion_deadline: stored_u64(raw.inclusion_deadline, "inclusion_deadline")?,
        state: intent_state_from_name(&raw.state)?,
        finality_evidence_sha256: raw.finality_evidence_sha256,
        finality_evidence_bytes: raw.finality_evidence_bytes,
        dispatch_eligible_at: stored_optional_u64(
            raw.dispatch_eligible_at,
            "dispatch_eligible_at",
        )?,
        published_map_epoch: stored_optional_u64(raw.published_map_epoch, "published_map_epoch")?,
        published_epoch_id: raw.published_epoch_id,
        created_at: stored_u64(raw.created_at, "created_at")?,
        updated_at: stored_u64(raw.updated_at, "updated_at")?,
    };
    verify_intent_record_shape(&record)?;
    Ok(record)
}

fn verify_intent_record_shape(
    record: &FindingRetractionIntentRecord,
) -> Result<(), FindingStatusStoreError> {
    match record.state {
        FindingRetractionIntentState::WaitingFinality => {
            if record.finality_evidence_sha256.is_some()
                || record.finality_evidence_bytes.is_some()
                || record.dispatch_eligible_at.is_some()
                || record.published_map_epoch.is_some()
                || record.published_epoch_id.is_some()
            {
                return Err(invariant("waiting-finality intent has later-state fields"));
            }
        }
        FindingRetractionIntentState::DispatchEligible => {
            if record.finality_evidence_sha256.is_none()
                || record.finality_evidence_bytes.is_none()
                || record.dispatch_eligible_at.is_none()
                || record.published_map_epoch.is_some()
                || record.published_epoch_id.is_some()
            {
                return Err(invariant(
                    "dispatch-eligible intent has inconsistent lifecycle fields",
                ));
            }
        }
        FindingRetractionIntentState::Published => {
            if record.finality_evidence_sha256.is_none()
                || record.finality_evidence_bytes.is_none()
                || record.dispatch_eligible_at.is_none()
                || record.published_map_epoch.is_none()
                || record.published_epoch_id.is_none()
            {
                return Err(invariant(
                    "published intent has inconsistent lifecycle fields",
                ));
            }
        }
    }
    Ok(())
}

fn load_intent_tx(
    transaction: &Transaction<'_>,
    intent_id: &str,
) -> Result<Option<FindingRetractionIntentRecord>, FindingStatusStoreError> {
    let raw = transaction
        .query_row(
            r#"
            SELECT intent_id, feed_id, operator_id, finding_id, source,
                   intent_sha256, intent_bytes, issued_at, inclusion_deadline,
                   state, finality_evidence_sha256, finality_evidence_bytes,
                   dispatch_eligible_at, published_map_epoch,
                   published_epoch_id, created_at, updated_at
            FROM finding_retraction_intents
            WHERE intent_id = ?1
            "#,
            [intent_id],
            raw_intent_from_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(intent_from_raw).transpose()
}

fn load_intent_by_finding_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
    finding_id: &str,
) -> Result<Option<FindingRetractionIntentRecord>, FindingStatusStoreError> {
    let raw = transaction
        .query_row(
            r#"
            SELECT intent_id, feed_id, operator_id, finding_id, source,
                   intent_sha256, intent_bytes, issued_at, inclusion_deadline,
                   state, finality_evidence_sha256, finality_evidence_bytes,
                   dispatch_eligible_at, published_map_epoch,
                   published_epoch_id, created_at, updated_at
            FROM finding_retraction_intents
            WHERE feed_id = ?1 AND finding_id = ?2
            "#,
            params![feed_id, finding_id],
            raw_intent_from_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(intent_from_raw).transpose()
}

fn verify_intent_replay(
    record: &FindingRetractionIntentRecord,
    input: &FindingRetractionIntentInput<'_>,
    intent_sha256: &str,
) -> Result<(), FindingStatusStoreError> {
    if record.feed_id != input.feed_id
        || record.operator_id != input.operator_id
        || record.finding_id != input.finding_id
        || record.source != input.source
        || record.intent_sha256 != intent_sha256
        || record.intent_bytes != input.intent_bytes
        || record.issued_at != input.issued_at
        || record.inclusion_deadline != input.inclusion_deadline
    {
        return Err(FindingStatusStoreError::Conflict(format!(
            "retraction intent {} was replayed with different bytes or bindings",
            input.intent_id
        )));
    }
    Ok(())
}

#[derive(Debug)]
struct RawStatus {
    feed_id: String,
    operator_id: String,
    finding_id: String,
    state: String,
    retraction_intent_sha256: String,
    first_observed_at: i64,
    updated_at: i64,
    retracted_map_epoch: Option<i64>,
    retracted_epoch_id: Option<String>,
    retracted_root_hash: Option<String>,
}

fn raw_status_from_row(row: &Row<'_>) -> rusqlite::Result<RawStatus> {
    Ok(RawStatus {
        feed_id: row.get(0)?,
        operator_id: row.get(1)?,
        finding_id: row.get(2)?,
        state: row.get(3)?,
        retraction_intent_sha256: row.get(4)?,
        first_observed_at: row.get(5)?,
        updated_at: row.get(6)?,
        retracted_map_epoch: row.get(7)?,
        retracted_epoch_id: row.get(8)?,
        retracted_root_hash: row.get(9)?,
    })
}

fn status_from_raw(raw: RawStatus) -> Result<FindingStatusRecord, FindingStatusStoreError> {
    require_hex64(&raw.finding_id, "finding_id")?;
    require_hex64(&raw.retraction_intent_sha256, "retraction_intent_sha256")?;
    if let Some(epoch_id) = raw.retracted_epoch_id.as_deref() {
        require_hex64(epoch_id, "retracted_epoch_id")?;
    }
    if let Some(root_hash) = raw.retracted_root_hash.as_deref() {
        require_hex64(root_hash, "retracted_root_hash")?;
    }
    let record = FindingStatusRecord {
        feed_id: raw.feed_id,
        operator_id: raw.operator_id,
        finding_id: raw.finding_id,
        state: sticky_status_from_name(&raw.state)?,
        retraction_intent_sha256: raw.retraction_intent_sha256,
        first_observed_at: stored_u64(raw.first_observed_at, "first_observed_at")?,
        updated_at: stored_u64(raw.updated_at, "updated_at")?,
        retracted_map_epoch: stored_optional_u64(raw.retracted_map_epoch, "retracted_map_epoch")?,
        retracted_epoch_id: raw.retracted_epoch_id,
        retracted_root_hash: raw.retracted_root_hash,
    };
    match record.state {
        FindingStickyStatus::Pending
            if record.retracted_map_epoch.is_some()
                || record.retracted_epoch_id.is_some()
                || record.retracted_root_hash.is_some() =>
        {
            Err(invariant("pending status has retracted epoch fields"))
        }
        FindingStickyStatus::Retracted
            if record.retracted_map_epoch.is_none()
                || record.retracted_epoch_id.is_none()
                || record.retracted_root_hash.is_none() =>
        {
            Err(invariant("retracted status is missing epoch fields"))
        }
        _ => Ok(record),
    }
}

fn load_status_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
    finding_id: &str,
) -> Result<Option<FindingStatusRecord>, FindingStatusStoreError> {
    let raw = transaction
        .query_row(
            r#"
            SELECT feed_id, operator_id, finding_id, state,
                   retraction_intent_sha256, first_observed_at, updated_at,
                   retracted_map_epoch, retracted_epoch_id,
                   retracted_root_hash
            FROM finding_status_states
            WHERE feed_id = ?1 AND finding_id = ?2
            "#,
            params![feed_id, finding_id],
            raw_status_from_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(status_from_raw).transpose()
}

#[derive(Debug)]
struct RawLeaf {
    feed_id: String,
    operator_id: String,
    finding_id: String,
    key_domain_nonce: i64,
    status_value_sha256: String,
    status_value_bytes: Vec<u8>,
    retraction_intent_sha256: String,
    local_intent_id: Option<String>,
    first_map_epoch: i64,
    first_epoch_id: String,
    recorded_at: i64,
}

fn raw_leaf_from_row(row: &Row<'_>) -> rusqlite::Result<RawLeaf> {
    Ok(RawLeaf {
        feed_id: row.get(0)?,
        operator_id: row.get(1)?,
        finding_id: row.get(2)?,
        key_domain_nonce: row.get(3)?,
        status_value_sha256: row.get(4)?,
        status_value_bytes: row.get(5)?,
        retraction_intent_sha256: row.get(6)?,
        local_intent_id: row.get(7)?,
        first_map_epoch: row.get(8)?,
        first_epoch_id: row.get(9)?,
        recorded_at: row.get(10)?,
    })
}

fn leaf_from_raw(raw: RawLeaf) -> Result<FindingStatusLeafRecord, FindingStatusStoreError> {
    let nonce = stored_u64(raw.key_domain_nonce, "key_domain_nonce")?;
    require_fixed_nonce(nonce)?;
    require_hex64(&raw.finding_id, "finding_id")?;
    require_hex64(&raw.status_value_sha256, "status_value_sha256")?;
    require_bytes(
        &raw.status_value_bytes,
        MAX_FINDING_STATUS_VALUE_BYTES,
        "status_value_bytes",
    )?;
    if sha256_hex(&raw.status_value_bytes) != raw.status_value_sha256 {
        return Err(invariant("retained status leaf fails its value digest"));
    }
    require_hex64(&raw.retraction_intent_sha256, "retraction_intent_sha256")?;
    if let Some(intent_id) = raw.local_intent_id.as_deref() {
        require_hex64(intent_id, "local_intent_id")?;
    }
    require_hex64(&raw.first_epoch_id, "first_epoch_id")?;
    Ok(FindingStatusLeafRecord {
        feed_id: raw.feed_id,
        operator_id: raw.operator_id,
        finding_id: raw.finding_id,
        key_domain_nonce: nonce,
        status_value_sha256: raw.status_value_sha256,
        status_value_bytes: raw.status_value_bytes,
        retraction_intent_sha256: raw.retraction_intent_sha256,
        local_intent_id: raw.local_intent_id,
        first_map_epoch: stored_u64(raw.first_map_epoch, "first_map_epoch")?,
        first_epoch_id: raw.first_epoch_id,
        recorded_at: stored_u64(raw.recorded_at, "recorded_at")?,
    })
}

fn load_leaf_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
    finding_id: &str,
) -> Result<Option<FindingStatusLeafRecord>, FindingStatusStoreError> {
    let raw = transaction
        .query_row(
            r#"
            SELECT feed_id, operator_id, finding_id, key_domain_nonce,
                   status_value_sha256, status_value_bytes,
                   retraction_intent_sha256, local_intent_id,
                   first_map_epoch, first_epoch_id, recorded_at
            FROM finding_status_leaves
            WHERE feed_id = ?1 AND finding_id = ?2
            "#,
            params![feed_id, finding_id],
            raw_leaf_from_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(leaf_from_raw).transpose()
}

#[derive(Debug)]
struct RawProof {
    feed_id: String,
    operator_id: String,
    finding_id: String,
    key_domain_nonce: i64,
    map_epoch: i64,
    epoch_id: String,
    root_hash: String,
    proof_kind: String,
    proof_sha256: String,
    proof_bytes: Vec<u8>,
    status_value_sha256: Option<String>,
    status_value_bytes: Option<Vec<u8>>,
    retraction_intent_sha256: Option<String>,
    checked_at: i64,
    valid_until: i64,
    recorded_at: i64,
    signed_epoch_sha256: String,
    signed_epoch_bytes: Vec<u8>,
}

fn raw_proof_from_row(row: &Row<'_>) -> rusqlite::Result<RawProof> {
    Ok(RawProof {
        feed_id: row.get(0)?,
        operator_id: row.get(1)?,
        finding_id: row.get(2)?,
        key_domain_nonce: row.get(3)?,
        map_epoch: row.get(4)?,
        epoch_id: row.get(5)?,
        root_hash: row.get(6)?,
        proof_kind: row.get(7)?,
        proof_sha256: row.get(8)?,
        proof_bytes: row.get(9)?,
        status_value_sha256: row.get(10)?,
        status_value_bytes: row.get(11)?,
        retraction_intent_sha256: row.get(12)?,
        checked_at: row.get(13)?,
        valid_until: row.get(14)?,
        recorded_at: row.get(15)?,
        signed_epoch_sha256: row.get(16)?,
        signed_epoch_bytes: row.get(17)?,
    })
}

fn proof_from_raw(raw: RawProof) -> Result<FindingStatusProofRecord, FindingStatusStoreError> {
    let nonce = stored_u64(raw.key_domain_nonce, "key_domain_nonce")?;
    require_fixed_nonce(nonce)?;
    require_hex64(&raw.finding_id, "finding_id")?;
    require_hex64(&raw.epoch_id, "epoch_id")?;
    require_hex64(&raw.root_hash, "root_hash")?;
    require_hex64(&raw.proof_sha256, "proof_sha256")?;
    require_bytes(
        &raw.proof_bytes,
        MAX_FINDING_STATUS_PROOF_BYTES,
        "proof_bytes",
    )?;
    if sha256_hex(&raw.proof_bytes) != raw.proof_sha256 {
        return Err(invariant("retained proof bytes fail their digest"));
    }
    match (
        raw.status_value_sha256.as_deref(),
        raw.status_value_bytes.as_deref(),
    ) {
        (Some(digest), Some(bytes)) => {
            require_hex64(digest, "status_value_sha256")?;
            require_bytes(bytes, MAX_FINDING_STATUS_VALUE_BYTES, "status_value_bytes")?;
            if sha256_hex(bytes) != digest {
                return Err(invariant("retained proof value fails its digest"));
            }
        }
        (None, None) => {}
        _ => return Err(invariant("retained proof has a partial status value")),
    }
    if let Some(digest) = raw.retraction_intent_sha256.as_deref() {
        require_hex64(digest, "retraction_intent_sha256")?;
    }
    require_hex64(&raw.signed_epoch_sha256, "signed_epoch_sha256")?;
    require_bytes(
        &raw.signed_epoch_bytes,
        MAX_FINDING_STATUS_EPOCH_BYTES,
        "signed_epoch_bytes",
    )?;
    if sha256_hex(&raw.signed_epoch_bytes) != raw.signed_epoch_sha256 {
        return Err(invariant(
            "proof's retained signed epoch bytes fail their digest",
        ));
    }
    let record = FindingStatusProofRecord {
        feed_id: raw.feed_id,
        operator_id: raw.operator_id,
        key_domain_nonce: nonce,
        map_epoch: stored_u64(raw.map_epoch, "map_epoch")?,
        epoch_id: raw.epoch_id,
        root_hash: raw.root_hash,
        finding_id: raw.finding_id,
        kind: proof_kind_from_name(&raw.proof_kind)?,
        proof_sha256: raw.proof_sha256,
        proof_bytes: raw.proof_bytes,
        status_value_sha256: raw.status_value_sha256,
        status_value_bytes: raw.status_value_bytes,
        retraction_intent_sha256: raw.retraction_intent_sha256,
        checked_at: stored_u64(raw.checked_at, "checked_at")?,
        valid_until: stored_u64(raw.valid_until, "valid_until")?,
        recorded_at: stored_u64(raw.recorded_at, "recorded_at")?,
        signed_epoch_sha256: raw.signed_epoch_sha256,
        signed_epoch_bytes: raw.signed_epoch_bytes,
    };
    match record.kind {
        FindingStatusProofKind::Inclusion
            if record.status_value_sha256.is_none()
                || record.status_value_bytes.is_none()
                || record.retraction_intent_sha256.is_none() =>
        {
            Err(invariant("retained inclusion proof lost branch fields"))
        }
        FindingStatusProofKind::NonInclusion
            if record.status_value_sha256.is_some()
                || record.status_value_bytes.is_some()
                || record.retraction_intent_sha256.is_some() =>
        {
            Err(invariant(
                "retained non-inclusion proof has inclusion branch fields",
            ))
        }
        _ => Ok(record),
    }
}

const PROOF_SELECT: &str = r#"
    SELECT p.feed_id, p.operator_id, p.finding_id, p.key_domain_nonce,
           p.map_epoch, p.epoch_id, p.root_hash, p.proof_kind,
           p.proof_sha256, p.proof_bytes, p.status_value_sha256,
           p.status_value_bytes, p.retraction_intent_sha256, p.checked_at,
           p.valid_until, p.recorded_at, e.signed_epoch_sha256,
           e.signed_epoch_bytes
    FROM finding_status_proofs p
    JOIN finding_status_epochs e
      ON e.feed_id = p.feed_id AND e.map_epoch = p.map_epoch
"#;

fn load_proof_tx(
    transaction: &Transaction<'_>,
    feed_id: &str,
    finding_id: &str,
    map_epoch: u64,
) -> Result<Option<FindingStatusProofRecord>, FindingStatusStoreError> {
    let query =
        format!("{PROOF_SELECT} WHERE p.feed_id = ?1 AND p.finding_id = ?2 AND p.map_epoch = ?3");
    let raw = transaction
        .query_row(
            &query,
            params![feed_id, finding_id, sqlite_i64(map_epoch, "map_epoch")?],
            raw_proof_from_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(proof_from_raw).transpose()
}

fn proof_record_matches_input(
    record: &FindingStatusProofRecord,
    input: &VerifiedFindingStatusProofInput<'_>,
    proof_sha256: &str,
    status_value_sha256: Option<&str>,
) -> bool {
    record.feed_id == input.feed_id
        && record.operator_id == input.operator_id
        && record.key_domain_nonce == input.key_domain_nonce
        && record.map_epoch == input.map_epoch
        && record.epoch_id == input.epoch_id
        && record.root_hash == input.root_hash
        && record.finding_id == input.finding_id
        && record.kind == input.kind
        && record.proof_sha256 == proof_sha256
        && record.proof_bytes == input.proof_bytes
        && record.status_value_sha256.as_deref() == status_value_sha256
        && record.status_value_bytes.as_deref() == input.status_value_bytes
        && record.retraction_intent_sha256.as_deref() == input.retraction_intent_sha256
        && record.checked_at == input.checked_at
        && record.valid_until == input.valid_until
}

fn verify_proof_record_at_floor(
    proof: &FindingStatusProofRecord,
    floor: &FindingStatusFeedFloor,
) -> Result<(), FindingStatusStoreError> {
    if proof.feed_id != floor.feed_id
        || proof.operator_id != floor.operator_id
        || proof.key_domain_nonce != floor.key_domain_nonce
        || proof.map_epoch != floor.map_epoch
        || proof.epoch_id != floor.epoch_id
        || proof.root_hash != floor.root_hash
        || proof.signed_epoch_sha256 != floor.signed_epoch_sha256
    {
        return Err(invariant(
            "status proof does not match the exact durable current floor",
        ));
    }
    Ok(())
}

const fn intent_source_name(source: FindingRetractionIntentSource) -> &'static str {
    match source {
        FindingRetractionIntentSource::Voluntary => "voluntary",
        FindingRetractionIntentSource::Enforcement => "enforcement",
    }
}

fn intent_source_from_name(
    name: &str,
) -> Result<FindingRetractionIntentSource, FindingStatusStoreError> {
    match name {
        "voluntary" => Ok(FindingRetractionIntentSource::Voluntary),
        "enforcement" => Ok(FindingRetractionIntentSource::Enforcement),
        other => Err(invariant(format!(
            "unknown retraction intent source {other}"
        ))),
    }
}

fn intent_state_from_name(
    name: &str,
) -> Result<FindingRetractionIntentState, FindingStatusStoreError> {
    match name {
        "waiting_finality" => Ok(FindingRetractionIntentState::WaitingFinality),
        "dispatch_eligible" => Ok(FindingRetractionIntentState::DispatchEligible),
        "published" => Ok(FindingRetractionIntentState::Published),
        other => Err(invariant(format!(
            "unknown retraction intent state {other}"
        ))),
    }
}

fn sticky_status_from_name(name: &str) -> Result<FindingStickyStatus, FindingStatusStoreError> {
    match name {
        "pending" => Ok(FindingStickyStatus::Pending),
        "retracted" => Ok(FindingStickyStatus::Retracted),
        other => Err(invariant(format!("unknown sticky finding status {other}"))),
    }
}

const fn proof_kind_name(kind: FindingStatusProofKind) -> &'static str {
    match kind {
        FindingStatusProofKind::Inclusion => "inclusion",
        FindingStatusProofKind::NonInclusion => "non_inclusion",
    }
}

fn proof_kind_from_name(name: &str) -> Result<FindingStatusProofKind, FindingStatusStoreError> {
    match name {
        "inclusion" => Ok(FindingStatusProofKind::Inclusion),
        "non_inclusion" => Ok(FindingStatusProofKind::NonInclusion),
        other => Err(invariant(format!(
            "unknown finding status proof kind {other}"
        ))),
    }
}

fn require_fixed_nonce(nonce: u64) -> Result<(), FindingStatusStoreError> {
    if nonce != FINDING_STATUS_KEY_DOMAIN_NONCE {
        return Err(invariant(format!(
            "key_domain_nonce must equal fixed finding-status nonce {FINDING_STATUS_KEY_DOMAIN_NONCE}"
        )));
    }
    Ok(())
}

fn require_identifier(value: &str, field: &'static str) -> Result<(), FindingStatusStoreError> {
    require_identifier_with_bound(value, 512, field)
}

fn require_identifier_with_bound(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), FindingStatusStoreError> {
    if value.is_empty() || value.len() > maximum {
        return Err(invariant(format!("{field} byte length is out of bounds")));
    }
    Ok(())
}

fn require_hex64(value: &str, field: &'static str) -> Result<(), FindingStatusStoreError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(invariant(format!(
        "{field} is not 64 lowercase hex characters"
    )))
}

fn require_bytes(
    bytes: &[u8],
    maximum: usize,
    field: &'static str,
) -> Result<(), FindingStatusStoreError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(invariant(format!("{field} byte length is out of bounds")));
    }
    Ok(())
}

fn require_positive(value: u64, field: &'static str) -> Result<(), FindingStatusStoreError> {
    if value == 0 {
        return Err(invariant(format!("{field} must be positive")));
    }
    sqlite_i64(value, field).map(|_| ())
}

fn sqlite_i64(value: u64, field: &'static str) -> Result<i64, FindingStatusStoreError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite integer range")))
}

fn stored_u64(value: i64, field: &'static str) -> Result<u64, FindingStatusStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("{field} is negative")))
}

fn stored_optional_u64(
    value: Option<i64>,
    field: &'static str,
) -> Result<Option<u64>, FindingStatusStoreError> {
    value.map(|value| stored_u64(value, field)).transpose()
}

fn invariant(detail: impl Into<String>) -> FindingStatusStoreError {
    FindingStatusStoreError::Invariant(detail.into())
}

fn admission_error(error: AdmissionOperationStoreError) -> FindingStatusStoreError {
    match error {
        AdmissionOperationStoreError::Fenced => FindingStatusStoreError::Fenced,
        AdmissionOperationStoreError::NotFound => {
            FindingStatusStoreError::Unavailable("serving-owner state not found".to_owned())
        }
        AdmissionOperationStoreError::Unavailable(detail) => {
            FindingStatusStoreError::Unavailable(detail)
        }
        AdmissionOperationStoreError::OutcomeUnknown(detail) => {
            FindingStatusStoreError::OutcomeUnknown(detail)
        }
        AdmissionOperationStoreError::Invariant(detail) => {
            FindingStatusStoreError::Invariant(detail)
        }
        AdmissionOperationStoreError::Operation(error) => invariant(error.to_string()),
    }
}

fn sqlite_error(error: rusqlite::Error) -> FindingStatusStoreError {
    match &error {
        rusqlite::Error::SqliteFailure(code, _)
            if matches!(
                code.code,
                ErrorCode::ConstraintViolation
                    | ErrorCode::DatabaseBusy
                    | ErrorCode::DatabaseLocked
            ) =>
        {
            if code.code == ErrorCode::ConstraintViolation {
                FindingStatusStoreError::Conflict(error.to_string())
            } else {
                FindingStatusStoreError::Unavailable(error.to_string())
            }
        }
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::Utf8Error(..) => invariant(error.to_string()),
        _ => FindingStatusStoreError::Unavailable(error.to_string()),
    }
}

pub(crate) fn initialize_finding_status_schema(
    connection: &mut Connection,
) -> Result<(), FindingStatusStoreError> {
    let on_disk = crate::check_schema_version(
        connection,
        FINDING_STATUS_SCHEMA_KEY,
        FINDING_STATUS_SUPPORTED_SCHEMA_VERSION,
        FINDING_STATUS_SCHEMA_ANCHORS,
    )
    .map_err(|error| invariant(error.to_string()))?;
    if on_disk == FINDING_STATUS_SUPPORTED_SCHEMA_VERSION {
        return verify_finding_status_invariants(connection);
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(FINDING_STATUS_SCHEMA)
        .map_err(sqlite_error)?;
    crate::stamp_schema_version(
        &transaction,
        FINDING_STATUS_SCHEMA_KEY,
        FINDING_STATUS_SUPPORTED_SCHEMA_VERSION,
    )
    .map_err(|error| invariant(error.to_string()))?;
    verify_finding_status_invariants(&transaction)?;
    transaction.commit().map_err(sqlite_error)
}

pub(crate) fn verify_finding_status_invariants(
    connection: &Connection,
) -> Result<(), FindingStatusStoreError> {
    let expected = Connection::open_in_memory().map_err(sqlite_error)?;
    expected
        .execute_batch(FINDING_STATUS_SCHEMA)
        .map_err(sqlite_error)?;
    if finding_status_schema_catalog(connection)? != finding_status_schema_catalog(&expected)? {
        return Err(invariant(
            "finding status schema differs from the canonical definition",
        ));
    }
    verify_status_content_invariants(connection)
}

type SchemaCatalogEntry = (String, String, String, Option<String>);

fn finding_status_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SchemaCatalogEntry>, FindingStatusStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT type, name, tbl_name, sql
            FROM sqlite_schema
            WHERE name LIKE 'finding_status_%'
               OR tbl_name LIKE 'finding_status_%'
               OR name LIKE 'finding_retraction_%'
               OR tbl_name LIKE 'finding_retraction_%'
            ORDER BY type, name, tbl_name
            "#,
        )
        .map_err(sqlite_error)?;
    let catalog = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(catalog)
}

fn verify_status_content_invariants(
    connection: &Connection,
) -> Result<(), FindingStatusStoreError> {
    let missing_floor_epoch: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM finding_status_feed_floors f
                LEFT JOIN finding_status_epochs e
                  ON e.feed_id = f.feed_id AND e.map_epoch = f.map_epoch
                WHERE e.feed_id IS NULL
                   OR e.epoch_id <> f.epoch_id
                   OR e.root_hash <> f.root_hash
                   OR e.signed_epoch_sha256 <> f.signed_epoch_sha256
                   OR e.operator_id <> f.operator_id
                   OR e.key_domain_nonce <> f.key_domain_nonce
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if missing_floor_epoch {
        return Err(invariant(
            "finding status floor is missing its exact retained epoch",
        ));
    }

    let epoch_without_floor: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM finding_status_epochs e
                LEFT JOIN finding_status_feed_floors f
                  ON f.feed_id = e.feed_id
                WHERE f.feed_id IS NULL
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if epoch_without_floor {
        return Err(invariant(
            "retained finding status epoch is missing its feed floor",
        ));
    }

    let missing_sticky_state: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM finding_retraction_intents i
                LEFT JOIN finding_status_states s
                  ON s.feed_id = i.feed_id AND s.finding_id = i.finding_id
                WHERE s.finding_id IS NULL
                   OR s.retraction_intent_sha256 <> i.intent_sha256
                   OR (i.state = 'published' AND s.state <> 'retracted')
                   OR (i.state <> 'published' AND s.state <> 'pending')
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if missing_sticky_state {
        return Err(invariant(
            "finding retraction intent is missing its sticky status state",
        ));
    }
    let missing_leaf_state: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM finding_status_leaves l
                LEFT JOIN finding_status_states s
                  ON s.feed_id = l.feed_id AND s.finding_id = l.finding_id
                WHERE s.finding_id IS NULL
                   OR s.state <> 'retracted'
                   OR s.retraction_intent_sha256
                      <> l.retraction_intent_sha256
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if missing_leaf_state {
        return Err(invariant(
            "finding status leaf is missing its sticky retracted state",
        ));
    }
    Ok(())
}
