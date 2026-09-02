// Shared write-transaction helpers for transitions and verdicts.

/// The caller names the state it believes a head is in, and that state
/// must be the only legal source of the edge it is asking for, so no
/// caller can skip a state by naming a later one.
fn require_transition_source(
    expected_state: FindingLiabilityState,
    source_state: FindingLiabilityState,
    target_state: FindingLiabilityState,
) -> Result<(), FindingChallengeStoreError> {
    if expected_state == source_state {
        return Ok(());
    }
    Err(FindingChallengeStoreError::Conflict(format!(
        "state {} is not the source of the transition to {}",
        liability_state_name(expected_state),
        liability_state_name(target_state)
    )))
}

/// One liability edge applied inside a caller-supplied transaction, paired
/// with the head as this transaction read it so a composing caller reaches
/// the listing it names without a second load. Identity columns are frozen
/// at insert, so the listing that record names is the one the edge moved.
/// Idempotent once the head already sits at the target.
fn apply_liability_transition_tx(
    transaction: &Transaction<'_>,
    liability_key: &str,
    source_state: FindingLiabilityState,
    target_state: FindingLiabilityState,
    publication_pending: Option<bool>,
    now: u64,
) -> Result<(FindingChallengeWriteOutcome, FindingLiabilityRecord), FindingChallengeStoreError> {
    let liability = load_liability_tx(transaction, liability_key)?
        .ok_or(FindingChallengeStoreError::NotFound)?;
    if liability.state == target_state {
        return Ok((FindingChallengeWriteOutcome::ExistingSame, liability));
    }
    if liability.state != source_state {
        return Err(FindingChallengeStoreError::Conflict(format!(
            "liability is in state {}, not the expected {}",
            liability_state_name(liability.state),
            liability_state_name(source_state)
        )));
    }
    let pending = publication_pending.unwrap_or(liability.publication_pending);
    let changed = transaction
        .execute(
            r#"
            UPDATE liability_heads
            SET state = ?3, publication_pending = ?4, updated_at = ?5
            WHERE liability_key = ?1 AND state = ?2
            "#,
            params![
                liability_key,
                liability_state_name(source_state),
                liability_state_name(target_state),
                i64::from(pending),
                sqlite_i64(now, "now")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(invariant("liability transition did not affect one row"));
    }
    Ok((FindingChallengeWriteOutcome::Inserted, liability))
}

/// Whether a liability head other than `liability_key` still holds one
/// listing's sales block. Every head past `open` carries an upheld
/// challenge, and so holds the listing until it is exonerated; a head that
/// never left `open` never blocked anything.
fn listing_holds_another_liability_tx(
    transaction: &Transaction<'_>,
    listing_id: &str,
    liability_key: &str,
) -> Result<bool, FindingChallengeStoreError> {
    let held: bool = transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM liability_heads
                WHERE listing_id = ?1 AND liability_key <> ?2
                  AND state NOT IN ('open', 'reversed_before_impairment')
            )
            "#,
            params![listing_id, liability_key],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    Ok(held)
}

/// The upheld transaction, exposed on a caller-supplied transaction so a
/// coordinator can compose it with further writes on the same connection
/// without losing atomicity.
pub(crate) fn uphold_liability_tx(
    transaction: &Transaction<'_>,
    liability_key: &str,
    challenge_id: &str,
    cutoff_slot: u64,
    claim_deadline: u64,
    now: u64,
) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
    let liability = load_liability_tx(transaction, liability_key)?
        .ok_or(FindingChallengeStoreError::NotFound)?;
    let challenge = load_challenge_tx(transaction, challenge_id)?
        .ok_or(FindingChallengeStoreError::NotFound)?;
    if challenge.state != FindingChallengeState::Upheld {
        return Err(FindingChallengeStoreError::Conflict(format!(
            "a challenge in state {} cannot uphold a liability",
            challenge_state_name(challenge.state)
        )));
    }
    if challenge.finding_id != liability.finding_id || challenge.listing_id != liability.listing_id
    {
        return Err(FindingChallengeStoreError::Conflict(
            "challenge does not name the liability's finding and listing".to_owned(),
        ));
    }
    // The cutoff has to cover every slot the listing has already handed
    // out. A cutoff below the high-water mark would leave buyers who paid
    // before the block sitting above the claim line, silently outside the
    // snapshot the payout derives from.
    let high_water =
        highest_slot_ordinal_tx(transaction, &liability.listing_id).map_err(purchase_error)?;
    if cutoff_slot < high_water {
        return Err(FindingChallengeStoreError::Conflict(format!(
            "purchase cutoff {cutoff_slot} is below the listing slot high-water mark {high_water}"
        )));
    }
    if liability.state != FindingLiabilityState::Open {
        if liability.upheld_challenge_id.as_deref() == Some(challenge_id)
            && liability.purchase_cutoff_slot == Some(cutoff_slot)
        {
            // The block committed with the freeze, so it is already
            // durable; recording it again is a no-op that keeps the
            // replay path identical to the first call.
            block_new_slots_tx(transaction, &liability.listing_id, now).map_err(purchase_error)?;
            return Ok(FindingChallengeWriteOutcome::ExistingSame);
        }
        return Err(FindingChallengeStoreError::Conflict(format!(
            "liability is in state {} and cannot be upheld again",
            liability_state_name(liability.state)
        )));
    }
    let changed = transaction
        .execute(
            r#"
            UPDATE liability_heads
            SET state = 'upheld_pending_claims', upheld_challenge_id = ?2,
                purchase_cutoff_slot = ?3, claim_deadline = ?4, updated_at = ?5
            WHERE liability_key = ?1 AND state = 'open'
            "#,
            params![
                liability_key,
                challenge_id,
                sqlite_i64(cutoff_slot, "cutoff_slot")?,
                sqlite_i64(claim_deadline, "claim_deadline")?,
                sqlite_i64(now, "now")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(invariant("liability uphold did not affect one row"));
    }
    block_new_slots_tx(transaction, &liability.listing_id, now).map_err(purchase_error)?;
    Ok(FindingChallengeWriteOutcome::Inserted)
}

const CHALLENGE_COLUMNS: &str = r#"
    challenge_id, finding_id, listing_id, challenge_envelope_sha256,
    authorization_branch, evidence_class, challenger_hex, state, retry_count,
    retry_deadline, outcome_envelope_sha256, submitted_at, updated_at
"#;

fn record_verdict_tx(
    transaction: &Transaction<'_>,
    challenge_id: &str,
    verdict: FindingChallengeVerdict,
    outcome_envelope_sha256: &str,
    outcome_envelope_json: &[u8],
    now: u64,
) -> Result<FindingChallengeState, FindingChallengeStoreError> {
    let challenge = load_challenge_tx(transaction, challenge_id)?
        .ok_or(FindingChallengeStoreError::NotFound)?;
    store_outcome_envelope_tx(
        transaction,
        challenge_id,
        outcome_envelope_sha256,
        outcome_envelope_json,
        now,
    )?;
    match challenge.state {
        FindingChallengeState::Evaluating => {}
        FindingChallengeState::Submitted => {
            return Err(FindingChallengeStoreError::Conflict(
                "a verdict requires an evaluation already in progress".to_owned(),
            ));
        }
        recorded => {
            if challenge.outcome_envelope_sha256.as_deref() == Some(outcome_envelope_sha256)
                && verdict_admits_state(verdict, recorded)
            {
                return Ok(recorded);
            }
            return Err(FindingChallengeStoreError::Conflict(format!(
                "challenge already carries a verdict in state {}",
                challenge_state_name(recorded)
            )));
        }
    }
    let (target, retry_count, retry_deadline) = match verdict {
        FindingChallengeVerdict::Upheld => (
            FindingChallengeState::Upheld,
            challenge.retry_count,
            challenge.retry_deadline,
        ),
        FindingChallengeVerdict::Rejected => (
            FindingChallengeState::Rejected,
            challenge.retry_count,
            challenge.retry_deadline,
        ),
        FindingChallengeVerdict::Indeterminate { retry_deadline } => {
            match retry_deadline.filter(|deadline| *deadline > now) {
                Some(deadline) if challenge.retry_count < MAX_CHALLENGE_RETRIES => {
                    let spent = challenge
                        .retry_count
                        .checked_add(1)
                        .ok_or_else(|| invariant("challenge retry count overflowed u64"))?;
                    (
                        FindingChallengeState::IndeterminateRetryable,
                        spent,
                        Some(deadline),
                    )
                }
                _ => (
                    FindingChallengeState::IndeterminateClosed,
                    challenge.retry_count,
                    challenge.retry_deadline,
                ),
            }
        }
    };
    let changed = transaction
        .execute(
            r#"
            UPDATE challenges
            SET state = ?2, retry_count = ?3, retry_deadline = ?4,
                outcome_envelope_sha256 = ?5, updated_at = ?6
            WHERE challenge_id = ?1 AND state = 'evaluating'
            "#,
            params![
                challenge_id,
                challenge_state_name(target),
                sqlite_i64(retry_count, "retry_count")?,
                retry_deadline
                    .map(|deadline| sqlite_i64(deadline, "retry_deadline"))
                    .transpose()?,
                outcome_envelope_sha256,
                sqlite_i64(now, "now")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(invariant("challenge verdict did not affect one row"));
    }
    Ok(target)
}

fn store_outcome_envelope_tx(
    transaction: &Transaction<'_>,
    challenge_id: &str,
    outcome_envelope_sha256: &str,
    outcome_envelope_json: &[u8],
    now: u64,
) -> Result<(), FindingChallengeStoreError> {
    let inserted = transaction
        .execute(
            r#"
            INSERT OR IGNORE INTO finding_challenge_outcomes (
                outcome_envelope_sha256, challenge_id,
                outcome_envelope_json, recorded_at
            ) VALUES (?1, ?2, ?3, ?4)
            "#,
            params![
                outcome_envelope_sha256,
                challenge_id,
                outcome_envelope_json,
                sqlite_i64(now, "recorded_at")?,
            ],
        )
        .map_err(sqlite_error)?;
    if inserted == 1 {
        return Ok(());
    }
    let existing: Option<(String, Vec<u8>)> = transaction
        .query_row(
            r#"
            SELECT challenge_id, outcome_envelope_json
            FROM finding_challenge_outcomes
            WHERE outcome_envelope_sha256 = ?1
            "#,
            [outcome_envelope_sha256],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    match existing {
        Some((stored_challenge_id, stored_json))
            if stored_challenge_id == challenge_id && stored_json == outcome_envelope_json =>
        {
            Ok(())
        }
        Some(_) => Err(FindingChallengeStoreError::Conflict(
            "outcome envelope digest is already bound to different bytes or challenge".to_owned(),
        )),
        None => Err(invariant(
            "ignored outcome insert did not resolve an existing outcome",
        )),
    }
}

struct RawChallenge {
    challenge_id: String,
    finding_id: String,
    listing_id: String,
    challenge_envelope_sha256: String,
    authorization_branch: String,
    evidence_class: String,
    challenger_hex: Option<String>,
    state: String,
    retry_count: i64,
    retry_deadline: Option<i64>,
    outcome_envelope_sha256: Option<String>,
    submitted_at: i64,
    updated_at: i64,
}
