// Row mappers and per-record load helpers.

fn map_challenge(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawChallenge> {
    Ok(RawChallenge {
        challenge_id: row.get(0)?,
        finding_id: row.get(1)?,
        listing_id: row.get(2)?,
        challenge_envelope_sha256: row.get(3)?,
        authorization_branch: row.get(4)?,
        evidence_class: row.get(5)?,
        challenger_hex: row.get(6)?,
        state: row.get(7)?,
        retry_count: row.get(8)?,
        retry_deadline: row.get(9)?,
        outcome_envelope_sha256: row.get(10)?,
        submitted_at: row.get(11)?,
        updated_at: row.get(12)?,
    })
}

fn challenge_from_raw(
    raw: RawChallenge,
) -> Result<FindingChallengeRecord, FindingChallengeStoreError> {
    Ok(FindingChallengeRecord {
        challenge_id: raw.challenge_id,
        finding_id: raw.finding_id,
        listing_id: raw.listing_id,
        challenge_envelope_sha256: raw.challenge_envelope_sha256,
        authorization_branch: authorization_branch_from_name(&raw.authorization_branch)?,
        evidence_class: evidence_class_from_name(&raw.evidence_class)?,
        challenger_hex: raw.challenger_hex,
        state: challenge_state_from_name(&raw.state)?,
        retry_count: stored_u64(raw.retry_count, "retry_count")?,
        retry_deadline: raw
            .retry_deadline
            .map(|value| stored_u64(value, "retry_deadline"))
            .transpose()?,
        outcome_envelope_sha256: raw.outcome_envelope_sha256,
        submitted_at: stored_u64(raw.submitted_at, "submitted_at")?,
        updated_at: stored_u64(raw.updated_at, "updated_at")?,
    })
}

fn load_challenge_tx(
    transaction: &Transaction<'_>,
    challenge_id: &str,
) -> Result<Option<FindingChallengeRecord>, FindingChallengeStoreError> {
    let raw = transaction
        .query_row(
            &format!("SELECT {CHALLENGE_COLUMNS} FROM challenges WHERE challenge_id = ?1"),
            [challenge_id],
            map_challenge,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(challenge_from_raw).transpose()
}

fn load_dispute_lock_tx(
    transaction: &Transaction<'_>,
    challenge_id: &str,
) -> Result<Option<FindingDisputeLockRecord>, FindingChallengeStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT lock_id, challenge_id, owner_hex, bond_class,
                   schedule_envelope_sha256, amount_units, currency,
                   pool_principal_id, pool_rail_destination,
                   pool_authority_epoch, expires_at, state, locked_at,
                   updated_at
            FROM dispute_locks WHERE challenge_id = ?1
            "#,
            [challenge_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, i64>(13)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((
        lock_id,
        challenge_id,
        owner_hex,
        bond_class,
        schedule_envelope_sha256,
        amount_units,
        currency,
        pool_principal_id,
        pool_rail_destination,
        pool_authority_epoch,
        expires_at,
        state,
        locked_at,
        updated_at,
    )) = row
    else {
        return Ok(None);
    };
    Ok(Some(FindingDisputeLockRecord {
        lock_id,
        challenge_id,
        owner_hex,
        bond_class,
        schedule_envelope_sha256,
        amount_units: stored_u64(amount_units, "amount_units")?,
        currency,
        pool_principal_id,
        pool_rail_destination,
        pool_authority_epoch: stored_u64(pool_authority_epoch, "pool_authority_epoch")?,
        expires_at: stored_u64(expires_at, "expires_at")?,
        state: dispute_lock_state_from_name(&state)?,
        locked_at: stored_u64(locked_at, "locked_at")?,
        updated_at: stored_u64(updated_at, "updated_at")?,
    }))
}

const LIABILITY_COLUMNS: &str = r#"
    liability_key, defect_key, finding_id, listing_id, allocation_id, seller_hex,
    venue_id, chain_id, vault_contract, vault_id, state, upheld_challenge_id,
    purchase_cutoff_slot, claim_deadline, appeal_window_opened_at,
    appeal_deadline, appeal_terms_envelope_sha256, snapshot_digest,
    allocation_digest, publication_pending, quarantined, opened_at, updated_at
"#;

struct RawLiability {
    liability_key: String,
    defect_key: String,
    finding_id: String,
    listing_id: String,
    allocation_id: String,
    seller_hex: String,
    venue_id: String,
    chain_id: String,
    vault_contract: String,
    vault_id: String,
    state: String,
    upheld_challenge_id: Option<String>,
    purchase_cutoff_slot: Option<i64>,
    claim_deadline: Option<i64>,
    appeal_window_opened_at: Option<i64>,
    appeal_deadline: Option<i64>,
    appeal_terms_envelope_sha256: Option<String>,
    snapshot_digest: Option<String>,
    allocation_digest: Option<String>,
    publication_pending: i64,
    quarantined: i64,
    opened_at: i64,
    updated_at: i64,
}

fn map_liability(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawLiability> {
    Ok(RawLiability {
        liability_key: row.get(0)?,
        defect_key: row.get(1)?,
        finding_id: row.get(2)?,
        listing_id: row.get(3)?,
        allocation_id: row.get(4)?,
        seller_hex: row.get(5)?,
        venue_id: row.get(6)?,
        chain_id: row.get(7)?,
        vault_contract: row.get(8)?,
        vault_id: row.get(9)?,
        state: row.get(10)?,
        upheld_challenge_id: row.get(11)?,
        purchase_cutoff_slot: row.get(12)?,
        claim_deadline: row.get(13)?,
        appeal_window_opened_at: row.get(14)?,
        appeal_deadline: row.get(15)?,
        appeal_terms_envelope_sha256: row.get(16)?,
        snapshot_digest: row.get(17)?,
        allocation_digest: row.get(18)?,
        publication_pending: row.get(19)?,
        quarantined: row.get(20)?,
        opened_at: row.get(21)?,
        updated_at: row.get(22)?,
    })
}

fn liability_from_raw(
    raw: RawLiability,
) -> Result<FindingLiabilityRecord, FindingChallengeStoreError> {
    Ok(FindingLiabilityRecord {
        liability_key: raw.liability_key,
        defect_key: raw.defect_key,
        finding_id: raw.finding_id,
        listing_id: raw.listing_id,
        allocation_id: raw.allocation_id,
        seller_hex: raw.seller_hex,
        venue_id: raw.venue_id,
        chain_id: raw.chain_id,
        vault_contract: raw.vault_contract,
        vault_id: raw.vault_id,
        state: liability_state_from_name(&raw.state)?,
        upheld_challenge_id: raw.upheld_challenge_id,
        purchase_cutoff_slot: raw
            .purchase_cutoff_slot
            .map(|value| stored_u64(value, "purchase_cutoff_slot"))
            .transpose()?,
        claim_deadline: raw
            .claim_deadline
            .map(|value| stored_u64(value, "claim_deadline"))
            .transpose()?,
        appeal_window_opened_at: raw
            .appeal_window_opened_at
            .map(|value| stored_u64(value, "appeal_window_opened_at"))
            .transpose()?,
        appeal_deadline: raw
            .appeal_deadline
            .map(|value| stored_u64(value, "appeal_deadline"))
            .transpose()?,
        appeal_terms_envelope_sha256: raw.appeal_terms_envelope_sha256,
        snapshot_digest: raw.snapshot_digest,
        allocation_digest: raw.allocation_digest,
        publication_pending: stored_flag(raw.publication_pending, "publication_pending")?,
        quarantined: stored_flag(raw.quarantined, "quarantined")?,
        opened_at: stored_u64(raw.opened_at, "opened_at")?,
        updated_at: stored_u64(raw.updated_at, "updated_at")?,
    })
}

fn load_liability_tx(
    transaction: &Transaction<'_>,
    liability_key: &str,
) -> Result<Option<FindingLiabilityRecord>, FindingChallengeStoreError> {
    let raw = transaction
        .query_row(
            &format!("SELECT {LIABILITY_COLUMNS} FROM liability_heads WHERE liability_key = ?1"),
            [liability_key],
            map_liability,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(liability_from_raw).transpose()
}

const CASE_COLUMNS: &str = r#"
    case_id, finding_id, listing_id, liability_key, case_kind, case_state,
    appeal_of_case_id, supersedes_case_id, superseded_by_case_id, recorded_at
"#;

struct RawCase {
    case_id: String,
    finding_id: String,
    listing_id: String,
    liability_key: String,
    case_kind: String,
    case_state: String,
    appeal_of_case_id: Option<String>,
    supersedes_case_id: Option<String>,
    superseded_by_case_id: Option<String>,
    recorded_at: i64,
}

fn map_case(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawCase> {
    Ok(RawCase {
        case_id: row.get(0)?,
        finding_id: row.get(1)?,
        listing_id: row.get(2)?,
        liability_key: row.get(3)?,
        case_kind: row.get(4)?,
        case_state: row.get(5)?,
        appeal_of_case_id: row.get(6)?,
        supersedes_case_id: row.get(7)?,
        superseded_by_case_id: row.get(8)?,
        recorded_at: row.get(9)?,
    })
}

fn case_from_raw(raw: RawCase) -> Result<FindingGovernanceCaseRecord, FindingChallengeStoreError> {
    Ok(FindingGovernanceCaseRecord {
        case_id: raw.case_id,
        finding_id: raw.finding_id,
        listing_id: raw.listing_id,
        liability_key: raw.liability_key,
        case_kind: case_kind_from_name(&raw.case_kind)?,
        case_state: raw.case_state,
        appeal_of_case_id: raw.appeal_of_case_id,
        supersedes_case_id: raw.supersedes_case_id,
        superseded_by_case_id: raw.superseded_by_case_id,
        recorded_at: stored_u64(raw.recorded_at, "recorded_at")?,
    })
}

fn load_case_tx(
    transaction: &Transaction<'_>,
    case_id: &str,
) -> Result<Option<FindingGovernanceCaseRecord>, FindingChallengeStoreError> {
    let raw = transaction
        .query_row(
            &format!("SELECT {CASE_COLUMNS} FROM governance_case_index WHERE case_id = ?1"),
            [case_id],
            map_case,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(case_from_raw).transpose()
}

/// Resolve the unique unsuperseded case inside a caller-owned transaction.
/// A write path uses this to serialize its lifecycle decision against case
/// insertion; the public read path uses the same ambiguity semantics.
pub(crate) fn resolve_case_head_tx(
    transaction: &Transaction<'_>,
    liability_key: &str,
) -> Result<Option<FindingGovernanceCaseRecord>, FindingChallengeStoreError> {
    let mut statement = transaction
        .prepare(&format!(
            r#"
            SELECT {CASE_COLUMNS} FROM governance_case_index
            WHERE liability_key = ?1 AND superseded_by_case_id IS NULL
            ORDER BY recorded_at ASC, case_id ASC
            LIMIT 2
            "#
        ))
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([liability_key], map_case)
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    let mut live = rows
        .into_iter()
        .map(case_from_raw)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter();
    let Some(head) = live.next() else {
        return Ok(None);
    };
    if let Some(rival) = live.next() {
        return Err(FindingChallengeStoreError::AmbiguousCaseHead {
            liability_key: liability_key.to_owned(),
            first_case_id: head.case_id,
            second_case_id: rival.case_id,
        });
    }
    Ok(Some(head))
}

fn load_claim_snapshot_tx(
    transaction: &Transaction<'_>,
    liability_key: &str,
) -> Result<Option<FindingClaimSnapshotRecord>, FindingChallengeStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT liability_key, cutoff_slot, snapshot_digest,
                   allocation_digest, total_realized_spend_units, currency,
                   buyer_pool_units, community_fund_units, sealed_at
            FROM claim_snapshots WHERE liability_key = ?1
            "#,
            [liability_key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((
        liability_key,
        cutoff_slot,
        snapshot_digest,
        allocation_digest,
        total_realized_spend_units,
        currency,
        buyer_pool_units,
        community_fund_units,
        sealed_at,
    )) = row
    else {
        return Ok(None);
    };
    Ok(Some(FindingClaimSnapshotRecord {
        liability_key,
        cutoff_slot: stored_u64(cutoff_slot, "cutoff_slot")?,
        snapshot_digest,
        allocation_digest,
        total_realized_spend_units: stored_u64(
            total_realized_spend_units,
            "total_realized_spend_units",
        )?,
        currency,
        buyer_pool_units: stored_u64(buyer_pool_units, "buyer_pool_units")?,
        community_fund_units: stored_u64(community_fund_units, "community_fund_units")?,
        sealed_at: stored_u64(sealed_at, "sealed_at")?,
    }))
}

const EFFECT_INTENT_COLUMNS: &str = r#"
    intent_key, liability_key, kind, intent_digest, settlement_required, state,
    attempt_count, recorded_at, updated_at
"#;

struct RawEffectIntent {
    intent_key: String,
    liability_key: Option<String>,
    kind: String,
    intent_digest: String,
    settlement_required: i64,
    state: String,
    attempt_count: i64,
    recorded_at: i64,
    updated_at: i64,
}

fn map_effect_intent(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawEffectIntent> {
    Ok(RawEffectIntent {
        intent_key: row.get(0)?,
        liability_key: row.get(1)?,
        kind: row.get(2)?,
        intent_digest: row.get(3)?,
        settlement_required: row.get(4)?,
        state: row.get(5)?,
        attempt_count: row.get(6)?,
        recorded_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

fn effect_intent_from_raw(
    raw: RawEffectIntent,
) -> Result<FindingEffectIntentRecord, FindingChallengeStoreError> {
    Ok(FindingEffectIntentRecord {
        intent_key: raw.intent_key,
        liability_key: raw.liability_key,
        kind: effect_intent_kind_from_name(&raw.kind)?,
        intent_digest: raw.intent_digest,
        settlement_required: stored_flag(raw.settlement_required, "settlement_required")?,
        state: effect_intent_state_from_name(&raw.state)?,
        attempt_count: stored_u64(raw.attempt_count, "attempt_count")?,
        recorded_at: stored_u64(raw.recorded_at, "recorded_at")?,
        updated_at: stored_u64(raw.updated_at, "updated_at")?,
    })
}

fn load_effect_intent_tx(
    transaction: &Transaction<'_>,
    intent_key: &str,
) -> Result<Option<FindingEffectIntentRecord>, FindingChallengeStoreError> {
    let raw = transaction
        .query_row(
            &format!("SELECT {EFFECT_INTENT_COLUMNS} FROM effect_intents WHERE intent_key = ?1"),
            [intent_key],
            map_effect_intent,
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map(effect_intent_from_raw).transpose()
}

fn load_seller_impairment_reconciliation_tx(
    transaction: &Transaction<'_>,
    intent_key: &str,
) -> Result<Option<FindingSellerImpairmentReconciliationRecord>, FindingChallengeStoreError> {
    transaction
        .query_row(
            r#"
            SELECT intent_key, liability_key, intent_digest, tx_hash,
                   reconciliation_sha256, recorded_at
            FROM finding_seller_impairment_reconciliations
            WHERE intent_key = ?1
            "#,
            [intent_key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?
        .map(
            |(
                intent_key,
                liability_key,
                intent_digest,
                tx_hash,
                reconciliation_sha256,
                recorded_at,
            )| {
                Ok(FindingSellerImpairmentReconciliationRecord {
                    intent_key,
                    liability_key,
                    intent_digest,
                    tx_hash,
                    reconciliation_sha256,
                    recorded_at: stored_u64(recorded_at, "recorded_at")?,
                })
            },
        )
        .transpose()
}
fn advance_challenge_state_tx(
    transaction: &Transaction<'_>,
    challenge_id: &str,
    from: &str,
    to: &str,
    now: u64,
) -> Result<(), FindingChallengeStoreError> {
    let changed = transaction
        .execute(
            r#"
            UPDATE challenges SET state = ?3, updated_at = ?4
            WHERE challenge_id = ?1 AND state = ?2
            "#,
            params![challenge_id, from, to, sqlite_i64(now, "now")?],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(invariant("challenge transition did not affect one row"));
    }
    Ok(())
}
