// Record matching, validation, and state-name parsing.

/// Reject a natural key already bound to a different row. The unique
/// indexes make this unreachable as a silent overwrite; catching it here
/// turns a constraint abort into a typed conflict.
///
/// `query` is a compile-time-fixed statement from this module, never
/// caller input.
fn reject_bound_identifier(
    transaction: &Transaction<'_>,
    query: &str,
    value: &str,
    what: &str,
) -> Result<(), FindingChallengeStoreError> {
    let bound: Option<String> = transaction
        .query_row(query, [value], |row| row.get(0))
        .optional()
        .map_err(sqlite_error)?;
    if bound.is_some() {
        return Err(FindingChallengeStoreError::Conflict(format!(
            "{what} is already bound to another challenge"
        )));
    }
    Ok(())
}

/// Whether a stored challenge is the same submission the caller is
/// recording. Identity is what the challenge asserts: which finding on
/// which listing, under which signed envelope, on which authorization
/// branch, in which evidence class, by which challenger.
///
/// `submitted_at` is deliberately excluded, following the sibling
/// purchase store: a caller derives it from its clock, so an honest retry
/// carries a later value than the durable row and comparing them would
/// strand the submission it is retrying. The stored row is returned
/// untouched, so the first submission time remains the durable one.
fn challenge_matches(
    existing: &FindingChallengeRecord,
    input: &FindingChallengeSubmission<'_>,
) -> bool {
    existing.finding_id == input.finding_id
        && existing.listing_id == input.listing_id
        && existing.challenge_envelope_sha256 == input.challenge_envelope_sha256
        && existing.authorization_branch == input.authorization_branch
        && existing.evidence_class == input.evidence_class
        && existing.challenger_hex.as_deref() == input.challenger_hex
}

fn dispute_lock_reservation_matches(
    transaction: &Transaction<'_>,
    input: &FindingDisputeLockInput<'_>,
) -> Result<Option<bool>, FindingChallengeStoreError> {
    let exists = transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM dispute_lock_reservations WHERE challenge_id = ?1
            )
            "#,
            [input.challenge_id],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if !exists {
        return Ok(None);
    }
    transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM dispute_lock_reservations
                WHERE challenge_id = ?1
                  AND lock_id = ?2
                  AND owner_hex = ?3
                  AND schedule_envelope_sha256 = ?4
                  AND amount_units = ?5
                  AND currency = ?6
                  AND pool_principal_id = ?7
                  AND pool_rail_destination = ?8
                  AND pool_authority_epoch = ?9
                  AND expires_at = ?10
                  AND locked_at = ?11
            )
            "#,
            params![
                input.challenge_id,
                input.lock_id,
                input.owner_hex,
                input.schedule_envelope_sha256,
                sqlite_i64(input.amount_units, "amount_units")?,
                input.currency,
                input.pool_principal_id,
                input.pool_rail_destination,
                sqlite_i64(input.pool_authority_epoch, "pool_authority_epoch")?,
                sqlite_i64(input.expires_at, "expires_at")?,
                sqlite_i64(input.locked_at, "locked_at")?,
            ],
            |row| row.get::<_, bool>(0),
        )
        .map(Some)
        .map_err(sqlite_error)
}

/// Whether a stored dispute lock is the same bond the caller is locking.
/// `expires_at` and `locked_at` are both clock-derived, so neither is
/// part of identity; the durable row keeps the expiry the first lock
/// fenced.
fn dispute_lock_matches(
    existing: &FindingDisputeLockRecord,
    input: &FindingDisputeLockInput<'_>,
) -> bool {
    existing.lock_id == input.lock_id
        && existing.owner_hex == input.owner_hex
        && existing.schedule_envelope_sha256 == input.schedule_envelope_sha256
        && existing.amount_units == input.amount_units
        && existing.currency == input.currency
        && existing.pool_principal_id == input.pool_principal_id
        && existing.pool_rail_destination == input.pool_rail_destination
        && existing.pool_authority_epoch == input.pool_authority_epoch
}

fn liability_matches(existing: &FindingLiabilityRecord, input: &FindingLiabilityInput<'_>) -> bool {
    existing.defect_key == input.defect_key
        && existing.finding_id == input.finding_id
        && existing.listing_id == input.listing_id
        && existing.allocation_id == input.allocation_id
        && existing.seller_hex == input.seller_hex
        && existing.venue_id == input.venue_id
        && existing.chain_id == input.chain_id
        && existing.vault_contract == input.vault_contract
        && existing.vault_id == input.vault_id
}

fn governance_case_matches(
    existing: &FindingGovernanceCaseRecord,
    input: &FindingGovernanceCaseInput<'_>,
) -> bool {
    existing.finding_id == input.finding_id
        && existing.listing_id == input.listing_id
        && existing.liability_key == input.liability_key
        && existing.case_kind == input.case_kind
        && existing.case_state == input.case_state
        && existing.appeal_of_case_id.as_deref() == input.appeal_of_case_id
        && existing.supersedes_case_id.as_deref() == input.supersedes_case_id
}

fn claim_snapshot_matches(
    existing: &FindingClaimSnapshotRecord,
    input: &FindingClaimSnapshotInput<'_>,
) -> bool {
    existing.cutoff_slot == input.cutoff_slot
        && existing.snapshot_digest == input.snapshot_digest
        && existing.allocation_digest == input.allocation_digest
        && existing.total_realized_spend_units == input.total_realized_spend_units
        && existing.currency == input.currency
        && existing.buyer_pool_units == input.buyer_pool_units
        && existing.community_fund_units == input.community_fund_units
}

fn validate_dispute_lock(
    input: &FindingDisputeLockInput<'_>,
) -> Result<(), FindingChallengeStoreError> {
    require_identifier(input.lock_id, "lock_id")?;
    require_identifier(input.challenge_id, "challenge_id")?;
    require_hex64(input.owner_hex, "owner_hex")?;
    require_hex64(input.schedule_envelope_sha256, "schedule_envelope_sha256")?;
    require_currency(input.currency)?;
    require_identifier(input.pool_principal_id, "pool_principal_id")?;
    require_identifier(input.pool_rail_destination, "pool_rail_destination")?;
    if input.amount_units == 0 {
        return Err(invariant("dispute bond amount must be nonzero"));
    }
    require_trusted_time(input.pool_authority_epoch, "pool_authority_epoch")?;
    require_trusted_time(input.locked_at, "locked_at")?;
    require_trusted_time(input.expires_at, "expires_at")?;
    if input.expires_at <= input.locked_at {
        return Err(invariant("dispute bond expiry does not follow its lock"));
    }
    Ok(())
}

fn validate_liability(input: &FindingLiabilityInput<'_>) -> Result<(), FindingChallengeStoreError> {
    require_hex64(input.liability_key, "liability_key")?;
    require_hex64(input.defect_key, "defect_key")?;
    require_hex64(input.finding_id, "finding_id")?;
    require_hex64(input.allocation_id, "allocation_id")?;
    require_hex64(input.seller_hex, "seller_hex")?;
    require_identifier(input.listing_id, "listing_id")?;
    require_identifier(input.venue_id, "venue_id")?;
    require_identifier(input.chain_id, "chain_id")?;
    require_identifier(input.vault_contract, "vault_contract")?;
    require_identifier(input.vault_id, "vault_id")?;
    require_trusted_time(input.opened_at, "opened_at")
}

fn validate_governance_case(
    input: &FindingGovernanceCaseInput<'_>,
) -> Result<(), FindingChallengeStoreError> {
    require_identifier(input.case_id, "case_id")?;
    require_hex64(input.finding_id, "finding_id")?;
    require_hex64(input.liability_key, "liability_key")?;
    require_identifier(input.listing_id, "listing_id")?;
    if input.case_state.is_empty() || input.case_state.len() > MAX_CASE_STATE_BYTES {
        return Err(invariant("case_state byte length is out of bounds"));
    }
    if let Some(appealed) = input.appeal_of_case_id {
        require_identifier(appealed, "appeal_of_case_id")?;
        if input.case_kind != FindingGovernanceCaseKind::Appeal {
            return Err(invariant("only an appeal appeals a prior case"));
        }
        if appealed == input.case_id {
            return Err(invariant("a case cannot appeal itself"));
        }
    }
    if let Some(superseded) = input.supersedes_case_id {
        require_identifier(superseded, "supersedes_case_id")?;
        if superseded == input.case_id {
            return Err(invariant("a case cannot supersede itself"));
        }
    }
    require_trusted_time(input.recorded_at, "recorded_at")
}

fn validate_claim_snapshot(
    input: &FindingClaimSnapshotInput<'_>,
) -> Result<(), FindingChallengeStoreError> {
    require_hex64(input.liability_key, "liability_key")?;
    require_hex64(input.snapshot_digest, "snapshot_digest")?;
    require_hex64(input.allocation_digest, "allocation_digest")?;
    require_currency(input.currency)?;
    if input.buyer_pool_units > input.total_realized_spend_units {
        return Err(invariant(
            "buyer pool exceeds the realized spend it is capped by",
        ));
    }
    input
        .buyer_pool_units
        .checked_add(input.community_fund_units)
        .ok_or_else(|| invariant("sealed claim distribution overflowed u64"))?;
    require_trusted_time(input.sealed_at, "sealed_at")
}

/// Whether a verdict is consistent with the terminal state a challenge
/// already reached, which is what lets an honest replay of one verdict
/// succeed while a different verdict against the same closed challenge
/// rejects.
const fn verdict_admits_state(
    verdict: FindingChallengeVerdict,
    state: FindingChallengeState,
) -> bool {
    match verdict {
        FindingChallengeVerdict::Upheld => matches!(state, FindingChallengeState::Upheld),
        FindingChallengeVerdict::Rejected => matches!(state, FindingChallengeState::Rejected),
        FindingChallengeVerdict::Indeterminate { .. } => matches!(
            state,
            FindingChallengeState::IndeterminateRetryable
                | FindingChallengeState::IndeterminateClosed
        ),
    }
}

const fn is_terminal_challenge_state(state: FindingChallengeState) -> bool {
    matches!(
        state,
        FindingChallengeState::Rejected
            | FindingChallengeState::IndeterminateClosed
            | FindingChallengeState::Upheld
    )
}

const fn is_terminal_liability_state(state: FindingLiabilityState) -> bool {
    matches!(
        state,
        FindingLiabilityState::Settled | FindingLiabilityState::ReversedBeforeImpairment
    )
}

const fn disposed_lock_state(
    disposition: FindingDisputeLockDisposition,
) -> FindingDisputeLockState {
    match disposition {
        FindingDisputeLockDisposition::Returned => FindingDisputeLockState::Returned,
        FindingDisputeLockDisposition::Forfeited => FindingDisputeLockState::Forfeited,
    }
}

/// The effect-intent lifecycle, mirroring the schema trigger so an
/// illegal edge is a typed conflict rather than a constraint abort.
const fn effect_intent_edge_is_legal(
    from: FindingEffectIntentState,
    to: FindingEffectIntentState,
) -> bool {
    matches!(
        (from, to),
        (
            FindingEffectIntentState::Pending,
            FindingEffectIntentState::Dispatched
                | FindingEffectIntentState::Failed
                | FindingEffectIntentState::Quarantined
        ) | (
            FindingEffectIntentState::Dispatched,
            FindingEffectIntentState::Confirmed
                | FindingEffectIntentState::Failed
                | FindingEffectIntentState::Quarantined
        ) | (
            FindingEffectIntentState::Failed,
            FindingEffectIntentState::Dispatched | FindingEffectIntentState::Quarantined
        )
    )
}

const fn challenge_state_name(state: FindingChallengeState) -> &'static str {
    match state {
        FindingChallengeState::Submitted => "submitted",
        FindingChallengeState::Evaluating => "evaluating",
        FindingChallengeState::Rejected => "rejected",
        FindingChallengeState::IndeterminateRetryable => "indeterminate_retryable",
        FindingChallengeState::IndeterminateClosed => "indeterminate_closed",
        FindingChallengeState::Upheld => "upheld",
    }
}

fn challenge_state_from_name(
    name: &str,
) -> Result<FindingChallengeState, FindingChallengeStoreError> {
    match name {
        "submitted" => Ok(FindingChallengeState::Submitted),
        "evaluating" => Ok(FindingChallengeState::Evaluating),
        "rejected" => Ok(FindingChallengeState::Rejected),
        "indeterminate_retryable" => Ok(FindingChallengeState::IndeterminateRetryable),
        "indeterminate_closed" => Ok(FindingChallengeState::IndeterminateClosed),
        "upheld" => Ok(FindingChallengeState::Upheld),
        other => Err(invariant(format!("unknown challenge state {other}"))),
    }
}

const fn authorization_branch_name(branch: FindingChallengeAuthorizationBranch) -> &'static str {
    match branch {
        FindingChallengeAuthorizationBranch::BuyerSubmission => "buyer_submission",
        FindingChallengeAuthorizationBranch::VenueAudit => "venue_audit",
    }
}

fn authorization_branch_from_name(
    name: &str,
) -> Result<FindingChallengeAuthorizationBranch, FindingChallengeStoreError> {
    match name {
        "buyer_submission" => Ok(FindingChallengeAuthorizationBranch::BuyerSubmission),
        "venue_audit" => Ok(FindingChallengeAuthorizationBranch::VenueAudit),
        other => Err(invariant(format!("unknown authorization branch {other}"))),
    }
}

const fn evidence_class_name(class: FindingChallengeEvidenceClass) -> &'static str {
    match class {
        FindingChallengeEvidenceClass::DigestMismatch => "digest_mismatch",
        FindingChallengeEvidenceClass::EvidenceInvalid => "evidence_invalid",
        FindingChallengeEvidenceClass::ReplayContradiction => "replay_contradiction",
    }
}

fn evidence_class_from_name(
    name: &str,
) -> Result<FindingChallengeEvidenceClass, FindingChallengeStoreError> {
    match name {
        "digest_mismatch" => Ok(FindingChallengeEvidenceClass::DigestMismatch),
        "evidence_invalid" => Ok(FindingChallengeEvidenceClass::EvidenceInvalid),
        "replay_contradiction" => Ok(FindingChallengeEvidenceClass::ReplayContradiction),
        other => Err(invariant(format!("unknown evidence class {other}"))),
    }
}

const fn dispute_lock_state_name(state: FindingDisputeLockState) -> &'static str {
    match state {
        FindingDisputeLockState::Locked => "locked",
        FindingDisputeLockState::Returned => "returned",
        FindingDisputeLockState::Forfeited => "forfeited",
    }
}

fn dispute_lock_state_from_name(
    name: &str,
) -> Result<FindingDisputeLockState, FindingChallengeStoreError> {
    match name {
        "locked" => Ok(FindingDisputeLockState::Locked),
        "returned" => Ok(FindingDisputeLockState::Returned),
        "forfeited" => Ok(FindingDisputeLockState::Forfeited),
        other => Err(invariant(format!("unknown dispute lock state {other}"))),
    }
}

const fn liability_state_name(state: FindingLiabilityState) -> &'static str {
    match state {
        FindingLiabilityState::Open => "open",
        FindingLiabilityState::UpheldPendingClaims => "upheld_pending_claims",
        FindingLiabilityState::PendingAppeal => "pending_appeal",
        FindingLiabilityState::Finalizing => "finalizing",
        FindingLiabilityState::Settled => "settled",
        FindingLiabilityState::ReversedBeforeImpairment => "reversed_before_impairment",
    }
}

fn liability_state_from_name(
    name: &str,
) -> Result<FindingLiabilityState, FindingChallengeStoreError> {
    match name {
        "open" => Ok(FindingLiabilityState::Open),
        "upheld_pending_claims" => Ok(FindingLiabilityState::UpheldPendingClaims),
        "pending_appeal" => Ok(FindingLiabilityState::PendingAppeal),
        "finalizing" => Ok(FindingLiabilityState::Finalizing),
        "settled" => Ok(FindingLiabilityState::Settled),
        "reversed_before_impairment" => Ok(FindingLiabilityState::ReversedBeforeImpairment),
        other => Err(invariant(format!("unknown liability state {other}"))),
    }
}

const fn case_kind_name(kind: FindingGovernanceCaseKind) -> &'static str {
    match kind {
        FindingGovernanceCaseKind::Sanction => "sanction",
        FindingGovernanceCaseKind::Appeal => "appeal",
    }
}

fn case_kind_from_name(
    name: &str,
) -> Result<FindingGovernanceCaseKind, FindingChallengeStoreError> {
    match name {
        "sanction" => Ok(FindingGovernanceCaseKind::Sanction),
        "appeal" => Ok(FindingGovernanceCaseKind::Appeal),
        other => Err(invariant(format!("unknown governance case kind {other}"))),
    }
}

const fn effect_intent_kind_name(kind: FindingEffectIntentKind) -> &'static str {
    match kind {
        FindingEffectIntentKind::SellerImpair => "seller_impair",
        FindingEffectIntentKind::ChallengeBond => "challenge_bond",
        FindingEffectIntentKind::Fee => "fee",
        FindingEffectIntentKind::RootIntent => "root_intent",
        FindingEffectIntentKind::Retraction => "retraction",
    }
}

fn effect_intent_kind_from_name(
    name: &str,
) -> Result<FindingEffectIntentKind, FindingChallengeStoreError> {
    match name {
        "seller_impair" => Ok(FindingEffectIntentKind::SellerImpair),
        "challenge_bond" => Ok(FindingEffectIntentKind::ChallengeBond),
        "fee" => Ok(FindingEffectIntentKind::Fee),
        "root_intent" => Ok(FindingEffectIntentKind::RootIntent),
        "retraction" => Ok(FindingEffectIntentKind::Retraction),
        other => Err(invariant(format!("unknown effect intent kind {other}"))),
    }
}

const fn effect_intent_state_name(state: FindingEffectIntentState) -> &'static str {
    match state {
        FindingEffectIntentState::Pending => "pending",
        FindingEffectIntentState::Dispatched => "dispatched",
        FindingEffectIntentState::Confirmed => "confirmed",
        FindingEffectIntentState::Failed => "failed",
        FindingEffectIntentState::Quarantined => "quarantined",
    }
}

fn effect_intent_state_from_name(
    name: &str,
) -> Result<FindingEffectIntentState, FindingChallengeStoreError> {
    match name {
        "pending" => Ok(FindingEffectIntentState::Pending),
        "dispatched" => Ok(FindingEffectIntentState::Dispatched),
        "confirmed" => Ok(FindingEffectIntentState::Confirmed),
        "failed" => Ok(FindingEffectIntentState::Failed),
        "quarantined" => Ok(FindingEffectIntentState::Quarantined),
        other => Err(invariant(format!("unknown effect intent state {other}"))),
    }
}
