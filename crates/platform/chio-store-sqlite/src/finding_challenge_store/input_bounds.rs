// Input bounds, required-field checks, and error mapping.

/// Apply the appeal-final transition and retain its exact authorization in a
/// caller-owned transaction. The status store uses this boundary so the
/// signed authorization, sticky retraction outbox, and liability edge cannot
/// be committed independently.
pub(crate) fn begin_finalizing_under_sanction_tx(
    transaction: &Transaction<'_>,
    liability_key: &str,
    expected_state: FindingLiabilityState,
    sanction_case_id: &str,
    authorization: &FindingFinalizingAuthorizationInput<'_>,
    now: u64,
) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
    require_hex64(liability_key, "liability_key")?;
    require_identifier(sanction_case_id, "sanction_case_id")?;
    require_finalizing_authorization(authorization)?;
    if authorization.liability_key != liability_key || authorization.recorded_at != now {
        return Err(invariant(
            "finalizing authorization does not bind the transition",
        ));
    }
    require_trusted_time(now, "now")?;
    require_transition_source(
        expected_state,
        FindingLiabilityState::PendingAppeal,
        FindingLiabilityState::Finalizing,
    )?;
    let head = resolve_case_head_tx(transaction, liability_key)?.ok_or_else(|| {
        FindingChallengeStoreError::Conflict("liability carries no live governance case".to_owned())
    })?;
    if head.case_kind != FindingGovernanceCaseKind::Sanction || head.case_id != sanction_case_id {
        return Err(FindingChallengeStoreError::Conflict(
            "the named sanction is not the live governance case".to_owned(),
        ));
    }
    let retained = transaction
        .query_row(
            r#"
            SELECT authorization_json, authorization_sha256, recorded_at
            FROM finding_finalizing_authorizations
            WHERE liability_key = ?1
            "#,
            [liability_key],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    if let Some((bytes, digest, recorded_at)) = &retained {
        if bytes != authorization.authorization_json
            || digest != authorization.authorization_sha256
            || stored_u64(*recorded_at, "finalizing authorization recorded_at")?
                != authorization.recorded_at
        {
            return Err(FindingChallengeStoreError::Conflict(
                "finalizing authorization is already bound to different bytes".to_owned(),
            ));
        }
    }
    let (outcome, _) = apply_liability_transition_tx(
        transaction,
        liability_key,
        FindingLiabilityState::PendingAppeal,
        FindingLiabilityState::Finalizing,
        Some(true),
        now,
    )?;
    if outcome == FindingChallengeWriteOutcome::ExistingSame && retained.is_none() {
        return Err(invariant(
            "finalizing liability has no retained authorization",
        ));
    }
    if outcome == FindingChallengeWriteOutcome::ExistingSame {
        return Ok(outcome);
    }
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO finding_finalizing_authorizations (
                liability_key, authorization_json,
                authorization_sha256, recorded_at
            ) VALUES (?1, ?2, ?3, ?4)
            "#,
            params![
                liability_key,
                authorization.authorization_json,
                authorization.authorization_sha256,
                sqlite_i64(authorization.recorded_at, "recorded_at")?,
            ],
        )
        .map_err(sqlite_error)?;
    if inserted != 1 {
        return Err(invariant(
            "finalizing authorization insert did not affect one row",
        ));
    }
    Ok(outcome)
}

fn list_limit() -> Result<i64, FindingChallengeStoreError> {
    sqlite_i64(u64::try_from(MAX_LIST_ROWS).unwrap_or(u64::MAX), "limit")
}

fn require_hex64(value: &str, field: &'static str) -> Result<(), FindingChallengeStoreError> {
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

fn require_outcome_envelope(
    outcome_envelope_sha256: &str,
    outcome_envelope_json: &[u8],
) -> Result<(), FindingChallengeStoreError> {
    require_hex64(outcome_envelope_sha256, "outcome_envelope_sha256")?;
    if outcome_envelope_json.is_empty() || outcome_envelope_json.len() > MAX_OUTCOME_ENVELOPE_BYTES
    {
        return Err(invariant("outcome envelope byte length is out of bounds"));
    }
    if sha256_hex(outcome_envelope_json) != outcome_envelope_sha256 {
        return Err(invariant(
            "outcome envelope bytes do not match their recorded digest",
        ));
    }
    Ok(())
}

fn require_outcome_allocation_binding(
    outcome_envelope_json: &[u8],
    allocation_id: &str,
) -> Result<(), FindingChallengeStoreError> {
    let envelope: serde_json::Value = serde_json::from_slice(outcome_envelope_json)
        .map_err(|_| invariant("outcome envelope is not typed JSON"))?;
    let retained_allocation_id = envelope
        .get("body")
        .and_then(|body| body.get("backing_allocation_id"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invariant("outcome envelope omits its backing allocation"))?;
    require_hex64(retained_allocation_id, "outcome.backing_allocation_id")?;
    if retained_allocation_id != allocation_id {
        return Err(FindingChallengeStoreError::Conflict(
            "exposure fence allocation does not match the retained outcome".to_owned(),
        ));
    }
    Ok(())
}

fn require_finalizing_authorization(
    authorization: &FindingFinalizingAuthorizationInput<'_>,
) -> Result<(), FindingChallengeStoreError> {
    require_hex64(authorization.liability_key, "liability_key")?;
    require_hex64(authorization.authorization_sha256, "authorization_sha256")?;
    require_trusted_time(authorization.recorded_at, "recorded_at")?;
    if authorization.authorization_json.is_empty()
        || authorization.authorization_json.len() > MAX_FINALIZING_AUTHORIZATION_BYTES
    {
        return Err(invariant(
            "finalizing authorization byte length is out of bounds",
        ));
    }
    if sha256_hex(authorization.authorization_json) != authorization.authorization_sha256 {
        return Err(invariant(
            "finalizing authorization bytes do not match their digest",
        ));
    }
    Ok(())
}

fn require_chain_hash(value: &str, field: &'static str) -> Result<(), FindingChallengeStoreError> {
    if value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(invariant(format!(
        "{field} is not a 0x-prefixed 32-byte lowercase hash"
    )))
}

fn require_identifier(value: &str, field: &'static str) -> Result<(), FindingChallengeStoreError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(invariant(format!("{field} byte length is out of bounds")));
    }
    Ok(())
}

fn require_currency(currency: &str) -> Result<(), FindingChallengeStoreError> {
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(invariant("currency is not a three-letter uppercase code"));
    }
    Ok(())
}

fn require_trusted_time(value: u64, field: &'static str) -> Result<(), FindingChallengeStoreError> {
    if value == 0 {
        return Err(invariant(format!("{field} must be nonzero")));
    }
    Ok(())
}

fn sqlite_i64(value: u64, field: &'static str) -> Result<i64, FindingChallengeStoreError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite integer range")))
}

fn stored_u64(value: i64, field: &'static str) -> Result<u64, FindingChallengeStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("{field} is negative")))
}

fn stored_flag(value: i64, field: &'static str) -> Result<bool, FindingChallengeStoreError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invariant(format!("{field} is not a boolean flag"))),
    }
}

fn invariant(detail: impl Into<String>) -> FindingChallengeStoreError {
    FindingChallengeStoreError::Invariant(detail.into())
}

fn admission_error(error: AdmissionOperationStoreError) -> FindingChallengeStoreError {
    match error {
        AdmissionOperationStoreError::Fenced => FindingChallengeStoreError::Fenced,
        AdmissionOperationStoreError::NotFound => FindingChallengeStoreError::NotFound,
        AdmissionOperationStoreError::Unavailable(detail) => {
            FindingChallengeStoreError::Unavailable(detail)
        }
        AdmissionOperationStoreError::OutcomeUnknown(detail) => {
            FindingChallengeStoreError::OutcomeUnknown(detail)
        }
        AdmissionOperationStoreError::Invariant(detail) => {
            FindingChallengeStoreError::Invariant(detail)
        }
        AdmissionOperationStoreError::Operation(error) => invariant(error.to_string()),
    }
}

/// Map a purchase-store failure raised inside a shared transaction. The
/// sales block is part of the upheld transaction, so its failures are the
/// challenge lane's failures.
fn purchase_error(error: FindingPurchaseStoreError) -> FindingChallengeStoreError {
    match error {
        FindingPurchaseStoreError::Fenced => FindingChallengeStoreError::Fenced,
        FindingPurchaseStoreError::NotFound => FindingChallengeStoreError::NotFound,
        FindingPurchaseStoreError::Unavailable(detail) => {
            FindingChallengeStoreError::Unavailable(detail)
        }
        FindingPurchaseStoreError::OutcomeUnknown(detail) => {
            FindingChallengeStoreError::OutcomeUnknown(detail)
        }
        FindingPurchaseStoreError::Invariant(detail) => {
            FindingChallengeStoreError::Invariant(detail)
        }
        other => FindingChallengeStoreError::Conflict(other.to_string()),
    }
}

fn sqlite_error(error: rusqlite::Error) -> FindingChallengeStoreError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::Utf8Error(..) => invariant(error.to_string()),
        other => FindingChallengeStoreError::Unavailable(other.to_string()),
    }
}
