use super::*;

/// Exact active-admission identity a fresh participation renewal must
/// still observe when it opens its durable fee intent.
#[derive(Debug, Clone, Copy)]
pub struct FindingParticipationAdmissionFence<'a> {
    pub admission_id: &'a str,
    pub admission_envelope_sha256: &'a str,
}

pub(super) fn paid_through_epoch_tx(
    transaction: &Transaction<'_>,
    finding_id: &str,
    listing_id: &str,
    fee_schedule_envelope_sha256: &str,
) -> Result<Option<u64>, FindingMarketStoreError> {
    let mut statement = transaction
        .prepare(
            r#"
            SELECT DISTINCT epoch_index FROM fee_events
            WHERE finding_id = ?1 AND listing_id = ?2
              AND fee_schedule_envelope_sha256 = ?3
              AND event_kind = 'participation_epoch' AND state = 'reconciled'
            ORDER BY epoch_index ASC
            "#,
        )
        .map_err(sqlite_error)?;
    let epochs = statement
        .query_map(
            params![finding_id, listing_id, fee_schedule_envelope_sha256],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    let mut paid_through: Option<u64> = None;
    let mut expected: u64 = 0;
    for epoch in epochs {
        if stored_u64(epoch, "epoch_index")? != expected {
            break;
        }
        paid_through = Some(expected);
        expected = expected
            .checked_add(1)
            .ok_or_else(|| invariant("participation epoch index overflowed"))?;
    }
    Ok(paid_through)
}

pub(super) fn require_current_participation_admission_tx(
    transaction: &Transaction<'_>,
    intent: &FindingFeeIntent<'_>,
    admission_fence: &FindingParticipationAdmissionFence<'_>,
    trusted_now: u64,
) -> Result<(), FindingMarketStoreError> {
    require_hex64(admission_fence.admission_id, "admission_id")?;
    require_hex64(
        admission_fence.admission_envelope_sha256,
        "admission_envelope_sha256",
    )?;
    let row = transaction
        .query_row(
            r#"
            SELECT admission_id, listing_id, admission_envelope_sha256,
                   admission_envelope_json, expires_at
            FROM admissions
            WHERE finding_id = ?1 AND state = 'active'
            "#,
            [intent.finding_id],
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
        .map_err(sqlite_error)?;
    let Some((admission_id, listing_id, envelope_sha256, envelope_json, expires_at)) = row else {
        return Err(FindingMarketStoreError::Conflict(
            "participation renewal has no current admission".to_owned(),
        ));
    };
    if admission_id != admission_fence.admission_id
        || envelope_sha256 != admission_fence.admission_envelope_sha256
    {
        return Err(FindingMarketStoreError::Conflict(
            "current admission changed before participation renewal".to_owned(),
        ));
    }
    verify_stored_digest(
        envelope_json.as_bytes(),
        &envelope_sha256,
        "admission envelope",
    )?;
    let admission: SignedFindingAdmission = serde_json::from_str(&envelope_json)
        .map_err(|error| invariant(format!("stored admission envelope decode failed: {error}")))?;
    admission
        .body
        .validate()
        .map_err(|error| invariant(format!("stored admission rejected: {error}")))?;
    if admission.body.admission_id != admission_id
        || admission.body.finding_id != intent.finding_id
        || admission.body.listing_id != listing_id
        || admission.body.listing_id != intent.listing_id
        || admission.body.fee_schedule_envelope_sha256 != intent.fee_schedule_envelope_sha256
        || admission.body.publisher_operator_id != intent.payer
    {
        return Err(FindingMarketStoreError::Conflict(
            "participation intent does not match the current admission".to_owned(),
        ));
    }
    if trusted_now >= stored_u64(expires_at, "expires_at")?
        || trusted_now >= admission.body.expires_at
    {
        return Err(FindingMarketStoreError::Conflict(
            "current admission expired before participation renewal".to_owned(),
        ));
    }
    let FindingFeeEvent::ParticipationEpoch { epoch_index } = intent.event else {
        return Err(invariant(
            "live participation fencing requires a participation epoch event",
        ));
    };
    let paid_through = paid_through_epoch_tx(
        transaction,
        intent.finding_id,
        intent.listing_id,
        intent.fee_schedule_envelope_sha256,
    )?
    .ok_or_else(|| {
        FindingMarketStoreError::Conflict(
            "participation renewal requires reconciled epoch zero".to_owned(),
        )
    })?;
    let expected_epoch = paid_through
        .checked_add(1)
        .ok_or_else(|| invariant("participation epoch index overflowed"))?;
    if *epoch_index != expected_epoch {
        return Err(FindingMarketStoreError::Conflict(
            "participation renewal does not name the next unpaid epoch".to_owned(),
        ));
    }
    Ok(())
}
