use super::*;

pub(crate) fn insert_payment_journal(
    transaction: &rusqlite::Transaction<'_>,
    record: &PaymentJournalRecord,
) -> Result<(), BudgetStoreError> {
    record
        .validate()
        .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
    if record.state != PaymentJournalState::HoldPlaced {
        return Err(BudgetStoreError::Invariant(
            "a new payment journal must start in hold_placed".to_owned(),
        ));
    }
    let hold_id = record.hold_id.as_deref().ok_or_else(|| {
        BudgetStoreError::Invariant("payment journal omitted its budget hold".to_owned())
    })?;
    transaction.execute(
        r#"
        INSERT INTO payment_journal (
            operation_id, journal_version, request_namespace_digest, request_id, capability_id,
            grant_index, hold_id, rail, rail_mode, authorization_id,
            transaction_id, amount_units, settle_action, settle_amount_units,
            release_authority_kind, release_authority_evidence_id,
            release_authority_evidence_digest, release_authority_operation_version,
            currency, state, created_at_unix_ms, updated_at_unix_ms
        ) VALUES (
            ?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, ?9,
            NULL, NULL, NULL, NULL, NULL, NULL, ?10, ?11, ?12, ?12
        )
        "#,
        params![
            &record.operation_id,
            &record.request_namespace_digest,
            &record.request_id,
            &record.capability_id,
            i64::from(record.grant_index),
            hold_id,
            &record.rail,
            payment_rail_mode_text(record.rail_mode),
            budget_u64_to_sqlite(record.amount_units, "payment amount_units")?,
            &record.currency,
            payment_journal_state_text(record.state),
            budget_u64_to_sqlite(record.created_at_unix_ms, "payment created_at_unix_ms")?,
        ],
    )?;
    Ok(())
}

pub(crate) fn load_payment_journal(
    transaction: &rusqlite::Transaction<'_>,
    operation_id: &str,
) -> Result<Option<PaymentJournalRecord>, BudgetStoreError> {
    transaction
        .query_row(
            r#"
            SELECT operation_id, request_namespace_digest, request_id, capability_id,
                   grant_index, hold_id, rail, rail_mode, authorization_id,
                   transaction_id, amount_units, settle_action, settle_amount_units,
                   release_authority_kind, release_authority_evidence_id,
                   release_authority_evidence_digest, release_authority_operation_version,
                   currency, state, created_at_unix_ms, journal_version
            FROM payment_journal
            WHERE operation_id = ?1
            "#,
            params![operation_id],
            payment_journal_from_row,
        )
        .optional()
        .map_err(Into::into)
}

pub(crate) fn advance_payment_journal(
    transaction: &rusqlite::Transaction<'_>,
    expected: &PaymentJournalRecord,
    transition: &PaymentJournalTransition,
    release_evidence: Option<&MonetaryReleaseEvidenceV1>,
    trusted_now_unix_ms: u64,
) -> Result<(PaymentJournalRecord, bool), BudgetStoreError> {
    expected
        .validate()
        .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
    let desired = expected
        .apply_transition(transition)
        .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
    let stored = load_payment_journal(transaction, &expected.operation_id)?
        .ok_or_else(|| BudgetStoreError::Invariant("payment journal is absent".to_owned()))?;
    if stored == desired {
        verify_release_evidence(
            transaction,
            transition,
            release_evidence,
            trusted_now_unix_ms,
            false,
        )?;
        return Ok((stored, false));
    }
    if stored != *expected {
        return Err(BudgetStoreError::Invariant(
            "payment journal compare-and-set conflicted".to_owned(),
        ));
    }
    verify_release_evidence(
        transaction,
        transition,
        release_evidence,
        trusted_now_unix_ms,
        true,
    )?;
    let release = desired.release_authority.as_ref();
    let changed = transaction.execute(
        r#"
        UPDATE payment_journal
        SET journal_version = ?1, authorization_id = ?2, transaction_id = ?3,
            settle_action = ?4, settle_amount_units = ?5,
            release_authority_kind = ?6, release_authority_evidence_id = ?7,
            release_authority_evidence_digest = ?8,
            release_authority_operation_version = ?9,
            state = ?10, updated_at_unix_ms = ?11
        WHERE operation_id = ?12 AND journal_version = ?13 AND state = ?14
        "#,
        params![
            budget_u64_to_sqlite(desired.journal_version, "payment journal_version")?,
            desired.authorization_id.as_deref(),
            desired.transaction_id.as_deref(),
            desired.settle_action.map(payment_settle_action_text),
            desired
                .settle_amount_units
                .map(|value| budget_u64_to_sqlite(value, "payment settle_amount_units"))
                .transpose()?,
            release.map(|binding| payment_release_authority_kind_text(binding.kind)),
            release.map(|binding| binding.evidence_id.as_str()),
            release.map(|binding| binding.evidence_digest.as_str()),
            release
                .map(|binding| {
                    budget_u64_to_sqlite(
                        binding.operation_version,
                        "release authority operation_version",
                    )
                })
                .transpose()?,
            payment_journal_state_text(desired.state),
            budget_u64_to_sqlite(trusted_now_unix_ms, "payment updated_at_unix_ms")?,
            &expected.operation_id,
            budget_u64_to_sqlite(expected.journal_version, "expected journal_version")?,
            payment_journal_state_text(expected.state),
        ],
    )?;
    if changed != 1 {
        return Err(BudgetStoreError::Invariant(
            "payment journal compare-and-set did not advance exactly once".to_owned(),
        ));
    }
    let updated = load_payment_journal(transaction, &expected.operation_id)?.ok_or_else(|| {
        BudgetStoreError::Invariant("advanced payment journal is absent".to_owned())
    })?;
    if updated != desired {
        return Err(BudgetStoreError::Invariant(
            "advanced payment journal does not match its transition".to_owned(),
        ));
    }
    Ok((updated, true))
}

fn verify_release_evidence(
    transaction: &rusqlite::Transaction<'_>,
    transition: &PaymentJournalTransition,
    evidence: Option<&MonetaryReleaseEvidenceV1>,
    trusted_now_unix_ms: u64,
    insert_allowed: bool,
) -> Result<(), BudgetStoreError> {
    let PaymentJournalTransition::BeginRelease { authority } = transition else {
        if evidence.is_some() {
            return Err(BudgetStoreError::Invariant(
                "release evidence was supplied for a non-release transition".to_owned(),
            ));
        }
        return Ok(());
    };
    let evidence = evidence.ok_or_else(|| {
        BudgetStoreError::Invariant(
            "release transition omitted its canonical evidence bundle".to_owned(),
        )
    })?;
    let canonical = evidence
        .canonical_bytes()
        .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
    let persisted = evidence.to_persisted();
    let expected_kind = match persisted.evidence_kind {
        MonetaryReleaseEvidenceKindV1::BeforeDispatchNoEffect => {
            PaymentReleaseAuthorityKind::PreDispatchNoEffect
        }
        MonetaryReleaseEvidenceKindV1::NotAcceptedAfterDispatch => {
            PaymentReleaseAuthorityKind::TransportNotAccepted
        }
        MonetaryReleaseEvidenceKindV1::ContractualZeroCharge => {
            PaymentReleaseAuthorityKind::ContractualZeroCharge
        }
    };
    if authority.kind != expected_kind
        || authority.operation_id != persisted.operation_id.as_str()
        || authority.operation_version != persisted.operation_version
        || authority.evidence_id != persisted.evidence_id.as_str()
        || authority.evidence_digest != persisted.bundle_digest.as_str()
    {
        return Err(BudgetStoreError::Invariant(
            "release authority does not match its canonical evidence bundle".to_owned(),
        ));
    }
    if insert_allowed {
        transaction.execute(
            r#"
            INSERT INTO payment_release_evidence (
                operation_id, evidence_id, evidence_kind, operation_version,
                canonical_bundle, bundle_digest, created_at_unix_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(operation_id) DO NOTHING
            "#,
            params![
                &authority.operation_id,
                &authority.evidence_id,
                payment_release_authority_kind_text(authority.kind),
                budget_u64_to_sqlite(
                    authority.operation_version,
                    "release authority operation_version"
                )?,
                &canonical,
                &authority.evidence_digest,
                budget_u64_to_sqlite(trusted_now_unix_ms, "release evidence created_at_unix_ms")?,
            ],
        )?;
    }
    let stored = transaction
        .query_row(
            r#"
            SELECT evidence_id, evidence_kind, operation_version,
                   canonical_bundle, bundle_digest
            FROM payment_release_evidence
            WHERE operation_id = ?1
            "#,
            [&authority.operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    let expected_version = budget_u64_to_sqlite(
        authority.operation_version,
        "release authority operation_version",
    )?;
    if stored.as_ref()
        != Some(&(
            authority.evidence_id.clone(),
            payment_release_authority_kind_text(authority.kind).to_owned(),
            expected_version,
            canonical,
            authority.evidence_digest.clone(),
        ))
    {
        return Err(BudgetStoreError::Invariant(
            "stored payment release evidence conflicts with its authority".to_owned(),
        ));
    }
    Ok(())
}

fn payment_journal_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<PaymentJournalRecord, rusqlite::Error> {
    let release_kind = row
        .get::<_, Option<String>>(13)?
        .map(|value| payment_release_authority_kind(&value))
        .transpose()?;
    let release_evidence_id = row.get::<_, Option<String>>(14)?;
    let release_evidence_digest = row.get::<_, Option<String>>(15)?;
    let release_operation_version = row
        .get::<_, Option<i64>>(16)?
        .map(|value| payment_u64_from_i64(value, "release operation_version"))
        .transpose()?;
    let release_authority = match (
        release_kind,
        release_evidence_id,
        release_evidence_digest,
        release_operation_version,
    ) {
        (Some(kind), Some(evidence_id), Some(evidence_digest), Some(operation_version)) => {
            Some(PaymentReleaseAuthorityBinding {
                kind,
                operation_id: row.get(0)?,
                operation_version,
                evidence_id,
                evidence_digest,
            })
        }
        (None, None, None, None) => None,
        _ => {
            return Err(invalid_payment_column(
                "incomplete release authority binding",
            ))
        }
    };
    let grant_index =
        u32::try_from(row.get::<_, i64>(4)?).map_err(|_| invalid_payment_column("grant_index"))?;
    let record = PaymentJournalRecord {
        operation_id: row.get(0)?,
        journal_version: payment_u64_from_i64(row.get(20)?, "journal_version")?,
        request_namespace_digest: row.get(1)?,
        request_id: row.get(2)?,
        capability_id: row.get(3)?,
        grant_index,
        hold_id: Some(row.get(5)?),
        rail: row.get(6)?,
        rail_mode: payment_rail_mode(&row.get::<_, String>(7)?)?,
        authorization_id: row.get(8)?,
        transaction_id: row.get(9)?,
        amount_units: payment_u64_from_i64(row.get(10)?, "amount_units")?,
        settle_action: row
            .get::<_, Option<String>>(11)?
            .map(|value| payment_settle_action(&value))
            .transpose()?,
        settle_amount_units: row
            .get::<_, Option<i64>>(12)?
            .map(|value| payment_u64_from_i64(value, "settle_amount_units"))
            .transpose()?,
        release_authority,
        currency: row.get(17)?,
        state: payment_journal_state(&row.get::<_, String>(18)?)?,
        created_at_unix_ms: payment_u64_from_i64(row.get(19)?, "created_at_unix_ms")?,
    };
    record
        .validate()
        .map_err(|_| invalid_payment_column("invalid payment journal record"))?;
    Ok(record)
}

pub(super) const fn payment_journal_state_text(state: PaymentJournalState) -> &'static str {
    match state {
        PaymentJournalState::HoldPlaced => "hold_placed",
        PaymentJournalState::Authorized => "authorized",
        PaymentJournalState::Settling => "settling",
        PaymentJournalState::Settled => "settled",
        PaymentJournalState::Closed => "closed",
        PaymentJournalState::ReconcileFailed => "reconcile_failed",
    }
}

fn payment_journal_state(value: &str) -> Result<PaymentJournalState, rusqlite::Error> {
    match value {
        "hold_placed" => Ok(PaymentJournalState::HoldPlaced),
        "authorized" => Ok(PaymentJournalState::Authorized),
        "settling" => Ok(PaymentJournalState::Settling),
        "settled" => Ok(PaymentJournalState::Settled),
        "closed" => Ok(PaymentJournalState::Closed),
        "reconcile_failed" => Ok(PaymentJournalState::ReconcileFailed),
        _ => Err(invalid_payment_column("state")),
    }
}

pub(super) const fn payment_rail_mode_text(mode: PaymentRailMode) -> &'static str {
    match mode {
        PaymentRailMode::ReversibleHold => "reversible_hold",
        PaymentRailMode::PrepaidFinal => "prepaid_final",
    }
}

fn payment_rail_mode(value: &str) -> Result<PaymentRailMode, rusqlite::Error> {
    match value {
        "reversible_hold" => Ok(PaymentRailMode::ReversibleHold),
        "prepaid_final" => Ok(PaymentRailMode::PrepaidFinal),
        _ => Err(invalid_payment_column("rail_mode")),
    }
}

pub(super) const fn payment_settle_action_text(action: PaymentSettleAction) -> &'static str {
    match action {
        PaymentSettleAction::Capture => "capture",
        PaymentSettleAction::Release => "release",
    }
}

fn payment_settle_action(value: &str) -> Result<PaymentSettleAction, rusqlite::Error> {
    match value {
        "capture" => Ok(PaymentSettleAction::Capture),
        "release" => Ok(PaymentSettleAction::Release),
        _ => Err(invalid_payment_column("settle_action")),
    }
}

pub(super) const fn payment_release_authority_kind_text(
    kind: PaymentReleaseAuthorityKind,
) -> &'static str {
    match kind {
        PaymentReleaseAuthorityKind::PreDispatchNoEffect => "pre_dispatch_no_effect",
        PaymentReleaseAuthorityKind::TransportNotAccepted => "transport_not_accepted",
        PaymentReleaseAuthorityKind::ContractualZeroCharge => "contractual_zero_charge",
    }
}

fn payment_release_authority_kind(
    value: &str,
) -> Result<PaymentReleaseAuthorityKind, rusqlite::Error> {
    match value {
        "pre_dispatch_no_effect" => Ok(PaymentReleaseAuthorityKind::PreDispatchNoEffect),
        "transport_not_accepted" => Ok(PaymentReleaseAuthorityKind::TransportNotAccepted),
        "contractual_zero_charge" => Ok(PaymentReleaseAuthorityKind::ContractualZeroCharge),
        _ => Err(invalid_payment_column("release_authority_kind")),
    }
}

fn payment_u64_from_i64(value: i64, field: &'static str) -> Result<u64, rusqlite::Error> {
    u64::try_from(value).map_err(|_| invalid_payment_column(field))
}

fn invalid_payment_column(field: &'static str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        format!("invalid payment journal {field}").into(),
    )
}
