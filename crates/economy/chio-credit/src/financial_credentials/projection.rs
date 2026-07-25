use super::*;

pub(super) fn project_credit_scorecard_subject(
    report: &SignedCreditScorecardReport,
) -> Result<CreditScorecardCredentialSubjectV1, FinancialCredentialProjectionError> {
    let subject = source_subject_did(report.body.filters.agent_subject.as_deref())?;
    if !report.body.summary.overall_score.is_finite()
        || !(0.0..=1.0).contains(&report.body.summary.overall_score)
        || report.body.reputation.accepted_imported_signal_count
            > report.body.reputation.imported_signal_count
    {
        return Err(FinancialCredentialProjectionError::InvalidSource(
            "credit scorecard metrics are invalid".to_string(),
        ));
    }
    let imported_signal_count = count_i_json(report.body.reputation.imported_signal_count)?;
    let accepted_imported_signal_count =
        count_i_json(report.body.reputation.accepted_imported_signal_count)?;
    Ok(CreditScorecardCredentialSubjectV1 {
        id: subject,
        band: match report.body.summary.band {
            CreditScorecardBand::Prime => CreditScorecardRiskBandV1::Prime,
            CreditScorecardBand::Standard => CreditScorecardRiskBandV1::Standard,
            CreditScorecardBand::Guarded => CreditScorecardRiskBandV1::Guarded,
            CreditScorecardBand::Probationary => CreditScorecardRiskBandV1::Probationary,
            CreditScorecardBand::Restricted => CreditScorecardRiskBandV1::Restricted,
        },
        confidence: match report.body.summary.confidence {
            CreditScorecardConfidence::Low => CreditScorecardConfidenceV1::Low,
            CreditScorecardConfidence::Medium => CreditScorecardConfidenceV1::Medium,
            CreditScorecardConfidence::High => CreditScorecardConfidenceV1::High,
        },
        overall_score: report.body.summary.overall_score,
        probationary: report.body.summary.probationary,
        imported_signals: CreditScorecardImportedSignalContextV1 {
            imported_signal_count,
            accepted_imported_signal_count,
        },
    })
}

pub(super) fn project_exposure_history_subject(
    report: &SignedExposureLedgerReport,
) -> Result<ExposureHistoryCredentialSubjectV1, FinancialCredentialProjectionError> {
    let id = source_subject_did(report.body.filters.agent_subject.as_deref())?;
    let mut seen = BTreeSet::new();
    let mut positions = Vec::with_capacity(report.body.positions.len());
    for position in &report.body.positions {
        if !valid_currency(&position.currency) || !seen.insert(position.currency.as_str()) {
            return Err(FinancialCredentialProjectionError::InvalidSource(
                "exposure positions contain invalid or duplicate currencies".to_string(),
            ));
        }
        let amount = |units| -> Result<MonetaryAmount, FinancialCredentialProjectionError> {
            ensure_i_json(units)?;
            Ok(MonetaryAmount {
                units,
                currency: position.currency.clone(),
            })
        };
        positions.push(ExposureHistoryPositionV1 {
            governed_max: amount(position.governed_max_exposure_units)?,
            reserved: amount(position.reserved_units)?,
            settled: amount(position.settled_units)?,
            pending: amount(position.pending_units)?,
            failed: amount(position.failed_units)?,
            provisional_loss: amount(position.provisional_loss_units)?,
            recovered: amount(position.recovered_units)?,
        });
    }
    if positions.is_empty() {
        return Err(FinancialCredentialProjectionError::IncompleteSource);
    }
    Ok(ExposureHistoryCredentialSubjectV1 { id, positions })
}

pub(super) fn project_premium_history_subject(
    decisions: &[SignedUnderwritingDecision],
) -> Result<PremiumHistoryCredentialSubjectV1, FinancialCredentialProjectionError> {
    let ordered = ordered_underwriting_decisions(decisions)?;
    let mut subject = None;
    let mut quoted_count = 0_u64;
    let mut totals = BTreeMap::<String, u64>::new();
    for decision in ordered {
        let current = source_subject_did(
            decision
                .body
                .evaluation
                .input
                .filters
                .agent_subject
                .as_deref(),
        )?;
        bind_subject(&mut subject, current)?;
        match (
            &decision.body.premium.state,
            &decision.body.premium.quoted_amount,
        ) {
            (UnderwritingPremiumState::Quoted, Some(amount)) => {
                validate_money(amount)?;
                if amount.units == 0 {
                    return Err(FinancialCredentialProjectionError::InvalidSource(
                        "quoted premium amount is invalid".to_string(),
                    ));
                }
                quoted_count = checked_i_json_add(quoted_count, 1)?;
                let total = totals.entry(amount.currency.clone()).or_default();
                *total = checked_i_json_add(*total, amount.units)?;
            }
            (UnderwritingPremiumState::Quoted, None) => {
                return Err(FinancialCredentialProjectionError::InvalidSource(
                    "quoted premium is missing its amount".to_string(),
                ));
            }
            (_, Some(_)) => {
                return Err(FinancialCredentialProjectionError::InvalidSource(
                    "non-quoted premium carries an amount".to_string(),
                ));
            }
            (_, None) => {}
        }
    }
    if quoted_count == 0 {
        return Err(FinancialCredentialProjectionError::IncompleteSource);
    }
    Ok(PremiumHistoryCredentialSubjectV1 {
        id: subject.ok_or(FinancialCredentialProjectionError::InvalidSourceSubject)?,
        quoted_count,
        quoted_amounts: totals
            .into_iter()
            .map(|(currency, units)| MonetaryAmount { units, currency })
            .collect(),
    })
}

pub(super) fn project_loss_history_subject(
    events: &[&SignedCreditLossLifecycle],
) -> Result<LossHistoryCredentialSubjectV1, FinancialCredentialProjectionError> {
    let mut subject = None;
    let mut latest_by_bond = BTreeMap::new();
    let mut counts = [0_u64; 5];
    for event in events {
        let current = source_subject_did(event.body.report.summary.agent_subject.as_deref())?;
        bind_subject(&mut subject, current)?;
        let index = match event.body.event_kind {
            CreditLossLifecycleEventKind::Delinquency => 0,
            CreditLossLifecycleEventKind::Recovery => 1,
            CreditLossLifecycleEventKind::ReserveRelease => 2,
            CreditLossLifecycleEventKind::ReserveSlash => 3,
            CreditLossLifecycleEventKind::WriteOff => 4,
        };
        counts[index] = checked_i_json_add(counts[index], 1)?;
        latest_by_bond.insert(
            event.body.bond_id.clone(),
            event
                .body
                .report
                .summary
                .outstanding_delinquent_amount
                .clone(),
        );
    }
    let mut totals = BTreeMap::<String, u64>::new();
    for amount in latest_by_bond.into_values().flatten() {
        validate_money(&amount)?;
        let total = totals.entry(amount.currency).or_default();
        *total = checked_i_json_add(*total, amount.units)?;
    }
    Ok(LossHistoryCredentialSubjectV1 {
        id: subject.ok_or(FinancialCredentialProjectionError::InvalidSourceSubject)?,
        delinquency_count: counts[0],
        recovery_count: counts[1],
        reserve_release_count: counts[2],
        reserve_slash_count: counts[3],
        write_off_count: counts[4],
        outstanding_amounts: totals
            .into_iter()
            .map(|(currency, units)| MonetaryAmount { units, currency })
            .collect(),
    })
}

pub(super) fn ordered_underwriting_decisions(
    decisions: &[SignedUnderwritingDecision],
) -> Result<Vec<&SignedUnderwritingDecision>, FinancialCredentialProjectionError> {
    if decisions.is_empty() || decisions.len() > MAX_SOURCE_ARTIFACTS {
        return Err(FinancialCredentialProjectionError::IncompleteSource);
    }
    let mut ordered = decisions.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        (left.body.issued_at, left.body.decision_id.as_str())
            .cmp(&(right.body.issued_at, right.body.decision_id.as_str()))
    });
    let mut ids = BTreeSet::new();
    let signer = &ordered[0].signer_key;
    for decision in &ordered {
        inspect_source_signature(decision.verify_signature())?;
        if decision.body.schema != crate::underwriting::UNDERWRITING_DECISION_ARTIFACT_SCHEMA
            || !ids.insert(decision.body.decision_id.as_str())
            || &decision.signer_key != signer
        {
            return Err(FinancialCredentialProjectionError::InvalidSourceSchema);
        }
        ensure_i_json(decision.body.issued_at)?;
    }
    Ok(ordered)
}

pub(super) fn ordered_loss_events(
    events: &[SignedCreditLossLifecycle],
) -> Result<Vec<&SignedCreditLossLifecycle>, FinancialCredentialProjectionError> {
    if events.is_empty() || events.len() > MAX_SOURCE_ARTIFACTS {
        return Err(FinancialCredentialProjectionError::IncompleteSource);
    }
    let mut ordered = events.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        (
            left.body.issued_at,
            left.body.bond_id.as_str(),
            left.body.event_id.as_str(),
        )
            .cmp(&(
                right.body.issued_at,
                right.body.bond_id.as_str(),
                right.body.event_id.as_str(),
            ))
    });
    let signer = &ordered[0].signer_key;
    let mut ids = BTreeSet::new();
    let mut bond_times = BTreeSet::new();
    for event in &ordered {
        inspect_source_signature(event.verify_signature())?;
        ensure_i_json(event.body.issued_at)?;
        ensure_i_json(event.body.report.generated_at)?;
        if event.body.schema != CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA
            || event.body.report.schema != CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA
            || !ids.insert(event.body.event_id.as_str())
            || !bond_times.insert((event.body.bond_id.as_str(), event.body.issued_at))
            || &event.signer_key != signer
            || event.body.bond_id != event.body.report.query.bond_id
            || event.body.bond_id != event.body.report.summary.bond_id
            || event.body.event_kind != event.body.report.query.event_kind
            || event.body.projected_bond_lifecycle_state
                != event.body.report.summary.projected_bond_lifecycle_state
            || event.body.report.generated_at > event.body.issued_at
        {
            return Err(FinancialCredentialProjectionError::InvalidSource(
                "loss lifecycle artifact is inconsistent with its report".to_string(),
            ));
        }
    }
    Ok(ordered)
}

pub(super) fn validate_loss_lifecycle_continuity(
    events: &[&SignedCreditLossLifecycle],
) -> Result<(), FinancialCredentialProjectionError> {
    let mut projected_by_bond = BTreeMap::<&str, CreditBondLifecycleState>::new();
    for event in events {
        if let Some(previous) = projected_by_bond.get(event.body.bond_id.as_str()) {
            if *previous != event.body.report.summary.current_bond_lifecycle_state {
                return Err(FinancialCredentialProjectionError::InvalidSource(
                    "loss lifecycle range is not state-contiguous".to_string(),
                ));
            }
        }
        projected_by_bond.insert(
            event.body.bond_id.as_str(),
            event.body.projected_bond_lifecycle_state,
        );
    }
    Ok(())
}

pub(super) fn complete_report_window(
    starts_at: Option<u64>,
    ends_at: Option<u64>,
    generated_at: u64,
) -> Result<FinancialCredentialWindowV1, FinancialCredentialProjectionError> {
    let starts_at = starts_at.ok_or(FinancialCredentialProjectionError::IncompleteSource)?;
    let ends_at = ends_at.ok_or(FinancialCredentialProjectionError::IncompleteSource)?;
    ensure_i_json(starts_at)?;
    ensure_i_json(ends_at)?;
    ensure_i_json(generated_at)?;
    if starts_at >= ends_at || ends_at != generated_at {
        return Err(FinancialCredentialProjectionError::IncompleteSource);
    }
    Ok(FinancialCredentialWindowV1 { starts_at, ends_at })
}

pub(super) fn ensure_complete_counts(
    matching: u64,
    returned: u64,
) -> Result<(), FinancialCredentialProjectionError> {
    ensure_i_json(matching)?;
    ensure_i_json(returned)?;
    if matching != returned {
        return Err(FinancialCredentialProjectionError::IncompleteSource);
    }
    Ok(())
}

pub(super) fn inspect_source_signature(
    result: Result<bool, chio_core_types::Error>,
) -> Result<(), FinancialCredentialProjectionError> {
    match result {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(FinancialCredentialProjectionError::InvalidSourceSignature),
    }
}
