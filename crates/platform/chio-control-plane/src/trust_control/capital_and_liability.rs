use super::reports::build_exposure_ledger_report;
use super::*;

#[path = "capital_and_liability/liability.rs"]
mod liability;
pub use liability::*;

pub(crate) fn build_capital_book_report_from_store(
    receipt_store: &SqliteReceiptStore,
    query: &CapitalBookQuery,
) -> Result<CapitalBookReport, TrustHttpError> {
    let normalized = query.normalized();
    normalized.validate().map_err(TrustHttpError::bad_request)?;
    let subject_key = normalized
        .agent_subject
        .clone()
        .ok_or_else(|| TrustHttpError::bad_request("capital book requires --agent-subject"))?;

    let exposure = build_exposure_ledger_report(receipt_store, &normalized.exposure_query())?;
    validate_capital_book_receipts(&exposure.receipts, &subject_key)?;

    let facility_report = receipt_store
        .query_credit_facilities(&normalized.facility_query())
        .map_err(trust_http_error_from_receipt_store)?;
    let current_facility_rows = facility_report
        .facilities
        .iter()
        .filter(|row| row.superseded_by_facility_id.is_none())
        .collect::<Vec<_>>();
    let active_granted_facilities = current_facility_rows
        .iter()
        .copied()
        .filter(|row| {
            row.lifecycle_state == CreditFacilityLifecycleState::Active
                && row.facility.body.report.disposition == CreditFacilityDisposition::Grant
        })
        .collect::<Vec<_>>();
    if active_granted_facilities.len() > 1 {
        return Err(TrustHttpError::new(
            StatusCode::CONFLICT,
            "capital book requires one current granted facility because Chio will not blend live source-of-funds attribution across multiple active facilities",
        ));
    }
    let current_facility_row = active_granted_facilities.into_iter().next();
    let current_facility_terms = current_facility_row.and_then(|row| {
        row.facility
            .body
            .report
            .terms
            .as_ref()
            .map(|terms| (row, terms))
    });

    let bond_report = receipt_store
        .query_credit_bonds(&normalized.bond_query())
        .map_err(trust_http_error_from_receipt_store)?;
    let current_bond_rows = bond_report
        .bonds
        .iter()
        .filter(|row| row.superseded_by_bond_id.is_none())
        .collect::<Vec<_>>();
    if current_bond_rows.len() > 1 {
        return Err(TrustHttpError::new(
            StatusCode::CONFLICT,
            "capital book requires one current bond posture because Chio will not blend multiple live reserve books into one deterministic capital source",
        ));
    }
    let current_bond_row = current_bond_rows.into_iter().next();
    let current_bond_terms = current_bond_row.and_then(|row| {
        row.bond
            .body
            .report
            .terms
            .as_ref()
            .map(|terms| (row, terms))
    });

    let loss_history = if let Some((bond_row, _)) = current_bond_terms {
        receipt_store
            .query_credit_loss_lifecycle(&CreditLossLifecycleListQuery {
                event_id: None,
                bond_id: Some(bond_row.bond.body.bond_id.clone()),
                facility_id: bond_row.bond.body.report.latest_facility_id.clone(),
                capability_id: normalized.capability_id.clone(),
                agent_subject: normalized.agent_subject.clone(),
                tool_server: normalized.tool_server.clone(),
                tool_name: normalized.tool_name.clone(),
                event_kind: None,
                limit: normalized.loss_event_limit,
            })
            .map_err(trust_http_error_from_receipt_store)?
    } else {
        CreditLossLifecycleListReport {
            schema: chio_kernel::CREDIT_LOSS_LIFECYCLE_LIST_REPORT_SCHEMA.to_string(),
            generated_at: unix_timestamp_now(),
            query: CreditLossLifecycleListQuery {
                event_id: None,
                bond_id: None,
                facility_id: None,
                capability_id: normalized.capability_id.clone(),
                agent_subject: normalized.agent_subject.clone(),
                tool_server: normalized.tool_server.clone(),
                tool_name: normalized.tool_name.clone(),
                event_kind: None,
                limit: normalized.loss_event_limit,
            },
            summary: chio_kernel::CreditLossLifecycleListSummary {
                matching_events: 0,
                returned_events: 0,
                delinquency_events: 0,
                recovery_events: 0,
                reserve_release_events: 0,
                reserve_slash_events: 0,
                write_off_events: 0,
            },
            events: Vec::new(),
        }
    };

    let mut currencies = BTreeSet::new();
    for position in &exposure.positions {
        currencies.insert(position.currency.clone());
    }
    if let Some((_, terms)) = current_facility_terms {
        currencies.insert(terms.credit_limit.currency.clone());
    }
    if let Some((_, terms)) = current_bond_terms {
        currencies.insert(terms.credit_limit.currency.clone());
        currencies.insert(terms.collateral_amount.currency.clone());
        currencies.insert(terms.reserve_requirement_amount.currency.clone());
        currencies.insert(terms.outstanding_exposure_amount.currency.clone());
    }
    for row in &loss_history.events {
        if let Some(amount) = row.event.body.report.summary.event_amount.as_ref() {
            currencies.insert(amount.currency.clone());
        }
    }
    if currencies.len() > 1 {
        return Err(TrustHttpError::new(
            StatusCode::CONFLICT,
            "capital book requires one coherent currency because Chio does not auto-net live capital across currencies",
        ));
    }
    let currency = currencies.into_iter().next();

    let has_monetary_activity = exposure.positions.iter().any(|position| {
        position.governed_max_exposure_units > 0
            || position.reserved_units > 0
            || position.settled_units > 0
            || position.pending_units > 0
            || position.failed_units > 0
            || position.provisional_loss_units > 0
            || position.recovered_units > 0
    });
    if has_monetary_activity && current_facility_terms.is_none() {
        return Err(TrustHttpError::new(
            StatusCode::CONFLICT,
            "capital book requires one active granted facility with terms to attribute committed and disbursed funds",
        ));
    }

    let exposure_position =
        match (&currency, exposure.positions.as_slice()) {
            (Some(_), [position]) => Some(position),
            (Some(_), []) => None,
            (Some(_), _) => return Err(TrustHttpError::new(
                StatusCode::CONFLICT,
                "capital book requires one coherent exposure position after currency resolution",
            )),
            (None, _) => None,
        };

    if let (Some(book_currency), Some((_, terms))) = (&currency, current_facility_terms) {
        if &terms.credit_limit.currency != book_currency {
            return Err(TrustHttpError::new(
                StatusCode::CONFLICT,
                format!(
                    "capital book facility currency `{}` does not match book currency `{}`",
                    terms.credit_limit.currency, book_currency
                ),
            ));
        }
    }
    if let (Some(book_currency), Some((bond_row, terms))) = (&currency, current_bond_terms) {
        for amount in [
            &terms.credit_limit,
            &terms.collateral_amount,
            &terms.reserve_requirement_amount,
            &terms.outstanding_exposure_amount,
        ] {
            if &amount.currency != book_currency {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "capital book bond `{}` mixes currency `{}` with book currency `{}`",
                        bond_row.bond.body.bond_id, amount.currency, book_currency
                    ),
                ));
            }
        }
        if let Some((facility_row, _)) = current_facility_terms {
            if bond_row.bond.body.report.latest_facility_id.as_deref()
                != Some(facility_row.facility.body.facility_id.as_str())
            {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "capital book bond `{}` does not resolve to current facility `{}`",
                        bond_row.bond.body.bond_id, facility_row.facility.body.facility_id
                    ),
                ));
            }
        }
    }

    let accounting = if let Some(book_currency) = currency.as_deref() {
        compute_credit_loss_lifecycle_accounting(book_currency, &loss_history)
            .map_err(|message| TrustHttpError::new(StatusCode::CONFLICT, message))?
    } else {
        CreditLossLifecycleAccountingState {
            currency: String::new(),
            delinquent_units: 0,
            recovered_units: 0,
            reserve_released_units: 0,
            reserve_slashed_units: 0,
            written_off_units: 0,
        }
    };

    let mut sources = Vec::new();
    let mut events = Vec::new();
    let live_outstanding_units = exposure_position
        .map(credit_bond_outstanding_units)
        .unwrap_or(0);
    let live_reserve_units = current_bond_terms
        .map(|(_, terms)| {
            credit_bond_reserve_units(live_outstanding_units, terms.reserve_ratio_bps)
        })
        .or_else(|| {
            current_facility_terms.map(|(_, terms)| {
                credit_bond_reserve_units(live_outstanding_units, terms.reserve_ratio_bps)
            })
        })
        .unwrap_or(0);
    if let (Some(book_currency), Some((facility_row, facility_terms))) =
        (currency.as_deref(), current_facility_terms)
    {
        let source_id = capital_book_facility_source_id(&facility_row.facility.body.facility_id);
        let owner_role = capital_book_owner_role(facility_terms.capital_source);
        let drawn_units = current_bond_terms
            .map(|(_, terms)| terms.outstanding_exposure_amount.units)
            .unwrap_or(0)
            .max(live_outstanding_units);
        let disbursed_units = exposure_position.map_or(0, |position| position.settled_units);
        sources.push(CapitalBookSource {
            source_id: source_id.clone(),
            kind: CapitalBookSourceKind::FacilityCommitment,
            owner_role,
            counterparty_role: CapitalBookRole::AgentCounterparty,
            counterparty_id: subject_key.clone(),
            currency: book_currency.to_string(),
            jurisdiction: None,
            capital_source: Some(facility_terms.capital_source),
            facility_id: Some(facility_row.facility.body.facility_id.clone()),
            bond_id: current_bond_row.map(|row| row.bond.body.bond_id.clone()),
            committed_amount: amount_if_nonzero(facility_terms.credit_limit.units, book_currency),
            held_amount: None,
            drawn_amount: amount_if_nonzero(drawn_units, book_currency),
            disbursed_amount: amount_if_nonzero(disbursed_units, book_currency),
            released_amount: None,
            repaid_amount: None,
            impaired_amount: None,
            description: format!(
                "current facility `{}` defines the committed source of funds for the subject-scoped capital book",
                facility_row.facility.body.facility_id
            ),
        });
        events.push(CapitalBookEvent {
            event_id: format!("commit:{}", facility_row.facility.body.facility_id),
            kind: CapitalBookEventKind::Commit,
            occurred_at: facility_row.facility.body.issued_at,
            source_id: source_id.clone(),
            owner_role,
            counterparty_role: CapitalBookRole::AgentCounterparty,
            counterparty_id: subject_key.clone(),
            amount: facility_terms.credit_limit.clone(),
            facility_id: Some(facility_row.facility.body.facility_id.clone()),
            bond_id: None,
            loss_event_id: None,
            receipt_id: None,
            description: "facility grant committed capital into the live capital book".to_string(),
            evidence_refs: vec![capital_book_facility_evidence(&facility_row.facility)],
        });
        for receipt in &exposure.receipts {
            let Some(amount) = receipt.financial_amount.as_ref() else {
                continue;
            };
            if amount.currency != book_currency
                || amount.units == 0
                || receipt.settlement_status != SettlementStatus::Settled
            {
                continue;
            }
            events.push(CapitalBookEvent {
                event_id: format!("disburse:{}", receipt.receipt_id),
                kind: CapitalBookEventKind::Disburse,
                occurred_at: receipt.timestamp,
                source_id: source_id.clone(),
                owner_role,
                counterparty_role: CapitalBookRole::AgentCounterparty,
                counterparty_id: subject_key.clone(),
                amount: amount.clone(),
                facility_id: Some(facility_row.facility.body.facility_id.clone()),
                bond_id: current_bond_row.map(|row| row.bond.body.bond_id.clone()),
                loss_event_id: None,
                receipt_id: Some(receipt.receipt_id.clone()),
                description:
                    "settled governed receipt disbursed capital against the committed source"
                        .to_string(),
                evidence_refs: capital_book_receipt_evidence(receipt),
            });
        }
    }

    if let (Some(book_currency), Some((bond_row, bond_terms))) =
        (currency.as_deref(), current_bond_terms)
    {
        let owner_role = current_facility_terms
            .map(|(_, terms)| capital_book_owner_role(terms.capital_source))
            .unwrap_or_else(|| capital_book_owner_role(bond_terms.capital_source));
        let source_id = capital_book_bond_source_id(&bond_row.bond.body.bond_id);
        let drawn_units = bond_terms
            .outstanding_exposure_amount
            .units
            .max(live_outstanding_units);
        let held_units = match bond_row.bond.body.report.disposition {
            CreditBondDisposition::Lock | CreditBondDisposition::Hold => bond_terms
                .reserve_requirement_amount
                .units
                .max(live_reserve_units),
            CreditBondDisposition::Release | CreditBondDisposition::Impair => 0,
        };
        let released_units = if accounting.reserve_released_units > 0 {
            accounting.reserve_released_units
        } else if bond_row.bond.body.report.disposition == CreditBondDisposition::Release {
            bond_terms.reserve_requirement_amount.units
        } else {
            0
        };
        let repaid_units = accounting.recovered_units;
        let impaired_units = if accounting.delinquent_units > 0 {
            accounting
                .delinquent_units
                .saturating_sub(accounting.recovered_units)
        } else if bond_row.bond.body.report.disposition == CreditBondDisposition::Impair {
            bond_terms
                .outstanding_exposure_amount
                .units
                .max(exposure_position.map_or(0, |position| {
                    position
                        .provisional_loss_units
                        .saturating_sub(position.recovered_units)
                }))
        } else {
            0
        };
        sources.push(CapitalBookSource {
            source_id: source_id.clone(),
            kind: CapitalBookSourceKind::ReserveBook,
            owner_role,
            counterparty_role: CapitalBookRole::AgentCounterparty,
            counterparty_id: subject_key.clone(),
            currency: book_currency.to_string(),
            jurisdiction: None,
            capital_source: Some(bond_terms.capital_source),
            facility_id: Some(bond_terms.facility_id.clone()),
            bond_id: Some(bond_row.bond.body.bond_id.clone()),
            committed_amount: None,
            held_amount: amount_if_nonzero(held_units, book_currency),
            drawn_amount: None,
            disbursed_amount: None,
            released_amount: amount_if_nonzero(released_units, book_currency),
            repaid_amount: amount_if_nonzero(repaid_units, book_currency),
            impaired_amount: amount_if_nonzero(impaired_units, book_currency),
            description: format!(
                "bond `{}` preserves reserve and impairment state over the current source of funds",
                bond_row.bond.body.bond_id
            ),
        });
        if held_units > 0 {
            events.push(CapitalBookEvent {
                event_id: format!("hold:{}", bond_row.bond.body.bond_id),
                kind: CapitalBookEventKind::Hold,
                occurred_at: bond_row.bond.body.issued_at,
                source_id: source_id.clone(),
                owner_role,
                counterparty_role: CapitalBookRole::AgentCounterparty,
                counterparty_id: subject_key.clone(),
                amount: MonetaryAmount {
                    units: held_units,
                    currency: book_currency.to_string(),
                },
                facility_id: Some(bond_terms.facility_id.clone()),
                bond_id: Some(bond_row.bond.body.bond_id.clone()),
                loss_event_id: None,
                receipt_id: None,
                description: "bond posture held reserve against the committed capital source"
                    .to_string(),
                evidence_refs: vec![capital_book_bond_evidence(&bond_row.bond)],
            });
        }
        if drawn_units > 0 {
            events.push(CapitalBookEvent {
                event_id: format!("draw:{}", bond_row.bond.body.bond_id),
                kind: CapitalBookEventKind::Draw,
                occurred_at: bond_row.bond.body.issued_at,
                source_id: source_id.clone(),
                owner_role,
                counterparty_role: CapitalBookRole::AgentCounterparty,
                counterparty_id: subject_key.clone(),
                amount: MonetaryAmount {
                    units: drawn_units,
                    currency: book_currency.to_string(),
                },
                facility_id: Some(bond_terms.facility_id.clone()),
                bond_id: Some(bond_row.bond.body.bond_id.clone()),
                loss_event_id: None,
                receipt_id: None,
                description: "bond posture drew against the live facility commitment".to_string(),
                evidence_refs: vec![capital_book_bond_evidence(&bond_row.bond)],
            });
        }
        let lifecycle_has_release = loss_history
            .events
            .iter()
            .any(|row| row.event.body.event_kind == CreditLossLifecycleEventKind::ReserveRelease);
        let lifecycle_has_impairment = loss_history.events.iter().any(|row| {
            matches!(
                row.event.body.event_kind,
                CreditLossLifecycleEventKind::Delinquency
                    | CreditLossLifecycleEventKind::ReserveSlash
                    | CreditLossLifecycleEventKind::WriteOff
            )
        });
        if released_units > 0 && !lifecycle_has_release {
            events.push(CapitalBookEvent {
                event_id: format!("release:{}", bond_row.bond.body.bond_id),
                kind: CapitalBookEventKind::Release,
                occurred_at: bond_row.bond.body.issued_at,
                source_id: source_id.clone(),
                owner_role,
                counterparty_role: CapitalBookRole::AgentCounterparty,
                counterparty_id: subject_key.clone(),
                amount: MonetaryAmount {
                    units: released_units,
                    currency: book_currency.to_string(),
                },
                facility_id: Some(bond_terms.facility_id.clone()),
                bond_id: Some(bond_row.bond.body.bond_id.clone()),
                loss_event_id: None,
                receipt_id: None,
                description: "bond posture released previously held reserve state".to_string(),
                evidence_refs: vec![capital_book_bond_evidence(&bond_row.bond)],
            });
        }
        if impaired_units > 0 && !lifecycle_has_impairment {
            events.push(CapitalBookEvent {
                event_id: format!("impair:{}", bond_row.bond.body.bond_id),
                kind: CapitalBookEventKind::Impair,
                occurred_at: bond_row.bond.body.issued_at,
                source_id: source_id.clone(),
                owner_role,
                counterparty_role: CapitalBookRole::AgentCounterparty,
                counterparty_id: subject_key.clone(),
                amount: MonetaryAmount {
                    units: impaired_units,
                    currency: book_currency.to_string(),
                },
                facility_id: Some(bond_terms.facility_id.clone()),
                bond_id: Some(bond_row.bond.body.bond_id.clone()),
                loss_event_id: None,
                receipt_id: None,
                description: "bond posture impaired capital against outstanding loss state"
                    .to_string(),
                evidence_refs: vec![capital_book_bond_evidence(&bond_row.bond)],
            });
        }
        for row in &loss_history.events {
            let Some(amount) = row.event.body.report.summary.event_amount.as_ref() else {
                continue;
            };
            if amount.currency != book_currency || amount.units == 0 {
                continue;
            }
            let (kind, description) = match row.event.body.event_kind {
                CreditLossLifecycleEventKind::Delinquency => (
                    CapitalBookEventKind::Impair,
                    "loss lifecycle recorded delinquent impairment against the reserve book",
                ),
                CreditLossLifecycleEventKind::Recovery => (
                    CapitalBookEventKind::Repay,
                    "loss lifecycle recorded repayment against previously impaired capital",
                ),
                CreditLossLifecycleEventKind::ReserveRelease => (
                    CapitalBookEventKind::Release,
                    "loss lifecycle released held reserve after delinquency cleared",
                ),
                CreditLossLifecycleEventKind::ReserveSlash => (
                    CapitalBookEventKind::Disburse,
                    "loss lifecycle slashed reserve against outstanding delinquent exposure",
                ),
                CreditLossLifecycleEventKind::WriteOff => (
                    CapitalBookEventKind::Impair,
                    "loss lifecycle wrote off impaired capital against the reserve book",
                ),
            };
            events.push(CapitalBookEvent {
                event_id: format!("capital-event:{}", row.event.body.event_id),
                kind,
                occurred_at: row.event.body.issued_at,
                source_id: source_id.clone(),
                owner_role,
                counterparty_role: CapitalBookRole::AgentCounterparty,
                counterparty_id: subject_key.clone(),
                amount: amount.clone(),
                facility_id: row.event.body.report.summary.facility_id.clone(),
                bond_id: Some(row.event.body.bond_id.clone()),
                loss_event_id: Some(row.event.body.event_id.clone()),
                receipt_id: None,
                description: description.to_string(),
                evidence_refs: vec![
                    capital_book_loss_event_evidence(&row.event),
                    capital_book_bond_evidence(&bond_row.bond),
                ],
            });
        }
    }

    events.sort_by(|left, right| {
        left.occurred_at
            .cmp(&right.occurred_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });

    let summary_currencies = currency.into_iter().collect::<Vec<_>>();
    Ok(CapitalBookReport {
        schema: CAPITAL_BOOK_REPORT_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        query: normalized,
        subject_key,
        support_boundary: CapitalBookSupportBoundary::default(),
        summary: CapitalBookSummary {
            matching_receipts: exposure.summary.matching_receipts,
            returned_receipts: exposure.receipts.len() as u64,
            matching_facilities: facility_report.summary.matching_facilities,
            returned_facilities: facility_report.facilities.len() as u64,
            matching_bonds: bond_report.summary.matching_bonds,
            returned_bonds: bond_report.bonds.len() as u64,
            matching_loss_events: loss_history.summary.matching_events,
            returned_loss_events: loss_history.events.len() as u64,
            currencies: summary_currencies.clone(),
            mixed_currency_book: summary_currencies.len() > 1,
            funding_sources: sources.len() as u64,
            ledger_events: events.len() as u64,
            truncated_receipts: exposure.summary.truncated_receipts,
            truncated_facilities: facility_report.summary.matching_facilities
                > facility_report.facilities.len() as u64,
            truncated_bonds: bond_report.summary.matching_bonds > bond_report.bonds.len() as u64,
            truncated_loss_events: loss_history.summary.matching_events
                > loss_history.events.len() as u64,
        },
        sources,
        events,
    })
}

fn validate_capital_book_receipts(
    receipts: &[ExposureLedgerReceiptEntry],
    subject_key: &str,
) -> Result<(), TrustHttpError> {
    let mut seen_monetary_receipt_ids = std::collections::BTreeSet::<&str>::new();
    for receipt in receipts {
        let carries_monetary_state = receipt.governed_max_amount.is_some()
            || receipt.financial_amount.is_some()
            || receipt.reserve_required_amount.is_some()
            || receipt.provisional_loss_amount.is_some()
            || receipt.recovered_amount.is_some();
        if !carries_monetary_state {
            continue;
        }
        if !seen_monetary_receipt_ids.insert(receipt.receipt_id.as_str()) {
            return Err(TrustHttpError::new(
                StatusCode::CONFLICT,
                format!(
                    "capital book resolved duplicate monetary receipt `{}`; governed receipt ids must be unique",
                    receipt.receipt_id
                ),
            ));
        }
        let Some(receipt_subject) = receipt.subject_key.as_deref() else {
            return Err(TrustHttpError::new(
                StatusCode::CONFLICT,
                format!(
                    "capital book receipt `{}` is missing counterparty subject attribution",
                    receipt.receipt_id
                ),
            ));
        };
        if receipt_subject != subject_key {
            return Err(TrustHttpError::new(
                StatusCode::CONFLICT,
                format!(
                    "capital book receipt `{}` resolved subject `{}` but query subject is `{}`",
                    receipt.receipt_id, receipt_subject, subject_key
                ),
            ));
        }
    }
    Ok(())
}

pub(crate) fn build_capital_execution_instruction_artifact_from_store(
    receipt_store: &SqliteReceiptStore,
    request: &CapitalExecutionInstructionRequest,
) -> Result<CapitalExecutionInstructionArtifact, TrustHttpError> {
    let issued_at = unix_timestamp_now();
    let transfer_governed_receipt_id =
        validate_capital_execution_instruction_request(request, issued_at)?;

    let capital_book = build_capital_book_report_from_store(receipt_store, &request.query)?;
    let source = capital_book
        .sources
        .iter()
        .find(|source| source.kind == request.source_kind)
        .ok_or_else(|| {
            TrustHttpError::new(
                StatusCode::CONFLICT,
                format!(
                    "capital instruction requires a current {:?} source in the capital book",
                    request.source_kind
                ),
            )
        })?;

    match request.action {
        CapitalExecutionInstructionAction::TransferFunds
            if request.source_kind != CapitalBookSourceKind::FacilityCommitment =>
        {
            return Err(TrustHttpError::bad_request(
                "transfer_funds instructions require sourceKind=facility_commitment",
            ));
        }
        CapitalExecutionInstructionAction::LockReserve
        | CapitalExecutionInstructionAction::HoldReserve
        | CapitalExecutionInstructionAction::ReleaseReserve
            if request.source_kind != CapitalBookSourceKind::ReserveBook =>
        {
            return Err(TrustHttpError::bad_request(
                "reserve instructions require sourceKind=reserve_book",
            ));
        }
        _ => {}
    }

    let transfer_receipt_binding = match request.action {
        CapitalExecutionInstructionAction::TransferFunds => {
            let governed_receipt_id = transfer_governed_receipt_id.clone().ok_or_else(|| {
                TrustHttpError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "validated transfer_funds instruction lost governedReceiptId".to_string(),
                )
            })?;
            let matching_events = capital_book
                .events
                .iter()
                .filter(|event| {
                    event.source_id == source.source_id
                        && event.kind == CapitalBookEventKind::Disburse
                        && event.receipt_id.as_deref() == Some(governed_receipt_id.as_str())
                })
                .collect::<Vec<_>>();
            if matching_events.is_empty() {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "transfer_funds governed receipt `{}` does not resolve to one disburse event on source `{}`",
                        governed_receipt_id, source.source_id
                    ),
                ));
            }
            if matching_events.len() > 1 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "transfer_funds governed receipt `{}` matched multiple disburse events on source `{}`",
                        governed_receipt_id, source.source_id
                    ),
                ));
            }
            Some((governed_receipt_id, matching_events[0]))
        }
        _ => None,
    };

    let amount = match request.action {
        CapitalExecutionInstructionAction::CancelInstruction => {
            if request.amount.is_some() {
                return Err(TrustHttpError::bad_request(
                    "cancel_instruction does not accept an amount",
                ));
            }
            if request.related_instruction_id.is_none() {
                return Err(TrustHttpError::bad_request(
                    "cancel_instruction requires relatedInstructionId",
                ));
            }
            if request.observed_execution.is_some() {
                return Err(TrustHttpError::bad_request(
                    "cancel_instruction cannot carry observedExecution movement data",
                ));
            }
            None
        }
        _ => {
            let amount = request.amount.clone().ok_or_else(|| {
                TrustHttpError::bad_request(
                    "capital instructions require amount for non-cancel actions",
                )
            })?;
            if amount.units == 0 {
                return Err(TrustHttpError::bad_request(
                    "capital instruction amount must be greater than zero",
                ));
            }
            if amount.currency != source.currency {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "capital instruction amount currency `{}` does not match source currency `{}`",
                        amount.currency, source.currency
                    ),
                ));
            }
            let available_amount = capital_instruction_available_amount(source, request.action)?;
            if amount.units > available_amount.units {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "capital instruction amount {} exceeds available source amount {}",
                        amount.units, available_amount.units
                    ),
                ));
            }
            if let Some((governed_receipt_id, disburse_event)) = transfer_receipt_binding.as_ref() {
                if amount != disburse_event.amount {
                    return Err(TrustHttpError::new(
                        StatusCode::CONFLICT,
                        format!(
                            "transfer_funds amount for governed receipt `{}` must match the settled disburse event amount exactly",
                            governed_receipt_id
                        ),
                    ));
                }
            }
            Some(amount)
        }
    };

    let owner_role = capital_execution_role_from_book_role(source.owner_role);
    let counterparty_role = capital_execution_role_from_book_role(source.counterparty_role);
    ensure_capital_execution_owner_authority(&request.authority_chain, owner_role)?;

    let reconciled_state = if let Some(observed_execution) = &request.observed_execution {
        let intended_amount = amount.as_ref().ok_or_else(|| {
            TrustHttpError::bad_request(
                "observedExecution is only valid when the instruction carries an intended amount",
            )
        })?;
        if &observed_execution.amount != intended_amount {
            return Err(TrustHttpError::new(
                StatusCode::CONFLICT,
                "capital instruction observedExecution amount does not match intended amount",
            ));
        }
        if observed_execution.observed_at < request.execution_window.not_before
            || observed_execution.observed_at > request.execution_window.not_after
        {
            return Err(TrustHttpError::new(
                StatusCode::CONFLICT,
                "capital instruction observedExecution timestamp falls outside the execution window",
            ));
        }
        CapitalExecutionReconciledState::Matched
    } else {
        CapitalExecutionReconciledState::NotObserved
    };

    let intended_state = if request.action == CapitalExecutionInstructionAction::CancelInstruction {
        CapitalExecutionIntendedState::CancellationPending
    } else {
        CapitalExecutionIntendedState::PendingExecution
    };

    let mut evidence_refs = Vec::new();
    if let Some(facility_id) = source.facility_id.as_ref() {
        push_unique_capital_book_evidence(
            &mut evidence_refs,
            CapitalBookEvidenceReference {
                kind: CapitalBookEvidenceKind::CreditFacility,
                reference_id: facility_id.clone(),
                observed_at: Some(capital_book.generated_at),
                locator: Some(format!("credit-facility:{facility_id}")),
            },
        );
    }
    if let Some(bond_id) = source.bond_id.as_ref() {
        push_unique_capital_book_evidence(
            &mut evidence_refs,
            CapitalBookEvidenceReference {
                kind: CapitalBookEvidenceKind::CreditBond,
                reference_id: bond_id.clone(),
                observed_at: Some(capital_book.generated_at),
                locator: Some(format!("credit-bond:{bond_id}")),
            },
        );
    }
    for event in capital_book
        .events
        .iter()
        .filter(|event| event.source_id == source.source_id)
    {
        for evidence in &event.evidence_refs {
            push_unique_capital_book_evidence(&mut evidence_refs, evidence.clone());
        }
    }

    let instruction_id_input = canonical_json_bytes(&(
        CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA,
        &capital_book.query,
        &capital_book.subject_key,
        &source.source_id,
        request.source_kind,
        &request.governed_receipt_id,
        request.action,
        &amount,
        &request.authority_chain,
        &request.execution_window,
        &request.rail,
        &request.related_instruction_id,
        &request.observed_execution,
        &request.description,
    ))
    .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let instruction_id = format!("cei-{}", sha256_hex(&instruction_id_input));

    let description = request.description.clone().unwrap_or_else(|| {
        format!(
            "{:?} instruction over source `{}` for subject `{}`",
            request.action, source.source_id, capital_book.subject_key
        )
    });

    let artifact = CapitalExecutionInstructionArtifact {
        schema: CAPITAL_EXECUTION_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
        instruction_id,
        issued_at,
        query: capital_book.query,
        subject_key: capital_book.subject_key,
        source_id: source.source_id.clone(),
        source_kind: source.kind,
        governed_receipt_id: transfer_receipt_binding
            .as_ref()
            .map(|(governed_receipt_id, _)| governed_receipt_id.clone()),
        completion_flow_row_id: transfer_receipt_binding
            .as_ref()
            .map(|(governed_receipt_id, _)| economic_completion_flow_row_id(governed_receipt_id)),
        action: request.action,
        owner_role,
        counterparty_role,
        counterparty_id: source.counterparty_id.clone(),
        amount,
        authority_chain: request.authority_chain.clone(),
        execution_window: request.execution_window.clone(),
        rail: request.rail.clone(),
        intended_state,
        reconciled_state,
        related_instruction_id: request.related_instruction_id.clone(),
        observed_execution: request.observed_execution.clone(),
        support_boundary: CapitalExecutionInstructionSupportBoundary::default(),
        evidence_refs,
        description,
    };
    artifact
        .validate()
        .map_err(capital_execution_validation_error)?;
    Ok(artifact)
}

fn validate_capital_execution_instruction_request(
    request: &CapitalExecutionInstructionRequest,
    issued_at: u64,
) -> Result<Option<String>, TrustHttpError> {
    request
        .query
        .validate()
        .map_err(TrustHttpError::bad_request)?;
    let transfer_governed_receipt_id = match request.action {
        CapitalExecutionInstructionAction::TransferFunds => Some(
            request.governed_receipt_id.clone().ok_or_else(|| {
                TrustHttpError::bad_request(
                    "transfer_funds instructions require governedReceiptId so settlement provenance stays receipt-scoped",
                )
            })?,
        ),
        CapitalExecutionInstructionAction::LockReserve
        | CapitalExecutionInstructionAction::HoldReserve
        | CapitalExecutionInstructionAction::ReleaseReserve
        | CapitalExecutionInstructionAction::CancelInstruction
            if request.governed_receipt_id.is_some() =>
        {
            return Err(TrustHttpError::bad_request(
                "governedReceiptId is only valid for transfer_funds instructions",
            ));
        }
        _ => None,
    };
    validate_capital_execution_envelope(
        &request.authority_chain,
        &request.execution_window,
        &request.rail,
        issued_at,
    )?;
    Ok(transfer_governed_receipt_id)
}

pub(crate) fn validate_capital_execution_envelope(
    authority_chain: &[CapitalExecutionAuthorityStep],
    execution_window: &CapitalExecutionWindow,
    rail: &CapitalExecutionRail,
    issued_at: u64,
) -> Result<(), TrustHttpError> {
    chio_kernel::validate_capital_execution_envelope(
        authority_chain,
        execution_window,
        rail,
        issued_at,
    )
    .map_err(capital_execution_validation_error)
}

pub(crate) fn ensure_capital_execution_owner_authority(
    authority_chain: &[CapitalExecutionAuthorityStep],
    owner_role: CapitalExecutionRole,
) -> Result<(), TrustHttpError> {
    chio_kernel::ensure_capital_execution_owner_authority(authority_chain, owner_role)
        .map_err(capital_execution_validation_error)
}

pub(crate) fn ensure_capital_execution_custodian_authority(
    authority_chain: &[CapitalExecutionAuthorityStep],
    rail: &CapitalExecutionRail,
) -> Result<(), TrustHttpError> {
    chio_kernel::ensure_capital_execution_custodian_authority(authority_chain, rail)
        .map_err(capital_execution_validation_error)
}

fn capital_execution_validation_error(message: String) -> TrustHttpError {
    if message.contains("already expired")
        || message.contains("stale")
        || message.contains("expires before")
        || message.contains("missing source-owner")
        || message.contains("missing the custody-provider")
        || message.contains("does not match intended amount")
        || message.contains("falls outside the execution window")
    {
        TrustHttpError::new(StatusCode::CONFLICT, message)
    } else {
        TrustHttpError::bad_request(message)
    }
}

pub(crate) fn select_capital_allocation_receipt<'a>(
    receipts: &'a [BehavioralFeedReceiptRow],
    receipt_id: Option<&str>,
) -> Result<&'a BehavioralFeedReceiptRow, TrustHttpError> {
    let actionable = |row: &&BehavioralFeedReceiptRow| {
        row.action_required
            && row.authorized
            && row
                .governed
                .as_ref()
                .and_then(|governed| governed.max_amount.as_ref())
                .is_some()
    };

    if let Some(receipt_id) = receipt_id {
        let row = receipts
            .iter()
            .find(|row| row.receipt_id == receipt_id)
            .ok_or_else(|| {
                TrustHttpError::new(
                    StatusCode::NOT_FOUND,
                    format!("capital allocation receipt `{receipt_id}` not found"),
                )
            })?;
        if actionable(&row) {
            return Ok(row);
        }
        return Err(TrustHttpError::new(
            StatusCode::CONFLICT,
            format!(
                "capital allocation receipt `{receipt_id}` is not an approved actionable governed receipt with max_amount"
            ),
        ));
    }

    let actionable_rows = receipts.iter().filter(actionable).collect::<Vec<_>>();
    match actionable_rows.as_slice() {
        [] => Err(TrustHttpError::new(
            StatusCode::CONFLICT,
            "capital allocation requires one approved actionable governed receipt with max_amount",
        )),
        [row] => Ok(*row),
        _ => Err(TrustHttpError::new(
            StatusCode::CONFLICT,
            "capital allocation matched multiple approved actionable governed receipts; narrow the query or set receiptId",
        )),
    }
}

pub(crate) fn capital_allocation_ceiling_units(units: u64, ceiling_bps: u16) -> u64 {
    if units == 0 || ceiling_bps == 0 {
        0
    } else {
        (((units as u128) * (ceiling_bps as u128)) / 10_000_u128).min(u64::MAX as u128) as u64
    }
}

pub(crate) fn capital_book_evidence_from_exposure_refs(
    refs: &[ExposureLedgerEvidenceReference],
) -> Vec<CapitalBookEvidenceReference> {
    refs.iter()
        .filter_map(|reference| {
            let kind = match reference.kind {
                ExposureLedgerEvidenceKind::Receipt => CapitalBookEvidenceKind::Receipt,
                ExposureLedgerEvidenceKind::SettlementReconciliation => {
                    CapitalBookEvidenceKind::SettlementReconciliation
                }
                ExposureLedgerEvidenceKind::MeteredBillingReconciliation
                | ExposureLedgerEvidenceKind::UnderwritingDecision => return None,
            };
            Some(CapitalBookEvidenceReference {
                kind,
                reference_id: reference.reference_id.clone(),
                observed_at: reference.observed_at,
                locator: reference.locator.clone(),
            })
        })
        .collect()
}

fn capital_instruction_available_amount(
    source: &CapitalBookSource,
    action: CapitalExecutionInstructionAction,
) -> Result<MonetaryAmount, TrustHttpError> {
    let amount = match action {
        CapitalExecutionInstructionAction::TransferFunds => source.committed_amount.clone(),
        CapitalExecutionInstructionAction::LockReserve
        | CapitalExecutionInstructionAction::HoldReserve
        | CapitalExecutionInstructionAction::ReleaseReserve => source.held_amount.clone(),
        CapitalExecutionInstructionAction::CancelInstruction => None,
    }
    .ok_or_else(|| {
        TrustHttpError::new(
            StatusCode::CONFLICT,
            format!(
                "capital instruction action {:?} does not have a live source amount to bind against",
                action
            ),
        )
    })?;
    Ok(amount)
}

fn economic_completion_flow_row_id(receipt_id: &str) -> String {
    format!("economic-completion-flow:{receipt_id}")
}

pub(crate) fn capital_execution_role_from_book_role(role: CapitalBookRole) -> CapitalExecutionRole {
    match role {
        CapitalBookRole::OperatorTreasury => CapitalExecutionRole::OperatorTreasury,
        CapitalBookRole::ExternalCapitalProvider => CapitalExecutionRole::ExternalCapitalProvider,
        CapitalBookRole::AgentCounterparty => CapitalExecutionRole::AgentCounterparty,
    }
}

pub(crate) fn push_unique_capital_book_evidence(
    refs: &mut Vec<CapitalBookEvidenceReference>,
    evidence: CapitalBookEvidenceReference,
) {
    if !refs.contains(&evidence) {
        refs.push(evidence);
    }
}

pub fn build_credit_facility_report(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &ExposureLedgerQuery,
    trusted_kernel_keys: &[String],
) -> Result<CreditFacilityReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    build_credit_facility_report_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        issuance_policy,
        query,
        trusted_kernel_keys,
    )
    .map_err(CliError::from)
}

pub struct CreditIssuanceArgs<'a> {
    pub receipt_db_path: &'a Path,
    pub budget_db_path: Option<&'a Path>,
    pub authority_seed_path: Option<&'a Path>,
    pub authority_db_path: Option<&'a Path>,
    pub certification_registry_file: Option<&'a Path>,
    pub issuance_policy: Option<&'a crate::policy::ReputationIssuancePolicy>,
    pub query: &'a ExposureLedgerQuery,
    pub supersedes_artifact_id: Option<&'a str>,
}

pub fn issue_signed_credit_facility(
    args: CreditIssuanceArgs<'_>,
) -> Result<SignedCreditFacility, CliError> {
    issue_signed_credit_facility_detailed(args).map_err(CliError::from)
}

pub fn list_credit_facilities(
    receipt_db_path: &Path,
    query: &CreditFacilityListQuery,
) -> Result<CreditFacilityListReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .query_credit_facilities(query)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

pub fn build_credit_bond_report(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &ExposureLedgerQuery,
    trusted_kernel_keys: &[String],
) -> Result<CreditBondReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    build_credit_bond_report_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        issuance_policy,
        query,
        trusted_kernel_keys,
    )
    .map_err(CliError::from)
}

pub fn issue_signed_credit_bond(
    args: CreditIssuanceArgs<'_>,
) -> Result<SignedCreditBond, CliError> {
    issue_signed_credit_bond_detailed(args).map_err(CliError::from)
}

pub fn list_credit_bonds(
    receipt_db_path: &Path,
    query: &CreditBondListQuery,
) -> Result<CreditBondListReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .query_credit_bonds(query)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

pub fn build_credit_bonded_execution_simulation_report(
    receipt_db_path: &Path,
    request: &CreditBondedExecutionSimulationRequest,
) -> Result<CreditBondedExecutionSimulationReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    build_credit_bonded_execution_simulation_report_from_store(&receipt_store, request)
        .map_err(CliError::from)
}

pub fn build_credit_loss_lifecycle_report(
    receipt_db_path: &Path,
    query: &CreditLossLifecycleQuery,
) -> Result<CreditLossLifecycleReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    build_credit_loss_lifecycle_report_from_store(&receipt_store, query).map_err(CliError::from)
}

pub fn issue_signed_credit_loss_lifecycle(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &CreditLossLifecycleIssueRequest,
) -> Result<SignedCreditLossLifecycle, CliError> {
    issue_signed_credit_loss_lifecycle_detailed(
        receipt_db_path,
        authority_seed_path,
        authority_db_path,
        request,
    )
    .map_err(CliError::from)
}

pub fn list_credit_loss_lifecycle(
    receipt_db_path: &Path,
    query: &CreditLossLifecycleListQuery,
) -> Result<CreditLossLifecycleListReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .query_credit_loss_lifecycle(query)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

pub fn build_credit_backtest_report(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &CreditBacktestQuery,
    trusted_kernel_keys: &[String],
) -> Result<CreditBacktestReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    build_credit_backtest_report_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        issuance_policy,
        query,
        trusted_kernel_keys,
    )
    .map_err(CliError::from)
}

pub fn build_signed_credit_provider_risk_package(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &CreditProviderRiskPackageQuery,
) -> Result<SignedCreditProviderRiskPackage, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let package = build_credit_provider_risk_package_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        issuance_policy,
        &keypair,
        query,
        chio_kernel::ReceiptReadContext::local_operator_admin_all(),
    )
    .map_err(CliError::from)?;
    SignedCreditProviderRiskPackage::sign(package, &keypair).map_err(Into::into)
}

pub(crate) fn build_credit_backtest_report_from_store(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    issuance_policy: Option<&crate::policy::ReputationIssuancePolicy>,
    query: &CreditBacktestQuery,
    trusted_kernel_keys: &[String],
) -> Result<CreditBacktestReport, TrustHttpError> {
    let normalized = query.normalized();
    if let Err(message) = normalized.validate() {
        return Err(TrustHttpError::bad_request(message));
    }

    let window_count = normalized.window_count_or_default();
    let window_seconds = normalized.window_seconds_or_default();
    let stale_after_seconds = normalized.stale_after_seconds_or_default();
    let end_anchor = normalized.until.unwrap_or_else(unix_timestamp_now);
    let earliest_start = normalized.since.unwrap_or_else(|| {
        end_anchor.saturating_sub(window_seconds.saturating_mul(window_count as u64))
    });
    let mut windows = Vec::new();
    let mut previous_band = None;
    let mut previous_disposition = None;
    let mut drift_windows = 0_u64;
    let mut score_band_changes = 0_u64;
    let mut facility_disposition_changes = 0_u64;
    let mut manual_review_windows = 0_u64;
    let mut denied_windows = 0_u64;
    let mut stale_evidence_windows = 0_u64;
    let mut mixed_currency_windows = 0_u64;
    let mut over_utilized_windows = 0_u64;

    for offset_index in (0..window_count).rev() {
        let window_end = end_anchor.saturating_sub((offset_index as u64) * window_seconds);
        if window_end < earliest_start {
            continue;
        }
        let window_start = window_end
            .saturating_sub(window_seconds.saturating_sub(1))
            .max(earliest_start);
        let exposure_query = CreditBacktestQuery {
            since: Some(window_start),
            until: Some(window_end),
            ..normalized.clone()
        }
        .exposure_query()
        .normalized();
        let exposure = match build_exposure_ledger_report(receipt_store, &exposure_query) {
            Ok(report) => report,
            Err(error) if error.status == StatusCode::CONFLICT => continue,
            Err(error) => return Err(error),
        };
        let scorecard = build_credit_scorecard_report(
            receipt_store,
            receipt_db_path,
            budget_db_path,
            issuance_policy,
            &exposure_query,
            trusted_kernel_keys,
        )?;
        let facility = build_credit_facility_report_from_store(
            receipt_store,
            receipt_db_path,
            budget_db_path,
            certification_registry_file,
            issuance_policy,
            &exposure_query,
            trusted_kernel_keys,
        )?;
        let simulated_terms = facility
            .terms
            .clone()
            .or_else(|| build_credit_facility_terms(&scorecard));
        let newest_receipt_at = exposure.receipts.iter().map(|row| row.timestamp).max();
        let stale_evidence = newest_receipt_at
            .is_none_or(|timestamp| window_end.saturating_sub(timestamp) > stale_after_seconds);
        let utilization_bps =
            credit_backtest_utilization_bps(&exposure.positions, simulated_terms.as_ref());
        let over_utilized = utilization_bps.is_some_and(|bps| {
            simulated_terms.as_ref().map_or(bps > 10_000, |terms| {
                bps > u32::from(terms.utilization_ceiling_bps)
            })
        });
        let expected_band = previous_band;
        let expected_disposition = previous_disposition;
        let mut reason_codes = Vec::new();
        if expected_band.is_some_and(|band| band != scorecard.summary.band) {
            reason_codes.push(CreditBacktestReasonCode::ScoreBandShift);
            score_band_changes += 1;
        }
        if expected_disposition.is_some_and(|disposition| disposition != facility.disposition) {
            reason_codes.push(CreditBacktestReasonCode::FacilityDispositionShift);
            facility_disposition_changes += 1;
        }
        if exposure.summary.mixed_currency_book {
            reason_codes.push(CreditBacktestReasonCode::MixedCurrencyBook);
            mixed_currency_windows += 1;
        }
        if stale_evidence {
            reason_codes.push(CreditBacktestReasonCode::StaleEvidence);
            stale_evidence_windows += 1;
        }
        if over_utilized {
            reason_codes.push(CreditBacktestReasonCode::FacilityOverUtilization);
            over_utilized_windows += 1;
        }
        if credit_facility_has_reason(
            &scorecard,
            CreditScorecardReasonCode::PendingSettlementBacklog,
        ) {
            reason_codes.push(CreditBacktestReasonCode::PendingSettlementBacklog);
        }
        if credit_facility_has_reason(
            &scorecard,
            CreditScorecardReasonCode::FailedSettlementBacklog,
        ) {
            reason_codes.push(CreditBacktestReasonCode::FailedSettlementBacklog);
        }
        if !facility.prerequisites.runtime_assurance_met {
            reason_codes.push(CreditBacktestReasonCode::MissingRuntimeAssurance);
        }
        if facility.prerequisites.certification_required
            && !facility.prerequisites.certification_met
        {
            reason_codes.push(CreditBacktestReasonCode::CertificationNotActive);
        }
        if !reason_codes.is_empty() {
            drift_windows += 1;
        }
        match facility.disposition {
            CreditFacilityDisposition::Grant => {}
            CreditFacilityDisposition::ManualReview => manual_review_windows += 1,
            CreditFacilityDisposition::Deny => denied_windows += 1,
        }

        windows.push(CreditBacktestWindow {
            index: windows.len() as u64,
            window_started_at: window_start,
            window_ended_at: window_end,
            newest_receipt_at,
            expected_band,
            expected_disposition,
            simulated_scorecard: scorecard.summary.clone(),
            simulated_disposition: facility.disposition,
            simulated_terms,
            stale_evidence,
            utilization_bps,
            reason_codes,
        });

        previous_band = Some(scorecard.summary.band);
        previous_disposition = Some(facility.disposition);
    }

    if windows.is_empty() {
        return Err(TrustHttpError::new(
            StatusCode::CONFLICT,
            "credit backtest requires at least one historical window with matching governed receipts"
                .to_string(),
        ));
    }

    Ok(CreditBacktestReport {
        schema: CREDIT_BACKTEST_REPORT_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        query: normalized,
        summary: CreditBacktestSummary {
            windows_evaluated: windows.len() as u64,
            drift_windows,
            score_band_changes,
            facility_disposition_changes,
            manual_review_windows,
            denied_windows,
            stale_evidence_windows,
            mixed_currency_windows,
            over_utilized_windows,
        },
        windows,
    })
}

#[cfg(test)]
mod capital_and_liability_tests {
    use super::*;

    use chio_test_support::prelude::*;

    fn monetary_receipt(receipt_id: &str, subject_key: Option<&str>) -> ExposureLedgerReceiptEntry {
        ExposureLedgerReceiptEntry {
            receipt_id: receipt_id.to_string(),
            timestamp: 1_717_171_717,
            capability_id: "cap-1".to_string(),
            subject_key: subject_key.map(ToOwned::to_owned),
            issuer_key: Some("issuer-1".to_string()),
            tool_server: "ledger".to_string(),
            tool_name: "transfer".to_string(),
            decision: Decision::Allow,
            settlement_status: SettlementStatus::Settled,
            action_required: false,
            governed_max_amount: Some(MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            }),
            financial_amount: Some(MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            }),
            reserve_required_amount: None,
            provisional_loss_amount: None,
            recovered_amount: None,
            metered_action_required: false,
            evidence_refs: Vec::new(),
        }
    }

    #[test]
    fn validate_capital_book_receipts_rejects_duplicate_monetary_receipt_ids() {
        let error = validate_capital_book_receipts(
            &[
                monetary_receipt("rcpt-1", Some("subject-1")),
                monetary_receipt("rcpt-1", Some("subject-1")),
            ],
            "subject-1",
        )
        .test_unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert!(error
            .message
            .contains("governed receipt ids must be unique"));
    }
}
