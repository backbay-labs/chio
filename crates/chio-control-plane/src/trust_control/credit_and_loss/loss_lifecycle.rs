use super::*;

#[derive(Debug, Clone)]
pub(crate) struct CreditLossLifecycleAccountingState {
    pub(crate) currency: String,
    pub(crate) delinquent_units: u64,
    pub(crate) recovered_units: u64,
    pub(crate) reserve_released_units: u64,
    pub(crate) reserve_slashed_units: u64,
    pub(crate) written_off_units: u64,
}

impl CreditLossLifecycleAccountingState {
    pub(super) fn outstanding_delinquent_units(&self) -> u64 {
        self.delinquent_units.saturating_sub(
            self.recovered_units
                .saturating_add(self.written_off_units)
                .saturating_add(self.reserve_slashed_units),
        )
    }

    fn remaining_reserve_units(&self, total_reserve_units: u64) -> u64 {
        total_reserve_units.saturating_sub(
            self.reserve_released_units
                .saturating_add(self.reserve_slashed_units),
        )
    }
}

fn credit_loss_lifecycle_control_supported(kind: CreditLossLifecycleEventKind) -> bool {
    matches!(
        kind,
        CreditLossLifecycleEventKind::ReserveRelease | CreditLossLifecycleEventKind::ReserveSlash
    )
}

fn credit_loss_lifecycle_reserve_source_query(bond: &SignedCreditBond) -> CapitalBookQuery {
    CapitalBookQuery {
        capability_id: bond.body.report.filters.capability_id.clone(),
        agent_subject: bond.body.report.filters.agent_subject.clone(),
        tool_server: bond.body.report.filters.tool_server.clone(),
        tool_name: bond.body.report.filters.tool_name.clone(),
        since: bond.body.report.filters.since,
        until: bond.body.report.filters.until,
        receipt_limit: Some(chio_kernel::MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT),
        facility_limit: Some(MAX_CREDIT_FACILITY_LIST_LIMIT),
        bond_limit: Some(MAX_CREDIT_BOND_LIST_LIMIT),
        loss_event_limit: Some(MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT),
    }
}

fn resolve_credit_loss_lifecycle_reserve_source(
    receipt_store: &SqliteReceiptStore,
    bond: &SignedCreditBond,
) -> Result<CapitalBookSource, TrustHttpError> {
    let capital_book = build_capital_book_report_from_store(
        receipt_store,
        &credit_loss_lifecycle_reserve_source_query(bond),
    )?;
    capital_book
        .sources
        .into_iter()
        .find(|source| {
            source.kind == CapitalBookSourceKind::ReserveBook
                && source.bond_id.as_deref() == Some(bond.body.bond_id.as_str())
        })
        .ok_or_else(|| {
            TrustHttpError::new(
                StatusCode::CONFLICT,
                format!(
                    "credit reserve control requires one reserve-book source for bond `{}`",
                    bond.body.bond_id
                ),
            )
        })
}

pub(crate) fn build_credit_loss_lifecycle_report_from_store(
    receipt_store: &SqliteReceiptStore,
    query: &CreditLossLifecycleQuery,
) -> Result<CreditLossLifecycleReport, TrustHttpError> {
    query.validate().map_err(TrustHttpError::bad_request)?;

    let bond_row = receipt_store
        .resolve_credit_bond(&query.bond_id)
        .map_err(trust_http_error_from_receipt_store)?
        .ok_or_else(|| {
            TrustHttpError::new(
                StatusCode::NOT_FOUND,
                format!("credit bond `{}` not found", query.bond_id),
            )
        })?;
    let bond = &bond_row.bond;
    let terms = bond.body.report.terms.as_ref().ok_or_else(|| {
        TrustHttpError::new(
            StatusCode::CONFLICT,
            format!(
                "credit bond `{}` is missing terms required for loss lifecycle accounting",
                query.bond_id
            ),
        )
    })?;
    let currency = terms.collateral_amount.currency.clone();

    let lifecycle_history = receipt_store
        .query_credit_loss_lifecycle(&CreditLossLifecycleListQuery {
            event_id: None,
            bond_id: Some(query.bond_id.clone()),
            facility_id: None,
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            event_kind: None,
            limit: Some(MAX_CREDIT_LOSS_LIFECYCLE_LIST_LIMIT),
        })
        .map_err(trust_http_error_from_receipt_store)?;
    let accounting = compute_credit_loss_lifecycle_accounting(&currency, &lifecycle_history)
        .map_err(|message| TrustHttpError::new(StatusCode::CONFLICT, message))?;
    let loss_query = BehavioralFeedQuery {
        capability_id: bond.body.report.filters.capability_id.clone(),
        agent_subject: bond.body.report.filters.agent_subject.clone(),
        tool_server: bond.body.report.filters.tool_server.clone(),
        tool_name: bond.body.report.filters.tool_name.clone(),
        since: bond.body.report.filters.since,
        until: bond.body.report.filters.until,
        receipt_limit: Some(chio_kernel::MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT),
        read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
    };
    let (_, recent_loss_receipts) = receipt_store
        .query_recent_credit_loss_receipts(
            &loss_query,
            chio_kernel::MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT,
        )
        .map_err(trust_http_error_from_receipt_store)?;
    let (current_outstanding_loss_units, current_loss_evidence_refs) =
        build_credit_loss_lifecycle_outstanding_loss_state(&recent_loss_receipts, &currency)?;

    let exposure = build_exposure_ledger_report(receipt_store, &bond.body.report.filters)?;
    if exposure.summary.mixed_currency_book {
        return Err(TrustHttpError::new(
            StatusCode::CONFLICT,
            "credit loss lifecycle requires one coherent currency book because Chio does not auto-net lifecycle accounting across currencies"
                .to_string(),
        ));
    }
    let position = exposure
        .positions
        .iter()
        .find(|position| position.currency == currency)
        .cloned()
        .unwrap_or_else(|| empty_exposure_position(&currency));
    let outstanding_delinquent_units = accounting.outstanding_delinquent_units();
    let releaseable_reserve_units =
        accounting.remaining_reserve_units(terms.reserve_requirement_amount.units);
    let current_outstanding_exposure_units =
        credit_bond_outstanding_units(&position).max(current_outstanding_loss_units);
    let recordable_delinquency_units =
        current_outstanding_loss_units.saturating_sub(accounting.delinquent_units);
    let unresolved_live_exposure_units =
        current_outstanding_exposure_units.saturating_sub(accounting.delinquent_units);

    let (event_amount, projected_bond_lifecycle_state, findings) = match query.event_kind {
        CreditLossLifecycleEventKind::Delinquency => {
            if bond_row.lifecycle_state != CreditBondLifecycleState::Active {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "credit loss delinquency requires active bond `{}`",
                        query.bond_id
                    ),
                ));
            }
            if recordable_delinquency_units == 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit loss delinquency requires new outstanding failed or delinquent bonded exposure"
                        .to_string(),
                ));
            }
            let event_amount = match query.amount.as_ref() {
                Some(amount) => {
                    ensure_credit_loss_lifecycle_currency(amount, &currency)?;
                    if amount.units > recordable_delinquency_units {
                        return Err(TrustHttpError::new(
                            StatusCode::CONFLICT,
                            format!(
                                "credit loss delinquency amount {} exceeds recordable outstanding loss {}",
                                amount.units, recordable_delinquency_units
                            ),
                        ));
                    }
                    amount.clone()
                }
                None => MonetaryAmount {
                    units: recordable_delinquency_units,
                    currency: currency.clone(),
                },
            };

            (
                Some(event_amount),
                CreditBondLifecycleState::Impaired,
                vec![CreditLossLifecycleFinding {
                    code: CreditLossLifecycleReasonCode::DelinquencyRecorded,
                    description:
                        "new outstanding bonded loss has been recorded as delinquent against the bond"
                            .to_string(),
                    evidence_refs: current_loss_evidence_refs,
                }],
            )
        }
        CreditLossLifecycleEventKind::Recovery => {
            if outstanding_delinquent_units == 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit recovery requires outstanding delinquent amount".to_string(),
                ));
            }
            let amount = query.amount.as_ref().ok_or_else(|| {
                TrustHttpError::bad_request(
                    "credit recovery requires --amount-units and --amount-currency",
                )
            })?;
            ensure_credit_loss_lifecycle_currency(amount, &currency)?;
            if amount.units > outstanding_delinquent_units {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "credit recovery amount {} exceeds outstanding delinquent amount {}",
                        amount.units, outstanding_delinquent_units
                    ),
                ));
            }
            (
                Some(amount.clone()),
                bond_row.lifecycle_state,
                vec![CreditLossLifecycleFinding {
                    code: CreditLossLifecycleReasonCode::RecoveryRecorded,
                    description:
                        "recovery has been recorded against previously delinquent bonded exposure"
                            .to_string(),
                    evidence_refs: credit_loss_lifecycle_transition_evidence(
                        bond,
                        &lifecycle_history,
                        CreditLossLifecycleEventKind::Delinquency,
                    ),
                }],
            )
        }
        CreditLossLifecycleEventKind::ReserveRelease => {
            if outstanding_delinquent_units > 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit reserve release requires outstanding delinquency to be cleared first"
                        .to_string(),
                ));
            }
            if unresolved_live_exposure_units > 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit reserve release requires no unbooked outstanding exposure to remain"
                        .to_string(),
                ));
            }
            if releaseable_reserve_units == 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit reserve release is unavailable because the reserve is already fully released"
                        .to_string(),
                ));
            }
            let event_amount = match query.amount.as_ref() {
                Some(amount) => {
                    ensure_credit_loss_lifecycle_currency(amount, &currency)?;
                    if amount.units > releaseable_reserve_units {
                        return Err(TrustHttpError::new(
                            StatusCode::CONFLICT,
                            format!(
                                "credit reserve release amount {} exceeds releasable reserve {}",
                                amount.units, releaseable_reserve_units
                            ),
                        ));
                    }
                    amount.clone()
                }
                None => MonetaryAmount {
                    units: releaseable_reserve_units,
                    currency: currency.clone(),
                },
            };
            (
                Some(event_amount),
                CreditBondLifecycleState::Released,
                vec![CreditLossLifecycleFinding {
                    code: CreditLossLifecycleReasonCode::ReserveReleased,
                    description:
                        "reserve backing has been explicitly released after delinquency was cleared"
                            .to_string(),
                    evidence_refs: credit_loss_lifecycle_transition_evidence(
                        bond,
                        &lifecycle_history,
                        CreditLossLifecycleEventKind::Recovery,
                    ),
                }],
            )
        }
        CreditLossLifecycleEventKind::ReserveSlash => {
            if outstanding_delinquent_units == 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit reserve slash requires outstanding delinquent amount".to_string(),
                ));
            }
            if releaseable_reserve_units == 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit reserve slash is unavailable because the reserve is fully exhausted or released"
                        .to_string(),
                ));
            }
            let max_slash_units = releaseable_reserve_units.min(outstanding_delinquent_units);
            let event_amount = match query.amount.as_ref() {
                Some(amount) => {
                    ensure_credit_loss_lifecycle_currency(amount, &currency)?;
                    if amount.units > max_slash_units {
                        return Err(TrustHttpError::new(
                            StatusCode::CONFLICT,
                            format!(
                                "credit reserve slash amount {} exceeds slashable reserve {}",
                                amount.units, max_slash_units
                            ),
                        ));
                    }
                    amount.clone()
                }
                None => MonetaryAmount {
                    units: max_slash_units,
                    currency: currency.clone(),
                },
            };
            (
                Some(event_amount),
                CreditBondLifecycleState::Impaired,
                vec![CreditLossLifecycleFinding {
                    code: CreditLossLifecycleReasonCode::ReserveSlashed,
                    description:
                        "reserve backing has been explicitly slashed against outstanding delinquent exposure"
                            .to_string(),
                    evidence_refs: credit_loss_lifecycle_transition_evidence(
                        bond,
                        &lifecycle_history,
                        CreditLossLifecycleEventKind::Delinquency,
                    ),
                }],
            )
        }
        CreditLossLifecycleEventKind::WriteOff => {
            if outstanding_delinquent_units == 0 {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit write-off requires outstanding delinquent amount".to_string(),
                ));
            }
            let amount = query.amount.as_ref().ok_or_else(|| {
                TrustHttpError::bad_request(
                    "credit write-off requires --amount-units and --amount-currency",
                )
            })?;
            ensure_credit_loss_lifecycle_currency(amount, &currency)?;
            if amount.units > outstanding_delinquent_units {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "credit write-off amount {} exceeds outstanding delinquent amount {}",
                        amount.units, outstanding_delinquent_units
                    ),
                ));
            }
            (
                Some(amount.clone()),
                CreditBondLifecycleState::Impaired,
                vec![CreditLossLifecycleFinding {
                    code: CreditLossLifecycleReasonCode::WriteOffRecorded,
                    description: "outstanding delinquent exposure has been explicitly written off"
                        .to_string(),
                    evidence_refs: credit_loss_lifecycle_transition_evidence(
                        bond,
                        &lifecycle_history,
                        CreditLossLifecycleEventKind::Delinquency,
                    ),
                }],
            )
        }
    };

    Ok(CreditLossLifecycleReport {
        schema: CREDIT_LOSS_LIFECYCLE_REPORT_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        query: query.clone(),
        summary: chio_kernel::CreditLossLifecycleSummary {
            bond_id: bond.body.bond_id.clone(),
            facility_id: bond.body.report.latest_facility_id.clone(),
            capability_id: bond.body.report.filters.capability_id.clone(),
            agent_subject: bond.body.report.filters.agent_subject.clone(),
            tool_server: bond.body.report.filters.tool_server.clone(),
            tool_name: bond.body.report.filters.tool_name.clone(),
            current_bond_lifecycle_state: bond_row.lifecycle_state,
            projected_bond_lifecycle_state,
            current_delinquent_amount: amount_if_nonzero(accounting.delinquent_units, &currency),
            current_recovered_amount: amount_if_nonzero(accounting.recovered_units, &currency),
            current_written_off_amount: amount_if_nonzero(accounting.written_off_units, &currency),
            current_released_reserve_amount: amount_if_nonzero(
                accounting.reserve_released_units,
                &currency,
            ),
            current_slashed_reserve_amount: amount_if_nonzero(
                accounting.reserve_slashed_units,
                &currency,
            ),
            outstanding_delinquent_amount: amount_if_nonzero(
                outstanding_delinquent_units,
                &currency,
            ),
            releaseable_reserve_amount: amount_if_nonzero(releaseable_reserve_units, &currency),
            reserve_control_source_id: None,
            execution_state: None,
            appeal_state: None,
            appeal_window_ends_at: None,
            event_amount,
        },
        support_boundary: CreditLossLifecycleSupportBoundary::default(),
        findings,
    })
}

pub(crate) fn issue_signed_credit_loss_lifecycle_detailed(
    receipt_db_path: &Path,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &CreditLossLifecycleIssueRequest,
) -> Result<SignedCreditLossLifecycle, TrustHttpError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    let mut report = build_credit_loss_lifecycle_report_from_store(&receipt_store, &request.query)?;
    let issued_at = unix_timestamp_now();
    let (
        reserve_control_source_id,
        authority_chain,
        execution_window,
        rail,
        observed_execution,
        reconciled_state,
        execution_state,
        appeal_state,
        appeal_window_ends_at,
        description,
    ) = if credit_loss_lifecycle_control_supported(request.query.event_kind) {
        let execution_window = request.execution_window.clone().ok_or_else(|| {
            TrustHttpError::bad_request("credit reserve control issuance requires executionWindow")
        })?;
        let rail = request.rail.clone().ok_or_else(|| {
            TrustHttpError::bad_request("credit reserve control issuance requires rail")
        })?;
        validate_capital_execution_envelope(
            &request.authority_chain,
            &execution_window,
            &rail,
            issued_at,
        )?;
        let bond_row = receipt_store
            .resolve_credit_bond(&request.query.bond_id)
            .map_err(trust_http_error_from_receipt_store)?
            .ok_or_else(|| {
                TrustHttpError::new(
                    StatusCode::NOT_FOUND,
                    format!("credit bond `{}` not found", request.query.bond_id),
                )
            })?;
        let reserve_source =
            resolve_credit_loss_lifecycle_reserve_source(&receipt_store, &bond_row.bond)?;
        let owner_role = capital_execution_role_from_book_role(reserve_source.owner_role);
        ensure_capital_execution_owner_authority(&request.authority_chain, owner_role)?;
        let event_amount = report.summary.event_amount.as_ref().ok_or_else(|| {
            TrustHttpError::new(
                StatusCode::CONFLICT,
                "credit reserve control requires a computed event amount".to_string(),
            )
        })?;
        let reconciled_state = if let Some(observed_execution) = &request.observed_execution {
            if &observed_execution.amount != event_amount {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit reserve control observedExecution amount does not match event amount",
                ));
            }
            if observed_execution.observed_at < execution_window.not_before
                || observed_execution.observed_at > execution_window.not_after
            {
                return Err(TrustHttpError::new(
                    StatusCode::CONFLICT,
                    "credit reserve control observedExecution timestamp falls outside the execution window",
                ));
            }
            Some(CapitalExecutionReconciledState::Matched)
        } else {
            Some(CapitalExecutionReconciledState::NotObserved)
        };
        let execution_state = Some(if request.observed_execution.is_some() {
            CreditReserveControlExecutionState::Executed
        } else {
            CreditReserveControlExecutionState::PendingExecution
        });
        let appeal_state = Some(match request.appeal_window_ends_at {
            Some(ends_at) => {
                if ends_at < issued_at {
                    return Err(TrustHttpError::bad_request(
                        "credit reserve control appealWindowEndsAt must be >= issuance time",
                    ));
                }
                if ends_at > issued_at {
                    CreditReserveControlAppealState::Open
                } else {
                    CreditReserveControlAppealState::Closed
                }
            }
            None => CreditReserveControlAppealState::Unsupported,
        });
        report.summary.reserve_control_source_id = Some(reserve_source.source_id.clone());
        report.summary.execution_state = execution_state;
        report.summary.appeal_state = appeal_state;
        report.summary.appeal_window_ends_at = request.appeal_window_ends_at;
        (
            Some(reserve_source.source_id),
            request.authority_chain.clone(),
            Some(execution_window),
            Some(rail),
            request.observed_execution.clone(),
            reconciled_state,
            execution_state,
            appeal_state,
            request.appeal_window_ends_at,
            Some(request.description.clone().unwrap_or_else(|| {
                format!(
                    "{:?} reserve control for bond `{}`",
                    request.query.event_kind, request.query.bond_id
                )
            })),
        )
    } else {
        if !request.authority_chain.is_empty()
            || request.execution_window.is_some()
            || request.rail.is_some()
            || request.observed_execution.is_some()
            || request.appeal_window_ends_at.is_some()
            || request.description.is_some()
        {
            return Err(TrustHttpError::bad_request(
                "execution metadata is only valid for reserve release and reserve slash lifecycle issuance",
            ));
        }
        (
            None,
            Vec::new(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    };
    let event_id_input = canonical_json_bytes(&(
        CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA,
        issued_at,
        &report,
        &reserve_control_source_id,
        &authority_chain,
        &execution_window,
        &rail,
        &observed_execution,
        &appeal_window_ends_at,
        &description,
    ))
    .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let event = CreditLossLifecycleArtifact {
        schema: CREDIT_LOSS_LIFECYCLE_ARTIFACT_SCHEMA.to_string(),
        event_id: format!("cll-{}", sha256_hex(&event_id_input)),
        issued_at,
        bond_id: report.query.bond_id.clone(),
        event_kind: report.query.event_kind,
        projected_bond_lifecycle_state: report.summary.projected_bond_lifecycle_state,
        reserve_control_source_id,
        authority_chain,
        execution_window,
        rail,
        observed_execution,
        reconciled_state,
        execution_state,
        appeal_state,
        appeal_window_ends_at,
        description,
        report,
    };
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let signed = SignedCreditLossLifecycle::sign(event, &keypair)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    receipt_store
        .record_credit_loss_lifecycle(&signed)
        .map_err(trust_http_error_from_receipt_store)?;
    Ok(signed)
}
