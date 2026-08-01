use super::reports::ResolvedBudgetGrant;
use super::*;

pub(crate) fn latest_credit_facility_snapshot(
    receipt_store: &SqliteReceiptStore,
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
) -> Result<Option<CreditProviderFacilitySnapshot>, TrustHttpError> {
    let report = receipt_store
        .query_credit_facilities(&CreditFacilityListQuery {
            facility_id: None,
            capability_id: capability_id.map(ToOwned::to_owned),
            agent_subject: agent_subject.map(ToOwned::to_owned),
            tool_server: tool_server.map(ToOwned::to_owned),
            tool_name: tool_name.map(ToOwned::to_owned),
            disposition: None,
            lifecycle_state: None,
            limit: Some(MAX_CREDIT_FACILITY_LIST_LIMIT),
        })
        .map_err(trust_http_error_from_receipt_store)?;
    Ok(report
        .facilities
        .into_iter()
        .next()
        .map(|row| CreditProviderFacilitySnapshot {
            facility_id: row.facility.body.facility_id,
            issued_at: row.facility.body.issued_at,
            expires_at: row.facility.body.expires_at,
            disposition: row.facility.body.report.disposition,
            lifecycle_state: row.lifecycle_state,
            credit_limit: row
                .facility
                .body
                .report
                .terms
                .as_ref()
                .map(|terms| terms.credit_limit.clone()),
            supersedes_facility_id: row.facility.body.supersedes_facility_id,
            signer_key: row.facility.signer_key.to_hex(),
        }))
}

pub(crate) fn latest_active_granted_credit_facility(
    receipt_store: &SqliteReceiptStore,
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    tool_server: Option<&str>,
    tool_name: Option<&str>,
) -> Result<Option<SignedCreditFacility>, TrustHttpError> {
    let report = receipt_store
        .query_credit_facilities(&CreditFacilityListQuery {
            facility_id: None,
            capability_id: capability_id.map(ToOwned::to_owned),
            agent_subject: agent_subject.map(ToOwned::to_owned),
            tool_server: tool_server.map(ToOwned::to_owned),
            tool_name: tool_name.map(ToOwned::to_owned),
            disposition: Some(CreditFacilityDisposition::Grant),
            lifecycle_state: Some(CreditFacilityLifecycleState::Active),
            limit: Some(1),
        })
        .map_err(trust_http_error_from_receipt_store)?;
    Ok(report.facilities.into_iter().next().map(|row| row.facility))
}

pub(crate) fn build_credit_bond_terms(
    position: &ExposureLedgerCurrencyPosition,
    facility_terms: &CreditFacilityTerms,
    facility_id: String,
) -> CreditBondTerms {
    let outstanding_exposure_units = credit_bond_outstanding_units(position);
    let collateral_units = credit_bond_reserve_units(
        facility_terms.credit_limit.units,
        facility_terms.reserve_ratio_bps,
    );
    let reserve_requirement_units = collateral_units.max(credit_bond_reserve_units(
        outstanding_exposure_units,
        facility_terms.reserve_ratio_bps,
    ));
    let coverage_ratio_bps = if reserve_requirement_units == 0 {
        10_000
    } else {
        (((collateral_units as u128) * 10_000) / (reserve_requirement_units as u128))
            .min(u16::MAX as u128) as u16
    };

    CreditBondTerms {
        facility_id,
        credit_limit: facility_terms.credit_limit.clone(),
        collateral_amount: MonetaryAmount {
            units: collateral_units,
            currency: position.currency.clone(),
        },
        reserve_requirement_amount: MonetaryAmount {
            units: reserve_requirement_units,
            currency: position.currency.clone(),
        },
        outstanding_exposure_amount: MonetaryAmount {
            units: outstanding_exposure_units,
            currency: position.currency.clone(),
        },
        reserve_ratio_bps: facility_terms.reserve_ratio_bps,
        coverage_ratio_bps,
        capital_source: facility_terms.capital_source,
    }
}

pub(crate) fn build_credit_bond_findings(
    scorecard: &CreditScorecardReport,
    exposure: &ExposureLedgerReport,
    prerequisites: &CreditBondPrerequisites,
    disposition: CreditBondDisposition,
    pending_backlog: bool,
    failed_backlog: bool,
    under_collateralized: bool,
) -> Vec<CreditBondFinding> {
    let mut findings = Vec::new();
    if prerequisites.active_facility_required && !prerequisites.active_facility_met {
        findings.push(CreditBondFinding {
            code: CreditBondReasonCode::ActiveFacilityMissing,
            description:
                "reserve-backed autonomy requires an active granted facility for the requested exposure"
                    .to_string(),
            evidence_refs: credit_bond_receipt_evidence_from_exposure(exposure, |receipt| {
                receipt.action_required
                    || receipt.settlement_status == SettlementStatus::Pending
                    || receipt.settlement_status == SettlementStatus::Failed
            }),
        });
    }
    if pending_backlog {
        findings.push(CreditBondFinding {
            code: CreditBondReasonCode::PendingSettlementBacklog,
            description:
                "pending settlement exposure remains open, so Chio keeps reserve state locked"
                    .to_string(),
            evidence_refs: if credit_facility_has_reason(
                scorecard,
                CreditScorecardReasonCode::PendingSettlementBacklog,
            ) {
                credit_facility_evidence_for_reason(
                    scorecard,
                    CreditScorecardReasonCode::PendingSettlementBacklog,
                )
            } else {
                credit_bond_receipt_evidence_from_exposure(exposure, |receipt| {
                    receipt.settlement_status == SettlementStatus::Pending
                })
            },
        });
    }
    if failed_backlog {
        findings.push(CreditBondFinding {
            code: CreditBondReasonCode::FailedSettlementBacklog,
            description:
                "failed settlement exposure remains unresolved, so Chio marks the bond impaired"
                    .to_string(),
            evidence_refs: if credit_facility_has_reason(
                scorecard,
                CreditScorecardReasonCode::FailedSettlementBacklog,
            ) {
                credit_facility_evidence_for_reason(
                    scorecard,
                    CreditScorecardReasonCode::FailedSettlementBacklog,
                )
            } else {
                credit_bond_receipt_evidence_from_exposure(exposure, |receipt| {
                    receipt.settlement_status == SettlementStatus::Failed
                })
            },
        });
    }
    let provisional_loss_refs = credit_bond_receipt_evidence_from_exposure(exposure, |receipt| {
        receipt
            .provisional_loss_amount
            .as_ref()
            .is_some_and(|amount| amount.units > 0)
    });
    if !provisional_loss_refs.is_empty() || failed_backlog {
        findings.push(CreditBondFinding {
            code: CreditBondReasonCode::ProvisionalLossOutstanding,
            description: "provisional loss remains outstanding in the selected exposure window"
                .to_string(),
            evidence_refs: if provisional_loss_refs.is_empty() {
                credit_bond_receipt_evidence_from_exposure(exposure, |receipt| {
                    receipt.settlement_status == SettlementStatus::Failed
                })
            } else {
                provisional_loss_refs
            },
        });
    }
    if under_collateralized {
        findings.push(CreditBondFinding {
            code: CreditBondReasonCode::UnderCollateralized,
            description: "required reserve exceeded the collateral held by the active facility"
                .to_string(),
            evidence_refs: credit_bond_receipt_evidence_from_exposure(exposure, |receipt| {
                receipt.action_required
            }),
        });
    }
    let disposition_finding = match disposition {
        CreditBondDisposition::Lock => Some((
            CreditBondReasonCode::ReserveLocked,
            "outstanding exposure is present, so Chio locks the reserve against the active facility",
        )),
        CreditBondDisposition::Hold => Some((
            CreditBondReasonCode::ReserveHeld,
            "the facility remains active with no current outstanding exposure, so Chio holds reserve state",
        )),
        CreditBondDisposition::Release => Some((
            CreditBondReasonCode::ReserveReleased,
            "no active facility-backed exposure remains, so Chio releases the reserve state",
        )),
        CreditBondDisposition::Impair => None,
    };
    if let Some((code, description)) = disposition_finding {
        findings.push(CreditBondFinding {
            code,
            description: description.to_string(),
            evidence_refs: credit_bond_receipt_evidence_from_exposure(exposure, |_| true),
        });
    }

    findings
}

fn credit_bond_receipt_evidence_from_exposure<F>(
    exposure: &ExposureLedgerReport,
    predicate: F,
) -> Vec<CreditScorecardEvidenceReference>
where
    F: Fn(&ExposureLedgerReceiptEntry) -> bool,
{
    let mut evidence_refs = Vec::new();
    for receipt in &exposure.receipts {
        if !predicate(receipt) {
            continue;
        }
        for reference in &receipt.evidence_refs {
            let kind = match reference.kind {
                ExposureLedgerEvidenceKind::Receipt => CreditScorecardEvidenceKind::Receipt,
                ExposureLedgerEvidenceKind::SettlementReconciliation => {
                    CreditScorecardEvidenceKind::SettlementReconciliation
                }
                ExposureLedgerEvidenceKind::MeteredBillingReconciliation => continue,
                ExposureLedgerEvidenceKind::UnderwritingDecision => {
                    CreditScorecardEvidenceKind::UnderwritingDecision
                }
            };
            evidence_refs.push(CreditScorecardEvidenceReference {
                kind,
                reference_id: reference.reference_id.clone(),
                observed_at: reference.observed_at,
                locator: reference.locator.clone(),
            });
        }
    }
    evidence_refs
}

pub(crate) fn compute_credit_loss_lifecycle_accounting(
    currency: &str,
    lifecycle_history: &CreditLossLifecycleListReport,
) -> Result<CreditLossLifecycleAccountingState, String> {
    let mut state = CreditLossLifecycleAccountingState {
        currency: currency.to_string(),
        delinquent_units: 0,
        recovered_units: 0,
        reserve_released_units: 0,
        reserve_slashed_units: 0,
        written_off_units: 0,
    };

    for row in &lifecycle_history.events {
        let Some(amount) = row.event.body.report.summary.event_amount.as_ref() else {
            continue;
        };
        if amount.currency != state.currency {
            return Err(format!(
                "credit loss lifecycle `{}` mixes currency `{}` with `{}`",
                row.event.body.event_id, amount.currency, state.currency
            ));
        }
        match row.event.body.event_kind {
            CreditLossLifecycleEventKind::Delinquency => {
                state.delinquent_units = state.delinquent_units.saturating_add(amount.units);
            }
            CreditLossLifecycleEventKind::Recovery => {
                state.recovered_units = state.recovered_units.saturating_add(amount.units);
            }
            CreditLossLifecycleEventKind::ReserveRelease => {
                state.reserve_released_units =
                    state.reserve_released_units.saturating_add(amount.units);
            }
            CreditLossLifecycleEventKind::ReserveSlash => {
                state.reserve_slashed_units =
                    state.reserve_slashed_units.saturating_add(amount.units);
            }
            CreditLossLifecycleEventKind::WriteOff => {
                state.written_off_units = state.written_off_units.saturating_add(amount.units);
            }
        }
    }

    Ok(state)
}

pub(crate) fn ensure_credit_loss_lifecycle_currency(
    amount: &MonetaryAmount,
    currency: &str,
) -> Result<(), TrustHttpError> {
    if amount.currency != currency {
        return Err(TrustHttpError::new(
            StatusCode::CONFLICT,
            format!(
                "credit loss lifecycle currency `{}` does not match bond currency `{}`",
                amount.currency, currency
            ),
        ));
    }
    Ok(())
}

pub(crate) fn amount_if_nonzero(units: u64, currency: &str) -> Option<MonetaryAmount> {
    (units > 0).then(|| MonetaryAmount {
        units,
        currency: currency.to_string(),
    })
}

pub(crate) fn empty_exposure_position(currency: &str) -> ExposureLedgerCurrencyPosition {
    ExposureLedgerCurrencyPosition {
        currency: currency.to_string(),
        governed_max_exposure_units: 0,
        reserved_units: 0,
        settled_units: 0,
        pending_units: 0,
        failed_units: 0,
        provisional_loss_units: 0,
        recovered_units: 0,
        quoted_premium_units: 0,
        active_quoted_premium_units: 0,
    }
}

pub(crate) fn build_credit_loss_lifecycle_outstanding_loss_state(
    receipts: &[chio_kernel::BehavioralFeedReceiptRow],
    currency: &str,
) -> Result<(u64, Vec<CreditScorecardEvidenceReference>), TrustHttpError> {
    let mut outstanding_units = 0_u64;
    let mut evidence_refs = Vec::new();
    let mut seen = BTreeSet::new();

    for row in receipts {
        let entry = build_exposure_ledger_receipt_entry(row)?;
        let Some(loss_amount) = entry
            .provisional_loss_amount
            .as_ref()
            .filter(|amount| amount.currency == currency && amount.units > 0)
        else {
            continue;
        };
        outstanding_units = outstanding_units.saturating_add(loss_amount.units);
        for reference in &entry.evidence_refs {
            let kind = match reference.kind {
                ExposureLedgerEvidenceKind::Receipt => CreditScorecardEvidenceKind::Receipt,
                ExposureLedgerEvidenceKind::SettlementReconciliation => {
                    CreditScorecardEvidenceKind::SettlementReconciliation
                }
                ExposureLedgerEvidenceKind::MeteredBillingReconciliation
                | ExposureLedgerEvidenceKind::UnderwritingDecision => continue,
            };
            let key = format!(
                "{kind:?}|{}|{:?}|{:?}",
                reference.reference_id, reference.observed_at, reference.locator
            );
            if seen.insert(key) {
                evidence_refs.push(CreditScorecardEvidenceReference {
                    kind,
                    reference_id: reference.reference_id.clone(),
                    observed_at: reference.observed_at,
                    locator: reference.locator.clone(),
                });
            }
        }
    }

    Ok((outstanding_units, evidence_refs))
}

pub(crate) fn credit_loss_lifecycle_transition_evidence(
    bond: &SignedCreditBond,
    lifecycle_history: &CreditLossLifecycleListReport,
    event_kind: CreditLossLifecycleEventKind,
) -> Vec<CreditScorecardEvidenceReference> {
    let mut evidence_refs = vec![CreditScorecardEvidenceReference {
        kind: CreditScorecardEvidenceKind::CreditBond,
        reference_id: bond.body.bond_id.clone(),
        observed_at: Some(bond.body.issued_at),
        locator: Some(format!("credit-bond:{}", bond.body.bond_id)),
    }];
    for row in &lifecycle_history.events {
        if row.event.body.event_kind != event_kind {
            continue;
        }
        evidence_refs.push(CreditScorecardEvidenceReference {
            kind: CreditScorecardEvidenceKind::CreditLossLifecycle,
            reference_id: row.event.body.event_id.clone(),
            observed_at: Some(row.event.body.issued_at),
            locator: Some(format!("credit-loss-lifecycle:{}", row.event.body.event_id)),
        });
    }
    evidence_refs
}

pub(crate) fn credit_bond_outstanding_units(position: &ExposureLedgerCurrencyPosition) -> u64 {
    let unsettled_units = position.pending_units.saturating_add(position.failed_units);
    let net_provisional_loss_units = position
        .provisional_loss_units
        .saturating_sub(position.recovered_units);
    position
        .reserved_units
        .max(unsettled_units)
        .max(net_provisional_loss_units)
}

pub(crate) fn credit_bond_reserve_units(units: u64, ratio_bps: u16) -> u64 {
    if units == 0 || ratio_bps == 0 {
        0
    } else {
        (((units as u128) * (ratio_bps as u128)).div_ceil(10_000_u128)).min(u64::MAX as u128) as u64
    }
}

pub(crate) fn credit_bond_ttl_seconds(report: &CreditBondReport) -> u64 {
    match report.disposition {
        CreditBondDisposition::Lock | CreditBondDisposition::Hold => 7 * 86_400,
        CreditBondDisposition::Release | CreditBondDisposition::Impair => 86_400,
    }
}

pub(crate) fn build_credit_recent_loss_history(
    matching_loss_events: u64,
    receipts: &[chio_kernel::BehavioralFeedReceiptRow],
    limit: usize,
) -> Result<CreditRecentLossHistory, TrustHttpError> {
    let mut entries = receipts
        .iter()
        .map(|row| {
            let entry = build_exposure_ledger_receipt_entry(row)?;
            Ok::<CreditRecentLossEntry, TrustHttpError>(CreditRecentLossEntry {
                receipt_id: entry.receipt_id,
                observed_at: entry.timestamp,
                settlement_status: entry.settlement_status,
                financial_amount: entry.financial_amount,
                provisional_loss_amount: entry.provisional_loss_amount,
                recovered_amount: entry.recovered_amount,
                evidence_refs: entry.evidence_refs,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by(|left, right| {
        right
            .observed_at
            .cmp(&left.observed_at)
            .then_with(|| left.receipt_id.cmp(&right.receipt_id))
    });
    entries.truncate(limit);
    let summary = CreditRecentLossSummary {
        matching_loss_events,
        returned_loss_events: entries.len() as u64,
        failed_settlement_events: entries
            .iter()
            .filter(|entry| entry.settlement_status == SettlementStatus::Failed)
            .count() as u64,
        provisional_loss_events: entries
            .iter()
            .filter(|entry| entry.provisional_loss_amount.is_some())
            .count() as u64,
        recovered_events: entries
            .iter()
            .filter(|entry| entry.recovered_amount.is_some())
            .count() as u64,
    };
    Ok(CreditRecentLossHistory { summary, entries })
}

pub(crate) fn collect_credit_provider_risk_evidence(
    scorecard: &CreditScorecardReport,
    underwriting_input: &UnderwritingPolicyInput,
) -> Vec<CreditScorecardEvidenceReference> {
    let mut seen = BTreeSet::<String>::new();
    let mut refs = Vec::new();
    let mut push_ref = |reference: CreditScorecardEvidenceReference| {
        let key = format!(
            "{:?}|{}|{:?}|{:?}",
            reference.kind, reference.reference_id, reference.observed_at, reference.locator
        );
        if seen.insert(key) {
            refs.push(reference);
        }
    };

    for reference in scorecard
        .dimensions
        .iter()
        .flat_map(|dimension| dimension.evidence_refs.iter())
        .chain(
            scorecard
                .anomalies
                .iter()
                .flat_map(|anomaly| anomaly.evidence_refs.iter()),
        )
    {
        push_ref(reference.clone());
    }
    for reference in credit_facility_receipt_refs_from_underwriting(underwriting_input) {
        push_ref(reference);
    }
    if let Some(compliance_score) = underwriting_input.compliance_score.as_ref() {
        push_ref(CreditScorecardEvidenceReference {
            kind: CreditScorecardEvidenceKind::ComplianceScore,
            reference_id: compliance_score.agent_id.clone(),
            observed_at: Some(compliance_score.generated_at),
            locator: Some(format!("compliance-score:{}", compliance_score.agent_id)),
        });
    }
    refs
}

pub(crate) fn capital_book_owner_role(
    capital_source: CreditFacilityCapitalSource,
) -> CapitalBookRole {
    match capital_source {
        CreditFacilityCapitalSource::OperatorInternal => CapitalBookRole::OperatorTreasury,
        CreditFacilityCapitalSource::ManualProviderReview => {
            CapitalBookRole::ExternalCapitalProvider
        }
    }
}

pub(crate) fn capital_book_facility_source_id(facility_id: &str) -> String {
    format!("capital-source:facility:{facility_id}")
}

pub(crate) fn capital_book_bond_source_id(bond_id: &str) -> String {
    format!("capital-source:bond:{bond_id}")
}

pub(crate) fn capital_book_facility_evidence(
    facility: &SignedCreditFacility,
) -> CapitalBookEvidenceReference {
    CapitalBookEvidenceReference {
        kind: CapitalBookEvidenceKind::CreditFacility,
        reference_id: facility.body.facility_id.clone(),
        observed_at: Some(facility.body.issued_at),
        locator: Some(format!("credit-facility:{}", facility.body.facility_id)),
    }
}

pub(crate) fn capital_book_bond_evidence(bond: &SignedCreditBond) -> CapitalBookEvidenceReference {
    CapitalBookEvidenceReference {
        kind: CapitalBookEvidenceKind::CreditBond,
        reference_id: bond.body.bond_id.clone(),
        observed_at: Some(bond.body.issued_at),
        locator: Some(format!("credit-bond:{}", bond.body.bond_id)),
    }
}

pub(crate) fn capital_book_loss_event_evidence(
    event: &SignedCreditLossLifecycle,
) -> CapitalBookEvidenceReference {
    CapitalBookEvidenceReference {
        kind: CapitalBookEvidenceKind::CreditLossLifecycle,
        reference_id: event.body.event_id.clone(),
        observed_at: Some(event.body.issued_at),
        locator: Some(format!("credit-loss-lifecycle:{}", event.body.event_id)),
    }
}

pub(crate) fn capital_book_receipt_evidence(
    receipt: &ExposureLedgerReceiptEntry,
) -> Vec<CapitalBookEvidenceReference> {
    let mut evidence_refs = receipt
        .evidence_refs
        .iter()
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
        .collect::<Vec<_>>();
    if evidence_refs.is_empty() {
        evidence_refs.push(CapitalBookEvidenceReference {
            kind: CapitalBookEvidenceKind::Receipt,
            reference_id: receipt.receipt_id.clone(),
            observed_at: Some(receipt.timestamp),
            locator: Some(format!("receipt:{}", receipt.receipt_id)),
        });
    }
    evidence_refs
}

pub(crate) fn build_credit_scorecard_dimensions(
    subject_key: &str,
    exposure: &ExposureLedgerReport,
    inspection: &issuance::LocalReputationInspection,
    exposure_units: f64,
) -> Vec<CreditScorecardDimension> {
    let settlement_penalty = credit_scorecard_penalty_ratio(
        credit_scorecard_total_units(&exposure.positions, |position| {
            position.failed_units.saturating_mul(2) + position.pending_units
        }) as f64
            / 2.0,
        exposure_units,
    );
    let loss_penalty = credit_scorecard_penalty_ratio(
        credit_scorecard_total_units(&exposure.positions, |position| {
            position.provisional_loss_units
        }) as f64,
        exposure_units,
    );
    let reserve_penalty = credit_scorecard_penalty_ratio(
        credit_scorecard_total_units(&exposure.positions, |position| position.reserved_units)
            as f64,
        exposure_units,
    );

    vec![
        CreditScorecardDimension {
            kind: CreditScorecardDimensionKind::ReputationSupport,
            score: Some(round_credit_score_value(inspection.effective_score)),
            weight: 0.40,
            description: "effective local reputation score carried into credit posture".to_string(),
            evidence_refs: vec![credit_scorecard_reputation_ref(subject_key)],
        },
        CreditScorecardDimension {
            kind: CreditScorecardDimensionKind::SettlementDiscipline,
            score: Some(round_credit_score_value(1.0 - settlement_penalty)),
            weight: 0.25,
            description:
                "penalizes pending and failed settlement exposure relative to the governed book"
                    .to_string(),
            evidence_refs: credit_scorecard_receipt_refs(
                &exposure.receipts,
                |row| {
                    matches!(
                        row.settlement_status,
                        SettlementStatus::Pending | SettlementStatus::Failed
                    )
                },
                CreditScorecardEvidenceKind::SettlementReconciliation,
            ),
        },
        CreditScorecardDimension {
            kind: CreditScorecardDimensionKind::LossPressure,
            score: Some(round_credit_score_value(1.0 - loss_penalty)),
            weight: 0.20,
            description:
                "penalizes provisional-loss exposure relative to the governed maximum exposure"
                    .to_string(),
            evidence_refs: credit_scorecard_receipt_refs(
                &exposure.receipts,
                |row| row.provisional_loss_amount.is_some(),
                CreditScorecardEvidenceKind::Receipt,
            ),
        },
        CreditScorecardDimension {
            kind: CreditScorecardDimensionKind::ExposureStewardship,
            score: Some(round_credit_score_value(1.0 - reserve_penalty)),
            weight: 0.15,
            description: "penalizes reserve-heavy exposure that still requires operator follow-up"
                .to_string(),
            evidence_refs: credit_scorecard_receipt_refs(
                &exposure.receipts,
                |row| row.reserve_required_amount.is_some(),
                CreditScorecardEvidenceKind::Receipt,
            ),
        },
    ]
}

pub(crate) fn round_credit_score_value(value: f64) -> f64 {
    (value * 1_000_000.0).round() / 1_000_000.0
}

pub(crate) fn build_credit_scorecard_probation(
    inspection: &issuance::LocalReputationInspection,
    confidence: CreditScorecardConfidence,
) -> CreditScorecardProbationStatus {
    let mut reasons = Vec::new();
    if inspection.probationary_status.below_receipt_target {
        reasons.push(CreditScorecardReasonCode::SparseReceiptHistory);
    }
    if inspection.probationary_status.below_day_target {
        reasons.push(CreditScorecardReasonCode::SparseDayHistory);
    }
    if confidence == CreditScorecardConfidence::Low {
        reasons.push(CreditScorecardReasonCode::LowConfidence);
    }

    CreditScorecardProbationStatus {
        probationary: inspection.probationary || confidence == CreditScorecardConfidence::Low,
        reasons,
        receipt_count: inspection.scorecard.history_depth.receipt_count as u64,
        span_days: inspection.scorecard.history_depth.span_days,
        target_receipt_count: inspection.probationary_receipt_count,
        target_span_days: inspection.probationary_min_days,
    }
}

pub(crate) fn build_credit_scorecard_anomalies(
    subject_key: &str,
    exposure: &ExposureLedgerReport,
    inspection: &issuance::LocalReputationInspection,
    exposure_units: u64,
) -> Vec<CreditScorecardAnomaly> {
    let mut anomalies = Vec::new();

    if exposure.summary.pending_settlement_receipts > 0 {
        anomalies.push(CreditScorecardAnomaly {
            code: CreditScorecardReasonCode::PendingSettlementBacklog,
            severity: CreditScorecardAnomalySeverity::Warning,
            description: format!(
                "credit window contains {} pending settlement receipt(s)",
                exposure.summary.pending_settlement_receipts
            ),
            evidence_refs: credit_scorecard_receipt_refs(
                &exposure.receipts,
                |row| row.settlement_status == SettlementStatus::Pending,
                CreditScorecardEvidenceKind::SettlementReconciliation,
            ),
        });
    }

    if exposure.summary.failed_settlement_receipts > 0 {
        anomalies.push(CreditScorecardAnomaly {
            code: CreditScorecardReasonCode::FailedSettlementBacklog,
            severity: CreditScorecardAnomalySeverity::Critical,
            description: format!(
                "credit window contains {} failed settlement receipt(s)",
                exposure.summary.failed_settlement_receipts
            ),
            evidence_refs: credit_scorecard_receipt_refs(
                &exposure.receipts,
                |row| row.settlement_status == SettlementStatus::Failed,
                CreditScorecardEvidenceKind::SettlementReconciliation,
            ),
        });
    }

    let provisional_loss_units = credit_scorecard_total_units(&exposure.positions, |position| {
        position.provisional_loss_units
    });
    if provisional_loss_units > 0 && provisional_loss_units.saturating_mul(10) >= exposure_units {
        anomalies.push(CreditScorecardAnomaly {
            code: CreditScorecardReasonCode::ProvisionalLossPressure,
            severity: if provisional_loss_units.saturating_mul(4) >= exposure_units {
                CreditScorecardAnomalySeverity::Critical
            } else {
                CreditScorecardAnomalySeverity::Warning
            },
            description: format!(
                "provisional-loss exposure totals {} unit(s) across the requested book",
                provisional_loss_units
            ),
            evidence_refs: credit_scorecard_receipt_refs(
                &exposure.receipts,
                |row| row.provisional_loss_amount.is_some(),
                CreditScorecardEvidenceKind::Receipt,
            ),
        });
    }

    if exposure.summary.mixed_currency_book {
        anomalies.push(CreditScorecardAnomaly {
            code: CreditScorecardReasonCode::MixedCurrencyBook,
            severity: CreditScorecardAnomalySeverity::Info,
            description: "credit book spans multiple currencies and is not netted across them"
                .to_string(),
            evidence_refs: vec![CreditScorecardEvidenceReference {
                kind: CreditScorecardEvidenceKind::ExposureLedger,
                reference_id: subject_key.to_string(),
                observed_at: Some(exposure.generated_at),
                locator: Some(format!("exposure-ledger:{}", subject_key)),
            }],
        });
    }

    if inspection.effective_score < 0.40 {
        anomalies.push(CreditScorecardAnomaly {
            code: CreditScorecardReasonCode::LowReputation,
            severity: CreditScorecardAnomalySeverity::Warning,
            description: format!(
                "effective local reputation score {:.4} is below the guarded credit baseline",
                inspection.effective_score
            ),
            evidence_refs: vec![credit_scorecard_reputation_ref(subject_key)],
        });
    }

    if inspection
        .imported_trust
        .as_ref()
        .is_some_and(|report| report.accepted_count > 0)
    {
        let accepted = inspection
            .imported_trust
            .as_ref()
            .map(|report| report.accepted_count)
            .unwrap_or(0);
        anomalies.push(CreditScorecardAnomaly {
            code: CreditScorecardReasonCode::ImportedTrustDependency,
            severity: CreditScorecardAnomalySeverity::Info,
            description: format!(
                "credit posture depends on {} accepted imported-trust signal(s)",
                accepted
            ),
            evidence_refs: vec![credit_scorecard_reputation_ref(subject_key)],
        });
    }

    if exposure.summary.matching_decisions == 0 {
        anomalies.push(CreditScorecardAnomaly {
            code: CreditScorecardReasonCode::MissingDecisionCoverage,
            severity: CreditScorecardAnomalySeverity::Info,
            description: "no persisted underwriting decisions matched the requested credit window"
                .to_string(),
            evidence_refs: vec![CreditScorecardEvidenceReference {
                kind: CreditScorecardEvidenceKind::ExposureLedger,
                reference_id: subject_key.to_string(),
                observed_at: Some(exposure.generated_at),
                locator: Some(format!("exposure-ledger:{}", subject_key)),
            }],
        });
    }

    anomalies
}

pub(crate) fn resolve_credit_scorecard_confidence(
    inspection: &issuance::LocalReputationInspection,
) -> CreditScorecardConfidence {
    let receipt_count = inspection.scorecard.history_depth.receipt_count as u64;
    let span_days = inspection.scorecard.history_depth.span_days;
    let mut confidence = if receipt_count >= 100 && span_days >= 30 {
        CreditScorecardConfidence::High
    } else if receipt_count >= 25 && span_days >= 7 {
        CreditScorecardConfidence::Medium
    } else {
        CreditScorecardConfidence::Low
    };

    if inspection.scorecard.effective_weight_sum < 0.60 {
        confidence = match confidence {
            CreditScorecardConfidence::High => CreditScorecardConfidence::Medium,
            CreditScorecardConfidence::Medium | CreditScorecardConfidence::Low => {
                CreditScorecardConfidence::Low
            }
        };
    }

    confidence
}

pub(crate) fn resolve_credit_scorecard_band(
    overall_score: f64,
    probationary: bool,
) -> CreditScorecardBand {
    if probationary {
        CreditScorecardBand::Probationary
    } else if overall_score >= 0.85 {
        CreditScorecardBand::Prime
    } else if overall_score >= 0.70 {
        CreditScorecardBand::Standard
    } else if overall_score >= 0.50 {
        CreditScorecardBand::Guarded
    } else {
        CreditScorecardBand::Restricted
    }
}

pub(crate) fn compute_credit_scorecard_overall_score(
    dimensions: &[CreditScorecardDimension],
) -> Option<f64> {
    let mut weighted_sum = 0.0;
    let mut total_weight = 0.0;
    for dimension in dimensions {
        if let Some(score) = dimension.score {
            weighted_sum += score.clamp(0.0, 1.0) * dimension.weight;
            total_weight += dimension.weight;
        }
    }
    (total_weight > 0.0).then_some((weighted_sum / total_weight).clamp(0.0, 1.0))
}

fn credit_scorecard_penalty_ratio(units: f64, denominator: f64) -> f64 {
    if denominator <= 0.0 {
        return 1.0;
    }
    (units / denominator).clamp(0.0, 1.0)
}

pub(crate) fn credit_scorecard_position_denominator(
    positions: &[ExposureLedgerCurrencyPosition],
) -> Option<u64> {
    let governed =
        credit_scorecard_total_units(positions, |position| position.governed_max_exposure_units);
    let settled = credit_scorecard_total_units(positions, |position| position.settled_units);
    let pending = credit_scorecard_total_units(positions, |position| position.pending_units);
    let failed = credit_scorecard_total_units(positions, |position| position.failed_units);
    let denominator = governed.max(settled.saturating_add(pending).saturating_add(failed));
    (denominator > 0).then_some(denominator)
}

fn credit_scorecard_total_units<F>(positions: &[ExposureLedgerCurrencyPosition], units: F) -> u64
where
    F: Fn(&ExposureLedgerCurrencyPosition) -> u64,
{
    positions.iter().map(units).sum()
}

fn credit_scorecard_reputation_ref(subject_key: &str) -> CreditScorecardEvidenceReference {
    CreditScorecardEvidenceReference {
        kind: CreditScorecardEvidenceKind::ReputationInspection,
        reference_id: subject_key.to_string(),
        observed_at: None,
        locator: Some(format!("reputation:{}", subject_key)),
    }
}

fn credit_scorecard_receipt_refs<F>(
    receipts: &[ExposureLedgerReceiptEntry],
    predicate: F,
    kind: CreditScorecardEvidenceKind,
) -> Vec<CreditScorecardEvidenceReference>
where
    F: Fn(&ExposureLedgerReceiptEntry) -> bool,
{
    receipts
        .iter()
        .filter(|row| predicate(row))
        .take(8)
        .map(|row| CreditScorecardEvidenceReference {
            kind,
            reference_id: row.receipt_id.clone(),
            observed_at: Some(row.timestamp),
            locator: Some(format!("receipt:{}", row.receipt_id)),
        })
        .collect()
}

pub fn build_signed_underwriting_policy_input(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    query: &UnderwritingPolicyInputQuery,
) -> Result<SignedUnderwritingPolicyInput, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    // Load the signing keypair up front so its public key can anchor the
    // reputation scoring trust set; an empty set would silently filter every
    // signed receipt out (see chio-reputation::receipt_integrity_valid).
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let trusted_kernel_keys = vec![keypair.public_key().to_hex()];
    let report = build_underwriting_policy_input(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        query,
        chio_kernel::ReceiptReadContext::local_operator_admin_all(),
        &trusted_kernel_keys,
    )
    .map_err(CliError::from)?;
    SignedUnderwritingPolicyInput::sign(report, &keypair).map_err(Into::into)
}

pub fn build_underwriting_decision_report(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    query: &UnderwritingPolicyInputQuery,
    trusted_kernel_keys: &[String],
) -> Result<UnderwritingDecisionReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    build_underwriting_decision_report_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        query,
        chio_kernel::ReceiptReadContext::local_operator_admin_all(),
        trusted_kernel_keys,
    )
    .map_err(CliError::from)
}

pub(crate) fn build_underwriting_decision_report_from_store(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    query: &UnderwritingPolicyInputQuery,
    read_context: chio_kernel::ReceiptReadContext,
    trusted_kernel_keys: &[String],
) -> Result<UnderwritingDecisionReport, TrustHttpError> {
    let input = build_underwriting_policy_input(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        query,
        read_context,
        trusted_kernel_keys,
    )?;
    let policy = UnderwritingDecisionPolicy::default();
    chio_kernel::evaluate_underwriting_policy_input(input, &policy)
        .map_err(TrustHttpError::bad_request)
}

pub fn build_underwriting_simulation_report(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    request: &UnderwritingSimulationRequest,
    trusted_kernel_keys: &[String],
) -> Result<UnderwritingSimulationReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    build_underwriting_simulation_report_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        request,
        chio_kernel::ReceiptReadContext::local_operator_admin_all(),
        trusted_kernel_keys,
    )
    .map_err(CliError::from)
}

pub(crate) fn build_underwriting_simulation_report_from_store(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    request: &UnderwritingSimulationRequest,
    read_context: chio_kernel::ReceiptReadContext,
    trusted_kernel_keys: &[String],
) -> Result<UnderwritingSimulationReport, TrustHttpError> {
    let input = build_underwriting_policy_input(
        receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        &request.query,
        read_context,
        trusted_kernel_keys,
    )?;
    let default_evaluation = chio_kernel::evaluate_underwriting_policy_input(
        input.clone(),
        &UnderwritingDecisionPolicy::default(),
    )
    .map_err(TrustHttpError::bad_request)?;
    let simulated_evaluation =
        chio_kernel::evaluate_underwriting_policy_input(input.clone(), &request.policy)
            .map_err(TrustHttpError::bad_request)?;

    Ok(UnderwritingSimulationReport {
        schema: UNDERWRITING_SIMULATION_REPORT_SCHEMA.to_string(),
        generated_at: unix_timestamp_now(),
        input,
        delta: build_underwriting_simulation_delta(&default_evaluation, &simulated_evaluation),
        default_evaluation,
        simulated_evaluation,
    })
}

pub fn issue_signed_underwriting_decision(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    query: &UnderwritingPolicyInputQuery,
    supersedes_decision_id: Option<&str>,
) -> Result<SignedUnderwritingDecision, CliError> {
    issue_signed_underwriting_decision_detailed(
        receipt_db_path,
        budget_db_path,
        authority_seed_path,
        authority_db_path,
        certification_registry_file,
        query,
        supersedes_decision_id,
        chio_kernel::ReceiptReadContext::local_operator_admin_all(),
        None,
    )
    .map_err(CliError::from)
}

pub(crate) fn issue_signed_underwriting_decision_detailed(
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    query: &UnderwritingPolicyInputQuery,
    supersedes_decision_id: Option<&str>,
    read_context: chio_kernel::ReceiptReadContext,
    fiscal_runtime: Option<&TrustFiscalRuntime>,
) -> Result<SignedUnderwritingDecision, TrustHttpError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    // Load the signing keypair first so its public key anchors the reputation
    // scoring trust set (chio-reputation::receipt_integrity_valid fails closed
    // on an empty set, which would zero out the reputation contribution).
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let trusted_kernel_keys = vec![keypair.public_key().to_hex()];
    let report = build_underwriting_decision_report_from_store(
        &receipt_store,
        receipt_db_path,
        budget_db_path,
        certification_registry_file,
        query,
        read_context.clone(),
        &trusted_kernel_keys,
    )?;
    let quoted_exposure = build_underwriting_quoted_exposure(&receipt_store, query, read_context)?;
    let issued_at = unix_timestamp_now();
    let mut artifact = if let Some(runtime) = fiscal_runtime {
        runtime
            .with_resolver(|resolver| {
                chio_underwriting::build_fiscal_underwriting_decision_artifact(
                    report,
                    issued_at,
                    supersedes_decision_id.map(ToOwned::to_owned),
                    quoted_exposure.amount_for_pricing(),
                    resolver,
                )
            })
            .map_err(|error| TrustHttpError::internal(error.to_string()))?
            .map_err(|error| TrustHttpError::bad_request(error.to_string()))?
    } else {
        chio_kernel::build_underwriting_decision_artifact(
            report,
            issued_at,
            supersedes_decision_id.map(ToOwned::to_owned),
            quoted_exposure.amount_for_pricing(),
        )
        .map_err(TrustHttpError::bad_request)?
    };
    quoted_exposure.apply_to_artifact(&mut artifact);
    let signed = SignedUnderwritingDecision::sign(artifact, &keypair)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    receipt_store
        .record_underwriting_decision(&signed)
        .map_err(trust_http_error_from_receipt_store)?;
    Ok(signed)
}

pub fn list_underwriting_decisions(
    receipt_db_path: &Path,
    query: &UnderwritingDecisionQuery,
) -> Result<UnderwritingDecisionListReport, CliError> {
    let receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .query_underwriting_decisions(query)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

pub fn create_underwriting_appeal(
    receipt_db_path: &Path,
    request: &UnderwritingAppealCreateRequest,
) -> Result<UnderwritingAppealRecord, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .create_underwriting_appeal(request)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

pub fn resolve_underwriting_appeal(
    receipt_db_path: &Path,
    request: &UnderwritingAppealResolveRequest,
) -> Result<UnderwritingAppealRecord, CliError> {
    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path)?;
    receipt_store
        .resolve_underwriting_appeal(request)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

pub(crate) fn build_exposure_ledger_receipt_entry(
    receipt: &chio_kernel::BehavioralFeedReceiptRow,
) -> Result<ExposureLedgerReceiptEntry, TrustHttpError> {
    let governed_max_amount = receipt
        .governed
        .as_ref()
        .and_then(|governed| governed.max_amount.clone());
    let financial_amount = exposure_ledger_financial_amount(receipt);
    if let (Some(governed), Some(financial)) = (&governed_max_amount, &financial_amount) {
        if governed.currency != financial.currency {
            return Err(TrustHttpError::new(
                StatusCode::CONFLICT,
                format!(
                    "receipt `{}` cannot project one exposure row across multiple currencies (`{}` vs `{}`)",
                    receipt.receipt_id, governed.currency, financial.currency
                ),
            ));
        }
    }

    let reserve_required_amount = if receipt.action_required {
        governed_max_amount
            .clone()
            .or_else(|| financial_amount.clone())
    } else {
        None
    };
    let provisional_loss_amount =
        if receipt.settlement_status == SettlementStatus::Failed && receipt.action_required {
            financial_amount
                .clone()
                .or_else(|| governed_max_amount.clone())
        } else {
            None
        };
    let metered_action_required = receipt
        .metered_reconciliation
        .as_ref()
        .is_some_and(|row| row.action_required);
    let mut evidence_refs = vec![ExposureLedgerEvidenceReference {
        kind: ExposureLedgerEvidenceKind::Receipt,
        reference_id: receipt.receipt_id.clone(),
        observed_at: Some(receipt.timestamp),
        locator: Some(format!("receipt:{}", receipt.receipt_id)),
    }];
    if receipt.settlement_status != SettlementStatus::NotApplicable || receipt.action_required {
        evidence_refs.push(ExposureLedgerEvidenceReference {
            kind: ExposureLedgerEvidenceKind::SettlementReconciliation,
            reference_id: receipt.receipt_id.clone(),
            observed_at: Some(receipt.timestamp),
            locator: Some(format!("settlement:{}", receipt.receipt_id)),
        });
    }
    if metered_action_required {
        evidence_refs.push(ExposureLedgerEvidenceReference {
            kind: ExposureLedgerEvidenceKind::MeteredBillingReconciliation,
            reference_id: receipt.receipt_id.clone(),
            observed_at: Some(receipt.timestamp),
            locator: Some(format!("metered-billing:{}", receipt.receipt_id)),
        });
    }

    Ok(ExposureLedgerReceiptEntry {
        receipt_id: receipt.receipt_id.clone(),
        timestamp: receipt.timestamp,
        capability_id: receipt.capability_id.clone(),
        subject_key: receipt.subject_key.clone(),
        issuer_key: receipt.issuer_key.clone(),
        tool_server: receipt.tool_server.clone(),
        tool_name: receipt.tool_name.clone(),
        decision: receipt.decision.clone().unwrap_or(Decision::Incomplete {
            reason: "non-mediated receipt has no decision".to_string(),
        }),
        settlement_status: receipt.settlement_status.clone(),
        action_required: receipt.action_required,
        governed_max_amount,
        financial_amount,
        reserve_required_amount,
        provisional_loss_amount,
        recovered_amount: None,
        metered_action_required,
        evidence_refs,
    })
}

pub(crate) fn build_exposure_ledger_decision_entry(
    row: &chio_kernel::UnderwritingDecisionRow,
) -> ExposureLedgerDecisionEntry {
    let filters = &row.decision.body.evaluation.input.filters;
    let decision_id = row.decision.body.decision_id.clone();
    ExposureLedgerDecisionEntry {
        decision_id: decision_id.clone(),
        issued_at: row.decision.body.issued_at,
        capability_id: filters.capability_id.clone(),
        agent_subject: filters.agent_subject.clone(),
        tool_server: filters.tool_server.clone(),
        tool_name: filters.tool_name.clone(),
        outcome: row.decision.body.evaluation.outcome,
        lifecycle_state: row.lifecycle_state,
        review_state: row.decision.body.review_state,
        risk_class: row.decision.body.evaluation.risk_class,
        supersedes_decision_id: row.decision.body.supersedes_decision_id.clone(),
        quoted_premium_amount: row.decision.body.premium.quoted_amount.clone(),
        evidence_refs: vec![ExposureLedgerEvidenceReference {
            kind: ExposureLedgerEvidenceKind::UnderwritingDecision,
            reference_id: decision_id.clone(),
            observed_at: Some(row.decision.body.issued_at),
            locator: Some(format!("underwriting-decision:{decision_id}")),
        }],
    }
}

fn exposure_ledger_financial_amount(
    receipt: &chio_kernel::BehavioralFeedReceiptRow,
) -> Option<MonetaryAmount> {
    let units = receipt
        .cost_charged
        .filter(|units| *units > 0)
        .or_else(|| receipt.attempted_cost.filter(|units| *units > 0))?;
    Some(MonetaryAmount {
        units,
        currency: receipt.currency.clone()?,
    })
}

pub(crate) fn accumulate_exposure_position<F>(
    positions_by_currency: &mut BTreeMap<String, ExposureLedgerCurrencyPosition>,
    amount: Option<&MonetaryAmount>,
    update: F,
) where
    F: FnOnce(&mut ExposureLedgerCurrencyPosition, &MonetaryAmount),
{
    let Some(amount) = amount else {
        return;
    };
    let position = positions_by_currency
        .entry(amount.currency.clone())
        .or_insert_with(|| ExposureLedgerCurrencyPosition {
            currency: amount.currency.clone(),
            governed_max_exposure_units: 0,
            reserved_units: 0,
            settled_units: 0,
            pending_units: 0,
            failed_units: 0,
            provisional_loss_units: 0,
            recovered_units: 0,
            quoted_premium_units: 0,
            active_quoted_premium_units: 0,
        });
    update(position, amount);
}

fn build_underwriting_quoted_exposure(
    receipt_store: &SqliteReceiptStore,
    query: &UnderwritingPolicyInputQuery,
    read_context: chio_kernel::ReceiptReadContext,
) -> Result<UnderwritingQuotedExposure, TrustHttpError> {
    let normalized_query = query.normalized();
    if let Err(message) = normalized_query.validate() {
        return Err(TrustHttpError::bad_request(message));
    }

    let behavioral_query = BehavioralFeedQuery {
        capability_id: normalized_query.capability_id,
        agent_subject: normalized_query.agent_subject,
        tool_server: normalized_query.tool_server,
        tool_name: normalized_query.tool_name,
        since: normalized_query.since,
        until: normalized_query.until,
        receipt_limit: normalized_query.receipt_limit,
        read_context: Some(read_context),
    };
    let (_, _, _, selection) = receipt_store
        .query_behavioral_feed_receipts(&behavioral_query)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;

    let mut max_by_currency = BTreeMap::<String, MonetaryAmount>::new();
    for amount in selection
        .receipts
        .into_iter()
        .filter_map(|receipt| receipt.governed.and_then(|governed| governed.max_amount))
    {
        max_by_currency
            .entry(amount.currency.clone())
            .and_modify(|current| {
                if amount.units > current.units {
                    *current = amount.clone();
                }
            })
            .or_insert(amount);
    }

    Ok(match max_by_currency.len() {
        0 => UnderwritingQuotedExposure::None,
        1 => match max_by_currency.into_values().next() {
            Some(amount) => UnderwritingQuotedExposure::Single(amount),
            None => UnderwritingQuotedExposure::None,
        },
        _ => UnderwritingQuotedExposure::MixedCurrencies(max_by_currency.into_keys().collect()),
    })
}

fn build_underwriting_simulation_delta(
    default_evaluation: &UnderwritingDecisionReport,
    simulated_evaluation: &UnderwritingDecisionReport,
) -> UnderwritingSimulationDelta {
    let default_reasons = underwriting_simulation_reason_keys(default_evaluation);
    let simulated_reasons = underwriting_simulation_reason_keys(simulated_evaluation);

    UnderwritingSimulationDelta {
        outcome_changed: default_evaluation.outcome != simulated_evaluation.outcome,
        risk_class_changed: default_evaluation.risk_class != simulated_evaluation.risk_class,
        added_reasons: simulated_reasons
            .iter()
            .filter(|reason| !default_reasons.contains(reason))
            .cloned()
            .collect(),
        removed_reasons: default_reasons
            .iter()
            .filter(|reason| !simulated_reasons.contains(reason))
            .cloned()
            .collect(),
        default_ceiling_factor: default_evaluation.suggested_ceiling_factor,
        simulated_ceiling_factor: simulated_evaluation.suggested_ceiling_factor,
    }
}

fn underwriting_simulation_reason_keys(report: &UnderwritingDecisionReport) -> Vec<String> {
    let mut reasons = Vec::new();
    for reason in report
        .findings
        .iter()
        .map(underwriting_simulation_reason_key)
    {
        if !reasons.contains(&reason) {
            reasons.push(reason);
        }
    }
    reasons
}

fn underwriting_runtime_family_label(
    family: chio_core::appraisal::AttestationVerifierFamily,
) -> &'static str {
    match family {
        chio_core::appraisal::AttestationVerifierFamily::AzureMaa => "azure_maa",
        chio_core::appraisal::AttestationVerifierFamily::AwsNitro => "aws_nitro",
        chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation => "google_attestation",
        chio_core::appraisal::AttestationVerifierFamily::EnterpriseVerifier => {
            "enterprise_verifier"
        }
    }
}

fn underwriting_simulation_reason_key(
    finding: &chio_kernel::UnderwritingDecisionFinding,
) -> String {
    if let Some(reason) = finding.signal_reason {
        serde_json::to_string(&reason)
            .unwrap_or_else(|_| format!("{reason:?}"))
            .trim_matches('"')
            .to_string()
    } else {
        serde_json::to_string(&finding.reason)
            .unwrap_or_else(|_| format!("{:?}", finding.reason))
            .trim_matches('"')
            .to_string()
    }
}

#[path = "underwriting_and_support/policy_support.rs"]
mod policy_support;

pub(crate) use self::policy_support::*;

#[cfg(test)]
mod underwriting_and_support_tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_test_support::prelude::*;

    fn unique_temp_path(prefix: &str, extension: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.{extension}"))
    }

    #[test]
    fn behavioral_feed_signer_uses_local_db_seed_after_replica_snapshot() {
        let source_path = unique_temp_path("chio-behavioral-feed-source", "sqlite");
        let follower_path = unique_temp_path("chio-behavioral-feed-follower", "sqlite");
        let source = SqliteCapabilityAuthority::open(&source_path).test_unwrap();
        let follower = SqliteCapabilityAuthority::open(&follower_path).test_unwrap();
        let follower_local_key = follower.local_keypair().test_unwrap();

        source.rotate().test_unwrap();
        let snapshot = source.snapshot().test_unwrap();
        assert!(follower.apply_snapshot(&snapshot).test_unwrap());
        assert!(follower.current_keypair().is_err());

        let signing_key =
            load_behavioral_feed_signing_keypair(None, Some(&follower_path)).test_unwrap();
        assert_eq!(signing_key.public_key(), follower_local_key.public_key());

        let _ = fs::remove_file(source_path);
        let _ = fs::remove_file(follower_path);
    }

    #[test]
    fn underwriting_compliance_evidence_rejects_subject_mismatch() {
        let activity = chio_kernel::ReceiptAnalyticsResponse {
            summary: chio_kernel::ReceiptAnalyticsMetrics::from_raw(5, 4, 1, 0, 0, 10, 2),
            by_agent: Vec::new(),
            by_tool: Vec::new(),
            by_time: Vec::new(),
        };
        let report = chio_kernel::ComplianceReport {
            matching_receipts: 5,
            evidence_ready_receipts: 5,
            uncheckpointed_receipts: 0,
            checkpoint_coverage_rate: Some(1.0),
            lineage_covered_receipts: 5,
            lineage_gap_receipts: 0,
            lineage_coverage_rate: Some(1.0),
            pending_settlement_receipts: 0,
            failed_settlement_receipts: 0,
            direct_evidence_export_supported: true,
            child_receipt_scope: chio_kernel::EvidenceChildReceiptScope::OmittedNoJoinPath,
            proofs_complete: true,
            export_query: chio_kernel::EvidenceExportQuery {
                agent_subject: Some("subject-other".to_string()),
                ..chio_kernel::EvidenceExportQuery::default()
            },
            export_scope_note: None,
        };
        let selection = chio_kernel::BehavioralFeedReceiptSelection {
            matching_receipts: 0,
            receipts: Vec::new(),
        };

        let error = build_underwriting_compliance_evidence(
            "subject-expected",
            1_717_171_717,
            &activity,
            &report,
            &selection,
        )
        .test_unwrap_err();
        assert!(error.contains("compliance report subject mismatch"));
    }

    fn minimal_trust_service_config() -> TrustServiceConfig {
        TrustServiceConfig {
            listen: "127.0.0.1:0".parse().test_unwrap(),
            service_token: "token".to_string(),
            tenant_read_tokens: BTreeMap::new(),
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            budget_db_path: None,
            joint_authority_db_path: None,
            fiscal_runtime: None,
            enterprise_providers_file: None,
            federation_policies_file: None,
            scim_lifecycle_file: None,
            verifier_policies_file: None,
            verifier_challenge_db_path: None,
            passport_statuses_file: None,
            passport_issuance_offers_file: None,
            certification_registry_file: None,
            certification_discovery_file: None,
            issuance_policy: None,
            runtime_assurance_policy: None,
            advertise_url: None,
            allow_local_peer_urls: false,
            certification_public_metadata_ttl_seconds: 900,
            peer_urls: Vec::new(),
            cluster_sync_interval: Duration::from_millis(200),
            roster_policy: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            finding_market: None,
        }
    }

    #[test]
    fn trusted_kernel_keys_none_without_authority_material() {
        let keys =
            trusted_kernel_keys_from_service_config(&minimal_trust_service_config()).test_unwrap();
        assert_eq!(keys, None);
    }

    #[test]
    fn trusted_kernel_keys_loads_configured_authority_seed() {
        let seed_path = unique_temp_path("chio-trusted-kernel-seed", "yaml");
        let keypair = load_or_create_authority_keypair(&seed_path).test_unwrap();
        let mut config = minimal_trust_service_config();
        config.authority_seed_path = Some(seed_path.clone());

        let keys = trusted_kernel_keys_from_service_config(&config).test_unwrap();
        assert_eq!(
            keys,
            Some(vec![keypair.public_key().to_hex()]),
            "configured authority seed must surface the local kernel key"
        );

        let _ = fs::remove_file(seed_path);
    }

    #[test]
    fn trusted_kernel_keys_propagates_malformed_authority_seed_failure() {
        let seed_path = unique_temp_path("chio-trusted-kernel-bad-seed", "yaml");
        fs::write(&seed_path, "not-a-valid-seed").test_unwrap();
        let mut config = minimal_trust_service_config();
        config.authority_seed_path = Some(seed_path.clone());

        let error = trusted_kernel_keys_from_service_config(&config).test_unwrap_err();
        let message = error.to_string();
        assert!(
            !message.is_empty(),
            "malformed authority seed must fail at load time"
        );

        let _ = fs::remove_file(seed_path);
    }

    #[test]
    fn trusted_kernel_keys_rejects_dual_authority_sources() {
        let mut config = minimal_trust_service_config();
        config.authority_seed_path = Some(unique_temp_path("chio-trusted-kernel-seed", "yaml"));
        config.authority_db_path = Some(unique_temp_path("chio-trusted-kernel-db", "sqlite"));

        let error = trusted_kernel_keys_from_service_config(&config).test_unwrap_err();
        assert!(
            error.to_string().contains("not both"),
            "dual authority sources must fail closed"
        );
    }
}
