use std::collections::{BTreeMap, BTreeSet};

use super::*;

pub(super) fn validate_risk_reserve_ledger(
    report: &RiskComptrollerReport,
    entries: &[RiskReserveLedgerEntry],
) -> Result<(), TransactionPassportError> {
    if entries.is_empty() {
        if report.reconciliation.consumed_reserve_units == 0
            && report.reconciliation.payout_units == 0
        {
            return Ok(());
        }
        return Err(claim_failed("risk reserve ledger missing"));
    }

    let mut entry_ids = BTreeSet::new();
    let mut receipt_refs = BTreeSet::new();
    let mut terminal_consumption_by_reserve_claim: BTreeMap<(&str, &str), &str> = BTreeMap::new();
    let mut prior_reserve_slash_units: BTreeMap<(&str, &str), u64> = BTreeMap::new();
    let mut reversed_reserve_slash_units: BTreeMap<(&str, &str), u64> = BTreeMap::new();
    let mut consumed_units = 0u64;
    let mut claim_payout_units = 0u64;
    for entry in entries {
        validate_risk_reserve_ledger_entry(report, entry)?;
        if !entry_ids.insert(entry.entry_id.as_str()) {
            return Err(claim_failed("risk reserve ledger duplicate entry"));
        }
        if !receipt_refs.insert(entry.receipt_ref.as_str()) {
            return Err(claim_failed("risk reserve ledger duplicate receipt"));
        }
        let reserve_claim = (entry.reserve_ref.as_str(), entry.claim_id.as_str());
        if entry.lane == "reverse_slash" {
            let Some(prior_slash_units) = prior_reserve_slash_units.get(&reserve_claim).copied()
            else {
                return Err(claim_failed(
                    "risk reverse slash missing prior reserve slash",
                ));
            };
            let reversed_units = reversed_reserve_slash_units
                .entry(reserve_claim)
                .or_insert(0);
            *reversed_units = reversed_units
                .checked_add(entry.units)
                .ok_or_else(|| claim_failed("risk reverse slash overflow"))?;
            if *reversed_units > prior_slash_units {
                return Err(claim_failed(
                    "risk reverse slash exceeds prior reserve slash",
                ));
            }
            consumed_units = consumed_units
                .checked_sub(entry.units)
                .ok_or_else(|| claim_failed("risk reverse slash exceeds prior reserve slash"))?;
        }
        if is_terminal_reserve_consumption(&entry.lane) {
            if terminal_consumption_by_reserve_claim
                .insert(reserve_claim, entry.lane.as_str())
                .is_some()
            {
                return Err(claim_failed("risk reserve double consumption"));
            }
            consumed_units = consumed_units
                .checked_add(entry.units)
                .ok_or_else(|| claim_failed("risk reserve ledger overflow"))?;
        }
        if entry.lane == "claim_payout" {
            claim_payout_units = claim_payout_units
                .checked_add(entry.units)
                .ok_or_else(|| claim_failed("risk payout ledger overflow"))?;
        }
        if entry.lane == "reserve_slash" {
            let prior_slash_units = prior_reserve_slash_units.entry(reserve_claim).or_insert(0);
            *prior_slash_units = prior_slash_units
                .checked_add(entry.units)
                .ok_or_else(|| claim_failed("risk reserve slash overflow"))?;
        }
    }

    if consumed_units != report.reconciliation.consumed_reserve_units {
        return Err(claim_failed("risk reserve ledger consumption mismatch"));
    }
    if claim_payout_units != report.reconciliation.payout_units {
        return Err(claim_failed("risk payout ledger mismatch"));
    }
    Ok(())
}

pub(super) fn validate_risk_sanction_reserve_ledger(
    report: &RiskComptrollerReport,
    reserve_entries: &[RiskReserveLedgerEntry],
    sanction_entries: &[RiskSanctionReserveLedgerEntry],
) -> Result<(), TransactionPassportError> {
    let market_slashes: Vec<&RiskReserveLedgerEntry> = reserve_entries
        .iter()
        .filter(|entry| entry.lane == "market_slash")
        .collect();
    if market_slashes.is_empty() {
        if sanction_entries.is_empty() {
            return Ok(());
        }
        return Err(claim_failed("risk sanction reserve ledger unsupported"));
    }
    if sanction_entries.is_empty() {
        return Err(claim_failed("risk sanction reserve ledger missing"));
    }

    let mut bridge_ids = BTreeSet::new();
    for market_slash in &market_slashes {
        let Some(sanction_bridge) = market_slash.sanction_bridge.as_ref() else {
            return Err(claim_failed("risk market slash requires sanction bridge"));
        };
        if !bridge_ids.insert(sanction_bridge.bridge_id.as_str()) {
            return Err(claim_failed("risk sanction bridge duplicate"));
        }
    }

    let mut entry_ids = BTreeSet::new();
    let mut receipt_refs = BTreeSet::new();
    for sanction_entry in sanction_entries {
        validate_risk_sanction_reserve_ledger_entry(report, sanction_entry)?;
        if !entry_ids.insert(sanction_entry.entry_id.as_str()) {
            return Err(claim_failed("risk sanction reserve ledger duplicate entry"));
        }
        if !receipt_refs.insert(sanction_entry.receipt_ref.as_str()) {
            return Err(claim_failed(
                "risk sanction reserve ledger duplicate receipt",
            ));
        }
    }

    for sanction_entry in sanction_entries {
        let matches_market_slash = market_slashes.iter().any(|market_slash| {
            market_slash
                .sanction_bridge
                .as_ref()
                .is_some_and(|bridge| sanction_entry.matches_market_slash(market_slash, bridge))
        });
        if !matches_market_slash {
            return Err(claim_failed("risk sanction reserve ledger unbound entry"));
        }
    }

    for market_slash in market_slashes {
        let Some(sanction_bridge) = market_slash.sanction_bridge.as_ref() else {
            return Err(claim_failed("risk market slash requires sanction bridge"));
        };
        if !sanction_entries.iter().any(|sanction_entry| {
            sanction_entry.matches_market_slash(market_slash, sanction_bridge)
        }) {
            return Err(claim_failed("risk sanction reserve ledger missing"));
        }
    }
    Ok(())
}

impl RiskSanctionReserveLedgerEntry {
    fn matches_market_slash(
        &self,
        market_slash: &RiskReserveLedgerEntry,
        sanction_bridge: &RiskSanctionBridge,
    ) -> bool {
        self.lane == "market_slash"
            && self.bridge_id == sanction_bridge.bridge_id
            && self.receipt_ref == market_slash.receipt_ref
            && self.reserve_ref == market_slash.reserve_ref
            && self.claim_id == market_slash.claim_id
            && self.currency == market_slash.currency
            && self.units == market_slash.units
            && self.settlement_ref == market_slash.settlement_ref
            && self.authority_receipt_ref == sanction_bridge.authority_receipt_ref
            && self.evidence_ref == sanction_bridge.evidence_ref
            && self.jurisdiction_ref == sanction_bridge.jurisdiction_ref
    }
}

fn validate_risk_sanction_reserve_ledger_entry(
    report: &RiskComptrollerReport,
    entry: &RiskSanctionReserveLedgerEntry,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("sanction_reserve_ledger_entry_id", &entry.entry_id),
        ("sanction_reserve_ledger_bridge_id", &entry.bridge_id),
        ("sanction_reserve_ledger_lane", &entry.lane),
        ("sanction_reserve_ledger_receipt_ref", &entry.receipt_ref),
        ("sanction_reserve_ledger_reserve_ref", &entry.reserve_ref),
        ("sanction_reserve_ledger_claim_id", &entry.claim_id),
        ("sanction_reserve_ledger_currency", &entry.currency),
        (
            "sanction_reserve_ledger_settlement_ref",
            &entry.settlement_ref,
        ),
        (
            "sanction_reserve_ledger_authority_receipt_ref",
            &entry.authority_receipt_ref,
        ),
        ("sanction_reserve_ledger_evidence_ref", &entry.evidence_ref),
        (
            "sanction_reserve_ledger_jurisdiction_ref",
            &entry.jurisdiction_ref,
        ),
    ] {
        require_non_empty(value, field)?;
    }
    if entry.lane != "market_slash" {
        return Err(claim_failed(
            "risk sanction reserve ledger lane unsupported",
        ));
    }
    if entry.reserve_ref != report.facility.reserve_ref {
        return Err(claim_failed(
            "risk sanction reserve ledger reserve mismatch",
        ));
    }
    if entry.currency != report.facility.reserve_currency {
        return Err(claim_failed(
            "risk sanction reserve ledger currency mismatch",
        ));
    }
    if entry.units == 0 {
        return Err(claim_failed("risk sanction reserve ledger units missing"));
    }
    Ok(())
}

fn validate_risk_reserve_ledger_entry(
    report: &RiskComptrollerReport,
    entry: &RiskReserveLedgerEntry,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("reserve_ledger_entry_id", &entry.entry_id),
        ("reserve_ledger_receipt_ref", &entry.receipt_ref),
        ("reserve_ledger_lane", &entry.lane),
        ("reserve_ledger_reserve_ref", &entry.reserve_ref),
        ("reserve_ledger_claim_id", &entry.claim_id),
        ("reserve_ledger_currency", &entry.currency),
        ("reserve_ledger_settlement_ref", &entry.settlement_ref),
    ] {
        require_non_empty(value, field)?;
    }
    if !matches!(
        entry.lane.as_str(),
        "claim_payout"
            | "reserve_release"
            | "reserve_slash"
            | "market_slash"
            | "hold"
            | "reverse_slash"
            | "write_off"
    ) {
        return Err(claim_failed("risk reserve ledger lane unsupported"));
    }
    if entry.lane == "market_slash" {
        validate_market_slash_sanction_bridge(report, entry)?;
    } else if entry.sanction_bridge.is_some() {
        return Err(claim_failed("risk sanction bridge lane unsupported"));
    }
    if entry.reserve_ref != report.facility.reserve_ref {
        return Err(claim_failed("risk reserve ledger reserve mismatch"));
    }
    if !report.coverage.covered_claim_ids.is_empty()
        && !report
            .coverage
            .covered_claim_ids
            .iter()
            .any(|claim_id| claim_id == &entry.claim_id)
    {
        return Err(claim_failed("risk claim outside coverage"));
    }
    if entry.currency != report.facility.reserve_currency {
        return Err(claim_failed("risk reserve ledger currency mismatch"));
    }
    if entry.units == 0 {
        return Err(claim_failed("risk reserve ledger units missing"));
    }
    validate_risk_settlement_counterparties(report, entry)?;
    Ok(())
}

fn validate_market_slash_sanction_bridge(
    report: &RiskComptrollerReport,
    entry: &RiskReserveLedgerEntry,
) -> Result<(), TransactionPassportError> {
    let Some(sanction_bridge) = entry.sanction_bridge.as_ref() else {
        return Err(claim_failed("risk market slash requires sanction bridge"));
    };
    for (field, value) in [
        ("sanction_bridge_id", &sanction_bridge.bridge_id),
        (
            "sanction_bridge_authority_receipt_ref",
            &sanction_bridge.authority_receipt_ref,
        ),
        (
            "sanction_bridge_evidence_ref",
            &sanction_bridge.evidence_ref,
        ),
        (
            "sanction_bridge_jurisdiction_ref",
            &sanction_bridge.jurisdiction_ref,
        ),
        ("sanction_bridge_subject", &sanction_bridge.sanction_subject),
    ] {
        require_non_empty(value, field)?;
    }
    if sanction_bridge.sanction_subject != report.coverage.subject {
        return Err(claim_failed("risk market slash sanction subject mismatch"));
    }
    if sanction_bridge.maximum_slash_units == 0 {
        return Err(claim_failed("risk market slash sanction limit missing"));
    }
    if entry.units > sanction_bridge.maximum_slash_units {
        return Err(claim_failed("risk market slash exceeds sanction bridge"));
    }
    Ok(())
}
pub(super) fn is_terminal_reserve_consumption(lane: &str) -> bool {
    matches!(
        lane,
        "claim_payout" | "reserve_release" | "reserve_slash" | "market_slash" | "write_off"
    )
}
