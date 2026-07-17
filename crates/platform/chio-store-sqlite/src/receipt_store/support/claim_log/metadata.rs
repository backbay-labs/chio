use super::*;

pub(crate) fn parse_settlement_status(value: &str) -> Result<SettlementStatus, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn settlement_reconciliation_action_required(
    settlement_status: SettlementStatus,
    reconciliation_state: SettlementReconciliationState,
) -> bool {
    matches!(
        settlement_status,
        SettlementStatus::Pending | SettlementStatus::Failed
    ) && !matches!(
        reconciliation_state,
        SettlementReconciliationState::Reconciled | SettlementReconciliationState::Ignored
    )
}

pub(crate) fn metered_billing_evidence_record_from_columns(
    adapter_kind: Option<String>,
    evidence_id: Option<String>,
    observed_units: Option<i64>,
    billed_cost_units: Option<i64>,
    billed_cost_currency: Option<String>,
    evidence_sha256: Option<String>,
    recorded_at: Option<i64>,
) -> Option<MeteredBillingEvidenceRecord> {
    let (
        Some(adapter_kind),
        Some(evidence_id),
        Some(observed_units),
        Some(billed_cost_units),
        Some(billed_cost_currency),
        Some(recorded_at),
    ) = (
        adapter_kind,
        evidence_id,
        observed_units,
        billed_cost_units,
        billed_cost_currency,
        recorded_at,
    )
    else {
        return None;
    };

    Some(MeteredBillingEvidenceRecord {
        usage_evidence: chio_core::receipt::governance::MeteredUsageEvidenceReceiptMetadata {
            evidence_kind: adapter_kind,
            evidence_id,
            observed_units: observed_units.max(0) as u64,
            evidence_sha256,
        },
        billed_cost: chio_core::capability::scope::MonetaryAmount {
            units: billed_cost_units.max(0) as u64,
            currency: billed_cost_currency,
        },
        recorded_at: recorded_at.max(0) as u64,
    })
}

pub(crate) struct MeteredBillingReconciliationAnalysis {
    pub(crate) evidence_missing: bool,
    pub(crate) exceeds_quoted_units: bool,
    pub(crate) exceeds_max_billed_units: bool,
    pub(crate) exceeds_quoted_cost: bool,
    pub(crate) financial_mismatch: bool,
    pub(crate) action_required: bool,
}

pub(crate) fn analyze_metered_billing_reconciliation(
    metered: &chio_core::receipt::governance::MeteredBillingReceiptMetadata,
    financial: Option<&FinancialReceiptMetadata>,
    evidence: Option<&MeteredBillingEvidenceRecord>,
    reconciliation_state: MeteredBillingReconciliationState,
) -> MeteredBillingReconciliationAnalysis {
    let evidence_missing = evidence.is_none();
    let exceeds_quoted_units = evidence
        .is_some_and(|record| record.usage_evidence.observed_units > metered.quote.quoted_units);
    let exceeds_max_billed_units = evidence.is_some_and(|record| {
        metered
            .max_billed_units
            .is_some_and(|max_units| record.usage_evidence.observed_units > max_units)
    });
    let exceeds_quoted_cost = evidence.is_some_and(|record| {
        record.billed_cost.currency != metered.quote.quoted_cost.currency
            || record.billed_cost.units > metered.quote.quoted_cost.units
    });
    let financial_mismatch = evidence.is_some_and(|record| {
        financial.is_some_and(|financial| {
            record.billed_cost.currency != financial.currency
                || record.billed_cost.units != financial.cost_charged
        })
    });
    let action_required = (evidence_missing
        || exceeds_quoted_units
        || exceeds_max_billed_units
        || exceeds_quoted_cost
        || financial_mismatch)
        && !matches!(
            reconciliation_state,
            MeteredBillingReconciliationState::Reconciled
                | MeteredBillingReconciliationState::Ignored
        );

    MeteredBillingReconciliationAnalysis {
        evidence_missing,
        exceeds_quoted_units,
        exceeds_max_billed_units,
        exceeds_quoted_cost,
        financial_mismatch,
        action_required,
    }
}

#[derive(Default)]
pub(crate) struct RootAggregate {
    pub(crate) receipt_count: u64,
    pub(crate) total_cost_charged: u64,
    pub(crate) total_attempted_cost: u64,
    pub(crate) max_delegation_depth: u64,
    pub(crate) leaf_subjects: BTreeSet<String>,
}

#[derive(Default)]
pub(crate) struct LeafAggregate {
    pub(crate) receipt_count: u64,
    pub(crate) total_cost_charged: u64,
    pub(crate) total_attempted_cost: u64,
    pub(crate) max_delegation_depth: u64,
}

#[derive(Default)]
pub(crate) struct ReceiptAttributionColumns {
    pub(crate) subject_key: Option<String>,
    pub(crate) issuer_key: Option<String>,
    pub(crate) grant_index: Option<u32>,
}

pub(crate) fn extract_receipt_attribution(receipt: &ChioReceipt) -> ReceiptAttributionColumns {
    let Some(metadata) = receipt.metadata.as_ref() else {
        return ReceiptAttributionColumns::default();
    };

    let attribution = metadata
        .get("attribution")
        .cloned()
        .and_then(|value| serde_json::from_value::<ReceiptAttributionMetadata>(value).ok());
    let grant_index = attribution
        .as_ref()
        .and_then(|value| value.grant_index)
        .or_else(|| {
            metadata
                .get("financial")
                .and_then(|value| value.get("grant_index"))
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
        });

    ReceiptAttributionColumns {
        subject_key: attribution.as_ref().map(|value| value.subject_key.clone()),
        issuer_key: attribution.as_ref().map(|value| value.issuer_key.clone()),
        grant_index,
    }
}

pub(crate) fn extract_financial_metadata(
    receipt: &ChioReceipt,
) -> Option<FinancialReceiptMetadata> {
    receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"))
        .cloned()
        .and_then(|value| serde_json::from_value::<FinancialReceiptMetadata>(value).ok())
}

pub(crate) fn extract_governed_transaction_metadata(
    receipt: &ChioReceipt,
) -> Option<GovernedTransactionReceiptMetadata> {
    receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .cloned()
        .and_then(|value| serde_json::from_value::<GovernedTransactionReceiptMetadata>(value).ok())
}

pub(crate) fn extract_economic_authorization_metadata(
    receipt: &ChioReceipt,
) -> Option<chio_core::receipt::economics::EconomicAuthorizationReceiptMetadata> {
    extract_governed_transaction_metadata(receipt)
        .and_then(|governed| governed.economic_authorization)
}

pub(crate) fn authorization_details_from_governed_metadata(
    governed: &GovernedTransactionReceiptMetadata,
) -> Vec<GovernedAuthorizationDetail> {
    let mut details = vec![GovernedAuthorizationDetail {
        detail_type: CHIO_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE.to_string(),
        locations: vec![governed.server_id.clone()],
        actions: vec![governed.tool_name.clone()],
        purpose: Some(governed.purpose.clone()),
        max_amount: governed.max_amount.clone(),
        commerce: None,
        metered_billing: None,
    }];

    if let Some(commerce) = governed.commerce.as_ref() {
        details.push(GovernedAuthorizationDetail {
            detail_type: CHIO_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE.to_string(),
            locations: Vec::new(),
            actions: Vec::new(),
            purpose: None,
            max_amount: governed.max_amount.clone(),
            commerce: Some(GovernedAuthorizationCommerceDetail {
                seller: commerce.seller.clone(),
                shared_payment_token_id: commerce.shared_payment_token_id.clone(),
            }),
            metered_billing: None,
        });
    }

    if let Some(metered) = governed.metered_billing.as_ref() {
        details.push(GovernedAuthorizationDetail {
            detail_type: CHIO_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE.to_string(),
            locations: Vec::new(),
            actions: Vec::new(),
            purpose: None,
            max_amount: None,
            commerce: None,
            metered_billing: Some(GovernedAuthorizationMeteredBillingDetail {
                settlement_mode: metered.settlement_mode,
                provider: metered.quote.provider.clone(),
                quote_id: metered.quote.quote_id.clone(),
                billing_unit: metered.quote.billing_unit.clone(),
                quoted_units: metered.quote.quoted_units,
                quoted_cost: metered.quote.quoted_cost.clone(),
                max_billed_units: metered.max_billed_units,
            }),
        });
    }

    details
}

pub(crate) fn authorization_transaction_context_from_governed_metadata(
    governed: &GovernedTransactionReceiptMetadata,
) -> GovernedAuthorizationTransactionContext {
    GovernedAuthorizationTransactionContext {
        intent_id: governed.intent_id.clone(),
        intent_hash: governed.intent_hash.clone(),
        approval_token_id: governed
            .approval
            .as_ref()
            .map(|value| value.token_id.clone()),
        approval_approved: governed.approval.as_ref().map(|value| value.approved),
        approver_key: governed
            .approval
            .as_ref()
            .map(|value| value.approver_key.clone()),
        runtime_assurance_tier: governed.runtime_assurance.as_ref().map(|value| value.tier),
        runtime_assurance_schema: governed
            .runtime_assurance
            .as_ref()
            .map(|value| value.schema.clone()),
        runtime_assurance_verifier_family: governed
            .runtime_assurance
            .as_ref()
            .and_then(|value| value.verifier_family),
        runtime_assurance_verifier: governed
            .runtime_assurance
            .as_ref()
            .map(|value| value.verifier.clone()),
        runtime_assurance_evidence_sha256: governed
            .runtime_assurance
            .as_ref()
            .map(|value| value.evidence_sha256.clone()),
        call_chain: governed.call_chain.clone(),
        identity_assertion: None,
    }
}
