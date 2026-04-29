use std::cell::RefCell;

use super::*;
use chio_appraisal::{verify_runtime_attestation_record, VerifiedRuntimeAttestationRecord};
use chio_core::capability::{
    GovernedCallChainContext, GovernedCallChainEvidenceSource, GovernedCallChainProvenance,
    GovernedProvenanceEvidenceClass, GovernedUpstreamCallChainProof,
};
use chio_core::receipt::GuardEvidence;
use uuid::Uuid;

use crate::evidence_export::EvidenceLineageReferences;
use crate::operator_report::GovernedTransactionDiagnostics;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GovernedCallChainReceiptEvidence {
    pub(crate) local_parent_request_id: Option<String>,
    pub(crate) local_parent_receipt_id: Option<String>,
    pub(crate) capability_delegator_subject: Option<String>,
    pub(crate) capability_origin_subject: Option<String>,
    pub(crate) upstream_proof: Option<GovernedUpstreamCallChainProof>,
    pub(crate) continuation_token_id: Option<String>,
    pub(crate) session_anchor_id: Option<String>,
}

thread_local! {
    static GOVERNED_CALL_CHAIN_RECEIPT_EVIDENCE: RefCell<Option<GovernedCallChainReceiptEvidence>> =
        const { RefCell::new(None) };
    static GOVERNED_RUNTIME_ATTESTATION_RECORD: RefCell<Option<VerifiedRuntimeAttestationRecord>> =
        const { RefCell::new(None) };
    static POST_INVOCATION_GUARD_EVIDENCE: RefCell<Vec<GuardEvidence>> =
        const { RefCell::new(Vec::new()) };
}

pub(crate) struct ScopedGovernedCallChainReceiptEvidence {
    previous: Option<GovernedCallChainReceiptEvidence>,
}

impl Drop for ScopedGovernedCallChainReceiptEvidence {
    fn drop(&mut self) {
        let previous = self.previous.take();
        GOVERNED_CALL_CHAIN_RECEIPT_EVIDENCE.with(|slot| {
            slot.replace(previous);
        });
    }
}

pub(crate) fn scope_governed_call_chain_receipt_evidence(
    evidence: Option<GovernedCallChainReceiptEvidence>,
) -> ScopedGovernedCallChainReceiptEvidence {
    let previous = GOVERNED_CALL_CHAIN_RECEIPT_EVIDENCE.with(|slot| slot.replace(evidence));
    ScopedGovernedCallChainReceiptEvidence { previous }
}

fn current_governed_call_chain_receipt_evidence() -> Option<GovernedCallChainReceiptEvidence> {
    GOVERNED_CALL_CHAIN_RECEIPT_EVIDENCE.with(|slot| slot.borrow().clone())
}

pub(crate) struct ScopedGovernedRuntimeAttestationRecord {
    previous: Option<VerifiedRuntimeAttestationRecord>,
}

impl Drop for ScopedGovernedRuntimeAttestationRecord {
    fn drop(&mut self) {
        let previous = self.previous.take();
        GOVERNED_RUNTIME_ATTESTATION_RECORD.with(|slot| {
            slot.replace(previous);
        });
    }
}

pub(crate) fn scope_governed_runtime_attestation_receipt_record(
    record: Option<VerifiedRuntimeAttestationRecord>,
) -> ScopedGovernedRuntimeAttestationRecord {
    let previous = GOVERNED_RUNTIME_ATTESTATION_RECORD.with(|slot| slot.replace(record));
    ScopedGovernedRuntimeAttestationRecord { previous }
}

fn current_governed_runtime_attestation_record() -> Option<VerifiedRuntimeAttestationRecord> {
    GOVERNED_RUNTIME_ATTESTATION_RECORD.with(|slot| slot.borrow().clone())
}

pub(crate) struct ScopedPostInvocationGuardEvidence {
    previous: Vec<GuardEvidence>,
}

impl Drop for ScopedPostInvocationGuardEvidence {
    fn drop(&mut self) {
        let previous = core::mem::take(&mut self.previous);
        POST_INVOCATION_GUARD_EVIDENCE.with(|slot| {
            slot.replace(previous);
        });
    }
}

pub(crate) fn scope_post_invocation_guard_evidence(
    evidence: Vec<GuardEvidence>,
) -> ScopedPostInvocationGuardEvidence {
    let previous = POST_INVOCATION_GUARD_EVIDENCE.with(|slot| slot.replace(evidence));
    ScopedPostInvocationGuardEvidence { previous }
}

pub(crate) fn current_post_invocation_guard_evidence() -> Vec<GuardEvidence> {
    POST_INVOCATION_GUARD_EVIDENCE.with(|slot| slot.borrow().clone())
}

fn governed_call_chain_provenance(
    context: GovernedCallChainContext,
) -> GovernedCallChainProvenance {
    let Some(evidence) = current_governed_call_chain_receipt_evidence() else {
        return GovernedCallChainProvenance::asserted(context);
    };

    let upstream_proof = evidence.upstream_proof.clone();
    let mut evidence_sources = Vec::new();

    if evidence.local_parent_request_id.as_deref() == Some(context.parent_request_id.as_str()) {
        evidence_sources.push(GovernedCallChainEvidenceSource::SessionParentRequestLineage);
    }
    if evidence.local_parent_receipt_id.is_some()
        && evidence.local_parent_receipt_id.as_deref() == context.parent_receipt_id.as_deref()
    {
        evidence_sources.push(GovernedCallChainEvidenceSource::LocalParentReceiptLinkage);
    }
    if evidence.capability_delegator_subject.as_deref() == Some(context.delegator_subject.as_str())
    {
        evidence_sources.push(GovernedCallChainEvidenceSource::CapabilityDelegatorSubject);
    }
    if evidence.capability_origin_subject.as_deref() == Some(context.origin_subject.as_str()) {
        evidence_sources.push(GovernedCallChainEvidenceSource::CapabilityOriginSubject);
    }
    if upstream_proof.is_some() {
        evidence_sources.push(GovernedCallChainEvidenceSource::UpstreamDelegatorProof);
    }

    let mut provenance = GovernedCallChainProvenance::new(
        context,
        if upstream_proof.is_some() {
            GovernedProvenanceEvidenceClass::Verified
        } else if evidence_sources.is_empty() {
            GovernedProvenanceEvidenceClass::Asserted
        } else {
            GovernedProvenanceEvidenceClass::Observed
        },
    )
    .with_evidence_sources(evidence_sources);

    if let Some(upstream_proof) = upstream_proof {
        provenance = provenance.with_upstream_proof(upstream_proof);
    }
    if let Some(continuation_token_id) = evidence.continuation_token_id {
        provenance = provenance.with_continuation_token_id(continuation_token_id);
    }
    if let Some(session_anchor_id) = evidence.session_anchor_id {
        provenance = provenance.with_session_anchor_id(session_anchor_id);
    }

    provenance
}

fn governed_transaction_diagnostics(
    call_chain: Option<&GovernedCallChainProvenance>,
) -> Option<GovernedTransactionDiagnostics> {
    let diagnostics = GovernedTransactionDiagnostics {
        asserted_call_chain: call_chain.cloned().filter(|call_chain| {
            call_chain.evidence_class == GovernedProvenanceEvidenceClass::Asserted
        }),
        lineage_references: EvidenceLineageReferences {
            session_anchor_id: call_chain
                .and_then(|call_chain| call_chain.session_anchor_id.clone()),
            request_lineage_id: None,
            receipt_lineage_statement_id: call_chain
                .and_then(|call_chain| call_chain.receipt_lineage_statement_id.clone()),
        },
    };

    (!diagnostics.is_empty()).then_some(diagnostics)
}

pub(super) fn build_child_request_receipt(
    policy_hash: &str,
    keypair: &Keypair,
    context: &OperationContext,
    operation_kind: OperationKind,
    terminal_state: OperationTerminalState,
    outcome_payload: serde_json::Value,
) -> Result<ChildRequestReceipt, KernelError> {
    let outcome_hash = canonical_json_bytes(&outcome_payload)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| {
            KernelError::ReceiptSigningFailed(format!("failed to hash child outcome: {error}"))
        })?;
    let metadata = child_receipt_metadata(&outcome_payload);
    let parent_request_id = context.parent_request_id.clone().ok_or_else(|| {
        KernelError::ReceiptSigningFailed("child receipt requires parent request lineage".into())
    })?;

    let body = ChildRequestReceiptBody {
        id: next_receipt_id("child-rcpt"),
        timestamp: current_unix_timestamp(),
        session_id: context.session_id.clone(),
        parent_request_id,
        request_id: context.request_id.clone(),
        operation_kind,
        terminal_state,
        outcome_hash,
        policy_hash: policy_hash.to_string(),
        metadata,
        kernel_key: keypair.public_key(),
    };

    ChildRequestReceipt::sign(body, keypair)
        .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))
}

pub(super) fn next_receipt_id(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::now_v7())
}

pub(super) fn merge_metadata_objects(
    base: Option<serde_json::Value>,
    extra: Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    match (base, extra) {
        (None, extra) => extra,
        (Some(base), None) => Some(base),
        (Some(mut base), Some(extra)) => {
            if let (Some(base_obj), Some(extra_obj)) = (base.as_object_mut(), extra.as_object()) {
                for (key, value) in extra_obj {
                    base_obj.insert(key.clone(), value.clone());
                }
            }
            Some(base)
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ReceiptProvenanceMetadata {
    otel: ReceiptProvenanceOtelMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    supply_chain: Option<serde_json::Value>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ReceiptProvenanceOtelMetadata {
    trace_id: String,
    span_id: String,
}

fn is_w3c_lower_hex_id(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value.chars().any(|char| char != '0')
        && value
            .chars()
            .all(|char| matches!(char, '0'..='9' | 'a'..='f'))
}

fn is_w3c_trace_id(value: &str) -> bool {
    is_w3c_lower_hex_id(value, 32)
}

fn is_w3c_span_id(value: &str) -> bool {
    is_w3c_lower_hex_id(value, 16)
}

fn receipt_provenance_metadata(
    extra_metadata: Option<&serde_json::Value>,
) -> Result<Option<serde_json::Value>, KernelError> {
    let Some(provenance) = extra_metadata
        .and_then(serde_json::Value::as_object)
        .and_then(|extra_metadata| extra_metadata.get("provenance"))
    else {
        return Ok(None);
    };

    if provenance
        .as_object()
        .and_then(|provenance| provenance.get("supply_chain"))
        .is_some_and(serde_json::Value::is_null)
    {
        return Err(KernelError::ReceiptSigningFailed(
            "receipt provenance metadata supply_chain must be an object".to_string(),
        ));
    }

    let provenance: ReceiptProvenanceMetadata = serde_json::from_value(provenance.clone())
        .map_err(|error| {
            KernelError::ReceiptSigningFailed(format!(
                "receipt provenance metadata violates schema: {error}"
            ))
        })?;

    if !is_w3c_trace_id(&provenance.otel.trace_id) {
        return Err(KernelError::ReceiptSigningFailed(format!(
            "receipt provenance metadata trace_id must be 32 non-zero lowercase hex chars, got {:?}",
            provenance.otel.trace_id
        )));
    }
    if !is_w3c_span_id(&provenance.otel.span_id) {
        return Err(KernelError::ReceiptSigningFailed(format!(
            "receipt provenance metadata span_id must be 16 non-zero lowercase hex chars, got {:?}",
            provenance.otel.span_id
        )));
    }
    if provenance
        .supply_chain
        .as_ref()
        .is_some_and(|supply_chain| !supply_chain.is_object())
    {
        return Err(KernelError::ReceiptSigningFailed(
            "receipt provenance metadata supply_chain must be an object".to_string(),
        ));
    }

    serde_json::to_value(provenance)
        .map(|provenance| Some(serde_json::json!({ "provenance": provenance })))
        .map_err(|error| {
            KernelError::ReceiptSigningFailed(format!(
                "failed to serialize receipt provenance metadata: {error}"
            ))
        })
}

pub(super) fn verify_governed_runtime_attestation_record(
    attestation: &chio_core::capability::RuntimeAttestationEvidence,
    attestation_trust_policy: Option<&AttestationTrustPolicy>,
    now: u64,
) -> Result<VerifiedRuntimeAttestationRecord, KernelError> {
    verify_runtime_attestation_record(attestation, attestation_trust_policy, now).map_err(|error| {
        KernelError::GovernedTransactionDenied(format!(
            "runtime attestation evidence rejected by local verification boundary: {error}"
        ))
    })
}

fn verified_runtime_assurance_receipt_metadata(
    verified_runtime_attestation: &VerifiedRuntimeAttestationRecord,
) -> Option<RuntimeAssuranceReceiptMetadata> {
    if !verified_runtime_attestation.is_locally_accepted() {
        return None;
    }

    Some(RuntimeAssuranceReceiptMetadata {
        schema: verified_runtime_attestation.evidence.schema.clone(),
        verifier_family: Some(verified_runtime_attestation.provenance.verifier_family),
        tier: verified_runtime_attestation.effective_tier(),
        verifier: verified_runtime_attestation
            .provenance
            .canonical_verifier
            .clone(),
        evidence_sha256: verified_runtime_attestation
            .evidence
            .evidence_sha256
            .clone(),
        workload_identity: verified_runtime_attestation.workload_identity().cloned(),
    })
}

fn governed_runtime_assurance_receipt_metadata(
    attestation: Option<&chio_core::capability::RuntimeAttestationEvidence>,
    attestation_trust_policy: Option<&AttestationTrustPolicy>,
    now: u64,
) -> Option<RuntimeAssuranceReceiptMetadata> {
    let attestation = attestation?;
    let verified_runtime_attestation =
        verify_governed_runtime_attestation_record(attestation, attestation_trust_policy, now)
            .ok()?;
    verified_runtime_assurance_receipt_metadata(&verified_runtime_attestation)
}

fn governed_economic_authorization_metadata(
    request: &ToolCallRequest,
    financial: &FinancialReceiptMetadata,
) -> Result<Option<chio_core::receipt::EconomicAuthorizationReceiptMetadata>, KernelError> {
    let Some(intent) = request.governed_intent.as_ref() else {
        return Ok(None);
    };

    let approved_max = intent
        .max_amount
        .clone()
        .unwrap_or(chio_core::capability::MonetaryAmount {
            units: financial.budget_total,
            currency: financial.currency.clone(),
        });
    let hold_amount_units = financial.attempted_cost.or_else(|| {
        financial
            .payment_reference
            .as_ref()
            .map(|_| financial.cost_charged)
    });
    let settlement_cap_units = financial.attempted_cost.unwrap_or(financial.cost_charged);
    let commerce = intent.commerce.as_ref();
    let metered = intent.metered_billing.as_ref();

    let pricing_basis = metered
        .map(|metered| {
            canonical_json_bytes(&metered.quote)
                .map(|quote_bytes| chio_core::sha256_hex(&quote_bytes))
                .map(
                    |quote_hash| chio_core::receipt::EconomicPricingBasisReceiptMetadata {
                        quote_hash: Some(quote_hash),
                        tariff_hash: None,
                        quote_expiry: metered.quote.expires_at,
                    },
                )
                .map_err(|error| {
                    KernelError::ReceiptSigningFailed(format!(
                        "failed to canonicalize metered billing quote for receipt metadata: {error}"
                    ))
                })
        })
        .transpose()?;

    let metering = metered
        .map(|metered| {
            canonical_json_bytes(&serde_json::json!({
                "provider": &metered.quote.provider,
                "billing_unit": &metered.quote.billing_unit,
                "quoted_units": metered.quote.quoted_units,
                "settlement_mode": metered.settlement_mode,
                "max_billed_units": metered.max_billed_units,
            }))
            .map(|profile_bytes| chio_core::sha256_hex(&profile_bytes))
            .map(
                |meter_profile_hash| chio_core::receipt::EconomicMeteringReceiptMetadata {
                    provider: metered.quote.provider.clone(),
                    meter_profile_hash,
                    max_billable_units: metered.max_billed_units,
                    billing_unit: Some(metered.quote.billing_unit.clone()),
                },
            )
            .map_err(|error| {
                KernelError::ReceiptSigningFailed(format!(
                    "failed to canonicalize metering profile for receipt metadata: {error}"
                ))
            })
        })
        .transpose()?;

    let economic_mode = if let Some(metered) = metered {
        match metered.settlement_mode {
            chio_core::capability::MeteredSettlementMode::MustPrepay => {
                chio_core::receipt::EconomicAuthorizationMode::PrepaidFixed
            }
            chio_core::capability::MeteredSettlementMode::HoldCapture => {
                chio_core::receipt::EconomicAuthorizationMode::MeteredHoldCapture
            }
            chio_core::capability::MeteredSettlementMode::AllowThenSettle => {
                chio_core::receipt::EconomicAuthorizationMode::ExternalDispatch
            }
        }
    } else if financial.payment_reference.is_some() {
        chio_core::receipt::EconomicAuthorizationMode::HoldCapture
    } else {
        chio_core::receipt::EconomicAuthorizationMode::BudgetOnly
    };

    Ok(Some(
        chio_core::receipt::EconomicAuthorizationReceiptMetadata {
            version: chio_core::receipt::EconomicAuthorizationReceiptMetadataVersion::V1,
            economic_mode,
            payer: chio_core::receipt::EconomicPayerReceiptMetadata {
                party_id: request.agent_id.clone(),
                funding_source_ref: commerce
                    .map(|commerce| commerce.shared_payment_token_id.clone())
                    .or_else(|| financial.payment_reference.clone())
                    .unwrap_or_else(|| request.capability.id.clone()),
                custody_provider: None,
                obligor_ref: None,
            },
            merchant: chio_core::receipt::EconomicMerchantReceiptMetadata {
                merchant_id: commerce
                    .map(|commerce| commerce.seller.clone())
                    .unwrap_or_else(|| request.server_id.clone()),
                merchant_of_record: None,
                order_ref: Some(request.request_id.clone()),
            },
            payee: chio_core::receipt::EconomicPayeeReceiptMetadata {
                beneficiary_id: request.server_id.clone(),
                settlement_destination_ref: financial
                    .payment_reference
                    .clone()
                    .or_else(|| commerce.map(|commerce| commerce.shared_payment_token_id.clone()))
                    .unwrap_or_else(|| request.server_id.clone()),
            },
            rail: chio_core::receipt::EconomicRailReceiptMetadata {
                kind: if commerce.is_some() {
                    "shared_payment_token".to_string()
                } else if metered.is_some() {
                    "metered_billing".to_string()
                } else if financial.payment_reference.is_some() {
                    "payment_adapter".to_string()
                } else {
                    "kernel_budget".to_string()
                },
                asset: financial.currency.clone(),
                network: None,
                facilitator: metered.map(|metered| metered.quote.provider.clone()),
                contract_or_account_ref: financial
                    .payment_reference
                    .clone()
                    .or_else(|| commerce.map(|commerce| commerce.shared_payment_token_id.clone())),
            },
            amount_bounds: chio_core::receipt::EconomicAmountBoundsReceiptMetadata {
                approved_max,
                hold_amount: hold_amount_units.map(|units| chio_core::capability::MonetaryAmount {
                    units,
                    currency: financial.currency.clone(),
                }),
                settlement_cap: chio_core::capability::MonetaryAmount {
                    units: settlement_cap_units,
                    currency: financial.currency.clone(),
                },
            },
            pricing_basis,
            metering,
            liability_refs: None,
            budget: chio_core::receipt::EconomicBudgetReceiptMetadata {
                grant_index: financial.grant_index,
                cost_charged: financial.cost_charged,
                currency: financial.currency.clone(),
                budget_remaining: financial.budget_remaining,
                budget_total: financial.budget_total,
                delegation_depth: financial.delegation_depth,
                root_budget_holder: financial.root_budget_holder.clone(),
                attempted_cost: financial.attempted_cost,
            },
            settlement: chio_core::receipt::EconomicSettlementReceiptMetadata {
                settlement_status: financial.settlement_status.clone(),
            },
        },
    ))
}

fn inject_governed_economic_authorization_metadata(
    metadata: Option<serde_json::Value>,
    economic_authorization: Option<chio_core::receipt::EconomicAuthorizationReceiptMetadata>,
) -> Result<Option<serde_json::Value>, KernelError> {
    let Some(economic_authorization) = economic_authorization else {
        return Ok(metadata);
    };
    let Some(mut metadata) = metadata else {
        return Ok(None);
    };
    let Some(metadata_object) = metadata.as_object_mut() else {
        return Ok(Some(metadata));
    };
    let Some(governed_transaction) = metadata_object.get_mut("governed_transaction") else {
        return Ok(Some(metadata));
    };
    let Some(governed_transaction_object) = governed_transaction.as_object_mut() else {
        return Err(KernelError::ReceiptSigningFailed(
            "governed receipt metadata was not an object while attaching economic authorization"
                .to_string(),
        ));
    };

    governed_transaction_object.insert(
        "economic_authorization".to_string(),
        serde_json::to_value(economic_authorization).map_err(|error| {
            KernelError::ReceiptSigningFailed(format!(
                "failed to serialize governed economic receipt metadata: {error}"
            ))
        })?,
    );

    Ok(Some(metadata))
}

pub(super) fn governed_request_metadata(
    request: &ToolCallRequest,
    attestation_trust_policy: Option<&AttestationTrustPolicy>,
    now: u64,
) -> Result<Option<serde_json::Value>, KernelError> {
    let Some(intent) = request.governed_intent.as_ref() else {
        return Ok(None);
    };

    let approval =
        request
            .approval_token
            .as_ref()
            .map(|approval_token| GovernedApprovalReceiptMetadata {
                token_id: approval_token.id.clone(),
                approver_key: approval_token.approver.to_hex(),
                approved: approval_token.decision == GovernedApprovalDecision::Approved,
            });
    let commerce = intent
        .commerce
        .as_ref()
        .map(|commerce| GovernedCommerceReceiptMetadata {
            seller: commerce.seller.clone(),
            shared_payment_token_id: commerce.shared_payment_token_id.clone(),
        });
    let metered_billing =
        intent
            .metered_billing
            .as_ref()
            .map(|metered| MeteredBillingReceiptMetadata {
                settlement_mode: metered.settlement_mode,
                quote: metered.quote.clone(),
                max_billed_units: metered.max_billed_units,
                usage_evidence: None,
            });
    let runtime_assurance = if let Some(verified_runtime_attestation) =
        current_governed_runtime_attestation_record()
    {
        if intent
            .runtime_attestation
            .as_ref()
            .is_some_and(|attestation| verified_runtime_attestation.evidence != *attestation)
        {
            return Err(KernelError::ReceiptSigningFailed(
                "governed request runtime attestation does not match the scoped verified runtime attestation record".to_string(),
            ));
        }
        verified_runtime_assurance_receipt_metadata(&verified_runtime_attestation)
    } else {
        governed_runtime_assurance_receipt_metadata(
            intent.runtime_attestation.as_ref(),
            attestation_trust_policy,
            now,
        )
    };
    let autonomy = intent
        .autonomy
        .as_ref()
        .map(|autonomy| GovernedAutonomyReceiptMetadata {
            tier: autonomy.tier,
            delegation_bond_id: autonomy.delegation_bond_id.clone(),
        });
    let call_chain = intent
        .call_chain
        .clone()
        .map(governed_call_chain_provenance);
    let governed_transaction_diagnostics = governed_transaction_diagnostics(call_chain.as_ref());
    let metadata = GovernedTransactionReceiptMetadata {
        intent_id: intent.id.clone(),
        intent_hash: intent.binding_hash().map_err(|error| {
            KernelError::ReceiptSigningFailed(format!(
                "failed to hash governed transaction intent for receipt metadata: {error}"
            ))
        })?,
        purpose: intent.purpose.clone(),
        server_id: intent.server_id.clone(),
        tool_name: intent.tool_name.clone(),
        max_amount: intent.max_amount.clone(),
        commerce,
        metered_billing,
        approval,
        runtime_assurance,
        call_chain: call_chain.clone(),
        autonomy,
        economic_authorization: None,
    };

    let mut metadata_object = serde_json::Map::from_iter([(
        "governed_transaction".to_string(),
        serde_json::to_value(metadata).map_err(|error| {
            KernelError::ReceiptSigningFailed(format!(
                "failed to serialize governed receipt metadata: {error}"
            ))
        })?,
    )]);
    if let Some(diagnostics) = governed_transaction_diagnostics {
        metadata_object.insert(
            "governed_transaction_diagnostics".to_string(),
            serde_json::to_value(diagnostics).map_err(|error| {
                KernelError::ReceiptSigningFailed(format!(
                    "failed to serialize governed transaction diagnostics: {error}"
                ))
            })?,
        );
    }

    Ok(Some(serde_json::Value::Object(metadata_object)))
}

pub(super) fn request_receipt_metadata(
    request: &ToolCallRequest,
    attestation_trust_policy: Option<&AttestationTrustPolicy>,
    now: u64,
    extra_metadata: Option<&serde_json::Value>,
) -> Result<Option<serde_json::Value>, KernelError> {
    let governed_metadata = governed_request_metadata(request, attestation_trust_policy, now)?;
    let financial = extra_metadata
        .and_then(serde_json::Value::as_object)
        .and_then(|extra_metadata| extra_metadata.get("financial"))
        .cloned()
        .and_then(|financial| serde_json::from_value::<FinancialReceiptMetadata>(financial).ok());
    let governed_metadata = inject_governed_economic_authorization_metadata(
        governed_metadata,
        financial
            .as_ref()
            .map(|financial| governed_economic_authorization_metadata(request, financial))
            .transpose()?
            .flatten(),
    )?;
    let provenance_metadata = receipt_provenance_metadata(extra_metadata)?;

    Ok(merge_metadata_objects(
        merge_metadata_objects(
            governed_metadata,
            request_model_metadata_receipt_metadata(request),
        ),
        provenance_metadata,
    ))
}

pub(super) fn receipt_attribution_metadata(
    capability: &CapabilityToken,
    matched_grant_index: Option<usize>,
) -> Option<serde_json::Value> {
    Some(serde_json::json!({
        "attribution": ReceiptAttributionMetadata {
            subject_key: capability.subject.to_hex(),
            issuer_key: capability.issuer.to_hex(),
            delegation_depth: capability.delegation_chain.len() as u32,
            grant_index: matched_grant_index.map(|index| index as u32),
        }
    }))
}

pub(super) fn request_model_metadata_receipt_metadata(
    request: &ToolCallRequest,
) -> Option<serde_json::Value> {
    request.model_metadata.as_ref().map(|model_metadata| {
        serde_json::json!({
            "model_metadata": chio_core::receipt::ModelMetadataReceiptMetadata::from(model_metadata)
        })
    })
}

fn child_receipt_metadata(outcome_payload: &serde_json::Value) -> Option<serde_json::Value> {
    outcome_payload
        .get("outcome")
        .and_then(serde_json::Value::as_str)
        .map(|outcome| {
            let mut metadata = serde_json::Map::new();
            metadata.insert(
                "outcome".to_string(),
                serde_json::Value::String(outcome.to_string()),
            );
            if let Some(message) = outcome_payload
                .get("message")
                .and_then(serde_json::Value::as_str)
            {
                metadata.insert(
                    "message".to_string(),
                    serde_json::Value::String(message.to_string()),
                );
            }
            serde_json::Value::Object(metadata)
        })
}

pub(super) fn child_terminal_state<T>(
    request_id: &RequestId,
    result: &Result<T, KernelError>,
) -> OperationTerminalState {
    match result {
        Ok(_) => OperationTerminalState::Completed,
        Err(KernelError::RequestCancelled {
            request_id: cancelled_request_id,
            reason,
        }) if cancelled_request_id == request_id => OperationTerminalState::Cancelled {
            reason: reason.clone(),
        },
        Err(KernelError::RequestIncomplete(reason)) => OperationTerminalState::Incomplete {
            reason: reason.clone(),
        },
        Err(_) => OperationTerminalState::Completed,
    }
}

pub(super) fn child_outcome_payload<T: serde::Serialize>(
    result: &Result<T, KernelError>,
) -> Result<serde_json::Value, KernelError> {
    match result {
        Ok(value) => {
            let mut payload = serde_json::Map::new();
            payload.insert(
                "outcome".to_string(),
                serde_json::Value::String("result".into()),
            );
            payload.insert(
                "result".to_string(),
                serde_json::to_value(value).map_err(|error| {
                    KernelError::ReceiptSigningFailed(format!(
                        "failed to serialize child result: {error}"
                    ))
                })?,
            );
            Ok(serde_json::Value::Object(payload))
        }
        Err(error) => Ok(serde_json::json!({
            "outcome": "error",
            "message": error.to_string(),
        })),
    }
}

pub(super) fn receipt_content_for_output(
    output: Option<&ToolCallOutput>,
    stream_chunks_expected: Option<u64>,
) -> Result<ReceiptContent, KernelError> {
    match output {
        Some(ToolCallOutput::Value(value)) => {
            let bytes = canonical_json_bytes(value).map_err(|e| {
                KernelError::ReceiptSigningFailed(format!("failed to hash tool output: {e}"))
            })?;
            Ok(ReceiptContent {
                content_hash: sha256_hex(&bytes),
                metadata: None,
            })
        }
        Some(ToolCallOutput::Stream(stream)) => {
            stream_receipt_content(stream, stream_chunks_expected)
        }
        None => Ok(ReceiptContent {
            content_hash: sha256_hex(b"null"),
            metadata: None,
        }),
    }
}

fn stream_receipt_content(
    stream: &ToolCallStream,
    chunks_expected: Option<u64>,
) -> Result<ReceiptContent, KernelError> {
    let mut chunk_hashes = Vec::with_capacity(stream.chunks.len());
    let mut combined = Vec::new();
    let mut total_bytes = 0u64;

    for chunk in &stream.chunks {
        let bytes = canonical_json_bytes(&chunk.data).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash stream chunk: {e}"))
        })?;
        total_bytes += bytes.len() as u64;
        let chunk_hash = sha256_hex(&bytes);
        combined.extend_from_slice(chunk_hash.as_bytes());
        chunk_hashes.push(chunk_hash);
    }

    Ok(ReceiptContent {
        content_hash: sha256_hex(&combined),
        metadata: Some(serde_json::json!({
            "stream": {
                "chunks_expected": chunks_expected,
                "chunks_received": stream.chunk_count(),
                "total_bytes": total_bytes,
                "chunk_hashes": chunk_hashes,
            }
        })),
    })
}

pub(super) fn truncate_stream_to_byte_limit(
    stream: &ToolCallStream,
    max_stream_total_bytes: u64,
) -> Result<(ToolCallStream, u64, bool), KernelError> {
    let mut accepted = Vec::new();
    let mut total_bytes = 0u64;
    let mut truncated = false;

    for chunk in &stream.chunks {
        let bytes = canonical_json_bytes(&chunk.data).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to size stream chunk: {e}"))
        })?;
        let chunk_bytes = bytes.len() as u64;
        if max_stream_total_bytes > 0
            && total_bytes.saturating_add(chunk_bytes) > max_stream_total_bytes
        {
            truncated = true;
            break;
        }
        total_bytes += chunk_bytes;
        accepted.push(chunk.clone());
    }

    Ok((ToolCallStream { chunks: accepted }, total_bytes, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::capability::{
        AttestationTrustPolicy, AttestationTrustRule, CapabilityToken, CapabilityTokenBody,
        ChioScope, GovernedCallChainContext, GovernedProvenanceEvidenceClass,
        GovernedTransactionIntent, GovernedUpstreamCallChainProof,
        GovernedUpstreamCallChainProofBody, RuntimeAssuranceTier, RuntimeAttestationEvidence,
    };
    use chio_core::crypto::sha256_hex;

    fn test_capability() -> CapabilityToken {
        let keypair = Keypair::generate();
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap-test".to_string(),
                issuer: keypair.public_key(),
                subject: keypair.public_key(),
                scope: ChioScope::default(),
                issued_at: 100,
                expires_at: 200,
                delegation_chain: Vec::new(),
            },
            &keypair,
        )
        .expect("test capability should sign")
    }

    fn trusted_attestation_trust_policy() -> AttestationTrustPolicy {
        AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "azure-contoso".to_string(),
                schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(chio_core::appraisal::AttestationVerifierFamily::AzureMaa),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: vec!["sgx".to_string()],
                required_assertions: std::collections::BTreeMap::new(),
            }],
        }
    }

    fn raw_runtime_attestation() -> RuntimeAttestationEvidence {
        RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.v1".to_string(),
            verifier: "verifier.chio".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: sha256_hex(b"raw-runtime-attestation"),
            runtime_identity: Some("spiffe://chio/runtime/test".to_string()),
            workload_identity: None,
            claims: None,
        }
    }

    fn trusted_runtime_attestation() -> RuntimeAttestationEvidence {
        RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test/".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: sha256_hex(b"trusted-runtime-attestation"),
            runtime_identity: Some("spiffe://chio/runtime/test".to_string()),
            workload_identity: None,
            claims: Some(serde_json::json!({
                "azureMaa": {
                    "attestationType": "sgx"
                }
            })),
        }
    }

    fn trusted_nitro_attestation_trust_policy() -> AttestationTrustPolicy {
        AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "aws-nitro".to_string(),
                schema: "chio.runtime-attestation.aws-nitro-attestation.v1".to_string(),
                verifier: "https://nitro.aws.example".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(chio_core::appraisal::AttestationVerifierFamily::AwsNitro),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: Vec::new(),
                required_assertions: std::collections::BTreeMap::new(),
            }],
        }
    }

    fn trusted_nitro_runtime_attestation() -> RuntimeAttestationEvidence {
        RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.aws-nitro-attestation.v1".to_string(),
            verifier: "https://nitro.aws.example/".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: sha256_hex(b"trusted-nitro-runtime-attestation"),
            runtime_identity: None,
            workload_identity: None,
            claims: Some(serde_json::json!({
                "awsNitro": {
                    "moduleId": "nitro-enclave-1",
                    "digest": "sha384:aws-measurement",
                    "pcrs": { "0": "0123" }
                }
            })),
        }
    }

    #[test]
    fn governed_request_metadata_preserves_asserted_call_chain_and_diagnostics() {
        let call_chain = GovernedCallChainContext {
            chain_id: "chain-1".to_string(),
            parent_request_id: "req-parent-1".to_string(),
            parent_receipt_id: Some("rcpt-parent-1".to_string()),
            origin_subject: "origin-subject".to_string(),
            delegator_subject: "delegator-subject".to_string(),
        };
        let request = ToolCallRequest {
            request_id: "req-current-1".to_string(),
            capability: test_capability(),
            tool_name: "charge".to_string(),
            server_id: "srv-pay".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({ "invoice_id": "inv-1" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-1".to_string(),
                server_id: "srv-pay".to_string(),
                tool_name: "charge".to_string(),
                purpose: "pay supplier".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: Some(call_chain.clone()),
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };

        let metadata = governed_request_metadata(&request, None, 0)
            .expect("metadata should build")
            .expect("governed metadata should exist");
        let governed: GovernedTransactionReceiptMetadata =
            serde_json::from_value(metadata["governed_transaction"].clone())
                .expect("receipt metadata should deserialize");
        let governed_call_chain = governed
            .call_chain
            .expect("asserted call-chain should remain visible on the signed receipt");
        assert_eq!(
            governed_call_chain.evidence_class,
            GovernedProvenanceEvidenceClass::Asserted
        );
        assert_eq!(
            metadata["governed_transaction_diagnostics"]["assertedCallChain"]["evidenceClass"],
            serde_json::json!("asserted")
        );
        assert_eq!(
            metadata["governed_transaction_diagnostics"]["assertedCallChain"]["chainId"],
            serde_json::json!("chain-1")
        );
        assert_eq!(
            metadata["governed_transaction_diagnostics"]["assertedCallChain"]["parentRequestId"],
            serde_json::json!("req-parent-1")
        );
        let diagnostics: GovernedTransactionDiagnostics =
            serde_json::from_value(metadata["governed_transaction_diagnostics"].clone())
                .expect("diagnostics should deserialize");
        let provenance = diagnostics
            .asserted_call_chain
            .expect("asserted call-chain should be preserved in diagnostics");
        assert_eq!(
            provenance.evidence_class,
            GovernedProvenanceEvidenceClass::Asserted
        );
        assert!(provenance.evidence_sources.is_empty());
        assert_eq!(provenance.into_inner(), call_chain);
    }

    #[test]
    fn governed_request_metadata_marks_matching_local_call_chain_evidence_as_observed() {
        let call_chain = GovernedCallChainContext {
            chain_id: "chain-2".to_string(),
            parent_request_id: "req-parent-2".to_string(),
            parent_receipt_id: Some("rcpt-parent-2".to_string()),
            origin_subject: "subject-origin".to_string(),
            delegator_subject: "subject-delegator".to_string(),
        };
        let request = ToolCallRequest {
            request_id: "req-current-2".to_string(),
            capability: test_capability(),
            tool_name: "charge".to_string(),
            server_id: "srv-pay".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({ "invoice_id": "inv-2" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-2".to_string(),
                server_id: "srv-pay".to_string(),
                tool_name: "charge".to_string(),
                purpose: "pay supplier".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: Some(call_chain.clone()),
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        let _scope =
            scope_governed_call_chain_receipt_evidence(Some(GovernedCallChainReceiptEvidence {
                local_parent_request_id: Some("req-parent-2".to_string()),
                local_parent_receipt_id: Some("rcpt-parent-2".to_string()),
                capability_delegator_subject: Some("subject-delegator".to_string()),
                capability_origin_subject: Some("subject-origin".to_string()),
                upstream_proof: None,
                continuation_token_id: None,
                session_anchor_id: None,
            }));

        let metadata = governed_request_metadata(&request, None, 0)
            .expect("metadata should build")
            .expect("governed metadata should exist");
        let governed: GovernedTransactionReceiptMetadata =
            serde_json::from_value(metadata["governed_transaction"].clone())
                .expect("receipt metadata should deserialize");
        let provenance = governed
            .call_chain
            .expect("call-chain provenance should be present");

        assert_eq!(
            provenance.evidence_class,
            GovernedProvenanceEvidenceClass::Observed
        );
        assert_eq!(
            provenance.evidence_sources,
            vec![
                GovernedCallChainEvidenceSource::SessionParentRequestLineage,
                GovernedCallChainEvidenceSource::LocalParentReceiptLinkage,
                GovernedCallChainEvidenceSource::CapabilityDelegatorSubject,
                GovernedCallChainEvidenceSource::CapabilityOriginSubject,
            ]
        );
        assert_eq!(provenance.into_inner(), call_chain);
        assert!(metadata.get("governed_transaction_diagnostics").is_none());
    }

    #[test]
    fn governed_request_metadata_marks_validated_upstream_call_chain_proof_as_verified() {
        let signer = Keypair::generate();
        let subject = Keypair::generate();
        let call_chain = GovernedCallChainContext {
            chain_id: "chain-verified".to_string(),
            parent_request_id: "req-parent-verified".to_string(),
            parent_receipt_id: Some("rcpt-parent-verified".to_string()),
            origin_subject: "subject-origin".to_string(),
            delegator_subject: "subject-delegator".to_string(),
        };
        let upstream_proof = GovernedUpstreamCallChainProof::sign(
            GovernedUpstreamCallChainProofBody {
                signer: signer.public_key(),
                subject: subject.public_key(),
                chain_id: call_chain.chain_id.clone(),
                parent_request_id: call_chain.parent_request_id.clone(),
                parent_receipt_id: call_chain.parent_receipt_id.clone(),
                origin_subject: call_chain.origin_subject.clone(),
                delegator_subject: call_chain.delegator_subject.clone(),
                issued_at: 100,
                expires_at: 200,
            },
            &signer,
        )
        .expect("upstream proof should sign");
        let request = ToolCallRequest {
            request_id: "req-current-verified".to_string(),
            capability: test_capability(),
            tool_name: "charge".to_string(),
            server_id: "srv-pay".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({ "invoice_id": "inv-verified" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-verified".to_string(),
                server_id: "srv-pay".to_string(),
                tool_name: "charge".to_string(),
                purpose: "pay supplier".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: Some(call_chain.clone()),
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        let _scope =
            scope_governed_call_chain_receipt_evidence(Some(GovernedCallChainReceiptEvidence {
                local_parent_request_id: None,
                local_parent_receipt_id: None,
                capability_delegator_subject: None,
                capability_origin_subject: None,
                upstream_proof: Some(upstream_proof.clone()),
                continuation_token_id: Some("continuation-verified".to_string()),
                session_anchor_id: Some("anchor-verified".to_string()),
            }));

        let metadata = governed_request_metadata(&request, None, 0)
            .expect("metadata should build")
            .expect("governed metadata should exist");
        let governed: GovernedTransactionReceiptMetadata =
            serde_json::from_value(metadata["governed_transaction"].clone())
                .expect("receipt metadata should deserialize");
        let provenance = governed
            .call_chain
            .expect("call-chain provenance should be present");

        assert_eq!(
            provenance.evidence_class,
            GovernedProvenanceEvidenceClass::Verified
        );
        assert_eq!(
            provenance.evidence_sources,
            vec![GovernedCallChainEvidenceSource::UpstreamDelegatorProof]
        );
        assert_eq!(provenance.upstream_proof, Some(upstream_proof));
        assert_eq!(
            provenance.continuation_token_id.as_deref(),
            Some("continuation-verified")
        );
        assert_eq!(
            provenance.session_anchor_id.as_deref(),
            Some("anchor-verified")
        );
        assert_eq!(provenance.into_inner(), call_chain);
        assert_eq!(
            metadata["governed_transaction_diagnostics"]["lineageReferences"]["sessionAnchorId"],
            serde_json::json!("anchor-verified")
        );
        assert!(metadata["governed_transaction_diagnostics"]["assertedCallChain"].is_null());
    }

    #[test]
    fn governed_request_metadata_omits_unverified_runtime_assurance() {
        let request = ToolCallRequest {
            request_id: "req-current-3".to_string(),
            capability: test_capability(),
            tool_name: "charge".to_string(),
            server_id: "srv-pay".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({ "invoice_id": "inv-3" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-3".to_string(),
                server_id: "srv-pay".to_string(),
                tool_name: "charge".to_string(),
                purpose: "pay supplier".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: Some(raw_runtime_attestation()),
                call_chain: None,
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };

        let metadata = governed_request_metadata(&request, None, 150)
            .expect("metadata should build")
            .expect("governed metadata should exist");
        let governed: GovernedTransactionReceiptMetadata =
            serde_json::from_value(metadata["governed_transaction"].clone())
                .expect("receipt metadata should deserialize");

        assert!(
            governed.runtime_assurance.is_none(),
            "raw runtime attestation should not appear as verified receipt authority"
        );
    }

    #[test]
    fn governed_request_metadata_uses_verified_runtime_assurance_boundary() {
        let request = ToolCallRequest {
            request_id: "req-current-4".to_string(),
            capability: test_capability(),
            tool_name: "charge".to_string(),
            server_id: "srv-pay".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({ "invoice_id": "inv-4" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-4".to_string(),
                server_id: "srv-pay".to_string(),
                tool_name: "charge".to_string(),
                purpose: "pay supplier".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: Some(trusted_runtime_attestation()),
                call_chain: None,
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };

        let metadata =
            governed_request_metadata(&request, Some(&trusted_attestation_trust_policy()), 150)
                .expect("metadata should build")
                .expect("governed metadata should exist");
        let governed: GovernedTransactionReceiptMetadata =
            serde_json::from_value(metadata["governed_transaction"].clone())
                .expect("receipt metadata should deserialize");
        let runtime_assurance = governed
            .runtime_assurance
            .expect("verified runtime assurance should be present");

        assert_eq!(runtime_assurance.tier, RuntimeAssuranceTier::Verified);
        assert_eq!(
            runtime_assurance.verifier_family,
            Some(chio_core::appraisal::AttestationVerifierFamily::AzureMaa)
        );
        assert_eq!(runtime_assurance.verifier, "https://maa.contoso.test");
        assert_eq!(
            runtime_assurance
                .workload_identity
                .expect("verified workload identity should be present")
                .trust_domain,
            "chio"
        );
    }

    #[test]
    fn governed_request_metadata_prefers_scoped_nitro_verified_record() {
        let attestation = trusted_nitro_runtime_attestation();
        let verified_runtime_attestation = verify_governed_runtime_attestation_record(
            &attestation,
            Some(&trusted_nitro_attestation_trust_policy()),
            150,
        )
        .expect("nitro attestation should verify at governed admission");
        let request = ToolCallRequest {
            request_id: "req-current-nitro".to_string(),
            capability: test_capability(),
            tool_name: "charge".to_string(),
            server_id: "srv-pay".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({ "invoice_id": "inv-nitro" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-nitro".to_string(),
                server_id: "srv-pay".to_string(),
                tool_name: "charge".to_string(),
                purpose: "pay supplier".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: Some(attestation),
                call_chain: None,
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        let _scope =
            scope_governed_runtime_attestation_receipt_record(Some(verified_runtime_attestation));

        let metadata = governed_request_metadata(&request, None, 150)
            .expect("metadata should build")
            .expect("governed metadata should exist");
        let governed: GovernedTransactionReceiptMetadata =
            serde_json::from_value(metadata["governed_transaction"].clone())
                .expect("receipt metadata should deserialize");
        let runtime_assurance = governed
            .runtime_assurance
            .expect("scoped verified runtime assurance should be present");

        assert_eq!(runtime_assurance.tier, RuntimeAssuranceTier::Verified);
        assert_eq!(
            runtime_assurance.verifier_family,
            Some(chio_core::appraisal::AttestationVerifierFamily::AwsNitro)
        );
        assert_eq!(runtime_assurance.verifier, "https://nitro.aws.example");
        assert_eq!(
            runtime_assurance.evidence_sha256,
            sha256_hex(b"trusted-nitro-runtime-attestation")
        );
    }

    #[test]
    fn governed_request_metadata_rejects_mismatched_scoped_runtime_attestation_record() {
        let attestation = trusted_nitro_runtime_attestation();
        let verified_runtime_attestation = verify_governed_runtime_attestation_record(
            &attestation,
            Some(&trusted_nitro_attestation_trust_policy()),
            150,
        )
        .expect("nitro attestation should verify at governed admission");
        let mut mismatched_attestation = attestation.clone();
        mismatched_attestation.evidence_sha256 =
            sha256_hex(b"mismatched-nitro-runtime-attestation");
        let request = ToolCallRequest {
            request_id: "req-current-nitro-mismatch".to_string(),
            capability: test_capability(),
            tool_name: "charge".to_string(),
            server_id: "srv-pay".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({ "invoice_id": "inv-nitro-mismatch" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-nitro-mismatch".to_string(),
                server_id: "srv-pay".to_string(),
                tool_name: "charge".to_string(),
                purpose: "pay supplier".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: Some(mismatched_attestation),
                call_chain: None,
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        let _scope =
            scope_governed_runtime_attestation_receipt_record(Some(verified_runtime_attestation));

        let error = governed_request_metadata(&request, None, 150)
            .expect_err("mismatched scoped runtime attestation should fail closed");
        assert!(
            error.to_string().contains(
                "governed request runtime attestation does not match the scoped verified runtime attestation record"
            ),
            "expected mismatch error, got {error}"
        );
    }

    #[test]
    fn request_receipt_metadata_projects_economic_authorization_from_financial_metadata() {
        let request = ToolCallRequest {
            request_id: "req-economic-1".to_string(),
            capability: test_capability(),
            tool_name: "charge".to_string(),
            server_id: "srv-pay".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({ "invoice_id": "inv-economic-1" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-economic-1".to_string(),
                server_id: "srv-pay".to_string(),
                tool_name: "charge".to_string(),
                purpose: "pay supplier".to_string(),
                max_amount: Some(chio_core::capability::MonetaryAmount {
                    units: 500,
                    currency: "USD".to_string(),
                }),
                commerce: Some(chio_core::capability::GovernedCommerceContext {
                    seller: "seller-1".to_string(),
                    shared_payment_token_id: "shared-token-1".to_string(),
                }),
                metered_billing: Some(chio_core::capability::MeteredBillingContext {
                    settlement_mode: chio_core::capability::MeteredSettlementMode::HoldCapture,
                    quote: chio_core::capability::MeteredBillingQuote {
                        quote_id: "quote-1".to_string(),
                        provider: "meterd".to_string(),
                        billing_unit: "1k_tokens".to_string(),
                        quoted_units: 42,
                        quoted_cost: chio_core::capability::MonetaryAmount {
                            units: 230,
                            currency: "USD".to_string(),
                        },
                        issued_at: 100,
                        expires_at: Some(200),
                    },
                    max_billed_units: Some(100),
                }),
                runtime_attestation: None,
                call_chain: None,
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        let extra_metadata = serde_json::json!({
            "financial": FinancialReceiptMetadata {
                grant_index: 1,
                cost_charged: 230,
                currency: "USD".to_string(),
                budget_remaining: 770,
                budget_total: 1000,
                delegation_depth: 0,
                root_budget_holder: "issuer-1".to_string(),
                payment_reference: Some("payref-1".to_string()),
                settlement_status: SettlementStatus::Pending,
                cost_breakdown: None,
                oracle_evidence: None,
                attempted_cost: Some(250),
            }
        });

        let metadata = request_receipt_metadata(&request, None, 150, Some(&extra_metadata))
            .expect("metadata should build")
            .expect("receipt metadata should exist");
        let governed: GovernedTransactionReceiptMetadata =
            serde_json::from_value(metadata["governed_transaction"].clone())
                .expect("governed metadata should deserialize");
        let economic = governed
            .economic_authorization
            .expect("economic authorization should be present");

        assert_eq!(
            economic.economic_mode,
            chio_core::receipt::EconomicAuthorizationMode::MeteredHoldCapture
        );
        assert_eq!(economic.budget.currency, "USD");
        assert_eq!(economic.budget.cost_charged, 230);
        assert_eq!(economic.rail.kind, "shared_payment_token");
        assert_eq!(
            economic.rail.contract_or_account_ref.as_deref(),
            Some("payref-1")
        );
        assert_eq!(
            economic.settlement.settlement_status,
            SettlementStatus::Pending
        );
        assert_eq!(
            economic
                .metering
                .expect("metering projection should be present")
                .provider,
            "meterd"
        );
    }

    #[test]
    fn request_receipt_metadata_treats_untyped_financial_extra_metadata_as_pass_through() {
        let request = ToolCallRequest {
            request_id: "req-economic-legacy-financial".to_string(),
            capability: test_capability(),
            tool_name: "charge".to_string(),
            server_id: "srv-pay".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({ "invoice_id": "inv-legacy-financial" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-legacy-financial".to_string(),
                server_id: "srv-pay".to_string(),
                tool_name: "charge".to_string(),
                purpose: "pay supplier".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: None,
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        let extra_metadata = serde_json::json!({
            "financial": {
                "legacy_payload": true,
                "vendor": "custom-financial-metadata"
            }
        });

        let metadata = request_receipt_metadata(&request, None, 150, Some(&extra_metadata))
            .expect("legacy financial metadata should not fail receipt metadata")
            .expect("governed metadata should still exist");
        let governed: GovernedTransactionReceiptMetadata =
            serde_json::from_value(metadata["governed_transaction"].clone())
                .expect("governed metadata should deserialize");

        assert!(governed.economic_authorization.is_none());
    }
}
