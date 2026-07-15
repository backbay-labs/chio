#[cfg(test)]
use super::receipt_scopes::{
    current_governed_call_chain_receipt_evidence, current_governed_runtime_attestation_record,
};
use crate::evidence_export::EvidenceLineageReferences;
use crate::kernel::EvaluationReceiptContext;
use crate::operator_report::GovernedTransactionDiagnostics;
use crate::*;
use chio_appraisal::{verify_runtime_attestation_record, VerifiedRuntimeAttestationRecord};
use chio_core::capability::governance::{
    GovernedCallChainContext, GovernedCallChainEvidenceSource, GovernedCallChainProvenance,
    GovernedProvenanceEvidenceClass,
};

fn governed_call_chain_provenance_from_evidence(
    context: GovernedCallChainContext,
    evidence: &GovernedCallChainReceiptEvidence,
) -> GovernedCallChainProvenance {
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
    if let Some(continuation_token_id) = evidence.continuation_token_id.as_ref() {
        provenance = provenance.with_continuation_token_id(continuation_token_id.clone());
    }
    if let Some(session_anchor_id) = evidence.session_anchor_id.as_ref() {
        provenance = provenance.with_session_anchor_id(session_anchor_id.clone());
    }

    provenance
}

fn governed_call_chain_provenance_with_authoritative_evidence(
    context: GovernedCallChainContext,
    evidence: Option<&GovernedCallChainReceiptEvidence>,
) -> GovernedCallChainProvenance {
    let Some(evidence) = evidence else {
        return GovernedCallChainProvenance::asserted(context);
    };
    governed_call_chain_provenance_from_evidence(context, evidence)
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

pub(crate) fn merge_metadata_objects(
    base: Option<serde_json::Value>,
    extra: Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    match (base, extra) {
        (None, extra) => extra,
        (Some(base), None) => Some(base),
        (Some(mut base), Some(extra)) => match (base.as_object_mut(), extra.as_object()) {
            (Some(base_obj), Some(extra_obj)) => {
                for (key, value) in extra_obj {
                    match (base_obj.get_mut(key), value.as_object()) {
                        (Some(serde_json::Value::Object(base_nested)), Some(extra_nested)) => {
                            for (nested_key, nested_value) in extra_nested {
                                base_nested.insert(nested_key.clone(), nested_value.clone());
                            }
                        }
                        _ => {
                            base_obj.insert(key.clone(), value.clone());
                        }
                    }
                }
                Some(base)
            }
            // Structured receipt evidence dominates an unstructured value on
            // either side. This prevents caller-shaped scalar or array
            // metadata from suppressing trusted admission, budget, or
            // attribution objects while retaining normal extra precedence
            // when both values are unstructured.
            (Some(_), None) => Some(base),
            (None, Some(_)) | (None, None) => Some(extra),
        },
    }
}

pub(crate) fn sanitize_external_receipt_metadata(
    metadata: Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    const KERNEL_OWNED_KEYS: &[&str] = &[
        "acp",
        "actor_subject",
        "agent_web_receipt_ref",
        "attribution",
        "budget_authority",
        "checkpoint_id",
        "chio_runtime",
        "execution_nonce",
        "financial",
        "governed_transaction",
        "governed_transaction_diagnostics",
        "lineageReferences",
        "memory_provenance",
        "mercury",
        "model_metadata",
        "post_invocation",
        "receipt_context",
        "redaction_status",
        "runtime_admission",
        "stream",
    ];

    let mut metadata = metadata?;
    let Some(object) = metadata.as_object_mut() else {
        return Some(metadata);
    };
    for key in KERNEL_OWNED_KEYS {
        object.remove(*key);
    }
    (!object.is_empty()).then_some(metadata)
}

pub(crate) fn strip_external_receipt_provenance(
    metadata: Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    let mut metadata = metadata?;
    let Some(object) = metadata.as_object_mut() else {
        return Some(metadata);
    };
    object.remove("provenance");
    (!object.is_empty()).then_some(metadata)
}

pub(crate) fn normalize_external_receipt_metadata(
    metadata: Option<serde_json::Value>,
) -> Result<Option<serde_json::Value>, KernelError> {
    let normalized_provenance = receipt_provenance_metadata(metadata.as_ref())?;
    Ok(merge_metadata_objects(
        strip_external_receipt_provenance(metadata),
        normalized_provenance,
    ))
}

pub(crate) fn project_runtime_admission_receipt_metadata(
    metadata: Option<&serde_json::Value>,
) -> Result<Option<serde_json::Value>, KernelError> {
    let Some(metadata) = metadata else {
        return Ok(None);
    };
    let Some(object) = metadata.as_object() else {
        return Err(KernelError::Internal(
            "runtime admission metadata must be a JSON object".to_string(),
        ));
    };
    let mut projected = serde_json::Map::new();
    for key in ["chio_runtime", "runtime_admission"] {
        let Some(value) = object.get(key) else {
            continue;
        };
        let Some(namespace) = value.as_object() else {
            return Err(KernelError::Internal(format!(
                "runtime admission metadata namespace {key} must be a JSON object"
            )));
        };
        let mut namespace = namespace.clone();
        namespace.remove("federation_treaty_dsse");
        if !namespace.is_empty() {
            projected.insert(key.to_string(), serde_json::Value::Object(namespace));
        }
    }
    Ok((!projected.is_empty()).then_some(serde_json::Value::Object(projected)))
}

pub(crate) fn validate_runtime_admission_receipt_metadata(
    metadata: Option<&serde_json::Value>,
) -> Result<Option<serde_json::Value>, KernelError> {
    let Some(metadata) = metadata else {
        return Ok(None);
    };
    let Some(object) = metadata.as_object() else {
        return Err(KernelError::Internal(
            "runtime admission metadata must be a JSON object".to_string(),
        ));
    };
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "chio_runtime" | "runtime_admission"))
    {
        return Err(KernelError::Internal(
            "runtime admission metadata contains an unsupported top-level namespace".to_string(),
        ));
    }
    project_runtime_admission_receipt_metadata(Some(metadata))
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

pub(crate) fn verify_governed_runtime_attestation_record(
    attestation: &chio_core::capability::runtime_attestation::RuntimeAttestationEvidence,
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
    attestation: Option<&chio_core::capability::runtime_attestation::RuntimeAttestationEvidence>,
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
) -> Result<Option<chio_core::receipt::economics::EconomicAuthorizationReceiptMetadata>, KernelError>
{
    let Some(intent) = request.governed_intent.as_ref() else {
        return Ok(None);
    };

    let approved_max =
        intent
            .max_amount
            .clone()
            .unwrap_or(chio_core::capability::scope::MonetaryAmount {
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
                .map(|quote_hash| {
                    chio_core::receipt::economics::EconomicPricingBasisReceiptMetadata {
                        quote_hash: Some(quote_hash),
                        tariff_hash: None,
                        quote_expiry: metered.quote.expires_at,
                    }
                })
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
            .map(|meter_profile_hash| {
                chio_core::receipt::economics::EconomicMeteringReceiptMetadata {
                    provider: metered.quote.provider.clone(),
                    meter_profile_hash,
                    max_billable_units: metered.max_billed_units,
                    billing_unit: Some(metered.quote.billing_unit.clone()),
                }
            })
            .map_err(|error| {
                KernelError::ReceiptSigningFailed(format!(
                    "failed to canonicalize metering profile for receipt metadata: {error}"
                ))
            })
        })
        .transpose()?;

    let economic_mode = if let Some(metered) = metered {
        match metered.settlement_mode {
            chio_core::capability::governance::MeteredSettlementMode::MustPrepay => {
                chio_core::receipt::economics::EconomicAuthorizationMode::PrepaidFixed
            }
            chio_core::capability::governance::MeteredSettlementMode::HoldCapture => {
                chio_core::receipt::economics::EconomicAuthorizationMode::MeteredHoldCapture
            }
            chio_core::capability::governance::MeteredSettlementMode::AllowThenSettle => {
                chio_core::receipt::economics::EconomicAuthorizationMode::ExternalDispatch
            }
        }
    } else if financial.payment_reference.is_some() {
        chio_core::receipt::economics::EconomicAuthorizationMode::HoldCapture
    } else {
        chio_core::receipt::economics::EconomicAuthorizationMode::BudgetOnly
    };

    Ok(Some(
        chio_core::receipt::economics::EconomicAuthorizationReceiptMetadata {
            version: chio_core::receipt::economics::EconomicAuthorizationReceiptMetadataVersion::V1,
            economic_mode,
            payer: chio_core::receipt::economics::EconomicPayerReceiptMetadata {
                party_id: request.agent_id.clone(),
                funding_source_ref: commerce
                    .map(|commerce| commerce.shared_payment_token_id.clone())
                    .or_else(|| financial.payment_reference.clone())
                    .unwrap_or_else(|| request.capability.id.clone()),
                custody_provider: None,
                obligor_ref: None,
            },
            merchant: chio_core::receipt::economics::EconomicMerchantReceiptMetadata {
                merchant_id: commerce
                    .map(|commerce| commerce.seller.clone())
                    .unwrap_or_else(|| request.server_id.clone()),
                merchant_of_record: None,
                order_ref: Some(request.request_id.clone()),
            },
            payee: chio_core::receipt::economics::EconomicPayeeReceiptMetadata {
                beneficiary_id: request.server_id.clone(),
                settlement_destination_ref: financial
                    .payment_reference
                    .clone()
                    .or_else(|| commerce.map(|commerce| commerce.shared_payment_token_id.clone()))
                    .unwrap_or_else(|| request.server_id.clone()),
            },
            rail: chio_core::receipt::economics::EconomicRailReceiptMetadata {
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
            amount_bounds: chio_core::receipt::economics::EconomicAmountBoundsReceiptMetadata {
                approved_max,
                hold_amount: hold_amount_units.map(|units| {
                    chio_core::capability::scope::MonetaryAmount {
                        units,
                        currency: financial.currency.clone(),
                    }
                }),
                settlement_cap: chio_core::capability::scope::MonetaryAmount {
                    units: settlement_cap_units,
                    currency: financial.currency.clone(),
                },
            },
            pricing_basis,
            metering,
            liability_refs: None,
            budget: chio_core::receipt::economics::EconomicBudgetReceiptMetadata {
                grant_index: financial.grant_index,
                cost_charged: financial.cost_charged,
                currency: financial.currency.clone(),
                budget_remaining: financial.budget_remaining,
                budget_total: financial.budget_total,
                delegation_depth: financial.delegation_depth,
                root_budget_holder: financial.root_budget_holder.clone(),
                attempted_cost: financial.attempted_cost,
            },
            settlement: chio_core::receipt::economics::EconomicSettlementReceiptMetadata {
                settlement_status: financial.settlement_status.clone(),
            },
        },
    ))
}

fn inject_governed_economic_authorization_metadata(
    metadata: Option<serde_json::Value>,
    economic_authorization: Option<
        chio_core::receipt::economics::EconomicAuthorizationReceiptMetadata,
    >,
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

pub(crate) fn governed_request_metadata_with_context(
    request: &ToolCallRequest,
    attestation_trust_policy: Option<&AttestationTrustPolicy>,
    now: u64,
    evaluation_context: &EvaluationReceiptContext,
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
    let scoped_runtime_attestation = evaluation_context.runtime_attestation.clone();
    let runtime_assurance = if let Some(verified_runtime_attestation) = scoped_runtime_attestation {
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
    let call_chain_evidence = evaluation_context.governed_call_chain.as_ref();
    let call_chain = intent.call_chain.clone().map(|call_chain| {
        governed_call_chain_provenance_with_authoritative_evidence(call_chain, call_chain_evidence)
    });
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

#[cfg(test)]
pub(crate) fn governed_request_metadata(
    request: &ToolCallRequest,
    attestation_trust_policy: Option<&AttestationTrustPolicy>,
    now: u64,
) -> Result<Option<serde_json::Value>, KernelError> {
    let evaluation_context = legacy_test_evaluation_receipt_context();
    governed_request_metadata_with_context(
        request,
        attestation_trust_policy,
        now,
        &evaluation_context,
    )
}

pub(crate) fn request_receipt_metadata_with_context(
    request: &ToolCallRequest,
    attestation_trust_policy: Option<&AttestationTrustPolicy>,
    now: u64,
    extra_metadata: Option<&serde_json::Value>,
    evaluation_context: &EvaluationReceiptContext,
) -> Result<Option<serde_json::Value>, KernelError> {
    let governed_metadata = governed_request_metadata_with_context(
        request,
        attestation_trust_policy,
        now,
        evaluation_context,
    )?;
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

#[cfg(test)]
pub(crate) fn request_receipt_metadata(
    request: &ToolCallRequest,
    attestation_trust_policy: Option<&AttestationTrustPolicy>,
    now: u64,
    extra_metadata: Option<&serde_json::Value>,
) -> Result<Option<serde_json::Value>, KernelError> {
    let evaluation_context = legacy_test_evaluation_receipt_context();
    request_receipt_metadata_with_context(
        request,
        attestation_trust_policy,
        now,
        extra_metadata,
        &evaluation_context,
    )
}

#[cfg(test)]
fn legacy_test_evaluation_receipt_context() -> EvaluationReceiptContext {
    EvaluationReceiptContext {
        governed_call_chain: current_governed_call_chain_receipt_evidence(),
        runtime_attestation: current_governed_runtime_attestation_record(),
        ..EvaluationReceiptContext::default()
    }
}

pub(crate) fn receipt_attribution_metadata(
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

pub(crate) fn request_model_metadata_receipt_metadata(
    request: &ToolCallRequest,
) -> Option<serde_json::Value> {
    request.model_metadata.as_ref().map(|model_metadata| {
        serde_json::json!({
            "model_metadata": chio_core::receipt::metadata::ModelMetadataReceiptMetadata::from(model_metadata)
        })
    })
}
