use super::*;

pub(crate) fn build_underwriting_policy_input(
    receipt_store: &SqliteReceiptStore,
    receipt_db_path: &Path,
    budget_db_path: Option<&Path>,
    certification_registry_file: Option<&Path>,
    query: &UnderwritingPolicyInputQuery,
    read_context: chio_kernel::ReceiptReadContext,
    trusted_kernel_keys: &[String],
) -> Result<UnderwritingPolicyInput, TrustHttpError> {
    let normalized_query = query.normalized();
    if let Err(message) = normalized_query.validate() {
        return Err(TrustHttpError::bad_request(message));
    }

    let behavioral_query = BehavioralFeedQuery {
        capability_id: normalized_query.capability_id.clone(),
        agent_subject: normalized_query.agent_subject.clone(),
        tool_server: normalized_query.tool_server.clone(),
        tool_name: normalized_query.tool_name.clone(),
        since: normalized_query.since,
        until: normalized_query.until,
        receipt_limit: normalized_query.receipt_limit,
        read_context: Some(read_context),
    };
    let operator_query = behavioral_query.to_operator_report_query();
    let activity = receipt_store
        .query_receipt_analytics(&operator_query.to_receipt_analytics_query())
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let shared_evidence = receipt_store
        .query_shared_evidence_report(&operator_query.to_shared_evidence_query())
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let (settlements, governed_actions, metered_billing, selection) = receipt_store
        .query_behavioral_feed_receipts(&behavioral_query)
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let generated_at = unix_timestamp_now();
    let reputation = match normalized_query.agent_subject.as_deref() {
        Some(subject_key) => Some(
            reputation::build_behavioral_feed_reputation_summary(
                receipt_db_path,
                budget_db_path,
                subject_key,
                normalized_query.since,
                normalized_query.until,
                generated_at,
                trusted_kernel_keys,
            )
            .map(underwriting_reputation_from_behavioral_summary)
            .map_err(|error| TrustHttpError::internal(error.to_string()))?,
        ),
        None => None,
    };
    let certification = normalized_query
        .tool_server
        .as_deref()
        .map(|tool_server| {
            resolve_underwriting_certification_evidence(certification_registry_file, tool_server)
        })
        .transpose()
        .map_err(|error| TrustHttpError::internal(error.to_string()))?;
    let receipts = build_underwriting_receipt_evidence(
        &activity,
        &settlements,
        &governed_actions,
        &metered_billing,
        &shared_evidence,
        &selection,
    );
    let runtime_assurance = build_underwriting_runtime_assurance_evidence(
        &selection,
        governed_actions.governed_receipts,
    );
    let compliance_score = normalized_query
        .agent_subject
        .as_deref()
        .map(|subject_key| {
            receipt_store
                .query_compliance_report(&operator_query)
                .map_err(|error| TrustHttpError::internal(error.to_string()))
                .and_then(|report| {
                    build_underwriting_compliance_evidence(
                        subject_key,
                        generated_at,
                        &activity,
                        &report,
                        &selection,
                    )
                    .map_err(TrustHttpError::internal)
                })
        })
        .transpose()?;
    let signals = derive_underwriting_signals(
        &normalized_query,
        &receipts,
        &selection,
        reputation.as_ref(),
        certification.as_ref(),
        runtime_assurance.as_ref(),
    );

    Ok(UnderwritingPolicyInput {
        schema: UNDERWRITING_POLICY_INPUT_SCHEMA.to_string(),
        generated_at,
        filters: normalized_query,
        taxonomy: UnderwritingRiskTaxonomy::default(),
        receipts,
        reputation,
        certification,
        runtime_assurance,
        compliance_score,
        signals,
    })
}

pub(crate) fn build_underwriting_compliance_evidence(
    subject_key: &str,
    generated_at: u64,
    activity: &chio_kernel::ReceiptAnalyticsResponse,
    report: &chio_kernel::ComplianceReport,
    selection: &chio_kernel::BehavioralFeedReceiptSelection,
) -> Result<chio_kernel::UnderwritingComplianceEvidence, String> {
    if report.export_query.agent_subject.as_deref() != Some(subject_key) {
        return Err(format!(
            "compliance report subject mismatch: expected `{subject_key}` but report was scoped to {:?}",
            report.export_query.agent_subject
        ));
    }
    let observed_capabilities = selection
        .receipts
        .iter()
        .map(|receipt| receipt.capability_id.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .len() as u64;
    let latest_receipt_timestamp = selection
        .receipts
        .iter()
        .map(|receipt| receipt.timestamp)
        .max();
    let inputs = chio_kernel::ComplianceScoreInputs::new(
        activity.summary.total_receipts,
        activity.summary.deny_count,
        observed_capabilities,
        0,
        activity.by_time.len() as u64,
        0,
        latest_receipt_timestamp.map(|timestamp| generated_at.saturating_sub(timestamp)),
    );
    let score = report.compliance_score(
        &inputs,
        &chio_kernel::ComplianceScoreConfig::default(),
        subject_key,
        generated_at,
    );
    Ok(score.as_underwriting_evidence())
}

fn underwriting_reputation_from_behavioral_summary(
    summary: chio_kernel::BehavioralFeedReputationSummary,
) -> UnderwritingReputationEvidence {
    UnderwritingReputationEvidence {
        subject_key: summary.subject_key,
        effective_score: summary.effective_score,
        probationary: summary.probationary,
        resolved_tier: summary.resolved_tier,
        imported_signal_count: summary.imported_signal_count,
        accepted_imported_signal_count: summary.accepted_imported_signal_count,
    }
}

fn resolve_underwriting_certification_evidence(
    certification_registry_file: Option<&Path>,
    tool_server_id: &str,
) -> Result<UnderwritingCertificationEvidence, CliError> {
    let Some(path) = certification_registry_file else {
        return Ok(UnderwritingCertificationEvidence {
            tool_server_id: tool_server_id.to_string(),
            state: UnderwritingCertificationState::Unavailable,
            artifact_id: None,
            verdict: None,
            checked_at: None,
            published_at: None,
        });
    };

    let registry = CertificationRegistry::load(path)?;
    let resolution = registry.resolve(tool_server_id);
    let current = resolution.current;
    let verdict = current
        .as_ref()
        .map(|entry| entry.verdict.label().to_string());
    Ok(UnderwritingCertificationEvidence {
        tool_server_id: resolution.tool_server_id,
        state: match resolution.state {
            CertificationResolutionState::Active => UnderwritingCertificationState::Active,
            CertificationResolutionState::Superseded => UnderwritingCertificationState::Superseded,
            CertificationResolutionState::Revoked => UnderwritingCertificationState::Revoked,
            CertificationResolutionState::NotFound => UnderwritingCertificationState::NotFound,
        },
        artifact_id: current.as_ref().map(|entry| entry.artifact_id.clone()),
        verdict,
        checked_at: current.as_ref().map(|entry| entry.checked_at),
        published_at: current.as_ref().map(|entry| entry.published_at),
    })
}

fn build_underwriting_receipt_evidence(
    activity: &ReceiptAnalyticsResponse,
    settlements: &chio_kernel::BehavioralFeedSettlementSummary,
    governed_actions: &chio_kernel::BehavioralFeedGovernedActionSummary,
    metered_billing: &chio_kernel::BehavioralFeedMeteredBillingSummary,
    shared_evidence: &SharedEvidenceReferenceReport,
    selection: &chio_kernel::BehavioralFeedReceiptSelection,
) -> UnderwritingReceiptEvidence {
    let runtime_assurance_receipts = selection
        .receipts
        .iter()
        .filter(|receipt| {
            receipt
                .governed
                .as_ref()
                .and_then(|governed| governed.runtime_assurance.as_ref())
                .is_some()
        })
        .count() as u64;
    let call_chain_receipts = selection
        .receipts
        .iter()
        .filter(|receipt| underwriting_receipt_call_chain(receipt).is_some())
        .count() as u64;

    UnderwritingReceiptEvidence {
        matching_receipts: selection.matching_receipts,
        returned_receipts: selection.receipts.len() as u64,
        allow_count: activity.summary.allow_count,
        deny_count: activity.summary.deny_count,
        cancelled_count: activity.summary.cancelled_count,
        incomplete_count: activity.summary.incomplete_count,
        governed_receipts: governed_actions.governed_receipts,
        approval_receipts: governed_actions.approval_receipts,
        approved_receipts: governed_actions.approved_receipts,
        call_chain_receipts,
        runtime_assurance_receipts,
        pending_settlement_receipts: settlements.pending_receipts,
        failed_settlement_receipts: settlements.failed_receipts,
        actionable_settlement_receipts: settlements.actionable_receipts,
        metered_receipts: metered_billing.metered_receipts,
        actionable_metered_receipts: metered_billing.actionable_receipts,
        shared_evidence_reference_count: shared_evidence.summary.matching_references,
        shared_evidence_proof_required_count: shared_evidence.summary.proof_required_shares,
        receipt_refs: selection
            .receipts
            .iter()
            .map(|receipt| UnderwritingEvidenceReference {
                kind: UnderwritingEvidenceKind::Receipt,
                reference_id: receipt.receipt_id.clone(),
                observed_at: Some(receipt.timestamp),
                digest_sha256: None,
                locator: Some(format!("receipt:{}", receipt.receipt_id)),
            })
            .collect(),
    }
}

fn build_underwriting_runtime_assurance_evidence(
    selection: &chio_kernel::BehavioralFeedReceiptSelection,
    governed_receipts: u64,
) -> Option<UnderwritingRuntimeAssuranceEvidence> {
    let mut observed_verifier_families = BTreeSet::new();
    let mut highest_tier: Option<RuntimeAssuranceTier> = None;
    let mut latest_observed = None;
    let mut runtime_assurance_receipts = 0_u64;

    for receipt in &selection.receipts {
        let Some(runtime_assurance) = receipt
            .governed
            .as_ref()
            .and_then(|governed| governed.runtime_assurance.as_ref())
        else {
            continue;
        };
        runtime_assurance_receipts += 1;
        if let Some(verifier_family) = runtime_assurance.verifier_family {
            observed_verifier_families.insert(verifier_family);
        }
        highest_tier = Some(match highest_tier {
            Some(current) => current.max(runtime_assurance.tier),
            None => runtime_assurance.tier,
        });
        if latest_observed
            .as_ref()
            .is_none_or(|(_, timestamp)| receipt.timestamp > *timestamp)
        {
            latest_observed = Some((runtime_assurance.clone(), receipt.timestamp));
        }
    }

    if governed_receipts == 0 && runtime_assurance_receipts == 0 {
        return None;
    }

    let latest = latest_observed.map(|(value, _)| value);
    Some(UnderwritingRuntimeAssuranceEvidence {
        governed_receipts,
        runtime_assurance_receipts,
        highest_tier,
        latest_schema: latest.as_ref().map(|value| value.schema.clone()),
        latest_verifier_family: latest.as_ref().and_then(|value| value.verifier_family),
        latest_verifier: latest.as_ref().map(|value| value.verifier.clone()),
        latest_evidence_sha256: latest.as_ref().map(|value| value.evidence_sha256.clone()),
        observed_verifier_families: observed_verifier_families.into_iter().collect(),
    })
}

fn derive_underwriting_signals(
    query: &UnderwritingPolicyInputQuery,
    receipts: &UnderwritingReceiptEvidence,
    selection: &chio_kernel::BehavioralFeedReceiptSelection,
    reputation: Option<&UnderwritingReputationEvidence>,
    certification: Option<&UnderwritingCertificationEvidence>,
    runtime_assurance: Option<&UnderwritingRuntimeAssuranceEvidence>,
) -> Vec<UnderwritingSignal> {
    let mut signals = Vec::new();

    if let Some(reputation) = reputation {
        let reputation_ref = UnderwritingEvidenceReference {
            kind: UnderwritingEvidenceKind::ReputationInspection,
            reference_id: reputation.subject_key.clone(),
            observed_at: None,
            digest_sha256: None,
            locator: Some(format!("reputation:{}", reputation.subject_key)),
        };
        if reputation.probationary {
            signals.push(UnderwritingSignal {
                class: UnderwritingRiskClass::Guarded,
                reason: UnderwritingReasonCode::ProbationaryHistory,
                description: "local reputation is still probationary for the requested window"
                    .to_string(),
                evidence_refs: vec![reputation_ref.clone()],
            });
        }
        if reputation.effective_score < 0.4 {
            signals.push(UnderwritingSignal {
                class: UnderwritingRiskClass::Elevated,
                reason: UnderwritingReasonCode::LowReputation,
                description: format!(
                    "effective local reputation score {:.4} is below the baseline threshold",
                    reputation.effective_score
                ),
                evidence_refs: vec![reputation_ref.clone()],
            });
        }
        if reputation.accepted_imported_signal_count > 0 {
            signals.push(UnderwritingSignal {
                class: UnderwritingRiskClass::Guarded,
                reason: UnderwritingReasonCode::ImportedTrustDependency,
                description: format!(
                    "underwriting input includes {} accepted imported-trust signal(s)",
                    reputation.accepted_imported_signal_count
                ),
                evidence_refs: vec![reputation_ref],
            });
        }
    }

    if let Some(certification) = certification {
        let certification_ref =
            certification
                .artifact_id
                .as_ref()
                .map(|artifact_id| UnderwritingEvidenceReference {
                    kind: UnderwritingEvidenceKind::CertificationArtifact,
                    reference_id: artifact_id.clone(),
                    observed_at: certification.published_at,
                    digest_sha256: certification.artifact_id.clone(),
                    locator: Some(format!("certification:{}", certification.tool_server_id)),
                });
        match certification.state {
            UnderwritingCertificationState::Unavailable
            | UnderwritingCertificationState::NotFound => {
                signals.push(UnderwritingSignal {
                    class: UnderwritingRiskClass::Elevated,
                    reason: UnderwritingReasonCode::MissingCertification,
                    description: format!(
                        "no active certification evidence is available for tool server `{}`",
                        certification.tool_server_id
                    ),
                    evidence_refs: certification_ref.into_iter().collect(),
                });
            }
            UnderwritingCertificationState::Revoked => {
                signals.push(UnderwritingSignal {
                    class: UnderwritingRiskClass::Critical,
                    reason: UnderwritingReasonCode::RevokedCertification,
                    description: format!(
                        "current certification evidence for tool server `{}` is revoked",
                        certification.tool_server_id
                    ),
                    evidence_refs: certification_ref.into_iter().collect(),
                });
            }
            UnderwritingCertificationState::Active
                if certification.verdict.as_deref() == Some("fail") =>
            {
                signals.push(UnderwritingSignal {
                    class: UnderwritingRiskClass::Critical,
                    reason: UnderwritingReasonCode::FailedCertification,
                    description: format!(
                        "active certification evidence for tool server `{}` has fail verdict",
                        certification.tool_server_id
                    ),
                    evidence_refs: certification_ref.into_iter().collect(),
                });
            }
            UnderwritingCertificationState::Superseded => {
                signals.push(UnderwritingSignal {
                    class: UnderwritingRiskClass::Guarded,
                    reason: UnderwritingReasonCode::MissingCertification,
                    description: format!(
                        "only superseded certification evidence is available for tool server `{}`",
                        certification.tool_server_id
                    ),
                    evidence_refs: certification_ref.into_iter().collect(),
                });
            }
            UnderwritingCertificationState::Active => {}
        }
    } else if query.tool_server.is_some() {
        signals.push(UnderwritingSignal {
            class: UnderwritingRiskClass::Elevated,
            reason: UnderwritingReasonCode::MissingCertification,
            description: "tool-scoped underwriting input is missing certification evidence"
                .to_string(),
            evidence_refs: Vec::new(),
        });
    }

    if let Some(runtime_assurance) = runtime_assurance {
        let runtime_ref =
            runtime_assurance
                .latest_evidence_sha256
                .as_ref()
                .map(|evidence_sha256| UnderwritingEvidenceReference {
                    kind: UnderwritingEvidenceKind::RuntimeAssuranceEvidence,
                    reference_id: evidence_sha256.clone(),
                    observed_at: None,
                    digest_sha256: Some(evidence_sha256.clone()),
                    locator: runtime_assurance
                        .latest_verifier
                        .as_ref()
                        .map(|verifier| format!("runtime-assurance:{verifier}")),
                });
        if runtime_assurance.governed_receipts > 0
            && runtime_assurance.runtime_assurance_receipts == 0
        {
            signals.push(UnderwritingSignal {
                class: UnderwritingRiskClass::Elevated,
                reason: UnderwritingReasonCode::MissingRuntimeAssurance,
                description:
                    "governed receipts were observed without any bound runtime-assurance evidence"
                        .to_string(),
                evidence_refs: runtime_ref.clone().into_iter().collect(),
            });
        } else if matches!(
            runtime_assurance.highest_tier,
            Some(RuntimeAssuranceTier::None | RuntimeAssuranceTier::Basic)
        ) {
            let family_suffix = runtime_assurance
                .latest_verifier_family
                .map(underwriting_runtime_family_label)
                .map(|family| format!(" from {family}"))
                .unwrap_or_default();
            signals.push(UnderwritingSignal {
                class: UnderwritingRiskClass::Guarded,
                reason: UnderwritingReasonCode::WeakRuntimeAssurance,
                description: format!(
                    "runtime-assurance evidence{family_suffix} is present but does not exceed the basic tier"
                ),
                evidence_refs: runtime_ref.into_iter().collect(),
            });
        }
    }

    if receipts.pending_settlement_receipts > 0 {
        signals.push(UnderwritingSignal {
            class: UnderwritingRiskClass::Guarded,
            reason: UnderwritingReasonCode::PendingSettlementExposure,
            description: format!(
                "{} receipt(s) still have pending settlement exposure",
                receipts.pending_settlement_receipts
            ),
            evidence_refs: settlement_signal_evidence_refs(selection, SettlementStatus::Pending),
        });
    }
    if receipts.failed_settlement_receipts > 0 {
        signals.push(UnderwritingSignal {
            class: UnderwritingRiskClass::Critical,
            reason: UnderwritingReasonCode::FailedSettlementExposure,
            description: format!(
                "{} receipt(s) have failed settlement state",
                receipts.failed_settlement_receipts
            ),
            evidence_refs: settlement_signal_evidence_refs(selection, SettlementStatus::Failed),
        });
    }
    if receipts.actionable_metered_receipts > 0 {
        signals.push(UnderwritingSignal {
            class: UnderwritingRiskClass::Elevated,
            reason: UnderwritingReasonCode::MeteredBillingMismatch,
            description: format!(
                "{} metered receipt(s) require reconciliation or exceed quoted bounds",
                receipts.actionable_metered_receipts
            ),
            evidence_refs: metered_signal_evidence_refs(selection),
        });
    }
    if receipts.call_chain_receipts > 0 {
        signals.push(UnderwritingSignal {
            class: UnderwritingRiskClass::Guarded,
            reason: UnderwritingReasonCode::DelegatedCallChain,
            description: format!(
                "{} receipt(s) include delegated call-chain context",
                receipts.call_chain_receipts
            ),
            evidence_refs: call_chain_signal_evidence_refs(selection),
        });
    }
    if receipts.shared_evidence_proof_required_count > 0 {
        signals.push(UnderwritingSignal {
            class: UnderwritingRiskClass::Guarded,
            reason: UnderwritingReasonCode::SharedEvidenceProofRequired,
            description: format!(
                "{} shared-evidence reference(s) still require proof handling",
                receipts.shared_evidence_proof_required_count
            ),
            evidence_refs: vec![UnderwritingEvidenceReference {
                kind: UnderwritingEvidenceKind::SharedEvidenceReference,
                reference_id: format!(
                    "shared-evidence:{}",
                    query
                        .agent_subject
                        .as_deref()
                        .or(query.capability_id.as_deref())
                        .or(query.tool_server.as_deref())
                        .unwrap_or("scoped-query")
                ),
                observed_at: None,
                digest_sha256: None,
                locator: Some("shared-evidence-report".to_string()),
            }],
        });
    }

    signals
}

pub(crate) fn trust_http_error_from_receipt_store(error: ReceiptStoreError) -> TrustHttpError {
    match error {
        ReceiptStoreError::NotFound(message) => TrustHttpError::new(StatusCode::NOT_FOUND, message),
        ReceiptStoreError::Conflict(message) => TrustHttpError::new(StatusCode::CONFLICT, message),
        ReceiptStoreError::ReadBoundary(message) => {
            TrustHttpError::new(StatusCode::FORBIDDEN, message)
        }
        other => TrustHttpError::internal(other.to_string()),
    }
}

fn settlement_signal_evidence_refs(
    selection: &chio_kernel::BehavioralFeedReceiptSelection,
    status: SettlementStatus,
) -> Vec<UnderwritingEvidenceReference> {
    selection
        .receipts
        .iter()
        .filter(|receipt| receipt.settlement_status == status)
        .map(|receipt| UnderwritingEvidenceReference {
            kind: UnderwritingEvidenceKind::SettlementReconciliation,
            reference_id: receipt.receipt_id.clone(),
            observed_at: Some(receipt.timestamp),
            digest_sha256: None,
            locator: Some(format!("settlement:{}", receipt.receipt_id)),
        })
        .collect()
}

fn metered_signal_evidence_refs(
    selection: &chio_kernel::BehavioralFeedReceiptSelection,
) -> Vec<UnderwritingEvidenceReference> {
    selection
        .receipts
        .iter()
        .filter(|receipt| {
            receipt
                .metered_reconciliation
                .as_ref()
                .is_some_and(|row| row.action_required)
        })
        .map(|receipt| UnderwritingEvidenceReference {
            kind: UnderwritingEvidenceKind::MeteredBillingReconciliation,
            reference_id: receipt.receipt_id.clone(),
            observed_at: Some(receipt.timestamp),
            digest_sha256: receipt
                .metered_reconciliation
                .as_ref()
                .and_then(|row| row.evidence.as_ref())
                .and_then(|evidence| evidence.usage_evidence.evidence_sha256.clone()),
            locator: Some(format!("metered-billing:{}", receipt.receipt_id)),
        })
        .collect()
}

fn call_chain_signal_evidence_refs(
    selection: &chio_kernel::BehavioralFeedReceiptSelection,
) -> Vec<UnderwritingEvidenceReference> {
    selection
        .receipts
        .iter()
        .filter(|receipt| underwriting_receipt_call_chain(receipt).is_some())
        .map(|receipt| UnderwritingEvidenceReference {
            kind: UnderwritingEvidenceKind::Receipt,
            reference_id: receipt.receipt_id.clone(),
            observed_at: Some(receipt.timestamp),
            digest_sha256: None,
            locator: Some(format!("receipt:{}", receipt.receipt_id)),
        })
        .collect()
}

fn underwriting_receipt_call_chain(
    receipt: &chio_kernel::BehavioralFeedReceiptRow,
) -> Option<&chio_core::capability::governance::GovernedCallChainProvenance> {
    receipt
        .governed
        .as_ref()
        .and_then(|governed| governed.call_chain.as_ref())
        .or_else(|| {
            receipt
                .governed_transaction_diagnostics
                .as_ref()
                .and_then(|diagnostics| diagnostics.asserted_call_chain.as_ref())
        })
}

pub(crate) fn load_behavioral_feed_signing_keypair(
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
) -> Result<Keypair, CliError> {
    match (authority_seed_path, authority_db_path) {
        (Some(_), Some(_)) => Err(CliError::cli_other_error(
            "behavioral feed export requires either --authority-seed-file or --authority-db, not both"
                .to_string(),
        )),
        (Some(path), None) => load_or_create_authority_keypair(path),
        (None, Some(path)) => Ok(SqliteCapabilityAuthority::open(path)?.local_keypair()?),
        (None, None) => Err(CliError::cli_other_error(
            "behavioral feed export requires --authority-seed-file or --authority-db so the export can be signed"
                .to_string(),
        )),
    }
}

/// Derive a trusted-kernel-key list from a trust service's configured authority
/// material. Returns the local kernel's public key when an authority source is
/// configured and loadable, or `Ok(None)` when neither a seed file nor
/// authority db is present. Returns `Err(..)` when an authority source IS
/// configured but cannot be loaded (missing file, malformed YAML, unreadable
/// sqlite, etc.) so that operators see misconfigured trust roots at startup
/// rather than discovering them later as silently-empty reputation scores.
///
/// Plumbing this into reputation scoring prevents an empty trust set from
/// silently filtering out every locally signed receipt (see
/// `chio-reputation::receipt_integrity_valid`).
pub(crate) fn trusted_kernel_keys_from_service_config(
    config: &TrustServiceConfig,
) -> Result<Option<Vec<String>>, CliError> {
    let seed = config.authority_seed_path.as_deref();
    let db = config.authority_db_path.as_deref();
    match (seed, db) {
        (None, None) => Ok(None),
        (Some(_), Some(_)) | (Some(_), None) | (None, Some(_)) => {
            let keypair = load_behavioral_feed_signing_keypair(seed, db)?;
            Ok(Some(vec![keypair.public_key().to_hex()]))
        }
    }
}

pub(crate) fn response_status_text(response: &Response) -> String {
    format!("request failed with status {}", response.status())
}

pub(crate) fn build_budget_utilization_report(
    receipt_store: &SqliteReceiptStore,
    budget_store: &SqliteBudgetStore,
    query: &OperatorReportQuery,
) -> Result<BudgetUtilizationReport, Response> {
    let usages = if let Some(capability_id) = query.capability_id.as_deref() {
        budget_store
            .list_usages(usize::MAX, Some(capability_id))
            .map_err(|error| {
                plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            })?
    } else {
        budget_store.list_all_usages().map_err(|error| {
            plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        })?
    };

    let mut snapshot_cache = HashMap::<String, Option<CapabilitySnapshot>>::new();
    let mut distinct_capabilities = HashSet::<String>::new();
    let mut distinct_subjects = HashSet::<String>::new();
    let mut rows = Vec::new();
    let mut matching_grants = 0_u64;
    let mut total_invocations = 0_u64;
    let mut total_committed_cost_units = 0_u64;
    let mut near_limit_count = 0_u64;
    let mut exhausted_count = 0_u64;
    let mut rows_missing_scope = 0_u64;
    let mut rows_missing_lineage = 0_u64;
    let row_limit = query.budget_limit_or_default();

    for usage in usages {
        let snapshot = match snapshot_cache.get(&usage.capability_id) {
            Some(cached) => cached.clone(),
            None => {
                let loaded = receipt_store
                    .get_lineage(&usage.capability_id)
                    .map_err(|error| {
                        plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                    })?;
                snapshot_cache.insert(usage.capability_id.clone(), loaded.clone());
                loaded
            }
        };

        let subject_key = snapshot.as_ref().map(|value| value.subject_key.clone());
        if let Some(agent_subject) = query.agent_subject.as_deref() {
            if subject_key.as_deref() != Some(agent_subject) {
                continue;
            }
        }

        let resolved = match snapshot.as_ref() {
            Some(snapshot) => resolve_budget_grant(snapshot, usage.grant_index),
            None => ResolvedBudgetGrant {
                scope_resolution_error: Some(
                    "capability lineage snapshot not found for budget row".to_string(),
                ),
                ..ResolvedBudgetGrant::default()
            },
        };

        if let Some(tool_server) = query.tool_server.as_deref() {
            if resolved.tool_server.as_deref() != Some(tool_server) {
                continue;
            }
        }
        if let Some(tool_name) = query.tool_name.as_deref() {
            if resolved.tool_name.as_deref() != Some(tool_name) {
                continue;
            }
        }

        let committed_cost_units = usage.committed_cost_units().map_err(|error| {
            plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        })?;
        let invocation_utilization_rate = resolved
            .max_invocations
            .and_then(|max| ratio_option(usage.invocation_count as u64, max as u64));
        let cost_utilization_rate = resolved
            .max_total_cost_units
            .and_then(|max| ratio_option(committed_cost_units, max));
        let remaining_invocations = resolved
            .max_invocations
            .map(|max| max.saturating_sub(usage.invocation_count));
        let remaining_cost_units = resolved
            .max_total_cost_units
            .map(|max| max.saturating_sub(committed_cost_units));
        let exhausted = resolved
            .max_invocations
            .is_some_and(|max| usage.invocation_count >= max)
            || resolved
                .max_total_cost_units
                .is_some_and(|max| committed_cost_units >= max);
        let near_limit = exhausted
            || invocation_utilization_rate.is_some_and(|rate| rate >= 0.8)
            || cost_utilization_rate.is_some_and(|rate| rate >= 0.8);

        matching_grants = matching_grants.saturating_add(1);
        total_invocations = total_invocations.saturating_add(usage.invocation_count as u64);
        total_committed_cost_units =
            total_committed_cost_units.saturating_add(committed_cost_units);
        distinct_capabilities.insert(usage.capability_id.clone());
        if let Some(subject_key) = subject_key.clone() {
            distinct_subjects.insert(subject_key);
        }
        if snapshot.is_none() {
            rows_missing_lineage = rows_missing_lineage.saturating_add(1);
        }
        if !resolved.scope_resolved {
            rows_missing_scope = rows_missing_scope.saturating_add(1);
        }
        if near_limit {
            near_limit_count = near_limit_count.saturating_add(1);
        }
        if exhausted {
            exhausted_count = exhausted_count.saturating_add(1);
        }

        if rows.len() < row_limit {
            rows.push(BudgetUtilizationRow {
                capability_id: usage.capability_id,
                grant_index: usage.grant_index,
                subject_key,
                tool_server: resolved.tool_server,
                tool_name: resolved.tool_name,
                invocation_count: usage.invocation_count,
                max_invocations: resolved.max_invocations,
                total_cost_charged: committed_cost_units,
                currency: resolved.currency,
                max_total_cost_units: resolved.max_total_cost_units,
                remaining_cost_units,
                invocation_utilization_rate,
                cost_utilization_rate,
                near_limit,
                exhausted,
                updated_at: usage.updated_at,
                scope_resolved: resolved.scope_resolved,
                scope_resolution_error: resolved.scope_resolution_error,
                dimensions: Some(BudgetDimensionProfile {
                    invocations: resolved.max_invocations.map(|max| {
                        let exhausted = usage.invocation_count >= max;
                        let near_limit = exhausted
                            || invocation_utilization_rate.is_some_and(|rate| rate >= 0.8);
                        BudgetDimensionUsage {
                            used: usage.invocation_count as u64,
                            limit: max as u64,
                            remaining: remaining_invocations.unwrap_or(0) as u64,
                            utilization_rate: invocation_utilization_rate,
                            near_limit,
                            exhausted,
                        }
                    }),
                    money: resolved.max_total_cost_units.map(|max| {
                        let exhausted = committed_cost_units >= max;
                        let near_limit =
                            exhausted || cost_utilization_rate.is_some_and(|rate| rate >= 0.8);
                        BudgetDimensionUsage {
                            used: committed_cost_units,
                            limit: max,
                            remaining: remaining_cost_units.unwrap_or(0),
                            utilization_rate: cost_utilization_rate,
                            near_limit,
                            exhausted,
                        }
                    }),
                }),
            });
        }
    }

    Ok(BudgetUtilizationReport {
        summary: BudgetUtilizationSummary {
            matching_grants,
            returned_grants: rows.len() as u64,
            distinct_capabilities: distinct_capabilities.len() as u64,
            distinct_subjects: distinct_subjects.len() as u64,
            total_invocations,
            total_cost_charged: total_committed_cost_units,
            near_limit_count,
            exhausted_count,
            rows_missing_scope,
            rows_missing_lineage,
            truncated: matching_grants > rows.len() as u64,
        },
        rows,
    })
}

fn resolve_budget_grant(snapshot: &CapabilitySnapshot, grant_index: u32) -> ResolvedBudgetGrant {
    let scope = match serde_json::from_str::<ChioScope>(&snapshot.grants_json) {
        Ok(scope) => scope,
        Err(error) => {
            return ResolvedBudgetGrant {
                scope_resolution_error: Some(format!(
                    "failed to parse grants_json for capability {}: {error}",
                    snapshot.capability_id
                )),
                ..ResolvedBudgetGrant::default()
            }
        }
    };

    let Some(grant) = scope.grants.get(grant_index as usize) else {
        return ResolvedBudgetGrant {
            scope_resolution_error: Some(format!(
                "grant_index {} is out of bounds for capability {}",
                grant_index, snapshot.capability_id
            )),
            ..ResolvedBudgetGrant::default()
        };
    };

    ResolvedBudgetGrant {
        tool_server: Some(grant.server_id.clone()),
        tool_name: Some(grant.tool_name.clone()),
        max_invocations: grant.max_invocations,
        max_total_cost_units: grant.max_total_cost.as_ref().map(|value| value.units),
        currency: grant
            .max_total_cost
            .as_ref()
            .map(|value| value.currency.clone())
            .or_else(|| {
                grant
                    .max_cost_per_invocation
                    .as_ref()
                    .map(|value| value.currency.clone())
            }),
        scope_resolved: true,
        scope_resolution_error: None,
    }
}

fn ratio_option(numerator: u64, denominator: u64) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64)
    }
}

pub(crate) fn unix_timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn open_receipt_store(
    config: &TrustServiceConfig,
) -> Result<SqliteReceiptStore, Response> {
    let Some(path) = config.receipt_db_path.as_deref() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "trust control service requires --receipt-db",
        ));
    };
    SqliteReceiptStore::open(path)
        .map_err(|error| plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))
}

pub(crate) fn revocation_list_response(
    capability_id: Option<String>,
    revoked: Option<bool>,
    revocations: Vec<RevocationRecord>,
) -> RevocationListResponse {
    RevocationListResponse {
        configured: true,
        backend: "sqlite".to_string(),
        capability_id,
        revoked,
        count: revocations.len(),
        revocations: revocations
            .into_iter()
            .map(|entry| RevocationRecordView {
                capability_id: entry.capability_id,
                revoked_at: entry.revoked_at,
            })
            .collect(),
    }
}

pub(crate) fn list_limit(requested: Option<usize>) -> usize {
    requested
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT)
}

pub(crate) fn plain_http_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}
