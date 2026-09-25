use serde::Serialize;

use super::*;
use crate::finding_denial::{record_finding_denial, FindingDenial};
use crate::kernel::delivery_contract;

pub(crate) struct DurableToolReturn {
    raw: RawInvocationOutcomeV1,
    outcome: ToolOutcomeRecordV1,
}

impl DurableToolReturn {
    pub(super) fn recovery_request(&self) -> Result<Option<ToolCallRequest>, ToolOutcomeError> {
        self.raw.recovery_request()
    }
}

pub(crate) struct DurableToolReturnInput<'a> {
    pub(crate) request: &'a ToolCallRequest,
    pub(crate) output: &'a ToolServerOutput,
    pub(crate) reported_cost: Option<ToolInvocationCost>,
    pub(crate) matched_grant_index: usize,
    pub(crate) elapsed: Duration,
    pub(crate) extra_receipt_metadata: Option<serde_json::Value>,
    pub(crate) pre_invocation_guard_evidence: &'a [chio_core::receipt::metadata::GuardEvidence],
    pub(crate) verified_payee_binding: Option<&'a VerifiedGovernedPayeeBinding>,
    pub(crate) verified_purchase: Option<&'a crate::finding_purchase::VerifiedFindingPurchase>,
    pub(crate) verified_recovery: Option<&'a delivery_contract::VerifiedFindingRecoveryAdmission>,
    pub(crate) trusted_now_unix_ms: u64,
}

#[derive(Serialize)]
struct LocalToolReturnEvidence<'a> {
    schema: &'static str,
    operation_id: &'a str,
    provider_attempt: &'a ProviderAttemptBindingV1,
    matched_grant_index: u64,
    elapsed_millis: u64,
    stream_limits: InvocationStreamLimitsV1,
    output: &'a InvocationOutputV1,
    reported_cost: &'a Option<ToolInvocationCost>,
    receipt_metadata_snapshot: &'a Option<serde_json::Value>,
    pre_invocation_guard_evidence: &'a [chio_core::receipt::metadata::GuardEvidence],
}

#[derive(Serialize)]
struct KernelPostReturnContext<'a> {
    schema: &'static str,
    request_binding_hash: &'a str,
    matched_grant_index: usize,
    elapsed_millis: u64,
    max_stream_total_bytes: u64,
    max_stream_chunks: u64,
    max_stream_duration_secs: u64,
}

#[derive(Serialize)]
struct KernelOutputMaterialization<'a> {
    schema: &'static str,
    content_hash: &'a str,
    incomplete_reason: Option<&'a str>,
}

struct DurableEvaluatedOutput {
    output: ToolCallOutput,
    incomplete_reason: Option<String>,
    post_invocation_metadata: Option<serde_json::Value>,
    post_invocation_evidence: Vec<chio_core::receipt::metadata::GuardEvidence>,
    step_result_digests: Vec<AdmissionDigest>,
}

#[derive(Serialize)]
struct KernelOutputGuardDecision<'a> {
    schema: &'static str,
    resolved_output_digest: &'a str,
    decision: &'a Decision,
}

#[derive(Serialize)]
struct KernelPricingVerdict<'a> {
    schema: &'static str,
    disposition: &'a SettlementDispositionV1,
}

struct DurablePaymentTerminal {
    journal: crate::payment::PaymentJournalRecord,
    reconcile: BudgetReconcileHoldDecision,
    amount_units: u64,
}

struct DurablePaymentSettlementInput<'a> {
    admission: &'a DurableToolAdmission,
    runtime: &'a DurableAdmissionRuntime,
    lease: &'a crate::admission_operation::AdmissionRecoveryLease,
    journal: crate::payment::PaymentJournalRecord,
    disposition: &'a SettlementDispositionV1,
    context: &'a AdmissionProjectionContext,
    purchase: Option<&'a crate::finding_purchase::VerifiedFindingPurchase>,
    trusted_now_unix_ms: u64,
}

struct CompletedDurableReceiptExpectation<'a> {
    content_hash: &'a str,
    non_admission_metadata: Option<serde_json::Value>,
    decision: &'a Decision,
    post_invocation_evidence: &'a [chio_core::receipt::metadata::GuardEvidence],
}

const DELIVERY_MISMATCH_REDACTION_DOMAIN: &[u8] = b"chio.delivery-mismatch.redacted.v1\0";

/// Produce the receipt-visible content binding for a delivery verdict.
///
/// A mismatch keeps the actual output and digest only in the durable outcome
/// store for privileged challenge handling. The public Deny receipt binds a
/// domain-separated redaction preimage keyed by the committed expected digest,
/// so neither its content hash, delivery-contract block, nor stream metadata
/// becomes a payload confirmation oracle. Replaying the same mismatch
/// reconstructs identical receipt bytes without requiring new randomness.
fn receipt_visible_delivery_content(
    actual: &ReceiptContent,
    digest_mismatched: bool,
    expected_digest: Option<&str>,
) -> ReceiptContent {
    if digest_mismatched {
        let mut canonical_content = Vec::with_capacity(
            DELIVERY_MISMATCH_REDACTION_DOMAIN.len() + expected_digest.map_or(0, str::len),
        );
        canonical_content.extend_from_slice(DELIVERY_MISMATCH_REDACTION_DOMAIN);
        if let Some(expected_digest) = expected_digest {
            canonical_content.extend_from_slice(expected_digest.as_bytes());
        }
        return ReceiptContent {
            content_hash: sha256_hex(&canonical_content),
            metadata: None,
            canonical_content,
        };
    }
    ReceiptContent {
        content_hash: actual.content_hash.clone(),
        metadata: actual.metadata.clone(),
        canonical_content: actual.canonical_content.clone(),
    }
}

fn record_terminal_finding_denial(
    metadata: Option<serde_json::Value>,
    denial: Option<&FindingDenial>,
) -> Option<serde_json::Value> {
    match denial {
        Some(denial) => record_finding_denial(metadata, denial.code()),
        None => metadata,
    }
}

fn payment_journal_matches_settlement(
    journal: &crate::payment::PaymentJournalRecord,
    action: crate::payment::PaymentSettleAction,
    amount_units: u64,
) -> bool {
    journal.settle_action == Some(action)
        && match action {
            crate::payment::PaymentSettleAction::Capture => {
                journal.settle_amount_units == Some(amount_units)
                    && journal.release_authority.is_none()
            }
            crate::payment::PaymentSettleAction::Release => {
                journal.settle_amount_units.is_none()
                    && journal.release_authority.as_ref().is_some_and(|authority| {
                        authority.kind
                            == crate::payment::PaymentReleaseAuthorityKind::ContractualZeroCharge
                    })
            }
        }
}

impl ChioKernel {
    pub(crate) fn record_durable_tool_return(
        &self,
        admission: &mut DurableToolAdmission,
        input: DurableToolReturnInput<'_>,
    ) -> Result<DurableToolReturn, KernelError> {
        let DurableToolReturnInput {
            request,
            output,
            reported_cost,
            matched_grant_index,
            elapsed,
            extra_receipt_metadata,
            pre_invocation_guard_evidence,
            verified_payee_binding,
            verified_purchase,
            verified_recovery,
            trusted_now_unix_ms,
        } = input;
        self.validate_guarded_output(request, matched_grant_index, output, false)?;
        let purchase_replay_metadata =
            self.capture_purchase_replay_metadata(request, matched_grant_index, verified_purchase)?;
        let recovery_replay_metadata =
            self.capture_recovery_replay_metadata(request, matched_grant_index, verified_recovery)?;
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms);
        if admission.operation.state() != AdmissionOperationState::DispatchCommitted {
            return Err(KernelError::DurableAdmission(format!(
                "tool return cannot be recorded from state {:?}",
                admission.operation.state()
            )));
        }
        let provider_attempt =
            admission
                .operation
                .provider_attempt()
                .cloned()
                .ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "durable tool return has no registered provider attempt".to_owned(),
                    )
                })?;
        let invocation_output = match output {
            ToolServerOutput::Value(value) => InvocationOutputV1::Value {
                value: value.clone(),
            },
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream)) => {
                InvocationOutputV1::CompleteStream {
                    chunks: stream
                        .chunks
                        .iter()
                        .map(|chunk| chunk.data.clone())
                        .collect(),
                }
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, reason }) => {
                InvocationOutputV1::IncompleteStream {
                    chunks: stream
                        .chunks
                        .iter()
                        .map(|chunk| chunk.data.clone())
                        .collect(),
                    reason: reason.clone(),
                }
            }
        };
        let elapsed_millis = if fixed_runtime_unix_secs_for_current_thread().is_some() {
            0
        } else {
            u64::try_from(elapsed.as_millis())
                .unwrap_or(I_JSON_MAX_SAFE_INTEGER)
                .min(I_JSON_MAX_SAFE_INTEGER)
        };
        let matched_grant_index_usize = matched_grant_index;
        let matched_grant_index = u64::try_from(matched_grant_index_usize)
            .ok()
            .filter(|index| *index <= I_JSON_MAX_SAFE_INTEGER)
            .ok_or_else(|| {
                KernelError::DurableAdmission("matched grant index is not I-JSON safe".to_owned())
            })?;
        let stream_limits = self.durable_stream_limits()?;
        let receipt_timestamp = trusted_now_unix_ms / 1_000;
        let request_metadata = request_receipt_metadata_with_payee_binding(
            request,
            self.attestation_trust_policy.as_ref(),
            receipt_timestamp,
            extra_receipt_metadata.as_ref(),
            verified_payee_binding,
        )?;
        let memory_read_metadata = match crate::memory_provenance::classify_memory_action(
            &request.tool_name,
            &request.arguments,
        ) {
            Some(crate::memory_provenance::MemoryActionKind::Read { store, key }) => {
                self.resolve_memory_read_provenance_metadata(&store, &key)
            }
            _ => None,
        };
        let receipt_metadata_snapshot = merge_metadata_objects(
            merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(
                        merge_metadata_objects(request_metadata, extra_receipt_metadata),
                        receipt_attribution_metadata(
                            &request.capability,
                            Some(matched_grant_index_usize),
                        ),
                    ),
                    memory_read_metadata,
                ),
                purchase_replay_metadata,
            ),
            recovery_replay_metadata,
        );
        let receipt_metadata_snapshot = merge_metadata_objects(
            receipt_metadata_snapshot,
            Some(serde_json::json!({
                "receipt_context": {
                    "request_id": request.request_id.as_str()
                }
            })),
        );
        let transport_terminal_evidence_digest = admission_digest(
            "transport_terminal_evidence_digest",
            &LocalToolReturnEvidence {
                schema: "chio.local-tool-return-evidence.v1",
                operation_id: admission.operation_id(),
                provider_attempt: &provider_attempt,
                matched_grant_index,
                elapsed_millis,
                stream_limits,
                output: &invocation_output,
                reported_cost: &reported_cost,
                receipt_metadata_snapshot: &receipt_metadata_snapshot,
                pre_invocation_guard_evidence,
            },
        )?;
        let monetary_cost =
            reported_cost
                .as_ref()
                .map(|cost| chio_core::capability::scope::MonetaryAmount {
                    units: cost.units,
                    currency: cost.currency.clone(),
                });
        let commit = admission
            .operation
            .dispatch_commit()
            .cloned()
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "durable tool return lost its dispatch commit".to_owned(),
                )
            })?;
        let raw = RawInvocationOutcomeV1::from_committed_dispatch_with_request(
            &admission.operation,
            &commit,
            AdmissionIdentifier::try_new("tool_server", request.server_id.clone())?,
            AdmissionIdentifier::try_new("tool_name", request.tool_name.clone())?,
            provider_attempt,
            transport_terminal_evidence_digest,
            matched_grant_index,
            elapsed_millis,
            stream_limits,
            invocation_output,
            monetary_cost,
            receipt_metadata_snapshot,
            pre_invocation_guard_evidence.to_vec(),
            request,
        )
        .map_err(tool_outcome_error)?;
        let blob = raw.canonical_blob().map_err(tool_outcome_error)?;
        let record = ToolOutcomeRecordV1::record_tool_returned(
            &admission.operation,
            &raw,
            &blob,
            runtime.fence.clone(),
            trusted_now_unix_ms,
        )
        .map_err(tool_outcome_error)?;
        let expires_at_unix_ms = trusted_now_unix_ms
            .checked_add(RECOVERY_LEASE_DURATION_MS)
            .ok_or_else(|| {
                KernelError::DurableAdmission("recovery lease expiration overflowed".to_owned())
            })?;
        let lease = runtime
            .store
            .claim_recovery(
                admission.operation.binding().operation_id(),
                admission.operation.version(),
                &runtime.claimant_id,
                trusted_now_unix_ms,
                expires_at_unix_ms,
                &runtime.fence,
            )
            .map_err(durable_store_error)?;
        let (stored, finalizing) = runtime
            .outcome_store
            .record_tool_returned(
                &admission.operation,
                &lease,
                &blob,
                &record,
                &runtime.fence,
                trusted_now_unix_ms,
            )
            .map_err(durable_outcome_store_error)?
            .into_parts();
        admission.operation = finalizing;
        Ok(DurableToolReturn {
            raw,
            outcome: stored,
        })
    }

    pub(crate) fn recover_durable_tool_admission(
        &self,
        admission: &mut DurableToolAdmission,
        request: &ToolCallRequest,
    ) -> Result<Option<ToolCallResponse>, KernelError> {
        match admission.state() {
            AdmissionOperationState::Finalizing => {
                let tool_return = self.load_durable_tool_return(admission)?;
                self.finalize_durable_tool_return(admission, request, &tool_return)
                    .map(Some)
            }
            AdmissionOperationState::Completed | AdmissionOperationState::DeniedAfterDelivery => {
                self.completed_durable_tool_response(admission, request)
                    .map(Some)
            }
            _ => Ok(None),
        }
    }

    pub(super) fn load_durable_tool_return(
        &self,
        admission: &DurableToolAdmission,
    ) -> Result<DurableToolReturn, KernelError> {
        let runtime = self.durable_runtime()?;
        let operation_id = admission.operation.binding().operation_id();
        let raw = runtime
            .outcome_store
            .load_raw_invocation_by_operation(operation_id)
            .map_err(durable_outcome_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission("raw tool return disappeared".to_owned())
            })?;
        let outcome = runtime
            .outcome_store
            .lookup_by_operation(operation_id)
            .map_err(durable_outcome_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission("recorded tool outcome disappeared".to_owned())
            })?;
        let blob = raw.canonical_blob().map_err(tool_outcome_error)?;
        outcome
            .validate_canonical_blob(&admission.operation, &blob)
            .map_err(tool_outcome_error)?;
        Ok(DurableToolReturn { raw, outcome })
    }

    fn terminal_tool_call_output(output: ToolServerOutput) -> (ToolCallOutput, Option<String>) {
        match output {
            ToolServerOutput::Value(value) => (ToolCallOutput::Value(value), None),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream)) => {
                (ToolCallOutput::Stream(stream), None)
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, reason }) => {
                (ToolCallOutput::Stream(stream), Some(reason))
            }
        }
    }

    fn evaluate_durable_post_return_output(
        &self,
        request: &ToolCallRequest,
        raw: &RawInvocationOutcomeV1,
        matched_grant_index: usize,
        plan: &DurablePostReturnPlan,
    ) -> Result<DurableEvaluatedOutput, KernelError> {
        let materialized = self.apply_stream_limit_snapshot(
            invocation_output_to_server_output(raw.output()),
            Duration::from_millis(raw.elapsed_millis()),
            raw.stream_limits(),
        )?;
        let (materialized_output, materialized_incomplete_reason) =
            Self::terminal_tool_call_output(materialized.clone());
        let materialized_chunks = match (&materialized_output, &materialized_incomplete_reason) {
            (ToolCallOutput::Stream(stream), None) => Some(stream.chunk_count()),
            (ToolCallOutput::Value(_), _) => None,
            (ToolCallOutput::Stream(_), Some(_)) => None,
        };
        let materialized_content =
            receipt_content_for_output(Some(&materialized_output), materialized_chunks)?;
        let materialization_digest = admission_digest(
            "output_materialization_digest",
            &KernelOutputMaterialization {
                schema: "chio.kernel-output-materialization.v1",
                content_hash: &materialized_content.content_hash,
                incomplete_reason: materialized_incomplete_reason.as_deref(),
            },
        )?;
        let (handling, hook_results) = self.apply_durable_post_invocation_pipeline(
            request,
            materialized,
            matched_grant_index,
            None,
            &plan.hook_identities,
            raw.stream_limits(),
        )?;
        if handling.blocked_reason.is_some() {
            return Err(KernelError::DurableAdmission(
                "durable post-invocation pipeline returned an unsupported blocking verdict"
                    .to_owned(),
            ));
        }
        self.validate_guarded_output(request, matched_grant_index, &handling.output, true)?;
        let (output, transformed_incomplete_reason) =
            Self::terminal_tool_call_output(handling.output);
        let incomplete_reason = materialized_incomplete_reason.or(transformed_incomplete_reason);
        let mut step_result_digests = Vec::with_capacity(hook_results.len() + 1);
        step_result_digests.push(materialization_digest);
        for result in hook_results {
            step_result_digests.push(admission_digest(
                "post_invocation_step_result_digest",
                &result,
            )?);
        }
        if step_result_digests.len() != plan.frozen_steps.len() {
            return Err(KernelError::DurableAdmission(
                "durable post-invocation result count changed after admission".to_owned(),
            ));
        }
        Ok(DurableEvaluatedOutput {
            output,
            incomplete_reason,
            post_invocation_metadata: handling.extra_metadata,
            post_invocation_evidence: handling.evidence,
            step_result_digests,
        })
    }
}

struct DurableEvaluationContract {
    matched_grant_index: usize,
    plan: DurablePostReturnPlan,
    normalized_context: PostReturnNormalizedRequestContextV1,
    expected_output_digest: Option<String>,
    purchase: Option<crate::finding_purchase::VerifiedFindingPurchase>,
    recovery: Option<crate::finding_recovery::VerifiedFindingRecovery>,
    recovery_status: Option<crate::finding_purchase::VerifiedFindingStatusProof>,
}

impl ChioKernel {
    /// The frozen evaluation facts every durable terminal pass re-derives
    /// from the recorded request: the selected grant, the frozen
    /// post-return plan, the normalized replay context, the committed
    /// output digest, and the purchase binding for a marked reveal.
    fn durable_evaluation_contract(
        &self,
        admission: &DurableToolAdmission,
        request: &ToolCallRequest,
        raw: &RawInvocationOutcomeV1,
    ) -> Result<DurableEvaluationContract, KernelError> {
        let matched_grant_index = raw.matched_grant_index().map_err(tool_outcome_error)?;
        let matching_grants = resolve_required_matching_grants(
            &request.capability,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        )
        .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        let plan = self.durable_post_return_plan()?;
        let recovered_request_hash =
            immutable_tool_admission_request_hash(request, &matching_grants, &plan)?;
        if &recovered_request_hash != admission.operation.binding().immutable_request_hash() {
            return Err(KernelError::DurableAdmission(
                "recovered post-return plan does not match durable admission".to_owned(),
            ));
        }
        if let Some(reason) =
            crate::kernel::evaluation::evaluation_helpers::delivery_marked_selection_denial(
                &matching_grants,
                matched_grant_index,
            )
        {
            return Err(KernelError::DurableAdmission(format!(
                "recorded delivery contract is invalid: {reason}"
            )));
        }
        let Some(selected_grant) = matching_grants.iter().find(|matching| {
            matching.index == matched_grant_index && admission.permits_matching_grant(matching)
        }) else {
            return Err(KernelError::DurableAdmission(
                "recorded tool return does not match the captured grant".to_owned(),
            ));
        };
        // The expected output digest is frozen: the whole matching-grant
        // set is covered by the durable binding's immutable_request_hash
        // (revalidated below) and the selected index by the raw blob, so
        // this reads the same digest the grant fixed at admission. The
        // selection-cardinality rule guarantees at most one.
        let mut expected_output_digest = None;
        for constraint in &selected_grant.grant.constraints {
            if let Constraint::OutputDigestSha256(digest) = constraint {
                if expected_output_digest.replace(digest.clone()).is_some() {
                    return Err(KernelError::DurableAdmission(
                        "selected grant carries more than one output digest constraint".to_owned(),
                    ));
                }
            }
        }
        let stream_limits = raw.stream_limits();
        let normalized_context = PostReturnNormalizedRequestContextV1::from_verified_normalization(
            serde_json::to_value(KernelPostReturnContext {
                schema: "chio.kernel-post-return-context.v1",
                request_binding_hash: admission
                    .operation
                    .binding()
                    .request_binding_hash()
                    .as_str(),
                matched_grant_index,
                elapsed_millis: raw.elapsed_millis(),
                max_stream_total_bytes: stream_limits.max_total_bytes,
                max_stream_chunks: stream_limits.max_chunks,
                max_stream_duration_secs: stream_limits.max_duration_secs,
            })
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?,
        )
        .map_err(tool_outcome_error)?;
        // The purchase binding was verified when the authenticated raw tool
        // return was recorded. Reuse that frozen result so a later
        // status-operator rotation cannot strand an already-dispatched
        // operation. The raw outcome and immutable request hash bind the
        // snapshot to this exact request.
        let purchase = self.restore_purchase_replay_snapshot(
            selected_grant.grant,
            request,
            raw.receipt_metadata_snapshot(),
        )?;
        let recovery_snapshot = self.restore_recovery_replay_snapshot(
            selected_grant.grant,
            request,
            raw.receipt_metadata_snapshot(),
        )?;
        let (recovery, recovery_status) = recovery_snapshot.map_or((None, None), |admission| {
            (Some(admission.recovery), Some(admission.status))
        });
        Ok(DurableEvaluationContract {
            matched_grant_index,
            plan,
            normalized_context,
            expected_output_digest,
            purchase,
            recovery,
            recovery_status,
        })
    }

    fn completed_durable_tool_response(
        &self,
        admission: &DurableToolAdmission,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        let runtime = self.durable_runtime()?;
        let tool_return = self.load_durable_tool_return(admission)?;
        let DurableEvaluationContract {
            matched_grant_index,
            plan,
            normalized_context,
            expected_output_digest,
            purchase,
            recovery,
            recovery_status,
        } = self.durable_evaluation_contract(admission, request, &tool_return.raw)?;
        let DurableEvaluatedOutput {
            output,
            incomplete_reason,
            post_invocation_metadata,
            post_invocation_evidence,
            step_result_digests,
        } = self.evaluate_durable_post_return_output(
            request,
            &tool_return.raw,
            matched_grant_index,
            &plan,
        )?;
        let expected_chunks = match (&output, &incomplete_reason) {
            (ToolCallOutput::Stream(stream), None) => Some(stream.chunk_count()),
            _ => None,
        };
        let receipt_content = receipt_content_for_output(Some(&output), expected_chunks)?;
        let receipt_id = match admission.operation.terminal_replay() {
            Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) => receipt_id,
            _ => {
                return Err(KernelError::DurableAdmission(
                    "completed admission has no receipt replay reference".to_owned(),
                ));
            }
        };
        let receipt = runtime
            .store
            .load_chio_receipt(receipt_id.as_str())
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?
            .ok_or_else(|| {
                KernelError::DurableAdmission("projected receipt disappeared".to_owned())
            })?;
        let mut delivery_evaluation = delivery_contract::evaluate_delivery(
            expected_output_digest.as_deref(),
            &receipt_content.content_hash,
            matches!(output, ToolCallOutput::Value(_)),
            &receipt_content.canonical_content,
            purchase.as_ref(),
        );
        if let Some(reason) = self.revalidate_replayed_purchase_delivery(
            receipt.decision.as_ref(),
            &mut delivery_evaluation,
            purchase.as_ref(),
            current_unix_timestamp_ms() / 1_000,
        ) {
            warn!(request_id = %request.request_id, reason = %redacted!(&reason), "finding purchase replay output withheld");
        }
        let receipt_visible_content = receipt_visible_delivery_content(
            &receipt_content,
            delivery_evaluation.digest_mismatched,
            expected_output_digest.as_deref(),
        );
        let expected_decision = match &delivery_evaluation.denial {
            Some(denial) => Decision::Deny {
                reason: denial.message.to_owned(),
                guard: denial.guard.to_owned(),
            },
            None => incomplete_reason
                .as_ref()
                .map_or(Decision::Allow, |reason| Decision::Incomplete {
                    reason: reason.clone(),
                }),
        };
        let expected_non_financial_metadata = merge_metadata_objects(
            merge_metadata_objects(
                receipt_visible_content.metadata.clone(),
                tool_return.raw.receipt_metadata_snapshot().cloned(),
            ),
            post_invocation_metadata,
        );
        let evaluation = runtime
            .outcome_store
            .lookup_post_return_evaluation(admission.operation.binding().operation_id())
            .map_err(durable_outcome_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission("terminal evaluation disappeared".to_owned())
            })?;
        evaluation
            .validate_against(&admission.operation, &tool_return.outcome)
            .and_then(|_| {
                evaluation.validate_replay_contract(&plan.frozen_steps, &normalized_context)
            })
            .map_err(tool_outcome_error)?;
        if !matches!(
            evaluation.state(),
            PostReturnEvaluationStateV1::Resolved { .. }
        ) {
            return Err(KernelError::DurableAdmission(
                "completed admission retains a nonterminal evaluation".to_owned(),
            ));
        }
        for (index, expected) in step_result_digests.iter().enumerate() {
            if evaluation.step_result_digest(index) != Some(expected) {
                return Err(KernelError::DurableAdmission(
                    "completed post-invocation result conflicts with replay".to_owned(),
                ));
            }
        }
        if evaluation
            .step_result_digest(step_result_digests.len())
            .is_some()
        {
            return Err(KernelError::DurableAdmission(
                "completed post-invocation result count conflicts with replay".to_owned(),
            ));
        }
        let resolved_output = runtime
            .outcome_store
            .load_resolved_output_by_operation(admission.operation.binding().operation_id())
            .map_err(durable_outcome_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission("resolved output preimage disappeared".to_owned())
            })?;
        let ResolvedToolOutcomeV1::Resolved {
            resolved_output: expected_output,
            resolved_output_size_bytes,
            settlement_disposition,
            ..
        } = tool_return.outcome.disposition()
        else {
            return Err(KernelError::DurableAdmission(
                "completed admission retains an unresolved tool outcome".to_owned(),
            ));
        };
        if resolved_output.blob_ref() != expected_output
            || u64::try_from(resolved_output.bytes().len()).ok()
                != Some(*resolved_output_size_bytes)
            || resolved_output.bytes() != receipt_content.canonical_content.as_slice()
        {
            return Err(KernelError::DurableAdmission(
                "completed output conflicts with its retained preimage".to_owned(),
            ));
        }
        if let Some(binding) = purchase.as_ref() {
            self.settle_finding_pool_delivery_terminal(
                admission.operation.binding().operation_id().as_str(),
                binding,
                settlement_disposition,
            )?;
        }
        let retained_financial_metadata = receipt
            .metadata
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .and_then(|metadata| metadata.get("financial"))
            .cloned()
            .map(|financial| serde_json::json!({ "financial": financial }));
        let expected_non_admission_metadata =
            merge_metadata_objects(expected_non_financial_metadata, retained_financial_metadata);
        // Reproduce the delivery-contract and finding-delivery blocks so
        // the replayed metadata byte-matches the persisted receipt.
        let expected_non_admission_metadata =
            if let Some(expected) = expected_output_digest.as_deref() {
                let block = chio_core::receipt::metadata::DeliveryContract {
                    schema: chio_core::receipt::metadata::DELIVERY_CONTRACT_SCHEMA.to_owned(),
                    expected_digest: expected.to_owned(),
                    observed_digest: receipt_visible_content.content_hash.clone(),
                    result: if delivery_evaluation.digest_mismatched {
                        chio_core::receipt::metadata::DeliveryResult::Mismatched
                    } else {
                        chio_core::receipt::metadata::DeliveryResult::Matched
                    },
                };
                merge_metadata_objects(
                    expected_non_admission_metadata,
                    Some(serde_json::json!({
                        chio_core::receipt::metadata::DELIVERY_CONTRACT_METADATA_KEY: block
                    })),
                )
            } else {
                expected_non_admission_metadata
            };
        let expected_non_admission_metadata = if let Some(binding) = purchase.as_ref() {
            let block = delivery_contract::finding_delivery_block(binding, &delivery_evaluation);
            merge_metadata_objects(
                expected_non_admission_metadata,
                Some(serde_json::json!({
                    chio_core::receipt::metadata::FINDING_DELIVERY_METADATA_KEY: block
                })),
            )
        } else {
            expected_non_admission_metadata
        };
        let expected_non_admission_metadata = if let Some(binding) = recovery.as_ref() {
            let block = delivery_contract::finding_recovery_block(binding);
            merge_metadata_objects(
                expected_non_admission_metadata,
                Some(serde_json::json!({
                    chio_core::receipt::metadata::FINDING_RECOVERY_METADATA_KEY: block
                })),
            )
        } else {
            expected_non_admission_metadata
        };
        self.validate_completed_durable_receipt(
            admission,
            request,
            &tool_return,
            CompletedDurableReceiptExpectation {
                content_hash: &receipt_visible_content.content_hash,
                non_admission_metadata: expected_non_admission_metadata,
                decision: &expected_decision,
                post_invocation_evidence: &post_invocation_evidence,
            },
            &receipt,
        )?;
        self.revalidate_completed_recovery_status(
            matched_grant_index,
            request,
            recovery.as_ref(),
            recovery_status.as_ref(),
            current_unix_timestamp_ms() / 1_000,
        )
        .map_err(|reason| {
            KernelError::DurableAdmission(format!(
                "finding recovery terminal status revalidation failed: {reason}"
            ))
        })?;
        self.materialize_durable_admission_receipt(&receipt)?;
        self.mirror_durable_admission_receipt(&receipt)?;
        if let Some(binding) = recovery.as_ref() {
            let verifier = self.finding_recovery_verifier.as_ref().ok_or_else(|| {
                KernelError::DurableAdmission(
                    "finding recovery verifier disappeared during replay".to_owned(),
                )
            })?;
            verifier
                .record_recovery_receipt(binding, &receipt.id, receipt.timestamp)
                .map_err(|error| {
                    KernelError::DurableAdmission(format!(
                        "finding recovery lineage could not be recorded: {error}"
                    ))
                })?;
        }
        if request.federated_origin_kernel_id.is_some()
            && (self.dual_signed_receipt(&receipt.id).is_none()
                || self.federation_dsse_envelope(&receipt.id).is_none())
        {
            // A completed replay enters recovery before the ordinary runtime
            // admission stage. Re-admit and reinstall the verified treaty
            // material before retrying the missing bilateral projection.
            let now_unix_ms = current_unix_timestamp_ms();
            let treaty_admission = self.run_runtime_admission_hook(
                request,
                tool_return.raw.receipt_metadata_snapshot(),
                now_unix_ms / 1_000,
                now_unix_ms,
                Some(matched_grant_index),
            );
            if !treaty_admission.allowed {
                return Err(KernelError::Internal(format!(
                    "federation runtime treaty re-admission failed during completed replay: {}",
                    treaty_admission
                        .reason
                        .unwrap_or_else(|| "runtime admission denied".to_string())
                )));
            }
            self.apply_federation_cosign_for_admitted_request(request, &receipt)?;
        }
        if let Some(crate::memory_provenance::MemoryActionKind::Write { store, key }) =
            crate::memory_provenance::classify_memory_action(&request.tool_name, &request.arguments)
                .as_ref()
        {
            self.append_memory_provenance_for_write(store, key, request, &receipt)?;
        }
        let (verdict, reason, terminal_state) =
            if let Some(denial) = delivery_evaluation.denial.as_ref() {
                (
                    Verdict::Deny,
                    Some(denial.message.to_owned()),
                    OperationTerminalState::Completed,
                )
            } else {
                incomplete_reason.map_or(
                    (Verdict::Allow, None, OperationTerminalState::Completed),
                    |reason| {
                        (
                            Verdict::Deny,
                            Some(reason.clone()),
                            OperationTerminalState::Incomplete { reason },
                        )
                    },
                )
            };
        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict,
            // A denied delivery returns no payload. An actual digest mismatch
            // exposes only the deterministic redaction binding; another
            // delivery denial may retain the already-committed matched digest.
            output: delivery_evaluation.denial.is_none().then_some(output),
            reason,
            terminal_state,
            receipt,
            execution_nonce: None,
        })
    }

    fn validate_completed_durable_receipt(
        &self,
        admission: &DurableToolAdmission,
        request: &ToolCallRequest,
        tool_return: &DurableToolReturn,
        expectation: CompletedDurableReceiptExpectation<'_>,
        receipt: &chio_core::receipt::body::ChioReceipt,
    ) -> Result<(), KernelError> {
        let CompletedDurableReceiptExpectation {
            content_hash: expected_content_hash,
            non_admission_metadata: expected_non_admission_metadata,
            decision: expected_decision,
            post_invocation_evidence: expected_post_invocation_evidence,
        } = expectation;
        // A delivery-digest mismatch is the only durable terminal that renders
        // a Deny: it persists as DeniedAfterDelivery and attaches no
        // completed-tool-outcome, unlike an Allow or Incomplete Completed.
        let denied = matches!(expected_decision, Decision::Deny { .. });
        let runtime = self.durable_runtime()?;
        let operation = &admission.operation;
        let replay_receipt_id = match operation.terminal_replay() {
            Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) => receipt_id.as_str(),
            _ => "",
        };
        let action =
            ToolCallAction::from_parameters(request.arguments.clone()).map_err(|error| {
                KernelError::DurableAdmission(format!("replay action is invalid: {error}"))
            })?;
        let binding = operation.binding().to_persisted();
        let expected_tenant = (binding.authenticated_tenant_id.as_str() != LOCAL_SYSTEM_TENANT_ID)
            .then_some(binding.authenticated_tenant_id.as_str());
        let signature_valid = receipt.verify_signature().map_err(|error| {
            KernelError::DurableAdmission(format!("replay receipt verification failed: {error}"))
        })?;
        let metadata = receipt
            .metadata
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .and_then(|value| value.get(ADMISSION_RECEIPT_METADATA_KEY))
            .cloned()
            .and_then(|value| serde_json::from_value::<AdmissionReceiptMetadataV1>(value).ok())
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "replay receipt admission metadata is invalid".to_owned(),
                )
            })?;
        let expected_outcome_id = Some(tool_return.outcome.outcome_id());
        let financial = receipt
            .metadata
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .and_then(|metadata| metadata.get("financial"))
            .cloned()
            .map(serde_json::from_value::<FinancialReceiptMetadata>)
            .transpose()
            .map_err(|_| {
                KernelError::DurableAdmission(
                    "projected receipt financial metadata is invalid".to_owned(),
                )
            })?;
        if operation.binding().participant_requirements().payment {
            let journal = runtime
                .store
                .load_payment_journal(operation.binding().operation_id().as_str(), &runtime.fence)
                .map_err(|error| KernelError::DurableAdmission(error.to_string()))?
                .ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "completed payment journal disappeared".to_owned(),
                    )
                })?;
            let expected_cost = match (journal.rail_mode, journal.settle_action) {
                (crate::payment::PaymentRailMode::PrepaidFinal, _) => journal.amount_units,
                (
                    crate::payment::PaymentRailMode::ReversibleHold,
                    Some(crate::payment::PaymentSettleAction::Capture),
                ) => journal.settle_amount_units.ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "completed capture journal omitted its amount".to_owned(),
                    )
                })?,
                (
                    crate::payment::PaymentRailMode::ReversibleHold,
                    Some(crate::payment::PaymentSettleAction::Release),
                ) => 0,
                _ => {
                    return Err(KernelError::DurableAdmission(
                        "completed payment journal omitted its settlement action".to_owned(),
                    ));
                }
            };
            let financial = financial.as_ref().ok_or_else(|| {
                KernelError::DurableAdmission(
                    "completed payment receipt omitted financial metadata".to_owned(),
                )
            })?;
            let payment_reference = journal
                .transaction_id
                .as_ref()
                .or(journal.authorization_id.as_ref());
            if journal.state != crate::payment::PaymentJournalState::Settled
                || financial.grant_index != journal.grant_index
                || financial.cost_charged != expected_cost
                || financial.currency != journal.currency
                || financial.payment_reference.as_ref() != payment_reference
                || financial.settlement_status != SettlementStatus::Settled
                || financial.delegation_depth
                    != u32::try_from(request.capability.delegation_chain.len()).unwrap_or(u32::MAX)
                || financial.root_budget_holder != request.capability.issuer.to_hex()
                || financial.budget_remaining > financial.budget_total
                || financial.attempted_cost.is_some()
            {
                return Err(KernelError::DurableAdmission(
                    "projected receipt financial metadata conflicts with the payment journal"
                        .to_owned(),
                ));
            }
        } else if financial.is_some() {
            return Err(KernelError::DurableAdmission(
                "nonpayment admission projected financial metadata".to_owned(),
            ));
        }
        let signing_nonce = receipt
            .metadata
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .and_then(|metadata| {
                metadata.get(chio_core::receipt::signing::CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY)
            })
            .and_then(serde_json::Value::as_str)
            .filter(|nonce| !nonce.is_empty())
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "projected receipt has no canonical signing nonce".to_owned(),
                )
            })?;
        let expected_metadata = merge_metadata_objects(
            merge_metadata_objects(
                expected_non_admission_metadata,
                Some(serde_json::json!({
                    ADMISSION_RECEIPT_METADATA_KEY: metadata.clone()
                })),
            ),
            Some(serde_json::json!({
                chio_core::receipt::signing::CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY:
                    signing_nonce
            })),
        );
        let dispatch_fence = operation
            .dispatch_commit()
            .map(|commit| &commit.store_fence);
        if receipt.metadata != expected_metadata {
            return Err(KernelError::DurableAdmission(
                "projected receipt metadata conflicts with the retained snapshot".to_owned(),
            ));
        }
        if dispatch_fence.is_none_or(|fence| {
            metadata.store_fence.store_uuid != fence.store_uuid
                || metadata.store_fence.owner_epoch < fence.owner_epoch
        }) || metadata.store_fence.store_uuid != runtime.fence.store_uuid
            || metadata.store_fence.owner_epoch > runtime.fence.owner_epoch
        {
            return Err(KernelError::DurableAdmission(
                "projected receipt store fence conflicts with the admission lineage".to_owned(),
            ));
        }
        if !signature_valid
            || receipt.id != replay_receipt_id
            || receipt.kernel_key != self.config.keypair.public_key()
            || receipt.decision.as_ref() != Some(expected_decision)
            || receipt.capability_id != request.capability.id
            || receipt.tool_server != request.server_id
            || receipt.tool_name != request.tool_name
            || receipt.action.parameters != action.parameters
            || receipt.action.parameter_hash != action.parameter_hash
            || receipt.content_hash != expected_content_hash
            || receipt.policy_hash != operation.binding().policy_hash().as_str()
            || receipt.tenant_id.as_deref() != expected_tenant
            || receipt.evidence
                != tool_return
                    .raw
                    .pre_invocation_guard_evidence()
                    .iter()
                    .chain(expected_post_invocation_evidence)
                    .cloned()
                    .collect::<Vec<_>>()
            || metadata.schema != AdmissionReceiptSchema::V1
            || metadata.operation_id != *operation.binding().operation_id()
            || metadata.request_id != *operation.binding().request_id()
            || metadata.request_namespace_digest != *operation.binding().request_namespace_digest()
            || metadata.request_binding_hash != *operation.binding().request_binding_hash()
            || metadata.projected_operation_version != operation.version()
            || metadata.projected_state
                != if denied {
                    AdmissionOperationState::DeniedAfterDelivery
                } else {
                    AdmissionOperationState::Completed
                }
            || metadata.projected_dispatch_state != AdmissionDispatchState::Terminal
            || metadata.trusted_time_unix_ms == 0
            || receipt.timestamp != metadata.trusted_time_unix_ms / 1_000
            || metadata.coordinator_lease_epoch != operation.coordinator_lease_epoch()
            || metadata.retained_dispatch_commit != operation.dispatch_commit().cloned()
            || metadata.compensation_status != AdmissionCompensationStatus::NotCompensated
            || metadata.tool_outcome_id.as_ref() != if denied { None } else { expected_outcome_id }
            || metadata.tool_outcome_version
                != if denied {
                    None
                } else {
                    Some(tool_return.outcome.version())
                }
        {
            return Err(KernelError::DurableAdmission(
                "projected receipt conflicts with the completed admission".to_owned(),
            ));
        }
        Ok(())
    }

    fn durable_payment_disposition(
        &self,
        admission: &DurableToolAdmission,
        runtime: &DurableAdmissionRuntime,
        raw: &RawInvocationOutcomeV1,
        trusted_now_unix_ms: u64,
        delivery_denied: bool,
    ) -> Result<
        Option<(
            crate::payment::PaymentJournalRecord,
            SettlementDispositionV1,
        )>,
        KernelError,
    > {
        if !admission.requires_payment() {
            return Ok(None);
        }
        let journal = runtime
            .store
            .load_payment_journal(admission.operation_id(), &runtime.fence)
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "durable payment participant disappeared during finalization".to_owned(),
                )
            })?;
        journal
            .validate()
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        if journal.capability_id != admission.operation.binding().capability_id().as_str()
            || usize::try_from(journal.grant_index).ok()
                != Some(raw.matched_grant_index().map_err(tool_outcome_error)?)
        {
            return Err(KernelError::DurableAdmission(
                "payment journal does not match the recorded tool outcome".to_owned(),
            ));
        }
        let amount_units = match journal.rail_mode {
            crate::payment::PaymentRailMode::PrepaidFinal => journal.amount_units,
            crate::payment::PaymentRailMode::ReversibleHold => {
                let reported = raw.reported_cost();
                let units = match reported {
                    Some(cost) if cost.currency != journal.currency => {
                        let cost = ToolInvocationCost {
                            units: cost.units,
                            currency: cost.currency.clone(),
                            breakdown: None,
                        };
                        self.resolve_cross_currency_cost(
                            &cost,
                            &journal.currency,
                            trusted_now_unix_ms / 1_000,
                        )?
                        .0
                    }
                    Some(cost) => cost.units,
                    None => journal.amount_units,
                };
                if units > journal.amount_units {
                    return Err(KernelError::DurableAdmission(
                        "reported cost exceeds the durable payment authorization".to_owned(),
                    ));
                }
                units
            }
        };
        // A delivery mismatch releases the open hold and captures zero. The
        // pre-dispatch gate rejects every non-reversible rail for a
        // digest-constrained request, so a denied delivery is always a
        // reversible hold; assert that invariant rather than silently
        // producing an unreleasable zero-charge.
        if delivery_denied && journal.rail_mode != crate::payment::PaymentRailMode::ReversibleHold {
            return Err(KernelError::DurableAdmission(
                "delivery denial requires a reversible-hold rail".to_owned(),
            ));
        }
        let disposition = if delivery_denied || amount_units == 0 {
            SettlementDispositionV1::ContractualZeroCharge {
                currency: journal.currency.clone(),
            }
        } else {
            SettlementDispositionV1::Capture {
                amount: chio_core::capability::scope::MonetaryAmount {
                    units: amount_units,
                    currency: journal.currency.clone(),
                },
            }
        };
        Ok(Some((journal, disposition)))
    }

    pub(super) fn continue_durable_payment_settlement(
        &self,
        operation: &AdmissionOperationV1,
        runtime: &DurableAdmissionRuntime,
        lease: &crate::admission_operation::AdmissionRecoveryLease,
        mut journal: crate::payment::PaymentJournalRecord,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<crate::payment::PaymentJournalRecord>, KernelError> {
        journal
            .validate()
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        if journal.operation_id != operation.binding().operation_id().as_str() {
            return Err(KernelError::DurableAdmission(
                "payment settlement changed operation identity".to_owned(),
            ));
        }
        if journal.state == crate::payment::PaymentJournalState::Settled {
            return Ok(Some(journal));
        }
        // A journal sealed as reconcile_failed still carries its settle action and
        // authorization, so the same intent is re-driven against the rail rather
        // than leaving the operation non-terminal with its hold already reconciled.
        if journal.rail_mode != crate::payment::PaymentRailMode::ReversibleHold
            || !matches!(
                journal.state,
                crate::payment::PaymentJournalState::Settling
                    | crate::payment::PaymentJournalState::ReconcileFailed
            )
        {
            return Err(KernelError::DurableAdmission(
                "payment journal has no replayable settlement intent".to_owned(),
            ));
        }
        let settle_action = journal.settle_action.ok_or_else(|| {
            KernelError::DurableAdmission("settling payment journal omitted its action".to_owned())
        })?;
        let authorization_id = journal.authorization_id.as_deref().ok_or_else(|| {
            KernelError::DurableAdmission(
                "settling payment journal omitted authorization_id".to_owned(),
            )
        })?;
        let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
            KernelError::DurableAdmission(
                "durable payment adapter disappeared during settlement".to_owned(),
            )
        })?;
        if adapter.rail_id() != journal.rail || adapter.rail_mode() != Some(journal.rail_mode) {
            return Err(KernelError::DurableAdmission(
                "durable payment adapter changed before settlement".to_owned(),
            ));
        }
        let result = match settle_action {
            crate::payment::PaymentSettleAction::Capture => adapter.capture(
                authorization_id,
                journal.settle_amount_units.ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "capture journal omitted its settlement amount".to_owned(),
                    )
                })?,
                &journal.currency,
                &journal.operation_id,
            ),
            crate::payment::PaymentSettleAction::Release => {
                adapter.release(authorization_id, &journal.operation_id)
            }
        }
        .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        let compatible = matches!(
            (settle_action, result.settlement_status),
            (
                crate::payment::PaymentSettleAction::Capture,
                crate::payment::RailSettlementStatus::Captured
                    | crate::payment::RailSettlementStatus::Settled
            ) | (
                crate::payment::PaymentSettleAction::Release,
                crate::payment::RailSettlementStatus::Released
            )
        );
        if compatible {
            let transition = crate::payment::PaymentJournalTransition::SettlementCompleted {
                transaction_id: result.transaction_id,
            };
            journal = runtime
                .store
                .advance_payment_journal(crate::receipt_store::AdmissionPaymentJournalAdvance {
                    operation,
                    recovery_lease: lease,
                    expected: &journal,
                    transition: &transition,
                    release_evidence: None,
                    active_fence: &runtime.fence,
                    trusted_now_unix_ms,
                })
                .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
            return Ok(Some(journal));
        }
        if result.settlement_status == crate::payment::RailSettlementStatus::Pending {
            return Ok(None);
        }
        if journal.state != crate::payment::PaymentJournalState::ReconcileFailed {
            let transition = crate::payment::PaymentJournalTransition::ReconcileFailed;
            runtime
                .store
                .advance_payment_journal(crate::receipt_store::AdmissionPaymentJournalAdvance {
                    operation,
                    recovery_lease: lease,
                    expected: &journal,
                    transition: &transition,
                    release_evidence: None,
                    active_fence: &runtime.fence,
                    trusted_now_unix_ms,
                })
                .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        }
        Err(KernelError::DurableAdmission(
            "payment rail returned an incompatible settlement status".to_owned(),
        ))
    }

    fn settle_durable_payment(
        &self,
        input: DurablePaymentSettlementInput<'_>,
    ) -> Result<DurablePaymentTerminal, KernelError> {
        let DurablePaymentSettlementInput {
            admission,
            runtime,
            lease,
            mut journal,
            disposition,
            context,
            purchase,
            trusted_now_unix_ms,
        } = input;
        let (amount_units, settle_action) = match disposition {
            SettlementDispositionV1::Capture { amount } => {
                if amount.currency != journal.currency
                    || amount.units == 0
                    || amount.units > journal.amount_units
                {
                    return Err(KernelError::DurableAdmission(
                        "durable capture disposition conflicts with the payment journal".to_owned(),
                    ));
                }
                (amount.units, crate::payment::PaymentSettleAction::Capture)
            }
            SettlementDispositionV1::ContractualZeroCharge { currency } => {
                if currency != &journal.currency
                    || journal.rail_mode != crate::payment::PaymentRailMode::ReversibleHold
                {
                    return Err(KernelError::DurableAdmission(
                        "zero-charge disposition conflicts with the payment journal".to_owned(),
                    ));
                }
                (0, crate::payment::PaymentSettleAction::Release)
            }
            SettlementDispositionV1::NotApplicable => {
                return Err(KernelError::DurableAdmission(
                    "payment participant cannot use a not-applicable settlement".to_owned(),
                ));
            }
        };
        let hold_id = journal.hold_id.clone().ok_or_else(|| {
            KernelError::DurableAdmission("payment journal omitted its budget hold".to_owned())
        })?;
        let (transition, release_evidence) = match (journal.rail_mode, journal.state) {
            (
                crate::payment::PaymentRailMode::PrepaidFinal,
                crate::payment::PaymentJournalState::Settled,
            ) if journal.authorization_id.is_some() && amount_units == journal.amount_units => {
                (None, None)
            }
            (
                crate::payment::PaymentRailMode::ReversibleHold,
                crate::payment::PaymentJournalState::Authorized,
            ) => match settle_action {
                crate::payment::PaymentSettleAction::Capture => (
                    Some(crate::payment::PaymentJournalTransition::BeginCapture { amount_units }),
                    None,
                ),
                crate::payment::PaymentSettleAction::Release => {
                    let proof = runtime
                        .verify_contractual_zero_charge(&admission.operation, context)
                        .map_err(tool_outcome_error)?;
                    let evidence =
                        crate::tool_outcome::MonetaryReleaseAuthority::ContractualZeroCharge(
                            Box::new(proof),
                        )
                        .evidence_bundle()
                        .map_err(tool_outcome_error)?;
                    let persisted = evidence.to_persisted();
                    let authority = crate::payment::PaymentReleaseAuthorityBinding {
                        kind: crate::payment::PaymentReleaseAuthorityKind::ContractualZeroCharge,
                        operation_id: persisted.operation_id.as_str().to_owned(),
                        operation_version: persisted.operation_version,
                        evidence_id: persisted.evidence_id.as_str().to_owned(),
                        evidence_digest: persisted.bundle_digest.as_str().to_owned(),
                    };
                    (
                        Some(crate::payment::PaymentJournalTransition::BeginRelease { authority }),
                        Some(evidence),
                    )
                }
            },
            (
                crate::payment::PaymentRailMode::ReversibleHold,
                crate::payment::PaymentJournalState::Settling
                | crate::payment::PaymentJournalState::Settled,
            ) if payment_journal_matches_settlement(&journal, settle_action, amount_units) => {
                (None, None)
            }
            (crate::payment::PaymentRailMode::PrepaidFinal, _) => {
                return Err(KernelError::DurableAdmission(
                    "final prepayment journal is not terminal and fixed-price".to_owned(),
                ));
            }
            (crate::payment::PaymentRailMode::ReversibleHold, _) => {
                return Err(KernelError::DurableAdmission(
                    "payment journal has no replayable settlement intent".to_owned(),
                ));
            }
        };
        let settlement = runtime
            .store
            .begin_payment_settlement(crate::receipt_store::AdmissionPaymentSettlementBegin {
                operation: &admission.operation,
                recovery_lease: lease,
                expected: &journal,
                transition: transition.as_ref(),
                release_evidence: release_evidence.as_ref(),
                budget_reconcile: BudgetReconcileHoldRequest {
                    capability_id: journal.capability_id.clone(),
                    grant_index: usize::try_from(journal.grant_index).map_err(|_| {
                        KernelError::DurableAdmission(
                            "payment journal grant index overflowed".to_owned(),
                        )
                    })?,
                    exposed_cost_units: journal.amount_units,
                    realized_spend_units: amount_units,
                    hold_id: Some(hold_id.clone()),
                    event_id: Some(format!("{hold_id}:reconcile")),
                    authority: Some(runtime.authority()),
                },
                active_fence: &runtime.fence,
                trusted_now_unix_ms,
            })
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        journal = settlement.journal;
        let reconcile = settlement.budget;
        if !payment_journal_matches_settlement(&journal, settle_action, amount_units) {
            return Err(KernelError::DurableAdmission(
                "payment journal conflicts with the pricing disposition".to_owned(),
            ));
        }
        if settle_action == crate::payment::PaymentSettleAction::Capture {
            if let Some(purchase) = purchase {
                let verifier = self.finding_purchase_verifier.as_ref().ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "purchase capture lost its configured verifier".to_owned(),
                    )
                })?;
                verifier
                    .mark_capture_pending(purchase, trusted_now_unix_ms / 1_000)
                    .map_err(|error| {
                        KernelError::DurableAdmission(format!(
                            "purchase capture fence failed: {error}"
                        ))
                    })?;
            }
        }
        journal = self
            .continue_durable_payment_settlement(
                &admission.operation,
                runtime,
                lease,
                journal,
                trusted_now_unix_ms,
            )?
            .ok_or_else(|| {
                KernelError::DurableAdmission("payment settlement remains pending".to_owned())
            })?;
        if journal.state != crate::payment::PaymentJournalState::Settled {
            return Err(KernelError::DurableAdmission(
                "payment journal did not reach a terminal settlement".to_owned(),
            ));
        }
        Ok(DurablePaymentTerminal {
            journal,
            reconcile,
            amount_units,
        })
    }

    pub(crate) fn finalize_durable_tool_return(
        &self,
        admission: &mut DurableToolAdmission,
        request: &ToolCallRequest,
        tool_return: &DurableToolReturn,
    ) -> Result<ToolCallResponse, KernelError> {
        let runtime = self.durable_runtime()?;
        if admission.operation.state() != AdmissionOperationState::Finalizing {
            return Err(KernelError::DurableAdmission(format!(
                "terminal projection cannot start from state {:?}",
                admission.operation.state()
            )));
        }
        let raw_blob = tool_return
            .raw
            .canonical_blob()
            .map_err(tool_outcome_error)?;
        tool_return
            .outcome
            .validate_canonical_blob(&admission.operation, &raw_blob)
            .map_err(tool_outcome_error)?;
        let _guard_evidence_scope = scope_pre_invocation_guard_evidence(
            tool_return.raw.pre_invocation_guard_evidence().to_vec(),
        );
        let DurableEvaluationContract {
            matched_grant_index,
            plan,
            normalized_context,
            expected_output_digest,
            purchase,
            recovery,
            recovery_status,
        } = self.durable_evaluation_contract(admission, request, &tool_return.raw)?;
        let DurableEvaluatedOutput {
            output,
            incomplete_reason,
            post_invocation_metadata,
            post_invocation_evidence,
            step_result_digests,
        } = self.evaluate_durable_post_return_output(
            request,
            &tool_return.raw,
            matched_grant_index,
            &plan,
        )?;
        let _post_invocation_evidence_scope =
            scope_post_invocation_guard_evidence(post_invocation_evidence);
        let expected_chunks = match (&output, &incomplete_reason) {
            (ToolCallOutput::Stream(stream), None) => Some(stream.chunk_count()),
            _ => None,
        };
        let receipt_content = receipt_content_for_output(Some(&output), expected_chunks)?;
        let resolved_output_digest = AdmissionDigest::try_new(
            "resolved_output_digest",
            receipt_content.content_hash.clone(),
        )?;
        // Evaluate the frozen delivery contract after transforms and before settlement.
        if purchase.is_some() && !plan.hook_identities.is_empty() {
            return Err(KernelError::DurableAdmission(
                "purchase-marked delivery requires the frozen identity output plan".to_owned(),
            ));
        }
        let mut terminal_finding_denial: Option<FindingDenial> = None;
        let mut delivery_evaluation = delivery_contract::evaluate_delivery(
            expected_output_digest.as_deref(),
            resolved_output_digest.as_str(),
            matches!(output, ToolCallOutput::Value(_)),
            &receipt_content.canonical_content,
            purchase.as_ref(),
        );
        if delivery_evaluation.denial.is_none() {
            if let Err(denial) = self.revalidate_completed_purchase_status(
                purchase.as_ref(),
                current_unix_timestamp_ms() / 1_000,
            ) {
                warn!(request_id = %request.request_id, reason = %redacted!(&denial), "finding purchase terminal output withheld");
                #[cfg(feature = "finding-market")]
                {
                    terminal_finding_denial = Some(denial);
                }
                delivery_evaluation.denial =
                    Some(delivery_contract::finding_status_delivery_denial());
            }
        }
        let stored_outcome = runtime
            .outcome_store
            .lookup_by_operation(admission.operation.binding().operation_id())
            .map_err(durable_outcome_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission("recorded tool outcome disappeared".to_owned())
            })?;
        if !stored_outcome.same_immutable_outcome(&tool_return.outcome) {
            return Err(KernelError::DurableAdmission(
                "recorded tool outcome conflicts with the recovery input".to_owned(),
            ));
        }
        stored_outcome
            .validate_canonical_blob(&admission.operation, &raw_blob)
            .map_err(tool_outcome_error)?;
        let existing_evaluation = runtime
            .outcome_store
            .lookup_post_return_evaluation(admission.operation.binding().operation_id())
            .map_err(durable_outcome_store_error)?;
        let mutation_guard = runtime.lock_mutations()?;
        let trusted_now_unix_ms = current_unix_timestamp_ms()
            .max(stored_outcome.recorded_at_unix_ms())
            .max(
                existing_evaluation
                    .as_ref()
                    .map_or(0, PostReturnEvaluationRecordV1::trusted_time_unix_ms),
            )
            .max(1);
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms);
        let lease = self.claim_admission_recovery(&admission.operation, trusted_now_unix_ms)?;
        let mut evaluation = match existing_evaluation {
            Some(existing) => existing,
            None => {
                if !matches!(
                    stored_outcome.disposition(),
                    ResolvedToolOutcomeV1::Returned
                ) {
                    return Err(KernelError::DurableAdmission(
                        "terminal tool outcome has no retained evaluation".to_owned(),
                    ));
                }
                let prepared = PostReturnEvaluationRecordV1::prepare(
                    &admission.operation,
                    &stored_outcome,
                    plan.frozen_steps.clone(),
                    trusted_now_unix_ms,
                    normalized_context.clone(),
                )
                .map_err(tool_outcome_error)?;
                runtime
                    .outcome_store
                    .begin_post_return_evaluation(
                        &lease,
                        &prepared,
                        &runtime.fence,
                        trusted_now_unix_ms,
                    )
                    .map_err(durable_outcome_store_error)?
            }
        };
        evaluation
            .validate_against(&admission.operation, &stored_outcome)
            .and_then(|_| {
                evaluation.validate_replay_contract(&plan.frozen_steps, &normalized_context)
            })
            .map_err(tool_outcome_error)?;
        if delivery_evaluation.denial.is_none() {
            if let Err(denial) = self.revalidate_completed_purchase_status(
                purchase.as_ref(),
                current_unix_timestamp_ms() / 1_000,
            ) {
                warn!(request_id = %request.request_id, reason = %redacted!(&denial), "finding purchase final terminal output withheld");
                #[cfg(feature = "finding-market")]
                {
                    terminal_finding_denial = Some(denial);
                }
                delivery_evaluation.denial =
                    Some(delivery_contract::finding_status_delivery_denial());
            }
        }
        if delivery_evaluation.denial.is_none() {
            if let Err(denial) = self.revalidate_completed_recovery_status(
                matched_grant_index,
                request,
                recovery.as_ref(),
                recovery_status.as_ref(),
                current_unix_timestamp_ms() / 1_000,
            ) {
                warn!(request_id = %request.request_id, reason = %redacted!(&denial), "finding recovery final terminal output withheld");
                terminal_finding_denial = Some(denial);
                delivery_evaluation.denial =
                    Some(delivery_contract::finding_status_delivery_denial());
            }
        }
        let delivery_denied = delivery_evaluation.denial.is_some();
        let projected_terminal_state = if delivery_denied {
            AdmissionOperationState::DeniedAfterDelivery
        } else {
            AdmissionOperationState::Completed
        };
        let receipt_visible_content = receipt_visible_delivery_content(
            &receipt_content,
            delivery_evaluation.digest_mismatched,
            expected_output_digest.as_deref(),
        );
        let receipt_visible_digest = AdmissionDigest::try_new(
            "receipt_visible_output_digest",
            receipt_visible_content.content_hash.clone(),
        )?;
        let terminal_decision = match &delivery_evaluation.denial {
            Some(denial) => Decision::Deny {
                reason: denial.message.to_owned(),
                guard: denial.guard.to_owned(),
            },
            None => incomplete_reason
                .as_ref()
                .map_or(Decision::Allow, |reason| Decision::Incomplete {
                    reason: reason.clone(),
                }),
        };
        let post_guard_decision_digest = admission_digest(
            "post_guard_decision_digest",
            &KernelOutputGuardDecision {
                schema: "chio.kernel-output-guard-decision.post-return.v1",
                resolved_output_digest: resolved_output_digest.as_str(),
                decision: &terminal_decision,
            },
        )?;
        let payment_plan = self.durable_payment_disposition(
            admission,
            runtime,
            &tool_return.raw,
            trusted_now_unix_ms,
            delivery_denied,
        )?;
        let settlement_disposition = payment_plan.as_ref().map_or(
            SettlementDispositionV1::NotApplicable,
            |(_, disposition)| disposition.clone(),
        );
        if let Some(binding) = purchase.as_ref() {
            self.require_finding_pool_delivery_terminal(binding, &settlement_disposition)?;
        }
        let pricing_verdict_digest = admission_digest(
            "pricing_verdict_digest",
            &KernelPricingVerdict {
                schema: "chio.kernel-pricing-verdict.v1",
                disposition: &settlement_disposition,
            },
        )?;
        let (_terminal_evaluation, terminal_outcome) = match evaluation.state() {
            PostReturnEvaluationStateV1::Evaluating => {
                for (index, expected_digest) in step_result_digests.iter().enumerate() {
                    match evaluation.step_result_digest(index) {
                        Some(recorded) if recorded != expected_digest => {
                            return Err(KernelError::DurableAdmission(
                                "retained post-invocation result conflicts with replay".to_owned(),
                            ));
                        }
                        Some(_) => {}
                        None => {
                            let next = evaluation
                                .record_next_pure_result(expected_digest.clone())
                                .map_err(tool_outcome_error)?;
                            evaluation = runtime
                                .outcome_store
                                .stage_post_return_evaluation(
                                    admission.operation.binding().operation_id(),
                                    evaluation.version(),
                                    &lease,
                                    &next,
                                    &runtime.fence,
                                    trusted_now_unix_ms,
                                )
                                .map_err(durable_outcome_store_error)?;
                        }
                    }
                }
                if evaluation
                    .step_result_digest(step_result_digests.len())
                    .is_some()
                {
                    return Err(KernelError::DurableAdmission(
                        "retained post-invocation result count conflicts with replay".to_owned(),
                    ));
                }
                if !matches!(
                    stored_outcome.disposition(),
                    ResolvedToolOutcomeV1::Returned
                ) {
                    return Err(KernelError::DurableAdmission(
                        "resolved tool outcome retains an incomplete evaluation".to_owned(),
                    ));
                }
                let (terminal_evaluation, resolved_output) = evaluation
                    .resolve_with_signing_preimage(
                        receipt_content.canonical_content.clone(),
                        post_guard_decision_digest.clone(),
                        pricing_verdict_digest.clone(),
                        settlement_disposition.clone(),
                    )
                    .map_err(tool_outcome_error)?;
                let terminal_outcome = stored_outcome
                    .transition(
                        stored_outcome.version(),
                        ToolOutcomeTransitionV1::Resolve(
                            terminal_evaluation
                                .terminal_evidence()
                                .map_err(tool_outcome_error)?,
                        ),
                    )
                    .map_err(tool_outcome_error)?;
                let (terminal_evaluation, terminal_outcome) = runtime
                    .outcome_store
                    .finalize_post_return(
                        admission.operation.binding().operation_id(),
                        evaluation.version(),
                        &lease,
                        &terminal_evaluation,
                        stored_outcome.version(),
                        &terminal_outcome,
                        Some(&resolved_output),
                        &runtime.fence,
                        trusted_now_unix_ms,
                    )
                    .map_err(durable_outcome_store_error)?;
                (terminal_evaluation, terminal_outcome)
            }
            PostReturnEvaluationStateV1::Resolved { .. } => {
                let ResolvedToolOutcomeV1::Resolved {
                    resolved_output: expected_output,
                    resolved_output_size_bytes,
                    post_guard_decision_digest: recorded_guard,
                    pricing_verdict_digest: recorded_pricing,
                    settlement_disposition: recorded_settlement,
                    ..
                } = stored_outcome.disposition()
                else {
                    return Err(KernelError::DurableAdmission(
                        "resolved evaluation has no resolved tool outcome".to_owned(),
                    ));
                };
                let resolved_output = runtime
                    .outcome_store
                    .load_resolved_output_by_operation(admission.operation.binding().operation_id())
                    .map_err(durable_outcome_store_error)?
                    .ok_or_else(|| {
                        KernelError::DurableAdmission(
                            "resolved output preimage disappeared".to_owned(),
                        )
                    })?;
                if step_result_digests
                    .iter()
                    .enumerate()
                    .any(|(index, expected)| evaluation.step_result_digest(index) != Some(expected))
                    || evaluation
                        .step_result_digest(step_result_digests.len())
                        .is_some()
                    || resolved_output.blob_ref() != expected_output
                    || u64::try_from(resolved_output.bytes().len()).ok()
                        != Some(*resolved_output_size_bytes)
                    || resolved_output.bytes() != receipt_content.canonical_content.as_slice()
                    || recorded_guard != &post_guard_decision_digest
                    || recorded_pricing != &pricing_verdict_digest
                    || recorded_settlement != &settlement_disposition
                {
                    return Err(KernelError::DurableAdmission(
                        "resolved finalization artifacts conflict with replay".to_owned(),
                    ));
                }
                (evaluation, stored_outcome)
            }
            PostReturnEvaluationStateV1::Frozen { .. } => {
                return Err(KernelError::DurableAdmission(
                    "post-return evaluation is frozen".to_owned(),
                ));
            }
        };
        let context = AdmissionProjectionContext {
            operation_id: admission.operation.binding().operation_id().clone(),
            request_id: admission.operation.binding().request_id().clone(),
            expected_operation_version: admission.operation.version(),
            trusted_time_unix_ms: trusted_now_unix_ms,
            coordinator_lease_id: lease.coordinator_lease_id().clone(),
            coordinator_lease_epoch: lease.coordinator_lease_epoch(),
            store_fence: runtime.fence.clone(),
        };
        let payment_terminal = payment_plan
            .map(|(journal, _)| {
                self.settle_durable_payment(DurablePaymentSettlementInput {
                    admission,
                    runtime,
                    lease: &lease,
                    journal,
                    disposition: &settlement_disposition,
                    context: &context,
                    purchase: purchase.as_ref(),
                    trusted_now_unix_ms,
                })
            })
            .transpose()?;
        if let Some(binding) = purchase.as_ref() {
            self.settle_finding_pool_delivery_terminal(
                admission.operation.binding().operation_id().as_str(),
                binding,
                &settlement_disposition,
            )?;
        }
        let tool_outcome = runtime
            .verify_terminal_outcome(&admission.operation, &context)
            .map_err(tool_outcome_error)?;
        let projected_operation_version =
            admission
                .operation
                .version()
                .checked_add(1)
                .ok_or_else(|| {
                    KernelError::DurableAdmission("operation version overflowed".to_owned())
                })?;
        let admission_metadata = AdmissionReceiptMetadataV1 {
            schema: AdmissionReceiptSchema::V1,
            operation_id: context.operation_id.clone(),
            request_id: context.request_id.clone(),
            request_namespace_digest: admission
                .operation
                .binding()
                .request_namespace_digest()
                .clone(),
            request_binding_hash: admission.operation.binding().request_binding_hash().clone(),
            projected_operation_version,
            // A delivery denial terminates as DeniedAfterDelivery, which,
            // like the other non-Completed terminals, attaches no public
            // completed-tool-outcome reference. The actual output remains in
            // the durable outcome store. On a digest mismatch, the receipt
            // exposes only a domain-separated redaction commitment.
            projected_state: projected_terminal_state,
            projected_dispatch_state: AdmissionDispatchState::Terminal,
            trusted_time_unix_ms: trusted_now_unix_ms,
            coordinator_lease_id: context.coordinator_lease_id.clone(),
            coordinator_lease_epoch: context.coordinator_lease_epoch,
            store_fence: context.store_fence.clone(),
            retained_dispatch_commit: admission.operation.dispatch_commit().cloned(),
            compensation_status: AdmissionCompensationStatus::NotCompensated,
            tool_outcome_id: if delivery_denied {
                None
            } else {
                Some(terminal_outcome.outcome_id().clone())
            },
            tool_outcome_version: if delivery_denied {
                None
            } else {
                Some(terminal_outcome.version())
            },
        };
        let memory_action_kind = crate::memory_provenance::classify_memory_action(
            &request.tool_name,
            &request.arguments,
        );
        let timestamp = trusted_now_unix_ms / 1_000;
        let financial_metadata = payment_terminal.as_ref().map(|payment| {
            let budget_total = request
                .capability
                .scope
                .grants
                .get(matched_grant_index)
                .and_then(|grant| grant.max_total_cost.as_ref())
                .map_or(payment.journal.amount_units, |amount| amount.units);
            let payment_reference = payment
                .journal
                .transaction_id
                .clone()
                .or_else(|| payment.journal.authorization_id.clone());
            serde_json::json!({
                "financial": FinancialReceiptMetadata {
                    grant_index: payment.journal.grant_index,
                    cost_charged: payment.amount_units,
                    currency: payment.journal.currency.clone(),
                    budget_remaining: budget_total
                        .saturating_sub(payment.reconcile.committed_cost_units_after),
                    budget_total,
                    delegation_depth: request.capability.delegation_chain.len() as u32,
                    root_budget_holder: request.capability.issuer.to_hex(),
                    payment_reference,
                    settlement_status: SettlementStatus::Settled,
                    cost_breakdown: Some(serde_json::json!({
                        "payment": {
                            "rail": payment.journal.rail,
                            "rail_mode": payment.journal.rail_mode,
                            "authorization_id": payment.journal.authorization_id,
                            "transaction_id": payment.journal.transaction_id,
                            "preauthorized_units": payment.journal.amount_units,
                            "recorded_units": payment.amount_units
                        }
                    })),
                    oracle_evidence: None,
                    attempted_cost: None,
                }
            })
        });
        let metadata = merge_metadata_objects(
            merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(
                        receipt_visible_content.metadata.clone(),
                        tool_return.raw.receipt_metadata_snapshot().cloned(),
                    ),
                    post_invocation_metadata,
                ),
                financial_metadata,
            ),
            Some(serde_json::json!({
                ADMISSION_RECEIPT_METADATA_KEY: admission_metadata
            })),
        );
        let metadata = record_terminal_finding_denial(metadata, terminal_finding_denial.as_ref());
        // The delivery-contract block is the kernel's own verdict, so it is
        // merged last and a pre-existing key from caller or hook metadata is
        // a hard error: the shallow last-write-wins merge would otherwise
        // let it forge or shadow the kernel's block.
        let metadata = if let Some(expected) = expected_output_digest.as_deref() {
            if metadata
                .as_ref()
                .and_then(|value| {
                    value.get(chio_core::receipt::metadata::DELIVERY_CONTRACT_METADATA_KEY)
                })
                .is_some()
            {
                return Err(KernelError::DurableAdmission(
                    "receipt metadata already carries a delivery_contract block".to_owned(),
                ));
            }
            let block = chio_core::receipt::metadata::DeliveryContract {
                schema: chio_core::receipt::metadata::DELIVERY_CONTRACT_SCHEMA.to_owned(),
                expected_digest: expected.to_owned(),
                observed_digest: receipt_visible_content.content_hash.clone(),
                result: if delivery_evaluation.digest_mismatched {
                    chio_core::receipt::metadata::DeliveryResult::Mismatched
                } else {
                    chio_core::receipt::metadata::DeliveryResult::Matched
                },
            };
            block.validate().map_err(|error| {
                KernelError::DurableAdmission(format!(
                    "delivery contract metadata is invalid: {error}"
                ))
            })?;
            merge_metadata_objects(
                metadata,
                Some(
                    serde_json::json!({ chio_core::receipt::metadata::DELIVERY_CONTRACT_METADATA_KEY: block }),
                ),
            )
        } else {
            metadata
        };
        // The finding overlay is likewise kernel-owned and forge-checked;
        // it is present exactly when the grant carried the verified
        // purchase marker.
        let metadata = if let Some(binding) = purchase.as_ref() {
            if metadata
                .as_ref()
                .and_then(|value| {
                    value.get(chio_core::receipt::metadata::FINDING_DELIVERY_METADATA_KEY)
                })
                .is_some()
            {
                return Err(KernelError::DurableAdmission(
                    "receipt metadata already carries a finding_delivery block".to_owned(),
                ));
            }
            let block = delivery_contract::finding_delivery_block(binding, &delivery_evaluation);
            merge_metadata_objects(
                metadata,
                Some(
                    serde_json::json!({ chio_core::receipt::metadata::FINDING_DELIVERY_METADATA_KEY: block }),
                ),
            )
        } else {
            metadata
        };
        let metadata = if let Some(binding) = recovery.as_ref() {
            if metadata
                .as_ref()
                .and_then(|value| {
                    value.get(chio_core::receipt::metadata::FINDING_RECOVERY_METADATA_KEY)
                })
                .is_some()
            {
                return Err(KernelError::DurableAdmission(
                    "receipt metadata already carries a finding_recovery block".to_owned(),
                ));
            }
            let block = delivery_contract::finding_recovery_block(binding);
            merge_metadata_objects(
                metadata,
                Some(serde_json::json!({
                    chio_core::receipt::metadata::FINDING_RECOVERY_METADATA_KEY: block
                })),
            )
        } else {
            metadata
        };
        let action =
            ToolCallAction::from_parameters(request.arguments.clone()).map_err(|error| {
                KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {error}"))
            })?;
        let persisted_binding = admission.operation.binding().to_persisted();
        let authenticated_tenant_id = persisted_binding.authenticated_tenant_id.as_str();
        let receipt_tenant_id = (authenticated_tenant_id != LOCAL_SYSTEM_TENANT_ID)
            .then(|| authenticated_tenant_id.to_owned());
        let receipt = self.build_and_sign_receipt(ReceiptParams {
            request_id: Some(&request.request_id),
            capability_id: &request.capability.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: terminal_decision.clone(),
            action,
            content_hash: receipt_visible_content.content_hash,
            canonical_content: receipt_visible_content.canonical_content,
            metadata,
            timestamp,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: receipt_tenant_id,
        })?;
        let receipt = if delivery_denied {
            VerifiedAdmissionReceipt::from_kernel_verified_denied_after_delivery(
                receipt,
                &self.config.keypair.public_key(),
                &terminal_decision,
                &request.server_id,
                &request.tool_name,
                &receipt_visible_digest,
                &admission.operation,
                &context,
            )
        } else {
            VerifiedAdmissionReceipt::from_kernel_verified_terminal(
                receipt,
                &self.config.keypair.public_key(),
                &terminal_decision,
                &admission.operation,
                &context,
                &tool_outcome,
            )
        }
        .map_err(|error| {
            KernelError::DurableAdmission(format!("terminal receipt qualification failed: {error}"))
        })?;
        let payment_evidence = payment_terminal
            .as_ref()
            .map(|payment| {
                PaymentTerminalEvidence::from_source_verified(
                    &admission.operation,
                    &context,
                    &receipt,
                    AdmissionIdentifier::try_new(
                        "payment_participant_id",
                        admission.operation_id().to_owned(),
                    )?,
                    admission_digest("payment_source_authority_digest", &runtime.fence)?,
                    AdmissionIdentifier::try_new(
                        "payment_source_record_id",
                        format!("payment:{}", admission.operation_id()),
                    )?,
                    admission_digest("payment_source_record_digest", &payment.journal)?,
                    trusted_now_unix_ms,
                    terminal_outcome.outcome_id().clone(),
                    terminal_outcome.version(),
                    projected_terminal_state,
                )
                .map_err(KernelError::from)
            })
            .transpose()?;
        let observer_work = if admission
            .operation
            .binding()
            .participant_requirements()
            .observation_attempt_zero
        {
            Some(ObservationAttemptZero::from_verified(
                &admission.operation,
                &context,
                &receipt,
                terminal_outcome.outcome_id().clone(),
                terminal_outcome.version(),
                projected_terminal_state,
            )?)
        } else {
            None
        };
        let channel_prepared = if admission
            .operation
            .binding()
            .participant_requirements()
            .channel
        {
            Some(
                crate::admission_operation::prepare_channel_terminal_projection(
                    runtime.channel_terminal_authority.as_deref(),
                    &admission.operation,
                    &context,
                    &receipt,
                    &tool_outcome,
                    &self.config.keypair,
                )
                .map_err(|error| KernelError::DurableAdmission(error.to_string()))?,
            )
        } else {
            None
        };
        let projected_receipt = receipt.receipt().clone();
        let (terminal, expected_terminal_state) = if let Some(denial) =
            delivery_evaluation.denial.as_ref()
        {
            // A delivery denial terminates as a persisted signed Deny
            // whose hold was released and whose capture is zero. The
            // payment evidence binds the released journal and the
            // observation attempt binds the release settlement, so the
            // terminal carries the same participant proof a completed
            // capture carries. Channel terminals do not apply: the
            // pre-dispatch gate admits only a reversible-hold tool
            // dispatch for a digest-constrained request.
            let projection =
                crate::admission_operation::AdmissionTerminalProjection::DeniedAfterDelivery {
                    context,
                    reason: denial.reason,
                    evidence: Box::new(
                        crate::admission_operation::AdmissionReceiptOrIncident::Receipt(Box::new(
                            receipt,
                        )),
                    ),
                    payment_evidence: payment_evidence.map(Box::new),
                    observer_work: observer_work.map(Box::new),
                };
            let terminal = runtime
                .store
                .commit_admission_projection(&projection)
                .map_err(|error| {
                    KernelError::DurableAdmission(format!(
                        "atomic terminal projection failed: {error}"
                    ))
                })?;
            (terminal, AdmissionOperationState::DeniedAfterDelivery)
        } else {
            let projection =
                AdmissionTerminalProjection::Completed(Box::new(AdmissionCompletedProjection {
                    context,
                    receipt,
                    tool_outcome: Some(tool_outcome),
                    payment_evidence,
                    authorization: None,
                    eligibility: None,
                    observer_work,
                    obligation: channel_prepared
                        .as_ref()
                        .and_then(|prepared| prepared.obligation().cloned()),
                    channel_terminal: channel_prepared
                        .as_ref()
                        .map(|prepared| prepared.channel().clone()),
                }));
            let terminal = if let Some(prepared) = channel_prepared.as_ref() {
                let authority = runtime
                    .channel_terminal_authority
                    .as_deref()
                    .ok_or_else(|| {
                        KernelError::DurableAdmission(
                            "qualified channel terminal authority disappeared".to_owned(),
                        )
                    })?;
                crate::admission_operation::commit_prepared_channel_terminal_projection(
                    authority,
                    &admission.operation,
                    &lease,
                    &projection,
                    &runtime.store.admission_projection_capabilities(),
                    prepared,
                    &self.config.keypair,
                    &runtime.fence,
                    trusted_now_unix_ms,
                )
                .map_err(|error| KernelError::DurableAdmission(error.to_string()))?
            } else {
                runtime
                    .store
                    .commit_admission_projection(&projection)
                    .map_err(|error| {
                        KernelError::DurableAdmission(format!(
                            "atomic terminal projection failed: {error}"
                        ))
                    })?
            };
            (terminal, AdmissionOperationState::Completed)
        };
        if terminal.state != expected_terminal_state {
            return Err(KernelError::DurableAdmission(
                "terminal projection did not reach the expected terminal state".to_owned(),
            ));
        }
        admission.operation = runtime
            .store
            .load_by_operation_id(admission.operation.binding().operation_id())
            .map_err(durable_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "completed admission operation disappeared".to_owned(),
                )
            })?;
        drop(mutation_guard);
        self.materialize_durable_admission_receipt(&projected_receipt)?;
        self.mirror_durable_admission_receipt(&projected_receipt)?;
        if let Some(binding) = recovery.as_ref() {
            let verifier = self.finding_recovery_verifier.as_ref().ok_or_else(|| {
                KernelError::DurableAdmission(
                    "finding recovery verifier disappeared during terminalization".to_owned(),
                )
            })?;
            verifier
                .record_recovery_receipt(
                    binding,
                    &projected_receipt.id,
                    projected_receipt.timestamp,
                )
                .map_err(|error| {
                    KernelError::DurableAdmission(format!(
                        "finding recovery lineage could not be recorded: {error}"
                    ))
                })?;
        }
        self.apply_federation_cosign_for_admitted_request(request, &projected_receipt)?;
        if let Some(crate::memory_provenance::MemoryActionKind::Write { store, key }) =
            memory_action_kind.as_ref()
        {
            self.append_memory_provenance_for_write(store, key, request, &projected_receipt)?;
        }
        let (verdict, reason, terminal_state, execution_nonce) =
            if let Some(denial) = delivery_evaluation.denial.as_ref() {
                (
                    Verdict::Deny,
                    Some(denial.message.to_owned()),
                    OperationTerminalState::Completed,
                    None,
                )
            } else {
                match incomplete_reason {
                    Some(reason) => (
                        Verdict::Deny,
                        Some(reason.clone()),
                        OperationTerminalState::Incomplete { reason },
                        None,
                    ),
                    None => (
                        Verdict::Allow,
                        None,
                        OperationTerminalState::Completed,
                        self.mint_execution_nonce_for_allow(
                            request,
                            &request.capability,
                            &projected_receipt,
                        )?,
                    ),
                }
            };
        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict,
            // A denied delivery returns no payload. An actual digest mismatch
            // exposes only the deterministic redaction binding; another
            // delivery denial may retain the already-committed matched digest.
            output: delivery_evaluation.denial.is_none().then_some(output),
            reason,
            terminal_state,
            receipt: projected_receipt,
            execution_nonce,
        })
    }
}

#[cfg(test)]
#[path = "terminal_tests.rs"]
mod tests;
