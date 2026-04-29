use std::sync::atomic::Ordering;

use super::*;

pub(crate) struct FinalizeToolOutputCostContext<'a> {
    pub(crate) charge_result: Option<BudgetChargeResult>,
    pub(crate) reported_cost: Option<ToolInvocationCost>,
    pub(crate) payment_authorization: Option<PaymentAuthorization>,
    pub(crate) cap: &'a CapabilityToken,
}

struct PostInvocationHandling {
    output: ToolServerOutput,
    extra_metadata: Option<serde_json::Value>,
    blocked_reason: Option<String>,
    evidence: Vec<chio_core::receipt::GuardEvidence>,
}

impl ChioKernel {
    /// denial reason is monetary budget exhaustion.
    pub(crate) fn build_monetary_deny_response(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matching_grants: &[MatchingGrant<'_>],
        cap: &CapabilityToken,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_monetary_deny_response_with_metadata(
            request,
            reason,
            timestamp,
            matching_grants,
            cap,
            None,
        )
    }

    pub(crate) fn build_monetary_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matching_grants: &[MatchingGrant<'_>],
        cap: &CapabilityToken,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        // Look for a monetary grant among the matching candidates to populate metadata.
        let monetary_grant = matching_grants.iter().find(|m| {
            m.grant.max_cost_per_invocation.is_some() || m.grant.max_total_cost.is_some()
        });

        if let Some(mg) = monetary_grant {
            let grant = mg.grant;
            let currency = grant
                .max_cost_per_invocation
                .as_ref()
                .map(|m| m.currency.clone())
                .or_else(|| grant.max_total_cost.as_ref().map(|m| m.currency.clone()))
                .unwrap_or_else(|| "USD".to_string());
            let budget_total = grant
                .max_total_cost
                .as_ref()
                .map(|m| m.units)
                .unwrap_or(u64::MAX);
            let attempted_cost = grant
                .max_cost_per_invocation
                .as_ref()
                .map(|m| m.units)
                .unwrap_or(0);
            let delegation_depth = cap.delegation_chain.len() as u32;
            let root_budget_holder = cap.issuer.to_hex();
            let (payment_reference, settlement_status) =
                ReceiptSettlement::not_applicable().into_receipt_parts();

            let financial_meta = FinancialReceiptMetadata {
                grant_index: mg.index as u32,
                cost_charged: 0,
                currency,
                budget_remaining: 0,
                budget_total,
                delegation_depth,
                root_budget_holder,
                payment_reference,
                settlement_status,
                cost_breakdown: None,
                oracle_evidence: None,
                attempted_cost: Some(attempted_cost),
            };
            let financial_metadata = Some(serde_json::json!({ "financial": financial_meta }));
            let deny_extra_metadata =
                merge_metadata_objects(financial_metadata.clone(), extra_metadata.clone());
            let request_metadata = request_receipt_metadata(
                request,
                self.attestation_trust_policy.as_ref(),
                timestamp,
                deny_extra_metadata.as_ref(),
            )?;

            let metadata = merge_metadata_objects(
                merge_metadata_objects(
                    receipt_attribution_metadata(cap, Some(mg.index)),
                    deny_extra_metadata,
                ),
                request_metadata,
            );
            let receipt_content = receipt_content_for_output(None, None)?;

            let action =
                ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
                    KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
                })?;

            let receipt = self.build_and_sign_receipt(ReceiptParams {
                capability_id: &cap.id,
                tool_name: &request.tool_name,
                server_id: &request.server_id,
                decision: Decision::Deny {
                    reason: reason.to_string(),
                    guard: "kernel".to_string(),
                },
                action,
                content_hash: receipt_content.content_hash,
                metadata,
                timestamp,
                trust_level: chio_core::TrustLevel::default(),
                tenant_id: None,
            })?;

            self.record_chio_receipt_with_federation(request, &receipt)?;

            return Ok(ToolCallResponse {
                request_id: request.request_id.clone(),
                verdict: Verdict::Deny,
                output: None,
                reason: Some(reason.to_string()),
                terminal_state: OperationTerminalState::Completed,
                receipt,
                execution_nonce: None,
            });
        }

        // No monetary grant -- standard deny.
        self.build_deny_response_with_metadata(request, reason, timestamp, None, extra_metadata)
    }

    pub(crate) fn build_pre_execution_monetary_deny_response(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        charge: &BudgetChargeResult,
        committed_cost_after_release: u64,
        cap: &CapabilityToken,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_pre_execution_monetary_deny_response_with_metadata(
            request,
            reason,
            timestamp,
            charge,
            committed_cost_after_release,
            cap,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_pre_execution_monetary_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        charge: &BudgetChargeResult,
        committed_cost_after_release: u64,
        cap: &CapabilityToken,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let delegation_depth = cap.delegation_chain.len() as u32;
        let root_budget_holder = cap.issuer.to_hex();
        let (payment_reference, settlement_status) =
            ReceiptSettlement::not_applicable().into_receipt_parts();
        let budget_remaining = charge
            .budget_total
            .saturating_sub(committed_cost_after_release);

        let financial_meta = FinancialReceiptMetadata {
            grant_index: charge.grant_index as u32,
            cost_charged: 0,
            currency: charge.currency.clone(),
            budget_remaining,
            budget_total: charge.budget_total,
            delegation_depth,
            root_budget_holder,
            payment_reference,
            settlement_status,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: Some(charge.cost_charged),
        };
        let financial_metadata = Some(serde_json::json!({ "financial": financial_meta }));
        let deny_extra_metadata =
            merge_metadata_objects(financial_metadata.clone(), extra_metadata.clone());
        let request_metadata = request_receipt_metadata(
            request,
            self.attestation_trust_policy.as_ref(),
            timestamp,
            deny_extra_metadata.as_ref(),
        )?;

        let receipt_content = receipt_content_for_output(None, None)?;
        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Deny {
                reason: reason.to_string(),
                guard: "kernel".to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    receipt_attribution_metadata(cap, Some(charge.grant_index)),
                    deny_extra_metadata,
                ),
                request_metadata,
            ),
            timestamp,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
        })?;

        self.record_chio_receipt_with_federation(request, &receipt)?;

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Deny,
            output: None,
            reason: Some(reason.to_string()),
            terminal_state: OperationTerminalState::Completed,
            receipt,
            execution_nonce: None,
        })
    }

    pub(crate) fn finalize_tool_output(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        matched_grant_index: usize,
    ) -> Result<ToolCallResponse, KernelError> {
        self.finalize_tool_output_with_metadata(
            request,
            output,
            elapsed,
            timestamp,
            matched_grant_index,
            None,
        )
    }

    pub(crate) fn finalize_tool_output_with_metadata(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        matched_grant_index: usize,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let output = self.apply_stream_limits(output, elapsed)?;
        let post_invocation = self.apply_post_invocation_pipeline(
            request,
            output,
            Some(matched_grant_index),
            extra_metadata,
        )?;
        let _post_invocation_evidence_scope =
            scope_post_invocation_guard_evidence(post_invocation.evidence);
        if let Some(reason) = post_invocation.blocked_reason.as_deref() {
            return self.build_deny_response_with_metadata(
                request,
                reason,
                timestamp,
                Some(matched_grant_index),
                post_invocation.extra_metadata,
            );
        }

        match post_invocation.output {
            ToolServerOutput::Value(value) => self.build_allow_response_with_metadata(
                request,
                ToolCallOutput::Value(value),
                timestamp,
                Some(matched_grant_index),
                post_invocation.extra_metadata,
            ),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream)) => self
                .build_allow_response_with_metadata(
                    request,
                    ToolCallOutput::Stream(stream),
                    timestamp,
                    Some(matched_grant_index),
                    post_invocation.extra_metadata,
                ),
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, reason }) => self
                .build_incomplete_response_with_output_and_metadata(
                    request,
                    Some(ToolCallOutput::Stream(stream)),
                    &reason,
                    timestamp,
                    Some(matched_grant_index),
                    post_invocation.extra_metadata,
                ),
        }
    }

    /// Finalize a tool output with optional monetary metadata injected into the receipt.
    pub(crate) fn finalize_tool_output_with_cost(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        matched_grant_index: usize,
        cost_context: FinalizeToolOutputCostContext<'_>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.finalize_tool_output_with_cost_and_metadata(
            request,
            output,
            elapsed,
            timestamp,
            matched_grant_index,
            cost_context,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finalize_tool_output_with_cost_and_metadata(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        matched_grant_index: usize,
        cost_context: FinalizeToolOutputCostContext<'_>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let FinalizeToolOutputCostContext {
            charge_result,
            reported_cost,
            payment_authorization,
            cap,
        } = cost_context;
        let Some(charge) = charge_result else {
            // Non-monetary grant: use normal path.
            return self.finalize_tool_output_with_metadata(
                request,
                output,
                elapsed,
                timestamp,
                matched_grant_index,
                extra_metadata,
            );
        };

        let reported_cost_ref = reported_cost.as_ref();
        let mut oracle_evidence = None;
        let mut cross_currency_note = None;
        let (actual_cost, cross_currency_failed) =
            if let Some(cost) = reported_cost_ref.filter(|cost| cost.currency != charge.currency) {
                match self.resolve_cross_currency_cost(cost, &charge.currency, timestamp) {
                    Ok((converted_units, evidence)) => {
                        oracle_evidence = Some(evidence);
                        cross_currency_note = Some(serde_json::json!({
                            "oracle_conversion": {
                                "status": "applied",
                                "reported_currency": cost.currency,
                                "grant_currency": charge.currency,
                                "reported_units": cost.units,
                                "converted_units": converted_units
                            }
                        }));
                        (converted_units, false)
                    }
                    Err(error) => {
                        warn!(
                            request_id = %request.request_id,
                            reported_currency = %cost.currency,
                            charged_currency = %charge.currency,
                            reason = %error,
                            "cross-currency reconciliation failed; keeping provisional charge"
                        );
                        cross_currency_note = Some(serde_json::json!({
                            "oracle_conversion": {
                                "status": "failed",
                                "reported_currency": cost.currency,
                                "grant_currency": charge.currency,
                                "reported_units": cost.units,
                                "provisional_units": charge.cost_charged,
                                "reason": error.to_string()
                            }
                        }));
                        (charge.cost_charged, true)
                    }
                }
            } else {
                (
                    reported_cost_ref
                        .map(|cost| cost.units)
                        .unwrap_or(charge.cost_charged),
                    false,
                )
            };
        let keep_provisional_charge = cross_currency_failed
            || matches!(payment_authorization.as_ref(), Some(authorization) if authorization.settled);
        let cost_overrun =
            !cross_currency_failed && actual_cost > charge.cost_charged && charge.cost_charged > 0;

        if cost_overrun {
            warn!(
                request_id = %request.request_id,
                reported = actual_cost,
                charged = charge.cost_charged,
                "tool server reported cost exceeds max_cost_per_invocation; settlement_status=failed"
            );
        }

        let running_committed_cost_units = if keep_provisional_charge || cost_overrun {
            charge.new_committed_cost_units
        } else {
            self.reduce_budget_charge_to_actual(&cap.id, &charge, actual_cost)?
        };

        let payment_result = if let Some(authorization) = payment_authorization.as_ref() {
            if authorization.settled || cross_currency_failed || cost_overrun {
                None
            } else {
                let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                    KernelError::Internal(
                        "payment authorization present without configured adapter".to_string(),
                    )
                })?;
                Some(if actual_cost == 0 {
                    adapter.release(&authorization.authorization_id, &request.request_id)
                } else {
                    adapter.capture(
                        &authorization.authorization_id,
                        actual_cost,
                        &charge.currency,
                        &request.request_id,
                    )
                })
            }
        } else {
            None
        };

        let settlement = if cross_currency_failed || cost_overrun {
            ReceiptSettlement {
                payment_reference: payment_authorization
                    .as_ref()
                    .map(|authorization| authorization.authorization_id.clone()),
                settlement_status: SettlementStatus::Failed,
            }
        } else if let Some(authorization) = payment_authorization.as_ref() {
            if authorization.settled {
                ReceiptSettlement::from_authorization(authorization)
            } else if let Some(payment_result) = payment_result.as_ref() {
                match payment_result {
                    Ok(result) => ReceiptSettlement::from_payment_result(result),
                    Err(error) => {
                        warn!(
                            request_id = %request.request_id,
                            reason = %error,
                            "post-execution payment settlement failed"
                        );
                        ReceiptSettlement {
                            payment_reference: Some(authorization.authorization_id.clone()),
                            settlement_status: SettlementStatus::Failed,
                        }
                    }
                }
            } else {
                warn!(
                    request_id = %request.request_id,
                    authorization_id = %authorization.authorization_id,
                    "unsettled authorization completed without a payment result"
                );
                ReceiptSettlement {
                    payment_reference: Some(authorization.authorization_id.clone()),
                    settlement_status: SettlementStatus::Failed,
                }
            }
        } else {
            ReceiptSettlement::settled()
        };
        let recorded_cost = if keep_provisional_charge && !cross_currency_failed && !cost_overrun {
            charge.cost_charged
        } else {
            actual_cost
        };

        // Use the running total charged so far (not just this invocation) so that
        // budget_remaining reflects cumulative spend across all prior invocations.
        let budget_remaining = charge
            .budget_total
            .saturating_sub(running_committed_cost_units);
        let delegation_depth = cap.delegation_chain.len() as u32;
        let root_budget_holder = cap.issuer.to_hex();
        let (payment_reference, settlement_status) = settlement.into_receipt_parts();
        let payment_breakdown = payment_authorization.as_ref().map(|authorization| {
            serde_json::json!({
                "payment": {
                    "authorization_id": authorization.authorization_id,
                    "adapter_metadata": authorization.metadata,
                    "preauthorized_units": charge.cost_charged,
                    "recorded_units": recorded_cost
                }
            })
        });

        let financial_meta = FinancialReceiptMetadata {
            grant_index: charge.grant_index as u32,
            cost_charged: recorded_cost,
            currency: charge.currency.clone(),
            budget_remaining,
            budget_total: charge.budget_total,
            delegation_depth,
            root_budget_holder,
            payment_reference,
            settlement_status,
            cost_breakdown: merge_metadata_objects(
                merge_metadata_objects(
                    reported_cost_ref.and_then(|cost| cost.breakdown.clone()),
                    payment_breakdown,
                ),
                cross_currency_note,
            ),
            oracle_evidence,
            attempted_cost: None,
        };
        let financial_json = Some(serde_json::json!({ "financial": financial_meta }));

        let limited_output = self.apply_stream_limits(output, elapsed)?;
        let post_invocation = self.apply_post_invocation_pipeline(
            request,
            limited_output,
            Some(charge.grant_index),
            merge_metadata_objects(financial_json, extra_metadata.clone()),
        )?;
        let _post_invocation_evidence_scope =
            scope_post_invocation_guard_evidence(post_invocation.evidence);
        if let Some(reason) = post_invocation.blocked_reason.as_deref() {
            return self.build_deny_response_with_metadata(
                request,
                reason,
                timestamp,
                Some(charge.grant_index),
                post_invocation.extra_metadata,
            );
        }

        let tool_call_output = match &post_invocation.output {
            ToolServerOutput::Value(v) => ToolCallOutput::Value(v.clone()),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(s)) => {
                ToolCallOutput::Stream(s.clone())
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, .. }) => {
                ToolCallOutput::Stream(stream.clone())
            }
        };

        match post_invocation.output {
            ToolServerOutput::Value(_)
            | ToolServerOutput::Stream(ToolServerStreamResult::Complete(_)) => self
                .build_allow_response_with_metadata(
                    request,
                    tool_call_output,
                    timestamp,
                    Some(charge.grant_index),
                    post_invocation.extra_metadata,
                ),
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { reason, .. }) => self
                .build_incomplete_response_with_output_and_metadata(
                    request,
                    Some(tool_call_output),
                    &reason,
                    timestamp,
                    Some(charge.grant_index),
                    post_invocation.extra_metadata,
                ),
        }
    }

    fn apply_post_invocation_pipeline(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<PostInvocationHandling, KernelError> {
        if self.post_invocation_pipeline.is_empty() {
            return Ok(PostInvocationHandling {
                output,
                extra_metadata,
                blocked_reason: None,
                evidence: Vec::new(),
            });
        }

        let response = self.output_to_post_invocation_value(&output);
        let context = crate::post_invocation::PostInvocationContext::from_request(
            request,
            matched_grant_index,
        );
        let outcome = self
            .post_invocation_pipeline
            .evaluate_with_context_and_evidence(&context, &response);
        let metadata =
            merge_metadata_objects(extra_metadata, self.post_invocation_metadata(&outcome));

        match outcome.verdict {
            crate::post_invocation::PostInvocationVerdict::Allow
            | crate::post_invocation::PostInvocationVerdict::Escalate(_) => {
                Ok(PostInvocationHandling {
                    output,
                    extra_metadata: metadata,
                    blocked_reason: None,
                    evidence: outcome.evidence,
                })
            }
            crate::post_invocation::PostInvocationVerdict::Block(reason) => {
                Ok(PostInvocationHandling {
                    output,
                    extra_metadata: metadata,
                    blocked_reason: Some(reason),
                    evidence: outcome.evidence,
                })
            }
            crate::post_invocation::PostInvocationVerdict::Redact(redacted) => {
                Ok(PostInvocationHandling {
                    output: self.apply_redacted_output(redacted)?,
                    extra_metadata: metadata,
                    blocked_reason: None,
                    evidence: outcome.evidence,
                })
            }
        }
    }

    fn output_to_post_invocation_value(&self, output: &ToolServerOutput) -> serde_json::Value {
        match output {
            ToolServerOutput::Value(value) => serde_json::json!({
                "kind": "value",
                "value": value,
            }),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream)) => {
                serde_json::json!({
                    "kind": "stream",
                    "stream": {
                        "complete": true,
                        "chunks": stream.chunks.iter().map(|chunk| chunk.data.clone()).collect::<Vec<_>>(),
                    }
                })
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, reason }) => {
                serde_json::json!({
                    "kind": "stream",
                    "stream": {
                        "complete": false,
                        "reason": reason,
                        "chunks": stream.chunks.iter().map(|chunk| chunk.data.clone()).collect::<Vec<_>>(),
                    }
                })
            }
        }
    }

    fn apply_redacted_output(
        &self,
        redacted: serde_json::Value,
    ) -> Result<ToolServerOutput, KernelError> {
        parse_redacted_output(redacted)
    }

    fn post_invocation_metadata(
        &self,
        outcome: &crate::post_invocation::PipelineOutcome,
    ) -> Option<serde_json::Value> {
        let mut metadata = serde_json::Map::new();

        if matches!(
            outcome.verdict,
            crate::post_invocation::PostInvocationVerdict::Redact(_)
        ) {
            metadata.insert("sanitized".to_string(), serde_json::Value::Bool(true));
        }
        if !outcome.escalations.is_empty() {
            metadata.insert(
                "escalations".to_string(),
                serde_json::Value::Array(
                    outcome
                        .escalations
                        .iter()
                        .cloned()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }

        if metadata.is_empty() {
            None
        } else {
            Some(serde_json::json!({ "post_invocation": metadata }))
        }
    }

    pub(crate) fn apply_stream_limits(
        &self,
        output: ToolServerOutput,
        elapsed: Duration,
    ) -> Result<ToolServerOutput, KernelError> {
        let ToolServerOutput::Stream(stream_result) = output else {
            return Ok(output);
        };

        let duration_limit = Duration::from_secs(self.config.max_stream_duration_secs);
        let duration_exceeded =
            self.config.max_stream_duration_secs > 0 && elapsed > duration_limit;

        let (stream, base_reason) = match stream_result {
            ToolServerStreamResult::Complete(stream) => (stream, None),
            ToolServerStreamResult::Incomplete { stream, reason } => (stream, Some(reason)),
        };

        let (stream, total_bytes, truncated) =
            truncate_stream_to_byte_limit(&stream, self.config.max_stream_total_bytes)?;

        let limit_reason = if truncated {
            Some(format!(
                "CHIO_SERVER_STREAM_LIMIT: stream exceeded max total bytes of {}",
                self.config.max_stream_total_bytes
            ))
        } else if duration_exceeded {
            Some(format!(
                "CHIO_SERVER_STREAM_LIMIT: stream exceeded max duration of {}s",
                self.config.max_stream_duration_secs
            ))
        } else {
            None
        };

        if let Some(reason) = limit_reason {
            warn!(
                request_bytes = total_bytes,
                elapsed_ms = elapsed.as_millis(),
                "stream output exceeded configured limits"
            );
            return Ok(ToolServerOutput::Stream(
                ToolServerStreamResult::Incomplete { stream, reason },
            ));
        }

        if let Some(reason) = base_reason {
            Ok(ToolServerOutput::Stream(
                ToolServerStreamResult::Incomplete { stream, reason },
            ))
        } else {
            Ok(ToolServerOutput::Stream(ToolServerStreamResult::Complete(
                stream,
            )))
        }
    }

    /// Build a denial response with a signed receipt.
    pub(crate) fn build_deny_response(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_deny_response_with_metadata(
            request,
            reason,
            timestamp,
            matched_grant_index,
            None,
        )
    }

    pub(crate) fn build_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let receipt_content = receipt_content_for_output(None, None)?;

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;
        let request_metadata = request_receipt_metadata(
            request,
            self.attestation_trust_policy.as_ref(),
            timestamp,
            extra_metadata.as_ref(),
        )?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Deny {
                reason: reason.to_string(),
                guard: "kernel".to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(receipt_content.metadata, request_metadata),
                    extra_metadata,
                ),
                receipt_attribution_metadata(cap, matched_grant_index),
            ),
            timestamp,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
        })?;

        self.record_chio_receipt_with_federation(request, &receipt)?;

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Deny,
            output: None,
            reason: Some(reason.to_string()),
            terminal_state: OperationTerminalState::Completed,
            receipt,
            execution_nonce: None,
        })
    }

    /// Build a cancellation response with a signed cancelled receipt.
    pub(crate) fn build_cancelled_response(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_cancelled_response_with_metadata(
            request,
            reason,
            timestamp,
            matched_grant_index,
            None,
        )
    }

    pub(crate) fn build_cancelled_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let receipt_content = receipt_content_for_output(None, None)?;

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;
        let request_metadata = request_receipt_metadata(
            request,
            self.attestation_trust_policy.as_ref(),
            timestamp,
            extra_metadata.as_ref(),
        )?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Cancelled {
                reason: reason.to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(receipt_content.metadata, request_metadata),
                    extra_metadata,
                ),
                receipt_attribution_metadata(cap, matched_grant_index),
            ),
            timestamp,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
        })?;

        self.record_chio_receipt_with_federation(request, &receipt)?;

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Deny,
            output: None,
            reason: Some(reason.to_string()),
            terminal_state: OperationTerminalState::Cancelled {
                reason: reason.to_string(),
            },
            receipt,
            execution_nonce: None,
        })
    }

    /// Build an incomplete response with a signed incomplete receipt.
    pub(crate) fn build_incomplete_response(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_incomplete_response_with_output(
            request,
            None,
            reason,
            timestamp,
            matched_grant_index,
        )
    }

    /// Build an incomplete response with optional partial output and a signed incomplete receipt.
    pub(crate) fn build_incomplete_response_with_output(
        &self,
        request: &ToolCallRequest,
        output: Option<ToolCallOutput>,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_incomplete_response_with_output_and_metadata(
            request,
            output,
            reason,
            timestamp,
            matched_grant_index,
            None,
        )
    }

    pub(crate) fn build_incomplete_response_with_output_and_metadata(
        &self,
        request: &ToolCallRequest,
        output: Option<ToolCallOutput>,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let receipt_content = receipt_content_for_output(output.as_ref(), None)?;

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;
        let request_metadata = request_receipt_metadata(
            request,
            self.attestation_trust_policy.as_ref(),
            timestamp,
            extra_metadata.as_ref(),
        )?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Incomplete {
                reason: reason.to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(receipt_content.metadata, request_metadata),
                    extra_metadata,
                ),
                receipt_attribution_metadata(cap, matched_grant_index),
            ),
            timestamp,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
        })?;

        self.record_chio_receipt_with_federation(request, &receipt)?;

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Deny,
            output,
            reason: Some(reason.to_string()),
            terminal_state: OperationTerminalState::Incomplete {
                reason: reason.to_string(),
            },
            receipt,
            execution_nonce: None,
        })
    }

    pub(crate) fn build_allow_response(
        &self,
        request: &ToolCallRequest,
        output: ToolCallOutput,
        timestamp: u64,
        matched_grant_index: Option<usize>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_allow_response_with_metadata(
            request,
            output,
            timestamp,
            matched_grant_index,
            None,
        )
    }

    pub(crate) fn build_allow_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        output: ToolCallOutput,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let expected_chunks = match &output {
            ToolCallOutput::Stream(stream) => Some(stream.chunk_count()),
            ToolCallOutput::Value(_) => None,
        };
        let receipt_content = receipt_content_for_output(Some(&output), expected_chunks)?;

        // Phase 18.2: classify the call against the memory-provenance
        // action conventions and, for reads, look up the latest chain
        // entry BEFORE the receipt is signed so the provenance evidence
        // rides in the signed metadata. Writes append AFTER signing
        // (see below) because the chain entry needs the receipt id.
        let memory_action_kind = crate::memory_provenance::classify_memory_action(
            &request.tool_name,
            &request.arguments,
        );
        let memory_read_metadata = match memory_action_kind.as_ref() {
            Some(crate::memory_provenance::MemoryActionKind::Read { store, key }) => {
                self.resolve_memory_read_provenance_metadata(store, key)
            }
            _ => None,
        };
        let request_metadata = request_receipt_metadata(
            request,
            self.attestation_trust_policy.as_ref(),
            timestamp,
            extra_metadata.as_ref(),
        )?;

        // Merge extra_metadata (e.g. "financial") into receipt_content.metadata.
        let metadata = merge_metadata_objects(
            merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(receipt_content.metadata, request_metadata),
                    extra_metadata,
                ),
                receipt_attribution_metadata(cap, matched_grant_index),
            ),
            memory_read_metadata,
        );

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Allow,
            action,
            content_hash: receipt_content.content_hash,
            metadata,
            timestamp,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
        })?;

        self.record_chio_receipt_with_federation(request, &receipt)?;

        info!(
            request_id = %request.request_id,
            tool = %request.tool_name,
            receipt_id = %receipt.id,
            "tool call allowed"
        );

        // Phase 18.2: for governed writes, append an entry to the
        // provenance chain once the receipt is signed. A failure here
        // is fatal (fail-closed): we do not want to acknowledge the
        // write to the caller while silently dropping provenance.
        if let Some(crate::memory_provenance::MemoryActionKind::Write { store, key }) =
            memory_action_kind.as_ref()
        {
            self.append_memory_provenance_for_write(
                store,
                key,
                &cap.id,
                &receipt.id,
                receipt.timestamp,
            )?;
        }

        // Phase 1.1: mint a short-lived, single-use execution nonce bound
        // to this allow verdict so tool servers can verify the kernel
        // authorized this exact invocation. Opt-in; when no config is
        // installed the field remains `None` for backward compatibility.
        let execution_nonce = self.mint_execution_nonce_for_allow(request, cap, &receipt)?;

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Allow,
            output: Some(output),
            reason: None,
            terminal_state: OperationTerminalState::Completed,
            receipt,
            execution_nonce,
        })
    }

    /// Phase 18.2: build receipt metadata describing the provenance
    /// record that governs the memory read identified by `(store, key)`.
    ///
    /// Returns `None` when no provenance store has been installed
    /// (backward-compatible no-op), and returns an `unverified` metadata
    /// object when the store is installed but the key has no chain
    /// entry OR the chain is tampered / unavailable. This is the
    /// fail-closed signal: the receipt explicitly records that the
    /// memory read was not backed by a provenance record.
    fn resolve_memory_read_provenance_metadata(
        &self,
        store: &str,
        key: &str,
    ) -> Option<serde_json::Value> {
        let chain = self.memory_provenance_store()?;

        let latest = match chain.latest_for_key(store, key) {
            Ok(entry) => entry,
            Err(error) => {
                warn!(
                    store = %store,
                    key = %key,
                    error = %error,
                    "memory provenance lookup failed; marking read unverified"
                );
                return Some(memory_read_unverified_metadata(
                    store,
                    key,
                    crate::memory_provenance::UnverifiedReason::StoreUnavailable,
                ));
            }
        };

        let Some(entry) = latest else {
            return Some(memory_read_unverified_metadata(
                store,
                key,
                crate::memory_provenance::UnverifiedReason::NoProvenance,
            ));
        };

        let verification = match chain.verify_entry(&entry.entry_id) {
            Ok(verification) => verification,
            Err(error) => {
                warn!(
                    store = %store,
                    key = %key,
                    entry_id = %entry.entry_id,
                    error = %error,
                    "memory provenance verification failed; marking read unverified"
                );
                return Some(memory_read_unverified_metadata(
                    store,
                    key,
                    crate::memory_provenance::UnverifiedReason::StoreUnavailable,
                ));
            }
        };

        match verification {
            crate::memory_provenance::ProvenanceVerification::Verified {
                entry,
                chain_digest,
            } => Some(serde_json::json!({
                "memory_provenance": {
                    "status": "verified",
                    "store": entry.store,
                    "key": entry.key,
                    "entry_id": entry.entry_id,
                    "capability_id": entry.capability_id,
                    "receipt_id": entry.receipt_id,
                    "written_at": entry.written_at,
                    "prev_hash": entry.prev_hash,
                    "hash": entry.hash,
                    "chain_digest": chain_digest,
                }
            })),
            crate::memory_provenance::ProvenanceVerification::Unverified { reason } => {
                Some(memory_read_unverified_metadata(store, key, reason))
            }
        }
    }

    /// Phase 18.2: append a provenance entry for a governed memory write
    /// once the allow receipt is signed. Fails closed on chain-store
    /// errors.
    fn append_memory_provenance_for_write(
        &self,
        store: &str,
        key: &str,
        capability_id: &str,
        receipt_id: &str,
        written_at: u64,
    ) -> Result<(), KernelError> {
        let Some(chain) = self.memory_provenance_store() else {
            return Ok(());
        };
        chain
            .append(crate::memory_provenance::MemoryProvenanceAppend {
                store: store.to_string(),
                key: key.to_string(),
                capability_id: capability_id.to_string(),
                receipt_id: receipt_id.to_string(),
                written_at,
            })
            .map(|_| ())
            .map_err(|error| {
                KernelError::Internal(format!(
                    "memory provenance append failed for store={store} key={key}: {error}"
                ))
            })
    }

    /// Build and sign a receipt from a `ReceiptParams` descriptor.
    pub(crate) fn build_and_sign_receipt(
        &self,
        params: ReceiptParams<'_>,
    ) -> Result<ChioReceipt, KernelError> {
        // Phase 1.5 multi-tenant receipt isolation: resolve tenant_id for
        // this receipt. Precedence:
        //   1. An explicit override on `ReceiptParams` (currently unused).
        //   2. The active scoped tenant context set by the evaluate path
        //      from `session.auth_context().enterprise_identity.tenant_id`.
        //
        // Tenant_id is never taken from a caller-provided field on the
        // request: allowing caller choice would defeat the isolation the
        // store-level WHERE clause enforces.
        let tenant_id = params
            .tenant_id
            .clone()
            .or_else(current_scoped_receipt_tenant_id);

        let body = ChioReceiptBody {
            id: next_receipt_id("rcpt"),
            timestamp: params.timestamp,
            capability_id: params.capability_id.to_string(),
            tool_server: params.server_id.to_string(),
            tool_name: params.tool_name.to_string(),
            action: params.action,
            decision: params.decision,
            content_hash: params.content_hash,
            policy_hash: self.config.policy_hash.clone(),
            evidence: current_post_invocation_guard_evidence(),
            metadata: params.metadata,
            trust_level: params.trust_level,
            tenant_id,
            kernel_key: self.config.keypair.public_key(),
        };

        // Phase 14.1: delegate the pure signing step to chio-kernel-core so the
        // portable TCB stays in one place. The full kernel still owns body
        // construction (tenant scope resolution, policy_hash injection,
        // evidence assembly) because those are std/tokio-aware concerns.
        //
        // Verified-core boundary note:
        // `formal/proof-manifest.toml` includes this shell method only for the
        // direct call into `chio_kernel_core::sign_receipt`. Receipt body
        // assembly, metadata shaping, and persistence remain operational-shell
        // behavior outside the current bounded proof claim.
        let backend = chio_core::crypto::Ed25519Backend::new(self.config.keypair.clone());
        chio_kernel_core::sign_receipt(body, &backend).map_err(|error| {
            use chio_kernel_core::ReceiptSigningError;
            let message = match error {
                ReceiptSigningError::KernelKeyMismatch => {
                    "kernel signing key does not match receipt body kernel_key".to_string()
                }
                ReceiptSigningError::SigningFailed(reason) => reason,
            };
            KernelError::ReceiptSigningFailed(message)
        })
    }

    /// Phase 20.3: record the receipt AND drive the bilateral co-signing
    /// hook when the request crosses a federation boundary.
    ///
    /// Fail-closed: a co-sign failure aborts the record path so the
    /// receipt is never persisted without its paired remote signature.
    /// Non-federated requests (request.federated_origin_kernel_id is
    /// `None`) behave identically to [`Self::record_chio_receipt`].
    pub(crate) fn record_chio_receipt_with_federation(
        &self,
        request: &crate::runtime::ToolCallRequest,
        receipt: &ChioReceipt,
    ) -> Result<(), KernelError> {
        self.apply_federation_cosign(request, receipt)?;
        self.record_chio_receipt(receipt)
    }

    pub(crate) fn record_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), KernelError> {
        let _receipt_store_write = self
            .receipt_store_write_lock
            .lock()
            .map_err(|_| KernelError::Internal("receipt store write lock poisoned".to_string()))?;
        if let Some(seq) = self
            .with_receipt_store(|store| Ok(store.append_chio_receipt_returning_seq(receipt)?))?
            .flatten()
        {
            if self.should_checkpoint_after_seq(seq) {
                self.maybe_trigger_checkpoint_locked(seq)?;
            }
        }
        self.append_chio_receipt_to_local_log(receipt.clone());
        Ok(())
    }

    /// Trigger a Merkle checkpoint for all receipts in [last_checkpoint_seq+1, batch_end_seq].
    pub(crate) fn maybe_trigger_checkpoint(&self, batch_end_seq: u64) -> Result<(), KernelError> {
        let _receipt_store_write = self
            .receipt_store_write_lock
            .lock()
            .map_err(|_| KernelError::Internal("receipt store write lock poisoned".to_string()))?;
        self.maybe_trigger_checkpoint_locked(batch_end_seq)
    }

    pub(crate) fn should_checkpoint_after_seq(&self, seq: u64) -> bool {
        let last_checkpoint_seq = self.last_checkpoint_seq.load(Ordering::SeqCst);
        seq > 0
            && self.checkpoint_batch_size > 0
            && seq > last_checkpoint_seq
            && (seq - last_checkpoint_seq) >= self.checkpoint_batch_size
    }

    pub(crate) fn maybe_trigger_checkpoint_locked(
        &self,
        batch_end_seq: u64,
    ) -> Result<(), KernelError> {
        const CHECKPOINT_CONFLICT_RETRIES: usize = 8;

        for attempt in 0..=CHECKPOINT_CONFLICT_RETRIES {
            let previous_checkpoint = self.refresh_checkpoint_counters_from_store()?;
            let last_checkpoint_seq = self.last_checkpoint_seq.load(Ordering::SeqCst);
            if batch_end_seq <= last_checkpoint_seq {
                return Ok(());
            }
            let batch_start_seq = last_checkpoint_seq + 1;

            let Some(receipt_bytes_with_seqs) = self.with_receipt_store(|store| {
                Ok(store.receipts_canonical_bytes_range(batch_start_seq, batch_end_seq)?)
            })?
            else {
                return Ok(());
            };

            if receipt_bytes_with_seqs.is_empty() {
                return Ok(());
            }

            let receipt_bytes: Vec<Vec<u8>> = receipt_bytes_with_seqs
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect();

            let checkpoint_seq = self.checkpoint_seq_counter.load(Ordering::SeqCst) + 1;
            let checkpoint = checkpoint::build_checkpoint_with_previous(
                checkpoint_seq,
                batch_start_seq,
                batch_end_seq,
                &receipt_bytes,
                &self.config.keypair,
                previous_checkpoint.as_ref(),
            )
            .map_err(|e| KernelError::Internal(format!("checkpoint build failed: {e}")))?;

            match self.with_receipt_store(|store| Ok(store.store_checkpoint(&checkpoint)?)) {
                Ok(_) => {
                    self.checkpoint_seq_counter
                        .store(checkpoint_seq, Ordering::SeqCst);
                    self.last_checkpoint_seq
                        .store(batch_end_seq, Ordering::SeqCst);
                    return Ok(());
                }
                Err(KernelError::ReceiptPersistence(ReceiptStoreError::Conflict(_)))
                    if attempt < CHECKPOINT_CONFLICT_RETRIES =>
                {
                    let latest = self.refresh_checkpoint_counters_from_store()?;
                    if latest
                        .as_ref()
                        .is_some_and(|checkpoint| checkpoint.body.batch_end_seq >= batch_end_seq)
                    {
                        return Ok(());
                    }
                }
                Err(err) => return Err(err),
            }
        }

        Err(KernelError::Internal(
            "checkpoint store conflict retry budget exhausted".to_string(),
        ))
    }

    fn refresh_checkpoint_counters_from_store(
        &self,
    ) -> Result<Option<KernelCheckpoint>, KernelError> {
        let latest = self
            .with_receipt_store(|store| Ok(store.load_latest_checkpoint()?))?
            .flatten();
        match latest.as_ref() {
            Some(checkpoint) => {
                self.checkpoint_seq_counter
                    .store(checkpoint.body.checkpoint_seq, Ordering::SeqCst);
                self.last_checkpoint_seq
                    .store(checkpoint.body.batch_end_seq, Ordering::SeqCst);
            }
            None => {
                self.checkpoint_seq_counter.store(0, Ordering::SeqCst);
                self.last_checkpoint_seq.store(0, Ordering::SeqCst);
            }
        }
        Ok(latest)
    }
}

/// Phase 18.2 helper: produce the canonical `memory_provenance`
/// metadata object that signals an unverified read.
///
/// Kept as a free function so both the pre-sign metadata resolver and
/// the fallback paths share a single serialisation shape.
fn memory_read_unverified_metadata(
    store: &str,
    key: &str,
    reason: crate::memory_provenance::UnverifiedReason,
) -> serde_json::Value {
    serde_json::json!({
        "memory_provenance": {
            "status": "unverified",
            "store": store,
            "key": key,
            "reason": reason.as_str(),
        }
    })
}

fn parse_redacted_output(redacted: serde_json::Value) -> Result<ToolServerOutput, KernelError> {
    let envelope = redacted.as_object().ok_or_else(|| {
        KernelError::Internal(
            "post-invocation hook returned a non-object output envelope".to_string(),
        )
    })?;
    let kind = envelope
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            KernelError::Internal(
                "post-invocation hook output envelope is missing kind".to_string(),
            )
        })?;

    match kind {
        "value" => Ok(ToolServerOutput::Value(
            envelope
                .get("value")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )),
        "stream" => {
            let stream = envelope
                .get("stream")
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| {
                    KernelError::Internal(
                        "post-invocation hook output envelope is missing stream".to_string(),
                    )
                })?;
            let chunks = stream
                .get("chunks")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    KernelError::Internal(
                        "post-invocation hook stream envelope is missing chunks".to_string(),
                    )
                })?
                .iter()
                .cloned()
                .map(|data| ToolCallChunk { data })
                .collect();
            let tool_stream = ToolCallStream { chunks };
            let complete = stream
                .get("complete")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| {
                    KernelError::Internal(
                        "post-invocation hook stream envelope is missing complete".to_string(),
                    )
                })?;
            if complete {
                Ok(ToolServerOutput::Stream(ToolServerStreamResult::Complete(
                    tool_stream,
                )))
            } else {
                let reason = stream
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        KernelError::Internal(
                            "post-invocation hook incomplete stream is missing reason".to_string(),
                        )
                    })?;
                Ok(ToolServerOutput::Stream(
                    ToolServerStreamResult::Incomplete {
                        stream: tool_stream,
                        reason: reason.to_string(),
                    },
                ))
            }
        }
        other => Err(KernelError::Internal(format!(
            "post-invocation hook returned unsupported output kind {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_stream_requires_complete_flag() {
        let err = parse_redacted_output(serde_json::json!({
            "kind": "stream",
            "stream": {
                "chunks": []
            }
        }))
        .expect_err("missing complete flag should be rejected");

        match err {
            KernelError::Internal(message) => {
                assert!(
                    message.contains("missing complete"),
                    "unexpected error message: {message}"
                );
            }
            other => panic!("expected KernelError::Internal, got {other:?}"),
        }
    }
}
