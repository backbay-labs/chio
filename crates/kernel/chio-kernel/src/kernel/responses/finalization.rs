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
    evidence: Vec<chio_core::receipt::metadata::GuardEvidence>,
}

impl ChioKernel {
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
                            reason = %redacted!(&error),
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
                            reason = %redacted!(&error),
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
