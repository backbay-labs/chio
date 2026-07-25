use super::*;

pub(crate) struct FinalizeToolOutputCostContext<'a> {
    pub(crate) charge_result: Option<BudgetChargeResult>,
    pub(crate) reported_cost: Option<ToolInvocationCost>,
    pub(crate) payment_authorization: Option<PaymentAuthorization>,
    pub(crate) cap: &'a CapabilityToken,
}

pub(crate) struct PostInvocationHandling {
    pub(crate) output: ToolServerOutput,
    pub(crate) extra_metadata: Option<serde_json::Value>,
    pub(crate) blocked_reason: Option<String>,
    pub(crate) evidence: Vec<chio_core::receipt::metadata::GuardEvidence>,
}

impl ChioKernel {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finalize_tool_output_with_metadata_and_payee_binding(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        matched_grant_index: usize,
        extra_metadata: Option<serde_json::Value>,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
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
            return self.build_deny_response_with_metadata_and_payee_binding(
                request,
                reason,
                timestamp,
                Some(matched_grant_index),
                // The tool already ran (a side effect may have committed)
                // before this post-invocation guard blocked the returned
                // output, so any runtime-admission lease consumed at admission
                // is retained, not released. Mark it so the burned lease is
                // recoverable from the receipt, matching the incomplete-stream
                // and RequestIncomplete arms.
                self.mark_runtime_admission_reservations_retained_fail_closed(
                    post_invocation.extra_metadata,
                ),
                verified_payee_binding,
            );
        }

        match post_invocation.output {
            ToolServerOutput::Value(value) => self
                .build_allow_response_with_metadata_and_payee_binding(
                    request,
                    ToolCallOutput::Value(value),
                    timestamp,
                    Some(matched_grant_index),
                    post_invocation.extra_metadata,
                    verified_payee_binding,
                    AllowResponseNonce::MintForAllow,
                ),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream)) => self
                .build_allow_response_with_metadata_and_payee_binding(
                    request,
                    ToolCallOutput::Stream(stream),
                    timestamp,
                    Some(matched_grant_index),
                    post_invocation.extra_metadata,
                    verified_payee_binding,
                    AllowResponseNonce::MintForAllow,
                ),
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, reason }) => self
                .build_incomplete_response_with_output_metadata_and_payee_binding(
                    request,
                    Some(ToolCallOutput::Stream(stream)),
                    &reason,
                    timestamp,
                    Some(matched_grant_index),
                    // The tool ran (a side effect may have committed) but the
                    // stream ended incomplete, so any runtime-admission lease
                    // consumed at admission is retained, not released. Mark it
                    // so the burned lease is recoverable from the receipt,
                    // matching the RequestIncomplete error arm.
                    self.mark_runtime_admission_reservations_retained_fail_closed(
                        post_invocation.extra_metadata,
                    ),
                    verified_payee_binding,
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
        self.finish_post_invocation_pipeline(
            output,
            extra_metadata,
            outcome,
            crate::tool_outcome::InvocationStreamLimitsV1 {
                max_total_bytes: self.config.max_stream_total_bytes,
                max_chunks: self.config.memory_budget.max_stream_chunks,
                max_duration_secs: self.config.max_stream_duration_secs,
            },
        )
    }

    pub(crate) fn apply_durable_post_invocation_pipeline(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        matched_grant_index: usize,
        extra_metadata: Option<serde_json::Value>,
        identities: &[crate::post_invocation::PostInvocationHookIdentity],
        stream_limits: crate::tool_outcome::InvocationStreamLimitsV1,
    ) -> Result<
        (
            PostInvocationHandling,
            Vec<crate::post_invocation::DurablePipelineStepResult>,
        ),
        KernelError,
    > {
        if self.post_invocation_pipeline.is_empty() {
            return Ok((
                PostInvocationHandling {
                    output,
                    extra_metadata,
                    blocked_reason: None,
                    evidence: Vec::new(),
                },
                Vec::new(),
            ));
        }

        let response = self.output_to_post_invocation_value(&output);
        let context = crate::post_invocation::PostInvocationContext::from_request(
            request,
            Some(matched_grant_index),
        );
        let durable = self
            .post_invocation_pipeline
            .evaluate_durable_with_context_and_evidence(&context, &response, identities)
            .map_err(KernelError::DurableAdmission)?;
        let handling = self.finish_post_invocation_pipeline(
            output,
            extra_metadata,
            durable.outcome,
            stream_limits,
        )?;
        Ok((handling, durable.step_results))
    }

    fn finish_post_invocation_pipeline(
        &self,
        output: ToolServerOutput,
        extra_metadata: Option<serde_json::Value>,
        outcome: crate::post_invocation::PipelineOutcome,
        stream_limits: crate::tool_outcome::InvocationStreamLimitsV1,
    ) -> Result<PostInvocationHandling, KernelError> {
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
                // Redaction replaces the retained stream with hook-supplied
                // content that never passed `apply_stream_limits` (that ran on the
                // ORIGINAL output, before this hook). The byte + chunk caps are
                // re-applied while the redacted chunks are drained so a
                // sanitizer/custom hook that emits more than
                // `max_stream_total_bytes` / `max_stream_chunks` cannot make the
                // kernel materialize the whole redacted stream, nor grow the final
                // signed output and receipt preimage past the configured budget.
                Ok(PostInvocationHandling {
                    output: self.apply_redacted_output(redacted, stream_limits)?,
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

    /// Parse a post-invocation `Redact` hook's output envelope, enforcing the
    /// byte + chunk stream retention caps WHILE the redacted chunks are drained.
    ///
    /// `apply_stream_limits` runs on the ORIGINAL tool output, before the
    /// post-invocation pipeline. A `Redact` verdict swaps in hook-supplied content
    /// that has not been capped, so the caps are re-applied here. Enforcing them
    /// during accumulation (rather than after the whole envelope is materialized)
    /// means a hook that emits a huge `chunks` array cannot make the kernel
    /// allocate the full redacted stream: parsing stops at `max_stream_chunks`
    /// retained chunks or once retaining the next chunk would exceed
    /// `max_stream_total_bytes`, and the retained stream can never grow the signed
    /// output and receipt preimage past the configured budget.
    ///
    /// Only the retention caps are enforced. The stream-duration limit is
    /// intentionally NOT re-evaluated: it bounds tool execution time, not redacted
    /// content, and was already decided on the original output. A non-stream
    /// redacted output (a value) is returned unchanged. Any pre-existing
    /// incomplete reason on the redacted stream is preserved unless a cap fires.
    fn apply_redacted_output(
        &self,
        redacted: serde_json::Value,
        stream_limits: crate::tool_outcome::InvocationStreamLimitsV1,
    ) -> Result<ToolServerOutput, KernelError> {
        parse_redacted_output(
            redacted,
            stream_limits.max_total_bytes,
            stream_limits.max_chunks,
        )
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
        let limits = crate::tool_outcome::InvocationStreamLimitsV1 {
            max_total_bytes: self.config.max_stream_total_bytes,
            max_chunks: self.config.memory_budget.max_stream_chunks,
            max_duration_secs: self.config.max_stream_duration_secs,
        };
        self.apply_stream_limit_snapshot(output, elapsed, limits)
    }

    pub(crate) fn apply_stream_limit_snapshot(
        &self,
        output: ToolServerOutput,
        elapsed: Duration,
        limits: crate::tool_outcome::InvocationStreamLimitsV1,
    ) -> Result<ToolServerOutput, KernelError> {
        let ToolServerOutput::Stream(stream_result) = output else {
            return Ok(output);
        };

        let duration_limit = Duration::from_secs(limits.max_duration_secs);
        let duration_exceeded = limits.max_duration_secs > 0 && elapsed > duration_limit;

        let (stream, base_reason) = match stream_result {
            ToolServerStreamResult::Complete(stream) => (stream, None),
            ToolServerStreamResult::Incomplete { stream, reason } => (stream, Some(reason)),
        };

        let (stream, total_bytes, truncation_cause) =
            truncate_stream_to_limits(&stream, limits.max_total_bytes, limits.max_chunks)?;

        let limit_reason = match truncation_cause {
            Some(cause) => Some(stream_limit_reason(
                cause,
                limits.max_total_bytes,
                limits.max_chunks,
            )),
            None if duration_exceeded => Some(format!(
                "CHIO_SERVER_STREAM_LIMIT: stream exceeded max duration of {}s",
                limits.max_duration_secs
            )),
            None => None,
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

fn parse_redacted_output(
    redacted: serde_json::Value,
    max_stream_total_bytes: u64,
    max_stream_chunks: u64,
) -> Result<ToolServerOutput, KernelError> {
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
            let raw_chunks = stream
                .get("chunks")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    KernelError::Internal(
                        "post-invocation hook stream envelope is missing chunks".to_string(),
                    )
                })?;
            let complete = stream
                .get("complete")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| {
                    KernelError::Internal(
                        "post-invocation hook stream envelope is missing complete".to_string(),
                    )
                })?;

            // Cap the retained stream as the hook's chunk array is drained, so an
            // oversized redacted stream is bounded during accumulation rather than
            // after the whole array is materialized. Cloning is lazy: only the
            // retained prefix (plus the boundary chunk that trips a cap) is copied.
            let (tool_stream, _total_bytes, cause) = accumulate_stream_under_caps(
                raw_chunks
                    .iter()
                    .map(|data| ToolCallChunk { data: data.clone() }),
                max_stream_total_bytes,
                max_stream_chunks,
            )?;

            if let Some(cause) = cause {
                return Ok(ToolServerOutput::Stream(
                    ToolServerStreamResult::Incomplete {
                        stream: tool_stream,
                        reason: stream_limit_reason(
                            cause,
                            max_stream_total_bytes,
                            max_stream_chunks,
                        ),
                    },
                ));
            }
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
        let err = parse_redacted_output(
            serde_json::json!({
                "kind": "stream",
                "stream": {
                    "chunks": []
                }
            }),
            0,
            0,
        )
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

    #[test]
    fn redacted_stream_chunk_cap_applies_before_materializing_all_chunks() {
        // A redaction hook can return an arbitrarily long `chunks` array. The
        // chunk cap must bound the retained stream WHILE the array is drained, so
        // the parsed output already carries only `max_stream_chunks` chunks and is
        // marked incomplete rather than first materializing the whole array.
        let chunks: Vec<serde_json::Value> = (0..1_000).map(|i| serde_json::json!(i)).collect();
        let output = parse_redacted_output(
            serde_json::json!({
                "kind": "stream",
                "stream": { "complete": true, "chunks": chunks },
            }),
            0,
            3,
        )
        .expect("stream envelope should parse");

        match output {
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, reason }) => {
                assert_eq!(
                    stream.chunks.len(),
                    3,
                    "retained chunk count must equal the cap, not the hook's array length"
                );
                assert!(
                    reason.contains("max chunk count of 3"),
                    "unexpected truncation reason: {reason}"
                );
            }
            other => panic!("expected a capped incomplete stream, got {other:?}"),
        }
    }

    #[test]
    fn redacted_stream_byte_cap_applies_before_materializing_all_chunks() {
        // The byte cap likewise bounds the retained stream during accumulation: a
        // hook emitting more than `max_stream_total_bytes` cannot grow the parsed
        // stream past the budget.
        let chunks: Vec<serde_json::Value> = (0..1_000)
            .map(|i| serde_json::json!(format!("chunk-{i}")))
            .collect();
        let output = parse_redacted_output(
            serde_json::json!({
                "kind": "stream",
                "stream": { "complete": true, "chunks": chunks },
            }),
            16,
            0,
        )
        .expect("stream envelope should parse");

        match output {
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, reason }) => {
                assert!(
                    !stream.chunks.is_empty() && stream.chunks.len() < 1_000,
                    "byte cap must retain a bounded prefix, got {} chunks",
                    stream.chunks.len()
                );
                assert!(
                    reason.contains("max total bytes of 16"),
                    "unexpected truncation reason: {reason}"
                );
            }
            other => panic!("expected a capped incomplete stream, got {other:?}"),
        }
    }
}
