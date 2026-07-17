use super::*;

fn require_receipt_body_fields_coupled(
    body: &ChioReceiptBody,
    expected: &ReceiptCouplingExpectation<'_>,
) -> Result<(), KernelError> {
    if receipt_body_fields_coupled(body, expected) {
        Ok(())
    } else {
        Err(KernelError::ReceiptSigningFailed(
            "receipt fields diverged from the admitted decision inputs".to_string(),
        ))
    }
}

impl ChioKernel {
    /// Build and sign a receipt from a `ReceiptParams` descriptor.
    pub(crate) fn build_and_sign_receipt(
        &self,
        params: ReceiptParams<'_>,
    ) -> Result<ChioReceipt, KernelError> {
        // Multi-tenant receipt isolation: resolve tenant_id for this receipt.
        // Precedence:
        //   1. An explicit override on `ReceiptParams` (currently unused).
        //   2. The request-keyed tenant context set by the evaluate path.
        //      A present entry is authoritative even when it resolves to
        //      no tenant: falling through to the thread-local scope from a
        //      known-tenantless request would adopt whatever tenant a
        //      concurrent sibling task's scope guard left on the resuming
        //      worker thread.
        //   3. The active scoped tenant context set by the evaluate path
        //      from `session.auth_context().enterprise_identity.tenant_id`,
        //      for receipts built outside any request-scoped evaluation.
        //
        // Tenant_id is never taken from a caller-provided field on the
        // request: allowing caller choice would defeat the isolation the
        // store-level WHERE clause enforces.
        let tenant_id = params
            .tenant_id
            .clone()
            .or_else(|| params.evaluation_context.tenant_id.clone())
            .or_else(|| {
                self.receipt_tenant_id_for_request(params.request_id)
                    .unwrap_or_else(current_scoped_receipt_tenant_id)
            });

        let request_metadata = params.request_id.map(|request_id| {
            serde_json::json!({
                "receipt_context": {
                    "request_id": request_id,
                }
            })
        });
        let metadata = merge_metadata_objects(params.metadata, request_metadata);

        let mut evidence = current_pre_invocation_guard_evidence();
        evidence.extend(current_post_invocation_guard_evidence());

        let body = ChioReceiptBody {
            id: next_receipt_id("rcpt"),
            timestamp: params.timestamp,
            capability_id: params.capability_id.to_string(),
            tool_server: params.server_id.to_string(),
            tool_name: params.tool_name.to_string(),
            action: params.action.clone(),
            decision: Some(params.decision.clone()),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: params.content_hash.clone(),
            policy_hash: self.config.policy_hash.clone(),
            evidence,
            metadata,
            trust_level: params.trust_level,
            tenant_id,
            kernel_key: self.config.keypair.public_key(),
            bbs_projection_version: None,
        };

        let expected = ReceiptCouplingExpectation {
            capability_id: params.capability_id,
            server_id: params.server_id,
            tool_name: params.tool_name,
            action: &params.action,
            decision: &params.decision,
            content_hash: &params.content_hash,
            policy_hash: &self.config.policy_hash,
            trust_level: params.trust_level,
        };
        require_receipt_body_fields_coupled(&body, &expected)?;

        // WYSIWYS: bind the signature to the exact content this receipt's
        // `content_hash` was derived from. The handle recomputes
        // `sha256_hex(canonical_content)` and the signing primitive refuses to
        // sign if it disagrees with `body.content_hash`, closing the
        // render-A / sign-B hole on the production path. The
        // canonical_content is the same preimage `receipt_content_for_output`
        // hashed to produce `content_hash`.
        let handle = ReceiptSigningHandle::from_content_preimage(params.canonical_content);

        // Delegate the pure signing step to chio-kernel-core so the portable
        // TCB stays in one place. The full kernel still owns body construction
        // (tenant scope resolution, policy_hash injection, evidence assembly)
        // because those are std/tokio-aware concerns.
        //
        // Verified-core boundary note:
        // `formal/proof-manifest.toml` includes this shell method only for the
        // direct call into `chio_kernel_core::sign_receipt_with_handle`. Receipt
        // body assembly, metadata shaping, and persistence remain
        // operational-shell behavior outside the current bounded proof claim.
        let backend = chio_core::crypto::Ed25519Backend::new(self.config.keypair.clone());
        chio_kernel_core::sign_receipt_with_handle(body, &backend, handle).map_err(|error| {
            use chio_kernel_core::ReceiptSigningError;
            let message = match error {
                ReceiptSigningError::KernelKeyMismatch => {
                    "kernel signing key does not match receipt body kernel_key".to_string()
                }
                ReceiptSigningError::ContentHashMismatch {
                    recomputed,
                    claimed,
                } => format!(
                    "receipt content_hash mismatch: body claimed {claimed} but signer \
                     recomputed {recomputed} over the canonical content (WYSIWYS refused)"
                ),
                ReceiptSigningError::SigningFailed(reason) => reason,
            };
            KernelError::ReceiptSigningFailed(message)
        })
    }

    /// Record the receipt and drive the bilateral co-signing hook when the
    /// request crosses a federation boundary.
    ///
    /// Local durability happens before remote co-signing. A co-sign
    /// failure can abort the caller's response path, but it must never
    /// create an externally visible remote side effect before the local
    /// receipt state is durable.
    pub(crate) fn record_chio_receipt_with_federation(
        &self,
        request: &crate::runtime::ToolCallRequest,
        receipt: &ChioReceipt,
        evaluation_context: &EvaluationReceiptContext,
    ) -> Result<(), KernelError> {
        // Persistence uses the admission-time peer-key snapshot installed
        // by the evaluate path. Re-resolving freshness here is unsafe: the
        // tool has already executed, so a peer that expires mid-dispatch
        // must not skip dual-sign evidence for the side effect admitted
        // under the fresh snapshot.
        self.record_terminal_chio_receipt(request, receipt, evaluation_context)?;
        let admitted_peer = if let Some(origin_kernel_id) =
            request.federated_origin_kernel_id.as_deref()
        {
            let request_admission = self.receipt_federation_admission_for_request(
                &request.request_id,
                request.federated_origin_kernel_id.as_deref(),
            );
            let thread_admission = current_scoped_receipt_federation_admission();
            let admission = evaluation_context
                .federation_admission
                .as_ref()
                .or(request_admission.as_ref())
                .or(thread_admission.as_ref())
                .ok_or_else(|| {
                    KernelError::Internal(format!(
                        "federation admission snapshot missing for origin kernel {origin_kernel_id}"
                    ))
                })?;
            if admission.remote_kernel_id.as_deref() != Some(origin_kernel_id) {
                return Err(KernelError::Internal(format!(
                    "federation admission snapshot does not match origin kernel {origin_kernel_id}"
                )));
            }
            let peer = admission.peer.as_ref().ok_or_else(|| {
                KernelError::Internal(format!(
                    "federation admission peer snapshot missing for origin kernel {origin_kernel_id}"
                ))
            })?;
            if peer.kernel_id != origin_kernel_id {
                return Err(KernelError::Internal(format!(
                    "federation admission peer snapshot identifies {} instead of {origin_kernel_id}",
                    peer.kernel_id
                )));
            }
            Some(peer.clone())
        } else {
            None
        };
        self.apply_federation_cosign(
            request,
            receipt,
            admitted_peer.as_ref(),
            evaluation_context.verified_treaty_material.as_ref(),
        )?;
        Ok(())
    }

    pub(super) fn record_chio_receipt_with_mode(
        &self,
        request: &crate::runtime::ToolCallRequest,
        receipt: &ChioReceipt,
        mode: ReceiptRecordMode,
        evaluation_context: &EvaluationReceiptContext,
    ) -> Result<(), KernelError> {
        match mode {
            ReceiptRecordMode::WithFederation => {
                self.record_chio_receipt_with_federation(request, receipt, evaluation_context)
            }
            ReceiptRecordMode::LocalOnly => self
                .record_chio_receipt_for_admitted_request_local_only(
                    request,
                    receipt,
                    evaluation_context,
                ),
        }
    }

    fn record_chio_receipt_for_admitted_request_local_only(
        &self,
        request: &crate::runtime::ToolCallRequest,
        receipt: &ChioReceipt,
        evaluation_context: &EvaluationReceiptContext,
    ) -> Result<(), KernelError> {
        // Persist the v1 deny receipt locally and
        // deliberately stop before the federation co-signature hook. The
        // runtime-admission deny path does not co-sign because the deny
        // decision is locally authoritative and may have been triggered
        // before any federation peer was contacted.
        self.record_terminal_chio_receipt(request, receipt, evaluation_context)
    }

    pub(crate) fn record_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), KernelError> {
        self.record_chio_receipt_inner(receipt, None, None, None)
    }

    fn record_terminal_chio_receipt(
        &self,
        request: &crate::runtime::ToolCallRequest,
        receipt: &ChioReceipt,
        evaluation_context: &EvaluationReceiptContext,
    ) -> Result<(), KernelError> {
        self.record_chio_receipt_inner(
            receipt,
            Some(request),
            Some(evaluation_context),
            Some(&request.request_id),
        )
    }

    /// Persist a receipt and atomically consume a matching durable dispatch
    /// intent when one is registered for `request_id`.
    #[cfg(test)]
    pub(crate) fn record_chio_receipt_consuming_optional_intent(
        &self,
        receipt: &ChioReceipt,
        request_id: Option<&str>,
    ) -> Result<(), KernelError> {
        self.record_chio_receipt_inner(receipt, None, None, request_id)
    }

    fn record_chio_receipt_inner(
        &self,
        receipt: &ChioReceipt,
        request: Option<&crate::runtime::ToolCallRequest>,
        evaluation_context: Option<&EvaluationReceiptContext>,
        request_id: Option<&str>,
    ) -> Result<(), KernelError> {
        // Serialize revocation and persistence before the store lock, then
        // release both locks before callbacks.
        let trace_transition = self.lock_runtime_trace_transition()?;
        if receipt.is_allowed() {
            if let Some(request) = request {
                self.check_revocation(&request.capability)?;
            } else if evaluation_context.is_some() {
                return Err(KernelError::Internal(
                    "terminal allow receipt persistence requires its admitted request".to_string(),
                ));
            }
        }
        let trace_event;
        // Scope the receipt-store write lock so it is released before the
        // settlement observer runs. Holding the mutex across
        // `run_settlement_observer` would serialize all concurrent receipt
        // persistence behind potentially I/O-bound hook latency; the observer
        // needs only a fully-persisted receipt, so the guard is dropped first.
        // Checkpoint construction runs on the store's writer actor, so this
        // critical section holds no checkpoint work.
        {
            let _receipt_store_write = self.receipt_store_write_lock.lock().map_err(|_| {
                KernelError::Internal("receipt store write lock poisoned".to_string())
            })?;
            if evaluation_context.is_some_and(|context| !context.begin_terminal_receipt_append()) {
                return Err(KernelError::Internal(
                    "terminal receipt persistence was already attempted for this evaluation"
                        .to_string(),
                ));
            }
            // Resolve the request's intent handle only under the write lock.
            // A request can persist more than one receipt concurrently (a
            // cleanup-fault receipt racing the terminal outcome), and the
            // first to commit consumes the durable row and drops the handle
            // below. A lookup before the lock would hand both callers the
            // handle and send the loser into the consuming append against
            // the already-deleted row; under the lock the loser observes the
            // removal and appends plainly.
            let intent = self.dispatch_intent_for_request(request_id);
            // Bound the commit round trip so a wedged writer cannot pin the
            // kernel-wide receipt write lock (and thus every subsequent tool
            // call) indefinitely. On timeout this fails closed with
            // ReceiptPersistence(Timeout); no allow response is signed until the
            // append succeeds.
            let budget = self.config.deadlines.receipt_append_budget();
            let append_result = match intent {
                Some(intent) => {
                    // The key binds the consume to the exact attested call:
                    // request id from the pre-dispatch handle, parameter hash
                    // and tenant from the receipt itself. Any disagreement
                    // aborts the transaction with the receipt unpersisted.
                    let key = crate::receipt_store::DispatchIntentKey {
                        request_id: intent.request_id,
                        parameter_hash: receipt.action.parameter_hash.clone(),
                        tenant_id: receipt.tenant_id.clone(),
                    };
                    match self.with_receipt_store(|store| {
                        Ok(store.append_chio_receipt_consuming_intent_with_timeout(
                            receipt, &key, budget,
                        ))
                    }) {
                        Ok(Some(Ok(sequence))) => {
                            // The consuming append deleted the durable
                            // row; drop the request-scoped handle under
                            // the same write lock so any later receipt
                            // for this request appends plainly instead of
                            // retrying the consume against the missing
                            // row.
                            self.mark_dispatch_intent_consumed(&key.request_id);
                            Ok(sequence)
                        }
                        Ok(Some(Err(error))) => {
                            // A timeout is an UNCERTAIN consume: the job
                            // is still queued on the single writer and
                            // may commit after this wait expired, so a
                            // retained handle could send a later receipt
                            // for the request back through the consume
                            // and reject it against a row the late commit
                            // already deleted. Drop the handle so later
                            // receipts append plainly; if the queued job
                            // never lands, the still-open row surfaces at
                            // the next boot instead of costing an audit
                            // record now. A definitive refusal (the row
                            // is provably still present) keeps the handle
                            // so the next receipt can consume it. This
                            // receipt's own error propagates unchanged
                            // either way.
                            if matches!(
                                error,
                                crate::receipt_store::ReceiptStoreError::Timeout { .. }
                            ) {
                                self.mark_dispatch_intent_consumed(&key.request_id);
                            }
                            Err(error.into())
                        }
                        Ok(None) => Ok(None),
                        Err(error) => Err(error),
                    }
                }
                None => match self.with_receipt_store(|store| {
                    Ok(store.append_chio_receipt_with_timeout(receipt, budget))
                }) {
                    Ok(Some(Ok(sequence))) => Ok(sequence),
                    Ok(Some(Err(error))) => Err(error.into()),
                    Ok(None) => Ok(None),
                    Err(error) => Err(error),
                },
            };
            if let Err(error) = append_result {
                warn!(
                    receipt_id = %receipt.id,
                    reason = %redacted!(&error),
                    audit_fault = "terminal_receipt_append_outcome_unknown",
                    "terminal receipt append returned an error after persistence began"
                );
                return Err(error);
            }
            self.append_chio_receipt_to_local_log(receipt.clone());
            if let Some(evaluation_context) = evaluation_context {
                evaluation_context.mark_terminal_receipt_committed();
            }
            trace_event = if self.runtime_trace_observer.is_some() {
                Some(RuntimeTraceEvent::ReceiptAppended {
                    source_sequence: self.allocate_runtime_trace_source_sequence()?,
                    receipt: Box::new(receipt.clone()),
                })
            } else {
                None
            };
        }
        drop(trace_transition);
        if let Some(event) = trace_event {
            self.observe_runtime_trace(event);
        }
        // The terminal receipt is durable: the money path's journal row (if
        // any) has served its purpose and closes. A crash before this close
        // leaves a row boot reconciliation closes against this receipt. The
        // close is state-aware: a row still in Settling belongs to a failed
        // or unconfirmed rail call and survives for boot reconciliation to
        // replay (see close_payment_journal_best_effort).
        if let Some(request_id) = request_id {
            self.close_payment_journal_best_effort(request_id);
        }
        let settlement_status = self.run_settlement_observer(receipt);
        self.route_settlement_observer_status(receipt, &settlement_status);
        Ok(())
    }

    /// Whether a durable receipt store is configured but no longer serving (its
    /// commit writer has died or its verified head is poisoned). This is exactly
    /// the condition the pre-dispatch persistence gate denies on, so the deny it
    /// produces must not try to append to the same store.
    fn receipt_store_serving_closed(&self) -> bool {
        matches!(
            self.with_receipt_store(|store| Ok(store.writer_serving_closed())),
            Ok(Some(true))
        )
    }

    /// Persist a fail-closed deny receipt, tolerating a serving-closed durable
    /// store. Several pre-dispatch gates deny precisely because the durable
    /// receipt writer can no longer persist; appending this deny receipt to that
    /// same closed store would fail and mask a clean signed Deny as an opaque
    /// error. A deny executes no tool, so nothing is admitted without a durable
    /// receipt: when the store is serving-closed, record the signed deny in the
    /// in-memory log for local audit and surface the verdict instead of failing.
    /// When the store is serving, persist durably as usual.
    pub(crate) fn record_failclosed_deny_receipt(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<(), KernelError> {
        if self.receipt_store_serving_closed() {
            self.append_chio_receipt_to_local_log(receipt.clone());
            return Ok(());
        }
        self.record_chio_receipt(receipt)
    }
}

#[cfg(test)]
mod coupling_tests {
    use super::*;

    struct Fixture {
        body: ChioReceiptBody,
        action: ToolCallAction,
        decision: Decision,
        content_hash: String,
        policy_hash: String,
    }

    impl Fixture {
        fn expectation(&self) -> ReceiptCouplingExpectation<'_> {
            ReceiptCouplingExpectation {
                capability_id: "cap",
                server_id: "server",
                tool_name: "tool",
                action: &self.action,
                decision: &self.decision,
                content_hash: &self.content_hash,
                policy_hash: &self.policy_hash,
                trust_level: chio_core::receipt::kinds::TrustLevel::Mediated,
            }
        }
    }

    fn fixture() -> Fixture {
        let action = ToolCallAction::from_parameters(serde_json::json!({"key": "value"}))
            .expect("test action is canonicalizable");
        let decision = Decision::Allow;
        let content_hash = "content-hash".to_string();
        let policy_hash = "policy-hash".to_string();
        let body = ChioReceiptBody {
            id: "receipt".to_string(),
            timestamp: 1,
            capability_id: "cap".to_string(),
            tool_server: "server".to_string(),
            tool_name: "tool".to_string(),
            action: action.clone(),
            decision: Some(decision.clone()),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: content_hash.clone(),
            policy_hash: policy_hash.clone(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: Keypair::from_seed(&[7; 32]).public_key(),
            bbs_projection_version: None,
        };
        Fixture {
            body,
            action,
            decision,
            content_hash,
            policy_hash,
        }
    }

    fn assert_signing_refused(fixture: &Fixture) {
        assert!(matches!(
            require_receipt_body_fields_coupled(&fixture.body, &fixture.expectation()),
            Err(KernelError::ReceiptSigningFailed(_))
        ));
    }

    fn assert_body_mutation_refused(mutate: impl FnOnce(&mut ChioReceiptBody)) {
        let mut fixture = fixture();
        mutate(&mut fixture.body);
        assert_signing_refused(&fixture);
    }

    #[test]
    fn rejects_capability_mismatch() {
        let mut fixture = fixture();
        fixture.body.capability_id = "other-cap".to_string();
        assert_signing_refused(&fixture);
    }

    #[test]
    fn rejects_request_mismatch() {
        assert_body_mutation_refused(|body| body.tool_name = "other-tool".to_string());
    }

    #[test]
    fn rejects_every_request_subfield_mismatch() {
        assert_body_mutation_refused(|body| body.tool_server = "other-server".to_string());
        assert_body_mutation_refused(|body| {
            body.action.parameters = serde_json::json!({"other": "value"});
        });
        assert_body_mutation_refused(|body| {
            body.action.parameter_hash = "other-parameter-hash".to_string();
        });
        assert_body_mutation_refused(|body| body.content_hash = "other-content".to_string());
    }

    #[test]
    fn rejects_verdict_mismatch() {
        let mut fixture = fixture();
        fixture.body.decision = Some(Decision::Deny {
            reason: "denied".to_string(),
            guard: "guard".to_string(),
        });
        assert_signing_refused(&fixture);
    }

    #[test]
    fn rejects_policy_hash_mismatch() {
        let mut fixture = fixture();
        fixture.body.policy_hash = "other-policy".to_string();
        assert_signing_refused(&fixture);
    }

    #[test]
    fn rejects_evidence_class_mismatch() {
        assert_body_mutation_refused(|body| body.boundary_class = BoundaryClass::AdvisoryOnly);
    }

    #[test]
    fn rejects_every_evidence_subfield_mismatch() {
        assert_body_mutation_refused(|body| body.receipt_kind = ReceiptKind::TraceObservation);
        assert_body_mutation_refused(|body| {
            body.observation_outcome =
                Some(chio_core::receipt::kinds::ObservationOutcome::Observed);
        });
        assert_body_mutation_refused(|body| {
            body.tool_origin = ToolOrigin::HostExecutedProviderReported;
        });
        assert_body_mutation_refused(|body| body.redaction_mode = RedactionMode::Summary);
        assert_body_mutation_refused(|body| {
            body.actor_chain = vec![chio_core::receipt::metadata::ActorRef {
                actor_id: "actor".to_string(),
                actor_kind: None,
            }];
        });
        assert_body_mutation_refused(|body| {
            body.trust_level = chio_core::receipt::kinds::TrustLevel::Verified;
        });
    }
}
