use super::*;

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
        let tenant_id = match params.tenant_id.clone() {
            Some(tenant_id) => Some(tenant_id),
            None => self
                .receipt_tenant_id_for_request(params.request_id)
                .unwrap_or_else(current_scoped_receipt_tenant_id),
        };

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
            action: params.action,
            decision: Some(params.decision),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: params.content_hash,
            policy_hash: self.config.policy_hash.clone(),
            evidence,
            metadata,
            trust_level: params.trust_level,
            tenant_id,
            kernel_key: self.config.keypair.public_key(),
            bbs_projection_version: None,
        };

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
    ) -> Result<(), KernelError> {
        // Persistence uses the admission-time peer-key snapshot installed
        // by the evaluate path. Re-resolving freshness here is unsafe: the
        // tool has already executed, so a peer that expires mid-dispatch
        // must not skip dual-sign evidence for the side effect admitted
        // under the fresh snapshot.
        let request_admission = self.receipt_federation_admission_for_request(
            &request.request_id,
            request.federated_origin_kernel_id.as_deref(),
        );
        let thread_admission = current_scoped_receipt_federation_admission();
        let thread_admission = thread_admission.as_ref().filter(|admission| {
            admission.remote_kernel_id.as_deref() == request.federated_origin_kernel_id.as_deref()
        });
        let scoped_admission = request_admission.as_ref().or(thread_admission);
        self.record_chio_receipt_consuming_optional_intent(receipt, Some(&request.request_id))?;
        self.apply_federation_cosign(
            request,
            receipt,
            scoped_admission.and_then(|admission| admission.peer.as_ref()),
        )?;
        Ok(())
    }

    pub(super) fn record_chio_receipt_with_mode(
        &self,
        request: &crate::runtime::ToolCallRequest,
        receipt: &ChioReceipt,
        mode: ReceiptRecordMode,
    ) -> Result<(), KernelError> {
        match mode {
            ReceiptRecordMode::WithFederation => {
                self.record_chio_receipt_with_federation(request, receipt)
            }
            ReceiptRecordMode::LocalOnly => {
                self.record_chio_receipt_for_admitted_request_local_only(request, receipt)
            }
        }
    }

    fn record_chio_receipt_for_admitted_request_local_only(
        &self,
        request: &crate::runtime::ToolCallRequest,
        receipt: &ChioReceipt,
    ) -> Result<(), KernelError> {
        // Persist the v1 deny receipt locally and
        // deliberately stop before the federation co-signature hook. The
        // runtime-admission deny path does not co-sign because the deny
        // decision is locally authoritative and may have been triggered
        // before any federation peer was contacted.
        self.record_chio_receipt_consuming_optional_intent(receipt, Some(&request.request_id))
    }

    pub(crate) fn record_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), KernelError> {
        self.record_chio_receipt_consuming_optional_intent(receipt, None)
    }

    /// Persist a terminal receipt and, when the request journaled a dispatch
    /// intent, consume that intent in the SAME transaction as the receipt
    /// insert. Request-id-less callers pass `None` and get the plain append.
    /// The request-aware sinks pass the request id, so allow, post-dispatch
    /// deny, cancelled, and incomplete receipts all consume the intent and an
    /// effecting call that ends in any terminal receipt leaves no false
    /// orphan behind.
    pub(crate) fn record_chio_receipt_consuming_optional_intent(
        &self,
        receipt: &ChioReceipt,
        request_id: Option<&str>,
    ) -> Result<(), KernelError> {
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
            match intent {
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
                    let append = self.with_receipt_store(|store| {
                        Ok(store.append_chio_receipt_consuming_intent_with_timeout(
                            receipt, &key, budget,
                        ))
                    })?;
                    if let Some(append) = append {
                        match append {
                            Ok(_) => {
                                // The consuming append deleted the durable
                                // row; drop the request-scoped handle under
                                // the same write lock so any later receipt
                                // for this request appends plainly instead of
                                // retrying the consume against the missing
                                // row.
                                self.mark_dispatch_intent_consumed(&key.request_id);
                            }
                            Err(error) => {
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
                                return Err(error.into());
                            }
                        }
                    }
                }
                None => {
                    self.with_receipt_store(|store| {
                        Ok(store.append_chio_receipt_with_timeout(receipt, budget)?)
                    })?;
                }
            }
            self.append_chio_receipt_to_local_log(receipt.clone());
        }
        let _settlement_status = self.run_settlement_observer(receipt);
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
