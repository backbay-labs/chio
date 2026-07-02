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
        //   3. The active scoped tenant context set by the evaluate path
        //      from `session.auth_context().enterprise_identity.tenant_id`.
        //
        // Tenant_id is never taken from a caller-provided field on the
        // request: allowing caller choice would defeat the isolation the
        // store-level WHERE clause enforces.
        let tenant_id = params
            .tenant_id
            .clone()
            .or_else(|| self.receipt_tenant_id_for_request(params.request_id))
            .or_else(current_scoped_receipt_tenant_id);

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
        // render-A / sign-B hole on the production path (BAC-539). The
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
        self.record_chio_receipt(receipt)?;
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
        _request: &crate::runtime::ToolCallRequest,
        receipt: &ChioReceipt,
    ) -> Result<(), KernelError> {
        // Persist the v1 deny receipt locally and
        // deliberately stop before the federation co-signature hook. The
        // runtime-admission deny path does not co-sign because the deny
        // decision is locally authoritative and may have been triggered
        // before any federation peer was contacted.
        self.record_chio_receipt(receipt)
    }

    pub(crate) fn record_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), KernelError> {
        // Scope the receipt-store write lock so it is released before
        // the settlement observer runs. Holding the mutex across
        // `run_settlement_observer` would serialize all concurrent
        // receipt persistence behind potentially I/O-bound hook
        // latency; the observer needs only a fully-persisted receipt,
        // so the guard is dropped first.
        {
            let _receipt_store_write = self.receipt_store_write_lock.lock().map_err(|_| {
                KernelError::Internal("receipt store write lock poisoned".to_string())
            })?;
            if let Some(seq) = self
                .with_receipt_store(|store| Ok(store.append_chio_receipt_returning_seq(receipt)?))?
                .flatten()
            {
                if self.should_checkpoint_after_seq(seq) {
                    self.maybe_trigger_checkpoint_locked(seq)?;
                }
            }
            self.append_chio_receipt_to_local_log(receipt.clone());
        }
        let _settlement_status = self.run_settlement_observer(receipt);
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
            self.refresh_checkpoint_counters_from_store()?;
            let last_checkpoint_seq = self.last_checkpoint_seq.load(Ordering::SeqCst);
            if batch_end_seq <= last_checkpoint_seq {
                return Ok(());
            }

            match self.with_receipt_store(|store| {
                Ok(store.create_next_receipt_checkpoint(
                    self.checkpoint_batch_size,
                    &self.config.keypair,
                )?)
            }) {
                Ok(Some(report)) if report.created => {
                    if let Some(checkpoint_seq) = report.checkpoint_seq {
                        self.checkpoint_seq_counter
                            .store(checkpoint_seq, Ordering::SeqCst);
                    }
                    self.last_checkpoint_seq
                        .store(report.latest_checkpointed_entry_seq, Ordering::SeqCst);
                    return Ok(());
                }
                Ok(Some(_)) | Ok(None) => {
                    self.refresh_checkpoint_counters_from_store()?;
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
