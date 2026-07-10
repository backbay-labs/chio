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
            self.with_receipt_store(|store| Ok(store.append_chio_receipt_returning_seq(receipt)?))?;
            self.append_chio_receipt_to_local_log(receipt.clone());
        }
        let _settlement_status = self.run_settlement_observer(receipt);
        Ok(())
    }
}
