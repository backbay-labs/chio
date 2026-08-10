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

fn receipts_match(left: &ChioReceipt, right: &ChioReceipt) -> Result<bool, KernelError> {
    let left = chio_core::canonical::canonical_json_bytes(left)
        .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
    let right = chio_core::canonical::canonical_json_bytes(right)
        .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
    Ok(left == right)
}

impl ChioKernel {
    /// Sign the exact state transition a qualified finding-pool backend is
    /// about to commit. The backend stores this receipt in its transaction,
    /// then the kernel copies the durable outbox entry into the ordinary
    /// receipt log.
    #[cfg(feature = "cognition-market-experimental")]
    pub(crate) fn build_finding_pool_mutation_receipt(
        &self,
        mutation: &crate::finding_pool::FindingPoolMutation,
    ) -> Result<ChioReceipt, KernelError> {
        let parameters = serde_json::to_value(mutation)
            .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?;
        let action = ToolCallAction::from_parameters(parameters.clone())
            .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?;
        let canonical_content = chio_core::canonical::canonical_json_bytes(mutation)
            .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?;
        let content_hash = chio_core::crypto::sha256_hex(&canonical_content);
        let timestamp = mutation
            .occurred_at_unix_ms
            .parse::<u64>()
            .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?
            / 1_000;
        let authority = self
            .finding_pool_receipt_authority
            .as_ref()
            .ok_or_else(|| {
                KernelError::ReceiptSigningFailed(
                    crate::finding_pool::FindingPoolLedgerError::ReceiptAuthorityMissing
                        .to_string(),
                )
            })?;
        self.build_and_sign_receipt_with_authority(
            ReceiptParams {
                request_id: None,
                capability_id: &mutation.allocation_envelope_sha256,
                tool_name: "finding_pool_mutation",
                server_id: "chio-kernel",
                decision: Decision::Allow,
                action,
                content_hash,
                canonical_content,
                metadata: Some(serde_json::json!({
                    "finding_pool_mutation": parameters,
                })),
                timestamp,
                trust_level: chio_core::receipt::kinds::TrustLevel::Mediated,
                tenant_id: None,
            },
            authority,
        )
    }

    /// Build and sign a receipt from a `ReceiptParams` descriptor.
    pub(crate) fn build_and_sign_receipt(
        &self,
        params: ReceiptParams<'_>,
    ) -> Result<ChioReceipt, KernelError> {
        self.build_and_sign_receipt_with_authority(params, &self.config.keypair)
    }

    fn build_and_sign_receipt_with_authority(
        &self,
        params: ReceiptParams<'_>,
        authority: &chio_core::crypto::Keypair,
    ) -> Result<ChioReceipt, KernelError> {
        let expected_action = params.action.clone();
        let expected_decision = params.decision.clone();
        let expected_content_hash = params.content_hash.clone();
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
            kernel_key: authority.public_key(),
            bbs_projection_version: None,
        };
        let expected = ReceiptCouplingExpectation {
            capability_id: params.capability_id,
            server_id: params.server_id,
            tool_name: params.tool_name,
            action: &expected_action,
            decision: &expected_decision,
            content_hash: &expected_content_hash,
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
        let backend = chio_core::crypto::Ed25519Backend::new(authority.clone());
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
        let thread_admission = thread_admission.as_ref();
        let trace_transition = self.lock_runtime_trace_transition()?;
        if receipt.is_allowed() {
            self.check_revocation(&request.capability)?;
        }
        let (trace_event, settlement_visible_at_ms) =
            self.record_chio_receipt_during_trace_transition(receipt, &trace_transition, true)?;
        drop(trace_transition);
        self.finish_record_chio_receipt(receipt, trace_event, settlement_visible_at_ms)?;
        self.apply_federation_cosign_for_admitted_request_with_snapshot(
            request,
            receipt,
            request_admission.as_ref().or(thread_admission),
        )?;
        Ok(())
    }

    pub(crate) fn apply_federation_cosign_for_admitted_request(
        &self,
        request: &crate::runtime::ToolCallRequest,
        receipt: &ChioReceipt,
    ) -> Result<(), KernelError> {
        let request_admission = self.receipt_federation_admission_for_request(
            &request.request_id,
            request.federated_origin_kernel_id.as_deref(),
        );
        let thread_admission = current_scoped_receipt_federation_admission();
        let thread_admission = thread_admission.as_ref();
        self.apply_federation_cosign_for_admitted_request_with_snapshot(
            request,
            receipt,
            request_admission.as_ref().or(thread_admission),
        )
    }

    fn apply_federation_cosign_for_admitted_request_with_snapshot(
        &self,
        request: &crate::runtime::ToolCallRequest,
        receipt: &ChioReceipt,
        admission: Option<&ReceiptFederationAdmission>,
    ) -> Result<(), KernelError> {
        self.apply_federation_cosign(request, receipt, admission)
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
        let trace_transition = self.lock_runtime_trace_transition()?;
        let (trace_event, settlement_visible_at_ms) =
            self.record_chio_receipt_during_trace_transition(receipt, &trace_transition, true)?;
        drop(trace_transition);
        self.finish_record_chio_receipt(receipt, trace_event, settlement_visible_at_ms)
    }

    /// Persist an internal audit receipt without presenting it to the
    /// financial settlement observer. The durable receipt store and local
    /// trace still receive the exact signed receipt.
    pub(crate) fn record_chio_receipt_without_settlement(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<(), KernelError> {
        let trace_transition = self.lock_runtime_trace_transition()?;
        let (trace_event, settlement_visible_at_ms) =
            self.record_chio_receipt_during_trace_transition(receipt, &trace_transition, false)?;
        drop(trace_transition);
        self.finish_record_chio_receipt(receipt, trace_event, settlement_visible_at_ms)
    }

    fn record_chio_receipt_during_trace_transition(
        &self,
        receipt: &ChioReceipt,
        _trace_transition: &std::sync::MutexGuard<'_, ()>,
        settlement_eligible: bool,
    ) -> Result<(Option<RuntimeTraceEvent>, Option<u64>), KernelError> {
        let settlement_visible_at_ms = if settlement_eligible {
            self.settlement_observer
                .as_ref()
                .map(|_| current_unix_timestamp_ms())
        } else {
            None
        };
        {
            let _receipt_store_write = self.receipt_store_write_lock.lock().map_err(|_| {
                KernelError::Internal("receipt store write lock poisoned".to_string())
            })?;
            if let Some(next_visible_at_ms) = settlement_visible_at_ms {
                self.with_receipt_store(|store| {
                    Ok(
                        store.append_chio_receipt_with_pending_observation_and_timeout(
                            receipt,
                            &PendingSettlementObservation { next_visible_at_ms },
                            self.config.deadlines.receipt_append_budget(),
                        )?,
                    )
                })
                .inspect_err(|_| {
                    // The critical write is inflight-preserving on expiry, so the
                    // attempt row may still commit after this caller gives up.
                    // Surface it as due work instead of losing it on the timeout.
                    crate::settlement_routing::record_unresolved_claim_missed(&receipt.id);
                })?;
            } else {
                // Bound the commit round trip so a wedged writer cannot pin
                // the kernel-wide receipt write lock indefinitely. On timeout
                // this fails closed before an allow response is signed.
                self.with_receipt_store(|store| {
                    Ok(store.append_chio_receipt_with_timeout(
                        receipt,
                        self.config.deadlines.receipt_append_budget(),
                    )?)
                })?;
            }
            self.append_chio_receipt_to_local_log(receipt.clone());
        }
        let trace_event = if self.runtime_trace_observer.is_some() {
            Some(RuntimeTraceEvent::ReceiptAppended {
                source_sequence: self.allocate_runtime_trace_source_sequence()?,
                receipt: Box::new(receipt.clone()),
            })
        } else {
            None
        };
        Ok((trace_event, settlement_visible_at_ms))
    }

    fn finish_record_chio_receipt(
        &self,
        receipt: &ChioReceipt,
        trace_event: Option<RuntimeTraceEvent>,
        settlement_visible_at_ms: Option<u64>,
    ) -> Result<(), KernelError> {
        if let Some(event) = trace_event {
            self.observe_runtime_trace(event);
        }

        let Some(runtime) = self.settlement_observer.as_ref() else {
            return Ok(());
        };
        let Some(next_visible_at_ms) = settlement_visible_at_ms else {
            return Ok(());
        };
        let claim_now_ms = current_unix_timestamp_ms().max(next_visible_at_ms);
        let claim = match runtime.claim_receipt(&receipt.id, receipt.timestamp, claim_now_ms) {
            Ok(Some(claim)) => claim,
            Ok(None) => {
                // The attempt row this transaction seeded is already leased or in
                // an unexpected state. It stays due for a later claim, so surface
                // the miss rather than dropping it silently.
                crate::settlement_routing::record_unresolved_claim_missed(&receipt.id);
                return Ok(());
            }
            Err(error) => {
                crate::settlement_routing::record_unresolved_claim_failure(&receipt.id, &error);
                return Ok(());
            }
        };
        let idempotency_key = chio_settle::SettlementIdempotencyKey {
            receipt_id: claim.receipt_id.clone(),
            row_version: claim.row_version,
        };
        let status = self.run_settlement_observer(receipt, &idempotency_key);
        runtime.record_claimed_status(
            &claim,
            &status,
            current_unix_timestamp_ms().max(claim_now_ms),
        );
        Ok(())
    }

    pub(crate) fn materialize_durable_admission_receipt(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<(), KernelError> {
        if self.receipt_store.is_none() {
            return Ok(());
        }
        // Seed the settlement attempt alongside the durable receipt exactly as
        // `record_chio_receipt` does on the non-durable path. The terminal
        // projection records observation-attempt-zero as due work, but the
        // claimable `settle_attempts` row only exists once the receipt is
        // appended with a pending observation, so without this branch a durable
        // monetary receipt strands its observation with nothing for the
        // settlement observer to claim. Seeding only on the first append keeps
        // it exactly-once: a replay finds the receipt already present.
        let settlement_visible_at_ms = self
            .settlement_observer
            .as_ref()
            .map(|_| current_unix_timestamp_ms());
        let _receipt_store_write = self
            .receipt_store_write_lock
            .lock()
            .map_err(|_| KernelError::Internal("receipt store write lock poisoned".to_string()))?;
        self.with_receipt_store(|store| match store.load_chio_receipt(&receipt.id)? {
            Some(existing) => {
                if receipts_match(&existing, receipt)? {
                    Ok(())
                } else {
                    Err(KernelError::DurableAdmission(format!(
                        "receipt projection {} conflicts with the canonical admission receipt",
                        receipt.id
                    )))
                }
            }
            None => {
                if let Some(next_visible_at_ms) = settlement_visible_at_ms {
                    store.append_chio_receipt_with_pending_observation_and_timeout(
                        receipt,
                        &PendingSettlementObservation { next_visible_at_ms },
                        self.config.deadlines.receipt_append_budget(),
                    )?;
                } else {
                    store.append_chio_receipt_with_timeout(
                        receipt,
                        self.config.deadlines.receipt_append_budget(),
                    )?;
                }
                Ok(())
            }
        })?;
        Ok(())
    }

    pub(crate) fn mirror_durable_admission_receipt(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<(), KernelError> {
        let mut log = match self.receipt_log.lock() {
            Ok(log) => log,
            Err(poisoned) => poisoned.into_inner(),
        };
        let existing = log
            .iter()
            .find(|existing| existing.id == receipt.id)
            .cloned();
        match existing {
            Some(existing) => {
                if receipts_match(&existing, receipt)? {
                    Ok(())
                } else {
                    Err(KernelError::DurableAdmission(format!(
                        "local receipt mirror {} conflicts with the canonical admission receipt",
                        receipt.id
                    )))
                }
            }
            None => {
                log.append(receipt.clone());
                Ok(())
            }
        }
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
