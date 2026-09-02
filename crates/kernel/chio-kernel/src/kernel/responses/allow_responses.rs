use super::*;

pub(crate) enum ReservedHoldStamp<'a> {
    Monetary {
        charge: &'a BudgetChargeResult,
        payment_reference: Option<String>,
    },
    Invocation {
        hold_id: String,
        grant_index: usize,
    },
}

impl ReservedHoldStamp<'_> {
    fn hold_id(&self) -> &str {
        match self {
            Self::Monetary { charge, .. } => charge.budget_hold_id.as_str(),
            Self::Invocation { hold_id, .. } => hold_id.as_str(),
        }
    }
}

pub(crate) enum AllowResponseNonce {
    Preminted(Box<crate::execution_nonce::SignedExecutionNonce>),
    MintForAllow,
    Suppressed,
}

impl ChioKernel {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_allow_response_with_metadata_and_payee_binding(
        &self,
        request: &ToolCallRequest,
        output: ToolCallOutput,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
        nonce: AllowResponseNonce,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        if let Err(error) = self.check_revocation(cap) {
            let reason =
                format!("capability authorization changed before allow finalization: {error}");
            return self.build_deny_response_with_metadata_and_payee_binding(
                request,
                &reason,
                timestamp,
                matched_grant_index,
                extra_metadata,
                verified_payee_binding,
            );
        }
        let expected_chunks = match &output {
            ToolCallOutput::Stream(stream) => Some(stream.chunk_count()),
            ToolCallOutput::Value(_) => None,
        };
        let receipt_content = receipt_content_for_output(Some(&output), expected_chunks)?;

        // Classify the call against the memory-provenance action conventions
        // and, for reads, look up the latest chain entry BEFORE the receipt
        // is signed so the provenance evidence rides in the signed metadata.
        // Writes append AFTER signing (see below) because the chain entry
        // needs the receipt id.
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
        let request_metadata = request_receipt_metadata_with_payee_binding(
            request,
            self.attestation_trust_policy.as_ref(),
            timestamp,
            extra_metadata.as_ref(),
            verified_payee_binding,
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
            request_id: Some(&request.request_id),
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Allow,
            action,
            content_hash: receipt_content.content_hash,
            canonical_content: receipt_content.canonical_content,
            metadata,
            timestamp,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })?;

        self.record_chio_receipt_with_federation(request, &receipt)?;

        info!(
            request_id = %request.request_id,
            tool = %request.tool_name,
            receipt_id = %receipt.id,
            "tool call allowed"
        );

        // For governed writes, append an entry to the provenance chain once
        // the receipt is signed. A failure here is fatal (fail-closed): we
        // do not want to acknowledge the write to the caller while silently
        // dropping provenance.
        if let Some(crate::memory_provenance::MemoryActionKind::Write { store, key }) =
            memory_action_kind.as_ref()
        {
            self.append_memory_provenance_for_write(store, key, request, &receipt)?;
        }

        // Mint a short-lived, single-use execution nonce for allow responses
        // that did not already present one. A request that consumed a nonce
        // to execute must not chain-mint a replacement for the same call.
        let execution_nonce = match nonce {
            AllowResponseNonce::Preminted(nonce) => Some(nonce),
            AllowResponseNonce::MintForAllow => {
                self.mint_execution_nonce_for_allow(request, cap, &receipt)?
            }
            AllowResponseNonce::Suppressed => None,
        };

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

    pub(crate) fn build_execution_nonce_preflight_allow_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
        incomplete_reason: &str,
        reserved_hold: Option<ReservedHoldStamp<'_>>,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let receipt_content = receipt_content_for_output(None, None)?;
        let request_metadata = request_receipt_metadata(
            request,
            self.attestation_trust_policy.as_ref(),
            timestamp,
            extra_metadata.as_ref(),
        )?;
        let metadata = merge_metadata_objects(
            merge_metadata_objects(
                merge_metadata_objects(receipt_content.metadata, request_metadata),
                extra_metadata,
            ),
            receipt_attribution_metadata(cap, matched_grant_index),
        );

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            request_id: Some(&request.request_id),
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Incomplete {
                reason: incomplete_reason.to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            canonical_content: receipt_content.canonical_content,
            metadata,
            timestamp,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })?;

        let execution_nonce = self.mint_execution_nonce_for_allow_reserving(
            request,
            cap,
            &receipt,
            reserved_hold.as_ref().map(ReservedHoldStamp::hold_id),
        )?;

        if let (Some(stamp), Some(nonce)) = (reserved_hold.as_ref(), execution_nonce.as_ref()) {
            let reserved_until = nonce.expires_at();
            match stamp {
                ReservedHoldStamp::Monetary {
                    charge,
                    payment_reference,
                } => {
                    let envelope = crate::budget_store::ReservedHoldEnvelope {
                        budget_total: Some(charge.budget_total),
                        delegation_depth: cap.delegation_chain.len() as u32,
                        root_budget_holder: cap.issuer.to_hex(),
                    };
                    if let Err(error) = self.with_budget_store(|store| {
                        Ok(store.mark_hold_reserved(
                            charge.budget_hold_id.as_str(),
                            reserved_until,
                            charge.currency.as_str(),
                            payment_reference.as_deref(),
                            &envelope,
                        )?)
                    }) {
                        self.reverse_budget_charge(&cap.id, charge)?;
                        self.release_admitted_capability_budget(cap)
                            .map_err(KernelError::DelegationInvalid)?;
                        return Err(error);
                    }
                    self.record_reserved_sibling_share(charge.budget_hold_id.as_str(), cap);
                }
                ReservedHoldStamp::Invocation {
                    hold_id,
                    grant_index,
                } => {
                    let envelope = crate::budget_store::ReservedHoldEnvelope {
                        budget_total: None,
                        delegation_depth: cap.delegation_chain.len() as u32,
                        root_budget_holder: cap.issuer.to_hex(),
                    };
                    if let Err(error) = self.with_budget_store(|store| {
                        Ok(store.reserve_invocation_hold(
                            hold_id,
                            &cap.id,
                            *grant_index,
                            reserved_until,
                            &envelope,
                        )?)
                    }) {
                        self.with_budget_store(|store| {
                            Ok(store.reverse_charge_cost(&cap.id, *grant_index, 0)?)
                        })?;
                        self.release_admitted_capability_budget(cap)
                            .map_err(KernelError::DelegationInvalid)?;
                        return Err(error);
                    }
                    self.record_reserved_sibling_share(hold_id, cap);
                }
            }
        }

        if let Err(error) = self.record_chio_receipt_with_federation(request, &receipt) {
            warn!(
                request_id = %request.request_id,
                hold_id = reserved_hold.as_ref().map(ReservedHoldStamp::hold_id),
                receipt_id = %receipt.id,
                reason = %redacted!(&error),
                "durable receipt persistence failed for a stamped reservation"
            );
        }

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Allow,
            output: None,
            reason: None,
            terminal_state: OperationTerminalState::Incomplete {
                reason: incomplete_reason.to_string(),
            },
            receipt,
            execution_nonce,
        })
    }

    /// Build receipt metadata describing the provenance record that governs
    /// the memory read identified by `(store, key)`.
    ///
    /// Returns `None` when no provenance store has been installed
    /// (backward-compatible no-op), and returns an `unverified` metadata
    /// object when the store is installed but the key has no chain
    /// entry OR the chain is tampered / unavailable. This is the
    /// fail-closed signal: the receipt explicitly records that the
    /// memory read was not backed by a provenance record.
    pub(crate) fn resolve_memory_read_provenance_metadata(
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
                    error = %redacted!(&error),
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
                    error = %redacted!(&error),
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

    /// Validate the authenticated delivery, exact content, and durable parent
    /// receipt for a governed Finding memory write before tool dispatch.
    pub(crate) fn validate_finding_memory_write_admission(
        &self,
        request: &ToolCallRequest,
    ) -> Result<(), KernelError> {
        let Some(binding) = request
            .arguments
            .get(crate::memory_provenance::FINDING_DELIVERY_RECEIPT_ID_ARGUMENT)
        else {
            return Ok(());
        };
        let Some(crate::memory_provenance::MemoryActionKind::Write { key, .. }) =
            crate::memory_provenance::classify_memory_action(
                &request.tool_name,
                &request.arguments,
            )
        else {
            return Err(KernelError::Internal(
                "Finding delivery lineage requires a governed memory write".to_owned(),
            ));
        };
        if request.governed_intent.is_none() {
            return Err(KernelError::Internal(
                "Finding delivery lineage requires a governed memory write".to_owned(),
            ));
        }
        if self.memory_provenance_store().is_none() {
            return Err(KernelError::Internal(
                "Finding memory write requires a memory provenance store".to_owned(),
            ));
        }
        let guard_context = GuardContext {
            request,
            scope: &request.capability.scope,
            agent_id: &request.agent_id,
            server_id: &request.server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };
        let mut required_status_feed: Option<String> = None;
        for guard in self.guards.iter() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                guard.required_finding_status_feed_id(&guard_context)
            }));
            let feed_id = match result {
                Ok(result) => result?,
                Err(_) => {
                    return Err(KernelError::GuardDenied(
                        "Finding memory guard feed requirement panicked (fail-closed)".to_owned(),
                    ));
                }
            };
            let Some(feed_id) = feed_id else {
                continue;
            };
            if required_status_feed
                .as_deref()
                .is_some_and(|required| required != feed_id)
            {
                return Err(KernelError::GuardDenied(
                    "Finding memory guards require different status feeds".to_owned(),
                ));
            }
            required_status_feed = Some(feed_id);
        }
        let parent_receipt_id = binding
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                KernelError::Internal(
                    "Finding delivery receipt binding must be a nonempty string".to_owned(),
                )
            })?;
        let Some(()) = self.with_receipt_store(|store| {
            let parent = store
                .load_retained_chio_receipt(parent_receipt_id)?
                .ok_or_else(|| {
                    KernelError::Internal(
                        "Finding delivery receipt binding is not durably available".to_owned(),
                    )
                })?;
            if parent.id != parent_receipt_id
                || !parent.is_allowed()
                || !self
                    .finding_delivery_receipt_authorities
                    .contains(&parent.kernel_key)
                || !parent.verify_signature().map_err(|error| {
                    KernelError::Internal(format!(
                        "Finding delivery receipt signature verification failed: {error}"
                    ))
                })?
            {
                return Err(KernelError::Internal(
                    "Finding delivery receipt binding is not an authentic allow receipt".to_owned(),
                ));
            }
            let delivery: chio_core::receipt::metadata::FindingDelivery = parent
                .metadata
                .as_ref()
                .and_then(|metadata| {
                    metadata.get(chio_core::receipt::metadata::FINDING_DELIVERY_METADATA_KEY)
                })
                .cloned()
                .ok_or_else(|| {
                    KernelError::Internal(
                        "Finding delivery receipt binding has no typed delivery metadata"
                            .to_owned(),
                    )
                })
                .and_then(|value| {
                    serde_json::from_value(value).map_err(|error| {
                        KernelError::Internal(format!(
                            "Finding delivery receipt metadata is malformed: {error}"
                        ))
                    })
                })?;
            delivery.validate().map_err(|error| {
                KernelError::Internal(format!(
                    "Finding delivery receipt metadata is invalid: {error}"
                ))
            })?;
            let status_proof = delivery.status_proof.as_ref().ok_or_else(|| {
                KernelError::Internal(
                    "Finding memory write requires a delivery status proof".to_owned(),
                )
            })?;
            if required_status_feed
                .as_deref()
                .is_some_and(|required| status_proof.feed_id != required)
            {
                return Err(KernelError::Internal(
                    "Finding delivery status feed differs from the installed quarantine resolver"
                        .to_owned(),
                ));
            }
            if delivery.finding_id != key
                || delivery.digest_check != chio_core::receipt::metadata::DeliveryResult::Matched
                || delivery.media_type_check
                    != chio_core::receipt::metadata::FindingMediaTypeCheck::Matched
            {
                return Err(KernelError::Internal(
                    "Finding delivery receipt does not authorize this memory entry".to_owned(),
                ));
            }
            let contract: chio_core::receipt::metadata::DeliveryContract = parent
                .metadata
                .as_ref()
                .and_then(|metadata| {
                    metadata.get(chio_core::receipt::metadata::DELIVERY_CONTRACT_METADATA_KEY)
                })
                .cloned()
                .ok_or_else(|| {
                    KernelError::Internal(
                        "Finding delivery receipt has no typed delivery contract".to_owned(),
                    )
                })
                .and_then(|value| {
                    serde_json::from_value(value).map_err(|error| {
                        KernelError::Internal(format!(
                            "Finding delivery contract metadata is malformed: {error}"
                        ))
                    })
                })?;
            contract.validate().map_err(|error| {
                KernelError::Internal(format!(
                    "Finding delivery contract metadata is invalid: {error}"
                ))
            })?;
            let written_content = request.arguments.get("content").ok_or_else(|| {
                KernelError::Internal(
                    "Finding memory write requires the exact delivered content".to_owned(),
                )
            })?;
            let written_content_bytes = chio_core::canonical::canonical_json_bytes(written_content)
                .map_err(|error| {
                    KernelError::Internal(format!(
                        "Finding memory write content canonicalization failed: {error}"
                    ))
                })?;
            let written_content_digest = chio_core::crypto::sha256_hex(&written_content_bytes);
            if contract.result != chio_core::receipt::metadata::DeliveryResult::Matched
                || contract.expected_digest != contract.observed_digest
                || contract.expected_digest != parent.content_hash
                || contract.expected_digest != written_content_digest
            {
                return Err(KernelError::Internal(
                    "Finding memory write content differs from the authenticated delivery"
                        .to_owned(),
                ));
            }
            Ok(())
        })?
        else {
            return Err(KernelError::Internal(
                "Finding delivery lineage requires a durable receipt store".to_owned(),
            ));
        };
        Ok(())
    }

    /// Recheck a bound delivery against the current authenticated Finding
    /// status floor immediately before the memory mutation crosses dispatch.
    pub(crate) fn revalidate_finding_memory_write_status_before_dispatch(
        &self,
        request: &ToolCallRequest,
        now_unix_secs: u64,
    ) -> Result<(), KernelError> {
        let Some(parent_receipt_id) = request
            .arguments
            .get(crate::memory_provenance::FINDING_DELIVERY_RECEIPT_ID_ARGUMENT)
            .and_then(serde_json::Value::as_str)
        else {
            return Ok(());
        };
        // Re-run the complete admission binding against the latest retained
        // parent before deriving mutable status from it. The receipt store is
        // outside the kernel trust boundary and may have changed since the
        // earlier admission pass.
        self.validate_finding_memory_write_admission(request)?;
        let Some(crate::memory_provenance::MemoryActionKind::Write { key, .. }) =
            crate::memory_provenance::classify_memory_action(
                &request.tool_name,
                &request.arguments,
            )
        else {
            return Err(KernelError::Internal(
                "Finding delivery lineage requires a governed memory write".to_owned(),
            ));
        };
        let Some((finding_id, status_proof)) = self.with_receipt_store(|store| {
            let parent = store
                .load_retained_chio_receipt(parent_receipt_id)?
                .ok_or_else(|| {
                    KernelError::Internal(
                        "Finding delivery receipt binding is not durably available".to_owned(),
                    )
                })?;
            if parent.id != parent_receipt_id
                || !parent.is_allowed()
                || !self
                    .finding_delivery_receipt_authorities
                    .contains(&parent.kernel_key)
                || !parent.verify_signature().map_err(|error| {
                    KernelError::Internal(format!(
                        "Finding delivery receipt signature verification failed: {error}"
                    ))
                })?
            {
                return Err(KernelError::Internal(
                    "Finding delivery receipt binding is not an authentic allow receipt".to_owned(),
                ));
            }
            let delivery: chio_core::receipt::metadata::FindingDelivery = parent
                .metadata
                .as_ref()
                .and_then(|metadata| {
                    metadata.get(chio_core::receipt::metadata::FINDING_DELIVERY_METADATA_KEY)
                })
                .cloned()
                .ok_or_else(|| {
                    KernelError::Internal(
                        "Finding delivery receipt binding has no typed delivery metadata"
                            .to_owned(),
                    )
                })
                .and_then(|value| {
                    serde_json::from_value(value).map_err(|error| {
                        KernelError::Internal(format!(
                            "Finding delivery receipt metadata is malformed: {error}"
                        ))
                    })
                })?;
            delivery.validate().map_err(|error| {
                KernelError::Internal(format!(
                    "Finding delivery receipt metadata is invalid: {error}"
                ))
            })?;
            if delivery.finding_id != key
                || delivery.digest_check != chio_core::receipt::metadata::DeliveryResult::Matched
                || delivery.media_type_check
                    != chio_core::receipt::metadata::FindingMediaTypeCheck::Matched
            {
                return Err(KernelError::Internal(
                    "Finding delivery receipt does not authorize this memory entry".to_owned(),
                ));
            }
            let status_proof = delivery.status_proof.ok_or_else(|| {
                KernelError::Internal(
                    "Finding memory write requires a delivery status proof".to_owned(),
                )
            })?;
            Ok((delivery.finding_id, status_proof))
        })?
        else {
            return Err(KernelError::Internal(
                "Finding delivery lineage requires a durable receipt store".to_owned(),
            ));
        };
        let Some(()) = self.with_receipt_store(|store| {
            if !store.supports_kernel_signed_checkpoints() {
                return Err(KernelError::Internal(
                    "Finding memory write requires kernel-signed receipt checkpoint support"
                        .to_owned(),
                ));
            }
            // Flush and authenticate the inherited receipt tail before the
            // provider can mutate memory. The post-return checkpoint then has
            // only this write's receipt to cover, so an oversized prior tail
            // or an unavailable signer denies before the external effect.
            let report = store.create_next_receipt_checkpoint(u64::MAX, &self.config.keypair)?;
            if report.latest_committed_entry_seq != report.latest_checkpointed_entry_seq {
                return Err(KernelError::Internal(
                    "Finding memory write checkpoint preflight left an unanchored receipt tail"
                        .to_owned(),
                ));
            }
            store
                .load_retained_chio_receipt_commitment(parent_receipt_id)?
                .ok_or_else(|| {
                    KernelError::Internal(
                        "Finding delivery receipt is not covered by an authenticated checkpoint"
                            .to_owned(),
                    )
                })?;
            Ok(())
        })?
        else {
            return Err(KernelError::Internal(
                "Finding delivery lineage requires a durable receipt store".to_owned(),
            ));
        };
        let verifier = self.finding_status_proof_verifier.as_ref().ok_or_else(|| {
            KernelError::GuardDenied(
                "Finding memory write requires a configured finding status verifier".to_owned(),
            )
        })?;
        verifier
            .verify_current_status_admission(
                &crate::finding_purchase::FindingCurrentStatusContextView {
                    expected_finding_id: &finding_id,
                    expected_feed_id: &status_proof.feed_id,
                    minimum_map_epoch: status_proof.map_epoch,
                    minimum_non_inclusion_checked_at: status_proof.non_inclusion_checked_at,
                },
                now_unix_secs,
            )
            .map_err(|error| {
                KernelError::GuardDenied(format!(
                    "Finding memory write status revalidation failed: {error}"
                ))
            })?;
        Ok(())
    }

    /// Append a provenance entry for a governed memory write once the allow
    /// receipt is signed. Fails closed on chain-store errors.
    pub(crate) fn append_memory_provenance_for_write(
        &self,
        store: &str,
        key: &str,
        request: &ToolCallRequest,
        receipt: &ChioReceipt,
    ) -> Result<(), KernelError> {
        let Some(chain) = self.memory_provenance_store() else {
            if request
                .arguments
                .get(crate::memory_provenance::FINDING_DELIVERY_RECEIPT_ID_ARGUMENT)
                .is_some()
            {
                return Err(KernelError::Internal(
                    "Finding memory write requires a memory provenance store".to_owned(),
                ));
            }
            return Ok(());
        };
        chain
            .append(crate::memory_provenance::MemoryProvenanceAppend {
                store: store.to_string(),
                key: key.to_string(),
                capability_id: request.capability.id.clone(),
                receipt_id: receipt.id.clone(),
                written_at: receipt.timestamp,
            })
            .map_err(|error| {
                KernelError::Internal(format!(
                    "memory provenance append failed for store={store} key={key}: {error}"
                ))
            })?;
        self.record_finding_memory_write_lineage(request, receipt, key)
    }

    fn record_finding_memory_write_lineage(
        &self,
        request: &ToolCallRequest,
        child: &ChioReceipt,
        memory_key: &str,
    ) -> Result<(), KernelError> {
        let Some(binding) = request
            .arguments
            .get(crate::memory_provenance::FINDING_DELIVERY_RECEIPT_ID_ARGUMENT)
        else {
            return Ok(());
        };
        if request.governed_intent.is_none() {
            return Err(KernelError::Internal(
                "Finding delivery lineage requires a governed memory write".to_owned(),
            ));
        }
        let parent_receipt_id = binding
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                KernelError::Internal(
                    "Finding delivery receipt binding must be a nonempty string".to_owned(),
                )
            })?;
        let Some(()) = self.with_receipt_store(|store| {
            let parent = store
                .load_retained_chio_receipt(parent_receipt_id)?
                .ok_or_else(|| {
                    KernelError::Internal(
                        "Finding delivery receipt binding is not durably available".to_owned(),
                    )
                })?;
            if parent.id != parent_receipt_id
                || !parent.is_allowed()
                || !self
                    .finding_delivery_receipt_authorities
                    .contains(&parent.kernel_key)
                || !parent.verify_signature().map_err(|error| {
                    KernelError::Internal(format!(
                        "Finding delivery receipt signature verification failed: {error}"
                    ))
                })?
            {
                return Err(KernelError::Internal(
                    "Finding delivery receipt binding is not an authentic allow receipt".to_owned(),
                ));
            }
            let delivery_value = parent
                .metadata
                .as_ref()
                .and_then(|metadata| {
                    metadata.get(chio_core::receipt::metadata::FINDING_DELIVERY_METADATA_KEY)
                })
                .cloned()
                .ok_or_else(|| {
                    KernelError::Internal(
                        "Finding delivery receipt binding has no typed delivery metadata".to_owned(),
                    )
                })?;
            let delivery: chio_core::receipt::metadata::FindingDelivery =
                serde_json::from_value(delivery_value).map_err(|error| {
                    KernelError::Internal(format!(
                        "Finding delivery receipt metadata is malformed: {error}"
                    ))
                })?;
            delivery.validate().map_err(|error| {
                KernelError::Internal(format!(
                    "Finding delivery receipt metadata is invalid: {error}"
                ))
            })?;
            if delivery.status_proof.is_none() {
                return Err(KernelError::Internal(
                    "Finding memory lineage requires a delivery status proof".to_owned(),
                ));
            }
            if delivery.finding_id != memory_key
                || delivery.digest_check
                    != chio_core::receipt::metadata::DeliveryResult::Matched
                || delivery.media_type_check
                    != chio_core::receipt::metadata::FindingMediaTypeCheck::Matched
            {
                return Err(KernelError::Internal(
                    "Finding delivery receipt does not authorize this memory entry".to_owned(),
                ));
            }
            let contract_value = parent
                .metadata
                .as_ref()
                .and_then(|metadata| {
                    metadata.get(chio_core::receipt::metadata::DELIVERY_CONTRACT_METADATA_KEY)
                })
                .cloned()
                .ok_or_else(|| {
                    KernelError::Internal(
                        "Finding delivery receipt has no typed delivery contract".to_owned(),
                    )
                })?;
            let contract: chio_core::receipt::metadata::DeliveryContract =
                serde_json::from_value(contract_value).map_err(|error| {
                    KernelError::Internal(format!(
                        "Finding delivery contract metadata is malformed: {error}"
                    ))
                })?;
            contract.validate().map_err(|error| {
                KernelError::Internal(format!(
                    "Finding delivery contract metadata is invalid: {error}"
                ))
            })?;
            let written_content = request.arguments.get("content").ok_or_else(|| {
                KernelError::Internal(
                    "Finding memory write requires the exact delivered content".to_owned(),
                )
            })?;
            let written_content_bytes = chio_core::canonical::canonical_json_bytes(written_content)
                .map_err(|error| {
                    KernelError::Internal(format!(
                        "Finding memory write content canonicalization failed: {error}"
                    ))
                })?;
            let written_content_digest = chio_core::crypto::sha256_hex(&written_content_bytes);
            if contract.result != chio_core::receipt::metadata::DeliveryResult::Matched
                || contract.expected_digest != contract.observed_digest
                || contract.expected_digest != parent.content_hash
                || contract.expected_digest != written_content_digest
            {
                return Err(KernelError::Internal(
                    "Finding memory write content differs from the authenticated delivery"
                        .to_owned(),
                ));
            }
            let parent_request_id = parent
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get("receipt_context"))
                .and_then(|context| context.get("request_id"))
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    KernelError::Internal(
                        "Finding delivery receipt has no authenticated request id".to_owned(),
                    )
                })?;
            let parent_bytes = chio_core::canonical::canonical_json_bytes(&parent).map_err(|error| {
                KernelError::Internal(format!(
                    "Finding delivery receipt canonicalization failed: {error}"
                ))
            })?;
            let child_bytes = chio_core::canonical::canonical_json_bytes(child).map_err(|error| {
                KernelError::Internal(format!(
                    "Finding memory write receipt canonicalization failed: {error}"
                ))
            })?;
            let parent_anchor = chio_core::session::SessionAnchorReference::new(
                format!("receipt:{}", parent.id),
                chio_core::crypto::sha256_hex(&parent_bytes),
            );
            let child_anchor = chio_core::session::SessionAnchorReference::new(
                format!("receipt:{}", child.id),
                chio_core::crypto::sha256_hex(&child_bytes),
            );
            let session_id = format!("finding-memory-write:{}", child.id);
            let auth_context_fingerprint = chio_core::crypto::sha256_hex(
                format!("{}:{}", request.agent_id, request.capability.id).as_bytes(),
            );
            store.record_session_anchor(
                &session_id,
                &child_anchor.session_anchor_id,
                &auth_context_fingerprint,
                child.timestamp,
                None,
                &serde_json::json!({
                    "schema": "chio.finding.memory-write-anchor.v1",
                    "receipt_id": child.id,
                    "receipt_sha256": child_anchor.session_anchor_hash,
                }),
            )?;
            let request_lineage = chio_core::session::RequestLineageRecord::new(
                chio_core::session::RequestId::new(&request.request_id),
                child_anchor.clone(),
                chio_core::session::OperationKind::ToolCall,
                chio_core::session::RequestLineageMode::LocalChild,
                child.timestamp,
            )
            .with_parent_request_id(chio_core::session::RequestId::new(parent_request_id));
            store.record_request_lineage(
                &session_id,
                &request.request_id,
                Some(parent_request_id),
                Some(&child_anchor.session_anchor_id),
                child.timestamp,
                Some(&child.content_hash),
                &serde_json::to_value(&request_lineage).map_err(|error| {
                    KernelError::Internal(format!(
                        "Finding memory write request lineage serialization failed: {error}"
                    ))
                })?,
            )?;
            let statement = chio_core::receipt::lineage::ReceiptLineageStatement::sign(
                chio_core::receipt::lineage::ReceiptLineageStatementBody::new(
                    format!("finding-memory-lineage:{}", child.id),
                    chio_core::receipt::lineage::ReceiptLineageEndpoints::new(
                        parent.id.clone(),
                        child.id.clone(),
                        chio_core::session::RequestId::new(parent_request_id),
                        chio_core::session::RequestId::new(&request.request_id),
                        parent_anchor,
                        child_anchor.clone(),
                    ),
                    chio_core::receipt::lineage::ReceiptLineageRelationKind::FindingMemoryWriteToDelivery,
                    child.timestamp,
                    self.config.keypair.public_key(),
                ),
                &self.config.keypair,
            )
            .map_err(|error| {
                KernelError::Internal(format!(
                    "Finding memory write lineage signing failed: {error}"
                ))
            })?;
            store.record_receipt_lineage_statement(
                &child.id,
                Some(&request.request_id),
                Some(&session_id),
                Some(&child_anchor.session_anchor_id),
                Some(parent_request_id),
                Some(&parent.id),
                Some(&format!("finding:{}", delivery.finding_id)),
                child.timestamp,
                &serde_json::to_value(&statement).map_err(|error| {
                    KernelError::Internal(format!(
                        "Finding memory write lineage serialization failed: {error}"
                    ))
                })?,
            )?;
            store.create_next_receipt_checkpoint(u64::MAX, &self.config.keypair)?;
            store
                .load_retained_chio_receipt_commitment(&child.id)?
                .ok_or_else(|| {
                    KernelError::Internal(
                        "Finding memory write receipt is not covered by an authenticated checkpoint"
                            .to_owned(),
                    )
                })?;
            Ok(())
        })? else {
            return Err(KernelError::Internal(
                "Finding delivery lineage requires a durable receipt store".to_owned(),
            ));
        };
        Ok(())
    }
}

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
