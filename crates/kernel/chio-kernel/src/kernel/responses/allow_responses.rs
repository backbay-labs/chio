use super::*;

/// The reserve-for-caller hold threaded into a preflight allow response: the
/// authorized reservation to keep open, plus the accounting needed to reverse it
/// if the reservation stamp fails. The TTL reaper deadline is derived from the
/// minted nonce's exact expiry inside the response builder so a hold never
/// expires before its own nonce.
pub(crate) enum ReservedHoldStamp<'a> {
    /// A monetary reserve: the durable hold was already authorized during
    /// `check_and_increment_budget` and is kept open; the builder marks it
    /// reserved with the grant currency and reverses the charge on stamp failure.
    /// `payment_reference` carries the rail transaction id of a prepaid MustPrepay
    /// reservation so reconcile-by-nonce can stamp it onto the authoritative
    /// receipt; `None` for a mediated reserve with no prepayment.
    Monetary {
        charge: &'a BudgetChargeResult,
        payment_reference: Option<String>,
    },
    /// An invocation-only reserve: the invocation was already debited by
    /// `try_increment`. The builder adopts it into a durable zero-exposure
    /// reserved hold so the TTL reaper and reconcile-by-nonce can settle it, and
    /// reverse-by-nonce or a stamp failure can return the invocation.
    Invocation { hold_id: String, grant_index: usize },
}

impl ReservedHoldStamp<'_> {
    fn hold_id(&self) -> &str {
        match self {
            Self::Monetary { charge, .. } => charge.budget_hold_id.as_str(),
            Self::Invocation { hold_id, .. } => hold_id.as_str(),
        }
    }
}

/// How `build_allow_response_with_metadata` populates the response execution nonce.
pub(crate) enum AllowResponseNonce {
    /// Use a nonce the caller already minted (cost-bearing reserving paths that
    /// need the nonce id in the receipt metadata before signing).
    Preminted(Box<crate::execution_nonce::SignedExecutionNonce>),
    /// Mint a fresh allow nonce after signing (the standard measured-cost path).
    MintForAllow,
    /// Emit no execution nonce. For provisional allow paths that reversed the
    /// budget hold and did not execute the tool at the kernel: there is no
    /// reserved hold to reconcile and nothing to authorize downstream.
    Suppressed,
}

impl ChioKernel {
    pub(crate) fn build_allow_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        output: ToolCallOutput,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
        nonce: AllowResponseNonce,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
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
            self.append_memory_provenance_for_write(
                store,
                key,
                &cap.id,
                &receipt.id,
                receipt.timestamp,
            )?;
        }

        // Populate the response execution nonce per the caller's disposition:
        // reuse a pre-minted nonce (cost-bearing paths that recorded the nonce id
        // in the receipt metadata before signing), mint a fresh allow nonce after
        // signing (the standard measured path), or emit none for a provisional
        // path that reversed its hold and authorizes nothing downstream.
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

        // Mint the nonce and stamp the reserved hold BEFORE persisting the
        // receipt. A failed stamp reverses the hold, so the receipt must not
        // already be recorded: a persisted `hold_disposition: reserved` receipt
        // with no terminal event standing over a reversed hold is a corrupted
        // audit view.
        let execution_nonce = self.mint_execution_nonce_for_allow_reserving(
            request,
            cap,
            &receipt,
            reserved_hold.as_ref().map(ReservedHoldStamp::hold_id),
        )?;

        // Stamp the reserved hold's TTL deadline from the minted nonce's exact
        // `expires_at` (not a separately sampled evaluation clock), so an
        // unreconciled reserved hold can never expire before its own nonce. Only
        // the reserve-for-caller path supplies a stamp; the reverse-for-retry
        // preflight passes `None` and marks nothing.
        if let (Some(stamp), Some(nonce)) = (reserved_hold.as_ref(), execution_nonce.as_ref()) {
            let reserved_until = nonce.expires_at();
            match stamp {
                ReservedHoldStamp::Monetary {
                    charge,
                    payment_reference,
                } => {
                    // Record the grant ceiling and delegation lineage on the hold
                    // so reconcile-by-nonce stamps the grant's budget total/remaining
                    // and the true depth/root, not the reservation's own exposure.
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
                        // The hold was authorized but the reservation stamp did not
                        // land. The TTL reaper only settles stamped holds, so an
                        // unstamped open hold would stay reserved forever, blocking
                        // later authorizations on the grant. Reverse the hold and
                        // release the sibling-sum headroom it was holding before
                        // surfacing the error, leaving no committed exposure and no
                        // stranded parent budget. The receipt is not yet persisted,
                        // so a reversed hold leaves no orphaned receipt.
                        self.reverse_budget_charge(&cap.id, charge)?;
                        self.release_admitted_capability_budget(cap)
                            .map_err(KernelError::DelegationInvalid)?;
                        return Err(error);
                    }
                    // The stamp landed: keep the delegated child's sibling-sum share
                    // admitted and remember it against the reserved hold so
                    // reconcile-by-nonce or the TTL reaper releases the parent's
                    // headroom when it closes.
                    self.record_reserved_sibling_share(charge.budget_hold_id.as_str(), cap);
                }
                ReservedHoldStamp::Invocation {
                    hold_id,
                    grant_index,
                } => {
                    // An invocation reserve carries no monetary ceiling, but its
                    // delegation lineage is still recorded so reconcile-by-nonce
                    // stamps the true depth/root rather than zero.
                    let envelope = crate::budget_store::ReservedHoldEnvelope {
                        budget_total: None,
                        delegation_depth: cap.delegation_chain.len() as u32,
                        root_budget_holder: cap.issuer.to_hex(),
                    };
                    if let Err(error) = self.with_budget_store(|store| {
                        Ok(store.reserve_invocation_hold(
                            hold_id.as_str(),
                            &cap.id,
                            *grant_index,
                            reserved_until,
                            &envelope,
                        )?)
                    }) {
                        // The invocation was already debited by `try_increment`;
                        // adopting it into a durable reserved hold failed, so no hold
                        // exists to reap or reconcile. Reverse the bare invocation
                        // debit (no hold id) so the grant is not left permanently
                        // short an invocation, and release the delegated child's
                        // sibling-sum share this reservation was holding, before
                        // surfacing the error. The receipt is not yet persisted, so
                        // no orphaned receipt stands over the released state.
                        self.with_budget_store(|store| {
                            Ok(store.reverse_charge_cost(&cap.id, *grant_index, 0)?)
                        })?;
                        self.release_admitted_capability_budget(cap)
                            .map_err(KernelError::DelegationInvalid)?;
                        return Err(error);
                    }
                    // The invocation hold is durable: keep the delegated child's
                    // sibling-sum share admitted and record it against the hold so
                    // reconcile-by-nonce or the TTL reaper releases the parent's
                    // headroom when the hold closes, matching the monetary reserve.
                    self.record_reserved_sibling_share(hold_id.as_str(), cap);
                }
            }
        }

        // Persist the receipt only after the hold is successfully stamped. The
        // reservation is now durable in the budget store and the minted nonce binds
        // it, so a durable-receipt (or federation co-signature) failure here is
        // NON-FATAL: reversing the stamped hold would strand the receipt persist's
        // partial state and void a valid reservation the caller could otherwise
        // reconcile downstream with the nonce. Log the failure and return the
        // response with the nonce instead; the reservation stands, and if the caller
        // never reconciles the TTL reaper forfeits it. A stamp failure above (no
        // durable hold, no returned nonce) still reverses, fail-closed.
        if let Err(error) = self.record_chio_receipt_with_federation(request, &receipt) {
            warn!(
                request_id = %request.request_id,
                hold_id = reserved_hold.as_ref().map(ReservedHoldStamp::hold_id),
                receipt_id = %receipt.id,
                reason = %redacted!(&error),
                "durable receipt persistence failed for a stamped reservation; returning the \
                 minted nonce so the caller can reconcile the durable reservation"
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

    /// Append a provenance entry for a governed memory write once the allow
    /// receipt is signed. Fails closed on chain-store errors.
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
