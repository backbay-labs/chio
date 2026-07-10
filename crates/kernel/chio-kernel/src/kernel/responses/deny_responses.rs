use super::*;

impl ChioKernel {
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
                request_id: Some(&request.request_id),
                capability_id: &cap.id,
                tool_name: &request.tool_name,
                server_id: &request.server_id,
                decision: Decision::Deny {
                    reason: reason.to_string(),
                    guard: "kernel".to_string(),
                },
                action,
                content_hash: receipt_content.content_hash,
                canonical_content: receipt_content.canonical_content,
                metadata,
                timestamp,
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
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
        self.build_pre_execution_monetary_deny_response_with_recording(
            request,
            reason,
            timestamp,
            charge,
            committed_cost_after_release,
            cap,
            extra_metadata,
            ReceiptRecordMode::WithFederation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_runtime_admission_pre_execution_monetary_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        charge: &BudgetChargeResult,
        committed_cost_after_release: u64,
        cap: &CapabilityToken,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_pre_execution_monetary_deny_response_with_recording(
            request,
            reason,
            timestamp,
            charge,
            committed_cost_after_release,
            cap,
            extra_metadata,
            ReceiptRecordMode::LocalOnly,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_pre_execution_monetary_deny_response_with_recording(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        charge: &BudgetChargeResult,
        committed_cost_after_release: u64,
        cap: &CapabilityToken,
        extra_metadata: Option<serde_json::Value>,
        record_mode: ReceiptRecordMode,
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
            request_id: Some(&request.request_id),
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Deny {
                reason: reason.to_string(),
                guard: "kernel".to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            canonical_content: receipt_content.canonical_content,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    receipt_attribution_metadata(cap, Some(charge.grant_index)),
                    deny_extra_metadata,
                ),
                request_metadata,
            ),
            timestamp,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })?;

        self.record_chio_receipt_with_mode(request, &receipt, record_mode)?;

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

    fn build_local_v1_failclosed_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
        guard: &str,
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
            request_id: Some(&request.request_id),
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Deny {
                reason: reason.to_string(),
                guard: guard.to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            canonical_content: receipt_content.canonical_content,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(receipt_content.metadata, request_metadata),
                    extra_metadata,
                ),
                receipt_attribution_metadata(cap, matched_grant_index),
            ),
            timestamp,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })?;

        self.record_chio_receipt(&receipt)?;

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

    /// Build a Deny response for the pre-dispatch federation admission
    /// gate. By definition the named federation peer is NOT pinned fresh
    /// on this path, so we cannot run the federation cosign hook because it
    /// would attempt the same peer-freshness lookup that just failed. The
    /// v1 deny receipt is signed by the local kernel and persisted as
    /// evidence of the closed admission.
    pub(crate) fn build_negotiation_failclosed_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        // Local record only: skip `record_chio_receipt_with_federation`
        // because that helper would re-run the freshness check we just
        // lost. The fail-closed deny is intentionally non-federated.
        self.build_local_v1_failclosed_deny_response_with_metadata(
            request,
            reason,
            timestamp,
            matched_grant_index,
            extra_metadata,
            "kernel.negotiation",
        )
    }

    /// Build a Deny response for the emergency stop gate. The stopped-kernel
    /// path must not perform federation peer lookup or remote co-signing,
    /// because the kill switch is stronger than negotiation state and must
    /// always surface the emergency reason.
    pub(crate) fn build_emergency_stop_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_local_v1_failclosed_deny_response_with_metadata(
            request,
            reason,
            timestamp,
            matched_grant_index,
            extra_metadata,
            "kernel",
        )
    }

    /// Persist a signed local deny receipt for an RSS/allocation load-shed.
    ///
    /// The shed is checked on the same pre-negotiation fast path as the
    /// emergency stop, which already records a signed deny receipt. Recording
    /// one here keeps overload denials inside the same receipt-totality audit
    /// trail every other admission decision has, and makes the `OverloadResource`
    /// actually appear in a receipt deny reason as `error.rs` documents. The
    /// caller still returns [`KernelError::Overloaded`] so the
    /// tower load-shed edge surfaces backpressure; this only records evidence and
    /// never changes the error. A receipt-persist failure is surfaced to the
    /// caller, which logs it without masking the shed decision (fail-closed).
    pub(crate) fn record_overload_shed_deny_receipt(
        &self,
        request: &ToolCallRequest,
        resource: crate::OverloadResource,
        timestamp: u64,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<(), KernelError> {
        let reason =
            format!("kernel shed load to stay within its memory budget (resource: {resource:?})");
        // Local, non-federated v1 deny receipt: the shed runs before receipt
        // negotiation and peer pinning, exactly like the emergency-stop path.
        let _response = self.build_local_v1_failclosed_deny_response_with_metadata(
            request,
            &reason,
            timestamp,
            None,
            extra_metadata,
            "kernel.overload",
        )?;
        Ok(())
    }

    /// Build a Deny response for pre-dispatch receipt persistence admission.
    /// Federated dispatches require a durable local receipt store before any
    /// tool side effect, even when the negotiated receipt version is v1.
    pub(crate) fn build_receipt_persistence_failclosed_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_local_v1_failclosed_deny_response_with_metadata(
            request,
            reason,
            timestamp,
            matched_grant_index,
            extra_metadata,
            "kernel.receipt_persistence",
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
        self.build_deny_response_with_recording(
            request,
            reason,
            timestamp,
            matched_grant_index,
            extra_metadata,
            ReceiptRecordMode::WithFederation,
        )
    }

    pub(crate) fn build_runtime_admission_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_deny_response_with_recording(
            request,
            reason,
            timestamp,
            matched_grant_index,
            extra_metadata,
            ReceiptRecordMode::LocalOnly,
        )
    }

    fn build_deny_response_with_recording(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
        record_mode: ReceiptRecordMode,
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
            request_id: Some(&request.request_id),
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Deny {
                reason: reason.to_string(),
                guard: "kernel".to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            canonical_content: receipt_content.canonical_content,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(receipt_content.metadata, request_metadata),
                    extra_metadata,
                ),
                receipt_attribution_metadata(cap, matched_grant_index),
            ),
            timestamp,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })?;

        self.record_chio_receipt_with_mode(request, &receipt, record_mode)?;

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
}
