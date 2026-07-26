use super::*;

impl ChioKernel {
    pub(crate) fn build_pending_approval_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        proposal: &chio_core::capability::governance::ThresholdApprovalProposal,
        timestamp: u64,
        matched_grant_index: usize,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let output = ToolCallOutput::Value(
            serde_json::to_value(proposal)
                .map_err(|error| KernelError::Internal(error.to_string()))?,
        );
        let receipt_content = receipt_content_for_output(Some(&output), None)?;
        let action =
            ToolCallAction::from_parameters(request.arguments.clone()).map_err(|error| {
                KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {error}"))
            })?;
        let request_metadata = request_receipt_metadata(
            request,
            self.attestation_trust_policy.as_ref(),
            timestamp,
            extra_metadata.as_ref(),
        )?;
        let proposal_hash = proposal
            .artifact_digest()
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        let metadata = merge_metadata_objects(
            merge_metadata_objects(
                merge_metadata_objects(receipt_content.metadata, request_metadata),
                extra_metadata,
            ),
            merge_metadata_objects(
                receipt_attribution_metadata(&request.capability, Some(matched_grant_index)),
                Some(serde_json::json!({
                    "threshold_approval": {
                        "proposal_id": proposal.body.proposal_id,
                        "proposal_hash": proposal_hash,
                        "proposal_deadline": proposal.body.proposal_deadline,
                        "state": "approval_required"
                    }
                })),
            ),
        );
        let receipt = self.build_and_sign_receipt(ReceiptParams {
            request_id: Some(&request.request_id),
            capability_id: &request.capability.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Deny {
                reason: "cumulative approval required".to_owned(),
                guard: "kernel".to_owned(),
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
        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::PendingApproval,
            output: Some(output),
            reason: None,
            terminal_state: OperationTerminalState::Incomplete {
                reason: "approval_required".to_owned(),
            },
            receipt,
            execution_nonce: None,
        })
    }
}
