use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedChannelTerminalProjectionV1 {
    binding: AdmissionExactProjectionBindingV1,
    request_namespace_digest: RequestNamespaceDigest,
    provider_attempt: ProviderAttemptBindingV1,
    action_parameter_hash: AdmissionDigest,
    proposal_digest: AdmissionDigest,
    reservation_id: AdmissionIdentifier,
    reservation_digest: AdmissionDigest,
    receipt_id: AdmissionIdentifier,
    receipt_digest: AdmissionDigest,
    receipt_authority_digest: AdmissionDigest,
    actual_charge: MonetaryAmount,
    obligation_atom_id: Option<AdmissionIdentifier>,
    obligation_atom_digest: Option<AdmissionDigest>,
    signed_reservation: SignedChannelReservationV1,
    signed_next_state: SignedChannelStateV1,
    terminal_lifecycle: ChannelLifecycleViewV1,
    terminal_escrow: ChannelEscrowReservationViewV1,
    predecessor_view: EconomicStateAnchorViewV1,
    terminal_batch: EconomicStateBatchV1,
    batch_id: AdmissionDigest,
    previous_checkpoint_digest: AdmissionDigest,
    checkpoint_digest: AdmissionDigest,
    batch_issued_at: u64,
    prior_channel_head_digest: AdmissionDigest,
    prior_escrow_head_digest: AdmissionDigest,
    prior_effect_head_digest: AdmissionDigest,
    terminal_channel_head_digest: AdmissionDigest,
    terminal_escrow_head_digest: AdmissionDigest,
    completed_effect_slot: EconomicEffectSlotV1,
    completed_effect_head_digest: AdmissionDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UntrustedChannelTerminalProjectionV1 {
    binding: AdmissionExactProjectionBindingV1,
    request_namespace_digest: RequestNamespaceDigest,
    provider_attempt: ProviderAttemptBindingV1,
    action_parameter_hash: AdmissionDigest,
    proposal_digest: AdmissionDigest,
    reservation_id: AdmissionIdentifier,
    reservation_digest: AdmissionDigest,
    receipt_id: AdmissionIdentifier,
    receipt_digest: AdmissionDigest,
    receipt_authority_digest: AdmissionDigest,
    actual_charge: MonetaryAmount,
    obligation_atom_id: Option<AdmissionIdentifier>,
    obligation_atom_digest: Option<AdmissionDigest>,
    signed_reservation: SignedChannelReservationV1,
    signed_next_state: SignedChannelStateV1,
    terminal_lifecycle: ChannelLifecycleViewV1,
    terminal_escrow: ChannelEscrowReservationViewV1,
    predecessor_view: EconomicStateAnchorViewV1,
    terminal_batch: EconomicStateBatchV1,
    batch_id: AdmissionDigest,
    previous_checkpoint_digest: AdmissionDigest,
    checkpoint_digest: AdmissionDigest,
    batch_issued_at: u64,
    prior_channel_head_digest: AdmissionDigest,
    prior_escrow_head_digest: AdmissionDigest,
    prior_effect_head_digest: AdmissionDigest,
    terminal_channel_head_digest: AdmissionDigest,
    terminal_escrow_head_digest: AdmissionDigest,
    completed_effect_slot: EconomicEffectSlotV1,
    completed_effect_head_digest: AdmissionDigest,
}

impl From<UntrustedChannelTerminalProjectionV1> for VerifiedChannelTerminalProjectionV1 {
    fn from(value: UntrustedChannelTerminalProjectionV1) -> Self {
        Self {
            binding: value.binding,
            request_namespace_digest: value.request_namespace_digest,
            provider_attempt: value.provider_attempt,
            action_parameter_hash: value.action_parameter_hash,
            proposal_digest: value.proposal_digest,
            reservation_id: value.reservation_id,
            reservation_digest: value.reservation_digest,
            receipt_id: value.receipt_id,
            receipt_digest: value.receipt_digest,
            receipt_authority_digest: value.receipt_authority_digest,
            actual_charge: value.actual_charge,
            obligation_atom_id: value.obligation_atom_id,
            obligation_atom_digest: value.obligation_atom_digest,
            signed_reservation: value.signed_reservation,
            signed_next_state: value.signed_next_state,
            terminal_lifecycle: value.terminal_lifecycle,
            terminal_escrow: value.terminal_escrow,
            predecessor_view: value.predecessor_view,
            terminal_batch: value.terminal_batch,
            batch_id: value.batch_id,
            previous_checkpoint_digest: value.previous_checkpoint_digest,
            checkpoint_digest: value.checkpoint_digest,
            batch_issued_at: value.batch_issued_at,
            prior_channel_head_digest: value.prior_channel_head_digest,
            prior_escrow_head_digest: value.prior_escrow_head_digest,
            prior_effect_head_digest: value.prior_effect_head_digest,
            terminal_channel_head_digest: value.terminal_channel_head_digest,
            terminal_escrow_head_digest: value.terminal_escrow_head_digest,
            completed_effect_slot: value.completed_effect_slot,
            completed_effect_head_digest: value.completed_effect_head_digest,
        }
    }
}

impl VerifiedChannelTerminalProjectionV1 {
    #[cfg(feature = "admission-test-support")]
    pub fn from_verified_for_test(
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        receipt: &VerifiedAdmissionReceipt,
        tool_outcome: &ToolOutcomeTerminalEvidenceV1,
        advance: &VerifiedChannelTerminalAdvanceV1,
    ) -> Result<(Self, Option<ObligationProjection>), AdmissionOperationError> {
        Self::from_verified(operation, context, receipt, tool_outcome, advance)
    }

    pub(in crate::admission_operation) fn from_canonical_record_verified(
        canonical_json: &[u8],
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<Self, AdmissionOperationError> {
        let untrusted: UntrustedChannelTerminalProjectionV1 =
            serde_json::from_slice(canonical_json)
                .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?;
        if canonical_json_bytes(&untrusted)
            .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?
            != canonical_json
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
        }
        let projection = Self::from(untrusted);
        projection.validate_record_binding(operation, context)?;
        Ok(projection)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified(
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        receipt: &VerifiedAdmissionReceipt,
        tool_outcome: &ToolOutcomeTerminalEvidenceV1,
        advance: &VerifiedChannelTerminalAdvanceV1,
    ) -> Result<(Self, Option<ObligationProjection>), AdmissionOperationError> {
        let obligation = ObligationProjection::from_verified_channel_advance(
            operation,
            context,
            receipt,
            tool_outcome,
            advance,
        )?;
        let payee_signature = advance
            .next_state()
            .payee_signature()
            .cloned()
            .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
        let projection = Self {
            binding: AdmissionExactProjectionBindingV1::from_verified(
                operation,
                context,
                AdmissionOperationState::Completed,
            )?,
            request_namespace_digest: operation.binding().request_namespace_digest().clone(),
            provider_attempt: operation
                .provider_attempt()
                .cloned()
                .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?,
            action_parameter_hash: operation.binding().action_parameter_hash().clone(),
            proposal_digest: AdmissionDigest::try_new(
                "channel_reservation_proposal_digest",
                advance
                    .reservation_proposal()
                    .artifact()
                    .body
                    .proposal_digest()
                    .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?,
            )?,
            reservation_id: AdmissionIdentifier::try_new(
                "channel_reservation_id",
                advance.reservation_id().to_owned(),
            )?,
            reservation_digest: AdmissionDigest::try_new(
                "channel_reservation_digest",
                advance.reservation_digest().to_owned(),
            )?,
            receipt_id: AdmissionIdentifier::try_new(
                "channel_receipt_id",
                advance.receipt().receipt_id().to_owned(),
            )?,
            receipt_digest: AdmissionDigest::try_new(
                "channel_receipt_digest",
                advance.receipt().receipt_digest().to_owned(),
            )?,
            receipt_authority_digest: AdmissionDigest::try_new(
                "channel_receipt_authority_digest",
                advance.receipt().receipt_authority_digest().to_owned(),
            )?,
            actual_charge: advance.actual_charge().clone(),
            obligation_atom_id: advance
                .obligation_atom_id()
                .map(|value| AdmissionIdentifier::try_new("channel_obligation_atom_id", value))
                .transpose()?,
            obligation_atom_digest: advance
                .obligation_atom_digest()
                .map(|value| AdmissionDigest::try_new("channel_obligation_atom_digest", value))
                .transpose()?,
            signed_reservation: advance.reservation().artifact().clone(),
            signed_next_state: SignedChannelStateV1 {
                body: advance.next_state().body().clone(),
                payee_signature,
            },
            terminal_lifecycle: advance.terminal_lifecycle().clone(),
            terminal_escrow: advance.terminal_escrow().clone(),
            predecessor_view: advance.current_view().view().clone(),
            terminal_batch: advance.batch().clone(),
            batch_id: AdmissionDigest::try_new(
                "channel_terminal_batch_id",
                advance.batch_id().to_owned(),
            )?,
            previous_checkpoint_digest: AdmissionDigest::try_new(
                "channel_previous_checkpoint_digest",
                advance.previous_checkpoint_digest().to_owned(),
            )?,
            checkpoint_digest: AdmissionDigest::try_new(
                "channel_checkpoint_digest",
                advance.checkpoint_digest().to_owned(),
            )?,
            batch_issued_at: advance.batch_issued_at(),
            prior_channel_head_digest: AdmissionDigest::try_new(
                "channel_prior_head_digest",
                advance.prior_channel_head_digest().to_owned(),
            )?,
            prior_escrow_head_digest: AdmissionDigest::try_new(
                "channel_prior_escrow_head_digest",
                advance.prior_escrow_head_digest().to_owned(),
            )?,
            prior_effect_head_digest: AdmissionDigest::try_new(
                "channel_prior_effect_head_digest",
                advance.prior_effect_head_digest().to_owned(),
            )?,
            terminal_channel_head_digest: AdmissionDigest::try_new(
                "channel_terminal_head_digest",
                advance.terminal_channel_head_digest().to_owned(),
            )?,
            terminal_escrow_head_digest: AdmissionDigest::try_new(
                "channel_terminal_escrow_head_digest",
                advance.terminal_escrow_head_digest().to_owned(),
            )?,
            completed_effect_slot: advance.effect_slot().clone(),
            completed_effect_head_digest: AdmissionDigest::try_new(
                "channel_completed_effect_head_digest",
                advance.effect_head_digest().to_owned(),
            )?,
        };
        projection.validate_against(
            operation,
            context,
            receipt,
            tool_outcome,
            obligation.as_ref(),
        )?;
        Ok((projection, obligation))
    }

    fn validate_anchored_batch(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<(), AdmissionOperationError> {
        let mismatch = || AdmissionOperationError::TerminalProjectionBindingMismatch;
        self.predecessor_view.validate().map_err(|_| mismatch())?;
        self.terminal_batch.validate().map_err(|_| mismatch())?;
        validate_positive_ijson("channel_terminal_batch_issued_at", self.batch_issued_at)?;
        let channel_key = &self.completed_effect_slot.resource_key;
        let escrow_key = EconomicResourceKeyV1 {
            resource_family: CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY.to_owned(),
            scope_id: channel_key.scope_id.clone(),
            resource_id: self.signed_reservation.body.channel_id.clone(),
        };
        let effect_key = self.completed_effect_slot.resource_head_key();
        let transition = |key: &EconomicResourceKeyV1| {
            self.terminal_batch
                .transitions
                .iter()
                .find(|transition| &transition.resource_key == key)
                .ok_or_else(mismatch)
        };
        let channel_transition = transition(channel_key)?;
        let escrow_transition = transition(&escrow_key)?;
        let effect_transition = transition(&effect_key)?;
        let predecessor_head =
            |key: &EconomicResourceKeyV1| self.predecessor_view.head(key).ok_or_else(mismatch);
        let prior_channel = predecessor_head(channel_key)?
            .digest()
            .map_err(|_| mismatch())?;
        let prior_escrow = predecessor_head(&escrow_key)?
            .digest()
            .map_err(|_| mismatch())?;
        let prior_effect = predecessor_head(&effect_key)?
            .digest()
            .map_err(|_| mismatch())?;
        let terminal_channel = channel_transition
            .next_head
            .digest()
            .map_err(|_| mismatch())?;
        let terminal_escrow = escrow_transition
            .next_head
            .digest()
            .map_err(|_| mismatch())?;
        let terminal_effect = effect_transition
            .next_head
            .digest()
            .map_err(|_| mismatch())?;
        let expected_channel = EconomicContentV1::Inline {
            value: serde_json::to_value(&self.terminal_lifecycle)
                .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?,
        };
        let expected_escrow = EconomicContentV1::Inline {
            value: serde_json::to_value(&self.terminal_escrow)
                .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?,
        };
        let expected_effect = EconomicContentV1::Inline {
            value: serde_json::to_value(&self.completed_effect_slot)
                .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?,
        };
        if self.terminal_batch.transitions.len() != 3
            || !self.terminal_batch.effect_slots.is_empty()
            || !self.terminal_batch.request_replays.is_empty()
            || self
                .terminal_batch
                .transitions
                .iter()
                .any(|transition| transition.prepared_effect.is_some())
            || self.terminal_batch.operation_id.as_deref()
                != Some(operation.binding().operation_id().as_str())
            || self.terminal_batch.anchor_id != self.predecessor_view.anchor_id
            || self.terminal_batch.namespace != self.predecessor_view.namespace
            || self.terminal_batch.signer_key_id != self.predecessor_view.signer_key_id
            || self.terminal_batch.signer_key_epoch != self.predecessor_view.signer_key_epoch
            || self.terminal_batch.batch_id != self.batch_id.as_str()
            || self.terminal_batch.previous_checkpoint_digest.as_deref()
                != Some(self.previous_checkpoint_digest.as_str())
            || self.predecessor_view.checkpoint_digest != self.previous_checkpoint_digest.as_str()
            || self.terminal_batch.checkpoint_digest != self.checkpoint_digest.as_str()
            || self.terminal_batch.issued_at != self.batch_issued_at
            || context.trusted_time_unix_ms > self.batch_issued_at
            || self.batch_issued_at < self.predecessor_view.observed_at
            || channel_transition.expected_head_digest.as_deref()
                != Some(self.prior_channel_head_digest.as_str())
            || escrow_transition.expected_head_digest.as_deref()
                != Some(self.prior_escrow_head_digest.as_str())
            || effect_transition.expected_head_digest.as_deref()
                != Some(self.prior_effect_head_digest.as_str())
            || prior_channel != self.prior_channel_head_digest.as_str()
            || prior_escrow != self.prior_escrow_head_digest.as_str()
            || prior_effect != self.prior_effect_head_digest.as_str()
            || terminal_channel != self.terminal_channel_head_digest.as_str()
            || terminal_escrow != self.terminal_escrow_head_digest.as_str()
            || terminal_effect != self.completed_effect_head_digest.as_str()
            || channel_transition.next_head.state != expected_channel
            || escrow_transition.next_head.state != expected_escrow
            || effect_transition.next_head.state != expected_effect
        {
            return Err(mismatch());
        }
        Ok(())
    }

    fn validate_record_binding(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<(), AdmissionOperationError> {
        let mismatch = || AdmissionOperationError::TerminalProjectionBindingMismatch;
        self.binding
            .validate_against(operation, context, AdmissionOperationState::Completed)?;
        self.completed_effect_slot
            .validate()
            .map_err(|_| mismatch())?;
        self.terminal_lifecycle.validate().map_err(|_| mismatch())?;
        self.terminal_escrow.validate().map_err(|_| mismatch())?;
        self.validate_anchored_batch(operation, context)?;
        let requirements = operation.binding().participant_requirements();
        let commit = operation.dispatch_commit().ok_or_else(mismatch)?;
        let provider_attempt = operation.provider_attempt().ok_or_else(mismatch)?;
        let proposal_digest = AdmissionDigest::try_new(
            "channel_reservation_proposal_digest",
            self.signed_reservation
                .body
                .proposal_digest()
                .map_err(|_| mismatch())?,
        )?;
        let reservation_digest = AdmissionDigest::try_new(
            "channel_reservation_digest",
            self.signed_reservation.digest().map_err(|_| mismatch())?,
        )?;
        let next_state_digest = self.signed_next_state.digest().map_err(|_| mismatch())?;
        let obligation_shape_matches = matches!(
            (
                self.actual_charge.units,
                self.obligation_atom_id.as_ref(),
                self.obligation_atom_digest.as_ref(),
            ),
            (0, None, None) | (1.., Some(_), Some(_))
        );
        if !requirements.channel
            || !requirements.obligation
            || self.actual_charge.units > I_JSON_MAX_SAFE_INTEGER
            || self.actual_charge.currency.len() != 3
            || !self
                .actual_charge
                .currency
                .bytes()
                .all(|byte| byte.is_ascii_uppercase())
            || self.request_namespace_digest != *operation.binding().request_namespace_digest()
            || self.provider_attempt != *provider_attempt
            || commit.provider_attempt.as_ref() != Some(provider_attempt)
            || self.action_parameter_hash != *operation.binding().action_parameter_hash()
            || self.proposal_digest != proposal_digest
            || self.reservation_id.as_str() != self.signed_reservation.body.reservation_id
            || self.reservation_digest != reservation_digest
            || operation.channel_reservation_proposal_digest() != Some(&self.proposal_digest)
            || operation.channel_reservation_digest() != Some(&self.reservation_digest)
            || self.signed_reservation.body.operation_id
                != operation.binding().operation_id().as_str()
            || self.signed_reservation.body.request_id != operation.replay_key().request_id.as_str()
            || self.signed_reservation.body.receipt_authority_digest
                != self.receipt_authority_digest.as_str()
            || self.actual_charge.currency != self.signed_reservation.body.maximum_charge.currency
            || self.actual_charge.units > self.signed_reservation.body.maximum_charge.units
            || self.completed_effect_slot.operation_id
                != operation.binding().operation_id().as_str()
            || self.completed_effect_slot.request.request_id
                != operation.replay_key().request_id.as_str()
            || self.completed_effect_slot.request.request_namespace_digest
                != operation.replay_key().request_namespace_digest.as_str()
            || self.completed_effect_slot.request.request_binding_digest
                != operation.binding().request_binding_hash().as_str()
            || self.completed_effect_slot.admission_handoff.state
                != EconomicAdmissionHandoffStateV1::DispatchCommitted
            || self
                .completed_effect_slot
                .admission_handoff
                .operation_version
                != commit.committed_version
            || self.completed_effect_slot.admission_handoff.lifecycle_fence
                != commit.coordinator_lease_epoch
            || self.completed_effect_slot.admission_handoff.store_fence != commit.store_fence
            || self.completed_effect_slot.target.target_id != provider_attempt.transport_id
            || self.completed_effect_slot.target.target_key_epoch
                != provider_attempt.transport_key_epoch
            || self.completed_effect_slot.action_digest != self.action_parameter_hash.as_str()
            || self.completed_effect_slot.parameters_digest != self.reservation_digest.as_str()
            || self.completed_effect_slot.resource_head_digest
                != self.prior_channel_head_digest.as_str()
            || self.signed_next_state.body.receipt_id.as_deref() != Some(self.receipt_id.as_str())
            || self.signed_next_state.body.receipt_digest.as_deref()
                != Some(self.receipt_digest.as_str())
            || self
                .signed_next_state
                .body
                .receipt_authority_digest
                .as_deref()
                != Some(self.receipt_authority_digest.as_str())
            || self
                .signed_next_state
                .body
                .obligation_atom_digest
                .as_deref()
                != self
                    .obligation_atom_digest
                    .as_ref()
                    .map(AdmissionDigest::as_str)
            || self.signed_next_state.body.actual_charge.as_ref() != Some(&self.actual_charge)
            || self.signed_next_state.body.reservation_digest.as_deref()
                != Some(self.reservation_digest.as_str())
            || self.terminal_lifecycle.channel_id != self.signed_reservation.body.channel_id
            || self.terminal_lifecycle.latest_state_digest != next_state_digest
            || self.terminal_lifecycle.latest_sequence != self.signed_next_state.body.seq
            || self.terminal_lifecycle.live_reservation_id.is_some()
            || self.terminal_lifecycle.operation_id.is_some()
            || self.terminal_escrow.channel_id != self.signed_reservation.body.channel_id
            || self.terminal_escrow.open_digest != self.signed_reservation.body.open_digest
            || self.terminal_escrow.lifecycle_fence != self.terminal_lifecycle.lifecycle_fence
            || !obligation_shape_matches
        {
            return Err(mismatch());
        }
        Ok(())
    }

    pub(super) fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        receipt: &VerifiedAdmissionReceipt,
        tool_outcome: &ToolOutcomeTerminalEvidenceV1,
        obligation: Option<&ObligationProjection>,
    ) -> Result<(), AdmissionOperationError> {
        let mismatch = || AdmissionOperationError::TerminalProjectionBindingMismatch;
        self.binding
            .validate_against(operation, context, AdmissionOperationState::Completed)?;
        tool_outcome
            .validate_against(operation, context)
            .map_err(|_| mismatch())?;
        receipt.validate_against(
            operation,
            context,
            AdmissionOperationState::Completed,
            AdmissionCompensationStatus::NotCompensated,
            Some((tool_outcome.outcome_id(), tool_outcome.outcome_version())),
        )?;
        self.completed_effect_slot
            .validate()
            .map_err(|_| mismatch())?;
        self.terminal_lifecycle.validate().map_err(|_| mismatch())?;
        self.terminal_escrow.validate().map_err(|_| mismatch())?;
        self.validate_anchored_batch(operation, context)?;
        let requirements = operation.binding().participant_requirements();
        let commit = operation.dispatch_commit().ok_or_else(mismatch)?;
        let provider_attempt = operation.provider_attempt().ok_or_else(mismatch)?;
        if let Some(obligation) = obligation {
            obligation.validate_against(
                operation,
                context,
                receipt,
                tool_outcome.outcome_id(),
                tool_outcome.outcome_version(),
            )?;
        }
        let expected_result = EconomicContentV1::Inline {
            value: serde_json::to_value(tool_outcome)
                .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?,
        };
        let expected_result_digest = AdmissionDigest::try_new(
            "channel_effect_result_digest",
            expected_result.digest().map_err(|_| mismatch())?,
        )?;
        let effect_result_matches = matches!(
            self.completed_effect_slot.terminal.as_ref(),
            Some(chio_core::economic_continuity::EconomicEffectTerminalV1::Completed {
                result_id,
                result_digest,
                result,
            }) if result_id == tool_outcome.outcome_id().as_str()
                && result_digest == expected_result_digest.as_str()
                && result == &expected_result
        );
        let proposal_digest = AdmissionDigest::try_new(
            "channel_reservation_proposal_digest",
            self.signed_reservation
                .body
                .proposal_digest()
                .map_err(|_| mismatch())?,
        )?;
        let reservation_digest = AdmissionDigest::try_new(
            "channel_reservation_digest",
            self.signed_reservation.digest().map_err(|_| mismatch())?,
        )?;
        let next_state_digest = self.signed_next_state.digest().map_err(|_| mismatch())?;
        let receipt_digest = receipt_digest(receipt.receipt())?;
        let expected_receipt_authority_digest = AdmissionDigest::try_new(
            "channel_receipt_authority_digest",
            derive_channel_receipt_authority_digest(&receipt.receipt().kernel_key)
                .map_err(|_| mismatch())?,
        )?;
        let financial = receipt
            .receipt()
            .financial_metadata()
            .ok_or_else(mismatch)?;
        let channel = receipt.receipt().channel_metadata().ok_or_else(mismatch)?;
        let disposition_matches = match tool_outcome.settlement_disposition() {
            SettlementDispositionV1::Capture { amount } => {
                self.actual_charge.units > 0 && amount == &self.actual_charge
            }
            SettlementDispositionV1::ContractualZeroCharge { currency } => {
                self.actual_charge.units == 0 && currency == &self.actual_charge.currency
            }
            SettlementDispositionV1::NotApplicable => self.actual_charge.units == 0,
        };
        let obligation_matches = if self.actual_charge.units == 0 {
            obligation.is_none()
                && self.obligation_atom_id.is_none()
                && self.obligation_atom_digest.is_none()
        } else {
            let Some(obligation) = obligation else {
                return Err(mismatch());
            };
            self.obligation_atom_id.as_ref() == Some(obligation.obligation_id())
                && self.obligation_atom_digest.as_ref() == Some(obligation.atom_digest())
                && obligation.amount() == &self.actual_charge
                && obligation.disposition()
                    == &ObligationDispositionV1::Channelized {
                        channel_id: self.signed_reservation.body.channel_id.clone(),
                        reservation_id: self.signed_reservation.body.reservation_id.clone(),
                    }
        };
        if !requirements.channel
            || !requirements.obligation
            || self.request_namespace_digest != *operation.binding().request_namespace_digest()
            || self.provider_attempt != *provider_attempt
            || commit.provider_attempt.as_ref() != Some(provider_attempt)
            || self.action_parameter_hash != *operation.binding().action_parameter_hash()
            || self.proposal_digest != proposal_digest
            || self.reservation_id.as_str() != self.signed_reservation.body.reservation_id
            || self.reservation_digest != reservation_digest
            || operation.channel_reservation_proposal_digest() != Some(&self.proposal_digest)
            || operation.channel_reservation_digest() != Some(&self.reservation_digest)
            || self.signed_reservation.body.operation_id
                != operation.binding().operation_id().as_str()
            || self.signed_reservation.body.request_id != operation.replay_key().request_id.as_str()
            || self.signed_reservation.body.receipt_authority_digest
                != self.receipt_authority_digest.as_str()
            || self.completed_effect_slot.operation_id
                != operation.binding().operation_id().as_str()
            || self.completed_effect_slot.request.request_id
                != operation.replay_key().request_id.as_str()
            || self.completed_effect_slot.request.request_namespace_digest
                != operation.replay_key().request_namespace_digest.as_str()
            || self.completed_effect_slot.request.request_binding_digest
                != operation.binding().request_binding_hash().as_str()
            || self.completed_effect_slot.admission_handoff.state
                != EconomicAdmissionHandoffStateV1::DispatchCommitted
            || self
                .completed_effect_slot
                .admission_handoff
                .operation_version
                != commit.committed_version
            || self.completed_effect_slot.admission_handoff.lifecycle_fence
                != commit.coordinator_lease_epoch
            || self.completed_effect_slot.admission_handoff.store_fence != commit.store_fence
            || self.completed_effect_slot.target.target_id != provider_attempt.transport_id
            || self.completed_effect_slot.target.target_key_epoch
                != provider_attempt.transport_key_epoch
            || self.completed_effect_slot.action_digest != self.action_parameter_hash.as_str()
            || self.completed_effect_slot.parameters_digest != self.reservation_digest.as_str()
            || self.completed_effect_slot.resource_head_digest
                != self.prior_channel_head_digest.as_str()
            || self.receipt_id.as_str() != receipt.receipt().id
            || self.receipt_digest != receipt_digest
            || self.receipt_authority_digest != expected_receipt_authority_digest
            || financial.cost_charged != self.actual_charge.units
            || financial.currency != self.actual_charge.currency
            || !channel.is_valid()
            || channel.channel_id != self.signed_reservation.body.channel_id
            || channel.open_digest != self.signed_reservation.body.open_digest
            || channel.reservation_id != self.signed_reservation.body.reservation_id
            || channel.reservation_digest != self.reservation_digest.as_str()
            || channel.sequence != self.signed_reservation.body.next_sequence
            || self.signed_next_state.body.receipt_id.as_deref() != Some(self.receipt_id.as_str())
            || self.signed_next_state.body.receipt_digest.as_deref()
                != Some(self.receipt_digest.as_str())
            || self
                .signed_next_state
                .body
                .receipt_authority_digest
                .as_deref()
                != Some(self.receipt_authority_digest.as_str())
            || self
                .signed_next_state
                .body
                .obligation_atom_digest
                .as_deref()
                != self
                    .obligation_atom_digest
                    .as_ref()
                    .map(AdmissionDigest::as_str)
            || self.signed_next_state.body.actual_charge.as_ref() != Some(&self.actual_charge)
            || self.signed_next_state.body.reservation_digest.as_deref()
                != Some(self.reservation_digest.as_str())
            || self.terminal_lifecycle.channel_id != self.signed_reservation.body.channel_id
            || self.terminal_lifecycle.latest_state_digest != next_state_digest
            || self.terminal_lifecycle.latest_sequence != self.signed_next_state.body.seq
            || self.terminal_lifecycle.live_reservation_id.is_some()
            || self.terminal_lifecycle.operation_id.is_some()
            || self.terminal_escrow.channel_id != self.signed_reservation.body.channel_id
            || self.terminal_escrow.open_digest != self.signed_reservation.body.open_digest
            || self.terminal_escrow.lifecycle_fence != self.terminal_lifecycle.lifecycle_fence
            || !effect_result_matches
            || !disposition_matches
            || !obligation_matches
        {
            return Err(mismatch());
        }
        Ok(())
    }

    #[must_use]
    pub const fn record_id(&self) -> &AdmissionIdentifier {
        &self.reservation_id
    }

    #[must_use]
    pub const fn operation_binding(&self) -> &AdmissionExactProjectionBindingV1 {
        &self.binding
    }

    #[must_use]
    pub const fn request_namespace_digest(&self) -> &RequestNamespaceDigest {
        &self.request_namespace_digest
    }

    #[must_use]
    pub const fn provider_attempt(&self) -> &ProviderAttemptBindingV1 {
        &self.provider_attempt
    }

    #[must_use]
    pub const fn reservation_digest(&self) -> &AdmissionDigest {
        &self.reservation_digest
    }

    #[must_use]
    pub const fn receipt_id(&self) -> &AdmissionIdentifier {
        &self.receipt_id
    }

    #[must_use]
    pub const fn receipt_digest(&self) -> &AdmissionDigest {
        &self.receipt_digest
    }

    #[must_use]
    pub const fn receipt_authority_digest(&self) -> &AdmissionDigest {
        &self.receipt_authority_digest
    }

    #[must_use]
    pub const fn actual_charge(&self) -> &MonetaryAmount {
        &self.actual_charge
    }

    #[must_use]
    pub const fn obligation_atom_id(&self) -> Option<&AdmissionIdentifier> {
        self.obligation_atom_id.as_ref()
    }

    #[must_use]
    pub const fn obligation_atom_digest(&self) -> Option<&AdmissionDigest> {
        self.obligation_atom_digest.as_ref()
    }

    #[must_use]
    pub const fn signed_reservation(&self) -> &SignedChannelReservationV1 {
        &self.signed_reservation
    }

    #[must_use]
    pub const fn signed_next_state(&self) -> &SignedChannelStateV1 {
        &self.signed_next_state
    }

    #[must_use]
    pub const fn terminal_lifecycle(&self) -> &ChannelLifecycleViewV1 {
        &self.terminal_lifecycle
    }

    #[must_use]
    pub const fn terminal_escrow(&self) -> &ChannelEscrowReservationViewV1 {
        &self.terminal_escrow
    }

    #[must_use]
    pub const fn predecessor_view(&self) -> &EconomicStateAnchorViewV1 {
        &self.predecessor_view
    }

    #[must_use]
    pub const fn terminal_batch(&self) -> &EconomicStateBatchV1 {
        &self.terminal_batch
    }

    #[must_use]
    pub const fn batch_id(&self) -> &AdmissionDigest {
        &self.batch_id
    }

    #[must_use]
    pub const fn previous_checkpoint_digest(&self) -> &AdmissionDigest {
        &self.previous_checkpoint_digest
    }

    #[must_use]
    pub const fn checkpoint_digest(&self) -> &AdmissionDigest {
        &self.checkpoint_digest
    }

    #[must_use]
    pub const fn batch_issued_at(&self) -> u64 {
        self.batch_issued_at
    }

    #[must_use]
    pub const fn prior_channel_head_digest(&self) -> &AdmissionDigest {
        &self.prior_channel_head_digest
    }

    #[must_use]
    pub const fn prior_escrow_head_digest(&self) -> &AdmissionDigest {
        &self.prior_escrow_head_digest
    }

    #[must_use]
    pub const fn prior_effect_head_digest(&self) -> &AdmissionDigest {
        &self.prior_effect_head_digest
    }

    #[must_use]
    pub const fn terminal_channel_head_digest(&self) -> &AdmissionDigest {
        &self.terminal_channel_head_digest
    }

    #[must_use]
    pub const fn terminal_escrow_head_digest(&self) -> &AdmissionDigest {
        &self.terminal_escrow_head_digest
    }

    #[must_use]
    pub const fn terminal_effect_head_digest(&self) -> &AdmissionDigest {
        &self.completed_effect_head_digest
    }

    #[must_use]
    pub const fn completed_effect_slot(&self) -> &EconomicEffectSlotV1 {
        &self.completed_effect_slot
    }

    pub fn qualify_anchored_advance(
        &self,
        advance: &VerifiedEconomicStateBatchAdvance,
    ) -> Result<&EconomicEffectSlotV1, AdmissionOperationError> {
        self.qualify_retained_anchored_advance(advance.current().view(), advance.batch())
    }

    pub fn qualify_retained_anchored_advance(
        &self,
        predecessor_view: &EconomicStateAnchorViewV1,
        terminal_batch: &EconomicStateBatchV1,
    ) -> Result<&EconomicEffectSlotV1, AdmissionOperationError> {
        if predecessor_view != &self.predecessor_view || terminal_batch != &self.terminal_batch {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
        }
        Ok(&self.completed_effect_slot)
    }
}
