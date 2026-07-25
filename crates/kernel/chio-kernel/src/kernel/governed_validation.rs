//! Governed-admission validators for `ChioKernel`.
//!
//! Keeps approval tokens, runtime-attestation requirements, metered billing,
//! call-chain proof validation, autonomy bond validation, and governed
//! transaction receipt evidence out of the capability and budget validation
//! module.

use chio_appraisal::VerifiedRuntimeAttestationRecord;

use super::*;

#[path = "governed_validation/verified_outcome.rs"]
mod verified_outcome;

use verified_outcome::validate_verified_outcome_request;

impl ChioKernel {
    pub(crate) fn threshold_approval_requirement(
        &self,
        request: &ToolCallRequest,
        now: u64,
    ) -> Result<chio_core::capability::threshold_approval::ThresholdApprovalRequirement, KernelError>
    {
        let peer = self
            .capability_negotiation_for_remote(request.federated_origin_kernel_id.as_deref(), now)
            .map_err(KernelError::GovernedTransactionDenied)?;
        if !peer.supports(chio_core::capability::features::THRESHOLD_GOVERNED_APPROVALS) {
            return Err(KernelError::GovernedTransactionDenied(
                "threshold governed approvals were not negotiated".to_string(),
            ));
        }
        let resolver = self
            .threshold_approval_requirement_resolver
            .as_ref()
            .ok_or_else(|| {
                KernelError::GovernedTransactionDenied(
                    "threshold approval requirement resolver is unavailable".to_string(),
                )
            })?;
        let requirement = resolver
            .resolve_requirement(
                &self.config.policy_hash,
                &request.server_id,
                &request.tool_name,
            )
            .map_err(|error| {
                KernelError::GovernedTransactionDenied(format!(
                    "threshold approval requirement resolution failed: {error}"
                ))
            })?
            .ok_or_else(|| {
                KernelError::GovernedTransactionDenied(
                    "request has no matching threshold approval policy requirement".to_string(),
                )
            })?;
        requirement
            .validate()
            .map_err(KernelError::GovernedTransactionDenied)?;
        if requirement.policy_hash != self.config.policy_hash {
            return Err(KernelError::GovernedTransactionDenied(
                "threshold approval requirement is stale for the active policy".to_string(),
            ));
        }
        Ok(requirement)
    }

    pub(crate) fn validate_active_response_intent(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        intent: &chio_core::capability::governance::GovernedTransactionIntent,
        now: u64,
    ) -> Result<(), KernelError> {
        use chio_core::capability::governance::{
            GovernedTransactionIntentBody, ACTIVE_RESPONSE_PLAN_TOOL_NAME,
            ACTIVE_RESPONSE_SERVER_ID,
        };

        let GovernedTransactionIntentBody::ActiveResponsePlan(plan) = &intent.body else {
            return Ok(());
        };
        let peer = self
            .capability_negotiation_for_remote(request.federated_origin_kernel_id.as_deref(), now)
            .map_err(KernelError::GovernedTransactionDenied)?;
        if !peer.supports(chio_core::capability::features::GOVERNED_ACTIVE_RESPONSE_PLAN) {
            return Err(KernelError::GovernedTransactionDenied(
                "governed active-response plans were not negotiated".to_string(),
            ));
        }
        plan.validate()
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        let capability_hash = sha256_hex(&canonical_json_bytes(cap).map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "operator capability is not canonical: {error}"
            ))
        })?);
        if intent.id != plan.plan_id
            || request.request_id != plan.plan_id
            || intent.server_id != ACTIVE_RESPONSE_SERVER_ID
            || intent.tool_name != ACTIVE_RESPONSE_PLAN_TOOL_NAME
            || plan.operator_capability_id != cap.id
            || plan.operator_capability_hash != capability_hash
            || plan.operator_capability_expires_at != cap.expires_at
            || plan.executor_subject != cap.subject
            || now >= plan.expires_at
        {
            return Err(KernelError::GovernedTransactionDenied(
                "active-response intent does not match its request or operator capability"
                    .to_string(),
            ));
        }
        let plan_body_effects = plan
            .canonical_plan_body
            .get("effects")
            .ok_or_else(|| {
                KernelError::GovernedTransactionDenied(
                    "active-response plan body must contain an effects list".to_string(),
                )
            })
            .and_then(|effects| {
                serde_json::from_value::<
                    Vec<chio_core::capability::governance::GovernedResponseEffect>,
                >(effects.clone())
                .map_err(|_| {
                    KernelError::GovernedTransactionDenied(
                        "active-response plan body effects list is invalid".to_string(),
                    )
                })
            })?;
        if plan_body_effects != plan.ordered_effects {
            return Err(KernelError::GovernedTransactionDenied(
                "active-response plan body effects do not match ordered effects".to_string(),
            ));
        }
        for effect in &plan.ordered_effects {
            let covered = cap.scope.grants.iter().any(|grant| {
                grant.server_id == ACTIVE_RESPONSE_SERVER_ID
                    && grant.tool_name == effect.tool_name()
                    && grant.operations.contains(&Operation::Invoke)
            });
            if !covered {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "operator capability does not grant active-response effect {}",
                    effect.tool_name()
                )));
            }
        }
        Ok(())
    }

    fn governed_requirements(
        grant: &ToolGrant,
    ) -> (
        bool,
        Option<u64>,
        Option<String>,
        Option<RuntimeAssuranceTier>,
        Option<GovernedAutonomyTier>,
    ) {
        let mut intent_required = false;
        let mut approval_threshold_units = None;
        let mut seller = None;
        let mut minimum_runtime_assurance = None;
        let mut minimum_autonomy_tier = None;

        for constraint in &grant.constraints {
            match constraint {
                Constraint::GovernedIntentRequired => {
                    intent_required = true;
                }
                Constraint::RequireApprovalAbove { threshold_units } => {
                    approval_threshold_units = Some(
                        approval_threshold_units.map_or(*threshold_units, |current: u64| {
                            current.max(*threshold_units)
                        }),
                    );
                }
                Constraint::SellerExact(expected_seller) => {
                    seller = Some(expected_seller.clone());
                }
                Constraint::MinimumRuntimeAssurance(required_tier) => {
                    minimum_runtime_assurance = Some(
                        minimum_runtime_assurance
                            .map_or(*required_tier, |current: RuntimeAssuranceTier| {
                                current.max(*required_tier)
                            }),
                    );
                }
                Constraint::MinimumAutonomyTier(required_tier) => {
                    minimum_autonomy_tier = Some(
                        minimum_autonomy_tier
                            .map_or(*required_tier, |current: GovernedAutonomyTier| {
                                current.max(*required_tier)
                            }),
                    );
                }
                // The argument/path matchers and the data-layer,
                // communication, financial, model-routing, and
                // memory-governance constraints do not contribute
                // governed-transaction requirements. Their enforcement is
                // wired into request_matching.rs (argument-level checks)
                // and downstream data/content guards (SQL parsing, result
                // shaping, HITL replay). This arm is exhaustive with no
                // `_` catch-all: a new Constraint variant must choose
                // explicitly here rather than be silently dropped from
                // governance requirements.
                Constraint::PathPrefix(_)
                | Constraint::DomainExact(_)
                | Constraint::DomainGlob(_)
                | Constraint::RegexMatch(_)
                | Constraint::MaxLength(_)
                | Constraint::Custom(_, _)
                | Constraint::TableAllowlist(_)
                | Constraint::ColumnDenylist(_)
                | Constraint::MaxRowsReturned(_)
                | Constraint::OperationClass(_)
                | Constraint::AudienceAllowlist(_)
                | Constraint::MaxArgsSize(_)
                | Constraint::ContentReviewTier(_)
                | Constraint::MaxTransactionAmountUsd(_)
                | Constraint::RequireDualApproval(_)
                | Constraint::RequireCumulativeApprovalAbove { .. }
                | Constraint::ModelConstraint { .. }
                | Constraint::MemoryStoreAllowlist(_)
                | Constraint::MemoryWriteDenyPatterns(_) => {}
            }
        }

        (
            intent_required,
            approval_threshold_units,
            seller,
            minimum_runtime_assurance,
            minimum_autonomy_tier,
        )
    }

    fn verify_governed_approval_signature(
        &self,
        approval_token: &GovernedApprovalToken,
    ) -> Result<(), String> {
        // Multi-algorithm dispatch happens inside `approval_token.verify_signature()`:
        // the `approver` public key and the `signature` field are each algorithm-
        // tagged (Ed25519 by default; `p256:` / `p384:` under the FIPS crypto
        // path), so ECDSA approvals are validated through aws-lc-rs when the
        // `chio-core-types/fips` feature is enabled without any kernel-side
        // algorithm plumbing.
        let kernel_pk = self.config.keypair.public_key();
        let mut trusted = self.config.ca_public_keys.clone();
        for authority_pk in self.capability_authority.trusted_public_keys() {
            if !trusted.contains(&authority_pk) {
                trusted.push(authority_pk);
            }
        }
        if !trusted.contains(&kernel_pk) {
            trusted.push(kernel_pk);
        }

        for pk in &trusted {
            if *pk == approval_token.approver {
                return match approval_token.verify_signature() {
                    Ok(true) => Ok(()),
                    Ok(false) => Err("signature did not verify".to_string()),
                    Err(error) => Err(error.to_string()),
                };
            }
        }

        Err("approval signer public key not found among trusted authorities".to_string())
    }

    fn trusted_governance_authorities(&self) -> Vec<chio_core::PublicKey> {
        let kernel_pk = self.config.keypair.public_key();
        let mut trusted = self.config.ca_public_keys.clone();
        for authority_pk in self.capability_authority.trusted_public_keys() {
            if !trusted.contains(&authority_pk) {
                trusted.push(authority_pk);
            }
        }
        if !trusted.contains(&kernel_pk) {
            trusted.push(kernel_pk);
        }
        trusted
    }

    fn verify_governed_runtime_attestation(
        &self,
        attestation: &chio_core::capability::runtime_attestation::RuntimeAttestationEvidence,
        now: u64,
    ) -> Result<VerifiedRuntimeAttestationRecord, KernelError> {
        verify_governed_runtime_attestation_record(
            attestation,
            self.attestation_trust_policy.as_ref(),
            now,
        )
    }

    fn verify_governed_request_runtime_attestation(
        &self,
        request: &ToolCallRequest,
        now: u64,
    ) -> Result<Option<VerifiedRuntimeAttestationRecord>, KernelError> {
        request
            .governed_intent
            .as_ref()
            .and_then(|intent| intent.runtime_attestation.as_ref())
            .map(|attestation| self.verify_governed_runtime_attestation(attestation, now))
            .transpose()
    }

    fn validate_runtime_assurance(
        verified_runtime_attestation: Option<&VerifiedRuntimeAttestationRecord>,
        required_tier: RuntimeAssuranceTier,
        requirement_source: &str,
    ) -> Result<(), KernelError> {
        let Some(verified_runtime_attestation) = verified_runtime_attestation else {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "runtime attestation tier '{required_tier:?}' required by {requirement_source}"
            )));
        };

        if !verified_runtime_attestation.is_locally_accepted() {
            let reason = verified_runtime_attestation
                .policy_outcome
                .reason
                .as_deref()
                .unwrap_or(
                    "runtime attestation evidence did not cross a local verified trust boundary",
                );
            return Err(KernelError::GovernedTransactionDenied(format!(
                "runtime attestation tier '{required_tier:?}' required by {requirement_source}; {reason}"
            )));
        }

        let effective_tier = verified_runtime_attestation.effective_tier();
        if effective_tier < required_tier {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "runtime attestation tier '{effective_tier:?}' is below required '{required_tier:?}' for {requirement_source}"
            )));
        }

        Ok(())
    }

    fn validate_governed_approval_token_pure(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        intent_hash: &str,
        approval_token: &GovernedApprovalToken,
        now: u64,
    ) -> Result<(), KernelError> {
        approval_token
            .validate_time(now)
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;

        if approval_token.request_id != request.request_id {
            return Err(KernelError::GovernedTransactionDenied(
                "approval token request binding does not match the tool call".to_string(),
            ));
        }

        if approval_token.governed_intent_hash != intent_hash {
            return Err(KernelError::GovernedTransactionDenied(
                "approval token intent binding does not match the governed intent".to_string(),
            ));
        }

        if approval_token.subject != cap.subject {
            return Err(KernelError::GovernedTransactionDenied(
                "approval token subject does not match the capability subject".to_string(),
            ));
        }

        if approval_token.decision != GovernedApprovalDecision::Approved {
            return Err(KernelError::GovernedTransactionDenied(
                "approval token does not approve the governed transaction".to_string(),
            ));
        }

        self.verify_governed_approval_signature(approval_token)
            .map_err(|reason| {
                KernelError::GovernedTransactionDenied(format!(
                    "approval token verification failed: {reason}"
                ))
            })?;

        // Step 7: Cap approval token lifetime. Tokens with expires_at more
        // than MAX_APPROVAL_TTL_SECS beyond issued_at are rejected to prevent
        // long-lived tokens from outliving the replay store's eviction window.
        const MAX_APPROVAL_TTL_SECS: u64 = 3600; // 1 hour max
        let token_lifetime = approval_token
            .expires_at
            .saturating_sub(approval_token.issued_at);
        if token_lifetime > MAX_APPROVAL_TTL_SECS {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "approval token lifetime ({token_lifetime}s) exceeds maximum ({MAX_APPROVAL_TTL_SECS}s)"
            )));
        }

        Ok(())
    }

    fn reserve_legacy_governed_approval(
        &self,
        approval_token: &GovernedApprovalToken,
        intent_hash: &str,
    ) -> Result<(), KernelError> {
        if let Some(ref replay_store) = self.approval_replay_store {
            let is_fresh = replay_store
                .check_and_insert(&approval_token.request_id, intent_hash)
                .map_err(|_| {
                    KernelError::GovernedTransactionDenied(
                        "approval replay store unavailable; denying as fail-closed".to_string(),
                    )
                })?;
            if !is_fresh {
                return Err(KernelError::GovernedTransactionDenied(
                    "approval token has already been consumed (replay detected)".to_string(),
                ));
            }
        } else {
            return Err(KernelError::GovernedTransactionDenied(
                "approval replay store not configured; denying as fail-closed".to_string(),
            ));
        }

        Ok(())
    }

    pub(crate) fn validate_threshold_approval_set(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        intent_hash: &str,
        now: u64,
    ) -> Result<VerifiedThresholdApprovalSet, KernelError> {
        use std::collections::HashSet;

        const MAX_APPROVAL_TOKENS: usize =
            chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS;
        if request.approval_tokens.is_empty() || request.approval_tokens.len() > MAX_APPROVAL_TOKENS
        {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "threshold approval set must contain between 1 and {MAX_APPROVAL_TOKENS} tokens"
            )));
        }
        let requirement = self.threshold_approval_requirement(request, now)?;
        let proposal = request
            .threshold_approval_proposal
            .as_ref()
            .ok_or_else(|| {
                KernelError::GovernedTransactionDenied(
                    "threshold approval set omitted its signed proposal".to_string(),
                )
            })?;
        proposal
            .validate_at(now)
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        if !self
            .trusted_governance_authorities()
            .contains(&proposal.body.policy_authority)
        {
            return Err(KernelError::GovernedTransactionDenied(
                "threshold proposal signer is not a trusted policy authority".to_string(),
            ));
        }
        if !proposal
            .verify_signature()
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?
        {
            return Err(KernelError::GovernedTransactionDenied(
                "threshold proposal signature did not verify".to_string(),
            ));
        }
        let capability_digest = sha256_hex(&canonical_json_bytes(cap).map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "authorizing capability is not canonical: {error}"
            ))
        })?);
        let proposal_body = &proposal.body;
        let expected_deadline = proposal_body
            .proposal_created_at
            .checked_add(requirement.timeout_seconds)
            .ok_or_else(|| {
                KernelError::GovernedTransactionDenied(
                    "threshold proposal deadline overflowed".to_string(),
                )
            })?
            .min(cap.expires_at)
            .min(
                request
                    .governed_intent
                    .as_ref()
                    .and_then(|intent| intent.governed_operation_expires_at())
                    .unwrap_or(u64::MAX),
            );
        if proposal_body.request_id != request.request_id
            || proposal_body.governed_intent_hash != intent_hash
            || proposal_body.subject != cap.subject
            || proposal_body.authorizing_capability_digest != capability_digest
            || proposal_body.policy_hash != requirement.policy_hash
            || proposal_body.threshold != requirement.threshold
            || proposal_body.eligible_set_digest != requirement.eligible_set_digest
            || proposal_body.proposal_deadline != expected_deadline
        {
            return Err(KernelError::GovernedTransactionDenied(
                "threshold proposal does not match the request, capability, or active policy"
                    .to_string(),
            ));
        }
        let proposal_hash = proposal
            .artifact_digest()
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        let mut token_ids = HashSet::new();
        let mut token_digests = HashSet::new();
        let mut approvers = HashSet::new();
        for token in &request.approval_tokens {
            token
                .validate_time(now)
                .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
            if token.id.is_empty()
                || token.id.trim() != token.id
                || token.request_id != request.request_id
                || token.governed_intent_hash != intent_hash
                || token.subject != cap.subject
                || token.decision != GovernedApprovalDecision::Approved
                || token.threshold_proposal_hash.as_deref() != Some(proposal_hash.as_str())
                || token.issued_at < proposal_body.proposal_created_at
                || token.issued_at >= proposal_body.proposal_deadline
                || token.expires_at > proposal_body.proposal_deadline
            {
                return Err(KernelError::GovernedTransactionDenied(
                    "threshold approval token does not match the signed proposal".to_string(),
                ));
            }
            if !requirement
                .eligible_approvers
                .iter()
                .any(|eligible| eligible.public_key == token.approver)
            {
                return Err(KernelError::GovernedTransactionDenied(
                    "threshold approval token signer is not eligible".to_string(),
                ));
            }
            if !token
                .verify_signature()
                .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?
            {
                return Err(KernelError::GovernedTransactionDenied(
                    "threshold approval token signature did not verify".to_string(),
                ));
            }
            let token_digest = token
                .artifact_digest()
                .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
            if !token_ids.insert(token.id.clone())
                || !token_digests.insert(token_digest)
                || !approvers.insert(token.approver.to_hex())
            {
                return Err(KernelError::GovernedTransactionDenied(
                    "threshold approval tokens, digests, and signers must be distinct".to_string(),
                ));
            }
        }
        if approvers.len()
            < usize::try_from(requirement.threshold).map_err(|_| {
                KernelError::GovernedTransactionDenied(
                    "threshold approval quorum does not fit this platform".to_string(),
                )
            })?
        {
            return Err(KernelError::GovernedTransactionDenied(
                "threshold approval set does not satisfy the required quorum".to_string(),
            ));
        }
        let verified = chio_core::capability::governance::VerifiedApprovalSetBody::new(
            token_digests.into_iter().collect(),
            proposal,
        )
        .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        let replay = ThresholdApprovalReplayReservationV1::new(
            proposal.clone(),
            request.approval_tokens.clone(),
            verified.clone(),
        )
        .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        Ok(VerifiedThresholdApprovalSet {
            requirement,
            body: verified,
            replay,
        })
    }

    fn validate_metered_billing_context(
        intent: &chio_core::capability::governance::GovernedTransactionIntent,
        charge_currency: Option<&str>,
        now: u64,
    ) -> Result<(), KernelError> {
        let Some(metered) = intent.metered_billing.as_ref() else {
            return Ok(());
        };

        let quote = &metered.quote;
        if quote.quote_id.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing quote_id must not be empty".to_string(),
            ));
        }
        if quote.provider.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing provider must not be empty".to_string(),
            ));
        }
        if quote.billing_unit.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing unit must not be empty".to_string(),
            ));
        }
        if quote.quoted_units == 0 {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing quoted_units must be greater than zero".to_string(),
            ));
        }
        if quote
            .expires_at
            .is_some_and(|expires_at| expires_at <= quote.issued_at)
        {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing quote expires_at must be after issued_at".to_string(),
            ));
        }
        if !quote.is_valid_at(now) {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing quote is not valid at the current time".to_string(),
            ));
        }
        if metered.max_billed_units == Some(0) {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing max_billed_units must be greater than zero when present"
                    .to_string(),
            ));
        }
        if metered
            .max_billed_units
            .is_some_and(|max_billed_units| max_billed_units < quote.quoted_units)
        {
            return Err(KernelError::GovernedTransactionDenied(
                "metered billing max_billed_units cannot be lower than quote.quoted_units"
                    .to_string(),
            ));
        }
        validate_verified_outcome_request(metered)?;
        if let Some(intent_amount) = intent.max_amount.as_ref() {
            if intent_amount.currency != quote.quoted_cost.currency {
                return Err(KernelError::GovernedTransactionDenied(
                    "metered billing quote currency does not match governed intent currency"
                        .to_string(),
                ));
            }
        }
        if let Some(currency) = charge_currency {
            if currency != quote.quoted_cost.currency {
                return Err(KernelError::GovernedTransactionDenied(
                    "metered billing quote currency does not match the grant currency".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn mustprepay_prepaid_units(
        intent: &chio_core::capability::governance::GovernedTransactionIntent,
    ) -> Option<u64> {
        intent
            .metered_billing
            .as_ref()
            .filter(|metered| {
                metered.settlement_mode
                    == chio_core::capability::governance::MeteredSettlementMode::MustPrepay
            })
            .map(|metered| metered.quote.quoted_cost.units)
    }

    fn validate_governed_call_chain_context(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        intent: &chio_core::capability::governance::GovernedTransactionIntent,
        parent_context: Option<&OperationContext>,
        now: u64,
    ) -> Result<Option<ValidatedGovernedCallChainProof>, KernelError> {
        let Some(call_chain) = intent.call_chain.as_ref() else {
            return Ok(None);
        };

        if call_chain.chain_id.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain.chain_id must not be empty".to_string(),
            ));
        }
        if call_chain.parent_request_id.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain.parent_request_id must not be empty".to_string(),
            ));
        }
        if call_chain.parent_request_id == request.request_id {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain.parent_request_id must not equal the current request_id"
                    .to_string(),
            ));
        }
        if let Some(parent_context) = parent_context {
            let local_parent_request_id = parent_context.request_id.to_string();
            if call_chain.parent_request_id != local_parent_request_id {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain.parent_request_id does not match the locally authenticated parent request".to_string(),
                ));
            }
            self.validate_parent_request_continuation(request, parent_context)?;
        }
        if call_chain.origin_subject.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain.origin_subject must not be empty".to_string(),
            ));
        }
        if call_chain.delegator_subject.trim().is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain.delegator_subject must not be empty".to_string(),
            ));
        }
        if call_chain
            .parent_receipt_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain.parent_receipt_id must not be empty when present".to_string(),
            ));
        }
        if let Some(capability_delegator_subject) = cap
            .delegation_chain
            .last()
            .map(|link| link.delegator.to_hex())
        {
            if call_chain.delegator_subject != capability_delegator_subject {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain.delegator_subject does not match the validated capability delegation source".to_string(),
                ));
            }
        }
        if let Some(capability_origin_subject) = cap
            .delegation_chain
            .first()
            .map(|link| link.delegator.to_hex())
        {
            if call_chain.origin_subject != capability_origin_subject {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain.origin_subject does not match the validated capability lineage origin".to_string(),
                ));
            }
        }

        self.validate_governed_call_chain_upstream_proof(
            request,
            cap,
            intent,
            call_chain,
            parent_context,
            now,
        )
    }

    fn validate_governed_call_chain_upstream_proof(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        intent: &chio_core::capability::governance::GovernedTransactionIntent,
        call_chain: &chio_core::capability::governance::GovernedCallChainContext,
        parent_context: Option<&OperationContext>,
        now: u64,
    ) -> Result<Option<ValidatedGovernedCallChainProof>, KernelError> {
        if let Some(continuation_token) = intent.explicit_continuation_token().map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "governed call_chain continuation token is malformed: {error}"
            ))
        })? {
            let signature_valid = continuation_token.verify_signature().map_err(|error| {
                KernelError::GovernedTransactionDenied(format!(
                    "governed call_chain continuation token failed signature verification: {error}"
                ))
            })?;
            if !signature_valid {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token failed signature verification"
                        .to_string(),
                ));
            }
            continuation_token.validate_time(now).map_err(|error| {
                KernelError::GovernedTransactionDenied(format!(
                    "governed call_chain continuation token rejected by time bounds: {error}"
                ))
            })?;
            if continuation_token.subject != cap.subject {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token subject does not match the capability subject"
                        .to_string(),
                ));
            }
            if continuation_token.current_subject != cap.subject.to_hex() {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token current_subject does not match the capability subject"
                        .to_string(),
                ));
            }

            let signer_matches_capability_lineage = cap
                .delegation_chain
                .last()
                .is_some_and(|link| link.delegator == continuation_token.signer);
            if !self.is_trusted_governed_continuation_signer(&continuation_token.signer)
                && !signer_matches_capability_lineage
            {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token signer is not trusted".to_string(),
                ));
            }
            if continuation_token.chain_id != call_chain.chain_id {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token chain_id does not match the asserted call_chain".to_string(),
                ));
            }
            if continuation_token.parent_request_id != call_chain.parent_request_id {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token parent_request_id does not match the asserted call_chain".to_string(),
                ));
            }
            if continuation_token.parent_receipt_id != call_chain.parent_receipt_id {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token parent_receipt_id does not match the asserted call_chain".to_string(),
                ));
            }
            if continuation_token.origin_subject != call_chain.origin_subject {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token origin_subject does not match the asserted call_chain".to_string(),
                ));
            }
            if continuation_token.delegator_subject != call_chain.delegator_subject {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token delegator_subject does not match the asserted call_chain".to_string(),
                ));
            }
            if continuation_token.audience.is_some()
                && !continuation_token.matches_target(&request.server_id, &request.tool_name)
            {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed call_chain continuation token target does not match the tool call"
                        .to_string(),
                ));
            }
            if let Some(expected_intent_hash) = continuation_token.governed_intent_hash.as_deref() {
                let intent_hash = intent.binding_hash().map_err(|error| {
                    KernelError::GovernedTransactionDenied(format!(
                        "failed to hash governed transaction intent for continuation validation: {error}"
                    ))
                })?;
                if expected_intent_hash != intent_hash {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token intent_hash does not match the governed intent".to_string(),
                    ));
                }
            }
            if let Some(parent_capability_id) = continuation_token.parent_capability_id.as_deref() {
                let Some(expected_parent_capability_id) = cap
                    .delegation_chain
                    .last()
                    .map(|link| link.capability_id.as_str())
                else {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token parent_capability_id requires a delegated capability lineage".to_string(),
                    ));
                };
                if parent_capability_id != expected_parent_capability_id {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token parent_capability_id does not match the capability lineage".to_string(),
                    ));
                }
            }
            if let Some(expected_link_hash) = continuation_token.delegation_link_hash.as_deref() {
                let Some(last_link) = cap.delegation_chain.last() else {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token delegation_link_hash requires a delegated capability lineage".to_string(),
                    ));
                };
                let actual_link_hash =
                    canonical_json_bytes(&last_link.body()).map_err(|error| {
                        KernelError::GovernedTransactionDenied(format!(
                            "failed to hash capability delegation lineage for continuation validation: {error}"
                        ))
                    })?;
                if sha256_hex(&actual_link_hash) != expected_link_hash {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token delegation_link_hash does not match the capability lineage".to_string(),
                    ));
                }
            }

            let local_parent_receipt = if let Some(parent_receipt_id) =
                continuation_token.parent_receipt_id.as_deref()
            {
                match self.local_receipt_artifact(parent_receipt_id)? {
                    Some(parent_receipt) => {
                        let signature_valid = parent_receipt.verify_signature_with_floor(
                            receipt_crypto_floor(self.capability_crypto_floor),
                        )?;
                        if !signature_valid {
                            return Err(KernelError::GovernedTransactionDenied(
                                "governed call_chain parent receipt failed signature verification"
                                    .to_string(),
                            ));
                        }
                        Some(parent_receipt)
                    }
                    None => {
                        if continuation_token.parent_receipt_hash.is_some()
                            || continuation_token.parent_session_anchor.is_some()
                        {
                            return Err(KernelError::GovernedTransactionDenied(
                                "governed call_chain continuation token parent_receipt_id does not resolve to a locally persisted receipt".to_string(),
                            ));
                        }
                        None
                    }
                }
            } else {
                if continuation_token.parent_receipt_hash.is_some() {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token parent_receipt_hash requires parent_receipt_id".to_string(),
                    ));
                }
                None
            };

            if let Some(expected_parent_receipt_hash) =
                continuation_token.parent_receipt_hash.as_deref()
            {
                let Some(parent_receipt) = local_parent_receipt.as_ref() else {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token parent_receipt_hash requires a locally persisted parent receipt".to_string(),
                    ));
                };
                if parent_receipt.artifact_hash()? != expected_parent_receipt_hash {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token parent_receipt_hash does not match the authoritative parent receipt".to_string(),
                    ));
                }
            }

            let validated_session_anchor_id = if let Some(parent_session_anchor) =
                continuation_token.parent_session_anchor.as_ref()
            {
                let authoritative_parent_anchor = if let Some(parent_context) = parent_context {
                    Some(self.with_session(&parent_context.session_id, |session| {
                        session.validate_context(parent_context)?;
                        Ok(session.session_anchor().reference())
                    })?)
                } else {
                    local_parent_receipt
                        .as_ref()
                        .and_then(LocalReceiptArtifact::session_anchor_reference)
                };
                let Some(authoritative_parent_anchor) = authoritative_parent_anchor else {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token parent_session_anchor could not be verified against authoritative parent lineage".to_string(),
                    ));
                };
                if authoritative_parent_anchor != *parent_session_anchor {
                    return Err(KernelError::GovernedTransactionDenied(
                        "governed call_chain continuation token session anchor does not match the authoritative parent lineage".to_string(),
                    ));
                }
                Some(parent_session_anchor.session_anchor_id.clone())
            } else {
                None
            };

            return Ok(Some(ValidatedGovernedCallChainProof {
                upstream_proof: None,
                continuation_token_id: Some(continuation_token.token_id.clone()),
                session_anchor_id: validated_session_anchor_id,
            }));
        }

        let Some(upstream_proof) = intent.upstream_call_chain_proof().map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "governed call_chain upstream proof is malformed: {error}"
            ))
        })?
        else {
            return Ok(None);
        };

        let signature_valid = upstream_proof.verify_signature().map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "governed call_chain upstream proof failed signature verification: {error}"
            ))
        })?;
        if !signature_valid {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain upstream proof failed signature verification".to_string(),
            ));
        }
        upstream_proof.validate_time(now).map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "governed call_chain upstream proof rejected by time bounds: {error}"
            ))
        })?;
        if upstream_proof.subject != cap.subject {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain upstream proof subject does not match the capability subject"
                    .to_string(),
            ));
        }

        let Some(expected_signer) = cap.delegation_chain.last().map(|link| &link.delegator) else {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain upstream proof requires a delegated capability lineage"
                    .to_string(),
            ));
        };
        if upstream_proof.signer != *expected_signer {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain upstream proof signer does not match the validated capability delegation source".to_string(),
            ));
        }
        if upstream_proof.chain_id != call_chain.chain_id {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain upstream proof chain_id does not match the asserted call_chain".to_string(),
            ));
        }
        if upstream_proof.parent_request_id != call_chain.parent_request_id {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain upstream proof parent_request_id does not match the asserted call_chain".to_string(),
            ));
        }
        if upstream_proof.parent_receipt_id != call_chain.parent_receipt_id {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain upstream proof parent_receipt_id does not match the asserted call_chain".to_string(),
            ));
        }
        if upstream_proof.origin_subject != call_chain.origin_subject {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain upstream proof origin_subject does not match the asserted call_chain".to_string(),
            ));
        }
        if upstream_proof.delegator_subject != call_chain.delegator_subject {
            return Err(KernelError::GovernedTransactionDenied(
                "governed call_chain upstream proof delegator_subject does not match the asserted call_chain".to_string(),
            ));
        }

        Ok(Some(ValidatedGovernedCallChainProof {
            upstream_proof: Some(upstream_proof),
            continuation_token_id: None,
            session_anchor_id: None,
        }))
    }

    fn validate_governed_autonomy_bond(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        bond_id: &str,
        now: u64,
    ) -> Result<(), KernelError> {
        let Some(bond_row) = self.with_receipt_store(|store| {
            store.resolve_credit_bond(bond_id).map_err(|error| {
                KernelError::GovernedTransactionDenied(format!(
                    "failed to resolve delegation bond `{bond_id}`: {error}"
                ))
            })
        })?
        else {
            return Err(KernelError::GovernedTransactionDenied(
                "delegation bond lookup unavailable because no receipt store is configured"
                    .to_string(),
            ));
        };
        let bond_row = bond_row.ok_or_else(|| {
            KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` was not found"
            ))
        })?;

        let signed_bond = &bond_row.bond;
        let signature_valid = signed_bond.verify_signature().map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` failed signature verification: {error}"
            ))
        })?;
        if !signature_valid {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` failed signature verification"
            )));
        }
        if bond_row.lifecycle_state != CreditBondLifecycleState::Active {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` is not active"
            )));
        }
        if signed_bond.body.expires_at <= now {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` is expired"
            )));
        }

        let report = &signed_bond.body.report;
        if !report.support_boundary.autonomy_gating_supported {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` does not advertise runtime autonomy gating support"
            )));
        }
        if !report.prerequisites.active_facility_met {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` is missing an active granted facility"
            )));
        }
        if !report.prerequisites.runtime_assurance_met {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` was issued without satisfied runtime assurance prerequisites"
            )));
        }
        if report.prerequisites.certification_required && !report.prerequisites.certification_met {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` requires an active certification record"
            )));
        }
        match report.disposition {
            CreditBondDisposition::Lock | CreditBondDisposition::Hold => {}
            CreditBondDisposition::Release => {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "delegation bond `{bond_id}` is released and does not back autonomous execution"
                )));
            }
            CreditBondDisposition::Impair => {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "delegation bond `{bond_id}` is impaired and does not back autonomous execution"
                )));
            }
        }

        let subject_key = cap.subject.to_hex();
        let mut bound_to_subject_or_capability = false;
        if let Some(bound_subject) = report.filters.agent_subject.as_deref() {
            if bound_subject != subject_key {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "delegation bond `{bond_id}` subject binding does not match the capability subject"
                )));
            }
            bound_to_subject_or_capability = true;
        }
        if let Some(bound_capability_id) = report.filters.capability_id.as_deref() {
            if bound_capability_id != cap.id {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "delegation bond `{bond_id}` capability binding does not match the executing capability"
                )));
            }
            bound_to_subject_or_capability = true;
        }
        if !bound_to_subject_or_capability {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` must be bound to the current capability or subject"
            )));
        }

        let Some(bound_server) = report.filters.tool_server.as_deref() else {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` must be scoped to the current tool server"
            )));
        };
        if bound_server != request.server_id {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "delegation bond `{bond_id}` tool server scope does not match the governed request"
            )));
        }
        if let Some(bound_tool) = report.filters.tool_name.as_deref() {
            if bound_tool != request.tool_name {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "delegation bond `{bond_id}` tool scope does not match the governed request"
                )));
            }
        }

        Ok(())
    }

    fn validate_governed_autonomy(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        intent: &chio_core::capability::governance::GovernedTransactionIntent,
        minimum_autonomy_tier: Option<GovernedAutonomyTier>,
        verified_runtime_attestation: Option<&VerifiedRuntimeAttestationRecord>,
        now: u64,
    ) -> Result<(), KernelError> {
        let autonomy = match (intent.autonomy.as_ref(), minimum_autonomy_tier) {
            (None, None) => return Ok(()),
            (Some(autonomy), _) => autonomy,
            (None, Some(required_tier)) => {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "governed autonomy tier '{required_tier:?}' required by grant"
                )));
            }
        };

        if let Some(required_tier) = minimum_autonomy_tier {
            if autonomy.tier < required_tier {
                return Err(KernelError::GovernedTransactionDenied(format!(
                    "governed autonomy tier '{:?}' is below required '{required_tier:?}'",
                    autonomy.tier
                )));
            }
        }

        let bond_id = autonomy
            .delegation_bond_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());

        if !autonomy.tier.requires_delegation_bond() {
            if bond_id.is_some() {
                return Err(KernelError::GovernedTransactionDenied(
                    "direct governed autonomy tier must not attach a delegation bond".to_string(),
                ));
            }
            return Ok(());
        }

        if autonomy.tier.requires_call_chain() && intent.call_chain.is_none() {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "governed autonomy tier '{:?}' requires delegated call-chain context",
                autonomy.tier
            )));
        }

        let required_runtime_assurance = autonomy.tier.minimum_runtime_assurance();
        let requirement_source = format!("governed autonomy tier '{:?}'", autonomy.tier);
        Self::validate_runtime_assurance(
            verified_runtime_attestation,
            required_runtime_assurance,
            &requirement_source,
        )?;

        let bond_id = bond_id.ok_or_else(|| {
            KernelError::GovernedTransactionDenied(format!(
                "governed autonomy tier '{:?}' requires a delegation bond attachment",
                autonomy.tier
            ))
        })?;
        self.validate_governed_autonomy_bond(request, cap, bond_id, now)
    }

    pub(crate) fn validate_governed_transaction_pure(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        grant: &ToolGrant,
        context: GovernedValidationContext<'_>,
    ) -> Result<Option<ValidatedGovernedAdmission>, KernelError> {
        let GovernedValidationContext {
            parent_context,
            now,
        } = context;
        let (
            intent_required,
            approval_threshold_units,
            required_seller,
            minimum_runtime_assurance,
            minimum_autonomy_tier,
        ) = Self::governed_requirements(grant);
        let governed_request_present = request.governed_intent.is_some()
            || request.approval_token.is_some()
            || !request.approval_tokens.is_empty()
            || request.threshold_approval_proposal.is_some();

        if !intent_required
            && approval_threshold_units.is_none()
            && required_seller.is_none()
            && minimum_runtime_assurance.is_none()
            && minimum_autonomy_tier.is_none()
            && !governed_request_present
        {
            return Ok(None);
        }

        let intent = request.governed_intent.as_ref().ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "governed transaction intent required by grant or request".to_string(),
            )
        })?;

        if intent.server_id != request.server_id || intent.tool_name != request.tool_name {
            return Err(KernelError::GovernedTransactionDenied(
                "governed transaction intent target does not match the tool call".to_string(),
            ));
        }

        self.validate_active_response_intent(request, cap, intent, now)?;
        if matches!(
            &intent.body,
            chio_core::capability::governance::GovernedTransactionIntentBody::ActiveResponsePlan(_)
        ) {
            return Err(KernelError::GovernedTransactionDenied(
                "active-response plans require the approval-only admission API".to_owned(),
            ));
        }

        let verified_runtime_attestation =
            self.verify_governed_request_runtime_attestation(request, now)?;

        let validated_upstream_call_chain_proof =
            self.validate_governed_call_chain_context(request, cap, intent, parent_context, now)?;

        let intent_hash = intent.binding_hash().map_err(|error| {
            KernelError::GovernedTransactionDenied(format!(
                "failed to hash governed transaction intent: {error}"
            ))
        })?;
        let commerce = intent.commerce.as_ref();

        if let Some(commerce) = commerce {
            if commerce.seller.trim().is_empty() {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed commerce seller scope must not be empty".to_string(),
                ));
            }
            if commerce.shared_payment_token_id.trim().is_empty() {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed commerce approval requires a shared payment token reference"
                        .to_string(),
                ));
            }
            if intent.max_amount.is_none() {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed commerce approval requires an explicit max_amount bound".to_string(),
                ));
            }
            if commerce
                .settlement_destination_ref
                .as_deref()
                .is_some_and(|destination| {
                    destination.is_empty()
                        || destination.trim() != destination
                        || destination.chars().count() > 2_048
                        || destination.chars().any(char::is_control)
                })
            {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed commerce settlement destination is invalid".to_string(),
                ));
            }
        }

        if let Some(required_seller) = required_seller.as_deref() {
            let commerce = commerce.ok_or_else(|| {
                KernelError::GovernedTransactionDenied(
                    "seller-scoped governed request requires commerce approval context".to_string(),
                )
            })?;
            if commerce.seller != required_seller {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed commerce seller does not match the grant seller scope".to_string(),
                ));
            }
        }

        if let Some(required_tier) = minimum_runtime_assurance {
            Self::validate_runtime_assurance(
                verified_runtime_attestation.as_ref(),
                required_tier,
                "grant",
            )?;
        }
        self.validate_governed_autonomy(
            request,
            cap,
            intent,
            minimum_autonomy_tier,
            verified_runtime_attestation.as_ref(),
            now,
        )?;

        let projected_cost = grant
            .max_cost_per_invocation
            .as_ref()
            .map(|amount| (amount.units, amount.currency.as_str()));
        let charge_currency = projected_cost.map(|(_, currency)| currency).or_else(|| {
            grant
                .max_total_cost
                .as_ref()
                .map(|amount| amount.currency.as_str())
        });
        Self::validate_metered_billing_context(intent, charge_currency, now)?;
        if Self::mustprepay_prepaid_units(intent).is_some() && self.payment_adapter.is_none() {
            return Err(KernelError::GovernedTransactionDenied(
                "governed intent mandates prepayment (settlement_mode=MustPrepay) but no payment adapter is configured"
                    .to_string(),
            ));
        }

        if let (Some(intent_amount), Some((cost_units, currency))) =
            (intent.max_amount.as_ref(), projected_cost)
        {
            if intent_amount.currency != currency {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed intent currency does not match the grant currency".to_string(),
                ));
            }
            if intent_amount.units < cost_units {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed intent amount is lower than the provisional invocation charge"
                        .to_string(),
                ));
            }
        }

        let mustprepay_prepaid_units = Self::mustprepay_prepaid_units(intent);
        if let Some(prepaid_units) = mustprepay_prepaid_units {
            // The pre-execution budget debit is the per-invocation ceiling, so a grant that
            // declares only a cumulative ceiling debits nothing and never advances its own
            // total. Prepayment against that shape cannot be accounted across calls.
            if grant.max_cost_per_invocation.is_none() && grant.max_total_cost.is_some() {
                return Err(KernelError::GovernedTransactionDenied(
                    "MustPrepay against a cumulative-only grant cannot be accounted; declare max_cost_per_invocation"
                        .to_string(),
                ));
            }
            for (limit_name, limit) in [
                ("per-invocation", grant.max_cost_per_invocation.as_ref()),
                ("cumulative", grant.max_total_cost.as_ref()),
            ] {
                if limit.is_some_and(|amount| prepaid_units > amount.units) {
                    return Err(KernelError::GovernedTransactionDenied(format!(
                        "MustPrepay quoted cost exceeds the grant {limit_name} cost limit"
                    )));
                }
            }
        }
        if let (Some(intent_amount), Some(prepaid_units)) =
            (intent.max_amount.as_ref(), mustprepay_prepaid_units)
        {
            if intent_amount.units < prepaid_units {
                return Err(KernelError::GovernedTransactionDenied(
                    "governed intent amount is lower than the MustPrepay quoted cost".to_string(),
                ));
            }
        }

        let base_units = projected_cost
            .map(|(cost_units, _)| cost_units)
            .or_else(|| intent.max_amount.as_ref().map(|amount| amount.units));
        let requested_units = match (base_units, mustprepay_prepaid_units) {
            (Some(base), Some(prepaid)) => base.max(prepaid),
            (base, prepaid) => base.or(prepaid).unwrap_or(0),
        };
        let economy_value_requires_payee =
            projected_cost.is_some_and(|(cost_units, _)| cost_units > 0) && commerce.is_some();
        if economy_value_requires_payee
            && commerce
                .and_then(|commerce| commerce.settlement_destination_ref.as_ref())
                .is_none()
        {
            return Err(KernelError::GovernedTransactionDenied(
                "governed economy value requires an explicit settlement destination".to_string(),
            ));
        }
        let approval_required = approval_threshold_units
            .map(|threshold_units| requested_units >= threshold_units)
            .unwrap_or(false)
            || economy_value_requires_payee;

        if request.approval_token.is_some() && !request.approval_tokens.is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "request must not supply both singular and threshold approval tokens".to_string(),
            ));
        }
        if request.threshold_approval_proposal.is_some() && request.approval_tokens.is_empty() {
            return Err(KernelError::GovernedTransactionDenied(
                "threshold approval proposal requires an approval token set".to_string(),
            ));
        }
        let (approval_artifact_digest, approval_reservation) = if let Some(approval_token) =
            request.approval_token.as_ref()
        {
            self.validate_governed_approval_token_pure(
                request,
                cap,
                &intent_hash,
                approval_token,
                now,
            )?;
            let digest = approval_token
                .artifact_digest()
                .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
            (
                Some(digest.clone()),
                Some(VerifiedApprovalReservation {
                    threshold_proposal_hash: digest.clone(),
                    approval_set_hash: digest,
                    threshold_replay: None,
                }),
            )
        } else if !request.approval_tokens.is_empty() {
            let verified = self.validate_threshold_approval_set(request, cap, &intent_hash, now)?;
            let digest = verified
                .body
                .approval_set_hash()
                .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
            (
                Some(digest.clone()),
                Some(VerifiedApprovalReservation {
                    threshold_proposal_hash: verified.body.threshold_proposal_hash.clone(),
                    approval_set_hash: digest,
                    threshold_replay: Some(verified.replay),
                }),
            )
        } else {
            (None, None)
        };
        if approval_required && approval_artifact_digest.is_none() {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "approval token required for governed transaction intent {}",
                intent.id
            )));
        }

        let verified_payee_binding = match (
            economy_value_requires_payee,
            commerce,
            approval_artifact_digest.as_ref(),
        ) {
            (true, Some(commerce), Some(approval_artifact_digest)) => {
                let settlement_destination_ref = commerce
                    .settlement_destination_ref
                    .as_ref()
                    .ok_or_else(|| {
                        KernelError::GovernedTransactionDenied(
                            "governed economy value requires an explicit settlement destination"
                                .to_string(),
                        )
                    })?;
                Some(
                    VerifiedGovernedPayeeBinding::new(
                        commerce.seller.clone(),
                        settlement_destination_ref.clone(),
                        intent_hash.clone(),
                        approval_artifact_digest.clone(),
                    )
                    .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?,
                )
            }
            _ => None,
        };

        Ok(Some(ValidatedGovernedAdmission {
            call_chain_proof: validated_upstream_call_chain_proof,
            verified_runtime_attestation,
            verified_payee_binding,
            approval_intent_hash: intent_hash,
            approval_reservation,
        }))
    }

    pub(crate) fn reserve_validated_governed_approval(
        &self,
        request: &ToolCallRequest,
        validated: Option<&ValidatedGovernedAdmission>,
        durable_admission: Option<&mut DurableToolAdmission>,
        trusted_now_unix_ms: u64,
    ) -> Result<(), KernelError> {
        let Some(validated) = validated else {
            return Ok(());
        };
        if let Some(approval_token) = request.approval_token.as_ref() {
            self.reserve_legacy_governed_approval(approval_token, &validated.approval_intent_hash)?;
        }
        let Some(reservation) = validated.approval_reservation.as_ref() else {
            return Ok(());
        };
        if reservation.threshold_replay.is_none() {
            return Ok(());
        }
        let admission = durable_admission.ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "threshold approval requires a durable admission operation".to_string(),
            )
        })?;
        self.reserve_durable_approval_set(admission, reservation, trusted_now_unix_ms)
    }

    pub(crate) fn governed_call_chain_receipt_evidence(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        parent_context: Option<&OperationContext>,
        validated_proof: Option<ValidatedGovernedCallChainProof>,
    ) -> Result<Option<GovernedCallChainReceiptEvidence>, KernelError> {
        let Some(call_chain) = request
            .governed_intent
            .as_ref()
            .and_then(|intent| intent.call_chain.as_ref())
        else {
            return Ok(None);
        };
        let continuation_token_id = validated_proof
            .as_ref()
            .and_then(|proof| proof.continuation_token_id.clone());
        let session_anchor_id = validated_proof
            .as_ref()
            .and_then(|proof| proof.session_anchor_id.clone());
        let upstream_proof = validated_proof.and_then(|proof| proof.upstream_proof);
        let local_parent_request_id = parent_context
            .map(|context| context.request_id.to_string())
            .filter(|_| {
                parent_context.is_some_and(|context| {
                    self.validate_parent_request_continuation(request, context)
                        .is_ok()
                })
            });
        // A store READ ERROR fails closed and propagates; only a genuine
        // presence check (`Ok(false)`) omits the id.
        let local_parent_receipt_id = match call_chain.parent_receipt_id.as_ref() {
            Some(receipt_id) if self.has_local_receipt_id(receipt_id)? => Some(receipt_id.clone()),
            _ => None,
        };
        let capability_delegator_subject = cap
            .delegation_chain
            .last()
            .map(|link| link.delegator.to_hex());
        let capability_origin_subject = cap
            .delegation_chain
            .first()
            .map(|link| link.delegator.to_hex());

        if local_parent_request_id.is_none()
            && local_parent_receipt_id.is_none()
            && capability_delegator_subject.is_none()
            && capability_origin_subject.is_none()
            && continuation_token_id.is_none()
            && session_anchor_id.is_none()
            && upstream_proof.is_none()
        {
            return Ok(None);
        }

        Ok(Some(GovernedCallChainReceiptEvidence {
            local_parent_request_id,
            local_parent_receipt_id,
            capability_delegator_subject,
            capability_origin_subject,
            upstream_proof,
            continuation_token_id,
            session_anchor_id,
        }))
    }
}
