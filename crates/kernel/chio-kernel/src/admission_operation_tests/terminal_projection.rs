use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chio_credit::obligation::{
    derive_obligation_payee_binding_digest, ObligationAtomInputV1, ObligationAtomV1,
    ObligationCreditElectionV1,
};

#[test]
fn completed_projection_cannot_omit_required_atomic_sidecars() {
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        authorization_consumption: true,
        observation_attempt_zero: true,
        obligation: true,
        credit_exposure: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let operation = finalizing_tool_operation_with(requirements);
    let context = projection_context(&operation);
    let outcome_id = digest("outcome_id", POLICY_HASH);
    let outcome_version = 3;
    let mut metadata = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    metadata.tool_outcome_id = Some(outcome_id.clone());
    metadata.tool_outcome_version = Some(outcome_version);
    let kernel = Keypair::generate();
    let receipt = verify_completed_receipt(
        &operation,
        &context,
        signed_projection_receipt(&operation, Some(metadata), &kernel),
        &kernel,
        Some((&outcome_id, outcome_version)),
    )
    .expect("exact consumer receipt must qualify");
    let mut mismatched_metadata = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    mismatched_metadata.tool_outcome_id = Some(outcome_id.clone());
    mismatched_metadata.tool_outcome_version = Some(outcome_version);
    assert!(matches!(
        verify_completed_receipt(
            &operation,
            &context,
            signed_projection_receipt(&operation, Some(mismatched_metadata), &kernel),
            &kernel,
            Some((&outcome_id, outcome_version + 1)),
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));
    let obligation = ObligationProjection::from_source_verified(
        &operation,
        &context,
        &receipt,
        identifier("debtor_id", "debtor-1"),
        identifier("original_creditor_id", "creditor-1"),
        MonetaryAmount {
            units: 10,
            currency: "USD".to_string(),
        },
        2_000,
        ObligationDispositionV1::PerCall,
        digest("credit_authority_digest", AUTH_HASH),
        outcome_id.clone(),
        outcome_version,
    )
    .expect("obligation must bind to the exact terminal projection");
    let source_tenant = identifier("source_tenant_id", "tenant-123");
    let authorization = VerifiedAuthorizationReceiptConsumption::from_source_verified(
        &operation,
        &context,
        &receipt,
        AuthorizationReceiptConsumption {
            authorization_receipt_id: "authorization-1".to_string(),
            consumer_receipt_id: receipt.receipt().id.clone(),
            request_id: operation.binding.request_id.as_str().to_string(),
            session_id: "session-1".to_string(),
            tool_call_id: "tool-call-1".to_string(),
            tenant_id: Some("tenant-123".to_string()),
            parameter_hash: POLICY_HASH.to_string(),
            consumed_at_unix_ms: context.trusted_time_unix_ms,
        },
        &identifier("authorization_receipt_id", "authorization-1"),
        &identifier("session_id", "session-1"),
        &identifier("tool_call_id", "tool-call-1"),
        Some(&source_tenant),
        &digest("parameter_hash", POLICY_HASH),
        digest("authorization_receipt_digest", AUTH_HASH),
        outcome_id.clone(),
        outcome_version,
    )
    .expect("authorization consumption must be source verified");
    let observer_work = ObservationAttemptZero::from_verified(
        &operation,
        &context,
        &receipt,
        outcome_id,
        outcome_version,
        AdmissionOperationState::Completed,
    )
    .expect("attempt zero must bind immediate visibility");
    let completed = AdmissionCompletedProjection {
        context: context.clone(),
        authorization: Some(authorization),
        observer_work: Some(observer_work),
        obligation: Some(obligation),
        receipt,
        tool_outcome: None,
        payment_evidence: None,
        eligibility: None,
        channel_terminal: None,
    };
    validate_completed_participant_presence(requirements, &completed)
        .expect("all immutable participant requirements are present");

    let mut missing_authorization = completed.clone();
    missing_authorization.authorization = None;
    let mut missing_observer = completed.clone();
    missing_observer.observer_work = None;
    let mut missing_obligation = completed.clone();
    missing_obligation.obligation = None;
    for missing in [
        &missing_authorization,
        &missing_observer,
        &missing_obligation,
    ] {
        assert_eq!(
            validate_completed_participant_presence(requirements, missing),
            Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
        );
    }

    let projection = AdmissionTerminalProjection::Completed(Box::new(completed));
    for (capabilities, capability) in [
        (
            AdmissionProjectionCapabilities {
                authorization_consumption: false,
                ..full_projection_capabilities()
            },
            "authorization_consumption",
        ),
        (
            AdmissionProjectionCapabilities {
                observation_attempt_zero: false,
                ..full_projection_capabilities()
            },
            "observation_attempt_zero",
        ),
        (
            AdmissionProjectionCapabilities {
                obligation: false,
                ..full_projection_capabilities()
            },
            "obligation",
        ),
        (
            AdmissionProjectionCapabilities {
                credit_exposure_terminal: false,
                ..full_projection_capabilities()
            },
            "credit_exposure_terminal",
        ),
    ] {
        assert_eq!(
            operation.apply_terminal_projection(&projection, &capabilities),
            Err(AdmissionOperationError::MissingProjectionCapability { capability })
        );
    }
    full_projection_capabilities()
        .validate_for(&operation, &projection)
        .expect("store capabilities cover every immutable participant requirement");
}

#[test]
fn economic_obligation_projection_requires_exact_signed_payee_authority() {
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        obligation: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let operation = finalizing_tool_operation_with(requirements);
    let context = projection_context(&operation);
    let outcome_id = digest("outcome_id", POLICY_HASH);
    let outcome_version = 3;
    let kernel = Keypair::generate();
    let payee_binding_digest =
        derive_obligation_payee_binding_digest("creditor-1", "acct:creditor-1")
            .expect("payee binding must derive");
    let payee_binding = crate::kernel::VerifiedGovernedPayeeBinding::for_test(
        "creditor-1",
        "acct:creditor-1",
        REQUEST_HASH,
        AUTH_HASH,
    )
    .expect("verified payee binding fixture must derive");
    let signed_receipt = |approval_artifact_digest: Option<&str>| {
        let mut admission = receipt_metadata(
            &operation,
            &context,
            AdmissionOperationState::Completed,
            AdmissionCompensationStatus::NotCompensated,
        );
        admission.tool_outcome_id = Some(outcome_id.clone());
        admission.tool_outcome_version = Some(outcome_version);
        let mut body = signed_projection_receipt(&operation, Some(admission), &kernel).body();
        let metadata = body
            .metadata
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("receipt metadata must be an object");
        metadata.insert(
            "financial".to_owned(),
            serde_json::json!({
                "grant_index": 0,
                "cost_charged": 10,
                "currency": "USD",
                "budget_remaining": 90,
                "budget_total": 100,
                "delegation_depth": 0,
                "root_budget_holder": "debtor-1",
                "settlement_status": "pending"
            }),
        );
        metadata.insert(
            "governed_transaction".to_owned(),
            serde_json::json!({
                "intent_id": "intent-1",
                "intent_hash": REQUEST_HASH,
                "purpose": "buy result",
                "server_id": TOOL_SERVER,
                "tool_name": TOOL_NAME,
                "max_amount": { "units": 10, "currency": "USD" },
                "commerce": {
                    "seller": "creditor-1",
                    "shared_payment_token_id": "token-1",
                    "settlement_destination_ref": "acct:creditor-1"
                },
                "approval": {
                    "token_id": "approval-1",
                    "approver_key": "approver-1",
                    "approval_artifact_digest": approval_artifact_digest,
                    "approved": true
                },
                "economic_authorization": {
                    "version": "v1",
                    "economic_intent_digest": REQUEST_HASH,
                    "payee_binding_digest": payee_binding_digest,
                    "pre_action_authority_digest": AUTH_HASH,
                    "economic_mode": "external_dispatch",
                    "payer": {
                        "party_id": "debtor-1",
                        "funding_source_ref": "token-1"
                    },
                    "merchant": {
                        "merchant_id": "creditor-1"
                    },
                    "payee": {
                        "beneficiary_id": "creditor-1",
                        "settlement_destination_ref": "acct:creditor-1"
                    },
                    "rail": {
                        "kind": "credit",
                        "asset": "USD"
                    },
                    "amount_bounds": {
                        "approved_max": { "units": 10, "currency": "USD" },
                        "settlement_cap": { "units": 10, "currency": "USD" }
                    },
                    "budget": {
                        "grant_index": 0,
                        "cost_charged": 10,
                        "currency": "USD",
                        "budget_remaining": 90,
                        "budget_total": 100,
                        "delegation_depth": 0,
                        "root_budget_holder": "debtor-1"
                    },
                    "settlement": { "settlement_status": "pending" }
                }
            }),
        );
        let receipt = ChioReceipt::sign(body, &kernel).expect("economic receipt must sign");
        verify_completed_receipt(
            &operation,
            &context,
            receipt,
            &kernel,
            Some((&outcome_id, outcome_version)),
        )
        .expect("economic receipt must qualify")
    };
    let atom_for = |receipt: &VerifiedAdmissionReceipt| {
        let source_receipt_digest = chio_core::sha256_hex(
            &chio_core::canonical::canonical_json_bytes(receipt.receipt())
                .expect("receipt must canonicalize"),
        );
        ObligationAtomV1::new(ObligationAtomInputV1 {
            economic_intent_digest: REQUEST_HASH.to_owned(),
            source_receipt_id: receipt.receipt().id.clone(),
            source_receipt_digest,
            debtor_id: "debtor-1".to_owned(),
            original_creditor_id: "creditor-1".to_owned(),
            original_settlement_destination_ref: "acct:creditor-1".to_owned(),
            payee_binding_digest: payee_binding_digest.clone(),
            amount: MonetaryAmount {
                units: 10,
                currency: "USD".to_owned(),
            },
            credit_election: ObligationCreditElectionV1::NotCredit,
            pre_action_authority_digest: AUTH_HASH.to_owned(),
            created_at_unix_ms: context.trusted_time_unix_ms,
            due_at_unix_ms: context.trusted_time_unix_ms + 1_000,
        })
        .expect("obligation atom must derive")
    };

    let receipt = signed_receipt(Some(AUTH_HASH));
    ObligationProjection::from_verified_economic_receipt(
        &operation,
        &context,
        &receipt,
        &payee_binding,
        atom_for(&receipt),
        outcome_id.clone(),
        outcome_version,
    )
    .expect("exact signed economic authority must qualify");

    for approval_artifact_digest in [None, Some(POLICY_HASH)] {
        let receipt = signed_receipt(approval_artifact_digest);
        assert_eq!(
            ObligationProjection::from_verified_economic_receipt(
                &operation,
                &context,
                &receipt,
                &payee_binding,
                atom_for(&receipt),
                outcome_id.clone(),
                outcome_version,
            ),
            Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
        );
    }
}

#[test]
fn completed_channel_projection_requires_store_capability() -> Result<(), AdmissionOperationError> {
    let operation = finalizing_tool_operation_with(channel_requirements());
    let context = projection_context(&operation);
    let outcome_id = digest("outcome_id", POLICY_HASH);
    let outcome_version = 3;
    let mut metadata = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    metadata.tool_outcome_id = Some(outcome_id.clone());
    metadata.tool_outcome_version = Some(outcome_version);
    let kernel = Keypair::generate();
    let receipt = verify_completed_receipt(
        &operation,
        &context,
        signed_projection_receipt(&operation, Some(metadata), &kernel),
        &kernel,
        Some((&outcome_id, outcome_version)),
    )?;
    let completed = AdmissionCompletedProjection {
        context,
        receipt,
        tool_outcome: None,
        payment_evidence: None,
        authorization: None,
        eligibility: None,
        observer_work: None,
        obligation: None,
        channel_terminal: None,
    };

    assert_eq!(
        validate_completed_participant_presence(channel_requirements(), &completed),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );
    let projection = AdmissionTerminalProjection::Completed(Box::new(completed));

    assert_eq!(
        AdmissionProjectionCapabilities {
            channel_terminal: false,
            ..full_projection_capabilities()
        }
        .validate_for(&operation, &projection),
        Err(AdmissionOperationError::MissingProjectionCapability {
            capability: "channel_terminal"
        })
    );
    Ok(())
}

#[test]
fn terminal_participant_evidence_rejects_cross_binding_and_substitution() {
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        outcome_eligibility: true,
        payment: true,
        obligation: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let operation = finalizing_tool_operation_with(requirements);
    let context = projection_context(&operation);
    let outcome_id = digest("outcome_id", POLICY_HASH);
    let outcome_version = 3;
    let mut metadata = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    metadata.tool_outcome_id = Some(outcome_id.clone());
    metadata.tool_outcome_version = Some(outcome_version);
    let kernel = Keypair::generate();
    let receipt = verify_completed_receipt(
        &operation,
        &context,
        signed_projection_receipt(&operation, Some(metadata), &kernel),
        &kernel,
        Some((&outcome_id, outcome_version)),
    )
    .expect("exact consumer receipt must qualify");
    let payment_from = |participant_id, recorded_at| {
        PaymentTerminalEvidence::from_source_verified(
            &operation,
            &context,
            &receipt,
            identifier("payment_participant_id", participant_id),
            digest("payment_authority_digest", AUTH_HASH),
            identifier("payment_record_id", "payment-record-1"),
            digest("payment_record_digest", REQUEST_HASH),
            recorded_at,
            outcome_id.clone(),
            outcome_version,
            AdmissionOperationState::Completed,
        )
    };
    let payment =
        payment_from("payment-1", 900).expect("exact payment participant evidence must qualify");
    assert!(payment
        .validate_against(
            &operation,
            &context,
            &receipt,
            &outcome_id,
            outcome_version,
            AdmissionOperationState::Completed,
        )
        .is_ok());
    assert!(matches!(
        payment_from("payment-2", 900),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));
    assert!(matches!(
        payment_from("payment-1", context.trusted_time_unix_ms + 1),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));
    assert_eq!(
        payment.validate_against(
            &operation,
            &context,
            &receipt,
            &outcome_id,
            outcome_version + 1,
            AdmissionOperationState::Completed,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );
    let other_kernel = Keypair::generate();
    let mut other_metadata = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    other_metadata.tool_outcome_id = Some(outcome_id.clone());
    other_metadata.tool_outcome_version = Some(outcome_version);
    let substituted_receipt = verify_completed_receipt(
        &operation,
        &context,
        signed_projection_receipt(&operation, Some(other_metadata), &other_kernel),
        &other_kernel,
        Some((&outcome_id, outcome_version)),
    )
    .expect("alternate pinned kernel receipt must qualify independently");
    assert_eq!(
        payment.validate_against(
            &operation,
            &context,
            &substituted_receipt,
            &outcome_id,
            outcome_version,
            AdmissionOperationState::Completed,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );

    assert!(OutcomeEligibilityFinalization::from_source_verified(
        &operation,
        &context,
        &receipt,
        digest("outcome_eligibility_digest", POLICY_HASH),
        digest("eligibility_authority_digest", AUTH_HASH),
        identifier("eligibility_record_id", "eligibility-1"),
        digest("eligibility_record_digest", REQUEST_HASH),
        950,
        outcome_id.clone(),
        outcome_version,
        AdmissionOperationState::Completed,
    )
    .is_ok());
    assert!(matches!(
        OutcomeEligibilityFinalization::from_source_verified(
            &operation,
            &context,
            &receipt,
            digest("outcome_eligibility_digest", REQUEST_HASH),
            digest("eligibility_authority_digest", AUTH_HASH),
            identifier("eligibility_record_id", "eligibility-1"),
            digest("eligibility_record_digest", REQUEST_HASH),
            950,
            outcome_id.clone(),
            outcome_version,
            AdmissionOperationState::Completed,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));

    let obligation = ObligationProjection::from_source_verified(
        &operation,
        &context,
        &receipt,
        identifier("debtor_id", "debtor-1"),
        identifier("original_creditor_id", "creditor-1"),
        MonetaryAmount {
            units: 25,
            currency: "USD".to_string(),
        },
        2_000,
        ObligationDispositionV1::PerCall,
        digest("credit_authority_digest", AUTH_HASH),
        outcome_id.clone(),
        outcome_version,
    )
    .expect("canonical obligation atom must qualify");
    let encoded = serde_json::to_value(&obligation).expect("obligation evidence must serialize");
    assert_eq!(encoded["atom"]["debtorId"], "debtor-1");
    assert_eq!(encoded["atom"]["originalCreditorId"], "creditor-1");
    assert_eq!(encoded["atom"]["amount"]["units"], 25);
    assert_eq!(encoded["atom"]["dueAtUnixMs"], 2_000);
    assert_eq!(
        encoded["disposition_record"]["disposition"]["kind"],
        "per_call"
    );
    assert_eq!(encoded["source"]["outcome_id"], POLICY_HASH);
    assert!(matches!(
        ObligationProjection::from_source_verified(
            &operation,
            &context,
            &receipt,
            identifier("debtor_id", "debtor-1"),
            identifier("original_creditor_id", "creditor-1"),
            MonetaryAmount {
                units: 25,
                currency: "usd".to_string(),
            },
            2_000,
            ObligationDispositionV1::PerCall,
            digest("credit_authority_digest", AUTH_HASH),
            outcome_id,
            outcome_version,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));
}

#[test]
fn authorization_and_attempt_zero_are_exact_source_verified_contracts() {
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        authorization_consumption: true,
        observation_attempt_zero: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let operation = finalizing_tool_operation_with(requirements);
    let context = projection_context(&operation);
    let outcome_id = digest("outcome_id", POLICY_HASH);
    let outcome_version = 3;
    let mut metadata = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    metadata.tool_outcome_id = Some(outcome_id.clone());
    metadata.tool_outcome_version = Some(outcome_version);
    let kernel = Keypair::generate();
    let receipt = verify_completed_receipt(
        &operation,
        &context,
        signed_projection_receipt(&operation, Some(metadata), &kernel),
        &kernel,
        Some((&outcome_id, outcome_version)),
    )
    .expect("exact consumer receipt must qualify");
    let source_authorization_id = identifier("authorization_receipt_id", "authorization-1");
    let source_session_id = identifier("session_id", "session-1");
    let source_tool_call_id = identifier("tool_call_id", "tool-call-1");
    let source_tenant_id = identifier("tenant_id", "tenant-123");
    let source_parameter_hash = digest("parameter_hash", POLICY_HASH);
    let base = AuthorizationReceiptConsumption {
        authorization_receipt_id: source_authorization_id.as_str().to_string(),
        consumer_receipt_id: receipt.receipt().id.clone(),
        request_id: operation.binding.request_id.as_str().to_string(),
        session_id: source_session_id.as_str().to_string(),
        tool_call_id: source_tool_call_id.as_str().to_string(),
        tenant_id: Some(source_tenant_id.as_str().to_string()),
        parameter_hash: source_parameter_hash.as_str().to_string(),
        consumed_at_unix_ms: context.trusted_time_unix_ms,
    };
    let verify = |consumption| {
        VerifiedAuthorizationReceiptConsumption::from_source_verified(
            &operation,
            &context,
            &receipt,
            consumption,
            &source_authorization_id,
            &source_session_id,
            &source_tool_call_id,
            Some(&source_tenant_id),
            &source_parameter_hash,
            digest("authorization_receipt_digest", AUTH_HASH),
            outcome_id.clone(),
            outcome_version,
        )
    };
    let verified = verify(base.clone()).expect("exact source consumption must qualify");
    assert_eq!(verified.consumption(), &base);
    assert_eq!(
        verified.validate_against(&operation, &context, &receipt, &outcome_id, 4),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );
    let mut substitutions = Vec::new();
    macro_rules! substitute {
        ($field:ident, $value:expr) => {{
            let mut value = base.clone();
            value.$field = $value;
            substitutions.push(value);
        }};
    }
    substitute!(authorization_receipt_id, "authorization-2".to_string());
    substitute!(consumer_receipt_id, "receipt-2".to_string());
    substitute!(request_id, "request-2".to_string());
    substitute!(session_id, "session-2".to_string());
    substitute!(tool_call_id, "tool-call-2".to_string());
    substitute!(tenant_id, Some("tenant-2".to_string()));
    substitute!(parameter_hash, REQUEST_HASH.to_string());
    substitute!(consumed_at_unix_ms, context.trusted_time_unix_ms + 1);
    for substitution in substitutions {
        assert!(matches!(
            verify(substitution),
            Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
        ));
    }

    let attempt_zero = ObservationAttemptZero::from_verified(
        &operation,
        &context,
        &receipt,
        outcome_id.clone(),
        outcome_version,
        AdmissionOperationState::Completed,
    )
    .expect("attempt zero must qualify");
    assert_eq!(
        attempt_zero.pending().next_visible_at_ms,
        context.trusted_time_unix_ms
    );
    let delayed = attempt_zero.with_visibility_for_test(context.trusted_time_unix_ms + 1);
    assert_eq!(
        delayed.validate_against(
            &operation,
            &context,
            &receipt,
            &outcome_id,
            outcome_version,
            AdmissionOperationState::Completed,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );
}

#[test]
fn terminal_projection_accepts_new_owner_fence_only_on_the_same_store() {
    let operation = finalizing_active_operation();
    let retained_dispatch_commit = operation
        .dispatch_commit
        .clone()
        .expect("finalizing operation must retain dispatch commit");
    let mut recovered_context = projection_context(&operation);
    recovered_context.store_fence = StoreMutationFence {
        store_uuid: retained_dispatch_commit.store_fence.store_uuid.clone(),
        lease_id: "owner-lease-2".to_string(),
        owner_epoch: retained_dispatch_commit.store_fence.owner_epoch + 1,
    };
    let kernel = Keypair::generate();
    let metadata = receipt_metadata(
        &operation,
        &recovered_context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    let receipt = verify_completed_receipt(
        &operation,
        &recovered_context,
        signed_projection_receipt(&operation, Some(metadata), &kernel),
        &kernel,
        None,
    )
    .expect("same-store recovery receipt must qualify");
    let recovered =
        AdmissionTerminalProjection::Completed(Box::new(AdmissionCompletedProjection {
            context: recovered_context.clone(),
            receipt,
            tool_outcome: None,
            payment_evidence: None,
            authorization: None,
            eligibility: None,
            observer_work: None,
            obligation: None,
            channel_terminal: None,
        }));
    let terminal = operation
        .apply_terminal_projection(&recovered, &full_projection_capabilities())
        .expect("same-store recovery fence must terminalize");
    assert_eq!(
        terminal.dispatch_commit.as_ref(),
        Some(&retained_dispatch_commit)
    );

    for fence in [
        StoreMutationFence {
            store_uuid: retained_dispatch_commit.store_fence.store_uuid.clone(),
            lease_id: "different-lease-at-same-epoch".to_string(),
            owner_epoch: retained_dispatch_commit.store_fence.owner_epoch,
        },
        StoreMutationFence {
            store_uuid: retained_dispatch_commit.store_fence.store_uuid.clone(),
            lease_id: "older-owner-lease".to_string(),
            owner_epoch: retained_dispatch_commit.store_fence.owner_epoch - 1,
        },
    ] {
        let mut stale_context = recovered_context.clone();
        stale_context.store_fence = fence;
        let metadata = receipt_metadata(
            &operation,
            &stale_context,
            AdmissionOperationState::Completed,
            AdmissionCompensationStatus::NotCompensated,
        );
        assert!(matches!(
            verify_completed_receipt(
                &operation,
                &stale_context,
                signed_projection_receipt(&operation, Some(metadata), &kernel),
                &kernel,
                None,
            ),
            Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
        ));
    }

    let mut foreign_context = recovered_context;
    foreign_context.store_fence.store_uuid = "different-store".to_string();
    let metadata = receipt_metadata(
        &operation,
        &foreign_context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    assert!(matches!(
        verify_completed_receipt(
            &operation,
            &foreign_context,
            signed_projection_receipt(&operation, Some(metadata), &kernel),
            &kernel,
            None,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));
}

#[test]
fn denied_after_delivery_projection_round_trips_through_the_signed_envelope() {
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        payment: true,
        observation_attempt_zero: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let operation = finalizing_tool_operation_with(requirements);
    let context = projection_context(&operation);
    let outcome_id = digest("tool_outcome_id", POLICY_HASH);
    let outcome_version = 3;
    let kernel = Keypair::generate();
    let decision = Decision::Deny {
        reason: "delivered output does not match the committed output digest".to_string(),
        guard: "delivery_contract".to_string(),
    };
    let metadata = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::DeniedAfterDelivery,
        AdmissionCompensationStatus::NotCompensated,
    );
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "test-receipt-denied-delivery".to_string(),
            timestamp: context.trusted_time_unix_ms / 1_000,
            capability_id: operation.binding.capability_id.as_str().to_owned(),
            tool_server: TOOL_SERVER.to_string(),
            tool_name: TOOL_NAME.to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({}))
                .expect("test action must be valid"),
            decision: Some(decision.clone()),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: CONTENT_HASH.to_string(),
            policy_hash: operation.binding.policy_hash.as_str().to_owned(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                ADMISSION_RECEIPT_METADATA_KEY: metadata,
                "delivery_contract": chio_core::receipt::metadata::DeliveryContract {
                        schema: chio_core::receipt::metadata::DELIVERY_CONTRACT_SCHEMA.to_owned(),
                        expected_digest: POLICY_HASH.to_owned(),
                        observed_digest: CONTENT_HASH.to_owned(),
                        result: chio_core::receipt::metadata::DeliveryResult::Mismatched,
                    }
            })),
            trust_level: Default::default(),
            tenant_id: Some("tenant-123".to_string()),
            kernel_key: kernel.public_key(),
            bbs_projection_version: None,
        },
        &kernel,
    )
    .expect("deny receipt must sign");
    let receipt = VerifiedAdmissionReceipt::from_kernel_verified_for_test(
        receipt,
        &kernel.public_key(),
        &decision,
        TOOL_SERVER,
        TOOL_NAME,
        &digest("expected_parameter_hash", EMPTY_PARAMETER_HASH),
        &digest("expected_content_hash", CONTENT_HASH),
        &operation,
        &context,
        AdmissionOperationState::DeniedAfterDelivery,
        AdmissionCompensationStatus::NotCompensated,
        None,
    )
    .expect("denied receipt must qualify");
    let payment_evidence = PaymentTerminalEvidence::from_source_verified(
        &operation,
        &context,
        &receipt,
        identifier("payment_participant_id", "payment-1"),
        digest("payment_source_authority_digest", AUTH_HASH),
        identifier("payment_source_record_id", "payment:op-denied"),
        digest("payment_source_record_digest", CONTENT_HASH),
        900,
        outcome_id.clone(),
        outcome_version,
        AdmissionOperationState::DeniedAfterDelivery,
    )
    .expect("payment evidence must bind the denied terminal");
    let observer_work = ObservationAttemptZero::from_verified(
        &operation,
        &context,
        &receipt,
        outcome_id,
        outcome_version,
        AdmissionOperationState::DeniedAfterDelivery,
    )
    .expect("observation attempt must bind the denied terminal");
    let projection = AdmissionTerminalProjection::DeniedAfterDelivery {
        context,
        reason: DeliveryDenialReason::DigestMismatch,
        evidence: Box::new(AdmissionReceiptOrIncident::Receipt(Box::new(receipt))),
        payment_evidence: Some(Box::new(payment_evidence)),
        observer_work: Some(Box::new(observer_work)),
    };
    let envelope = SignedAdmissionTerminalProjectionV1::from_verified(
        &operation,
        &projection,
        &full_projection_capabilities(),
        &kernel,
    )
    .expect("denied projection must produce a signed envelope");

    let mismatched_replay = envelope
        .clone()
        .with_replay_receipt_id_for_test(
            identifier("tampered_receipt_id", "other-receipt"),
            &kernel,
        )
        .expect("the test envelope must be re-signed");
    assert_eq!(
        mismatched_replay.verify(),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch),
        "the terminal replay must identify the projected receipt"
    );

    let verified = envelope
        .verify()
        .expect("denied terminal envelope must import");
    assert_eq!(verified.source_operation(), &operation);
    assert_eq!(
        verified.terminal_operation().state(),
        AdmissionOperationState::DeniedAfterDelivery
    );
    let terminal = verified.terminal().expect("terminal must project");
    assert_eq!(terminal.state, AdmissionOperationState::DeniedAfterDelivery);
    assert!(matches!(
        terminal.replay,
        AdmissionTerminalReplay::Receipt { .. }
    ));
    let kinds: Vec<_> = verified
        .records()
        .iter()
        .map(VerifiedAdmissionTerminalProjectionRecordV1::kind)
        .collect();
    assert!(kinds.contains(&AdmissionProjectionRecordKind::Receipt));
    assert!(kinds.contains(&AdmissionProjectionRecordKind::PaymentTerminal));
    assert!(kinds.contains(&AdmissionProjectionRecordKind::ObservationAttemptZero));
    assert!(verified.observer().is_some());
    assert!(verified.authorization_consumption().is_none());
}

#[test]
fn signed_terminal_projection_envelope_rejects_canonical_body_tampering() {
    let operation = finalizing_active_operation();
    let context = projection_context(&operation);
    let kernel = Keypair::generate();
    let metadata = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    let receipt = verify_completed_receipt(
        &operation,
        &context,
        signed_projection_receipt(&operation, Some(metadata), &kernel),
        &kernel,
        None,
    )
    .expect("completed receipt must qualify");
    let projection =
        AdmissionTerminalProjection::Completed(Box::new(AdmissionCompletedProjection {
            context,
            receipt,
            tool_outcome: None,
            payment_evidence: None,
            authorization: None,
            eligibility: None,
            observer_work: None,
            obligation: None,
            channel_terminal: None,
        }));
    let envelope = SignedAdmissionTerminalProjectionV1::from_verified(
        &operation,
        &projection,
        &full_projection_capabilities(),
        &kernel,
    )
    .expect("verified projection must produce a signed envelope");
    let verified = envelope
        .verify()
        .expect("untampered terminal envelope must verify");
    assert_eq!(verified.source_operation(), &operation);
    assert_eq!(
        verified.terminal_operation().state(),
        AdmissionOperationState::Completed
    );

    let mut encoded = serde_json::to_value(&envelope).expect("envelope must encode");
    encoded["body"]["projection_json"] = serde_json::Value::String("e30=".to_string());
    let tampered: SignedAdmissionTerminalProjectionV1 =
        serde_json::from_value(encoded).expect("tampered wire value must decode structurally");
    assert!(matches!(
        tampered.verify(),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));
}

#[test]
fn resigned_compensation_envelope_rejects_semantically_tampered_release_proof(
) -> Result<(), Box<dyn std::error::Error>> {
    let operation = prepared(AdmissionOperationKind::ToolDispatch);
    let projection =
        verified_pre_dispatch_compensation_projection(&operation, projection_context(&operation))?;
    let kernel = Keypair::generate();
    let envelope = SignedAdmissionTerminalProjectionV1::from_verified(
        &operation,
        &projection,
        &full_projection_capabilities(),
        &kernel,
    )?;
    envelope.verify()?;

    let mut encoded = serde_json::to_value(envelope)?;
    let record = encoded["body"]["records"]
        .as_array_mut()
        .and_then(|records| {
            records.iter_mut().find(|record| {
                record.get("kind").and_then(serde_json::Value::as_str) == Some("release_proof")
            })
        })
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    let proof_bytes = STANDARD.decode(
        record["canonical_json"]
            .as_str()
            .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?,
    )?;
    let mut proof: serde_json::Value = serde_json::from_slice(&proof_bytes)?;
    let operation_version = proof
        .pointer("/snapshot/operation_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    proof["snapshot"]["operation_version"] = serde_json::Value::from(operation_version + 1);
    let proof_bytes = canonical_json_bytes(&proof)?;
    let proof_digest = chio_core::crypto::sha256_hex(&proof_bytes);
    record["canonical_json"] = serde_json::Value::String(STANDARD.encode(&proof_bytes));
    record["record_digest"] = serde_json::Value::String(proof_digest.clone());

    let manifest_bytes = STANDARD.decode(
        encoded["body"]["manifest_json"]
            .as_str()
            .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?,
    )?;
    let mut manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)?;
    let manifest_record = manifest["records"]
        .as_array_mut()
        .and_then(|records| {
            records.iter_mut().find(|record| {
                record.get("kind").and_then(serde_json::Value::as_str) == Some("release_proof")
            })
        })
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    manifest_record["record_digest"] = serde_json::Value::String(proof_digest);
    let manifest_bytes = canonical_json_bytes(&manifest)?;
    encoded["body"]["manifest_json"] = serde_json::Value::String(STANDARD.encode(&manifest_bytes));
    let replay_digest = encoded
        .pointer_mut("/body/terminal_operation/terminal_replay/incident/projection_digest")
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    *replay_digest = serde_json::Value::String(chio_core::crypto::sha256_hex(&manifest_bytes));

    let canonical_body = canonical_json_bytes(&encoded["body"])?;
    let mut preimage = b"chio.signed-admission-terminal-projection.v1\0".to_vec();
    preimage.extend_from_slice(&canonical_body);
    encoded["signature"] = serde_json::to_value(kernel.sign(&preimage))?;
    let tampered: SignedAdmissionTerminalProjectionV1 = serde_json::from_value(encoded)?;
    assert_eq!(
        tampered.verify(),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );
    Ok(())
}

#[test]
fn signed_terminal_projection_rejects_channel_attachment_substitution(
) -> Result<(), Box<dyn std::error::Error>> {
    let operation = finalizing_tool_operation_with(channel_requirements());
    let context = projection_context(&operation);
    let kernel = Keypair::generate();
    let incident = AdmissionIncident::from_verified(
        &operation,
        &context,
        AdmissionOperationState::OutcomeUnknownAfterDispatch,
        identifier("incident_id", "channel-outcome-unknown"),
        digest("incident_digest", POLICY_HASH),
    )?;
    let projection = AdmissionTerminalProjection::OutcomeUnknownAfterDispatch {
        context,
        incident: Box::new(incident),
    };
    let envelope = SignedAdmissionTerminalProjectionV1::from_verified(
        &operation,
        &projection,
        &full_projection_capabilities(),
        &kernel,
    )?;

    let mut encoded = serde_json::to_value(&envelope)?;
    let attachments = encoded["body"]["source_operation"]["attachments"]
        .as_array_mut()
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    let reservation = attachments
        .iter_mut()
        .find(|attachment| attachment.get("ChannelReservationDigest").is_some())
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    reservation["ChannelReservationDigest"] = serde_json::Value::String(AUTH_HASH.to_owned());
    let canonical_body = canonical_json_bytes(&encoded["body"])?;
    let mut preimage = b"chio.signed-admission-terminal-projection.v1\0".to_vec();
    preimage.extend_from_slice(&canonical_body);
    encoded["signature"] = serde_json::to_value(kernel.sign(&preimage))?;
    let tampered: SignedAdmissionTerminalProjectionV1 = serde_json::from_value(encoded)?;
    assert_eq!(
        tampered.verify(),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );
    Ok(())
}

#[test]
fn signed_terminal_projection_envelope_rejects_signer_substitution() {
    let operation = finalizing_active_operation();
    let context = projection_context(&operation);
    let kernel = Keypair::generate();
    let metadata = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    let receipt = verify_completed_receipt(
        &operation,
        &context,
        signed_projection_receipt(&operation, Some(metadata), &kernel),
        &kernel,
        None,
    )
    .expect("completed receipt must qualify");
    let projection =
        AdmissionTerminalProjection::Completed(Box::new(AdmissionCompletedProjection {
            context,
            receipt,
            tool_outcome: None,
            payment_evidence: None,
            authorization: None,
            eligibility: None,
            observer_work: None,
            obligation: None,
            channel_terminal: None,
        }));
    let envelope = SignedAdmissionTerminalProjectionV1::from_verified(
        &operation,
        &projection,
        &full_projection_capabilities(),
        &kernel,
    )
    .expect("verified projection must produce a signed envelope");

    let mut encoded = serde_json::to_value(&envelope).expect("envelope must encode");
    encoded["body"]["signer_key"] =
        serde_json::to_value(Keypair::generate().public_key()).expect("key must encode");
    let tampered: SignedAdmissionTerminalProjectionV1 =
        serde_json::from_value(encoded).expect("tampered wire value must decode structurally");
    assert!(matches!(
        tampered.verify(),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));
}

#[test]
fn tool_outcome_attachment_is_required_and_exact_before_finalizing() {
    assert!(
        serde_json::from_value::<AdmissionAttachment>(serde_json::json!({
            "ToolOutcomeId": "outcome-1"
        }))
        .is_err()
    );
    let mut operation = prepared(AdmissionOperationKind::ToolDispatch);
    for next in [
        AdmissionOperationState::BrokerAttemptRegistered,
        AdmissionOperationState::BudgetAuthorized,
        AdmissionOperationState::ReadyToDispatch,
        AdmissionOperationState::CapturePending,
        AdmissionOperationState::DispatchCommitted,
    ] {
        let command = transition_command(&operation, next, None);
        operation = operation
            .apply_command(&command, 1_000)
            .expect("tool dispatch transition must apply")
            .into_operation();
    }
    let missing = AdmissionOperationCommand::new(
        operation.binding.operation_id.clone(),
        operation.version,
        lease(&operation, operation.version),
        Vec::new(),
        Some(AdmissionOperationState::Finalizing),
        None,
        None,
    )
    .expect("finalizing command must be structurally valid");
    assert_eq!(
        operation.apply_command(&missing, 1_000),
        Err(AdmissionOperationError::MissingParticipantAttachment {
            field: "tool_outcome_id"
        })
    );

    let exact = transition_command(&operation, AdmissionOperationState::Finalizing, None);
    let operation = operation
        .apply_command(&exact, 1_000)
        .expect("attaching the outcome must allow finalizing")
        .into_operation();
    assert!(operation
        .validate_completed_tool_outcome_attachment(&digest("outcome_id", POLICY_HASH))
        .is_ok());
    assert_eq!(
        operation.validate_completed_tool_outcome_attachment(&digest(
            "outcome_id",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        )),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );
    assert_eq!(
        validate_state_attachments(
            AdmissionOperationKind::ToolDispatch,
            operation.binding.participant_requirements(),
            AdmissionOperationState::NotAcceptedAfterDispatchCommit,
            &operation.attachments,
        ),
        Err(AdmissionOperationError::ForbiddenAttachment {
            field: "tool_outcome_id"
        })
    );
    assert!(validate_state_attachments(
        AdmissionOperationKind::ToolDispatch,
        operation.binding.participant_requirements(),
        AdmissionOperationState::OutcomeUnknownAfterDispatch,
        &operation.attachments,
    )
    .is_ok());
}

#[test]
fn terminal_replay_reference_is_typed_and_retained() {
    let mut operation = prepared(AdmissionOperationKind::ToolDispatch);
    for next in [
        AdmissionOperationState::BrokerAttemptRegistered,
        AdmissionOperationState::BudgetAuthorized,
        AdmissionOperationState::ReadyToDispatch,
        AdmissionOperationState::CapturePending,
        AdmissionOperationState::DispatchCommitted,
        AdmissionOperationState::Finalizing,
    ] {
        let command = transition_command(&operation, next, None);
        operation = operation
            .apply_command(&command, 1_000)
            .expect("legal transition must apply")
            .into_operation();
    }
    let dispatch_commit = operation
        .dispatch_commit
        .clone()
        .expect("post-dispatch operation must retain its commit binding");
    assert_eq!(dispatch_commit.committed_version, 6);
    assert_eq!(dispatch_commit.coordinator_lease_epoch, 7);
    assert_eq!(
        AdmissionOperationCommand::new(
            operation.binding.operation_id.clone(),
            operation.version,
            lease(&operation, operation.version),
            Vec::new(),
            Some(AdmissionOperationState::OutcomeUnknownAfterDispatch),
            Some(AdmissionTerminalReplay::Incident {
                incident_id: identifier("incident_id", "incident-1"),
                projection_digest: digest("projection_digest", REQUEST_HASH),
            }),
            None,
        ),
        Err(AdmissionOperationError::TerminalProjectionRequired)
    );
    let context = AdmissionProjectionContext {
        operation_id: operation.binding.operation_id.clone(),
        request_id: operation.binding.request_id.clone(),
        expected_operation_version: operation.version,
        trusted_time_unix_ms: 1_000,
        coordinator_lease_id: identifier("coordinator_lease_id", "coordinator-lease-1"),
        coordinator_lease_epoch: operation.coordinator_lease_epoch,
        store_fence: dispatch_commit.store_fence.clone(),
    };
    let incident = AdmissionIncident::from_verified(
        &operation,
        &context,
        AdmissionOperationState::OutcomeUnknownAfterDispatch,
        identifier("incident_id", "incident-1"),
        digest("incident_digest", POLICY_HASH),
    )
    .expect("incident must bind to the exact terminal projection");
    let projection = AdmissionTerminalProjection::OutcomeUnknownAfterDispatch {
        context: context.clone(),
        incident: Box::new(incident),
    };
    let canonical_projection = projection
        .canonical_projection()
        .expect("terminal projection must have a canonical commitment");
    assert_eq!(canonical_projection.records().len(), 1);
    assert_eq!(
        canonical_projection.records()[0].commitment().kind(),
        AdmissionProjectionRecordKind::Incident
    );
    let restored_manifest =
        AdmissionProjectionManifestV1::from_canonical_bytes(canonical_projection.manifest_bytes())
            .expect("projection manifest must round trip canonically");
    restored_manifest
        .verify_projection_body(canonical_projection.projection_bytes())
        .expect("projection body must match its manifest");
    assert_eq!(
        restored_manifest
            .projection_digest()
            .expect("manifest must derive its digest"),
        *canonical_projection.projection_digest()
    );
    let substituted_incident = AdmissionIncident::from_verified(
        &operation,
        &context,
        AdmissionOperationState::OutcomeUnknownAfterDispatch,
        identifier("incident_id", "incident-1"),
        digest("incident_digest", REQUEST_HASH),
    )
    .expect("substituted incident remains structurally bound");
    let substituted_projection = AdmissionTerminalProjection::OutcomeUnknownAfterDispatch {
        context,
        incident: Box::new(substituted_incident),
    };
    assert_ne!(
        substituted_projection
            .projection_digest()
            .expect("substituted projection must derive"),
        *canonical_projection.projection_digest()
    );
    let replay = AdmissionTerminalReplay::Incident {
        incident_id: identifier("incident_id", "incident-1"),
        projection_digest: canonical_projection.projection_digest().clone(),
    };
    operation = operation
        .apply_terminal_projection(&projection, &full_projection_capabilities())
        .expect("closed terminal projection must apply");
    assert_eq!(operation.dispatch_commit.as_ref(), Some(&dispatch_commit));
    assert!(operation.has_attachment(AdmissionAttachmentKind::ToolOutcome));
    assert_eq!(operation.terminal_replay(), Some(&replay));
    assert_eq!(
        operation.classify_replay(&prepared(AdmissionOperationKind::ToolDispatch)),
        AdmissionReplayClassification::Exact {
            terminal_replay: Some(replay)
        }
    );
}

#[test]
fn denied_after_delivery_projection_requires_participant_evidence() {
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        payment: true,
        observation_attempt_zero: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let operation = finalizing_tool_operation_with(requirements);
    let context = projection_context(&operation);
    let outcome_id = digest("outcome_id", POLICY_HASH);
    let outcome_version = 3;
    let denied_decision = Decision::Deny {
        reason: "delivered output does not match the committed output digest".to_string(),
        guard: "delivery_contract".to_string(),
    };
    let kernel = Keypair::generate();
    let receipt = VerifiedAdmissionReceipt::from_kernel_verified_for_test(
        signed_projection_receipt_with_decision(
            &operation,
            Some(receipt_metadata(
                &operation,
                &context,
                AdmissionOperationState::DeniedAfterDelivery,
                AdmissionCompensationStatus::NotCompensated,
            )),
            Some("tenant-123".to_string()),
            denied_decision.clone(),
            &kernel,
        ),
        &kernel.public_key(),
        &denied_decision,
        TOOL_SERVER,
        TOOL_NAME,
        &digest("expected_parameter_hash", EMPTY_PARAMETER_HASH),
        &digest("expected_content_hash", CONTENT_HASH),
        &operation,
        &context,
        AdmissionOperationState::DeniedAfterDelivery,
        AdmissionCompensationStatus::NotCompensated,
        None,
    )
    .expect("the signed delivery denial must qualify");
    let payment = PaymentTerminalEvidence::from_source_verified(
        &operation,
        &context,
        &receipt,
        identifier("payment_participant_id", "payment-1"),
        digest("payment_authority_digest", AUTH_HASH),
        identifier("payment_record_id", "payment-record-1"),
        digest("payment_record_digest", REQUEST_HASH),
        900,
        outcome_id.clone(),
        outcome_version,
        AdmissionOperationState::DeniedAfterDelivery,
    )
    .expect("payment evidence must bind the denied terminal");
    let observer = ObservationAttemptZero::from_verified(
        &operation,
        &context,
        &receipt,
        outcome_id.clone(),
        outcome_version,
        AdmissionOperationState::DeniedAfterDelivery,
    )
    .expect("the release observation must bind the denied terminal");

    validate_denied_after_delivery_participant_presence(
        requirements,
        Some(&payment),
        Some(&observer),
    )
    .expect("a paid observed denial carries both participants");
    for (missing_payment, missing_observer) in [(true, false), (false, true), (true, true)] {
        assert_eq!(
            validate_denied_after_delivery_participant_presence(
                requirements,
                (!missing_payment).then_some(&payment),
                (!missing_observer).then_some(&observer),
            ),
            Err(AdmissionOperationError::TerminalProjectionBindingMismatch),
            "a required participant record must not be omittable"
        );
    }
    // Requirements the denied terminal cannot represent deny outright.
    assert_eq!(
        validate_denied_after_delivery_participant_presence(
            AdmissionParticipantRequirements {
                obligation: true,
                ..requirements
            },
            Some(&payment),
            Some(&observer),
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );

    let projection = AdmissionTerminalProjection::DeniedAfterDelivery {
        context: context.clone(),
        reason: DeliveryDenialReason::DigestMismatch,
        evidence: Box::new(AdmissionReceiptOrIncident::Receipt(Box::new(
            receipt.clone(),
        ))),
        payment_evidence: Some(Box::new(payment.clone())),
        observer_work: Some(Box::new(observer.clone())),
    };
    for (capabilities, capability) in [
        (
            AdmissionProjectionCapabilities {
                payment_terminal: false,
                ..full_projection_capabilities()
            },
            "payment_terminal",
        ),
        (
            AdmissionProjectionCapabilities {
                observation_attempt_zero: false,
                ..full_projection_capabilities()
            },
            "observation_attempt_zero",
        ),
    ] {
        assert_eq!(
            operation.apply_terminal_projection(&projection, &capabilities),
            Err(AdmissionOperationError::MissingProjectionCapability { capability })
        );
    }
    let terminal = operation
        .apply_terminal_projection(&projection, &full_projection_capabilities())
        .expect("the complete denied projection must apply");
    assert_eq!(
        terminal.state(),
        AdmissionOperationState::DeniedAfterDelivery
    );
    assert!(matches!(
        terminal.terminal_replay(),
        Some(AdmissionTerminalReplay::Receipt { .. })
    ));
    let canonical = projection
        .canonical_projection()
        .expect("the denied projection must canonicalize");
    let mut kinds = canonical
        .records()
        .iter()
        .map(|record| record.commitment().kind())
        .collect::<Vec<_>>();
    kinds.sort();
    let mut expected_kinds = vec![
        AdmissionProjectionRecordKind::Receipt,
        AdmissionProjectionRecordKind::PaymentTerminal,
        AdmissionProjectionRecordKind::ObservationAttemptZero,
    ];
    expected_kinds.sort();
    assert_eq!(
        kinds, expected_kinds,
        "the denied terminal commits its participant records"
    );

    // A stripped projection for the same paid operation must not apply:
    // the terminal cannot silently drop the release evidence.
    let stripped = AdmissionTerminalProjection::DeniedAfterDelivery {
        context: context.clone(),
        reason: DeliveryDenialReason::DigestMismatch,
        evidence: Box::new(AdmissionReceiptOrIncident::Receipt(Box::new(
            receipt.clone(),
        ))),
        payment_evidence: None,
        observer_work: None,
    };
    assert_eq!(
        operation.apply_terminal_projection(&stripped, &full_projection_capabilities()),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );

    // Participant evidence bound to the completed terminal cannot be
    // replayed onto the denied one.
    assert!(matches!(
        PaymentTerminalEvidence::from_source_verified(
            &operation,
            &context,
            &receipt,
            identifier("payment_participant_id", "payment-1"),
            digest("payment_authority_digest", AUTH_HASH),
            identifier("payment_record_id", "payment-record-1"),
            digest("payment_record_digest", REQUEST_HASH),
            900,
            outcome_id,
            outcome_version,
            AdmissionOperationState::Completed,
        )
        .expect("completed-bound evidence still qualifies on its own terms")
        .validate_against(
            &operation,
            &context,
            &receipt,
            &digest("outcome_id", POLICY_HASH),
            outcome_version,
            AdmissionOperationState::DeniedAfterDelivery,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));
}
