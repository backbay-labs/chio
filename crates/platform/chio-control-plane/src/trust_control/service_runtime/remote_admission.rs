use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chio_core::crypto::Keypair;
use chio_core::receipt::{body::ChioReceipt, lineage::ChildRequestReceipt};
use chio_kernel::admission_operation::{
    AdmissionBeginResult, AdmissionCaptureError, AdmissionCommandResult, AdmissionOperationCommand,
    AdmissionOperationState, AdmissionOperationStore, AdmissionOperationStoreError,
    AdmissionOperationV1, AdmissionProjectionCapabilities, AdmissionRecoveryLease,
    AdmissionReplayKey, AdmissionTerminal, AdmissionTerminalProjection,
    QualifiedAdmissionOperationStore, SignedAdmissionTerminalProjectionV1, StoreMutationFence,
    UntrustedAdmissionRecoveryClaim,
};
use chio_kernel::budget_store::{
    BudgetAuthorizeHoldRequest, BudgetCaptureInvocationRequest, BudgetGuaranteeLevel,
};
use chio_kernel::receipt_store::{
    AdmissionBudgetAuthorization, AdmissionBudgetAuthorizationError, AdmissionBudgetCapture,
    AdmissionPaymentJournalAdvance, AdmissionPaymentJournalError, AdmissionPaymentSettlement,
    AdmissionPaymentSettlementBegin, QualifiedAdmissionProjectionStore, ReceiptStore,
    ReceiptStoreError,
};
use chio_kernel::tool_outcome::{
    CanonicalInvocationBlobV1, CanonicalResolvedOutputBlobV1, PostReturnEvaluationRecordV1,
    QualifiedToolOutcomeStore, RawInvocationOutcomeV1, ToolOutcomeInsertResultV1,
    ToolOutcomeRecordV1, ToolOutcomeStore, ToolOutcomeStoreError,
};
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::super::*;
use super::client::build_client;

const ADMISSION_AUTHORITY_RESPONSE_LIMIT: u64 = 384 * 1024 * 1024;

pub(crate) struct RemoteAdmissionStores {
    pub(crate) operations: Arc<dyn QualifiedAdmissionProjectionStore>,
    pub(crate) outcomes: Arc<dyn QualifiedToolOutcomeStore>,
    pub(crate) budget: Arc<dyn chio_kernel::BudgetStore>,
    pub(crate) fence: StoreMutationFence,
}

struct RemoteAdmissionAuthority {
    client: TrustControlClient,
    fence: StoreMutationFence,
    signer: Keypair,
    budget: Arc<RemoteBudgetStore>,
}

#[derive(Debug)]
enum RemoteAdmissionError {
    Transport(String),
    Protocol(String),
    Authority(AdmissionAuthorityWireError),
}

pub(crate) fn build_remote_admission_stores(
    control_url: &str,
    control_token: &str,
    signer: Keypair,
) -> Result<RemoteAdmissionStores, CliError> {
    let client = build_client(control_url, control_token)?;
    let request = AdmissionAuthorityRequest::new(
        None,
        AdmissionAuthorityAction::Status,
        &serde_json::Value::Null,
    )?;
    let response: AdmissionAuthorityResponse = client.post_json_capped(
        INTERNAL_ADMISSION_AUTHORITY_PATH,
        &request,
        ADMISSION_AUTHORITY_RESPONSE_LIMIT,
    )?;
    let status: AdmissionAuthorityStatusWire = decode_response(response).map_err(|error| {
        CliError::cli_other_error(format!("failed to connect to admission authority: {error}"))
    })?;
    let budget = super::budget::build_shared_remote_budget_store(control_url, control_token)?;
    let authority = Arc::new(RemoteAdmissionAuthority {
        client,
        fence: status.fence.clone(),
        signer,
        budget: budget.clone(),
    });
    Ok(RemoteAdmissionStores {
        operations: authority.clone(),
        outcomes: authority,
        budget,
        fence: status.fence,
    })
}

impl RemoteAdmissionAuthority {
    fn call<B: Serialize, T: DeserializeOwned>(
        &self,
        action: AdmissionAuthorityAction,
        payload: &B,
    ) -> Result<T, RemoteAdmissionError> {
        let request = AdmissionAuthorityRequest::new(Some(self.fence.clone()), action, payload)
            .map_err(|error| RemoteAdmissionError::Protocol(error.to_string()))?;
        let response = self
            .client
            .post_json_capped(
                INTERNAL_ADMISSION_AUTHORITY_PATH,
                &request,
                ADMISSION_AUTHORITY_RESPONSE_LIMIT,
            )
            .map_err(|error| RemoteAdmissionError::Transport(error.to_string()))?;
        decode_response(response)
    }

    fn recovery_claim(lease: &AdmissionRecoveryLease) -> RecoveryClaimWire {
        RecoveryClaimWire::from_claim(lease.untrusted_claim())
    }
}

fn decode_response<T: DeserializeOwned>(
    response: AdmissionAuthorityResponse,
) -> Result<T, RemoteAdmissionError> {
    if !response.schema_is_valid() {
        return Err(RemoteAdmissionError::Protocol(
            "admission authority response schema is invalid".to_owned(),
        ));
    }
    match (response.result, response.error) {
        (Some(result), None) => serde_json::from_value(result.value)
            .map_err(|error| RemoteAdmissionError::Protocol(error.to_string())),
        (None, Some(error)) => Err(RemoteAdmissionError::Authority(error)),
        _ => Err(RemoteAdmissionError::Protocol(
            "admission authority response must contain exactly one outcome".to_owned(),
        )),
    }
}

impl std::fmt::Display for RemoteAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(message) | Self::Protocol(message) => formatter.write_str(message),
            Self::Authority(error) => formatter.write_str(&error.message),
        }
    }
}

impl AdmissionOperationStore for RemoteAdmissionAuthority {
    fn begin(
        &self,
        operation: &AdmissionOperationV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionBeginResult, AdmissionOperationStoreError> {
        let result: AdmissionBeginResultWire = self
            .call(
                AdmissionAuthorityAction::Begin,
                &AdmissionBeginWire {
                    operation: operation.to_persisted(),
                    fence: fence.clone(),
                    trusted_now_unix_ms,
                },
            )
            .map_err(operation_error)?;
        match result {
            AdmissionBeginResultWire::Created { operation } => Ok(AdmissionBeginResult::Created(
                AdmissionOperationV1::from_persisted(operation)?,
            )),
            AdmissionBeginResultWire::ExactReplay {
                operation,
                terminal_replay,
            } => Ok(AdmissionBeginResult::ExactReplay {
                operation: AdmissionOperationV1::from_persisted(operation)?,
                terminal_replay,
            }),
            AdmissionBeginResultWire::Conflict {
                existing_operation_id,
            } => Ok(AdmissionBeginResult::Conflict {
                existing_operation_id,
            }),
        }
    }

    fn load_by_operation_id(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
        let operation: Option<chio_kernel::admission_operation::PersistedAdmissionOperationV1> =
            self.call(
                AdmissionAuthorityAction::LoadByOperationId,
                &OperationIdWire {
                    operation_id: operation_id.clone(),
                },
            )
            .map_err(operation_error)?;
        operation
            .map(AdmissionOperationV1::from_persisted)
            .transpose()
            .map_err(Into::into)
    }

    fn load_by_replay_key(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
        let operation: Option<chio_kernel::admission_operation::PersistedAdmissionOperationV1> =
            self.call(
                AdmissionAuthorityAction::LoadByReplayKey,
                &ReplayKeyWire {
                    replay_key: replay_key.clone(),
                },
            )
            .map_err(operation_error)?;
        operation
            .map(AdmissionOperationV1::from_persisted)
            .transpose()
            .map_err(Into::into)
    }

    fn compare_and_swap(
        &self,
        command: &AdmissionOperationCommand,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        let result: AdmissionCommandResultWire = self
            .call(
                AdmissionAuthorityAction::CompareAndSwap,
                &AdmissionCommandWire {
                    operation_id: command.operation_id().clone(),
                    expected_version: command.expected_version(),
                    recovery_claim: Self::recovery_claim(command.recovery_lease()),
                    attachments: command.attachments().to_vec(),
                    next_state: command.next_state(),
                    terminal_replay: command.terminal_replay().cloned(),
                    last_error: command.last_error().cloned(),
                    trusted_now_unix_ms,
                },
            )
            .map_err(operation_error)?;
        let operation = AdmissionOperationV1::from_persisted(result.operation)?;
        Ok(if result.applied {
            AdmissionCommandResult::Applied(operation)
        } else {
            AdmissionCommandResult::Idempotent(operation)
        })
    }

    fn claim_recovery_untrusted(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
        expected_version: u64,
        claimant_id: &chio_kernel::admission_operation::AdmissionIdentifier,
        trusted_now_unix_ms: u64,
        expires_at_unix_ms: u64,
        fence: &StoreMutationFence,
    ) -> Result<UntrustedAdmissionRecoveryClaim, AdmissionOperationStoreError> {
        let claim: RecoveryClaimWire = self
            .call(
                AdmissionAuthorityAction::ClaimRecovery,
                &ClaimRecoveryWire {
                    operation_id: operation_id.clone(),
                    expected_version,
                    claimant_id: claimant_id.clone(),
                    trusted_now_unix_ms,
                    expires_at_unix_ms,
                    fence: fence.clone(),
                },
            )
            .map_err(operation_error)?;
        claim.into_claim().map_err(Into::into)
    }

    fn revalidate_recovery_claim(
        &self,
        operation: &AdmissionOperationV1,
        claim: &UntrustedAdmissionRecoveryClaim,
        trusted_now_unix_ms: u64,
        current_store_fence: &StoreMutationFence,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.call(
            AdmissionAuthorityAction::RevalidateRecoveryClaim,
            &RevalidateRecoveryClaimWire {
                operation: operation.to_persisted(),
                claim: RecoveryClaimWire::from_claim(claim),
                trusted_now_unix_ms,
                current_fence: current_store_fence.clone(),
            },
        )
        .map_err(operation_error)
    }

    fn list_recoverable(
        &self,
        not_after_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<AdmissionOperationV1>, AdmissionOperationStoreError> {
        let operations: Vec<chio_kernel::admission_operation::PersistedAdmissionOperationV1> = self
            .call(
                AdmissionAuthorityAction::ListRecoverable,
                &ListRecoverableWire {
                    not_after_unix_ms,
                    limit,
                },
            )
            .map_err(operation_error)?;
        operations
            .into_iter()
            .map(AdmissionOperationV1::from_persisted)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    fn load_terminal_replay(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<
        Option<chio_kernel::admission_operation::AdmissionTerminalReplay>,
        AdmissionOperationStoreError,
    > {
        self.call(
            AdmissionAuthorityAction::LoadTerminalReplay,
            &ReplayKeyWire {
                replay_key: replay_key.clone(),
            },
        )
        .map_err(operation_error)
    }
}

impl QualifiedAdmissionOperationStore for RemoteAdmissionAuthority {}

impl ReceiptStore for RemoteAdmissionAuthority {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Unsupported(
            "admission receipts must be committed through a terminal projection".to_owned(),
        ))
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Unsupported(
            "child receipts do not belong to the admission projection store".to_owned(),
        ))
    }

    fn admission_projection_capabilities(&self) -> AdmissionProjectionCapabilities {
        AdmissionProjectionCapabilities {
            operation_terminal: true,
            incident_terminal: true,
            tool_outcome: true,
            payment_terminal: true,
            authorization_consumption: true,
            outcome_eligibility: true,
            observation_attempt_zero: true,
            obligation: true,
            channel_terminal: true,
            credit_exposure_terminal: true,
            economic_mutation_terminal: true,
        }
    }

    fn commit_admission_projection(
        &self,
        projection: &AdmissionTerminalProjection,
    ) -> Result<AdmissionTerminal, ReceiptStoreError> {
        let source = self
            .load_by_operation_id(&projection.context().operation_id)
            .map_err(operation_as_receipt_error)?
            .ok_or_else(|| ReceiptStoreError::NotFound("admission operation".to_owned()))?;
        let envelope = SignedAdmissionTerminalProjectionV1::from_verified(
            &source,
            projection,
            &self.admission_projection_capabilities(),
            &self.signer,
        )
        .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
        let terminal: AdmissionTerminalWire = self
            .call(
                AdmissionAuthorityAction::CommitTerminalProjection,
                &CommitTerminalProjectionWire {
                    projection: envelope,
                },
            )
            .map_err(receipt_error)?;
        Ok(AdmissionTerminal {
            operation_id: terminal.operation_id,
            state: terminal.state,
            replay: terminal.replay,
        })
    }

    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        self.call(
            AdmissionAuthorityAction::LoadAdmissionReceipt,
            &ReceiptIdWire {
                receipt_id: receipt_id.to_owned(),
            },
        )
        .map_err(receipt_error)
    }
}

impl QualifiedAdmissionProjectionStore for RemoteAdmissionAuthority {
    fn load_payment_journal(
        &self,
        operation_id: &str,
        active_fence: &StoreMutationFence,
    ) -> Result<Option<chio_kernel::payment::PaymentJournalRecord>, AdmissionPaymentJournalError>
    {
        if active_fence != &self.fence {
            return Err(AdmissionPaymentJournalError::Fenced);
        }
        let operation_id =
            chio_kernel::admission_operation::AdmissionOperationId::from_persisted(operation_id)
                .map_err(|error| AdmissionPaymentJournalError::Invariant(error.to_string()))?;
        let journal: Option<chio_kernel::payment::PaymentJournalRecord> = self
            .call(
                AdmissionAuthorityAction::LoadPaymentJournal,
                &OperationIdWire {
                    operation_id: operation_id.clone(),
                },
            )
            .map_err(payment_journal_error)?;
        if let Some(journal) = &journal {
            journal
                .validate()
                .map_err(|error| AdmissionPaymentJournalError::Invariant(error.to_string()))?;
            if journal.operation_id != operation_id.as_str() {
                return Err(AdmissionPaymentJournalError::Invariant(
                    "remote payment journal changed operation identity".to_owned(),
                ));
            }
        }
        Ok(journal)
    }

    fn advance_payment_journal(
        &self,
        advance: AdmissionPaymentJournalAdvance<'_>,
    ) -> Result<chio_kernel::payment::PaymentJournalRecord, AdmissionPaymentJournalError> {
        let AdmissionPaymentJournalAdvance {
            operation,
            recovery_lease,
            expected,
            transition,
            release_evidence,
            active_fence,
            trusted_now_unix_ms,
        } = advance;
        if active_fence != &self.fence
            || recovery_lease.store_fence() != active_fence
            || expected.operation_id != operation.binding().operation_id().as_str()
        {
            return Err(AdmissionPaymentJournalError::Fenced);
        }
        expected
            .validate()
            .map_err(|error| AdmissionPaymentJournalError::Invariant(error.to_string()))?;
        let desired = expected
            .apply_transition(transition)
            .map_err(|error| AdmissionPaymentJournalError::Invariant(error.to_string()))?;
        let journal: chio_kernel::payment::PaymentJournalRecord = self
            .call(
                AdmissionAuthorityAction::AdvancePaymentJournal,
                &AdmissionPaymentAdvanceWire {
                    operation: operation.to_persisted(),
                    recovery_claim: Self::recovery_claim(recovery_lease),
                    expected: expected.clone(),
                    transition: transition.clone(),
                    release_evidence: release_evidence.map(|evidence| evidence.to_persisted()),
                    active_fence: active_fence.clone(),
                    trusted_now_unix_ms,
                },
            )
            .map_err(payment_journal_error)?;
        journal
            .validate()
            .map_err(|error| AdmissionPaymentJournalError::Invariant(error.to_string()))?;
        if journal != desired {
            return Err(AdmissionPaymentJournalError::Invariant(
                "remote payment journal returned a non-canonical successor".to_owned(),
            ));
        }
        Ok(journal)
    }

    fn begin_payment_settlement(
        &self,
        begin: AdmissionPaymentSettlementBegin<'_>,
    ) -> Result<AdmissionPaymentSettlement, AdmissionPaymentJournalError> {
        let AdmissionPaymentSettlementBegin {
            operation,
            recovery_lease,
            expected,
            transition,
            release_evidence,
            budget_reconcile,
            active_fence,
            trusted_now_unix_ms,
        } = begin;
        if active_fence != &self.fence
            || recovery_lease.store_fence() != active_fence
            || expected.operation_id != operation.binding().operation_id().as_str()
        {
            return Err(AdmissionPaymentJournalError::Fenced);
        }
        expected
            .validate()
            .map_err(|error| AdmissionPaymentJournalError::Invariant(error.to_string()))?;
        budget_reconcile
            .validate()
            .map_err(|error| AdmissionPaymentJournalError::Invariant(error.to_string()))?;
        let authority = budget_reconcile.authority.as_ref().ok_or_else(|| {
            AdmissionPaymentJournalError::Invariant(
                "remote payment settlement requires budget authority".to_owned(),
            )
        })?;
        let hold_id = budget_reconcile.hold_id.clone().ok_or_else(|| {
            AdmissionPaymentJournalError::Invariant(
                "remote payment settlement requires hold_id".to_owned(),
            )
        })?;
        let event_id = budget_reconcile.event_id.clone().ok_or_else(|| {
            AdmissionPaymentJournalError::Invariant(
                "remote payment settlement requires event_id".to_owned(),
            )
        })?;
        let grant_index = u32::try_from(budget_reconcile.grant_index).map_err(|_| {
            AdmissionPaymentJournalError::Invariant(
                "remote payment settlement grant index overflowed".to_owned(),
            )
        })?;
        let expected_successor = transition
            .map(|transition| expected.apply_transition(transition))
            .transpose()
            .map_err(|error| AdmissionPaymentJournalError::Invariant(error.to_string()))?
            .unwrap_or_else(|| expected.clone());
        let response: AdmissionPaymentSettlementResultWire = self
            .call(
                AdmissionAuthorityAction::BeginPaymentSettlement,
                &AdmissionPaymentSettlementBeginWire {
                    operation: operation.to_persisted(),
                    recovery_claim: Self::recovery_claim(recovery_lease),
                    expected: expected.clone(),
                    transition: transition.cloned(),
                    release_evidence: release_evidence.map(|evidence| evidence.to_persisted()),
                    budget_reconcile: StructuredBudgetReconcileRequest {
                        schema: STRUCTURED_BUDGET_REQUEST_SCHEMA.to_owned(),
                        capability_id: budget_reconcile.capability_id.clone(),
                        grant_index,
                        hold_id,
                        event_id,
                        exposed_cost_units: budget_reconcile.exposed_cost_units,
                        realized_spend_units: budget_reconcile.realized_spend_units,
                    },
                    authority_id: authority.authority_id.clone(),
                    authority_lease_id: authority.lease_id.clone(),
                    authority_lease_epoch: authority.lease_epoch,
                    active_fence: active_fence.clone(),
                    trusted_now_unix_ms,
                },
            )
            .map_err(payment_journal_error)?;
        response
            .journal
            .validate()
            .map_err(|error| AdmissionPaymentJournalError::Invariant(error.to_string()))?;
        if response.journal != expected_successor {
            return Err(AdmissionPaymentJournalError::Invariant(
                "remote payment settlement returned a non-canonical journal".to_owned(),
            ));
        }
        let (budget, budget_already_reconciled) = self
            .budget
            .qualify_reconcile_response(&budget_reconcile, response.budget, true)
            .map_err(|error| AdmissionPaymentJournalError::Invariant(error.to_string()))?;
        Ok(AdmissionPaymentSettlement {
            journal: response.journal,
            budget,
            budget_already_reconciled,
        })
    }

    fn authorize_budget_and_commit_admission(
        &self,
        operation: &AdmissionOperationV1,
        recovery_lease: &AdmissionRecoveryLease,
        request: BudgetAuthorizeHoldRequest,
        payment_journal: Option<chio_kernel::payment::PaymentJournalRecord>,
        credit_exposure: Option<chio_kernel::CreditExposureReservationRequest>,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionBudgetAuthorization, AdmissionBudgetAuthorizationError> {
        if credit_exposure.is_some() {
            return Err(AdmissionBudgetAuthorizationError::Unavailable(
                "remote admission authority does not support credit exposure reservation"
                    .to_owned(),
            ));
        }
        let authority = request.authority.as_ref().ok_or_else(|| {
            AdmissionBudgetAuthorizationError::Invariant(
                "remote combined authorization omitted its authority".to_owned(),
            )
        })?;
        let hold_id = request.hold_id.clone().ok_or_else(|| {
            AdmissionBudgetAuthorizationError::Invariant(
                "remote combined authorization omitted hold_id".to_owned(),
            )
        })?;
        if request.admission_binding.as_ref().is_none_or(|binding| {
            binding.operation_id != operation.binding().operation_id().as_str()
        }) {
            return Err(AdmissionBudgetAuthorizationError::Invariant(
                "remote combined authorization changed operation identity".to_owned(),
            ));
        }
        let wire = StructuredBudgetAuthorizeRequest::from_core(&request)
            .map_err(AdmissionBudgetAuthorizationError::Invariant)?;
        let response: AdmissionBudgetAuthorizeResultWire = self
            .call(
                AdmissionAuthorityAction::AuthorizeBudgetAndCommitAdmission,
                &AdmissionBudgetAuthorizeWire {
                    operation: operation.to_persisted(),
                    recovery_claim: Self::recovery_claim(recovery_lease),
                    budget: wire.clone(),
                    payment_journal: payment_journal.clone(),
                    authority_id: authority.authority_id.clone(),
                    authority_lease_id: authority.lease_id.clone(),
                    authority_lease_epoch: authority.lease_epoch,
                    active_fence: active_fence.clone(),
                    trusted_now_unix_ms,
                },
            )
            .map_err(authorization_error)?;
        let decision = self
            .budget
            .decode_structured_budget_authorization(
                request,
                wire,
                response.budget,
                BudgetGuaranteeLevel::SingleNodeAtomic,
            )
            .map_err(|error| AdmissionBudgetAuthorizationError::Invariant(error.to_string()))?;
        let updated = AdmissionOperationV1::from_persisted(response.operation)
            .map_err(AdmissionBudgetAuthorizationError::Operation)?;
        let expected = if matches!(
            decision,
            chio_kernel::budget_store::BudgetAuthorizeHoldDecision::Authorized(_)
        ) {
            let requirements = operation.binding().participant_requirements();
            if requirements.payment != payment_journal.is_some() {
                return Err(AdmissionBudgetAuthorizationError::Invariant(
                    "remote payment participant does not match operation requirements".to_owned(),
                ));
            }
            let mut attachments = vec![
                chio_kernel::admission_operation::AdmissionAttachment::BudgetHoldId(
                    chio_kernel::admission_operation::AdmissionIdentifier::try_new(
                        "budget_hold_id",
                        hold_id,
                    )?,
                ),
            ];
            if requirements.payment {
                attachments.push(
                    chio_kernel::admission_operation::AdmissionAttachment::PaymentParticipantId(
                        chio_kernel::admission_operation::AdmissionIdentifier::try_new(
                            "payment_participant_id",
                            operation.binding().operation_id().as_str(),
                        )?,
                    ),
                );
            }
            let command = AdmissionOperationCommand::new(
                operation.binding().operation_id().clone(),
                operation.version(),
                recovery_lease.clone(),
                attachments,
                Some(AdmissionOperationState::BudgetAuthorized),
                None,
                None,
            )?;
            operation
                .apply_command(&command, trusted_now_unix_ms)?
                .into_operation()
        } else {
            operation.clone()
        };
        if updated != expected {
            return Err(AdmissionBudgetAuthorizationError::Invariant(
                "remote combined authorization returned a non-canonical operation successor"
                    .to_owned(),
            ));
        }
        Ok(AdmissionBudgetAuthorization {
            decision,
            operation: updated,
        })
    }

    fn capture_invocation_and_commit_dispatch(
        &self,
        operation: &AdmissionOperationV1,
        recovery_lease: &AdmissionRecoveryLease,
        request: BudgetCaptureInvocationRequest,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionBudgetCapture, AdmissionCaptureError> {
        let authority = request.authority.as_ref().ok_or_else(|| {
            AdmissionCaptureError::Invariant(
                "remote combined capture omitted its authority".to_owned(),
            )
        })?;
        if request.trusted_time.is_some() {
            return Err(AdmissionCaptureError::Invariant(
                "remote combined capture cannot supply caller time to the budget authority"
                    .to_owned(),
            ));
        }
        let grant_index = u32::try_from(request.grant_index).map_err(|_| {
            AdmissionCaptureError::Invariant(
                "remote combined capture grant index overflowed".to_owned(),
            )
        })?;
        let response: AdmissionDispatchCaptureResultWire = self
            .call(
                AdmissionAuthorityAction::CaptureInvocationAndCommitDispatch,
                &AdmissionDispatchCaptureWire {
                    operation: operation.to_persisted(),
                    recovery_claim: Self::recovery_claim(recovery_lease),
                    capability_id: request.capability_id.clone(),
                    grant_index,
                    hold_id: request.hold_id.clone(),
                    event_id: request.event_id.clone(),
                    authority_id: authority.authority_id.clone(),
                    authority_lease_id: authority.lease_id.clone(),
                    authority_lease_epoch: authority.lease_epoch,
                    active_fence: active_fence.clone(),
                    trusted_now_unix_ms,
                },
            )
            .map_err(capture_error)?;
        let updated = AdmissionOperationV1::from_persisted(response.operation)
            .map_err(AdmissionCaptureError::Operation)?;
        let command = AdmissionOperationCommand::new(
            operation.binding().operation_id().clone(),
            operation.version(),
            recovery_lease.clone(),
            Vec::new(),
            Some(AdmissionOperationState::DispatchCommitted),
            None,
            None,
        )
        .map_err(AdmissionCaptureError::Operation)?;
        let expected = operation
            .apply_command(&command, trusted_now_unix_ms)
            .map_err(AdmissionCaptureError::Operation)?
            .into_operation();
        if updated != expected {
            return Err(AdmissionCaptureError::Invariant(
                "remote combined capture returned a non-canonical admission successor".to_owned(),
            ));
        }
        let decision = self
            .budget
            .qualify_invocation_capture_response(&request, response.budget)
            .map_err(|error| AdmissionCaptureError::Invariant(error.to_string()))?;
        Ok(AdmissionBudgetCapture {
            decision,
            operation: updated,
        })
    }

    fn list_admission_receipts_after(
        &self,
        after_receipt_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ChioReceipt>, ReceiptStoreError> {
        self.call(
            AdmissionAuthorityAction::ListAdmissionReceipts,
            &ListAdmissionReceiptsWire {
                after_receipt_id: after_receipt_id.map(str::to_owned),
                limit,
            },
        )
        .map_err(receipt_error)
    }
}

impl ToolOutcomeStore for RemoteAdmissionAuthority {
    fn record_tool_returned(
        &self,
        operation: &AdmissionOperationV1,
        recovery_lease: &AdmissionRecoveryLease,
        blob: &CanonicalInvocationBlobV1,
        record: &ToolOutcomeRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<ToolOutcomeInsertResultV1, ToolOutcomeStoreError> {
        let raw = RawInvocationOutcomeV1::from_canonical_bytes(blob.bytes())
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        let result: ToolOutcomeInsertResultWire = self
            .call(
                AdmissionAuthorityAction::RecordToolReturned,
                &RecordToolReturnedWire {
                    operation: operation.to_persisted(),
                    recovery_claim: Self::recovery_claim(recovery_lease),
                    raw: raw.to_persisted(),
                    record: record.to_persisted(),
                    active_fence: active_fence.clone(),
                    trusted_now_unix_ms,
                },
            )
            .map_err(outcome_error)?;
        let outcome = ToolOutcomeRecordV1::from_persisted(result.outcome)
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        let operation = AdmissionOperationV1::from_persisted(result.operation)
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        Ok(if result.inserted {
            ToolOutcomeInsertResultV1::Inserted { outcome, operation }
        } else {
            ToolOutcomeInsertResultV1::ExactReplay { outcome, operation }
        })
    }

    fn lookup_by_operation(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
    ) -> Result<Option<ToolOutcomeRecordV1>, ToolOutcomeStoreError> {
        let value: Option<chio_kernel::tool_outcome::PersistedToolOutcomeRecordV1> = self
            .call(
                AdmissionAuthorityAction::LookupToolOutcome,
                &OperationIdWire {
                    operation_id: operation_id.clone(),
                },
            )
            .map_err(outcome_error)?;
        value
            .map(ToolOutcomeRecordV1::from_persisted)
            .transpose()
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))
    }

    fn load_raw_invocation_by_operation(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
    ) -> Result<Option<RawInvocationOutcomeV1>, ToolOutcomeStoreError> {
        let value: Option<chio_kernel::tool_outcome::PersistedRawInvocationOutcomeV1> = self
            .call(
                AdmissionAuthorityAction::LoadRawInvocation,
                &OperationIdWire {
                    operation_id: operation_id.clone(),
                },
            )
            .map_err(outcome_error)?;
        value
            .map(RawInvocationOutcomeV1::from_persisted)
            .transpose()
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))
    }

    fn lookup_post_return_evaluation(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
    ) -> Result<Option<PostReturnEvaluationRecordV1>, ToolOutcomeStoreError> {
        let value: Option<chio_kernel::tool_outcome::PersistedPostReturnEvaluationRecordV1> = self
            .call(
                AdmissionAuthorityAction::LookupPostReturnEvaluation,
                &OperationIdWire {
                    operation_id: operation_id.clone(),
                },
            )
            .map_err(outcome_error)?;
        value
            .map(PostReturnEvaluationRecordV1::from_persisted)
            .transpose()
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))
    }

    fn begin_post_return_evaluation(
        &self,
        recovery_lease: &AdmissionRecoveryLease,
        record: &PostReturnEvaluationRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeStoreError> {
        let value: chio_kernel::tool_outcome::PersistedPostReturnEvaluationRecordV1 = self
            .call(
                AdmissionAuthorityAction::BeginPostReturnEvaluation,
                &BeginPostReturnEvaluationWire {
                    recovery_claim: Self::recovery_claim(recovery_lease),
                    record: record.to_persisted(),
                    active_fence: active_fence.clone(),
                    trusted_now_unix_ms,
                },
            )
            .map_err(outcome_error)?;
        PostReturnEvaluationRecordV1::from_persisted(value)
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))
    }

    fn stage_post_return_evaluation(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
        expected_version: u64,
        recovery_lease: &AdmissionRecoveryLease,
        next: &PostReturnEvaluationRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeStoreError> {
        let value: chio_kernel::tool_outcome::PersistedPostReturnEvaluationRecordV1 = self
            .call(
                AdmissionAuthorityAction::StagePostReturnEvaluation,
                &StagePostReturnEvaluationWire {
                    operation_id: operation_id.clone(),
                    expected_version,
                    recovery_claim: Self::recovery_claim(recovery_lease),
                    next: next.to_persisted(),
                    active_fence: active_fence.clone(),
                    trusted_now_unix_ms,
                },
            )
            .map_err(outcome_error)?;
        PostReturnEvaluationRecordV1::from_persisted(value)
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))
    }

    fn finalize_post_return(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
        expected_evaluation_version: u64,
        recovery_lease: &AdmissionRecoveryLease,
        terminal_evaluation: &PostReturnEvaluationRecordV1,
        expected_outcome_version: u64,
        terminal_outcome: &ToolOutcomeRecordV1,
        resolved_output: Option<&CanonicalResolvedOutputBlobV1>,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(PostReturnEvaluationRecordV1, ToolOutcomeRecordV1), ToolOutcomeStoreError> {
        let value: FinalizePostReturnResultWire = self
            .call(
                AdmissionAuthorityAction::FinalizePostReturn,
                &FinalizePostReturnWire {
                    operation_id: operation_id.clone(),
                    expected_evaluation_version,
                    recovery_claim: Self::recovery_claim(recovery_lease),
                    terminal_evaluation: terminal_evaluation.to_persisted(),
                    expected_outcome_version,
                    terminal_outcome: terminal_outcome.to_persisted(),
                    resolved_output: resolved_output.map(|blob| STANDARD.encode(blob.bytes())),
                    active_fence: active_fence.clone(),
                    trusted_now_unix_ms,
                },
            )
            .map_err(outcome_error)?;
        Ok((
            PostReturnEvaluationRecordV1::from_persisted(value.evaluation)
                .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?,
            ToolOutcomeRecordV1::from_persisted(value.outcome)
                .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?,
        ))
    }

    fn load_resolved_output_by_operation(
        &self,
        operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
    ) -> Result<Option<CanonicalResolvedOutputBlobV1>, ToolOutcomeStoreError> {
        let value: Option<String> = self
            .call(
                AdmissionAuthorityAction::LoadResolvedOutput,
                &OperationIdWire {
                    operation_id: operation_id.clone(),
                },
            )
            .map_err(outcome_error)?;
        value
            .map(|encoded| {
                STANDARD
                    .decode(encoded)
                    .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))
                    .and_then(|bytes| {
                        CanonicalResolvedOutputBlobV1::from_signing_preimage(bytes)
                            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))
                    })
            })
            .transpose()
    }
}

impl QualifiedToolOutcomeStore for RemoteAdmissionAuthority {}

fn operation_error(error: RemoteAdmissionError) -> AdmissionOperationStoreError {
    match error {
        RemoteAdmissionError::Authority(error) => match error.code {
            AdmissionAuthorityErrorCode::Fenced => AdmissionOperationStoreError::Fenced,
            AdmissionAuthorityErrorCode::NotFound => AdmissionOperationStoreError::NotFound,
            AdmissionAuthorityErrorCode::OutcomeUnknown => {
                AdmissionOperationStoreError::OutcomeUnknown(error.message)
            }
            AdmissionAuthorityErrorCode::Unavailable | AdmissionAuthorityErrorCode::Timeout => {
                AdmissionOperationStoreError::Unavailable(error.message)
            }
            _ => AdmissionOperationStoreError::Invariant(error.message),
        },
        RemoteAdmissionError::Transport(message) => {
            AdmissionOperationStoreError::Unavailable(message)
        }
        RemoteAdmissionError::Protocol(message) => AdmissionOperationStoreError::Invariant(message),
    }
}

fn capture_error(error: RemoteAdmissionError) -> AdmissionCaptureError {
    match error {
        RemoteAdmissionError::Authority(error) => match error.code {
            AdmissionAuthorityErrorCode::Fenced => AdmissionCaptureError::Fenced,
            AdmissionAuthorityErrorCode::OutcomeUnknown => {
                AdmissionCaptureError::OutcomeUnknown(error.message)
            }
            AdmissionAuthorityErrorCode::Unavailable | AdmissionAuthorityErrorCode::Timeout => {
                AdmissionCaptureError::Unavailable(error.message)
            }
            _ => AdmissionCaptureError::Invariant(error.message),
        },
        RemoteAdmissionError::Transport(message) => AdmissionCaptureError::Unavailable(message),
        RemoteAdmissionError::Protocol(message) => AdmissionCaptureError::Invariant(message),
    }
}

fn authorization_error(error: RemoteAdmissionError) -> AdmissionBudgetAuthorizationError {
    match error {
        RemoteAdmissionError::Authority(error) => match error.code {
            AdmissionAuthorityErrorCode::Fenced => AdmissionBudgetAuthorizationError::Fenced,
            AdmissionAuthorityErrorCode::OutcomeUnknown => {
                AdmissionBudgetAuthorizationError::OutcomeUnknown(error.message)
            }
            AdmissionAuthorityErrorCode::Unavailable | AdmissionAuthorityErrorCode::Timeout => {
                AdmissionBudgetAuthorizationError::Unavailable(error.message)
            }
            _ => AdmissionBudgetAuthorizationError::Invariant(error.message),
        },
        RemoteAdmissionError::Transport(message) => {
            AdmissionBudgetAuthorizationError::Unavailable(message)
        }
        RemoteAdmissionError::Protocol(message) => {
            AdmissionBudgetAuthorizationError::Invariant(message)
        }
    }
}

fn payment_journal_error(error: RemoteAdmissionError) -> AdmissionPaymentJournalError {
    match error {
        RemoteAdmissionError::Authority(error) => match error.code {
            AdmissionAuthorityErrorCode::Fenced => AdmissionPaymentJournalError::Fenced,
            AdmissionAuthorityErrorCode::CasConflict | AdmissionAuthorityErrorCode::Conflict => {
                AdmissionPaymentJournalError::Conflict(error.message)
            }
            AdmissionAuthorityErrorCode::OutcomeUnknown => {
                AdmissionPaymentJournalError::OutcomeUnknown(error.message)
            }
            AdmissionAuthorityErrorCode::Unavailable | AdmissionAuthorityErrorCode::Timeout => {
                AdmissionPaymentJournalError::Unavailable(error.message)
            }
            _ => AdmissionPaymentJournalError::Invariant(error.message),
        },
        RemoteAdmissionError::Transport(message) => {
            AdmissionPaymentJournalError::Unavailable(message)
        }
        RemoteAdmissionError::Protocol(message) => AdmissionPaymentJournalError::Invariant(message),
    }
}

fn outcome_error(error: RemoteAdmissionError) -> ToolOutcomeStoreError {
    match error {
        RemoteAdmissionError::Authority(error) => match error.code {
            AdmissionAuthorityErrorCode::Fenced => ToolOutcomeStoreError::Fenced,
            AdmissionAuthorityErrorCode::NotFound => ToolOutcomeStoreError::NotFound,
            AdmissionAuthorityErrorCode::Conflict => ToolOutcomeStoreError::Conflict,
            AdmissionAuthorityErrorCode::CasConflict => ToolOutcomeStoreError::CasConflict,
            AdmissionAuthorityErrorCode::Unavailable
            | AdmissionAuthorityErrorCode::Timeout
            | AdmissionAuthorityErrorCode::OutcomeUnknown => {
                ToolOutcomeStoreError::Unavailable(error.message)
            }
            _ => ToolOutcomeStoreError::Invariant(error.message),
        },
        RemoteAdmissionError::Transport(message) => ToolOutcomeStoreError::Unavailable(message),
        RemoteAdmissionError::Protocol(message) => ToolOutcomeStoreError::Invariant(message),
    }
}

fn receipt_error(error: RemoteAdmissionError) -> ReceiptStoreError {
    match error {
        RemoteAdmissionError::Authority(error) => match error.code {
            AdmissionAuthorityErrorCode::Fenced => ReceiptStoreError::Fenced,
            AdmissionAuthorityErrorCode::NotFound => ReceiptStoreError::NotFound(error.message),
            AdmissionAuthorityErrorCode::Conflict => ReceiptStoreError::Conflict(error.message),
            AdmissionAuthorityErrorCode::Unsupported => {
                ReceiptStoreError::Unsupported(error.message)
            }
            AdmissionAuthorityErrorCode::OutcomeUnknown => {
                ReceiptStoreError::OutcomeUnknown(error.message)
            }
            AdmissionAuthorityErrorCode::Timeout => ReceiptStoreError::Timeout {
                operation: "remote admission authority".to_owned(),
                timeout_ms: 0,
            },
            _ => ReceiptStoreError::ReadBoundary(error.message),
        },
        RemoteAdmissionError::Transport(message) | RemoteAdmissionError::Protocol(message) => {
            ReceiptStoreError::ReadBoundary(message)
        }
    }
}

fn operation_as_receipt_error(error: AdmissionOperationStoreError) -> ReceiptStoreError {
    match error {
        AdmissionOperationStoreError::Fenced => ReceiptStoreError::Fenced,
        AdmissionOperationStoreError::NotFound => {
            ReceiptStoreError::NotFound("admission operation".to_owned())
        }
        AdmissionOperationStoreError::OutcomeUnknown(message) => {
            ReceiptStoreError::OutcomeUnknown(message)
        }
        other => ReceiptStoreError::ReadBoundary(other.to_string()),
    }
}
