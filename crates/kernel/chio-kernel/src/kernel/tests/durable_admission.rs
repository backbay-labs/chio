use crate::admission_operation::{
    AdmissionAttachment, AdmissionBeginResult, AdmissionCaptureError, AdmissionCommandResult,
    AdmissionIdentifier, AdmissionOperationCommand, AdmissionOperationError, AdmissionOperationId,
    AdmissionOperationState, AdmissionOperationStore, AdmissionOperationStoreError,
    AdmissionOperationV1, AdmissionProjectionCapabilities, AdmissionReplayClassification,
    AdmissionReplayKey, AdmissionTerminal, AdmissionTerminalProjection, AdmissionTerminalReplay,
    QualifiedAdmissionOperationStore, StoreMutationFence, UntrustedAdmissionRecoveryClaim,
};
use crate::receipt_store::{QualifiedAdmissionProjectionStore, ReceiptStore, ReceiptStoreError};
use crate::tool_outcome::{
    validate_evaluation_store_successor, validate_terminal_store_pair, CanonicalInvocationBlobV1,
    CanonicalResolvedOutputBlobV1, PostReturnEvaluationRecordV1, QualifiedToolOutcomeStore,
    RawInvocationOutcomeV1, ToolOutcomeInsertResultV1, ToolOutcomeRecordV1, ToolOutcomeStore,
    ToolOutcomeStoreError,
};

#[path = "durable_admission/monetary.rs"]
mod monetary;
#[path = "durable_admission/review_regressions.rs"]
mod review_regressions;

#[test]
fn durable_admission_runtime_defaults_closed_and_off_requires_explicit_unsafe_ephemeral_mode() {
    use crate::admission_operation::{AdmissionOperationError, DurableAdmissionMode};

    let mut kernel = make_kernel(make_config());
    assert_eq!(
        kernel.durable_admission_mode(),
        DurableAdmissionMode::SideEffecting
    );
    assert_eq!(
        kernel.configure_durable_admission(DurableAdmissionMode::Off, false),
        Err(AdmissionOperationError::UnsafeDurableAdmissionOff)
    );
    kernel
        .configure_durable_admission(DurableAdmissionMode::Monetary, false)
        .expect("monetary qualification mode");
    assert_eq!(
        kernel.durable_admission_mode(),
        DurableAdmissionMode::Monetary
    );
    kernel
        .configure_durable_admission(DurableAdmissionMode::Off, true)
        .expect("explicit unsafe ephemeral mode");
    assert_eq!(kernel.durable_admission_mode(), DurableAdmissionMode::Off);

    let mut durable_config = make_config();
    durable_config.allow_ephemeral_receipt_log = false;
    let mut durable_kernel = make_kernel(durable_config);
    assert_eq!(
        durable_kernel.configure_durable_admission(DurableAdmissionMode::Off, true),
        Err(AdmissionOperationError::UnsafeDurableAdmissionOff)
    );
}

#[test]
fn side_effecting_mode_exempts_only_explicitly_read_only_tools() {
    struct ReadOnlyServer;

    #[async_trait::async_trait]
    impl ToolServerConnection for ReadOnlyServer {
        fn server_id(&self) -> &str {
            "read-only-server"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["lookup".to_owned()]
        }

        fn tool_is_read_only(&self, tool_name: &str) -> bool {
            tool_name == "lookup"
        }

        async fn invoke(
            &self,
            _tool_name: &str,
            _arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            Ok(serde_json::json!({"found": true}))
        }
    }

    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(ReadOnlyServer));
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant("read-only-server", "lookup")]),
        300,
    );
    let request = make_request(
        "durable-read-only-classification",
        &capability,
        "lookup",
        "read-only-server",
    );
    let matching = resolve_required_matching_grants(
        &capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )
    .expect("matching read-only grant");

    assert!(kernel
        .begin_durable_tool_admission(&request, &matching, current_unix_timestamp_ms())
        .expect("read-only classification")
        .is_none());
}

#[derive(Default)]
struct TestAdmissionState {
    operation: Option<AdmissionOperationV1>,
    claim: Option<UntrustedAdmissionRecoveryClaim>,
    raw_outcome: Option<RawInvocationOutcomeV1>,
    tool_outcome: Option<ToolOutcomeRecordV1>,
    post_return_evaluation: Option<PostReturnEvaluationRecordV1>,
    resolved_output: Option<CanonicalResolvedOutputBlobV1>,
    receipt: Option<chio_core::receipt::body::ChioReceipt>,
    budget_authorization: Option<crate::budget_store::BudgetAuthorizeHoldRequest>,
    payment_journal: Option<crate::payment::PaymentJournalRecord>,
    payment_release_evidence: Option<crate::tool_outcome::PersistedMonetaryReleaseEvidenceV1>,
}

struct TestAdmissionOperationStore {
    fence: std::sync::Mutex<StoreMutationFence>,
    fail_next_outcome_write: std::sync::atomic::AtomicBool,
    fail_next_evaluation_begin: std::sync::atomic::AtomicBool,
    fail_next_evaluation_stage: std::sync::atomic::AtomicBool,
    fail_next_evaluation_finalization: std::sync::atomic::AtomicBool,
    fail_next_terminal_projection: std::sync::atomic::AtomicBool,
    fail_next_payment_settlement_intent: std::sync::atomic::AtomicBool,
    fail_next_budget_authorization: std::sync::atomic::AtomicBool,
    budget: std::sync::Arc<crate::budget_store::InMemoryBudgetStore>,
    state: std::sync::Mutex<TestAdmissionState>,
}

impl TestAdmissionOperationStore {
    fn new(fence: StoreMutationFence) -> Self {
        Self {
            fence: std::sync::Mutex::new(fence),
            fail_next_outcome_write: std::sync::atomic::AtomicBool::new(false),
            fail_next_evaluation_begin: std::sync::atomic::AtomicBool::new(false),
            fail_next_evaluation_stage: std::sync::atomic::AtomicBool::new(false),
            fail_next_evaluation_finalization: std::sync::atomic::AtomicBool::new(false),
            fail_next_terminal_projection: std::sync::atomic::AtomicBool::new(false),
            fail_next_payment_settlement_intent: std::sync::atomic::AtomicBool::new(false),
            fail_next_budget_authorization: std::sync::atomic::AtomicBool::new(false),
            budget: std::sync::Arc::new(crate::budget_store::InMemoryBudgetStore::new()),
            state: std::sync::Mutex::new(TestAdmissionState::default()),
        }
    }

    fn fail_next_outcome_write(&self) {
        self.fail_next_outcome_write.store(true, Ordering::SeqCst);
    }

    fn fail_next_terminal_projection(&self) {
        self.fail_next_terminal_projection
            .store(true, Ordering::SeqCst);
    }

    fn fail_next_evaluation_begin(&self) {
        self.fail_next_evaluation_begin
            .store(true, Ordering::SeqCst);
    }

    fn fail_next_evaluation_stage(&self) {
        self.fail_next_evaluation_stage
            .store(true, Ordering::SeqCst);
    }

    fn fail_next_evaluation_finalization(&self) {
        self.fail_next_evaluation_finalization
            .store(true, Ordering::SeqCst);
    }

    fn outcome_versions(&self) -> (Option<u64>, Option<u64>) {
        let state = self.state.lock().expect("test admission state lock");
        (
            state
                .post_return_evaluation
                .as_ref()
                .map(PostReturnEvaluationRecordV1::version),
            state
                .tool_outcome
                .as_ref()
                .map(ToolOutcomeRecordV1::version),
        )
    }

    fn rotate_fence(&self, fence: StoreMutationFence) {
        *self.fence.lock().expect("test admission fence lock") = fence;
    }

    fn operation(&self) -> AdmissionOperationV1 {
        self.state
            .lock()
            .expect("test admission state lock")
            .operation
            .clone()
            .expect("retained operation")
    }

    fn has_operation(&self) -> bool {
        self.state
            .lock()
            .expect("test admission state lock")
            .operation
            .is_some()
    }

    fn payment_journal(&self) -> Option<crate::payment::PaymentJournalRecord> {
        self.state
            .lock()
            .expect("test admission state lock")
            .payment_journal
            .clone()
    }

    fn payment_release_evidence(
        &self,
    ) -> Option<crate::tool_outcome::PersistedMonetaryReleaseEvidenceV1> {
        self.state
            .lock()
            .expect("test admission state lock")
            .payment_release_evidence
            .clone()
    }

    fn fail_next_payment_settlement_intent(&self) {
        self.fail_next_payment_settlement_intent
            .store(true, Ordering::SeqCst);
    }

    fn fail_next_budget_authorization(&self) {
        self.fail_next_budget_authorization
            .store(true, Ordering::SeqCst);
    }

    fn budget_store(&self) -> std::sync::Arc<crate::budget_store::InMemoryBudgetStore> {
        self.budget.clone()
    }

    fn require_fence(
        &self,
        fence: &StoreMutationFence,
    ) -> Result<(), AdmissionOperationStoreError> {
        (fence == &*self.fence.lock().expect("test admission fence lock"))
            .then_some(())
            .ok_or(AdmissionOperationStoreError::Fenced)
    }
}

impl AdmissionOperationStore for TestAdmissionOperationStore {
    fn begin(
        &self,
        operation: &AdmissionOperationV1,
        fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<AdmissionBeginResult, AdmissionOperationStoreError> {
        self.require_fence(fence)?;
        operation.validate()?;
        let mut state = self.state.lock().expect("test admission state lock");
        let Some(existing) = state.operation.as_ref() else {
            state.operation = Some(operation.clone());
            return Ok(AdmissionBeginResult::Created(operation.clone()));
        };
        Ok(match existing.classify_replay(operation) {
            AdmissionReplayClassification::Exact { terminal_replay } => {
                AdmissionBeginResult::ExactReplay {
                    operation: existing.clone(),
                    terminal_replay,
                }
            }
            AdmissionReplayClassification::Conflict => AdmissionBeginResult::Conflict {
                existing_operation_id: existing.binding().operation_id().clone(),
            },
        })
    }

    fn load_by_operation_id(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
        Ok(self
            .state
            .lock()
            .expect("test admission state lock")
            .operation
            .as_ref()
            .filter(|operation| operation.binding().operation_id() == operation_id)
            .cloned())
    }

    fn load_by_replay_key(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
        Ok(self
            .state
            .lock()
            .expect("test admission state lock")
            .operation
            .as_ref()
            .filter(|operation| &operation.replay_key() == replay_key)
            .cloned())
    }

    fn compare_and_swap(
        &self,
        command: &AdmissionOperationCommand,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        let mut state = self.state.lock().expect("test admission state lock");
        let operation = state
            .operation
            .as_ref()
            .filter(|operation| operation.binding().operation_id() == command.operation_id())
            .cloned()
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        let claim = state
            .claim
            .as_ref()
            .filter(|claim| claim.operation_id() == command.operation_id())
            .ok_or(AdmissionOperationStoreError::Fenced)?;
        let lease = command.recovery_lease();
        if claim.claimant_id() != lease.claimant_id()
            || claim.coordinator_lease_id() != lease.coordinator_lease_id()
            || claim.claimed_version() != lease.claimed_version()
            || claim.expires_at_unix_ms() != lease.expires_at_unix_ms()
            || claim.store_fence() != lease.store_fence()
        {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        let result = operation.apply_command(command, trusted_now_unix_ms)?;
        state.operation = Some(result.clone().into_operation());
        state.claim = None;
        Ok(result)
    }

    fn claim_recovery_untrusted(
        &self,
        operation_id: &AdmissionOperationId,
        expected_version: u64,
        claimant_id: &AdmissionIdentifier,
        _trusted_now_unix_ms: u64,
        expires_at_unix_ms: u64,
        fence: &StoreMutationFence,
    ) -> Result<UntrustedAdmissionRecoveryClaim, AdmissionOperationStoreError> {
        self.require_fence(fence)?;
        let mut state = self.state.lock().expect("test admission state lock");
        let operation = state
            .operation
            .as_ref()
            .filter(|operation| operation.binding().operation_id() == operation_id)
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        if operation.version() != expected_version {
            return Err(AdmissionOperationError::StaleVersion {
                expected: expected_version,
                actual: operation.version(),
            }
            .into());
        }
        let claim = UntrustedAdmissionRecoveryClaim::new(
            operation_id.clone(),
            claimant_id.clone(),
            AdmissionIdentifier::try_new("coordinator_lease_id", fence.lease_id.clone())?,
            operation.coordinator_lease_epoch(),
            expected_version,
            expires_at_unix_ms,
            fence.clone(),
        )?;
        state.claim = Some(claim.clone());
        Ok(claim)
    }

    fn revalidate_recovery_claim(
        &self,
        operation: &AdmissionOperationV1,
        claim: &UntrustedAdmissionRecoveryClaim,
        trusted_now_unix_ms: u64,
        current_store_fence: &StoreMutationFence,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.require_fence(current_store_fence)?;
        let state = self.state.lock().expect("test admission state lock");
        if state.operation.as_ref() != Some(operation)
            || state.claim.as_ref() != Some(claim)
            || trusted_now_unix_ms >= claim.expires_at_unix_ms()
        {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        Ok(())
    }

    fn list_recoverable(
        &self,
        not_after_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<AdmissionOperationV1>, AdmissionOperationStoreError> {
        let store_fence = self.fence.lock().expect("test admission fence lock").clone();
        let state = self.state.lock().expect("test admission state lock");
        // Mirror the durable store's recovery contract: an operation still under a
        // live recovery lease held by the serving fence is being actively driven
        // and is not recoverable. Only an expired lease, a lease from another
        // fence, or no lease at all makes an operation eligible for the sweep.
        Ok(state
            .operation
            .iter()
            .filter(|operation| !operation.state().is_terminal())
            .filter(|operation| {
                operation.state() != AdmissionOperationState::ApprovalRequired
            })
            .filter(|operation| {
                !state.claim.as_ref().is_some_and(|claim| {
                    claim.operation_id() == operation.binding().operation_id()
                        && claim.expires_at_unix_ms() > not_after_unix_ms
                        && claim.store_fence() == &store_fence
                })
            })
            .take(limit)
            .cloned()
            .collect())
    }

    fn load_terminal_replay(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionTerminalReplay>, AdmissionOperationStoreError> {
        Ok(self
            .load_by_replay_key(replay_key)?
            .and_then(|operation| operation.terminal_replay().cloned()))
    }
}

impl QualifiedAdmissionOperationStore for TestAdmissionOperationStore {}

impl ReceiptStore for TestAdmissionOperationStore {
    fn append_chio_receipt(
        &self,
        _receipt: &chio_core::receipt::body::ChioReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Unsupported(
            "test admissions require a terminal projection".to_owned(),
        ))
    }

    fn admission_projection_capabilities(&self) -> AdmissionProjectionCapabilities {
        AdmissionProjectionCapabilities {
            operation_terminal: true,
            tool_outcome: true,
            payment_terminal: true,
            incident_terminal: true,
            ..AdmissionProjectionCapabilities::default()
        }
    }

    fn commit_admission_projection(
        &self,
        projection: &AdmissionTerminalProjection,
    ) -> Result<AdmissionTerminal, ReceiptStoreError> {
        if self
            .fail_next_terminal_projection
            .swap(false, Ordering::SeqCst)
        {
            return Err(ReceiptStoreError::Conflict(
                "injected terminal projection failure".to_owned(),
            ));
        }
        let mut state = self.state.lock().map_err(|_| {
            ReceiptStoreError::Conflict("test admission state lock poisoned".to_owned())
        })?;
        let operation = state
            .operation
            .clone()
            .ok_or_else(|| ReceiptStoreError::NotFound("test admission operation".to_owned()))?;
        let claim = state.claim.as_ref().ok_or_else(|| {
            ReceiptStoreError::Conflict("terminal projection has no recovery claim".to_owned())
        })?;
        let context = projection.context();
        if claim.operation_id() != &context.operation_id
            || claim.coordinator_lease_id() != &context.coordinator_lease_id
            || claim.coordinator_lease_epoch() != context.coordinator_lease_epoch
            || claim.store_fence() != &context.store_fence
        {
            return Err(ReceiptStoreError::Conflict(
                "terminal projection recovery claim mismatch".to_owned(),
            ));
        }
        let updated = operation
            .apply_terminal_projection(projection, &self.admission_projection_capabilities())
            .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
        let replay = updated
            .terminal_replay()
            .cloned()
            .ok_or_else(|| ReceiptStoreError::Conflict("terminal replay is absent".to_owned()))?;
        if let AdmissionTerminalProjection::Completed(completed) = projection {
            state.receipt = Some(completed.receipt.receipt().clone());
        }
        state.operation = Some(updated.clone());
        state.claim = None;
        Ok(AdmissionTerminal {
            operation_id: updated.binding().operation_id().clone(),
            state: updated.state(),
            replay,
        })
    }

    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<chio_core::receipt::body::ChioReceipt>, ReceiptStoreError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| {
                ReceiptStoreError::Conflict("test admission state lock poisoned".to_owned())
            })?
            .receipt
            .as_ref()
            .filter(|receipt| receipt.id == receipt_id)
            .cloned())
    }

    fn append_child_receipt(
        &self,
        _receipt: &chio_core::receipt::lineage::ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Unsupported(
            "test child receipt persistence".to_owned(),
        ))
    }
}

struct QualifiedDurablePaymentAdapter {
    authorization_references: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    settlement_actions: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
}

impl PaymentAdapter for QualifiedDurablePaymentAdapter {
    fn rail_id(&self) -> &'static str {
        "test-reversible"
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::ReversibleHold)
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.authorization_references
            .lock()
            .map_err(|_| PaymentError::RailError("test payment lock poisoned".to_owned()))?
            .push(request.reference.clone());
        Ok(PaymentAuthorization {
            authorization_id: "authorization-durable".to_owned(),
            state: PaymentAuthorizationState::Held,
            metadata: serde_json::json!({}),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.settlement_actions
            .lock()
            .map_err(|_| PaymentError::RailError("test payment lock poisoned".to_owned()))?
            .push("capture");
        Ok(PaymentResult {
            transaction_id: authorization_id.to_owned(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({}),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.settlement_actions
            .lock()
            .map_err(|_| PaymentError::RailError("test payment lock poisoned".to_owned()))?
            .push("release");
        Ok(PaymentResult {
            transaction_id: authorization_id.to_owned(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({}),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: transaction_id.to_owned(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({}),
        })
    }
}

impl QualifiedAdmissionProjectionStore for TestAdmissionOperationStore {
    fn reserve_threshold_approval_and_commit_admission(
        &self,
        command: &AdmissionOperationCommand,
        _reservation: &crate::ThresholdApprovalReplayReservationV1,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        self.compare_and_swap(command, trusted_now_unix_ms)
    }

    fn load_payment_journal(
        &self,
        operation_id: &str,
        active_fence: &StoreMutationFence,
    ) -> Result<
        Option<crate::payment::PaymentJournalRecord>,
        crate::receipt_store::AdmissionPaymentJournalError,
    > {
        self.require_fence(active_fence)
            .map_err(|_| crate::receipt_store::AdmissionPaymentJournalError::Fenced)?;
        Ok(self
            .state
            .lock()
            .map_err(|_| {
                crate::receipt_store::AdmissionPaymentJournalError::Invariant(
                    "test admission state lock poisoned".to_owned(),
                )
            })?
            .payment_journal
            .as_ref()
            .filter(|journal| journal.operation_id == operation_id)
            .cloned())
    }

    fn advance_payment_journal(
        &self,
        advance: crate::receipt_store::AdmissionPaymentJournalAdvance<'_>,
    ) -> Result<
        crate::payment::PaymentJournalRecord,
        crate::receipt_store::AdmissionPaymentJournalError,
    > {
        let crate::receipt_store::AdmissionPaymentJournalAdvance {
            operation,
            recovery_lease,
            expected,
            transition,
            release_evidence,
            active_fence,
            trusted_now_unix_ms: _,
        } = advance;
        self.require_fence(active_fence)
            .map_err(|_| crate::receipt_store::AdmissionPaymentJournalError::Fenced)?;
        let desired = expected.apply_transition(transition).map_err(|error| {
            crate::receipt_store::AdmissionPaymentJournalError::Invariant(error.to_string())
        })?;
        let mut state = self.state.lock().map_err(|_| {
            crate::receipt_store::AdmissionPaymentJournalError::Invariant(
                "test admission state lock poisoned".to_owned(),
            )
        })?;
        if state.operation.as_ref() != Some(operation)
            || state.claim.as_ref() != Some(recovery_lease.untrusted_claim())
        {
            return Err(crate::receipt_store::AdmissionPaymentJournalError::Fenced);
        }
        match (transition, release_evidence) {
            (
                crate::payment::PaymentJournalTransition::BeginRelease { authority },
                Some(evidence),
            ) => {
                let persisted = evidence.to_persisted();
                if persisted.operation_id.as_str() != authority.operation_id
                    || persisted.operation_version != authority.operation_version
                    || persisted.evidence_id.as_str() != authority.evidence_id
                    || persisted.bundle_digest.as_str() != authority.evidence_digest
                {
                    return Err(
                        crate::receipt_store::AdmissionPaymentJournalError::Invariant(
                            "test release evidence binding mismatch".to_owned(),
                        ),
                    );
                }
                if state
                    .payment_release_evidence
                    .as_ref()
                    .is_some_and(|stored| stored != &persisted)
                {
                    return Err(
                        crate::receipt_store::AdmissionPaymentJournalError::Conflict(
                            "test release evidence replay mismatch".to_owned(),
                        ),
                    );
                }
                state.payment_release_evidence = Some(persisted);
            }
            (crate::payment::PaymentJournalTransition::BeginRelease { .. }, None)
            | (_, Some(_)) => {
                return Err(
                    crate::receipt_store::AdmissionPaymentJournalError::Invariant(
                        "test release transition evidence mismatch".to_owned(),
                    ),
                );
            }
            (_, None) => {}
        }
        if state.payment_journal.as_ref() == Some(&desired) {
            return Ok(desired);
        }
        if state.payment_journal.as_ref() != Some(expected) {
            return Err(
                crate::receipt_store::AdmissionPaymentJournalError::Conflict(
                    "test payment journal compare-and-set conflicted".to_owned(),
                ),
            );
        }
        state.payment_journal = Some(desired.clone());
        Ok(desired)
    }

    fn begin_payment_settlement(
        &self,
        begin: crate::receipt_store::AdmissionPaymentSettlementBegin<'_>,
    ) -> Result<
        crate::receipt_store::AdmissionPaymentSettlement,
        crate::receipt_store::AdmissionPaymentJournalError,
    > {
        if self
            .fail_next_payment_settlement_intent
            .swap(false, Ordering::SeqCst)
        {
            return Err(
                crate::receipt_store::AdmissionPaymentJournalError::OutcomeUnknown(
                    "injected payment settlement intent failure".to_owned(),
                ),
            );
        }
        let journal = match begin.transition {
            Some(transition) => self.advance_payment_journal(
                crate::receipt_store::AdmissionPaymentJournalAdvance {
                    operation: begin.operation,
                    recovery_lease: begin.recovery_lease,
                    expected: begin.expected,
                    transition,
                    release_evidence: begin.release_evidence,
                    active_fence: begin.active_fence,
                    trusted_now_unix_ms: begin.trusted_now_unix_ms,
                },
            )?,
            None => {
                if begin.release_evidence.is_some() {
                    return Err(
                        crate::receipt_store::AdmissionPaymentJournalError::Invariant(
                            "test payment settlement evidence requires a transition".to_owned(),
                        ),
                    );
                }
                self.load_payment_journal(
                    begin.operation.binding().operation_id().as_str(),
                    begin.active_fence,
                )?
                .filter(|journal| journal == begin.expected)
                .ok_or_else(|| {
                    crate::receipt_store::AdmissionPaymentJournalError::Conflict(
                        "test payment settlement journal changed".to_owned(),
                    )
                })?
            }
        };
        let budget = crate::budget_store::BudgetStore::reconcile_budget_hold(
            self.budget.as_ref(),
            begin.budget_reconcile,
        )
        .map_err(|error| {
            crate::receipt_store::AdmissionPaymentJournalError::Invariant(error.to_string())
        })?;
        Ok(crate::receipt_store::AdmissionPaymentSettlement {
            journal,
            budget,
            budget_already_reconciled: false,
        })
    }

    fn authorize_budget_and_commit_admission(
        &self,
        operation: &AdmissionOperationV1,
        recovery_lease: &crate::admission_operation::AdmissionRecoveryLease,
        request: crate::budget_store::BudgetAuthorizeHoldRequest,
        payment_journal: Option<crate::payment::PaymentJournalRecord>,
        credit_exposure: Option<chio_credit::obligation::CreditExposureReservationRequest>,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<
        crate::receipt_store::AdmissionBudgetAuthorization,
        crate::receipt_store::AdmissionBudgetAuthorizationError,
    > {
        self.require_fence(active_fence)
            .map_err(|_| crate::receipt_store::AdmissionBudgetAuthorizationError::Fenced)?;
        request.validate().map_err(|error| {
            crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(error.to_string())
        })?;
        if operation.binding().participant_requirements().payment != payment_journal.is_some()
            || operation
                .binding()
                .participant_requirements()
                .credit_exposure
                != credit_exposure.is_some()
        {
            return Err(
                crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                    "test monetary participant mismatch".to_owned(),
                ),
            );
        }
        if let Some(credit_exposure) = credit_exposure.as_ref() {
            credit_exposure.validate().map_err(|error| {
                crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                    error.to_string(),
                )
            })?;
            if credit_exposure.operation_id != operation.binding().operation_id().as_str()
                || credit_exposure.request_id != operation.replay_key().request_id.as_str()
            {
                return Err(
                    crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                        "test credit exposure participant mismatch".to_owned(),
                    ),
                );
            }
        }
        if let Some(journal) = payment_journal.as_ref() {
            journal.validate().map_err(|error| {
                crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                    error.to_string(),
                )
            })?;
        }
        if self
            .fail_next_budget_authorization
            .swap(false, Ordering::SeqCst)
        {
            return Err(
                crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                    "authorization backend unavailable".to_owned(),
                ),
            );
        }
        let request_for_replay = request.clone();
        let decision =
            crate::budget_store::BudgetStore::authorize_budget_hold(self.budget.as_ref(), request)
                .map_err(|error| {
                    crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                        error.to_string(),
                    )
                })?;
        let mut state = self.state.lock().map_err(|_| {
            crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                "test admission state lock poisoned".to_owned(),
            )
        })?;
        let stored = state.operation.clone().ok_or_else(|| {
            crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                "test admission operation is absent".to_owned(),
            )
        })?;
        if &stored != operation {
            return Err(crate::receipt_store::AdmissionBudgetAuthorizationError::Fenced);
        }
        if stored.state() == AdmissionOperationState::BudgetAuthorized {
            let journal_matches = match (&state.payment_journal, &payment_journal) {
                (None, None) => true,
                (Some(stored), Some(proposed)) => stored.matches_hold_replay(proposed),
                _ => false,
            };
            if state.budget_authorization.as_ref() != Some(&request_for_replay) || !journal_matches
            {
                return Err(
                    crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                        "test combined authorization replay mismatch".to_owned(),
                    ),
                );
            }
            return Ok(crate::receipt_store::AdmissionBudgetAuthorization {
                decision,
                operation: stored,
            });
        }
        if !matches!(
            decision,
            crate::budget_store::BudgetAuthorizeHoldDecision::Authorized(_)
        ) {
            return Ok(crate::receipt_store::AdmissionBudgetAuthorization {
                decision,
                operation: stored,
            });
        }
        if state.claim.as_ref() != Some(recovery_lease.untrusted_claim()) {
            return Err(crate::receipt_store::AdmissionBudgetAuthorizationError::Fenced);
        }
        let hold_id = request_for_replay.hold_id.as_deref().ok_or_else(|| {
            crate::receipt_store::AdmissionBudgetAuthorizationError::Invariant(
                "test combined authorization omitted hold_id".to_owned(),
            )
        })?;
        let mut attachments = vec![AdmissionAttachment::BudgetHoldId(
            AdmissionIdentifier::try_new("budget_hold_id", hold_id.to_owned())?,
        )];
        if stored.binding().participant_requirements().payment {
            attachments.push(AdmissionAttachment::PaymentParticipantId(
                AdmissionIdentifier::try_new(
                    "payment_participant_id",
                    stored.binding().operation_id().as_str().to_owned(),
                )?,
            ));
        }
        let command = AdmissionOperationCommand::new(
            stored.binding().operation_id().clone(),
            stored.version(),
            recovery_lease.clone(),
            attachments,
            Some(AdmissionOperationState::BudgetAuthorized),
            None,
            None,
        )?;
        let updated = stored
            .apply_command(&command, trusted_now_unix_ms)?
            .into_operation();
        state.operation = Some(updated.clone());
        state.claim = None;
        state.budget_authorization = Some(request_for_replay);
        state.payment_journal = payment_journal;
        Ok(crate::receipt_store::AdmissionBudgetAuthorization {
            decision,
            operation: updated,
        })
    }

    fn capture_invocation_and_commit_dispatch(
        &self,
        operation: &AdmissionOperationV1,
        recovery_lease: &crate::admission_operation::AdmissionRecoveryLease,
        request: crate::budget_store::BudgetCaptureInvocationRequest,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<crate::receipt_store::AdmissionBudgetCapture, AdmissionCaptureError> {
        self.require_fence(active_fence)
            .map_err(|_| AdmissionCaptureError::Fenced)?;
        request
            .validate()
            .map_err(|error| AdmissionCaptureError::Invariant(error.to_string()))?;
        if operation.state() != AdmissionOperationState::CapturePending
            || operation.binding().capability_id().as_str() != request.capability_id
            || operation
                .budget_hold_id()
                .is_none_or(|hold_id| hold_id.as_str() != request.hold_id)
        {
            return Err(AdmissionCaptureError::Invariant(
                "test combined capture binding mismatch".to_owned(),
            ));
        }
        let decision = crate::budget_store::BudgetStore::capture_invocation_reservations(
            self.budget.as_ref(),
            request,
        )
        .map_err(|error| AdmissionCaptureError::Invariant(error.to_string()))?;
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
        let operation = self
            .compare_and_swap(&command, trusted_now_unix_ms)
            .map(AdmissionCommandResult::into_operation)
            .map_err(|error| AdmissionCaptureError::Invariant(error.to_string()))?;
        Ok(crate::receipt_store::AdmissionBudgetCapture {
            decision,
            operation,
        })
    }

    fn list_admission_receipts_after(
        &self,
        after_receipt_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<chio_core::receipt::body::ChioReceipt>, ReceiptStoreError> {
        let receipt = self
            .state
            .lock()
            .map_err(|_| {
                ReceiptStoreError::Conflict("test admission state lock poisoned".to_owned())
            })?
            .receipt
            .clone();
        Ok(receipt
            .into_iter()
            .filter(|receipt| after_receipt_id.is_none_or(|after| receipt.id.as_str() > after))
            .take(limit)
            .collect())
    }
}

impl ToolOutcomeStore for TestAdmissionOperationStore {
    fn record_tool_returned(
        &self,
        operation: &AdmissionOperationV1,
        recovery_lease: &crate::admission_operation::AdmissionRecoveryLease,
        blob: &CanonicalInvocationBlobV1,
        record: &ToolOutcomeRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<ToolOutcomeInsertResultV1, ToolOutcomeStoreError> {
        self.require_fence(active_fence)
            .map_err(|_| ToolOutcomeStoreError::Fenced)?;
        record
            .validate_for_store_insert(operation, blob, active_fence, trusted_now_unix_ms)
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        if self.fail_next_outcome_write.swap(false, Ordering::SeqCst) {
            return Err(ToolOutcomeStoreError::Unavailable(
                "injected tool outcome write failure".to_owned(),
            ));
        }
        let mut state = self.state.lock().expect("test admission state lock");
        let current = state
            .operation
            .as_ref()
            .filter(|current| *current == operation)
            .cloned()
            .ok_or(ToolOutcomeStoreError::CasConflict)?;
        if let Some(existing) = state.tool_outcome.as_ref() {
            if !existing.same_immutable_outcome(record) {
                return Err(ToolOutcomeStoreError::Conflict);
            }
            return Ok(ToolOutcomeInsertResultV1::ExactReplay {
                outcome: existing.clone(),
                operation: current,
            });
        }
        let command = crate::tool_outcome::finalizing_outcome_command(
            operation,
            recovery_lease.clone(),
            record.outcome_id().clone(),
        )
        .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        let finalizing = current
            .apply_command(&command, trusted_now_unix_ms)
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?
            .into_operation();
        let raw = RawInvocationOutcomeV1::from_canonical_bytes(blob.bytes())
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        state.raw_outcome = Some(raw);
        state.tool_outcome = Some(record.clone());
        state.operation = Some(finalizing.clone());
        Ok(ToolOutcomeInsertResultV1::Inserted {
            outcome: record.clone(),
            operation: finalizing,
        })
    }

    fn lookup_by_operation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<ToolOutcomeRecordV1>, ToolOutcomeStoreError> {
        Ok(self
            .state
            .lock()
            .expect("test admission state lock")
            .tool_outcome
            .as_ref()
            .filter(|outcome| outcome.operation_id() == operation_id)
            .cloned())
    }

    fn load_raw_invocation_by_operation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<RawInvocationOutcomeV1>, ToolOutcomeStoreError> {
        let state = self.state.lock().expect("test admission state lock");
        Ok(state
            .tool_outcome
            .as_ref()
            .filter(|outcome| outcome.operation_id() == operation_id)
            .and(state.raw_outcome.clone()))
    }

    fn lookup_post_return_evaluation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<PostReturnEvaluationRecordV1>, ToolOutcomeStoreError> {
        let state = self.state.lock().expect("test admission state lock");
        Ok(state
            .post_return_evaluation
            .as_ref()
            .filter(|evaluation| evaluation.operation_id() == operation_id)
            .cloned())
    }

    fn begin_post_return_evaluation(
        &self,
        recovery_lease: &crate::admission_operation::AdmissionRecoveryLease,
        record: &PostReturnEvaluationRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeStoreError> {
        self.require_fence(active_fence)
            .map_err(|_| ToolOutcomeStoreError::Fenced)?;
        let mut state = self.state.lock().expect("test admission state lock");
        let operation = state
            .operation
            .as_ref()
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        let outcome = state
            .tool_outcome
            .as_ref()
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        if state.claim.as_ref() != Some(recovery_lease.untrusted_claim()) {
            return Err(ToolOutcomeStoreError::Fenced);
        }
        record
            .validate_against(operation, outcome)
            .and_then(|_| record.validate_for_store_mutation(trusted_now_unix_ms))
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        if self
            .fail_next_evaluation_begin
            .swap(false, Ordering::SeqCst)
        {
            return Err(ToolOutcomeStoreError::Unavailable(
                "injected evaluation begin failure".to_owned(),
            ));
        }
        match state.post_return_evaluation.as_ref() {
            Some(existing) if existing == record => Ok(existing.clone()),
            Some(_) => Err(ToolOutcomeStoreError::Conflict),
            None => {
                state.post_return_evaluation = Some(record.clone());
                Ok(record.clone())
            }
        }
    }

    fn stage_post_return_evaluation(
        &self,
        operation_id: &AdmissionOperationId,
        expected_version: u64,
        recovery_lease: &crate::admission_operation::AdmissionRecoveryLease,
        next: &PostReturnEvaluationRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeStoreError> {
        self.require_fence(active_fence)
            .map_err(|_| ToolOutcomeStoreError::Fenced)?;
        let mut state = self.state.lock().expect("test admission state lock");
        if state.claim.as_ref() != Some(recovery_lease.untrusted_claim()) {
            return Err(ToolOutcomeStoreError::Fenced);
        }
        let current = state
            .post_return_evaluation
            .as_ref()
            .filter(|evaluation| evaluation.operation_id() == operation_id)
            .cloned()
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        if current.version() != expected_version {
            return Err(ToolOutcomeStoreError::CasConflict);
        }
        validate_evaluation_store_successor(&current, next)
            .and_then(|_| next.validate_for_store_mutation(trusted_now_unix_ms))
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        if self
            .fail_next_evaluation_stage
            .swap(false, Ordering::SeqCst)
        {
            return Err(ToolOutcomeStoreError::Unavailable(
                "injected evaluation stage failure".to_owned(),
            ));
        }
        state.post_return_evaluation = Some(next.clone());
        Ok(next.clone())
    }

    fn finalize_post_return(
        &self,
        operation_id: &AdmissionOperationId,
        expected_evaluation_version: u64,
        recovery_lease: &crate::admission_operation::AdmissionRecoveryLease,
        terminal_evaluation: &PostReturnEvaluationRecordV1,
        expected_outcome_version: u64,
        terminal_outcome: &ToolOutcomeRecordV1,
        resolved_output: Option<&CanonicalResolvedOutputBlobV1>,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(PostReturnEvaluationRecordV1, ToolOutcomeRecordV1), ToolOutcomeStoreError> {
        self.require_fence(active_fence)
            .map_err(|_| ToolOutcomeStoreError::Fenced)?;
        let mut state = self.state.lock().expect("test admission state lock");
        if state.claim.as_ref() != Some(recovery_lease.untrusted_claim()) {
            return Err(ToolOutcomeStoreError::Fenced);
        }
        let operation = state
            .operation
            .as_ref()
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        let current_outcome = state
            .tool_outcome
            .as_ref()
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        let current_evaluation = state
            .post_return_evaluation
            .as_ref()
            .filter(|evaluation| evaluation.operation_id() == operation_id)
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        if current_evaluation.version() != expected_evaluation_version
            || current_outcome.version() != expected_outcome_version
        {
            return Err(ToolOutcomeStoreError::CasConflict);
        }
        validate_terminal_store_pair(
            operation,
            current_outcome,
            current_evaluation,
            terminal_evaluation,
            terminal_outcome,
            resolved_output,
        )
        .and_then(|_| terminal_evaluation.validate_for_store_mutation(trusted_now_unix_ms))
        .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        if self
            .fail_next_evaluation_finalization
            .swap(false, Ordering::SeqCst)
        {
            return Err(ToolOutcomeStoreError::Unavailable(
                "injected evaluation finalization failure".to_owned(),
            ));
        }
        state.post_return_evaluation = Some(terminal_evaluation.clone());
        state.tool_outcome = Some(terminal_outcome.clone());
        state.resolved_output = resolved_output.cloned();
        Ok((terminal_evaluation.clone(), terminal_outcome.clone()))
    }

    fn load_resolved_output_by_operation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<CanonicalResolvedOutputBlobV1>, ToolOutcomeStoreError> {
        let state = self.state.lock().expect("test admission state lock");
        Ok(state
            .tool_outcome
            .as_ref()
            .filter(|outcome| outcome.operation_id() == operation_id)
            .and(state.resolved_output.clone()))
    }
}

impl QualifiedToolOutcomeStore for TestAdmissionOperationStore {}

#[derive(Clone, Default)]
struct AdmissionReceiptProjectionStore {
    receipt: std::sync::Arc<std::sync::Mutex<Option<ChioReceipt>>>,
    successful_appends: std::sync::Arc<AtomicU64>,
    fail_next_append: std::sync::Arc<AtomicBool>,
}

impl AdmissionReceiptProjectionStore {
    fn fail_next_append(&self) {
        self.fail_next_append.store(true, Ordering::SeqCst);
    }

    fn receipt(&self) -> Option<ChioReceipt> {
        self.receipt
            .lock()
            .expect("admission receipt projection lock")
            .clone()
    }

    fn successful_appends(&self) -> u64 {
        self.successful_appends.load(Ordering::SeqCst)
    }
}

impl ReceiptStore for AdmissionReceiptProjectionStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        if self.fail_next_append.swap(false, Ordering::SeqCst) {
            return Err(ReceiptStoreError::Conflict(
                "injected admission receipt projection failure".to_owned(),
            ));
        }
        let mut stored = self.receipt.lock().map_err(|_| {
            ReceiptStoreError::Conflict("admission receipt projection lock poisoned".to_owned())
        })?;
        if let Some(existing) = stored.as_ref() {
            let existing = chio_core::canonical::canonical_json_bytes(existing)
                .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
            let projected = chio_core::canonical::canonical_json_bytes(receipt)
                .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
            return (existing == projected).then_some(()).ok_or_else(|| {
                ReceiptStoreError::Conflict("admission receipt projection id conflicts".to_owned())
            });
        }
        *stored = Some(receipt.clone());
        self.successful_appends.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        Ok(self
            .receipt
            .lock()
            .map_err(|_| {
                ReceiptStoreError::Conflict("admission receipt projection lock poisoned".to_owned())
            })?
            .as_ref()
            .filter(|receipt| receipt.id == receipt_id)
            .cloned())
    }

    fn append_child_receipt(
        &self,
        _receipt: &chio_core::receipt::lineage::ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Unsupported(
            "test child receipt persistence".to_owned(),
        ))
    }
}

fn assert_same_receipt(left: &ChioReceipt, right: &ChioReceipt) {
    assert_eq!(
        chio_core::canonical::canonical_json_bytes(left).expect("canonical left receipt"),
        chio_core::canonical::canonical_json_bytes(right).expect("canonical right receipt")
    );
}

fn admission_test_fence() -> StoreMutationFence {
    StoreMutationFence {
        store_uuid: "test-admission-authority".to_string(),
        lease_id: "test-admission-lease".to_string(),
        owner_epoch: 1,
    }
}

struct DurableAdmissionCheckingServer {
    id: String,
    tools: Vec<String>,
    invocations: std::sync::Arc<AtomicU64>,
    store: std::sync::Arc<TestAdmissionOperationStore>,
}

#[async_trait::async_trait]
impl ToolServerConnection for DurableAdmissionCheckingServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        assert_eq!(
            self.store.operation().state(),
            AdmissionOperationState::DispatchCommitted,
            "dispatch must be durably committed before tool invocation"
        );
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({
            "tool": tool_name,
            "echo": arguments,
        }))
    }
}

struct DurableIncompleteStreamServer {
    invocations: std::sync::Arc<AtomicU64>,
    store: std::sync::Arc<TestAdmissionOperationStore>,
}

#[async_trait::async_trait]
impl ToolServerConnection for DurableIncompleteStreamServer {
    fn server_id(&self) -> &str {
        "durable-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".to_owned()]
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        assert_eq!(
            self.store.operation().state(),
            AdmissionOperationState::DispatchCommitted,
            "dispatch must be durably committed before tool invocation"
        );
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(Some(ToolServerStreamResult::Incomplete {
            stream: ToolCallStream {
                chunks: vec![ToolCallChunk {
                    data: serde_json::json!({"partial": "ledger-7"}),
                }],
            },
            reason: "transport ended after the side effect".to_owned(),
        }))
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "streaming durable server unexpectedly used value invocation".to_owned(),
        ))
    }
}

fn durable_admission_fixture(
    request_id: &str,
) -> (
    ChioKernel,
    ToolCallRequest,
    std::sync::Arc<TestAdmissionOperationStore>,
    std::sync::Arc<AtomicU64>,
) {
    durable_admission_fixture_with_grants(request_id, vec![make_grant("durable-server", "mutate")])
}

fn durable_admission_fixture_with_grants(
    request_id: &str,
    grants: Vec<ToolGrant>,
) -> (
    ChioKernel,
    ToolCallRequest,
    std::sync::Arc<TestAdmissionOperationStore>,
    std::sync::Arc<AtomicU64>,
) {
    let tools = grants
        .iter()
        .map(|grant| grant.tool_name.clone())
        .collect::<Vec<_>>();
    let mut config = make_config();
    config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    let mut kernel = make_kernel(config);
    let fence = admission_test_fence();
    let store = std::sync::Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel
        .set_durable_admission_store(store.clone(), store.clone(), fence)
        .expect("qualified admission store");
    kernel.set_budget_store_handle(store.budget_store());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_string(),
        tools,
        invocations: invocations.clone(),
        store: store.clone(),
    }));
    let agent = make_keypair();
    let capability = make_capability(&kernel, &agent, make_scope(grants), 300);
    let request = make_request_with_arguments(
        request_id,
        &capability,
        "mutate",
        "durable-server",
        serde_json::json!({"record": "ledger-7", "value": "settled"}),
    );
    (kernel, request, store, invocations)
}

#[test]
fn cumulative_approval_membership_does_not_change_operation_identity() {
    let (kernel, mut request, _store, _invocations) =
        durable_admission_fixture("cumulative-stable-operation");
    let mut body = request.capability.body();
    body.scope.grants[0]
        .constraints
        .push(Constraint::RequireCumulativeApprovalAbove {
            threshold: MonetaryAmount {
                units: 100,
                currency: "USD".to_owned(),
            },
            approval_budget_id: "budget-identity".to_owned(),
            approval_budget_epoch: 1,
            cumulative_approval_root_binding: None,
        });
    request.capability = CapabilityToken::sign(body, &kernel.config.keypair)
        .expect("cumulative capability must sign");
    let first = {
        let matching = [MatchingGrant {
            index: 0,
            grant: &request.capability.scope.grants[0],
            specificity: (0, 0, 0),
        }];
        kernel
            .begin_durable_tool_admission(&request, &matching, current_unix_timestamp_ms())
            .expect("prepare cumulative operation")
            .expect("cumulative admission must be durable")
    };

    let approver = CoreKeypair::generate();
    let subject = CoreKeypair::generate();
    request.approval_tokens.push(hitl_sign_token(
        &approver,
        &subject,
        "cumulative-stable-operation",
        &sha256_hex(b"cumulative-stable-intent"),
        GovernedApprovalDecision::Approved,
        current_unix_timestamp(),
    ));
    let resumed = {
        let matching = [MatchingGrant {
            index: 0,
            grant: &request.capability.scope.grants[0],
            specificity: (0, 0, 0),
        }];
        kernel
            .begin_durable_tool_admission(&request, &matching, current_unix_timestamp_ms())
            .expect("resume cumulative operation")
            .expect("cumulative admission must remain durable")
    };

    assert_eq!(first.operation_id(), resumed.operation_id());
}

#[test]
fn cumulative_approval_resumes_the_same_hold_and_dispatches_once() {
    let (mut kernel, mut request, store, invocations) =
        durable_admission_fixture("cumulative-approval-dispatch");
    let approver_a = CoreKeypair::generate();
    let approver_b = CoreKeypair::generate();
    let requirement = ThresholdApprovalRequirement::new(
        kernel.config.policy_hash.clone(),
        2,
        vec![
            ThresholdApproverIdentity {
                identifier: "approver-a".to_owned(),
                public_key: approver_a.public_key(),
            },
            ThresholdApproverIdentity {
                identifier: "approver-b".to_owned(),
                public_key: approver_b.public_key(),
            },
        ],
        "cumulative-approval-directory-v1".to_owned(),
        300,
    )
    .expect("threshold requirement");
    kernel.set_threshold_approval_requirement_resolver(StdArc::new(FixedThresholdRequirement(
        requirement,
    )));
    let mut body = request.capability.body();
    body.scope.grants[0]
        .constraints
        .push(Constraint::RequireCumulativeApprovalAbove {
            threshold: MonetaryAmount {
                units: 100,
                currency: "USD".to_owned(),
            },
            approval_budget_id: "budget-dispatch".to_owned(),
            approval_budget_epoch: 7,
            cumulative_approval_root_binding: None,
        });
    request.capability = CapabilityToken::sign(body, &kernel.config.keypair)
        .expect("cumulative capability must sign");
    let intent = GovernedTransactionIntent {
        id: "cumulative-approval-intent".to_owned(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "authorize a bounded ledger mutation".to_owned(),
        max_amount: Some(MonetaryAmount {
            units: 100,
            currency: "USD".to_owned(),
        }),
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    };
    let intent_hash = intent.binding_hash().expect("intent hash");
    request.governed_intent = Some(intent);

    let pending = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("pending approval response");
    assert_eq!(
        pending.verdict,
        Verdict::PendingApproval,
        "{:?}",
        pending.reason
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let proposal: ThresholdApprovalProposal = match pending.output {
        Some(ToolCallOutput::Value(value)) => {
            serde_json::from_value(value).expect("stored threshold proposal")
        }
        _ => panic!("pending response must return the stored proposal"),
    };
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::ApprovalRequired
    );
    let operation_id = store
        .operation()
        .binding()
        .operation_id()
        .as_str()
        .to_owned();
    let proposal_hash = proposal.artifact_digest().expect("proposal digest");
    let sign_token = |id: &str, approver: &CoreKeypair| {
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: id.to_owned(),
                approver: approver.public_key(),
                subject: request.capability.subject.clone(),
                governed_intent_hash: intent_hash.clone(),
                request_id: request.request_id.clone(),
                threshold_proposal_hash: Some(proposal_hash.clone()),
                issued_at: proposal.body.proposal_created_at,
                expires_at: proposal.body.proposal_deadline,
                decision: GovernedApprovalDecision::Approved,
            },
            approver,
        )
        .expect("approval token")
    };
    let approval_tokens = vec![
        sign_token("cumulative-token-b", &approver_b),
        sign_token("cumulative-token-a", &approver_a),
    ];
    let mut approved = request.clone();
    approved.threshold_approval_proposal = Some(proposal);
    approved.approval_tokens = approval_tokens;

    let response = kernel
        .evaluate_tool_call_blocking(&approved)
        .expect("approved cumulative dispatch");
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.operation().binding().operation_id().as_str(),
        operation_id
    );
    let usage = crate::budget_store::BudgetStore::get_cumulative_approval_operation_usage(
        store.budget_store().as_ref(),
        &operation_id,
    )
    .expect("cumulative operation lookup")
    .expect("captured cumulative operation");
    assert_eq!(
        usage.state,
        crate::budget_store::BudgetCumulativeApprovalState::Captured
    );

    let replay = kernel
        .evaluate_tool_call_blocking(&approved)
        .expect("completed cumulative replay");
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn cumulative_approval_below_threshold_dispatches_without_a_proposal() {
    let (kernel, mut request, store, invocations) =
        durable_admission_fixture("cumulative-below-threshold");
    let mut body = request.capability.body();
    body.scope.grants[0]
        .constraints
        .push(Constraint::RequireCumulativeApprovalAbove {
            threshold: MonetaryAmount {
                units: 100,
                currency: "USD".to_owned(),
            },
            approval_budget_id: "budget-below-threshold".to_owned(),
            approval_budget_epoch: 1,
            cumulative_approval_root_binding: None,
        });
    request.capability = CapabilityToken::sign(body, &kernel.config.keypair)
        .expect("cumulative capability must sign");
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "cumulative-below-threshold-intent".to_owned(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "authorize a bounded ledger mutation".to_owned(),
        max_amount: Some(MonetaryAmount {
            units: 60,
            currency: "USD".to_owned(),
        }),
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    });

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("below-threshold cumulative dispatch");
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert!(store.operation().threshold_proposal().is_none());
}

#[test]
fn cumulative_approval_guard_denial_creates_no_budget_state() {
    struct DenyAll;

    impl Guard for DenyAll {
        fn name(&self) -> &str {
            "cumulative-deny-all"
        }

        fn evaluate(&self, _context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
            Ok(GuardDecision::deny(Vec::new()))
        }
    }

    let (mut kernel, mut request, store, invocations) =
        durable_admission_fixture("cumulative-guard-denial");
    let mut body = request.capability.body();
    body.scope.grants[0]
        .constraints
        .push(Constraint::RequireCumulativeApprovalAbove {
            threshold: MonetaryAmount {
                units: 100,
                currency: "USD".to_owned(),
            },
            approval_budget_id: "budget-guard-denial".to_owned(),
            approval_budget_epoch: 1,
            cumulative_approval_root_binding: None,
        });
    request.capability = CapabilityToken::sign(body, &kernel.config.keypair)
        .expect("cumulative capability must sign");
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "cumulative-guard-denial-intent".to_owned(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "authorize a bounded ledger mutation".to_owned(),
        max_amount: Some(MonetaryAmount {
            units: 60,
            currency: "USD".to_owned(),
        }),
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    });
    kernel.add_guard(Box::new(DenyAll));

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("guard denial must produce a signed response");
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let operation = store.operation();
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(
        crate::budget_store::BudgetStore::get_cumulative_approval_operation_usage(
            store.budget_store().as_ref(),
            operation.binding().operation_id().as_str(),
        )
        .expect("cumulative operation lookup")
        .is_none()
    );
}

#[test]
fn nested_cumulative_approval_resumes_and_dispatches_once() {
    let (mut kernel, mut request, _store, invocations) =
        durable_admission_fixture("nested-cumulative-approval");
    let approver = CoreKeypair::generate();
    let requirement = ThresholdApprovalRequirement::new(
        kernel.config.policy_hash.clone(),
        1,
        vec![ThresholdApproverIdentity {
            identifier: "nested-approver".to_owned(),
            public_key: approver.public_key(),
        }],
        "nested-cumulative-directory-v1".to_owned(),
        300,
    )
    .expect("threshold requirement");
    kernel.set_threshold_approval_requirement_resolver(StdArc::new(FixedThresholdRequirement(
        requirement,
    )));
    let mut body = request.capability.body();
    body.scope.grants[0]
        .constraints
        .push(Constraint::RequireCumulativeApprovalAbove {
            threshold: MonetaryAmount {
                units: 25,
                currency: "USD".to_owned(),
            },
            approval_budget_id: "nested-cumulative-budget".to_owned(),
            approval_budget_epoch: 1,
            cumulative_approval_root_binding: None,
        });
    request.capability = CapabilityToken::sign(body, &kernel.config.keypair)
        .expect("cumulative capability must sign");
    let intent = GovernedTransactionIntent {
        id: "nested-cumulative-intent".to_owned(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "authorize nested ledger mutation".to_owned(),
        max_amount: Some(MonetaryAmount {
            units: 25,
            currency: "USD".to_owned(),
        }),
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    };
    let intent_hash = intent.binding_hash().expect("intent hash");
    request.governed_intent = Some(intent);
    let session_id = kernel
        .open_session("nested-cumulative-parent".to_owned(), Vec::new())
        .expect("parent session");
    kernel
        .activate_session(&session_id)
        .expect("activate parent session");
    let parent_context = make_operation_context(
        &session_id,
        "nested-cumulative-parent-request",
        "nested-cumulative-parent",
    );
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .expect("begin parent request");
    let mut client = NoopNestedFlowClient;

    let pending = kernel
        .evaluate_tool_call_with_nested_flow_client(&parent_context, &request, &mut client, None)
        .expect("nested pending response");
    assert_eq!(
        pending.verdict,
        Verdict::PendingApproval,
        "{:?}",
        pending.reason
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let proposal: ThresholdApprovalProposal = match pending.output {
        Some(ToolCallOutput::Value(value)) => {
            serde_json::from_value(value).expect("stored nested proposal")
        }
        _ => panic!("nested pending response must return its proposal"),
    };
    let proposal_hash = proposal.artifact_digest().expect("proposal digest");
    let token = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "nested-cumulative-token".to_owned(),
            approver: approver.public_key(),
            subject: request.capability.subject.clone(),
            governed_intent_hash: intent_hash,
            request_id: request.request_id.clone(),
            threshold_proposal_hash: Some(proposal_hash),
            issued_at: proposal.body.proposal_created_at,
            expires_at: proposal.body.proposal_deadline,
            decision: GovernedApprovalDecision::Approved,
        },
        &approver,
    )
    .expect("nested approval token");
    request.threshold_approval_proposal = Some(proposal);
    request.approval_tokens = vec![token];

    let response = kernel
        .evaluate_tool_call_with_nested_flow_client(&parent_context, &request, &mut client, None)
        .expect("nested approved response");
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn aggregate_invocation_budget_exhausts_across_grants_atomically() {
    use chio_core::capability::aggregate_invocation::{
        AggregateInvocationBudget, AggregateInvocationScope,
    };

    let mut first_grant = make_grant("durable-server", "mutate");
    first_grant.max_invocations = Some(1);
    let mut second_grant = make_grant("durable-server", "mutate-alt");
    second_grant.max_invocations = Some(1);
    let (kernel, mut first, store, invocations) =
        durable_admission_fixture_with_grants("aggregate-first", vec![first_grant, second_grant]);
    let mut body = first.capability.body();
    body.aggregate_invocation_budget = Some(AggregateInvocationBudget {
        scope: AggregateInvocationScope::Capability,
        max_invocations: 1,
        root_binding: None,
    });
    first.capability = CapabilityToken::sign(body, &kernel.config.keypair)
        .expect("aggregate capability must sign");

    let first_response = kernel
        .evaluate_tool_call_blocking(&first)
        .expect("first aggregate invocation");
    assert_eq!(
        first_response.verdict,
        Verdict::Allow,
        "{:?}",
        first_response.reason
    );

    let mut second = first.clone();
    second.request_id = "aggregate-second".to_string();
    second.tool_name = "mutate-alt".to_string();
    let second_response = kernel
        .evaluate_tool_call_blocking(&second)
        .expect("aggregate exhaustion must produce a signed denial");
    assert_eq!(second_response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let second_grant_usage = store
        .budget_store()
        .get_invocation_quota_usage(&crate::budget_store::BudgetQuotaKey::grant(
            first.capability.id.clone(),
            1,
        ))
        .expect("second grant quota lookup");
    assert!(second_grant_usage.is_none());
}

#[test]
fn durable_admission_passes_opaque_supplemental_bytes_to_installed_verifier() {
    struct BoundVerifier;

    impl crate::supplemental_quota::SupplementalQuotaVerifier for BoundVerifier {
        fn verify(
            &self,
            signed_extension: &[u8],
            context: &crate::supplemental_quota::SupplementalQuotaVerificationContext,
        ) -> Result<
            crate::supplemental_quota::VerifiedSupplementalQuotaClaim,
            crate::supplemental_quota::SupplementalQuotaVerifierError,
        > {
            let request_binding_hash =
                crate::supplemental_quota::supplemental_request_binding_hash(context).map_err(
                    |error| {
                        crate::supplemental_quota::SupplementalQuotaVerifierError::new(
                            error.to_string(),
                        )
                    },
                )?;
            Ok(crate::supplemental_quota::VerifiedSupplementalQuotaClaim {
                profile: crate::supplemental_quota::BROKER_CAPABILITY_EXECUTION_PROFILE.to_string(),
                broker_capability_id: "broker-capability-7".to_string(),
                issuer: context.subject.clone(),
                request_constraint_digest: "a".repeat(64),
                max_invocations: 7,
                authorization_artifact_digest:
                    crate::supplemental_quota::supplemental_authorization_artifact_digest(
                        signed_extension,
                    ),
                supplemental_revocation_ids: vec!["broker-capability-7".to_string()],
                expires_at: current_unix_timestamp() + 300,
                request_binding_hash,
                capability_id: context.capability_id.clone(),
                capability_digest: context.capability_digest.clone(),
                request_namespace_digest: context.request_namespace_digest.clone(),
                operation_id: context.operation_id.clone(),
                subject: context.subject.clone(),
                request_id: context.request_id.clone(),
                normalized_destination: context.normalized_destination.clone(),
                arguments_hash: context.arguments_hash.clone(),
                negotiated_features: context.negotiated_features.clone(),
            })
        }
    }

    let (mut kernel, mut request, _store, _invocations) =
        durable_admission_fixture("durable-supplemental-verifier");
    kernel
        .set_supplemental_quota_verifier(
            std::sync::Arc::new(BoundVerifier),
            crate::supplemental_quota::SupplementalQuotaVerifierBinding {
                verifier_identity: "test/bound-verifier.v1".to_string(),
                configuration_digest: "b".repeat(64),
            },
        )
        .expect("valid verifier binding");
    request.supplemental_authorization = Some(
        chio_core::capability::supplemental_authorization::OpaqueSupplementalAuthorization {
            signed_extension: "opaque-signed-extension".to_string(),
        },
    );
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )
    .expect("matching grants");

    let admission = kernel
        .begin_durable_tool_admission(&request, &matching, current_unix_timestamp_ms())
        .expect("verified durable admission")
        .expect("covered durable admission");

    let verified = admission
        .supplemental_quota()
        .expect("verified supplemental quota");
    assert_eq!(verified.max_invocations(), 7);
    assert_eq!(verified.broker_capability_id(), "broker-capability-7");
    assert_eq!(
        admission
            .operation()
            .supplemental_authorization_digest()
            .map(crate::admission_operation::AdmissionDigest::as_str),
        Some(verified.authorization_artifact_digest())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_durable_guard_evaluation_terminalizes_before_dispatch() {
    struct ParkingGuard {
        started: std::sync::Arc<tokio::sync::Notify>,
    }

    impl Guard for ParkingGuard {
        fn name(&self) -> &str {
            "durable-parking-guard"
        }

        fn evaluate(&self, _context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
            self.started.notify_one();
            std::thread::sleep(std::time::Duration::from_secs(2));
            Ok(GuardDecision::allow())
        }
    }

    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-dropped-guard-evaluation");
    kernel.config.deadlines.always_offload_guards = true;
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    kernel.add_guard(Box::new(ParkingGuard {
        started: started.clone(),
    }));
    let kernel = std::sync::Arc::new(kernel);
    let evaluation = {
        let kernel = kernel.clone();
        tokio::spawn(async move { kernel.evaluate_tool_call(&request).await })
    };

    tokio::time::timeout(std::time::Duration::from_secs(5), started.notified())
        .await
        .expect("guard evaluation started");
    evaluation.abort();
    assert!(evaluation.await.is_err());

    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn startup_recovery_terminalizes_admission_before_budget_authorization() {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("durable-startup-before-budget");
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )
    .expect("matching grants");
    let admission = kernel
        .begin_durable_tool_admission(&request, &matching, current_unix_timestamp_ms())
        .expect("begin durable admission")
        .expect("covered durable admission");
    assert_eq!(
        admission.state(),
        AdmissionOperationState::BrokerAttemptRegistered
    );

    assert_eq!(
        kernel
            .reconcile_recoverable_admissions()
            .expect("recover pre-budget admission"),
        1
    );
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn durable_pre_dispatch_denial_commits_terminal_compensation() {
    struct DenyAll;

    impl Guard for DenyAll {
        fn name(&self) -> &str {
            "durable-deny-all"
        }

        fn evaluate(&self, _context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
            Ok(GuardDecision::deny(Vec::new()))
        }
    }

    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-pre-dispatch-denial");
    kernel.add_guard(Box::new(DenyAll));

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("terminal pre-dispatch denial");
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("terminal compensation replay");
    assert_eq!(replay.verdict, Verdict::Deny);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

struct VersionlessPostInvocationHook;

impl crate::post_invocation::PostInvocationHook for VersionlessPostInvocationHook {
    fn name(&self) -> &str {
        "versionless-post-hook"
    }

    fn inspect(
        &self,
        _context: &crate::post_invocation::PostInvocationContext<'_>,
        _response: &serde_json::Value,
    ) -> crate::post_invocation::PostInvocationVerdict {
        crate::post_invocation::PostInvocationVerdict::Allow
    }
}

struct StableRedactingPostInvocationHook {
    replacement: &'static str,
}

impl crate::post_invocation::PostInvocationHook for StableRedactingPostInvocationHook {
    fn name(&self) -> &str {
        "stable-redacting-post-hook"
    }

    fn inspect(
        &self,
        _context: &crate::post_invocation::PostInvocationContext<'_>,
        _response: &serde_json::Value,
    ) -> crate::post_invocation::PostInvocationVerdict {
        crate::post_invocation::PostInvocationVerdict::Redact(serde_json::json!({
            "kind": "value",
            "value": {"replacement": self.replacement}
        }))
    }

    fn durable_identity(
        &self,
    ) -> Result<Option<crate::post_invocation::PostInvocationHookIdentity>, String> {
        crate::post_invocation::PostInvocationHookIdentity::from_canonical_config(
            "stable-redacting-post-hook",
            "1",
            "chio-kernel.tests.stable-redacting-post-hook.v1",
            &self.replacement,
        )
        .map(Some)
    }
}

struct StableStreamRedactingPostInvocationHook;

impl crate::post_invocation::PostInvocationHook for StableStreamRedactingPostInvocationHook {
    fn name(&self) -> &str {
        "stable-stream-redacting-post-hook"
    }

    fn inspect(
        &self,
        _context: &crate::post_invocation::PostInvocationContext<'_>,
        _response: &serde_json::Value,
    ) -> crate::post_invocation::PostInvocationVerdict {
        crate::post_invocation::PostInvocationVerdict::Redact(serde_json::json!({
            "kind": "stream",
            "stream": {
                "complete": true,
                "chunks": [{"part": 1}, {"part": 2}]
            }
        }))
    }

    fn durable_identity(
        &self,
    ) -> Result<Option<crate::post_invocation::PostInvocationHookIdentity>, String> {
        crate::post_invocation::PostInvocationHookIdentity::from_canonical_config(
            "stable-stream-redacting-post-hook",
            "1",
            "chio-kernel.tests.stable-stream-redacting-post-hook.v1",
            &(),
        )
        .map(Some)
    }
}

#[test]
fn top_level_durable_admission_commits_before_dispatch_and_blocks_replay() {
    let (kernel, request, store, invocations) = durable_admission_fixture("durable-top-level");

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("first durable dispatch");
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("exact replay delivery");
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(replay.output, response.output);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let mut conflict = request.clone();
    conflict.arguments = serde_json::json!({"record": "ledger-7", "value": "reopened"});
    let conflict = kernel
        .evaluate_tool_call_blocking(&conflict)
        .expect("conflicting replay denial");
    assert_eq!(conflict.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_completion_projects_the_canonical_receipt_idempotently() {
    let (mut kernel, request, _store, invocations) =
        durable_admission_fixture("durable-receipt-projection");
    let projection = AdmissionReceiptProjectionStore::default();
    kernel
        .set_receipt_store(Box::new(projection.clone()))
        .expect("receipt projection store");

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("durable receipt projection");
    assert_same_receipt(
        projection.receipt().as_ref().expect("projected receipt"),
        &response.receipt,
    );
    assert_eq!(projection.successful_appends(), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("idempotent durable receipt projection replay");
    assert_same_receipt(&replay.receipt, &response.receipt);
    assert_eq!(projection.successful_appends(), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn completed_replay_heals_a_failed_receipt_projection_without_redispatch() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-receipt-projection-recovery");
    let projection = AdmissionReceiptProjectionStore::default();
    projection.fail_next_append();
    kernel
        .set_receipt_store(Box::new(projection.clone()))
        .expect("receipt projection store");

    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("receipt projection failure must fail closed");
    assert!(error
        .to_string()
        .contains("injected admission receipt projection failure"));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert!(projection.receipt().is_none());
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("completed replay must heal receipt projection");
    assert_same_receipt(
        projection.receipt().as_ref().expect("healed receipt"),
        &replay.receipt,
    );
    assert_eq!(projection.successful_appends(), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn completed_federated_replay_remains_closed_until_cosign_succeeds(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut kernel, mut request, store, invocations) =
        durable_admission_fixture("durable-federation-cosign-retry");
    kernel.set_receipt_store(Box::new(AdmissionReceiptProjectionStore::default()))?;

    let origin_keypair = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let local_kernel_id = "kernel.org-b";
    kernel.set_federation_local_kernel_id(local_kernel_id);
    let trust = KernelTrustExchange::new(local_kernel_id, kernel.config.keypair.clone())
        .with_trusted_peer(origin_kernel_id, origin_keypair.public_key());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let peer = handshake_and_pin(&trust, origin_kernel_id, &origin_keypair, now);
    let mut kernel = kernel.with_federation_peers(vec![peer]);
    kernel.set_runtime_admission_hook(std::sync::Arc::new(TreatyDsseAdmissionHook));
    let cosigner_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_federation_cosigner(std::sync::Arc::new(CountingRejectingCosigner {
        calls: std::sync::Arc::clone(&cosigner_calls),
    }));
    request.federated_origin_kernel_id = Some(origin_kernel_id.to_owned());

    assert!(matches!(
        kernel.evaluate_tool_call_blocking(&request),
        Err(KernelError::Internal(reason)) if reason.contains("bilateral co-sign failed")
    ));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(cosigner_calls.load(Ordering::SeqCst), 1);

    assert!(matches!(
        kernel.evaluate_tool_call_blocking(&request),
        Err(KernelError::Internal(reason)) if reason.contains("bilateral co-sign failed")
    ));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(cosigner_calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[test]
fn admission_receipt_reconciliation_heals_a_crash_gap_before_serving() {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("durable-receipt-startup-recovery");
    let completed = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("canonical admission completion");

    let mut recovered_config = make_config();
    recovered_config.keypair = kernel.config.keypair.clone();
    recovered_config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    let mut recovered_kernel = make_kernel(recovered_config);
    let projection = AdmissionReceiptProjectionStore::default();
    recovered_kernel
        .set_receipt_store(Box::new(projection.clone()))
        .expect("receipt projection store");
    recovered_kernel
        .set_durable_admission_store(store.clone(), store.clone(), admission_test_fence())
        .expect("qualified admission store");

    assert_eq!(
        recovered_kernel
            .reconcile_durable_admission_receipt_projections()
            .expect("startup receipt reconciliation"),
        1
    );
    assert_same_receipt(
        projection.receipt().as_ref().expect("reconciled receipt"),
        &completed.receipt,
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn failed_tool_return_persistence_retains_dispatch_and_blocks_redispatch() {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("durable-return-write-failure");
    store.fail_next_outcome_write();

    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("tool return journal failure must fail closed");
    assert!(matches!(
        error,
        KernelError::DurableAdmission(ref reason)
            if reason.contains("injected tool outcome write failure")
    ));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    let failure_receipt = receipt_log.get(0).expect("tool return failure receipt");
    assert!(failure_receipt.is_denied());
    assert!(failure_receipt.verify_signature().expect("signed receipt"));

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("retained dispatch must produce a denial");
    assert_eq!(replay.verdict, Verdict::Deny);
    assert!(replay
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("DispatchCommitted")));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn failed_terminal_projection_retains_finalizing_operation_and_blocks_redispatch() {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("durable-terminal-projection-failure");
    store.fail_next_terminal_projection();

    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("terminal projection failure must fail closed");
    assert!(matches!(
        error,
        KernelError::DurableAdmission(ref reason)
            if reason.contains("injected terminal projection failure")
    ));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("retained finalization must recover delivery");
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

fn assert_finalization_crash_recovers(
    request_id: &str,
    inject: fn(&TestAdmissionOperationStore),
    expected_error: &str,
    expected_versions: (Option<u64>, Option<u64>),
) {
    let (kernel, request, store, invocations) = durable_admission_fixture(request_id);
    inject(&store);

    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("injected finalization crash must fail closed");
    assert!(matches!(
        error,
        KernelError::DurableAdmission(ref reason) if reason.contains(expected_error)
    ));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(store.outcome_versions(), expected_versions);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let recovered = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("finalization replay must recover delivery");
    assert_eq!(recovered.verdict, Verdict::Allow);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("completed replay must redeliver the recovered result");
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(replay.receipt.id, recovered.receipt.id);
    assert_eq!(replay.output, recovered.output);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn finalization_recovers_before_evaluation_creation() {
    assert_finalization_crash_recovers(
        "durable-evaluation-begin-failure",
        TestAdmissionOperationStore::fail_next_evaluation_begin,
        "injected evaluation begin failure",
        (None, Some(1)),
    );
}

#[test]
fn finalization_recovers_after_frozen_evaluation_creation() {
    assert_finalization_crash_recovers(
        "durable-evaluation-stage-failure",
        TestAdmissionOperationStore::fail_next_evaluation_stage,
        "injected evaluation stage failure",
        (Some(1), Some(1)),
    );
}

#[test]
fn finalization_recovers_after_pure_result_staging() {
    assert_finalization_crash_recovers(
        "durable-evaluation-finalization-failure",
        TestAdmissionOperationStore::fail_next_evaluation_finalization,
        "injected evaluation finalization failure",
        (Some(2), Some(1)),
    );
}

#[test]
fn finalization_recovers_after_store_owner_rotation() {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("durable-owner-rotation-recovery");
    store.fail_next_evaluation_begin();

    kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("injected finalization crash must fail closed");
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let rotated_fence = StoreMutationFence {
        store_uuid: admission_test_fence().store_uuid,
        lease_id: "test-admission-lease-2".to_owned(),
        owner_epoch: 2,
    };
    store.rotate_fence(rotated_fence.clone());
    let mut recovered_config = make_config();
    recovered_config.keypair = kernel.config.keypair.clone();
    recovered_config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    let mut recovered_kernel = make_kernel(recovered_config);
    recovered_kernel
        .set_durable_admission_store(store.clone(), store.clone(), rotated_fence)
        .expect("rotated qualified admission store");
    recovered_kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_owned(),
        tools: vec!["mutate".to_owned()],
        invocations: invocations.clone(),
        store: store.clone(),
    }));

    let recovered = recovered_kernel
        .evaluate_tool_call_blocking(&request)
        .expect("new serving owner must finish retained finalization");
    assert_eq!(recovered.verdict, Verdict::Allow);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_post_invocation_identity_binds_transformed_output_and_replay() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-versioned-post-hook");
    kernel.add_post_invocation_hook(Box::new(StableRedactingPostInvocationHook {
        replacement: "filtered",
    }));

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("versioned post hook dispatch");
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        response.output,
        Some(ToolCallOutput::Value(
            serde_json::json!({"replacement": "filtered"})
        ))
    );
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(store.outcome_versions(), (Some(4), Some(2)));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("versioned post hook replay");
    assert_eq!(replay.output, response.output);
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_redaction_cannot_upgrade_incomplete_transport_and_replay_is_exactly_once() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-incomplete-redacted-stream");
    kernel.register_tool_server(Box::new(DurableIncompleteStreamServer {
        invocations: invocations.clone(),
        store: store.clone(),
    }));
    kernel.add_post_invocation_hook(Box::new(StableRedactingPostInvocationHook {
        replacement: "filtered-partial",
    }));

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("durable incomplete stream finalization");
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.output,
        Some(ToolCallOutput::Value(
            serde_json::json!({"replacement": "filtered-partial"})
        ))
    );
    assert_eq!(
        response.reason.as_deref(),
        Some("transport ended after the side effect")
    );
    assert_eq!(
        response.receipt.decision,
        Some(chio_core::receipt::decision::Decision::Incomplete {
            reason: "transport ended after the side effect".to_owned(),
        })
    );
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("durable incomplete stream replay");
    assert_eq!(replay.output, response.output);
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(replay.terminal_state, response.terminal_state);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_redaction_recovery_uses_the_recorded_stream_limits() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-redaction-stream-limit-snapshot");
    kernel.config.memory_budget.max_stream_chunks = 1;
    kernel.add_post_invocation_hook(Box::new(StableStreamRedactingPostInvocationHook));
    store.fail_next_evaluation_begin();

    kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("injected finalization crash");
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let mut recovered_config = make_config();
    recovered_config.keypair = kernel.config.keypair.clone();
    recovered_config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    recovered_config.memory_budget.max_stream_chunks = 2;
    let mut recovered_kernel = make_kernel(recovered_config);
    recovered_kernel
        .set_durable_admission_store(store.clone(), store.clone(), admission_test_fence())
        .expect("qualified admission store");
    recovered_kernel.add_post_invocation_hook(Box::new(StableStreamRedactingPostInvocationHook));
    recovered_kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_owned(),
        tools: vec!["mutate".to_owned()],
        invocations: invocations.clone(),
        store: store.clone(),
    }));

    let recovered = recovered_kernel
        .evaluate_tool_call_blocking(&request)
        .expect("recover redacted stream with recorded limits");
    assert_eq!(recovered.verdict, Verdict::Deny);
    assert!(recovered
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("max chunk count of 1")));
    let Some(ToolCallOutput::Stream(stream)) = recovered.output else {
        panic!("expected retained redacted stream");
    };
    assert_eq!(stream.chunk_count(), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_post_invocation_identity_change_cannot_replace_recovered_finalization() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-post-hook-identity-change");
    kernel.add_post_invocation_hook(Box::new(StableRedactingPostInvocationHook {
        replacement: "first",
    }));
    store.fail_next_evaluation_begin();
    kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("injected finalization crash");
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    // Recovery runs under a rotated store lease, exactly as a restarted process
    // takes over: the crashed operation's recovery lease belongs to the prior
    // owner, so the sweep sees it as recoverable rather than actively leased.
    let rotated_fence = StoreMutationFence {
        store_uuid: admission_test_fence().store_uuid,
        lease_id: "test-admission-lease-2".to_owned(),
        owner_epoch: 2,
    };
    store.rotate_fence(rotated_fence.clone());
    let mut recovered_config = make_config();
    recovered_config.keypair = kernel.config.keypair.clone();
    recovered_config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    let mut recovered_kernel = make_kernel(recovered_config);
    recovered_kernel
        .set_durable_admission_store(store.clone(), store.clone(), rotated_fence)
        .expect("qualified admission store");
    recovered_kernel.add_post_invocation_hook(Box::new(StableRedactingPostInvocationHook {
        replacement: "second",
    }));
    recovered_kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_owned(),
        tools: vec!["mutate".to_owned()],
        invocations: invocations.clone(),
        store: store.clone(),
    }));

    let error = recovered_kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("identity substitution must fail closed");
    assert!(error
        .to_string()
        .contains("recovered post-return plan does not match durable admission"));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}
