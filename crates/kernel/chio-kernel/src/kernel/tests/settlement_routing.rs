mod settlement_routing_tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Mutex, MutexGuard};
    use std::thread;
    use std::time::Duration;

    use chio_core::crypto::Keypair;
    use chio_core::receipt::{
        body::{ChioReceipt, ChioReceiptBody},
        decision::{Decision, ToolCallAction},
        kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
        lineage::ChildRequestReceipt,
    };
    use chio_settle::{
        RetryPolicy, SettlementAttemptClaim, SettlementFailureCode, SettlementFailureReason,
        SettlementHook, SettlementHookError, SettlementObservation, SettlementOutcome,
        SettlementOutcomeStore, SettlementRoute, SettlementRouteError, SettlementRoutingInput,
        SettlementSkipReason, SettlementStoreBinding,
    };

    use super::*;

    const STORE_BINDING: SettlementStoreBinding = SettlementStoreBinding::from_digest([17; 32]);

    #[derive(Clone, Copy)]
    enum ClaimMode {
        Claim,
        None,
        Error,
    }

    #[derive(Clone, Copy)]
    enum RouteMode {
        Contract,
        Error,
    }

    struct RoutingStoreState {
        receipts: HashMap<String, ChioReceipt>,
        attempts: HashMap<String, PendingSettlementObservation>,
        inputs: Vec<SettlementRoutingInput>,
        legacy_appends: usize,
        atomic_appends: usize,
        legacy_atomic_appends: usize,
        timed_atomic_appends: usize,
        timed_atomic_budget_ms: Option<u64>,
        claim_calls: usize,
        route_calls: usize,
        seed_fails: bool,
        claim_mode: ClaimMode,
        route_mode: RouteMode,
        receipt_queryable_at_claim: bool,
        receipt_queryable_at_hook: bool,
    }

    impl RoutingStoreState {
        fn new(claim_mode: ClaimMode, route_mode: RouteMode) -> Self {
            Self {
                receipts: HashMap::new(),
                attempts: HashMap::new(),
                inputs: Vec::new(),
                legacy_appends: 0,
                atomic_appends: 0,
                legacy_atomic_appends: 0,
                timed_atomic_appends: 0,
                timed_atomic_budget_ms: None,
                claim_calls: 0,
                route_calls: 0,
                seed_fails: false,
                claim_mode,
                route_mode,
                receipt_queryable_at_claim: false,
                receipt_queryable_at_hook: false,
            }
        }
    }

    struct RoutingStore {
        state: Mutex<RoutingStoreState>,
    }

    impl RoutingStore {
        fn new(claim_mode: ClaimMode, route_mode: RouteMode) -> Self {
            Self {
                state: Mutex::new(RoutingStoreState::new(claim_mode, route_mode)),
            }
        }

        fn state(&self) -> MutexGuard<'_, RoutingStoreState> {
            match self.state.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            }
        }

        fn set_seed_failure(&self) {
            self.state().seed_fails = true;
        }

        fn note_hook_query(&self, receipt_id: &str) {
            let mut state = self.state();
            state.receipt_queryable_at_hook = state.receipts.contains_key(receipt_id);
        }
    }

    impl ReceiptStore for RoutingStore {
        fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
            self.append_chio_receipt_returning_seq(receipt).map(|_| ())
        }

        fn append_chio_receipt_returning_seq(
            &self,
            receipt: &ChioReceipt,
        ) -> Result<Option<u64>, ReceiptStoreError> {
            let mut state = self.state();
            state.legacy_appends += 1;
            state.receipts.insert(receipt.id.clone(), receipt.clone());
            Ok(Some(state.legacy_appends as u64))
        }

        fn load_chio_receipt(
            &self,
            receipt_id: &str,
        ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
            Ok(self.state().receipts.get(receipt_id).cloned())
        }

        fn settlement_store_binding(&self) -> Option<SettlementStoreBinding> {
            Some(STORE_BINDING)
        }

        fn atomic_receipt_projection(&self) -> AtomicReceiptProjection {
            AtomicReceiptProjection::SettlementObservationV1
        }

        fn supports_atomic_receipt_projection_with_timeout(&self) -> bool {
            true
        }

        fn append_chio_receipt_with_pending_observation(
            &self,
            receipt: &ChioReceipt,
            pending: &PendingSettlementObservation,
        ) -> Result<(), ReceiptStoreError> {
            let mut state = self.state();
            state.atomic_appends += 1;
            state.legacy_atomic_appends += 1;
            if state.seed_fails {
                return Err(ReceiptStoreError::Conflict(
                    "forced atomic settlement seed failure".to_string(),
                ));
            }
            state.receipts.insert(receipt.id.clone(), receipt.clone());
            state.attempts.insert(receipt.id.clone(), *pending);
            Ok(())
        }

        fn append_chio_receipt_with_pending_observation_and_timeout(
            &self,
            receipt: &ChioReceipt,
            pending: &PendingSettlementObservation,
            budget: Duration,
        ) -> Result<Option<u64>, ReceiptStoreError> {
            let mut state = self.state();
            state.atomic_appends += 1;
            state.timed_atomic_appends += 1;
            state.timed_atomic_budget_ms =
                Some(budget.as_millis().min(u128::from(u64::MAX)) as u64);
            if state.seed_fails {
                return Err(ReceiptStoreError::Conflict(
                    "forced atomic settlement seed failure".to_string(),
                ));
            }
            state.receipts.insert(receipt.id.clone(), receipt.clone());
            state.attempts.insert(receipt.id.clone(), *pending);
            Ok(Some(state.atomic_appends as u64))
        }

        fn append_child_receipt(
            &self,
            _receipt: &ChildRequestReceipt,
        ) -> Result<(), ReceiptStoreError> {
            Ok(())
        }
    }

    impl SettlementOutcomeStore for RoutingStore {
        fn settlement_store_binding(&self) -> SettlementStoreBinding {
            STORE_BINDING
        }

        fn claim_receipt(
            &self,
            receipt_id: &str,
            worker_id: &str,
            now_ms: u64,
            lease_ms: u64,
        ) -> Result<Option<SettlementAttemptClaim>, SettlementRouteError> {
            let mut state = self.state();
            state.claim_calls += 1;
            state.receipt_queryable_at_claim = state.receipts.contains_key(receipt_id);
            match state.claim_mode {
                ClaimMode::None => Ok(None),
                ClaimMode::Error => Err(SettlementRouteError::Backend {
                    detail: "forced claim failure".to_string(),
                }),
                ClaimMode::Claim => {
                    let Some(pending) = state.attempts.get(receipt_id) else {
                        return Ok(None);
                    };
                    let Some(receipt) = state.receipts.get(receipt_id) else {
                        return Err(SettlementRouteError::InvalidRecord {
                            detail: "attempt has no receipt".to_string(),
                        });
                    };
                    let lease_until_ms = match now_ms.checked_add(lease_ms) {
                        Some(deadline) => deadline,
                        None => {
                            return Err(SettlementRouteError::InvalidRecord {
                                detail: "lease deadline overflow".to_string(),
                            });
                        }
                    };
                    if pending.next_visible_at_ms > now_ms {
                        return Ok(None);
                    }
                    Ok(Some(SettlementAttemptClaim {
                        receipt_id: receipt_id.to_string(),
                        finalized_at: receipt.timestamp,
                        attempts: 0,
                        row_version: 1,
                        lease_owner: worker_id.to_string(),
                        lease_token: format!("lease-{receipt_id}"),
                        lease_until_ms,
                    }))
                }
            }
        }

        fn claim_due(
            &self,
            _worker_id: &str,
            _now_ms: u64,
            _lease_ms: u64,
            _limit: usize,
        ) -> Result<Vec<SettlementAttemptClaim>, SettlementRouteError> {
            Ok(Vec::new())
        }

        fn record_claimed_outcome(
            &self,
            claim: &SettlementAttemptClaim,
            outcome: &SettlementRoutingInput,
            _policy: RetryPolicy,
            _observed_at_ms: u64,
        ) -> Result<SettlementRoute, SettlementRouteError> {
            let mut state = self.state();
            state.route_calls += 1;
            state.inputs.push(outcome.clone());
            if matches!(state.route_mode, RouteMode::Error) {
                return Err(SettlementRouteError::Backend {
                    detail: "forced route failure".to_string(),
                });
            }
            match outcome {
                SettlementRoutingInput::Accepted | SettlementRoutingInput::Skipped { .. } => {
                    state.attempts.remove(&claim.receipt_id);
                    Ok(SettlementRoute::NoAction)
                }
                SettlementRoutingInput::Retryable { .. } => Ok(SettlementRoute::RetryScheduled {
                    attempt: claim.attempts + 1,
                    next_visible_at_ms: claim.lease_until_ms,
                }),
                SettlementRoutingInput::Permanent { .. } => {
                    state.attempts.remove(&claim.receipt_id);
                    Ok(SettlementRoute::DeadLettered {
                        attempts: claim.attempts + 1,
                    })
                }
            }
        }
    }

    #[derive(Clone, Copy)]
    enum HookBehavior {
        Accepted,
        Retryable,
        Permanent,
        Skipped,
        TransientError,
    }

    struct RecordingHook {
        behavior: HookBehavior,
        calls: AtomicUsize,
        store: Arc<RoutingStore>,
    }

    impl RecordingHook {
        fn new(behavior: HookBehavior, store: Arc<RoutingStore>) -> Self {
            Self {
                behavior,
                calls: AtomicUsize::new(0),
                store,
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl SettlementHook for RecordingHook {
        fn observe(
            &self,
            observation: &SettlementObservation,
            _idempotency_key: &chio_settle::SettlementIdempotencyKey,
        ) -> Result<SettlementOutcome, SettlementHookError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.store.note_hook_query(&observation.receipt_id);
            let rpc = || {
                SettlementFailureReason::from_detail(
                    SettlementFailureCode::Rpc,
                    "test settlement RPC failure",
                )
            };
            match self.behavior {
                HookBehavior::Accepted => Ok(SettlementOutcome::accepted("accepted")),
                HookBehavior::Retryable => Ok(SettlementOutcome::retryable(rpc())),
                HookBehavior::Permanent => Ok(SettlementOutcome::permanent(
                    SettlementFailureReason::from_detail(
                        SettlementFailureCode::InvalidBinding,
                        "test invalid binding",
                    ),
                )),
                HookBehavior::Skipped => Ok(SettlementOutcome::skipped(
                    SettlementSkipReason::NoEconomicIntent,
                )),
                HookBehavior::TransientError => {
                    Err(SettlementHookError::Transient("test transient".to_string()))
                }
            }
        }
    }

    struct BlockingHook {
        calls: AtomicUsize,
        store: Arc<RoutingStore>,
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl SettlementHook for BlockingHook {
        fn observe(
            &self,
            observation: &SettlementObservation,
            _idempotency_key: &chio_settle::SettlementIdempotencyKey,
        ) -> Result<SettlementOutcome, SettlementHookError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.store.note_hook_query(&observation.receipt_id);
            let _ = self.entered.send(());
            let released = match self.release.lock() {
                Ok(receiver) => receiver.recv_timeout(Duration::from_secs(5)).is_ok(),
                Err(_) => false,
            };
            if !released {
                return Err(SettlementHookError::Transient(
                    "blocking test hook was not released".to_string(),
                ));
            }
            Ok(SettlementOutcome::accepted("accepted"))
        }
    }

    fn signed_receipt(
        keypair: &Keypair,
        sequence: u64,
        financial: Option<serde_json::Value>,
    ) -> ChioReceipt {
        let action = match ToolCallAction::from_parameters(serde_json::json!({
            "sequence": sequence,
        })) {
            Ok(action) => action,
            Err(error) => panic!("test action construction failed: {error}"),
        };
        let metadata = financial.map(|financial| serde_json::json!({ "financial": financial }));
        let body = ChioReceiptBody {
            id: format!("settlement-routing-{sequence}"),
            timestamp: 1_700_000_000 + sequence,
            capability_id: format!("cap-{sequence}"),
            tool_server: "settlement-test".to_string(),
            tool_name: "charge".to_string(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: format!("{sequence:064x}"),
            policy_hash: "test-policy-hash".to_string(),
            evidence: Vec::new(),
            metadata,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        };
        match ChioReceipt::sign(body, keypair) {
            Ok(receipt) => receipt,
            Err(error) => panic!("test receipt signing failed: {error}"),
        }
    }

    fn positive_receipt(keypair: &Keypair, sequence: u64) -> ChioReceipt {
        signed_receipt(
            keypair,
            sequence,
            Some(serde_json::json!({
                "cost_charged": 100,
                "currency": "USD",
            })),
        )
    }

    fn test_kernel(keypair: &Keypair) -> ChioKernel {
        let mut config = make_config();
        config.keypair = keypair.clone();
        config.checkpoint_batch_size = 0;
        make_kernel(config)
    }

    fn attach_store(kernel: &mut ChioKernel, store: &Arc<RoutingStore>) {
        let receipt_store: Arc<dyn ReceiptStore> = store.clone();
        if let Err(error) = kernel.set_receipt_store_handle(receipt_store) {
            panic!("test receipt store installation failed: {error}");
        }
    }

    fn install_runtime(
        kernel: &mut ChioKernel,
        store: &Arc<RoutingStore>,
        hook: Arc<dyn SettlementHook>,
    ) {
        attach_store(kernel, store);
        let outcome_store: Arc<dyn SettlementOutcomeStore> = store.clone();
        if let Err(error) =
            kernel.set_settlement_observer_runtime(hook, outcome_store, RetryPolicy::default())
        {
            panic!("test settlement runtime installation failed: {error}");
        }
    }

    struct RecordingHarness {
        kernel: ChioKernel,
        keypair: Keypair,
        store: Arc<RoutingStore>,
        hook: Arc<RecordingHook>,
    }

    fn recording_harness(
        claim_mode: ClaimMode,
        route_mode: RouteMode,
        behavior: HookBehavior,
    ) -> RecordingHarness {
        let keypair = Keypair::generate();
        let store = Arc::new(RoutingStore::new(claim_mode, route_mode));
        let hook = Arc::new(RecordingHook::new(behavior, Arc::clone(&store)));
        let mut kernel = test_kernel(&keypair);
        let hook_handle: Arc<dyn SettlementHook> = hook.clone();
        install_runtime(&mut kernel, &store, hook_handle);
        RecordingHarness {
            kernel,
            keypair,
            store,
            hook,
        }
    }

    fn recorded_input(
        behavior: HookBehavior,
        financial: Option<serde_json::Value>,
        sequence: u64,
    ) -> (SettlementRoutingInput, usize) {
        let harness = recording_harness(ClaimMode::Claim, RouteMode::Contract, behavior);
        let receipt = signed_receipt(&harness.keypair, sequence, financial);
        if let Err(error) = harness.kernel.record_chio_receipt(&receipt) {
            panic!("test receipt routing failed: {error}");
        }
        let state = harness.store.state();
        let input = match state.inputs.as_slice() {
            [input] => input.clone(),
            inputs => panic!("expected one routed input, got {inputs:?}"),
        };
        (input, harness.hook.calls())
    }

    #[test]
    fn no_runtime_uses_the_legacy_append_without_routing() {
        let keypair = Keypair::generate();
        let store = Arc::new(RoutingStore::new(ClaimMode::Claim, RouteMode::Contract));
        let mut kernel = test_kernel(&keypair);
        attach_store(&mut kernel, &store);
        let receipt = positive_receipt(&keypair, 1);

        assert!(kernel.record_chio_receipt(&receipt).is_ok());

        let state = store.state();
        assert_eq!(state.legacy_appends, 1);
        assert_eq!(state.atomic_appends, 0);
        assert_eq!(state.claim_calls, 0);
        assert_eq!(state.route_calls, 0);
        assert!(state.receipts.contains_key(&receipt.id));
        assert!(state.attempts.is_empty());
    }

    #[test]
    fn internal_receipt_from_distinct_authority_skips_settlement_routing() {
        let harness = recording_harness(
            ClaimMode::Claim,
            RouteMode::Contract,
            HookBehavior::Accepted,
        );
        let pool_authority = Keypair::generate();
        assert_ne!(pool_authority.public_key(), harness.keypair.public_key());
        let receipt = signed_receipt(&pool_authority, 91, None);

        assert!(harness
            .kernel
            .record_chio_receipt_without_settlement(&receipt)
            .is_ok());

        let state = harness.store.state();
        assert_eq!(state.legacy_appends, 1);
        assert_eq!(state.atomic_appends, 0);
        assert_eq!(state.claim_calls, 0);
        assert_eq!(state.route_calls, 0);
        assert!(state.attempts.is_empty());
        assert!(state.receipts.contains_key(&receipt.id));
        assert_eq!(harness.hook.calls(), 0);
    }

    #[test]
    fn installed_runtime_seeds_before_claim_and_routes_after_the_receipt_is_queryable() {
        let harness = recording_harness(
            ClaimMode::Claim,
            RouteMode::Contract,
            HookBehavior::Accepted,
        );
        let receipt = positive_receipt(&harness.keypair, 2);

        assert!(harness.kernel.record_chio_receipt(&receipt).is_ok());

        let state = harness.store.state();
        assert_eq!(state.legacy_appends, 0);
        assert_eq!(state.atomic_appends, 1);
        assert_eq!(state.claim_calls, 1);
        assert_eq!(state.route_calls, 1);
        assert!(state.receipt_queryable_at_claim);
        assert!(state.receipt_queryable_at_hook);
        assert!(state.receipts.contains_key(&receipt.id));
        assert!(state.attempts.is_empty());
        assert_eq!(harness.hook.calls(), 1);
        assert!(matches!(
            state.inputs.as_slice(),
            [SettlementRoutingInput::Accepted]
        ));
    }

    #[test]
    fn installed_runtime_uses_the_configured_bounded_atomic_append() {
        let keypair = Keypair::generate();
        let store = Arc::new(RoutingStore::new(ClaimMode::Claim, RouteMode::Contract));
        let hook = Arc::new(RecordingHook::new(
            HookBehavior::Accepted,
            Arc::clone(&store),
        ));
        let mut config = make_config();
        config.keypair = keypair.clone();
        config.checkpoint_batch_size = 0;
        config.deadlines.receipt_append_budget_ms = 321;
        let mut kernel = make_kernel(config);
        let hook_handle: Arc<dyn SettlementHook> = hook;
        install_runtime(&mut kernel, &store, hook_handle);
        let receipt = positive_receipt(&keypair, 21);

        assert!(kernel.record_chio_receipt(&receipt).is_ok());

        let state = store.state();
        assert_eq!(state.timed_atomic_appends, 1);
        assert_eq!(state.legacy_atomic_appends, 0);
        assert_eq!(state.timed_atomic_budget_ms, Some(321));
        assert_eq!(state.legacy_appends, 0);
        assert!(state.receipts.contains_key(&receipt.id));
    }

    #[test]
    fn atomic_seed_failure_persists_neither_receipt_nor_work_and_skips_the_hook() {
        let harness = recording_harness(
            ClaimMode::Claim,
            RouteMode::Contract,
            HookBehavior::Accepted,
        );
        harness.store.set_seed_failure();
        let receipt = positive_receipt(&harness.keypair, 3);

        let result = harness.kernel.record_chio_receipt(&receipt);

        assert!(matches!(result, Err(KernelError::ReceiptPersistence(_))));
        let state = harness.store.state();
        assert!(state.receipts.is_empty());
        assert!(state.attempts.is_empty());
        assert_eq!(state.claim_calls, 0);
        assert_eq!(state.route_calls, 0);
        assert_eq!(harness.hook.calls(), 0);
        assert!(harness.kernel.receipt_log().is_empty());
    }

    #[test]
    fn a_live_claimant_leaves_the_seeded_row_without_invoking_the_hook() {
        let harness =
            recording_harness(ClaimMode::None, RouteMode::Contract, HookBehavior::Accepted);
        let receipt = positive_receipt(&harness.keypair, 4);

        assert!(harness.kernel.record_chio_receipt(&receipt).is_ok());

        let state = harness.store.state();
        assert!(state.attempts.contains_key(&receipt.id));
        assert_eq!(state.claim_calls, 1);
        assert_eq!(state.route_calls, 0);
        assert_eq!(harness.hook.calls(), 0);
    }

    #[test]
    fn post_commit_claim_failure_does_not_change_receipt_success() {
        let harness = recording_harness(
            ClaimMode::Error,
            RouteMode::Contract,
            HookBehavior::Accepted,
        );
        let receipt = positive_receipt(&harness.keypair, 5);

        assert!(harness.kernel.record_chio_receipt(&receipt).is_ok());

        let state = harness.store.state();
        assert!(state.receipts.contains_key(&receipt.id));
        assert!(state.attempts.contains_key(&receipt.id));
        assert_eq!(state.claim_calls, 1);
        assert_eq!(state.route_calls, 0);
        assert_eq!(harness.hook.calls(), 0);
    }

    #[test]
    fn normalized_observer_statuses_reach_the_durable_store() {
        let positive = Some(serde_json::json!({
            "cost_charged": 100,
            "currency": "USD",
        }));
        let (accepted, accepted_calls) =
            recorded_input(HookBehavior::Accepted, positive.clone(), 10);
        let (retryable, retryable_calls) =
            recorded_input(HookBehavior::Retryable, positive.clone(), 11);
        let (permanent, permanent_calls) =
            recorded_input(HookBehavior::Permanent, positive.clone(), 12);
        let (failed_hook, failed_hook_calls) =
            recorded_input(HookBehavior::TransientError, positive.clone(), 13);
        let (hook_skip, hook_skip_calls) = recorded_input(HookBehavior::Skipped, positive, 14);
        let (pre_hook_skip, pre_hook_skip_calls) = recorded_input(HookBehavior::Accepted, None, 15);

        assert!(matches!(accepted, SettlementRoutingInput::Accepted));
        assert!(matches!(
            retryable,
            SettlementRoutingInput::Retryable { reason }
                if reason.code() == SettlementFailureCode::Rpc
        ));
        assert!(matches!(
            permanent,
            SettlementRoutingInput::Permanent { reason }
                if reason.code() == SettlementFailureCode::InvalidBinding
        ));
        assert!(matches!(
            failed_hook,
            SettlementRoutingInput::Retryable { reason }
                if reason.code() == SettlementFailureCode::Backend
        ));
        assert!(matches!(
            hook_skip,
            SettlementRoutingInput::Permanent { reason }
                if reason.code() == SettlementFailureCode::InvalidObservation
        ));
        assert!(matches!(
            pre_hook_skip,
            SettlementRoutingInput::Skipped {
                reason: SettlementSkipReason::NoEconomicIntent
            }
        ));
        assert_eq!(
            [
                accepted_calls,
                retryable_calls,
                permanent_calls,
                failed_hook_calls,
                hook_skip_calls,
                pre_hook_skip_calls,
            ],
            [1, 1, 1, 1, 1, 0]
        );
    }

    #[test]
    fn route_failure_leaves_the_receipt_and_work_durable() {
        let harness = recording_harness(ClaimMode::Claim, RouteMode::Error, HookBehavior::Accepted);
        let receipt = positive_receipt(&harness.keypair, 20);

        assert!(harness.kernel.record_chio_receipt(&receipt).is_ok());

        let state = harness.store.state();
        assert!(state.receipts.contains_key(&receipt.id));
        assert!(state.attempts.contains_key(&receipt.id));
        assert_eq!(state.route_calls, 1);
        assert_eq!(harness.hook.calls(), 1);
    }

    #[test]
    fn settlement_hook_does_not_hold_the_receipt_store_write_lock() {
        let keypair = Keypair::generate();
        let store = Arc::new(RoutingStore::new(ClaimMode::Claim, RouteMode::Contract));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let hook = Arc::new(BlockingHook {
            calls: AtomicUsize::new(0),
            store: Arc::clone(&store),
            entered: entered_tx,
            release: Mutex::new(release_rx),
        });
        let mut kernel = test_kernel(&keypair);
        let hook_handle: Arc<dyn SettlementHook> = hook.clone();
        install_runtime(&mut kernel, &store, hook_handle);
        let kernel = Arc::new(kernel);
        let first_receipt = positive_receipt(&keypair, 30);
        let second_receipt = signed_receipt(&keypair, 31, None);

        let first_kernel = Arc::clone(&kernel);
        let first = thread::spawn(move || first_kernel.record_chio_receipt(&first_receipt));
        let entered = entered_rx.recv_timeout(Duration::from_secs(2)).is_ok();

        let (second_tx, second_rx) = mpsc::channel();
        let second_kernel = Arc::clone(&kernel);
        let second = thread::spawn(move || {
            let result = second_kernel.record_chio_receipt(&second_receipt);
            let _ = second_tx.send(result);
        });
        let second_result = second_rx.recv_timeout(Duration::from_secs(2));
        let completed_while_hook_blocked = matches!(second_result, Ok(Ok(())));

        let _ = release_tx.send(());
        let first_result = match first.join() {
            Ok(result) => result,
            Err(_) => panic!("first receipt thread panicked"),
        };
        if second.join().is_err() {
            panic!("second receipt thread panicked");
        }

        assert!(entered, "first hook did not start");
        assert!(first_result.is_ok());
        assert!(
            completed_while_hook_blocked,
            "second receipt could not persist while the first hook was blocked"
        );
        assert_eq!(hook.calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.state().atomic_appends, 2);
    }

    #[test]
    fn durable_materialization_seeds_a_claimable_settlement_attempt() {
        let harness =
            recording_harness(ClaimMode::Claim, RouteMode::Contract, HookBehavior::Accepted);
        let receipt = positive_receipt(&harness.keypair, 40);

        // A durable monetary receipt must seed its settlement attempt exactly
        // as the non-durable path does, so the observation the terminal
        // projection records is claimable rather than stranded as durable-only
        // work.
        if let Err(error) = harness
            .kernel
            .materialize_durable_admission_receipt(&receipt)
        {
            panic!("durable receipt materialization failed: {error}");
        }

        let pending = {
            let state = harness.store.state();
            assert_eq!(state.timed_atomic_appends, 1);
            assert_eq!(state.atomic_appends, 1);
            assert_eq!(state.legacy_appends, 0);
            assert!(state.receipts.contains_key(&receipt.id));
            match state.attempts.get(&receipt.id) {
                Some(pending) => *pending,
                None => panic!("durable materialization left no claimable settlement attempt"),
            }
        };

        // A settlement worker can genuinely claim the seeded row.
        let claim = match harness.store.claim_receipt(
            &receipt.id,
            "settlement-worker",
            pending.next_visible_at_ms,
            1_000,
        ) {
            Ok(claim) => claim,
            Err(error) => panic!("claiming the seeded attempt failed: {error}"),
        };
        assert!(
            claim.is_some(),
            "durable settlement attempt was seeded but is not claimable"
        );

        // Replaying materialization finds the receipt already durable and does
        // not seed a second attempt.
        if let Err(error) = harness
            .kernel
            .materialize_durable_admission_receipt(&receipt)
        {
            panic!("durable receipt re-materialization failed: {error}");
        }
        assert_eq!(
            harness.store.state().atomic_appends,
            1,
            "replay must not seed a second settlement attempt"
        );
    }
}
