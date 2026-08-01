#[derive(Clone, Copy)]
enum ReleaseFault {
    Error,
    Panic,
    PanicAfterReacquire,
}

#[derive(Clone, Copy)]
enum ConsumeFault {
    Error,
    Panic,
}

#[derive(Clone)]
struct FaultInjectingAdmissionStore {
    inner: InMemoryRuntimeAdmissionStore,
    bundle_calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
    panic_bundle_on_call: Option<u64>,
    destructive_consume_fault: Option<ConsumeFault>,
    treaty_consume_fault: Option<ConsumeFault>,
    swarm_consume_fault: Option<ConsumeFault>,
    panic_trust_floor: bool,
    reject_trust_floor: bool,
    destructive_release_fault: Option<ReleaseFault>,
    treaty_release_error: bool,
    destructive_releases: std::sync::Arc<std::sync::atomic::AtomicU64>,
    treaty_releases: std::sync::Arc<std::sync::atomic::AtomicU64>,
    swarm_releases: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl FaultInjectingAdmissionStore {
    fn new(inner: InMemoryRuntimeAdmissionStore) -> Self {
        Self {
            inner,
            bundle_calls: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            panic_bundle_on_call: None,
            destructive_consume_fault: None,
            treaty_consume_fault: None,
            swarm_consume_fault: None,
            panic_trust_floor: false,
            reject_trust_floor: false,
            destructive_release_fault: None,
            treaty_release_error: false,
            destructive_releases: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            treaty_releases: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            swarm_releases: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }
}

impl RuntimeAdmissionStore for FaultInjectingAdmissionStore {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError> {
        let call = self
            .bundle_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.panic_bundle_on_call == Some(call) {
            panic!("injected admission bundle callback panic on call {call}");
        }
        self.inner.bundle(admission_id)
    }

    fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChioRuntimeError> {
        self.inner
            .treaty_runtime_artifact(evidence_kind, evidence_id)
    }

    fn swarm_authority_bundle(
        &self,
        task_graph_id: &str,
    ) -> Result<Option<SwarmAuthorityBundle>, ChioRuntimeError> {
        self.inner.swarm_authority_bundle(task_graph_id)
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        match self.destructive_consume_fault {
            Some(ConsumeFault::Error) => {
                return Err(ChioRuntimeError::Store(
                    "injected destructive consume failure".to_string(),
                ));
            }
            Some(ConsumeFault::Panic) => {
                panic!("destructive consume callback panicked before delegating");
            }
            None => {}
        }
        self.inner.consume_destructive_lease(lease_id, admission_id)
    }

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.destructive_releases
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match self.destructive_release_fault {
            Some(ReleaseFault::Error) => Err(ChioRuntimeError::Store(
                "injected destructive release failure".to_string(),
            )),
            Some(ReleaseFault::Panic) => panic!("injected destructive release panic"),
            Some(ReleaseFault::PanicAfterReacquire) => {
                self.inner
                    .release_destructive_lease(lease_id, admission_id)?;
                self.inner
                    .consume_destructive_lease(lease_id, admission_id)?;
                panic!("injected destructive release panic after same-admission reacquire");
            }
            None => self.inner.release_destructive_lease(lease_id, admission_id),
        }
    }

    fn consume_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        match self.treaty_consume_fault {
            Some(ConsumeFault::Error) => {
                return Err(ChioRuntimeError::Store(
                    "injected treaty consume failure".to_string(),
                ));
            }
            Some(ConsumeFault::Panic) => {
                panic!("treaty consume callback panicked before delegating");
            }
            None => {}
        }
        self.inner
            .consume_treaty_continuation(continuation_id, admission_id)
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.treaty_releases
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.treaty_release_error {
            return Err(ChioRuntimeError::Store(
                "injected treaty release failure".to_string(),
            ));
        }
        self.inner
            .release_treaty_continuation(continuation_id, admission_id)
    }

    fn consume_swarm_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        match self.swarm_consume_fault {
            Some(ConsumeFault::Error) => {
                return Err(ChioRuntimeError::Store(
                    "injected swarm consume failure".to_string(),
                ));
            }
            Some(ConsumeFault::Panic) => {
                panic!("swarm consume callback panicked before delegating");
            }
            None => {}
        }
        self.inner
            .consume_swarm_continuation(continuation_id, admission_id)
    }

    fn release_swarm_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.swarm_releases
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner
            .release_swarm_continuation(continuation_id, admission_id)
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        self.inner.runtime_trust_floor(verifier_id, key_id)
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        self.inner.record_runtime_trust_floor(entry)
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        if self.panic_trust_floor {
            self.inner
                .validate_and_record_runtime_trust_floor(entry, previous_hash_sha256)?;
            panic!("runtime trust floor callback panicked after recording");
        }
        if self.reject_trust_floor {
            return Err(ChioRuntimeError::Rejected {
                code: "runtime_trust_rollback",
                detail: "injected runtime trust floor rejection".to_string(),
            });
        }
        self.inner
            .validate_and_record_runtime_trust_floor(entry, previous_hash_sha256)
    }
}

fn assert_destructive_consume_fault_preserves_same_admission_replay_marker(
    fault: ConsumeFault,
    expected_reason: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let inner = InMemoryRuntimeAdmissionStore::new();
    inner.insert_bundle(bundle())?;
    inner.consume_destructive_lease("lease-live-1", "adm-live-1")?;
    let mut store = FaultInjectingAdmissionStore::new(inner.clone());
    store.destructive_consume_fault = Some(fault);
    let (signed_trust, trusted, advisory, signed_policy, signed_weights) =
        signed_policy_inputs(0.10)?;

    let report = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&signed_trust),
        trusted_verifier_keys: &trusted,
        pheromone_query_report: Some(&advisory),
        runtime_pheromone_policy: Some(&signed_policy),
        runtime_peer_weights: Some(&signed_weights),
        now_unix_ms: 1_800_000_001_000,
    })?;

    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("destructive_lease_consume_error")
    );
    assert_eq!(
        store
            .destructive_releases
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        report.receipt_metadata["chio_runtime"]["ambiguous_destructive_lease_id"],
        "lease-live-1"
    );
    assert_eq!(
        report.receipt_metadata["chio_runtime"]["reservation_ownership_ambiguous"],
        true
    );
    assert!(
        report.receipt_metadata["chio_runtime"]["reservation_consumption_failure_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(expected_reason))
    );
    assert!(report.receipt_metadata["chio_runtime"]
        .get("reserved_destructive_lease_id")
        .is_none());
    let replay = match inner.consume_destructive_lease("lease-live-1", "adm-live-1") {
        Ok(()) => {
            return Err(
                io::Error::other("same-admission destructive replay marker was erased").into(),
            )
        }
        Err(error) => error,
    };
    assert_eq!(replay.code(), "destructive_lease_replay");
    Ok(())
}

#[test]
fn destructive_consume_panic_preserves_same_admission_replay_marker(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_destructive_consume_fault_preserves_same_admission_replay_marker(
        ConsumeFault::Panic,
        "callback panicked",
    )
}

#[test]
fn destructive_consume_error_preserves_same_admission_replay_marker(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_destructive_consume_fault_preserves_same_admission_replay_marker(
        ConsumeFault::Error,
        "injected destructive consume failure",
    )
}

#[test]
fn runtime_trust_floor_panic_is_denied_and_releases_destructive_lease(
) -> Result<(), Box<dyn std::error::Error>> {
    let inner = InMemoryRuntimeAdmissionStore::new();
    inner.insert_bundle(bundle())?;
    let mut store = FaultInjectingAdmissionStore::new(inner.clone());
    store.panic_trust_floor = true;
    let (signed_trust, trusted, advisory, signed_policy, signed_weights) =
        signed_policy_inputs(0.10)?;

    let report = evaluate_runtime_admission(RuntimeAdmissionInput {
        profile: &profile(),
        store: &store,
        admission_id: "adm-live-1",
        request: &binding(),
        action_class_id: None,
        runtime_trust_input: Some(&signed_trust),
        trusted_verifier_keys: &trusted,
        pheromone_query_report: Some(&advisory),
        runtime_pheromone_policy: Some(&signed_policy),
        runtime_peer_weights: Some(&signed_weights),
        now_unix_ms: 1_800_000_001_000,
    })?;

    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_trust_floor_error")
    );
    assert_eq!(
        store
            .destructive_releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert!(report.receipt_metadata["chio_runtime"]
        .get("reserved_destructive_lease_id")
        .is_none());
    inner.consume_destructive_lease("lease-live-1", "adm-retry")?;
    inner.release_destructive_lease("lease-live-1", "adm-retry")?;
    Ok(())
}

fn runtime_hook_cleanup_request(
    store: &InMemoryRuntimeAdmissionStore,
    include_swarm: bool,
) -> Result<(ToolCallRequest, Option<serde_json::Value>), Box<dyn std::error::Error>> {
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    let bundle_hash = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    let treaty_fixture = treaty_runtime_fixture()?;
    insert_in_memory_treaty_runtime_fixture(store, &treaty_fixture)?;

    if !include_swarm {
        return Ok((
            treaty_runtime_request(args, bundle_hash, treaty_runtime_context(&treaty_fixture))?,
            None,
        ));
    }

    let swarm_bundle = runtime_swarm_bundle(false)?;
    store.insert_swarm_authority_bundle(swarm_bundle.clone())?;
    let mut request =
        chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(&swarm_bundle)?)?;
    request.federated_origin_kernel_id = Some("kernel.buyer".to_string());
    let context = request
        .governed_intent
        .as_mut()
        .and_then(|intent| intent.context.as_mut())
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| io::Error::other("governed runtime context missing"))?;
    context.insert(
        "chioTreaty".to_string(),
        treaty_runtime_context(&treaty_fixture),
    );
    Ok((request, Some(swarm_route_metadata())))
}

fn assert_treaty_consume_fault_preserves_same_admission_replay_marker(
    fault: ConsumeFault,
    expected_reason: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let inner = InMemoryRuntimeAdmissionStore::new();
    let (request, extra_metadata) = runtime_hook_cleanup_request(&inner, false)?;
    inner.consume_treaty_continuation("continue-runtime-1", "adm-live-1")?;
    let mut store = FaultInjectingAdmissionStore::new(inner.clone());
    store.treaty_consume_fault = Some(fault);
    let observer = store.clone();
    let hook = allowing_chio_policy_hook(store)?;

    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: extra_metadata.as_ref(),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "treaty_continuation_consume_error"
    );
    assert_eq!(
        observer
            .treaty_releases
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        metadata["chio_runtime"]["ambiguous_treaty_continuation_id"],
        "continue-runtime-1"
    );
    assert_eq!(
        metadata["chio_runtime"]["reservation_ownership_ambiguous"],
        true
    );
    assert!(
        metadata["chio_runtime"]["reservation_consumption_failure_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(expected_reason))
    );
    assert!(metadata["chio_runtime"]
        .get("reserved_treaty_continuation_id")
        .is_none());
    let replay = match inner.consume_treaty_continuation("continue-runtime-1", "adm-live-1") {
        Ok(()) => {
            return Err(io::Error::other("same-admission treaty replay marker was erased").into())
        }
        Err(error) => error,
    };
    assert_eq!(replay.code(), "chio_treaty_continuation_replay");
    Ok(())
}

#[test]
fn treaty_consume_panic_preserves_same_admission_replay_marker(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_treaty_consume_fault_preserves_same_admission_replay_marker(
        ConsumeFault::Panic,
        "callback panicked",
    )
}

#[test]
fn treaty_consume_error_preserves_same_admission_replay_marker(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_treaty_consume_fault_preserves_same_admission_replay_marker(
        ConsumeFault::Error,
        "injected treaty consume failure",
    )
}

fn assert_swarm_consume_fault_releases_treaty_and_preserves_same_admission_marker(
    fault: ConsumeFault,
    expected_reason: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let inner = InMemoryRuntimeAdmissionStore::new();
    let (request, extra_metadata) = runtime_hook_cleanup_request(&inner, true)?;
    inner.consume_swarm_continuation("continuation-child-a", "adm-live-1")?;
    let mut store = FaultInjectingAdmissionStore::new(inner.clone());
    store.swarm_consume_fault = Some(fault);
    let observer = store.clone();
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());

    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: extra_metadata.as_ref(),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "swarm_continuation_consume_error"
    );
    assert_eq!(
        observer
            .treaty_releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        observer
            .swarm_releases
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        metadata["chio_runtime"]["ambiguous_swarm_continuation_id"],
        "continuation-child-a"
    );
    assert_eq!(
        metadata["chio_runtime"]["reservation_ownership_ambiguous"],
        true
    );
    assert!(
        metadata["chio_runtime"]["reservation_consumption_failure_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(expected_reason))
    );
    assert!(metadata["chio_runtime"]
        .get("reserved_treaty_continuation_id")
        .is_none());
    assert!(metadata["chio_runtime"]
        .get("reserved_swarm_continuation_id")
        .is_none());
    inner.consume_treaty_continuation("continue-runtime-1", "adm-live-1")?;
    inner.release_treaty_continuation("continue-runtime-1", "adm-live-1")?;
    let replay = match inner.consume_swarm_continuation("continuation-child-a", "adm-live-1") {
        Ok(()) => {
            return Err(io::Error::other("same-admission swarm replay marker was erased").into())
        }
        Err(error) => error,
    };
    assert_eq!(replay.code(), "chio_swarm_continuation_replay");
    Ok(())
}

#[test]
fn swarm_consume_panic_releases_treaty_and_preserves_same_admission_swarm_marker(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_swarm_consume_fault_releases_treaty_and_preserves_same_admission_marker(
        ConsumeFault::Panic,
        "callback panicked",
    )
}

#[test]
fn swarm_consume_error_releases_treaty_and_preserves_same_admission_swarm_marker(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_swarm_consume_fault_releases_treaty_and_preserves_same_admission_marker(
        ConsumeFault::Error,
        "injected swarm consume failure",
    )
}

#[test]
fn evaluator_bundle_panic_releases_only_observed_continuation_reservations(
) -> Result<(), Box<dyn std::error::Error>> {
    let inner = InMemoryRuntimeAdmissionStore::new();
    let (request, extra_metadata) = runtime_hook_cleanup_request(&inner, true)?;
    let mut store = FaultInjectingAdmissionStore::new(inner);
    store.panic_bundle_on_call = Some(2);
    let observer = store.clone();
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());

    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: extra_metadata.as_ref(),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "admission_bundle_store_error"
    );
    assert_eq!(
        observer
            .destructive_releases
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        observer
            .treaty_releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        observer
            .swarm_releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert!(metadata["chio_runtime"]
        .get("reservation_release_failed")
        .is_none());
    Ok(())
}

fn assert_destructive_release_fault_does_not_block_other_releases(
    release_fault: ReleaseFault,
    expected_reason: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let inner = InMemoryRuntimeAdmissionStore::new();
    let (request, extra_metadata) = runtime_hook_cleanup_request(&inner, true)?;
    let mut store = FaultInjectingAdmissionStore::new(inner);
    store.reject_trust_floor = true;
    store.destructive_release_fault = Some(release_fault);
    let observer = store.clone();
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());

    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: extra_metadata.as_ref(),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        observer
            .destructive_releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        observer
            .treaty_releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        observer
            .swarm_releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-live-1"
    );
    assert!(metadata["chio_runtime"]
        .get("reserved_treaty_continuation_id")
        .is_none());
    assert!(metadata["chio_runtime"]
        .get("reserved_swarm_continuation_id")
        .is_none());
    assert_eq!(metadata["chio_runtime"]["reservation_release_failed"], true);
    assert!(
        metadata["chio_runtime"]["reservation_release_failure_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(expected_reason))
    );
    Ok(())
}

#[test]
fn destructive_release_error_does_not_block_treaty_or_swarm_release(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_destructive_release_fault_does_not_block_other_releases(
        ReleaseFault::Error,
        "injected destructive release failure",
    )
}

#[test]
fn destructive_release_panic_does_not_block_treaty_or_swarm_release(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_destructive_release_fault_does_not_block_other_releases(
        ReleaseFault::Panic,
        "release callback panicked",
    )
}

#[test]
fn mixed_release_failures_preserve_each_failed_id_and_reason(
) -> Result<(), Box<dyn std::error::Error>> {
    let inner = InMemoryRuntimeAdmissionStore::new();
    let (request, extra_metadata) = runtime_hook_cleanup_request(&inner, true)?;
    let mut store = FaultInjectingAdmissionStore::new(inner);
    store.reject_trust_floor = true;
    store.destructive_release_fault = Some(ReleaseFault::Error);
    store.treaty_release_error = true;
    let observer = store.clone();
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());

    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: extra_metadata.as_ref(),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        observer
            .destructive_releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        observer
            .treaty_releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        observer
            .swarm_releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-live-1"
    );
    assert_eq!(
        metadata["chio_runtime"]["reserved_treaty_continuation_id"],
        "continue-runtime-1"
    );
    assert!(metadata["chio_runtime"]
        .get("reserved_swarm_continuation_id")
        .is_none());
    assert_eq!(metadata["chio_runtime"]["reservation_release_failed"], true);
    let reason = metadata["chio_runtime"]["reservation_release_failure_reason"]
        .as_str()
        .ok_or_else(|| io::Error::other("release failure reason missing"))?;
    assert!(reason.contains("injected destructive release failure"));
    assert!(reason.contains("injected treaty release failure"));
    Ok(())
}

#[test]
fn ambiguous_release_failure_is_not_retried_after_same_admission_reacquire(
) -> Result<(), Box<dyn std::error::Error>> {
    let inner = InMemoryRuntimeAdmissionStore::new();
    let (request, extra_metadata) = runtime_hook_cleanup_request(&inner, true)?;
    let mut store = FaultInjectingAdmissionStore::new(inner.clone());
    store.reject_trust_floor = true;
    store.destructive_release_fault = Some(ReleaseFault::PanicAfterReacquire);
    let observer = store.clone();
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());

    let decision = hook.evaluate(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: extra_metadata.as_ref(),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;

    assert!(!decision.allowed);
    let metadata = decision
        .metadata
        .ok_or_else(|| io::Error::other("runtime metadata missing"))?;
    assert_eq!(
        observer
            .destructive_releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        observer
            .treaty_releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        observer
            .swarm_releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-live-1"
    );
    assert!(metadata["chio_runtime"]
        .get("reserved_treaty_continuation_id")
        .is_none());
    assert!(metadata["chio_runtime"]
        .get("reserved_swarm_continuation_id")
        .is_none());
    assert_eq!(metadata["chio_runtime"]["reservation_release_failed"], true);
    assert!(
        metadata["chio_runtime"]["reservation_release_failure_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("release callback panicked"))
    );
    let replay = match inner.consume_destructive_lease("lease-live-1", "adm-live-1") {
        Ok(()) => {
            return Err(io::Error::other(
                "same-admission marker was erased by an ambiguous release retry",
            )
            .into())
        }
        Err(error) => error,
    };
    assert_eq!(replay.code(), "destructive_lease_replay");
    Ok(())
}
