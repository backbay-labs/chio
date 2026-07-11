//! `ChioKernel` construction and configuration surface.
//!
//! Holds the kernel constructor, session/store accessors, and the
//! `set_*` / `with_*` / `register_*` configuration setters, including
//! federation, emergency-stop, DPoP, and execution-nonce wiring.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use chio_log_redact::redacted;
use dashmap::DashMap;

use super::*;

impl ChioKernel {
    pub(crate) fn with_sessions_read<R>(
        &self,
        f: impl FnOnce(&DashMap<SessionId, Arc<Session>>) -> Result<R, KernelError>,
    ) -> Result<R, KernelError> {
        f(&self.sessions)
    }

    pub(crate) fn with_sessions_write<R>(
        &self,
        f: impl FnOnce(&DashMap<SessionId, Arc<Session>>) -> Result<R, KernelError>,
    ) -> Result<R, KernelError> {
        f(&self.sessions)
    }

    pub(crate) fn with_session<R>(
        &self,
        session_id: &SessionId,
        f: impl FnOnce(&Arc<Session>) -> Result<R, KernelError>,
    ) -> Result<R, KernelError> {
        let session = self
            .sessions
            .get(session_id)
            .map(|entry| Arc::clone(entry.value()))
            .ok_or_else(|| KernelError::UnknownSession(session_id.clone()))?;
        f(&session)
    }

    /// Resolve the tenant_id for a given session by walking its
    /// authenticated auth context into the enterprise identity's tenant
    /// claim. Returns `None` for single-tenant / anonymous sessions, for
    /// unknown session IDs, or when the caller did not supply one.
    ///
    /// Tenant_id is taken from the OAuth bearer's `enterprise_identity`
    /// (preferred, richer SSO claims) and falls back to the OAuth
    /// `federated_claims.tenant_id` when the IdP surfaces only the minimal
    /// federated claim set. Both sources originate from the authenticated
    /// session -- never from caller-provided request fields, because
    /// caller choice would defeat the isolation guarantee.
    pub(crate) fn resolve_tenant_id_for_session(
        &self,
        session_id: Option<&SessionId>,
    ) -> Option<String> {
        let id = session_id?;
        self.with_session(id, |session| {
            let auth_context = session.auth_context();
            Ok(extract_tenant_id_from_auth_context(&auth_context))
        })
        .ok()
        .flatten()
    }

    pub(crate) fn scope_receipt_tenant_id_for_request(
        &self,
        request_id: &str,
        tenant_id: Option<String>,
    ) -> ScopedKernelReceiptTenantId {
        let previous = match tenant_id {
            Some(tenant_id) => self
                .receipt_tenant_ids
                .insert(request_id.to_string(), tenant_id),
            None => self
                .receipt_tenant_ids
                .remove(request_id)
                .map(|(_, previous)| previous),
        };
        ScopedKernelReceiptTenantId {
            request_id: request_id.to_string(),
            tenant_ids: Arc::clone(&self.receipt_tenant_ids),
            previous,
        }
    }

    pub(crate) fn receipt_tenant_id_for_request(&self, request_id: Option<&str>) -> Option<String> {
        request_id.and_then(|request_id| {
            self.receipt_tenant_ids
                .get(request_id)
                .map(|entry| entry.value().clone())
        })
    }

    pub(crate) fn with_session_mut<R>(
        &self,
        session_id: &SessionId,
        f: impl FnOnce(&Arc<Session>) -> Result<R, KernelError>,
    ) -> Result<R, KernelError> {
        self.with_session(session_id, f)
    }

    pub(crate) fn with_budget_store<R>(
        &self,
        f: impl FnOnce(&dyn BudgetStore) -> Result<R, KernelError>,
    ) -> Result<R, KernelError> {
        let _guard = match self.budget_store_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(self.budget_store.as_ref())
    }

    pub(crate) fn with_revocation_store<R>(
        &self,
        f: impl FnOnce(&dyn RevocationStore) -> Result<R, KernelError>,
    ) -> Result<R, KernelError> {
        f(self.revocation_store.as_ref())
    }

    pub(crate) fn with_receipt_store<R>(
        &self,
        f: impl FnOnce(&dyn ReceiptStore) -> Result<R, KernelError>,
    ) -> Result<Option<R>, KernelError> {
        let Some(store) = self.receipt_store.as_ref() else {
            return Ok(None);
        };
        f(store.as_ref()).map(Some)
    }

    /// Flush any queued receipt writes to durable storage, bounded by `timeout`.
    ///
    /// A shutdown drain calls this to prove the commit-actor queue is empty
    /// before the process exits. `Ok(None)` means no receipt store is
    /// configured; a configured store's flush error is surfaced rather than
    /// swallowed, so a drain can exit non-zero when a receipt might not be
    /// durable.
    pub fn flush_receipt_writes_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> Result<Option<crate::ReceiptFlushReport>, KernelError> {
        self.with_receipt_store(|store| {
            store
                .flush_receipt_writes_with_timeout(timeout)
                .map_err(KernelError::from)
        })
    }

    pub fn new(config: KernelConfig) -> Self {
        info!("initializing Chio kernel");
        let authority_keypair = config.keypair.clone();
        let checkpoint_batch_size = config.checkpoint_batch_size;
        // Build the mpsc-backed signing-task handle. The handle clones the
        // signing keypair so the receipt-signing critical path no longer borrows
        // from `self.config.keypair` while the evaluate pipeline is mid-flight.
        // The tokio task is spawned LAZILY on first `signing_task.sign(_)` call
        // so `ChioKernel::new` remains constructible from sync contexts; by the
        // time any caller reaches `sign`, a tokio runtime is necessarily active.
        let signing_keypair = config.keypair.clone();
        // WYSIWYS: the async signer admits exactly what the inline
        // signer admits, then bounds queue memory by an AGGREGATE byte budget.
        //
        // - Per-request cap = 0 (unlimited). The inline `build_and_sign_receipt`
        //   path applies NO preimage cap, and `max_stream_total_bytes` limits
        //   *raw stream bytes*, a different unit from the *preimage bytes* a
        //   queued request holds (a stream receipt's preimage is the
        //   concatenation of 64-char per-chunk digests, not the raw payload).
        //   Comparing a preimage length against `max_stream_total_bytes` would
        //   falsely reject stream receipts the inline signer accepts (case 3),
        //   and a `max_stream_total_bytes == 0` ("unlimited") config must not
        //   collapse to a 1-byte cap (case 2). So we disable the per-request
        //   cap and let the aggregate budget bound memory instead.
        // - Aggregate budget tracks the configured stream/output max (saturating
        //   into `usize`), with a non-zero floor so a `0` ("unlimited") stream
        //   config still bounds queued memory at the documented default rather
        //   than growing unbounded (case 1). Always BOUNDED.
        let configured_stream_max =
            usize::try_from(config.max_stream_total_bytes).unwrap_or(usize::MAX);
        let signing_queued_budget = if configured_stream_max == 0 {
            signing_task::DEFAULT_MAX_SIGNING_QUEUED_BYTES
        } else {
            configured_stream_max
        };
        let signing_task = std::sync::Arc::new(
            signing_task::SigningTaskHandle::with_capacity_max_content_and_queued_bytes(
                signing_keypair,
                signing_task::DEFAULT_SIGNING_CHANNEL_CAPACITY,
                /* per-request cap */ 0,
                signing_queued_budget,
            ),
        );
        // Read the memory-budget-driven caps before `config` is moved into the
        // struct literal.
        let receipt_mirror_capacity = config.memory_budget_receipt_mirror_capacity();
        let federation_cache_capacity = config.memory_budget_federation_cache_capacity();
        let federation_cache_idle_ttl = config.memory_budget_federation_cache_idle_ttl_secs();
        let rss_soft_limit_bytes = config.memory_budget.rss_soft_limit_bytes;
        let rss_sample_interval_secs = config.memory_budget.rss_sample_interval_secs;
        // Build the bounded-structure gauges first so they can be shared between
        // each structure and the telemetry / registry readers.
        let receipt_mirror_gauge;
        let child_receipt_mirror_gauge;
        let federation_dual_receipts_gauge;
        let federation_dsse_envelopes_gauge;
        let mut kernel = Self {
            config,
            guards: Vec::new(),
            post_invocation_pipeline: crate::post_invocation::PostInvocationPipeline::new(),
            budget_store: Arc::new(InMemoryBudgetStore::new()),
            budget_store_lock: Mutex::new(()),
            revocation_store: Arc::new(InMemoryRevocationStore::new()),
            capability_authority: Box::new(LocalCapabilityAuthority::new(authority_keypair)),
            tool_servers: HashMap::new(),
            resource_providers: Vec::new(),
            prompt_providers: Vec::new(),
            sessions: DashMap::new(),
            receipt_log: {
                let gauge = chio_bounded::SizeGauge::new();
                receipt_mirror_gauge = gauge.clone();
                Mutex::new(ReceiptLog::with_capacity(receipt_mirror_capacity, gauge))
            },
            child_receipt_log: {
                let gauge = chio_bounded::SizeGauge::new();
                child_receipt_mirror_gauge = gauge.clone();
                Mutex::new(ChildReceiptLog::with_capacity(
                    receipt_mirror_capacity,
                    gauge,
                ))
            },
            receipt_mirror_gauge,
            child_receipt_mirror_gauge,
            receipt_store: None,
            receipt_store_write_lock: Mutex::new(()),
            payment_adapter: None,
            price_oracle: None,
            runtime_admission_hook: None,
            attestation_trust_policy: None,
            capability_crypto_floor: KernelCryptoFloor::AllowClassical,
            checkpoint_batch_size,
            checkpoint_seq_counter: AtomicU64::new(0),
            last_checkpoint_seq: AtomicU64::new(0),
            dpop_nonce_store: None,
            dpop_config: None,
            execution_nonce_config: None,
            execution_nonce_store: None,
            approval_replay_store: Some(dpop::DpopNonceStore::new(
                8192,
                std::time::Duration::from_secs(3600),
            )),
            emergency_stopped: AtomicBool::new(false),
            emergency_stopped_since: AtomicU64::new(0),
            emergency_stop_reason: ArcSwap::from_pointee(Option::<String>::None),
            memory_provenance: None,
            federation_peers: ArcSwap::from_pointee(HashMap::new()),
            capability_trust_roots: ArcSwap::from_pointee(HashMap::new()),
            capability_trust_roots_write_lock: Mutex::new(()),
            federation_cosigner: None,
            federation_dual_receipts: {
                let gauge = chio_bounded::SizeGauge::new();
                federation_dual_receipts_gauge = gauge.clone();
                Mutex::new(chio_bounded::BoundedMap::new(
                    federation_cache_capacity,
                    federation_cache_idle_ttl,
                    gauge,
                ))
            },
            federation_dual_receipts_gauge,
            federation_dsse_envelopes: {
                let gauge = chio_bounded::SizeGauge::new();
                federation_dsse_envelopes_gauge = gauge.clone();
                Mutex::new(chio_bounded::BoundedMap::new(
                    federation_cache_capacity,
                    federation_cache_idle_ttl,
                    gauge,
                ))
            },
            federation_dsse_envelopes_gauge,
            federation_artifact_store: None,
            receipt_tenant_ids: Arc::new(DashMap::new()),
            receipt_federation_admissions: Arc::new(DashMap::new()),
            federation_local_kernel_id: ArcSwap::from_pointee(Option::<String>::None),
            signing_task,
            settlement_observer: None,
            revocation_view: None,
            budget_registry: Mutex::new(chio_kernel_core::InMemoryBudgetRegistry::new()),
            rss_shed: Arc::new(AtomicBool::new(false)),
            rss_sampler: None,
        };
        // Start the RSS soft-ceiling sampler only when a limit is configured; with
        // no limit set, no thread is spawned.
        if let Some(limit) = rss_soft_limit_bytes {
            kernel.rss_sampler = Some(kernel_struct::RssSamplerHandle::spawn(
                Arc::clone(&kernel.rss_shed),
                limit,
                rss_sample_interval_secs,
            ));
        }
        kernel
    }

    pub(crate) fn ensure_federated_receipt_persistence_ready(
        &self,
        remote_kernel_id: Option<&str>,
    ) -> Result<(), KernelError> {
        if remote_kernel_id.is_none() {
            return Ok(());
        }
        if self.receipt_store.is_none() {
            return Err(KernelError::Internal(
                "federated receipt persistence unavailable: no durable receipt store configured"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn ensure_receipt_persistence_ready(&self) -> Result<(), KernelError> {
        if self.receipt_store.is_some() || self.config.allow_ephemeral_receipt_log {
            return Ok(());
        }
        Err(KernelError::Internal(
            "durable receipt persistence unavailable: no receipt store configured".to_string(),
        ))
    }

    pub(crate) fn scope_receipt_federation_admission_for_request(
        &self,
        request_id: &str,
        admission: ReceiptFederationAdmission,
    ) -> ScopedKernelReceiptFederationAdmission {
        let previous = self
            .receipt_federation_admissions
            .insert(request_id.to_string(), admission);
        ScopedKernelReceiptFederationAdmission {
            request_id: request_id.to_string(),
            admissions: Arc::clone(&self.receipt_federation_admissions),
            previous,
        }
    }

    pub(crate) fn receipt_federation_admission_for_request(
        &self,
        request_id: &str,
        remote_kernel_id: Option<&str>,
    ) -> Option<ReceiptFederationAdmission> {
        let admission = self
            .receipt_federation_admissions
            .get(request_id)
            .map(|entry| entry.value().clone())?;
        if admission.remote_kernel_id.as_deref() == remote_kernel_id {
            Some(admission)
        } else {
            None
        }
    }

    /// Resolve and snapshot federation receipt admission at the boundary.
    /// The returned snapshot must be carried through receipt persistence and
    /// federation cosigning; persistence must not re-resolve peer freshness
    /// after the tool has already executed.
    pub(crate) fn kernel_receipt_admission_for_remote(
        &self,
        remote_kernel_id: Option<&str>,
        now: u64,
    ) -> Result<ReceiptFederationAdmission, KernelError> {
        if let Some(remote) = remote_kernel_id {
            if let Some(peer) = self.federation_peer(remote, now) {
                return Ok(ReceiptFederationAdmission {
                    remote_kernel_id: Some(remote.to_string()),
                    peer: Some(peer),
                });
            }
            return Err(KernelError::Internal(format!(
                "named federation peer {remote} is not pinned fresh"
            )));
        }
        Ok(ReceiptFederationAdmission {
            remote_kernel_id: None,
            peer: None,
        })
    }

    /// Install (or replace) the recursive-delegation oracle handle.
    /// Default deployments leave this `None` and rely on the compatibility
    /// per-row `RevocationStore` lookup. Installing a
    /// [`chio_kernel_core::RevocationView`] here causes the verifier to
    /// consult it on every delegated dispatch.
    ///
    /// The handle is `Arc`-shared so federation gossip can install
    /// monotone snapshot updates without holding a kernel mutex.
    pub fn set_revocation_view(&mut self, view: std::sync::Arc<chio_kernel_core::RevocationView>) {
        self.revocation_view = Some(view);
    }

    /// Borrow the currently-installed revocation view, if any.
    #[must_use]
    pub fn revocation_view(&self) -> Option<&std::sync::Arc<chio_kernel_core::RevocationView>> {
        self.revocation_view.as_ref()
    }

    /// Borrow the kernel's mpsc-backed signing-task handle.
    ///
    /// Internal callers submit `ChioReceiptBody` payloads through this handle
    /// and `.await` the signed `ChioReceipt`. The underlying tokio task is
    /// spawned lazily on the first call.
    ///
    /// Not exposed publicly: callers should go through
    /// [`Self::sign_receipt_via_channel`] or the `ToolEvaluator` trait so the
    /// channel boundary stays an implementation detail of the kernel crate.
    /// Crash-recovery tests reach this directly.
    #[allow(dead_code)]
    pub(crate) fn signing_task_handle(&self) -> &signing_task::SigningTaskHandle {
        &self.signing_task
    }

    /// Sign a [`ChioReceiptBody`] off the kernel critical path via the
    /// mpsc-backed signing task.
    ///
    /// Producers `.await` on bounded backpressure rather than on a
    /// receipt-log mutex. Returns
    /// `Err(KernelError::ReceiptSigningFailed)` if the signing step
    /// itself rejected the body (e.g. the body's `kernel_key` does not
    /// match the kernel's signing public key) and
    /// `Err(KernelError::Internal)` if the signing task is no longer
    /// running.
    ///
    /// This method is async because it `.await`s on the channel send
    /// (backpressure) and on the oneshot reply. The caller must run
    /// inside a tokio runtime; every kernel-internal call site already
    /// does (the `ToolEvaluator` trait methods are async, and so is
    /// the public `evaluate_tool_call` entrypoint).
    ///
    /// `canonical_content` is the exact byte preimage `body.content_hash` was
    /// derived from. The signing task recomputes `sha256_hex(canonical_content)`
    /// inside the trust boundary and refuses to sign on mismatch (WYSIWYS,
    /// ), so this channel path is as fail-closed as the inline
    /// `build_and_sign_receipt` path.
    pub async fn sign_receipt_via_channel(
        &self,
        body: ChioReceiptBody,
        canonical_content: Vec<u8>,
    ) -> Result<ChioReceipt, KernelError> {
        self.signing_task.sign(body, canonical_content).await
    }

    /// Drain the in-flight signing-task queue and join the task. After this
    /// call, every signing request that successfully `.send().await`-ed before
    /// shutdown has been signed and replied to; new sends surface
    /// `KernelError::Internal`.
    ///
    /// Idempotent: safe to call more than once. Safe to call on a
    /// kernel whose signing task was never spawned (no signing
    /// happened); in that case shutdown is a no-op.
    ///
    /// Note: shutdown does NOT mark the kernel as terminally stopped
    /// for other paths (capability validation, guard pipeline, store
    /// lookups). Operators that want a hard stop should call
    /// [`Self::emergency_stop`] in addition.
    pub async fn shutdown(&self) {
        self.signing_task.shutdown().await;
    }

    pub fn set_receipt_store(
        &mut self,
        receipt_store: Box<dyn ReceiptStore>,
    ) -> Result<(), KernelError> {
        self.set_receipt_store_handle(Arc::from(receipt_store))
    }

    pub fn set_receipt_store_handle(
        &mut self,
        receipt_store: Arc<dyn ReceiptStore>,
    ) -> Result<(), KernelError> {
        self.try_set_receipt_store_handle(receipt_store)
    }

    pub fn try_set_receipt_store_handle(
        &mut self,
        receipt_store: Arc<dyn ReceiptStore>,
    ) -> Result<(), KernelError> {
        match receipt_store.load_latest_checkpoint() {
            Ok(Some(checkpoint)) => {
                self.checkpoint_seq_counter
                    .store(checkpoint.body.checkpoint_seq, Ordering::SeqCst);
                self.last_checkpoint_seq
                    .store(checkpoint.body.batch_end_seq, Ordering::SeqCst);
            }
            Ok(None) => {
                self.checkpoint_seq_counter.store(0, Ordering::SeqCst);
                self.last_checkpoint_seq.store(0, Ordering::SeqCst);
            }
            Err(error) => {
                return Err(KernelError::Internal(format!(
                    "failed to hydrate checkpoint counters from receipt store: {error}"
                )));
            }
        }
        // Honor disabled checkpointing: KernelConfig
        // documents `checkpoint_batch_size = 0` as DISABLING automatic
        // checkpointing (non-web3 deployments). Only require a background signer
        // when checkpointing is enabled (batch_size > 0); with 0 the store
        // attaches with no checkpoint machinery. Web3-enabled deployments that
        // MUST checkpoint are separately guarded by
        // `validate_web3_evidence_prerequisites`, which rejects batch_size == 0.
        if self.checkpoint_batch_size > 0 && receipt_store.supports_kernel_signed_checkpoints() {
            let background_enabled = receipt_store
                .enable_background_checkpoints(
                    self.config.keypair.clone(),
                    self.checkpoint_batch_size,
                )
                .map_err(|error| {
                    KernelError::Internal(format!(
                        "failed to enable background receipt checkpoints: {error}"
                    ))
                })?;
            // Fail-closed: a store that claims checkpoint capability but did
            // not install a background signer (default hook returns
            // `Ok(false)`) would append forever without producing kernel-signed
            // Web3 checkpoints now that the synchronous trigger is gone. Reject
            // the attach rather than serve silently-checkpointless.
            if !background_enabled {
                return Err(KernelError::Internal(
                    "receipt store reports kernel-signed checkpoint support but did not install a \
                     background checkpoint signer; refusing to attach a store that would append \
                     without producing checkpoints"
                        .to_string(),
                ));
            }
        }
        self.receipt_store = Some(receipt_store);
        Ok(())
    }

    pub fn set_payment_adapter(&mut self, payment_adapter: Box<dyn PaymentAdapter>) {
        self.payment_adapter = Some(payment_adapter);
    }

    pub fn set_price_oracle(&mut self, price_oracle: Box<dyn PriceOracle>) {
        self.price_oracle = Some(price_oracle);
    }

    pub fn set_attestation_trust_policy(
        &mut self,
        attestation_trust_policy: AttestationTrustPolicy,
    ) {
        self.attestation_trust_policy = Some(attestation_trust_policy);
    }

    pub fn set_revocation_store(&mut self, revocation_store: Box<dyn RevocationStore>) {
        self.set_revocation_store_handle(Arc::from(revocation_store));
    }

    pub fn set_revocation_store_handle(&mut self, revocation_store: Arc<dyn RevocationStore>) {
        self.revocation_store = revocation_store;
    }

    pub fn set_capability_authority(&mut self, capability_authority: Box<dyn CapabilityAuthority>) {
        self.capability_authority = capability_authority;
    }

    pub fn set_budget_store(&mut self, budget_store: Box<dyn BudgetStore>) {
        self.set_budget_store_handle(Arc::from(budget_store));
    }

    pub fn set_budget_store_handle(&mut self, budget_store: Arc<dyn BudgetStore>) {
        self.budget_store = budget_store;
    }

    pub fn set_post_invocation_pipeline(
        &mut self,
        pipeline: crate::post_invocation::PostInvocationPipeline,
    ) {
        self.post_invocation_pipeline = pipeline;
    }

    pub fn add_post_invocation_hook(
        &mut self,
        hook: Box<dyn crate::post_invocation::PostInvocationHook>,
    ) {
        self.post_invocation_pipeline.add(hook);
    }

    /// Install a settlement hook that runs after each receipt is signed
    /// and persisted. Settlement is strictly an observer relative to
    /// receipt bytes; the hook MUST NOT mutate the receipt store and
    /// MUST NOT block the dispatch path on its own latency. Hook
    /// failures are surfaced through
    /// [`Self::run_settlement_observer`]'s return value and are routed
    /// through the retry/dead-letter machinery.
    pub fn set_settlement_observer(
        &mut self,
        hook: std::sync::Arc<dyn chio_settle::SettlementHook>,
    ) {
        self.settlement_observer = Some(hook);
    }

    /// Return a clone of the active settlement observer, or `None` when
    /// no hook has been installed. Useful for integration tests that
    /// want to assert observer state directly.
    #[must_use]
    pub fn settlement_observer(&self) -> Option<std::sync::Arc<dyn chio_settle::SettlementHook>> {
        self.settlement_observer.clone()
    }

    /// Invoke the registered settlement hook against a
    /// freshly signed receipt. The receipt is observer-only relative
    /// to this call: callers MUST pass a receipt that has already been
    /// signed and stored, and the returned status NEVER feeds back
    /// into the dispatch path.
    #[must_use]
    pub fn run_settlement_observer(
        &self,
        receipt: &chio_core::receipt::body::ChioReceipt,
    ) -> settlement_observer::SettlementObserverStatus {
        settlement_observer::run_observer(
            self.settlement_observer.as_ref(),
            receipt,
            &[self.public_key()],
        )
    }

    /// Install a memory-provenance chain.
    ///
    /// Once installed, every governed `MemoryWrite`-shaped tool call
    /// appends an entry to the chain after the allow receipt is
    /// signed. A chain-store failure on that path is fatal: the call
    /// surfaces `KernelError::Internal(...)` so operators can detect
    /// and repair the drift rather than silently shipping a write
    /// without provenance evidence.
    ///
    /// Every `MemoryRead`-shaped tool call looks the entry up by
    /// `(store, key)` and attaches the result to the receipt as
    /// `memory_provenance` evidence metadata. Reads with no chain
    /// entry or with a tampered chain surface as
    /// [`crate::memory_provenance::ProvenanceVerification::Unverified`]
    /// so the receipt unambiguously records the gap.
    pub fn set_memory_provenance_store(
        &mut self,
        store: Arc<dyn crate::memory_provenance::MemoryProvenanceStore>,
    ) {
        self.memory_provenance = Some(store);
    }

    /// Return a clone of the active memory-provenance store handle,
    /// or `None` when no provenance chain has been installed.
    ///
    /// Useful for integration tests that want to assert on the chain
    /// state directly after driving `evaluate_tool_call`.
    #[must_use]
    pub fn memory_provenance_store(
        &self,
    ) -> Option<Arc<dyn crate::memory_provenance::MemoryProvenanceStore>> {
        self.memory_provenance.as_ref().map(Arc::clone)
    }

    /// Install a set of [`chio_federation::trust_establishment::FederationPeer`]s
    /// this kernel trusts for bilateral co-signing. Overwrites any
    /// previously declared set. Callers typically obtain these peers
    /// from [`chio_federation::trust_establishment::KernelTrustExchange::accept_envelope`]
    /// after a successful mTLS handshake.
    ///
    /// Builder-style so deployments can chain `.with_federation_peers(...)`
    /// onto `ChioKernel::new(config)`.
    #[must_use]
    pub fn with_federation_peers(
        self,
        peers: Vec<chio_federation::trust_establishment::FederationPeer>,
    ) -> Self {
        let mut next = HashMap::new();
        for peer in peers {
            next.insert(peer.kernel_id.clone(), peer);
        }
        self.federation_peers.store(Arc::new(next));
        self
    }

    /// Builder-style so deployments can chain
    /// `.with_capability_trust_roots(...)` onto `ChioKernel::new(config)`.
    #[must_use]
    pub fn with_capability_trust_roots(
        self,
        roots: Vec<(
            chio_core::PublicKey,
            chio_core::capability::attenuation::ScopeHash,
        )>,
    ) -> Self {
        {
            let _guard = self
                .capability_trust_roots_write_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut next: HashMap<String, chio_core::capability::attenuation::ScopeHash> =
                HashMap::new();
            for (issuer, root) in roots {
                next.insert(issuer.to_hex(), root);
            }
            self.capability_trust_roots.store(Arc::new(next));
        }
        self
    }

    /// Install or update a single capability trust-root entry without
    /// requiring builder-style construction. Returns the previous root
    /// hash for that issuer, if any.
    pub fn set_capability_trust_root(
        &self,
        issuer: chio_core::PublicKey,
        root: chio_core::capability::attenuation::ScopeHash,
    ) -> Option<chio_core::capability::attenuation::ScopeHash> {
        let _guard = self
            .capability_trust_roots_write_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = self.capability_trust_roots.load_full();
        let mut next: HashMap<String, chio_core::capability::attenuation::ScopeHash> =
            (*current).clone();
        let prev = next.insert(issuer.to_hex(), root);
        self.capability_trust_roots.store(Arc::new(next));
        prev
    }

    /// Snapshot the currently registered capability trust-root registry.
    /// Hot-path callers should prefer the resolver returned by
    /// `capability_trust_root_resolver_snapshot`.
    pub fn capability_trust_roots_snapshot(
        &self,
    ) -> HashMap<String, chio_core::capability::attenuation::ScopeHash> {
        (*self.capability_trust_roots.load_full()).clone()
    }

    /// Build an owned snapshot of the capability trust-root registry
    /// suitable for use as a `chio_kernel_core::TrustRootResolver`. The
    /// returned closure captures a frozen snapshot so concurrent
    /// rotations cannot tear an in-flight verification.
    pub(crate) fn capability_trust_root_resolver_snapshot(
        &self,
    ) -> impl Fn(&chio_core::PublicKey) -> Option<chio_core::capability::attenuation::ScopeHash>
           + Send
           + Sync
           + 'static {
        let snapshot: Arc<HashMap<String, chio_core::capability::attenuation::ScopeHash>> =
            self.capability_trust_roots.load_full();
        move |issuer: &chio_core::PublicKey| -> Option<chio_core::capability::attenuation::ScopeHash> {
            snapshot.get(&issuer.to_hex()).cloned()
        }
    }

    pub(crate) fn capability_negotiation_for_remote(
        &self,
        remote_kernel_id: Option<&str>,
        now: u64,
    ) -> Result<chio_core::capability::features::CapabilityNegotiation, String> {
        if let Some(remote) = remote_kernel_id {
            if let Some(peer) = self.federation_peer(remote, now) {
                return Ok(peer.capabilities);
            }
            return Err(format!(
                "no fresh federation peer negotiation profile pinned for remote kernel {remote}"
            ));
        }
        Ok(chio_core::capability::features::CapabilityNegotiation::t1_default())
    }

    /// Install the bilateral cosigner responsible for
    /// contacting a peer kernel to obtain a co-signature. Production
    /// deployments plug in an mTLS-backed RPC client; tests can use
    /// [`chio_federation::bilateral::InProcessCoSigner`].
    pub fn set_federation_cosigner(
        &mut self,
        cosigner: Arc<dyn chio_federation::bilateral::BilateralCoSigningProtocol>,
    ) {
        self.federation_cosigner = Some(cosigner);
    }

    /// Install a durable [`crate::federation_artifact_store::FederationArtifactStore`]
    /// for bilateral co-sign artifacts.
    ///
    /// When set, [`Self::apply_federation_cosign`] writes each
    /// `DualSignedReceipt` / `DsseEnvelope` through to the store BEFORE inserting
    /// it into the bounded in-memory caches, and [`Self::dual_signed_receipt`] /
    /// [`Self::federation_dsse_envelope`] fall back to the store on a cache miss.
    /// This closes the evidence-loss window where a federated deployment
    /// producing more than `federation_cache_capacity` receipts would drop
    /// evicted co-sign artifacts while the durable receipt store keeps only the
    /// base receipt. Without a store installed, evicted co-sign artifacts are
    /// lossy by policy (the bounded caches drop-oldest at capacity).
    ///
    /// A deployment requiring durable bilateral evidence installs a
    /// database-backed impl; the bundled
    /// [`crate::federation_artifact_store::InMemoryFederationArtifactStore`] is a
    /// capped, idle-swept reference impl and test double.
    pub fn set_federation_artifact_store(
        &mut self,
        store: Arc<dyn crate::federation_artifact_store::FederationArtifactStore>,
    ) {
        self.federation_artifact_store = Some(store);
    }

    /// Advertise this kernel's stable identifier as seen by
    /// remote federation peers. When unset, the hex encoding of the
    /// signing public key is used. Setting this is recommended in
    /// production so receipts reference DNS names rather than raw keys.
    pub fn set_federation_local_kernel_id(&self, kernel_id: impl Into<String>) {
        self.federation_local_kernel_id
            .store(Arc::new(Some(kernel_id.into())));
    }

    /// Resolve the active federation peer for
    /// `remote_kernel_id`, refusing stale pins fail-closed.
    pub fn federation_peer(
        &self,
        remote_kernel_id: &str,
        now: u64,
    ) -> Option<chio_federation::trust_establishment::FederationPeer> {
        let peers = self.federation_peers.load();
        let peer = peers.get(remote_kernel_id)?.clone();
        if peer.is_fresh(now) {
            Some(peer)
        } else {
            None
        }
    }

    /// Snapshot the currently-pinned federation peer set.
    pub fn federation_peers_snapshot(
        &self,
    ) -> Vec<chio_federation::trust_establishment::FederationPeer> {
        self.federation_peers.load().values().cloned().collect()
    }

    /// Look up a dual-signed receipt by the underlying
    /// [`chio_core::receipt::body::ChioReceipt`] id. Returns `None` when the
    /// receipt did not cross a federation boundary or when the
    /// co-signing hook has not yet produced a dual-signed artifact
    /// for it.
    pub fn dual_signed_receipt(
        &self,
        receipt_id: &str,
    ) -> Option<chio_federation::bilateral::DualSignedReceipt> {
        let now = current_unix_timestamp();
        {
            let mut cache = match self.federation_dual_receipts.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(hit) = cache.get(&receipt_id.to_string(), now) {
                return Some(hit.clone());
            }
        }
        self.federation_artifact_store.as_ref().and_then(|store| {
            // A store READ error is not an admission gate (writes fail closed via
            // `?` elsewhere), but collapsing Err to None silently makes a transient
            // read failure indistinguishable from an absent artifact. Log it so the
            // read-through fallback is observable.
            match store.get_dual_signed(receipt_id) {
                Ok(hit) => hit,
                Err(error) => {
                    debug!(
                        receipt_id = %receipt_id,
                        reason = %redacted!(&error.to_string()),
                        "federation artifact-store dual-signed read failed; treating as absent"
                    );
                    None
                }
            }
        })
    }

    pub fn federation_dsse_envelope(
        &self,
        receipt_id: &str,
    ) -> Option<chio_federation::bilateral_dsse::DsseEnvelope> {
        let now = current_unix_timestamp();
        {
            let mut cache = match self.federation_dsse_envelopes.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(hit) = cache.get(&receipt_id.to_string(), now) {
                return Some(hit.clone());
            }
        }
        self.federation_artifact_store.as_ref().and_then(|store| {
            // As with the dual-signed read above: log a swallowed store read error
            // so a transient failure is not silently reported as an absent DSSE
            // envelope.
            match store.get_dsse(receipt_id) {
                Ok(hit) => hit,
                Err(error) => {
                    debug!(
                        receipt_id = %receipt_id,
                        reason = %redacted!(&error.to_string()),
                        "federation artifact-store DSSE read failed; treating as absent"
                    );
                    None
                }
            }
        })
    }

    /// Local kernel identifier used in bilateral co-signing. Falls back
    /// to the hex encoding of the signing public key.
    pub fn federation_local_kernel_id(&self) -> String {
        if let Some(id) = self.federation_local_kernel_id.load_full().as_ref() {
            return id.clone();
        }
        self.config.keypair.public_key().to_hex()
    }

    fn treaty_dsse_extensions_from_receipt_metadata(
        &self,
        receipt: &chio_core::receipt::body::ChioReceipt,
    ) -> Result<Option<chio_federation::bilateral_dsse::BilateralPredicateExtensions>, KernelError>
    {
        let Some(metadata) = receipt.metadata.as_ref() else {
            return Ok(None);
        };
        let Some(value) = metadata
            .get("chio_runtime")
            .and_then(|runtime| runtime.get("federation_treaty_dsse"))
        else {
            return Ok(None);
        };
        let material: KernelFederationTreatyDsseMetadata = serde_json::from_value(value.clone())
            .map_err(|error| {
                KernelError::Internal(format!(
                    "federation treaty DSSE metadata is invalid: {error}"
                ))
            })?;
        let consistency_model = material.consistency_model.clone().ok_or_else(|| {
            KernelError::Internal(
                "federation treaty DSSE consistency model is missing from runtime material"
                    .to_string(),
            )
        })?;
        if consistency_model != material.treaty_binding_ref.consistency_model {
            return Err(KernelError::Internal(
                "federation treaty DSSE consistency model does not match treaty binding"
                    .to_string(),
            ));
        }
        let mut treaty_binding_ref = material.treaty_binding_ref;
        if treaty_binding_ref.request_sha256 != receipt.action.parameter_hash {
            return Err(KernelError::Internal(
                "federation treaty DSSE request hash does not match receipt action hash"
                    .to_string(),
            ));
        }
        treaty_binding_ref.outcome_sha256 = receipt.content_hash.clone();
        treaty_binding_ref.remote_receipt_sha256 = chio_core::crypto::sha256_hex(
            &chio_core::canonical::canonical_json_bytes(receipt).map_err(|error| {
                KernelError::Internal(format!(
                    "federation treaty DSSE receipt canonicalization failed: {error}"
                ))
            })?,
        );
        Ok(Some(
            chio_federation::bilateral_dsse::BilateralPredicateExtensions {
                capability_lease_ref: Some(material.capability_lease_ref),
                policy_evaluation_summary: Some(material.policy_evaluation_summary),
                governance_receipt_ref: material.governance_receipt_ref,
                consistency_anchor: material.consistency_anchor,
                consistency_model: Some(consistency_model),
                cross_org_visibility: material.cross_org_visibility,
                treaty_binding_ref: Some(treaty_binding_ref),
            },
        ))
    }

    /// Post-sign hook. Invoked immediately after
    /// [`Self::build_and_sign_receipt`] so the local (tool-host)
    /// signature has already landed in the `ChioReceipt`. When
    /// `federated_origin_kernel_id` is set and the admission-time peer
    /// snapshot is available, this dispatches the receipt to the
    /// cosigner, assembles a [`chio_federation::bilateral::DualSignedReceipt`],
    /// and stashes it for retrieval via [`Self::dual_signed_receipt`].
    ///
    /// Fail-closed: any error from peer resolution or the cosigner is
    /// surfaced as a [`KernelError::Internal`] so operators see the
    /// federation drift rather than silently shipping a receipt without
    /// the remote signature. Production evaluate paths pass the
    /// admission-time snapshot; direct record callers still get a
    /// fresh-peer fallback. Non-federated requests (`None` origin) are a
    /// no-op.
    pub(crate) fn apply_federation_cosign(
        &self,
        request: &crate::runtime::ToolCallRequest,
        receipt: &chio_core::receipt::body::ChioReceipt,
        admitted_peer: Option<&chio_federation::trust_establishment::FederationPeer>,
    ) -> Result<(), KernelError> {
        let Some(origin_kernel_id) = request.federated_origin_kernel_id.as_ref() else {
            return Ok(());
        };
        let Some(cosigner) = self.federation_cosigner.as_ref() else {
            return Err(KernelError::Internal(format!(
                "federation cosigner missing for request {request_id} bound to origin kernel {origin_kernel_id}",
                request_id = request.request_id,
            )));
        };
        let peer = match admitted_peer {
            Some(peer) if peer.kernel_id == *origin_kernel_id => peer.clone(),
            _ => {
                let now = current_unix_timestamp();
                self.federation_peer(origin_kernel_id, now).ok_or_else(|| {
                    KernelError::Internal(format!(
                        "federation peer {origin_kernel_id} is not pinned fresh and no admission-time peer snapshot is in scope"
                    ))
                })?
            }
        };

        let local_kernel_id = self.federation_local_kernel_id();
        let extensions = match self.treaty_dsse_extensions_from_receipt_metadata(receipt)? {
            Some(extensions) => extensions,
            None => {
                // A federated request rejected before runtime treaty admission
                // ran (capability verification, time bounds, revocation, subject
                // binding) never produced the bilateral treaty material the
                // dual-sign path binds, and dispatched no cross-org outcome to
                // co-sign. Record such a deny single-signed, with no dual-signed
                // or DSSE artifact, matching the pre-dispatch denial contract in
                // federated_request_without_receipt_store_denies_before_dispatch_or_cosign.
                // An allowed federated outcome always carries treaty material, so
                // any non-deny receipt still fails closed here.
                if matches!(
                    receipt.decision,
                    Some(chio_core::receipt::decision::Decision::Deny { .. })
                ) {
                    return Ok(());
                }
                return Err(KernelError::Internal(
                    "federation runtime treaty material missing; refusing treaty-bound DSSE"
                        .to_string(),
                ));
            }
        };
        let dual = chio_federation::bilateral::co_sign_with_origin(
            origin_kernel_id,
            &peer.public_key,
            &local_kernel_id,
            &self.config.keypair,
            receipt.clone(),
            cosigner.as_ref(),
        )
        .map_err(|e| KernelError::Internal(format!("bilateral co-sign failed: {e}")))?;
        let timestamp_unix_ms = current_unix_timestamp().saturating_mul(1000);
        let dsse_envelope =
            chio_federation::bilateral_dsse::sign_chio_bilateral_dsse_envelope_with_cosigner(
                receipt,
                &peer.public_key,
                &self.config.keypair,
                origin_kernel_id,
                &local_kernel_id,
                &request.tool_name,
                timestamp_unix_ms,
                extensions,
                cosigner.as_ref(),
            )
            .map_err(|e| KernelError::Internal(format!("bilateral DSSE co-sign failed: {e}")))?;

        // Write through to the artifact store (if one is installed via
        // set_federation_artifact_store) BEFORE the bounded caches. An entry
        // evicted from a cache is only guaranteed resolvable when the store
        // DURABLY retains it: a bounded in-memory store can evict the same id the
        // caches did, so only a store that reports itself durable suppresses the
        // evidence-loss signal below.
        let durable_store_installed = self
            .federation_artifact_store
            .as_ref()
            .is_some_and(|store| store.is_durable());
        if let Some(store) = self.federation_artifact_store.as_ref() {
            store.put_dual_signed(&receipt.id, &dual)?;
            store.put_dsse(&receipt.id, &dsse_envelope)?;
        }
        let now = current_unix_timestamp();
        {
            let mut cache = match self.federation_dual_receipts.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            // An evicted entry survives only through a durable store. Without one
            // the drop is lossy by policy (bounded drop-oldest); log it so the
            // evidence loss is explicit for operators.
            if cache.insert(receipt.id.clone(), dual, now).is_some() && !durable_store_installed {
                debug!(
                    request_id = %request.request_id,
                    "dropping an evicted dual-signed co-sign artifact: bounded federation cache is full and no durable FederationArtifactStore is installed"
                );
            }
        }
        {
            let mut cache = match self.federation_dsse_envelopes.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if cache
                .insert(receipt.id.clone(), dsse_envelope, now)
                .is_some()
                && !durable_store_installed
            {
                debug!(
                    request_id = %request.request_id,
                    "dropping an evicted co-sign DSSE envelope: bounded federation cache is full and no durable FederationArtifactStore is installed"
                );
            }
        }
        Ok(())
    }

    /// Engage the emergency kill switch.
    ///
    /// After this call, every `evaluate_tool_call*` path returns a signed
    /// deny receipt with reason `"kernel emergency stop active"` before
    /// touching capability validation or the guard pipeline. The kernel
    /// remains running so orchestrators and health probes see a live
    /// process; it is inert.
    ///
    /// The active capability set is NOT purged from the revocation store:
    /// the current `RevocationStore` trait has no bulk revoke API and
    /// capability expiration plus the kill-switch flag together
    /// cover this surface. When a future revision adds `revoke_all`,
    /// this method should call it; until then, capability revocation is
    /// delegated to natural expiration.
    pub fn emergency_stop(&self, reason: &str) -> Result<(), KernelError> {
        let now_unix_ms = current_unix_timestamp_ms();
        let now = now_unix_ms / 1000;
        // Record the timestamp first so any concurrent reader that observes
        // `emergency_stopped == true` sees a non-zero `since` value.
        self.emergency_stopped_since.store(now, Ordering::SeqCst);
        self.emergency_stop_reason
            .store(Arc::new(Some(reason.to_string())));
        self.emergency_stopped.store(true, Ordering::SeqCst);

        warn!(
            reason = %redacted!(reason),
            timestamp = now,
            "emergency stop engaged -- all evaluations will be denied"
        );
        Ok(())
    }

    /// Disengage the emergency kill switch and resume normal operation.
    ///
    /// Subsequent `evaluate_tool_call*` calls follow the full validation
    /// pipeline again. Capabilities that naturally expired while the
    /// kernel was stopped remain expired; the kill switch does not
    /// retroactively grant anything.
    pub fn emergency_resume(&self) -> Result<(), KernelError> {
        self.emergency_stopped.store(false, Ordering::SeqCst);
        self.emergency_stopped_since.store(0, Ordering::SeqCst);

        warn!("emergency stop disengaged -- evaluations will resume");

        self.emergency_stop_reason
            .store(Arc::new(Option::<String>::None));
        Ok(())
    }

    /// Return `true` when the emergency kill switch is engaged.
    #[must_use]
    pub fn is_emergency_stopped(&self) -> bool {
        self.emergency_stopped.load(Ordering::SeqCst)
    }

    /// Return `true` when the RSS soft-ceiling sampler has flagged that process
    /// RSS crossed `memory_budget.rss_soft_limit_bytes`. A single relaxed atomic
    /// load on the admission fast path.
    #[must_use]
    pub fn is_rss_shedding(&self) -> bool {
        self.rss_shed.load(Ordering::Relaxed)
    }

    /// Enumerate each long-lived bounded structure's telemetry label and its
    /// current live entry count. This is the registry the size-metric convention
    /// and the soak harness read; adding a
    /// new long-lived collection without a gauge here fails the registry test.
    #[must_use]
    pub fn bounded_structure_gauges(&self) -> Vec<(&'static str, usize)> {
        vec![
            ("receipt_mirror", self.receipt_mirror_gauge.get()),
            (
                "child_receipt_mirror",
                self.child_receipt_mirror_gauge.get(),
            ),
            (
                "federation_dual_receipts",
                self.federation_dual_receipts_gauge.get(),
            ),
            (
                "federation_dsse_envelopes",
                self.federation_dsse_envelopes_gauge.get(),
            ),
        ]
    }

    #[cfg(test)]
    pub(crate) fn set_rss_shed_for_test(&self, on: bool) {
        self.rss_shed.store(on, Ordering::Relaxed);
    }

    /// Return the unix timestamp (seconds) at which the kill switch was
    /// engaged, or `None` when the kernel is currently running normally.
    #[must_use]
    pub fn emergency_stopped_since(&self) -> Option<u64> {
        if !self.is_emergency_stopped() {
            return None;
        }
        let since = self.emergency_stopped_since.load(Ordering::SeqCst);
        if since == 0 {
            None
        } else {
            Some(since)
        }
    }

    /// Return the operator-supplied reason for the current emergency stop,
    /// or `None` when the kernel is running normally.
    #[must_use]
    pub fn emergency_stop_reason(&self) -> Option<String> {
        if !self.is_emergency_stopped() {
            return None;
        }
        self.emergency_stop_reason.load_full().as_ref().clone()
    }

    /// Install a DPoP nonce replay store and verification config.
    ///
    /// Once installed, any invocation whose matched grant has `dpop_required == Some(true)`
    /// must carry a valid `DpopProof` on the `ToolCallRequest`. Requests that lack a proof
    /// or whose proof fails verification are denied fail-closed.
    pub fn set_dpop_store(&mut self, nonce_store: dpop::DpopNonceStore, config: dpop::DpopConfig) {
        self.dpop_nonce_store = Some(nonce_store);
        self.dpop_config = Some(config);
    }

    /// Install an execution-nonce config and replay store.
    ///
    /// Once installed, every `Verdict::Allow` carries a short-lived signed
    /// nonce on `ToolCallResponse::execution_nonce`. Tool servers re-present
    /// that nonce via `ToolCallRequest::execution_nonce` and the kernel's
    /// `verify_presented_execution_nonce` helper (or directly via the
    /// free-standing `verify_execution_nonce` function) before executing.
    ///
    /// Set `config.require_nonce = true` to put the kernel into strict mode:
    /// any call that reaches `require_presented_execution_nonce` without a
    /// nonce is denied. When `require_nonce == false` the feature is opt-in
    /// per tool server and non-nonce callers continue to work (backward
    /// compatibility).
    pub fn set_execution_nonce_store(
        &mut self,
        config: crate::execution_nonce::ExecutionNonceConfig,
        store: Box<dyn crate::execution_nonce::ExecutionNonceStore>,
    ) {
        self.execution_nonce_config = Some(config);
        self.execution_nonce_store = Some(store);
    }

    /// Returns `true` when execution-nonce strict mode is active.
    ///
    /// Strict mode requires every presented tool call to carry a fresh,
    /// valid, single-use nonce. When `false` the kernel is either not
    /// minting nonces at all (no config installed) or is in opt-in mode
    /// where tool servers can verify presented nonces but non-nonce calls
    /// are not outright rejected.
    #[must_use]
    pub fn execution_nonce_required(&self) -> bool {
        self.execution_nonce_config
            .as_ref()
            .is_some_and(|cfg| cfg.require_nonce)
    }

    /// Mint a signed execution nonce for an allow verdict.
    ///
    /// Returns `Ok(None)` when no config is installed (nonces disabled) or
    /// when this request already presented a nonce for execution. Otherwise
    /// returns `Ok(Some(nonce))` once configured. The nonce binding is
    /// derived from the capability subject, capability ID, target server/tool,
    /// and the canonical parameter hash embedded in the just-signed allow
    /// receipt so the verify-time check is always comparing apples to apples.
    pub(crate) fn mint_execution_nonce_for_allow(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        receipt: &ChioReceipt,
    ) -> Result<Option<Box<crate::execution_nonce::SignedExecutionNonce>>, KernelError> {
        if request.execution_nonce.is_some() {
            return Ok(None);
        }
        let Some(config) = self.execution_nonce_config.as_ref() else {
            return Ok(None);
        };
        let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
        let binding = crate::execution_nonce::NonceBinding {
            subject_id: cap.subject.to_hex(),
            capability_id: cap.id.clone(),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            parameter_hash: receipt.action.parameter_hash.clone(),
        };
        let signed = crate::execution_nonce::mint_execution_nonce(
            &self.config.keypair,
            binding,
            config,
            now,
        )?;
        Ok(Some(Box::new(signed)))
    }

    /// Verify a caller-presented execution nonce against the
    /// expected binding, consuming it in the replay store on success.
    ///
    /// Returns `Ok(())` when the nonce is fresh, correctly bound, signed
    /// by this kernel, and has not been consumed. Returns an error
    /// wrapping `ExecutionNonceError` on any failure (expired, tampered,
    /// replayed, binding mismatch, store unreachable).
    pub fn verify_presented_execution_nonce(
        &self,
        presented: &crate::execution_nonce::SignedExecutionNonce,
        expected: &crate::execution_nonce::NonceBinding,
    ) -> Result<(), crate::execution_nonce::ExecutionNonceError> {
        let store = self.execution_nonce_store.as_deref().ok_or_else(|| {
            crate::execution_nonce::ExecutionNonceError::Store(
                "execution nonce store is not installed".to_string(),
            )
        })?;
        let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
        crate::execution_nonce::verify_execution_nonce(
            presented,
            &self.config.keypair.public_key(),
            expected,
            now,
            store,
        )
    }

    /// Execution-nonce dispatch gate.
    ///
    /// Denies fail-closed when strict mode is configured and the request
    /// lacks a nonce. When strict mode is disabled, a request with no
    /// nonce remains backward-compatible. Any presented nonce is still
    /// verified and consumed so opt-in callers cannot bypass binding,
    /// expiry, signature, or replay checks.
    ///
    /// Returns `Ok(())` when:
    /// * no nonce is required and none was presented, OR
    /// * a nonce is presented, signed by this kernel, correctly bound,
    ///   non-expired, and has not been consumed.
    ///
    /// Returns `Err(KernelError::Internal(...))` fail-closed otherwise.
    pub fn require_presented_execution_nonce(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
    ) -> Result<(), KernelError> {
        let presented = request.execution_nonce.as_ref();
        if !self.execution_nonce_required() && presented.is_none() {
            return Ok(());
        }
        let presented = presented.ok_or_else(|| {
            KernelError::Internal(
                "execution nonce required but not presented on tool call".to_string(),
            )
        })?;
        let parameter_hash = chio_core::receipt::decision::ToolCallAction::from_parameters(
            request.arguments.clone(),
        )
        .map_err(|e| KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}")))?
        .parameter_hash;
        let expected = crate::execution_nonce::NonceBinding {
            subject_id: cap.subject.to_hex(),
            capability_id: cap.id.clone(),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            parameter_hash,
        };
        self.verify_presented_execution_nonce(presented, &expected)
            .map_err(|e| KernelError::Internal(format!("{e}")))
    }

    /// Strict-mode nonce issuance gate.
    ///
    /// In strict mode, a request that reaches evaluation without a presented
    /// nonce is an authorization preflight. It may receive a freshly signed
    /// nonce, but it must not execute the target tool. Actual execution
    /// presents that nonce on a later request and consumes it immediately
    /// before dispatch.
    #[must_use]
    pub(crate) fn execution_nonce_preflight_required(&self, request: &ToolCallRequest) -> bool {
        self.execution_nonce_required() && request.execution_nonce.is_none()
    }

    pub fn requires_web3_evidence(&self) -> bool {
        self.config.require_web3_evidence
    }

    pub fn validate_web3_evidence_prerequisites(&self) -> Result<(), KernelError> {
        if !self.requires_web3_evidence() {
            return Ok(());
        }

        let Some(supports_kernel_signed_checkpoints) =
            self.with_receipt_store(|store| Ok(store.supports_kernel_signed_checkpoints()))?
        else {
            return Err(KernelError::Web3EvidenceUnavailable(
                "web3-enabled deployments require a durable receipt store".to_string(),
            ));
        };

        if self.checkpoint_batch_size == 0 {
            return Err(KernelError::Web3EvidenceUnavailable(
                "web3-enabled deployments require checkpoint_batch_size > 0".to_string(),
            ));
        }

        if !supports_kernel_signed_checkpoints {
            return Err(KernelError::Web3EvidenceUnavailable(
                "web3-enabled deployments require local receipt persistence with kernel-signed checkpoint support; append-only remote receipt mirrors are unsupported".to_string(),
            ));
        }

        Ok(())
    }

    /// Register a policy guard. Guards are evaluated in registration order.
    /// If any guard denies, the request is denied.
    pub fn add_guard(&mut self, guard: Box<dyn Guard>) {
        self.guards.push(guard);
    }

    /// Install a product-specific runtime admission hook. The hook runs after
    /// core authorization checks and guards, but before tool dispatch.
    pub fn set_runtime_admission_hook(&mut self, hook: Arc<dyn RuntimeAdmissionHook>) {
        self.runtime_admission_hook = Some(hook);
    }

    /// Remove the product-specific runtime admission hook.
    pub fn clear_runtime_admission_hook(&mut self) {
        self.runtime_admission_hook = None;
    }

    /// Register a tool server connection.
    pub fn register_tool_server(&mut self, connection: Box<dyn ToolServerConnection>) {
        let id = connection.server_id().to_owned();
        info!(server_id = %id, "registering tool server");
        self.tool_servers.insert(id, connection);
    }

    /// Register a resource provider.
    pub fn register_resource_provider(&mut self, provider: Box<dyn ResourceProvider>) {
        info!("registering resource provider");
        self.resource_providers.push(provider);
    }

    /// Register a prompt provider.
    pub fn register_prompt_provider(&mut self, provider: Box<dyn PromptProvider>) {
        info!("registering prompt provider");
        self.prompt_providers.push(provider);
    }
}
