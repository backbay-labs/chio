use serde::Serialize;
use std::{fmt, path::Path};

use crate::{
    unwrap_runtime, wrap_runtime, ChioRuntimeError, RuntimeAdmissionBundle, RuntimeCoreError,
    RuntimeEvidenceManifestEntry, RuntimeOpsStatusReport, RuntimeOrchestrationProfile,
    RuntimeOrchestrationStatusReport, RuntimeOrchestrationStepState, RuntimeRecoveryDrillReport,
    RuntimeRunLease, RuntimeSchedulerTickReport, RuntimeSupervisorProfile, RuntimeTrustFloorEntry,
    SwarmAuthorityBundle, TreatyRuntimeArtifactRecord,
};

pub trait ChioRuntimeAdmissionStore: Send + Sync {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError>;

    fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChioRuntimeError>;

    fn swarm_authority_bundle(
        &self,
        task_graph_id: &str,
    ) -> Result<Option<SwarmAuthorityBundle>, ChioRuntimeError>;

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError>;

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError>;

    fn consume_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError>;

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError>;

    fn consume_swarm_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError>;

    fn release_swarm_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError>;

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError>;

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError>;

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryRuntimeAdmissionStore {
    inner: chio_runtime_core::InMemoryRuntimeAdmissionStore,
}

impl InMemoryRuntimeAdmissionStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: chio_runtime_core::InMemoryRuntimeAdmissionStore::new(),
        }
    }

    pub fn insert_bundle(&self, bundle: RuntimeAdmissionBundle) -> Result<(), ChioRuntimeError> {
        wrap_runtime(self.inner.insert_bundle(bundle))
    }

    pub fn insert_treaty_runtime_artifact<T: Serialize>(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
        artifact: &T,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(self.inner.insert_treaty_runtime_artifact(
            evidence_kind,
            evidence_id,
            artifact,
        ))
    }

    pub fn insert_swarm_authority_bundle(
        &self,
        bundle: SwarmAuthorityBundle,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(self.inner.insert_swarm_authority_bundle(bundle))
    }
}

impl ChioRuntimeAdmissionStore for InMemoryRuntimeAdmissionStore {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError> {
        wrap_runtime(chio_runtime_core::RuntimeAdmissionStore::bundle(
            &self.inner,
            admission_id,
        ))
    }

    fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChioRuntimeError> {
        wrap_runtime(
            chio_runtime_core::RuntimeAdmissionStore::treaty_runtime_artifact(
                &self.inner,
                evidence_kind,
                evidence_id,
            ),
        )
    }

    fn swarm_authority_bundle(
        &self,
        task_graph_id: &str,
    ) -> Result<Option<SwarmAuthorityBundle>, ChioRuntimeError> {
        wrap_runtime(
            chio_runtime_core::RuntimeAdmissionStore::swarm_authority_bundle(
                &self.inner,
                task_graph_id,
            ),
        )
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(
            chio_runtime_core::RuntimeAdmissionStore::consume_destructive_lease(
                &self.inner,
                lease_id,
                admission_id,
            ),
        )
    }

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(
            chio_runtime_core::RuntimeAdmissionStore::release_destructive_lease(
                &self.inner,
                lease_id,
                admission_id,
            ),
        )
    }

    fn consume_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(
            chio_runtime_core::RuntimeAdmissionStore::consume_treaty_continuation(
                &self.inner,
                continuation_id,
                admission_id,
            ),
        )
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(
            chio_runtime_core::RuntimeAdmissionStore::release_treaty_continuation(
                &self.inner,
                continuation_id,
                admission_id,
            ),
        )
    }

    fn consume_swarm_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(
            chio_runtime_core::RuntimeAdmissionStore::consume_swarm_continuation(
                &self.inner,
                continuation_id,
                admission_id,
            ),
        )
    }

    fn release_swarm_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(
            chio_runtime_core::RuntimeAdmissionStore::release_swarm_continuation(
                &self.inner,
                continuation_id,
                admission_id,
            ),
        )
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        wrap_runtime(
            chio_runtime_core::RuntimeAdmissionStore::runtime_trust_floor(
                &self.inner,
                verifier_id,
                key_id,
            ),
        )
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(
            chio_runtime_core::RuntimeAdmissionStore::record_runtime_trust_floor(
                &self.inner,
                entry,
            ),
        )
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(
            chio_runtime_core::RuntimeAdmissionStore::validate_and_record_runtime_trust_floor(
                &self.inner,
                entry,
                previous_hash_sha256,
            ),
        )
    }
}

pub trait ChioRuntimeTrustFloorStore: Send + Sync {
    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError>;

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError>;

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError>;
}

impl<T> ChioRuntimeTrustFloorStore for T
where
    T: ChioRuntimeAdmissionStore + ?Sized,
{
    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        ChioRuntimeAdmissionStore::runtime_trust_floor(self, verifier_id, key_id)
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        ChioRuntimeAdmissionStore::record_runtime_trust_floor(self, entry)
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        ChioRuntimeAdmissionStore::validate_and_record_runtime_trust_floor(
            self,
            entry,
            previous_hash_sha256,
        )
    }
}

#[derive(Debug, Clone)]
pub struct JsonRuntimeAdmissionStore {
    inner: chio_runtime_core::JsonRuntimeAdmissionStore,
}

impl JsonRuntimeAdmissionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ChioRuntimeError> {
        wrap_runtime(chio_runtime_core::JsonRuntimeAdmissionStore::open(path))
            .map(|inner| Self { inner })
    }

    pub fn insert_bundle(&self, bundle: RuntimeAdmissionBundle) -> Result<(), ChioRuntimeError> {
        wrap_runtime(self.inner.insert_bundle(bundle))
    }

    pub fn insert_swarm_authority_bundle(
        &self,
        bundle: SwarmAuthorityBundle,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(self.inner.insert_swarm_authority_bundle(bundle))
    }
}

pub struct JsonRuntimeTrustFloorStateStore {
    inner: chio_runtime_core::JsonRuntimeTrustFloorStateStore,
}

impl fmt::Debug for JsonRuntimeTrustFloorStateStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JsonRuntimeTrustFloorStateStore")
            .finish_non_exhaustive()
    }
}

impl JsonRuntimeTrustFloorStateStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ChioRuntimeError> {
        wrap_runtime(chio_runtime_core::JsonRuntimeTrustFloorStateStore::open(
            path,
        ))
        .map(|inner| Self { inner })
    }
}

pub struct LayeredRuntimeAdmissionStore<'a> {
    admission_store: &'a dyn ChioRuntimeAdmissionStore,
    trust_floor_store: &'a dyn ChioRuntimeTrustFloorStore,
}

impl fmt::Debug for LayeredRuntimeAdmissionStore<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LayeredRuntimeAdmissionStore")
            .finish_non_exhaustive()
    }
}

impl<'a> LayeredRuntimeAdmissionStore<'a> {
    #[must_use]
    pub fn new(
        admission_store: &'a dyn ChioRuntimeAdmissionStore,
        trust_floor_store: &'a dyn ChioRuntimeTrustFloorStore,
    ) -> Self {
        Self {
            admission_store,
            trust_floor_store,
        }
    }
}

pub struct SqliteRuntimeOrchestrationStore {
    inner: chio_runtime_core::SqliteRuntimeOrchestrationStore,
}

impl fmt::Debug for SqliteRuntimeOrchestrationStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteRuntimeOrchestrationStore")
            .finish_non_exhaustive()
    }
}

impl SqliteRuntimeOrchestrationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ChioRuntimeError> {
        wrap_runtime(chio_runtime_core::SqliteRuntimeOrchestrationStore::open(
            path,
        ))
        .map(|inner| Self { inner })
    }

    pub fn insert_bundle(&self, bundle: RuntimeAdmissionBundle) -> Result<(), ChioRuntimeError> {
        wrap_runtime(self.inner.insert_bundle(bundle))
    }

    pub fn insert_treaty_runtime_artifact<T: Serialize>(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
        artifact: &T,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(self.inner.insert_treaty_runtime_artifact(
            evidence_kind,
            evidence_id,
            artifact,
        ))
    }

    pub fn insert_swarm_authority_bundle(
        &self,
        bundle: SwarmAuthorityBundle,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(self.inner.insert_swarm_authority_bundle(bundle))
    }

    pub fn record_run_state(
        &self,
        run_id: &str,
        status: &str,
        failure_code: Option<&str>,
        now_unix_ms: u64,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(
            self.inner
                .record_run_state(run_id, status, failure_code, now_unix_ms),
        )
    }

    pub fn record_step_state(
        &self,
        state: RuntimeOrchestrationStepState,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(self.inner.record_step_state(state))
    }

    pub fn record_run_step_state(
        &self,
        run_id: &str,
        state: RuntimeOrchestrationStepState,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(self.inner.record_run_step_state(run_id, state))
    }

    pub fn record_evidence_artifact(
        &self,
        run_id: &str,
        entry: &RuntimeEvidenceManifestEntry,
        recorded_at_unix_ms: u64,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(
            self.inner
                .record_evidence_artifact(run_id, entry, recorded_at_unix_ms),
        )
    }

    pub fn recorded_run_ids(&self) -> Result<Vec<String>, ChioRuntimeError> {
        wrap_runtime(self.inner.recorded_run_ids())
    }

    pub fn status_report(
        &self,
        profile: &RuntimeOrchestrationProfile,
        profile_sha256: String,
        now_unix_ms: u64,
        evidence_sink_healthy: bool,
    ) -> Result<RuntimeOrchestrationStatusReport, ChioRuntimeError> {
        wrap_runtime(self.inner.status_report(
            profile,
            profile_sha256,
            now_unix_ms,
            evidence_sink_healthy,
        ))
    }

    pub fn recovery_drill_report(
        &self,
        run_id: &str,
        now_unix_ms: u64,
    ) -> Result<RuntimeRecoveryDrillReport, ChioRuntimeError> {
        wrap_runtime(self.inner.recovery_drill_report(run_id, now_unix_ms))
    }

    pub fn recovery_drill_report_for_profile(
        &self,
        profile: &RuntimeSupervisorProfile,
        run_id: &str,
        now_unix_ms: u64,
    ) -> Result<RuntimeRecoveryDrillReport, ChioRuntimeError> {
        wrap_runtime(
            self.inner
                .recovery_drill_report_for_profile(profile, run_id, now_unix_ms),
        )
    }

    pub fn ops_status_report(
        &self,
        profile: &RuntimeSupervisorProfile,
        now_unix_ms: u64,
        evidence_sink_healthy: bool,
        provider_healthy: bool,
    ) -> Result<RuntimeOpsStatusReport, ChioRuntimeError> {
        wrap_runtime(self.inner.ops_status_report(
            profile,
            now_unix_ms,
            evidence_sink_healthy,
            provider_healthy,
        ))
    }

    pub fn acquire_run_lease(
        &self,
        run_id: &str,
        owner_id: &str,
        now_unix_ms: u64,
        ttl_ms: u64,
    ) -> Result<RuntimeRunLease, ChioRuntimeError> {
        wrap_runtime(
            self.inner
                .acquire_run_lease(run_id, owner_id, now_unix_ms, ttl_ms),
        )
    }

    pub fn heartbeat_run_lease(
        &self,
        run_id: &str,
        owner_id: &str,
        fencing_token: u64,
        now_unix_ms: u64,
        ttl_ms: u64,
    ) -> Result<RuntimeRunLease, ChioRuntimeError> {
        wrap_runtime(self.inner.heartbeat_run_lease(
            run_id,
            owner_id,
            fencing_token,
            now_unix_ms,
            ttl_ms,
        ))
    }

    pub fn scheduler_tick_report(
        &self,
        profile: &RuntimeSupervisorProfile,
        owner_id: &str,
        now_unix_ms: u64,
        max_runs: u64,
    ) -> Result<RuntimeSchedulerTickReport, ChioRuntimeError> {
        wrap_runtime(
            self.inner
                .scheduler_tick_report(profile, owner_id, now_unix_ms, max_runs),
        )
    }
}

macro_rules! impl_chio_runtime_admission_store_for_inner {
    ($type:ty) => {
        impl ChioRuntimeAdmissionStore for $type {
            fn bundle(
                &self,
                admission_id: &str,
            ) -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError> {
                wrap_runtime(chio_runtime_core::RuntimeAdmissionStore::bundle(
                    &self.inner,
                    admission_id,
                ))
            }

            fn treaty_runtime_artifact(
                &self,
                evidence_kind: &str,
                evidence_id: &str,
            ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChioRuntimeError> {
                wrap_runtime(
                    chio_runtime_core::RuntimeAdmissionStore::treaty_runtime_artifact(
                        &self.inner,
                        evidence_kind,
                        evidence_id,
                    ),
                )
            }

            fn swarm_authority_bundle(
                &self,
                task_graph_id: &str,
            ) -> Result<Option<SwarmAuthorityBundle>, ChioRuntimeError> {
                wrap_runtime(
                    chio_runtime_core::RuntimeAdmissionStore::swarm_authority_bundle(
                        &self.inner,
                        task_graph_id,
                    ),
                )
            }

            fn consume_destructive_lease(
                &self,
                lease_id: &str,
                admission_id: &str,
            ) -> Result<(), ChioRuntimeError> {
                wrap_runtime(
                    chio_runtime_core::RuntimeAdmissionStore::consume_destructive_lease(
                        &self.inner,
                        lease_id,
                        admission_id,
                    ),
                )
            }

            fn release_destructive_lease(
                &self,
                lease_id: &str,
                admission_id: &str,
            ) -> Result<(), ChioRuntimeError> {
                wrap_runtime(
                    chio_runtime_core::RuntimeAdmissionStore::release_destructive_lease(
                        &self.inner,
                        lease_id,
                        admission_id,
                    ),
                )
            }

            fn consume_treaty_continuation(
                &self,
                continuation_id: &str,
                admission_id: &str,
            ) -> Result<(), ChioRuntimeError> {
                wrap_runtime(
                    chio_runtime_core::RuntimeAdmissionStore::consume_treaty_continuation(
                        &self.inner,
                        continuation_id,
                        admission_id,
                    ),
                )
            }

            fn release_treaty_continuation(
                &self,
                continuation_id: &str,
                admission_id: &str,
            ) -> Result<(), ChioRuntimeError> {
                wrap_runtime(
                    chio_runtime_core::RuntimeAdmissionStore::release_treaty_continuation(
                        &self.inner,
                        continuation_id,
                        admission_id,
                    ),
                )
            }

            fn consume_swarm_continuation(
                &self,
                continuation_id: &str,
                admission_id: &str,
            ) -> Result<(), ChioRuntimeError> {
                wrap_runtime(
                    chio_runtime_core::RuntimeAdmissionStore::consume_swarm_continuation(
                        &self.inner,
                        continuation_id,
                        admission_id,
                    ),
                )
            }

            fn release_swarm_continuation(
                &self,
                continuation_id: &str,
                admission_id: &str,
            ) -> Result<(), ChioRuntimeError> {
                wrap_runtime(
                    chio_runtime_core::RuntimeAdmissionStore::release_swarm_continuation(
                        &self.inner,
                        continuation_id,
                        admission_id,
                    ),
                )
            }

            fn runtime_trust_floor(
                &self,
                verifier_id: &str,
                key_id: &str,
            ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
                wrap_runtime(
                    chio_runtime_core::RuntimeAdmissionStore::runtime_trust_floor(
                        &self.inner,
                        verifier_id,
                        key_id,
                    ),
                )
            }

            fn record_runtime_trust_floor(
                &self,
                entry: RuntimeTrustFloorEntry,
            ) -> Result<(), ChioRuntimeError> {
                wrap_runtime(
                    chio_runtime_core::RuntimeAdmissionStore::record_runtime_trust_floor(
                        &self.inner,
                        entry,
                    ),
                )
            }

            fn validate_and_record_runtime_trust_floor(
                &self,
                entry: RuntimeTrustFloorEntry,
                previous_hash_sha256: Option<&str>,
            ) -> Result<(), ChioRuntimeError> {
                wrap_runtime(
                    chio_runtime_core::RuntimeAdmissionStore::validate_and_record_runtime_trust_floor(
                        &self.inner,
                        entry,
                        previous_hash_sha256,
                    ),
                )
            }
        }
    };
}

impl_chio_runtime_admission_store_for_inner!(JsonRuntimeAdmissionStore);
impl_chio_runtime_admission_store_for_inner!(SqliteRuntimeOrchestrationStore);

impl ChioRuntimeAdmissionStore for LayeredRuntimeAdmissionStore<'_> {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError> {
        self.admission_store.bundle(admission_id)
    }

    fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChioRuntimeError> {
        self.admission_store
            .treaty_runtime_artifact(evidence_kind, evidence_id)
    }

    fn swarm_authority_bundle(
        &self,
        task_graph_id: &str,
    ) -> Result<Option<SwarmAuthorityBundle>, ChioRuntimeError> {
        self.admission_store.swarm_authority_bundle(task_graph_id)
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.admission_store
            .consume_destructive_lease(lease_id, admission_id)
    }

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.admission_store
            .release_destructive_lease(lease_id, admission_id)
    }

    fn consume_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.admission_store
            .consume_treaty_continuation(continuation_id, admission_id)
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.admission_store
            .release_treaty_continuation(continuation_id, admission_id)
    }

    fn consume_swarm_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.admission_store
            .consume_swarm_continuation(continuation_id, admission_id)
    }

    fn release_swarm_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        self.admission_store
            .release_swarm_continuation(continuation_id, admission_id)
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        self.trust_floor_store
            .runtime_trust_floor(verifier_id, key_id)
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        self.trust_floor_store.record_runtime_trust_floor(entry)
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        self.trust_floor_store
            .validate_and_record_runtime_trust_floor(entry, previous_hash_sha256)
    }
}

impl ChioRuntimeTrustFloorStore for JsonRuntimeTrustFloorStateStore {
    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        wrap_runtime(
            chio_runtime_core::RuntimeTrustFloorStore::runtime_trust_floor(
                &self.inner,
                verifier_id,
                key_id,
            ),
        )
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(
            chio_runtime_core::RuntimeTrustFloorStore::record_runtime_trust_floor(
                &self.inner,
                entry,
            ),
        )
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        wrap_runtime(
            chio_runtime_core::RuntimeTrustFloorStore::validate_and_record_runtime_trust_floor(
                &self.inner,
                entry,
                previous_hash_sha256,
            ),
        )
    }
}

pub(crate) struct RuntimeCoreAdmissionStoreAdapter<'a> {
    pub(crate) inner: &'a dyn ChioRuntimeAdmissionStore,
}

impl chio_runtime_core::RuntimeAdmissionStore for RuntimeCoreAdmissionStoreAdapter<'_> {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, RuntimeCoreError> {
        unwrap_runtime(self.inner.bundle(admission_id))
    }

    fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, RuntimeCoreError> {
        unwrap_runtime(
            self.inner
                .treaty_runtime_artifact(evidence_kind, evidence_id),
        )
    }

    fn swarm_authority_bundle(
        &self,
        task_graph_id: &str,
    ) -> Result<Option<SwarmAuthorityBundle>, RuntimeCoreError> {
        unwrap_runtime(self.inner.swarm_authority_bundle(task_graph_id))
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), RuntimeCoreError> {
        unwrap_runtime(self.inner.consume_destructive_lease(lease_id, admission_id))
    }

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), RuntimeCoreError> {
        unwrap_runtime(self.inner.release_destructive_lease(lease_id, admission_id))
    }

    fn consume_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), RuntimeCoreError> {
        unwrap_runtime(
            self.inner
                .consume_treaty_continuation(continuation_id, admission_id),
        )
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), RuntimeCoreError> {
        unwrap_runtime(
            self.inner
                .release_treaty_continuation(continuation_id, admission_id),
        )
    }

    fn consume_swarm_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), RuntimeCoreError> {
        unwrap_runtime(
            self.inner
                .consume_swarm_continuation(continuation_id, admission_id),
        )
    }

    fn release_swarm_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), RuntimeCoreError> {
        unwrap_runtime(
            self.inner
                .release_swarm_continuation(continuation_id, admission_id),
        )
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, RuntimeCoreError> {
        unwrap_runtime(self.inner.runtime_trust_floor(verifier_id, key_id))
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), RuntimeCoreError> {
        unwrap_runtime(self.inner.record_runtime_trust_floor(entry))
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), RuntimeCoreError> {
        unwrap_runtime(
            self.inner
                .validate_and_record_runtime_trust_floor(entry, previous_hash_sha256),
        )
    }
}
