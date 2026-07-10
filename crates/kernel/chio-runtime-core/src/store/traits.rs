use chio_swarm_authority::SwarmAuthorityBundle;

use crate::*;

fn unsupported_treaty_continuation_store(
    operation: &str,
    continuation_id: &str,
) -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code: "chio_treaty_continuation_store_unsupported",
        detail: format!(
            "runtime admission store does not support {operation} for treaty continuation {continuation_id}"
        ),
    }
}

fn unsupported_swarm_continuation_store(
    operation: &str,
    continuation_id: &str,
) -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code: "chio_swarm_continuation_store_unsupported",
        detail: format!(
            "runtime admission store does not support {operation} for swarm continuation {continuation_id}"
        ),
    }
}

pub trait RuntimeAdmissionStore: Send + Sync {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError>;

    fn treaty_runtime_artifact(
        &self,
        _evidence_kind: &str,
        _evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChioRuntimeError> {
        Ok(None)
    }

    fn swarm_authority_bundle(
        &self,
        _task_graph_id: &str,
    ) -> Result<Option<SwarmAuthorityBundle>, ChioRuntimeError> {
        Ok(None)
    }

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
        _admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        Err(unsupported_treaty_continuation_store(
            "consume",
            continuation_id,
        ))
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        Err(unsupported_treaty_continuation_store(
            "release",
            continuation_id,
        ))
    }

    fn consume_swarm_continuation(
        &self,
        continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        Err(unsupported_swarm_continuation_store(
            "consume",
            continuation_id,
        ))
    }

    fn release_swarm_continuation(
        &self,
        continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        Err(unsupported_swarm_continuation_store(
            "release",
            continuation_id,
        ))
    }

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
    ) -> Result<(), ChioRuntimeError> {
        validate_runtime_trust_floor_transition(
            self.runtime_trust_floor(&entry.verifier_id, &entry.key_id)?,
            &entry,
            previous_hash_sha256,
        )?;
        self.record_runtime_trust_floor(entry)
    }
}

pub trait RuntimeTrustFloorStore: Send + Sync {
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
    ) -> Result<(), ChioRuntimeError> {
        validate_runtime_trust_floor_transition(
            self.runtime_trust_floor(&entry.verifier_id, &entry.key_id)?,
            &entry,
            previous_hash_sha256,
        )?;
        self.record_runtime_trust_floor(entry)
    }
}

impl<T> RuntimeTrustFloorStore for T
where
    T: RuntimeAdmissionStore + ?Sized,
{
    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        RuntimeAdmissionStore::runtime_trust_floor(self, verifier_id, key_id)
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        RuntimeAdmissionStore::record_runtime_trust_floor(self, entry)
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        RuntimeAdmissionStore::validate_and_record_runtime_trust_floor(
            self,
            entry,
            previous_hash_sha256,
        )
    }
}

pub struct LayeredRuntimeAdmissionStore<'a> {
    admission_store: &'a dyn RuntimeAdmissionStore,
    trust_floor_store: &'a dyn RuntimeTrustFloorStore,
}

impl<'a> LayeredRuntimeAdmissionStore<'a> {
    #[must_use]
    pub fn new(
        admission_store: &'a dyn RuntimeAdmissionStore,
        trust_floor_store: &'a dyn RuntimeTrustFloorStore,
    ) -> Self {
        Self {
            admission_store,
            trust_floor_store,
        }
    }
}

impl RuntimeAdmissionStore for LayeredRuntimeAdmissionStore<'_> {
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
