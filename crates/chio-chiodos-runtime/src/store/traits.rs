use crate::*;

fn unsupported_treaty_continuation_store(
    operation: &str,
    continuation_id: &str,
) -> ChiodosRuntimeError {
    ChiodosRuntimeError::Rejected {
        code: "chiodos_treaty_continuation_store_unsupported",
        detail: format!(
            "runtime admission store does not support {operation} for treaty continuation {continuation_id}"
        ),
    }
}

pub trait RuntimeAdmissionStore: Send + Sync {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChiodosRuntimeError>;

    fn treaty_runtime_artifact(
        &self,
        _evidence_kind: &str,
        _evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChiodosRuntimeError> {
        Ok(None)
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError>;

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError>;

    fn consume_treaty_continuation(
        &self,
        continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        Err(unsupported_treaty_continuation_store(
            "consume",
            continuation_id,
        ))
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        Err(unsupported_treaty_continuation_store(
            "release",
            continuation_id,
        ))
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChiodosRuntimeError>;

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChiodosRuntimeError>;

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChiodosRuntimeError> {
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
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChiodosRuntimeError>;

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChiodosRuntimeError>;

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChiodosRuntimeError> {
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
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChiodosRuntimeError> {
        RuntimeAdmissionStore::runtime_trust_floor(self, verifier_id, key_id)
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChiodosRuntimeError> {
        RuntimeAdmissionStore::record_runtime_trust_floor(self, entry)
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChiodosRuntimeError> {
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
    ) -> Result<Option<RuntimeAdmissionBundle>, ChiodosRuntimeError> {
        self.admission_store.bundle(admission_id)
    }

    fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChiodosRuntimeError> {
        self.admission_store
            .treaty_runtime_artifact(evidence_kind, evidence_id)
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        self.admission_store
            .consume_destructive_lease(lease_id, admission_id)
    }

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        self.admission_store
            .release_destructive_lease(lease_id, admission_id)
    }

    fn consume_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        self.admission_store
            .consume_treaty_continuation(continuation_id, admission_id)
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        admission_id: &str,
    ) -> Result<(), ChiodosRuntimeError> {
        self.admission_store
            .release_treaty_continuation(continuation_id, admission_id)
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChiodosRuntimeError> {
        self.trust_floor_store
            .runtime_trust_floor(verifier_id, key_id)
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChiodosRuntimeError> {
        self.trust_floor_store.record_runtime_trust_floor(entry)
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChiodosRuntimeError> {
        self.trust_floor_store
            .validate_and_record_runtime_trust_floor(entry, previous_hash_sha256)
    }
}
