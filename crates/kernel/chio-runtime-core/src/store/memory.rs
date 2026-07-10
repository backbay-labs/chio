use super::traits::RuntimeAdmissionStore;
use crate::validation::{validate_non_empty, validate_state_label};
use crate::*;
use chio_swarm_authority::SwarmAuthorityBundle;

#[derive(Debug, Clone, Default)]
pub struct InMemoryRuntimeAdmissionStore {
    bundles: Arc<Mutex<BTreeMap<String, RuntimeAdmissionBundle>>>,
    swarm_authority_bundles: Arc<Mutex<BTreeMap<String, SwarmAuthorityBundle>>>,
    treaty_artifacts: Arc<Mutex<BTreeMap<(String, String), TreatyRuntimeArtifactRecord>>>,
    consumed_leases: Arc<Mutex<BTreeSet<String>>>,
    consumed_treaty_continuations: Arc<Mutex<BTreeSet<String>>>,
    consumed_swarm_continuations: Arc<Mutex<BTreeSet<String>>>,
    trust_floors: Arc<Mutex<BTreeMap<String, RuntimeTrustFloorEntry>>>,
}

impl InMemoryRuntimeAdmissionStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_bundle(&self, bundle: RuntimeAdmissionBundle) -> Result<(), ChioRuntimeError> {
        let mut bundles = self.bundles.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime admission bundle store is poisoned".to_string())
        })?;
        if let Some(existing) = bundles.get(&bundle.admission_id) {
            if existing == &bundle {
                return Ok(());
            }
            return Err(ChioRuntimeError::DuplicateAdmissionBundle);
        }
        bundles.insert(bundle.admission_id.clone(), bundle);
        Ok(())
    }

    pub fn insert_treaty_runtime_artifact<T: Serialize>(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
        artifact: &T,
    ) -> Result<(), ChioRuntimeError> {
        validate_state_label(evidence_kind, "runtime_treaty_artifact_invalid_kind")?;
        validate_non_empty(evidence_id, "runtime_treaty_artifact_empty_id")?;
        let artifact_sha256 = canonical_sha256(artifact)?;
        let raw_json = serde_json::to_value(artifact)
            .map_err(|error| ChioRuntimeError::Json(error.to_string()))?;
        let mut treaty_artifacts = self.treaty_artifacts.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime treaty artifact store is poisoned".to_string())
        })?;
        let key = (evidence_kind.to_string(), evidence_id.to_string());
        if let Some(existing) = treaty_artifacts.get(&key) {
            if existing.artifact_sha256 == artifact_sha256 {
                return Ok(());
            }
            return Err(ChioRuntimeError::Rejected {
                code: "duplicate_treaty_runtime_artifact_mismatch",
                detail: "runtime treaty artifact id already exists with a different hash"
                    .to_string(),
            });
        }
        treaty_artifacts.insert(
            key,
            TreatyRuntimeArtifactRecord {
                evidence_kind: evidence_kind.to_string(),
                evidence_id: evidence_id.to_string(),
                artifact_sha256,
                raw_json,
            },
        );
        Ok(())
    }

    pub fn insert_swarm_authority_bundle(
        &self,
        bundle: SwarmAuthorityBundle,
    ) -> Result<(), ChioRuntimeError> {
        validate_non_empty(
            &bundle.task_graph.graph_id,
            "runtime_swarm_authority_empty_graph_id",
        )?;
        let bundle_sha256 = canonical_sha256(&bundle)?;
        let mut bundles = self.swarm_authority_bundles.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime swarm authority bundle store is poisoned".to_string())
        })?;
        if let Some(existing) = bundles.get(&bundle.task_graph.graph_id) {
            if canonical_sha256(existing)? == bundle_sha256 {
                return Ok(());
            }
            return Err(ChioRuntimeError::Rejected {
                code: "duplicate_swarm_authority_bundle_mismatch",
                detail:
                    "runtime swarm authority bundle graph id already exists with a different hash"
                        .to_string(),
            });
        }
        bundles.insert(bundle.task_graph.graph_id.clone(), bundle);
        Ok(())
    }
}

impl RuntimeAdmissionStore for InMemoryRuntimeAdmissionStore {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError> {
        let bundles = self.bundles.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime admission bundle store is poisoned".to_string())
        })?;
        Ok(bundles.get(admission_id).cloned())
    }

    fn treaty_runtime_artifact(
        &self,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<Option<TreatyRuntimeArtifactRecord>, ChioRuntimeError> {
        let treaty_artifacts = self.treaty_artifacts.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime treaty artifact store is poisoned".to_string())
        })?;
        Ok(treaty_artifacts
            .get(&(evidence_kind.to_string(), evidence_id.to_string()))
            .cloned())
    }

    fn swarm_authority_bundle(
        &self,
        task_graph_id: &str,
    ) -> Result<Option<SwarmAuthorityBundle>, ChioRuntimeError> {
        let bundles = self.swarm_authority_bundles.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime swarm authority bundle store is poisoned".to_string())
        })?;
        Ok(bundles.get(task_graph_id).cloned())
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        let mut consumed = self.consumed_leases.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime admission consumption store is poisoned".to_string())
        })?;
        if !consumed.insert(lease_id.to_string()) {
            return Err(ChioRuntimeError::Rejected {
                code: "destructive_lease_replay",
                detail: format!("destructive lease {lease_id} was already consumed"),
            });
        }
        Ok(())
    }

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        let mut consumed = self.consumed_leases.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime admission consumption store is poisoned".to_string())
        })?;
        consumed.remove(lease_id);
        Ok(())
    }

    fn consume_treaty_continuation(
        &self,
        continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        let mut consumed = self.consumed_treaty_continuations.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime treaty continuation store is poisoned".to_string())
        })?;
        if !consumed.insert(continuation_id.to_string()) {
            return Err(ChioRuntimeError::Rejected {
                code: "chio_treaty_continuation_replay",
                detail: format!("treaty continuation {continuation_id} was already consumed"),
            });
        }
        Ok(())
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        let mut consumed = self.consumed_treaty_continuations.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime treaty continuation store is poisoned".to_string())
        })?;
        consumed.remove(continuation_id);
        Ok(())
    }

    fn consume_swarm_continuation(
        &self,
        continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        let mut consumed = self.consumed_swarm_continuations.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime swarm continuation store is poisoned".to_string())
        })?;
        if !consumed.insert(continuation_id.to_string()) {
            return Err(ChioRuntimeError::Rejected {
                code: "chio_swarm_continuation_replay",
                detail: format!("swarm continuation {continuation_id} was already consumed"),
            });
        }
        Ok(())
    }

    fn release_swarm_continuation(
        &self,
        continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        let mut consumed = self.consumed_swarm_continuations.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime swarm continuation store is poisoned".to_string())
        })?;
        consumed.remove(continuation_id);
        Ok(())
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        let floors = self.trust_floors.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime admission trust floor store is poisoned".to_string())
        })?;
        Ok(floors
            .get(&trust_floor_identity(verifier_id, key_id))
            .cloned())
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        let mut floors = self.trust_floors.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime admission trust floor store is poisoned".to_string())
        })?;
        floors.insert(
            trust_floor_identity(&entry.verifier_id, &entry.key_id),
            entry,
        );
        Ok(())
    }
}
