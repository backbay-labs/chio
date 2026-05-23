use super::traits::RuntimeAdmissionStore;
use crate::*;

#[derive(Debug, Clone)]
pub struct JsonRuntimeAdmissionStore {
    path: PathBuf,
    state: Arc<Mutex<JsonRuntimeAdmissionStoreState>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JsonRuntimeAdmissionStoreState {
    schema: String,
    bundles: Vec<RuntimeAdmissionBundle>,
    consumed_lease_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    consumed_treaty_continuation_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    trust_floors: Vec<RuntimeTrustFloorEntry>,
}

impl Default for JsonRuntimeAdmissionStoreState {
    fn default() -> Self {
        Self {
            schema: CHIO_RUNTIME_ADMISSION_STORE_SCHEMA.to_string(),
            bundles: Vec::new(),
            consumed_lease_ids: Vec::new(),
            consumed_treaty_continuation_ids: Vec::new(),
            trust_floors: Vec::new(),
        }
    }
}

impl JsonRuntimeAdmissionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ChioRuntimeError> {
        let path = path.as_ref().to_path_buf();
        let state = if path.exists() {
            let json = fs::read_to_string(&path).map_err(|error| {
                ChioRuntimeError::Io(format!(
                    "failed to read runtime admission store {}: {error}",
                    path.display()
                ))
            })?;
            let state: JsonRuntimeAdmissionStoreState =
                serde_json::from_str(&json).map_err(|error| {
                    ChioRuntimeError::Json(format!(
                        "failed to parse runtime admission store {}: {error}",
                        path.display()
                    ))
                })?;
            if !is_runtime_admission_store_schema(&state.schema) {
                return Err(ChioRuntimeError::Rejected {
                    code: "unsupported_runtime_store_schema",
                    detail: format!(
                        "runtime admission store {} declared unsupported schema {}",
                        path.display(),
                        state.schema
                    ),
                });
            }
            let mut state = state;
            state.schema = CHIO_RUNTIME_ADMISSION_STORE_SCHEMA.to_string();
            state
        } else {
            JsonRuntimeAdmissionStoreState::default()
        };
        let store = Self {
            path,
            state: Arc::new(Mutex::new(state)),
        };
        store.validate_locked_state()?;
        Ok(store)
    }

    pub fn insert_bundle(&self, bundle: RuntimeAdmissionBundle) -> Result<(), ChioRuntimeError> {
        let mut state = self.lock_state()?;
        if let Some(existing) = state
            .bundles
            .iter()
            .find(|existing| existing.admission_id == bundle.admission_id)
        {
            if existing == &bundle {
                return Ok(());
            }
            return Err(ChioRuntimeError::DuplicateAdmissionBundle);
        }
        state.bundles.push(bundle);
        Self::validate_state(&state)?;
        self.persist_state(&state)
    }

    fn validate_locked_state(&self) -> Result<(), ChioRuntimeError> {
        let state = self.lock_state()?;
        Self::validate_state(&state)
    }

    fn validate_state(state: &JsonRuntimeAdmissionStoreState) -> Result<(), ChioRuntimeError> {
        let mut admission_ids = BTreeSet::new();
        for bundle in &state.bundles {
            if !admission_ids.insert(bundle.admission_id.as_str()) {
                return Err(ChioRuntimeError::DuplicateAdmissionBundle);
            }
        }
        let mut lease_ids = BTreeSet::new();
        for lease_id in &state.consumed_lease_ids {
            if !lease_ids.insert(lease_id.as_str()) {
                return Err(ChioRuntimeError::Rejected {
                    code: "duplicate_consumed_lease",
                    detail: format!("runtime admission store repeats consumed lease {lease_id}"),
                });
            }
        }
        let mut continuation_ids = BTreeSet::new();
        for continuation_id in &state.consumed_treaty_continuation_ids {
            if !continuation_ids.insert(continuation_id.as_str()) {
                return Err(ChioRuntimeError::Rejected {
                    code: "duplicate_consumed_treaty_continuation",
                    detail: format!(
                        "runtime admission store repeats treaty continuation {continuation_id}"
                    ),
                });
            }
        }
        let mut trust_floor_ids = BTreeSet::new();
        for entry in &state.trust_floors {
            let identity = trust_floor_identity(&entry.verifier_id, &entry.key_id);
            if !trust_floor_ids.insert(identity.clone()) {
                return Err(ChioRuntimeError::Rejected {
                    code: "duplicate_runtime_trust_floor",
                    detail: format!("runtime admission store repeats trust floor {identity}"),
                });
            }
            if entry.highest_version == 0 {
                return Err(ChioRuntimeError::Rejected {
                    code: "runtime_trust_floor_version_zero",
                    detail: format!("runtime trust floor {identity} has version zero"),
                });
            }
        }
        Ok(())
    }

    fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, JsonRuntimeAdmissionStoreState>, ChioRuntimeError> {
        self.state.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime admission JSON store is poisoned".to_string())
        })
    }

    fn persist_state(
        &self,
        state: &JsonRuntimeAdmissionStoreState,
    ) -> Result<(), ChioRuntimeError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    ChioRuntimeError::Io(format!(
                        "failed to create runtime admission store directory {}: {error}",
                        parent.display()
                    ))
                })?;
            }
        }
        let json = serde_json::to_string_pretty(state)
            .map_err(|error| ChioRuntimeError::Json(error.to_string()))?;
        fs::write(&self.path, format!("{json}\n")).map_err(|error| {
            ChioRuntimeError::Io(format!(
                "failed to write runtime admission store {}: {error}",
                self.path.display()
            ))
        })
    }
}

fn is_runtime_admission_store_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_ADMISSION_STORE_SCHEMA)
}

impl RuntimeAdmissionStore for JsonRuntimeAdmissionStore {
    fn bundle(
        &self,
        admission_id: &str,
    ) -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError> {
        let state = self.lock_state()?;
        Ok(state
            .bundles
            .iter()
            .find(|bundle| bundle.admission_id == admission_id)
            .cloned())
    }

    fn consume_destructive_lease(
        &self,
        lease_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        let mut state = self.lock_state()?;
        if state
            .consumed_lease_ids
            .iter()
            .any(|consumed| consumed == lease_id)
        {
            return Err(ChioRuntimeError::Rejected {
                code: "destructive_lease_replay",
                detail: format!("destructive lease {lease_id} was already consumed"),
            });
        }
        state.consumed_lease_ids.push(lease_id.to_string());
        Self::validate_state(&state)?;
        self.persist_state(&state)
    }

    fn release_destructive_lease(
        &self,
        lease_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        let mut state = self.lock_state()?;
        state
            .consumed_lease_ids
            .retain(|consumed| consumed != lease_id);
        Self::validate_state(&state)?;
        self.persist_state(&state)
    }

    fn consume_treaty_continuation(
        &self,
        continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        let mut state = self.lock_state()?;
        if state
            .consumed_treaty_continuation_ids
            .iter()
            .any(|consumed| consumed == continuation_id)
        {
            return Err(ChioRuntimeError::Rejected {
                code: "chio_treaty_continuation_replay",
                detail: format!("treaty continuation {continuation_id} was already consumed"),
            });
        }
        state
            .consumed_treaty_continuation_ids
            .push(continuation_id.to_string());
        Self::validate_state(&state)?;
        self.persist_state(&state)
    }

    fn release_treaty_continuation(
        &self,
        continuation_id: &str,
        _admission_id: &str,
    ) -> Result<(), ChioRuntimeError> {
        let mut state = self.lock_state()?;
        state
            .consumed_treaty_continuation_ids
            .retain(|consumed| consumed != continuation_id);
        Self::validate_state(&state)?;
        self.persist_state(&state)
    }

    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        let state = self.lock_state()?;
        Ok(state
            .trust_floors
            .iter()
            .find(|entry| entry.verifier_id == verifier_id && entry.key_id == key_id)
            .cloned())
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        let mut state = self.lock_state()?;
        if let Some(existing) = state.trust_floors.iter_mut().find(|existing| {
            existing.verifier_id == entry.verifier_id && existing.key_id == entry.key_id
        }) {
            *existing = entry;
        } else {
            state.trust_floors.push(entry);
        }
        Self::validate_state(&state)?;
        self.persist_state(&state)
    }
}
