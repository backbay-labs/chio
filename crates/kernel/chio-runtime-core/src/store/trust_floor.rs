use super::traits::RuntimeTrustFloorStore;
use crate::*;

pub struct JsonRuntimeTrustFloorStateStore {
    path: PathBuf,
    state: Arc<Mutex<RuntimeTrustFloorState>>,
}

impl JsonRuntimeTrustFloorStateStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ChioRuntimeError> {
        let path = path.as_ref().to_path_buf();
        let mut state = if path.exists() {
            let json = fs::read_to_string(&path).map_err(|error| {
                ChioRuntimeError::Io(format!(
                    "failed to read runtime trust-floor state {}: {error}",
                    path.display()
                ))
            })?;
            let state: RuntimeTrustFloorState = serde_json::from_str(&json).map_err(|error| {
                ChioRuntimeError::Json(format!(
                    "failed to parse runtime trust-floor state {}: {error}",
                    path.display()
                ))
            })?;
            state
        } else {
            RuntimeTrustFloorState {
                schema: CHIO_RUNTIME_TRUST_FLOOR_STATE_SCHEMA.to_string(),
                entries: Vec::new(),
            }
        };
        Self::normalize_schema(&mut state, Some(&path))?;
        let store = Self {
            path,
            state: Arc::new(Mutex::new(state)),
        };
        store.validate_locked_state()?;
        Ok(store)
    }

    fn normalize_schema(
        state: &mut RuntimeTrustFloorState,
        source_path: Option<&Path>,
    ) -> Result<(), ChioRuntimeError> {
        match state.schema.as_str() {
            CHIO_RUNTIME_TRUST_FLOOR_STATE_SCHEMA => {
                state.schema = CHIO_RUNTIME_TRUST_FLOOR_STATE_SCHEMA.to_string();
                Ok(())
            }
            unsupported => {
                let location = source_path
                    .map(|path| format!(" {}", path.display()))
                    .unwrap_or_default();
                Err(ChioRuntimeError::Rejected {
                    code: "unsupported_runtime_trust_floor_state_schema",
                    detail: format!(
                        "runtime trust-floor state{location} declared unsupported schema {unsupported}"
                    ),
                })
            }
        }
    }

    fn validate_locked_state(&self) -> Result<(), ChioRuntimeError> {
        let state = self.lock_state()?;
        Self::validate_state(&state)
    }

    fn validate_state(state: &RuntimeTrustFloorState) -> Result<(), ChioRuntimeError> {
        if state.schema != CHIO_RUNTIME_TRUST_FLOOR_STATE_SCHEMA {
            return Err(ChioRuntimeError::Rejected {
                code: "unsupported_runtime_trust_floor_state_schema",
                detail: format!(
                    "runtime trust-floor state declared unsupported schema {}",
                    state.schema
                ),
            });
        }
        let mut trust_floor_ids = BTreeSet::new();
        for entry in &state.entries {
            let identity = trust_floor_identity(&entry.verifier_id, &entry.key_id);
            if !trust_floor_ids.insert(identity.clone()) {
                return Err(ChioRuntimeError::Rejected {
                    code: "duplicate_runtime_trust_floor",
                    detail: format!("runtime trust-floor state repeats trust floor {identity}"),
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
    ) -> Result<std::sync::MutexGuard<'_, RuntimeTrustFloorState>, ChioRuntimeError> {
        self.state.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime trust-floor JSON state is poisoned".to_string())
        })
    }

    fn persist_state(&self, state: &RuntimeTrustFloorState) -> Result<(), ChioRuntimeError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    ChioRuntimeError::Io(format!(
                        "failed to create runtime trust-floor state directory {}: {error}",
                        parent.display()
                    ))
                })?;
            }
        }
        let json = serde_json::to_string_pretty(state)
            .map_err(|error| ChioRuntimeError::Json(error.to_string()))?;
        fs::write(&self.path, format!("{json}\n")).map_err(|error| {
            ChioRuntimeError::Io(format!(
                "failed to write runtime trust-floor state {}: {error}",
                self.path.display()
            ))
        })
    }
}

impl RuntimeTrustFloorStore for JsonRuntimeTrustFloorStateStore {
    fn runtime_trust_floor(
        &self,
        verifier_id: &str,
        key_id: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        let state = self.lock_state()?;
        Ok(state
            .entries
            .iter()
            .find(|entry| entry.verifier_id == verifier_id && entry.key_id == key_id)
            .cloned())
    }

    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        let mut state = self.lock_state()?;
        state.schema = CHIO_RUNTIME_TRUST_FLOOR_STATE_SCHEMA.to_string();
        if let Some(existing) = state.entries.iter_mut().find(|existing| {
            existing.verifier_id == entry.verifier_id && existing.key_id == entry.key_id
        }) {
            *existing = entry;
        } else {
            state.entries.push(entry);
        }
        Self::validate_state(&state)?;
        self.persist_state(&state)
    }

    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous_hash_sha256: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        let mut state = self.lock_state()?;
        state.schema = CHIO_RUNTIME_TRUST_FLOOR_STATE_SCHEMA.to_string();
        let existing = state
            .entries
            .iter()
            .find(|existing| {
                existing.verifier_id == entry.verifier_id && existing.key_id == entry.key_id
            })
            .cloned();
        validate_runtime_trust_floor_transition(existing, &entry, previous_hash_sha256)?;
        if let Some(existing) = state.entries.iter_mut().find(|existing| {
            existing.verifier_id == entry.verifier_id && existing.key_id == entry.key_id
        }) {
            *existing = entry;
        } else {
            state.entries.push(entry);
        }
        Self::validate_state(&state)?;
        self.persist_state(&state)
    }
}
